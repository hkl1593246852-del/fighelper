// Kc.m - keychain access-group histogram + selective value read.
//
// Established on iPhone14,3 / 27.0.1 (24A446):
//   [own] genp n=119, every item under agrp "8LDT2G2S8F.*"
//   that prefix is the codeSigningTeamID from the crash report, i.e. the
//   sideload signing identity; $(AppIdentifierPrefix) expands to a wildcard,
//   so one app sees the items of every app signed with the same certificate.
//   "com.apple.token" grants nothing (all classes notfound).
//
// This build keeps a compact histogram, then reads values only for the
// services named in Documents/kc_targets.txt:
//     tag<TAB>service
// Values land in Documents/out/kc_<tag>.bin; nothing is scanned wholesale.

#import "Kc.h"

#import <Security/Security.h>

static NSString *gKcDocs;
static NSString *gKcOut;
static NSMutableArray *gKcLines;
static NSMutableArray *gKcProduced;

static void kcNote(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [gKcLines addObject:s];
    NSLog(@"[kc] %@", s);
}

static NSString *osName(OSStatus st) {
    switch (st) {
        case errSecSuccess:               return @"ok";
        case errSecItemNotFound:          return @"notfound";
        case errSecInteractionNotAllowed: return @"locked";
        case errSecAuthFailed:            return @"authfail";
        case errSecMissingEntitlement:    return @"noent";
        default:                          return [NSString stringWithFormat:@"%d", (int)st];
    }
}

static NSString *strOf(NSDictionary *d, CFStringRef key) {
    id v = d[(__bridge id)key];
    if (v == nil) return @"-";
    return [v isKindOfClass:[NSString class]] ? v : [v description];
}

static void histogram(void) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    q[(__bridge id)kSecReturnAttributes] = @YES;

    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st != errSecSuccess || out == NULL || CFGetTypeID(out) != CFArrayGetTypeID()) {
        kcNote(@"hist genp %@ n=0", osName(st));
        if (out) CFRelease(out);
        return;
    }
    CFArrayRef arr = (CFArrayRef)out;
    CFIndex n = CFArrayGetCount(arr);
    NSMutableDictionary *groups = [NSMutableDictionary dictionary];
    NSMutableDictionary *services = [NSMutableDictionary dictionary];
    for (CFIndex i = 0; i < n; i++) {
        NSDictionary *d = (__bridge NSDictionary *)CFArrayGetValueAtIndex(arr, i);
        if (![d isKindOfClass:[NSDictionary class]]) continue;
        NSString *g = strOf(d, kSecAttrAccessGroup);
        NSString *s = strOf(d, kSecAttrService);
        groups[g] = @([groups[g] integerValue] + 1);
        services[s] = @([services[s] integerValue] + 1);
    }
    kcNote(@"hist genp n=%ld groups=%lu services=%lu", (long)n,
           (unsigned long)groups.count, (unsigned long)services.count);
    for (NSString *g in [[groups allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
        kcNote(@"    agrp %@ -> %@", g, groups[g]);
    }

    // Write the full service index so specific targets can be chosen without
    // guessing names, then show the busiest ones on screen.
    NSArray *ordered = [services keysSortedByValueUsingComparator:^NSComparisonResult(id a, id b) {
        return [b compare:a];
    }];
    NSMutableArray *lines = [NSMutableArray array];
    for (NSString *s in ordered) {
        [lines addObject:[NSString stringWithFormat:@"%3ld\t%@", (long)[services[s] integerValue], s]];
    }
    NSString *idx = [[lines componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    [[idx dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gKcOut stringByAppendingPathComponent:@"kc_services.txt"] atomically:YES];
    [gKcProduced addObject:@"kc_services.txt"];

    NSUInteger show = MIN(ordered.count, (NSUInteger)18);
    for (NSUInteger i = 0; i < show; i++) {
        NSString *s = ordered[i];
        kcNote(@"    svce %-44s %@", [s UTF8String], services[s]);
    }
    if (ordered.count > show) {
        kcNote(@"    ... %lu more in out/kc_services.txt", (unsigned long)(ordered.count - show));
    }
    CFRelease(out);
}

static void readService(NSString *tag, NSString *service) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    q[(__bridge id)kSecAttrService] = service;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    q[(__bridge id)kSecReturnAttributes] = @YES;
    q[(__bridge id)kSecReturnData] = @YES;

    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st != errSecSuccess || out == NULL) {
        kcNote(@"read %-20s %@ n=0", [tag UTF8String], osName(st));
        if (out) CFRelease(out);
        return;
    }

    CFTypeID tid = CFGetTypeID(out);
    CFArrayRef arr = (tid == CFArrayGetTypeID()) ? (CFArrayRef)out : NULL;
    CFIndex n = arr ? CFArrayGetCount(arr) : 1;

    NSMutableData *all = [NSMutableData data];
    for (CFIndex i = 0; i < n; i++) {
        NSDictionary *d = arr ? (__bridge NSDictionary *)CFArrayGetValueAtIndex(arr, i)
                              : (__bridge NSDictionary *)out;
        if (![d isKindOfClass:[NSDictionary class]]) continue;

        NSData *data = d[(__bridge id)kSecValueData];
        NSString *hdr = [NSString stringWithFormat:
            @"#%ld acct=%@ agrp=%@ len=%lu\n",
            (long)i,
            strOf(d, kSecAttrAccount),
            strOf(d, kSecAttrAccessGroup),
            (unsigned long)(data ? data.length : 0)];
        [all appendData:[hdr dataUsingEncoding:NSUTF8StringEncoding]];
        if (data) [all appendData:data];
        [all appendData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];
    }

    NSString *name = [NSString stringWithFormat:@"kc_%@.bin", tag];
    NSString *p = [gKcOut stringByAppendingPathComponent:name];
    if ([all writeToFile:p atomically:YES]) [gKcProduced addObject:name];
    kcNote(@"read %-20s ok items=%ld -> out/%@ (%lu B)", [tag UTF8String], (long)n,
           name, (unsigned long)all.length);
    CFRelease(out);
}

int kcRun(void) {
    gKcDocs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    gKcOut = [gKcDocs stringByAppendingPathComponent:@"out"];
    gKcLines = [NSMutableArray array];
    gKcProduced = [NSMutableArray array];
    [[NSFileManager defaultManager] createDirectoryAtPath:gKcOut
                             withIntermediateDirectories:YES attributes:nil error:nil];

    kcNote(@"=== kc start ===");

    NSString *db = @"/private/var/Keychains/keychain-2.db";
    int fd = open([db UTF8String], O_RDONLY);
    kcNote(@"db open=%s errno=%d", fd >= 0 ? "ok" : "denied", fd >= 0 ? 0 : errno);
    if (fd >= 0) close(fd);

    histogram();

    NSString *targets = [NSString stringWithContentsOfFile:
                         [gKcDocs stringByAppendingPathComponent:@"kc_targets.txt"]
                                                  encoding:NSUTF8StringEncoding error:nil];
    if (targets.length == 0) {
        kcNote(@"kc_targets.txt empty: histogram only");
    } else {
        for (NSString *line in [targets componentsSeparatedByString:@"\n"]) {
            if (line.length == 0) continue;
            NSArray *p = [line componentsSeparatedByString:@"\t"];
            if (p.count < 2) continue;
            readService(p[0], p[1]);
        }
    }

    NSString *text = [[gKcLines componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    [[text dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gKcDocs stringByAppendingPathComponent:@"kc.log"] atomically:YES];

    kcNote(@"=== kc end, %lu files ===", (unsigned long)gKcProduced.count);
    return 0;
}
