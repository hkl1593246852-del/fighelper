// Kc.m - keychain probe through securityd (SecItem).
//
// Result of the first run on iPhone14,3 / 27.0.1:
//   own   genp ok  n=119      <- far more than an app of our own should have
//   own   key  ok  n=16
//   token *    notfound n=0   <- "com.apple.token" grants nothing here
//
// 119 generic passwords only makes sense if the signing identity ends up with a
// wildcard access group ($(AppIdentifierPrefix) -> TEAM.*), which would expose
// every item created by any app signed with the same certificate. The attribute
// kSecAttrAccessGroup ("agrp") names the owner of each item, so dumping it turns
// the count into an answer.
//
// This build lists attributes only. Item data is not read.

#import "Kc.h"

#import <Security/Security.h>

static NSString *gKcDocs;
static NSMutableArray *gKcLines;

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
        case errSecAuthFailed:            return @"authfailed";
        case errSecMissingEntitlement:    return @"noent";
        default:                          return [NSString stringWithFormat:@"%d", (int)st];
    }
}

static NSString *strOf(NSDictionary *d, CFStringRef key) {
    id v = d[(__bridge id)key];
    if (v == nil) return @"-";
    return [v isKindOfClass:[NSString class]] ? v : [v description];
}

static void dumpClass(NSString *label, CFStringRef cls, NSString *group, NSUInteger cap) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass] = (__bridge id)cls;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    q[(__bridge id)kSecReturnAttributes] = @YES;
    if (group != nil) q[(__bridge id)kSecAttrAccessGroup] = group;

    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st != errSecSuccess || out == NULL || CFGetTypeID(out) != CFArrayGetTypeID()) {
        kcNote(@"[%@] %-5s %@ n=0", group == nil ? @"own" : @"token", [label UTF8String],
               osName(st));
        if (out) CFRelease(out);
        return;
    }

    CFArrayRef arr = (CFArrayRef)out;
    CFIndex n = CFArrayGetCount(arr);
    kcNote(@"[%@] %-5s ok n=%ld", group == nil ? @"own" : @"token", [label UTF8String], (long)n);

    NSMutableDictionary *groups = [NSMutableDictionary dictionary];
    for (CFIndex i = 0; i < n; i++) {
        NSDictionary *d = (__bridge NSDictionary *)CFArrayGetValueAtIndex(arr, i);
        if (![d isKindOfClass:[NSDictionary class]]) continue;
        NSString *agrp = strOf(d, kSecAttrAccessGroup);
        groups[agrp] = @([groups[agrp] integerValue] + 1);
    }
    NSArray *sorted = [[groups allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *g in sorted) {
        kcNote(@"    agrp %-40s %@", [g UTF8String], groups[g]);
    }

    for (CFIndex i = 0; i < n && i < (CFIndex)cap; i++) {
        NSDictionary *d = (__bridge NSDictionary *)CFArrayGetValueAtIndex(arr, i);
        if (![d isKindOfClass:[NSDictionary class]]) continue;
        kcNote(@"    #%03ld svce=%-24s acct=%-20s agrp=%@",
               (long)i,
               [strOf(d, kSecAttrService) UTF8String],
               [strOf(d, kSecAttrAccount) UTF8String],
               strOf(d, kSecAttrAccessGroup));
    }
    CFRelease(out);
}

int kcRun(void) {
    gKcDocs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    gKcLines = [NSMutableArray array];

    kcNote(@"=== kc start ===");

    NSString *db = @"/private/var/Keychains/keychain-2.db";
    int fd = open([db UTF8String], O_RDONLY);
    kcNote(@"db open=%s errno=%d", fd >= 0 ? "ok" : "denied", fd >= 0 ? 0 : errno);
    if (fd >= 0) close(fd);

    dumpClass(@"genp", kSecClassGenericPassword,   nil, 40);
    dumpClass(@"key",  kSecClassKey,               nil, 20);
    dumpClass(@"genp", kSecClassGenericPassword,   @"com.apple.token", 0);
    dumpClass(@"inet", kSecClassInternetPassword,  @"com.apple.token", 0);

    NSString *text = [[gKcLines componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    [[text dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gKcDocs stringByAppendingPathComponent:@"kc.log"] atomically:YES];

    kcNote(@"=== kc end ===");
    return 0;
}
