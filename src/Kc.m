// Kc.m - keychain probe through securityd (SecItem), not through the database.
//
// Background: /private/var/Keychains/keychain-2.db opens with EPERM from a
// sandboxed app, and our sandbox_extension work showed the file layer stays
// closed. SecItem is a different door: securityd evaluates the caller's
// keychain-access-groups instead of the file sandbox. A build carrying
// "com.apple.token" in that array can ask for items outside its own prefix,
// which is what the MConfPoC screenshot shows (genp 41 / inet 6 / cert 12 /
// key 7 / ident 1).
//
// This probe only counts. It reports which classes answer, and whether the
// token group widens the result versus the app's own group.

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
        case errSecSuccess:              return @"ok";
        case errSecItemNotFound:         return @"notfound";
        case errSecInteractionNotAllowed:return @"interaction";
        case errSecAuthFailed:           return @"authfailed";
        case errSecMissingEntitlement:   return @"noent";
        case errSecParam:                return @"param";
        default:                          return [NSString stringWithFormat:@"%d", (int)st];
    }
}

// Access group name -> count. group == nil means "no kSecAttrAccessGroup key".
static void countClass(NSString *label, CFStringRef cls, NSString *group) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass] = (__bridge id)cls;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    q[(__bridge id)kSecReturnAttributes] = @YES;
    if (group != nil) q[(__bridge id)kSecAttrAccessGroup] = group;

    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    NSUInteger n = 0;
    if (st == errSecSuccess && out != NULL) {
        CFTypeID t = CFGetTypeID(out);
        if (t == CFArrayGetTypeID()) n = (NSUInteger)CFArrayGetCount((CFArrayRef)out);
        CFRelease(out);
    }
    kcNote(@"%@ %-6s %-16s n=%lu", group == nil ? @"own  " : @"token",
           [label UTF8String], [osName(st) UTF8String], (unsigned long)n);
}

int kcRun(void) {
    gKcDocs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    gKcLines = [NSMutableArray array];

    kcNote(@"=== kc start ===");

    // Sanity: the database itself, which is expected to be denied.
    NSString *db = @"/private/var/Keychains/keychain-2.db";
    int fd = open([db UTF8String], O_RDONLY);
    kcNote(@"db open=%s errno=%d", fd >= 0 ? "ok" : "denied", fd >= 0 ? 0 : errno);
    if (fd >= 0) close(fd);

    // Our own groups, then the token group.
    NSArray *classes = @[
        @[@"genp", (__bridge id)kSecClassGenericPassword],
        @[@"inet", (__bridge id)kSecClassInternetPassword],
        @[@"cert", (__bridge id)kSecClassCertificate],
        @[@"key",  (__bridge id)kSecClassKey],
        @[@"ident",(__bridge id)kSecClassIdentity],
    ];

    for (NSArray *c in classes) {
        countClass(c[0], (__bridge CFStringRef)c[1], nil);
    }
    for (NSArray *c in classes) {
        countClass(c[0], (__bridge CFStringRef)c[1], @"com.apple.token");
    }

    NSString *text = [[gKcLines componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    [[text dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gKcDocs stringByAppendingPathComponent:@"kc.log"] atomically:YES];

    kcNote(@"=== kc end ===");
    return 0;
}
