// Renamer.m - fill in the display names the integration layer could not resolve.
//
// The integration builds worse_query/App Data (UUID)/<uuid> and tries to add a
// human name in worse_query/App Data (by app)/. Containers whose metadata is
// unreadable end up without a name. This pass reads the bundle id out of the
// container's own directory names and asks LaunchServices for the display name.

#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>

static BOOL WQRLooksLikeBundleID(NSString *value) {
    if (value.length < 6 || [value rangeOfString:@"."].location == NSNotFound) return NO;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
                               @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"];
    if ([value rangeOfCharacterFromSet:allowed.invertedSet].location != NSNotFound) return NO;
    return YES;
}

static NSString *WQRInferBundleID(NSString *container) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *subdirs = @[@"Library/Preferences", @"Library/Caches",
                         @"Library/Application Support", @"Documents", @"Library"];
    for (NSString *sub in subdirs) {
        NSString *dir = [container stringByAppendingPathComponent:sub];
        for (NSString *name in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            NSString *stem = [name stringByDeletingPathExtension];
            if (WQRLooksLikeBundleID(stem)) return stem;
            if (WQRLooksLikeBundleID(name)) return name;
        }
    }
    return nil;
}

static NSString *WQRDisplayName(NSString *bundleID) {
    if (bundleID.length == 0) return nil;
    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    SEL proxySel = NSSelectorFromString(@"applicationProxyForIdentifier:");
    if (proxyClass == Nil || ![proxyClass respondsToSelector:proxySel]) return nil;

    id proxy = ((id (*)(id, SEL, id))objc_msgSend)(proxyClass, proxySel, bundleID);
    if (proxy == nil) return nil;

    SEL nameSel = NSSelectorFromString(@"localizedName");
    if (![proxy respondsToSelector:nameSel]) return nil;
    id value = ((id (*)(id, SEL))objc_msgSend)(proxy, nameSel);
    return [value isKindOfClass:[NSString class]] ? value : nil;
}

static NSString *WQRSafeName(NSString *value) {
    NSMutableString *out = [NSMutableString string];
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        if (c == '/' || c == ':' || c == '\0') {
            [out appendString:@"_"];
        } else {
            [out appendFormat:@"%C", c];
        }
    }
    if (out.length == 0 || [out hasPrefix:@"."]) {
        return [@"app-" stringByAppendingString:out];
    }
    return out;
}

static NSString *WQRFindVirtualRoot(void) {
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count == 0) return nil;
    NSString *base = [docs objectAtIndex:0];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *direct = [base stringByAppendingPathComponent:@"worse_query"];
    if ([fm fileExistsAtPath:direct]) return direct;

    for (NSString *name in [fm contentsOfDirectoryAtPath:base error:nil]) {
        if ([name isEqualToString:@"worse_query"]) {
            return [base stringByAppendingPathComponent:name];
        }
    }
    return nil;
}

static void WQRRun(void) {
    NSString *root = WQRFindVirtualRoot();
    if (root.length == 0) return;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *uuidDir = [root stringByAppendingPathComponent:@"App Data (UUID)"];
    NSString *byAppDir = [root stringByAppendingPathComponent:@"App Data (by app)"];
    [fm createDirectoryAtPath:byAppDir withIntermediateDirectories:YES attributes:nil error:nil];

    NSUInteger added = 0;
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:uuidDir error:nil]) {
        NSString *link = [uuidDir stringByAppendingPathComponent:uuid];
        NSString *target = [NSString stringWithContentsOfFile:link
                                                     encoding:NSUTF8StringEncoding
                                                        error:nil];
        if (target.length == 0) {
            // symlink target, not a file: resolve it
            target = [[fm destinationOfSymbolicLinkAtPath:link error:nil] copy];
        }
        NSString *container = target.length > 0 ? target : link;

        NSString *bundleID = WQRInferBundleID(container) ?: uuid;
        NSString *name = WQRDisplayName(bundleID) ?: bundleID;

        NSString *linkName = WQRSafeName([NSString stringWithFormat:@"%@ [%@]", name, bundleID]);
        NSString *dest = [byAppDir stringByAppendingPathComponent:linkName];
        if ([fm fileExistsAtPath:dest]) continue;

        if ([fm createSymbolicLinkAtPath:dest withDestinationPath:container error:nil]) {
            added++;
        }
    }

    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count > 0) {
        NSString *log = [[docs objectAtIndex:0] stringByAppendingPathComponent:@"renamer.log"];
        [[NSString stringWithFormat:@"root %@\nadded %lu\n", root, (unsigned long)added]
            writeToFile:log atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

__attribute__((constructor))
static void WQRInit(void) {
    // The integration needs tens of seconds to index on first launch.
    for (int i = 1; i <= 6; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 15 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            WQRRun();
        });
    }
}
