// FilzaWQ.xm - grant Filza container access through worse_query.
//
// Injected into Filza's binary. On load it asks containermanagerd for sandbox
// extensions covering the container roots, by pointing an app group's
// Library/Caches symlink at each one in turn.
//
// The group is read from the app's own entitlements at runtime, so whichever
// group the signing profile carries is the one used. Without an app-group
// entitlement every call returns -1 and the log says so.

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Security/SecCode.h>
#import <Security/SecRequirement.h>
#import <UIKit/UIKit.h>
#import <os/log.h>

#import "Wq.h"
#import "fishhook.h"

// Filza validates its own signature and shows "Main binary was modified" once the
// binary carries an injected LC_LOAD_DYLIB. Making the validity check succeed is
// enough; the code object itself is still created normally.
static OSStatus (*orig_static_check)(SecStaticCodeRef, SecCSFlags, SecRequirementRef);
static OSStatus hook_static_check(SecStaticCodeRef code, SecCSFlags flags,
                                  SecRequirementRef requirement) {
    return errSecSuccess;
}

// SecTask lives in the private Security headers; declare just what is needed.
// The tweak compiles as Objective-C++, so these need C linkage to match the
// dylib's exported symbols.
#ifdef __cplusplus
extern "C" {
#endif
typedef struct __SecTask *WQSecTask;
extern WQSecTask SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(WQSecTask task,
                                                CFStringRef entitlement,
                                                CFErrorRef *error);
#ifdef __cplusplus
}
#endif

static NSString *const kFallbackGroup = @"group.com.you.filzalite";

static NSString *const kTargets[] = {
    @"/var/mobile/Containers/Data/Application",
    @"/var/mobile/Containers/Data/InternalDaemon",
    @"/var/mobile/Containers/Data/PluginKitPlugin",
    @"/var/mobile/Containers/Shared/AppGroup",
    @"/var/containers/Shared/SystemGroup",
    @"/var/containers/Data/System",
};

static os_log_t WQLog(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("com.you.filzawq", "escape"); });
    return log;
}

/// First app group listed in our own entitlements, or nil when the profile
/// carries none.
static NSString *WQGroupFromEntitlements(void) {
    WQSecTask task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (task == NULL) return nil;

    CFTypeRef value = SecTaskCopyValueForEntitlement(
        task, CFSTR("com.apple.security.application-groups"), NULL);
    CFRelease(task);
    if (value == NULL) return nil;

    NSString *group = nil;
    if (CFGetTypeID(value) == CFArrayGetTypeID() && CFArrayGetCount((CFArrayRef)value) > 0) {
        CFTypeRef first = CFArrayGetValueAtIndex((CFArrayRef)value, 0);
        if (CFGetTypeID(first) == CFStringGetTypeID()) {
            group = [NSString stringWithString:(__bridge NSString *)first];
        }
    }
    CFRelease(value);
    return group;
}

static void WQGrantAll(void) {
    NSString *group = WQGroupFromEntitlements();
    NSMutableArray<NSString *> *report = [NSMutableArray array];

    [report addObject:[NSString stringWithFormat:@"group=%@", group ?: @"(none)"]];
    os_log_fault(WQLog(), "app group = %{public}@", group ?: @"(none)");

    if (group.length == 0) {
        [report addObject:@"no com.apple.security.application-groups entitlement"];
    }

    NSString *effective = group.length > 0 ? group : kFallbackGroup;

    for (size_t i = 0; i < sizeof(kTargets) / sizeof(kTargets[0]); i++) {
        NSString *p = kTargets[i];
        int64_t h = WQAccess(p, effective, 0);
        int used = 0;
        if (h < 0 && h != -255) {
            h = WQAccess(p, effective, 1);      // iOS 26.x flag set
            used = 1;
        }
        [report addObject:[NSString stringWithFormat:@"%@ mode=%d handle=%lld", p, used, h]];
        os_log_fault(WQLog(), "%{public}@ mode=%d handle=%lld", p, used, h);
    }

    // Breadcrumb inside Filza's own Documents.
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"filzawq.log"];
    [[[report componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"]
        writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

%ctor {
    struct rebinding rebinds[] = {
        {"SecStaticCodeCheckValidity", hook_static_check, (void **)&orig_static_check},
        {"SecStaticCodeCheckValidityWithErrors", hook_static_check, (void **)&orig_static_check},
    };
    rebind_symbols(rebinds, sizeof(rebinds) / sizeof(rebinds[0]));

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        WQGrantAll();
    });

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *note) {
        WQGrantAll();
    }];
}
