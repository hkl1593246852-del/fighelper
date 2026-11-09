// FilzaWQ.xm - grant Filza container access through worse_query.
//
// Loaded in place of Frameworks/lib7z.framework/lib7z, which the main binary
// already links; nothing in Filza's main executable changes, so its
// Filza.signature check still passes.
//
// Every private API is resolved with dlsym at runtime: linking SecTask*
// directly makes dyld abort at launch when the symbol is not exported.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <os/log.h>

#import "Wq.h"

typedef struct __SecTask *WQSecTask;
typedef WQSecTask (*SecTaskCreateFromSelf_t)(CFAllocatorRef);
typedef CFTypeRef (*SecTaskCopyValueForEntitlement_t)(WQSecTask, CFStringRef, CFErrorRef *);

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

/// First app group in our own entitlements, or nil when the profile carries none.
static NSString *WQGroupFromEntitlements(void) {
    SecTaskCreateFromSelf_t create =
        (SecTaskCreateFromSelf_t)dlsym(RTLD_DEFAULT, "SecTaskCreateFromSelf");
    SecTaskCopyValueForEntitlement_t copy =
        (SecTaskCopyValueForEntitlement_t)dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
    if (create == NULL || copy == NULL) return nil;

    WQSecTask task = create(kCFAllocatorDefault);
    if (task == NULL) return nil;

    CFTypeRef value = copy(task, CFSTR("com.apple.security.application-groups"), NULL);
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

    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (docs.length > 0) {
        NSString *path = [docs stringByAppendingPathComponent:@"filzawq.log"];
        [[[report componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"]
            writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

__attribute__((constructor))
static void FilzaWQInit(void) {
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
