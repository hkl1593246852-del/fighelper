// FilzaWQ.xm - grant Filza container access through worse_query.
//
// Loaded in place of Frameworks/lib7z.framework/lib7z, which the main binary
// already links; nothing in Filza's main executable changes, so its
// Filza.signature check still passes.
//
// The container query takes an operation flag and a part; which pair works is
// not documented and changes between releases, so every combination is tried in
// turn and the first hit is kept. All attempts are logged to Documents/filzawq.log
// so a failure still says exactly which knob is wrong.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dirent.h>
#import <dlfcn.h>
#import <errno.h>
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

typedef struct {
    uint64_t flags;
    uint64_t part;
    const char *label;
} WQVariant;

// part: 1 = Data, 2 = Shared, 3 = Library/Caches, 4 = tmp
static const WQVariant kVariants[] = {
    {0x8000000000000000ULL, 3, "f27/p3"},
    {0x0000000800000000ULL, 3, "f26/p3"},
    {0ULL,                  3, "f0/p3"},
    {0x8000000000000000ULL, 1, "f27/p1"},
    {0x0000000800000000ULL, 1, "f26/p1"},
    {0ULL,                  1, "f0/p1"},
    {0x8000000000000000ULL, 2, "f27/p2"},
    {0ULL,                  2, "f0/p2"},
    {0x8000000000000000ULL, 4, "f27/p4"},
    {0ULL,                  4, "f0/p4"},
};

static os_log_t WQLog(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("com.you.filzawq", "escape"); });
    return log;
}

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

/// How many entries a plain opendir sees, and errno when it fails. This is the
/// real proof that the extension covers the path.
static NSString *WQProbe(NSString *path) {
    errno = 0;
    DIR *dp = opendir(path.fileSystemRepresentation);
    if (dp == NULL) {
        return [NSString stringWithFormat:@"opendir errno=%d", errno];
    }
    int n = 0;
    while (readdir(dp) != NULL) n++;
    closedir(dp);
    return [NSString stringWithFormat:@"opendir ok entries=%d", n];
}

static void WQGrantAll(void) {
    NSString *group = WQGroupFromEntitlements();
    NSMutableArray<NSString *> *report = [NSMutableArray array];

    [report addObject:[NSString stringWithFormat:@"group=%@", group ?: @"(none)"]];
    os_log_fault(WQLog(), "app group = %{public}@", group ?: @"(none)");

    NSString *effective = group.length > 0 ? group : kFallbackGroup;

    for (size_t i = 0; i < sizeof(kTargets) / sizeof(kTargets[0]); i++) {
        NSString *path = kTargets[i];
        [report addObject:[NSString stringWithFormat:@"--- %@", path]];

        int64_t best = -255;
        const char *bestLabel = "-";

        for (size_t v = 0; v < sizeof(kVariants) / sizeof(kVariants[0]); v++) {
            int64_t h = WQAccessEx(path, effective, kVariants[v].flags, kVariants[v].part);
            [report addObject:[NSString stringWithFormat:@"  %-8s handle=%lld",
                               kVariants[v].label, h]];
            os_log_fault(WQLog(), "%{public}@ %s -> %lld", path, kVariants[v].label, h);
            if (h >= 0) {
                best = h;
                bestLabel = kVariants[v].label;
                break;
            }
            if (h != -1) best = h;      // remember the most informative failure
        }

        NSString *probe = WQProbe(path);
        [report addObject:[NSString stringWithFormat:@"  best=%s handle=%lld  %@",
                           bestLabel, best, probe]];
        os_log_fault(WQLog(), "%{public}@ best=%s handle=%lld %{public}@",
                     path, bestLabel, best, probe);
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
