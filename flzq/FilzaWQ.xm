// FilzaWQ.xm - grant Filza container access through worse_query.
//
// Loaded in place of Frameworks/lib7z.framework/lib7z, which the main binary
// already links; nothing in Filza's main executable changes, so its
// Filza.signature check still passes.
//
// The container query takes an operation flag and a part; which pair works is
// undocumented and changes between releases, so the pairs are tried in order and
// the first success is kept. Every attempt lands in Documents/filzawq.log.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dirent.h>
#import <dlfcn.h>
#import <errno.h>

#import "Wq.h"

typedef struct __SecTask *WQSecTask;
typedef WQSecTask (*WQCreateTask)(CFAllocatorRef);
typedef CFTypeRef (*WQCopyEnt)(WQSecTask, CFStringRef, CFErrorRef *);

static NSString *const kGroupFallback = @"group.com.you.filzalite";

static NSString *const kTargets[6] = {
    @"/var/mobile/Containers/Data/Application",
    @"/var/mobile/Containers/Data/InternalDaemon",
    @"/var/mobile/Containers/Data/PluginKitPlugin",
    @"/var/mobile/Containers/Shared/AppGroup",
    @"/var/containers/Shared/SystemGroup",
    @"/var/containers/Data/System",
};

// part 1 = Data, 2 = Shared, 3 = Library/Caches, 4 = tmp
static const uint64_t kFlags[3] = { 0x8000000000000000ULL, 0x0000000800000000ULL, 0ULL };
static const char *const kFlagNames[3] = { "f27", "f26", "f0" };
static const uint64_t kParts[4] = { 3, 1, 2, 4 };

static NSMutableArray *gReport;

static void WQNote(NSString *line) {
    if (gReport == nil) {
        gReport = [NSMutableArray array];
    }
    [gReport addObject:line];
}

static NSString *WQOwnGroup(void) {
    WQCreateTask create = (WQCreateTask)dlsym(RTLD_DEFAULT, "SecTaskCreateFromSelf");
    WQCopyEnt copy = (WQCopyEnt)dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
    if (create == NULL || copy == NULL) {
        return nil;
    }

    WQSecTask task = create(kCFAllocatorDefault);
    if (task == NULL) {
        return nil;
    }

    CFTypeRef value = copy(task, CFSTR("com.apple.security.application-groups"), NULL);
    CFRelease(task);
    if (value == NULL) {
        return nil;
    }

    NSString *group = nil;
    if (CFGetTypeID(value) == CFArrayGetTypeID()) {
        CFArrayRef array = (CFArrayRef)value;
        if (CFArrayGetCount(array) > 0) {
            CFTypeRef first = CFArrayGetValueAtIndex(array, 0);
            if (CFGetTypeID(first) == CFStringGetTypeID()) {
                group = [NSString stringWithString:(__bridge NSString *)first];
            }
        }
    }
    CFRelease(value);
    return group;
}

static NSString *WQProbe(NSString *path) {
    errno = 0;
    DIR *dp = opendir([path fileSystemRepresentation]);
    if (dp == NULL) {
        return [NSString stringWithFormat:@"opendir errno %d", errno];
    }
    int count = 0;
    while (readdir(dp) != NULL) {
        count++;
    }
    closedir(dp);
    return [NSString stringWithFormat:@"opendir ok entries %d", count];
}

static void WQOneTarget(NSString *path, NSString *group) {
    WQNote([@"--- " stringByAppendingString:path]);

    int64_t best = -255;
    NSString *bestLabel = @"none";

    for (int f = 0; f < 3 && best < 0; f++) {
        for (int p = 0; p < 4; p++) {
            int64_t handle = WQAccessEx(path, group, kFlags[f], kParts[p]);
            NSString *label = [NSString stringWithFormat:@"%s part %llu",
                               kFlagNames[f], (unsigned long long)kParts[p]];
            WQNote([NSString stringWithFormat:@"  %@ handle %lld", label, handle]);
            if (handle >= 0) {
                best = handle;
                bestLabel = label;
                break;
            }
            if (handle != -1 && best == -255) {
                best = handle;
                bestLabel = label;
            }
        }
    }

    WQNote([NSString stringWithFormat:@"  best %@ handle %lld, %@",
           bestLabel, best, WQProbe(path)]);
}

static void WQGrantAll(void) {
    NSString *group = WQOwnGroup();
    if (group.length == 0) {
        WQNote(@"group none: no application-groups entitlement");
        group = kGroupFallback;
    } else {
        WQNote([@"group " stringByAppendingString:group]);
    }

    for (int i = 0; i < 6; i++) {
        WQOneTarget(kTargets[i], group);
    }

    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count > 0) {
        NSString *file = [[docs objectAtIndex:0] stringByAppendingPathComponent:@"filzawq.log"];
        NSString *text = [[gReport componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
        [text writeToFile:file atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

__attribute__((constructor))
static void FilzaWQInit(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        WQGrantAll();
    });

    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidBecomeActiveNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *note) {
                    WQGrantAll();
                }];
}
