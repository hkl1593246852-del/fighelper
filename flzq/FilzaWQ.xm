// FilzaWQ.xm - grant Filza container access through worse_query.
//
// Injected into Filza's binary. On load it asks containermanagerd for sandbox
// extensions covering the container roots, by pointing an app group's
// Library/Caches symlink at each one in turn.
//
// Requirement: the IPA must be signed with a provisioning profile that carries
// com.apple.security.application-groups. Without it WQAccess returns -1.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <os/log.h>

#import "Wq.h"

static NSString *const kGroup = @"group.com.you.filzalite";

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

static void WQGrantAll(void) {
    NSMutableArray<NSString *> *report = [NSMutableArray array];

    for (size_t i = 0; i < sizeof(kTargets) / sizeof(kTargets[0]); i++) {
        NSString *p = kTargets[i];
        int64_t h = WQAccess(p, kGroup, 0);
        int used = 0;
        if (h < 0 && h != -255) {
            h = WQAccess(p, kGroup, 1);      // iOS 26.x flag set
            used = 1;
        }
        [report addObject:[NSString stringWithFormat:@"%@ mode=%d handle=%lld", p, used, h]];
        os_log_fault(WQLog(), "%{public}@ mode=%d handle=%lld", p, used, h);
    }

    // Leave a breadcrumb the user can read from Filza itself.
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"filzawq.log"];
    [[[report componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"]
        writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

%ctor {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        WQGrantAll();
    });

    // Filza re-checks roots when it returns to the foreground; redo the grants.
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *note) {
        WQGrantAll();
    }];
}
