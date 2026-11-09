// Minimal probe: load, wait, call WQAccessEx once, write a log line.
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <os/log.h>

#import "Wq.h"

static NSString *const kGroupFallback = @"group.com.you.filzalite";

static void WQGrantAll(void) {
    int64_t handle = WQAccessEx(@"/var/mobile/Containers/Data/Application",
                                kGroupFallback,
                                0x8000000000000000ULL,
                                3);
    NSString *line = [NSString stringWithFormat:@"handle %lld", handle];
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count > 0) {
        NSString *file = [[docs objectAtIndex:0] stringByAppendingPathComponent:@"filzawq.log"];
        [line writeToFile:file atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    os_log_fault(OS_LOG_DEFAULT, "filzawq handle %lld", handle);
}

__attribute__((constructor))
static void FilzaWQInit(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        WQGrantAll();
    });
}
