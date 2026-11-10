// FilzaWQ.xm - worse_query container access plus an app list for Filza.
//
// Loaded through the FilzaApplySandboxExt slot the base already links, so the
// main binary and its load commands stay untouched.
//
// Everything the build needs to prove about itself is shown in one screen:
// whether the dylib ran, which app group the signature carries, how many
// containers and bundles were readable, and whether the extensions landed.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dirent.h>
#import <dlfcn.h>
#import <errno.h>
#import <string.h>
#import <sys/stat.h>

#import "Wq.h"

typedef struct __SecTask *WQSecTask;
typedef WQSecTask (*WQCreateTask)(CFAllocatorRef);
typedef CFTypeRef (*WQCopyEnt)(WQSecTask, CFStringRef, CFErrorRef *);

static NSString *const kGroupFallback = @"group.com.filza.wq";
static NSString *const kDataRoot = @"/var/mobile/Containers/Data/Application";
static NSString *const kBundleRoot = @"/var/containers/Bundle/Application";

static NSString *const kTargets[7] = {
    @"/var/mobile/Containers/Data/Application",
    @"/var/mobile/Containers/Data/InternalDaemon",
    @"/var/mobile/Containers/Data/PluginKitPlugin",
    @"/var/mobile/Containers/Shared/AppGroup",
    @"/var/containers/Shared/SystemGroup",
    @"/var/containers/Data/System",
    @"/var/containers/Bundle/Application",
};

static NSString *gGroup;
static NSString *gBaseline;
static NSString *gGranted;
static NSInteger gDataCount;
static NSInteger gBundleCount;

// ---------------------------------------------------------------------------
// Entitlements and extensions
// ---------------------------------------------------------------------------

static NSString *WQOwnGroup(void) {
    WQCreateTask create = (WQCreateTask)dlsym(RTLD_DEFAULT, "SecTaskCreateFromSelf");
    WQCopyEnt copy = (WQCopyEnt)dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
    if (create == NULL || copy == NULL) return nil;

    WQSecTask task = create(kCFAllocatorDefault);
    if (task == NULL) return nil;

    CFTypeRef value = copy(task, CFSTR("com.apple.security.application-groups"), NULL);
    CFRelease(task);
    if (value == NULL) return nil;

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

static NSInteger WQCountEntries(NSString *path, int *err) {
    errno = 0;
    DIR *dp = opendir(path.fileSystemRepresentation);
    if (dp == NULL) {
        if (err != NULL) *err = errno;
        return -1;
    }
    NSInteger n = 0;
    while (readdir(dp) != NULL) n++;
    closedir(dp);
    if (err != NULL) *err = 0;
    return n;
}

static void WQGrantAll(void) {
    NSString *group = WQOwnGroup();
    gGroup = group.length > 0 ? group : @"(none)";

    NSMutableArray *ok = [NSMutableArray array];
    for (int i = 0; i < 7; i++) {
        int64_t best = -255;
        for (int v = 0; v < 2; v++) {
            int64_t h = WQAccess(kTargets[i], gGroup, v);
            if (h >= 0) { best = h; break; }
            if (h != -255) best = h;
        }
        [ok addObject:[NSString stringWithFormat:@"%lld", best]];
    }
    gGranted = [ok componentsJoinedByString:@","];

    int err = 0;
    gDataCount = WQCountEntries(kDataRoot, &err);
    gBaseline = [NSString stringWithFormat:@"%ld (errno %d)", (long)gDataCount, err];

    gBundleCount = WQCountEntries(kBundleRoot, NULL);
}

// ---------------------------------------------------------------------------
// Tamper-alert suppression
// ---------------------------------------------------------------------------

static BOOL WQIsTamperAlert(UIViewController *vc) {
    if (![vc isKindOfClass:[UIAlertController class]]) return NO;
    NSString *message = [(UIAlertController *)vc message];
    NSString *title = [(UIAlertController *)vc title];
    return ([message rangeOfString:@"Main binary was modified"].location != NSNotFound ||
            [title rangeOfString:@"Main binary was modified"].location != NSNotFound);
}

/// Filza may present from a controller that overrides presentViewController:, so
/// besides filtering that method a timer sweeps whatever ended up on screen.
static void WQSweepAlerts(UIViewController *root) {
    if (root == nil) return;
    UIViewController *presented = root.presentedViewController;
    while (presented != nil) {
        if (WQIsTamperAlert(presented)) {
            [presented dismissViewControllerAnimated:NO completion:nil];
            return;
        }
        presented = presented.presentedViewController;
    }
}

static void (*WQOrigPresent)(id, SEL, UIViewController *, BOOL, void (^)(void));

static void WQPresent(id self, SEL cmd, UIViewController *vc, BOOL animated, void (^completion)(void)) {
    if (WQIsTamperAlert(vc)) {
        if (completion != nil) completion();
        return;
    }
    if (WQOrigPresent != NULL) WQOrigPresent(self, cmd, vc, animated, completion);
}

static void WQInstallAlertFilter(void) {
    Method m = class_getInstanceMethod([UIViewController class],
                                       @selector(presentViewController:animated:completion:));
    if (m != NULL) {
        WQOrigPresent = (void (*)(id, SEL, UIViewController *, BOOL, void (^)(void)))
            method_getImplementation(m);
        method_setImplementation(m, (IMP)WQPresent);
    }
}

// ---------------------------------------------------------------------------
// App list
// ---------------------------------------------------------------------------

@interface WQApp : NSObject
@property (nonatomic, copy) NSString *bundleID;
@property (nonatomic, copy) NSString *displayName;
@property (nonatomic, copy) NSString *containerPath;
@property (nonatomic, strong) UIImage *icon;
@end

@implementation WQApp
@end

static UIImage *WQIconForBundle(NSString *bundlePath) {
    if (bundlePath.length == 0) return nil;
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                          [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
    NSMutableArray *names = [NSMutableArray array];
    id icons = info[@"CFBundleIcons"][@"CFBundlePrimaryIcon"][@"CFBundleIconFiles"];
    if ([icons isKindOfClass:[NSArray class]]) [names addObjectsFromArray:icons];
    id legacy = info[@"CFBundleIconFiles"];
    if ([legacy isKindOfClass:[NSArray class]]) [names addObjectsFromArray:legacy];
    [names addObject:@"AppIcon60x60"];
    [names addObject:@"AppIcon"];

    NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundlePath error:nil];
    for (NSString *base in [names reverseObjectEnumerator]) {
        for (NSString *file in contents) {
            if (![file hasPrefix:base] || ![file hasSuffix:@".png"]) continue;
            UIImage *img = [UIImage imageWithContentsOfFile:
                            [bundlePath stringByAppendingPathComponent:file]];
            if (img != nil) return img;
        }
    }
    return nil;
}

static NSArray<WQApp *> *WQCollectApps(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableDictionary<NSString *, NSDictionary *> *bundles = [NSMutableDictionary dictionary];

    for (NSString *uuid in [fm contentsOfDirectoryAtPath:kBundleRoot error:nil]) {
        NSString *dir = [kBundleRoot stringByAppendingPathComponent:uuid];
        for (NSString *item in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            if (![item hasSuffix:@".app"]) continue;
            NSString *appPath = [dir stringByAppendingPathComponent:item];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                                  [appPath stringByAppendingPathComponent:@"Info.plist"]];
            NSString *bid = info[@"CFBundleIdentifier"];
            if (bid.length == 0) continue;
            bundles[bid] = @{ @"path": appPath,
                              @"name": info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: bid };
        }
    }

    NSMutableArray<WQApp *> *apps = [NSMutableArray array];
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:kDataRoot error:nil]) {
        NSString *container = [kDataRoot stringByAppendingPathComponent:uuid];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:
                              [container stringByAppendingPathComponent:
                               @".com.apple.mobile_container_manager.metadata.plist"]];
        NSString *bid = meta[@"MCMMetadataIdentifier"];

        WQApp *app = [WQApp new];
        app.bundleID = bid.length > 0 ? bid : @"(unknown)";
        app.containerPath = container;
        NSDictionary *b = bid.length > 0 ? bundles[bid] : nil;
        app.displayName = b[@"name"] ?: (bid.length > 0 ? bid : uuid);
        app.icon = WQIconForBundle(b[@"path"]);
        [apps addObject:app];
    }

    [apps sortUsingComparator:^NSComparisonResult(WQApp *a, WQApp *b) {
        return [a.displayName localizedCaseInsensitiveCompare:b.displayName];
    }];
    return apps;
}

@interface WQAppsController : UITableViewController
@property (nonatomic, strong) NSArray<WQApp *> *apps;
@end

@implementation WQAppsController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"App 容器";
    self.apps = WQCollectApps();

    self.tableView.tableHeaderView = ({
        UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 320, 92)];
        label.numberOfLines = 0;
        label.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
        label.text = [NSString stringWithFormat:
                      @"group %@\nbaseline %@\nbundles %ld  containers %ld\nhandles %@",
                      gGroup, gBaseline, (long)gBundleCount, (long)gDataCount, gGranted];
        label;
    });

    self.navigationItem.leftBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"关闭" style:UIBarButtonItemStylePlain
                                        target:self action:@selector(close)];
}

- (void)close {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return (NSInteger)self.apps.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellID = @"wqapp";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellID];
    if (cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:cellID];
    }
    WQApp *app = self.apps[indexPath.row];
    cell.textLabel.text = app.displayName;
    cell.textLabel.font = [UIFont systemFontOfSize:15];
    cell.detailTextLabel.text = app.bundleID;
    cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    if (app.icon != nil) {
        cell.imageView.image = app.icon;
    } else {
        cell.imageView.image = [UIImage systemImageNamed:@"square.grid.2x2.fill"];
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    WQApp *app = self.apps[indexPath.row];

    UIAlertController *a = [UIAlertController alertControllerWithTitle:app.displayName
                                                              message:app.containerPath
                                                       preferredStyle:UIAlertControllerStyleActionSheet];
    [a addAction:[UIAlertAction actionWithTitle:@"复制路径" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *x) {
        [UIPasteboard generalPasteboard].string = app.containerPath;
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    a.popoverPresentationController.sourceView = tableView;
    a.popoverPresentationController.sourceRect = [tableView rectForRowAtIndexPath:indexPath];
    [self presentViewController:a animated:YES completion:nil];
}

@end

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

static UIWindow *WQKeyWindow(void) {
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window.isKeyWindow) return window;
        }
    }
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window.rootViewController != nil) return window;
        }
    }
    return nil;
}

/// Walk to the controller that is actually on top, so presenting never targets a
/// controller that is already covered.
static UIViewController *WQTopController(void) {
    UIViewController *vc = WQKeyWindow().rootViewController;
    if (vc == nil) return nil;
    while (vc.presentedViewController != nil) {
        vc = vc.presentedViewController;
    }
    return vc;
}

static NSInteger gPresentTries;
static BOOL gPresented;

static void WQTryPresentApps(void) {
    if (gPresented) return;
    if (WQKeyWindow() == nil) return;

    UIViewController *top = WQTopController();
    if (top == nil || top.view.window == nil) return;

    // Skip controllers that are themselves an alert we are about to sweep.
    if (WQIsTamperAlert(top)) {
        [top dismissViewControllerAnimated:NO completion:nil];
        return;
    }

    WQAppsController *vc = [[WQAppsController alloc] initWithStyle:UITableViewStylePlain];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    [top presentViewController:nav animated:YES completion:^{ gPresented = YES; }];
}

__attribute__((constructor))
static void FilzaWQInit(void) {
    WQInstallAlertFilter();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        WQGrantAll();
        [UIApplication sharedApplication].applicationIconBadgeNumber = 1;

        // Retry for a minute: Filza shows its own launch UI first, and a single
        // attempt after a fixed delay silently gives up when that is on screen.
        [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *timer) {
            WQSweepAlerts(WQKeyWindow().rootViewController);

            gPresentTries++;
            if (gPresentTries > 120) {
                [timer invalidate];
                return;
            }
            WQTryPresentApps();

            if (gPresented) {
                [timer invalidate];
            }
        }];

        [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidBecomeActiveNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note) {
            WQGrantAll();
        }];
    });
}
