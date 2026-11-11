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
static NSString *const kDataRoot = @"/private/var/mobile/Containers/Data/Application";
static NSString *const kBundleRoot = @"/private/var/containers/Bundle/Application";

static NSString *const kTargets[7] = {
    @"/private/var/mobile/Containers/Data/Application",
    @"/private/var/mobile/Containers/Data/InternalDaemon",
    @"/private/var/mobile/Containers/Data/PluginKitPlugin",
    @"/private/var/mobile/Containers/Shared/AppGroup",
    @"/private/var/containers/Shared/SystemGroup",
    @"/private/var/containers/Data/System",
    @"/private/var/containers/Bundle/Application",
};

static NSString *gGroup;
static NSString *gBaseline;
static NSString *gGranted;
static NSInteger gDataCount;
static NSInteger gBundleCount;
static NSString *gReadableRoot;
static NSInteger gReadableCount;
static NSInteger gMetaRead;
static NSInteger gChildGrants;
static NSInteger gChildFiles;

static void WQGrantChildren(NSString *root, NSString *group, NSInteger limit);

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

    // part 3 is Library/Caches (the documented one); 1 = Data, 2 = Shared,
    // 4 = tmp. With the correct flag constants the extra parts are safe to try,
    // and some roots only answer to one of them.
    const uint64_t parts[4] = {3, 1, 2, 4};
    const uint64_t flags[2] = {0x0000008000000000ULL, 0x0000000800000000ULL};
    const char *flagNames[2] = {"27", "26"};

    NSMutableArray *summary = [NSMutableArray array];

    for (int i = 0; i < 7; i++) {
        int64_t best = -255;
        NSString *combo = @"-";

        for (int f = 0; f < 2 && best < 0; f++) {
            for (int p = 0; p < 4; p++) {
                int64_t h = WQAccessKeep(kTargets[i], gGroup, flags[f], parts[p]);
                if (h >= 0) {
                    best = h;
                    combo = [NSString stringWithFormat:@"p%llu/%s",
                             (unsigned long long)parts[p], flagNames[f]];
                    break;
                }
                if (h != -255) {
                    best = h;
                    combo = [NSString stringWithFormat:@"%lld", h];
                }
            }
        }

        int perr = 0;
        NSInteger n = best >= 0 ? WQCountEntries(kTargets[i], &perr) : -1;
        if (n > 0 && gReadableRoot == nil) {
            gReadableRoot = kTargets[i];
            gReadableCount = n;
        }
        [summary addObject:[NSString stringWithFormat:@"%@=%@/%ld",
                            combo,
                            best >= 0 ? [NSString stringWithFormat:@"%lld", best] : @"",
                            (long)n]];
    }

    gGranted = [summary componentsJoinedByString:@" "];

    if (gReadableRoot != nil) {
        WQGrantChildren(gReadableRoot, gGroup, 64);
    }

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
// Per-child grants
//
// A grant on the parent only covers that single level: files inside the child
// containers stay unreadable, which is why the folders looked empty. Each child
// gets its own extension so Filza's own browser can descend into it.
// ---------------------------------------------------------------------------

static void WQGrantChildren(NSString *root, NSString *group, NSInteger limit) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *children = [fm contentsOfDirectoryAtPath:root error:nil];
    NSInteger done = 0;

    for (NSString *name in children) {
        if (done >= limit) break;
        NSString *child = [root stringByAppendingPathComponent:name];

        int64_t h = WQAccessKeep(child, group, 0x0000008000000000ULL, 3);
        if (h < 0) {
            h = WQAccessKeep(child, group, 0x0000000800000000ULL, 3);
        }
        if (h < 0) continue;

        done++;
        gChildGrants++;

        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:
                              [child stringByAppendingPathComponent:
                               @".com.apple.mobile_container_manager.metadata.plist"]];
        if (meta != nil) gChildFiles++;
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

    // The per-app data root is refused on iOS 27, so when it cannot be opened the
    // reachable root is listed instead: Shared/AppGroup holds every app group
    // container, Data/System the system ones.
    if (gReadableRoot != nil && WQCountEntries(kDataRoot, NULL) <= 0) {
        NSMutableArray<WQApp *> *rows = [NSMutableArray array];
        for (NSString *name in [fm contentsOfDirectoryAtPath:gReadableRoot error:nil]) {
            NSString *path = [gReadableRoot stringByAppendingPathComponent:name];
            NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:
                                  [path stringByAppendingPathComponent:
                                   @".com.apple.mobile_container_manager.metadata.plist"]];
            NSString *ident = meta[@"MCMMetadataIdentifier"];
            if (ident.length > 0) gMetaRead++;

            WQApp *app = [WQApp new];
            app.bundleID = name;
            app.displayName = ident.length > 0 ? ident : name;
            app.containerPath = path;
            [rows addObject:app];
        }
        [rows sortUsingComparator:^NSComparisonResult(WQApp *a, WQApp *b) {
            return [a.displayName localizedCaseInsensitiveCompare:b.displayName];
        }];
        return rows;
    }

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

@interface WQPathController : UITableViewController
@property (nonatomic, copy) NSString *path;
@property (nonatomic, strong) NSArray<NSString *> *names;
- (instancetype)initWithPath:(NSString *)path;
@end

@implementation WQPathController

- (instancetype)initWithPath:(NSString *)path {
    self = [super initWithStyle:UITableViewStylePlain];
    if (self != nil) {
        _path = [path copy];
        _names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:path error:nil];
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = self.path.lastPathComponent.length > 0 ? self.path.lastPathComponent : @"/";
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"跳转" style:UIBarButtonItemStylePlain
                                        target:self action:@selector(prompt)];
}

- (void)prompt {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"跳转到路径"
                                                              message:self.path
                                                       preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = self.path;
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
        field.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"打开" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *x) {
        NSString *typed = a.textFields.firstObject.text;
        if (typed.length > 0) {
            [self.navigationController pushViewController:
                [[WQPathController alloc] initWithPath:typed] animated:YES];
        }
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (NSInteger)tableView:(UITableView *)t numberOfRowsInSection:(NSInteger)section {
    return (NSInteger)self.names.count;
}

- (UITableViewCell *)tableView:(UITableView *)t cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *cid = @"wqpath";
    UITableViewCell *cell = [t dequeueReusableCellWithIdentifier:cid];
    if (cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cid];
    }
    NSString *name = self.names[ip.row];
    NSString *full = [self.path stringByAppendingPathComponent:name];
    BOOL isDir = NO;
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:full error:nil];
    [attrs fileType] != NSFileTypeDirectory ? (isDir = NO) : (isDir = YES);

    cell.textLabel.text = name;
    cell.textLabel.font = [UIFont systemFontOfSize:14];
    cell.imageView.image = [UIImage systemImageNamed:isDir ? @"folder" : @"doc"];
    cell.detailTextLabel.text = [NSString stringWithFormat:@"%@  %@",
        isDir ? @"dir" : @"file",
        isDir ? @"" : [NSString stringWithFormat:@"%lld", [attrs fileSize]]];
    cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    return cell;
}

- (UISwipeActionsConfiguration *)tableView:(UITableView *)t
    trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)ip {
    NSString *name = self.names[ip.row];
    NSString *full = [self.path stringByAppendingPathComponent:name];

    UIContextualAction *del = [UIContextualAction
        contextualActionWithStyle:UIContextualActionStyleDestructive
                            title:@"删除"
                          handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
        NSError *err = nil;
        BOOL ok = [[NSFileManager defaultManager] removeItemAtPath:full error:&err];
        if (!ok) {
            UIAlertController *e =
                [UIAlertController alertControllerWithTitle:@"删除失败"
                                                    message:err.localizedDescription
                                             preferredStyle:UIAlertControllerStyleAlert];
            [e addAction:[UIAlertAction actionWithTitle:@"OK"
                                                  style:UIAlertActionStyleDefault
                                                handler:nil]];
            [self presentViewController:e animated:YES completion:nil];
        }
        self.names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:self.path error:nil];
        [t reloadData];
        done(ok);
    }];

    UIContextualAction *cpy = [UIContextualAction
        contextualActionWithStyle:UIContextualActionStyleNormal
                            title:@"复制路径"
                          handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
        [UIPasteboard generalPasteboard].string = full;
        done(YES);
    }];

    return [UISwipeActionsConfiguration configurationWithActions:@[del, cpy]];
}

- (UIContextMenuConfiguration *)tableView:(UITableView *)t
    contextMenuConfigurationForRowAtIndexPath:(NSIndexPath *)ip
                                        point:(CGPoint)point {
    NSString *full = [self.path stringByAppendingPathComponent:self.names[ip.row]];
    __weak typeof(self) weakSelf = self;
    return [UIContextMenuConfiguration
        configurationWithIdentifier:nil
                    previewProvider:nil
                     actionProvider:^UIMenu *(NSArray<UIMenuElement *> *suggested) {
        __strong typeof(weakSelf) self = weakSelf;
        if (self == nil) return nil;
        UIAction *ren = [UIAction actionWithTitle:@"重命名" image:nil identifier:nil
                                          handler:^(UIAction *a) { [self wqRename:ip]; }];
        UIAction *cp = [UIAction actionWithTitle:@"复制路径" image:nil identifier:nil
                                         handler:^(UIAction *a) {
            [UIPasteboard generalPasteboard].string = full;
        }];
        return [UIMenu menuWithTitle:@"" children:@[ren, cp]];
    }];
}

- (void)wqRename:(NSIndexPath *)ip {
    NSString *name = self.names[ip.row];
    NSString *full = [self.path stringByAppendingPathComponent:name];

    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"重命名"
                                                              message:full
                                                       preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *field) { field.text = name; }];
    [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *x) {
        NSString *to = a.textFields.firstObject.text;
        if (to.length == 0) return;
        NSString *dest = [self.path stringByAppendingPathComponent:to];
        [[NSFileManager defaultManager] moveItemAtPath:full toPath:dest error:nil];
        self.names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:self.path error:nil];
        [self.tableView reloadData];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)tableView:(UITableView *)t didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [t deselectRowAtIndexPath:ip animated:YES];
    NSString *name = self.names[ip.row];
    NSString *full = [self.path stringByAppendingPathComponent:name];
    BOOL isDir = NO;
    [[NSFileManager defaultManager] fileExistsAtPath:full isDirectory:&isDir];

    if (isDir) {
        [self.navigationController pushViewController:[[WQPathController alloc] initWithPath:full]
                                             animated:YES];
        return;
    }

    NSError *err = nil;
    NSData *data = [NSData dataWithContentsOfFile:full options:0 error:&err];
    NSString *text = data == nil
        ? [NSString stringWithFormat:@"read failed: %@", err.localizedDescription]
        : [NSString stringWithFormat:@"%lu bytes\n\n%@", (unsigned long)data.length,
           [[NSString alloc] initWithData:[data subdataWithRange:
               NSMakeRange(0, MIN((NSUInteger)600, data.length))] encoding:NSUTF8StringEncoding]
               ?: @"<binary>"];
    UIAlertController *a = [UIAlertController alertControllerWithTitle:name message:text
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"复制路径" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *x) {
        [UIPasteboard generalPasteboard].string = full;
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

@end

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
                      @"group %@\nroot %@ (%ld, meta %ld)\nchildren %ld/%ld\nbaseline %@\nbundles %ld  containers %ld\nhandles %@",
                      gGroup, gReadableRoot ?: @"-", (long)gReadableCount, (long)gMetaRead,
                      (long)gChildGrants, (long)gChildFiles,
                      gBaseline, (long)gBundleCount, (long)gDataCount, gGranted];
        label;
    });

    self.navigationItem.leftBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"关闭" style:UIBarButtonItemStylePlain
                                        target:self action:@selector(close)];
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"跳转" style:UIBarButtonItemStylePlain
                                        target:self action:@selector(gotoPath)];
}

- (void)close {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)gotoPath {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"打开路径"
                                                              message:@"支持 /var 与 /private/var"
                                                       preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = @"/private/var/mobile/Containers/Shared/AppGroup";
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
        field.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"打开" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *x) {
        NSString *typed = a.textFields.firstObject.text;
        if (typed.length == 0) return;
        [self.navigationController pushViewController:[[WQPathController alloc] initWithPath:typed]
                                             animated:YES];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
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


// ---------------------------------------------------------------------------
// Favorites
//
// Filza keeps its sidebar entries in NSUserDefaults inside its own container, so
// the two reachable roots can simply be appended there and show up in Filza's own
// UI, with no extra panel of ours.
// ---------------------------------------------------------------------------

static NSString *const kFavoritePaths[2] = {
    @"/private/var/mobile/Containers/Shared/AppGroup",
    @"/private/var/containers/Data/System",
};

static void WQInstallFavorites(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *all = [defaults dictionaryRepresentation];
    NSMutableString *report = [NSMutableString string];

    for (NSString *key in all) {
        NSString *lower = key.lowercaseString;
        BOOL looksLikeFavorites = ([lower containsString:@"bookmark"] ||
                                   [lower containsString:@"favorite"] ||
                                   [lower containsString:@"star"] ||
                                   [lower containsString:@"collect"]);
        if (!looksLikeFavorites) continue;

        id value = all[key];
        [report appendFormat:@"found %@ = %@\n", key, [value description]];

        if (![value isKindOfClass:[NSArray class]]) continue;

        NSMutableArray *updated = [NSMutableArray arrayWithArray:value];
        for (int i = 0; i < 2; i++) {
            NSString *wanted = kFavoritePaths[i];
            if (![updated containsObject:wanted]) {
                [updated addObject:wanted];
            }
        }
        [defaults setObject:updated forKey:key];
        [report appendFormat:@"wrote %@ (%lu entries)\n", key, (unsigned long)updated.count];
    }

    [defaults synchronize];

    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count > 0) {
        NSString *file = [[docs objectAtIndex:0] stringByAppendingPathComponent:@"filzawq.log"];
        NSString *head = [NSString stringWithFormat:@"group %@\nroot %@\nhandles %@\n",
                          gGroup ?: @"-", gReadableRoot ?: @"-", gGranted ?: @"-"];
        [[head stringByAppendingString:report]
            writeToFile:file atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

__attribute__((constructor))
static void FilzaWQInit(void) {
    WQInstallAlertFilter();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        WQGrantAll();
        WQInstallFavorites();
        [UIApplication sharedApplication].applicationIconBadgeNumber = 0;
    });
}
