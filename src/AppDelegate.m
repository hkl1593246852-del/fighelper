#import "AppDelegate.h"
#import "Fig.h"
#import "Sbx.h"
#import "Kc.h"
#import "Qc.h"
#import "BuildInfo.h"

@interface AppDelegate ()
@property (nonatomic, strong) UILabel *status;
@end

@implementation AppDelegate

static NSString *headOf(NSString *path, NSUInteger lines) {
    NSString *s = [NSString stringWithContentsOfFile:path
                                            encoding:NSUTF8StringEncoding error:nil];
    if (s.length == 0) return @"(empty)";
    NSArray *all = [s componentsSeparatedByString:@"\n"];
    NSMutableArray *keep = [NSMutableArray array];
    for (NSString *l in all) {
        if (l.length == 0) continue;
        [keep addObject:l];
        if (keep.count >= lines) break;
    }
    return [keep componentsJoinedByString:@"\n"];
}

- (void)show:(NSString *)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.status.text = [NSString stringWithFormat:@"build %@\n%@", FIG_BUILD_ID, text];
    });
}

- (BOOL)application:(UIApplication *)application
        didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor systemBackgroundColor];

    UILabel *label = [[UILabel alloc] initWithFrame:CGRectZero];
    label.text = [NSString stringWithFormat:@"build %@\nrunning ...", FIG_BUILD_ID];
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentLeft;
    label.font = [UIFont monospacedSystemFontOfSize:8 weight:UIFontWeightRegular];
    label.adjustsFontSizeToFitWidth = YES;
    label.minimumScaleFactor = 0.6;
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [vc.view addSubview:label];
    [NSLayoutConstraint activateConstraints:@[
        [label.leadingAnchor constraintEqualToAnchor:vc.view.leadingAnchor constant:6],
        [label.trailingAnchor constraintEqualToAnchor:vc.view.trailingAnchor constant:-6],
        [label.topAnchor constraintEqualToAnchor:vc.view.safeAreaLayoutGuide.topAnchor constant:6],
        [label.bottomAnchor constraintLessThanOrEqualToAnchor:vc.view.safeAreaLayoutGuide.bottomAnchor],
    ]];
    self.status = label;

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];

        int rc2 = sbxRun();
        int rc3 = kcRun();
        int rc4 = qcRun();
        int rc1 = figRun();
        [self show:[NSString stringWithFormat:@"fig=%d sbx=%d kc=%d qc=%d\n%@",
                    rc1, rc2, rc3, rc4,
                    headOf([docs stringByAppendingPathComponent:@"qc.log"], 14)]];

        NSLog(@"[fig] %@ fig=%d sbx=%d kc=%d qc=%d", FIG_BUILD_ID, rc1, rc2, rc3, rc4);
    });
    return YES;
}

@end
