#import "AppDelegate.h"
#import "Fig.h"
#import "Sbx.h"

@interface AppDelegate ()
@property (nonatomic, strong) UILabel *status;
@end

@implementation AppDelegate

static NSString *tailOf(NSString *path, NSUInteger lines) {
    NSString *s = [NSString stringWithContentsOfFile:path
                                            encoding:NSUTF8StringEncoding error:nil];
    if (s.length == 0) return @"(empty)";
    NSArray *all = [s componentsSeparatedByString:@"\n"];
    NSUInteger n = MIN(lines, all.count);
    NSRange r = NSMakeRange(all.count - n, n);
    return [[all subarrayWithRange:r] componentsJoinedByString:@"\n"];
}

- (void)show:(NSString *)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.status.text = text;
    });
}

- (BOOL)application:(UIApplication *)application
        didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor systemBackgroundColor];

    UILabel *label = [[UILabel alloc] initWithFrame:CGRectZero];
    label.text = @"fighelper\nrunning sbxRun() ...";
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentLeft;
    label.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [vc.view addSubview:label];
    [NSLayoutConstraint activateConstraints:@[
        [label.leadingAnchor constraintEqualToAnchor:vc.view.leadingAnchor constant:12],
        [label.trailingAnchor constraintEqualToAnchor:vc.view.trailingAnchor constant:-12],
        [label.topAnchor constraintEqualToAnchor:vc.view.safeAreaLayoutGuide.topAnchor constant:12],
    ]];
    self.status = label;

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];

        int rc2 = sbxRun();
        [self show:[NSString stringWithFormat:@"sbxRun rc=%d\n%@", rc2,
                    tailOf([docs stringByAppendingPathComponent:@"sbx.log"], 12)]];

        int rc1 = figRun();
        [self show:[NSString stringWithFormat:@"sbx=%d fig=%d\n--- sbx.log ---\n%@\n--- fig.log ---\n%@",
                    rc2, rc1,
                    tailOf([docs stringByAppendingPathComponent:@"sbx.log"], 8),
                    tailOf([docs stringByAppendingPathComponent:@"fig.log"], 8)]];

        NSLog(@"[fig] sbxRun rc=%d figRun rc=%d", rc2, rc1);
    });
    return YES;
}

@end
