#import <Foundation/Foundation.h>

// SecItem probe: count items per keychain class, first with the app's own
// access group, then with "com.apple.token" (the group the MConfPoC screenshot
// carries). Direct open of keychain-2.db is denied by the sandbox, so securityd
// is the only way in; the question is whether the token group is honoured.
int kcRun(void);
