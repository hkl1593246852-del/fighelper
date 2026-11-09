#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#ifdef __cplusplus
extern "C" {
#endif

/// Ask containermanagerd for a sandbox extension covering `path`, by pointing the
/// app group's Library/Caches symlink at it first.
/// @param mode 0 = iOS 27 flags, 1 = iOS 26.x flags.
/// @return sandbox extension handle, or a negative error:
///         -1 no app group, -2 dlsym failed, -3 query create failed,
///         -4 symlink failed, -5 query rejected, -6 no token
int64_t WQAccess(NSString *path, NSString *group, int mode);

void WQRelease(int64_t handle);

/// Brute-force inode -> path enumeration (replacement for readdir).
NSArray<NSString *> *WQList(NSString *dir, unsigned long long maxInode);

/// Directory listing that tries opendir first and falls back to WQList.
NSArray<NSString *> *WQEntries(NSString *dir, unsigned long long maxInode);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
