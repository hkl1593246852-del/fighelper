#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#ifdef __cplusplus
extern "C" {
#endif

/// Ask containermanagerd for a sandbox extension covering `path`.
///
/// The app group's Library/Caches symlink is pointed at `path` first, then the
/// container query is issued with the given operation flags and part.
///
/// @return sandbox extension handle (>= 0) or one of:
///         -1 no app group, -2 dlsym failed, -3 query create failed,
///         -4 symlink failed, -5 query rejected, -6 no token
int64_t WQAccessEx(NSString *path, NSString *group, uint64_t flags, uint64_t part);

/// Convenience wrapper: flags 0x8000000000000000, part 3 (iOS 27 defaults),
/// retrying with 0x0000000800000000 (the iOS 26 flags) before giving up.
int64_t WQAccess(NSString *path, NSString *group, int mode);

void WQRelease(int64_t handle);

/// Brute-force inode -> path enumeration (replacement for readdir).
NSArray<NSString *> *WQList(NSString *dir, unsigned long long maxInode);

NS_ASSUME_NONNULL_END
