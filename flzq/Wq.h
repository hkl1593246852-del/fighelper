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

/// Default flags 0x8000000000000000 with part 3 (Library/Caches), or the iOS 26
/// flag set when `mode` is non-zero.
int64_t WQAccess(NSString *path, NSString *group, int mode);

void WQRelease(int64_t handle);

/// Brute-force inode -> path enumeration (replacement for readdir).
NSArray<NSString *> *WQList(NSString *dir, unsigned long long maxInode);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
