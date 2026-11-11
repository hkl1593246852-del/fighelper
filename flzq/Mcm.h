#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#ifdef __cplusplus
extern "C" {
#endif

/// Container classes understood by containermanagerd.
/// 2 = app data, 7 = app group, 10 = system group (LaunchServices store).
typedef NS_ENUM(uint64_t, WQMcmClass) {
    WQMcmClassAppData = 2,
    WQMcmClassAppGroup = 7,
    WQMcmClassSystemGroup = 10,
};

/// Enumerate identifiers of a class. Returns an empty array when the daemon
/// refuses or the API is missing.
NSArray<NSString *> *WQMcmIdentifiers(uint64_t containerClass, NSUInteger limit);

/// Take a lease on one container and activate its sandbox extension.
/// @return the container's absolute path, or nil.
NSString *WQMcmActivate(uint64_t containerClass, NSString *identifier, BOOL group);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
