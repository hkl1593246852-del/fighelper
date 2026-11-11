// Mcm.m - MobileContainerManager bridge.
//
// Ported from the FilzaSlop-style integration: instead of the worse_query symlink
// trick, enumerate containers through container_query_iterate_results_sync and ask
// containermanagerd to activate a sandbox extension for each object. That path is
// not limited to shared containers, so app data containers become reachable.

#import "Mcm.h"

#import <dlfcn.h>
#import <xpc/xpc.h>

typedef void *(*McmQueryCreate)(void);
typedef void (*McmQuerySetU64)(void *, uint64_t);
typedef void (*McmQuerySetXPC)(void *, xpc_object_t);
typedef void *(*McmQueryGetSingle)(void *);
typedef void *(*McmQueryGetError)(void *);
typedef bool (*McmQueryIterate)(void *, bool (^)(void *));
typedef void (*McmQueryFree)(void *);
typedef const char *(*McmObjectPath)(void *);
typedef const char *(*McmObjectIdentifier)(void *);
typedef void *(*McmObjectCopy)(void *);
typedef bool (*McmObjectActivate)(void *, bool);
typedef void (*McmObjectFree)(void *);
typedef char *(*McmObjectToken)(void *);

static struct {
    void *handle;
    McmQueryCreate create;
    McmQuerySetU64 setClass;
    McmQuerySetXPC setIdentifiers;
    McmQuerySetXPC setGroupIdentifiers;
    McmQuerySetU64 setFlags;
    McmQueryGetSingle getSingle;
    McmQueryGetError getError;
    McmQueryIterate iterate;
    McmQueryFree queryFree;
    McmObjectPath objectPath;
    McmObjectIdentifier objectIdentifier;
    McmObjectCopy objectCopy;
    McmObjectActivate objectActivate;
    McmObjectFree objectFree;
    McmObjectToken objectToken;
} gMcm;

static void WQMcmLoad(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gMcm.handle = dlopen("/usr/lib/system/libsystem_containermanager.dylib",
                             RTLD_NOW | RTLD_LOCAL);
        void *h = gMcm.handle != NULL ? gMcm.handle : RTLD_DEFAULT;
#define LOAD(field, sym) gMcm.field = (__typeof__(gMcm.field))dlsym(h, sym)
        LOAD(create, "container_query_create");
        LOAD(setClass, "container_query_set_class");
        LOAD(setIdentifiers, "container_query_set_identifiers");
        LOAD(setGroupIdentifiers, "container_query_set_group_identifiers");
        LOAD(setFlags, "container_query_operation_set_flags");
        LOAD(getSingle, "container_query_get_single_result");
        LOAD(getError, "container_query_get_last_error");
        LOAD(iterate, "container_query_iterate_results_sync");
        LOAD(queryFree, "container_query_free");
        LOAD(objectPath, "container_object_get_path");
        LOAD(objectIdentifier, "container_object_get_identifier");
        LOAD(objectCopy, "container_object_copy");
        LOAD(objectActivate, "container_object_sandbox_extension_activate");
        LOAD(objectFree, "container_object_free");
        LOAD(objectToken, "container_copy_sandbox_token");
#undef LOAD
    });
}

NSArray<NSString *> *WQMcmIdentifiers(uint64_t containerClass, NSUInteger limit) {
    WQMcmLoad();
    if (gMcm.create == NULL || gMcm.iterate == NULL || gMcm.objectIdentifier == NULL || limit == 0) {
        return @[];
    }

    void *query = gMcm.create();
    if (query == NULL) return @[];

    gMcm.setClass(query, containerClass);
    if (gMcm.setFlags != NULL) {
        gMcm.setFlags(query, 0x100000000ULL);   // metadata only, no creation
    }

    NSMutableOrderedSet<NSString *> *out = [NSMutableOrderedSet orderedSet];
    gMcm.iterate(query, ^bool(void *object) {
        const char *raw = object != NULL ? gMcm.objectIdentifier(object) : NULL;
        NSString *ident = raw != NULL ? [NSString stringWithUTF8String:raw] : nil;
        if (ident.length > 0) [out addObject:ident];
        return out.count < limit;
    });
    gMcm.queryFree(query);
    return out.array;
}

NSString *WQMcmActivate(uint64_t containerClass, NSString *identifier, BOOL group) {
    WQMcmLoad();
    if (identifier.length == 0) return nil;
    if (gMcm.create == NULL || gMcm.getSingle == NULL || gMcm.objectPath == NULL) return nil;

    void *query = gMcm.create();
    if (query == NULL) return nil;

    gMcm.setClass(query, containerClass);
    xpc_object_t ident = xpc_string_create(identifier.UTF8String);
    if (group) {
        gMcm.setGroupIdentifiers(query, ident);
    } else {
        gMcm.setIdentifiers(query, ident);
    }
    // 0x900000000 is what the container manager expects when a lease will be
    // activated afterwards; 0x100000000 is metadata-only and yields no token.
    if (gMcm.setFlags != NULL) {
        gMcm.setFlags(query, 0x900000000ULL);
    }

    void *object = gMcm.getSingle(query);
    if (object == NULL) {
        gMcm.queryFree(query);
        return nil;
    }

    const char *rawPath = gMcm.objectPath(object);
    NSString *path = rawPath != NULL ? [NSString stringWithUTF8String:rawPath] : nil;
    if ([path hasPrefix:@"/var/"]) {
        path = [@"/private" stringByAppendingString:path];
    }

    // Ask for a real extension on this object; the lease has to stay alive with the
    // query, so both are kept until the process exits.
    void *copy = gMcm.objectCopy != NULL ? gMcm.objectCopy(object) : NULL;
    if (copy != NULL && gMcm.objectActivate != NULL) {
        gMcm.objectActivate(copy, false);
    }

    return path.length > 0 ? path : nil;
}

NSArray<NSString *> *WQMcmLaunchServicesBundleIDs(void) {
    NSString *lsd = WQMcmActivate(WQMcmClassSystemGroup, @"com.apple.lsd", NO);
    if (lsd.length == 0) return @[];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray<NSString *> *stores = [NSMutableArray array];
    for (NSString *sub in @[@"Library/Caches", @"Library", @""]) {
        NSString *dir = sub.length > 0 ? [lsd stringByAppendingPathComponent:sub] : lsd;
        for (NSString *name in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            if ([name hasPrefix:@"com.apple.LaunchServices-"]) {
                [stores addObject:[dir stringByAppendingPathComponent:name]];
            }
        }
    }

    NSMutableOrderedSet<NSString *> *ids = [NSMutableOrderedSet orderedSet];
    for (NSString *file in stores) {
        NSData *data = [NSData dataWithContentsOfFile:file];
        if (data.length == 0) continue;

        const uint8_t *bytes = data.bytes;
        NSUInteger len = data.length;
        NSUInteger i = 0;
        while (i + 4 < len) {
            if (bytes[i] != 'c' || bytes[i + 1] != 'o' || bytes[i + 2] != 'm' || bytes[i + 3] != '.') {
                i++;
                continue;
            }
            NSUInteger start = i;
            NSUInteger j = i;
            while (j < len && j - start < 96) {
                uint8_t c = bytes[j];
                BOOL valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                             (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
                if (!valid) break;
                j++;
            }
            if (j - start >= 8) {
                NSString *candidate = [[NSString alloc] initWithBytes:bytes + start
                                                               length:j - start
                                                             encoding:NSUTF8StringEncoding];
                if (candidate.length > 0) [ids addObject:candidate];
            }
            i = j > i ? j : i + 1;
            if (ids.count > 900) return ids.array;
        }
    }
    return ids.array;
}
