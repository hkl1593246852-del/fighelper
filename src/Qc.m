// Qc.m - read the CVE-2026-112688 constants off the loaded QuartzCore.

#import "Qc.h"

#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <QuartzCore/QuartzCore.h>
#import <string.h>

static NSString *gQcDocs;
static NSMutableArray *gQcLines;

static void qcNote(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [gQcLines addObject:s];
    NSLog(@"[qc] %@", s);
}

static BOOL isPacibsp(uint32_t w) { return w == 0xD503233F; }

// mov w9, #1  = 0x52800029 ; strb w9, [x8] = 0x39000109
static NSString *uuidString(const struct mach_header_64 *h) {
    const uint8_t *p = (const uint8_t *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_UUID) {
            const struct uuid_command *u = (const struct uuid_command *)lc;
            return [NSString stringWithFormat:
                    @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    u->uuid[0], u->uuid[1], u->uuid[2],  u->uuid[3],
                    u->uuid[4], u->uuid[5], u->uuid[6],  u->uuid[7],
                    u->uuid[8], u->uuid[9], u->uuid[10], u->uuid[11],
                    u->uuid[12], u->uuid[13], u->uuid[14], u->uuid[15]];
        }
        p += lc->cmdsize;
    }
    return @"?";
}

int qcRun(void) {
    gQcDocs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    gQcLines = [NSMutableArray array];
    qcNote(@"=== qc start ===");

    void *handle = dlopen("/System/Library/Frameworks/QuartzCore.framework/QuartzCore",
                          RTLD_NOW | RTLD_NOLOAD);
    if (handle == NULL) {
        handle = dlopen("/System/Library/Frameworks/QuartzCore.framework/QuartzCore", RTLD_NOW);
    }
    if (handle == NULL) {
        qcNote(@"dlopen QuartzCore failed: %s", dlerror());
        goto writeout;
    }

    void *sym = dlsym(handle, "CACurrentMediaTime");
    Dl_info info;
    if (sym == NULL || dladdr(sym, &info) == 0 || info.dli_fbase == NULL) {
        qcNote(@"dladdr failed");
        goto writeout;
    }

    const struct mach_header_64 *h = (const struct mach_header_64 *)info.dli_fbase;
    if (h->magic != MH_MAGIC_64) {
        qcNote(@"not MH_MAGIC_64 at base");
        goto writeout;
    }

    qcNote(@"base=%p uuid=%@", info.dli_fbase, uuidString(h));

    // __TEXT range
    const uint8_t *text = NULL;
    uint64_t textVM = 0, textSize = 0;
    const uint8_t *p = (const uint8_t *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                // dladdr's dli_fbase is the __TEXT load address, so the section
                // bytes start there and vmaddr maps as seg->vmaddr + offset.
                text = (const uint8_t *)info.dli_fbase;
                textVM = seg->vmaddr;
                textSize = seg->vmsize;
                break;
            }
        }
        p += lc->cmdsize;
    }
    if (text == NULL) { qcNote(@"__TEXT not found"); goto writeout; }
    qcNote(@"__TEXT vmaddr=%#llx size=%#llx", textVM, textSize);

    // Scan for mov w9,#1 ... strb w9,[x8]
    NSUInteger hits = 0;
    const NSUInteger limit = (NSUInteger)textSize - 32;
    for (NSUInteger off = 0; off < limit; off += 4) {
        uint32_t w0;
        memcpy(&w0, text + off, 4);
        if (w0 != 0x52800029) continue;

        for (NSUInteger k = 4; k <= 24; k += 4) {
            uint32_t w1;
            memcpy(&w1, text + off + k, 4);
            if (w1 != 0x39000109) continue;

            // walk back to the nearest pacibsp within 0x800
            uint64_t funcStart = 0;
            NSUInteger back = 0x800;
            if (off < back) back = off;
            for (NSUInteger b = 4; b <= back; b += 4) {
                uint32_t wb;
                memcpy(&wb, text + off - b, 4);
                if (isPacibsp(wb)) { funcStart = (uint64_t)(off - b); break; }
            }
            uint64_t siteVM = textVM + off;
            if (funcStart) {
                uint64_t funcVM = textVM + funcStart;
                qcNote(@"HIT site=%#llx func=%#llx delta=%#llx (strb +%lu)",
                       siteVM, funcVM, siteVM - funcVM, (unsigned long)k);
            } else {
                qcNote(@"HIT site=%#llx (no pacibsp within 0x800)", siteVM);
            }
            hits++;
            break;
        }
        if (hits >= 12) break;
    }
    qcNote(@"hits=%lu", (unsigned long)hits);

writeout:
    qcNote(@"=== qc end ===");
    NSString *text2 = [[gQcLines componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    [[text2 dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gQcDocs stringByAppendingPathComponent:@"qc.log"] atomically:YES];
    return 0;
}
