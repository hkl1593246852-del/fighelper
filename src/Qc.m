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

#define W_CBZ_X8_0C   0xB4000068u   // cbz   x8, +0xc
#define W_MOV_W9_1    0x52800029u   // mov   w9, #1
#define W_STRB_W9_X8  0x39000109u   // strb  w9, [x8]
#define W_STRB_WZR_SP 0x3903ABFFu   // strb  wzr, [sp, #0xea]
#define W_ADD_X9_SP   0x9103ABE9u   // add   x9, sp, #0xea
#define W_PACIBSP     0xD503233Fu
#define W_SUBSP380    0xD10E03FFu   // sub   sp, sp, #0x380

static uint32_t wordAt(const uint8_t *t, NSUInteger off) {
    uint32_t w = 0;
    memcpy(&w, t + off, 4);
    return w;
}

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

    void *handle = dlopen("/System/Library/Frameworks/QuartzCore.framework/QuartzCore", RTLD_NOW);
    if (handle == NULL) {
        qcNote(@"dlopen failed: %s", dlerror());
        goto writeout;
    }

    void *sym = dlsym(handle, "CACurrentMediaTime");
    Dl_info info;
    if (sym == NULL || dladdr(sym, &info) == 0 || info.dli_fbase == NULL) {
        qcNote(@"dladdr failed");
        goto writeout;
    }

    const struct mach_header_64 *h = (const struct mach_header_64 *)info.dli_fbase;
    if (h->magic != MH_MAGIC_64) { qcNote(@"bad magic"); goto writeout; }
    qcNote(@"base=%p uuid=%@", info.dli_fbase, uuidString(h));

    const uint8_t *text = (const uint8_t *)info.dli_fbase;
    uint64_t textVM = 0, textSize = 0;
    const uint8_t *p = (const uint8_t *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                textVM = seg->vmaddr;
                textSize = seg->vmsize;
                break;
            }
        }
        p += lc->cmdsize;
    }
    if (textSize == 0) { qcNote(@"__TEXT missing"); goto writeout; }
    qcNote(@"__TEXT vmaddr=%#llx size=%#llx slide=%#llx",
           textVM, textSize, (uint64_t)((uintptr_t)info.dli_fbase - textVM));

    // 1. tonemap write site, anchored on the triple
    NSUInteger sites[8];
    NSUInteger nSites = 0;
    for (NSUInteger off = 8; off + 4 < (NSUInteger)textSize && nSites < 8; off += 4) {
        if (wordAt(text, off)     != W_STRB_W9_X8)  continue;
        if (wordAt(text, off - 4) != W_MOV_W9_1)    continue;
        if (wordAt(text, off - 8) != W_CBZ_X8_0C)   continue;
        sites[nSites++] = off;
        qcNote(@"TRIPLE site=%#llx", textVM + off);
    }
    qcNote(@"triples=%lu", (unsigned long)nSites);

    // 2. for the first triple, find the function entry and the caller anchor
    if (nSites == 0) goto writeout;
    NSUInteger site = sites[0];

    uint64_t funcVM = 0;
    for (NSUInteger back = 4; back <= 0x4000 && back <= site; back += 4) {
        uint32_t w = wordAt(text, site - back);
        if (w == W_PACIBSP || w == W_SUBSP380) {
            funcVM = textVM + (site - back);
            qcNote(@"FUNC entry=%#llx via %s", funcVM,
                   w == W_PACIBSP ? "pacibsp" : "sub sp,#0x380");
            break;
        }
    }
    if (funcVM) {
        qcNote(@"DELTA site-func=%#llx", (textVM + site) - funcVM);
    }

    // 3. caller frame anchors near the site
    NSUInteger lo = (site > 0x4000) ? site - 0x4000 : 0;
    NSUInteger hi = site + 0x4000;
    if (hi > (NSUInteger)textSize - 4) hi = (NSUInteger)textSize - 4;
    for (NSUInteger off = lo; off < hi; off += 4) {
        uint32_t w = wordAt(text, off);
        if (w == W_STRB_WZR_SP) qcNote(@"ANCHOR strb wzr,[sp,#0xea] at %#llx", textVM + off);
        if (w == W_ADD_X9_SP)   qcNote(@"ANCHOR add x9,sp,#0xea     at %#llx", textVM + off);
    }

writeout:
    qcNote(@"=== qc end ===");
    NSString *out = [[gQcLines componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    [[out dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gQcDocs stringByAppendingPathComponent:@"qc.log"] atomically:YES];
    return 0;
}
