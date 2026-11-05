#import <Foundation/Foundation.h>

// QuartzCore constants for CVE-2026-112688.
//
// The upstream PoC gates on a hardcoded LC_UUID (27.1 / iPhone Duo:
// 21fa0104-f308-3bb3-8f3f-e9de66f7cdec) and on the write site
// `mov w9, #1 ; strb w9, [x8]` sitting 0x5b8 bytes into
// CA::HDRProcessorInternal::tonemap_surface_internal.
//
// Both are build specific, so this probe reads them off the QuartzCore that is
// actually loaded, in memory:
//   1. dlopen QuartzCore, dladdr a known symbol -> image base
//   2. parse mach_header_64 -> LC_UUID, __TEXT range
//   3. scan __TEXT for 29 00 80 52 (mov w9,#1) followed within 24 bytes by
//      09 01 00 39 (strb w9,[x8])
//   4. walk back to the nearest 3f 23 03 d5 (pacibsp) = function entry
//   5. report delta(s) so the payload constants can be recomputed
int qcRun(void);
