// Qc.m - read the CVE-2026-112688 constants off the loaded QuartzCore.
//
// First run on iPhone14,3 / 27.0.1 (24A446):
//   uuid = 76CE2A6E-DBA4-335D-A5AC-77A1C1B286A6
//   base = 0x196e93000, __TEXT vmaddr 0x1843e7000 (slide 0x12AAC000)
//   11 x (mov w9,#1 ; strb w9,[x8]) found, none reachable back to a pacibsp
//   within 0x800 -> the backward probe was the wrong anchor.
//
// v2 anchors on the instruction triple from upstream evidence instead:
//   0x18454ba3c  cbz   x8, +0xc     0xB4000068
//   0x18454ba40  mov   w9, #1       0x52800029
//   0x18454ba44  strb  w9, [x8]     0x39000109
// and on the caller's frame anchor:
//   0x18454e218  strb  wzr,[sp,#0xea]   0x3903ABFF
//   0x18454e3fc  add   x9, sp, #0xea    0x9103ABE9
// Function entry is then either a pacibsp or the tonemap prologue
//   sub sp, sp, #0x380                0xD10E03FF
int qcRun(void);
