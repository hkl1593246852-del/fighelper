#import <Foundation/Foundation.h>

// sandbox_extension TOCTOU reader.
// queue file: Documents/sbx.txt, one line per item: tag<TAB>absolute-path
// results:    Documents/out/<tag>.bin | .dir | .meta
int sbxRun(void);
