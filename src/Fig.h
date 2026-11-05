#import <Foundation/Foundation.h>

// Reads Documents/queue.txt (one line per item: tag<TAB>path[<TAB>service]),
// drives the CoreMedia bytestream XPC for each entry and writes the results
// into Documents/out/. Returns 0 when the handshake succeeded and the queue
// was processed.
int figRun(void);
