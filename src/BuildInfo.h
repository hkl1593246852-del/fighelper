#ifndef BUILD_INFO_H
#define BUILD_INFO_H

// Overwritten by CI (.github/workflows/build.yml) with the commit being built,
// so a screenshot always identifies the installed binary.
#ifndef FIG_BUILD_ID
#define FIG_BUILD_ID "dev-local"
#endif

#endif
