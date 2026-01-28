#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Minimal placeholder API for the zABI 2.5 runtime library.
// This will evolve as the real runtime is implemented.

const char *zingcore25_version(void);

// NOTE: caps registry lives in zi_caps.h.

#ifdef __cplusplus
}
#endif
