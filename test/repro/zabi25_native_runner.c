#include "zi_hostlib25.h"

#include <stdint.h>

// Provided by the lowered guest object.
extern int64_t zir_main(void);

int main(int argc, char **argv, char **envp) {
  if (!zi_hostlib25_init_all(argc, (const char *const *)argv,
                            (const char *const *)envp)) {
    return 111;
  }

  int64_t rc = zir_main();
  if (rc < 0) return 255;
  if (rc > 255) return 255;
  return (int)rc;
}
