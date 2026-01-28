#include "zi_runtime25.h"

#include <stddef.h>

static const zi_host_v1 *g_host;
static const zi_mem_v1 *g_mem;

void zi_runtime25_set_host(const zi_host_v1 *host) { g_host = host; }
void zi_runtime25_set_mem(const zi_mem_v1 *mem) { g_mem = mem; }

const zi_host_v1 *zi_runtime25_host(void) { return g_host; }
const zi_mem_v1 *zi_runtime25_mem(void) { return g_mem; }

static int native_map_ro(void *ctx, zi_ptr_t ptr, zi_size32_t len, const uint8_t **out) {
  (void)ctx;
  if (!out) return 0;
  if (len == 0) {
    *out = (const uint8_t *)(uintptr_t)ptr;
    return 1;
  }
  if (ptr == 0) return 0;
  *out = (const uint8_t *)(uintptr_t)ptr;
  return 1;
}

static int native_map_rw(void *ctx, zi_ptr_t ptr, zi_size32_t len, uint8_t **out) {
  (void)ctx;
  if (!out) return 0;
  if (len == 0) {
    *out = (uint8_t *)(uintptr_t)ptr;
    return 1;
  }
  if (ptr == 0) return 0;
  *out = (uint8_t *)(uintptr_t)ptr;
  return 1;
}

void zi_mem_v1_native_init(zi_mem_v1 *out) {
  if (!out) return;
  out->ctx = NULL;
  out->map_ro = native_map_ro;
  out->map_rw = native_map_rw;
}
