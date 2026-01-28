#include "zi_sysabi25.h"

#include "zi_runtime25.h"
#include "zi_caps.h"

#include <string.h>

static int32_t err_noent(void) { return ZI_E_NOENT; }

int32_t zi_cap_count(void) {
  const zi_cap_registry_v1 *reg = zi_cap_registry();
  if (!reg) return ZI_E_NOSYS;
  if (reg->cap_count > (size_t)0x7FFFFFFF) return ZI_E_INTERNAL;
  return (int32_t)reg->cap_count;
}

int32_t zi_cap_get_size(int32_t index) {
  const zi_cap_registry_v1 *reg = zi_cap_registry();
  if (!reg) return ZI_E_NOSYS;
  if (index < 0 || (size_t)index >= reg->cap_count) return err_noent();
  const zi_cap_v1 *c = reg->caps[(size_t)index];
  if (!c || !c->kind || !c->name) return ZI_E_INTERNAL;
  uint32_t kind_len = (uint32_t)strlen(c->kind);
  uint32_t name_len = (uint32_t)strlen(c->name);
  uint32_t total = 4 + kind_len + 4 + name_len + 4;
  if (total > 0x7FFFFFFF) return ZI_E_INTERNAL;
  return (int32_t)total;
}

int32_t zi_cap_get(int32_t index, zi_ptr_t out_ptr, zi_size32_t out_cap) {
  const zi_cap_registry_v1 *reg = zi_cap_registry();
  if (!reg) return ZI_E_NOSYS;
  if (index < 0 || (size_t)index >= reg->cap_count) return err_noent();

  const zi_mem_v1 *mem = zi_runtime25_mem();
  if (!mem || !mem->map_rw) return ZI_E_NOSYS;

  const zi_cap_v1 *c = reg->caps[(size_t)index];
  if (!c || !c->kind || !c->name) return ZI_E_INTERNAL;
  uint32_t kind_len = (uint32_t)strlen(c->kind);
  uint32_t name_len = (uint32_t)strlen(c->name);

  uint32_t need = 4 + kind_len + 4 + name_len + 4;
  if (out_cap < need) return ZI_E_BOUNDS;

  uint8_t *out = NULL;
  if (!mem->map_rw(mem->ctx, out_ptr, out_cap, &out) || !out) return ZI_E_BOUNDS;

  // Packed:
  //   H4 kind_len, bytes[kind_len] kind
  //   H4 name_len, bytes[name_len] name
  //   H4 flags
  out[0] = (uint8_t)(kind_len & 0xFF);
  out[1] = (uint8_t)((kind_len >> 8) & 0xFF);
  out[2] = (uint8_t)((kind_len >> 16) & 0xFF);
  out[3] = (uint8_t)((kind_len >> 24) & 0xFF);
  memcpy(out + 4, c->kind, kind_len);

  uint32_t off = 4 + kind_len;
  out[off + 0] = (uint8_t)(name_len & 0xFF);
  out[off + 1] = (uint8_t)((name_len >> 8) & 0xFF);
  out[off + 2] = (uint8_t)((name_len >> 16) & 0xFF);
  out[off + 3] = (uint8_t)((name_len >> 24) & 0xFF);
  memcpy(out + off + 4, c->name, name_len);
  off += 4 + name_len;

  uint32_t flags = c->cap_flags;
  out[off + 0] = (uint8_t)(flags & 0xFF);
  out[off + 1] = (uint8_t)((flags >> 8) & 0xFF);
  out[off + 2] = (uint8_t)((flags >> 16) & 0xFF);
  out[off + 3] = (uint8_t)((flags >> 24) & 0xFF);

  return (int32_t)need;
}

zi_handle_t zi_cap_open(zi_ptr_t req_ptr) {
  // Core 2.5 provides the caps listing plumbing. Opening is cap-specific.
  // A capability must advertise ZI_CAP_CAN_OPEN and provide an implementation in its runtime pack.
  (void)req_ptr;
  const zi_cap_registry_v1 *reg = zi_cap_registry();
  if (!reg) return (zi_handle_t)ZI_E_NOSYS;
  return (zi_handle_t)ZI_E_DENIED;
}
