<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# C Cloak (Legacy Host Interface)

This is a minimal C interface for hosts that integrate ZASM modules without WebAssembly.
It targets the retired legacy stream ABI and is kept for reference only.

Note: modern zABI modules use `main(req, res)` as the module entrypoint for `zrun`.
This legacy interface is kept for reference only; native apps use a normal `int main(...)`.

## Files

- `lembeh_cloak.h` — host vtable, memory model, and entrypoint signatures.
- `lembeh_cloak.c` — binding, invocation helpers, and a reference bump allocator.

## Usage (host side)

```c
#include "lembeh_cloak.h"

static int32_t host_req_read(int32_t req, int32_t ptr, int32_t cap);
static int32_t host_res_write(int32_t res, int32_t ptr, int32_t len);
static void host_res_end(int32_t res);
static void host_log(int32_t topic_ptr, int32_t topic_len, int32_t msg_ptr, int32_t msg_len);
static int32_t host_alloc(int32_t size);
static void host_free(int32_t ptr);
static int32_t host_ctl(int32_t req_ptr, int32_t req_len, int32_t resp_ptr, int32_t resp_cap);

extern void guest_entry(int32_t req, int32_t res);

int main(void) {
  lembeh_host_vtable_t host = {
    .req_read = host_req_read,
    .res_write = host_res_write,
    .res_end = host_res_end,
    .log = host_log,
    .alloc = host_alloc,
    .free = host_free,
    .ctl = host_ctl,
  };
  lembeh_bind_host(&host);
  lembeh_bind_memory(guest_mem, guest_mem_cap);
  return lembeh_invoke(guest_entry, 0, 0);
}
```

## Contract

This interface documents the retired stream ABI; it is not the zABI host surface.
