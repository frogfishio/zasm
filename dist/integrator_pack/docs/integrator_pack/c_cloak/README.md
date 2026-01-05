<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Lembeh C Cloak (Normative Host Interface)

This is a minimal, normative C interface for hosts that integrate zASM modules
without WebAssembly. It defines the required host primitives and a stable
entrypoint signature.

## Files

- `lembeh_cloak.h` — host vtable and module entrypoint signatures.
- `lembeh_cloak.c` — minimal binding and invocation helpers.

## Usage (host side)

```c
#include "lembeh_cloak.h"

static int32_t host_req_read(int32_t req, int32_t ptr, int32_t cap);
static int32_t host_res_write(int32_t res, int32_t ptr, int32_t len);
static void host_res_end(int32_t res);
static void host_log(int32_t topic_ptr, int32_t topic_len, int32_t msg_ptr, int32_t msg_len);
static int32_t host_alloc(int32_t size);
static void host_free(int32_t ptr);

extern void lembeh_handle(int32_t req, int32_t res);

int main(void) {
  lembeh_host_vtable_t host = {
    .req_read = host_req_read,
    .res_write = host_res_write,
    .res_end = host_res_end,
    .log = host_log,
    .alloc = host_alloc,
    .free = host_free,
  };
  lembeh_bind_host(&host);
  return lembeh_invoke(lembeh_handle, 0, 0);
}
```

## Contract

The semantics of each callback follow `docs/spec/abi.md`.
