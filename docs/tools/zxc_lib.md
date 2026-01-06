<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zxc_lib

Native code translation library for zasm opcode bytes. `libzxc.a` provides
architecture-specific translators that turn a `.zasm.bin` opcode stream into
machine code for JIT use (e.g., `zcloak-jit`).

## Build

```sh
make zxc-lib
make zxc
```

Outputs `bin/<platform>/libzxc.a` and `bin/<platform>/zxc`.

## API

The public header lives at:

- `include/zxc.h`

Key entrypoints:

- `zxc_arm64_translate(...)`
- `zxc_x86_64_translate(...)`

## Example

```c
#include "zxc.h"

zxc_result_t res = zxc_x86_64_translate(in, in_len, out, out_cap, mem_base, mem_size);
if (res.err != ZXC_OK) {
  // handle error
}
```

## Input format

Input is raw opcode bytes or a `.zasm.bin` container produced by `zop`.

## Exit codes

`libzxc` returns `zxc_result_t` with `err` set to an enum value in `zxc.h`.
