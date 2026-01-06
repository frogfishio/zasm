<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# JIT Codepack (Reference)

This folder is a **single codepack** snapshot of the first-party JIT runtime.
It compiles `.zasm.bin` opcode modules to native code via `libzxc` and runs them
through the Lembeh cloak host interface.

## Files

- `zcloak_jit.c` — JIT runner entrypoint (from `src/cloak/jit_main.c`).
- `host.c`, `host.h` — host ABI bindings and bounds checks.
- `lembeh_cloak.c`, `lembeh_cloak.h` — cloak ABI definitions and helpers.
- `zxc.h`, `zxc_arm64.c`, `zxc_x86_64.c` — minimal libzxc translation backends.
- `version.h` — build-time version string.

## Build (example)

```sh
cc -std=c11 -O2 -Wall -Wextra -Wpedantic \
  zcloak_jit.c host.c lembeh_cloak.c zxc_arm64.c zxc_x86_64.c \
  -o zcloak-jit
```

## Notes

- This is a **snapshot** for integrators. The authoritative sources live in
  `src/cloak/` and `src/zxc/`.
- The `.zasm.bin` container format is documented in `docs/spec/zasm_bin.md`.
