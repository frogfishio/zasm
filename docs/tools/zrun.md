<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zrun

Local runner for modules that export `lembeh_handle(req,res)` and use stream-style imports. Accepts `.wat` or `.wasm` inputs.

## Usage

```sh
bin/zrun build/hello.wat
bin/zrun --trace build/hello.wat
bin/zrun --strict build/hello.wat
bin/zrun --mem 512MB build/hello.wat
```

## Flags

- `--trace` log host calls to stderr.
- `--strict` trap on invalid host-call arguments and track alloc/free misuse.
- `--mem <size>` cap max linear memory (bytes/kb/mb/gb). Default `256MB`. Floor `2MB`, ceiling `2GB`.

`ZRUN_MEM` may also be set to override the default cap (same syntax as `--mem`).

If the program tries to grow beyond the cap, `zrun` traps with an OOM message.

## Exit codes

- `0` success
- non-zero on read/compile/instantiate/call failure
