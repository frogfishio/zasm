<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zrun

Local runner for modules that export `lembeh_handle(req,res)` and use stream-style imports. Accepts `.wat` or `.wasm` inputs.

## Usage

```sh
bin/zrun build/hello.wat
bin/zrun --trace build/hello.wat
bin/zrun --strict build/hello.wat
```

## Flags

- `--trace` log host calls to stderr.
- `--strict` trap on invalid host-call arguments and track alloc/free misuse.

## Exit codes

- `0` success
- non-zero on read/compile/instantiate/call failure
