<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zas

Assembler front-end. Reads ZASM from stdin and emits JSONL IR to stdout.

## Usage

```sh
cat examples/hello.asm | bin/zas > build/hello.jsonl
```

## Flags

- `--version` print tool version.
- `--lint` parse and validate input without emitting JSONL.

## Exit codes

- `0` success
- `1` parse failure
- `2` usage error
