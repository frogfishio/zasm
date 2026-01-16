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
- `--tool` enable filelist + `-o` output mode (non-stream).
- `-o <path>` write JSONL IR to a file (tool mode only).
- `--verbose` emit debug-friendly diagnostics to stderr (disabled with `--lint`).
- `--json` emit diagnostics as JSON lines (stderr).

See [docs/diagnostics.md](../diagnostics.md) for the JSONL schema and VS Code Problems integration.

## Tool mode

```sh
bin/zas --tool -o build/app.jsonl src/app.asm src/lib.asm
```

## Exit codes

- `0` success
- `1` parse failure
- `2` usage error
