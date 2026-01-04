<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zlnt

JSONL IR analyzer. Reads JSONL from stdin and emits diagnostics to stderr.

## Usage

```sh
cat examples/hello.asm | bin/zas | bin/zlnt
```

## Flags

- `--version` prints the tool version.
- `--json` emits diagnostics as JSON lines (stderr).
- `--tool` enables filelist mode (non-stream).

## Tool mode

```sh
bin/zlnt --tool build/app.jsonl
```

## Exit codes

- `0` no issues found
- non-zero on parse or validation errors

## Warnings

- `CALL _out` warns if `HL` or `DE` may be undefined at the call site, and includes the instruction context in the warning text.
