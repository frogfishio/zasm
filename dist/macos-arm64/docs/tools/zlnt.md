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
- `--json` emits diagnostics as JSON lines (stderr). See [docs/diagnostics.md](../diagnostics.md).
- `--tool` enables filelist mode (non-stream).

## Tool mode

```sh
bin/zlnt --tool build/app.jsonl
```

## Exit codes

- `0` no issues found
- non-zero on parse or validation errors

## Warnings

`zlnt` checks register-definition rules at `CALL` sites for zABI hostcalls. For example:

- `CALL zi_write` requires `HL` (handle), `DE` (ptr), `BC` (len)
- `CALL zi_read` requires `HL` (handle), `DE` (ptr), `BC` (cap)
- `CALL zi_telemetry` requires `HL`/`DE`/`BC`/`IX`
