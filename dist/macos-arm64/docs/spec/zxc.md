<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ZXC CLI Specification

`zxc` translates ZASM opcode bytes into native machine code for a target
architecture. It accepts raw opcode streams or `.zasm.bin` containers and
emits machine code bytes suitable for JIT use. Library API details live in
`docs/tools/zxc_lib.md`.

## Inputs

Accepted input formats:

- Raw opcode bytes (length must be a multiple of 4).
- `.zasm.bin` container (v2), as defined in `docs/spec/zasm_bin.md`.

Note: `.zasm.bin` v1 is retired and preserved at `docs/spec/zasm_bin_v1.md`.

If the input starts with the `ZASB` magic, it is treated as a container unless
`--container` is omitted and the header is invalid (which yields an error).

## Outputs

The output is a contiguous machine code byte stream written to stdout or to
`-o <path>`. The output size depends on the target backend and input opcodes.

## Target Selection

`--arch` selects the translation backend:

- `arm64`
- `x86_64`

If not provided, `zxc` uses the host architecture and errors on unsupported
hosts.

## Memory Bounds

`zxc` performs bounds checks against a virtual guest memory window:

- `--mem <size>` sets the guest memory size (bytes/kb/mb/gb).
- `--mem-base <addr>` sets the guest memory base address (default: 0).

These values are embedded in generated code to validate memory accesses.

## Options

- `--help` show usage.
- `--version` show version information.
- `--arch <arm64|x86_64>` select translation backend.
- `--mem <size>` guest memory size for bounds checks (bytes/kb/mb/gb).
- `--mem-base <addr>` guest memory base address (default: 0).
- `--container` require `.zasm.bin` container input.
- `-o <path>` write output bytes to a file (default: stdout).
- `--verbose` emit diagnostics to stderr.
- `-O` reserved for future translation optimizations.

## Exit Codes

- `0` success
- `1` translation or I/O failure
- `2` usage or option error
