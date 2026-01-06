<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zir

IR JSONL to opcode JSONL compiler. Reads **zasm-v1.0** JSONL records and emits
**zasm-opcodes-v1** bytes records for use with `zop` and `zxc`.

## Usage

```sh
zir < input.ir.jsonl > output.opcodes.jsonl
zir --tool -o output.opcodes.jsonl input1.ir.jsonl input2.ir.jsonl
zir --allow-extern-prim < input.ir.jsonl > output.opcodes.jsonl
```

## Pipeline

```sh
zas --target opcodes < input.asm | zop --container -o output.zasm.bin
zir < input.ir.jsonl | zop --container -o output.zasm.bin
zxc --container -o output.native.bin output.zasm.bin
```

## Notes

- `zir` resolves labels and `EQU` symbols for immediates and branches.
- Use `--allow-extern-prim` to keep `EXTERN` directives for host primitives (`_in`, `_out`, `_log`, `_alloc`, `_free`, `_ctl`). Other `EXTERN`
  directives remain unsupported. With this flag enabled, `CALL` instructions that
  target these primitives are encoded as dedicated primitive opcodes
  (`PRIM_IN` … `PRIM_CTL`), making the intent explicit to later stages (zop, zxc,
  cloak runtimes). Without the flag, such `EXTERN` directives are rejected.
- Only a subset of IR operand forms map cleanly to opcode encodings. Unsupported
  mnemonics or operand shapes are rejected with an error.
- The `.zasm.bin` payload emitted by `zop` can include non-instruction bytes
  (e.g., `.DB/.DW` data). `zxc --container` now truncates the opcode stream to
  the nearest 4-byte boundary for translation and leaves the trailing bytes alone
  so they remain available as data. Padding to a multiple of 4 is still
  recommended for clean diagnostics, but it is no longer required.

## Exit codes

- `0` success
- `1` translation or I/O failure
- `2` usage or option error
