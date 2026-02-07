<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zop

Opcode JSONL packer. Reads the **zasm-opcodes-v1** JSONL stream and emits
raw opcode bytes (or a `.zasm.bin` v2 container).

## Usage

```sh
cat build/app.opcodes.jsonl | bin/zop > build/app.zasm.bin
```

## Flags

- `--version` show version information.
- `--container` emit a `.zasm.bin` v2 container (see `docs/spec/zasm_bin.md`).
- `-o <path>` write output bytes to a file (default: stdout).

## Input format

Input must be **zasm-opcodes-v1** JSONL records as defined in:

- `schema/opcode/v1/record.schema.json`
- `schema/opcode/v1/README.md`

Records are either opcode records (`k: "op"`) or raw byte records
(`k: "bytes"`).

## Example

```sh
bin/zop --container -o build/app.zasm.bin build/app.opcodes.jsonl
```

## Exit codes

- `0` success
- `1` parse/validation failure
  (invalid record shape, out-of-range fields, bad hex length)
