<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zasm opcode stream v1 (JSONL)

This directory defines the **stable JSONL opcode stream** format used for
tooling and `zxc` ingestion. It is a lower-level, fully-resolved representation
of opcodes, distinct from the higher-level IR in `schema/ir/v1`.

Version: **v1.0** (current contract).

- Each line is one JSON object (JSONL).
- The stream is deterministic and fully linked: **no labels, no symbols, no relocations**.
- The binary opcode byte stream is the concatenation of all records in order.

## Pipeline Context

```
zas (ZASM text)
  -> JSONL IR (zasm-v1.0)
  -> JSONL opcode stream (zasm-opcodes-v1)
  -> zxc
  -> target backend (zasm opcode bytes | x86_64 | arm64 | ...)
```

`zxc` consumes raw opcode bytes; JSONL is an authoring/tooling format that can be
packed into the byte stream.

## Record Types

### 1) `op` records

Opcode records map 1:1 to the encoding defined in `docs/spec/opcode_encoding.md`.

```jsonl
{"ir":"zasm-opcodes-v1","k":"op","op":16,"rd":0,"rs1":1,"rs2":0,"imm12":0}
{"ir":"zasm-opcodes-v1","k":"op","op":112,"rd":0,"rs1":0,"rs2":0,"imm12":42}
```

Fields:

- `op`: integer 0..255 (opcode).
- `rd`, `rs1`, `rs2`: integer 0..15.
- `imm12`: signed integer -2048..2047 (two's complement).
- `ext`: optional array of 32-bit unsigned words (0..0xFFFFFFFF), length 0..2.
- `m`: optional mnemonic string (informational only; not used for encoding).
- `loc`: optional location (`line`, `col`, `unit`) for diagnostics.

**Encoding (normative):**

```
word0 = (op << 24) | (rd << 20) | (rs1 << 16) | (rs2 << 12) | (imm12 & 0xFFF)
```

- `imm12` is encoded as 12-bit two's complement.
- `word0` is emitted little-endian.
- Each `ext` word is emitted little-endian in order.

### 2) `bytes` records

Raw byte records insert literal bytes into the stream.

```jsonl
{"ir":"zasm-opcodes-v1","k":"bytes","hex":"48656C6C6F0A"}
```

Fields:

- `hex`: even-length hex string (case-insensitive).
- `loc`: optional location for diagnostics.

## Determinism Rules (Normative)

- Record order is **authoritative**.
- All numeric fields MUST be canonical integers (no floats).
- `m` is informational only and MUST NOT affect encoding.
- Unknown fields are forbidden by schema and MUST be rejected.

## Files

- `record.schema.json` — JSON Schema for **one JSONL record**.
  A `.zop.jsonl` file is valid if **every line** parses and validates.
