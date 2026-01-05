<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ZASM Binary Container (.zasm.bin) — v1

This document defines the **normative** container for `.zasm.bin` opcode files
consumed by the first-party cloak JIT.

All integers are **little-endian**.

## Header (16 bytes)

```
Offset  Size  Field       Description
------  ----  ----------  -------------------------------------------
0       4     magic       ASCII "ZASB"
4       2     version     Container version (1)
6       2     flags       Reserved (0)
8       4     entry_off   Entry offset in bytes (must be 0 in v1)
12      4     code_len    Opcode stream length in bytes
```

## Payload

Immediately after the header, the opcode stream follows:

```
payload = code_len bytes of ZASM opcode stream
```

## Validation Rules (Normative)

- `magic` MUST be "ZASB".
- `version` MUST be `1` and `flags` MUST be `0`.
- `entry_off` MUST be `0` in v1.
- `code_len` MUST be non-zero and a multiple of 4 bytes.
- The total file length MUST be exactly `16 + code_len`.

## Notes

- The opcode stream uses the encoding defined in `docs/spec/opcode_encoding.md`.
- Future versions MAY allow non-zero `entry_off` and metadata extensions.
