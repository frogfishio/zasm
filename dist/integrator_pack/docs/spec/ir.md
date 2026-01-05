<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zASM IR v1.0.0 (Normative)

## Purpose

The JSONL IR is the stable boundary between `zas` and `zld`.
Each line is a JSON object representing one record.

## Format

- One JSON object per line (JSONL).
- Each record MUST include: `"ir":"zasm-v1.0"`.
- `zld` MUST reject unknown or missing IR versions.

## Record kinds

- `label` — defines a label
- `instr` — instruction
- `dir` — directive

## Operands

Operands are typed objects:

- `{ "t":"sym", "v":"NAME" }`
- `{ "t":"num", "v":123 }`
- `{ "t":"str", "v":"text" }`
- `{ "t":"mem", "base":"HL" }`

## Location info

Optional `loc` object:

```json
"loc": { "line": 12, "col": 3 }
```

Tools SHOULD use `loc` for error reporting when present.

## Validation

The schema lives at:

- `schema/ir/v1/record.schema.json`

All records MUST validate against the schema.

## Versioning

- IR version is **v1.0.0**.
- Backward-compatible additions MAY be introduced in later minor versions.
