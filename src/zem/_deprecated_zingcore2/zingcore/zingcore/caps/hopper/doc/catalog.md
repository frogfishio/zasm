<!-- SPDX-FileCopyrightText: 2026 Frogfish -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Author: Alexander Croft <alex@frogfish.io> -->

# Hopper Catalog Guidance

Hopper does not parse PIC strings at runtime. Callers must supply a pre-parsed catalog (`hopper_catalog_t`) describing layouts and fields. This document captures how to shape that data and suggests a portable JSON form for toolchains that emit catalogs.

## In-memory structures (C ABI)
- `hopper_catalog_t`: `{ abi_version, layouts*, layout_count }`
- `hopper_layout_t`: `{ name_ascii, name_len, record_bytes, layout_id, fields*, field_count }`
- `hopper_field_t`: `{ name_ascii, name_len, offset, size, kind, pad_byte, pic, redefines_index }`
- `hopper_pic_t`: `{ digits, scale, is_signed, usage, mask_ascii, mask_len }`

Notes:
- `redefines_index` is -1 if none; otherwise index into the same `fields[]` array.
- `usage` is one of `HOPPER_USAGE_DISPLAY`, `HOPPER_USAGE_COMP`, `HOPPER_USAGE_COMP3`.
- `kind` is `HOPPER_FIELD_BYTES` or `HOPPER_FIELD_NUM_I32`.
- `mask_ascii` points to mask bytes (not necessarily NUL-terminated); `mask_len` is required if mask present.
- Bounds: enforce `(offset + size) <= record_bytes` before calling Hopper.

## Suggested JSON schema (for non-Zing toolchains)
```jsonc
{
  "abi_version": 1,
  "layouts": [
    {
      "name": "Sample",
      "layout_id": 1,
      "record_bytes": 24,
      "fields": [
        {
          "name": "raw",
          "offset": 0,
          "size": 4,
          "kind": "bytes",
          "pad_byte": 32
        },
        {
          "name": "num",
          "offset": 4,
          "size": 3,
          "kind": "num_i32",
          "pic": {
            "digits": 3,
            "scale": 0,
            "is_signed": false,
            "usage": "display",
            "mask": null
          }
        }
      ]
    }
  ]
}
```

Suggested enum encodings:
- `kind`: `"bytes"`, `"num_i32"`
- `usage`: `"display"`, `"comp"`, `"comp3"`

Masks:
- Encode mask as a string of literal bytes; ensure callers preserve length (not NUL-terminated).
- If `mask` is null/omitted, `mask_len` should be 0.

## Loading catalogs
- JSON parsing is outside Hopper; callers can parse into their own structs then populate the C structs.
- Validate:
  - `abi_version == HOPPER_ABI_VERSION`
  - `layout_id` uniqueness
  - field bounds within `record_bytes`
  - `mask_len` matches provided mask string length

## Zing alignment
- Zing codegen can emit this JSON alongside compiled output or embed a C array directly. Both must populate the same C structs before `hopper_init`.

## Future extensions
- If new field kinds/usages are added, extend the enum vocabulary but keep numeric values stable in the C ABI.
- Consider a binary form (length-prefixed strings) if JSON parsing cost matters; schema stays the same.
