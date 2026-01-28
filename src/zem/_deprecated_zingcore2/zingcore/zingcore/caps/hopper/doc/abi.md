<!-- SPDX-FileCopyrightText: 2026 Frogfish -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Author: Alexander Croft <alex@frogfish.io> -->

# Hopper ABI Guide

Current release: 1.0.0 (ABI version 1).

This document captures the frozen public ABI for Hopper as a universal C-callable library.

## Versioning
- `HOPPER_ABI_VERSION` is exported in `hopper.h`. Callers must pass the same version in `hopper_config_t.abi_version` and catalogs.
- Consider adding `hopper_version()` later if you want runtime introspection.

## Core types
- `hopper_ref_t`: opaque 32-bit handle, not a pointer.
- `hopper_err_t`: stable error codes; determinism and portability require callers to handle codes, not strings.
- Result wrappers (`hopper_result_*`) are simple POD structs for FFI-friendliness.

## Layout/catalog
- Layouts and fields are supplied by the caller via `hopper_catalog_t`. Hopper does not parse PIC strings; fields must be pre-parsed.
- Endianness rules are part of field usage:
  - DISPLAY: ASCII digits with leading sign (if signed).
  - COMP: little-endian binary (i16/i32 based on field size).
  - COMP-3: packed decimal; sign nibble accepts C/D/F only.
- Bounds: `(field.offset + field.size) <= layout.record_bytes` must hold; otherwise Hopper returns `HOPPER_E_BOUNDS`.

## Context configuration
- Hopper uses caller-provided memory:
  - `arena_mem` / `arena_bytes`: backing arena.
  - `ref_mem` / `ref_count`: reference table storage.
  - Size the ref table with `ref_count * hopper_ref_entry_sizeof()`.
- No hidden allocations; zero-initialized arena on init.

## Errors (selected)
- `HOPPER_E_OOM_ARENA`, `HOPPER_E_OOM_REFS` — capacity exhausted.
- `HOPPER_E_BAD_REF` — invalid handle.
- `HOPPER_E_BOUNDS` — offset/width out of record bounds.
- `HOPPER_E_DST_TOO_SMALL` — caller output buffer too small.
- `HOPPER_E_PIC_INVALID` — malformed digits/sign/nibble or mask.
- `HOPPER_E_OVERFLOW` — value exceeds declared digits.
- `HOPPER_E_UNSUPPORTED` — unsupported usage.

## ABI expectations
- C ABI, plain structs, no varargs. Little-endian COMP is required regardless of host endianness.
- No exposure of host pointers; references are opaque indices.
- Deterministic behavior: no locale, no clocks, no randomness.

## Symbol exposure
- `libhopper.a` (static) and `libhopper.so`/`dylib` (shared) are produced.
- Public symbols come from `include/hopper.h`.
- Use `pkg-config --cflags --libs hopper` after installation.

## Conformance checklist (current coverage)
- Allocation: OOM on arena/ref exhaustion, reset semantics.
- Bounds: raw read/write and field bounds enforced.
- DISPLAY numeric: leading sign, digit validation, overflow, Z suppression and commas via masks, DST-too-small.
- COMP: LE encoding, digit/overflow checks.
- COMP-3: packed BCD, C/D/F sign nibble, overflow.
- Overlays: overlapping and non-overlapping fields share bytes correctly.
- Scales: scaled integers enforced for DISPLAY/COMP/COMP-3 getters/setters.

## Open items
- If you add formatting for non-DISPLAY (e.g., COMP/COMP-3), define mask semantics.
- Decide on a serialized catalog format (binary/JSON) for non-Zing toolchains.
- Add `hopper_version()` if runtime version reporting is needed.
