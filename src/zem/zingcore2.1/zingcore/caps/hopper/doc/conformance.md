<!-- SPDX-FileCopyrightText: 2026 Frogfish -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Author: Alexander Croft <alex@frogfish.io> -->

# Hopper Conformance Checklist

Use this list to verify host/runtime behavior against the Hopper spec.

## Required behaviors
- **Determinism**: No locale/time/randomness; fixed endianness for COMP; no pointer leakage.
- **Arena & refs**:
  - Allocation fails with `HOPPER_E_OOM_ARENA` when arena space exhausted.
  - Allocation fails with `HOPPER_E_OOM_REFS` when ref table full.
  - Reset clears refs; optional arena wipe controlled by caller.
  - `hopper_ref_info` validates refs and returns bounds.
- **Bounds**:
  - Raw reads/writes fail with `HOPPER_E_BOUNDS` when offset+width exceeds record size.
  - Invalid refs return `HOPPER_E_BAD_REF`.
  - Field offsets/sizes must be within record bytes; else `HOPPER_E_BOUNDS`.
- **Bytes fields**:
  - Short writes pad with `pad_byte`; long writes fail (`HOPPER_E_PIC_INVALID`).
  - `hopper_field_get_bytes` fails with `HOPPER_E_DST_TOO_SMALL` if output too small.
- **DISPLAY numeric**:
  - Leading sign only (`+`/`-`), ASCII digits, scale as implied decimal (scaled integer externally).
  - Digit overflow -> `HOPPER_E_OVERFLOW`; invalid digit/sign -> `HOPPER_E_PIC_INVALID`.
  - Masks: fixed output length, Z suppression, conditional commas, `.` literal, sign positions required for signed fields, DST-too-small -> `HOPPER_E_DST_TOO_SMALL`.
- **COMP**:
  - Little-endian encoding for 2/4 byte sizes.
  - Digit overflow -> `HOPPER_E_OVERFLOW`; unsigned fields reject negatives.
- **COMP-3**:
  - Packed BCD, sign nibble accepts C/D/F only; others -> `HOPPER_E_PIC_INVALID`.
  - Digit overflow -> `HOPPER_E_OVERFLOW`.
- **Overlays**:
  - Fields sharing regions see the same bytes; non-overlapping fields remain independent.

## Suggested coverage (tests)
- Allocation OOM (arena/ref), reset semantics.
- Raw bounds checks; BAD_REF.
- DISPLAY signed/unsigned, scaled values, edit-mask variants (zero suppression, commas, decimals).
- COMP/COMP-3 encode/decode, sign nibble validation, overflows, scaled variants.
- Overlays: identical and partial overlaps.
- DST-too-small for bytes and masks.

## Platform/ABI notes
- C ABI; structs are POD; no varargs.
- COMP endianness is always little-endian regardless of host.
- Use `hopper_ref_entry_sizeof()` to size ref_mem; `hopper_sizeof()` for context storage.

## Open decisions to document if implemented
- Formatting for non-DISPLAY (COMP/COMP-3) masks.
- Serialized catalog format for toolchains.
- Runtime version reporting (e.g., `hopper_version()`).
