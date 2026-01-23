<!-- SPDX-FileCopyrightText: 2026 Frogfish -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Author: Alexander Croft <alex@frogfish.io> -->

# Binding Hopper from other languages

Hopper is a C ABI library. This note gives minimal guidance for building bindings or calling from other languages.

## Key properties
- No hidden allocations; callers provide arena and ref-table memory.
- Plain C structs and functions; no callbacks or varargs.
- Little-endian COMP; packed COMP-3 with C/D/F sign nibbles.
- Deterministic: no locale/time/randomness.

## Building
- Use `pkg-config --cflags --libs hopper` after installation.
- Shared library: `libhopper.so`/`dylib`; static: `libhopper.a`.
- Public header: `include/hopper.h`.
- Version: `hopper_version()` returns the ABI version compiled into the library.

## Memory sizing
- Hopper context storage: `hopper_sizeof()`.
- Ref table storage: `ref_count * hopper_ref_entry_sizeof()`.
- Arena storage: caller-decided `arena_bytes`.

## Common FFI tips
- **C**: include `hopper.h`; link via `pkg-config --cflags --libs hopper`. Size allocations with `hopper_sizeof()` and `hopper_ref_entry_sizeof()`.
- **C++**: wrap the header in `extern "C"` or provide thin RAII wrappers; compile with `pkg-config` flags.
- **Rust**: use bindgen on `hopper.h`; in Cargo, set `hopper` as a `links` dep and use `pkg-config` to find it. Model `hopper_err_t` as a Rust enum with the same repr.
- **Zig**: `@cImport` on `hopper.h`; ensure `-lhopper` is linked; pass slices as `[*]u8` plus length.
- **Python (cffi/ctypes)**: load shared lib; mirror structs and integer widths exactly.

## Catalog ingestion
- Hopper does not parse PIC strings. Bindings must populate `hopper_catalog_t` with pre-parsed fields (see `doc/catalog.md`).
- Enforce bounds before calling Hopper.

## Error handling
- All operations return explicit error codes or result structs; never rely on exceptions.
- Bounds and invalid refs must be handled by checking `ok`/`err`.

## Threading
- Hopper context has no internal locks; treat one context as single-thread-affine unless you add external synchronization.

## Versioning
- Ensure `abi_version` fields match `HOPPER_ABI_VERSION`. Consider exposing a version query from the shared library if you need runtime checks.
