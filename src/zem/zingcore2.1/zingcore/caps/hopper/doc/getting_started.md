<!-- SPDX-FileCopyrightText: 2026 Frogfish -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Author: Alexander Croft <alex@frogfish.io> -->

# Getting Started with Hopper

Current release: 1.0.0 (ABI version 1).

## Build
```sh
make check          # build static/shared libs and run tests
make install        # install headers, libs, pkg-config (PREFIX=/usr/local by default)
make dist           # stage headers/libs/pkgconfig into dist/
```

Artifacts:
- `libhopper.a` (static)
- `libhopper.so`/`dylib` (shared, SONAME 1)
- `hopper.pc` (pkg-config)
- Header: `include/hopper.h`
- Staged dist/: headers/libs/pkgconfig for packaging

## Minimal C usage
See `examples/basic.c`:
1. Allocate memory:
   - `ctx_size = hopper_sizeof()`
   - `ref_mem = hopper_ref_entry_sizeof() * ref_count`
   - `arena_mem` sized by you
2. Populate a `hopper_catalog_t` (pre-parsed fields).
3. Call `hopper_init`, then `hopper_record`, `hopper_field_*` APIs.

Build example:
```sh
make examples
./examples/basic
```

## Python
See `bindings/python/example.py`. Run:
```sh
make python-example
```
(Uses `libhopper.so` in the repo; override with `HOPPER_LIB`.)

## Rust
`bindings/rust` contains a bindgen-based crate. Requires network to fetch crates. Run:
```sh
make rust-example
```

## Catalogs
Hopper consumes pre-parsed catalogs. See `doc/catalog.md` and `tools/catalog_example.json`.
`tools/load_catalog.py` shows loading JSON into C structs via ctypes:
```sh
make catalog-load
```

## Versioning
`hopper_version()` returns `HOPPER_ABI_VERSION`. Keep ABI stable across releases; update pkg-config version when tagging.
