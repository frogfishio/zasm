<!-- SPDX-FileCopyrightText: 2026 Frogfish -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Author: Alexander Croft <alex@frogfish.io> -->

# Using Hopper from C

## Install or use dist/
- Build and stage artifacts:
  ```sh
  make dist   # creates dist/{lib,include,pkgconfig}
  ```
- Or install system-wide:
  ```sh
  make install PREFIX=/usr/local
  ```
- Use pkg-config:
  ```sh
  cc $(pkg-config --cflags hopper) -c your.c
  cc -o your your.o $(pkg-config --libs hopper)
  ```

## Minimal flow
1. Size buffers:
   ```c
   size_t ctx_sz = hopper_sizeof();
   size_t ref_sz = hopper_ref_entry_sizeof() * REF_COUNT;
   ```
2. Provide arena and ref-table memory (no hidden mallocs).
3. Build a `hopper_catalog_t` with pre-parsed fields/layouts (see `examples/basic.c`).
4. Init and use:
   ```c
   hopper_t *h = NULL;
   hopper_config_t cfg = { .abi_version = HOPPER_ABI_VERSION, .arena_mem = arena, .arena_bytes = ARENA_BYTES,
                           .ref_mem = refs, .ref_count = REF_COUNT, .catalog = &catalog };
   hopper_init(ctx_mem, &cfg, &h);
   hopper_result_ref_t rec = hopper_record(h, layout_id);
   hopper_field_set_bytes(h, rec.ref, field_idx, (hopper_bytes_t){data, len});
   hopper_field_set_i32(h, rec.ref, num_field_idx, value);
   ```
5. Read back with `hopper_field_get_*` or raw `hopper_read_*`.

## Example
See `examples/basic.c`. Build/run:
```sh
make dist           # optional staging
make examples
./examples/basic
```
