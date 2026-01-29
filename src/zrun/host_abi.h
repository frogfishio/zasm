/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once
#include <stddef.h>
#include <stdint.h>
#include <wasm.h>
#include <wasmtime.h>

typedef struct {
  size_t heap_ptr;
  int heap_init;
  int trace;
  int strict;
  uint64_t mem_cap_bytes;
  size_t* allocs;
  size_t allocs_n;
  size_t allocs_cap;
  uint32_t time_ms;
  struct {
    uint64_t key;
    int64_t value;
    int used;
  } mvars[256];
} zrun_abi_env_t;

int get_memory_from_caller(wasmtime_caller_t* caller, wasmtime_memory_t* out_mem);
uint8_t* mem_data(wasmtime_caller_t* caller, wasmtime_memory_t* mem, size_t* out_size);

// zABI (zi_*) host functions (WASM imports).
wasm_trap_t* zrun_zi_abi_version(void* env, wasmtime_caller_t* caller,
                                const wasmtime_val_t* args, size_t nargs,
                                wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_ctl(void* env, wasmtime_caller_t* caller,
                         const wasmtime_val_t* args, size_t nargs,
                         wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_alloc(void* env, wasmtime_caller_t* caller,
                           const wasmtime_val_t* args, size_t nargs,
                           wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_free(void* env, wasmtime_caller_t* caller,
                          const wasmtime_val_t* args, size_t nargs,
                          wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_read(void* env, wasmtime_caller_t* caller,
                          const wasmtime_val_t* args, size_t nargs,
                          wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_write(void* env, wasmtime_caller_t* caller,
                           const wasmtime_val_t* args, size_t nargs,
                           wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_end(void* env, wasmtime_caller_t* caller,
                         const wasmtime_val_t* args, size_t nargs,
                         wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_telemetry(void* env, wasmtime_caller_t* caller,
                               const wasmtime_val_t* args, size_t nargs,
                               wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_cap_count(void* env, wasmtime_caller_t* caller,
                              const wasmtime_val_t* args, size_t nargs,
                              wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_cap_get_size(void* env, wasmtime_caller_t* caller,
                                 const wasmtime_val_t* args, size_t nargs,
                                 wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_cap_get(void* env, wasmtime_caller_t* caller,
                            const wasmtime_val_t* args, size_t nargs,
                            wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_cap_open(void* env, wasmtime_caller_t* caller,
                              const wasmtime_val_t* args, size_t nargs,
                              wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_handle_hflags(void* env, wasmtime_caller_t* caller,
                                  const wasmtime_val_t* args, size_t nargs,
                                  wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_time_now_ms_u32(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_time_sleep_ms(void* env, wasmtime_caller_t* caller,
                                   const wasmtime_val_t* args, size_t nargs,
                                   wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_mvar_get_u64(void* env, wasmtime_caller_t* caller,
                                 const wasmtime_val_t* args, size_t nargs,
                                 wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_mvar_set_default_u64(void* env, wasmtime_caller_t* caller,
                                         const wasmtime_val_t* args, size_t nargs,
                                         wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_mvar_get(void* env, wasmtime_caller_t* caller,
                             const wasmtime_val_t* args, size_t nargs,
                             wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_zi_mvar_set_default(void* env, wasmtime_caller_t* caller,
                                     const wasmtime_val_t* args, size_t nargs,
                                     wasmtime_val_t* results, size_t nresults);

wasm_trap_t* zrun_zi_enum_alloc(void* env, wasmtime_caller_t* caller,
                                const wasmtime_val_t* args, size_t nargs,
                                wasmtime_val_t* results, size_t nresults);

wasm_trap_t* zrun_res_end(void* env, wasmtime_caller_t* caller,
                          const wasmtime_val_t* args, size_t nargs,
                          wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_res_write_i32(void* env, wasmtime_caller_t* caller,
                                const wasmtime_val_t* args, size_t nargs,
                                wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_res_write_u32(void* env, wasmtime_caller_t* caller,
                                const wasmtime_val_t* args, size_t nargs,
                                wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_res_write_i64(void* env, wasmtime_caller_t* caller,
                                const wasmtime_val_t* args, size_t nargs,
                                wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_res_write_u64(void* env, wasmtime_caller_t* caller,
                                const wasmtime_val_t* args, size_t nargs,
                                wasmtime_val_t* results, size_t nresults);
