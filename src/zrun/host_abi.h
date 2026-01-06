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
} zrun_abi_env_t;

int get_memory_from_caller(wasmtime_caller_t* caller, wasmtime_memory_t* out_mem);
uint8_t* mem_data(wasmtime_caller_t* caller, wasmtime_memory_t* mem, size_t* out_size);

wasm_trap_t* zrun_req_read(void* env, wasmtime_caller_t* caller,
                          const wasmtime_val_t* args, size_t nargs,
                          wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_res_write(void* env, wasmtime_caller_t* caller,
                           const wasmtime_val_t* args, size_t nargs,
                           wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_res_end(void* env, wasmtime_caller_t* caller,
                         const wasmtime_val_t* args, size_t nargs,
                         wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_log(void* env, wasmtime_caller_t* caller,
                     const wasmtime_val_t* args, size_t nargs,
                     wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_alloc(void* env, wasmtime_caller_t* caller,
                        const wasmtime_val_t* args, size_t nargs,
                        wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_free(void* env, wasmtime_caller_t* caller,
                       const wasmtime_val_t* args, size_t nargs,
                       wasmtime_val_t* results, size_t nresults);
wasm_trap_t* zrun_ctl(void* env, wasmtime_caller_t* caller,
                      const wasmtime_val_t* args, size_t nargs,
                      wasmtime_val_t* results, size_t nresults);
