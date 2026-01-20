/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once
#include <stddef.h>
#include <stdint.h>
#include <wasm.h>
#include <wasmtime.h>
#include "host_abi.h"

int zrun_load_module(wasm_engine_t* engine, const uint8_t* bytes, size_t len,
                     wasmtime_module_t** out_module);
int zrun_link_zabi_imports(wasmtime_store_t* store, wasmtime_linker_t* linker,
                           zrun_abi_env_t* env);
int zrun_instantiate(wasmtime_store_t* store, wasmtime_linker_t* linker,
                     wasmtime_module_t* module, wasmtime_instance_t* out_instance);
int zrun_get_export_func(wasmtime_store_t* store, wasmtime_instance_t* instance,
                         const char* name, wasmtime_func_t* out_func);
int zrun_call_lembeh_handle(wasmtime_store_t* store, wasmtime_func_t* func,
                            int32_t req, int32_t res);

void zrun_print_error(wasmtime_error_t* err);
void zrun_print_trap(wasm_trap_t* trap);
