/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "wasmtime_embed.h"
#include <stdio.h>
#include <string.h>

void zrun_print_error(wasmtime_error_t* err) {
  if (!err) return;
  wasm_byte_vec_t msg;
  wasmtime_error_message(err, &msg);
  fprintf(stderr, "zrun: %.*s\n", (int)msg.size, msg.data);
  wasm_byte_vec_delete(&msg);
  wasmtime_error_delete(err);
}

void zrun_print_trap(wasm_trap_t* trap) {
  if (!trap) return;
  wasm_byte_vec_t msg;
  wasm_trap_message(trap, &msg);
  fprintf(stderr, "zrun: trap: %.*s\n", (int)msg.size, msg.data);
  wasm_byte_vec_delete(&msg);
  wasm_trap_delete(trap);
}

// Small helpers keep all host ABI signatures centralized and consistent.
static wasm_functype_t* functype_i32_i32_i32_to_i32(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 3);
  params.data[0] = wasm_valtype_new_i32();
  params.data[1] = wasm_valtype_new_i32();
  params.data[2] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i32();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i32_to_void(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 1);
  params.data[0] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_empty(&results);
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i32_to_i32(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 1);
  params.data[0] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i32();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i32_i32_i32_i32_to_void(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 4);
  params.data[0] = wasm_valtype_new_i32();
  params.data[1] = wasm_valtype_new_i32();
  params.data[2] = wasm_valtype_new_i32();
  params.data[3] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_empty(&results);
  return wasm_functype_new(&params, &results);
}

int zrun_load_module(wasm_engine_t* engine, const uint8_t* bytes, size_t len,
                     wasmtime_module_t** out_module) {
  wasmtime_error_t* err = wasmtime_module_new(engine, bytes, len, out_module);
  if (err) {
    zrun_print_error(err);
    return 1;
  }
  return 0;
}

// Wire the local Lembeh-compatible imports used by generated modules.
int zrun_link_lembeh_imports(wasmtime_store_t* store, wasmtime_linker_t* linker,
                             zrun_abi_env_t* env) {
  (void)store;
  wasmtime_error_t* err = NULL;
  wasm_functype_t* ty = NULL;

  ty = functype_i32_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, "lembeh", 6, "req_read", 8, ty,
                                    zrun_req_read, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, "lembeh", 6, "res_write", 9, ty,
                                    zrun_res_write, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_void();
  err = wasmtime_linker_define_func(linker, "lembeh", 6, "res_end", 7, ty,
                                    zrun_res_end, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_i32_i32_to_void();
  err = wasmtime_linker_define_func(linker, "lembeh", 6, "log", 3, ty,
                                    zrun_log, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, "lembeh", 6, "alloc", 5, ty,
                                    zrun_alloc, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_void();
  err = wasmtime_linker_define_func(linker, "lembeh", 6, "free", 4, ty,
                                    zrun_free, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  return 0;
}

int zrun_instantiate(wasmtime_store_t* store, wasmtime_linker_t* linker,
                     wasmtime_module_t* module, wasmtime_instance_t* out_instance) {
  wasm_trap_t* trap = NULL;
  wasmtime_context_t* ctx = wasmtime_store_context(store);
  wasmtime_error_t* err = wasmtime_linker_instantiate(linker, ctx, module,
                                                      out_instance, &trap);
  if (err) { zrun_print_error(err); return 1; }
  if (trap) { zrun_print_trap(trap); return 1; }
  return 0;
}

int zrun_get_export_func(wasmtime_store_t* store, wasmtime_instance_t* instance,
                         const char* name, wasmtime_func_t* out_func) {
  wasmtime_extern_t ext;
  wasmtime_context_t* ctx = wasmtime_store_context(store);
  if (!wasmtime_instance_export_get(ctx, instance, name, strlen(name), &ext)) {
    fprintf(stderr, "zrun: export %s not found\n", name);
    return 1;
  }
  if (ext.kind != WASMTIME_EXTERN_FUNC) {
    fprintf(stderr, "zrun: export %s is not a func\n", name);
    return 1;
  }
  *out_func = ext.of.func;
  return 0;
}

int zrun_call_lembeh_handle(wasmtime_store_t* store, wasmtime_func_t* func,
                            int32_t req, int32_t res) {
  wasmtime_val_t args[2];
  args[0].kind = WASMTIME_I32;
  args[0].of.i32 = req;
  args[1].kind = WASMTIME_I32;
  args[1].of.i32 = res;

  wasm_trap_t* trap = NULL;
  wasmtime_context_t* ctx = wasmtime_store_context(store);
  wasmtime_error_t* err = wasmtime_func_call(ctx, func, args, 2, NULL, 0, &trap);
  if (err) { zrun_print_error(err); return 1; }
  if (trap) { zrun_print_trap(trap); return 1; }
  return 0;
}
