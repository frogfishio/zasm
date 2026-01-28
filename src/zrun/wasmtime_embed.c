/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "wasmtime_embed.h"
#include <stdio.h>
#include <string.h>

#define LIT(s) (s), (sizeof(s) - 1)

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
static wasm_functype_t* functype_void_to_i32(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_empty(&params);
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i32();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_void_to_i64(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_empty(&params);
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i64();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i32_i32_to_void(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 2);
  params.data[0] = wasm_valtype_new_i32();
  params.data[1] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_empty(&results);
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i32_i64_i32_to_i32(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 3);
  params.data[0] = wasm_valtype_new_i32();
  params.data[1] = wasm_valtype_new_i64();
  params.data[2] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i32();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i32_i64_to_i32(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 2);
  params.data[0] = wasm_valtype_new_i32();
  params.data[1] = wasm_valtype_new_i64();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i32();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i64_i32_to_i32(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 2);
  params.data[0] = wasm_valtype_new_i64();
  params.data[1] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i32();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i32_i64_i32_i32_to_i32(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 4);
  params.data[0] = wasm_valtype_new_i32();
  params.data[1] = wasm_valtype_new_i64();
  params.data[2] = wasm_valtype_new_i32();
  params.data[3] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i32();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i64_to_i64(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 1);
  params.data[0] = wasm_valtype_new_i64();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i64();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i64_i64_to_i64(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 2);
  params.data[0] = wasm_valtype_new_i64();
  params.data[1] = wasm_valtype_new_i64();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i64();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i32_to_i64(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 1);
  params.data[0] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i64();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i32_i32_to_i64(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 2);
  params.data[0] = wasm_valtype_new_i32();
  params.data[1] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i64();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i32_i32_i32_to_i64(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 3);
  params.data[0] = wasm_valtype_new_i32();
  params.data[1] = wasm_valtype_new_i32();
  params.data[2] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i64();
  return wasm_functype_new(&params, &results);
}

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

static wasm_functype_t* functype_i32_i32_to_i32(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 2);
  params.data[0] = wasm_valtype_new_i32();
  params.data[1] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i32();
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

static wasm_functype_t* functype_i32_i32_i32_i32_to_i32(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 4);
  params.data[0] = wasm_valtype_new_i32();
  params.data[1] = wasm_valtype_new_i32();
  params.data[2] = wasm_valtype_new_i32();
  params.data[3] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i32();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i64_i32_i64_i32_to_i32(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 4);
  params.data[0] = wasm_valtype_new_i64();
  params.data[1] = wasm_valtype_new_i32();
  params.data[2] = wasm_valtype_new_i64();
  params.data[3] = wasm_valtype_new_i32();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i32();
  return wasm_functype_new(&params, &results);
}

static wasm_functype_t* functype_i64_to_i32(void) {
  wasm_valtype_vec_t params;
  wasm_valtype_vec_new_uninitialized(&params, 1);
  params.data[0] = wasm_valtype_new_i64();
  wasm_valtype_vec_t results;
  wasm_valtype_vec_new_uninitialized(&results, 1);
  results.data[0] = wasm_valtype_new_i32();
  return wasm_functype_new(&params, &results);
}

static wasm_trap_t* zrun_stub_i32_i32_to_void(void* env, wasmtime_caller_t* caller,
                                              const wasmtime_val_t* args, size_t nargs,
                                              wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  (void)args;
  (void)nargs;
  (void)results;
  (void)nresults;
  return NULL;
}

static wasm_trap_t* zrun_stub_ret_i32_nosys(void* env, wasmtime_caller_t* caller,
                                           const wasmtime_val_t* args, size_t nargs,
                                           wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = -7; // ZI_E_NOSYS
  return NULL;
}

static wasm_trap_t* zrun_stub_ret_i64_zero(void* env, wasmtime_caller_t* caller,
                                          const wasmtime_val_t* args, size_t nargs,
                                          wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I64;
  results[0].of.i64 = 0;
  return NULL;
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

// Wire the zABI imports used by generated modules.
int zrun_link_zabi_imports(wasmtime_store_t* store, wasmtime_linker_t* linker,
                           zrun_abi_env_t* env) {
  (void)store;
  wasmtime_error_t* err = NULL;
  wasm_functype_t* ty = NULL;

  ty = functype_void_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_abi_version"), ty,
                                    zrun_zi_abi_version, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_void_to_i64();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_abi_features"), ty,
                                    zrun_zi_abi_features, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_read"), ty,
                                    zrun_zi_read, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_write"), ty,
                                    zrun_zi_write, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_end"), ty,
                                    zrun_zi_end, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i64();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_alloc"), ty,
                                    zrun_zi_alloc, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i64_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_free"), ty,
                                    zrun_zi_free, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i64_i32_i64_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_telemetry"), ty,
                                    zrun_zi_telemetry, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_void_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_cap_count"), ty,
                                    zrun_zi_cap_count, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_cap_get_size"), ty,
                                    zrun_zi_cap_get_size, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_cap_get"), ty,
                                    zrun_zi_cap_get, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i64_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_cap_open"), ty,
                                    zrun_zi_cap_open, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_handle_hflags"), ty,
                                    zrun_zi_handle_hflags, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_void_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_time_now_ms_u32"), ty,
                                    zrun_zi_time_now_ms_u32, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_time_sleep_ms"), ty,
                                    zrun_zi_time_sleep_ms, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i64_to_i64();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_mvar_get_u64"), ty,
                                    zrun_zi_mvar_get_u64, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i64_i64_to_i64();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_mvar_set_default_u64"), ty,
                                    zrun_zi_mvar_set_default_u64, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i64_to_i64();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_mvar_get"), ty,
                                    zrun_zi_mvar_get, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i64_i64_to_i64();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_mvar_set_default"), ty,
                                    zrun_zi_mvar_set_default, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  // Additional zABI entry points commonly imported by the Zing stdlib.
  // Many are optional; zrun provides safe defaults so modules can instantiate.

  ty = functype_i32_i32_i32_to_i64();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_enum_alloc"), ty,
                                    zrun_zi_enum_alloc, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i64_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_exec_run"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_fs_open_path"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_i32_to_i64();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_hop_alloc"), ty,
                                    zrun_stub_ret_i64_zero, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_to_i64();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_hop_alloc_buf"), ty,
                                    zrun_stub_ret_i64_zero, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_hop_mark"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_hop_release"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_hop_reset"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_hop_used"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_hop_cap"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_read_exact_timeout"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_zax_read_frame_timeout"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_zax_q_push"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_zax_q_pop"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_zax_q_pop_match"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_pump_bytes"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_pump_bytes_stage"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_pump_bytes_stages"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_pump_bytes_stages3"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_scope_new"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_scope_handle"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_scope_lo"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_scope_hi"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_scope_next_req"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_scope_next_future"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_scope_free"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_new"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_scope"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_handle"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_id_lo"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("zi_future_id_hi"), ty,
                                    zrun_stub_ret_i32_nosys, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("res_end"), ty,
                                    zrun_res_end, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("res_write_i32"), ty,
                                    zrun_res_write_i32, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i32_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("res_write_u32"), ty,
                                    zrun_res_write_u32, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("res_write_i64"), ty,
                                    zrun_res_write_i64, env, NULL);
  wasm_functype_delete(ty);
  if (err) { zrun_print_error(err); return 1; }

  ty = functype_i32_i64_to_i32();
  err = wasmtime_linker_define_func(linker, LIT("env"), LIT("res_write_u64"), ty,
                                    zrun_res_write_u64, env, NULL);
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
