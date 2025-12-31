/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wasmtime_embed.h"

static int read_file(const char* path, uint8_t** out_buf, size_t* out_len) {
  FILE* f = fopen(path, "rb");
  if (!f) return 1;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
  long sz = ftell(f);
  if (sz < 0) { fclose(f); return 1; }
  if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 1; }
  uint8_t* buf = (uint8_t*)malloc((size_t)sz + 1);
  if (!buf) { fclose(f); return 1; }
  size_t nread = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  if (nread != (size_t)sz) { free(buf); return 1; }
  buf[sz] = 0;
  *out_buf = buf;
  *out_len = (size_t)sz;
  return 0;
}

static int has_suffix(const char* s, const char* suf) {
  size_t n = strlen(s);
  size_t m = strlen(suf);
  if (n < m) return 0;
  return strcmp(s + (n - m), suf) == 0;
}

int main(int argc, char** argv) {
  int rc = 0;
  int trace = 0;
  int strict = 0;
  const char* path = NULL;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--trace") == 0) {
      trace = 1;
      continue;
    }
    if (strcmp(argv[i], "--strict") == 0) {
      strict = 1;
      continue;
    }
    if (!path) {
      path = argv[i];
      continue;
    }
    fprintf(stderr, "usage: zrun [--trace] [--strict] <module.wat|module.wasm>\n");
    return 1;
  }
  if (!path) {
    fprintf(stderr, "usage: zrun [--trace] [--strict] <module.wat|module.wasm>\n");
    return 1;
  }

  uint8_t* file_buf = NULL;
  size_t file_len = 0;
  if (read_file(path, &file_buf, &file_len) != 0) {
    fprintf(stderr, "zrun: failed to read %s\n", path);
    return 1;
  }

  uint8_t* wasm_bytes = NULL;
  size_t wasm_len = 0;
  wasm_byte_vec_t wasm_vec;
  int owns_wasm_vec = 0;

  // Accept WAT for local ergonomics and convert it in-process before instantiation.
  if (has_suffix(path, ".wat")) {
    wasmtime_error_t* err = wasmtime_wat2wasm((const char*)file_buf, file_len, &wasm_vec);
    free(file_buf);
    file_buf = NULL;
    if (err) {
      zrun_print_error(err);
      return 1;
    }
    wasm_bytes = (uint8_t*)wasm_vec.data;
    wasm_len = wasm_vec.size;
    owns_wasm_vec = 1;
  } else {
    wasm_bytes = file_buf;
    wasm_len = file_len;
  }

  wasm_engine_t* engine = wasm_engine_new();
  wasmtime_store_t* store = wasmtime_store_new(engine, NULL, NULL);
  wasmtime_linker_t* linker = wasmtime_linker_new(engine);

  // Local harness env (trace flag, allocator state, etc.).
  zrun_abi_env_t env;
  memset(&env, 0, sizeof(env));
  env.trace = trace;
  env.strict = strict;

  if (zrun_link_lembeh_imports(store, linker, &env) != 0) {
    rc = 1;
    goto cleanup;
  }

  wasmtime_module_t* module = NULL;
  if (zrun_load_module(engine, wasm_bytes, wasm_len, &module) != 0) {
    rc = 1;
    goto cleanup;
  }

  wasmtime_instance_t instance;
  if (zrun_instantiate(store, linker, module, &instance) != 0) {
    wasmtime_module_delete(module);
    rc = 1;
    goto cleanup;
  }

  wasmtime_func_t func;
  if (zrun_get_export_func(store, &instance, "lembeh_handle", &func) != 0) {
    wasmtime_module_delete(module);
    rc = 1;
    goto cleanup;
  }

  if (zrun_call_lembeh_handle(store, &func, 0, 1) != 0) {
    wasmtime_module_delete(module);
    rc = 1;
    goto cleanup;
  }

  wasmtime_module_delete(module);

cleanup:
  if (owns_wasm_vec) {
    wasm_byte_vec_delete(&wasm_vec);
  } else {
    free(wasm_bytes);
  }
  free(env.allocs);
  wasmtime_linker_delete(linker);
  wasmtime_store_delete(store);
  wasm_engine_delete(engine);
  return rc;
}
