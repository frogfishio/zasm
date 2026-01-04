/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef LEMBEH_CLOAK_H
#define LEMBEH_CLOAK_H

#include <stddef.h>
#include <stdint.h>

/* Host ABI function types (normative). */
typedef int32_t (*lembeh_req_read_t)(int32_t req, int32_t ptr, int32_t cap);
typedef int32_t (*lembeh_res_write_t)(int32_t res, int32_t ptr, int32_t len);
typedef void (*lembeh_res_end_t)(int32_t res);
typedef void (*lembeh_log_t)(int32_t topic_ptr, int32_t topic_len,
                             int32_t msg_ptr, int32_t msg_len);
typedef int32_t (*lembeh_alloc_t)(int32_t size);
typedef void (*lembeh_free_t)(int32_t ptr);
typedef int32_t (*lembeh_ctl_t)(int32_t req_ptr, int32_t req_len,
                                int32_t resp_ptr, int32_t resp_cap);

typedef struct {
  lembeh_req_read_t req_read;
  lembeh_res_write_t res_write;
  lembeh_res_end_t res_end;
  lembeh_log_t log;
  lembeh_alloc_t alloc;
  lembeh_free_t free;
  lembeh_ctl_t ctl;
} lembeh_host_vtable_t;

/* Guest memory model (flat byte space). */
typedef struct {
  uint8_t* base;
  size_t cap;
} lembeh_memory_t;

/* Bump allocator reference (optional helper). */
typedef struct {
  size_t head;
  size_t cap;
  uint8_t* base;
} lembeh_bump_alloc_t;

/* Module entrypoint signature (normative). */
typedef void (*lembeh_handle_t)(int32_t req, int32_t res);

/* Attach the host vtable for the module to use. */
void lembeh_bind_host(const lembeh_host_vtable_t* host);

/* Access the current host vtable. Returns NULL if unbound. */
const lembeh_host_vtable_t* lembeh_host(void);

/* Bind guest memory (required for non-WASM hosts). */
void lembeh_bind_memory(uint8_t* base, size_t cap);

/* Access guest memory (may be NULL if unbound). */
const lembeh_memory_t* lembeh_memory(void);

/* Reference bump allocator helpers. */
void lembeh_bump_init(lembeh_bump_alloc_t* a, uint8_t* base, size_t cap, size_t start);
int32_t lembeh_bump_alloc(lembeh_bump_alloc_t* a, int32_t size);
void lembeh_bump_free(lembeh_bump_alloc_t* a, int32_t ptr);

/* Safe wrapper for invoking the module entrypoint. */
int lembeh_invoke(lembeh_handle_t entry, int32_t req, int32_t res);

#endif /* LEMBEH_CLOAK_H */
