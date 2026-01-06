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

typedef struct lembeh_host_vtable_t {
  lembeh_req_read_t req_read;
  lembeh_res_write_t res_write;
  lembeh_res_end_t res_end;
  lembeh_log_t log;
  lembeh_alloc_t alloc;
  lembeh_free_t free;
} lembeh_host_vtable_t;

/* Module entrypoint signature (normative). */
typedef void (*lembeh_handle_t)(int32_t req, int32_t res);

/* Attach the host vtable for the module to use. */
void lembeh_bind_host(const lembeh_host_vtable_t* host);

/* Access the current host vtable. Returns NULL if unbound. */
const lembeh_host_vtable_t* lembeh_host(void);

/* Safe wrapper for invoking the module entrypoint. */
int lembeh_invoke(lembeh_handle_t entry, int32_t req, int32_t res);

#endif /* LEMBEH_CLOAK_H */
