/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef LEMBEH_CLOAK_H
#define LEMBEH_CLOAK_H

#include <stddef.h>
#include <stdint.h>

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

typedef struct {
  uint8_t* base;
  size_t cap;
} lembeh_memory_t;

typedef struct {
  size_t head;
  size_t cap;
  uint8_t* base;
} lembeh_bump_alloc_t;

typedef void (*lembeh_handle_t)(int32_t req, int32_t res);

void lembeh_bind_host(const lembeh_host_vtable_t* host);
const lembeh_host_vtable_t* lembeh_host(void);

void lembeh_bind_memory(uint8_t* base, size_t cap);
const lembeh_memory_t* lembeh_memory(void);

void lembeh_bump_init(lembeh_bump_alloc_t* a, uint8_t* base, size_t cap, size_t start);
int32_t lembeh_bump_alloc(lembeh_bump_alloc_t* a, int32_t size);
void lembeh_bump_free(lembeh_bump_alloc_t* a, int32_t ptr);

int lembeh_invoke(lembeh_handle_t entry, int32_t req, int32_t res);

#endif /* LEMBEH_CLOAK_H */
