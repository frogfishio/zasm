/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef ZXC_H
#define ZXC_H

#include <stddef.h>
#include <stdint.h>

struct lembeh_host_vtable_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  ZXC_OK = 0,
  ZXC_ERR_TRUNC = 1,
  ZXC_ERR_ALIGN = 2,
  ZXC_ERR_OUTBUF = 3,
  ZXC_ERR_OPCODE = 4,
  ZXC_ERR_UNIMPL = 5
} zxc_err_t;

typedef struct {
  zxc_err_t err;
  size_t in_off;
  size_t out_len;
} zxc_result_t;

/*
 * Translate ZASM opcode bytes to machine code.
 * mem_base/mem_size define the guest byte space for bounds checks.
 */
zxc_result_t zxc_arm64_translate(const uint8_t* in, size_t in_len,
                                 uint8_t* out, size_t out_cap,
                                 uint64_t mem_base, uint64_t mem_size,
                                 const struct lembeh_host_vtable_t* host);
zxc_result_t zxc_x86_64_translate(const uint8_t* in, size_t in_len,
                                  uint8_t* out, size_t out_cap,
                                  uint64_t mem_base, uint64_t mem_size);

#ifdef __cplusplus
}
#endif

#endif
