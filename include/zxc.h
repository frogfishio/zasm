/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef ZXC_H
#define ZXC_H

#include <stddef.h>
#include <stdint.h>

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

/* Zingcore syscall table ABI (zABI 2.5) for primitive host calls.
 *
 * On arm64, translated code expects the embedder to pass a third argument
 * (in x2) pointing at a `zxc_zi_syscalls_v1_t` table when primitives are
 * enabled. The translator will save this pointer in a reserved register and
 * perform indirect calls via fixed offsets.
 */
typedef struct zxc_zi_syscalls_v1 {
  int32_t (*read)(int32_t h, uint64_t dst_ptr, uint32_t cap);
  int32_t (*write)(int32_t h, uint64_t src_ptr, uint32_t len);
  uint64_t (*alloc)(uint32_t size);
  int32_t (*free)(uint64_t ptr);
  int32_t (*ctl)(uint64_t req_ptr, uint32_t req_len, uint64_t resp_ptr, uint32_t resp_cap);
  int32_t (*telemetry)(uint64_t topic_ptr, uint32_t topic_len, uint64_t msg_ptr, uint32_t msg_len);
} zxc_zi_syscalls_v1_t;

/*
 * Translate ZASM opcode bytes to machine code.
 * mem_base/mem_size define the guest byte space for bounds checks.
 */
zxc_result_t zxc_arm64_translate(const uint8_t* in, size_t in_len,
                                 uint8_t* out, size_t out_cap,
                                 uint64_t mem_base, uint64_t mem_size,
                                 uint64_t fuel_ptr, uint64_t trap_ptr,
                                 uint64_t trap_off_ptr);
zxc_result_t zxc_x86_64_translate(const uint8_t* in, size_t in_len,
                                  uint8_t* out, size_t out_cap,
                                  uint64_t mem_base, uint64_t mem_size,
                                  uint64_t fuel_ptr, uint64_t trap_ptr,
                                  uint64_t trap_off_ptr);

#ifdef __cplusplus
}
#endif

#endif
