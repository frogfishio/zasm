/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
  int (*ack)(void* ctx, uint64_t req_id, uint64_t future_id);
  int (*fail)(void* ctx, uint64_t req_id, const char* code, const char* msg);
  int (*future_ok)(void* ctx, uint64_t future_id, const uint8_t* val, uint32_t val_len);
  int (*future_fail)(void* ctx, uint64_t future_id, const char* code, const char* msg);
  int (*future_cancel)(void* ctx, uint64_t future_id);
} zi_async_emit;

typedef int (*zi_async_invoke)(const zi_async_emit* emit, void* emit_ctx,
                               const uint8_t* params, uint32_t params_len,
                               uint64_t req_id, uint64_t future_id);

typedef int (*zi_async_cancel_cb)(void* emit_ctx, uint64_t future_id);

typedef struct zi_async_selector {
  const char* cap_kind;   /* e.g., "async" */
  const char* cap_name;   /* e.g., "default" */
  const char* selector;   /* e.g., "ping.v1" */
  zi_async_invoke invoke;
  zi_async_cancel_cb cancel; /* optional */
} zi_async_selector;

int zi_async_register(const zi_async_selector* sel); /* returns 1 on success */
const zi_async_selector* zi_async_find(const char* kind, size_t kind_len,
                                       const char* name, size_t name_len,
                                       const char* selector, size_t selector_len);

/* ------------------------------------------------------------------------- */
/* Internal helpers for selector implementations (async hub integration)      */
/* ------------------------------------------------------------------------- */

/* Register a TCP socket fd for nonblocking connect completion.
   The async hub will poll and complete the future asynchronously. */
int zi_async_tcp_connect_pending_add(void* async_ctx, uint64_t future_id, int fd);

/* Remove and close any pending TCP connect for this future (best-effort). */
int zi_async_tcp_connect_pending_cancel(void* async_ctx, uint64_t future_id);

/* Register a connected TCP fd as a Zing stream handle (read/write/end). */
int32_t zi_async_tcp_register_fd(int fd);

/* Enqueue a DNS lookup (getaddrinfo) for `host`/`port` and complete the
   connection asynchronously. Returns 1 on success. */
int zi_async_tcp_dns_pending_add(void* async_ctx, uint64_t future_id,
                                 const uint8_t* host, uint32_t host_len,
                                 uint16_t port, uint32_t flags);

/* Cancel a pending DNS lookup for a future (best-effort). */
int zi_async_tcp_dns_pending_cancel(void* async_ctx, uint64_t future_id);

/* Register an accept operation on a listener fd; completes when a connection arrives. */
int zi_async_tcp_accept_pending_add(void* async_ctx, uint64_t future_id, int listener_fd);

/* Cancel a pending accept for a future (best-effort). */
int zi_async_tcp_accept_pending_cancel(void* async_ctx, uint64_t future_id);
