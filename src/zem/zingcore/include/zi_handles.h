/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct zi_handle_ops {
  int32_t (*read)(void* ctx, void* buf, size_t len);
  int32_t (*write)(void* ctx, const void* buf, size_t len);
  void (*end)(void* ctx);
} zi_handle_ops_t;

/* Register a handle with ops/context. Returns handle id (>=3) or -1 on failure. */
int32_t zi_handle_register(const zi_handle_ops_t* ops, void* ctx);

/* Unregisters the handle; safe to call multiple times. */
void zi_handle_unregister(int32_t handle);

/* Internal: expose handle lookup for caps that manage their own state (seek). */
typedef struct {
  const zi_handle_ops_t* ops;
  void* ctx;
  int in_use;
} zi_handle_slot_view_t;

/* Returns pointer to slot or NULL if not in use. */
const zi_handle_slot_view_t* zi_handle_get(int32_t handle);
