/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once
#include <stdint.h>

typedef struct exec_allow {
  const char* name;
  const char* path;
} exec_allow_t;

typedef struct exec_ctx {
  const exec_allow_t* allow;
  size_t allow_len;
  uint32_t max_argv;
  uint32_t max_env;
  uint32_t max_arg_bytes;
  uint32_t max_env_bytes;
} exec_ctx_t;

typedef struct files_ctx {
  const char* root;
} files_ctx_t;
