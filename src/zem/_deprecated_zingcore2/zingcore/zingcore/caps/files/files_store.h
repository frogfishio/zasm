/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

int zi_files_create(const uint8_t* id, uint32_t id_len,
                    const uint8_t* data, uint32_t data_len);
int zi_files_overwrite(const uint8_t* id, uint32_t id_len,
                       const uint8_t* data, uint32_t data_len);
int zi_files_delete(const uint8_t* id, uint32_t id_len);
int zi_files_truncate(const uint8_t* id, uint32_t id_len, uint32_t new_len);

/* Policy hook; weak default allows all. write_hint: 0=read/list, 1=write/modify. */
int zi_files_policy_allow(const char* op, const uint8_t* id, uint32_t id_len, int write_hint);

/* Expose the sandbox root used by file/fs. */
const char* zi_files_root(void);
