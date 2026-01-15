/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

// Provided by src/zem/host/zingcore.c (linked via libzingcore.a)
int32_t res_write(int32_t handle, const void *ptr, size_t len);
int32_t req_read(int32_t handle, void *ptr, size_t cap);
void res_end(int32_t handle);
void telemetry(const char *topic_ptr, int32_t topic_len, const char *msg_ptr,
               int32_t msg_len);
int32_t _ctl(const void *req_ptr, size_t req_len, void *resp_ptr,
             size_t resp_cap);
int32_t _cap(int32_t idx);
