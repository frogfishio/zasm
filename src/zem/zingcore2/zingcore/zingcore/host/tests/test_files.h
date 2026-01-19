/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

int test_async_files_list(void);
int test_async_files_open_read(void);
int test_async_files_create_and_list(void);
int test_async_files_write_update(void);
int test_async_files_overwrite(void);
int test_async_files_truncate_seek(void);
int test_async_files_seek_whence(void);
int test_async_files_concurrent_handles(void);
int test_async_files_errors(void);
int test_async_join_cancel(void);
int test_async_join_cancel_cross_handle(void);
int test_async_payload_cap_meta(void);
int test_async_files_delete(void);
int test_async_files_bad_scope(void);
int test_async_files_open_bad_params(void);
int test_async_files_create_bad_params(void);
int test_async_files_seek_bad_len(void);
int test_async_files_seek_bad_whence(void);

/* Async (non-file) helpers */
int test_async_payload_cap(void);
int test_async_cancel(void);
int test_async_opaque_source(void);
int test_async_join_detach(void);
int test_async_timeout_cancel(void);
