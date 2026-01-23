#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t zi_handle_t;

enum {
  ZI_OK = 0,

  ZI_E_INVALID  = -1,
  ZI_E_BOUNDS   = -2,
  ZI_E_NOENT    = -3,
  ZI_E_DENIED   = -4,
  ZI_E_CLOSED   = -5,
  ZI_E_AGAIN    = -6,
  ZI_E_NOSYS    = -7,
  ZI_E_OOM      = -8,
  ZI_E_IO       = -9,
  ZI_E_INTERNAL = -10,
};

enum {
  ZI_FEAT_FS   = 1ull << 0,
  ZI_FEAT_ASYNC= 1ull << 1,
  ZI_FEAT_TIME = 1ull << 2,
  ZI_FEAT_EXEC = 1ull << 3,
  ZI_FEAT_PROC = 1ull << 4,
};

enum {
  ZI_CAP_CAN_OPEN = 1u << 0,
  ZI_CAP_PURE     = 1u << 1,
  ZI_CAP_MAY_BLOCK= 1u << 2,
};

enum {
  ZI_H_READABLE = 1u << 0,
  ZI_H_WRITABLE = 1u << 1,
  ZI_H_ENDABLE  = 1u << 2,
  ZI_H_SEEKABLE = 1u << 3,
};

typedef struct {
  int32_t kind_ptr;
  int32_t kind_len;
  int32_t name_ptr;
  int32_t name_len;
  uint32_t mode;
  int32_t params_ptr;
  int32_t params_len;
} zi_cap_open_req_v2;

uint32_t zi_abi_version(void);
uint64_t zi_abi_features(void);

int32_t zi_alloc(int32_t size);
int32_t zi_free(int32_t ptr);

int32_t zi_read(zi_handle_t h, int32_t dst_ptr, int32_t cap);
int32_t zi_write(zi_handle_t h, int32_t src_ptr, int32_t len);
int32_t zi_end(zi_handle_t h);

int32_t zi_telemetry(int32_t topic_ptr, int32_t topic_len,
                     int32_t msg_ptr, int32_t msg_len);

// proc/default (optional)
int32_t zi_argc(void);
int32_t zi_argv_len(uint32_t index);
int32_t zi_argv_copy(uint32_t index, uint64_t out_ptr, int32_t out_cap);
int32_t zi_env_get_len(uint64_t key_ptr, int32_t key_len);
int32_t zi_env_get_copy(uint64_t key_ptr, int32_t key_len, uint64_t out_ptr, int32_t out_cap);

int32_t zi_cap_count(void);
int32_t zi_cap_get_size(int32_t index);
int32_t zi_cap_get(int32_t index, int32_t out_ptr, int32_t out_cap);
zi_handle_t zi_cap_open(int32_t req_ptr);
uint32_t zi_handle_hflags(zi_handle_t h);

// file/fs (optional)
int32_t zi_fs_count(void);
int32_t zi_fs_get_size(int32_t index);
int32_t zi_fs_get(int32_t index, int32_t out_ptr, int32_t out_cap);
zi_handle_t zi_fs_open_id(uint32_t mode, int32_t id_ptr, int32_t id_len);
zi_handle_t zi_fs_open_path(uint32_t mode, int32_t path_ptr, int32_t path_len);

// exec/default (optional, v2.0 draft)
// Executes a host command string (UTF-8). Returns the process exit code (0..255) or a negative error.
int32_t zi_exec_run(int32_t cmd_ptr, int32_t cmd_len);

// time/default (optional)
int32_t zi_time_now_ms_u32(void);
int32_t zi_time_sleep_ms(uint32_t ms);

// hopper (scope-owned arena; v2 draft)
// Allocates guest memory within a scope-owned arena.
// Returns 0 on failure (invalid scope / OOM / bad alignment).
int64_t zi_hop_alloc(uint32_t scope_id, uint32_t size, uint32_t align);
int64_t zi_hop_alloc_buf(uint32_t scope_id, uint32_t cap);
uint32_t zi_hop_mark(uint32_t scope_id);
int32_t  zi_hop_release(uint32_t scope_id, uint32_t mark, uint32_t wipe);
int32_t  zi_hop_reset(uint32_t scope_id, uint32_t wipe);
uint32_t zi_hop_used(uint32_t scope_id);
uint32_t zi_hop_cap(uint32_t scope_id);

// Free a scope id and release its Hopper arena (v2 draft).
int32_t zi_future_scope_free(uint32_t scope_id);

#ifdef __cplusplus
} // extern "C"
#endif
