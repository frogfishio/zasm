#pragma once

#include <stdint.h>

#include "zi_caps.h"
#include "zi_file_open_flags25.h"
#include "zi_sysabi25.h"

#ifdef __cplusplus
extern "C" {
#endif

// Golden capability: file/aio (version 1)
//
// kind = "file"
// name = "aio"
//
// This cap is opened via zi_cap_open() (params empty) and yields a pollable
// bidirectional stream handle.
//
// Requests are written as ZCL1 frames; immediate acknowledgements are read back
// as ZCL1 frames. Completions are delivered asynchronously as ZCL1 frames with:
//   op = ZI_FILE_AIO_EV_DONE
//   rid = the original request rid (job id)
//
// The handle is pollable via sys/loop for readability when responses/completions
// are available to read.

#ifndef ZI_CAP_KIND_FILE
#define ZI_CAP_KIND_FILE "file"
#endif

#define ZI_CAP_NAME_AIO "aio"

// file/aio operations (request opcodes)
typedef enum zi_file_aio_op_v1 {
  // payload is identical to file/fs open params:
  //   u64 path_ptr, u32 path_len, u32 oflags, u32 create_mode
  ZI_FILE_AIO_OP_OPEN = 1,

  // payload:
  //   u64 file_id
  ZI_FILE_AIO_OP_CLOSE = 2,

  // payload:
  //   u64 file_id
  //   u64 offset
  //   u32 max_len
  //   u32 flags (must be 0)
  ZI_FILE_AIO_OP_READ = 3,

  // payload:
  //   u64 file_id
  //   u64 offset
  //   u64 src_ptr
  //   u32 src_len
  //   u32 flags (must be 0)
  ZI_FILE_AIO_OP_WRITE = 4,
} zi_file_aio_op_v1;

// file/aio completion event opcode
enum {
  // ok payload:
  //   u16 orig_op
  //   u16 reserved
  //   u32 result      (bytes for READ/WRITE; 0 otherwise)
  //   [orig_op-specific extra]
  //     OPEN:  u64 file_id
  //     READ:  bytes[result]
  //     WRITE: (no extra)
  //     CLOSE: (no extra)
  //
  // error payload uses standard zi_zcl1_write_error encoding.
  ZI_FILE_AIO_EV_DONE = 100,
};

const zi_cap_v1 *zi_file_aio25_cap(void);
int zi_file_aio25_register(void);

// Implementation hook used by zi_cap_open() when file/aio is selected.
// params must be empty for v1.
zi_handle_t zi_file_aio25_open_from_params(zi_ptr_t params_ptr, zi_size32_t params_len);

#ifdef __cplusplus
} // extern "C"
#endif
