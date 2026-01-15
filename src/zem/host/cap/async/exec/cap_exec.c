/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "ctl_common.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cap_config.h"

static int allow_lookup(const exec_ctx_t* ctx, const char* prog) {
  for (size_t i = 0; i < ctx->allow_len; i++) {
    if (strcmp(ctx->allow[i].name, prog) == 0) return (int)i;
  }
  return -1;
}

static int is_control_ok(const char* s, size_t len) {
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == 0 || c < 0x20) return 0;
  }
  return 1;
}

static int exec_start(const exec_ctx_t* ctx, const ctl_frame_t* fr,
                      uint8_t* out, size_t cap, ctl_handles_t* handles) {
  /* Request: HSTR prog_id, H4 flags, H4 argc, args..., H4 envc, env... */
  const uint8_t* p = fr->payload;
  uint32_t plen = fr->payload_len;
  if (plen < 4) return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "payload");
  uint32_t prog_len = ctl_read_u32(p); p += 4; if (4 + prog_len > plen) return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "prog");
  const char* prog = (const char*)p; p += prog_len;
  if (!is_control_ok(prog, prog_len)) return ctl_write_error(out, cap, fr->op, fr->rid, "t_exec_bad_encoding", "prog");
  if (p + 4 > fr->payload + plen) return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "flags");
  uint32_t flags = ctl_read_u32(p); p += 4; (void)flags;
  if (p + 4 > fr->payload + plen) return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "argc");
  uint32_t argc = ctl_read_u32(p); p += 4;
  if (argc > ctx->max_argv) return ctl_write_error(out, cap, fr->op, fr->rid, "t_exec_limits", "argc");
  char* argv[256]; size_t arg_bytes = 0;
  for (uint32_t i = 0; i < argc; i++) {
    if (p + 4 > fr->payload + plen) return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "arglen");
    uint32_t alen = ctl_read_u32(p); p += 4;
    if (p + alen > fr->payload + plen) return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "arg");
    if (!is_control_ok((const char*)p, alen)) return ctl_write_error(out, cap, fr->op, fr->rid, "t_exec_bad_encoding", "arg");
    argv[i] = (char*)malloc(alen + 1);
    memcpy(argv[i], p, alen); argv[i][alen] = '\0';
    p += alen; arg_bytes += alen;
  }
  argv[argc] = NULL;
  if (arg_bytes > ctx->max_arg_bytes) {
    for (uint32_t i = 0; i < argc; i++) free(argv[i]);
    return ctl_write_error(out, cap, fr->op, fr->rid, "t_exec_limits", "arg bytes");
  }
  if (p + 4 > fr->payload + plen) { for (uint32_t i = 0; i < argc; i++) free(argv[i]); return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "envc"); }
  uint32_t envc = ctl_read_u32(p); p += 4;
  if (envc > ctx->max_env) { for (uint32_t i = 0; i < argc; i++) free(argv[i]); return ctl_write_error(out, cap, fr->op, fr->rid, "t_exec_limits", "envc"); }
  char* envv[256]; size_t env_bytes = 0;
  for (uint32_t i = 0; i < envc; i++) {
    if (p + 4 > fr->payload + plen) { for (uint32_t k = 0; k < argc; k++) free(argv[k]); return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "envk"); }
    uint32_t klen = ctl_read_u32(p); p += 4;
    if (p + klen + 4 > fr->payload + plen) { for (uint32_t k = 0; k < argc; k++) free(argv[k]); return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "envk len"); }
    const char* k = (const char*)p; p += klen;
    uint32_t vlen = ctl_read_u32(p); p += 4;
    if (p + vlen > fr->payload + plen) { for (uint32_t k = 0; k < argc; k++) free(argv[k]); return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_bad_params", "envv len"); }
    const char* v = (const char*)p; p += vlen;
    if (!is_control_ok(k, klen) || !is_control_ok(v, vlen)) { for (uint32_t k = 0; k < argc; k++) free(argv[k]); return ctl_write_error(out, cap, fr->op, fr->rid, "t_exec_bad_encoding", "env"); }
    size_t kv_len = klen + 1 + vlen;
    envv[i] = (char*)malloc(kv_len + 1);
    memcpy(envv[i], k, klen); envv[i][klen] = '='; memcpy(envv[i] + klen + 1, v, vlen); envv[i][kv_len] = '\0';
    env_bytes += kv_len;
  }
  envv[envc] = NULL;
  if (env_bytes > ctx->max_env_bytes) { for (uint32_t i = 0; i < argc; i++) free(argv[i]); for (uint32_t i = 0; i < envc; i++) free(envv[i]); return ctl_write_error(out, cap, fr->op, fr->rid, "t_exec_limits", "env bytes"); }

  int allow_idx = allow_lookup(ctx, prog);
  if (allow_idx < 0) { for (uint32_t i = 0; i < argc; i++) free(argv[i]); for (uint32_t i = 0; i < envc; i++) free(envv[i]); return ctl_write_error(out, cap, fr->op, fr->rid, "t_exec_not_allowed", "prog"); }
  const char* path = ctx->allow[allow_idx].path ? ctx->allow[allow_idx].path : prog;

  int stdout_pipe[2];
  int stderr_pipe[2];
  pipe(stdout_pipe);
  pipe(stderr_pipe);

  pid_t pid = fork();
  if (pid == 0) {
    dup2(stdout_pipe[1], STDOUT_FILENO);
    dup2(stderr_pipe[1], STDERR_FILENO);
    close(stdout_pipe[0]); close(stdout_pipe[1]);
    close(stderr_pipe[0]); close(stderr_pipe[1]);
    /* Use execve to avoid non-portable execvpe. */
    execve(path, argv, envv);
    _exit(127);
  }
  close(stdout_pipe[1]);
  close(stderr_pipe[1]);

  for (uint32_t i = 0; i < argc; i++) free(argv[i]);
  for (uint32_t i = 0; i < envc; i++) free(envv[i]);

  uint32_t exec_id = (uint32_t)pid;
  uint32_t h_out = ctl_handle_alloc(handles);
  uint32_t h_err = ctl_handle_alloc(handles);
  if (!h_out || !h_err) return ctl_write_error(out, cap, fr->op, fr->rid, "t_exec_too_many_handles", "handles");
  uint32_t payload_len = 4 + 4 + 4 + 4 + 4;
  if (cap < 20 + payload_len) return -1;
  uint8_t* o = out + 20;
  ctl_write_u32(o, exec_id); o += 4;
  ctl_write_u32(o, 1u); o += 4; /* started */
  ctl_write_u32(o, 0u); o += 4; /* stdin not granted */
  ctl_write_u32(o, h_out); o += 4;
  ctl_write_u32(o, h_err); o += 4;
  return ctl_write_ok(out, cap, fr->op, fr->rid, out + 20, payload_len);
}

static int exec_status(uint8_t* out, size_t cap, uint16_t op, uint32_t rid, const uint8_t* payload, uint32_t plen) {
  if (plen != 4) return ctl_write_error(out, cap, op, rid, "t_ctl_bad_params", "status payload");
  uint32_t exec_id = ctl_read_u32(payload);
  int status = 0;
  pid_t r = waitpid((pid_t)exec_id, &status, WNOHANG);
  uint32_t state = 0; /* running */
  uint32_t code = 0;
  if (r == (pid_t)exec_id) {
    if (WIFEXITED(status)) { state = (WEXITSTATUS(status) == 0) ? 1 : 2; code = (uint32_t)WEXITSTATUS(status); }
    else if (WIFSIGNALED(status)) { state = 4; code = (uint32_t)WTERMSIG(status); }
  }
  uint32_t payload_len = 8;
  if (cap < 20 + payload_len) return -1;
  uint8_t* p = out + 20;
  ctl_write_u32(p, state); p += 4;
  ctl_write_u32(p, code);
  return ctl_write_ok(out, cap, op, rid, out + 20, payload_len);
}

int cap_exec_handle(const exec_ctx_t* ctx, uint16_t op, const ctl_frame_t* fr,
                    uint8_t* out, size_t cap, ctl_handles_t* handles) {
  /* EXEC_START op=40, EXEC_STATUS op=41 */
  switch (op) {
    case 40: return exec_start(ctx, fr, out, cap, handles);
    case 41: return exec_status(out, cap, fr->op, fr->rid, fr->payload, fr->payload_len);
    default:
      return ctl_write_error(out, cap, fr->op, fr->rid, "t_ctl_unknown_op", "exec");
  }
}
