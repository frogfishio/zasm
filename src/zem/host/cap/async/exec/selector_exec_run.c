/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../../include/zi_async.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

typedef struct {
  pid_t pid;
  int in_use;
  int stdout_fd;
  uint64_t future_id;
} exec_proc_t;

#define EXEC_MAX 8
static exec_proc_t g_execs[EXEC_MAX];

static exec_proc_t* exec_alloc(void) {
  for (int i = 0; i < EXEC_MAX; i++) {
    if (!g_execs[i].in_use) {
      g_execs[i].in_use = 1;
      g_execs[i].pid = 0;
      g_execs[i].stdout_fd = -1;
      g_execs[i].future_id = 0;
      return &g_execs[i];
    }
  }
  return NULL;
}

static void exec_free(exec_proc_t* p) {
  if (!p) return;
  if (p->stdout_fd >= 0) close(p->stdout_fd);
  p->stdout_fd = -1;
  p->pid = 0;
   p->future_id = 0;
  p->in_use = 0;
}

static int exec_run_invoke(const zi_async_emit* emit, void* ctx,
                           const uint8_t* params, uint32_t params_len,
                           uint64_t req_id, uint64_t future_id) {
  (void)ctx; (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  if (params_len < 4) return emit->future_fail(ctx, future_id, "t_async_bad_params", "cmd len");
  uint32_t cmd_len = (uint32_t)params[0] | ((uint32_t)params[1] << 8) |
                     ((uint32_t)params[2] << 16) | ((uint32_t)params[3] << 24);
  if (4u + cmd_len != params_len) return emit->future_fail(ctx, future_id, "t_async_bad_params", "cmd bytes");
  if (cmd_len == 0 || cmd_len > 512) return emit->future_fail(ctx, future_id, "t_exec_bad_params", "cmd range");
  char* cmd = (char*)malloc(cmd_len + 1);
  if (!cmd) return emit->future_fail(ctx, future_id, "t_async_failed", "oom");
  memcpy(cmd, params + 4, cmd_len);
  cmd[cmd_len] = '\0';
  /* Restrict to echo-only for safety. */
  if (strncmp(cmd, "echo ", 5) != 0 && strcmp(cmd, "echo") != 0) {
    free(cmd);
    return emit->future_fail(ctx, future_id, "t_exec_not_allowed", "cmd");
  }
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    free(cmd);
    return emit->future_fail(ctx, future_id, "t_exec_failed", "pipe");
  }
  exec_proc_t* slot = exec_alloc();
  if (!slot) {
    free(cmd);
    close(pipefd[0]); close(pipefd[1]);
    return emit->future_fail(ctx, future_id, "t_exec_unavailable", "slots");
  }
  slot->future_id = future_id;
  pid_t pid = fork();
  if (pid == 0) {
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    execl("/bin/sh", "sh", "-c", cmd, (char*)NULL);
    _exit(127);
  }
  free(cmd);
  close(pipefd[1]);
  slot->pid = pid;
  slot->stdout_fd = pipefd[0];
  uint8_t buf[1024];
  ssize_t r = read(slot->stdout_fd, buf, sizeof(buf));
  int status = 0;
  waitpid(pid, &status, 0);
  exec_free(slot);
  if (r < 0) return emit->future_fail(ctx, future_id, "t_exec_failed", "read");
  /* prepend status (u32) then stdout/stderr bytes */
  uint32_t status_code = 0;
  if (WIFEXITED(status)) status_code = (uint32_t)WEXITSTATUS(status);
  else if (WIFSIGNALED(status)) status_code = 128u + (uint32_t)WTERMSIG(status);
  uint32_t out_len = (uint32_t)r;
  uint8_t* payload = (uint8_t*)malloc(4 + out_len);
  if (!payload) return emit->future_fail(ctx, future_id, "t_async_failed", "oom");
  payload[0] = (uint8_t)(status_code & 0xFF);
  payload[1] = (uint8_t)((status_code >> 8) & 0xFF);
  payload[2] = (uint8_t)((status_code >> 16) & 0xFF);
  payload[3] = (uint8_t)((status_code >> 24) & 0xFF);
  if (out_len) memcpy(payload + 4, buf, out_len);
  int ok = emit->future_ok(ctx, future_id, payload, 4 + out_len);
  free(payload);
  return ok;
}

static int exec_run_cancel(void* ctx, uint64_t future_id) {
  (void)ctx;
  for (int i = 0; i < EXEC_MAX; i++) {
    if (g_execs[i].in_use && g_execs[i].future_id == future_id) {
      if (g_execs[i].pid > 0) kill(g_execs[i].pid, SIGKILL);
      if (g_execs[i].pid > 0) {
        int status = 0;
        waitpid(g_execs[i].pid, &status, 0);
      }
      exec_free(&g_execs[i]);
      break;
    }
  }
  return 1;
}

static const zi_async_selector sel_exec_run = {
  .cap_kind = "exec",
  .cap_name = "run",
  .selector = "exec.run.v1",
  .invoke = exec_run_invoke,
  .cancel = exec_run_cancel,
};

__attribute__((constructor))
static void exec_run_autoreg(void) {
  zi_async_register(&sel_exec_run);
}
