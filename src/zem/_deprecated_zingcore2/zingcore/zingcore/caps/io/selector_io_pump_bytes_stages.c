/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../../include/zi_async.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint32_t read_u32_le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

enum {
  ZI_PUMP_STAGE_IDENTITY = 0,
  ZI_PUMP_STAGE_UPPER_ASCII = 1,
};

typedef struct pump_stages_job {
  uint64_t future_id;
  int src;
  int dst;
  uint32_t stage_count;
  uint32_t stages[64];
  atomic_int cancelled;
  zi_async_emit emit; /* copied callbacks */
  void *emit_ctx;
  struct pump_stages_job *next;
} pump_stages_job;

static pthread_mutex_t g_jobs_mu = PTHREAD_MUTEX_INITIALIZER;
static pump_stages_job *g_jobs = NULL;

static void jobs_add(pump_stages_job *j) {
  pthread_mutex_lock(&g_jobs_mu);
  j->next = g_jobs;
  g_jobs = j;
  pthread_mutex_unlock(&g_jobs_mu);
}

static pump_stages_job *jobs_find(uint64_t future_id) {
  pthread_mutex_lock(&g_jobs_mu);
  for (pump_stages_job *it = g_jobs; it; it = it->next) {
    if (it->future_id == future_id) {
      pthread_mutex_unlock(&g_jobs_mu);
      return it;
    }
  }
  pthread_mutex_unlock(&g_jobs_mu);
  return NULL;
}

static void jobs_remove(uint64_t future_id) {
  pthread_mutex_lock(&g_jobs_mu);
  pump_stages_job **pp = &g_jobs;
  while (*pp) {
    if ((*pp)->future_id == future_id) {
      *pp = (*pp)->next;
      break;
    }
    pp = &(*pp)->next;
  }
  pthread_mutex_unlock(&g_jobs_mu);
}

static void pump_apply_upper_ascii(uint8_t *buf, size_t n) {
  for (size_t i = 0; i < n; i++) {
    uint8_t c = buf[i];
    if (c >= (uint8_t)'a' && c <= (uint8_t)'z') {
      buf[i] = (uint8_t)(c - (uint8_t)('a' - 'A'));
    }
  }
}

static void *pump_thread_main(void *arg) {
  pump_stages_job *j = (pump_stages_job *)arg;
  if (!j) return NULL;

  enum { CHUNK = 16384 };
  uint8_t *buf = (uint8_t *)malloc(CHUNK);
  if (!buf) {
    if (!atomic_load(&j->cancelled) && j->emit.future_fail) {
      j->emit.future_fail(j->emit_ctx, j->future_id, "t_io_oom", "pump");
    }
    jobs_remove(j->future_id);
    free(j);
    return NULL;
  }

  for (;;) {
    if (atomic_load(&j->cancelled)) {
      break;
    }
    ssize_t n = read(j->src, buf, CHUNK);
    if (n < 0) {
      if (!atomic_load(&j->cancelled) && j->emit.future_fail) {
        int err = errno;
        j->emit.future_fail(j->emit_ctx, j->future_id, "t_io_pump_read_failed",
                            strerror(err));
      }
      break;
    }
    if (n == 0) {
      if (!atomic_load(&j->cancelled) && j->emit.future_ok) {
        j->emit.future_ok(j->emit_ctx, j->future_id, NULL, 0);
      }
      break;
    }

    for (uint32_t i = 0; i < j->stage_count; i++) {
      uint32_t stage = j->stages[i];
      if (stage == ZI_PUMP_STAGE_IDENTITY) {
        continue;
      }
      if (stage == ZI_PUMP_STAGE_UPPER_ASCII) {
        pump_apply_upper_ascii(buf, (size_t)n);
        continue;
      }
      if (!atomic_load(&j->cancelled) && j->emit.future_fail) {
        j->emit.future_fail(j->emit_ctx, j->future_id, "t_io_unknown_stage",
                            "pump_bytes_stages");
      }
      n = 0;
      break;
    }
    if (n == 0) {
      break;
    }

    ssize_t off = 0;
    while (off < n) {
      if (atomic_load(&j->cancelled)) {
        off = n;
        break;
      }
      ssize_t w = write(j->dst, buf + (size_t)off, (size_t)(n - off));
      if (w <= 0) {
        if (!atomic_load(&j->cancelled) && j->emit.future_fail) {
          int err = errno;
          j->emit.future_fail(j->emit_ctx, j->future_id, "t_io_pump_write_failed",
                              strerror(err));
        }
        off = n;
        n = 0;
        break;
      }
      off += w;
    }
    if (n == 0) {
      break;
    }
  }

  free(buf);
  jobs_remove(j->future_id);
  free(j);
  return NULL;
}

/* Params:
 *   H4 src
 *   H4 dst
 *   U4 stage_count
 *   U4[] stages (stage_count entries, max 64)
 */
static int io_pump_bytes_stages_invoke(const zi_async_emit *emit, void *ctx,
                                      const uint8_t *params, uint32_t params_len,
                                      uint64_t req_id, uint64_t future_id) {
  (void)req_id;
  if (!emit || !emit->future_ok || !emit->future_fail) return 0;
  if (!params || params_len < 12) {
    return emit->future_fail(ctx, future_id, "t_io_bad_params",
                             "pump_bytes_stages");
  }

  int32_t src = (int32_t)read_u32_le(params + 0);
  int32_t dst = (int32_t)read_u32_le(params + 4);
  uint32_t stage_count = read_u32_le(params + 8);
  if (stage_count > 64u) {
    return emit->future_fail(ctx, future_id, "t_io_bad_params",
                             "pump_bytes_stages");
  }

  uint32_t need = 12u + (stage_count * 4u);
  if (params_len != need) {
    return emit->future_fail(ctx, future_id, "t_io_bad_params",
                             "pump_bytes_stages");
  }

  pump_stages_job *j = (pump_stages_job *)calloc(1, sizeof(*j));
  if (!j) {
    return emit->future_fail(ctx, future_id, "t_io_oom", "pump_job");
  }
  j->future_id = future_id;
  j->src = src;
  j->dst = dst;
  j->stage_count = stage_count;
  for (uint32_t i = 0; i < stage_count; i++) {
    j->stages[i] = read_u32_le(params + 12u + (i * 4u));
  }
  atomic_init(&j->cancelled, 0);
  j->emit.future_ok = emit->future_ok;
  j->emit.future_fail = emit->future_fail;
  j->emit_ctx = ctx;

  jobs_add(j);

  pthread_t thr;
  int rc = pthread_create(&thr, NULL, pump_thread_main, j);
  if (rc != 0) {
    jobs_remove(future_id);
    free(j);
    return emit->future_fail(ctx, future_id, "t_io_thread_failed",
                             "pthread_create");
  }
  (void)pthread_detach(thr);
  return 1;
}

static int io_pump_bytes_stages_cancel(void *ctx, uint64_t future_id) {
  (void)ctx;
  pump_stages_job *j = jobs_find(future_id);
  if (j) {
    atomic_store(&j->cancelled, 1);
  }
  return 1;
}

static const zi_async_selector sel_io_pump_bytes_stages = {
    .cap_kind = "io",
    .cap_name = "default",
    .selector = "io.pump_bytes_stages.v1",
    .invoke = io_pump_bytes_stages_invoke,
    .cancel = io_pump_bytes_stages_cancel,
};

__attribute__((constructor)) static void io_pump_bytes_stages_autoreg(void) {
  zi_async_register(&sel_io_pump_bytes_stages);
}

