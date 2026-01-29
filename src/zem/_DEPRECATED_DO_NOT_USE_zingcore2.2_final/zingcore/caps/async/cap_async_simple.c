/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../ctl_common.h"
#include "../../include/zi_caps.h"
#include "../../include/zi_handles.h"
#include "../../include/zi_async.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <netdb.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

/* Deterministic time syscalls are provided by zingcore (ABI v2). */
extern int32_t zi_time_now_ms_u32(void);
extern int32_t zi_time_sleep_ms(uint32_t ms);

enum {
  CAP_FLAG_CAN_OPEN = 1u << 0,
  HFLAG_READABLE = 1u << 0,
  HFLAG_WRITABLE = 1u << 1,
  ASYNC_MAX_PAYLOAD = 1048576,
  FUTURE_PER_HANDLE_MAX = 32,
  FUTURE_MAX = 64,
  OP_REGISTER = 1,
  OP_CANCEL = 2,
  OP_DETACH = 3,
  OP_JOIN = 4,
  ASYNC_META_FLAG_TIMEOUT = 1u << 0,
  ASYNC_META_FLAG_BROADCAST = 1u << 1,
  ASYNC_META_FLAG_CANCEL_CB = 1u << 2,
  /* Stream handle hflags (matches zi_handle_hflags bits). */
  STREAM_READABLE = 1u << 0,
  STREAM_WRITABLE = 1u << 1,
  STREAM_ENDABLE = 1u << 2,
};

static void write_u16_le(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xff);
  p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void write_u32_le(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xff);
  p[1] = (uint8_t)((v >> 8) & 0xff);
  p[2] = (uint8_t)((v >> 16) & 0xff);
  p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void write_u64_le(uint8_t* p, uint64_t v) {
  write_u32_le(p, (uint32_t)(v & 0xffffffffu));
  write_u32_le(p + 4, (uint32_t)(v >> 32));
}

static uint32_t read_u32_le(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

typedef struct {
  uint8_t* out;
  size_t out_len;
  size_t out_cap;
  size_t out_pos;
  uint64_t scope_id;
  uint64_t task_id;
  int future_count;
} async_handle_t;

typedef struct {
  uint64_t id;
  int in_use;
  int canceled;
  uint64_t scope_id;
  uint64_t task_id;
  async_handle_t* owner;
  uint64_t deadline_ms;
  int has_deadline;
  zi_async_cancel_cb cancel_cb;
  void* cancel_ctx;
  int cancel_invoked;
} future_entry_t;

typedef struct {
  uint64_t id;
  int in_use;
} scope_entry_t;

typedef struct {
  uint64_t id;
  uint64_t scope_id;
  int in_use;
  int detached;
  char owner[64];
  uint32_t owner_len;
} task_entry_t;

static future_entry_t g_futures[FUTURE_MAX];
static scope_entry_t g_scopes[FUTURE_MAX];
static task_entry_t g_tasks[FUTURE_MAX];
static async_handle_t* g_handle_list[FUTURE_MAX];
static int g_handle_count = 0;

static int ensure_cap(uint8_t** buf, size_t* cap, size_t need);
static int enqueue_frame(async_handle_t* h, uint16_t kind, uint16_t op,
                         uint64_t req_id, uint64_t future_id,
                         const uint8_t* payload, uint32_t payload_len);
static void sweep_deadlines(void);
static int is_valid_utf8(const uint8_t* p, uint32_t len);
static void cancel_future_emit(uint64_t future_id);
static void broadcast_cancel(uint64_t future_id);
static void handle_untrack(async_handle_t* h);
static int async_emit_future_ok(void* ctx, uint64_t future_id,
                                const uint8_t* val, uint32_t val_len);
static int async_emit_future_fail(void* ctx, uint64_t future_id,
                                  const char* code, const char* msg);
static void handle_track(async_handle_t* h);

static uint64_t now_ms(void);

/* ------------------------------------------------------------------------- */
/* Pending TCP connects (Stage 1: nonblocking connect without reactor cap)     */
/* ------------------------------------------------------------------------- */

typedef struct {
  int in_use;
  int fd;
  uint64_t future_id;
  async_handle_t* owner;
  struct addrinfo* addrs;
  struct addrinfo* cur;
  uint32_t flags;
} tcp_pending_t;

#define TCP_PENDING_MAX 32
static tcp_pending_t g_tcp_pending[TCP_PENDING_MAX];

typedef struct {
  int in_use;
  int listener_fd;
  uint64_t future_id;
  async_handle_t* owner;
} tcp_accept_pending_t;

#define TCP_ACCEPT_PENDING_MAX 32
static tcp_accept_pending_t g_tcp_accept_pending[TCP_ACCEPT_PENDING_MAX];

typedef struct {
  int in_use;
  int queued;
  int done;
  int canceled;
  uint64_t future_id;
  async_handle_t* owner;
  char host[256];
  uint16_t port;
  uint32_t flags;
  struct addrinfo* res;
  int gai_err;
} dns_job_t;

#define DNS_JOB_MAX 16
static dns_job_t g_dns_jobs[DNS_JOB_MAX];
static int g_dns_queue[DNS_JOB_MAX];
static int g_dns_q_head = 0;
static int g_dns_q_tail = 0;
static int g_dns_q_count = 0;
static pthread_mutex_t g_dns_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_dns_cv = PTHREAD_COND_INITIALIZER;
static pthread_t g_dns_threads[2];
static pthread_once_t g_dns_once = PTHREAD_ONCE_INIT;

typedef struct {
  int fd;
} tcp_handle_t;

static int32_t tcp_handle_read(void* ctx, void* buf, size_t len) {
  tcp_handle_t* h = (tcp_handle_t*)ctx;
  if (!h || h->fd < 0) return -1;
  ssize_t n = read(h->fd, buf, len);
  if (n < 0) return -1;
  return (int32_t)n;
}

static int32_t tcp_handle_write(void* ctx, const void* buf, size_t len) {
  tcp_handle_t* h = (tcp_handle_t*)ctx;
  if (!h || h->fd < 0) return -1;
  ssize_t n = write(h->fd, buf, len);
  if (n < 0) return -1;
  return (int32_t)n;
}

static void tcp_handle_end(void* ctx) {
  tcp_handle_t* h = (tcp_handle_t*)ctx;
  if (!h) return;
  if (h->fd >= 0) {
    close(h->fd);
    h->fd = -1;
  }
  free(h);
}

static const zi_handle_ops_t k_tcp_ops = {
  .read = tcp_handle_read,
  .write = tcp_handle_write,
  .end = tcp_handle_end,
};

int32_t zi_async_tcp_register_fd(int fd) {
  if (fd < 0) return -1;
  tcp_handle_t* h = (tcp_handle_t*)calloc(1, sizeof(*h));
  if (!h) return -1;
  h->fd = fd;
  int32_t handle = zi_handle_register(&k_tcp_ops, h);
  if (handle < 0) {
    tcp_handle_end(h);
    return -1;
  }
  return handle;
}

static void tcp_pending_close(tcp_pending_t* e) {
  if (!e) return;
  if (e->fd >= 0) {
    close(e->fd);
  }
  if (e->addrs) {
    freeaddrinfo(e->addrs);
  }
  e->in_use = 0;
  e->fd = -1;
  e->future_id = 0;
  e->owner = NULL;
  e->addrs = NULL;
  e->cur = NULL;
  e->flags = 0;
}

int zi_async_tcp_connect_pending_add(void* async_ctx, uint64_t future_id, int fd) {
  async_handle_t* h = (async_handle_t*)async_ctx;
  if (!h || future_id == 0 || fd < 0) return 0;
  for (int i = 0; i < TCP_PENDING_MAX; i++) {
    if (!g_tcp_pending[i].in_use) {
      g_tcp_pending[i].in_use = 1;
      g_tcp_pending[i].fd = fd;
      g_tcp_pending[i].future_id = future_id;
      g_tcp_pending[i].owner = h;
      g_tcp_pending[i].addrs = NULL;
      g_tcp_pending[i].cur = NULL;
      g_tcp_pending[i].flags = 0;
      return 1;
    }
  }
  return 0;
}

int zi_async_tcp_connect_pending_cancel(void* async_ctx, uint64_t future_id) {
  async_handle_t* h = (async_handle_t*)async_ctx;
  if (!h || future_id == 0) return 0;
  for (int i = 0; i < TCP_PENDING_MAX; i++) {
    if (g_tcp_pending[i].in_use &&
        g_tcp_pending[i].future_id == future_id &&
        g_tcp_pending[i].owner == h) {
      tcp_pending_close(&g_tcp_pending[i]);
      return 1;
    }
  }
  return 0;
}

static void* dns_worker_main(void* unused) {
  (void)unused;
  for (;;) {
    int idx = -1;
    pthread_mutex_lock(&g_dns_mu);
    while (g_dns_q_count == 0) {
      pthread_cond_wait(&g_dns_cv, &g_dns_mu);
    }
    idx = g_dns_queue[g_dns_q_head];
    g_dns_q_head = (g_dns_q_head + 1) % DNS_JOB_MAX;
    g_dns_q_count--;
    if (idx < 0 || idx >= DNS_JOB_MAX) {
      pthread_mutex_unlock(&g_dns_mu);
      continue;
    }
    dns_job_t* j = &g_dns_jobs[idx];
    j->queued = 0;
    pthread_mutex_unlock(&g_dns_mu);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)j->port);
    struct addrinfo* res = NULL;
    int e = getaddrinfo(j->host, portbuf, &hints, &res);

    pthread_mutex_lock(&g_dns_mu);
    if (!j->in_use || j->canceled) {
      pthread_mutex_unlock(&g_dns_mu);
      if (res) freeaddrinfo(res);
      continue;
    }
    j->done = 1;
    j->gai_err = e;
    j->res = res;
    pthread_mutex_unlock(&g_dns_mu);
  }
}

static void dns_pool_init(void) {
  for (int i = 0; i < 2; i++) {
    if (pthread_create(&g_dns_threads[i], NULL, dns_worker_main, NULL) == 0) {
      pthread_detach(g_dns_threads[i]);
    }
  }
}

static void ensure_dns_pool_started(void) {
  pthread_once(&g_dns_once, dns_pool_init);
}

int zi_async_tcp_dns_pending_add(void* async_ctx, uint64_t future_id,
                                 const uint8_t* host, uint32_t host_len,
                                 uint16_t port, uint32_t flags) {
  async_handle_t* h = (async_handle_t*)async_ctx;
  if (!h || future_id == 0 || !host || host_len == 0) return 0;
  if (host_len >= sizeof(g_dns_jobs[0].host)) return 0;
  ensure_dns_pool_started();

  pthread_mutex_lock(&g_dns_mu);
  int idx = -1;
  for (int i = 0; i < DNS_JOB_MAX; i++) {
    if (!g_dns_jobs[i].in_use) { idx = i; break; }
  }
  if (idx < 0 || g_dns_q_count >= DNS_JOB_MAX) {
    pthread_mutex_unlock(&g_dns_mu);
    return 0;
  }
  dns_job_t* j = &g_dns_jobs[idx];
  memset(j, 0, sizeof(*j));
  j->in_use = 1;
  j->queued = 1;
  j->future_id = future_id;
  j->owner = h;
  memcpy(j->host, host, host_len);
  j->host[host_len] = '\0';
  j->port = port;
  j->flags = flags;
  g_dns_queue[g_dns_q_tail] = idx;
  g_dns_q_tail = (g_dns_q_tail + 1) % DNS_JOB_MAX;
  g_dns_q_count++;
  pthread_cond_signal(&g_dns_cv);
  pthread_mutex_unlock(&g_dns_mu);
  return 1;
}

int zi_async_tcp_dns_pending_cancel(void* async_ctx, uint64_t future_id) {
  async_handle_t* h = (async_handle_t*)async_ctx;
  if (!h || future_id == 0) return 0;
  pthread_mutex_lock(&g_dns_mu);
  for (int i = 0; i < DNS_JOB_MAX; i++) {
    if (g_dns_jobs[i].in_use && g_dns_jobs[i].future_id == future_id && g_dns_jobs[i].owner == h) {
      g_dns_jobs[i].canceled = 1;
      if (g_dns_jobs[i].res) {
        freeaddrinfo(g_dns_jobs[i].res);
        g_dns_jobs[i].res = NULL;
      }
      g_dns_jobs[i].in_use = 0;
      pthread_mutex_unlock(&g_dns_mu);
      return 1;
    }
  }
  pthread_mutex_unlock(&g_dns_mu);
  return 0;
}

static int set_nonblocking(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0) return 0;
  if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return 0;
  return 1;
}

static int set_blocking(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0) return 0;
  if (fcntl(fd, F_SETFL, fl & ~O_NONBLOCK) < 0) return 0;
  return 1;
}

static int set_nodelay(int fd) {
  int one = 1;
  return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0;
}

static int tcp_pending_start_connect(async_handle_t* owner, uint64_t future_id,
                                     struct addrinfo* addrs, struct addrinfo* start,
                                     uint32_t flags) {
  struct addrinfo* it = start ? start : addrs;
  int last_err = 0;
  while (it) {
    int fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) { last_err = errno; it = it->ai_next; continue; }
    if ((flags & (1u << 2)) != 0) (void)set_nodelay(fd); /* NODELAY */
    if (!set_nonblocking(fd)) { last_err = errno; close(fd); it = it->ai_next; continue; }
    int r = connect(fd, it->ai_addr, it->ai_addrlen);
    if (r == 0) {
      (void)set_blocking(fd);
      int32_t handle = zi_async_tcp_register_fd(fd);
      if (handle < 0) { close(fd); freeaddrinfo(addrs); return async_emit_future_fail(owner, future_id, "t_async_failed", "handle_register"); }
      uint8_t payload[12];
      write_u32_le(payload + 0, (uint32_t)handle);
      write_u32_le(payload + 4, (uint32_t)(STREAM_READABLE | STREAM_WRITABLE | STREAM_ENDABLE));
      write_u32_le(payload + 8, 0u);
      async_emit_future_ok(owner, future_id, payload, sizeof(payload));
      freeaddrinfo(addrs);
      return 1;
    }
    if (r < 0 && errno == EINPROGRESS) {
      for (int i = 0; i < TCP_PENDING_MAX; i++) {
        if (!g_tcp_pending[i].in_use) {
          g_tcp_pending[i].in_use = 1;
          g_tcp_pending[i].fd = fd;
          g_tcp_pending[i].future_id = future_id;
          g_tcp_pending[i].owner = owner;
          g_tcp_pending[i].addrs = addrs;
          g_tcp_pending[i].cur = it;
          g_tcp_pending[i].flags = flags;
          return 1;
        }
      }
      close(fd);
      freeaddrinfo(addrs);
      return async_emit_future_fail(owner, future_id, "t_async_overflow", "net_pending");
    }
    last_err = errno;
    close(fd);
    it = it->ai_next;
  }
  (void)last_err;
  freeaddrinfo(addrs);
  return async_emit_future_fail(owner, future_id, "t_net_unreachable", "connect");
}

static void dns_jobs_pump(void) {
  pthread_mutex_lock(&g_dns_mu);
  for (int i = 0; i < DNS_JOB_MAX; i++) {
    dns_job_t* j = &g_dns_jobs[i];
    if (!j->in_use || !j->done) continue;
    async_handle_t* owner = j->owner;
    uint64_t future_id = j->future_id;
    uint32_t flags = j->flags;
    struct addrinfo* res = j->res;
    int err = j->gai_err;
    j->in_use = 0;
    j->done = 0;
    j->res = NULL;
    pthread_mutex_unlock(&g_dns_mu);

    if (err != 0 || !res) {
      async_emit_future_fail(owner, future_id, "t_net_unreachable", "dns");
    } else {
      tcp_pending_start_connect(owner, future_id, res, res, flags);
    }
    pthread_mutex_lock(&g_dns_mu);
  }
  pthread_mutex_unlock(&g_dns_mu);
}

static void tcp_pending_pump_one(tcp_pending_t* e) {
  if (!e || !e->in_use || !e->owner) return;
  struct pollfd pfd;
  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = e->fd;
  pfd.events = POLLOUT | POLLERR | POLLHUP;
  int r = poll(&pfd, 1, 0);
  if (r <= 0) return;
  if ((pfd.revents & (POLLOUT | POLLERR | POLLHUP)) == 0) return;

  int soerr = 0;
  socklen_t sl = (socklen_t)sizeof(soerr);
  if (getsockopt(e->fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0) {
    soerr = errno;
  }
  if (soerr != 0) {
    close(e->fd);
    e->fd = -1;
    if (e->addrs && e->cur && e->cur->ai_next) {
      /* Try next address. */
      struct addrinfo* next = e->cur->ai_next;
      struct addrinfo* head = e->addrs;
      async_handle_t* owner = e->owner;
      uint64_t fid = e->future_id;
      uint32_t flags = e->flags;
      e->in_use = 0;
      e->addrs = NULL;
      e->cur = NULL;
      e->future_id = 0;
      e->owner = NULL;
      tcp_pending_start_connect(owner, fid, head, next, flags);
      return;
    }
    async_emit_future_fail(e->owner, e->future_id, "t_net_unreachable", "connect");
    tcp_pending_close(e);
    return;
  }

  (void)set_blocking(e->fd);
  int32_t handle = zi_async_tcp_register_fd(e->fd);
  if (handle < 0) {
    async_emit_future_fail(e->owner, e->future_id, "t_async_failed", "handle_register");
    tcp_pending_close(e);
    return;
  }

  uint8_t payload[12];
  write_u32_le(payload + 0, (uint32_t)handle);
  write_u32_le(payload + 4, (uint32_t)(STREAM_READABLE | STREAM_WRITABLE | STREAM_ENDABLE));
  write_u32_le(payload + 8, 0u); /* meta len */
  async_emit_future_ok(e->owner, e->future_id, payload, sizeof(payload));
  e->in_use = 0;
  e->fd = -1; /* ownership moved to handle ctx */
  e->future_id = 0;
  e->owner = NULL;
}

int zi_async_tcp_accept_pending_add(void* async_ctx, uint64_t future_id, int listener_fd) {
  async_handle_t* h = (async_handle_t*)async_ctx;
  if (!h || future_id == 0 || listener_fd < 0) return 0;
  for (int i = 0; i < TCP_ACCEPT_PENDING_MAX; i++) {
    if (!g_tcp_accept_pending[i].in_use) {
      g_tcp_accept_pending[i].in_use = 1;
      g_tcp_accept_pending[i].listener_fd = listener_fd;
      g_tcp_accept_pending[i].future_id = future_id;
      g_tcp_accept_pending[i].owner = h;
      return 1;
    }
  }
  return 0;
}

int zi_async_tcp_accept_pending_cancel(void* async_ctx, uint64_t future_id) {
  async_handle_t* h = (async_handle_t*)async_ctx;
  if (!h || future_id == 0) return 0;
  for (int i = 0; i < TCP_ACCEPT_PENDING_MAX; i++) {
    if (g_tcp_accept_pending[i].in_use &&
        g_tcp_accept_pending[i].future_id == future_id &&
        g_tcp_accept_pending[i].owner == h) {
      g_tcp_accept_pending[i].in_use = 0;
      g_tcp_accept_pending[i].listener_fd = -1;
      g_tcp_accept_pending[i].future_id = 0;
      g_tcp_accept_pending[i].owner = NULL;
      return 1;
    }
  }
  return 0;
}

static void tcp_accept_pending_pump_one(tcp_accept_pending_t* e) {
  if (!e || !e->in_use || !e->owner) return;
  struct pollfd pfd;
  memset(&pfd, 0, sizeof(pfd));
  pfd.fd = e->listener_fd;
  pfd.events = POLLIN | POLLERR | POLLHUP;
  int r = poll(&pfd, 1, 0);
  if (r <= 0) return;
  if ((pfd.revents & (POLLIN | POLLERR | POLLHUP)) == 0) return;

  int fd = accept(e->listener_fd, NULL, NULL);
  if (fd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return;
    async_emit_future_fail(e->owner, e->future_id, "t_net_unreachable", "accept");
    e->in_use = 0;
    e->listener_fd = -1;
    e->future_id = 0;
    e->owner = NULL;
    return;
  }
  (void)set_blocking(fd);
  uint8_t payload[12];
  write_u32_le(payload + 0, (uint32_t)fd);
  write_u32_le(payload + 4, (uint32_t)(STREAM_READABLE | STREAM_WRITABLE | STREAM_ENDABLE));
  write_u32_le(payload + 8, 0u);
  async_emit_future_ok(e->owner, e->future_id, payload, sizeof(payload));
  e->in_use = 0;
  e->listener_fd = -1;
  e->future_id = 0;
  e->owner = NULL;
}

static void tcp_pending_pump(void) {
  dns_jobs_pump();
  for (int i = 0; i < TCP_PENDING_MAX; i++) {
    if (g_tcp_pending[i].in_use) {
      tcp_pending_pump_one(&g_tcp_pending[i]);
    }
  }
  for (int i = 0; i < TCP_ACCEPT_PENDING_MAX; i++) {
    if (g_tcp_accept_pending[i].in_use) {
      tcp_accept_pending_pump_one(&g_tcp_accept_pending[i]);
    }
  }
}

static future_entry_t* future_find(uint64_t id) {
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_futures[i].in_use && g_futures[i].id == id) return &g_futures[i];
  }
  return NULL;
}

static int future_add(uint64_t id, uint64_t scope_id, uint64_t task_id, async_handle_t* owner,
                      uint64_t deadline_ms, int has_deadline,
                      zi_async_cancel_cb cancel_cb, void* cancel_ctx) {
  if (future_find(id)) return 1;
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (!g_futures[i].in_use) {
      g_futures[i].in_use = 1;
      g_futures[i].id = id;
      g_futures[i].canceled = 0;
      g_futures[i].scope_id = scope_id;
      g_futures[i].task_id = task_id;
      g_futures[i].owner = owner;
      g_futures[i].deadline_ms = deadline_ms;
      g_futures[i].has_deadline = has_deadline;
      g_futures[i].cancel_cb = cancel_cb;
      g_futures[i].cancel_ctx = cancel_ctx;
      g_futures[i].cancel_invoked = 0;
      return 1;
    }
  }
  return 0;
}

static void future_cancel(uint64_t id) {
  future_entry_t* f = future_find(id);
  if (f) f->canceled = 1;
}

static void future_clear(uint64_t id) {
  future_entry_t* f = future_find(id);
  if (f) {
    if (f->owner && f->owner->future_count > 0) {
      f->owner->future_count--;
    }
    f->in_use = 0;
    f->id = 0;
    f->canceled = 0;
    f->scope_id = 0;
    f->task_id = 0;
    f->owner = NULL;
    f->deadline_ms = 0;
    f->has_deadline = 0;
    f->cancel_cb = NULL;
    f->cancel_ctx = NULL;
    f->cancel_invoked = 0;
  }
}

static int future_is_canceled(uint64_t id) {
  future_entry_t* f = future_find(id);
  return f ? f->canceled : 0;
}

static int scope_add(uint64_t id) {
  if (id == 0) return 1;
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_scopes[i].in_use && g_scopes[i].id == id) return 1;
  }
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (!g_scopes[i].in_use) {
      g_scopes[i].in_use = 1;
      g_scopes[i].id = id;
      return 1;
    }
  }
  return 0;
}

static int scope_exists(uint64_t id) {
  if (id == 0) return 1;
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_scopes[i].in_use && g_scopes[i].id == id) return 1;
  }
  return 0;
}

static int task_add(uint64_t scope_id, uint64_t task_id) {
  if (task_id == 0) return 1;
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_tasks[i].in_use && g_tasks[i].id == task_id) return 1;
  }
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (!g_tasks[i].in_use) {
      g_tasks[i].in_use = 1;
      g_tasks[i].id = task_id;
      g_tasks[i].scope_id = scope_id;
      g_tasks[i].detached = 0;
      g_tasks[i].owner_len = 0;
      return 1;
    }
  }
  return 0;
}

static int task_exists(uint64_t task_id) {
  if (task_id == 0) return 1;
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_tasks[i].in_use && g_tasks[i].id == task_id) return 1;
  }
  return 0;
}

static void task_detach(uint64_t task_id) {
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_tasks[i].in_use && g_tasks[i].id == task_id) {
      g_tasks[i].detached = 1;
      g_tasks[i].owner_len = 0;
      return;
    }
  }
}

static void scope_resolve(async_handle_t* h, uint64_t scope_id) {
  (void)h;
  if (scope_id == 0) return;
  /* Cancel scoped futures deterministically */
  uint64_t ids[FUTURE_MAX];
  size_t n = 0;
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_futures[i].in_use && g_futures[i].scope_id == scope_id) {
      ids[n++] = g_futures[i].id;
    }
  }
  /* sort ascending */
  for (size_t i = 0; i + 1 < n; i++) {
    for (size_t j = i + 1; j < n; j++) {
      if (ids[j] < ids[i]) { uint64_t tmp = ids[i]; ids[i] = ids[j]; ids[j] = tmp; }
    }
  }
  for (size_t i = 0; i < n; i++) {
    cancel_future_emit(ids[i]);
  }
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_tasks[i].in_use && g_tasks[i].scope_id == scope_id && !g_tasks[i].detached) {
      g_tasks[i].in_use = 0;
      g_tasks[i].id = 0;
      g_tasks[i].scope_id = 0;
      g_tasks[i].detached = 0;
      g_tasks[i].owner_len = 0;
    }
  }
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_futures[i].in_use && g_futures[i].scope_id == scope_id) {
      g_futures[i].in_use = 0;
      g_futures[i].id = 0;
      g_futures[i].scope_id = 0;
      g_futures[i].task_id = 0;
      g_futures[i].owner = NULL;
      g_futures[i].deadline_ms = 0;
      g_futures[i].has_deadline = 0;
    }
  }
}

static void handle_track(async_handle_t* h) {
  if (!h) return;
  if (g_handle_count >= FUTURE_MAX) return;
  g_handle_list[g_handle_count++] = h;
}

static void handle_untrack(async_handle_t* h) {
  if (!h) return;
  for (int i = 0; i < g_handle_count; i++) {
    if (g_handle_list[i] == h) {
      for (int j = i + 1; j < g_handle_count; j++) {
        g_handle_list[j - 1] = g_handle_list[j];
      }
      g_handle_count--;
      break;
    }
  }
}

static void broadcast_cancel(uint64_t future_id) {
  for (int i = 0; i < g_handle_count; i++) {
    if (g_handle_list[i]) {
      enqueue_frame(g_handle_list[i], 2, 112, 0, future_id, NULL, 0);
    }
  }
}

static void cancel_future_emit(uint64_t future_id) {
  future_entry_t* f = future_find(future_id);
  if (!f || !f->in_use) {
    broadcast_cancel(future_id);
    return;
  }
  if (!f->canceled) {
    f->canceled = 1;
    if (f->cancel_cb && !f->cancel_invoked) {
      f->cancel_cb(f->cancel_ctx, future_id);
      f->cancel_invoked = 1;
    }
  }
  broadcast_cancel(future_id);
  future_clear(future_id);
}

static int is_valid_utf8(const uint8_t* p, uint32_t len) {
  uint32_t i = 0;
  while (i < len) {
    uint8_t c = p[i];
    if (c < 0x80) { i++; continue; }
    if ((c >> 5) == 0x6) {
      if (i + 1 >= len) return 0;
      if ((p[i + 1] & 0xc0) != 0x80) return 0;
      i += 2;
    } else if ((c >> 4) == 0xe) {
      if (i + 2 >= len) return 0;
      if ((p[i + 1] & 0xc0) != 0x80 || (p[i + 2] & 0xc0) != 0x80) return 0;
      i += 3;
    } else if ((c >> 3) == 0x1e) {
      if (i + 3 >= len) return 0;
      if ((p[i + 1] & 0xc0) != 0x80 || (p[i + 2] & 0xc0) != 0x80 || (p[i + 3] & 0xc0) != 0x80) return 0;
      i += 4;
    } else {
      return 0;
    }
  }
  return 1;
}

static uint64_t now_ms(void) {
  /* Deterministic clock: advanced only by zi_time_sleep_ms on the guest side. */
  return (uint64_t)(uint32_t)zi_time_now_ms_u32();
}

static int ensure_cap(uint8_t** buf, size_t* cap, size_t need) {
  if (*cap >= need) return 1;
  size_t next = (*cap == 0) ? 256 : *cap * 2;
  while (next < need) next *= 2;
  uint8_t* tmp = (uint8_t*)realloc(*buf, next);
  if (!tmp) return 0;
  *buf = tmp;
  *cap = next;
  return 1;
}

static int enqueue_frame(async_handle_t* h, uint16_t kind, uint16_t op,
                         uint64_t req_id, uint64_t future_id,
                         const uint8_t* payload, uint32_t payload_len) {
  if (!h) return 1;
  uint32_t frame_len = 48 + payload_len;
  if (!ensure_cap(&h->out, &h->out_cap, h->out_len + frame_len)) {
    return 0;
  }
  uint8_t* p = h->out + h->out_len;
  memcpy(p, "ZAX1", 4);
  write_u16_le(p + 4, 1);
  write_u16_le(p + 6, kind);
  write_u16_le(p + 8, op);
  write_u16_le(p + 10, 0);
  write_u64_le(p + 12, req_id);
  write_u64_le(p + 20, 0);
  write_u64_le(p + 28, 0);
  write_u64_le(p + 36, future_id);
  write_u32_le(p + 44, payload_len);
  if (payload_len && payload) {
    memcpy(p + 48, payload, payload_len);
  }
  h->out_len += frame_len;
  return 1;
}

static int enqueue_fail(async_handle_t* h, uint64_t req_id,
                        const char* code, const char* msg) {
  uint32_t code_len = (uint32_t)strlen(code);
  uint32_t msg_len = (uint32_t)strlen(msg);
  uint32_t payload_len = 4 + 4 + code_len + msg_len;
  uint8_t* payload = (uint8_t*)malloc(payload_len);
  if (!payload) return 0;
  write_u32_le(payload + 0, code_len);
  write_u32_le(payload + 4, msg_len);
  memcpy(payload + 8, code, code_len);
  memcpy(payload + 8 + code_len, msg, msg_len);
  int ok = enqueue_frame(h, 2, 102, req_id, 0, payload, payload_len);
  free(payload);
  return ok;
}

static int enqueue_join_limit(async_handle_t* h, uint64_t req_id) {
  const char* code = "t_async_join_limit";
  const char* msg = "join limit exceeded";
  uint32_t code_len = (uint32_t)strlen(code);
  uint32_t msg_len = (uint32_t)strlen(msg);
  uint32_t payload_len = 4 + 4 + code_len + msg_len;
  uint8_t* payload = (uint8_t*)malloc(payload_len);
  if (!payload) return 0;
  write_u32_le(payload + 0, code_len);
  write_u32_le(payload + 4, msg_len);
  memcpy(payload + 8, code, code_len);
  memcpy(payload + 8 + code_len, msg, msg_len);
  int ok = enqueue_frame(h, 2, 121, req_id, 0, payload, payload_len);
  free(payload);
  return ok;
}

static int async_emit_fail(void* ctx, uint64_t req_id,
                           const char* code, const char* msg) {
  return enqueue_fail((async_handle_t*)ctx, req_id, code, msg);
}

static int async_emit_future_ok(void* ctx, uint64_t future_id,
                                const uint8_t* val, uint32_t val_len) {
  if (future_is_canceled(future_id)) { future_clear(future_id); return 1; }
  async_handle_t* h = (async_handle_t*)ctx;
  uint32_t payload_len = 4 + val_len;
  uint8_t* payload = (uint8_t*)malloc(payload_len);
  if (!payload) return 0;
  write_u32_le(payload, val_len);
  if (val_len && val) memcpy(payload + 4, val, val_len);
  int ok = enqueue_frame(h, 2, 110, 0, future_id, payload, payload_len);
  free(payload);
  future_clear(future_id);
  return ok;
}

static int async_emit_future_fail(void* ctx, uint64_t future_id,
                                  const char* code, const char* msg) {
  if (future_is_canceled(future_id)) { future_clear(future_id); return 1; }
  async_handle_t* h = (async_handle_t*)ctx;
  uint32_t code_len = (uint32_t)strlen(code);
  uint32_t msg_len = (uint32_t)strlen(msg);
  uint32_t payload_len = 4 + 4 + code_len + msg_len;
  uint8_t* payload = (uint8_t*)malloc(payload_len);
  if (!payload) return 0;
  write_u32_le(payload + 0, code_len);
  write_u32_le(payload + 4, msg_len);
  memcpy(payload + 8, code, code_len);
  memcpy(payload + 8 + code_len, msg, msg_len);
  int ok = enqueue_frame(h, 2, 111, 0, future_id, payload, payload_len);
  free(payload);
  future_clear(future_id);
  return ok;
}

static int handle_register_future(async_handle_t* h,
                                  const uint8_t* payload, uint32_t payload_len,
                                  uint64_t req_id, uint64_t future_id,
                                  uint64_t scope_id, uint64_t task_id,
                                  uint64_t deadline_ms, int has_deadline) {
  if (h->future_count >= FUTURE_PER_HANDLE_MAX) {
    return enqueue_fail(h, req_id, "t_async_overflow", "futures_per_handle");
  }
  if (payload_len > ASYNC_MAX_PAYLOAD) return enqueue_fail(h, req_id, "t_async_payload", "too big");
  if (!scope_add(scope_id)) {
    return enqueue_fail(h, req_id, "t_async_overflow", "scopes");
  }
  if (!task_add(scope_id, task_id)) {
    return enqueue_fail(h, req_id, "t_async_overflow", "tasks");
  }
  if (payload_len < 5) return enqueue_fail(h, req_id, "t_async_bad_params", "too short");
  uint32_t off = 0;
  uint8_t variant = payload[off++];
  if (variant == 1) {
    /* Opaque source: not implemented, respond fail + ack. */
    async_emit_future_fail(h, future_id, "t_async_unimplemented", "opaque");
    if (req_id != 0) enqueue_frame(h, 2, 101, req_id, future_id, NULL, 0);
    future_clear(future_id);
    h->future_count++;
    return 1;
  }
  if (variant != 2) return enqueue_fail(h, req_id, "t_async_unknown_source", "variant");
  if (off + 4 > payload_len) return enqueue_fail(h, req_id, "t_async_bad_params", "body len");
  uint32_t body_len = read_u32_le(payload + off); off += 4;
  if (off + body_len != payload_len) return enqueue_fail(h, req_id, "t_async_bad_params", "body size");
  uint32_t end = off + body_len;
  if (off + 4 > end) return enqueue_fail(h, req_id, "t_async_bad_params", "kind len");
  uint32_t kind_len = read_u32_le(payload + off); off += 4;
  if (off + kind_len > end) return enqueue_fail(h, req_id, "t_async_bad_params", "kind bytes");
  const uint8_t* kind = payload + off; off += kind_len;
  if (off + 4 > end) return enqueue_fail(h, req_id, "t_async_bad_params", "name len");
  uint32_t name_len = read_u32_le(payload + off); off += 4;
  if (off + name_len > end) return enqueue_fail(h, req_id, "t_async_bad_params", "name bytes");
  const uint8_t* name = payload + off; off += name_len;
  if (off + 4 > end) return enqueue_fail(h, req_id, "t_async_bad_params", "selector len");
  uint32_t selector_len = read_u32_le(payload + off); off += 4;
  if (off + selector_len > end) return enqueue_fail(h, req_id, "t_async_bad_params", "selector bytes");
  const uint8_t* selector = payload + off; off += selector_len;
  if (off + 4 > end) return enqueue_fail(h, req_id, "t_async_bad_params", "params len");
  uint32_t params_len = read_u32_le(payload + off); off += 4;
  if (off + params_len != end) return enqueue_fail(h, req_id, "t_async_bad_params", "params bytes");
  if (params_len > ASYNC_MAX_PAYLOAD) return enqueue_fail(h, req_id, "t_async_payload", "params");
  const zi_async_selector* sel = zi_async_find((const char*)kind, kind_len,
                                               (const char*)name, name_len,
                                               (const char*)selector, selector_len);
  if (!sel || !sel->invoke) {
    async_emit_future_fail(h, future_id, "t_async_unimplemented", "selector");
    future_clear(future_id);
    return enqueue_fail(h, req_id, "t_async_unimplemented", "selector");
  }
  zi_async_cancel_cb cancel_cb = sel->cancel;
  void* cancel_ctx = h;
  zi_async_emit emit = {
    .ack = NULL,
    .fail = async_emit_fail,
    .future_ok = async_emit_future_ok,
    .future_fail = async_emit_future_fail,
    .future_cancel = NULL,
  };
  if (req_id != 0) {
    if (!enqueue_frame(h, 2, 101, req_id, future_id, NULL, 0)) return 0;
  }
  /* register future before invoking selector */
  if (!future_add(future_id, scope_id, task_id, h, deadline_ms, has_deadline, cancel_cb, cancel_ctx)) {
    return enqueue_fail(h, req_id, "t_async_overflow", "futures");
  }
  h->future_count++;
  int ok = sel->invoke(&emit, h, payload + off, params_len, req_id, future_id);
  if (!ok) {
    if (req_id != 0) enqueue_fail(h, req_id, "t_async_failed", "handler failed");
    future_clear(future_id);
    return 1;
  }
  return 1;
}

static void drop_future_frames(async_handle_t* h, uint64_t future_id) {
  size_t pos = h->out_pos;
  while (pos + 48 <= h->out_len) {
    const uint8_t* p = h->out + pos;
    if (p[0]!='Z'||p[1]!='A'||p[2]!='X'||p[3]!='1') break;
    uint32_t plen = read_u32_le(p + 44);
    size_t frame_len = 48u + plen;
    if (pos + frame_len > h->out_len) break;
    uint16_t kind = (uint16_t)(p[6] | (p[7] << 8));
    uint16_t op = (uint16_t)(p[8] | (p[9] << 8));
    uint64_t fid = read_u32_le(p + 36) | ((uint64_t)read_u32_le(p + 40) << 32);
    if (kind == 2 && (op == 110 || op == 111) && fid == future_id) {
      memmove(h->out + pos, h->out + pos + frame_len, h->out_len - (pos + frame_len));
      h->out_len -= frame_len;
      continue;
    }
    pos += frame_len;
  }
}

static int handle_cancel(async_handle_t* h, uint64_t req_id, uint64_t future_id) {
  future_cancel(future_id);
  drop_future_frames(h, future_id);
  cancel_future_emit(future_id);
  if (req_id != 0) enqueue_frame(h, 2, 101, req_id, future_id, NULL, 0);
  return 1;
}

static int handle_detach(async_handle_t* h, uint64_t req_id) {
  if (!task_exists(h->task_id)) {
    return enqueue_fail(h, req_id, "t_async_unknown_task", "detach");
  }
  task_detach(h->task_id);
  if (req_id != 0) enqueue_frame(h, 2, 101, req_id, 0, NULL, 0);
  return 1;
}

static int handle_join(async_handle_t* h, uint64_t req_id, const uint8_t* payload, uint32_t payload_len,
                       uint16_t timeout_ms, uint64_t scope_id) {
  uint64_t join_scope = (scope_id != 0) ? scope_id : h->scope_id;
  if (!scope_exists(join_scope)) {
    return enqueue_fail(h, req_id, "t_async_unknown_scope", "join");
  }
  if (payload_len != 8) {
    return enqueue_fail(h, req_id, "t_async_bad_params", "join payload");
  }
  uint64_t fuel = (uint64_t)read_u32_le(payload) | ((uint64_t)read_u32_le(payload + 4) << 32);
  /* fuel==0 and pending futures => join_limit */
  uint32_t pending = 0;
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_futures[i].in_use && g_futures[i].scope_id == join_scope) pending++;
  }
  if (pending > fuel) {
    enqueue_join_limit(h, req_id);
    return 1;
  }
  if (timeout_ms > 0 && pending > 0) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    while (pending > 0) {
      tcp_pending_pump();
      sweep_deadlines();
      pending = 0;
      for (int i = 0; i < FUTURE_MAX; i++) {
        if (g_futures[i].in_use && g_futures[i].scope_id == join_scope) pending++;
      }
      if (pending == 0) break;
      uint64_t nowv = now_ms();
      if (nowv >= deadline) break;
      /* Advance deterministic time and yield. */
      (void)zi_time_sleep_ms(1u);
    }
    if (pending > 0) {
      enqueue_join_limit(h, req_id);
      return 1;
    }
  }
  scope_resolve(h, join_scope);
  enqueue_frame(h, 2, 120, req_id, 0, NULL, 0);
  return 1;
}

static int async_handle_write(void* ctx, const void* buf, size_t len) {
  async_handle_t* h = (async_handle_t*)ctx;
  tcp_pending_pump();
  sweep_deadlines();
  /* Parse complete frames; assume single frame for test simplicity. */
  if (len < 48) { return -1; }
  const uint8_t* p = (const uint8_t*)buf;
  if (p[0]!='Z'||p[1]!='A'||p[2]!='X'||p[3]!='1') { return -1; }
  uint16_t kind = (uint16_t)(p[6] | (p[7] << 8));
  uint16_t op = (uint16_t)(p[8] | (p[9] << 8));
  uint16_t timeout_ms = (uint16_t)(p[10] | (p[11] << 8));
  uint64_t req_id = read_u32_le(p + 12) | ((uint64_t)read_u32_le(p + 16) << 32);
  uint64_t scope_id = read_u32_le(p + 20) | ((uint64_t)read_u32_le(p + 24) << 32);
  uint64_t task_id = read_u32_le(p + 28) | ((uint64_t)read_u32_le(p + 32) << 32);
  uint64_t future_id = read_u32_le(p + 36) | ((uint64_t)read_u32_le(p + 40) << 32);
  uint32_t payload_len = read_u32_le(p + 44);
  if (48u + payload_len > len) {
    return -1;
  }
  if (payload_len > ASYNC_MAX_PAYLOAD) {
    enqueue_fail(h, req_id, "t_async_payload", "too big");
    return (int32_t)len;
  }
  const uint8_t* payload = p + 48;
  if (kind != 1) { return -1; }
  if (op == OP_REGISTER) {
    uint64_t deadline = 0;
    int has_deadline = 0;
    if (timeout_ms > 0) {
      deadline = now_ms() + (uint64_t)timeout_ms;
      has_deadline = 1;
    }
    h->scope_id = scope_id;
    h->task_id = task_id;
    if (!handle_register_future(h, payload, payload_len, req_id, future_id, scope_id, task_id, deadline, has_deadline)) return -1;
  } else if (op == OP_CANCEL) {
    if (!handle_cancel(h, req_id, future_id)) return -1;
  } else if (op == OP_DETACH) {
    if (payload_len < 4) return enqueue_fail(h, req_id, "t_async_bad_params", "detach payload"), (int32_t)len;
    uint32_t owner_len = read_u32_le(payload);
    if (4u + owner_len != payload_len) return enqueue_fail(h, req_id, "t_async_bad_params", "detach payload"), (int32_t)len;
    if (owner_len > sizeof(g_tasks[0].owner)) return enqueue_fail(h, req_id, "t_async_bad_params", "owner too long"), (int32_t)len;
    if (!is_valid_utf8(payload + 4, owner_len)) return enqueue_fail(h, req_id, "t_async_bad_params", "owner utf8"), (int32_t)len;
    /* store owner */
    for (int i = 0; i < FUTURE_MAX; i++) {
      if (g_tasks[i].in_use && g_tasks[i].id == h->task_id) {
        memcpy(g_tasks[i].owner, payload + 4, owner_len);
        g_tasks[i].owner_len = owner_len;
        g_tasks[i].owner[owner_len < sizeof(g_tasks[i].owner) ? owner_len : sizeof(g_tasks[i].owner)-1] = '\0';
        break;
      }
    }
    if (!handle_detach(h, req_id)) return -1;
  } else if (op == OP_JOIN) {
    if (!handle_join(h, req_id, payload, payload_len, timeout_ms, scope_id)) return -1;
  } else {
    if (!enqueue_fail(h, req_id, "t_async_unknown_op", "op")) return -1;
  }
  return (int32_t)len;
}

static int async_handle_read(void* ctx, void* buf, size_t len) {
  async_handle_t* h = (async_handle_t*)ctx;
  tcp_pending_pump();
  sweep_deadlines();
  if (!h || !buf || len == 0) return -1;
  size_t avail = (h->out_len > h->out_pos) ? (h->out_len - h->out_pos) : 0;
  if (avail == 0) return 0;
  size_t n = (len < avail) ? len : avail;
  memcpy(buf, h->out + h->out_pos, n);
  h->out_pos += n;
  return (int32_t)n;
}

static void async_handle_end(void* ctx) {
  async_handle_t* h = (async_handle_t*)ctx;
  if (!h) return;
  /* Clear any futures tied to this handle to avoid leaks. */
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_futures[i].in_use && g_futures[i].owner == h) {
      cancel_future_emit(g_futures[i].id);
    }
  }
  for (int i = 0; i < TCP_PENDING_MAX; i++) {
    if (g_tcp_pending[i].in_use && g_tcp_pending[i].owner == h) {
      tcp_pending_close(&g_tcp_pending[i]);
    }
  }
  for (int i = 0; i < TCP_ACCEPT_PENDING_MAX; i++) {
    if (g_tcp_accept_pending[i].in_use && g_tcp_accept_pending[i].owner == h) {
      g_tcp_accept_pending[i].in_use = 0;
      g_tcp_accept_pending[i].listener_fd = -1;
      g_tcp_accept_pending[i].future_id = 0;
      g_tcp_accept_pending[i].owner = NULL;
    }
  }
  handle_untrack(h);
  free(h->out);
  free(h);
}

static void sweep_deadlines(void) {
  tcp_pending_pump();
  uint64_t now_ms_val = now_ms();
  for (int i = 0; i < FUTURE_MAX; i++) {
    if (g_futures[i].in_use && g_futures[i].has_deadline && !g_futures[i].canceled) {
      if (now_ms_val >= g_futures[i].deadline_ms) {
        cancel_future_emit(g_futures[i].id);
      }
    }
  }
}

static const zi_handle_ops_t k_async_ops = {
  .read = async_handle_read,
  .write = async_handle_write,
  .end = async_handle_end,
};

static int cap_async_describe(uint8_t* out, size_t cap,
                              uint16_t op, uint32_t rid,
                              const uint8_t* payload, uint32_t payload_len) {
  (void)payload;
  (void)payload_len;
  uint8_t pl[28];
  pl[0] = 1; pl[1] = 0; pl[2] = 0; pl[3] = 0; /* ok */
  ctl_write_u32(pl + 4, CAP_FLAG_CAN_OPEN);
  ctl_write_u32(pl + 8, 16); /* meta schema len */
  ctl_write_u32(pl + 12, ASYNC_MAX_PAYLOAD);
  ctl_write_u32(pl + 16, FUTURE_PER_HANDLE_MAX);
  ctl_write_u32(pl + 20, 65536); /* event queue bytes */
  ctl_write_u32(pl + 24, ASYNC_META_FLAG_TIMEOUT | ASYNC_META_FLAG_BROADCAST | ASYNC_META_FLAG_CANCEL_CB);
  return ctl_write_ok(out, cap, op, rid, pl, 28);
}

static int cap_async_open(uint8_t* out, size_t cap,
                          uint16_t op, uint32_t rid,
                          const uint8_t* payload, uint32_t payload_len) {
  (void)payload;
  (void)payload_len;
  async_handle_t* h = (async_handle_t*)calloc(1, sizeof(async_handle_t));
  if (!h) {
    return ctl_write_error(out, cap, op, rid, "t_ctl_overflow", "no mem");
  }
  int32_t handle = zi_handle_register(&k_async_ops, h);
  if (handle < 0) {
    free(h);
    return ctl_write_error(out, cap, op, rid, "t_ctl_overflow", "handles");
  }
  handle_track(h);
  uint8_t pl[32];
  pl[0] = 1; pl[1] = 0; pl[2] = 0; pl[3] = 0; /* ok */
  ctl_write_u32(pl + 4, (uint32_t)handle);
  ctl_write_u32(pl + 8, HFLAG_READABLE | HFLAG_WRITABLE);
  ctl_write_u32(pl + 12, 16); /* meta len */
  ctl_write_u32(pl + 16, ASYNC_MAX_PAYLOAD);
  ctl_write_u32(pl + 20, FUTURE_PER_HANDLE_MAX);
  ctl_write_u32(pl + 24, 65536);
  ctl_write_u32(pl + 28, ASYNC_META_FLAG_TIMEOUT | ASYNC_META_FLAG_BROADCAST | ASYNC_META_FLAG_CANCEL_CB);
  return ctl_write_ok(out, cap, op, rid, pl, 32);
}

/* ABI v2: direct syscall open (no ZCL1 framing). */
int32_t zi_cap_async_open_default(uint32_t *out_hflags) {
  async_handle_t* h = (async_handle_t*)calloc(1, sizeof(async_handle_t));
  if (!h) {
    return -1;
  }
  int32_t handle = zi_handle_register(&k_async_ops, h);
  if (handle < 0) {
    free(h);
    return -1;
  }
  handle_track(h);
  if (out_hflags) {
    *out_hflags = HFLAG_READABLE | HFLAG_WRITABLE;
  }
  return handle;
}

static const zi_cap_v1 cap_async_default_v1 = {
  .kind = "async",
  .name = "default",
  .version = 1,
  .cap_flags = CAP_FLAG_CAN_OPEN,
  .meta = NULL,
  .meta_len = 0,
  .describe = cap_async_describe,
  .open = cap_async_open,
};

__attribute__((constructor))
static void cap_async_autoreg(void) {
  zi_cap_register(&cap_async_default_v1);
}
