/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "lembeh_cloak.h"

typedef void (*lembeh_handle_t)(int32_t req, int32_t res);

static uint8_t* g_mem = NULL;
static size_t g_mem_cap = 0;

static int32_t host_req_read(int32_t req, int32_t ptr, int32_t cap) {
  (void)req;
  (void)ptr;
  (void)cap;
  return 0; /* stub */
}

static int32_t host_res_write(int32_t res, int32_t ptr, int32_t len) {
  (void)res;
  (void)ptr;
  return len; /* stub that “writes” len bytes */
}

static void host_res_end(int32_t res) { (void)res; }

static void host_log(int32_t topic_ptr, int32_t topic_len, int32_t msg_ptr, int32_t msg_len) {
  (void)topic_ptr;
  (void)topic_len;
  (void)msg_ptr;
  (void)msg_len;
}

static int32_t host_alloc(int32_t size) {
  static int32_t head = 0;
  int32_t aligned = (size + 3) & ~3;
  if (!g_mem || (size_t)(head + aligned) > g_mem_cap) return -1;
  int32_t out = head;
  head += aligned;
  return out;
}

static void host_free(int32_t ptr) { (void)ptr; }

static int32_t host_ctl(int32_t req_ptr, int32_t req_len, int32_t resp_ptr, int32_t resp_cap) {
  (void)req_ptr;
  (void)req_len;
  (void)resp_ptr;
  (void)resp_cap;
  return -1;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s guest.dylib\n", argv[0]);
    return 1;
  }
  const char* path = argv[1];

  g_mem_cap = 2 * 1024 * 1024; /* 2MB */
  g_mem = (uint8_t*)malloc(g_mem_cap);
  if (!g_mem) {
    perror("malloc");
    return 1;
  }

  lembeh_host_vtable_t host = {
    .req_read = host_req_read,
    .res_write = host_res_write,
    .res_end = host_res_end,
    .log = host_log,
    .alloc = host_alloc,
    .free = host_free,
    .ctl = host_ctl,
  };
  lembeh_bind_host(&host);
  lembeh_bind_memory(g_mem, g_mem_cap);

  void* h = dlopen(path, RTLD_NOW);
  if (!h) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    free(g_mem);
    return 1;
  }
  lembeh_handle_t entry = (lembeh_handle_t)dlsym(h, "lembeh_handle");
  if (!entry) {
    fprintf(stderr, "missing lembeh_handle\n");
    dlclose(h);
    free(g_mem);
    return 1;
  }

  int rc = lembeh_invoke(entry, 0, 0);
  dlclose(h);
  free(g_mem);
  return rc;
}
