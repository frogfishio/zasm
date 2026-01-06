/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include "lembeh_cloak.h"
#include "zxc.h"

static uint8_t* g_mem;
static size_t g_mem_cap;

static int32_t host_req_read(int32_t req, int32_t ptr, int32_t cap) {
  (void)req; (void)ptr; (void)cap; return 0;
}

static int32_t host_res_write(int32_t res, int32_t ptr, int32_t len) {
  (void)res;
  if (ptr < 0 || len < 0) return -1;
  size_t off = (size_t)ptr;
  size_t n = (size_t)len;
  if (!g_mem || off + n > g_mem_cap) return -1;
  fprintf(stderr, "host_res_write ptr=%zu len=%zu\n", off, n);
  size_t wrote = fwrite(g_mem + off, 1, n, stdout);
  fflush(stdout);
  return (int32_t)wrote;
}

static void host_res_end(int32_t res) { (void)res; }

static void host_log(int32_t tptr, int32_t tlen, int32_t mptr, int32_t mlen) {
  (void)tptr; (void)tlen; (void)mptr; (void)mlen;
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

static int32_t host_ctl(int32_t rptr, int32_t rlen, int32_t sptr, int32_t scap) {
  (void)rptr; (void)rlen; (void)sptr; (void)scap; return -1;
}

static int read_container(const char* path, uint8_t** out_buf, size_t* out_len) {
  FILE* f = fopen(path, "rb");
  if (!f) return errno ? errno : 1;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return errno ? errno : 1; }
  long sz = ftell(f);
  if (sz < 0) { fclose(f); return errno ? errno : 1; }
  if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return errno ? errno : 1; }
  uint8_t* buf = (uint8_t*)malloc((size_t)sz);
  if (!buf) { fclose(f); return ENOMEM; }
  size_t got = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  if (got != (size_t)sz) { free(buf); return EIO; }
  *out_buf = buf;
  *out_len = (size_t)sz;
  return 0;
}

static void guest_trampoline(void (*fn)(int32_t, int32_t)) {
  fn(0, 0);
}

static void alarm_handler(int sig) {
  (void)sig;
  fprintf(stderr, "timeout\n");
  _exit(1);
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s guest.zasm.bin\n", argv[0]);
    return 1;
  }
  const char* path = argv[1];

  uint8_t* buf = NULL;
  size_t buf_len = 0;
  int rc = read_container(path, &buf, &buf_len);
  if (rc != 0) {
    fprintf(stderr, "read_container failed (%d)\n", rc);
    return 1;
  }
  if (buf_len < 16 || memcmp(buf, "ZASB", 4) != 0) {
    fprintf(stderr, "bad container header\n");
    free(buf);
    return 1;
  }
  uint32_t code_len = 0;
  memcpy(&code_len, buf + 12, 4);
  const uint8_t* payload = buf + 16;
  size_t payload_len = (size_t)code_len;
  if (buf_len < 16 + payload_len) {
    fprintf(stderr, "container length mismatch (too small)\n");
    free(buf);
    return 1;
  }
  size_t trailing_len = buf_len - (16 + payload_len);
  if (trailing_len > 0) {
    fprintf(stderr, "info: copying %zu trailing data byte(s) after opcode region\n", trailing_len);
  }
  if ((payload_len % 4) != 0) {
    fprintf(stderr, "opcode payload not 4-byte aligned\n");
    free(buf);
    return 1;
  }

  g_mem_cap = 2 * 1024 * 1024; /* 2MB */
  g_mem = (uint8_t*)calloc(1, g_mem_cap);
  if (!g_mem) {
    fprintf(stderr, "alloc guest mem failed\n");
    free(buf);
    return 1;
  }
  lembeh_bind_memory(g_mem, g_mem_cap);

  if (trailing_len > 0) {
    if (payload_len + trailing_len > g_mem_cap) {
      fprintf(stderr, "guest memory too small for trailing data\n");
      free(g_mem);
      free(buf);
      return 1;
    }
    memcpy(g_mem + payload_len, payload + payload_len, trailing_len);
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

  signal(SIGALRM, alarm_handler);
  alarm(3);

  size_t out_cap = payload_len * 8 + 4096;
  uint8_t* out = (uint8_t*)mmap(NULL, out_cap, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANON, -1, 0);
  if (out == MAP_FAILED) {
    fprintf(stderr, "mmap failed\n");
    free(g_mem);
    free(buf);
    return 1;
  }

  zxc_result_t res = zxc_arm64_translate(payload, payload_len,
                                         out, out_cap,
                                         (uint64_t)(uintptr_t)g_mem, g_mem_cap,
                                         &host);
  if (res.err != ZXC_OK) {
    fprintf(stderr, "zxc translate failed: err=%d at %zu\n", res.err, res.in_off);
    munmap(out, out_cap);
    free(g_mem);
    free(buf);
    return 1;
  }

  FILE* dump = fopen("/tmp/native.out", "wb");
  if (dump) {
    fwrite(out, 1, res.out_len, dump);
    fclose(dump);
    fprintf(stderr, "dumped %zu bytes of code to /tmp/native.out\n", res.out_len);
  }

  __builtin___clear_cache((char*)out, (char*)out + res.out_len);

  if (mprotect(out, out_cap, PROT_READ | PROT_EXEC) != 0) {
    fprintf(stderr, "mprotect failed\n");
    munmap(out, out_cap);
    free(g_mem);
    free(buf);
    return 1;
  }

  typedef void (*guest_fn)(int32_t, int32_t);

  guest_fn entry = (guest_fn)out;
  fprintf(stderr, "entering guest...\n");
  guest_trampoline(entry);
  fprintf(stderr, "guest returned\n");

  munmap(out, out_cap);
  free(g_mem);
  free(buf);
  return 0;
}
