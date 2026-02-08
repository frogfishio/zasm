/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "version.h"
#include "zasm_rt.h"
#include "zi_hostlib25.h"

extern char **environ;

static void print_help(FILE *out) {
  fprintf(out,
          "zrt — run a .zasm.bin v2 container via zasm_rt\n"
          "\n"
          "Usage:\n"
          "  zrt <program.zasm.bin>\n"
          "\n"
          "Options:\n"
          "  --help        Show this help message\n"
          "  --version     Show version information\n");
}

static void print_version(void) {
  fprintf(stdout, "zrt %s\n", ZASM_VERSION);
}

static int read_whole_file(const char *path, uint8_t **out_buf, size_t *out_len) {
  if (!path || !out_buf || !out_len) return 0;
  *out_buf = NULL;
  *out_len = 0;

  int fd = open(path, O_RDONLY);
  if (fd < 0) return 0;

  struct stat st;
  if (fstat(fd, &st) != 0) {
    close(fd);
    return 0;
  }

  if (st.st_size < 0) {
    close(fd);
    return 0;
  }

  size_t cap = (size_t)st.st_size;
  if (cap == 0) {
    close(fd);
    return 0;
  }

  uint8_t *buf = (uint8_t *)malloc(cap);
  if (!buf) {
    close(fd);
    return 0;
  }

  size_t off = 0;
  while (off < cap) {
    ssize_t n = read(fd, buf + off, cap - off);
    if (n == 0) break;
    if (n < 0) {
      free(buf);
      close(fd);
      return 0;
    }
    off += (size_t)n;
  }

  close(fd);

  if (off != cap) {
    free(buf);
    return 0;
  }

  *out_buf = buf;
  *out_len = cap;
  return 1;
}

static void print_diag(const zasm_rt_diag_t *d) {
  if (!d) return;

  if (d->err == ZASM_RT_ERR_BAD_CONTAINER) {
    fprintf(stderr, "diag: container: bin_err=%d off=%u tag=%s\n",
            (int)d->bin_err, d->bin_off, d->bin_tag);
  }

  if (d->err == ZASM_RT_ERR_VERIFY_FAIL) {
    fprintf(stderr, "diag: verify: err=%d off=%zu opcode=0x%02x\n",
            (int)d->verify_err, d->verify_off, (unsigned)d->verify_opcode);
  }
}

int main(int argc, char **argv) {
  if (argc < 2) {
    print_help(stderr);
    return 2;
  }

  if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
    print_help(stdout);
    return 0;
  }

  if (strcmp(argv[1], "--version") == 0) {
    print_version();
    return 0;
  }

  const char *path = argv[1];

  if (!zi_hostlib25_init_all(argc, (const char *const *)argv, (const char *const *)environ)) {
    fprintf(stderr, "zrt: error: zi_hostlib25_init_all failed\n");
    return 1;
  }

  uint8_t *file = NULL;
  size_t file_len = 0;
  if (!read_whole_file(path, &file, &file_len)) {
    fprintf(stderr, "zrt: error: failed to read '%s' (%s)\n", path, strerror(errno));
    return 1;
  }

  zasm_rt_engine_t *engine = NULL;
  zasm_rt_err_t e = zasm_rt_engine_create(&engine);
  if (e != ZASM_RT_OK) {
    fprintf(stderr, "zrt: error: engine_create: %s\n", zasm_rt_err_str(e));
    free(file);
    return 1;
  }

  zasm_rt_diag_t diag;
  zasm_rt_module_t *module = NULL;
  e = zasm_rt_module_load_v2(engine, file, file_len, NULL, &module, &diag);
  free(file);
  if (e != ZASM_RT_OK) {
    fprintf(stderr, "zrt: error: module_load_v2: %s\n", zasm_rt_err_str(e));
    print_diag(&diag);
    zasm_rt_engine_destroy(engine);
    return 1;
  }

  const zi_host_v1 *host = zi_runtime25_host();
  zasm_rt_instance_t *inst = NULL;
  e = zasm_rt_instance_create(engine, module, NULL, host, &inst, &diag);
  if (e != ZASM_RT_OK) {
    fprintf(stderr, "zrt: error: instance_create: %s\n", zasm_rt_err_str(e));
    print_diag(&diag);
    zasm_rt_module_destroy(module);
    zasm_rt_engine_destroy(engine);
    return 1;
  }

  e = zasm_rt_instance_run(inst, &diag);
  if (e != ZASM_RT_OK) {
    fprintf(stderr, "zrt: error: instance_run: %s\n", zasm_rt_err_str(e));
    print_diag(&diag);
    zasm_rt_instance_destroy(inst);
    zasm_rt_module_destroy(module);
    zasm_rt_engine_destroy(engine);
    return 1;
  }

  zasm_rt_instance_destroy(inst);
  zasm_rt_module_destroy(module);
  zasm_rt_engine_destroy(engine);
  return 0;
}
