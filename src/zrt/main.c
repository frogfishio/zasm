/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
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
          "  --help             Show this help message\n"
          "  --version          Show version information\n"
          "  --safe             Apply tighter caps; disable primitives by default\n"
          "  --allow-primitives Allow host primitive calls (overrides --safe)\n"
          "  --timeout-ms <n>   Kill the guest after n milliseconds\n"
          "  --fuel <n>         Trap after n guest instructions (0 = unlimited)\n");
}

static void print_version(void) {
  fprintf(stdout, "zrt %s\n", ZASM_VERSION);
}

static const char* zxc_err_str_local(uint32_t err) {
  switch (err) {
    case 0: return "ok";
    case 1: return "trunc";
    case 2: return "align";
    case 3: return "outbuf";
    case 4: return "opcode";
    case 5: return "unimpl";
    default: return "unknown";
  }
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

  if (d->err == ZASM_RT_ERR_TRANSLATE_FAIL) {
    fprintf(stderr, "diag: translate: err=%u(%s) off=%zu opcode=0x%02x insn=0x%08x\n",
            (unsigned)d->translate_err, zxc_err_str_local(d->translate_err),
            d->translate_off, (unsigned)d->translate_opcode,
            (unsigned)d->translate_insn);
  }
}

static uint64_t monotonic_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static int run_guest(const char *path, int safe_mode, int allow_primitives, uint64_t timeout_ms, uint64_t fuel) {
  (void)timeout_ms;

  if (!zi_hostlib25_init_all(1, (const char *const *)&path, (const char *const *)environ)) {
    fprintf(stderr, "zrt: error: zi_hostlib25_init_all failed\n");
    return 1;
  }

  uint8_t *file = NULL;
  size_t file_len = 0;
  if (!read_whole_file(path, &file, &file_len)) {
    fprintf(stderr, "zrt: error: failed to read '%s' (%s)\n", path, strerror(errno));
    return 1;
  }

  zasm_rt_policy_t policy = zasm_rt_policy_default;
  if (safe_mode) {
    policy.strict = 1;
    policy.allow_primitives = 0;
    /* Fail-closed caps for untrusted inputs. */
    policy.max_file_len = 4u * 1024u * 1024u;
    policy.max_code_len = 2u * 1024u * 1024u;
    policy.max_insn_words = policy.max_code_len / 4u;
  }
  if (allow_primitives) policy.allow_primitives = 1;
  policy.fuel = fuel;

  zasm_rt_engine_t *engine = NULL;
  zasm_rt_err_t e = zasm_rt_engine_create(&engine);
  if (e != ZASM_RT_OK) {
    fprintf(stderr, "zrt: error: engine_create: %s\n", zasm_rt_err_str(e));
    free(file);
    return 1;
  }

  zasm_rt_diag_t diag;
  zasm_rt_module_t *module = NULL;
  e = zasm_rt_module_load_v2(engine, file, file_len, &policy, &module, &diag);
  free(file);
  if (e != ZASM_RT_OK) {
    fprintf(stderr, "zrt: error: module_load_v2: %s\n", zasm_rt_err_str(e));
    print_diag(&diag);
    zasm_rt_engine_destroy(engine);
    return 1;
  }

  const zi_host_v1 *host = zi_runtime25_host();
  zasm_rt_instance_t *inst = NULL;
  e = zasm_rt_instance_create(engine, module, &policy, host, &inst, &diag);
  if (e != ZASM_RT_OK) {
    fprintf(stderr, "zrt: error: instance_create: %s\n", zasm_rt_err_str(e));
    print_diag(&diag);
    zasm_rt_module_destroy(module);
    zasm_rt_engine_destroy(engine);
    return 1;
  }

  e = zasm_rt_instance_run(inst, &diag);
  if (e != ZASM_RT_OK) {
    if (e == ZASM_RT_ERR_EXEC_FAIL) {
      switch (diag.trap) {
        case ZASM_RT_TRAP_FUEL:
          fprintf(stderr, "zrt: trap: fuel exhausted\n");
          zasm_rt_instance_destroy(inst);
          zasm_rt_module_destroy(module);
          zasm_rt_engine_destroy(engine);
          return 1;
        case ZASM_RT_TRAP_OOB:
          fprintf(stderr, "zrt: trap: out of bounds memory access\n");
          zasm_rt_instance_destroy(inst);
          zasm_rt_module_destroy(module);
          zasm_rt_engine_destroy(engine);
          return 1;
        case ZASM_RT_TRAP_DIV0:
          fprintf(stderr, "zrt: trap: division by zero\n");
          zasm_rt_instance_destroy(inst);
          zasm_rt_module_destroy(module);
          zasm_rt_engine_destroy(engine);
          return 1;
        default:
          fprintf(stderr, "zrt: trap\n");
          zasm_rt_instance_destroy(inst);
          zasm_rt_module_destroy(module);
          zasm_rt_engine_destroy(engine);
          return 1;
      }
    }
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

static int run_guest_isolated(const char *path, int safe_mode, int allow_primitives, uint64_t timeout_ms, uint64_t fuel) {
  pid_t pid = fork();
  if (pid < 0) {
    fprintf(stderr, "zrt: error: fork failed (%s)\n", strerror(errno));
    return 1;
  }
  if (pid == 0) {
    int rc = run_guest(path, safe_mode, allow_primitives, timeout_ms, fuel);
    _exit(rc);
  }

  uint64_t start = monotonic_ms();
  for (;;) {
    int status = 0;
    pid_t w = waitpid(pid, &status, WNOHANG);
    if (w == pid) {
      if (WIFEXITED(status)) return WEXITSTATUS(status);
      if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        fprintf(stderr, "zrt: error: guest terminated by signal %d\n", sig);
        return 1;
      }
      return 1;
    }
    if (w < 0) {
      fprintf(stderr, "zrt: error: waitpid failed (%s)\n", strerror(errno));
      return 1;
    }

    if (timeout_ms != 0) {
      uint64_t now = monotonic_ms();
      if (now - start >= timeout_ms) {
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
        fprintf(stderr, "zrt: error: timeout after %llu ms\n", (unsigned long long)timeout_ms);
        return 1;
      }
    }

    struct timespec slp;
    slp.tv_sec = 0;
    slp.tv_nsec = 1000000; /* 1ms */
    (void)nanosleep(&slp, NULL);
  }
}

int main(int argc, char **argv) {
  int safe_mode = 0;
  int allow_primitives = 0;
  uint64_t timeout_ms = 0;
  uint64_t fuel = 0;

  const char *path = NULL;

  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    if (!a) continue;
    if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
      print_help(stdout);
      return 0;
    }
    if (strcmp(a, "--version") == 0) {
      print_version();
      return 0;
    }
    if (strcmp(a, "--safe") == 0) {
      safe_mode = 1;
      continue;
    }
    if (strcmp(a, "--allow-primitives") == 0) {
      allow_primitives = 1;
      continue;
    }
    if (strcmp(a, "--timeout-ms") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "zrt: error: --timeout-ms requires a value\n");
        return 2;
      }
      const char *v = argv[++i];
      char *end = NULL;
      unsigned long long n = strtoull(v, &end, 10);
      if (!v || v[0] == '\0' || !end || *end != '\0') {
        fprintf(stderr, "zrt: error: invalid --timeout-ms value\n");
        return 2;
      }
      timeout_ms = (uint64_t)n;
      continue;
    }
    if (strcmp(a, "--fuel") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "zrt: error: --fuel requires a value\n");
        return 2;
      }
      const char *v = argv[++i];
      char *end = NULL;
      unsigned long long n = strtoull(v, &end, 10);
      if (!v || v[0] == '\0' || !end || *end != '\0') {
        fprintf(stderr, "zrt: error: invalid --fuel value\n");
        return 2;
      }
      fuel = (uint64_t)n;
      continue;
    }
    if (a[0] == '-') {
      fprintf(stderr, "zrt: error: unknown option: %s\n", a);
      print_help(stderr);
      return 2;
    }
    if (!path) {
      path = a;
      continue;
    }
    fprintf(stderr, "zrt: error: unexpected extra argument: %s\n", a);
    return 2;
  }

  if (!path) {
    print_help(stderr);
    return 2;
  }

  /* Only fork/isolate when explicitly requested. */
  if (safe_mode || timeout_ms != 0 || fuel != 0) {
    return run_guest_isolated(path, safe_mode, allow_primitives, timeout_ms, fuel);
  }
  return run_guest(path, safe_mode, allow_primitives, timeout_ms, fuel);
}
