/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void usage(FILE *out) {
  fprintf(out,
          "ztriage — run a command over IR files and group failures\n"
          "\n"
          "Usage:\n"
          "  ztriage [options] <inputs...> -- <cmd> [args...]\n"
          "\n"
          "Command templating:\n"
          "  If any arg equals '{}' it is replaced with the input path.\n"
          "  Otherwise the input path is appended as the last arg.\n"
          "\n"
          "Options:\n"
          "  --want-exit N      Consider a failure iff cmd exits with code N\n"
          "  --want-nonzero     Consider a failure iff cmd exits nonzero (default)\n"
          "  --max-stderr N     Capture up to N bytes of stderr for signature (default: 4096)\n"
          "  --jsonl <path>     Write per-input JSONL records to <path> (default: stdout)\n"
          "  --summary          Print grouped summary to stderr\n"
          "  -v                 Verbose progress\n"
          "  --help             Show this help and exit\n"
          "\n"
          "Exit codes:\n"
          "  0  ran successfully (even if failures were found)\n"
          "  2  usage/error\n");
}

static void die(const char *msg) {
  fprintf(stderr, "ztriage: error: %s\n", msg);
  exit(2);
}

static void die2(const char *msg, const char *arg) {
  fprintf(stderr, "ztriage: error: %s: %s\n", msg, arg);
  exit(2);
}

static void *xmalloc(size_t n) {
  void *p = malloc(n);
  if (!p) die("out of memory");
  return p;
}

static void *xrealloc(void *p, size_t n) {
  void *r = realloc(p, n);
  if (!r) die("out of memory");
  return r;
}

static int run_cmd_redirect(char *const *argv, const char *stderr_path) {
  pid_t pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    int fd = open(stderr_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd >= 0) {
      dup2(fd, STDERR_FILENO);
      close(fd);
    }
    execvp(argv[0], argv);
    _exit(127);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) return -1;
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 255;
}

static char *slurp_prefix(const char *path, size_t max_bytes) {
  FILE *f = fopen(path, "r");
  if (!f) return NULL;

  char *buf = (char *)xmalloc(max_bytes + 1);
  size_t n = fread(buf, 1, max_bytes, f);
  buf[n] = 0;
  fclose(f);

  // trim trailing whitespace
  while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
    buf[n - 1] = 0;
    n--;
  }
  return buf;
}

static void json_escape_to(FILE *out, const char *s) {
  fputc('"', out);
  if (s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
      unsigned char c = *p;
      if (c == '"' || c == '\\') {
        fputc('\\', out);
        fputc((int)c, out);
      } else if (c == '\n') {
        fputs("\\n", out);
      } else if (c == '\r') {
        fputs("\\r", out);
      } else if (c == '\t') {
        fputs("\\t", out);
      } else if (c < 0x20) {
        fprintf(out, "\\u%04x", (unsigned)c);
      } else {
        fputc((int)c, out);
      }
    }
  }
  fputc('"', out);
}

typedef struct {
  char *sig;
  long count;
} bucket_t;

typedef struct {
  bucket_t *v;
  size_t n;
  size_t cap;
} buckets_t;

static void buckets_add(buckets_t *b, const char *sig) {
  const char *k = sig ? sig : "";
  for (size_t i = 0; i < b->n; i++) {
    if (strcmp(b->v[i].sig, k) == 0) {
      b->v[i].count++;
      return;
    }
  }
  if (b->n == b->cap) {
    b->cap = b->cap ? b->cap * 2 : 16;
    b->v = (bucket_t *)xrealloc(b->v, b->cap * sizeof(*b->v));
  }
  b->v[b->n].sig = strdup(k);
  b->v[b->n].count = 1;
  b->n++;
}

static void buckets_free(buckets_t *b) {
  for (size_t i = 0; i < b->n; i++) free(b->v[i].sig);
  free(b->v);
  b->v = NULL;
  b->n = b->cap = 0;
}

typedef struct {
  int want_exact;
  int want_code;
  int want_nonzero;
  size_t max_stderr;
  int verbose;
  int summary;
} opts_t;

static int is_failure(const opts_t *o, int exit_code) {
  if (o->want_exact) return exit_code == o->want_code;
  return exit_code != 0;
}

static char **build_argv(const char *input_path, char *const *cmd_argv, int cmd_argc) {
  int has_placeholder = 0;
  for (int i = 0; i < cmd_argc; i++) {
    if (strcmp(cmd_argv[i], "{}") == 0) {
      has_placeholder = 1;
      break;
    }
  }

  int extra = has_placeholder ? 0 : 1;
  char **argv = (char **)xmalloc(((size_t)cmd_argc + (size_t)extra + 1) * sizeof(*argv));
  int ai = 0;
  for (int i = 0; i < cmd_argc; i++) {
    if (strcmp(cmd_argv[i], "{}") == 0) argv[ai++] = (char *)input_path;
    else argv[ai++] = cmd_argv[i];
  }
  if (!has_placeholder) argv[ai++] = (char *)input_path;
  argv[ai] = NULL;
  return argv;
}

int ztriage_main(int argc, char **argv) {
  opts_t o;
  memset(&o, 0, sizeof(o));
  o.want_nonzero = 1;
  o.max_stderr = 4096;

  const char *jsonl_path = NULL;
  int cmd_start = -1;

  const char **inputs = (const char **)xmalloc((size_t)argc * sizeof(*inputs));
  int ninputs = 0;

  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    if (strcmp(arg, "--") == 0) {
      cmd_start = i + 1;
      break;
    }
    if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
      usage(stdout);
      free(inputs);
      return 0;
    }
    if (strcmp(arg, "-v") == 0) {
      o.verbose = 1;
      continue;
    }
    if (strcmp(arg, "--summary") == 0) {
      o.summary = 1;
      continue;
    }
    if (strcmp(arg, "--want-exit") == 0) {
      if (i + 1 >= argc) die("--want-exit requires a number");
      o.want_exact = 1;
      o.want_code = atoi(argv[++i]);
      o.want_nonzero = 0;
      continue;
    }
    if (strcmp(arg, "--want-nonzero") == 0) {
      o.want_exact = 0;
      o.want_nonzero = 1;
      continue;
    }
    if (strcmp(arg, "--max-stderr") == 0) {
      if (i + 1 >= argc) die("--max-stderr requires a number");
      long v = atol(argv[++i]);
      if (v <= 0) die("--max-stderr must be > 0");
      o.max_stderr = (size_t)v;
      continue;
    }
    if (strcmp(arg, "--jsonl") == 0) {
      if (i + 1 >= argc) die("--jsonl requires a path");
      jsonl_path = argv[++i];
      continue;
    }
    if (arg[0] == '-') die2("unknown option", arg);
    inputs[ninputs++] = arg;
  }

  if (cmd_start < 0 || cmd_start >= argc) {
    usage(stderr);
    free(inputs);
    return 2;
  }
  if (ninputs == 0) {
    die("expected at least one input file before --");
  }

  int cmd_argc = argc - cmd_start;
  if (cmd_argc <= 0) die("expected a command after --");
  char **cmd_argv = &argv[cmd_start];

  FILE *jsonl = stdout;
  if (jsonl_path) {
    jsonl = fopen(jsonl_path, "w");
    if (!jsonl) die2("failed to open --jsonl output", jsonl_path);
  }

  char tmp_template[] = "/tmp/ztriage_XXXXXX";
  int fd = mkstemp(tmp_template);
  if (fd < 0) die("mkstemp failed");
  close(fd);

  buckets_t buckets;
  memset(&buckets, 0, sizeof(buckets));

  for (int i = 0; i < ninputs; i++) {
    const char *in = inputs[i];

    // clear stderr capture
    FILE *tf = fopen(tmp_template, "w");
    if (tf) fclose(tf);

    char **run_argv = build_argv(in, cmd_argv, cmd_argc);
    int code = run_cmd_redirect(run_argv, tmp_template);
    free(run_argv);

    char *sig = slurp_prefix(tmp_template, o.max_stderr);
    int fail = is_failure(&o, code);
    if (fail) buckets_add(&buckets, sig ? sig : "");

    fprintf(jsonl, "{\"k\":\"ztriage\",\"path\":");
    json_escape_to(jsonl, in);
    fprintf(jsonl, ",\"exit\":%d,\"fail\":%s,\"sig\":", code, fail ? "true" : "false");
    json_escape_to(jsonl, sig ? sig : "");
    fprintf(jsonl, "}\n");

    if (o.verbose) {
      fprintf(stderr, "ztriage: %s exit=%d %s\n", in, code, fail ? "FAIL" : "ok");
    }

    free(sig);
  }

  if (o.summary) {
    fprintf(stderr, "ztriage: summary (by stderr signature)\n");
    for (size_t i = 0; i < buckets.n; i++) {
      fprintf(stderr, "  %ld\t%s\n", buckets.v[i].count, buckets.v[i].sig[0] ? buckets.v[i].sig : "<empty>");
    }
  }

  buckets_free(&buckets);
  unlink(tmp_template);

  if (jsonl_path) fclose(jsonl);
  free(inputs);
  return 0;
}

#if defined(ZASM_STANDALONE_ZTRIAGE)
int main(int argc, char **argv) {
  return ztriage_main(argc, argv);
}
#endif
