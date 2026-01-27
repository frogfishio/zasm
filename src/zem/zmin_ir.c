/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zem_workbench_usage.h"

static void die(const char *msg) {
  fprintf(stderr, "min-ir: error: %s\n", msg);
  exit(2);
}

static void die2(const char *msg, const char *arg) {
  fprintf(stderr, "min-ir: error: %s: %s\n", msg, arg);
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

static char *xstrdup(const char *s) {
  size_t n = strlen(s) + 1;
  char *p = (char *)xmalloc(n);
  memcpy(p, s, n);
  return p;
}

static int read_nonempty_lines(const char *path, char ***out_lines, size_t *out_n) {
  FILE *f = fopen(path, "r");
  if (!f) return -1;

  char **lines = NULL;
  size_t n = 0, cap = 0;

  char *line = NULL;
  size_t lcap = 0;
  ssize_t nread;

  while ((nread = getline(&line, &lcap, f)) != -1) {
    (void)nread;
    char *p = line;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == 0) continue;

    if (n == cap) {
      cap = cap ? cap * 2 : 256;
      lines = (char **)xrealloc(lines, cap * sizeof(*lines));
    }
    lines[n++] = xstrdup(line);
  }

  free(line);
  fclose(f);

  *out_lines = lines;
  *out_n = n;
  return 0;
}

static void free_lines(char **lines, size_t n) {
  for (size_t i = 0; i < n; i++) free(lines[i]);
  free(lines);
}

static int write_candidate(const char *path, char **lines, const size_t *idx, size_t nidx) {
  FILE *f = fopen(path, "w");
  if (!f) return -1;
  for (size_t i = 0; i < nidx; i++) {
    fputs(lines[idx[i]], f);
    size_t len = strlen(lines[idx[i]]);
    if (len == 0 || lines[idx[i]][len - 1] != '\n') fputc('\n', f);
  }
  if (fclose(f) != 0) return -1;
  return 0;
}

static int run_cmd(char *const *argv) {
  pid_t pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    execvp(argv[0], argv);
    _exit(127);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) return -1;
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 255;
}

typedef struct {
  int want_exact;
  int want_code;
  int want_nonzero;
  long max_steps;
  long steps;
  int verbose;
} predicate_t;

static int predicate_satisfied(predicate_t *pred, const char *candidate_path, char *const *cmd_argv, int cmd_argc) {
  if (pred->steps >= pred->max_steps) {
    die("predicate step limit exceeded");
  }
  pred->steps++;

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
    if (strcmp(cmd_argv[i], "{}") == 0) argv[ai++] = (char *)candidate_path;
    else argv[ai++] = cmd_argv[i];
  }
  if (!has_placeholder) argv[ai++] = (char *)candidate_path;
  argv[ai] = NULL;

  int code = run_cmd(argv);
  free(argv);

  int ok;
  if (pred->want_exact) ok = (code == pred->want_code);
  else ok = (code != 0);

  if (pred->verbose) {
    fprintf(stderr, "min-ir: step=%ld lines? cmd_exit=%d satisfied=%s\n", pred->steps, code, ok ? "yes" : "no");
  }
  return ok;
}

static size_t *idx_complement(const size_t *idx, size_t n, size_t drop_start, size_t drop_end, size_t *out_n) {
  size_t keep = n - (drop_end - drop_start);
  size_t *r = (size_t *)xmalloc(keep * sizeof(*r));
  size_t j = 0;
  for (size_t i = 0; i < n; i++) {
    if (i >= drop_start && i < drop_end) continue;
    r[j++] = idx[i];
  }
  *out_n = j;
  return r;
}

static size_t ceil_div(size_t a, size_t b) {
  return (a + b - 1) / b;
}

int zmin_ir_main(int argc, char **argv) {
  const char *out_path = NULL;
  predicate_t pred;
  memset(&pred, 0, sizeof(pred));
  pred.want_nonzero = 1;
  pred.max_steps = 2000;

  const char *in_path = NULL;
  int cmd_start = -1;

  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    if (strcmp(arg, "--") == 0) {
      cmd_start = i + 1;
      break;
    }
    if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
      zem_workbench_usage_zmin_ir(stdout);
      return 0;
    }
    if (strcmp(arg, "-v") == 0) {
      pred.verbose = 1;
      continue;
    }
    if (strcmp(arg, "-o") == 0) {
      if (i + 1 >= argc) die("-o requires a path");
      out_path = argv[++i];
      continue;
    }
    if (strcmp(arg, "--want-exit") == 0) {
      if (i + 1 >= argc) die("--want-exit requires a number");
      pred.want_exact = 1;
      pred.want_code = atoi(argv[++i]);
      pred.want_nonzero = 0;
      continue;
    }
    if (strcmp(arg, "--want-nonzero") == 0) {
      pred.want_exact = 0;
      pred.want_nonzero = 1;
      continue;
    }
    if (strcmp(arg, "--max-steps") == 0) {
      if (i + 1 >= argc) die("--max-steps requires a number");
      pred.max_steps = atol(argv[++i]);
      if (pred.max_steps <= 0) die("--max-steps must be > 0");
      continue;
    }
    if (arg[0] == '-') die2("unknown option", arg);
    if (in_path) die("expected exactly one input.jsonl before --");
    in_path = arg;
  }

  if (!in_path || cmd_start < 0 || cmd_start >= argc) {
    zem_workbench_usage_zmin_ir(stderr);
    return 2;
  }

  char **lines = NULL;
  size_t nlines = 0;
  if (read_nonempty_lines(in_path, &lines, &nlines) != 0) {
    die2("failed to read input", in_path);
  }
  if (nlines == 0) {
    free_lines(lines, nlines);
    die("input contained no non-empty lines");
  }

  char tmp_template[] = "/tmp/zmin_ir_XXXXXX";
  int fd = mkstemp(tmp_template);
  if (fd < 0) {
    free_lines(lines, nlines);
    die("mkstemp failed");
  }
  close(fd);

  int cmd_argc = argc - cmd_start;
  char **cmd_argv = &argv[cmd_start];

  // initial candidate: full file must satisfy predicate
  size_t *idx = (size_t *)xmalloc(nlines * sizeof(*idx));
  for (size_t i = 0; i < nlines; i++) idx[i] = i;
  size_t nidx = nlines;

  if (write_candidate(tmp_template, lines, idx, nidx) != 0) {
    unlink(tmp_template);
    free(idx);
    free_lines(lines, nlines);
    die("failed to write candidate");
  }

  if (!predicate_satisfied(&pred, tmp_template, cmd_argv, cmd_argc)) {
    unlink(tmp_template);
    free(idx);
    free_lines(lines, nlines);
    die("predicate does not hold for the original input (nothing to minimize)");
  }

  size_t gran = 2;
  while (nidx >= 2) {
    size_t chunk = ceil_div(nidx, gran);
    int reduced = 0;

    for (size_t g = 0; g < gran; g++) {
      size_t start = g * chunk;
      size_t end = start + chunk;
      if (start >= nidx) break;
      if (end > nidx) end = nidx;
      if (end - start == 0) continue;

      size_t ncomp = 0;
      size_t *comp = idx_complement(idx, nidx, start, end, &ncomp);
      if (ncomp == 0) {
        free(comp);
        continue;
      }

      if (write_candidate(tmp_template, lines, comp, ncomp) != 0) {
        free(comp);
        unlink(tmp_template);
        free(idx);
        free_lines(lines, nlines);
        die("failed to write candidate");
      }

      if (predicate_satisfied(&pred, tmp_template, cmd_argv, cmd_argc)) {
        free(idx);
        idx = comp;
        nidx = ncomp;
        if (gran > 2) gran--;
        reduced = 1;
        if (pred.verbose) fprintf(stderr, "min-ir: reduced to %zu lines (gran=%zu)\n", nidx, gran);
        break;
      }

      free(comp);
    }

    if (!reduced) {
      if (gran >= nidx) break;
      gran = (gran * 2 > nidx) ? nidx : gran * 2;
      if (pred.verbose) fprintf(stderr, "min-ir: increasing granularity to %zu\n", gran);
    }
  }

  // write final output
  FILE *out = stdout;
  if (out_path) {
    out = fopen(out_path, "w");
    if (!out) {
      unlink(tmp_template);
      free(idx);
      free_lines(lines, nlines);
      die2("failed to open output", out_path);
    }
  }

  for (size_t i = 0; i < nidx; i++) {
    fputs(lines[idx[i]], out);
    size_t len = strlen(lines[idx[i]]);
    if (len == 0 || lines[idx[i]][len - 1] != '\n') fputc('\n', out);
  }

  if (out_path) fclose(out);

  unlink(tmp_template);
  free(idx);
  free_lines(lines, nlines);
  return 0;
}
