/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void usage(FILE *out) {
  fprintf(out,
          "zduel — differential runner (A/B) over IR corpora\n"
          "\n"
          "Usage:\n"
          "  zduel [options] --a <cmd...> --b <cmd...> -- <inputs...>\n"
          "  zduel [options] --corpus <dir> --a <cmd...> --b <cmd...>\n"
          "\n"
          "Command templating:\n"
          "  If any arg equals '{}' it is replaced with the input path.\n"
          "  Otherwise the input path is appended as the last arg.\n"
          "\n"
          "Options:\n"
          "  --out <dir>         Write divergence artifacts under <dir>\n"
          "  --compare <mode>    exit|stdout|stderr|both (default: both)\n"
          "  --check             Single-input check: exit 1 iff divergent\n"
          "  --minimize           Minimize divergent input via zmin-ir\n"
          "  --zmin <path>       Path to zmin-ir (default: zmin-ir in PATH)\n"
          "  --corpus <dir>      Run over *.jsonl files in <dir>\n"
          "  -v                  Verbose\n"
          "  --help              Show this help and exit\n"
          "\n"
          "Exit codes:\n"
          "  0  no divergence\n"
          "  1  divergence found\n"
          "  2  usage/error\n");
}

static void die(const char *msg) {
  fprintf(stderr, "zduel: error: %s\n", msg);
  exit(2);
}

static void die2(const char *msg, const char *arg) {
  fprintf(stderr, "zduel: error: %s: %s\n", msg, arg);
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

static int ends_with(const char *s, const char *suffix) {
  size_t n = strlen(s);
  size_t m = strlen(suffix);
  if (m > n) return 0;
  return strcmp(s + (n - m), suffix) == 0;
}

static int mkdir_p(const char *path) {
  if (!path || !*path) return -1;
  char tmp[PATH_MAX];
  if (strlen(path) >= sizeof(tmp)) return -1;
  strcpy(tmp, path);

  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = 0;
      if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
      *p = '/';
    }
  }
  if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
  return 0;
}

static int file_equal(const char *a, const char *b) {
  struct stat sa, sb;
  if (stat(a, &sa) != 0) return 0;
  if (stat(b, &sb) != 0) return 0;
  if (sa.st_size != sb.st_size) return 0;

  FILE *fa = fopen(a, "rb");
  FILE *fb = fopen(b, "rb");
  if (!fa || !fb) {
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    return 0;
  }

  char ba[8192];
  char bb[8192];
  size_t n;
  int ok = 1;
  while ((n = fread(ba, 1, sizeof(ba), fa)) > 0) {
    size_t m = fread(bb, 1, n, fb);
    if (m != n || memcmp(ba, bb, n) != 0) {
      ok = 0;
      break;
    }
  }
  if (ferror(fa) || ferror(fb)) ok = 0;

  fclose(fa);
  fclose(fb);
  return ok;
}

static int run_capture(const char *input_path, char *const *cmd_argv, int cmd_argc,
                       const char *out_path, const char *err_path) {
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

  pid_t pid = fork();
  if (pid < 0) {
    free(argv);
    return -1;
  }
  if (pid == 0) {
    int ofd = open(out_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    int efd = open(err_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (ofd >= 0) {
      dup2(ofd, STDOUT_FILENO);
      close(ofd);
    }
    if (efd >= 0) {
      dup2(efd, STDERR_FILENO);
      close(efd);
    }
    execvp(argv[0], argv);
    _exit(127);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    free(argv);
    return -1;
  }
  free(argv);

  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 255;
}

typedef enum {
  CMP_EXIT = 1,
  CMP_STDOUT = 2,
  CMP_STDERR = 4,
  CMP_BOTH = CMP_STDOUT | CMP_STDERR
} cmp_mode_t;

static cmp_mode_t parse_compare(const char *s) {
  if (!s) return CMP_BOTH;
  if (strcmp(s, "exit") == 0) return CMP_EXIT;
  if (strcmp(s, "stdout") == 0) return CMP_STDOUT;
  if (strcmp(s, "stderr") == 0) return CMP_STDERR;
  if (strcmp(s, "both") == 0) return CMP_BOTH;
  return 0;
}

typedef struct {
  const char *out_dir;
  const char *corpus_dir;
  const char *zmin_path;
  cmp_mode_t mode;
  int check;
  int minimize;
  int verbose;

  int a_start;
  int a_end;
  int b_start;
  int b_end;
  int inputs_start;
  int ninputs;
} opts_t;

static void push_input(char ***arr, int *n, int *cap, const char *s) {
  if (*n == *cap) {
    *cap = *cap ? (*cap * 2) : 64;
    *arr = (char **)xrealloc(*arr, (size_t)(*cap) * sizeof(**arr));
  }
  (*arr)[(*n)++] = strdup(s);
}

static int collect_corpus(const char *dir, char ***out_inputs, int *out_n) {
  DIR *d = opendir(dir);
  if (!d) return -1;

  char **inputs = NULL;
  int n = 0, cap = 0;

  struct dirent *ent;
  while ((ent = readdir(d)) != NULL) {
    const char *name = ent->d_name;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
    if (!(ends_with(name, ".jsonl") || ends_with(name, ".ir.jsonl") || ends_with(name, ".zir.jsonl"))) continue;

    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path)) continue;
    push_input(&inputs, &n, &cap, path);
  }

  closedir(d);
  *out_inputs = inputs;
  *out_n = n;
  return 0;
}

static void free_inputs(char **inputs, int n) {
  for (int i = 0; i < n; i++) free(inputs[i]);
  free(inputs);
}

static int base_name(const char *path, char *out, size_t outlen) {
  const char *s = strrchr(path, '/');
  s = s ? (s + 1) : path;
  if (strlen(s) + 1 > outlen) return -1;
  strcpy(out, s);
  // sanitize
  for (char *p = out; *p; p++) {
    if (*p == ' ' || *p == '\t') *p = '_';
  }
  return 0;
}

static int do_check_one(opts_t *o, char **argv, const char *input_path,
                        char *const *a_argv, int a_argc, char *const *b_argv, int b_argc,
                        const char *case_dir) {
  (void)argv;
  char a_out[PATH_MAX], a_err[PATH_MAX], b_out[PATH_MAX], b_err[PATH_MAX];
  if (snprintf(a_out, sizeof(a_out), "%s/a.stdout", case_dir) >= (int)sizeof(a_out)) return -1;
  if (snprintf(a_err, sizeof(a_err), "%s/a.stderr", case_dir) >= (int)sizeof(a_err)) return -1;
  if (snprintf(b_out, sizeof(b_out), "%s/b.stdout", case_dir) >= (int)sizeof(b_out)) return -1;
  if (snprintf(b_err, sizeof(b_err), "%s/b.stderr", case_dir) >= (int)sizeof(b_err)) return -1;

  int a_code = run_capture(input_path, a_argv, a_argc, a_out, a_err);
  int b_code = run_capture(input_path, b_argv, b_argc, b_out, b_err);
  if (a_code < 0 || b_code < 0) return -1;

  int diverge = 0;
  if (o->mode & CMP_EXIT) {
    if (a_code != b_code) diverge = 1;
  }
  if (!diverge && (o->mode & CMP_STDOUT)) {
    if (!file_equal(a_out, b_out)) diverge = 1;
  }
  if (!diverge && (o->mode & CMP_STDERR)) {
    if (!file_equal(a_err, b_err)) diverge = 1;
  }

  if (o->verbose) {
    fprintf(stderr, "zduel: %s a=%d b=%d %s\n", input_path, a_code, b_code, diverge ? "DIVERGE" : "ok");
  }

  // In non-artifact mode, we still wrote temp outputs into case_dir.
  // Caller decides whether to keep or delete them.
  return diverge ? 1 : 0;
}

static int run_minimize(const opts_t *o, char **argv,
                        char *const *a_argv, int a_argc, char *const *b_argv, int b_argc,
                        const char *input_path, const char *out_dir) {
  (void)argv;
  if (!out_dir) die("--minimize requires --out");

  char min_path[PATH_MAX];
  if (snprintf(min_path, sizeof(min_path), "%s/min.jsonl", out_dir) >= (int)sizeof(min_path)) {
    die("--out path too long");
  }

  const char *zmin = o->zmin_path ? o->zmin_path : "zmin-ir";

  // Build argv for: zmin-ir --want-exit 1 -o <min_path> <input> -- zduel --check --compare X --a ... --b ... -- {}
  int cap = 64 + a_argc + b_argc;
  char **zargv = (char **)xmalloc((size_t)cap * sizeof(*zargv));
  int zi = 0;
  zargv[zi++] = (char *)zmin;
  zargv[zi++] = (char *)"--want-exit";
  zargv[zi++] = (char *)"1";
  zargv[zi++] = (char *)"-o";
  zargv[zi++] = (char *)min_path;
  zargv[zi++] = (char *)input_path;
  zargv[zi++] = (char *)"--";
  zargv[zi++] = (char *)"zduel";
  zargv[zi++] = (char *)"--check";
  if (o->mode == CMP_EXIT) {
    zargv[zi++] = (char *)"--compare";
    zargv[zi++] = (char *)"exit";
  } else if (o->mode == CMP_STDOUT) {
    zargv[zi++] = (char *)"--compare";
    zargv[zi++] = (char *)"stdout";
  } else if (o->mode == CMP_STDERR) {
    zargv[zi++] = (char *)"--compare";
    zargv[zi++] = (char *)"stderr";
  } else {
    zargv[zi++] = (char *)"--compare";
    zargv[zi++] = (char *)"both";
  }

  zargv[zi++] = (char *)"--a";
  for (int i = 0; i < a_argc; i++) zargv[zi++] = a_argv[i];
  zargv[zi++] = (char *)"--b";
  for (int i = 0; i < b_argc; i++) zargv[zi++] = b_argv[i];
  zargv[zi++] = (char *)"--";
  zargv[zi++] = (char *)"{}";
  zargv[zi] = NULL;

  pid_t pid = fork();
  if (pid < 0) {
    free(zargv);
    return -1;
  }
  if (pid == 0) {
    execvp(zargv[0], zargv);
    _exit(127);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    free(zargv);
    return -1;
  }
  free(zargv);

  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 255;
}

int zduel_main(int argc, char **argv) {
  opts_t o;
  memset(&o, 0, sizeof(o));
  o.mode = CMP_BOTH;
  o.a_start = o.a_end = o.b_start = o.b_end = -1;

  // parse options and split command slices
  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
      usage(stdout);
      return 0;
    }

    #if defined(ZASM_STANDALONE_ZDUEL)
    int main(int argc, char **argv) {
      return zduel_main(argc, argv);
    }
    #endif
    if (strcmp(arg, "-v") == 0) {
      o.verbose = 1;
      continue;
    }
    if (strcmp(arg, "--out") == 0) {
      if (i + 1 >= argc) die("--out requires a dir");
      o.out_dir = argv[++i];
      continue;
    }
    if (strcmp(arg, "--zmin") == 0) {
      if (i + 1 >= argc) die("--zmin requires a path");
      o.zmin_path = argv[++i];
      continue;
    }
    if (strcmp(arg, "--compare") == 0) {
      if (i + 1 >= argc) die("--compare requires a mode");
      o.mode = parse_compare(argv[++i]);
      if (!o.mode) die("invalid --compare mode");
      continue;
    }
    if (strcmp(arg, "--check") == 0) {
      o.check = 1;
      continue;
    }
    if (strcmp(arg, "--minimize") == 0) {
      o.minimize = 1;
      continue;
    }
    if (strcmp(arg, "--corpus") == 0) {
      if (i + 1 >= argc) die("--corpus requires a dir");
      o.corpus_dir = argv[++i];
      continue;
    }

    if (strcmp(arg, "--a") == 0) {
      if (o.a_start != -1) die("--a specified twice");
      o.a_start = i + 1;
      // find --b
      int j = o.a_start;
      for (; j < argc; j++) {
        if (strcmp(argv[j], "--b") == 0) break;
      }
      if (j >= argc) die("--a must be followed by --b");
      o.a_end = j;
      o.b_start = j + 1;
      // find final --
      int k = o.b_start;
      for (; k < argc; k++) {
        if (strcmp(argv[k], "--") == 0) break;
      }
      o.b_end = k;
      o.inputs_start = (k < argc) ? (k + 1) : argc;
      break;
    }

    if (arg[0] == '-') {
      die2("unknown option", arg);
    }

    // bare args only allowed after --
    die("inputs must come after --a/--b and a final --");
  }

  if (o.a_start < 0 || o.a_end <= o.a_start || o.b_start < 0 || o.b_end <= o.b_start) {
    die("expected --a <cmd...> --b <cmd...> -- <inputs...> (or --corpus)");
  }

  char **a_argv = &argv[o.a_start];
  int a_argc = o.a_end - o.a_start;
  char **b_argv = &argv[o.b_start];
  int b_argc = (o.b_end > o.b_start) ? (o.b_end - o.b_start) : (argc - o.b_start);

  char **inputs = NULL;
  int ninputs = 0;

  if (o.corpus_dir) {
    if (collect_corpus(o.corpus_dir, &inputs, &ninputs) != 0) {
      die2("failed to read corpus dir", o.corpus_dir);
    }
  } else {
    if (o.inputs_start >= argc) die("no inputs after --");
    int cap = argc - o.inputs_start;
    inputs = (char **)xmalloc((size_t)cap * sizeof(*inputs));
    for (int i = o.inputs_start; i < argc; i++) {
      inputs[ninputs++] = strdup(argv[i]);
    }
  }

  if (ninputs == 0) die("no inputs");

  if (o.check || o.minimize) {
    if (ninputs != 1) die("--check/--minimize require exactly one input");
  }

  if (o.minimize) {
    if (!o.out_dir) die("--minimize requires --out");
    if (mkdir_p(o.out_dir) != 0) die2("failed to create --out", o.out_dir);

    // quick check first
    char case_dir[PATH_MAX];
    if (snprintf(case_dir, sizeof(case_dir), "%s/check", o.out_dir) >= (int)sizeof(case_dir)) die("--out too long");
    if (mkdir_p(case_dir) != 0) die("failed to create case dir");

    int diverge = do_check_one(&o, argv, inputs[0], a_argv, a_argc, b_argv, b_argc, case_dir);
    if (diverge <= 0) {
      // 0 = ok, -1 = error
      free_inputs(inputs, ninputs);
      return diverge < 0 ? 2 : 0;
    }

    int rc = run_minimize(&o, argv, a_argv, a_argc, b_argv, b_argc, inputs[0], o.out_dir);
    free_inputs(inputs, ninputs);
    return rc == 0 ? 1 : 2;
  }

  int any_diverge = 0;
  for (int i = 0; i < ninputs; i++) {
    const char *in = inputs[i];

    char case_dir[PATH_MAX];
    if (o.out_dir) {
      if (mkdir_p(o.out_dir) != 0) die2("failed to create --out", o.out_dir);
      char base[256];
      if (base_name(in, base, sizeof(base)) != 0) strcpy(base, "case");
      if (snprintf(case_dir, sizeof(case_dir), "%s/%04d_%s", o.out_dir, i, base) >= (int)sizeof(case_dir)) {
        die("case dir path too long");
      }
      if (mkdir_p(case_dir) != 0) die("failed to create case dir");
    } else {
      // temp case dir (mkstemp + mkdir, avoids mkdtemp portability issues)
      strcpy(case_dir, "/tmp/zduel_case_XXXXXX");
      int tfd = mkstemp(case_dir);
      if (tfd < 0) die("mkstemp failed");
      close(tfd);
      unlink(case_dir);
      if (mkdir(case_dir, 0755) != 0) die("failed to create temp case dir");
    }

    int diverge = do_check_one(&o, argv, in, a_argv, a_argc, b_argv, b_argc, case_dir);
    if (diverge < 0) {
      free_inputs(inputs, ninputs);
      return 2;
    }

    if (diverge) {
      any_diverge = 1;
    } else if (!o.out_dir) {
      // delete temp dir outputs best-effort
      char p[PATH_MAX];
      snprintf(p, sizeof(p), "%s/a.stdout", case_dir);
      unlink(p);
      snprintf(p, sizeof(p), "%s/a.stderr", case_dir);
      unlink(p);
      snprintf(p, sizeof(p), "%s/b.stdout", case_dir);
      unlink(p);
      snprintf(p, sizeof(p), "%s/b.stderr", case_dir);
      unlink(p);
      rmdir(case_dir);
    }

    if (o.check) {
      free_inputs(inputs, ninputs);
      return diverge ? 1 : 0;
    }
  }

  free_inputs(inputs, ninputs);
  return any_diverge ? 1 : 0;
}
