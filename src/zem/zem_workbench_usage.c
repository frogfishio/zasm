/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_workbench_usage.h"

static void puts_all(FILE *out, const char *const *lines, size_t n) {
  for (size_t i = 0; i < n; i++) {
    fputs(lines[i], out);
  }
}

void zem_workbench_usage_zirdiff(FILE *out) {
  static const char *const help[] = {
    "zem --irdiff — IR diff for ZASM IR JSONL\n",
      "\n",
      "Usage:\n",
    "  zem --irdiff [options] <a.jsonl> <b.jsonl>\n",
      "\n",
      "Options:\n",
      "  --help           Show this help and exit\n",
      "  --include-ids    Include v1.1 record id (default: ignore)\n",
      "  --include-src    Include v1.1 src_ref (default: ignore)\n",
      "  --include-loc    Include loc.line (default: ignore)\n",
      "\n",
      "Exit codes:\n",
      "  0  equal\n",
      "  1  different\n",
      "  2  error\n",
  };
  puts_all(out, help, sizeof(help) / sizeof(help[0]));
}

void zem_workbench_usage_zmin_ir(FILE *out) {
  static const char *const help[] = {
    "zem --min-ir — delta-minimize an IR JSONL file against a predicate\n",
      "\n",
      "Usage:\n",
    "  zem --min-ir [options] <input.jsonl> -- <cmd> [args...]\n",
      "\n",
      "Behavior:\n",
      "  Writes smaller IR JSONL that still reproduces the predicate.\n",
      "  The command is run repeatedly against candidate files.\n",
      "\n",
      "Command templating:\n",
      "  If any arg equals '{}' it is replaced with the candidate path.\n",
      "  Otherwise the candidate path is appended as the last arg.\n",
      "\n",
      "Options:\n",
      "  -o <path>        Output path (default: stdout)\n",
      "  --want-exit N    Predicate is satisfied iff cmd exits with code N\n",
      "  --want-nonzero   Predicate is satisfied iff cmd exits nonzero (default)\n",
      "  --max-steps N    Limit predicate invocations (default: 2000)\n",
      "  -v              Verbose progress\n",
      "  --help          Show this help and exit\n",
      "\n",
      "Exit codes:\n",
      "  0  minimized output written\n",
      "  2  usage/error\n",
  };
  puts_all(out, help, sizeof(help) / sizeof(help[0]));
}

void zem_workbench_usage_ztriage(FILE *out) {
  static const char *const help[] = {
    "zem --triage — run a command over IR files and group failures\n",
      "\n",
      "Usage:\n",
    "  zem --triage [options] <inputs...> -- <cmd> [args...]\n",
      "\n",
      "Command templating:\n",
      "  If any arg equals '{}' it is replaced with the input path.\n",
      "  Otherwise the input path is appended as the last arg.\n",
      "\n",
      "Options:\n",
      "  --want-exit N      Consider a failure iff cmd exits with code N\n",
      "  --want-nonzero     Consider a failure iff cmd exits nonzero (default)\n",
      "  --max-stderr N     Capture up to N bytes of stderr for signature (default: 4096)\n",
      "  --jsonl <path>     Write per-input JSONL records to <path> (default: stdout)\n",
      "  --summary          Print grouped summary to stderr\n",
      "  -v                 Verbose progress\n",
      "  --help             Show this help and exit\n",
      "\n",
      "Exit codes:\n",
      "  0  ran successfully (even if failures were found)\n",
      "  2  usage/error\n",
  };
  puts_all(out, help, sizeof(help) / sizeof(help[0]));
}

void zem_workbench_usage_zduel(FILE *out) {
  static const char *const help[] = {
    "zem --duel — differential runner (A/B) over IR corpora\n",
      "\n",
      "Usage:\n",
    "  zem --duel [options] --a <cmd...> --b <cmd...> -- <inputs...>\n",
    "  zem --duel [options] --corpus <dir> --a <cmd...> --b <cmd...>\n",
      "\n",
      "Command templating:\n",
      "  If any arg equals '{}' it is replaced with the input path.\n",
      "  Otherwise the input path is appended as the last arg.\n",
      "\n",
      "Options:\n",
      "  --out <dir>         Write divergence artifacts under <dir>\n",
      "  --compare <mode>    exit|stdout|stderr|both (default: both)\n",
      "  --check             Single-input check: exit 1 iff divergent\n",
        "  --minimize          Minimize divergent input via --min-ir\n",
        "  --zem <path>        Path to zem (default: this zem)\n",
      "  --corpus <dir>      Run over *.jsonl files in <dir>\n",
      "  -v                  Verbose\n",
      "  --help              Show this help and exit\n",
      "\n",
      "Exit codes:\n",
      "  0  no divergence\n",
      "  1  divergence found\n",
      "  2  usage/error\n",
  };
  puts_all(out, help, sizeof(help) / sizeof(help[0]));
}
