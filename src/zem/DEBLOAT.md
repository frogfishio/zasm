# zem debloating / size-optimization roadmap

This document captures debloating ideas for `zem` as tangible deliverables.

The core concept:

- `zem` can already execute programs deterministically and collect detailed execution telemetry (coverage, labels, trap diagnostics).
- If a test suite is treated as a *contract* (not a proof), we can produce **specialized artifacts** optimized for the behaviors exercised by that contract.

This is deliberately split into **safe** vs **aggressive** modes.

---

## Goals

- Shrink delivered artifacts by removing or folding unused code.
- Provide an explicit, auditable build output that describes *what was removed/folded and why*.
- Keep failure modes crisp:
  - Safe modes must preserve semantics.
  - Aggressive modes may change semantics outside the exercised contract, but should fail loudly (trap stubs) rather than silently.
- Compose with existing `zem` features:
  - coverage collection and black-hole reporting
  - debug-events-only JSONL streams
  - trap-time diagnosis and provenance

## Non-goals

- This is not a formal verifier.
- This is not a general-purpose compiler optimizer.
- This does not try to infer intent from source languages.

---

## Glossary

- **PC**: a program counter value in `zem` (instruction/program location notion in the execution engine).
- **Label**: a named location or symbolic region; in `zem` coverage work we already introduced label aggregates.
- **Coverage artifact**: a file produced by a test run that summarizes what executed.
- **Black hole**: a label/PC region with 0 hits in coverage.
- **Debloat**: any size-reducing transformation driven by coverage and/or structural identity.
- **ICF**: Identical Code Folding (merge identical functions).
- **Outlining**: factor repeated basic-block sequences into shared helpers.

---

## Deliverable 0: Make coverage a first-class, stable artifact

We already have coverage JSONL output and merge.

### Current behavior (implemented)

How to collect coverage:

```sh
bin/zem --coverage --coverage-out /tmp/zem.coverage.jsonl /tmp/program.jsonl
```

Print a quick “black holes” summary (labels with uncovered instructions):

```sh
bin/zem --coverage --coverage-blackholes 20 --coverage-out /tmp/zem.coverage.jsonl /tmp/program.jsonl
```

Merge multiple runs (useful for CI shards or multi-phase pipelines):

```sh
bin/zem --coverage --coverage-merge /tmp/zem.coverage.jsonl \
  --coverage-out /tmp/zem.coverage.merged.jsonl \
  /tmp/program.jsonl
```

Notes:

- Coverage is per IR record index (`pc`). Only instruction records are reported as per-PC hit counts.
- The JSONL report includes per-label aggregates (`k == "zem_cov_label"`) to support black-hole analysis.
- `--coverage-blackholes` prints a human-oriented summary to stderr.
- When `--debug-events-only` is used:
  - `--coverage` requires `--coverage-out` (to keep stderr clean JSONL).
  - `--coverage-blackholes` is rejected (since it prints to stderr).

### Current JSONL schema (implemented)

The coverage report is line-delimited JSON (JSONL). Record keys:

- `k == "zem_cov"` (summary)
  - `v`: schema version (currently `1`)
  - `nrecs`: number of IR records loaded
  - `total_instr`: number of instruction records
  - `covered_instr`: instruction records with `count > 0`
  - `steps`: total instruction steps executed
  - `stdin_source_name`: source name for stdin inputs (string or `null`)
  - `module_hash`: stable identity for the loaded IR (string)
    - format: `fnv1a64:0123456789abcdef`

- `k == "zem_cov_rec"` (per-PC instruction record)
  - `pc`: IR record index (0-based)
  - `count`: hit count (can be `0`)
  - `label`: current label at-or-before `pc` (string or `null`)
  - `line`: source line if present (number or `null`)
  - `m`: mnemonic (string)
  - `src`: source identity string if known (string or `null`)

- `k == "zem_cov_label"` (per-label aggregates)
  - `label`: label name (string)
  - `total_instr`: number of instruction records under this label
  - `covered_instr`: instruction records under this label with `count > 0`
  - `uncovered_instr`: `total_instr - covered_instr`
  - `first_pc`: first IR record index where this label appears

- `k == "zem_strip"` (strip-stage metrics)
  - `v`: schema version (currently `1`)
  - `mode`: strip mode (string)
  - `profile`: coverage JSONL path used (string)
  - `profile_module_hash`: module hash read from the coverage summary (string)
  - `in_module_hash`: module hash of the input IR (string)
  - `out_module_hash`: module hash of the output IR (string)
  - `nrecs`: number of IR records loaded
  - `total_instr`: number of instruction records
  - `covered_instr`: instruction records with `count > 0` in the profile
  - `dead_by_profile_instr`: `total_instr - covered_instr`
  - `changed_instr`: number of instruction records rewritten by the strip pass
  - `removed_instr`: number of instruction records deleted by the strip pass
  - `bytes_in`: approximate input JSONL bytes processed
  - `bytes_out`: bytes written in the output JSONL

- `k == "zem_rep"` (repetition / bloat summary)
  - `v`: schema version (currently `1`)
  - `mode`: repetition tokenization mode (`"exact"` or `"shape"`)
  - `n`: n-gram length
  - `path`: input path (string)
  - `lines`: number of lines read
  - `instr`: number of instruction records observed
  - `unique_ngrams`: unique n-grams observed
  - `repeated_ngrams`: n-grams with count > 1
  - `best_ngram_saved_instr_est`: heuristic outline savings estimate (instr)
  - `bloat_score`: `dead_by_profile_instr + best_ngram_saved_instr_est`

- `k == "zem_rep_cov"` (optional repetition/coverage enrichment)
  - `v`: schema version (currently `1`)
  - `total_instr`: from coverage summary
  - `covered_instr`: from coverage summary
  - `blackhole_labels`: number of labels with uncovered instructions

Notes:

- This is a C implementation intended to eventually replace the Python repetition scan for CI/one-binary workflows.
- The detailed “top repeated n-grams” report (`zem_rep_ngram`) is not emitted yet.

### Requirements

- Stable schema (versioned) for downstream tooling.
- Records should support:
  - per-PC hits (exact)
  - per-label hits (aggregate)
  - build id / input module hash (so we don’t apply coverage to the wrong binary)

### Gaps / roadmap additions

The current schema is intentionally simple and already useful, but downstream debloat passes will benefit from a stronger “profile identity” contract.

Additions worth doing before `--strip` becomes real:

- `module_hash` is now implemented in `zem_cov` and should be treated as *required* for coverage-guided strip/debloat passes.
- (Optional) Add `build_id` / tool version strings for auditability.

Notes:

- Downstream passes should treat per-PC counts (`zem_cov_rec`) as authoritative; label aggregates are convenience.
- Keep `module_hash` *required* for coverage-guided debloat passes.

---

## Deliverable 1: `--strip=dead` (semantics-preserving)

**Definition:** remove code that is statically unreachable from entrypoints.

This is classic dead-code elimination (DCE). It does not rely on coverage.

### Why it’s safe

If code is unreachable by control-flow and not referenced by data/exports, removing it does not change behavior.

### Implementation notes

- Requires a control-flow graph (CFG) / reachability analysis over the executed program representation.
- Entry points include:
  - program start
  - exported/public symbols (if applicable)
  - any host-callback entry points (if applicable)
- Must account for indirect jumps/dispatch mechanisms.

### Output

- A rewritten artifact (see “Rewrite targets” below).
- A `strip report` listing:
  - removed regions
  - why they were removed (unreachable)

### Tests

- A fixture with unreachable blocks that contain:
  - memory writes
  - host calls
  - traps
  - ensure behavior of reachable code unchanged

---

## Deliverable 2: `--strip=uncovered` (coverage-guided, aggressive)

**Definition:** treat coverage as contract and strip code not executed in the coverage profile.

This is powerful but not “mathematically safe”. It should be packaged with guardrails.

### Modes

1) `--strip=uncovered` (default safe-ish behavior):
   - replace uncovered regions with a small **trap stub** that reports:
     - "stripped uncovered code reached"
     - region label / pc range
     - suggestion: "re-run tests with coverage" or "disable uncovered stripping"

2) `--strip=uncovered-delete` (explicitly dangerous):
   - actually delete uncovered regions and rewire control-flow.
   - this can turn latent bugs into silent misbehavior if the control-flow rewrite is wrong.

### Why trap-stubs are a big deal

Coverage proves "not hit", not "not reachable".

Trap-stubbing yields:

- size win close to deletion
- correctness: any surprise path fails loudly
- better diagnosability for missing tests

### Coverage constraints

- Require coverage artifact’s `module_hash` to match.
- Provide `--strip-allow-mismatch` only for experiments.

### Keep rules

Even in uncovered mode, some regions should be protected:

- explicit keep list: `--strip-keep label:foo,label:bar,pc:1234..1288`
- always keep:
  - initialization/entry scaffolding
  - host ABI glue
  - trap handlers / diagnostics (so errors stay readable)

### Tests

- Run a program under coverage from a limited test.
- Produce a stripped artifact.
- Verify:
  - tested behavior still works
  - untested path traps with the expected message

---

## Deliverable 3: `--strip=repetitious` (deduplicate repeated code)

**Definition:** identify repeated code sequences and replace duplicates with shared implementations.

This is generally less scary than uncovered deletion because it can be semantics-preserving when done conservatively.

### Three levels of aggressiveness

1) `--strip=repetitious=func` (ICF)
   - Merge *entire functions* that are identical after canonicalization.
   - This is the best first milestone: big win, low risk.

2) `--strip=repetitious=tail` (tail merging)
   - Merge identical suffix sequences (common tails) of basic blocks.
   - Often yields good wins for error paths and epilogues.

3) `--strip=repetitious=outline` (outlining)
   - Extract repeated straight-line regions into helpers.
   - Higher risk: introduces calls/returns and may change performance.

### Canonicalization requirements

“Identical” must be defined on a normalized form, not raw bytes/text.

Canonicalize:

- local indices / temporaries (alpha-renaming)
- block ids / labels (alpha-renaming)
- symbolic references to labels/addresses (resolve to stable symbol ids)

After hashing, always do a deep structural equality check.

### Safety constraints

Refuse to deduplicate if any of these differ:

- calls to host primitives / imports
- memory access width/signing
- observable trap behavior
- stack/register effects

### Coverage-aware heuristics (optional but valuable)

Use coverage to pick which candidates to fold:

- prioritize cold duplicates (near-zero hits)
- avoid outlining in hot loops

This can be a key differentiator vs generic optimizers.

### Report output

Add strip report entries like:

- `{"k":"zem_strip_icf","from":"f123","to":"f77","bytes_saved":512}`
- `{"k":"zem_strip_outline","region":"Lfoo+0..+64","helper":"H3","bytes_saved":128}`

### Tests

- Synthetic fixture with duplicated functions and blocks.
- Assert output equivalence before/after.
- If coverage-aware heuristics are enabled, include a profile to ensure the pass chooses cold regions first.

---

## Rewrite targets (where the stripping happens)

We need a concrete representation to rewrite.

Options:

1) **Rewrite at the `zem` program/IR level** (preferred)
   - Pros: preserves semantics model, stable ids, easier reports.
   - Cons: requires exposing a load/save format for that internal representation.

2) **Rewrite at WAT/WASM level**
   - Pros: tool-agnostic artifacts.
   - Cons: canonicalization is harder; lots of incidental differences.

3) **Rewrite native code**
   - Pros: maximum size win.
   - Cons: complex, platform-specific.

Recommendation:

- Start with rewriting the same level that `zem` coverage understands best.
- Produce a new artifact type (e.g. `*.zemprog` or a JSONL form) plus a tiny loader.

---

## CLI sketch

These flags are conceptual; final spelling can change.

Current implementation (conservative stage) uses:

- `--strip MODE` (currently: `uncovered-ret`)
- `--strip-profile PATH` (coverage JSONL; must match `module_hash`)
- `--strip-out PATH` (stripped IR JSONL)
- `--strip-stats-out PATH` (optional JSONL metrics; use `-` to write to stderr)

- `--coverage ...` (already exists)
- `--coverage-out PATH` (already exists)
- `--strip PATH_TO_COVERAGE` (apply debloat using coverage)
- `--strip-mode dead|uncovered|uncovered-delete|repetitious|…`
- `--strip-report PATH` (JSONL)
- `--strip-keep ...`

Or split into two subcommands:

- `zem run … --coverage-out prof.jsonl`
- `zem strip --in prog --out prog.stripped --profile prof.jsonl --mode …`

Subcommands are attractive because stripping is a *build step*, not a runtime option.

---

## Compatibility and safety philosophy

- `dead` and conservative `repetitious=func` can be treated as stable optimizations.
- `uncovered` is an explicit specialization step.
- Default uncovered behavior should be **trap stubs**, not deletion.

This is how we keep it "killer" without making it a foot-gun.

---

## Open questions

- What exact artifact do we rewrite and emit?
- What is the stable identity of a function/block/pc across builds?
- How do we handle indirect control flow (br_table / dispatch loops) in reachability?
- What is the right “keep” default for host ABI glue?
- Do we want determinism controls for dedup ordering (so builds are reproducible)?

---

## Suggested implementation plan (phased)

1) Stabilize coverage schema + `module_hash` in output.
2) Implement `strip report` format.
3) Implement `--strip=dead`.
4) Implement `--strip=uncovered` as trap-stubbing.
5) Implement `--strip=repetitious=func` (ICF).
6) Consider tail-merge / outlining as optional advanced passes.

---

## Recommended experiment fixture: `hello.zir.jsonl`

There is a deliberately “degenerate” but extremely useful fixture:

- `src/zem/testdata2/hello.zir.jsonl` (~18MB JSONL)

It behaves like a “hello world” program, but brings along a large amount of IR.
That makes it a great patsy for aggressive experiments:

- coverage-driven stripping (`uncovered` modes)
- repetition detection / dedup heuristics (`repetitious` modes)

Local harness:

- `make test-zem-debloat-hello-big`

The harness writes reports to stable paths under `/tmp/`:

- `/tmp/zem_debloat_hello_big.coverage.jsonl`
- `/tmp/zem_debloat_hello_big.repetition.jsonl`
- `/tmp/zem_debloat_hello_big.report.html`

This target is **not** part of `test-all`/`test-validation` because it is intentionally heavy and intended for local iteration.

### Repetition + coverage diagnosis tooling

There is a small analysis tool for repetition detection:

```sh
python3 tools/zem_repetition_scan.py src/zem/testdata2/hello.zir.jsonl \
  --n 8 --mode shape \
  --coverage-jsonl /tmp/zem.coverage.jsonl \
  --report-jsonl /tmp/zem.repetition.jsonl \
  --report-html /tmp/zem.debloat.html \
  --diag
```

- `--report-jsonl` writes a machine-readable report suitable for future `--strip=repetitious` planning.
- `--report-html` writes a self-contained HTML report (pie charts + top tables for blackhole labels and repeated n-grams).
- `--diag` prints a one-line bloat diagnosis (coverage %s, blackhole %, repetition signals, and a trendable `bloat_score`).
