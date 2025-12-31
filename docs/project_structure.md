<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zasm Project Structure

This layout keeps the assembler deterministic, the toolchain modular, and tests reproducible.

## Root

- `Makefile` — Build rules and test targets.
- `README.md` — Overview and links to specs/tools.
- `CONTRIBUTING.md` — Contribution guidelines.
- `LICENSE` — GPL-3.0-or-later for the toolchain.
- `LICENSE-ASM` — MIT for assembly examples and library modules.
- `TRADEMARK.md` — Trademark usage rules.
- `COPYRIGHT` — Copyright statement.

## `bin/` (binaries)

Built tools (not committed).

- `zas` — Assembler (ZASM -> JSONL IR).
- `zld` — Linker/lowerer (JSONL IR -> WAT).
- `zlnt` — JSONL IR linter.
- `zrun` — Local runner for `.wat`/`.wasm`.

## `src/` (toolchain source)

- `src/zas/` — Lexer/parser and IR emission.
- `src/zld/` — Lowering and WAT emission.
- `src/zlnt/` — Static analysis for JSONL IR.
- `src/zrun/` — Wasmtime-based local harness.
- `src/common/` — Shared utilities (arena, JSON, helpers).

## `schema/`

JSONL schema definitions and documentation.

- `schema/ir/v1/` — IR schema and spec for v1.

## `docs/`

Canonical docs.

- `docs/spec/` — Normative specs (ABI, ISA, IR).
- `docs/tools/` — Tool manuals (zas/zld/zlnt/zrun).
- `docs/architecture.md` — Design notes.
- `docs/developers.md` — Getting started guide.
- `docs/project_structure.md` — This document.
- `docs/history/` — Archived checklists or retired docs.

## `examples/`

MIT-licensed assembly examples and demos (`*.asm`).

## `lib/`

MIT-licensed reusable ZASM modules. Current contents are small and focused (for example,
`lib/itoa.asm`). These are intended to be concatenated with application code.

## `test/`

Regression and fuzz tooling.

- `test/golden/` — Golden fixtures and expected output.
- `test/fixtures/` — Input files for tests.
- `test/run.sh` — Test harness entry point.
- `test/fuzz_zas.sh` — Fuzzer for `zas`.
- `test/fuzz_zld_jsonl.sh` — Fuzzer for JSONL input to `zld`.
- `test/validate_wat.sh` — WAT validation helpers.

## `build/`

Local build artifacts (not committed).

## `external/`

Vendored or unpacked third-party dependencies (for example, the Wasmtime C API).

## Conventions

- Assembly files are `.asm` and MIT-licensed.
- Host primitives use the `_` prefix (`_in`, `_out`, `_log`).
- `cat`-and-link uses concatenated JSONL streams (or concatenated `.asm` through `zas`).
