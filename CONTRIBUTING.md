<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Contributing to zasm

Thanks for contributing. This repo is intentionally small, stream-first, and hostile to bloat.

## Project shape

`zasm` is a two-stage toolchain:

- **`zas`** — zASM (text) → **JSONL IR** (one record per line) on stdout
- **`zld`** — JSONL IR → **WAT** (single module) on stdout
- **`zrun`** — local runner/harness (Wasmtime host) for tests + debugging

Design rule: **stage boundaries are stable**. If you change the JSONL IR, you are changing the contract.

## License and trademarks

- All contributions are accepted under **GPL-3.0-or-later** (see `LICENSE.md`).
- By submitting a PR, you agree your contribution may be redistributed under that license.
- **Trademarks:** “zasm” and related marks are not granted under the GPL. Don’t use the project name/logo to market forks.

## Setup (macOS)

### Required tools

- `clang` (or `cc`)
- GNU **Bison 3.x** (macOS `/usr/bin/bison` is often too old)
- `flex`
- `make`

Homebrew:

```sh
brew install bison flex
```

Then either:

```sh
export PATH="/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/flex/bin:$PATH"
```

or build with overrides:

```sh
make BISON=/opt/homebrew/opt/bison/bin/bison FLEX=/opt/homebrew/opt/flex/bin/flex
```

## Build

```sh
make zas zld zrun
```

Outputs:

- `bin/zas`
- `bin/zld`
- `bin/zrun`

## Quick pipeline

```sh
cat examples/hello.asm | bin/zas | bin/zld > build/out.wat
```

(Optional) if you have WABT installed:

```sh
wat2wasm build/out.wat -o build/out.wasm
```

## Run examples (local harness)

`zrun` exists so we can test without depending on external runtimes.

```sh
# compile
cat examples/hello.asm | bin/zas | bin/zld > build/hello.wat

# run (writes stdout bytes to a file, logs to stderr)
./bin/zrun build/hello.wat --in examples/input.txt --out build/out.txt
```

See `Makefile` for current smoke targets.

## Tests

We prefer **golden tests**:

- input fixture → expected output bytes
- keep tests deterministic (no timestamps, no randomness)

Run:

```sh
make test
```

If you add a new opcode or directive, add at least:

1) a tiny `.asm` program in `examples/`
2) a golden test that exercises it end-to-end (`zas | zld | zrun`)

## Adding ISA support

When adding instructions/directives, do the minimum to keep the system consistent:

1) **Parser (zas)**
   - update lexer/parser to accept the syntax
   - emit JSONL IR records

2) **Lowering (zld)**
   - implement semantics in `wat_emit.c`
   - reject unsupported forms with clear errors (include line numbers)

3) **Example + test**

Guidelines:

- Prefer incremental additions (one opcode, one PR).
- Validate operand forms strictly.
- If an instruction has multiple legal forms, implement one first, then extend.

## IR changes (JSONL contract)

If you need to change the IR schema:

- Update the schema in `schema/`.
- Update both `zas` and `zld` in the same PR.
- Add a migration note in the PR description.

Strong preference: **extend** rather than break. New fields should be optional when possible.

## Style

- C is C11.
- Keep code boring and readable.
- Avoid hidden global state.
- Errors should include `tool: message` and a source line if available.

## PR checklist

- [ ] Builds: `make zas zld zrun`
- [ ] Tests: `make test`
- [ ] Added/updated examples if behavior changes
- [ ] IR/schema updated if needed
- [ ] No gratuitous refactors (separate PRs)

## Security

If you find a security issue (especially around parsing or bounds handling), please open a private report instead of posting a public issue.

---

Welcome aboard.