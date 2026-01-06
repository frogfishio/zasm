<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Integrator Pack (README)

This folder is the **Integrator Pack** bundle. It exists so third-party
compiler and runtime authors can integrate with the zasm toolchain without
having to pull the whole repo. It includes the IR schema, normative specs,
conformance tests, and a cloak integration guide.

## What This Pack Is For

- **Compiler authors**: emit JSONL IR that `zld` accepts.
- **Runtime authors**: implement the cloak ABI correctly.
- **Tooling authors**: validate conformance before shipping integrations.

## What Is Where (and Why)

### Core Guides

- `CLOAK_INTEGRATOR_GUIDE.md`  
  The **normative** cloak ABI guide. This is the single source of truth for
  host/guest integration behavior (imports, memory model, `_ctl` framing, etc.).

- `docs/integrator_pack.md`  
  A high-level overview of the pack and how to use it.

### Schemas and Specs

- `schema/ir/v1/record.schema.json`  
  JSON Schema for the **ZASM JSONL IR** (what compilers emit).

- `docs/spec/abi.md`  
  Normative ABI contract for host primitives and memory rules.

- `docs/spec/ir.md`  
  Normative JSONL IR record definitions.

- `docs/spec/isa.md`  
  Normative ISA description (registers, instructions, directives).

### Conformance Tests

- `test/conform_zld.sh` and `test/conform_zld/*`  
  Schema compliance tests for JSONL IR.

- `test/abi_*`  
  ABI behavior tests (alloc/free, streaming, log, entrypoints, imports).

## How To Use It

1. **Emit JSONL IR** that matches `schema/ir/v1/record.schema.json`.
2. **Run schema checks** with `zld --conform` or the provided tests.
3. **Implement the cloak ABI** exactly as described in
   `CLOAK_INTEGRATOR_GUIDE.md`.
4. **Run ABI tests** to validate host behavior.

## Notes

The contents here are a curated bundle of files from the main repo. If you need
the authoritative source, refer back to the main project.
