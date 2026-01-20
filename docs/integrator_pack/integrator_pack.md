<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Integrator Pack (Third-Party Compiler Authors)

This pack defines the normative contract for compilers that emit JSONL IR for `zld`.
Use it to validate that your compiler output is compatible with the zasm toolchain
without assuming a `zas` frontend.

## Goals

- Provide a stable, testable contract for JSONL IR emitters.
- Make conformance reproducible across toolchains and hosts.
- Keep ABI behavior verifiable before and after ABI changes.

## Pack contents

- **IR Schema:** `schema/ir/v1/record.schema.json`
- **IR Conformance Tests:** `test/conform_zld.sh` and `test/conform_zld/*`
- **ABI Tests:** `test/abi_*` (zABI syscall surface, alloc/free, entrypoint, imports)
- **ABI Spec:** `docs/spec/abi.md`
- **IR Spec:** `docs/spec/ir.md`
- **ISA Spec:** `docs/spec/isa.md`
- **Tooling:** `zld --conform` and `zld --conform=strict`
- **C Cloak:** `docs/integrator_pack/c_cloak/` (normative host interface)
- **JIT Codepack:** `docs/integrator_pack/jit/` (reference JIT runtime snapshot)

## Bundled pack locations

- Repository bundle: `integrator_pack/`
- Dist bundle: `dist/integrator_pack/`
- Pack manifest + builder: `docs/integrator_pack/`

To (re)build the bundles:

```sh
make integrator-pack
make dist-integrator-pack
```

## Compliance steps

1. **Emit JSONL IR** that matches the schema:
   - One JSON object per line.
   - `ir` is `zasm-v1.0`.
   - `loc.line` is strongly recommended; strict mode allows missing `loc`.
2. **Run strict schema checks**:
   - `bin/zld --conform=strict --verify < your_output.jsonl`
3. **Run ABI conformance** for the current ABI:
   - `make test-abi` (or run specific ABI tests)

## Required guarantees

- **Schema compliance:** record shape, identifiers, operand kinds, directive enums.
- **Version tag:** `ir: "zasm-v1.1"` is mandatory.
- **ABI behavior:** entrypoint, syscall surface, and allocation contract must match `docs/spec/abi.md`.

## Recommended outputs

- Provide JSONL fixtures for your compiler in a dedicated folder and run them
  through `zld --conform=strict --verify`.
- Store golden JSONL outputs for minimal programs to enable regression checks.

## Integration checklist

- Your compiler can emit all records described in `docs/spec/ir.md`.
- You can pass `zld --conform=strict --verify`.
- You can pass ABI tests for the current ABI (syscalls, alloc/free, entrypoint).
- You document your mapping from source language constructs to IR records.
