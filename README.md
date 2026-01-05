<p align="center">
  <strong>zasm</strong><br>
  <em>A Deterministic Virtual ISA and Cross-Compilation Toolchain</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.5-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-GPL--3.0-green" alt="License">
  <img src="https://img.shields.io/badge/targets-arm64%20%7C%20x86__64%20%7C%20WASM%20%7C%20RV64I-orange" alt="Targets">
</p>

---

## What is zasm?

**zasm** is a custom virtual instruction set architecture (ISA) and cross-compilation toolchain designed for **deterministic**, **auditable**, and **sandboxed** code execution across multiple hardware targets.

At its core, zasm defines a **64-bit register-based virtual processor** with a clean opcode encoding, which can be:

- **Interpreted** via the included cloak runtime
- **JIT-compiled** to native arm64 or x86_64 machine code
- **Ahead-of-time compiled** to WebAssembly (WASM)
- **Translated** to other ISAs (RISC-V RV64I planned)

Beyond the core CPU profile, future work explores specialized profiles:
**zASMA** (accelerator/GPU), **zASMF** (FPGA), and **zASM32** (Cortex‑M class).
These are parked specs today and are not implemented yet.

The assembly syntax uses Z80-inspired mnemonics for human readability—but this is **not a Z80 emulator**. It is a modern, purpose-built virtual silicon designed for cross-platform deterministic execution with formal ABI contracts.

> **Status:** v1.0.5 — Normative specs for ISA, IR, ABI, and opcode encoding are stable. Breaking changes trigger major version bumps.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SOURCE (.asm)                                  │
│                     Human-readable Z80-style mnemonics                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            zas (Assembler)                                  │
│               Parses source → Emits versioned JSONL IR                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
              ▼                       ▼                       ▼
┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────────┐
│   zld (Linker)      │   │   zop (Packer)      │   │  Third-Party Compilers  │
│   JSONL → WAT/WASM  │   │   JSONL → .zasm.bin │   │  (Your DSL → JSONL IR)  │
└─────────────────────┘   └─────────────────────┘   └─────────────────────────┘
          │                         │
          ▼                         ▼
┌─────────────────────┐   ┌─────────────────────────────────────────────────┐
│   WebAssembly       │   │              libzxc (Cross-Compiler)            │
│   (Any WASM host)   │   │   Opcode bytes → Native machine code            │
└─────────────────────┘   │   ┌─────────────┬─────────────┬───────────────┐ │
                          │   │   arm64     │   x86_64    │  RV64I (soon) │ │
                          │   └─────────────┴─────────────┴───────────────┘ │
                          └─────────────────────────────────────────────────┘
                                            │
                                            ▼
                          ┌─────────────────────────────────────────────────┐
                          │           Cloak Runtime (Sandbox)               │
                          │   Capability-gated execution with ABI contract  │
                          │   • zrun (WASM via wasmtime)                    │
                          │   • zcloak (Pure C interpreter)                 │
                          │   • zcloak-jit (JIT via libzxc)                 │
                          └─────────────────────────────────────────────────┘
```

---

## Key Differentiators

### 🎯 Custom Virtual ISA (Not an Emulator)

zasm defines a **64-bit register-based instruction set** with:

- **Fixed 32-bit base instruction word** with extension words for large immediates
- **16-register file** (5 currently mapped: HL, DE, A, BC, IX)
- **Explicit opcode encoding** (documented in `docs/spec/opcode_encoding.md`)
- **Both 32-bit and 64-bit arithmetic** with zero-extension semantics
- **Memory operations** with bounds checking built into the ABI

This is **not** a Z80 emulator—the mnemonics are merely a UX choice for readability. The underlying architecture is closer to RISC-V in philosophy.

### 🔒 Deterministic by Design

Every aspect of zasm is built for **byte-for-byte reproducibility**:

- No timestamps, random IDs, or host-dependent formatting
- Deterministic memory layout with fixed base offsets and 4-byte alignment
- Deterministic allocator behavior (`_alloc` results are reproducible for identical call sequences)
- Identical inputs → identical outputs across runs, machines, and platforms

This makes zasm ideal for **content-addressable systems**, **blockchain execution**, and **reproducible builds**.

### 🛡️ Capability-Gated Sandboxing

The **Cloak** runtime model enforces a strict capability boundary:

- **All host interactions** use explicit primitives prefixed with `_` (e.g., `_in`, `_out`, `_alloc`, `_ctl`)
- **No ambient authority**—if it's not in the ABI, it doesn't exist
- **Fail-closed security**—disallowed primitives cause instantiation failure
- **Full auditability**—every side effect is visible in source

The `_ctl` control plane uses **ZCL1 framing** for capability discovery and extension, allowing hosts to expose new features without changing the core ABI.

### 🔌 Multi-Target Cross-Compilation

A single source compiles to multiple backends:

| Target | Output | Use Case |
|--------|--------|----------|
| `--target wasm` | WebAssembly (WAT/WASM) | Browser, edge, serverless |
| `--target zasm` | Native opcode bytes | JIT/AOT via libzxc |
| `--target rv64i` | RISC-V RV64I | Embedded, FPGA, future hardware |

The **libzxc** library provides embeddable C APIs for translating opcode streams to native machine code:

```c
zxc_result_t zxc_arm64_translate(const uint8_t* in, size_t in_len,
                                 uint8_t* out, size_t out_cap,
                                 uint64_t mem_base, uint64_t mem_size);

zxc_result_t zxc_x86_64_translate(const uint8_t* in, size_t in_len,
                                  uint8_t* out, size_t out_cap,
                                  uint64_t mem_base, uint64_t mem_size);
```

### 📜 Stable, Versioned Contracts

zasm ships with **normative specifications** that third-party tools can rely on:

- **ISA Spec** (`docs/spec/isa.md`) — Registers, instructions, directives
- **ABI Spec** (`docs/spec/abi.md`) — Host primitives, memory model, handle semantics
- **IR Spec** (`docs/spec/ir.md`) — JSONL intermediate representation
- **Opcode Spec** (`docs/spec/opcode_encoding.md`) — Binary encoding for native backends

The **Integrator Pack** (`integrator_pack/`) provides schemas, conformance tests, and a reference C cloak implementation for third-party compiler authors.

---

## Use Cases

### 🏗️ DSL Backend / Compiler Target

Building a domain-specific language? Emit JSONL IR and let zasm handle the hard parts:

```json
{"ir":"zasm-v1.0","kind":"instr","op":"LD","ops":[{"t":"sym","v":"HL"},{"t":"sym","v":"msg"}],"loc":{"line":5}}
{"ir":"zasm-v1.0","kind":"instr","op":"CALL","ops":[{"t":"sym","v":"_out"}],"loc":{"line":6}}
```

No need to handle WASM's structured control flow—`zld` converts labels and jumps automatically.

### �� Zero-Trust Plugin Execution

Run untrusted code with full auditability:

- Every host call is explicit (`CALL _out`, `CALL _alloc`)
- No hidden syscalls or ambient capabilities
- Memory bounds checked at the ABI level
- Deterministic execution for replay/audit

### 🗄️ Content-Addressable / Immutable Systems

Perfect for systems where the **hash is the identity**:

- IPFS / Filecoin compute
- Blockchain smart contracts
- Build caches and artifact stores
- Reproducible research

### ⚡ High-Performance Stream Processing

The `(HL, DE)` = `(ptr, len)` slice convention enables:

- O(1) length lookups (no NUL scanning)
- Zero-copy buffer passing
- UNIX-style filter composition

---

## Quick Start

### Build

```sh
make              # Build core tools (zas, zld, zlnt, zop)
make zrun         # Build WASM runner (requires wasmtime-c-api)
make zcloak       # Build pure-C cloak runtime
make zcloak-jit   # Build JIT runner (via libzxc)
```

### Hello World (WASM Target)

```asm
; hello.asm
CALL print_hello
RET

print_hello:
  LD HL, msg
  LD DE, msg_len
  CALL _out
  RET

msg:      STR "Hello from zasm!"
```

```sh
cat hello.asm | bin/zas | bin/zld > hello.wat
wat2wasm hello.wat -o hello.wasm
bin/zrun hello.wat
```

### Native JIT Execution

```sh
cat hello.asm | bin/zas --target opcodes | bin/zop --container > hello.zasm.bin
bin/zcloak-jit --mem 2mb hello.zasm.bin
```

JIT error semantics:
- Bounds violations and div0 traps raise a signal and `zcloak-jit` exits non-zero with a diagnostic.
- Host ABI faults (invalid pointers/handles) are reported as `zcloak` faults after execution.

---

## Toolchain

| Tool | Description |
|------|-------------|
| `zas` | Assembler: zASM source → JSONL IR |
| `zld` | Linker: JSONL IR → WAT/WASM |
| `zop` | Packer: JSONL opcode stream → `.zasm.bin` |
| `zlnt` | Linter: Static analysis for JSONL IR |
| `zrun` | Runner: Execute WAT/WASM via wasmtime |
| `zcloak` | Pure-C cloak runtime (interpreter) |
| `zcloak-jit` | JIT runner via libzxc |
| `libzxc` | Embeddable cross-compiler library (C API) |

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](./docs/architecture.md) | System design and pipeline overview |
| [docs/developers.md](./docs/developers.md) | Getting started guide |
| [docs/spec/isa.md](./docs/spec/isa.md) | **Normative** instruction set specification |
| [docs/spec/abi.md](./docs/spec/abi.md) | **Normative** host ABI and capability model |
| [docs/spec/ir.md](./docs/spec/ir.md) | **Normative** JSONL IR format |
| [docs/spec/opcode_encoding.md](./docs/spec/opcode_encoding.md) | **Normative** binary opcode encoding |
| [docs/spec/zasm_bin.md](./docs/spec/zasm_bin.md) | **Normative** `.zasm.bin` container format |
| [docs/spec/accelerator.md](./docs/spec/accelerator.md) | Accelerator profile (CUDA/Vulkan/Metal; draft) |
| [docs/spec/fpga.md](./docs/spec/fpga.md) | FPGA profile (HLS/RTL; draft) |
| [docs/integrator_pack/jit/README.md](./docs/integrator_pack/jit/README.md) | JIT codepack snapshot (integrator pack) |
| [docs/integrator_pack.md](./docs/integrator_pack.md) | Third-party compiler integration guide |
| [lembeh/CLOAK_INTEGRATOR_GUIDE.md](./lembeh/CLOAK_INTEGRATOR_GUIDE.md) | **Normative** cloak runtime implementation guide |

---

## Project Status

### ✅ Stable (v1.x)

- JSONL IR schema and versioning
- Host ABI (`req_read`, `res_write`, `res_end`, `log`, `_alloc`, `_free`, `_ctl`)
- Core ISA (arithmetic, logic, shifts, loads, stores, branches, calls)
- WASM backend via `zld`
- Pure-C cloak runtime
- Opcode binary encoding

### 🚧 In Progress

- libzxc arm64 backend (partial coverage)
- libzxc x86_64 backend (Group A only)
- `zcloak-jit` native execution

### 📋 Planned

- RV64I backend
- Additional target architectures
- VS Code extension (syntax highlighting, diagnostics)
- Expanded conformance test suite

---

## Contributing

Contributions are welcome. Areas of interest:

- **Backend coverage**: Expanding opcode support in libzxc (arm64, x86_64)
- **New targets**: RV64I, additional architectures
- **Tooling**: Editor integrations, debugging support
- **Conformance tests**: Golden tests for all mnemonic/operand combinations
- **Documentation**: Examples, tutorials, integration guides

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## License

- **Toolchain code**: GPL-3.0-or-later
- **Assembly examples and libraries** (`examples/*.asm`, `lib/*.asm`): MIT
- See [LICENSE](./LICENSE), [LICENSE-ASM](./LICENSE-ASM), and [TRADEMARK.md](./TRADEMARK.md)

---

<p align="center">
  <em>zasm: Write once, run deterministically everywhere.</em>
</p>
