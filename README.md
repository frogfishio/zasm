<p align="center">
  <strong>zasm</strong><br>
  <em>A Deterministic Virtual CPU + IR Toolchain (WASM, native, and more)</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.5-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-GPL--3.0-green" alt="License">
  <img src="https://img.shields.io/badge/targets-arm64%20%7C%20x86__64%20%7C%20WASM%20%7C%20Mach--O%20%7C%20RV64I%20(planned)%20%7C%20JVM%2FCLR%20(planned)-orange" alt="Targets">
</p>

---

## What is zasm?

**zasm** is a compiler-and-runtime stack for **deterministic**, **auditable**, and **sandboxed** execution.

At the bottom, it defines a stable virtual CPU (the “ZASM64 / ZX64” model) with a concrete opcode encoding that can be:

- **Interpreted** (reference execution)
- **JIT-compiled** to native machine code (arm64 / x86_64; more planned)
- **AOT-lowered** to **WebAssembly** (WAT/WASM)
- **Packaged** as a portable opcode container for shipping and replay

But zasm is no longer “just a cute ISA”: it has grown into a **multi-IR toolchain** where:

- **Higher-level languages** can compile into a stable, streaming IR (SIR) and then lower through zasm layers.
- The host boundary is defined by a normative, capability-gated ABI (**zABI 2.x**, `env.zi_*`).
- Complex data lives in a controlled arena/record system (Hopper), enabling “memory-safe by default” frontends.

### Product lines (execution models)

zasm supports three closely-related runtime profiles:

- **ZX64** — classic register-machine virtual CPU (the stable baseline).
- **Z64+S** — ZX64 plus the optional **stacker coprocessor** (explicit stack substrate for mixed-work loads).
- **ZX64S** — a **stack-machine** runtime (stacker as the *whole CPU*; stacker-only control flow).

These are **compile-time/lowering-time choices** (no runtime auto-switch). If a target/runtime doesn’t support a requested profile, lowering fails.

> **Status:** v1.0.5 — core contracts are stable (ISA/IR/ABI/opcode encoding). Breaking changes trigger major version bumps.

---

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FRONTENDS (many languages)                           │
│              Oberon / C89 / DSLs / etc. → SIR (streaming typed IR)           │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         zasm layer (ZIR / zasm IR)                           │
│               Lowering, tooling, analysis, minimization, replay              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SOURCE (.asm) / zas (Assembler)                       │
│         Human-readable mnemonics → Emits versioned JSONL IR / opcode stream  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            zlnt (Analyzer)                                  │
│          Static analysis on JSONL IR (recommended safety gate)               │
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
│   WebAssembly       │   │              libzxc (Cross-Compiler)             │
│   (Any WASM host)   │   │   Opcode bytes → Native machine code             │
└─────────────────────┘   │   ┌─────────────┬─────────────┬───────────────┐  │
                          │   │   arm64     │   x86_64    │  RV64I (soon) │  │
                          │   └─────────────┴─────────────┴───────────────┘  │
                          └─────────────────────────────────────────────────┘
                                          │
                                          ▼
                          ┌─────────────────────────────────────────────────┐
                          │           Cloak Runtime (Sandbox)               │
                          │   Capability-gated execution with zABI 2.x      │
                          │   • zrun (WASM via wasmtime)                    │
                          │   • zcloak (Pure C interpreter)                 │
                          │   • zcloak-jit (JIT via libzxc)                 │
                          └─────────────────────────────────────────────────┘
```

---

## Key Differentiators

### 🎯 Custom Virtual ISA (Not an Emulator)

zasm defines a **64-bit virtual CPU** (ZX64) with:

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

### 🧱 More than an ISA: streaming IR + tooling

zasm is built around **line-oriented, versioned IR streams (JSONL)** so tools can operate on real programs:

- interpret and debug (reference semantics)
- trace execution and memory events
- compute and merge coverage
- delta-minimize and triage failures
- strip unreachable code and dead regions
- analyze repetition (n-grams) and bloat

This is the “compiler stack” part: a stable representation you can pipe through real toolchains.

### 🛡️ Capability-Gated Sandboxing

The runtime boundary is defined by a **normative host ABI** (zABI 2.x):

- **All host interactions** go through explicit `env.zi_*` syscalls (e.g. `zi_read`, `zi_write`, `zi_alloc`, `zi_ctl`).
- **No ambient authority** — if it’s not in the ABI surface, it doesn’t exist.
- **Fail-closed security** — missing capabilities are rejected via discovery/negotiation (`zi_ctl`).
- **Auditability** — host effects are explicit and can be traced, replayed, minimized, and certified.

This keeps zasm modules portable across hosts while preserving a strict sandbox contract.

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
                                 uint64_t mem_base, uint64_t mem_size,
                                 const struct zi_host_v1* host);

zxc_result_t zxc_x86_64_translate(const uint8_t* in, size_t in_len,
                                  uint8_t* out, size_t out_cap,
                                  uint64_t mem_base, uint64_t mem_size);
```

### 📜 Stable, Versioned Contracts

zasm ships with **normative specifications** that third-party tools can rely on:

- **ISA Spec** (`docs/spec/isa.md`) — Registers, instructions, directives
- | docs/spec/stacker.md | Stacker profile (coprocessor) and ZX64S addendum (stack CPU) |
- **ABI Spec** (`docs/spec/abi.md`) — Host primitives, memory model, handle semantics
- **IR Spec** (`docs/spec/ir.md`) — JSONL intermediate representation
- **Opcode Spec** (`docs/spec/opcode_encoding.md`) — Binary encoding for native backends

The historical **Integrator Pack** was ABI1-based and is now largely defunct; we will produce a new zABI 2.5 integrator pack later.

---

## Use Cases

### 🏗️ DSL Backend / Compiler Target

Building a domain-specific language? Emit JSONL IR and let zasm handle the hard parts:

```json
{"ir":"zasm-v1.1","kind":"instr","op":"LD","ops":[{"t":"reg","v":"DE"},{"t":"sym","v":"msg"}],"loc":{"line":5}}
{"ir":"zasm-v1.1","kind":"instr","op":"LD","ops":[{"t":"reg","v":"BC"},{"t":"sym","v":"msg_len"}],"loc":{"line":6}}
{"ir":"zasm-v1.1","kind":"instr","op":"LD","ops":[{"t":"reg","v":"HL"},{"t":"num","v":1}],"loc":{"line":7}}
{"ir":"zasm-v1.1","kind":"instr","op":"CALL","ops":[{"t":"sym","v":"zi_write"}],"loc":{"line":8}}
```

No need to handle WASM's structured control flow—`zld` converts labels and jumps automatically.

### �� Zero-Trust Plugin Execution

Run untrusted code with full auditability:

- Every host call is explicit (`CALL zi_write`, `CALL zi_alloc`)
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

The `(DE, BC)` = `(ptr, len)` slice convention (with `HL` as a handle for `zi_read/zi_write`) enables:

- O(1) length lookups (no NUL scanning)
- Zero-copy buffer passing
- UNIX-style filter composition

---

## Quick Start

## Deliverables

For end users, zasm is delivered as **self-contained compiled binaries** (e.g. `bin/<platform>/*`, with convenience symlinks under `bin/`).

The repository may contain scripts used for development, testing, or internal workflows; they are not part of the user-facing product surface.

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
  LD BC, DE
  LD DE, HL
  LD HL, #1
  CALL zi_write
  RET

msg:      STR "Hello from zasm!"
```

```sh
cat hello.asm | bin/zas | bin/zlnt | bin/zld > hello.wat
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
| `zem` | Emulator + debugger: Execute JSONL IR directly (trace/debug/events) |
| `zcloak` | Pure-C cloak runtime (interpreter) |
| `zcloak-jit` | JIT runner via libzxc |
| `libzxc` | Embeddable cross-compiler library (C API) |

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](./docs/architecture.md) | System design and pipeline overview |
| docs/spec/stacker.md | Stacker profile (coprocessor) and ZX64S addendum (stack CPU) |
| [docs/developers.md](./docs/developers.md) | Getting started guide |
| [docs/spec/isa.md](./docs/spec/isa.md) | **Normative** instruction set specification |
| [docs/spec/abi.md](./docs/spec/abi.md) | **Normative** host ABI and capability model |
| [docs/spec/ir.md](./docs/spec/ir.md) | **Normative** JSONL IR format |
| [docs/spec/opcode_encoding.md](./docs/spec/opcode_encoding.md) | **Normative** binary opcode encoding |
| [docs/spec/zasm_bin.md](./docs/spec/zasm_bin.md) | **Normative** `.zasm.bin` container format |
| [docs/tools/zem.md](./docs/tools/zem.md) | `zem` usage (debugger + JSONL stop events) |
| [docs/spec/accelerator.md](./docs/spec/accelerator.md) | Accelerator profile (CUDA/Vulkan/Metal; draft) |
| [docs/spec/fpga.md](./docs/spec/fpga.md) | FPGA profile (HLS/RTL; draft) |
| [docs/integrator_pack/jit/README.md](./docs/integrator_pack/jit/README.md) | JIT codepack snapshot (integrator pack) |
| [docs/integrator_pack/integrator_pack.md](./docs/integrator_pack/integrator_pack.md) | Third-party compiler integration guide |
| [docs/integrator_pack/integrator_pack/CLOAK_INTEGRATOR_GUIDE.md](./docs/integrator_pack/integrator_pack/CLOAK_INTEGRATOR_GUIDE.md) | Legacy cloak integration guide (retired) |

---

## Project Status

### ✅ Stable (v1.x)

- JSONL IR schema and versioning
- Host ABI (zABI 2.0: `env.zi_*` syscalls)
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

## Tools

- `zas`: assembler → JSONL/opcodes (docs/tools/zas.md)
- `lower`: JSON IR (zasm-v1.0/v1.1) → macOS arm64 Mach-O with rich dump/LLDB helper modes (docs/tools/lower.md)
- `zxc`: experimental cross-compilers (docs/tools/zxc.md)
- `zir`: IR utilities
