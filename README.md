
# zasm – A Deterministic, Pipeline-Friendly Assembler for WebAssembly

**zasm** is a small, focused toolchain that compiles a readable Z80-inspired assembly language (zASM) into WebAssembly via a clean, versioned intermediate representation.

> **Status:** v1.0.0 (Normative). The JSONL IR and host ABI are stable. Breaking changes will trigger a major version bump.

The toolchain is designed to behave like a classic UNIX filter pipeline:



```sh
cat hello.zasm | zas | zld > hello.wat

```

From there, any standard WAT-to-WASM tool (`wat2wasm`, etc.) produces the final binary.

Start here: `docs/developers.md` for setup + hello world.

---
### New flags (memory limits)

- `zld --mem-max <size>` sets a maximum linear memory size in the emitted module (bytes/kb/mb/gb).
- `zrun --mem <size>` caps runtime memory (default `256MB`, floor `2MB`, ceiling `2GB`).
- `ZRUN_MEM` can override the default cap (same syntax as `--mem`).

---

### Why use zasm? (The "Yeah, I need this" scenarios)

Most WASM toolchains are built around high-level languages with complex, non-deterministic backends. zasm is built for scenarios where predictability and auditability are the primary features.

#### 1. The "Zero-Trust" Logic Engine

**The Scenario:** You allow users or 3rd-party plugins to upload "filters" to your platform, but you need to guarantee they won't steal data or escape the sandbox.

* **Why zasm:** Unlike Rust or Go, which pull in massive standard libraries, zasm is "fail-closed." You can audit a `.zasm` file and see every host interaction because they all start with the `_` prefix. It is the world’s most auditable way to run untrusted code at near-native speeds.

#### 2. "Forever-Builds" for Content-Addressable Storage

**The Scenario:** You are building a system like IPFS, a blockchain, or a massive build cache where the *hash* of the binary is the source of truth.

* **Why zasm:** Traditional compilers inject timestamps or host paths that change the binary hash. zasm is fanatical about determinism. Identical inputs always produce identical WAT/WASM, ensuring perfect cache hits and immutable identity for your modules.

#### 3. The "Glue Language" for DSLs

**The Scenario:** You want to create a specialized language (for finance, IoT, or a visual logic builder) but don't want to spend months writing a WebAssembly backend.

* **Why zasm:** Targeting the JSONL IR is a "cheat code." You don't have to handle the complex structured control-flow requirements of WASM; you just emit JSON "labels" and "jumps," and `zld` handles the heavy lifting. It is effectively **WASM Backend-as-a-Service.**

#### 4. High-Efficiency Streaming Pipelines

**The Scenario:** You are building a data transformation pipeline where modules must handle gigabytes of data with minimal latency.

* **Why zasm:** The host ABI uses an explicit `(HL, DE)` slice convention for `(ptr, len)`. This avoids expensive NUL-terminated string scans and allows for O(1) length lookups, making it ideal for chaining tiny "nanoservices" together like UNIX tools.

---

### Quick example

`hello.zasm`:

```asm
; Entry point
CALL print_hello
RET

print_hello:
  LD HL, msg
  LD DE, msg_len
  CALL _out      ; Primitive: write(HL, DE)
  RET

msg:      DB "Hello, zasm from Zilog!", 10
msg_len:  EQU 24

```

**Build Pipeline:**

```sh
cat hello.zasm | zas | zld > hello.wat
wat2wasm hello.wat -o hello.wasm

```

---

### Documentation & Specifications

zasm is built on formal stability contracts. Detailed normative specifications are available in the repository:

* **[docs/spec/abi.md](./docs/spec/abi.md)** – The host ABI (stream primitives and imports).
* **[docs/spec/isa.md](./docs/spec/isa.md)** – The Instruction Set Architecture and directives.
* **[docs/spec/ir.md](./docs/spec/ir.md)** – JSONL IR format and versioning rules.
* **[docs/architecture.md](./docs/architecture.md)** – Design notes on lowering, determinism, and memory policy.
* **[docs/developers.md](./docs/developers.md)** – Getting started and hello world.
* **[docs/project_structure.md](./docs/project_structure.md)** – Repository layout and conventions.
* **[docs/integrator_pack.md](./docs/integrator_pack.md)** – Integrator Pack for third-party compiler authors.
* **[docs/tools/zas.md](./docs/tools/zas.md)** – Assembler usage (zASM → JSONL IR).
* **[docs/tools/zld.md](./docs/tools/zld.md)** – JSONL IR → WAT lowering behavior.
* **[docs/tools/zrun.md](./docs/tools/zrun.md)** – Local runner for modules exporting `lembeh_handle`.
* **[docs/tools/zlnt.md](./docs/tools/zlnt.md)** – JSONL lint/analyzer.

---

### Installation & Build

zasm is implemented in C using **flex** and **bison** for a robust, maintainable frontend.

**Prerequisites:**

* `bison`, `flex`, `llvm` (or `clang`)
* `wasmtime` (optional, for the `zrun` harness)

**Build:**

```sh
make
make zrun  # Requires wasmtime-c-api
sudo make install

```

**Make targets:**

```sh
make build        # Build all binaries (zas/zld/zrun/zlnt)
make dist         # Build and copy binaries to dist/<platform> with VERSION
make bump         # Bump patch version in VERSION
make test         # Run full test suite (grouped targets)
```

**Tool mode and diagnostics:**

```sh
bin/zas --tool -o build/app.jsonl src/app.asm src/lib.asm
bin/zld --tool -o build/app.wat build/app.jsonl
bin/zlnt --tool --json build/app.jsonl
bin/zrun --verbose build/app.wat
```

---

### Contributing

zasm remains intentionally narrow in scope: it is the stable core. Additional frontends can target the JSONL IR directly.

Contributions are welcome, especially regarding:

* Parser/grammar improvements and better diagnostics.
* Structured control-flow features that lower cleanly to WAT.
* Additional test coverage (golden `input.zasm → output.wat` pairs).

---

## License

Code is GPL-3.0-or-later. Assembly examples and libraries (`examples/*.asm`, `lib/*.asm`) are MIT. See `LICENSE`, `LICENSE-ASM`, and `TRADEMARK.md`.
