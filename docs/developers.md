
<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zasm Developer Guide

Welcome to the **zasm** developer community. This guide provides the technical foundation required to build the toolchain, understand the pipeline, and contribute.

## 1. Philosophical Foundation

**zasm** is not a general-purpose compiler; it is a **Deterministic Binary Factory**. We prioritize:

* **Predictability:** Identical source always produces identical, hashable WASM.
* **Auditability:** A human should be able to read the generated WAT and map it to the ZASM source.
* **Safety:** The host is protected by the WASM sandbox; the guest is protected by `zlnt` static analysis.

---

## 2. Environment & Toolchain Setup

### Prerequisites

To build the core toolchain, you need a standard C development environment:

* **Build Tools:** `make`, `gcc` or `clang`.
* **Parser Generators:** `flex` (lexical analyzer) and `bison` (parser).
* **WASM Tooling:** `wat2wasm` (from [wabt](https://github.com/WebAssembly/wabt)) if you want `.wasm` output. `zrun` can run `.wat` directly.

For reproducible tooling across macOS and Linux, install the pinned versions used by this repo:

```bash
scripts/install-tools.sh
source tools/env.sh
```

Edit `tools/versions.env` if you need to update the pinned tool versions.

### Building the Toolchain

```bash
git clone https://github.com/frogfish/zasm
cd zasm
make

```

### The `zrun` Harness (Optional)

`zrun` allows you to execute `.wat` files locally using the **Wasmtime** engine. It requires the Wasmtime C API.

```bash
export WASMTIME_C_API_DIR=/path/to/wasmtime-c-api
make zrun

```

---

## 2.1 Project Layout

The source lives under `src/`, specs under `docs/spec/`, tools under `docs/tools/`, with examples in `examples/` and reusable modules in `lib/`.
See `docs/project_structure.md` for the canonical repository map and conventions.

## 3. The "Z-Stack" Pipeline

The toolchain operates as a series of UNIX filters. Data flows through standard streams, allowing for easy composition and linting.

### The Standard Build Flow:

1. **Authoring:** Create `.zasm` source files.
2. **Assembly (`zas`):** Converts text to **JSONL IR**.
3. **Verification (`zlnt`):** Inspects the IR for register-contract violations.
4. **Linking/Lowering (`zld`):** Resolves labels and produces structured **WAT**.
5. **Emission (`wat2wasm`):** Produces the final `.wasm` binary.

**Command Line Execution:**

```bash
cat main.asm lib/itoa.asm | bin/zas | bin/zlnt
cat main.asm lib/itoa.asm | bin/zas | bin/zld > build/app.wat

```

---

## 4. Authoring Modules (ZASM)

### The `(HL, DE)` Slice Convention

All I/O in the standard system ABI revolves around the "Slice." Instead of passing pointers and assuming null-terminators, we pass an explicit `(ptr, len)` pair.

* **HL:** Points to the start of the data in linear memory.
* **DE:** Contains the length of the data (number of bytes).

### Example: A Reusable Library Function

`lib/hello.asm`:

```asm
; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

print_hello:
  LD HL, msg
  LD DE, msg_len
  CALL _out      ; Host primitive for output
  RET

msg: STR "Hello, zasm!", 10
; STR auto-defines msg_len for you.

```

---

## 5. Memory Model & Determinism

### Linear Memory Layout

`zld` manages the layout of your module's memory deterministically.

* **Static Data:** Starts at a fixed offset (usually `8` to avoid null-pointer accidents).
* **`RESB` (Reserve Bytes):** Moves the data cursor forward for uninitialized space.
* **`__heap_base`:** `zld` automatically exports this global to tell the host where safe dynamic allocation can begin.

### Reproducible Builds

Because `zld` calculates offsets and label positions in a single stable pass over the JSONL IR, the resulting WAT is bit-for-bit identical regardless of the host OS or build timestamp.

---

## 6. Security & Static Analysis (`zlnt`)

`zlnt` is the gatekeeper of the toolchain. It performs **Data-Flow Analysis** on the IR before it is linked.

### Current Security Checks:

* **Register Definitions:** Warns if `_out` is called without `HL` and `DE` being defined.
* **Register Use Errors:** Errors if `_in/_log/_alloc/_free` are called without required registers being defined.

---

## 7. Troubleshooting

| Error | Cause | Solution |
| --- | --- | --- |
| `zas: syntax error` | Malformed ZASM or unknown mnemonic. | Verify against `docs/spec/isa.md`. |
| `zld: unknown symbol` | A `CALL` or `JR` targets a non-existent label. | Ensure all library files are included in the `cat` pipe. |
| `zrun: trap` | Guest code accessed memory out of bounds. | Use `zlnt` to verify `HL` pointers and segment sizes. |
| `Linker Collision` | Multiple files define the same label. | Use unique prefixes or namespacing for library functions. |

---

## 8. Contributing to the Ecosystem

We welcome contributions that respect the "Boring Correctness" philosophy:

1. **Frontend DSLs:** Build a compiler that targets the **JSONL IR**.
2. **Standard Libraries:** Contribute MIT-licensed `.zasm` helpers (e.g., `math`, `base64`, `json-parser`).
3. **Linter Rules:** Add new safety checks to `zlnt`.
