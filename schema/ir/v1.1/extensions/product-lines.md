# ZX64 product lines — ZX64, Z64+S, ZX64S (why + how)

This document defines the **three runtime/product lines** that share the ZASM ecosystem:

- **ZX64** — classic (register-machine) virtual CPU
- **Z64+S** — ZX64 **plus** the *stacker coprocessor* (interop substrate)
- **ZX64S** — stack-machine virtual CPU (stacker as the whole CPU), specified by the **stacker CPU addendum**

These are **not marketing names**. They are **normative runtime models** with different legal opcode sets and different guarantees.

---

## 1. The one-line rule

- **ZX64**: classic CPU only.
- **Z64+S**: classic CPU **+ stacker coprocessor** (stacker is a *substrate*, not the control-flow engine).
- **ZX64S**: stack CPU (stacker is the **control-flow engine**; classic control flow is illegal).

If you remember only one thing:  
**ZX64S is not “ZX64 with more ops.” It’s a different execution model.**

---

## 2. Why three lines exist

### 2.1 ZX64 (classic) exists because it’s stable and already works
ZX64 is the “battle-tested default.” It’s a good model for:

- mixed workloads
- systems code
- predictable lowering to native AOT/JIT (Mach-O + ARM64, x86_64, RISC-V…)
- predictable debugging (regs + memory + PC)

ZX64 is the baseline platform: when in doubt, target ZX64.

### 2.2 Z64+S exists to mix paradigms without switching machines
Some frontends (WASM-ish, Forth-ish, some IR shapes) want a stack substrate sometimes, but **you do not want a pure stack ISA as your whole world**.

So Z64+S exists: it keeps classic ZX64 semantics intact, but adds a **WASM-representable stack substrate** you can enter/exit explicitly.

This gives you:

- stack-native lowering where it helps
- classic register logic where it helps
- explicit bridges between them (`SPUSH.*` / `SPOP.*`)
- no hidden type stack, no auto-switching
- deterministic validation and tooling hooks

### 2.3 ZX64S exists for “stack-first” targets and stack-first backends
Some targets *are* naturally a stack machine:

- WASM
- JVM bytecode
- CLR IL

These benefit from a stack CPU where the *entire program* can live in a stack discipline and the backend can emit stack maps / verifier proofs cleanly.

ZX64S exists for those cases — but it is intentionally constrained so it doesn’t become “a weird hybrid ISA with two conflicting branch models.”

---

## 3. Execution model differences (the important part)

### 3.1 Control flow

#### ZX64
- Control flow is classic: `JR`, `CALL`, `RET`, etc.
- PC semantics follow the ZX64 concrete model.
- No stacker requirements.

#### Z64+S
- Control flow is still classic: `JR`, `CALL`, `RET`, etc.
- Stacker is a **data substrate only**.
- You can push values to DS, do work, pop back to regs, and continue.

**Key property:** Z64+S remains representable as:
- classic machine state + DS/RS stacks (optional RS)
- every stacker state is WASM-style representable (if you choose WASM lowering)

#### ZX64S (Option A: stacker-only control flow)
- **Only stacker CPU control-flow ops may modify PC** (`SBR`, `SCBR`, `SCALL`, `SRET`).
- Any classic control-flow opcode MUST be rejected as `ILLEGAL_OPCODE`.
- PC is explicitly “instruction-record index” semantics.

**Why this matters:** it removes ambiguity and makes proofs/verification/trace tooling stable.

---

## 4. Opcode legality: the normative contract

Think of this as “what validators must reject.”

### 4.1 ZX64
Legal:
- all classic ZX64 opcodes

Illegal:
- stacker opcodes unless the runtime explicitly supports them (ZX64 alone does not)

### 4.2 Z64+S (coprocessor runtime)
Legal:
- classic ZX64 opcodes
- stacker coprocessor opcodes in `+stacker:v1` (and optional `+stacker.rs:v1`, `+stacker.i32ops:v1`)

Illegal (normative):
- any ZX64S CPU addendum opcodes (`+stacker.cpu:v1` family)
- the runtime MUST NOT expose or accept them

### 4.3 ZX64S (stack CPU runtime)
Legal:
- stacker base (`+stacker:v1`)
- (recommended) stacker RS (`+stacker.rs:v1`)
- stacker CPU addendum (`+stacker.cpu:v1`)
- stacker CPU control flow ops (`SBR`, `SCBR`, `SCALL`, `SRET`)

Illegal (normative):
- classic control-flow ops (`JR*`, `CALL`, `RET`, etc.)
- other classic “CPU model” ops unless explicitly reintroduced by a separate appendix (not planned)

---

## 5. “Why not just make everything Z64+S and call it a day?”

Because the **control-flow model** must be unambiguous.

- Z64+S has a classic PC/control flow and stacker is a data substrate.
- ZX64S has stacker as the CPU, PC is instruction-record index, and control flow is stack-defined.

Trying to allow both in one model forces you to specify:
- how classic CALL interacts with RS return addresses
- whether “return address” means native PC or record index
- how branch targets resolve across two families
- how validators and reducers preserve correctness

That complexity destroys the determinism and toolability you built.

So: two clean lines.

---

## 6. Choosing the line at lowering time (policy)

This is intentional: **no runtime auto-switch**.

### Choose ZX64 when:
- you want “normal CPU” semantics
- you want maximum backend availability
- you don’t need stack-native backends (WASM/JVM/CLR)
- you care about conventional debug ergonomics

### Choose Z64+S when:
- you want classic control flow but occasional stack work
- you want Forth/WASM-like frontends to interop with “classic world”
- you want stack shuffles for dense patterns / tooling (n-gram reducers, peepholes)
- you want to keep a single “mixed workload” runtime

### Choose ZX64S when:
- the backend is stack-first (WASM/JVM/CLR)
- the frontend is stack-native end-to-end
- you want verifier-friendly compilation and stack-map hooks
- you’re okay living entirely in stack control flow

---

## 7. How this maps to “profiles” conceptually

Profiles don’t mean “optional runtime magic.” They mean:

- The **program** declares required features
- The **target runtime** declares supported features
- If unsupported: lowering fails (static error)

### Common examples
- `+stacker:v1` → stack substrate present
- `+stacker.rs:v1` → second stack present
- `+stacker.i32ops:v1` → typed i32 ops / narrow loads/stores present
- `+stacker.cpu:v1` → ZX64S only (stack CPU control flow)

(Other profiles like FP/SIMD/tensor follow the same policy.)

---

## 8. A concrete mental model for implementers

### ZX64 runtime state
- classic regs (HL/DE/BC/IX/A/… as defined)
- memory model
- classic PC model

### Z64+S runtime state
- ZX64 state
- DS stack (cell64)
- optional RS stack (cell64), if enabled
- no extra PC model beyond classic ZX64

### ZX64S runtime state
- DS stack (cell64)
- optional RS stack (cell64)
- PC = instruction-record index
- control flow only via `SBR/SCBR/SCALL/SRET`

---

## 9. Non-goals (explicit)

- Z64+S is **not** “a stack CPU.”
- ZX64S is **not** “a hybrid that also accepts classic JR/CALL/RET.”
- No runtime auto-detection or auto-switching of profiles.
- Portability is policy-driven: if you target stack-only or SIMD-only, that is a compile-time choice.

---

## 10. Summary table

| Product line | Classic regs/ops | Classic control flow | Stacker DS/RS | Stacker CPU control flow | Primary targets |
|---|---:|---:|---:|---:|---|
| **ZX64** | ✅ | ✅ | ❌ | ❌ | native AOT/JIT |
| **Z64+S** | ✅ | ✅ | ✅ | ❌ | mixed workloads, WASM-ish + classic |
| **ZX64S** | (optional) ❌ | ❌ | ✅ | ✅ | WASM/JVM/CLR |

---

## 11. Where the specs live

- Stacker coprocessor ISA: `stacker.md` (main body)
- ZX64S stack CPU addendum: `stacker.md` Appendix A (`+stacker.cpu:v1`)
- (Future) ZX64 base ISA: `zx64.md` (separate doc)
- (Future) Profiles (fp/simd/etc.): separate extension docs following the same gating rules