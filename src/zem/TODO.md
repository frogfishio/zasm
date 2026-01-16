# zem — Prime-time TODO (Runner + Diagnostic Engine)

This document tracks ideas to take `zem` from “working emulator” to “prime-time” for two purposes:

1. Run ZASM IR efficiently.
2. Act as a deep diagnostic runtime for higher-level languages (e.g. Zing) during development.

## Debugger (CLI-first, then VS Code)

- Breakpoints
  - Conditional breakpoints (implemented: `bpcif`/`blabelif`, simple expr over regs/symbols)
- Stepping
- Inspection
  - Registers
  - Call stack (return addresses + nearest label)
  - Current record + surrounding window (implemented: `win [N]`)
  - Memory dump (`x`/`mem`), plus “decoded” views (bytes/str)
  - Extend decoded views (structs)

## Structured Trace / Event Stream

- Output control
  - Sampling and filtering (implemented: `--trace-mnemonic`, `--trace-pc`, `--trace-call-target`, `--trace-sample`)

See also: `dbg_stop` JSONL stop events are documented in `docs/ir_build_run.md`.

## Better Diagnostics (compiled-language friendly)

- Source correlation
  - Use `loc.line` when present (v0)
  - Extend to richer `loc`/span info when present (file/col/range)
- Value decoding helpers
  - Crash-time bytes/str preview for common Zing runtime shapes (v0)
  - Extend decoding + surface via debugger inspection

## Performance / Execution Efficiency

- Decode once, run fast
  - Pre-decode JSONL records into a compact internal instruction form
  - Faster dispatch strategy for the hot loop
- Profiling
  - Instruction counts and hot CALL targets
  - Optional basic-block/hot-path summaries

## VS Code DX (Zing + zem tandem)

- Debug Adapter Protocol (DAP)
  - Break/step/variables/call stack/memory view
  - Map Zing concepts onto IR stepping where possible
- Build pipeline integration
  - One command: build → run under `zem` debugger
  - Emit structured diagnostics that VS Code can hyperlink

## CI / Test Harness

- `zem` test runner that:
  - Sweeps `src/zem/testdata`
  - Skips empty/compile-fail fixtures
  - Reports pass/fail/skip counts

# GOD MODE

North Star

Deterministic execution + complete observability + reversible history.
Everything the developer asks is answered by data, not vibes:
“Why did this happen?”
“What changed memory X?”
“Which call chain led to this host interaction?”
“Show me the minimal replay.”

## 1) Time as a First-Class Dimension (Time-Travel Debugging)
This is the “GOD MODE” differentiator most tools can’t do well.

What it looks like:

reverse-step, reverse-next, reverse-continue.
“Go back to the last time HL changed to 0x1234.”
“Rewind to the first divergence between two runs.”
How to build it incrementally:

Start with checkpoint + diff log:
Periodic snapshots of registers + stack + dirty memory pages.
Between snapshots: log memory writes (addr/size/old/new) and register deltas.
Determinism makes this feasible and extremely powerful.
Why it’s special for zasm:

The machine state is small and structured.
IR is deterministic: time-travel can be reliable, not “best effort.”

## 2) Causality & Provenance (Answer “Why”, Not Just “What”)
You already have dbg_stop and tracing. GOD MODE is adding causal links.

Add the concept of “provenance”:

Every observable value can be traced:
“This memory word came from ST32 at pc=…”
“This pointer originated from _alloc call at pc=…”
“This string slice flowed from symbol msg then appended by routine X.”
Concrete features:

Last-writer tracking (cheap, high value) (implemented v0 for watches):
Maintain a shadow map: for each memory region/page/word, store last write pc (+ line/label).
When watch changes, emit “written by frame …”.
Register provenance (optional, but huge):
Track for each reg: last instruction that set it; include operand sources.

## 3) Queryable Execution (The “Flight Recorder” You Can Ask Questions Of)
Instead of “emit a stream and grep it”, make execution a query target.

Think: a tiny local “debug database”:

zem --record run.zemtrace …
Then:
zem --inspect run.zemtrace --query 'writes(addr=0x1000)'
--query 'calls(target=\"_ctl\")'
--query 'stops(reason=\"breakpoint\")'
Even without a full DB:

A compact indexed log format + a few queries gets you 80%.
This unlocks:

CI artifacts: attach run.zemtrace to failures.
Postmortems: reproduce and inspect after the fact.

## 4) Semantic Debugging (Map IR Reality to Developer Intent)
If Zing is the upstream language, developers don’t actually want “pc=123”; they want “function Foo, local bar, message payload”.

Two layers:

IR-native (always available): record indices, labels, directives, operands.
High-level overlays (optional, toolchain-provided):
A sidecar “debug symbols” map (pc → source span; stack frame → function; memory ranges → structs/strings/slices).
zem becomes the runtime that can interpret those overlays.
This is where you get:

“Variables view” in DAP that isn’t fake.
Memory view that decodes “string/slice/object header” instead of hex.

## 5) Breakpoints That Feel Like Power Tools
GOD MODE breakpoints are expressive and safe.

High-value breakpoint upgrades:

Conditional breakpoints with a tiny expression engine:
break if HL==0 && sp>3
break if mem32(0x1000)==0xdeadbeef
Data breakpoints:
“break on write to addr/range/symbol” (watchpoints → real “break on change”)
Temporal breakpoints:
“break when this becomes true for the first time”
“break when it changes from value A to B”

## 6) Host-Call Observability as a First-Class Debug Surface
In real programs, the “interesting” events are often _ctl, _out, _alloc, etc.

Make host calls debug-native:

A structured host_call event with:
target symbol, args (decoded), return values, and duration.
A “host-call stack view”:
“show me the call chain that led to _ctl.”
Optional strict modes that turn latent bugs into crisp diagnostics:
pointer/len checks, handle lifecycle tracking (some of this already exists in sibling tools).

## 7) The “Impossible” Developer Features (That Become Possible Here)
These are the “category of its own” moves:

Delta debugging built-in: given a failing run, automatically minimize the input or command sequence that triggers it.
Deterministic fuzz harness: run millions of steps with coverage-like signals (even without traditional coverage).
Invariant checking: “assert memory region X stays aligned / monotonic / non-overlapping”.
Differential execution: run two versions and stop at first divergence, with a minimal diff of state.
A Practical Roadmap (If You Want This Without Boiling the Ocean)
If I were sequencing this:

State history v0
checkpoints + write-log + reverse-step/continue.
Causality v0
last-writer for memory + reg-last-set; integrate into watch/break output and dbg_stop.
Record & replay artifacts
--record / --replay, with deterministic guarantees.
Semantic overlays
sidecar debug map format (pc ↔ source spans; memory decoders).
DAP adapter
now “just wiring”, because the runtime is already a truth engine.
