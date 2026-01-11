# TO DO

## GOAL
Deliver a feature-complete JSON IR (`zasm-v1.0`) → macOS arm64 lowerer that emits a Mach-O `.o` and static `.a` with C-call ABI (lembeh) semantics, matching the published IR schema and ABI contracts.

## TASKS
- IR model: Extend `ir.h` to represent all schema constructs (labels, instr + typed ops incl. mem/base, PUBLIC, EXTERN module/field/local, DB/DW/RESB, STR/EQU expansions, optional names, loc for diagnostics).
- Parser: Replace `json_ir.c` with a schema-faithful parser that enforces `ir: "zasm-v1.0"`, validates operand/directive shapes, expands STR/EQU into bytes/len symbols, collects EXTERNs, and rejects unknown fields with line-aware errors.
- Codegen backend: Implement `codegen.h/.c` (arm64) to lower zasm mnemonics to ARM64 with correct calling convention, prologue/epilogue, symbol table for code/data, data layout for DB/DW/RESB/STR/EQU, and reloc production for all symbol references (text/data, externs).
- Mach-O writer: Finish `main.c` to emit text/data sections with alignment, symbols for PUBLIC exports + locals + EXTERN imports, all needed ARM64 reloc types (text and data), and deterministic output; include guest-mem slot handling per ABI.
- Tooling: Add build target(s) to produce the lowerer binary; ensure deterministic `ar` invocation; document usage in `src/lower/README.md`.
- Tests: Add fixtures covering instrs, PUBLIC/EXTERN, data directives, relocations, and error cases; include a smoke link test that compiles the produced `.a` into a stub (if permissible).

## ACCEPTANCE CRITERIA
- Parses valid `schema/ir/v1/record.schema.json` streams and rejects invalid ones with clear line diagnostics.
- Emits correct ARM64 machine code and data for all supported mnemonics/directives, with relocations resolving against generated symbols and EXTERN imports.
- Produces a Mach-O object/archive that `clang` can link on macOS arm64; exports PUBLIC symbols (incl. `lembeh_handle`) and references host primitives via C ABI.
- Deterministic outputs for identical inputs (no timestamp/host variance); build target succeeds from a clean checkout; tests/fixtures pass.*** End Patch
