# TO DO

List of tasks to do


- Create linter and formatter as a part of compiler --lint, --format. This will be used manually as well as automatically by visual studio code plugin

- Create visual studio code plugin for ZASM, full syntax higlighting, linting, formatting

- Create POETICS.md with clear guide how assembly source code must be presented, look and formatted

- Add a conformance test suite that validates every mnemonic/directive accepts only the operand shapes in `schema/ir/v1/mnemonics.html`.
- Add negative parsing tests for invalid token cases (lowercase mnemonics, malformed labels, bad commas, stray tokens, unterminated strings).
- Add JSONL shape tests that compare emitted records against the normative schema (instr/dir/label shapes, ops arrays, loc.line behavior).
- Add register validation tests for unknown registers in all operand positions (including mem base and CALL/JR targets where applicable).
- Add memory operand tests for `(addr)` forms, rejecting non-ID bases and nested parentheses.
- Add boundary tests for numeric literals (hex/decimal, 0, max 64-bit, overflow handling) across all numeric-accepting operands.
- Add semantic tests for control flow (JR with each condition, invalid conditions, missing labels, forward/backward label resolution).
- Add ABI contract tests for FILL/LDIR (register usage, len=0 behavior, overlapping ranges).
- Add data directive tests for DB/DW/STR/RESB/EQU/PUBLIC/EXTERN (argument counts/types, label binding, zero/negative sizes).
- Add linker tests for duplicate labels, undefined symbols, export/import conflicts, and name collisions across multi-file assembly.
- Add wasm emission tests that ensure each mnemonic maps to expected WAT patterns (including trap/strict paths).
- Add round-trip tests that assemble → link → run and validate observable output for representative programs per feature class.
- Add fuzz targets for lexer, parser, and JSONL ingestion with crash-only and invariant-based checks.
