<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ZASM Text Syntax v1.0.0 (As Implemented)

## 1) Lexer rules (as implemented)

Source: `src/zas/zasm.l`

- **Whitespace / newlines**
  - Spaces and tabs are ignored.
  - Newlines are significant: each newline emits a `T_NL` token and ends a line/statement.
  - EOF emits a final `T_NL` once if the file does not end with a newline.
- **Comments**
  - Line comments start with `;` and run to end of line.
  - No block comments, no nesting.
- **Identifiers**
  - ASCII only: `[A-Za-z_.$][A-Za-z0-9_.$]*`.
  - Case sensitive. Reserved keywords (mnemonics/directives) are matched before identifiers.
- **Numeric literals**
  - Decimal: `[0-9]+`.
  - Hex: `0x`/`0X` prefix followed by `[0-9A-Fa-f]+`.
  - No sign, no binary/octal prefix, no `_` separators.
  - Parsed with `strtol`; overflow/underflow behavior is **UNSPECIFIED** (libc-dependent).
- **String literals**
  - Double-quoted: `"([^\\\"]|\\.)*"`.
  - Backslash escapes accept any single char after `\` (no validation).
  - Strings are **not unescaped**; backslashes are preserved literally.
  - Newlines are not allowed inside strings.
- **Punctuation / tokens**
  - `:` `,` `(` `)` are tokens.
  - No dedicated token for `#` or other punctuation.
- **Keywords (case sensitive, uppercase only)**
  - Instructions: `CALL RET LD INC DEC CP JR ADD SUB`.
  - Directives: `DB DW RESB STR EQU PUBLIC EXTERN`.
- **Unknown characters**
  - Any other single character is silently skipped (no lex error).
  - This can effectively delete characters like `#` from the input stream.

## 2) Parser rules (as implemented)

Source: `src/zas/zasm.y`

- **Line structure**
  - The grammar is newline-driven: each line ends with `T_NL`.
  - Valid line forms:
    - empty line
    - `label` alone
    - `stmtinfo`
    - `dirinfo`
    - `label stmtinfo`
    - `label dirinfo`
  - Only one statement per line; no multiple statements on a single line.
- **Labels**
  - `label := ID ':'`.
  - Labels can appear alone or before an instruction/directive on the same line.
  - Reserved keywords cannot be labels (they are tokenized as keywords, not IDs).
- **Instruction forms**
  - `CALL ID`
  - `RET`
  - `LD operand ',' operand`
  - `INC operand`
  - `DEC operand`
  - `CP operand ',' operand`
  - `JR ID` or `JR ID ',' ID`
  - `ADD operand ',' operand`
  - `SUB operand ',' operand`
- **Operand forms**
  - `operand := ID | NUM | '(' ID ')'`
  - The parser does not validate register names or mnemonic-specific operand classes.
- **Directives and args**
  - `DB args`
  - `DW args`
  - `RESB args`
  - `STR args`
  - `EQU args`
  - `PUBLIC args`
  - `EXTERN args`
  - `args := arg (',' arg)*` (one or more)
  - `arg := STR | NUM | ID`
- **Error handling**
  - All failures are parser errors (`zas: parse error at line X:Y`).
  - The lexer does not produce errors; unknown characters are ignored.

## 3) ZASM Text Syntax v1.0.0 (As Implemented)

All requirements below are strictly derived from the current `flex`/`bison` sources.

### Lexical requirements

- The input MUST be tokenizable using the rules in section 1.
- Keywords MUST be uppercase; lowercase mnemonics/directives MUST NOT be used.
- Identifiers MUST match `[A-Za-z_.$][A-Za-z0-9_.$]*` and are ASCII-only.
- Numbers MUST be decimal or `0x`/`0X` hexadecimal with no sign.
- Strings MUST be double-quoted and confined to a single line.
- Backslash escapes inside strings MAY be any single character; their interpretation is **UNSPECIFIED** because the lexer does not unescape.
- Characters not part of any token are silently ignored; this behavior is **REQUIRED** by the current implementation.

### Line/statement requirements

- The input MUST be newline-delimited. Each logical line MUST end with a newline or EOF (EOF injects an implicit newline).
- Each line MUST match one of:
  - empty line
  - `label` alone
  - `label` followed by an instruction
  - `label` followed by a directive
  - instruction alone
  - directive alone
- A label MUST appear before any instruction/directive on the same line.

### Instruction requirements

The following are the only instruction spellings accepted by the parser:

- `CALL ID`
- `RET`
- `LD operand , operand`
- `INC operand`
- `DEC operand`
- `CP operand , operand`
- `JR ID` or `JR ID , ID`
- `ADD operand , operand`
- `SUB operand , operand`

`operand` MUST be one of: `ID`, `NUM`, `(ID)`.

### Directive requirements

The following are the only directives accepted by the parser:

- `DB args`
- `DW args`
- `RESB args`
- `STR args`
- `EQU args`
- `PUBLIC args`
- `EXTERN args`

`args` MUST contain one or more comma-separated `arg` tokens, where `arg` is `STR`, `NUM`, or `ID`.

### Semantic constraints

- The parser performs **no semantic validation** of register names, operand classes, or directive argument types.
- Any additional semantic rules are **UNSPECIFIED** at the `zas` frontend level.

## 4) Mapping to JSONL IR

Source: `src/zas/emit_json.c`

### Record kinds and ordering

- Each accepted line emits zero or more JSONL records in source order:
  - `label` line: emits one `label` record.
  - `instruction` line: emits one `instr` record.
  - `directive` line: emits one `dir` record.
  - `label instruction` line: emits a `label` record, then an `instr` record.
  - `label directive` line: emits only a `dir` record with `"name"` set to the label.
- JSONL objects are emitted immediately (streaming).

### Record shapes

- **Label**
  - `{"ir":"zasm-v1.0","k":"label","name":<string>,"loc":{"line":N}}`
- **Instruction**
  - `{"ir":"zasm-v1.0","k":"instr","m":<string>,"ops":[...],"loc":{"line":N}}`
- **Directive**
  - `{"ir":"zasm-v1.0","k":"dir","d":<string>[,"name":<string>],"args":[...],"loc":{"line":N}}`

### Operand encoding

- `ID` → `{ "t":"sym", "v":"ID" }`
- `NUM` → `{ "t":"num", "v":<integer> }`
- `STR` → `{ "t":"str", "v":"STRING" }`
- `(ID)` → `{ "t":"mem", "base":"ID" }`

### Location info

- Only `loc.line` is emitted.
- `loc.line` is the lexer `yylineno` at the time the trailing newline is tokenized, so it effectively reports the line number of the newline (typically statement line + 1).
- `loc.col` and `loc.unit` are never emitted by `zas` (values are **UNSPECIFIED** in output).

### Normalization and escaping

- Mnemonics/directives are emitted exactly as hardcoded uppercase strings in the parser.
- Identifiers are emitted exactly as lexed (no case folding).
- Strings are not unescaped; JSON emission only applies minimal JSON escaping (`\`, `"`, `\n`, `\r`, `\t`).
- Whitespace and comments are not preserved in output.

## 5) Conformance suite (pass/fail)

All expected outputs below are exact JSONL lines as emitted by `zas`.

### PASS

**test/pass/empty_and_comment.asm**
```asm
; only a comment

```
Expected JSONL output:
```json

```

**test/pass/label_and_ret.asm**
```asm
start:
RET
```
Expected JSONL output:
```json
{"ir":"zasm-v1.0","k":"label","name":"start","loc":{"line":2}}
{"ir":"zasm-v1.0","k":"instr","m":"RET","ops":[],"loc":{"line":3}}
```

**test/pass/label_plus_instr.asm**
```asm
entry: RET
```
Expected JSONL output:
```json
{"ir":"zasm-v1.0","k":"label","name":"entry","loc":{"line":2}}
{"ir":"zasm-v1.0","k":"instr","m":"RET","ops":[],"loc":{"line":2}}
```

**test/pass/ld_operands.asm**
```asm
LD A, 1
LD (HL), A
LD A, (HL)
LD HL, 0x10
```
Expected JSONL output:
```json
{"ir":"zasm-v1.0","k":"instr","m":"LD","ops":[{"t":"sym","v":"A"},{"t":"num","v":1}],"loc":{"line":2}}
{"ir":"zasm-v1.0","k":"instr","m":"LD","ops":[{"t":"mem","base":"HL"},{"t":"sym","v":"A"}],"loc":{"line":3}}
{"ir":"zasm-v1.0","k":"instr","m":"LD","ops":[{"t":"sym","v":"A"},{"t":"mem","base":"HL"}],"loc":{"line":4}}
{"ir":"zasm-v1.0","k":"instr","m":"LD","ops":[{"t":"sym","v":"HL"},{"t":"num","v":16}],"loc":{"line":5}}
```

**test/pass/jr_forms.asm**
```asm
target:
JR target
JR EQ, target
```
Expected JSONL output:
```json
{"ir":"zasm-v1.0","k":"label","name":"target","loc":{"line":2}}
{"ir":"zasm-v1.0","k":"instr","m":"JR","ops":[{"t":"sym","v":"target"}],"loc":{"line":3}}
{"ir":"zasm-v1.0","k":"instr","m":"JR","ops":[{"t":"sym","v":"EQ"},{"t":"sym","v":"target"}],"loc":{"line":4}}
```

**test/pass/arithmetic.asm**
```asm
INC HL
DEC DE
ADD HL, DE
SUB HL, 5
CP HL, 0x2A
```
Expected JSONL output:
```json
{"ir":"zasm-v1.0","k":"instr","m":"INC","ops":[{"t":"sym","v":"HL"}],"loc":{"line":2}}
{"ir":"zasm-v1.0","k":"instr","m":"DEC","ops":[{"t":"sym","v":"DE"}],"loc":{"line":3}}
{"ir":"zasm-v1.0","k":"instr","m":"ADD","ops":[{"t":"sym","v":"HL"},{"t":"sym","v":"DE"}],"loc":{"line":4}}
{"ir":"zasm-v1.0","k":"instr","m":"SUB","ops":[{"t":"sym","v":"HL"},{"t":"num","v":5}],"loc":{"line":5}}
{"ir":"zasm-v1.0","k":"instr","m":"CP","ops":[{"t":"sym","v":"HL"},{"t":"num","v":42}],"loc":{"line":6}}
```

**test/pass/directives.asm**
```asm
msg: DB "A", 10, 0x2A, sym
word: DW 123
RESB 4
text: STR "Hi", 10
buf_size: EQU 16
PUBLIC entry
EXTERN "env", "noop", noop
```
Expected JSONL output:
```json
{"ir":"zasm-v1.0","k":"dir","d":"DB","name":"msg","args":[{"t":"str","v":"A"},{"t":"num","v":10},{"t":"num","v":42},{"t":"sym","v":"sym"}],"loc":{"line":2}}
{"ir":"zasm-v1.0","k":"dir","d":"DW","name":"word","args":[{"t":"num","v":123}],"loc":{"line":3}}
{"ir":"zasm-v1.0","k":"dir","d":"RESB","args":[{"t":"num","v":4}],"loc":{"line":4}}
{"ir":"zasm-v1.0","k":"dir","d":"STR","name":"text","args":[{"t":"str","v":"Hi"},{"t":"num","v":10}],"loc":{"line":5}}
{"ir":"zasm-v1.0","k":"dir","d":"EQU","name":"buf_size","args":[{"t":"num","v":16}],"loc":{"line":6}}
{"ir":"zasm-v1.0","k":"dir","d":"PUBLIC","args":[{"t":"sym","v":"entry"}],"loc":{"line":7}}
{"ir":"zasm-v1.0","k":"dir","d":"EXTERN","args":[{"t":"str","v":"env"},{"t":"str","v":"noop"},{"t":"sym","v":"noop"}],"loc":{"line":8}}
```

**test/pass/ident_chars.asm**
```asm
.L1: CALL $func
$func: RET
```
Expected JSONL output:
```json
{"ir":"zasm-v1.0","k":"label","name":".L1","loc":{"line":2}}
{"ir":"zasm-v1.0","k":"instr","m":"CALL","ops":[{"t":"sym","v":"$func"}],"loc":{"line":2}}
{"ir":"zasm-v1.0","k":"label","name":"$func","loc":{"line":3}}
{"ir":"zasm-v1.0","k":"instr","m":"RET","ops":[],"loc":{"line":3}}
```

**test/pass/strings_and_escapes.asm**
```asm
DB "a\\n", "b\\t", "c\\q", 0
```
Expected JSONL output:
```json
{"ir":"zasm-v1.0","k":"dir","d":"DB","args":[{"t":"str","v":"a\\n"},{"t":"str","v":"b\\t"},{"t":"str","v":"c\\q"},{"t":"num","v":0}],"loc":{"line":2}}
```

**test/pass/ignored_char_hash.asm**
```asm
ADD HL, #10
```
Expected JSONL output:
```json
{"ir":"zasm-v1.0","k":"instr","m":"ADD","ops":[{"t":"sym","v":"HL"},{"t":"num","v":10}],"loc":{"line":2}}
```

### FAIL

All failures are parser errors. The lexer never reports errors; it silently skips unknown characters.

**test/fail/missing_comma_ld.asm**
```asm
LD A B
```
Expected failure:
- Class: parse
- Message regex: `^zas: parse error at line 1:`
- Location: line 1 (column depends on last accepted token)

**test/fail/jr_missing_comma.asm**
```asm
JR EQ label
```
Expected failure:
- Class: parse
- Message regex: `^zas: parse error at line 1:`
- Location: line 1

**test/fail/empty_args_db.asm**
```asm
DB
```
Expected failure:
- Class: parse
- Message regex: `^zas: parse error at line 1:`
- Location: line 1

**test/fail/bad_mem_operand.asm**
```asm
LD (123), A
```
Expected failure:
- Class: parse
- Message regex: `^zas: parse error at line 1:`
- Location: line 1

**test/fail/lowercase_mnemonic.asm**
```asm
call foo
```
Expected failure:
- Class: parse
- Message regex: `^zas: parse error at line 1:`
- Location: line 1

**test/fail/keyword_as_label.asm**
```asm
CALL:
RET
```
Expected failure:
- Class: parse
- Message regex: `^zas: parse error at line 1:`
- Location: line 1

**test/fail/trailing_comma_dir.asm**
```asm
DB 1,
```
Expected failure:
- Class: parse
- Message regex: `^zas: parse error at line 1:`
- Location: line 1

## 6) Gap report

### Documented but not implemented (or not enforced)

- `docs/spec/isa.md` describes operand classes and register sets (`HL`, `DE`, `A`, `BC`, `IX`). The parser accepts any identifier or number for `operand` without validation.
- ISA immediate syntax with `#` (e.g., `ADD HL, #imm`) is not tokenized; `#` is silently ignored.
- ISA defines `JR COND, label` with `COND` in a fixed set; the parser accepts any identifier and does not enforce condition names.
- ISA narrows `LD` forms to specific register/memory combinations; the parser allows `LD` between any two operands (including `(ID)` and numbers in any position).
- `DEC`/`INC` are restricted to certain registers in ISA; the parser allows any operand type.
- Error behavior in docs implies unknown punctuation should be rejected; the lexer currently ignores unknown characters.

### Implemented but undocumented

- Labels may start with `.` or `$` (identifier rule allows these).
- Reserved keywords cannot be used as labels or symbol operands (keyword tokens win over IDs).
- `label + directive` lines emit only a `dir` record with `name` set; no separate `label` record is emitted.
- An EOF-inserted newline is always produced when missing a trailing newline.

### Potential contradictions / ambiguities

- IR spec examples show `loc` with `line` and `col`, but `zas` only emits `loc.line`.
- String escapes are shown in docs but the frontend does no unescaping; exact semantics are **UNSPECIFIED** beyond literal backslash preservation.
- Operand typing for directives (`EQU`, `PUBLIC`, `EXTERN`) is not constrained in the parser, while docs imply more specific meanings.
