# TO DO

Mnemonics to implement

## TODO ZASM mnemonics (missing today)

| TODO ZASM mnemonic | Operand shape (suggested) | WASM equivalent | What it does |
|---|---|---|---|
| **AND** | `AND r, x` | `i32.and` | Bitwise AND (i32). |
| **OR** | `OR r, x` | `i32.or` | Bitwise OR (i32). |
| **XOR** | `XOR r, x` | `i32.xor` | Bitwise XOR (i32). |
| **SLA** | `SLA r, x` | `i32.shl` | Shift left (variable count). |
| **SRA** | `SRA r, x` | `i32.shr_s` | Arithmetic right shift. |
| **SRL** | `SRL r, x` | `i32.shr_u` | Logical right shift. |
| **ROL** | `ROL r, x` | `i32.rotl` | Rotate left. |
| **ROR** | `ROR r, x` | `i32.rotr` | Rotate right. |
| **MUL** | `MUL r, x` | `i32.mul` | Multiply (i32). |
| **DIVS** | `DIVS r, x` | `i32.div_s` | Signed division (trap on div0/overflow like WASM). |
| **DIVU** | `DIVU r, x` | `i32.div_u` | Unsigned division. |
| **REMS** | `REMS r, x` | `i32.rem_s` | Signed remainder. |
| **REMU** | `REMU r, x` | `i32.rem_u` | Unsigned remainder. |
| **EQ** | `EQ r, x` | `i32.eq` | Compare equals → i32(0/1). |
| **NE** | `NE r, x` | `i32.ne` | Compare not-equals → i32(0/1). |
| **LTS** | `LTS r, x` | `i32.lt_s` | Signed `<` → i32(0/1). |
| **LTU** | `LTU r, x` | `i32.lt_u` | Unsigned `<` → i32(0/1). |
| **LES** | `LES r, x` | `i32.le_s` | Signed `<=` → i32(0/1). |
| **LEU** | `LEU r, x` | `i32.le_u` | Unsigned `<=` → i32(0/1). |
| **GTS** | `GTS r, x` | `i32.gt_s` | Signed `>` → i32(0/1). |
| **GTU** | `GTU r, x` | `i32.gt_u` | Unsigned `>` → i32(0/1). |
| **GES** | `GES r, x` | `i32.ge_s` | Signed `>=` → i32(0/1). |
| **GEU** | `GEU r, x` | `i32.ge_u` | Unsigned `>=` → i32(0/1). |
| **CLZ** | `CLZ r` | `i32.clz` | Count leading zeros. |
| **CTZ** | `CTZ r` | `i32.ctz` | Count trailing zeros. |
| **POPC** | `POPC r` | `i32.popcnt` | Popcount. |
| **LD8U** | `LD8U r, (addr)` | `i32.load8_u` | Load u8, zero-extend to i32. |
| **LD8S** | `LD8S r, (addr)` | `i32.load8_s` | Load i8, sign-extend to i32. |
| **LD16U** | `LD16U r, (addr)` | `i32.load16_u` | Load u16, zero-extend. |
| **LD16S** | `LD16S r, (addr)` | `i32.load16_s` | Load i16, sign-extend. |
| **LD32** | `LD32 r, (addr)` | `i32.load` | Load i32. |
| **ST8** | `ST8 (addr), r` | `i32.store8` | Store low 8 bits. |
| **ST16** | `ST16 (addr), r` | `i32.store16` | Store low 16 bits. |
| **ST32** | `ST32 (addr), r` | `i32.store` | Store i32. |
| **FILL** | `FILL` (uses regs) | `memory.fill` | Bulk fill (e.g. `HL=dst, A=byte, BC=len`). |
| **LDIR** | `LDIR` (uses regs) | `memory.copy` | Bulk copy (e.g. `HL=src, DE=dst, BC=len`). |
| **DROP** | `DROP r` *(optional)* | `drop` | Explicitly discard a value (useful in expr-lowering). |