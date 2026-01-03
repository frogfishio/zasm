; Zigzagger64 starts with a calm value and runs every 64-bit mnemonic to end at a predictable target.
LD64 HL, (start64)
ADD64 HL, 0x32
SUB64 HL, 0x12
LD BC, 6
MUL64 HL, BC
DIVU64 HL, 3
LD DE, 2
DIVS64 HL, DE
LD IX, 45
REMS64 HL, IX
REMU64 HL, 6
AND64 HL, 0xFF
OR64 HL, 0x220
XOR64 HL, 0x10
SLA64 HL, 3
SRA64 HL, 2
SRL64 HL, 1
ROL64 HL, 4
ROR64 HL, 4
ST64 (result64), HL

; Capture a few derived facts about the final value.
LD64 HL, (result64)
CLZ64 HL
ST64 (stat_clz), HL

LD64 HL, (result64)
CTZ64 HL
ST64 (stat_ctz), HL

LD64 HL, (result64)
POPC64 HL
ST64 (stat_popc), HL

; Fan out through every compare to confirm the final result.
LD64 HL, (result64)
EQ64 HL, 0x231
CP HL, 1

LD64 HL, (result64)
NE64 HL, 0x231
CP HL, 0

LD64 HL, (result64)
LTS64 HL, 0x232
CP HL, 1

LD64 HL, (result64)
LTU64 HL, 0x232
CP HL, 1

LD64 HL, (result64)
LES64 HL, 0x231
CP HL, 1

LD64 HL, (result64)
LEU64 HL, 0x231
CP HL, 1

LD64 HL, (result64)
GTS64 HL, 0x230
CP HL, 1

LD64 HL, (result64)
GTU64 HL, 0x230
CP HL, 1

LD64 HL, (result64)
GES64 HL, 0x231
CP HL, 1

LD64 HL, (result64)
GEU64 HL, 0x231
CP HL, 1

result64: RESB 8
stat_clz: RESB 8
stat_ctz: RESB 8
stat_popc: RESB 8

start64:
  DW 0x000001F4
  DW 0x00000000
