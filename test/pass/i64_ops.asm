; 64-bit arithmetic
ADD64 HL, DE
SUB64 HL, 1
MUL64 HL, BC
DIVS64 HL, 3
DIVU64 HL, 4
REMS64 HL, IX
REMU64 HL, 6

; 64-bit bitwise
AND64 HL, DE
OR64 HL, 0x10
XOR64 HL, 0xFF

; 64-bit shifts
SLA64 HL, 1
SRA64 HL, 2
SRL64 HL, 3

; 64-bit rotates
ROL64 HL, 4
ROR64 HL, 5

; 64-bit comparisons
EQ64 HL, DE
NE64 HL, 0
LTS64 HL, DE
LTU64 HL, BC
LES64 HL, 1
LEU64 HL, 2
GTS64 HL, 3
GTU64 HL, 4
GES64 HL, 5
GEU64 HL, 6

; 64-bit bit counts
CLZ64 HL
CTZ64 DE
POPC64 BC

; 64-bit memory moves
LD64 HL, (buf64)
ST64 (buf64), DE
LD64 BC, 0

; 64-bit narrow loads and stores
LD8S64 HL, (buf8)
LD8U64 DE, (buf8)
LD16S64 HL, (buf16)
LD16U64 DE, (buf16)
LD32S64 HL, (buf32)
LD32U64 BC, (buf32)
ST8_64 (buf8), HL
ST16_64 (buf16), DE
ST32_64 (buf32), BC

buf64: RESB 8
buf32: RESB 4
buf16: RESB 2
buf8: RESB 1
