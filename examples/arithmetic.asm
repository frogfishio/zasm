; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

main:
  LD HL, #10
  LD DE, #3
  ADD HL, DE
  SUB HL, #1
  SUB HL, DE
  AND HL, DE
  OR HL, #7
  XOR HL, #1
  SLA HL, #1
  SRA HL, #1
  SRL HL, #1
  ROL HL, #2
  ROR HL, #3
  MUL HL, #4
  DIVS HL, #3
  DIVU HL, #2
  REMS HL, #2
  REMU HL, #2
  EQ HL, #2
  NE HL, #1
  LTS HL, #3
  LTU HL, #3
  LES HL, #2
  LEU HL, #2
  GTS HL, #1
  GTU HL, #1
  GES HL, #2
  GEU HL, #2
  CLZ HL
  CTZ HL
  POPC HL
  LD IX, buf32
  ST32 (IX), HL
  LD32 DE, (IX)
  LD HL, buf8
  ST8 (HL), #255
  LD8U A, (HL)
  LD8S BC, (HL)
  LD IX, buf16
  ST16 (IX), BC
  LD16U DE, (IX)
  LD16S IX, (IX)
  DROP IX
  LD HL, buf_fill
  LD A, #1
  LD BC, #4
  FILL
  DROP BC
  LD HL, src_block
  LD DE, dst_block
  LD BC, #4
  LDIR
  INC DE
  DEC DE
  LD BC, #2
  INC BC
  DEC BC
  RET

buf32: RESB 4
buf16: RESB 4
buf8: RESB 2
buf_fill: RESB 8
src_block: DB 1, 2, 3, 4
dst_block: RESB 4
