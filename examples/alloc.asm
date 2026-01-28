; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

main:
  LD HL, #1
  CALL zi_alloc
  LD IX, HL
  LD A, #65
  LD (HL), A
  LD DE, #1
  LD BC, DE
  LD DE, HL
  LD HL, #1
  CALL zi_write
  LD HL, IX
  CALL zi_free
  RET
