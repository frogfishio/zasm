; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

main:
  LD HL, #1
  CALL _alloc
  LD A, #65
  LD (HL), A
  LD DE, #1
  CALL _out
  CALL _free
  RET
