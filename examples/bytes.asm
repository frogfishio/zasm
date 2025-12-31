; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

main:
  LD HL, buf
  LD A, #65
  LD (HL), A
  LD A, #0
  LD A, (HL)
  LD HL, buf
  LD DE, #1
  CALL _out
  RET

buf: RESB 4
