; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

main:
  LD HL, #10
  LD DE, #3
  ADD HL, DE
  SUB HL, #1
  SUB HL, DE
  INC DE
  DEC DE
  LD BC, #2
  INC BC
  DEC BC
  RET
