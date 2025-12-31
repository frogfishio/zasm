; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

; Deliberate guest trap: out-of-bounds load from linear memory.

main:
  LD HL, #70000
  LD A, (HL)
  RET
