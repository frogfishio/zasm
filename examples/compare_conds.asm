; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

main:
  LD HL, #0
  LD DE, #0
  CP HL, DE
  JR EQ, is_eq
  JR NE, fail

is_eq:
  CP HL, #1
  JR LT, is_lt
  JR GE, fail

is_lt:
  CP HL, #0
  JR LE, is_le
  JR GT, fail

is_le:
  CP HL, #0
  JR GE, done
  JR fail

done:
  RET

fail:
  RET
