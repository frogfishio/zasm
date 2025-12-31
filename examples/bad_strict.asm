; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

; Deliberate bad call to exercise zrun --strict behavior.

main:
  LD HL, #0
  LD DE, #70000
  CALL _out
  RET
