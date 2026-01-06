; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

main:
read_loop:
  LD HL, buf
  LD DE, #4096
  CALL _in          ; HL := n
  CP HL, #0
  JR le, done       ; n <= 0 => EOF or error => stop

  ; write n bytes from buf
  LD DE, HL         ; DE := n
  LD HL, buf
  CALL _out

  JR read_loop

done:
  RET

buf: RESB 4096
