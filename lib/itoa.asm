; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

; itoa: convert unsigned integer (0..255) from itoa_in to ASCII digits.
; Output: itoa_buf + itoa_len globals are updated.
; Clobbers: A, BC, DE, HL, IX

itoa:
  ; init output pointer and counters
  LD DE, itoa_buf
  LD A, #0
  LD HL, itoa_len
  LD (HL), A

  LD A, #0
  LD HL, started_flag
  LD (HL), A

  ; load input
  LD HL, itoa_in
  LD A, (HL)
  LD HL, A

  ; special-case 0
  CP HL, #0
  JR ne, itoa_digits

  LD A, #48
  LD HL, DE
  LD (HL), A
  LD HL, itoa_len
  LD A, #1
  LD (HL), A
  JR itoa_done

itoa_digits:
  ; ten-thousands (10000)
  LD BC, #0
itoa_div_10000:
  CP HL, #10000
  JR lt, itoa_div_10000_done
  SUB HL, #10000
  INC BC
  JR itoa_div_10000
itoa_div_10000_done:
  LD IX, HL
  LD HL, BC
  CP HL, #0
  JR eq, itoa_emit_check_started_10000
  JR itoa_emit_write_10000
itoa_emit_check_started_10000:
  LD HL, started_flag
  LD A, (HL)
  LD HL, A
  CP HL, #0
  JR eq, itoa_emit_restore_10000
itoa_emit_write_10000:
  LD HL, #1
  LD A, HL
  LD HL, started_flag
  LD (HL), A

  LD HL, BC
  ADD HL, #48
  LD A, HL
  LD HL, DE
  LD (HL), A
  LD HL, DE
  INC HL
  LD DE, HL
  LD HL, itoa_len
  LD A, (HL)
  LD HL, A
  INC HL
  LD A, HL
  LD HL, itoa_len
  LD (HL), A
itoa_emit_restore_10000:
  LD HL, IX

  ; thousands (1000)
  LD BC, #0
itoa_div_1000:
  CP HL, #1000
  JR lt, itoa_div_1000_done
  SUB HL, #1000
  INC BC
  JR itoa_div_1000
itoa_div_1000_done:
  LD IX, HL
  LD HL, BC
  CP HL, #0
  JR eq, itoa_emit_check_started_1000
  JR itoa_emit_write_1000
itoa_emit_check_started_1000:
  LD HL, started_flag
  LD A, (HL)
  LD HL, A
  CP HL, #0
  JR eq, itoa_emit_restore_1000
itoa_emit_write_1000:
  LD HL, #1
  LD A, HL
  LD HL, started_flag
  LD (HL), A

  LD HL, BC
  ADD HL, #48
  LD A, HL
  LD HL, DE
  LD (HL), A
  LD HL, DE
  INC HL
  LD DE, HL
  LD HL, itoa_len
  LD A, (HL)
  LD HL, A
  INC HL
  LD A, HL
  LD HL, itoa_len
  LD (HL), A
itoa_emit_restore_1000:
  LD HL, IX

  ; hundreds (100)
  LD BC, #0
itoa_div_100:
  CP HL, #100
  JR lt, itoa_div_100_done
  SUB HL, #100
  INC BC
  JR itoa_div_100
itoa_div_100_done:
  LD IX, HL
  LD HL, BC
  CP HL, #0
  JR eq, itoa_emit_check_started_100
  JR itoa_emit_write_100
itoa_emit_check_started_100:
  LD HL, started_flag
  LD A, (HL)
  LD HL, A
  CP HL, #0
  JR eq, itoa_emit_restore_100
itoa_emit_write_100:
  LD HL, #1
  LD A, HL
  LD HL, started_flag
  LD (HL), A

  LD HL, BC
  ADD HL, #48
  LD A, HL
  LD HL, DE
  LD (HL), A
  LD HL, DE
  INC HL
  LD DE, HL
  LD HL, itoa_len
  LD A, (HL)
  LD HL, A
  INC HL
  LD A, HL
  LD HL, itoa_len
  LD (HL), A
itoa_emit_restore_100:
  LD HL, IX

  ; tens (10)
  LD BC, #0
itoa_div_10:
  CP HL, #10
  JR lt, itoa_div_10_done
  SUB HL, #10
  INC BC
  JR itoa_div_10
itoa_div_10_done:
  LD IX, HL
  LD HL, BC
  CP HL, #0
  JR eq, itoa_emit_check_started_10
  JR itoa_emit_write_10
itoa_emit_check_started_10:
  LD HL, started_flag
  LD A, (HL)
  LD HL, A
  CP HL, #0
  JR eq, itoa_emit_restore_10
itoa_emit_write_10:
  LD HL, #1
  LD A, HL
  LD HL, started_flag
  LD (HL), A

  LD HL, BC
  ADD HL, #48
  LD A, HL
  LD HL, DE
  LD (HL), A
  LD HL, DE
  INC HL
  LD DE, HL
  LD HL, itoa_len
  LD A, (HL)
  LD HL, A
  INC HL
  LD A, HL
  LD HL, itoa_len
  LD (HL), A
itoa_emit_restore_10:
  LD HL, IX

  ; ones digit (HL is 0..9)
  ADD HL, #48
  LD A, HL
  LD HL, DE
  LD (HL), A
  LD HL, DE
  INC HL
  LD DE, HL
  LD HL, itoa_len
  LD A, (HL)
  LD HL, A
  INC HL
  LD A, HL
  LD HL, itoa_len
  LD (HL), A

itoa_done:
  RET

itoa_in: RESB 1
itoa_buf: RESB 6
itoa_len: RESB 1
started_flag: RESB 1
