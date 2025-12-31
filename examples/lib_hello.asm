; SPDX-FileCopyrightText: 2025 Frogfish
; SPDX-License-Identifier: MIT

print_hello:
  LD HL, msg
  LD DE, msg_len
  CALL _out
  RET

msg: STR "Hello from lib", 10
