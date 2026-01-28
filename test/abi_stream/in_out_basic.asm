LD DE, buf
LD BC, 8
LD HL, 0
CALL zi_read
LD BC, HL
LD DE, buf
LD HL, 1
CALL zi_write
RET
buf: RESB 8
