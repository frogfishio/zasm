LD DE, buf
LD BC, 0
LD HL, 1
CALL zi_write
RET
buf: DB "ABC", 0
