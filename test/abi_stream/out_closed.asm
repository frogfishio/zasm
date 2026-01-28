LD DE, msg
LD BC, 1
LD HL, 0
CALL zi_read
LD BC, HL
LD DE, msg
LD HL, 1
CALL zi_write
RET
msg: DB "X", 0
