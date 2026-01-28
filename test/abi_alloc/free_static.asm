LD HL, msg
CALL zi_free
RET
msg: DB "hi", 0
