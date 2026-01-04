LD HL, msg
CALL _free
RET
msg: DB "hi", 0
