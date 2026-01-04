LD HL, msg
LD DE, 1
CALL _in
LD DE, HL
LD HL, msg
CALL _out
RET
msg: DB "X", 0
