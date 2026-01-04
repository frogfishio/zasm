LD HL, buf
LD DE, 0
CALL _out
RET
buf: DB "ABC", 0
