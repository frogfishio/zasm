LD IX, buf
LD HL, buf
LD DE, 8
CALL _in
LD DE, HL
LD HL, IX
CALL _out
RET
buf: RESB 8
