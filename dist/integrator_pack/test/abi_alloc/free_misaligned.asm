LD HL, 4
CALL _alloc
ADD HL, 1
CALL _free
RET
