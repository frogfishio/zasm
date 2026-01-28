LD HL, 4
CALL zi_alloc
ADD HL, 1
CALL zi_free
RET
