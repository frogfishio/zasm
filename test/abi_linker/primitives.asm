LD HL, 4
CALL zi_alloc
CALL zi_free
LD HL, topic
LD DE, topic_len
LD BC, msg
LD IX, msg_len
CALL zi_telemetry
LD HL, 1
LD DE, topic
LD BC, topic_len
CALL zi_write
RET
topic: DB "TT", 0
topic_len: EQU 2
msg: DB "MSG", 0
msg_len: EQU 3
