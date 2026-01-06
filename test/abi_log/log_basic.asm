LD HL, topic
LD DE, topic_len
LD BC, msg
LD IX, msg_len
CALL _log
CALL _out
LD HL, BC
LD DE, IX
CALL _out
RET
topic: DB "TT", 0
topic_len: EQU 2
msg: DB "MSG", 0
msg_len: EQU 3
