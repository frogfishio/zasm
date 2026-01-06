msg: DB "A", 10, 0x2A, sym
word: DW 123
RESB 4
text: STR "Hi", 10
buf_size: EQU 16
PUBLIC entry
EXTERN "env", "noop", noop
