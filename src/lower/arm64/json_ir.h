#ifndef ZINGCC_JSON_IR_H
#define ZINGCC_JSON_IR_H

#include <stdio.h>
#include "ir.h"

int json_ir_read(FILE* fp, ir_prog_t* prog);

#endif
