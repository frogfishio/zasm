/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
#ifndef ZING_CODEGEN_H
#define ZING_CODEGEN_H

#include <stdio.h>

#include "zing_ast.h"

typedef enum {
  ZING_EMIT_ZASM = 0
} ZingEmitMode;

void zing_codegen_emit(FILE *out, ZingMethod *methods, ZingTest *tests,
                       int emit_tests, ZingEmitMode mode);

#endif
