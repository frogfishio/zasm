/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
#ifndef ZING_VALIDATE_H
#define ZING_VALIDATE_H

#include <stddef.h>

int zing_validate_types(void);
int zing_validate_consts(void);
int zing_validate_caps(void);
int zing_validate_modules(void);
int zing_validate_layouts(void);
int zing_validate_managed_vars(void);

/* Returns a newly allocated, sorted list of managed variable keys. Caller frees the array and each string. */
char **zing_managed_vars_list(size_t *out_count);
void zing_validate_set_float_error(int enabled);
void zing_validate_set_carrier_error(int enabled);
void zing_validate_set_quiet(int enabled);

#endif
