/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
#ifndef ZING_AST_H
#define ZING_AST_H

#include <stdint.h>
#include <stddef.h>

struct Expr;

typedef struct ZingName ZingName;
typedef struct ZingMethod ZingMethod;
typedef struct ZingMethodHead ZingMethodHead;
typedef struct ZingType ZingType;
typedef struct ZingTypeDecl ZingTypeDecl;
typedef struct ZingField ZingField;
typedef struct ZingStruct ZingStruct;
typedef struct ZingEnumCase ZingEnumCase;
typedef struct ZingEnum ZingEnum;
typedef struct ZingTypeUse ZingTypeUse;
typedef struct ZingCarrierUse ZingCarrierUse;
typedef struct ZingExtern ZingExtern;
typedef struct ZingUse ZingUse;
typedef struct ZingDecl ZingDecl;
typedef enum ZingDeclKind ZingDeclKind;
typedef struct ZingConst ZingConst;
typedef struct ZingLayoutField ZingLayoutField;
typedef struct ZingLayout ZingLayout;
typedef struct ZingDocBlock ZingDocBlock;
typedef struct ZingModuleDoc ZingModuleDoc;
typedef struct ZingTest ZingTest;

struct ZingName {
  char *name;
  ZingName *next;
};

struct ZingMethod {
  char *name;
  ZingName *params;
  ZingName *locals;
  struct Expr *body;
  char *module_id;
  int exported;
  ZingDocBlock *doc;
  ZingMethod *next;
};

struct ZingMethodHead {
  char *name;
  ZingName *params;
};

struct ZingType {
  char *name;
  ZingType *args;
  ZingType *next;
  int line;
  int col;
};

struct ZingTypeDecl {
  char *name;
  ZingType *type;
  char *module_id;
  int exported;
  ZingDocBlock *doc;
  ZingTypeDecl *next;
};

struct ZingField {
  char *name;
  ZingType *type;
  ZingField *next;
};

struct ZingStruct {
  char *name;
  ZingField *fields;
  char *module_id;
  int exported;
  ZingDocBlock *doc;
  ZingStruct *next;
};

struct ZingLayoutField {
  char *name;
  char *pic;
  char *usage;
  char *redefines;
  long offset;
  int has_offset;
  long size;
  int has_size;
  long pic_digits;
  long pic_scale;
  int pic_is_bytes;
  int pic_signed;
  int pic_edited;
  char *pic_edit_mask;
  long pic_edit_mask_len;
  long pic_edit_digits;
  int pic_edit_has_sign;
  int usage_kind;
  int line;
  int col;
  ZingLayoutField *next;
};

struct ZingLayout {
  char *name;
  long bytes;
  ZingLayoutField *fields;
  char *module_id;
  int exported;
  ZingDocBlock *doc;
  ZingLayout *next;
};

struct ZingEnumCase {
  char *name;
  ZingField *fields;
  ZingEnumCase *next;
};

struct ZingEnum {
  char *name;
  ZingName *params;
  ZingEnumCase *cases;
  char *module_id;
  int exported;
  ZingDocBlock *doc;
  ZingEnum *next;
};

struct ZingTypeUse {
  ZingType *type;
  char *context;
  char *module_id;
  ZingTypeUse *next;
};

struct ZingCarrierUse {
  char *symbol;
  char *context;
  int line;
  int col;
  ZingCarrierUse *next;
};

struct ZingExtern {
  char *name;
  ZingName *params;
  char *module_id;
  int exported;
  ZingDocBlock *doc;
  ZingExtern *next;
};

struct ZingConst {
  char *name;
  struct Expr *value;
  char *module_id;
  int int_width;
  int int_unsigned;
  int64_t sval;
  uint64_t uval;
  int has_value;
  ZingConst *next;
};

struct ZingUse {
  char *module_id;
  char *target_id;
  char *alias;
  ZingUse *next;
};

enum ZingDeclKind {
  ZING_DECL_LAYOUT,
  ZING_DECL_PROTOCOL,
  ZING_DECL_SERVICE
};

struct ZingDecl {
  ZingDeclKind kind;
  char *name;
  char *module_id;
  int exported;
  ZingDocBlock *doc;
  ZingDecl *next;
};

struct ZingDocBlock {
  char **lines;
  size_t count;
  size_t cap;
  char *file;
  int line;
};

struct ZingModuleDoc {
  char *module_id;
  ZingDocBlock *doc;
  ZingModuleDoc *next;
};

struct ZingTest {
  char *name;
  char *desc;
  struct Expr *body;
  char *module_id;
  ZingDocBlock *doc;
  ZingTest *next;
};

ZingName *zing_name_append(ZingName *list, const char *name);
void zing_name_free(ZingName *list);

ZingMethodHead *zing_method_head_new(const char *name, ZingName *params);
void zing_method_head_free(ZingMethodHead *head);

ZingMethod *zing_method_new(const char *name, ZingName *params,
                            ZingName *locals, struct Expr *body);

ZingType *zing_type_new(const char *name, ZingType *args, int line, int col);
ZingType *zing_type_append_arg(ZingType *list, ZingType *type);
void zing_type_free(ZingType *type);

ZingTypeDecl *zing_type_decl_new(const char *name, ZingType *type);
void zing_type_decl_free(ZingTypeDecl *decl);

ZingField *zing_field_new(const char *name, ZingType *type);
ZingField *zing_field_append(ZingField *list, ZingField *field);
void zing_field_free(ZingField *field);

ZingStruct *zing_struct_new(const char *name, ZingField *fields);
void zing_struct_free(ZingStruct *def);

ZingLayoutField *zing_layout_field_new(const char *name, long offset,
                                       int has_offset, const char *pic,
                                       const char *usage,
                                       const char *redefines,
                                       int line, int col);
ZingLayoutField *zing_layout_field_append(ZingLayoutField *list,
                                          ZingLayoutField *field);
void zing_layout_field_free(ZingLayoutField *field);

ZingLayout *zing_layout_new(const char *name, long bytes,
                            ZingLayoutField *fields);
void zing_layout_free(ZingLayout *layout);

ZingEnumCase *zing_enum_case_new(const char *name, ZingField *fields);
ZingEnumCase *zing_enum_case_append(ZingEnumCase *list, ZingEnumCase *node);
void zing_enum_case_free(ZingEnumCase *node);

ZingEnum *zing_enum_new(const char *name, ZingName *params,
                        ZingEnumCase *cases);
void zing_enum_free(ZingEnum *def);

void zing_ast_reset(void);
void zing_ast_add_method(ZingMethod *method);
ZingMethod *zing_ast_methods(void);

void zing_ast_add_type_decl(ZingTypeDecl *decl);
ZingTypeDecl *zing_ast_type_decls(void);

void zing_ast_add_struct(ZingStruct *def);
ZingStruct *zing_ast_structs(void);

void zing_ast_add_layout(ZingLayout *layout);
ZingLayout *zing_ast_layouts(void);

void zing_ast_add_enum(ZingEnum *def);
ZingEnum *zing_ast_enums(void);

void zing_ast_add_type_use(ZingType *type, const char *context);
ZingTypeUse *zing_ast_type_uses(void);

void zing_ast_add_carrier_use(const char *symbol, const char *context,
                              int line, int col);
ZingCarrierUse *zing_ast_carrier_uses(void);

void zing_ast_set_module_header(const char *module_id);
const char *zing_ast_module_header_id(void);
int zing_ast_has_module_header(void);
void zing_ast_mark_module_block(void);
int zing_ast_has_module_block(void);
void zing_ast_push_module(const char *module_id);
void zing_ast_pop_module(void);
const char *zing_ast_current_module_id(void);
char *zing_ast_dup_current_module_id(void);
void zing_ast_apply_default_module(const char *module_id);

void zing_ast_set_export_next(void);
int zing_ast_take_export_next(void);

void zing_ast_doc_line_slice(const char *file, int line, const char *text,
                             size_t len);
void zing_ast_doc_observe_token(int tok);
ZingDocBlock *zing_ast_take_doc_block(void);
void zing_ast_clear_doc_block(void);
void zing_ast_doc_suspend(void);
void zing_ast_doc_resume(void);
void zing_ast_attach_module_doc(const char *module_id);
ZingModuleDoc *zing_ast_module_docs(void);

ZingExtern *zing_extern_new(const char *name, ZingName *params);
void zing_extern_free(ZingExtern *decl);
void zing_ast_add_extern(ZingExtern *decl);
ZingExtern *zing_ast_externs(void);

ZingConst *zing_const_new(const char *name, struct Expr *value);
void zing_const_free(ZingConst *decl);
void zing_ast_add_const(ZingConst *decl);
ZingConst *zing_ast_consts(void);

ZingUse *zing_use_new(const char *module_id, const char *target_id,
                      const char *alias);
void zing_use_free(ZingUse *use);
void zing_ast_add_use(ZingUse *use);
ZingUse *zing_ast_uses(void);

ZingDecl *zing_decl_new(ZingDeclKind kind, const char *name);
void zing_decl_free(ZingDecl *decl);
void zing_ast_add_decl(ZingDecl *decl);
ZingDecl *zing_ast_decls(void);

ZingTest *zing_test_new(const char *name, const char *desc, struct Expr *body);
void zing_ast_add_test(ZingTest *test);
ZingTest *zing_ast_tests(void);
void zing_ast_clear_tests(void);

#endif
