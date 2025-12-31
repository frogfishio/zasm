/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "emit_json.h"
#include "zasm_types.h"
int yylex(void);
void yyerror(const char* s);

extern int yylineno;
extern int zasm_tok_col;
extern char* zasm_linebuf;

static opnode_t* opnode_new_sym(char* s) {
  opnode_t* n = (opnode_t*)calloc(1, sizeof(*n));
  n->op.t = OP_SYM; n->op.s = s;
  return n;
}
static opnode_t* opnode_new_num(long v) {
  opnode_t* n = (opnode_t*)calloc(1, sizeof(*n));
  n->op.t = OP_NUM; n->op.n = v;
  return n;
}
static opnode_t* opnode_new_str(char* s) {
  opnode_t* n = (opnode_t*)calloc(1, sizeof(*n));
  n->op.t = OP_STR; n->op.s = s;
  return n;
}
static opnode_t* opnode_new_mem(char* s) {
  opnode_t* n = (opnode_t*)calloc(1, sizeof(*n));
  n->op.t = OP_MEM; n->op.s = s;
  return n;
}

static opnode_t* opnode_append(opnode_t* a, opnode_t* b) {
  if (!a) return b;
  opnode_t* p = a;
  while (p->next) p = p->next;
  p->next = b;
  return a;
}

static void opnode_to_array(opnode_t* list, operand_t** out_ops, size_t* out_n) {
  size_t n = 0;
  for (opnode_t* p = list; p; p = p->next) n++;
  operand_t* ops = (operand_t*)calloc(n ? n : 1, sizeof(*ops));
  size_t i = 0;
  for (opnode_t* p = list; p; p = p->next) ops[i++] = p->op;
  *out_ops = ops;
  *out_n = n;
}

static void opnode_free_nodes(opnode_t* list) {
  // MVP: free nodes only. strings are leaked for now (fix later with arena).
  while (list) {
    opnode_t* n = list->next;
    free(list);
    list = n;
  }
}
%}

%union {
  char* str;
  long num;
  opnode_t* oplist;
  instrinfo_t instr;
  dirinfo_t dir;
}

%token T_NL T_COLON T_COMMA T_LPAREN T_RPAREN
%token T_CALL T_RET T_LD T_INC T_DEC T_CP T_JR T_ADD T_SUB T_DB T_DW T_RESB T_STRDIR T_EQU T_PUBLIC T_EXTERN
%token <str> T_ID T_STR
%token <num> T_NUM

%type <str> label
%type <str> jr_tail
%type <oplist> operand arg args
%type <instr> stmtinfo
%type <dir> dirinfo

%%

program
  : /* empty */
  | program line
  ;

line
  : T_NL
    /* Empty line; keeps the grammar newline-driven to preserve streaming behavior. */
  | label T_NL
    {
      emit_label($1, yylineno);
    }
  | stmtinfo T_NL
    {
      operand_t* ops = NULL; size_t nops = 0;
      opnode_to_array($1.ops, &ops, &nops);
      emit_instr($1.m, ops, nops, yylineno);

      free(ops);
      opnode_free_nodes($1.ops);
    }
  | dirinfo T_NL
    {
      operand_t* args = NULL; size_t nargs = 0;
      opnode_to_array($1.args, &args, &nargs);

      emit_dir($1.d, NULL, args, nargs, yylineno);

      free(args);
      opnode_free_nodes($1.args);
    }
  | label stmtinfo T_NL
    {
      emit_label($1, yylineno);

      operand_t* ops = NULL; size_t nops = 0;
      opnode_to_array($2.ops, &ops, &nops);
      emit_instr($2.m, ops, nops, yylineno);

      free(ops);
      opnode_free_nodes($2.ops);
    }
  | label dirinfo T_NL
    {
      operand_t* args = NULL; size_t nargs = 0;
      opnode_to_array($2.args, &args, &nargs);

      // IMPORTANT: directive gets the label name as "name"
      emit_dir($2.d, $1, args, nargs, yylineno);

      free(args);
      opnode_free_nodes($2.args);
    }
  ;

label
  : T_ID T_COLON { $$ = $1; }
  ;

stmtinfo
  : T_CALL T_ID
    {
      $$.m = "CALL";
      $$.ops = opnode_new_sym($2);
    }
  | T_RET
    {
      $$.m = "RET";
      $$.ops = NULL;
    }
  | T_LD operand T_COMMA operand
    {
      $$.m = "LD";
      $$.ops = opnode_append($2, $4);
    }
  | T_INC operand
    {
      $$.m = "INC";
      $$.ops = $2;
    }
  | T_DEC operand
    {
      $$.m = "DEC";
      $$.ops = $2;
    }
  | T_CP operand T_COMMA operand
    {
      $$.m = "CP";
      $$.ops = opnode_append($2, $4);
    }
  | T_JR T_ID jr_tail
    {
      $$.m = "JR";
      if ($3) {
        $$.ops = opnode_append(opnode_new_sym($2), opnode_new_sym($3));
      } else {
        $$.ops = opnode_new_sym($2);
      }
    }
  | T_ADD operand T_COMMA operand
    {
      $$.m = "ADD";
      $$.ops = opnode_append($2, $4);
    }
  | T_SUB operand T_COMMA operand
    {
      $$.m = "SUB";
      $$.ops = opnode_append($2, $4);
    }
  ;

jr_tail
  : /* empty */ { $$ = NULL; }
  | T_COMMA T_ID { $$ = $2; }
  ;

dirinfo
  : T_DB args
    {
      $$.d = "DB";
      $$.args = $2;
    }
  | T_DW args
    {
      $$.d = "DW";
      $$.args = $2;
    }
  | T_RESB args
    {
      $$.d = "RESB";
      $$.args = $2;
    }
  | T_STRDIR args
    {
      $$.d = "STR";
      $$.args = $2;
    }
  | T_EQU args
    {
      $$.d = "EQU";
      $$.args = $2;
    }
  | T_PUBLIC args
    {
      $$.d = "PUBLIC";
      $$.args = $2;
    }
  | T_EXTERN args
    {
      $$.d = "EXTERN";
      $$.args = $2;
    }
  ;

args
  : arg
  | args T_COMMA arg { $$ = opnode_append($1, $3); }
  ;

arg
  : T_STR { $$ = opnode_new_str($1); }
  | T_NUM { $$ = opnode_new_num($1); }
  | T_ID  { $$ = opnode_new_sym($1); }
  ;

operand
  : T_ID  { $$ = opnode_new_sym($1); }
  | T_NUM { $$ = opnode_new_num($1); }
  | T_LPAREN T_ID T_RPAREN { $$ = opnode_new_mem($2); }
  ;

%%

void yyerror(const char* s) {
  fprintf(stderr, "zas: parse error at line %d:%d: %s\n", yylineno, zasm_tok_col, s);
  if (zasm_linebuf && zasm_linebuf[0]) {
    fprintf(stderr, "%s\n", zasm_linebuf);
    int col = zasm_tok_col;
    if (col < 1) col = 1;
    for (int i = 1; i < col; i++) fputc(' ', stderr);
    fputc('^', stderr);
    fputc('\n', stderr);
  }
}
