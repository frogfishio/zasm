/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

%{
#define _POSIX_C_SOURCE 200809L

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
%token T_CALL T_RET T_LD T_INC T_DEC T_CP T_JR T_ADD T_MUL T_DIVS T_DIVU T_REMS T_REMU T_AND T_OR T_XOR T_EQ T_NE T_LTS T_LTU T_LES T_LEU T_GTS T_GTU T_GES T_GEU T_CLZ T_CTZ T_POPC T_SLA T_SRA T_SRL T_ROL T_ROR T_LD8U T_LD8S T_ST8 T_ST16 T_LD16U T_LD16S T_LD32 T_ST32 T_LD8U64 T_LD8S64 T_LD16U64 T_LD16S64 T_LD32U64 T_LD32S64 T_ST8_64 T_ST16_64 T_ST32_64 T_FILL T_LDIR T_DROP T_SUB T_DB T_DW T_RESB T_STRDIR T_EQU T_PUBLIC T_EXTERN
%token T_ADD64 T_SUB64 T_MUL64 T_DIVS64 T_DIVU64 T_REMS64 T_REMU64 T_AND64 T_OR64 T_XOR64 T_EQ64 T_NE64 T_LTS64 T_LTU64 T_LES64 T_LEU64 T_GTS64 T_GTU64 T_GES64 T_GEU64 T_CLZ64 T_CTZ64 T_POPC64 T_SLA64 T_SRA64 T_SRL64 T_ROL64 T_ROR64 T_LD64 T_ST64
%token <str> T_ID T_STR
%token <num> T_NUM

%type <str> label
%type <str> jr_head
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
  | T_JR jr_head jr_tail
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
  | T_ADD64 operand T_COMMA operand
    {
      $$.m = "ADD64";
      $$.ops = opnode_append($2, $4);
    }
  | T_MUL operand T_COMMA operand
    {
      $$.m = "MUL";
      $$.ops = opnode_append($2, $4);
    }
  | T_MUL64 operand T_COMMA operand
    {
      $$.m = "MUL64";
      $$.ops = opnode_append($2, $4);
    }
  | T_DIVS operand T_COMMA operand
    {
      $$.m = "DIVS";
      $$.ops = opnode_append($2, $4);
    }
  | T_DIVS64 operand T_COMMA operand
    {
      $$.m = "DIVS64";
      $$.ops = opnode_append($2, $4);
    }
  | T_DIVU operand T_COMMA operand
    {
      $$.m = "DIVU";
      $$.ops = opnode_append($2, $4);
    }
  | T_DIVU64 operand T_COMMA operand
    {
      $$.m = "DIVU64";
      $$.ops = opnode_append($2, $4);
    }
  | T_REMS operand T_COMMA operand
    {
      $$.m = "REMS";
      $$.ops = opnode_append($2, $4);
    }
  | T_REMS64 operand T_COMMA operand
    {
      $$.m = "REMS64";
      $$.ops = opnode_append($2, $4);
    }
  | T_REMU operand T_COMMA operand
    {
      $$.m = "REMU";
      $$.ops = opnode_append($2, $4);
    }
  | T_REMU64 operand T_COMMA operand
    {
      $$.m = "REMU64";
      $$.ops = opnode_append($2, $4);
    }
  | T_AND operand T_COMMA operand
    {
      $$.m = "AND";
      $$.ops = opnode_append($2, $4);
    }
  | T_AND64 operand T_COMMA operand
    {
      $$.m = "AND64";
      $$.ops = opnode_append($2, $4);
    }
  | T_OR operand T_COMMA operand
    {
      $$.m = "OR";
      $$.ops = opnode_append($2, $4);
    }
  | T_OR64 operand T_COMMA operand
    {
      $$.m = "OR64";
      $$.ops = opnode_append($2, $4);
    }
  | T_XOR operand T_COMMA operand
    {
      $$.m = "XOR";
      $$.ops = opnode_append($2, $4);
    }
  | T_XOR64 operand T_COMMA operand
    {
      $$.m = "XOR64";
      $$.ops = opnode_append($2, $4);
    }
  | T_EQ operand T_COMMA operand
    {
      $$.m = "EQ";
      $$.ops = opnode_append($2, $4);
    }
  | T_EQ64 operand T_COMMA operand
    {
      $$.m = "EQ64";
      $$.ops = opnode_append($2, $4);
    }
  | T_NE operand T_COMMA operand
    {
      $$.m = "NE";
      $$.ops = opnode_append($2, $4);
    }
  | T_NE64 operand T_COMMA operand
    {
      $$.m = "NE64";
      $$.ops = opnode_append($2, $4);
    }
  | T_LTS operand T_COMMA operand
    {
      $$.m = "LTS";
      $$.ops = opnode_append($2, $4);
    }
  | T_LTS64 operand T_COMMA operand
    {
      $$.m = "LTS64";
      $$.ops = opnode_append($2, $4);
    }
  | T_LTU operand T_COMMA operand
    {
      $$.m = "LTU";
      $$.ops = opnode_append($2, $4);
    }
  | T_LTU64 operand T_COMMA operand
    {
      $$.m = "LTU64";
      $$.ops = opnode_append($2, $4);
    }
  | T_LES operand T_COMMA operand
    {
      $$.m = "LES";
      $$.ops = opnode_append($2, $4);
    }
  | T_LES64 operand T_COMMA operand
    {
      $$.m = "LES64";
      $$.ops = opnode_append($2, $4);
    }
  | T_LEU operand T_COMMA operand
    {
      $$.m = "LEU";
      $$.ops = opnode_append($2, $4);
    }
  | T_LEU64 operand T_COMMA operand
    {
      $$.m = "LEU64";
      $$.ops = opnode_append($2, $4);
    }
  | T_GTS operand T_COMMA operand
    {
      $$.m = "GTS";
      $$.ops = opnode_append($2, $4);
    }
  | T_GTS64 operand T_COMMA operand
    {
      $$.m = "GTS64";
      $$.ops = opnode_append($2, $4);
    }
  | T_GTU operand T_COMMA operand
    {
      $$.m = "GTU";
      $$.ops = opnode_append($2, $4);
    }
  | T_GTU64 operand T_COMMA operand
    {
      $$.m = "GTU64";
      $$.ops = opnode_append($2, $4);
    }
  | T_GES operand T_COMMA operand
    {
      $$.m = "GES";
      $$.ops = opnode_append($2, $4);
    }
  | T_GES64 operand T_COMMA operand
    {
      $$.m = "GES64";
      $$.ops = opnode_append($2, $4);
    }
  | T_GEU operand T_COMMA operand
    {
      $$.m = "GEU";
      $$.ops = opnode_append($2, $4);
    }
  | T_GEU64 operand T_COMMA operand
    {
      $$.m = "GEU64";
      $$.ops = opnode_append($2, $4);
    }
  | T_CLZ operand
    {
      $$.m = "CLZ";
      $$.ops = $2;
    }
  | T_CLZ64 operand
    {
      $$.m = "CLZ64";
      $$.ops = $2;
    }
  | T_CTZ operand
    {
      $$.m = "CTZ";
      $$.ops = $2;
    }
  | T_CTZ64 operand
    {
      $$.m = "CTZ64";
      $$.ops = $2;
    }
  | T_POPC operand
    {
      $$.m = "POPC";
      $$.ops = $2;
    }
  | T_POPC64 operand
    {
      $$.m = "POPC64";
      $$.ops = $2;
    }
  | T_SLA operand T_COMMA operand
    {
      $$.m = "SLA";
      $$.ops = opnode_append($2, $4);
    }
  | T_SLA64 operand T_COMMA operand
    {
      $$.m = "SLA64";
      $$.ops = opnode_append($2, $4);
    }
  | T_SRA operand T_COMMA operand
    {
      $$.m = "SRA";
      $$.ops = opnode_append($2, $4);
    }
  | T_SRA64 operand T_COMMA operand
    {
      $$.m = "SRA64";
      $$.ops = opnode_append($2, $4);
    }
  | T_SRL operand T_COMMA operand
    {
      $$.m = "SRL";
      $$.ops = opnode_append($2, $4);
    }
  | T_SRL64 operand T_COMMA operand
    {
      $$.m = "SRL64";
      $$.ops = opnode_append($2, $4);
    }
  | T_ROL operand T_COMMA operand
    {
      $$.m = "ROL";
      $$.ops = opnode_append($2, $4);
    }
  | T_ROL64 operand T_COMMA operand
    {
      $$.m = "ROL64";
      $$.ops = opnode_append($2, $4);
    }
  | T_ROR operand T_COMMA operand
    {
      $$.m = "ROR";
      $$.ops = opnode_append($2, $4);
    }
  | T_ROR64 operand T_COMMA operand
    {
      $$.m = "ROR64";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD8U operand T_COMMA operand
    {
      $$.m = "LD8U";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD8S operand T_COMMA operand
    {
      $$.m = "LD8S";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD8U64 operand T_COMMA operand
    {
      $$.m = "LD8U64";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD8S64 operand T_COMMA operand
    {
      $$.m = "LD8S64";
      $$.ops = opnode_append($2, $4);
    }
  | T_ST8 operand T_COMMA operand
    {
      $$.m = "ST8";
      $$.ops = opnode_append($2, $4);
    }
  | T_ST16 operand T_COMMA operand
    {
      $$.m = "ST16";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD16U operand T_COMMA operand
    {
      $$.m = "LD16U";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD16S operand T_COMMA operand
    {
      $$.m = "LD16S";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD16U64 operand T_COMMA operand
    {
      $$.m = "LD16U64";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD16S64 operand T_COMMA operand
    {
      $$.m = "LD16S64";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD32 operand T_COMMA operand
    {
      $$.m = "LD32";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD32U64 operand T_COMMA operand
    {
      $$.m = "LD32U64";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD32S64 operand T_COMMA operand
    {
      $$.m = "LD32S64";
      $$.ops = opnode_append($2, $4);
    }
  | T_LD64 operand T_COMMA operand
    {
      $$.m = "LD64";
      $$.ops = opnode_append($2, $4);
    }
  | T_ST32 operand T_COMMA operand
    {
      $$.m = "ST32";
      $$.ops = opnode_append($2, $4);
    }
  | T_ST8_64 operand T_COMMA operand
    {
      $$.m = "ST8_64";
      $$.ops = opnode_append($2, $4);
    }
  | T_ST16_64 operand T_COMMA operand
    {
      $$.m = "ST16_64";
      $$.ops = opnode_append($2, $4);
    }
  | T_ST32_64 operand T_COMMA operand
    {
      $$.m = "ST32_64";
      $$.ops = opnode_append($2, $4);
    }
  | T_ST64 operand T_COMMA operand
    {
      $$.m = "ST64";
      $$.ops = opnode_append($2, $4);
    }
  | T_FILL
    {
      $$.m = "FILL";
      $$.ops = NULL;
    }
  | T_LDIR
    {
      $$.m = "LDIR";
      $$.ops = NULL;
    }
  | T_DROP operand
    {
      $$.m = "DROP";
      $$.ops = $2;
    }
  | T_SUB operand T_COMMA operand
    {
      $$.m = "SUB";
      $$.ops = opnode_append($2, $4);
    }
  | T_SUB64 operand T_COMMA operand
    {
      $$.m = "SUB64";
      $$.ops = opnode_append($2, $4);
    }
  ;

jr_tail
  : /* empty */ { $$ = NULL; }
  | T_COMMA T_ID { $$ = $2; }
  ;

jr_head
  : T_ID { $$ = $1; }
  | T_EQ { $$ = strdup("EQ"); }
  | T_NE { $$ = strdup("NE"); }
  | T_LTS { $$ = strdup("LTS"); }
  | T_LTU { $$ = strdup("LTU"); }
  | T_LES { $$ = strdup("LES"); }
  | T_LEU { $$ = strdup("LEU"); }
  | T_GTS { $$ = strdup("GTS"); }
  | T_GTU { $$ = strdup("GTU"); }
  | T_GES { $$ = strdup("GES"); }
  | T_GEU { $$ = strdup("GEU"); }
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
