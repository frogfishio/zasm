/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

%option noyywrap nodefault yylineno

%{
#include "zasm_types.h"
#include "zasm.tab.h"
#include <stdlib.h>
#include <string.h>

int zasm_tok_col = 1;
char* zasm_linebuf = NULL;
static size_t zasm_linecap = 0;
static size_t zasm_linelen = 0;
static int zasm_col = 1;

static void linebuf_append(const char* s, size_t n) {
  if (!s || n == 0) return;
  if (zasm_linecap < zasm_linelen + n + 1) {
    size_t newcap = zasm_linecap ? zasm_linecap * 2 : 128;
    while (newcap < zasm_linelen + n + 1) newcap *= 2;
    zasm_linebuf = (char*)realloc(zasm_linebuf, newcap);
    zasm_linecap = newcap;
  }
  memcpy(zasm_linebuf + zasm_linelen, s, n);
  zasm_linelen += n;
  zasm_linebuf[zasm_linelen] = 0;
}

static void linebuf_reset(void) {
  zasm_linelen = 0;
  if (zasm_linebuf) zasm_linebuf[0] = 0;
}

static void tok_advance(void) {
  zasm_tok_col = zasm_col;
  linebuf_append(yytext, (size_t)yyleng);
  zasm_col += (int)yyleng;
}

static void skip_advance(void) {
  linebuf_append(yytext, (size_t)yyleng);
  zasm_col += (int)yyleng;
}

static char* dup_lexeme(void) {
  size_t n = (size_t)yyleng;
  char* s = (char*)malloc(n + 1);
  memcpy(s, yytext, n);
  s[n] = 0;
  return s;
}

static int emitted_eof_nl = 0;
%}

WS      [ \t]+
NL      (\r\n|\n|\r)
ID      [A-Za-z_.$][A-Za-z0-9_.$]*
NUM     [0-9]+
HEX     0[xX][0-9A-Fa-f]+

%%

";".*               { skip_advance(); }
{WS}                { skip_advance(); }
{NL}                { linebuf_reset(); zasm_col = 1; return T_NL; }

":"                 { tok_advance(); return T_COLON; }
","                 { tok_advance(); return T_COMMA; }
"("                 { tok_advance(); return T_LPAREN; }
")"                 { tok_advance(); return T_RPAREN; }

"CALL"              { tok_advance(); return T_CALL; }
"RET"               { tok_advance(); return T_RET; }
"LD"                { tok_advance(); return T_LD; }
"INC"               { tok_advance(); return T_INC; }
"DEC"               { tok_advance(); return T_DEC; }
"CP"                { tok_advance(); return T_CP; }
"JR"                { tok_advance(); return T_JR; }
"ADD"               { tok_advance(); return T_ADD; }
"SUB"               { tok_advance(); return T_SUB; }
"DB"                { tok_advance(); return T_DB; }
"DW"                { tok_advance(); return T_DW; }
"RESB"              { tok_advance(); return T_RESB; }
"STR"               { tok_advance(); return T_STRDIR; }
"EQU"               { tok_advance(); return T_EQU; }
"PUBLIC"            { tok_advance(); return T_PUBLIC; }
"EXTERN"            { tok_advance(); return T_EXTERN; }

{HEX}               { tok_advance(); yylval.num = strtol(yytext, NULL, 0); return T_NUM; }
{NUM}               { tok_advance(); yylval.num = strtol(yytext, NULL, 10); return T_NUM; }

\"([^\\\"]|\\.)*\"  {
                      tok_advance();
                      // strip quotes for MVP; no full unescape yet
                      char* raw = dup_lexeme();
                      size_t len = strlen(raw);
                      raw[len-1] = 0;
                      char* inner = strdup(raw+1);
                      free(raw);
                      yylval.str = inner;
                      return T_STR;
                    }

{ID}                { tok_advance(); yylval.str = dup_lexeme(); return T_ID; }

<<EOF>>             {
                      if (!emitted_eof_nl) { emitted_eof_nl = 1; return T_NL; }
                      return 0;
                    }

.                   { skip_advance(); }

%%
