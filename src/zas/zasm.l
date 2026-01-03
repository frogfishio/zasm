/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

%option noyywrap nodefault yylineno

%{
#define _POSIX_C_SOURCE 200809L

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

static void collapse_backslash_pairs(char* s) {
  if (!s) return;
  char* w = s;
  for (char* r = s; *r; ++r) {
    if (*r == '\\' && r[1] == '\\') {
      *w++ = '\\';
      r++;
    } else {
      *w++ = *r;
    }
  }
  *w = 0;
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
"ADD64"             { tok_advance(); return T_ADD64; }
"SUB64"             { tok_advance(); return T_SUB64; }
"MUL64"             { tok_advance(); return T_MUL64; }
"DIVS64"            { tok_advance(); return T_DIVS64; }
"DIVU64"            { tok_advance(); return T_DIVU64; }
"REMS64"            { tok_advance(); return T_REMS64; }
"REMU64"            { tok_advance(); return T_REMU64; }
"AND64"             { tok_advance(); return T_AND64; }
"OR64"              { tok_advance(); return T_OR64; }
"XOR64"             { tok_advance(); return T_XOR64; }
"EQ64"              { tok_advance(); return T_EQ64; }
"NE64"              { tok_advance(); return T_NE64; }
"LTS64"             { tok_advance(); return T_LTS64; }
"LTU64"             { tok_advance(); return T_LTU64; }
"LES64"             { tok_advance(); return T_LES64; }
"LEU64"             { tok_advance(); return T_LEU64; }
"GTS64"             { tok_advance(); return T_GTS64; }
"GTU64"             { tok_advance(); return T_GTU64; }
"GES64"             { tok_advance(); return T_GES64; }
"GEU64"             { tok_advance(); return T_GEU64; }
"CLZ64"             { tok_advance(); return T_CLZ64; }
"CTZ64"             { tok_advance(); return T_CTZ64; }
"POPC64"            { tok_advance(); return T_POPC64; }
"SLA64"             { tok_advance(); return T_SLA64; }
"SRA64"             { tok_advance(); return T_SRA64; }
"SRL64"             { tok_advance(); return T_SRL64; }
"ROL64"             { tok_advance(); return T_ROL64; }
"ROR64"             { tok_advance(); return T_ROR64; }
"LD8S64"            { tok_advance(); return T_LD8S64; }
"LD8U64"            { tok_advance(); return T_LD8U64; }
"LD16S64"           { tok_advance(); return T_LD16S64; }
"LD16U64"           { tok_advance(); return T_LD16U64; }
"LD32S64"           { tok_advance(); return T_LD32S64; }
"LD32U64"           { tok_advance(); return T_LD32U64; }
"ST8_64"            { tok_advance(); return T_ST8_64; }
"ST16_64"           { tok_advance(); return T_ST16_64; }
"ST32_64"           { tok_advance(); return T_ST32_64; }
"LD"                { tok_advance(); return T_LD; }
"INC"               { tok_advance(); return T_INC; }
"DEC"               { tok_advance(); return T_DEC; }
"CP"                { tok_advance(); return T_CP; }
"JR"                { tok_advance(); return T_JR; }
"ADD"               { tok_advance(); return T_ADD; }
"MUL"               { tok_advance(); return T_MUL; }
"DIVS"              { tok_advance(); return T_DIVS; }
"DIVU"              { tok_advance(); return T_DIVU; }
"REMS"              { tok_advance(); return T_REMS; }
"REMU"              { tok_advance(); return T_REMU; }
"AND"               { tok_advance(); return T_AND; }
"OR"                { tok_advance(); return T_OR; }
"XOR"               { tok_advance(); return T_XOR; }
"EQ"                { tok_advance(); return T_EQ; }
"NE"                { tok_advance(); return T_NE; }
"LTS"               { tok_advance(); return T_LTS; }
"LTU"               { tok_advance(); return T_LTU; }
"LES"               { tok_advance(); return T_LES; }
"LEU"               { tok_advance(); return T_LEU; }
"GTS"               { tok_advance(); return T_GTS; }
"GTU"               { tok_advance(); return T_GTU; }
"GES"               { tok_advance(); return T_GES; }
"GEU"               { tok_advance(); return T_GEU; }
"CLZ"               { tok_advance(); return T_CLZ; }
"CTZ"               { tok_advance(); return T_CTZ; }
"POPC"              { tok_advance(); return T_POPC; }
"SLA"               { tok_advance(); return T_SLA; }
"SRA"               { tok_advance(); return T_SRA; }
"SRL"               { tok_advance(); return T_SRL; }
"ROL"               { tok_advance(); return T_ROL; }
"ROR"               { tok_advance(); return T_ROR; }
"LD64"              { tok_advance(); return T_LD64; }
"ST64"              { tok_advance(); return T_ST64; }
"LD8U"              { tok_advance(); return T_LD8U; }
"LD8S"              { tok_advance(); return T_LD8S; }
"ST8"               { tok_advance(); return T_ST8; }
"LD16U"             { tok_advance(); return T_LD16U; }
"LD16S"             { tok_advance(); return T_LD16S; }
"ST16"              { tok_advance(); return T_ST16; }
"LD32"              { tok_advance(); return T_LD32; }
"ST32"              { tok_advance(); return T_ST32; }
"FILL"              { tok_advance(); return T_FILL; }
"LDIR"              { tok_advance(); return T_LDIR; }
"DROP"              { tok_advance(); return T_DROP; }
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
                      collapse_backslash_pairs(inner);
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
