/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_op.h"

#include <string.h>

zem_op_t zem_decode_mnemonic(const char *m) {
  if (!m || !*m) return ZEM_OP_UNKNOWN;

  // The cost of this decoder is paid once per record; the hot loop should
  // only compare the returned enum.
  switch (m[0]) {
    case 'A':
      if (strcmp(m, "ADD") == 0) return ZEM_OP_ADD;
      if (strcmp(m, "ADD64") == 0) return ZEM_OP_ADD64;
      if (strcmp(m, "AND") == 0) return ZEM_OP_AND;
      if (strcmp(m, "AND64") == 0) return ZEM_OP_AND64;
      break;
    case 'C':
      if (strcmp(m, "CALL") == 0) return ZEM_OP_CALL;
      if (strcmp(m, "CP") == 0) return ZEM_OP_CP;
      if (strcmp(m, "CLZ") == 0) return ZEM_OP_CLZ;
      if (strcmp(m, "CTZ") == 0) return ZEM_OP_CTZ;
      if (strcmp(m, "CLZ64") == 0) return ZEM_OP_CLZ64;
      if (strcmp(m, "CTZ64") == 0) return ZEM_OP_CTZ64;
      break;
    case 'D':
      if (strcmp(m, "DEC") == 0) return ZEM_OP_DEC;
      if (strcmp(m, "DROP") == 0) return ZEM_OP_DROP;
      if (strcmp(m, "DIVS") == 0) return ZEM_OP_DIVS;
      if (strcmp(m, "DIVU") == 0) return ZEM_OP_DIVU;
      if (strcmp(m, "DIVS64") == 0) return ZEM_OP_DIVS64;
      if (strcmp(m, "DIVU64") == 0) return ZEM_OP_DIVU64;
      break;
    case 'E':
      if (strcmp(m, "EQ") == 0) return ZEM_OP_EQ;
      if (strcmp(m, "EQ64") == 0) return ZEM_OP_EQ64;
      break;
    case 'F':
      if (strcmp(m, "FILL") == 0) return ZEM_OP_FILL;
      break;
    case 'G':
      if (strcmp(m, "GES") == 0) return ZEM_OP_GES;
      if (strcmp(m, "GEU") == 0) return ZEM_OP_GEU;
      if (strcmp(m, "GTS") == 0) return ZEM_OP_GTS;
      if (strcmp(m, "GTU") == 0) return ZEM_OP_GTU;
      if (strcmp(m, "GES64") == 0) return ZEM_OP_GES64;
      if (strcmp(m, "GEU64") == 0) return ZEM_OP_GEU64;
      if (strcmp(m, "GTS64") == 0) return ZEM_OP_GTS64;
      if (strcmp(m, "GTU64") == 0) return ZEM_OP_GTU64;
      break;
    case 'I':
      if (strcmp(m, "INC") == 0) return ZEM_OP_INC;
      break;
    case 'J':
      if (strcmp(m, "JR") == 0) return ZEM_OP_JR;
      break;
    case 'L':
      if (strcmp(m, "LD") == 0) return ZEM_OP_LD;
      if (strcmp(m, "LDIR") == 0) return ZEM_OP_LDIR;
      if (strcmp(m, "LD8U") == 0) return ZEM_OP_LD8U;
      if (strcmp(m, "LD8S") == 0) return ZEM_OP_LD8S;
      if (strcmp(m, "LD16U") == 0) return ZEM_OP_LD16U;
      if (strcmp(m, "LD16S") == 0) return ZEM_OP_LD16S;
      if (strcmp(m, "LD32") == 0) return ZEM_OP_LD32;
      if (strcmp(m, "LD8U64") == 0) return ZEM_OP_LD8U64;
      if (strcmp(m, "LD8S64") == 0) return ZEM_OP_LD8S64;
      if (strcmp(m, "LD16U64") == 0) return ZEM_OP_LD16U64;
      if (strcmp(m, "LD16S64") == 0) return ZEM_OP_LD16S64;
      if (strcmp(m, "LD32U64") == 0) return ZEM_OP_LD32U64;
      if (strcmp(m, "LD32S64") == 0) return ZEM_OP_LD32S64;
      if (strcmp(m, "LD64") == 0) return ZEM_OP_LD64;
      break;
    case 'M':
      if (strcmp(m, "MUL") == 0) return ZEM_OP_MUL;
      if (strcmp(m, "MUL64") == 0) return ZEM_OP_MUL64;
      break;
    case 'N':
      if (strcmp(m, "NE") == 0) return ZEM_OP_NE;
      if (strcmp(m, "NE64") == 0) return ZEM_OP_NE64;
      break;
    case 'O':
      if (strcmp(m, "OR") == 0) return ZEM_OP_OR;
      if (strcmp(m, "OR64") == 0) return ZEM_OP_OR64;
      break;
    case 'P':
      if (strcmp(m, "POPC") == 0) return ZEM_OP_POPC;
      if (strcmp(m, "POPC64") == 0) return ZEM_OP_POPC64;
      break;
    case 'R':
      if (strcmp(m, "RET") == 0) return ZEM_OP_RET;
      if (strcmp(m, "REMS") == 0) return ZEM_OP_REMS;
      if (strcmp(m, "REMU") == 0) return ZEM_OP_REMU;
      if (strcmp(m, "REMS64") == 0) return ZEM_OP_REMS64;
      if (strcmp(m, "REMU64") == 0) return ZEM_OP_REMU64;
      if (strcmp(m, "ROL") == 0) return ZEM_OP_ROL;
      if (strcmp(m, "ROR") == 0) return ZEM_OP_ROR;
      if (strcmp(m, "ROL64") == 0) return ZEM_OP_ROL64;
      if (strcmp(m, "ROR64") == 0) return ZEM_OP_ROR64;
      break;
    case 'S':
      if (strcmp(m, "SUB") == 0) return ZEM_OP_SUB;
      if (strcmp(m, "SUB64") == 0) return ZEM_OP_SUB64;
      if (strcmp(m, "SLA") == 0) return ZEM_OP_SLA;
      if (strcmp(m, "SRL") == 0) return ZEM_OP_SRL;
      if (strcmp(m, "SRA") == 0) return ZEM_OP_SRA;
      if (strcmp(m, "SLA64") == 0) return ZEM_OP_SLA64;
      if (strcmp(m, "SRL64") == 0) return ZEM_OP_SRL64;
      if (strcmp(m, "SRA64") == 0) return ZEM_OP_SRA64;
      if (strcmp(m, "ST8") == 0) return ZEM_OP_ST8;
      if (strcmp(m, "ST16") == 0) return ZEM_OP_ST16;
      if (strcmp(m, "ST32") == 0) return ZEM_OP_ST32;
      if (strcmp(m, "ST8_64") == 0) return ZEM_OP_ST8_64;
      if (strcmp(m, "ST16_64") == 0) return ZEM_OP_ST16_64;
      if (strcmp(m, "ST32_64") == 0) return ZEM_OP_ST32_64;
      if (strcmp(m, "ST64") == 0) return ZEM_OP_ST64;
      break;
    case 'X':
      if (strcmp(m, "XOR") == 0) return ZEM_OP_XOR;
      if (strcmp(m, "XOR64") == 0) return ZEM_OP_XOR64;
      break;
  }

  // Two-char / three-char cases that overlap initial letters.
  if (strcmp(m, "LTS") == 0) return ZEM_OP_LTS;
  if (strcmp(m, "LTU") == 0) return ZEM_OP_LTU;
  if (strcmp(m, "LES") == 0) return ZEM_OP_LES;
  if (strcmp(m, "LEU") == 0) return ZEM_OP_LEU;
  if (strcmp(m, "LTS64") == 0) return ZEM_OP_LTS64;
  if (strcmp(m, "LTU64") == 0) return ZEM_OP_LTU64;
  if (strcmp(m, "LES64") == 0) return ZEM_OP_LES64;
  if (strcmp(m, "LEU64") == 0) return ZEM_OP_LEU64;

  return ZEM_OP_UNKNOWN;
}
