/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_hash.h"

#include <stddef.h>
#include <string.h>

static uint64_t fnv1a64_update(uint64_t h, const void *data, size_t n) {
  const unsigned char *p = (const unsigned char *)data;
  const uint64_t prime = 1099511628211ull;
  for (size_t i = 0; i < n; i++) {
    h ^= (uint64_t)p[i];
    h *= prime;
  }
  return h;
}

uint64_t zem_fnv1a64_init(void) { return 14695981039346656037ull; }

static uint64_t fnv_u8(uint64_t h, uint8_t v) { return fnv1a64_update(h, &v, 1); }

static uint64_t fnv_u32le(uint64_t h, uint32_t v) {
  unsigned char b[4];
  b[0] = (unsigned char)(v & 0xffu);
  b[1] = (unsigned char)((v >> 8) & 0xffu);
  b[2] = (unsigned char)((v >> 16) & 0xffu);
  b[3] = (unsigned char)((v >> 24) & 0xffu);
  return fnv1a64_update(h, b, sizeof(b));
}

static uint64_t fnv_u64le(uint64_t h, uint64_t v) {
  unsigned char b[8];
  b[0] = (unsigned char)(v & 0xffu);
  b[1] = (unsigned char)((v >> 8) & 0xffu);
  b[2] = (unsigned char)((v >> 16) & 0xffu);
  b[3] = (unsigned char)((v >> 24) & 0xffu);
  b[4] = (unsigned char)((v >> 32) & 0xffu);
  b[5] = (unsigned char)((v >> 40) & 0xffu);
  b[6] = (unsigned char)((v >> 48) & 0xffu);
  b[7] = (unsigned char)((v >> 56) & 0xffu);
  return fnv1a64_update(h, b, sizeof(b));
}

static uint64_t fnv_str(uint64_t h, const char *s) {
  if (!s) {
    return fnv_u32le(h, 0xffffffffu);
  }
  size_t n = strlen(s);
  if (n > 0xffffffffu) n = 0xffffffffu;
  h = fnv_u32le(h, (uint32_t)n);
  return fnv1a64_update(h, s, n);
}

static uint64_t fnv_operand(uint64_t h, const operand_t *op) {
  if (!op) return fnv_u8(h, 0);

  h = fnv_u8(h, (uint8_t)op->t);

  switch (op->t) {
    case JOP_NUM: {
      int64_t v = (int64_t)op->n;
      h = fnv_u64le(h, (uint64_t)v);
      break;
    }
    case JOP_MEM: {
      h = fnv_u8(h, (uint8_t)(op->base_is_reg ? 1 : 0));
      h = fnv_str(h, op->s);
      h = fnv_u64le(h, (uint64_t)(int64_t)op->disp);
      h = fnv_u32le(h, (uint32_t)op->size);
      break;
    }
    case JOP_SYM:
    case JOP_REG:
    case JOP_LBL:
    case JOP_STR:
      h = fnv_str(h, op->s);
      break;
    default:
      // Still hashed by type byte.
      break;
  }

  return h;
}

uint64_t zem_ir_module_hash_update(uint64_t h, const record_t *r) {
  if (!r) return fnv_u8(h, 0);

  h = fnv_u8(h, (uint8_t)r->k);

  if (r->k == JREC_INSTR) {
    h = fnv_str(h, r->m);
    h = fnv_u32le(h, (uint32_t)r->nops);
    for (size_t i = 0; i < r->nops; i++) {
      h = fnv_operand(h, &r->ops[i]);
    }
    return h;
  }

  if (r->k == JREC_DIR) {
    h = fnv_str(h, r->d);
    h = fnv_str(h, r->name);
    h = fnv_u32le(h, (uint32_t)r->nargs);
    for (size_t i = 0; i < r->nargs; i++) {
      h = fnv_operand(h, &r->args[i]);
    }
    // section is currently unused; keep it out of the identity.
    return h;
  }

  if (r->k == JREC_LABEL) {
    h = fnv_str(h, r->label);
    return h;
  }

  return h;
}

uint64_t zem_ir_module_hash(const recvec_t *recs) {
  uint64_t h = zem_fnv1a64_init();
  if (!recs || !recs->v) return h;
  for (size_t i = 0; i < recs->n; i++) {
    h = zem_ir_module_hash_update(h, &recs->v[i]);
  }
  return h;
}
