#include "ir_hash.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "jsonl.h" // src/zld/jsonl.h via -Isrc/zld

static uint64_t fnv1a64_update(uint64_t h, const void *data, size_t n) {
  const unsigned char *p = (const unsigned char *)data;
  const uint64_t prime = 1099511628211ull;
  for (size_t i = 0; i < n; i++) {
    h ^= (uint64_t)p[i];
    h *= prime;
  }
  return h;
}

static uint64_t fnv1a64_init(void) { return 14695981039346656037ull; }

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
      break;
  }

  return h;
}

static uint64_t ir_module_hash_update(uint64_t h, const record_t *r) {
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

char *lower_ir_module_hash_str_from_jsonl_path(const char *path) {
  if (!path) return NULL;

  FILE *fp = fopen(path, "r");
  if (!fp) return NULL;

  uint64_t h = fnv1a64_init();
  char *line = NULL;
  size_t cap = 0;
  ssize_t n = 0;
  while ((n = getline(&line, &cap, fp)) != -1) {
    (void)n;

    // Tolerate blank/whitespace-only lines (some producers pretty-print with spacing).
    const char *p = line;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == 0) continue;

    record_t r;
    memset(&r, 0, sizeof(r));
    if (parse_jsonl_record(line, &r) != 0) {
      free(line);
      fclose(fp);
      record_free(&r);
      return NULL;
    }
    h = ir_module_hash_update(h, &r);
    record_free(&r);
  }
  free(line);
  fclose(fp);

  char *out = (char *)malloc(32);
  if (!out) return NULL;
  snprintf(out, 32, "fnv1a64:%016" PRIx64, h);
  return out;
}
