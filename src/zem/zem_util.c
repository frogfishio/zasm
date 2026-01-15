/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_util.h"

#include <inttypes.h>
#include <string.h>

void zem_json_escape(FILE *out, const char *s) {
  if (!out) return;
  if (!s) {
    fputs("\"\"", out);
    return;
  }
  fputc('"', out);
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    unsigned char c = *p;
    if (c == '"' || c == '\\') {
      fputc('\\', out);
      fputc((int)c, out);
    } else if (c == '\n') {
      fputs("\\n", out);
    } else if (c == '\r') {
      fputs("\\r", out);
    } else if (c == '\t') {
      fputs("\\t", out);
    } else if (c < 0x20) {
      fprintf(out, "\\u%04x", (unsigned)c);
    } else {
      fputc((int)c, out);
    }
  }
  fputc('"', out);
}

void zem_u32set_clear(zem_u32set_t *s) {
  if (!s) return;
  s->n = 0;
}

int zem_u32set_add_unique(zem_u32set_t *s, uint32_t v) {
  if (!s) return 0;
  for (size_t i = 0; i < s->n; i++) {
    if (s->v[i] == v) return 1;
  }
  if (s->n >= (sizeof(s->v) / sizeof(s->v[0]))) return 0;
  s->v[s->n++] = v;
  return 1;
}

int zem_u32set_contains(const zem_u32set_t *s, uint32_t v) {
  if (!s) return 0;
  for (size_t i = 0; i < s->n; i++) {
    if (s->v[i] == v) return 1;
  }
  return 0;
}

int zem_u32set_remove(zem_u32set_t *s, uint32_t v) {
  if (!s) return 0;
  for (size_t i = 0; i < s->n; i++) {
    if (s->v[i] == v) {
      s->v[i] = s->v[s->n - 1];
      s->n--;
      return 1;
    }
  }
  return 0;
}

const char *dbg_stop_reason_str(dbg_stop_reason_t r) {
  switch (r) {
    case DBG_STOP_PAUSED:
      return "paused";
    case DBG_STOP_BREAKPOINT:
      return "breakpoint";
    case DBG_STOP_STEP:
      return "step";
    case DBG_STOP_NEXT:
      return "next";
    case DBG_STOP_FINISH:
      return "finish";
    default:
      return "unknown";
  }
}

int zem_watchset_add(zem_watchset_t *ws, uint32_t addr, uint32_t size) {
  if (!ws) return 0;
  if (!(size == 1 || size == 2 || size == 4 || size == 8)) return 0;
  for (size_t i = 0; i < ws->n; i++) {
    if (ws->v[i].addr == addr && ws->v[i].size == size) return 1;
  }
  if (ws->n >= (sizeof(ws->v) / sizeof(ws->v[0]))) return 0;
  ws->v[ws->n].addr = addr;
  ws->v[ws->n].size = size;
  ws->v[ws->n].last = 0;
  ws->v[ws->n].has_last = 0;
  ws->n++;
  return 1;
}

int zem_watchset_remove(zem_watchset_t *ws, uint32_t addr, uint32_t size) {
  if (!ws) return 0;
  for (size_t i = 0; i < ws->n; i++) {
    if (ws->v[i].addr == addr && ws->v[i].size == size) {
      ws->v[i] = ws->v[ws->n - 1];
      ws->n--;
      return 1;
    }
  }
  return 0;
}

int zem_str_ieq(const char *a, const char *b) {
  if (!a || !b) return 0;
  while (*a && *b) {
    char ca = *a++;
    char cb = *b++;
    if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
    if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
    if (ca != cb) return 0;
  }
  return (*a == 0 && *b == 0);
}

int zem_reg_ref(zem_regs_t *r, const char *name, uint64_t **out) {
  if (!r || !name || !out) return 0;
  if (strcmp(name, "HL") == 0) {
    *out = &r->HL;
    return 1;
  }
  if (strcmp(name, "DE") == 0) {
    *out = &r->DE;
    return 1;
  }
  if (strcmp(name, "BC") == 0) {
    *out = &r->BC;
    return 1;
  }
  if (strcmp(name, "IX") == 0) {
    *out = &r->IX;
    return 1;
  }
  if (strcmp(name, "A") == 0) {
    *out = &r->A;
    return 1;
  }
  return 0;
}

int zem_jump_to_label(const zem_symtab_t *labels, const char *label, size_t *pc) {
  if (!labels || !label || !pc) return 0;
  int ignored_is_ptr = 0;
  uint32_t idx = 0;
  if (!zem_symtab_get(labels, label, &ignored_is_ptr, &idx)) {
    return 0;
  }
  *pc = (size_t)idx + 1; // execute after the label record
  return 1;
}

int zem_mem_check_span(const zem_buf_t *mem, uint32_t addr, uint32_t len) {
  if (!mem) return 0;
  if ((size_t)addr > mem->len) return 0;
  if ((size_t)addr + (size_t)len > mem->len) return 0;
  return 1;
}

uint32_t zem_rotl32(uint32_t x, uint32_t r) {
  r &= 31u;
  return (r == 0) ? x : ((x << r) | (x >> (32u - r)));
}

uint32_t zem_rotr32(uint32_t x, uint32_t r) {
  r &= 31u;
  return (r == 0) ? x : ((x >> r) | (x << (32u - r)));
}

uint32_t zem_clz32(uint32_t x) {
  if (x == 0) return 32;
  uint32_t n = 0;
  for (uint32_t bit = 0x80000000u; (x & bit) == 0; bit >>= 1) n++;
  return n;
}

uint32_t zem_ctz32(uint32_t x) {
  if (x == 0) return 32;
  uint32_t n = 0;
  for (uint32_t bit = 1u; (x & bit) == 0; bit <<= 1) n++;
  return n;
}

uint32_t zem_popc32(uint32_t x) {
  uint32_t n = 0;
  while (x) {
    x &= (x - 1u);
    n++;
  }
  return n;
}

uint64_t zem_rotl64(uint64_t x, uint64_t r) {
  r &= 63u;
  return (r == 0) ? x : ((x << r) | (x >> (64u - r)));
}

uint64_t zem_rotr64(uint64_t x, uint64_t r) {
  r &= 63u;
  return (r == 0) ? x : ((x >> r) | (x << (64u - r)));
}

uint64_t zem_clz64(uint64_t x) {
  if (x == 0) return 64;
  uint64_t n = 0;
  for (uint64_t bit = 0x8000000000000000ull; (x & bit) == 0; bit >>= 1) n++;
  return n;
}

uint64_t zem_ctz64(uint64_t x) {
  if (x == 0) return 64;
  uint64_t n = 0;
  for (uint64_t bit = 1ull; (x & bit) == 0; bit <<= 1) n++;
  return n;
}

uint64_t zem_popc64(uint64_t x) {
  uint64_t n = 0;
  while (x) {
    x &= (x - 1ull);
    n++;
  }
  return n;
}
