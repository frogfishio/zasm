#include "zasm_bin.h"
#include "zasm_verify.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t xorshift32(uint32_t* s) {
  uint32_t x = *s;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  *s = x;
  return x;
}

static void put_u16_le(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
}

static void put_u32_le(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static uint32_t read_env_u32(const char* name, uint32_t def) {
  const char* s = getenv(name);
  if (!s || !*s) return def;
  char* end = NULL;
  unsigned long v = strtoul(s, &end, 10);
  if (!end || end == s) return def;
  if (v > 0xFFFFFFFFul) return def;
  return (uint32_t)v;
}

static size_t build_random_bytes(uint8_t* buf, size_t cap, uint32_t* rng) {
  size_t n = (size_t)(xorshift32(rng) % (uint32_t)(cap + 1));
  for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)xorshift32(rng);
  return n;
}

static size_t align4(size_t x) { return (x + 3u) & ~3u; }

/* Build a mostly-valid v2 container so the parser/verifier get exercised.
 * Also injects small, controlled corruptions to cover error paths.
 */
static size_t build_structured_v2(uint8_t* buf, size_t cap, uint32_t* rng) {
  if (cap < 64u) return build_random_bytes(buf, cap, rng);

  const uint32_t dir_count = 1u + (xorshift32(rng) % 4u);
  const uint32_t dir_off = 40u;
  const size_t dir_bytes = (size_t)dir_count * 20u;

  size_t payload_off = align4(40u + dir_bytes);
  if (payload_off + 16u > cap) return build_random_bytes(buf, cap, rng);

  memset(buf, 0, cap);
  memcpy(buf, "ZASB", 4);
  put_u16_le(buf + 4, 2);
  put_u16_le(buf + 6, 0);
  put_u32_le(buf + 12, dir_off);
  put_u32_le(buf + 16, dir_count);

  /* Decide sections.
   * Always include CODE.
   * Optionally include IMPT.
   */
  int want_impt = ((xorshift32(rng) & 3u) == 0u);
  size_t code_len = (size_t)(4u * (1u + (xorshift32(rng) % 64u))); /* 4..256 */
  if (payload_off + code_len > cap) code_len = 4;

  size_t impt_off = 0;
  if (want_impt) {
    impt_off = payload_off;
    if (impt_off + 8u > cap) {
      want_impt = 0;
    } else {
      payload_off = align4(payload_off + 8u);
    }
  }

  size_t code_off = payload_off;
  if (code_off + code_len > cap) {
    code_off = align4(40u + dir_bytes);
    code_len = 4;
  }
  payload_off = code_off + code_len;

  uint32_t file_len = (uint32_t)align4(payload_off);
  if (file_len < 40u) file_len = 40u;
  if ((size_t)file_len > cap) file_len = (uint32_t)cap;
  put_u32_le(buf + 8, file_len);

  /* Fill directory entries.
   * Entry 0: IMPT (if present) else CODE.
   * Remaining: random tags with small ranges.
   */
  for (uint32_t i = 0; i < dir_count; i++) {
    uint8_t* ent = buf + dir_off + (size_t)i * 20u;
    uint32_t off = 0, len = 0;

    if (i == 0 && want_impt) {
      memcpy(ent + 0, "IMPT", 4);
      off = (uint32_t)impt_off;
      len = 8;
    } else if ((i == 0 && !want_impt) || (i == 1 && want_impt)) {
      memcpy(ent + 0, "CODE", 4);
      off = (uint32_t)code_off;
      len = (uint32_t)code_len;
    } else {
      /* Random tag (not CODE/IMPT most of the time). */
      for (int j = 0; j < 4; j++) ent[j] = (uint8_t)('A' + (xorshift32(rng) % 26u));
      off = (uint32_t)(xorshift32(rng) % file_len);
      len = (uint32_t)(xorshift32(rng) % 16u);
      if ((uint64_t)off + (uint64_t)len > file_len) len = 0;
    }

    put_u32_le(ent + 4, off);
    put_u32_le(ent + 8, len);
    put_u32_le(ent + 12, 0);
    put_u32_le(ent + 16, 0);
  }

  /* Fill IMPT + CODE payloads. */
  if (want_impt) {
    uint32_t pm = xorshift32(rng);
    put_u32_le(buf + impt_off, pm);
    put_u32_le(buf + impt_off + 4, 0);
  }
  for (size_t i = 0; i < code_len; i++) buf[code_off + i] = (uint8_t)xorshift32(rng);

  /* Small corruption injection: flip one bit sometimes. */
  if ((xorshift32(rng) & 7u) == 0u) {
    size_t idx = (size_t)(xorshift32(rng) % (file_len ? file_len : 1u));
    buf[idx] ^= (uint8_t)(1u << (xorshift32(rng) % 8u));
  }

  /* Sometimes provide trailing bytes after file_len to ensure parser tolerates it. */
  size_t in_len = (size_t)file_len;
  if ((xorshift32(rng) & 3u) == 0u) {
    size_t extra = (size_t)(xorshift32(rng) % 17u);
    if (in_len + extra <= cap) in_len += extra;
  }
  return in_len;
}

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;

  const uint32_t iters = read_env_u32("ITERS", 2000);
  const uint32_t seed = read_env_u32("SEED", 1);
  const uint32_t max_len = read_env_u32("MAX_LEN", 4096);

  if (max_len < 64u) {
    fprintf(stderr, "MAX_LEN too small\n");
    return 2;
  }

  uint8_t* buf = (uint8_t*)malloc((size_t)max_len);
  if (!buf) {
    fprintf(stderr, "malloc failed\n");
    return 2;
  }

  zasm_bin_caps_t caps = zasm_bin_default_caps;
  caps.max_file_len = max_len;
  caps.max_dir_count = 32;
  caps.max_code_len = max_len;

  zasm_verify_opts_t vopts = zasm_verify_default_opts;
  vopts.allow_primitives = 1;
  vopts.max_code_len = max_len;
  vopts.max_insn_words = 0;

  uint32_t rng = seed ? seed : 1;
  zasm_bin_v2_t parsed;
  for (uint32_t i = 0; i < iters; i++) {
    size_t in_len;
    if ((xorshift32(&rng) & 1u) == 0u) {
      in_len = build_random_bytes(buf, (size_t)max_len, &rng);
    } else {
      in_len = build_structured_v2(buf, (size_t)max_len, &rng);
    }

    zasm_bin_err_t pe = zasm_bin_parse_v2(buf, in_len, &caps, &parsed);
    if (pe != ZASM_BIN_OK) continue;

    (void)zasm_verify_decode(parsed.code, parsed.code_len, &vopts);
    if (parsed.has_impt) {
      (void)zasm_verify_preflight_impt(parsed.code, parsed.code_len, &vopts, parsed.prim_mask);
    }
  }

  free(buf);
  printf("zasm_bin+verify fuzz ok (%u iters)\n", iters);
  return 0;
}
