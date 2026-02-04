#include "json_ir.h"
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimal embedded jsmn (MIT) for JSON tokenization. */
typedef enum { JSMN_UNDEFINED = 0, JSMN_OBJECT = 1, JSMN_ARRAY = 2, JSMN_STRING = 3, JSMN_PRIMITIVE = 4 } jsmntype_t;

typedef struct {
  jsmntype_t type;
  int start;
  int end;
  int size;
} jsmntok_t;

typedef struct {
  unsigned int pos;
  unsigned int toknext;
  int toksuper;
} jsmn_parser;

static void jsmn_init(jsmn_parser *parser) { parser->pos = 0; parser->toknext = 0; parser->toksuper = -1; }

static jsmntok_t *jsmn_alloc_token(jsmn_parser *parser, jsmntok_t *tokens, size_t num_tokens) {
  if (parser->toknext >= num_tokens) return NULL;
  jsmntok_t *tok = &tokens[parser->toknext++];
  tok->start = tok->end = -1;
  tok->size = 0;
  tok->type = JSMN_UNDEFINED;
  return tok;
}

static int jsmn_parse(jsmn_parser *parser, const char *js, size_t len, jsmntok_t *tokens, size_t num_tokens) {
  int i;
  size_t start = 0;
  for (; parser->pos < len; parser->pos++) {
    char c = js[parser->pos];
    jsmntok_t *tok;
    switch (c) {
      case '{':
      case '[':
        tok = jsmn_alloc_token(parser, tokens, num_tokens);
        if (!tok) return -1;
        tok->type = (c == '{') ? JSMN_OBJECT : JSMN_ARRAY;
        tok->start = (int)parser->pos;
        if (parser->toksuper != -1) {
          tokens[parser->toksuper].size++;
        }
        parser->toksuper = parser->toknext - 1;
        break;
      case '}':
      case ']': {
        jsmntype_t type = (c == '}') ? JSMN_OBJECT : JSMN_ARRAY;
        for (i = parser->toknext - 1; i >= 0; i--) {
          tok = &tokens[i];
          if (tok->start != -1 && tok->end == -1) {
            if (tok->type != type) return -2;
            tok->end = (int)parser->pos + 1;
            parser->toksuper = -1;
            break;
          }
        }
        for (; i >= 0; i--) {
          tok = &tokens[i];
          if (tok->start != -1 && tok->end == -1) {
            parser->toksuper = i;
            break;
          }
        }
        break;
      }
      case '"': {
        parser->pos++;
        size_t start = parser->pos;
        for (; parser->pos < len && js[parser->pos] != '"'; parser->pos++) {
          if (js[parser->pos] == '\\' && parser->pos + 1 < len) parser->pos++;
        }
        tok = jsmn_alloc_token(parser, tokens, num_tokens);
        if (!tok) return -1;
        tok->type = JSMN_STRING;
        tok->start = (int)start - 1;
        tok->end = (int)parser->pos + 1;
        tok->size = 0;
        if (parser->toksuper != -1) tokens[parser->toksuper].size++;
        break;
      }
      case '\t':
      case '\r':
      case '\n':
      case ' ':
        break;
      case ':':
        break;
      case ',':
        break;
      default:
        /* primitive */
        start = parser->pos;
        for (; parser->pos < len; parser->pos++) {
          c = js[parser->pos];
          if (c == '\t' || c == '\r' || c == '\n' || c == ' ' || c == ',' || c == ']' || c == '}') {
            break;
          }
        }
        tok = jsmn_alloc_token(parser, tokens, num_tokens);
        if (!tok) return -1;
        tok->type = JSMN_PRIMITIVE;
        tok->start = (int)start;
        tok->end = (int)parser->pos;
        tok->size = 0;
        parser->pos--;
        if (parser->toksuper != -1) tokens[parser->toksuper].size++;
        break;
    }
  }
  return (int)parser->toknext;
}

static char *dup_cstr(const char *s) {
  if (!s) return NULL;
  size_t n = strlen(s) + 1;
  char *d = (char *)malloc(n);
  if (!d) return NULL;
  memcpy(d, s, n);
  return d;
}

/* Utility helpers for token navigation */
static int tok_streq(const char *js, const jsmntok_t *tok, const char *s) {
  if (!tok || tok->type != JSMN_STRING) return 0;
  size_t tlen = (size_t)(tok->end - tok->start);
  if (tlen < 2) return 0;
  size_t slen = strlen(s);
  return slen == tlen - 2 && strncmp(js + tok->start + 1, s, tlen - 2) == 0;
}

static int decode_json_string(const char *js, const jsmntok_t *tok, char **out_str) {
  if (!tok || tok->type != JSMN_STRING || tok->start < 0 || tok->end <= tok->start) return -1;
  const char *p = js + tok->start + 1; /* skip leading quote */
  const char *end = js + tok->end - 1; /* before trailing quote */
  size_t cap = (size_t)(end - p) + 1;
  char *buf = (char *)malloc(cap);
  if (!buf) return -1;
  size_t out_len = 0;
  while (p < end) {
    char c = *p++;
    if (c == '\\') {
      if (p >= end) { free(buf); return -1; }
      char esc = *p++;
      switch (esc) {
        case '"': buf[out_len++] = '"'; break;
        case '\\': buf[out_len++] = '\\'; break;
        case '/': buf[out_len++] = '/'; break;
        case 'b': buf[out_len++] = '\b'; break;
        case 'f': buf[out_len++] = '\f'; break;
        case 'n': buf[out_len++] = '\n'; break;
        case 'r': buf[out_len++] = '\r'; break;
        case 't': buf[out_len++] = '\t'; break;
        case 'u': {
          if (end - p < 4) { free(buf); return -1; }
          unsigned code = 0;
          for (int i = 0; i < 4; i++) {
            char h = p[i];
            code <<= 4;
            if (h >= '0' && h <= '9') code |= (unsigned)(h - '0');
            else if (h >= 'a' && h <= 'f') code |= (unsigned)(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') code |= (unsigned)(h - 'A' + 10);
            else { free(buf); return -1; }
          }
          p += 4;
          /* Encode as UTF-8 */
          if (code <= 0x7F) {
            buf[out_len++] = (char)code;
          } else if (code <= 0x7FF) {
            buf[out_len++] = (char)(0xC0 | (code >> 6));
            buf[out_len++] = (char)(0x80 | (code & 0x3F));
          } else {
            buf[out_len++] = (char)(0xE0 | (code >> 12));
            buf[out_len++] = (char)(0x80 | ((code >> 6) & 0x3F));
            buf[out_len++] = (char)(0x80 | (code & 0x3F));
          }
          break;
        }
        default:
          free(buf);
          return -1;
      }
    } else {
      buf[out_len++] = c;
    }
  }
  buf[out_len] = 0;
  *out_str = buf;
  return 0;
}

static char *tok_strdup_json_string_fast(const char *js, const jsmntok_t *tok) {
  if (!tok || tok->type != JSMN_STRING || tok->start < 0 || tok->end <= tok->start) return NULL;
  const char *p = js + tok->start + 1;
  const char *end = js + tok->end - 1;
  size_t len = (size_t)(end - p);
  if (len == 0) {
    char *s = (char *)malloc(1);
    if (s) s[0] = 0;
    return s;
  }
  /* Fast path: no escapes */
  if (memchr(p, '\\', len) == NULL) {
    char *s = (char *)malloc(len + 1);
    if (!s) return NULL;
    memcpy(s, p, len);
    s[len] = 0;
    return s;
  }
  /* Slow path: decode escapes */
  char *s = NULL;
  if (decode_json_string(js, tok, &s) != 0) return NULL;
  return s;
}

static char *tok_strdup(const char *js, const jsmntok_t *tok) {
  if (!tok) return NULL;
  if (tok->type == JSMN_STRING) {
    return tok_strdup_json_string_fast(js, tok);
  }
  if (tok->start < 0 || tok->end < tok->start) return NULL;
  size_t len = (size_t)(tok->end - tok->start);
  char *s = (char *)malloc(len + 1);
  if (!s) return NULL;
  memcpy(s, js + tok->start, len);
  s[len] = 0;
  return s;
}

static void print_line_err(size_t line_no, const char *line, const char *msg) {
  char snippet[96];
  size_t i = 0, j = 0;
  while (line && line[i] && line[i] != '\n' && j < sizeof(snippet)-1) {
    if (!iscntrl((unsigned char)line[i])) snippet[j++] = line[i];
    i++;
  }
  snippet[j] = 0;
  fprintf(stderr, "[json-ir][line %zu] %s%s%s\n", line_no, msg, snippet[0] ? " | " : "", snippet);
}

static long long tok_to_int(const char *js, const jsmntok_t *tok, int *ok) {
  if (!tok || tok->type != JSMN_PRIMITIVE) { if (ok) *ok = 0; return 0; }
  errno = 0;
  long long v = strtoll(js + tok->start, NULL, 10);
  if (errno != 0) { if (ok) *ok = 0; return 0; }
  if (ok) *ok = 1;
  return v;
}

static int tok_skip(const jsmntok_t *toks, int idx) {
  int j = idx + 1;
  switch (toks[idx].type) {
    case JSMN_OBJECT:
      for (int k = 0; k < toks[idx].size; k++) {
        j = tok_skip(toks, j);
      }
      break;
    case JSMN_ARRAY:
      for (int k = 0; k < toks[idx].size; k++) {
        j = tok_skip(toks, j);
      }
      break;
    default:
      break;
  }
  return j;
}

static int parse_loc(const char *js, const jsmntok_t *toks, int loc_idx, ir_loc_t *out) {
  if (!out) return -1;
  memset(out, 0, sizeof(*out));
  if (toks[loc_idx].type != JSMN_OBJECT) return -1;
  int pairs = toks[loc_idx].size / 2;
  int idx = loc_idx + 1;
  out->has_loc = 1;
  for (int i = 0; i < pairs; i++) {
    jsmntok_t *k = (jsmntok_t *)&toks[idx];
    int v_idx = idx + 1;
    if (tok_streq(js, k, "line")) {
      int ok = 0;
      long long v = tok_to_int(js, &toks[v_idx], &ok);
      if (!ok || v < 1) return -1;
      out->line = (unsigned)v;
    } else if (tok_streq(js, k, "col")) {
      int ok = 0;
      long long v = tok_to_int(js, &toks[v_idx], &ok);
      if (!ok || v < 1) return -1;
      out->col = (unsigned)v;
    } else if (tok_streq(js, k, "unit")) {
      if (toks[v_idx].type != JSMN_STRING) return -1;
      out->unit = tok_strdup(js, &toks[v_idx]);
      if (!out->unit) return -1;
    } else {
      return -1;
    }
    idx = tok_skip(toks, v_idx);
  }
  return 0;
}

static int parse_operand(const char *js, const jsmntok_t *toks, int op_idx, ir_op_t *out) {
  if (!out || toks[op_idx].type != JSMN_OBJECT) return -1;
  memset(out, 0, sizeof(*out));

  int t_idx = -1;
  int v_idx = -1;
  int base_idx = -1;
  int disp_idx = -1;
  int loc_idx = -1;

  /* Collect keys in one pass and reject unknown keys */
  int pairs = toks[op_idx].size / 2;
  int idx = op_idx + 1;
  for (int i = 0; i < pairs; i++) {
    if (tok_streq(js, &toks[idx], "t")) {
      if (t_idx < 0) t_idx = idx + 1;
    } else if (tok_streq(js, &toks[idx], "v")) {
      if (v_idx < 0) v_idx = idx + 1;
    } else if (tok_streq(js, &toks[idx], "base")) {
      if (base_idx < 0) base_idx = idx + 1;
    } else if (tok_streq(js, &toks[idx], "disp")) {
      if (disp_idx < 0) disp_idx = idx + 1;
    } else if (tok_streq(js, &toks[idx], "loc")) {
      if (loc_idx < 0) loc_idx = idx + 1;
    } else if (tok_streq(js, &toks[idx], "size")) {
      /* accepted but ignored */
    } else {
      return -1;
    }
    idx = tok_skip(toks, idx + 1);
  }

  if (t_idx < 0 || toks[t_idx].type != JSMN_STRING) return -1;

  if (tok_streq(js, &toks[t_idx], "sym")) {
    if (v_idx < 0 || toks[v_idx].type != JSMN_STRING) return -1;
    out->kind = IR_OP_SYM;
    out->sym = tok_strdup(js, &toks[v_idx]);
    if (!out->sym) return -1;
  } else if (tok_streq(js, &toks[t_idx], "reg")) {
    if (v_idx < 0 || toks[v_idx].type != JSMN_STRING) return -1;
    // Lowerer represents regs/labels as symbols internally; codegen maps known names.
    out->kind = IR_OP_SYM;
    out->sym = tok_strdup(js, &toks[v_idx]);
    if (!out->sym) return -1;
  } else if (tok_streq(js, &toks[t_idx], "lbl")) {
    if (v_idx < 0 || toks[v_idx].type != JSMN_STRING) return -1;
    out->kind = IR_OP_SYM;
    out->sym = tok_strdup(js, &toks[v_idx]);
    if (!out->sym) return -1;
  } else if (tok_streq(js, &toks[t_idx], "num")) {
    if (v_idx < 0) return -1;
    int ok = 0;
    long long v = tok_to_int(js, &toks[v_idx], &ok);
    if (!ok) return -1;
    out->kind = IR_OP_NUM;
    out->num = v;
    out->unum = (unsigned long long)v;
    out->is_unsigned = 0;
  } else if (tok_streq(js, &toks[t_idx], "str")) {
    if (v_idx < 0 || toks[v_idx].type != JSMN_STRING) return -1;
    out->kind = IR_OP_STR;
    out->str = tok_strdup(js, &toks[v_idx]);
    if (!out->str) return -1;
  } else if (tok_streq(js, &toks[t_idx], "mem")) {
    out->kind = IR_OP_MEM;
    if (base_idx < 0) return -1;
    if (toks[base_idx].type == JSMN_STRING) {
      // zasm-v1.0 encoding: base is a bare string.
      out->mem_base = tok_strdup(js, &toks[base_idx]);
    } else if (toks[base_idx].type == JSMN_OBJECT) {
      // zasm-v1.1 encoding: base is a nested {t:"reg"|"sym", v:"..."} object.
      int bt_idx = -1;
      int bv_idx = -1;
      int bpairs = toks[base_idx].size / 2;
      int bscan = base_idx + 1;
      for (int bi = 0; bi < bpairs; bi++) {
        if (tok_streq(js, &toks[bscan], "t")) {
          if (bt_idx < 0) bt_idx = bscan + 1;
        } else if (tok_streq(js, &toks[bscan], "v")) {
          if (bv_idx < 0) bv_idx = bscan + 1;
        } else {
          return -1;
        }
        bscan = tok_skip(toks, bscan + 1);
      }
      if (bt_idx < 0 || bv_idx < 0 || toks[bt_idx].type != JSMN_STRING || toks[bv_idx].type != JSMN_STRING) return -1;
      if (!tok_streq(js, &toks[bt_idx], "reg") && !tok_streq(js, &toks[bt_idx], "sym")) return -1;
      out->mem_base = tok_strdup(js, &toks[bv_idx]);
    } else {
      return -1;
    }
    if (!out->mem_base) return -1;

    if (disp_idx >= 0) {
      int ok = 0;
      long long v = tok_to_int(js, &toks[disp_idx], &ok);
      if (!ok) return -1;
      out->has_mem_disp = 1;
      out->mem_disp = v;
    }
  } else {
    return -1;
  }

  if (loc_idx >= 0) {
    if (parse_loc(js, toks, loc_idx, &out->loc) != 0) return -1;
  }
  return 0;
}

static int parse_operands_array(const char *js, const jsmntok_t *toks, int arr_idx, ir_op_t **ops_out, size_t *count_out) {
  if (toks[arr_idx].type != JSMN_ARRAY) return -1;
  size_t cnt = (size_t)toks[arr_idx].size;
  ir_op_t *ops = NULL;
  if (cnt) {
    ops = (ir_op_t *)calloc(cnt, sizeof(ir_op_t));
    if (!ops) return -1;
  }
  int idx = arr_idx + 1;
  for (size_t i = 0; i < cnt; i++) {
    if (parse_operand(js, toks, idx, &ops[i]) != 0) {
      for (size_t k = 0; k < cnt; k++) {
        free(ops[k].sym);
        free(ops[k].str);
        free(ops[k].mem_base);
        if (ops[k].loc.unit) free(ops[k].loc.unit);
      }
      free(ops);
      return -1;
    }
    idx = tok_skip(toks, idx);
  }
  *ops_out = ops;
  *count_out = cnt;
  return 0;
}

static int append_bytes_from_args(const ir_op_t *args, size_t count, unsigned char **out, size_t *out_len) {
  size_t cap = 0;
  for (size_t i = 0; i < count; i++) {
    if (args[i].kind == IR_OP_STR && args[i].str) {
      cap += strlen(args[i].str);
    } else if (args[i].kind == IR_OP_NUM) {
      cap += 1;
    } else {
      return -1; /* Unsupported in data context */
    }
  }
  unsigned char *buf = NULL;
  if (cap) {
    buf = (unsigned char *)malloc(cap);
    if (!buf) return -1;
  }
  size_t pos = 0;
  for (size_t i = 0; i < count; i++) {
    if (args[i].kind == IR_OP_STR) {
      size_t n = strlen(args[i].str);
      memcpy(buf + pos, args[i].str, n);
      pos += n;
    } else if (args[i].kind == IR_OP_NUM) {
      buf[pos++] = (unsigned char)(args[i].num & 0xFF);
    }
  }
  *out = buf;
  *out_len = cap;
  return 0;
}

static int append_words_from_args(const ir_op_t *args, size_t count, unsigned char **out, size_t *out_len) {
  unsigned char *buf = NULL;
  if (count) {
    buf = (unsigned char *)malloc(count * 2);
    if (!buf) return -1;
  }
  for (size_t i = 0; i < count; i++) {
    if (args[i].kind != IR_OP_NUM) { free(buf); return -1; }
    unsigned long long v = args[i].unum;
    buf[i * 2] = (unsigned char)(v & 0xFF);
    buf[i * 2 + 1] = (unsigned char)((v >> 8) & 0xFF);
  }
  *out = buf;
  *out_len = count * 2;
  return 0;
}

int json_ir_read(FILE* fp, ir_prog_t* prog) {
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  size_t line_no = 0;
  size_t rec_idx = 0;
  int rc = 0;

  /* Reuse token buffer across lines to avoid malloc/free churn. */
  jsmntok_t *toks = NULL;
  int tok_cap = 0;

  while ((n = getline(&line, &cap, fp)) != -1) {
    line_no++;
    if (n <= 0) continue;
    int only_ws = 1;
    for (ssize_t i = 0; i < n; i++) {
      if (!isspace((unsigned char)line[i])) { only_ws = 0; break; }
    }
    if (only_ws) continue;

    /* JSONL record index (0-based) used by zem for PC/profiling. */
    const size_t jsonl_pc = rec_idx++;
    /* Tokenize */
    if (tok_cap == 0) tok_cap = 256;
    int tok_count = 0;
    for (;;) {
      toks = (jsmntok_t *)realloc(toks, sizeof(jsmntok_t) * tok_cap);
      if (!toks) { rc = -1; goto fail_line; }
      jsmn_parser p;
      jsmn_init(&p);
      tok_count = jsmn_parse(&p, line, (size_t)n, toks, (size_t)tok_cap);
      if (tok_count >= 0) break;
      if (tok_count == -1) { tok_cap *= 2; continue; }
      print_line_err(line_no, line, "invalid JSON");
      rc = -1;
      goto fail_line;
    }
    if (tok_count < 1 || toks[0].type != JSMN_OBJECT) {
      print_line_err(line_no, line, "expected object record");
      rc = -1;
      goto fail_line;
    }

    /* Collect top-level keys in one pass */
    int ir_idx = -1;
    int k_idx = -1;
    int id_idx = -1;
    int sr_idx = -1;
    int name_idx = -1;
    int loc_idx = -1;
    int m_idx = -1;
    int ops_idx = -1;
    int d_idx = -1;
    int args_idx = -1;
    int has_unknown_key = 0;

    enum {
      F_IR = 1 << 0,
      F_K = 1 << 1,
      F_ID = 1 << 2,
      F_SRC_REF = 1 << 3,
      F_NAME = 1 << 4,
      F_LOC = 1 << 5,
      F_M = 1 << 6,
      F_OPS = 1 << 7,
      F_D = 1 << 8,
      F_ARGS = 1 << 9,
    };
    unsigned present = 0;

    int top_pairs = toks[0].size / 2;
    int top_idx = 1;
    for (int i = 0; i < top_pairs; i++) {
      if (tok_streq(line, &toks[top_idx], "ir")) {
        present |= F_IR;
        if (ir_idx < 0) ir_idx = top_idx + 1;
      } else if (tok_streq(line, &toks[top_idx], "k")) {
        present |= F_K;
        if (k_idx < 0) k_idx = top_idx + 1;
      } else if (tok_streq(line, &toks[top_idx], "id")) {
        present |= F_ID;
        if (id_idx < 0) id_idx = top_idx + 1;
      } else if (tok_streq(line, &toks[top_idx], "src_ref")) {
        present |= F_SRC_REF;
        if (sr_idx < 0) sr_idx = top_idx + 1;
      } else if (tok_streq(line, &toks[top_idx], "name")) {
        present |= F_NAME;
        if (name_idx < 0) name_idx = top_idx + 1;
      } else if (tok_streq(line, &toks[top_idx], "loc")) {
        present |= F_LOC;
        if (loc_idx < 0) loc_idx = top_idx + 1;
      } else if (tok_streq(line, &toks[top_idx], "m")) {
        present |= F_M;
        if (m_idx < 0) m_idx = top_idx + 1;
      } else if (tok_streq(line, &toks[top_idx], "ops")) {
        present |= F_OPS;
        if (ops_idx < 0) ops_idx = top_idx + 1;
      } else if (tok_streq(line, &toks[top_idx], "d")) {
        present |= F_D;
        if (d_idx < 0) d_idx = top_idx + 1;
      } else if (tok_streq(line, &toks[top_idx], "args")) {
        present |= F_ARGS;
        if (args_idx < 0) args_idx = top_idx + 1;
      } else {
        has_unknown_key = 1;
      }
      top_idx = tok_skip(toks, top_idx + 1);
    }

    /* ir version */
    if (ir_idx < 0 || !(tok_streq(line, &toks[ir_idx], "zasm-v1.0") || tok_streq(line, &toks[ir_idx], "zasm-v1.1"))) {
      print_line_err(line_no, line, "missing or invalid ir version");
      rc = -1;
      goto fail_line;
    }
    if (k_idx < 0 || toks[k_idx].type != JSMN_STRING) {
      print_line_err(line_no, line, "missing k field");
      rc = -1;
      goto fail_line;
    }

    ir_entry_t *entry = NULL;
    /* Optional record id */
    size_t rec_id = 0;
    size_t src_ref = 0;
    if (id_idx >= 0 && toks[id_idx].type == JSMN_PRIMITIVE) {
      int ok = 0;
      long long v = tok_to_int(line, &toks[id_idx], &ok);
      if (ok && v >= 0) rec_id = (size_t)v;
    }
    if (sr_idx >= 0 && toks[sr_idx].type == JSMN_PRIMITIVE) {
      int ok = 0;
      long long v = tok_to_int(line, &toks[sr_idx], &ok);
      if (ok && v >= 0) src_ref = (size_t)v;
    }

    // v1.1 metadata/source/diagnostic records are not needed for codegen; ignore them.
    if (tok_streq(line, &toks[k_idx], "meta") ||
        tok_streq(line, &toks[k_idx], "src") ||
        tok_streq(line, &toks[k_idx], "diag")) {
      continue;
    }

    if (has_unknown_key) {
      print_line_err(line_no, line, "unknown field");
      rc = -1;
      goto fail_line;
    }

    if (tok_streq(line, &toks[k_idx], "label")) {
      /* Allowed: ir,k,name,loc,id */
      unsigned allowed = F_IR | F_K | F_NAME | F_LOC | F_ID;
      if ((present & ~allowed) != 0) {
        print_line_err(line_no, line, "unknown field");
        rc = -1;
        goto fail_line;
      }
      if (name_idx < 0 || toks[name_idx].type != JSMN_STRING) {
        print_line_err(line_no, line, "label missing name");
        rc = -1;
        goto fail_line;
      }
      entry = ir_entry_new(IR_ENTRY_LABEL);
      if (!entry) { rc = -1; goto fail_line; }
      entry->pc = jsonl_pc;
      entry->id = rec_id;
      entry->u.label.name = tok_strdup(line, &toks[name_idx]);
      if (!entry->u.label.name) { ir_entry_free(entry); rc = -1; goto fail_line; }
      if (loc_idx >= 0) {
        if (parse_loc(line, toks, loc_idx, &entry->loc) != 0) {
          print_line_err(line_no, line, "invalid loc");
          ir_entry_free(entry); rc = -1; goto fail_line;
        }
      }
    } else if (tok_streq(line, &toks[k_idx], "instr")) {
      /* Allowed: ir,k,m,ops,loc,id,src_ref */
      unsigned allowed = F_IR | F_K | F_M | F_OPS | F_LOC | F_ID | F_SRC_REF;
      if ((present & ~allowed) != 0) {
        print_line_err(line_no, line, "unknown field");
        rc = -1;
        goto fail_line;
      }
      if (m_idx < 0 || toks[m_idx].type != JSMN_STRING || ops_idx < 0) {
        print_line_err(line_no, line, "instr missing m/ops");
        rc = -1; goto fail_line;
      }
      entry = ir_entry_new(IR_ENTRY_INSTR);
      if (!entry) { rc = -1; goto fail_line; }
      entry->pc = jsonl_pc;
      entry->id = rec_id;
      entry->u.instr.src_ref = src_ref;
      entry->u.instr.mnem = tok_strdup(line, &toks[m_idx]);
      if (!entry->u.instr.mnem) { ir_entry_free(entry); rc = -1; goto fail_line; }
      if (parse_operands_array(line, toks, ops_idx, &entry->u.instr.ops, &entry->u.instr.op_count) != 0) {
        print_line_err(line_no, line, "invalid instr operands");
        ir_entry_free(entry); rc = -1; goto fail_line;
      }
      if (loc_idx >= 0) {
        if (parse_loc(line, toks, loc_idx, &entry->loc) != 0) {
          print_line_err(line_no, line, "invalid loc");
          ir_entry_free(entry); rc = -1; goto fail_line;
        }
      }
    } else if (tok_streq(line, &toks[k_idx], "dir")) {
      /* Allowed: ir,k,d,args,name,loc,id,src_ref */
      unsigned allowed = F_IR | F_K | F_D | F_ARGS | F_NAME | F_LOC | F_ID | F_SRC_REF;
      if ((present & ~allowed) != 0) {
        print_line_err(line_no, line, "unknown field");
        rc = -1;
        goto fail_line;
      }
      if (d_idx < 0 || toks[d_idx].type != JSMN_STRING || args_idx < 0 || toks[args_idx].type != JSMN_ARRAY) {
        print_line_err(line_no, line, "dir missing d/args");
        rc = -1; goto fail_line;
      }
      entry = ir_entry_new(IR_ENTRY_DIR);
      if (!entry) { rc = -1; goto fail_line; }
      entry->pc = jsonl_pc;
      entry->id = rec_id;
      entry->u.dir.src_ref = src_ref;
      if      (tok_streq(line, &toks[d_idx], "PUBLIC")) entry->u.dir.dir_kind = IR_DIR_PUBLIC;
      else if (tok_streq(line, &toks[d_idx], "EXTERN")) entry->u.dir.dir_kind = IR_DIR_EXTERN;
      else if (tok_streq(line, &toks[d_idx], "DB")) entry->u.dir.dir_kind = IR_DIR_DB;
      else if (tok_streq(line, &toks[d_idx], "DW")) entry->u.dir.dir_kind = IR_DIR_DW;
      else if (tok_streq(line, &toks[d_idx], "RESB")) entry->u.dir.dir_kind = IR_DIR_RESB;
      else if (tok_streq(line, &toks[d_idx], "STR")) entry->u.dir.dir_kind = IR_DIR_STR;
      else if (tok_streq(line, &toks[d_idx], "EQU")) entry->u.dir.dir_kind = IR_DIR_EQU;
      else {
        print_line_err(line_no, line, "unknown directive");
        ir_entry_free(entry); rc = -1; goto fail_line;
      }
      if (parse_operands_array(line, toks, args_idx, &entry->u.dir.args, &entry->u.dir.arg_count) != 0) {
        print_line_err(line_no, line, "invalid directive args");
        ir_entry_free(entry); rc = -1; goto fail_line;
      }
      if (name_idx >= 0) {
        if (toks[name_idx].type != JSMN_STRING) { print_line_err(line_no, line, "dir name must be string"); ir_entry_free(entry); rc = -1; goto fail_line; }
        entry->u.dir.name = tok_strdup(line, &toks[name_idx]);
        if (!entry->u.dir.name) { ir_entry_free(entry); rc = -1; goto fail_line; }
      }
      if (loc_idx >= 0) {
        if (parse_loc(line, toks, loc_idx, &entry->loc) != 0) {
          print_line_err(line_no, line, "invalid loc");
          ir_entry_free(entry); rc = -1; goto fail_line;
        }
      }
      /* Expand data / metadata based on directive kind */
      switch (entry->u.dir.dir_kind) {
        case IR_DIR_PUBLIC:
          if (entry->u.dir.arg_count < 1 || entry->u.dir.args[0].kind != IR_OP_SYM || !entry->u.dir.args[0].sym) {
            print_line_err(line_no, line, "PUBLIC requires sym arg");
            ir_entry_free(entry); rc = -1; goto fail_line;
          }
          if (entry->u.dir.name == NULL) {
            entry->u.dir.name = dup_cstr(entry->u.dir.args[0].sym);
            if (!entry->u.dir.name) { ir_entry_free(entry); rc = -1; goto fail_line; }
          }
          if (strcmp(entry->u.dir.name, "main") == 0) prog->has_public_main = 1;
          break;
        case IR_DIR_EXTERN:
          if (entry->u.dir.arg_count < 2 || entry->u.dir.args[0].kind != IR_OP_STR || entry->u.dir.args[1].kind != IR_OP_STR) {
            print_line_err(line_no, line, "EXTERN requires module/field strings");
            ir_entry_free(entry); rc = -1; goto fail_line;
          }
          entry->u.dir.extern_module = dup_cstr(entry->u.dir.args[0].str);
          entry->u.dir.extern_field = dup_cstr(entry->u.dir.args[1].str);
          if (!entry->u.dir.extern_module || !entry->u.dir.extern_field) {
            ir_entry_free(entry); rc = -1; goto fail_line;
          }
          if (entry->u.dir.arg_count >= 3) {
            if (entry->u.dir.args[2].kind == IR_OP_STR) {
              entry->u.dir.extern_as = dup_cstr(entry->u.dir.args[2].str);
            } else if (entry->u.dir.args[2].kind == IR_OP_SYM) {
              entry->u.dir.extern_as = dup_cstr(entry->u.dir.args[2].sym);
            }
            if (entry->u.dir.extern_as == NULL) {
              ir_entry_free(entry); rc = -1; goto fail_line;
            }
          }
          break;
        case IR_DIR_DB:
          if (append_bytes_from_args(entry->u.dir.args, entry->u.dir.arg_count, &entry->u.dir.data, &entry->u.dir.data_len) != 0) {
            print_line_err(line_no, line, "DB args invalid");
            ir_entry_free(entry); rc = -1; goto fail_line;
          }
          break;
        case IR_DIR_DW:
          if (append_words_from_args(entry->u.dir.args, entry->u.dir.arg_count, &entry->u.dir.data, &entry->u.dir.data_len) != 0) {
            print_line_err(line_no, line, "DW args invalid");
            ir_entry_free(entry); rc = -1; goto fail_line;
          }
          break;
        case IR_DIR_RESB:
          if (entry->u.dir.arg_count != 1 || entry->u.dir.args[0].kind != IR_OP_NUM || entry->u.dir.args[0].num < 0) {
            print_line_err(line_no, line, "RESB requires one non-negative num");
            ir_entry_free(entry); rc = -1; goto fail_line;
          }
          entry->u.dir.reserve_len = (size_t)entry->u.dir.args[0].num;
          break;
        case IR_DIR_STR:
          if (append_bytes_from_args(entry->u.dir.args, entry->u.dir.arg_count, &entry->u.dir.data, &entry->u.dir.data_len) != 0) {
            print_line_err(line_no, line, "STR args invalid");
            ir_entry_free(entry); rc = -1; goto fail_line;
          }
          entry->u.dir.has_equ_value = 1;
          entry->u.dir.equ_value = (long long)entry->u.dir.data_len;
          break;
        case IR_DIR_EQU:
          if (entry->u.dir.arg_count != 1 || entry->u.dir.args[0].kind != IR_OP_NUM) {
            print_line_err(line_no, line, "EQU requires one num");
            ir_entry_free(entry); rc = -1; goto fail_line;
          }
          entry->u.dir.has_equ_value = 1;
          entry->u.dir.equ_value = entry->u.dir.args[0].num;
          break;
      }
    } else {
      print_line_err(line_no, line, "unknown k kind");
      rc = -1; goto fail_line;
    }

    if (entry) {
      ir_append_entry(prog, entry);
    }
    continue;

fail_line:
    /* On failure, loop will exit after cleanup below. */
    rc = -1;
    break;
  }
  if (line) free(line);
  if (toks) free(toks);
  return rc;
}
