#include "ir.h"
#include <stdlib.h>
#include <string.h>

static char *dupstr(const char *s) {
  if (!s) return NULL;
  size_t n = strlen(s);
  char *d = (char *)malloc(n + 1);
  if (!d) return NULL;
  memcpy(d, s, n + 1);
  return d;
}

static void push(ir_prog_t *p, ir_entry_t *e) {
  if (!p->head) {
    p->head = p->tail = e;
  } else {
    p->tail->next = e;
    p->tail = e;
  }
}

void ir_init(ir_prog_t *p) {
  p->head = p->tail = NULL;
  p->has_public_lembeh = 0;
}

ir_entry_t *ir_entry_new(ir_entry_kind_t k) {
  ir_entry_t *e = (ir_entry_t *)calloc(1, sizeof(ir_entry_t));
  if (e) {
    e->kind = k;
    e->id = 0;
  }
  return e;
}

static void free_op(ir_op_t *op) {
  if (!op) return;
  free(op->sym);
  free(op->str);
  free(op->mem_base);
  if (op->loc.unit) free(op->loc.unit);
}

void ir_entry_free(ir_entry_t *e) {
  if (!e) return;
  if (e->loc.unit) free(e->loc.unit);
  switch (e->kind) {
    case IR_ENTRY_LABEL:
      free(e->u.label.name);
      break;
    case IR_ENTRY_INSTR:
      free(e->u.instr.mnem);
      if (e->u.instr.ops) {
        for (size_t i = 0; i < e->u.instr.op_count; i++) {
          free_op(&e->u.instr.ops[i]);
        }
        free(e->u.instr.ops);
      }
      break;
    case IR_ENTRY_DIR:
      free(e->u.dir.name);
      if (e->u.dir.args) {
        for (size_t i = 0; i < e->u.dir.arg_count; i++) {
          free_op(&e->u.dir.args[i]);
        }
        free(e->u.dir.args);
      }
      free(e->u.dir.data);
      free(e->u.dir.extern_module);
      free(e->u.dir.extern_field);
      free(e->u.dir.extern_as);
      break;
    default:
      break;
  }
  free(e);
}

int ir_append_entry(ir_prog_t *p, ir_entry_t *e) {
  if (!p || !e) return -1;
  push(p, e);
  return 0;
}

static int copy_op(ir_op_t *dst, const ir_op_t *src) {
  if (!dst || !src) return -1;
  memset(dst, 0, sizeof(*dst));
  dst->kind = src->kind;
  dst->mem_disp = src->mem_disp;
  dst->has_mem_disp = src->has_mem_disp;
  dst->num = src->num;
  dst->unum = src->unum;
  dst->is_unsigned = src->is_unsigned;
  dst->loc = src->loc;
  if (src->loc.unit) {
    dst->loc.unit = dupstr(src->loc.unit);
    if (src->loc.unit && !dst->loc.unit) return -1;
  }
  if (src->sym) {
    dst->sym = dupstr(src->sym);
    if (!dst->sym) return -1;
  }
  if (src->str) {
    dst->str = dupstr(src->str);
    if (!dst->str) return -1;
  }
  if (src->mem_base) {
    dst->mem_base = dupstr(src->mem_base);
    if (!dst->mem_base) return -1;
  }
  return 0;
}

int ir_append_label(ir_prog_t *p, const char *label) {
  ir_entry_t *e = ir_entry_new(IR_ENTRY_LABEL);
  if (!e) return -1;
  e->u.label.name = dupstr(label);
  if (!e->u.label.name) { free(e); return -1; }
  push(p, e);
  return 0;
}

int ir_append_call(ir_prog_t *p, const char *sym) {
  ir_entry_t *e = ir_entry_new(IR_ENTRY_INSTR);
  if (!e) return -1;
  e->u.instr.mnem = dupstr("CALL");
  if (!e->u.instr.mnem) { free(e); return -1; }
  e->u.instr.op_count = 1;
  e->u.instr.ops = (ir_op_t *)calloc(1, sizeof(ir_op_t));
  if (!e->u.instr.ops) { free(e->u.instr.mnem); free(e); return -1; }
  e->u.instr.ops[0].kind = IR_OP_SYM;
  e->u.instr.ops[0].sym = dupstr(sym);
  if (!e->u.instr.ops[0].sym) { ir_entry_free(e); return -1; }
  push(p, e);
  return 0;
}

int ir_append_ret(ir_prog_t *p) {
  ir_entry_t *e = ir_entry_new(IR_ENTRY_INSTR);
  if (!e) return -1;
  e->u.instr.mnem = dupstr("RET");
  if (!e->u.instr.mnem) { free(e); return -1; }
  e->u.instr.ops = NULL;
  e->u.instr.op_count = 0;
  push(p, e);
  return 0;
}

int ir_append_data(ir_prog_t *p, const char *sym, const unsigned char *data, size_t len) {
  ir_entry_t *e = ir_entry_new(IR_ENTRY_DIR);
  if (!e) return -1;
  e->u.dir.dir_kind = IR_DIR_DB;
  if (len) {
    e->u.dir.data = (unsigned char *)malloc(len);
    if (!e->u.dir.data) { free(e); return -1; }
    memcpy(e->u.dir.data, data, len);
    e->u.dir.data_len = len;
  }
  if (sym) {
    e->u.dir.name = dupstr(sym);
    if (!e->u.dir.name) { ir_entry_free(e); return -1; }
  }
  push(p, e);
  return 0;
}

int ir_append_public(ir_prog_t *p, const char *sym) {
  ir_entry_t *e = ir_entry_new(IR_ENTRY_DIR);
  if (!e) return -1;
  e->u.dir.dir_kind = IR_DIR_PUBLIC;
  e->u.dir.name = dupstr(sym);
  if (!e->u.dir.name) { free(e); return -1; }
  if (strcmp(sym, "lembeh_handle") == 0) p->has_public_lembeh = 1;
  push(p, e);
  return 0;
}

int ir_append_instr(ir_prog_t *p, const char *mnem, const ir_op_t *ops, size_t op_count) {
  ir_entry_t *e = ir_entry_new(IR_ENTRY_INSTR);
  if (!e) return -1;
  e->u.instr.mnem = dupstr(mnem);
  if (!e->u.instr.mnem) { ir_entry_free(e); return -1; }
  if (op_count) {
    e->u.instr.ops = (ir_op_t *)calloc(op_count, sizeof(ir_op_t));
    if (!e->u.instr.ops) { ir_entry_free(e); return -1; }
    e->u.instr.op_count = op_count;
    for (size_t i = 0; i < op_count; i++) {
      if (copy_op(&e->u.instr.ops[i], &ops[i]) != 0) { ir_entry_free(e); return -1; }
    }
  }
  push(p, e);
  return 0;
}

void ir_free(ir_prog_t *p) {
  ir_entry_t *e = p->head;
  while (e) {
    ir_entry_t *n = e->next;
    ir_entry_free(e);
    e = n;
  }
  p->head = p->tail = NULL;
}
