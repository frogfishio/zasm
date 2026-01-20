#include "codegen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Lightweight utilities */
static char *dupstr(const char *s) {
  if (!s) return NULL;
  size_t n = strlen(s);
  char *d = (char *)malloc(n + 1);
  if (!d) return NULL;
  memcpy(d, s, n + 1);
  return d;
}

static void symtab_free(symtab_entry *s) {
  while (s) {
    symtab_entry *n = s->next;
    free(s->name);
    free(s);
    s = n;
  }
}

static symtab_entry *symtab_add(symtab_entry **root, const char *name, size_t off) {
  if (!root || !name) return NULL;
  for (symtab_entry *s = *root; s; s = s->next) {
    if (s->name && strcmp(s->name, name) == 0) {
      if (off != (size_t)-1) s->off = off;
      return s;
    }
  }
  symtab_entry *e = (symtab_entry *)calloc(1, sizeof(symtab_entry));
  if (!e) return NULL;
  e->name = dupstr(name);
  if (!e->name) { free(e); return NULL; }
  e->off = off;
  e->next = *root;
  *root = e;
  return e;
}

static void symtab_update(symtab_entry *root, const char *name, size_t off) {
  for (symtab_entry *s = root; s; s = s->next) {
    if (s->name && strcmp(s->name, name) == 0) {
      s->off = off;
      return;
    }
  }
}

static int symtab_has(symtab_entry *root, const char *name) {
  for (symtab_entry *s = root; s; s = s->next) {
    if (s->name && strcmp(s->name, name) == 0) return 1;
  }
  return 0;
}

typedef struct {
  char *name;
  size_t line;
} seen_sym_t;

static int seen_has(seen_sym_t *arr, size_t n, const char *name) {
  if (!name) return 0;
  for (size_t i = 0; i < n; i++) {
    if (arr[i].name && strcmp(arr[i].name, name) == 0) return 1;
  }
  return 0;
}

static void seen_add(seen_sym_t **arr, size_t *n, size_t *cap, const char *name, size_t line) {
  if (!name) return;
  if (seen_has(*arr, *n, name)) return;
  if (*n >= *cap) {
    *cap = *cap ? (*cap * 2) : 16;
    *arr = (seen_sym_t *)realloc(*arr, (*cap) * sizeof(seen_sym_t));
  }
  (*arr)[(*n)++] = (seen_sym_t){dupstr(name), line};
}

static void seen_free(seen_sym_t *arr, size_t n) {
  if (!arr) return;
  for (size_t i = 0; i < n; i++) free(arr[i].name);
  free(arr);
}

static void relocs_free(cg_reloc_t *r) {
  while (r) {
    cg_reloc_t *n = r->next;
    free(r->sym);
    free(r);
    r = n;
  }
}

static void pcmap_free(cg_pc_map_t *p) {
  while (p) {
    cg_pc_map_t *n = p->next;
    free(p);
    p = n;
  }
}

void cg_free(cg_blob_t *out) {
  if (!out) return;
  free(out->code);
  free(out->data);
  symtab_free(out->syms);
  relocs_free(out->relocs);
  pcmap_free(out->pc_map);
  memset(out, 0, sizeof(*out));
}

static void add_reloc(cg_blob_t *out, uint32_t instr_off, uint32_t type, const char *sym, uint32_t line, size_t ir_id) {
  if (!out || !sym) return;
  cg_reloc_t *r = (cg_reloc_t *)calloc(1, sizeof(cg_reloc_t));
  if (!r) return;
  r->instr_off = instr_off;
  r->type = type;
  r->sym = dupstr(sym);
  r->line = line;
  r->ir_id = ir_id;
  r->next = out->relocs;
  out->relocs = r;
  out->reloc_count++;
}

static void add_pc_map(cg_blob_t *out, uint32_t off, size_t ir_id, uint32_t line) {
  if (!out) return;
  cg_pc_map_t *p = (cg_pc_map_t *)calloc(1, sizeof(cg_pc_map_t));
  if (!p) return;
  p->off = off;
  p->ir_id = ir_id;
  p->line = line;
  p->next = out->pc_map;
  out->pc_map = p;
  out->pc_map_count++;
}

/* ARM64 encodings */
static uint32_t enc_nop(void) { return 0xD503201Fu; }
static uint32_t enc_ret(void) { return 0xD65F03C0u; }
static uint32_t enc_bl_placeholder(void) { return 0x94000000u; }
static uint32_t enc_b_placeholder(void) { return 0x14000000u; }
static uint32_t enc_stp_fp_lr(void) { return 0xA9BF7BFDu; }
static uint32_t enc_ldp_fp_lr(void) { return 0xA8C17BFDu; }
static uint32_t enc_mov_fp_sp(void) { return 0x910003FDu; }
static uint32_t enc_movz(uint8_t rd, uint16_t imm16, uint8_t hw) { return 0xD2800000u|((uint32_t)imm16<<5)|((uint32_t)hw<<21)|rd; }
static uint32_t enc_movk(uint8_t rd, uint16_t imm16, uint8_t hw) { return 0xF2800000u|((uint32_t)imm16<<5)|((uint32_t)hw<<21)|rd; }
static uint32_t enc_add_reg(int is64, uint8_t rd, uint8_t rn, uint8_t rm) { return (is64?0x8B000000u:0x0B000000u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd; }
static uint32_t enc_add_imm(int is64, uint8_t rd, uint8_t rn, uint16_t imm12) { return (is64?0x91000000u:0x11000000u)|((uint32_t)imm12<<10)|((uint32_t)rn<<5)|rd; }
static uint32_t enc_sub_reg(int is64, uint8_t rd, uint8_t rn, uint8_t rm) { return (is64?0xCB000000u:0x4B000000u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd; }
static uint32_t enc_sub_imm(int is64, uint8_t rd, uint8_t rn, uint16_t imm12) { return (is64?0xD1000000u:0x51000000u)|((uint32_t)imm12<<10)|((uint32_t)rn<<5)|rd; }
static uint32_t enc_subs_imm(int is64, uint8_t rd, uint8_t rn, uint16_t imm12) { return (is64?0xF1000000u:0x71000000u)|((uint32_t)imm12<<10)|((uint32_t)rn<<5)|rd; }
static uint32_t enc_ldr_x_imm(uint8_t rt, uint8_t rn, uint16_t imm12_scaled) { return 0xF9400000u|((uint32_t)imm12_scaled<<10)|((uint32_t)rn<<5)|rt; }
static uint32_t enc_str_x_imm(uint8_t rt, uint8_t rn, uint16_t imm12_scaled) { return 0xF9000000u|((uint32_t)imm12_scaled<<10)|((uint32_t)rn<<5)|rt; }
static uint32_t enc_cmp_reg(int is64,uint8_t rn,uint8_t rm){return (is64?0xEB00001Fu:0x6B00001Fu)|((uint32_t)rm<<16)|((uint32_t)rn<<5);}
static uint32_t enc_cset(uint8_t rd,uint8_t cond){return 0x1A9F07E0u|((uint32_t)(cond^1u)<<12)|rd;}
static uint32_t enc_b_cond(uint8_t cond,int32_t imm19){return 0x54000000u|(((uint32_t)imm19&0x7FFFFu)<<5)|(cond&0xFu);}
static uint32_t enc_and_reg(int is64,uint8_t rd,uint8_t rn,uint8_t rm){return (is64?0x8A000000u:0x0A000000u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_orr_reg(int is64,uint8_t rd,uint8_t rn,uint8_t rm){return (is64?0xAA000000u:0x2A000000u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_eor_reg(int is64,uint8_t rd,uint8_t rn,uint8_t rm){return (is64?0xCA000000u:0x4A000000u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_ldr_sb_x(uint8_t rt,uint8_t rn,uint16_t imm12){return 0x38800000u|((uint32_t)imm12<<10)|((uint32_t)rn<<5)|rt;}
static uint32_t enc_ldr_sh_x(uint8_t rt,uint8_t rn,uint16_t imm12){return 0x78800000u|((uint32_t)imm12<<10)|((uint32_t)rn<<5)|rt;}
static uint32_t enc_ldr_sw_x(uint8_t rt,uint8_t rn,uint16_t imm12){return 0xB9800000u|((uint32_t)imm12<<10)|((uint32_t)rn<<5)|rt;}
static uint32_t enc_cbz(int is64,uint8_t rt,int32_t imm19){return (is64?0xB4000000u:0x34000000u)|(((uint32_t)imm19&0x7FFFFu)<<5)|rt;}
static uint32_t enc_cbnz(int is64,uint8_t rt,int32_t imm19){return (is64?0xB5000000u:0x35000000u)|(((uint32_t)imm19&0x7FFFFu)<<5)|rt;}
static uint32_t enc_madd(int is64,uint8_t rd,uint8_t rn,uint8_t rm,uint8_t ra){return (is64?0x9B000000u:0x1B000000u)|((uint32_t)rm<<16)|((uint32_t)ra<<10)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_msub(int is64,uint8_t rd,uint8_t rn,uint8_t rm,uint8_t ra){return (is64?0x9B008000u:0x1B008000u)|((uint32_t)rm<<16)|((uint32_t)ra<<10)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_lslv(int is64,uint8_t rd,uint8_t rn,uint8_t rm){return (is64?0x9AC02000u:0x1AC02000u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_lsrv(int is64,uint8_t rd,uint8_t rn,uint8_t rm){return (is64?0x9AC02400u:0x1AC02400u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_asrv(int is64,uint8_t rd,uint8_t rn,uint8_t rm){return (is64?0x9AC02800u:0x1AC02800u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_rorv(int is64,uint8_t rd,uint8_t rn,uint8_t rm){return (is64?0x9AC02C00u:0x1AC02C00u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_ldr_b(uint8_t rt,uint8_t rn,uint16_t imm12_scaled){return 0x39400000u|((uint32_t)imm12_scaled<<10)|((uint32_t)rn<<5)|rt;}
static uint32_t enc_ldr_h(uint8_t rt,uint8_t rn,uint16_t imm12_scaled){return 0x79400000u|((uint32_t)imm12_scaled<<10)|((uint32_t)rn<<5)|rt;}
static uint32_t enc_ldr_w(uint8_t rt,uint8_t rn,uint16_t imm12_scaled){return 0xB9400000u|((uint32_t)imm12_scaled<<10)|((uint32_t)rn<<5)|rt;}
static uint32_t enc_str_b(uint8_t rt,uint8_t rn,uint16_t imm12_scaled){return 0x39000000u|((uint32_t)imm12_scaled<<10)|((uint32_t)rn<<5)|rt;}
static uint32_t enc_str_h(uint8_t rt,uint8_t rn,uint16_t imm12_scaled){return 0x79000000u|((uint32_t)imm12_scaled<<10)|((uint32_t)rn<<5)|rt;}
static uint32_t enc_str_w(uint8_t rt,uint8_t rn,uint16_t imm12_scaled){return 0xB9000000u|((uint32_t)imm12_scaled<<10)|((uint32_t)rn<<5)|rt;}
static uint32_t enc_mul(int is64,uint8_t rd,uint8_t rn,uint8_t rm){return (is64?0x9B007C00u:0x1B007C00u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_udiv(int is64,uint8_t rd,uint8_t rn,uint8_t rm){return (is64?0x9AC00800u:0x1AC00800u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_sdiv(int is64,uint8_t rd,uint8_t rn,uint8_t rm){return (is64?0x9AC00C00u:0x1AC00C00u)|((uint32_t)rm<<16)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_clz(int is64,uint8_t rd,uint8_t rn){return (is64?0xDAC01000u:0x5AC01000u)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_rbit(int is64,uint8_t rd,uint8_t rn){return (is64?0xDAC00000u:0x5AC00000u)|((uint32_t)rn<<5)|rd;}
static uint32_t enc_cls(int is64,uint8_t rd,uint8_t rn){return (is64?0xDAC01400u:0x5AC01400u)|((uint32_t)rn<<5)|rd;}

static int map_reg(const char *sym) {
  if (!sym) return -1;
  if (strcmp(sym, "HL") == 0) return 0;  /* x0 */
  if (strcmp(sym, "DE") == 0) return 1;  /* x1 */
  if (strcmp(sym, "BC") == 0) return 2;  /* x2 */
  if (strcmp(sym, "A") == 0)  return 3;  /* x3 */
  if (strcmp(sym, "IX") == 0) return 4;  /* x4 */
  return -1;
}

static int imm12_ok(long long v) { return v >= 0 && v <= 4095; }
static int uimm12_scaled(long long off_bytes, int scale_log2, uint16_t *imm12_out) {
  if (off_bytes < 0) return 0;
  long long scale = 1LL << scale_log2;
  if ((off_bytes & (scale - 1)) != 0) return 0;
  long long imm = off_bytes / scale;
  if (imm < 0 || imm > 4095) return 0;
  if (imm12_out) *imm12_out = (uint16_t)imm;
  return 1;
}

static int fits_imm12_signed(long long v) {
  return v >= -2048 && v <= 2047;
}

static symtab_entry *find_sym(symtab_entry *root, const char *name) {
  for (symtab_entry *s = root; s; s = s->next) {
    if (s->name && strcmp(s->name, name) == 0) return s;
  }
  return NULL;
}

static int branch_rel_ok(int64_t disp_bytes) {
  int64_t imm26 = disp_bytes / 4;
  return imm26 >= -(1<<25) && imm26 < (1<<25);
}

static uint8_t cond_from_sym(const char *s){
  if (!s) return 0xE; /* always */
  if (strncmp(s,"EQ",2)==0) return 0x0;
  if (strncmp(s,"NE",2)==0) return 0x1;
  if (strncmp(s,"LTU",3)==0) return 0x3; /* CC */
  if (strncmp(s,"GEU",3)==0) return 0x2; /* CS */
  if (strncmp(s,"LT",2)==0) return 0xB; /* LT (signed) */
  if (strncmp(s,"GE",2)==0) return 0xA; /* GE (signed) */
  if (strncmp(s,"GT",2)==0) return 0xC; /* GT */
  if (strncmp(s,"LE",2)==0) return 0xD; /* LE */
  return 0xE;
}

static size_t estimate_instr_words(const ir_entry_t *e) {
  if (!e || e->kind!=IR_ENTRY_INSTR) return 0;
  const char *m = e->u.instr.mnem ? e->u.instr.mnem : "";
  if (strcmp(m,"RET")==0) return 2;
  if (strcmp(m,"CALL")==0) return 32; /* space for loading several args + bl */
  if (strcmp(m,"JR")==0) return 3; /* conditional fallbacks may emit extra skip */
  if (strcmp(m,"LD")==0 && e->u.instr.op_count>=2 && e->u.instr.ops[1].kind==IR_OP_SYM) return 4; /* adrp+add+ldr */
  if (strcmp(m,"LD")==0 || strncmp(m,"LD",2)==0) return 6; /* adr+add+mov+add+ldr */
  if (strncmp(m,"ST",2)==0) return 5; /* may need adrp/add/mov */
  if (strcmp(m,"INC")==0 || strcmp(m,"DEC")==0) return 1;
  if (strcmp(m,"DROP")==0) return 1;
  if (strcmp(m,"LDIR")==0) return 8;
  if (strcmp(m,"FILL")==0) return 7;
  if (strcmp(m,"CP")==0) return 3; /* may materialize imm */
  if (strncmp(m,"EQ",2)==0 || strncmp(m,"NE",2)==0 || strstr(m,"LT")||strstr(m,"GT")||strstr(m,"LE")||strstr(m,"GE")) return 2;
  if (strcmp(m,"ADD")==0 || strcmp(m,"SUB")==0 || strcmp(m,"MUL")==0 || strcmp(m,"AND")==0 || strcmp(m,"OR")==0 || strcmp(m,"XOR")==0 ||
      strcmp(m,"ADD64")==0 || strcmp(m,"SUB64")==0 || strcmp(m,"MUL64")==0 || strcmp(m,"AND64")==0 || strcmp(m,"OR64")==0 || strcmp(m,"XOR64")==0) return 3;
  if (strcmp(m,"DIVS")==0 || strcmp(m,"DIVU")==0 || strcmp(m,"REMS")==0 || strcmp(m,"REMU")==0 ||
      strcmp(m,"DIVS64")==0 || strcmp(m,"DIVU64")==0 || strcmp(m,"REMS64")==0 || strcmp(m,"REMU64")==0) return 4;
  if (strcmp(m,"SLA")==0 || strcmp(m,"SRL")==0 || strcmp(m,"SRA")==0 || strcmp(m,"ROL")==0 || strcmp(m,"ROR")==0 ||
      strcmp(m,"SLA64")==0 || strcmp(m,"SRL64")==0 || strcmp(m,"SRA64")==0 || strcmp(m,"ROL64")==0 || strcmp(m,"ROR64")==0) return 3;
  if (strcmp(m,"CLZ")==0 || strcmp(m,"CTZ")==0 || strcmp(m,"CLZ64")==0 || strcmp(m,"CTZ64")==0) return 2;
  if (strcmp(m,"POPC")==0 || strcmp(m,"POPC64")==0) return 24;
  return 1;
}

static void emit_mov_imm64(uint32_t *w, size_t *pcw, uint8_t rd, uint64_t imm) {
  uint16_t parts[4] = {(uint16_t)(imm&0xFFFFu),(uint16_t)((imm>>16)&0xFFFFu),(uint16_t)((imm>>32)&0xFFFFu),(uint16_t)((imm>>48)&0xFFFFu)};
  int emitted=0;
  for(int i=0;i<4;i++){
    if (parts[i]==0 && emitted) continue;
    w[(*pcw)++] = emitted ? enc_movk(rd, parts[i], (uint8_t)i) : enc_movz(rd, parts[i], (uint8_t)i);
    emitted=1;
  }
  if (!emitted) w[(*pcw)++] = enc_movz(rd,0,0);
}

static void emit_adrp_add(cg_blob_t *out,uint32_t *w,size_t *pcw,int rd,const char *sym, uint32_t line, size_t ir_id){
  size_t off = (*pcw)*4;
  w[(*pcw)++] = 0x90000000u | (uint32_t)rd; /* ADRP rd, sym@PAGE */
  add_reloc(out,(uint32_t)off,0,sym,line,ir_id);
  w[(*pcw)++] = 0x91000000u | ((uint32_t)rd<<5) | (uint32_t)rd; /* ADD rd, rd, sym@PAGEOFF */
  add_reloc(out,(uint32_t)(off+4),1,sym,line,ir_id);
}

int cg_emit_arm64(const ir_prog_t *ir, cg_blob_t *out) {
  if (!ir || !out) return -1;
  memset(out,0,sizeof(*out));
  symtab_add(&out->syms,"lembeh_handle",0);
#define CG_FAIL(ctx, msg) do { ir_entry_t *_ctx = (ir_entry_t *)(ctx); size_t _ln = _ctx ? _ctx->loc.line : 0; if (_ln) fprintf(stderr,"[lower] codegen: %s (line %zu)\n", msg, _ln); else fprintf(stderr,"[lower] codegen: %s\n", msg); cg_free(out); seen_free(call_targets,n_calls); seen_free(label_list,n_labels); return -1; } while (0)
#define CG_FAILF(ctx, fmt, arg) do { ir_entry_t *_ctx = (ir_entry_t *)(ctx); size_t _ln = _ctx ? _ctx->loc.line : 0; if (_ln) fprintf(stderr,"[lower] codegen: " fmt " (line %zu)\n", arg, _ln); else fprintf(stderr,"[lower] codegen: " fmt "\n", arg); cg_free(out); seen_free(call_targets,n_calls); seen_free(label_list,n_labels); return -1; } while (0)

  /* Collect labels and call targets for function boundary detection. */
  seen_sym_t *call_targets = NULL;
  size_t n_calls = 0, c_calls = 0;
  seen_sym_t *label_list = NULL;
  size_t n_labels = 0, c_labels = 0;

  /* Sizing pass */
  size_t code_words = 0;
  size_t data_len = 0;
  size_t func_count = 0;
  int first_label_seen = 0;
  int any_instr = 0;

  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_ENTRY_LABEL) {
      symtab_add(&out->syms, e->u.label.name ? e->u.label.name : "", (size_t)-1);
      seen_add(&label_list, &n_labels, &c_labels, e->u.label.name ? e->u.label.name : "", e->loc.line);
      continue;
    }
    if (e->kind == IR_ENTRY_DIR) {
      switch (e->u.dir.dir_kind) {
        case IR_DIR_DB:
        case IR_DIR_DW:
        case IR_DIR_STR:
          data_len += e->u.dir.data_len;
          if (e->u.dir.name) symtab_add(&out->syms, e->u.dir.name, (size_t)-1);
          break;
        case IR_DIR_RESB:
          data_len += e->u.dir.reserve_len;
          if (e->u.dir.name) symtab_add(&out->syms, e->u.dir.name, (size_t)-1);
          break;
        case IR_DIR_EQU:
          if (e->u.dir.name) symtab_add(&out->syms, e->u.dir.name, (size_t)e->u.dir.equ_value);
          break;
        case IR_DIR_PUBLIC:
          break;
        case IR_DIR_EXTERN:
          break;
      }
      continue;
    }
    if (e->kind == IR_ENTRY_INSTR) {
      any_instr = 1;
      if (strcmp(e->u.instr.mnem ? e->u.instr.mnem : "", "CALL") == 0 && e->u.instr.op_count >= 1 && e->u.instr.ops[0].kind == IR_OP_SYM) {
        seen_add(&call_targets, &n_calls, &c_calls, e->u.instr.ops[0].sym, e->loc.line);
      }
      /* Pre-declare memory symbols referenced by name (non-register base). */
      for (size_t i = 0; i < e->u.instr.op_count; i++) {
        ir_op_t *op = &e->u.instr.ops[i];
        if (op->kind == IR_OP_MEM && op->mem_base) {
          int base = map_reg(op->mem_base);
          if (base < 0 && !symtab_has(out->syms, op->mem_base)) {
            symtab_add(&out->syms, op->mem_base, (size_t)-1);
            data_len += 8; /* default slot */
          }
        }
      }
    }
  }

  /* Determine function entry labels: first label, labels named "main", labels prefixed with "fn_", and labels that are CALL targets. */
  for (size_t i = 0; i < n_labels; i++) {
    int is_func = 0;
    if (!first_label_seen) { is_func = 1; first_label_seen = 1; }
    if (label_list[i].name && strcmp(label_list[i].name, "main") == 0) is_func = 1;
    if (label_list[i].name && strncmp(label_list[i].name, "fn_", 3) == 0) is_func = 1;
    if (label_list[i].name && seen_has(call_targets, n_calls, label_list[i].name)) is_func = 1;
    if (is_func) func_count++;
  }
  if (func_count == 0 && any_instr) func_count = 1;

  /* Prologues add 2 words each; RET is budgeted at 2 words already. */
  code_words += func_count * 2;

  /* Second sizing loop for instructions. */
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_ENTRY_INSTR) code_words += estimate_instr_words(e);
  }

  out->code_len = code_words ? code_words*4 : 4;
  out->data_len = data_len;
  out->data_off = out->code_len;
  out->code = (unsigned char *)calloc(1,out->code_len);
  out->data = (unsigned char *)calloc(1,data_len?data_len:1);
  if (!out->code || !out->data) { CG_FAIL(NULL, "out of memory"); }
  uint32_t *w = (uint32_t *)out->code;

  /* Second pass */
  size_t pcw = 0;
  size_t data_off = 0;
  int in_func = 0;
  int func_has_prologue = 0;
  int func_seen = 0;

  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_ENTRY_LABEL) {
      if (e->u.label.name) {
        int is_func = 0;
        if (!func_seen) is_func = 1;
        if (strcmp(e->u.label.name, "main") == 0) is_func = 1;
        if (strncmp(e->u.label.name, "fn_", 3) == 0) is_func = 1;
        if (seen_has(call_targets, n_calls, e->u.label.name)) is_func = 1;
        if (is_func) {
          func_seen = 1;
          in_func = 1;
          func_has_prologue = 0;
        }
        symtab_update(out->syms, e->u.label.name, pcw*4);
      }
      continue;
    }
    if (e->kind == IR_ENTRY_DIR) {
      size_t sym_off = out->code_len + data_off;
      switch (e->u.dir.dir_kind) {
        case IR_DIR_DB:
        case IR_DIR_DW:
        case IR_DIR_STR:
          if (e->u.dir.data_len && e->u.dir.data) {
            memcpy(out->data + data_off, e->u.dir.data, e->u.dir.data_len);
            if (e->u.dir.name) symtab_update(out->syms, e->u.dir.name, sym_off);
            data_off += e->u.dir.data_len;
          }
          break;
        case IR_DIR_RESB:
          if (e->u.dir.reserve_len) {
            memset(out->data + data_off, 0, e->u.dir.reserve_len);
            if (e->u.dir.name) symtab_update(out->syms, e->u.dir.name, sym_off);
            data_off += e->u.dir.reserve_len;
          }
          break;
        case IR_DIR_EQU:
          if (e->u.dir.name) symtab_update(out->syms, e->u.dir.name, (size_t)e->u.dir.equ_value);
          break;
        default:
          break;
      }
      continue;
    }

    const char *m = e->u.instr.mnem ? e->u.instr.mnem : "";
    ir_op_t *ops = e->u.instr.ops;
    size_t nops = e->u.instr.op_count;

    if (!in_func) { in_func = 1; func_has_prologue = 0; func_seen = 1; }
    if (!func_has_prologue) {
      w[pcw++] = enc_stp_fp_lr();
      w[pcw++] = enc_mov_fp_sp();
      func_has_prologue = 1;
    }

    /* Record map entry for this IR instruction. */
    add_pc_map(out, (uint32_t)(pcw*4), e->id, (uint32_t)e->loc.line);

    if (strcmp(m,"RET")==0) {
      if (func_has_prologue) {
        w[pcw++] = enc_ldp_fp_lr();
      }
      w[pcw++] = enc_ret();
      in_func = 0;
      func_has_prologue = 0;
      continue;
    }

      if (strcmp(m,"CALL")==0 && nops>=1 && ops[0].kind==IR_OP_SYM) {
      /* Marshal arguments into x0-x7, spill rest on stack (16-byte aligned). */
      size_t arg_words = nops>1 ? nops-1 : 0;
      size_t gp_regs = 8;
      size_t to_spill = arg_words>gp_regs ? arg_words-gp_regs : 0;
      if (to_spill) {
        size_t spill_bytes = to_spill*8;
        /* align to 16 */
        if (spill_bytes & 0xF) spill_bytes = (spill_bytes + 0xF) & ~0xFULL;
        if (spill_bytes <= 4095) {
          w[pcw++] = enc_sub_imm(1, 31, 31, (uint16_t)spill_bytes); /* sp -= spill_bytes */
        } else {
          emit_mov_imm64(w,&pcw,7,spill_bytes);
          w[pcw++] = enc_sub_reg(1, 31, 31, 7);
        }
      }
      for (size_t i = 1; i < nops; i++) {
        ir_op_t *arg = &ops[i];
        if (i-1 < gp_regs) {
          uint8_t reg = (uint8_t)(i-1);
        if (arg->kind == IR_OP_NUM) {
          emit_mov_imm64(w, &pcw, reg, (uint64_t)arg->unum);
        } else if (arg->kind == IR_OP_SYM) {
          int rmap = map_reg(arg->sym);
          if (rmap >= 0) {
            w[pcw++] = enc_add_imm(1, reg, (uint8_t)rmap, 0);
          } else {
            emit_adrp_add(out, w, &pcw, reg, arg->sym, (uint32_t)e->loc.line, e->id);
          }
        } else if (arg->kind == IR_OP_MEM && arg->mem_base) {
            int base = map_reg(arg->mem_base);
            if (base < 0) { CG_FAIL(e, "CALL arg mem base must be register"); }
            w[pcw++] = enc_add_imm(1, reg, (uint8_t)base, 0);
          } else { CG_FAIL(e, "unsupported CALL arg"); }
        } else {
          size_t spill_index = i-1-gp_regs;
          size_t spill_off = spill_index*8;
          uint8_t tmp = 6;
          if (arg->kind == IR_OP_NUM) {
            emit_mov_imm64(w,&pcw,tmp,(uint64_t)arg->unum);
          } else if (arg->kind == IR_OP_SYM) {
            emit_adrp_add(out,w,&pcw,tmp,arg->sym,(uint32_t)e->loc.line,e->id);
          } else if (arg->kind == IR_OP_MEM && arg->mem_base) {
            int base = map_reg(arg->mem_base);
            if (base < 0) { CG_FAIL(e, "CALL spill mem base must be register"); }
            w[pcw++] = enc_add_imm(1, tmp, (uint8_t)base, 0);
          } else { CG_FAIL(e, "unsupported CALL spill arg"); }
          if (spill_off/8 < 4096) {
            uint16_t imm12 = (uint16_t)(spill_off/8);
            w[pcw++] = enc_str_x_imm(tmp, 31, imm12); /* store to sp+spill_off */
          } else {
            uint8_t addr = 7;
            emit_mov_imm64(w,&pcw,addr,(uint64_t)spill_off);
            w[pcw++] = enc_add_reg(1, addr, 31, addr);
            w[pcw++] = enc_str_x_imm(tmp, addr, 0);
          }
        }
      }
      w[pcw] = enc_bl_placeholder();
      add_reloc(out,(uint32_t)(pcw*4),2, ops[0].sym,(uint32_t)e->loc.line,e->id);
      pcw++;
      if (to_spill) {
        size_t spill_bytes = to_spill*8;
        if (spill_bytes & 0xF) spill_bytes = (spill_bytes + 0xF) & ~0xFULL;
        if (spill_bytes <= 4095) {
          w[pcw++] = enc_add_imm(1, 31, 31, (uint16_t)spill_bytes); /* sp += spill_bytes */
        } else {
          emit_mov_imm64(w,&pcw,7,spill_bytes);
          w[pcw++] = enc_add_reg(1, 31, 31, 7);
        }
      }
      continue;
    }

    if (strcmp(m,"JR")==0 && nops>=1 && ops[0].kind==IR_OP_SYM) {
      if (nops==1) {
        symtab_entry *target = find_sym(out->syms, ops[0].sym);
        if (target && target->off != (size_t)-1 && branch_rel_ok((int64_t)target->off - (int64_t)(pcw*4))) {
          int64_t disp = (int64_t)target->off - (int64_t)(pcw*4);
          int32_t imm26 = (int32_t)(disp/4);
          w[pcw++] = enc_b_placeholder() | ((uint32_t)imm26 & 0x03FFFFFFu);
        } else {
          w[pcw] = enc_b_placeholder();
          add_reloc(out,(uint32_t)(pcw*4),2, ops[0].sym,(uint32_t)e->loc.line,e->id);
          pcw++;
        }
      } else if (nops==2 && ops[1].kind==IR_OP_SYM) {
        symtab_entry *target = find_sym(out->syms, ops[1].sym);
        if (!target) { CG_FAILF(e, "JR target '%s' missing", ops[1].sym ? ops[1].sym : "(null)"); }
        int64_t disp = (int64_t)target->off - (int64_t)(pcw*4);
        int32_t imm19 = (int32_t)(disp/4);
        if (target->off == (size_t)-1 || imm19 < -0x40000 || imm19 > 0x3FFFF) {
          uint8_t cond = cond_from_sym(ops[0].sym);
          uint8_t inv = cond ^ 1u;
          /* skip over the reloc branch if condition false (skip 1 instruction -> imm19=2 because PC-relative) */
          w[pcw++] = enc_b_cond(inv, 2);
          w[pcw] = enc_b_placeholder();
          add_reloc(out,(uint32_t)(pcw*4),2, ops[1].sym,(uint32_t)e->loc.line,e->id);
          pcw++;
        } else {
          uint8_t cond = cond_from_sym(ops[0].sym);
          w[pcw++] = enc_b_cond(cond, imm19);
        }
      } else { CG_FAIL(e, "invalid JR operands"); }
      continue;
    }

    if (strcmp(m,"CP")==0 && nops>=2) {
      int r0 = (ops[0].kind==IR_OP_SYM)?map_reg(ops[0].sym):-1;
      if (r0<0) { CG_FAIL(e, "CP dst must be register"); }
      if (ops[1].kind==IR_OP_SYM) {
        int r1 = map_reg(ops[1].sym);
        if (r1<0) { CG_FAIL(e, "CP src must be register"); }
        w[pcw++] = enc_cmp_reg(0,r0,r1);
      } else if (ops[1].kind==IR_OP_NUM) {
        emit_mov_imm64(w,&pcw,5,(uint64_t)ops[1].unum);
        w[pcw++] = enc_cmp_reg(0,r0,5);
      } else { CG_FAIL(e, "CP src unsupported"); }
      continue;
    }

    if ((strcmp(m,"INC")==0 || strcmp(m,"DEC")==0) && nops>=1) {
      int rd = (ops[0].kind==IR_OP_SYM)?map_reg(ops[0].sym):-1;
      if (rd<0) { CG_FAIL(e, "INC/DEC requires register"); }
      if (strcmp(m,"INC")==0) w[pcw++] = enc_add_imm(1,(uint8_t)rd,(uint8_t)rd,1);
      else w[pcw++] = enc_sub_imm(1,(uint8_t)rd,(uint8_t)rd,1);
      continue;
    }

    if (strcmp(m,"DROP")==0 && nops>=1) {
      int rd = (ops[0].kind==IR_OP_SYM)?map_reg(ops[0].sym):-1;
      if (rd<0) { CG_FAIL(e, "DROP requires register"); }
      /* zero the register to mark drop */
      w[pcw++] = enc_sub_reg(1,(uint8_t)rd,(uint8_t)rd,(uint8_t)rd);
      continue;
    }

    if (strcmp(m,"FILL")==0) {
      /* HL=dst(x0), A=byte(x2), BC=len(x3) */
      size_t loop = pcw;
      /* if len==0 jump to exit */
      w[pcw++] = enc_cbz(1, 3, 4); /* skip body (4 inst) to exit */
      w[pcw++] = enc_str_b(2, 0, 0);
      w[pcw++] = enc_add_imm(1, 0, 0, 1);
      w[pcw++] = enc_sub_imm(1, 3, 3, 1);
      /* back-edge */
      int32_t back = (int32_t)((int64_t)(loop+1) - (int64_t)(pcw));
      w[pcw++] = enc_cbnz(1, 3, back);
      continue;
    }

    if (strcmp(m,"LDIR")==0) {
      /* DE=dst(x1), HL=src(x0), BC=len(x3) */
      size_t loop = pcw;
      w[pcw++] = enc_cbz(1, 3, 6); /* skip body if len==0 */
      w[pcw++] = enc_ldr_b(5, 0, 0);
      w[pcw++] = enc_str_b(5, 1, 0);
      w[pcw++] = enc_add_imm(1, 0, 0, 1);
      w[pcw++] = enc_add_imm(1, 1, 1, 1);
      w[pcw++] = enc_sub_imm(1, 3, 3, 1);
      int32_t back = (int32_t)((int64_t)(loop+1) - (int64_t)(pcw));
      w[pcw++] = enc_cbnz(1, 3, back);
      continue;
    }

    if ((strncmp(m,"EQ",2)==0 || strncmp(m,"NE",2)==0 || strstr(m,"LT")||strstr(m,"GT")||strstr(m,"LE")||strstr(m,"GE")) && nops>=2) {
      int r0 = (ops[0].kind==IR_OP_SYM)?map_reg(ops[0].sym):-1;
      if (r0<0) { CG_FAIL(e, "cmp dst must be register"); }
      int is64 = strstr(m,"64") != NULL;
      if (ops[1].kind==IR_OP_SYM) {
        int r1 = map_reg(ops[1].sym);
        if (r1<0) { CG_FAIL(e, "cmp src must be register"); }
        w[pcw++] = enc_cmp_reg(is64,r0,r1);
      } else if (ops[1].kind==IR_OP_NUM) {
        emit_mov_imm64(w,&pcw,5,(uint64_t)ops[1].unum);
        w[pcw++] = enc_cmp_reg(is64,r0,5);
      } else { CG_FAIL(e, "cmp src unsupported"); }
      uint8_t cond = cond_from_sym(m);
      w[pcw++] = enc_cset(r0, cond);
      continue;
    }

    if ((strcmp(m,"SLA")==0 || strcmp(m,"SRL")==0 || strcmp(m,"SRA")==0 || strcmp(m,"ROL")==0 || strcmp(m,"ROR")==0 ||
         strcmp(m,"SLA64")==0 || strcmp(m,"SRL64")==0 || strcmp(m,"SRA64")==0 || strcmp(m,"ROL64")==0 || strcmp(m,"ROR64")==0) && nops>=2) {
      int rd = map_reg(ops[0].sym);
      int rs = (ops[1].kind==IR_OP_SYM)?map_reg(ops[1].sym):-1;
      long long imm = (ops[1].kind==IR_OP_NUM)?ops[1].num:0;
      if (rd<0) { CG_FAIL(e, "shift dst must be register"); }
      int is64 = strstr(m,"64") != NULL;
      uint8_t rd_u = (uint8_t)rd;
      if (ops[1].kind==IR_OP_SYM) {
        if (rs<0) { CG_FAIL(e, "shift src must be register"); }
        if (strcmp(m,"SLA")==0 || strcmp(m,"SLA64")==0) w[pcw++] = enc_lslv(is64, rd_u, rd_u, (uint8_t)rs);
        else if (strcmp(m,"SRL")==0 || strcmp(m,"SRL64")==0) w[pcw++] = enc_lsrv(is64, rd_u, rd_u, (uint8_t)rs);
        else if (strcmp(m,"SRA")==0 || strcmp(m,"SRA64")==0) w[pcw++] = enc_asrv(is64, rd_u, rd_u, (uint8_t)rs);
        else if (strcmp(m,"ROL")==0 || strcmp(m,"ROL64")==0) {
          /* rol x,rs = ror x, (64 - (rs&63)) */
          w[pcw++] = enc_rorv(is64, rd_u, rd_u, (uint8_t)rs);
        } else if (strcmp(m,"ROR")==0 || strcmp(m,"ROR64")==0) {
          w[pcw++] = enc_rorv(is64, rd_u, rd_u, (uint8_t)rs);
        }
      } else {
        int width = is64 ? 64 : 32;
        if (imm < 0 || imm >= width) { CG_FAIL(e, "shift imm out of range"); }
        uint64_t adj = (strcmp(m,"ROL")==0 || strcmp(m,"ROL64")==0) ? (uint64_t)((width - (imm & (width-1))) & (width-1)) : (uint64_t)imm;
        emit_mov_imm64(w,&pcw,5,adj);
        if (strcmp(m,"SLA")==0 || strcmp(m,"SLA64")==0) w[pcw++] = enc_lslv(is64, rd_u, rd_u, 5);
        else if (strcmp(m,"SRL")==0 || strcmp(m,"SRL64")==0) w[pcw++] = enc_lsrv(is64, rd_u, rd_u, 5);
        else if (strcmp(m,"SRA")==0 || strcmp(m,"SRA64")==0) w[pcw++] = enc_asrv(is64, rd_u, rd_u, 5);
        else w[pcw++] = enc_rorv(is64, rd_u, rd_u, 5);
      }
      continue;
    }

    if ((strcmp(m,"LD")==0 || strncmp(m,"LD",2)==0) && nops>=2) {
      int rd = (ops[0].kind==IR_OP_SYM)?map_reg(ops[0].sym):-1;
      if (rd<0) { CG_FAIL(e, "LD dst must be register"); }
      if (ops[1].kind==IR_OP_SYM) {
        int rs = map_reg(ops[1].sym);
        if (rs>=0) {
          /* register move */
          w[pcw++] = enc_add_reg(1, (uint8_t)rd, 31, (uint8_t)rs);
        } else if (strcmp(m,"LD")==0) {
          emit_adrp_add(out,w,&pcw,rd,ops[1].sym,(uint32_t)e->loc.line,e->id); /* load address */
        } else {
          emit_adrp_add(out,w,&pcw,rd,ops[1].sym,(uint32_t)e->loc.line,e->id);
          if (strcmp(m,"LD8U")==0 || strcmp(m,"LD8S")==0 || strcmp(m,"LD8U64")==0 || strcmp(m,"LD8S64")==0) w[pcw++] = enc_ldr_b((uint8_t)rd,(uint8_t)rd,0);
          else if (strcmp(m,"LD16U")==0 || strcmp(m,"LD16S")==0 || strcmp(m,"LD16U64")==0 || strcmp(m,"LD16S64")==0) w[pcw++] = enc_ldr_h((uint8_t)rd,(uint8_t)rd,0);
          else if (strcmp(m,"LD32")==0 || strcmp(m,"LD32U64")==0 || strcmp(m,"LD32S64")==0) w[pcw++] = enc_ldr_w((uint8_t)rd,(uint8_t)rd,0);
          else w[pcw++] = enc_ldr_x_imm((uint8_t)rd,(uint8_t)rd,0);
        }
      } else if (ops[1].kind==IR_OP_NUM) {
        /* Immediate load for LD/LDxx: materialize constant. */
        emit_mov_imm64(w,&pcw,(uint8_t)rd,(uint64_t)ops[1].unum);
      } else if (ops[1].kind==IR_OP_MEM) {
        int base = map_reg(ops[1].mem_base);
        long long off = 0;
        if (nops>=3 && ops[2].kind==IR_OP_NUM) off = ops[2].num;
        else if (ops[1].has_mem_disp) off = ops[1].mem_disp;
        uint16_t imm12=0;
        int scale = 3;
        if (strcmp(m,"LD8U")==0 || strcmp(m,"LD8S")==0 || strcmp(m,"LD8U64")==0 || strcmp(m,"LD8S64")==0) scale=0;
        else if (strcmp(m,"LD16U")==0 || strcmp(m,"LD16S")==0 || strcmp(m,"LD16U64")==0 || strcmp(m,"LD16S64")==0) scale=1;
        else if (strcmp(m,"LD32")==0 || strcmp(m,"LD32S64")==0 || strcmp(m,"LD32U64")==0) scale=2;
        uint8_t addr_reg = (uint8_t)((base < 0) ? rd : base);
        if (base < 0) { /* treat mem base as symbol */
          emit_adrp_add(out,w,&pcw,addr_reg,ops[1].mem_base,(uint32_t)e->loc.line,e->id);
        }
        if (base >=0 && uimm12_scaled(off,scale,&imm12)) {
          if (strcmp(m,"LD8U")==0 || strcmp(m,"LD8U64")==0) w[pcw++] = enc_ldr_b((uint8_t)rd,addr_reg,imm12);
          else if (strcmp(m,"LD8S")==0 || strcmp(m,"LD8S64")==0) w[pcw++] = enc_ldr_sb_x((uint8_t)rd,addr_reg,imm12);
          else if (strcmp(m,"LD16U")==0 || strcmp(m,"LD16U64")==0) w[pcw++] = enc_ldr_h((uint8_t)rd,addr_reg,imm12);
          else if (strcmp(m,"LD16S")==0 || strcmp(m,"LD16S64")==0) w[pcw++] = enc_ldr_sh_x((uint8_t)rd,addr_reg,imm12);
          else if (strcmp(m,"LD32")==0 || strcmp(m,"LD32U64")==0) w[pcw++] = enc_ldr_w((uint8_t)rd,addr_reg,imm12);
          else if (strcmp(m,"LD32S64")==0) w[pcw++] = enc_ldr_sw_x((uint8_t)rd,addr_reg,imm12);
          else w[pcw++] = enc_ldr_x_imm((uint8_t)rd,addr_reg,imm12);
        } else {
          if (base >=0) {
            addr_reg = 5;
            w[pcw++] = enc_add_imm(1, addr_reg, (uint8_t)base, 0);
          }
          if (off) {
            if (fits_imm12_signed(off) && off>=0) {
              w[pcw++] = enc_add_imm(1, addr_reg, addr_reg, (uint16_t)off);
            } else {
              emit_mov_imm64(w,&pcw,6,(uint64_t)off);
              w[pcw++] = enc_add_reg(1, addr_reg, addr_reg, 6);
            }
          }
          if (strcmp(m,"LD8U")==0 || strcmp(m,"LD8U64")==0) w[pcw++] = enc_ldr_b((uint8_t)rd,addr_reg,0);
          else if (strcmp(m,"LD8S")==0 || strcmp(m,"LD8S64")==0) w[pcw++] = enc_ldr_sb_x((uint8_t)rd,addr_reg,0);
          else if (strcmp(m,"LD16U")==0 || strcmp(m,"LD16U64")==0) w[pcw++] = enc_ldr_h((uint8_t)rd,addr_reg,0);
          else if (strcmp(m,"LD16S")==0 || strcmp(m,"LD16S64")==0) w[pcw++] = enc_ldr_sh_x((uint8_t)rd,addr_reg,0);
          else if (strcmp(m,"LD32")==0 || strcmp(m,"LD32U64")==0) w[pcw++] = enc_ldr_w((uint8_t)rd,addr_reg,0);
          else if (strcmp(m,"LD32S64")==0) w[pcw++] = enc_ldr_sw_x((uint8_t)rd,addr_reg,0);
          else w[pcw++] = enc_ldr_x_imm((uint8_t)rd,addr_reg,0);
        }
      } else { CG_FAIL(e, "unsupported LD operand"); }
      continue;
    }

    if (strncmp(m,"ST",2)==0 && nops>=2) {
      int base=-1, src=-1; long long off=0;
      if (ops[0].kind==IR_OP_MEM) { base=map_reg(ops[0].mem_base); if (nops>=2 && ops[1].kind==IR_OP_SYM) src=map_reg(ops[1].sym); }
      if (src<0) { CG_FAIL(e, "ST src must be register"); }
      if (nops>=3 && ops[2].kind==IR_OP_NUM) off=ops[2].num;
      else if (ops[0].has_mem_disp) off = ops[0].mem_disp;
      uint16_t imm12=0;
      int scale=3;
      if (strcmp(m,"ST8")==0) scale=0;
      else if (strcmp(m,"ST16")==0 || strcmp(m,"ST16_64")==0) scale=1;
      else if (strcmp(m,"ST32")==0 || strcmp(m,"ST32_64")==0) scale=2;
      uint8_t addr_reg = (uint8_t)base;
      int base_is_sym = (base < 0);
      if (base_is_sym) {
        addr_reg = 5;
        emit_adrp_add(out,w,&pcw,addr_reg,ops[0].mem_base,(uint32_t)e->loc.line,e->id);
      }
      if (!uimm12_scaled(off,scale,&imm12)) {
        if (!base_is_sym) {
          addr_reg = 5;
          w[pcw++] = enc_add_imm(1, addr_reg, (uint8_t)base, 0);
        }
        if (fits_imm12_signed(off) && off>=0) {
          w[pcw++] = enc_add_imm(1, addr_reg, addr_reg, (uint16_t)off);
        } else {
          emit_mov_imm64(w,&pcw,6,(uint64_t)off);
          w[pcw++] = enc_add_reg(1, addr_reg, addr_reg, 6);
        }
        imm12 = 0;
      }
      if (strcmp(m,"ST8")==0 || strcmp(m,"ST8_64")==0) w[pcw++] = enc_str_b((uint8_t)src,addr_reg,imm12);
      else if (strcmp(m,"ST16")==0 || strcmp(m,"ST16_64")==0) w[pcw++] = enc_str_h((uint8_t)src,addr_reg,imm12);
      else if (strcmp(m,"ST32")==0 || strcmp(m,"ST32_64")==0) w[pcw++] = enc_str_w((uint8_t)src,addr_reg,imm12);
      else w[pcw++] = enc_str_x_imm((uint8_t)src,addr_reg,imm12);
      continue;
    }

    if ((strcmp(m,"ADD")==0 || strcmp(m,"SUB")==0 || strcmp(m,"MUL")==0 ||
         strcmp(m,"AND")==0 || strcmp(m,"OR")==0 || strcmp(m,"XOR")==0 ||
         strcmp(m,"ADD64")==0 || strcmp(m,"SUB64")==0 || strcmp(m,"MUL64")==0 ||
         strcmp(m,"AND64")==0 || strcmp(m,"OR64")==0 || strcmp(m,"XOR64")==0) && nops>=2) {
      int rd = map_reg(ops[0].sym);
      int rs = (ops[1].kind==IR_OP_SYM)?map_reg(ops[1].sym):-1;
      long long imm = (ops[1].kind==IR_OP_NUM)?ops[1].num:0;
      if (rd<0) { CG_FAIL(e, "arith dst must be register"); }
      int is64 = strstr(m,"64") != NULL;
      if (strcmp(m,"MUL")==0) {
        uint8_t rhs = (uint8_t)rs;
        if (rs<0) { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); rhs=5; }
        w[pcw++] = enc_mul(is64,(uint8_t)rd,(uint8_t)rd,rhs);
      } else if (strcmp(m,"MUL64")==0) {
        uint8_t rhs = (uint8_t)rs;
        if (rs<0) { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); rhs=5; }
        w[pcw++] = enc_mul(1,(uint8_t)rd,(uint8_t)rd,rhs);
      } else if (strcmp(m,"ADD")==0) {
        if (rs>=0) w[pcw++] = enc_add_reg(is64,(uint8_t)rd,(uint8_t)rd,(uint8_t)rs);
        else if (imm12_ok(imm)) w[pcw++] = enc_add_imm(is64,(uint8_t)rd,(uint8_t)rd,(uint16_t)imm);
        else { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); w[pcw++] = enc_add_reg(is64,(uint8_t)rd,(uint8_t)rd,5); }
      } else if (strcmp(m,"ADD64")==0) {
        if (rs>=0) w[pcw++] = enc_add_reg(1,(uint8_t)rd,(uint8_t)rd,(uint8_t)rs);
        else if (imm12_ok(imm)) w[pcw++] = enc_add_imm(1,(uint8_t)rd,(uint8_t)rd,(uint16_t)imm);
        else { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); w[pcw++] = enc_add_reg(1,(uint8_t)rd,(uint8_t)rd,5); }
      } else if (strcmp(m,"SUB")==0) {
        if (rs>=0) w[pcw++] = enc_sub_reg(is64,(uint8_t)rd,(uint8_t)rd,(uint8_t)rs);
        else if (imm12_ok(imm)) w[pcw++] = enc_sub_imm(is64,(uint8_t)rd,(uint8_t)rd,(uint16_t)imm);
        else { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); w[pcw++] = enc_sub_reg(is64,(uint8_t)rd,(uint8_t)rd,5); }
      } else if (strcmp(m,"SUB64")==0) {
        if (rs>=0) w[pcw++] = enc_sub_reg(1,(uint8_t)rd,(uint8_t)rd,(uint8_t)rs);
        else if (imm12_ok(imm)) w[pcw++] = enc_sub_imm(1,(uint8_t)rd,(uint8_t)rd,(uint16_t)imm);
        else { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); w[pcw++] = enc_sub_reg(1,(uint8_t)rd,(uint8_t)rd,5); }
      } else if (strcmp(m,"AND")==0) {
        uint8_t rhs = (uint8_t)rs;
        if (rs<0) { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); rhs=5; }
        w[pcw++] = enc_and_reg(is64,(uint8_t)rd,(uint8_t)rd,rhs);
      } else if (strcmp(m,"AND64")==0) {
        uint8_t rhs = (uint8_t)rs;
        if (rs<0) { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); rhs=5; }
        w[pcw++] = enc_and_reg(1,(uint8_t)rd,(uint8_t)rd,rhs);
      } else if (strcmp(m,"OR")==0) {
        uint8_t rhs = (uint8_t)rs;
        if (rs<0) { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); rhs=5; }
        w[pcw++] = enc_orr_reg(is64,(uint8_t)rd,(uint8_t)rd,rhs);
      } else if (strcmp(m,"OR64")==0) {
        uint8_t rhs = (uint8_t)rs;
        if (rs<0) { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); rhs=5; }
        w[pcw++] = enc_orr_reg(1,(uint8_t)rd,(uint8_t)rd,rhs);
      } else if (strcmp(m,"XOR")==0) {
        uint8_t rhs = (uint8_t)rs;
        if (rs<0) { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); rhs=5; }
        w[pcw++] = enc_eor_reg(is64,(uint8_t)rd,(uint8_t)rd,rhs);
      } else if (strcmp(m,"XOR64")==0) {
        uint8_t rhs = (uint8_t)rs;
        if (rs<0) { emit_mov_imm64(w,&pcw,5,(uint64_t)imm); rhs=5; }
        w[pcw++] = enc_eor_reg(1,(uint8_t)rd,(uint8_t)rd,rhs);
      }
      continue;
    }

    if ((strcmp(m,"DIVS")==0 || strcmp(m,"DIVU")==0 || strcmp(m,"REMS")==0 || strcmp(m,"REMU")==0 ||
         strcmp(m,"DIVS64")==0 || strcmp(m,"DIVU64")==0 || strcmp(m,"REMS64")==0 || strcmp(m,"REMU64")==0) && nops>=2) {
      int rd = map_reg(ops[0].sym);
      int rs = (ops[1].kind==IR_OP_SYM)?map_reg(ops[1].sym):-1;
      long long imm = (ops[1].kind==IR_OP_NUM)?ops[1].num:0;
      if (rd<0) { CG_FAIL(e, "div/rem dst must be register"); }
      int is64 = strstr(m,"64") != NULL;
      int is_signed = (strncmp(m,"DIVS",4)==0 || strncmp(m,"REMS",4)==0);
      int is_rem = (strncmp(m,"REM",3)==0);
      uint8_t rhs_reg = (uint8_t)rs;
      if (rs < 0) {
        emit_mov_imm64(w,&pcw,5,(uint64_t)imm);
        rhs_reg = 5;
      }
      /* div */
      if (is_signed) w[pcw++] = enc_sdiv(is64, (uint8_t)rd, (uint8_t)rd, rhs_reg);
      else w[pcw++] = enc_udiv(is64, (uint8_t)rd, (uint8_t)rd, rhs_reg);
      if (is_rem) {
        /* rem = original - (quot * rhs) */
        uint8_t qreg = (uint8_t)rd;
        uint8_t tmp = 6;
        w[pcw++] = enc_mul(is64, tmp, qreg, rhs_reg);
        w[pcw++] = enc_sub_reg(is64, (uint8_t)rd, (uint8_t)rd, tmp);
      }
      continue;
    }

    if ((strcmp(m,"CLZ")==0 || strcmp(m,"CTZ")==0 || strcmp(m,"CLZ64")==0 || strcmp(m,"CTZ64")==0) && nops>=1) {
      int rd = (ops[0].kind==IR_OP_SYM)?map_reg(ops[0].sym):-1;
      if (rd<0) { CG_FAIL(e, "CLZ/CTZ requires register"); }
      int is64 = strstr(m,"64") != NULL;
      if (strcmp(m,"CTZ")==0 || strcmp(m,"CTZ64")==0) {
        w[pcw++] = enc_rbit(is64, (uint8_t)rd, (uint8_t)rd);
        w[pcw++] = enc_clz(is64, (uint8_t)rd, (uint8_t)rd);
      } else {
        w[pcw++] = enc_clz(is64, (uint8_t)rd, (uint8_t)rd);
      }
      continue;
    }

    if ((strcmp(m,"POPC")==0 || strcmp(m,"POPC64")==0) && nops>=1) {
      int rd = (ops[0].kind==IR_OP_SYM)?map_reg(ops[0].sym):-1;
      if (rd<0) { CG_FAIL(e, "POPC requires register"); }
      int is64 = strstr(m,"64") != NULL;
      uint8_t tmp1 = 5, tmp2 = 6;
      uint64_t m1 = is64 ? 0x5555555555555555ULL : 0x55555555ULL;
      uint64_t m2 = is64 ? 0x3333333333333333ULL : 0x33333333ULL;
      uint64_t m4 = is64 ? 0x0F0F0F0F0F0F0F0FULL : 0x0F0F0F0F;
      uint64_t mask = is64 ? 0x7FULL : 0x3FULL;
      if (!is64) {
        emit_mov_imm64(w,&pcw,tmp1,0xFFFFFFFFu);
        w[pcw++] = enc_and_reg(1,(uint8_t)rd,(uint8_t)rd,tmp1);
      }
      emit_mov_imm64(w,&pcw,tmp1,1);
      w[pcw++] = enc_lsrv(is64, tmp2, (uint8_t)rd, tmp1);
      emit_mov_imm64(w,&pcw,tmp1,m1);
      w[pcw++] = enc_and_reg(is64, tmp2, tmp2, tmp1);
      w[pcw++] = enc_sub_reg(is64, (uint8_t)rd, (uint8_t)rd, tmp2);

      emit_mov_imm64(w,&pcw,tmp1,2);
      w[pcw++] = enc_lsrv(is64, tmp2, (uint8_t)rd, tmp1);
      emit_mov_imm64(w,&pcw,tmp1,m2);
      w[pcw++] = enc_and_reg(is64, tmp2, tmp2, tmp1);
      w[pcw++] = enc_and_reg(is64, (uint8_t)rd, (uint8_t)rd, tmp1);
      w[pcw++] = enc_add_reg(is64, (uint8_t)rd, (uint8_t)rd, tmp2);

      emit_mov_imm64(w,&pcw,tmp1,4);
      w[pcw++] = enc_lsrv(is64, tmp2, (uint8_t)rd, tmp1);
      w[pcw++] = enc_add_reg(is64, (uint8_t)rd, (uint8_t)rd, tmp2);
      emit_mov_imm64(w,&pcw,tmp1,m4);
      w[pcw++] = enc_and_reg(is64, (uint8_t)rd, (uint8_t)rd, tmp1);

      emit_mov_imm64(w,&pcw,tmp1,8);
      w[pcw++] = enc_lsrv(is64, tmp2, (uint8_t)rd, tmp1);
      w[pcw++] = enc_add_reg(is64, (uint8_t)rd, (uint8_t)rd, tmp2);
      emit_mov_imm64(w,&pcw,tmp1,16);
      w[pcw++] = enc_lsrv(is64, tmp2, (uint8_t)rd, tmp1);
      w[pcw++] = enc_add_reg(is64, (uint8_t)rd, (uint8_t)rd, tmp2);
      if (is64) {
        emit_mov_imm64(w,&pcw,tmp1,32);
        w[pcw++] = enc_lsrv(is64, tmp2, (uint8_t)rd, tmp1);
        w[pcw++] = enc_add_reg(is64, (uint8_t)rd, (uint8_t)rd, tmp2);
      }
      emit_mov_imm64(w,&pcw,tmp1,mask);
      w[pcw++] = enc_and_reg(is64, (uint8_t)rd, (uint8_t)rd, tmp1);
      continue;
    }

    CG_FAIL(e, "unsupported mnemonic");
  }

  /* Place any auto-reserved symbols that lacked offsets. */
  for (symtab_entry *s = out->syms; s; s = s->next) {
    if (s->off == (size_t)-1) {
      s->off = out->code_len + data_off;
      if (data_off + 8 <= out->data_len) {
        memset(out->data + data_off, 0, 8);
      }
      data_off += 8;
    }
  }

  seen_free(call_targets, n_calls);
  seen_free(label_list, n_labels);
  return 0;
}
