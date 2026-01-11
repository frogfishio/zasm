#include "codegen.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * ARM64 code emitter for Lembeh IR.
 *
 * Notes
 * - Virtual regs map to fixed AArch64 registers.
 * - Supports host "surface primitives" through a vtable pointed to by x9.
 * - Supports symbol addressing via ADRP+ADD plus reloc records (out->relocs).
 * - Load/store unsigned-immediate offsets are encoded with proper scaling
 *   (imm12 is scaled by access size).
 */

/* Virtual reg map */
#define REG_HL 10
#define REG_DE 11
#define REG_A  12
#define REG_BC 13
#define REG_IX 14

/* Temporary registers (caller-saved, avoid x16/x17 IP regs). */
#define REG_TMP1 15
#define REG_TMP2 6

/* Reloc types (consumer/loader patches the immediates). */
#define RELOC_ADRP_PAGE   0u
#define RELOC_ADD_PAGEOFF 1u
#define RELOC_BRANCH26    2u

/* -------------------------------------------------------------------------- */
/* Helpers */

static int emit_adrp_add(cg_blob_t *out, uint32_t *w, size_t *pc, int rd, const char *sym);

static int map_reg(const char *sym) {
  if (!sym) return -1;
  if (strcmp(sym, "HL") == 0) return REG_HL;
  if (strcmp(sym, "DE") == 0) return REG_DE;
  if (strcmp(sym, "A") == 0) return REG_A;
  if (strcmp(sym, "BC") == 0) return REG_BC;
  if (strcmp(sym, "IX") == 0) return REG_IX;
  return -1;
}

/* Unsigned imm12 for add/sub. */
static int imm12_ok(long long v) { return (v >= 0 && v <= 4095); }

/* Unsigned scaled imm12 used by LDR/STR (immediate, unsigned offset).
   scale_log2: 0=byte,1=halfword,2=word,3=dword. */
static int uimm12_scaled(long long off_bytes, int scale_log2, uint32_t *imm12_out) {
  if (off_bytes < 0) return 0;
  long long scale = 1LL << scale_log2;
  if ((off_bytes & (scale - 1)) != 0) return 0; /* alignment */
  long long imm = off_bytes / scale;
  if (imm < 0 || imm > 4095) return 0;
  if (imm12_out) *imm12_out = (uint32_t)imm;
  return 1;
}

/* Signed imm9 for LDUR/STUR (byte offset, -256..255). */
static int count_mov_imm64(uint64_t val) {
  int n = 1;
  uint16_t h1 = (uint16_t)((val >> 16) & 0xFFFFu);
  uint16_t h2 = (uint16_t)((val >> 32) & 0xFFFFu);
  uint16_t h3 = (uint16_t)((val >> 48) & 0xFFFFu);
  if (h1) n++;
  if (h2) n++;
  if (h3) n++;
  return n;
}

static int count_mov_imm32(uint32_t val) {
  int n = 1;
  uint16_t h1 = (uint16_t)((val >> 16) & 0xFFFFu);
  if (h1) n++;
  return n;
}

static int estimate_add_signed_offset(long long off_bytes) {
  if (off_bytes == 0) return 0;
  if (imm12_ok(off_bytes) || imm12_ok(-off_bytes)) return 1;
  return 1 + count_mov_imm64((uint64_t)off_bytes);
}

static void emit_mov_imm32(uint32_t *w, size_t *pc, int rd, uint32_t val) {
  uint16_t h0 = (uint16_t)(val & 0xFFFFu);
  uint16_t h1 = (uint16_t)((val >> 16) & 0xFFFFu);
  w[(*pc)++] = 0x52800000u | ((uint32_t)h0 << 5) | (uint32_t)rd; /* movz wRd,#imm16 */
  if (h1) {
    w[(*pc)++] = 0x72800000u | (1u << 21) | ((uint32_t)h1 << 5) | (uint32_t)rd; /* movk wRd,#imm16,lsl16 */
  }
}

/* Emit a 64-bit immediate into a 64-bit reg using MOVZ/MOVK. */
static void emit_mov_imm64(uint32_t *w, size_t *pc, int rd, uint64_t val) {
  uint16_t h0 = (uint16_t)(val & 0xFFFFu);
  uint16_t h1 = (uint16_t)((val >> 16) & 0xFFFFu);
  uint16_t h2 = (uint16_t)((val >> 32) & 0xFFFFu);
  uint16_t h3 = (uint16_t)((val >> 48) & 0xFFFFu);

  w[(*pc)++] = 0xD2800000u | ((uint32_t)h0 << 5) | (uint32_t)rd; /* movz xRd,#imm16 */
  if (h1) w[(*pc)++] = 0xF2800000u | (1u << 21) | ((uint32_t)h1 << 5) | (uint32_t)rd;
  if (h2) w[(*pc)++] = 0xF2800000u | (2u << 21) | ((uint32_t)h2 << 5) | (uint32_t)rd;
  if (h3) w[(*pc)++] = 0xF2800000u | (3u << 21) | ((uint32_t)h3 << 5) | (uint32_t)rd;
}

/* Add a signed offset to an address register: addr_reg = addr_reg + off.
   Uses tmp_reg as scratch if the immediate cannot be encoded in add/sub imm12. */
static void add_signed_offset(uint32_t *w, size_t *pc, int addr_reg, long long off_bytes, int tmp_reg) {
  if (off_bytes == 0) return;
  if (off_bytes > 0 && imm12_ok(off_bytes)) {
    w[(*pc)++] = 0x91000000u | ((uint32_t)off_bytes << 10) | ((uint32_t)addr_reg << 5) | (uint32_t)addr_reg;
    return;
  }
  if (off_bytes < 0 && imm12_ok(-off_bytes)) {
    w[(*pc)++] = 0xD1000000u | ((uint32_t)(-off_bytes) << 10) | ((uint32_t)addr_reg << 5) | (uint32_t)addr_reg;
    return;
  }
  /* Fallback: materialize offset in tmp_reg, then add. */
  emit_mov_imm64(w, pc, tmp_reg, (uint64_t)off_bytes);
  w[(*pc)++] = 0x8B000000u | ((uint32_t)addr_reg << 16) | ((uint32_t)tmp_reg << 5) | (uint32_t)addr_reg;
}

/* -------------------------------------------------------------------------- */
/* Relocs / symtab */

static void add_reloc(cg_blob_t *out, uint32_t instr_off, uint32_t type, const char *sym) {
  struct cg_reloc *r = (struct cg_reloc *)calloc(1, sizeof(*r));
  if (!r) return;
  r->instr_off = instr_off;
  r->type = type;
  r->sym = sym ? strdup(sym) : NULL;
  r->next = out->relocs;
  out->relocs = r;
  out->reloc_count++;
}

/* Emit ADRP+ADD then load/store using an unsigned scaled imm12 offset if possible,
   otherwise fall back to adding the byte offset (any signed value) and using offset 0. */
static int emit_sym_addr_plus_off(cg_blob_t *out, uint32_t *w, size_t *pc,
                                 int addr_reg, const char *sym,
                                 long long off_bytes, int scale_log2,
                                 uint32_t *imm12_scaled_out) {
  if (!emit_adrp_add(out, w, pc, addr_reg, sym)) return 0;

  /* Prefer keeping the offset in the load/store instruction (scaled imm12). */
  uint32_t imm12 = 0;
  if (uimm12_scaled(off_bytes, scale_log2, &imm12)) {
    if (imm12_scaled_out) *imm12_scaled_out = imm12;
    return 1;
  }

  /* Otherwise, materialize offset in addr_reg. */
  add_signed_offset(w, pc, addr_reg, off_bytes, REG_TMP1);
  if (imm12_scaled_out) *imm12_scaled_out = 0;
  return 1;
}

static void dump_symtab(symtab_entry *root) {
  fprintf(stderr, "[cg] symtab:\n");
  for (symtab_entry *e = root; e; e = e->next) {
    fprintf(stderr, "  %s -> off=%zu\n", e->name ? e->name : "(null)", e->off);
  }
}

symtab_entry *symtab_add(symtab_entry **root, const char *name, size_t off) {
  if (!root || !name) return NULL;
  symtab_entry *e = (symtab_entry *)calloc(1, sizeof(symtab_entry));
  if (!e) return NULL;
  e->name = strdup(name);
  if (!e->name) { free(e); return NULL; }
  e->off = off;
  e->next = *root;
  *root = e;
  return e;
}

static symtab_entry *symtab_find(symtab_entry *root, const char *name) {
  if (!name) return NULL;
  for (symtab_entry *e = root; e; e = e->next) {
    if (e->name && strcmp(e->name, name) == 0) return e;
  }
  return NULL;
}

static int emit_adrp_add(cg_blob_t *out, uint32_t *w, size_t *pc, int rd, const char *sym) {
  if (!sym || !out || !w || !pc) return 0;
  if (map_reg(sym) >= 0) {
    fprintf(stderr, "[cg][ERR] register name '%s' used as symbol\n", sym);
    return 0;
  }

  symtab_entry *se = symtab_find(out->syms, sym);
  if (!se) {
    // add as extern
    if (!symtab_add(&out->syms, sym, 0)) return 0;
    se = symtab_find(out->syms, sym);
  }

  // always use placeholders and relocs for relocatable .o
  w[*pc] = 0x90000000u | (uint32_t)rd;
  add_reloc(out, (uint32_t)((*pc) * 4), RELOC_ADRP_PAGE, sym);
  (*pc)++;
  w[*pc] = 0x91000000u | ((uint32_t)rd << 5) | (uint32_t)rd;
  add_reloc(out, (uint32_t)((*pc) * 4), RELOC_ADD_PAGEOFF, sym);
  (*pc)++;
  return 1;
}

static void symtab_free(symtab_entry *root) {
  while (root) {
    symtab_entry *n = root->next;
    free(root->name);
    free(root);
    root = n;
  }
}

/* -------------------------------------------------------------------------- */
/* Microcode expansions */

static void emit_memcpy_loop(uint32_t *w, size_t *pc, int dst, int src, int len) {
  /*
   * Simple byte loop:
   *   while (len != 0) { tmp = *(src); *(dst) = tmp; src++; dst++; len--; }
   *
   * Registers:
   *   dst = x<dst>, src = x<src>, len = w<len>, tmp = w<tmp>
   */
  int tmp = REG_TMP1; /* scratch */
  size_t loop = *pc;

  /* subs wzr, wlen, #0 */
  w[(*pc)++] = 0x7100001Fu | ((uint32_t)len << 5);

  /* beq end (patched) */
  int beq_slot = (int)(*pc);
  w[(*pc)++] = 0x54000000u;

  /* ldrb wtmp, [xsrc] */
  w[(*pc)++] = 0x39400000u | ((uint32_t)src << 5) | (uint32_t)tmp;

  /* strb wtmp, [xdst] */
  w[(*pc)++] = 0x39000000u | (uint32_t)tmp | ((uint32_t)dst << 5);

  /* add xsrc, xsrc, #1 */
  w[(*pc)++] = 0x91000400u | ((uint32_t)src << 5) | (uint32_t)src;

  /* add xdst, xdst, #1 */
  w[(*pc)++] = 0x91000400u | ((uint32_t)dst << 5) | (uint32_t)dst;

  /* sub wlen, wlen, #1 */
  w[(*pc)++] = 0x51000400u | ((uint32_t)len << 5) | (uint32_t)len;

  /* b loop */
  int64_t disp_back = ((int64_t)loop * 4) - ((int64_t)(*pc) * 4);
  w[(*pc)++] = 0x14000000u | ((uint32_t)(disp_back / 4) & 0x03FFFFFFu);

  /* patch beq to end */
  int64_t disp_end = ((int64_t)(*pc) * 4) - ((int64_t)beq_slot * 4);
  w[beq_slot] = 0x54000000u | (((uint32_t)(disp_end / 4) & 0x7FFFFu) << 5);
}

/* -------------------------------------------------------------------------- */
/* Sizing pass (must match emission exactly) */

static int host_vtable_index(const char *sym) {
  if (!sym) return -1;
  if (strcmp(sym, "req_read") == 0 || strcmp(sym, "_in") == 0) return 0;
  if (strcmp(sym, "res_write") == 0 || strcmp(sym, "_out") == 0) return 1;
  if (strcmp(sym, "res_end") == 0) return 2;
  if (strcmp(sym, "log") == 0 || strcmp(sym, "_log") == 0) return 3;
  if (strcmp(sym, "_alloc") == 0) return 4;
  if (strcmp(sym, "_free") == 0) return 5;
  if (strcmp(sym, "_ctl") == 0) return 6;
  return -1;
}

static int estimate_call_words(const ir_entry_t *e, size_t total_data_len) {
  if (!e || e->kind != IR_CALL) return 0;
  if (!e->sym) return -1;

  int host_idx = host_vtable_index(e->sym);
  if (host_idx >= 0) {
    /* BL + args */
    int words = 1; /* BL */
    if (host_idx == 1) {
      /* res_write(res=1, ptr=0, len=total_data_len) */
      words += count_mov_imm32(1u);
      words += count_mov_imm32(0u);
      words += count_mov_imm32((uint32_t)total_data_len);
    } else if (host_idx == 0 || host_idx == 2) {
      words += count_mov_imm32(1u);
    } else {
      words += count_mov_imm32(0u);
    }
    return words;
  }

  /* non-host call: single BL */
  return 1;
}

static int estimate_instr_words(const ir_entry_t *e, size_t total_data_len) {
  if (!e) return 0;
  if (e->kind == IR_LABEL) return 0;
  if (e->kind == IR_RET) return 2;
  if (e->kind == IR_CALL) return estimate_call_words(e, total_data_len);
  if (e->kind != IR_INSTR) return 0;

  const char *m = e->mnem ? e->mnem : "";
  ir_op_t *ops = e->ops;
  size_t nops = e->op_count;

  int has_off = (nops >= 3 && ops[2].kind == IR_OP_NUM);
  long long off_bytes = (has_off ? ops[2].num : 0);

  if (strcmp(m, "ADD") == 0 || strcmp(m, "SUB") == 0 || strcmp(m, "MUL") == 0 ||
      strcmp(m, "ADD64") == 0 || strcmp(m, "SUB64") == 0 || strcmp(m, "MUL64") == 0) return 1;

  if (strcmp(m, "DIVS") == 0 || strcmp(m, "DIVS64") == 0 ||
      strcmp(m, "DIVU") == 0 || strcmp(m, "DIVU64") == 0) {
    int extra = 0;
    if (nops >= 2 && ops[1].kind == IR_OP_NUM) extra = count_mov_imm64((uint64_t)ops[1].unum);
    return 1 + extra;
  }

  if (strcmp(m, "REMS") == 0 || strcmp(m, "REMS64") == 0 ||
      strcmp(m, "REMU") == 0 || strcmp(m, "REMU64") == 0) {
    int extra = 0;
    if (nops >= 2 && ops[1].kind == IR_OP_NUM) extra = count_mov_imm64((uint64_t)ops[1].unum);
    return 3 + extra; /* div + mul + sub */
  }

  if (strcmp(m, "CP") == 0) return 1;
  if (strcmp(m, "JR") == 0) return 1;

  if (strcmp(m, "EQ") == 0 || strcmp(m, "NE") == 0 || strcmp(m, "LTS") == 0 || strcmp(m, "GTS") == 0 ||
      strcmp(m, "LES") == 0 || strcmp(m, "GES") == 0 ||
      strcmp(m, "LTU") == 0 || strcmp(m, "GTU") == 0 ||
      strcmp(m, "LEU") == 0 || strcmp(m, "GEU") == 0 ||
      strcmp(m, "EQ64") == 0 || strcmp(m, "NE64") == 0 ||
      strcmp(m, "LTS64") == 0 || strcmp(m, "GTS64") == 0 ||
      strcmp(m, "LES64") == 0 || strcmp(m, "GES64") == 0 ||
      strcmp(m, "LTU64") == 0 || strcmp(m, "GTU64") == 0 ||
      strcmp(m, "LEU64") == 0 || strcmp(m, "GEU64") == 0) return 2; /* cmp + cset */

  if (strcmp(m, "AND") == 0 || strcmp(m, "OR") == 0 || strcmp(m, "XOR") == 0 ||
      strcmp(m, "AND64") == 0 || strcmp(m, "OR64") == 0 || strcmp(m, "XOR64") == 0) return 1;

  if (strcmp(m, "SLA") == 0 || strcmp(m, "SRL") == 0 || strcmp(m, "SRA") == 0 ||
      strcmp(m, "SLA64") == 0 || strcmp(m, "SRL64") == 0 || strcmp(m, "SRA64") == 0) return 1;

  if (strcmp(m, "CLZ") == 0 || strcmp(m, "CLZ64") == 0) return 1;
  if (strcmp(m, "CTZ") == 0 || strcmp(m, "CTZ64") == 0) return 2;

  if (strcmp(m, "POPC") == 0 || strcmp(m, "POPC64") == 0) {
    int is64 = (strstr(m, "64") != NULL);
    int count = 10;
    count += count_mov_imm64(is64 ? 0x5555555555555555ULL : 0x55555555ULL);
    count += count_mov_imm64(is64 ? 0x3333333333333333ULL : 0x33333333ULL);
    count += count_mov_imm64(is64 ? 0x0F0F0F0F0F0F0F0FULL : 0x0F0F0F0FULL);
    count += count_mov_imm64(is64 ? 0x0101010101010101ULL : 0x01010101ULL);
    return count;
  }

  if (strcmp(m, "ROL") == 0 || strcmp(m, "ROL64") == 0 ||
      strcmp(m, "ROR") == 0 || strcmp(m, "ROR64") == 0) {
    int count = 1; /* rorv */
    if (nops >= 2 && ops[1].kind == IR_OP_NUM) count += count_mov_imm64((uint64_t)ops[1].unum);
    if (strncmp(m, "ROL", 3) == 0) {
      count += 1; /* sub */
      count += count_mov_imm64(strstr(m, "64") ? 64u : 32u);
    }
    return count;
  }

  /* LD: immediate, address-of symbol, or mem (64-bit load). */
  if (strcmp(m, "LD") == 0) {
    if (nops >= 2 && ops[1].kind == IR_OP_NUM) return count_mov_imm64((uint64_t)ops[1].unum);

    if (nops >= 2 && ops[1].kind == IR_OP_SYM) {
      /* address-of symbol: adrp+add */
      return 2;
    }

    if (nops >= 2 && ops[1].kind == IR_OP_MEM) {
      const char *base = ops[1].sym;
      int base_reg = map_reg(base);
      if (base_reg >= 0) {
        /* register base: ldr (maybe unscaled) */
        uint32_t imm12 = 0;
        if (uimm12_scaled(off_bytes, 3, &imm12)) return 1;
        return 1 /* mov tmp,base */ + estimate_add_signed_offset(off_bytes) + 1; /* ldr [tmp] */
      }
      /* symbol base: adrp+add + maybe extra add + ldr */
      uint32_t imm12 = 0;
      if (uimm12_scaled(off_bytes, 3, &imm12)) return 3; /* keep offset in ldr */
      return 2 /* adrp+add */ + estimate_add_signed_offset(off_bytes) + 1; /* extra add + ldr [0] */
    }

    return -1;
  }

  /* Sized loads: LD8U/LD8S/LD16U/LD16S/LD32/LD64 and 64-bit-ext variants. */
  if (strncmp(m, "LD", 2) == 0 && strcmp(m, "LD") != 0) {
    if (nops < 2 || ops[1].kind != IR_OP_MEM) return -1;

    const char *base = ops[1].sym;
    int base_reg = map_reg(base);
    if (base_reg >= 0) {
      uint32_t imm12 = 0;
      int scale = 0;
      if (strcmp(m, "LD16U") == 0 || strcmp(m, "LD16S") == 0 ||
          strcmp(m, "LD16U64") == 0 || strcmp(m, "LD16S64") == 0) scale = 1;
      else if (strcmp(m, "LD32") == 0 || strcmp(m, "LD32U64") == 0 || strcmp(m, "LD32S64") == 0) scale = 2;
      else if (strcmp(m, "LD64") == 0) scale = 3;
      else scale = 0;
      if (uimm12_scaled(off_bytes, scale, &imm12)) return 1;
      return 1 /* mov tmp,base */ + estimate_add_signed_offset(off_bytes) + 1;
    }

    /* symbol base: adrp+add + maybe add + load */
    int scale = 0;
    if (strcmp(m, "LD16U") == 0 || strcmp(m, "LD16S") == 0 ||
        strcmp(m, "LD16U64") == 0 || strcmp(m, "LD16S64") == 0) scale = 1;
    else if (strcmp(m, "LD32") == 0 || strcmp(m, "LD32U64") == 0 || strcmp(m, "LD32S64") == 0) scale = 2;
    else if (strcmp(m, "LD64") == 0) scale = 3;
    else scale = 0; /* byte */

    uint32_t imm12 = 0;
    if (uimm12_scaled(off_bytes, scale, &imm12)) return 3; /* keep offset in load */
    return 2 /* adrp+add */ + estimate_add_signed_offset(off_bytes) + 1;
  }

  /* Stores: ST8/ST16/ST32/ST64 */
  if (strncmp(m, "ST", 2) == 0) {
    if (nops < 2) return -1;

    /* Accept either operand order: STxx mem,reg  OR  STxx reg,mem */
    size_t mem_i = (ops[0].kind == IR_OP_MEM) ? 0 : ((ops[1].kind == IR_OP_MEM) ? 1 : (size_t)-1);
    size_t reg_i = (ops[0].kind == IR_OP_SYM) ? 0 : ((ops[1].kind == IR_OP_SYM) ? 1 : (size_t)-1);
    if (mem_i == (size_t)-1 || reg_i == (size_t)-1) return -1;

    const char *base = ops[mem_i].sym;
    int base_reg = map_reg(base);
    if (base_reg >= 0) {
      uint32_t imm12 = 0;
      int scale = 0;
      if (strcmp(m, "ST16") == 0) scale = 1;
      else if (strcmp(m, "ST32") == 0) scale = 2;
      else if (strcmp(m, "ST64") == 0) scale = 3;
      if (uimm12_scaled(off_bytes, scale, &imm12)) return 1;
      return 1 /* mov tmp,base */ + estimate_add_signed_offset(off_bytes) + 1;
    }

    int scale = 0;
    if (strcmp(m, "ST16") == 0) scale = 1;
    else if (strcmp(m, "ST32") == 0) scale = 2;
    else if (strcmp(m, "ST64") == 0) scale = 3;

    uint32_t imm12 = 0;
    if (uimm12_scaled(off_bytes, scale, &imm12)) return 3; /* adrp+add+str imm */
    return 2 /* adrp+add */ + estimate_add_signed_offset(off_bytes) + 1;
  }

  if (strcmp(m, "LDIR") == 0) return 16;
  if (strcmp(m, "FILL") == 0) return 6;

  return -1;
}

/* -------------------------------------------------------------------------- */
/* Main emitter */

int cg_emit_arm64(const ir_prog_t *ir, cg_blob_t *out) {
  memset(out, 0, sizeof *out);

  /* Concatenate DATA blobs. */
  size_t total = 0;
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_DATA_BYTES) total += e->data_len;
  }
  out->data_len = total;
  out->data = (unsigned char *)malloc(total ? total : 1);
  if (!out->data) return -1;

  size_t doff = 0;
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_DATA_BYTES && e->data_len) {
      memcpy(out->data + doff, e->data, e->data_len);
      doff += e->data_len;
    }
  }

  /* First pass: assign label offsets and count instructions (prologue + body + epilogue). */
  size_t pc = 0;

  /* Prologue: stp fp,lr; mov x10,x0; mov x11,x1 */
  pc += 3;

  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_LABEL) {
      if (!symtab_add(&out->syms, e->sym, pc * 4)) goto fail;
      continue;
    }
    int words = estimate_instr_words(e, total);
    if (words < 0) {
      fprintf(stderr, "[cg][ERR] unsupported instr %s\n", e->mnem ? e->mnem : "(null)");
      goto fail;
    }
    pc += (size_t)words;
  }

  /* Epilogue: restore and ret (2 instr). */
  pc += 2;
  if (pc == 0) pc = 1;

  size_t epilogue_pc = pc - 2;
  out->code_len = pc * 4;
  out->data_off = out->code_len;
  size_t data_offset = 0;
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_DATA_BYTES && e->data_len) {
      if (e->sym && !symtab_add(&out->syms, e->sym, out->data_off + data_offset)) goto fail;
      data_offset += e->data_len;
    }
  }
  out->code = (unsigned char *)calloc(1, out->code_len);
  if (!out->code) goto fail;
  uint32_t *w = (uint32_t *)out->code;

  /* Second pass: emit */
  pc = 0;

  /* prologue */
  w[pc++] = 0xA9BF7BFDu; /* stp x29,x30,[sp,#-16]! */
  w[pc++] = 0xAA0003EAu; /* mov x10,x0 */
  w[pc++] = 0xAA0103EBu; /* mov x11,x1 */

  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_LABEL) continue;

    if (e->kind == IR_CALL) {
      if (!e->sym) { fprintf(stderr, "[cg][ERR] CALL missing target\n"); goto fail; }

      int host_idx = host_vtable_index(e->sym);
      if (host_idx >= 0) {
        /* Marshal basic ABI args as 32-bit (zero-extended via W regs). */
        if (host_idx == 1) { /* res_write */
          emit_mov_imm32(w, &pc, 0, 1u);                 /* res handle */
          emit_mov_imm32(w, &pc, 1, 0u);                 /* ptr */
          emit_mov_imm32(w, &pc, 2, (uint32_t)total);    /* len */
        } else if (host_idx == 0 || host_idx == 2) {     /* req_read / res_end */
          emit_mov_imm32(w, &pc, 0, 1u);
        } else {
          emit_mov_imm32(w, &pc, 0, 0u);
        }
        /* BL to symbol with reloc MUST follow args immediately. */
        w[pc++] = 0x94000000u; /* BL imm26=0 */
        add_reloc(out, (uint32_t)((pc-1) * 4), RELOC_BRANCH26, e->sym);
        continue;
      }

      /* Non-host: branch to label */
      symtab_entry *target = symtab_find(out->syms, e->sym);
      if (!target) {
        fprintf(stderr, "[cg][ERR] unknown call target: %s\n", e->sym);
        goto fail;
      }
      size_t curr_off = pc * 4;
      int64_t disp = (int64_t)target->off - (int64_t)curr_off;
      int32_t imm26 = (int32_t)(disp / 4);
      w[pc++] = 0x94000000u | ((uint32_t)imm26 & 0x03FFFFFFu); /* bl target */
      continue;
    }

    if (e->kind == IR_RET) {
      /* mov w0,#0 then branch to epilogue */
      w[pc++] = 0x52800000u; /* mov w0,#0 */
      size_t curr_off = pc * 4;
      int64_t disp = (int64_t)(epilogue_pc * 4) - (int64_t)curr_off;
      int32_t imm26 = (int32_t)(disp / 4);
      w[pc++] = 0x14000000u | ((uint32_t)imm26 & 0x03FFFFFFu);
      continue;
    }

    if (e->kind != IR_INSTR) continue;

    const char *m = e->mnem ? e->mnem : "";
    ir_op_t *ops = e->ops;
    size_t nops = e->op_count;

    int rd = -1, rs = -1;
    long long imm = 0;
    if (nops >= 1 && ops[0].kind == IR_OP_SYM) rd = map_reg(ops[0].sym);
    if (nops >= 2 && ops[1].kind == IR_OP_SYM) rs = map_reg(ops[1].sym);
    if (nops >= 2 && ops[1].kind == IR_OP_NUM) imm = ops[1].num;

    if (strcmp(m, "ADD") == 0 || strcmp(m, "SUB") == 0 || strcmp(m, "MUL") == 0 ||
        strcmp(m, "ADD64") == 0 || strcmp(m, "SUB64") == 0 || strcmp(m, "MUL64") == 0) {
      if (rd < 0) { fprintf(stderr, "[cg][ERR] %s dest\n", m); goto fail; }
      int is64 = (strstr(m, "64") != NULL);

      if ((strcmp(m, "MUL") == 0 || strcmp(m, "MUL64") == 0) && rs < 0) {
        fprintf(stderr, "[cg][ERR] MUL imm unsupported\n");
        goto fail;
      }

      if (strncmp(m, "ADD", 3) == 0) {
        if (rs >= 0) {
          w[pc++] = (is64 ? 0x8B000000u : 0x0B000000u) |
                    ((uint32_t)rs << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
        } else if (imm12_ok(imm)) {
          w[pc++] = (is64 ? 0x91000000u : 0x11000000u) |
                    ((uint32_t)imm << 10) | ((uint32_t)rd << 5) | (uint32_t)rd;
        } else {
          emit_mov_imm64(w, &pc, REG_TMP1, (uint64_t)imm);
          w[pc++] = (is64 ? 0x8B000000u : 0x0B000000u) |
                    ((uint32_t)REG_TMP1 << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
        }
      } else if (strncmp(m, "SUB", 3) == 0) {
        if (rs >= 0) {
          w[pc++] = (is64 ? 0xCB000000u : 0x4B000000u) |
                    ((uint32_t)rs << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
        } else if (imm12_ok(imm)) {
          w[pc++] = (is64 ? 0xD1000000u : 0x51000000u) |
                    ((uint32_t)imm << 10) | ((uint32_t)rd << 5) | (uint32_t)rd;
        } else {
          emit_mov_imm64(w, &pc, REG_TMP1, (uint64_t)imm);
          w[pc++] = (is64 ? 0xCB000000u : 0x4B000000u) |
                    ((uint32_t)REG_TMP1 << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
        }
      } else { /* MUL */
        w[pc++] = (is64 ? 0x9B007C00u : 0x1B007C00u) |
                  ((uint32_t)rs << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
      }
      continue;
    }

    if (strcmp(m, "DIVS") == 0 || strcmp(m, "DIVS64") == 0 ||
        strcmp(m, "DIVU") == 0 || strcmp(m, "DIVU64") == 0 ||
        strcmp(m, "REMS") == 0 || strcmp(m, "REMS64") == 0 ||
        strcmp(m, "REMU") == 0 || strcmp(m, "REMU64") == 0) {
      if (rd < 0) { fprintf(stderr, "[cg][ERR] %s dest\n", m); goto fail; }

      int is64 = (strstr(m, "64") != NULL);
      int is_signed = (strcmp(m, "DIVS") == 0 || strcmp(m, "DIVS64") == 0 ||
                       strcmp(m, "REMS") == 0 || strcmp(m, "REMS64") == 0);
      int is_rem = (strncmp(m, "REM", 3) == 0);

      int rhs_reg = rs;
      if (rhs_reg < 0) {
        if (!(nops >= 2 && ops[1].kind == IR_OP_NUM)) { fprintf(stderr, "[cg][ERR] %s rhs\n", m); goto fail; }
        rhs_reg = REG_TMP1;
        emit_mov_imm64(w, &pc, rhs_reg, (uint64_t)ops[1].unum);
      }

      uint32_t div_instr = is_signed
        ? (is64 ? 0x9AC00C00u : 0x1AC00C00u)
        : (is64 ? 0x9AC00800u : 0x1AC00800u);

      if (is_rem) {
        int qreg = REG_TMP2;
        w[pc++] = div_instr | ((uint32_t)rhs_reg << 16) | ((uint32_t)rd << 5) | (uint32_t)qreg;
        uint32_t mul_instr = is64 ? 0x9B007C00u : 0x1B007C00u;
        w[pc++] = mul_instr | ((uint32_t)rhs_reg << 16) | ((uint32_t)qreg << 5) | (uint32_t)qreg;
        uint32_t sub_instr = is64 ? 0xCB000000u : 0x4B000000u;
        w[pc++] = sub_instr | ((uint32_t)qreg << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
      } else {
        w[pc++] = div_instr | ((uint32_t)rhs_reg << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
      }
      continue;
    }

    if (strcmp(m, "CP") == 0) {
      if (rd < 0) { fprintf(stderr, "[cg][ERR] CP missing reg\n"); goto fail; }
      if (rs >= 0) {
        w[pc++] = 0x6B00001Fu | ((uint32_t)rs << 16) | ((uint32_t)rd << 5); /* cmp w */
      } else if (imm12_ok(imm)) {
        w[pc++] = 0x7100001Fu | ((uint32_t)imm << 10) | ((uint32_t)rd << 5);
      } else {
        emit_mov_imm64(w, &pc, REG_TMP1, (uint64_t)imm);
        w[pc++] = 0x6B00001Fu | ((uint32_t)REG_TMP1 << 16) | ((uint32_t)rd << 5);
      }
      continue;
    }

    if (strcmp(m, "JR") == 0) {
      if (nops == 1 && ops[0].kind == IR_OP_SYM) {
        symtab_entry *target = symtab_find(out->syms, ops[0].sym);
        if (!target) { fprintf(stderr, "[cg][ERR] JR target %s\n", ops[0].sym); goto fail; }
        size_t curr_off = pc * 4;
        int64_t disp = (int64_t)target->off - (int64_t)curr_off;
        int32_t imm26 = (int32_t)(disp / 4);
        w[pc++] = 0x14000000u | ((uint32_t)imm26 & 0x03FFFFFFu);
        continue;
      } else if (nops == 2 && ops[0].kind == IR_OP_SYM && ops[1].kind == IR_OP_SYM) {
        const char *cond = ops[0].sym;
        symtab_entry *target = symtab_find(out->syms, ops[1].sym);
        if (!target) { fprintf(stderr, "[cg][ERR] JR target %s\n", ops[1].sym); goto fail; }

        uint32_t br = 0;
        if (strcmp(cond, "EQ") == 0) br = 0x54000000u;
        else if (strcmp(cond, "NE") == 0) br = 0x54000001u;
        else if (strcmp(cond, "LTS") == 0) br = 0x5400000Bu; /* LT (signed) */
        else if (strcmp(cond, "GTS") == 0) br = 0x5400000Cu; /* GT (signed) */
        else if (strcmp(cond, "LES") == 0) br = 0x5400000Du; /* LE (signed) */
        else if (strcmp(cond, "GES") == 0) br = 0x5400000Au; /* GE (signed) */
        else if (strcmp(cond, "LTU") == 0) br = 0x54000003u; /* LO */
        else if (strcmp(cond, "GTU") == 0) br = 0x54000008u; /* HI */
        else if (strcmp(cond, "LEU") == 0) br = 0x54000009u; /* LS */
        else if (strcmp(cond, "GEU") == 0) br = 0x54000002u; /* HS */
        else { fprintf(stderr, "[cg][ERR] JR cond %s\n", cond); goto fail; }

        size_t curr_off = pc * 4;
        int64_t disp = (int64_t)target->off - (int64_t)curr_off;
        int32_t imm19 = (int32_t)(disp / 4);
        if (imm19 < -0x40000 || imm19 > 0x3FFFF) { fprintf(stderr, "[cg][ERR] JR range\n"); goto fail; }
        w[pc++] = br | ((uint32_t)(imm19 & 0x7FFFF) << 5);
        continue;
      } else {
        fprintf(stderr, "[cg][ERR] JR operands\n");
        goto fail;
      }
    }

    if (strcmp(m, "EQ") == 0 || strcmp(m, "NE") == 0 || strcmp(m, "LTS") == 0 || strcmp(m, "GTS") == 0 ||
        strcmp(m, "LES") == 0 || strcmp(m, "GES") == 0 ||
        strcmp(m, "LTU") == 0 || strcmp(m, "GTU") == 0 ||
        strcmp(m, "LEU") == 0 || strcmp(m, "GEU") == 0 ||
        strcmp(m, "EQ64") == 0 || strcmp(m, "NE64") == 0 ||
        strcmp(m, "LTS64") == 0 || strcmp(m, "GTS64") == 0 ||
        strcmp(m, "LES64") == 0 || strcmp(m, "GES64") == 0 ||
        strcmp(m, "LTU64") == 0 || strcmp(m, "GTU64") == 0 ||
        strcmp(m, "LEU64") == 0 || strcmp(m, "GEU64") == 0) {
      int is64 = (strstr(m, "64") != NULL);
      if (rd < 0 || (rs < 0 && !imm12_ok(imm))) { fprintf(stderr, "[cg][ERR] %s ops\n", m); goto fail; }

      /* cmp */
      if (rs >= 0) {
        w[pc++] = (is64 ? 0xEB00001Fu : 0x6B00001Fu) |
                  ((uint32_t)rs << 16) | ((uint32_t)rd << 5);
      } else {
        w[pc++] = (is64 ? 0xF100001Fu : 0x7100001Fu) |
                  ((uint32_t)(imm & 0xFFF) << 10) | ((uint32_t)rd << 5);
      }

      uint32_t cset = 0;
      if (strcmp(m, "EQ") == 0 || strcmp(m, "EQ64") == 0) cset = 0x1A9F07E0u;
      else if (strcmp(m, "NE") == 0 || strcmp(m, "NE64") == 0) cset = 0x1A9F17E0u;
      else if (strcmp(m, "LTS") == 0 || strcmp(m, "LTS64") == 0) cset = 0x1A9F97E0u;
      else if (strcmp(m, "GTS") == 0 || strcmp(m, "GTS64") == 0) cset = 0x1A9FA7E0u;
      else if (strcmp(m, "LES") == 0 || strcmp(m, "LES64") == 0) cset = 0x1A9FB7E0u; /* LE */
      else if (strcmp(m, "GES") == 0 || strcmp(m, "GES64") == 0) cset = 0x1A9F87E0u; /* GE */
      else if (strcmp(m, "LTU") == 0 || strcmp(m, "LTU64") == 0) cset = 0x1A9F37E0u; /* LO */
      else if (strcmp(m, "GTU") == 0 || strcmp(m, "GTU64") == 0) cset = 0x1A9F57E0u; /* HI */
      else if (strcmp(m, "LEU") == 0 || strcmp(m, "LEU64") == 0) cset = 0x1A9F5FE0u; /* LS */
      else if (strcmp(m, "GEU") == 0 || strcmp(m, "GEU64") == 0) cset = 0x1A9F27E0u; /* HS */

      w[pc++] = cset | ((uint32_t)rd << 5);
      continue;
    }

    if (strcmp(m, "AND") == 0 || strcmp(m, "OR") == 0 || strcmp(m, "XOR") == 0 ||
        strcmp(m, "AND64") == 0 || strcmp(m, "OR64") == 0 || strcmp(m, "XOR64") == 0) {
      if (rd < 0 || rs < 0) { fprintf(stderr, "[cg][ERR] %s requires regs\n", m); goto fail; }
      int is64 = (strstr(m, "64") != NULL);
      uint32_t op = 0;
      if (strncmp(m, "AND", 3) == 0) op = is64 ? 0x8A000000u : 0x0A000000u;
      else if (strncmp(m, "OR", 2) == 0) op = is64 ? 0xAA000000u : 0x2A000000u;
      else op = is64 ? 0xCA000000u : 0x4A000000u;
      w[pc++] = op | ((uint32_t)rs << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
      continue;
    }

    if (strcmp(m, "SLA") == 0 || strcmp(m, "SRL") == 0 || strcmp(m, "SRA") == 0 ||
        strcmp(m, "SLA64") == 0 || strcmp(m, "SRL64") == 0 || strcmp(m, "SRA64") == 0) {
      if (rd < 0 || rs < 0) { fprintf(stderr, "[cg][ERR] %s requires regs\n", m); goto fail; }
      int is64 = (strstr(m, "64") != NULL);
      uint32_t op = 0;
      if (strncmp(m, "SLA", 3) == 0) op = is64 ? 0x9AC02000u : 0x1AC02000u; /* lslv */
      else if (strncmp(m, "SRL", 3) == 0) op = is64 ? 0x9AC02400u : 0x1AC02400u; /* lsrv */
      else op = is64 ? 0x9AC02800u : 0x1AC02800u; /* asrv */
      w[pc++] = op | ((uint32_t)rs << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
      continue;
    }

    if (strcmp(m, "CLZ") == 0 || strcmp(m, "CLZ64") == 0 ||
        strcmp(m, "CTZ") == 0 || strcmp(m, "CTZ64") == 0) {
      if (rd < 0) { fprintf(stderr, "[cg][ERR] %s requires reg\n", m); goto fail; }
      int is64 = (strstr(m, "64") != NULL);
      uint32_t clz = is64 ? 0xDAC01000u : 0x5AC01000u;
      if (strncmp(m, "CTZ", 3) == 0) {
        uint32_t rbit = is64 ? 0xDAC00000u : 0x5AC00000u;
        w[pc++] = rbit | ((uint32_t)rd << 5) | (uint32_t)rd;
      }
      w[pc++] = clz | ((uint32_t)rd << 5) | (uint32_t)rd;
      continue;
    }

    if (strcmp(m, "POPC") == 0 || strcmp(m, "POPC64") == 0) {
      if (rd < 0) { fprintf(stderr, "[cg][ERR] %s requires reg\n", m); goto fail; }

      int is64 = (strstr(m, "64") != NULL);
      uint64_t mask1 = is64 ? 0x5555555555555555ULL : 0x55555555ULL;
      uint64_t mask2 = is64 ? 0x3333333333333333ULL : 0x33333333ULL;
      uint64_t mask3 = is64 ? 0x0F0F0F0F0F0F0F0FULL : 0x0F0F0F0FULL;
      uint64_t mulc  = is64 ? 0x0101010101010101ULL : 0x01010101ULL;
      int shift_final = is64 ? 56 : 24;

      /* x = x - ((x >> 1) & mask1) */
      emit_mov_imm64(w, &pc, REG_TMP1, mask1);
      w[pc++] = (is64 ? 0xD37DF800u : 0x531F7800u) | ((uint32_t)rd << 5) | (uint32_t)REG_TMP2; /* lsr tmp2, rd, #1 */
      w[pc++] = (is64 ? 0x8A200000u : 0x0A200000u) |
                ((uint32_t)REG_TMP1 << 16) | ((uint32_t)REG_TMP2 << 5) | (uint32_t)REG_TMP2;
      w[pc++] = (is64 ? 0xCB000000u : 0x4B000000u) |
                ((uint32_t)REG_TMP2 << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;

      /* (x & mask2) + ((x >> 2) & mask2) */
      emit_mov_imm64(w, &pc, REG_TMP1, mask2);
      w[pc++] = (is64 ? 0xD37E0000u : 0x531F8000u) | ((uint32_t)rd << 5) | (uint32_t)REG_TMP2; /* lsr tmp2, rd, #2 */
      w[pc++] = (is64 ? 0x8A200000u : 0x0A200000u) |
                ((uint32_t)REG_TMP1 << 16) | ((uint32_t)REG_TMP2 << 5) | (uint32_t)REG_TMP2;
      w[pc++] = (is64 ? 0x8A200000u : 0x0A200000u) |
                ((uint32_t)REG_TMP1 << 16) | ((uint32_t)rd << 5) | (uint32_t)REG_TMP1;
      w[pc++] = (is64 ? 0x8B000000u : 0x0B000000u) |
                ((uint32_t)REG_TMP2 << 16) | ((uint32_t)REG_TMP1 << 5) | (uint32_t)rd;

      /* x = (x + (x >> 4)) & mask3 */
      w[pc++] = (is64 ? 0xD37E4000u : 0x531FC000u) | ((uint32_t)rd << 5) | (uint32_t)REG_TMP2; /* lsr tmp2, rd, #4 */
      w[pc++] = (is64 ? 0x8B000000u : 0x0B000000u) |
                ((uint32_t)REG_TMP2 << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
      emit_mov_imm64(w, &pc, REG_TMP1, mask3);
      w[pc++] = (is64 ? 0x8A200000u : 0x0A200000u) |
                ((uint32_t)REG_TMP1 << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;

      /* rd = (rd * mulc) >> shift_final */
      emit_mov_imm64(w, &pc, REG_TMP1, mulc);
      w[pc++] = (is64 ? 0x9B007C00u : 0x1B007C00u) |
                ((uint32_t)REG_TMP1 << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
      w[pc++] = (is64 ? 0xD37F0000u : 0x531F0000u) |
                ((uint32_t)shift_final << 10) | ((uint32_t)rd << 5) | (uint32_t)rd;
      continue;
    }

    if (strcmp(m, "ROL") == 0 || strcmp(m, "ROL64") == 0 ||
        strcmp(m, "ROR") == 0 || strcmp(m, "ROR64") == 0) {
      if (rd < 0) { fprintf(stderr, "[cg][ERR] %s requires reg\n", m); goto fail; }
      int is64 = (strstr(m, "64") != NULL);

      int shift_reg = rs;
      if (nops < 2) { fprintf(stderr, "[cg][ERR] %s shift missing\n", m); goto fail; }

      if (ops[1].kind == IR_OP_NUM) {
        shift_reg = REG_TMP1;
        emit_mov_imm64(w, &pc, shift_reg, (uint64_t)ops[1].unum);
      } else if (shift_reg < 0) {
        fprintf(stderr, "[cg][ERR] %s shift reg\n", m);
        goto fail;
      }

      int final_shift_reg = shift_reg;
      if (strncmp(m, "ROL", 3) == 0) {
        emit_mov_imm64(w, &pc, REG_TMP2, is64 ? 64u : 32u);
        uint32_t subi = is64 ? 0xD1000000u : 0x51000000u;
        w[pc++] = subi | ((uint32_t)shift_reg << 16) | ((uint32_t)REG_TMP2 << 5) | (uint32_t)REG_TMP2; /* tmp2 = width - shift */
        final_shift_reg = REG_TMP2;
      }

      uint32_t rorv = is64 ? 0x9AC02C00u : 0x1AC02C00u;
      w[pc++] = rorv | ((uint32_t)final_shift_reg << 16) | ((uint32_t)rd << 5) | (uint32_t)rd;
      continue;
    }

    /* LD (load 64-bit value): immediate, symbol, or mem. */
    if (strcmp(m, "LD") == 0) {
      if (rd < 0 || nops < 2) { fprintf(stderr, "[cg][ERR] LD ops\n"); goto fail; }

      /* Check for register move: LD reg, reg */
      int rs = -1;
      if (ops[1].kind == IR_OP_SYM) rs = map_reg(ops[1].sym);
      if (rs >= 0) {
        w[pc++] = 0xAA0003E0u | ((uint32_t)rs << 16) | ((uint32_t)rd << 5) | (uint32_t)rd; /* mov xRd, xRs */
        continue;
      }

      if (ops[1].kind == IR_OP_NUM) {
        emit_mov_imm64(w, &pc, rd, (uint64_t)ops[1].unum);
        continue;
      }

      if (ops[1].kind == IR_OP_SYM) {
        const char *sym = ops[1].sym;
        /* Address-of symbol: just compute address, no dereference. */
        if (!emit_adrp_add(out, w, &pc, rd, sym)) goto fail;
        continue;
      }

      if (ops[1].kind == IR_OP_MEM) {
        const char *base = ops[1].sym;
        long long off_bytes = 0;
        if (nops >= 3 && ops[2].kind == IR_OP_NUM) off_bytes = ops[2].num;

        int base_reg = map_reg(base);
        if (base_reg >= 0) {
          uint32_t imm12 = 0;
          if (uimm12_scaled(off_bytes, 3, &imm12)) {
            w[pc++] = 0xF9400000u | (imm12 << 10) | ((uint32_t)base_reg << 5) | (uint32_t)rd; /* ldr xRd,[xBase,#imm] */
          } else {
            /* tmp = base; tmp += off_bytes; ldr [tmp] */
            int tmp = REG_TMP1;
            w[pc++] = 0xAA0003E0u | ((uint32_t)base_reg << 16) | ((uint32_t)tmp << 5) | (uint32_t)tmp; /* mov tmp,base */
            add_signed_offset(w, &pc, tmp, off_bytes, REG_TMP2);
            w[pc++] = 0xF9400000u | ((uint32_t)tmp << 5) | (uint32_t)rd;
          }
          continue;
        }

        /* symbol base */
        uint32_t imm12 = 0;
        if (!emit_sym_addr_plus_off(out, w, &pc, rd, base, off_bytes, 3, &imm12)) goto fail;
        w[pc++] = 0xF9400000u | (imm12 << 10) | ((uint32_t)rd << 5) | (uint32_t)rd;
        continue;
      }

      fprintf(stderr, "[cg][ERR] LD unsupported operand kind\n");
      goto fail;
    }

    /* Sized loads. */
    if (strncmp(m, "LD", 2) == 0 && strcmp(m, "LD") != 0) {
      if (rd < 0 || nops < 2 || ops[1].kind != IR_OP_MEM) { fprintf(stderr, "[cg][ERR] %s ops\n", m); goto fail; }

      const char *base = ops[1].sym;
      long long off_bytes = 0;
      if (nops >= 3 && ops[2].kind == IR_OP_NUM) off_bytes = ops[2].num;

      /* Determine encoding + scale. */
      uint32_t instr = 0;
      int scale = 0;

      if (strcmp(m, "LD8U") == 0)      { instr = 0x39400000u; scale = 0; } /* ldrb w */
      else if (strcmp(m, "LD8S") == 0) { instr = 0x39C00000u; scale = 0; } /* ldrsb w */
      else if (strcmp(m, "LD16U") == 0){ instr = 0x79400000u; scale = 1; } /* ldrh w */
      else if (strcmp(m, "LD16S") == 0){ instr = 0x79C00000u; scale = 1; } /* ldrsh w */
      else if (strcmp(m, "LD32") == 0) { instr = 0xB9400000u; scale = 2; } /* ldr w */
      else if (strcmp(m, "LD64") == 0) { instr = 0xF9400000u; scale = 3; } /* ldr x */

      else if (strcmp(m, "LD8U64") == 0)   { instr = 0x39400000u; scale = 0; } /* ldrb w (zero-extends) */
      else if (strcmp(m, "LD8S64") == 0)   { instr = 0x39800000u; scale = 0; } /* ldrsb x */
      else if (strcmp(m, "LD16U64") == 0)  { instr = 0x79400000u; scale = 1; } /* ldrh w (zero-extends) */
      else if (strcmp(m, "LD16S64") == 0)  { instr = 0x79800000u; scale = 1; } /* ldrsh x */
      else if (strcmp(m, "LD32U64") == 0)  { instr = 0xB9400000u; scale = 2; } /* ldr w (zero-extends) */
      else if (strcmp(m, "LD32S64") == 0)  { instr = 0xB9800000u; scale = 2; } /* ldrsw x */
      else { fprintf(stderr, "[cg][ERR] load kind %s\n", m); goto fail; }

      /* If base is a register name, use base register addressing. */
      int base_reg = map_reg(base);
      if (base_reg >= 0) {
        uint32_t imm12 = 0;
        if (uimm12_scaled(off_bytes, scale, &imm12)) {
          w[pc++] = instr | (imm12 << 10) | ((uint32_t)base_reg << 5) | (uint32_t)rd;
        } else {
          int tmp = REG_TMP1;
          w[pc++] = 0xAA0003E0u | ((uint32_t)base_reg << 16) | ((uint32_t)tmp << 5) | (uint32_t)tmp; /* mov tmp,base */
          add_signed_offset(w, &pc, tmp, off_bytes, REG_TMP2);
          w[pc++] = instr | ((uint32_t)tmp << 5) | (uint32_t)rd;
        }
        continue;
      }

      /* Symbolic base: ADRP+ADD then load with scaled imm12 if possible. */
      uint32_t imm12 = 0;
      if (!emit_sym_addr_plus_off(out, w, &pc, rd, base, off_bytes, scale, &imm12)) goto fail;
      w[pc++] = instr | (imm12 << 10) | ((uint32_t)rd << 5) | (uint32_t)rd;
      continue;
    }

    /* Stores. */
    if (strncmp(m, "ST", 2) == 0) {
      if (nops < 2) { fprintf(stderr, "[cg][ERR] %s ops\n", m); goto fail; }

      /* Accept either operand order: STxx mem,reg  OR  STxx reg,mem */
      size_t mem_i = (ops[0].kind == IR_OP_MEM) ? 0 : ((ops[1].kind == IR_OP_MEM) ? 1 : (size_t)-1);
      size_t reg_i = (ops[0].kind == IR_OP_SYM) ? 0 : ((ops[1].kind == IR_OP_SYM) ? 1 : (size_t)-1);
      if (mem_i == (size_t)-1 || reg_i == (size_t)-1) { fprintf(stderr, "[cg][ERR] %s ops\n", m); goto fail; }

      int rs2 = map_reg(ops[reg_i].sym);
      if (rs2 < 0) { fprintf(stderr, "[cg][ERR] %s reg\n", m); goto fail; }

      const char *base = ops[mem_i].sym;
      long long off_bytes = 0;
      if (nops >= 3 && ops[2].kind == IR_OP_NUM) off_bytes = ops[2].num;

      uint32_t instr = 0;
      int scale = 0;

      if (strcmp(m, "ST8") == 0)      { instr = 0x39000000u; scale = 0; } /* strb w */
      else if (strcmp(m, "ST16") == 0){ instr = 0x79000000u; scale = 1; } /* strh w */
      else if (strcmp(m, "ST32") == 0){ instr = 0xB9000000u; scale = 2; } /* str w */
      else if (strcmp(m, "ST64") == 0){ instr = 0xF9000000u; scale = 3; } /* str x */
      else { fprintf(stderr, "[cg][ERR] store kind %s\n", m); goto fail; }

      int base_reg = map_reg(base);
      if (base_reg >= 0) {
        uint32_t imm12 = 0;
        if (uimm12_scaled(off_bytes, scale, &imm12)) {
          w[pc++] = instr | (uint32_t)rs2 | ((uint32_t)base_reg << 5) | (imm12 << 10);
        } else {
          int tmp = REG_TMP1;
          w[pc++] = 0xAA0003E0u | ((uint32_t)base_reg << 16) | ((uint32_t)tmp << 5) | (uint32_t)tmp; /* mov tmp,base */
          add_signed_offset(w, &pc, tmp, off_bytes, REG_TMP2);
          w[pc++] = instr | (uint32_t)rs2 | ((uint32_t)tmp << 5);
        }
        continue;
      }

      /* Symbolic base uses x14 (IX) as scratch address reg. */
      int tmp = REG_IX;
      uint32_t imm12 = 0;
      if (!emit_sym_addr_plus_off(out, w, &pc, tmp, base, off_bytes, scale, &imm12)) goto fail;
      w[pc++] = instr | (uint32_t)rs2 | (imm12 << 10) | ((uint32_t)tmp << 5);
      continue;
    }

    if (strcmp(m, "LDIR") == 0 || strcmp(m, "FILL") == 0) {
      int dst = REG_DE;
      int src = REG_HL;
      int len = REG_BC;

      if (strcmp(m, "LDIR") == 0) {
        emit_memcpy_loop(w, &pc, dst, src, len);
      } else {
        /* fill: while (len != 0) { strb wA,[dst]; dst++; len--; } */
        size_t loop_label = pc;

        w[pc++] = 0x7100001Fu | ((uint32_t)len << 5); /* subs wZR,wlen,#0 */
        w[pc++] = 0x540000A0u; /* beq +5 instructions (to after the back-branch) */
        w[pc++] = 0x39000000u | ((uint32_t)REG_A) | ((uint32_t)dst << 5); /* strb wA,[dst] */
        w[pc++] = 0x91000400u | ((uint32_t)dst << 5) | (uint32_t)dst;     /* add dst,#1 */
        w[pc++] = 0x51000400u | ((uint32_t)len << 5) | (uint32_t)len;     /* sub len,#1 */

        int64_t disp = ((int64_t)loop_label * 4) - ((int64_t)pc * 4);
        int32_t imm26 = (int32_t)(disp / 4);
        w[pc++] = 0x14000000u | ((uint32_t)imm26 & 0x03FFFFFFu); /* b loop */
      }
      continue;
    }

    fprintf(stderr, "[cg][ERR] unsupported instr %s\n", m);
    goto fail;
  }

  /* epilogue */
  w[pc++] = 0xA8C17BFDu; /* ldp x29,x30,[sp],#16 */
  w[pc++] = 0xD65F03C0u; /* ret */

  out->code_len = pc * 4;

  /* Ensure a handle symbol exists (expected by some runtimes). */
  if (!symtab_find(out->syms, "lembeh_handle")) {
    if (!symtab_add(&out->syms, "lembeh_handle", 0)) goto fail;
  }

  dump_symtab(out->syms);
  fprintf(stderr, "[cg] code_len=%zu data_len=%zu\n", out->code_len, out->data_len);
  return 0;

fail:
  symtab_free(out->syms);
  out->syms = NULL;
  free(out->code);
  free(out->data);

  struct cg_reloc *r = out->relocs;
  while (r) {
    struct cg_reloc *n = r->next;
    free(r->sym);
    free(r);
    r = n;
  }

  memset(out, 0, sizeof *out);
  return -1;
}

void cg_free(cg_blob_t *b) {
  if (!b) return;
  free(b->code);
  free(b->data);

  struct cg_reloc *r = b->relocs;
  while (r) {
    struct cg_reloc *n = r->next;
    free(r->sym);
    free(r);
    r = n;
  }

  if (b->syms) symtab_free(b->syms);
  memset(b, 0, sizeof *b);
}
