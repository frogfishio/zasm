/* Minimal self-contained JSON-IR -> arm64 static library emitter.
 * Phase 1: parse IR, verify lembeh_handle PUBLIC, emit stub code/data, and
 * archive into a static lib. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <mach-o/arm64/reloc.h>
#include "json_ir.h"
#include "ir.h"
#include "codegen.h"

static void log_info(const char* msg) { fprintf(stderr, "[zingcc] %s\n", msg); }
static void log_err(const char* msg) { fprintf(stderr, "[zingcc][ERR] %s\n", msg); }
static void log_errf(const char* fmt, const char* a) {
  fprintf(stderr, "[zingcc][ERR] ");
  fprintf(stderr, fmt, a);
  fprintf(stderr, "\n");
}


static size_t align_up(size_t x, size_t a) {
  size_t mask = a - 1;
  return (x + mask) & ~mask;
}

static int sym_is(const char* a, const char* b) {
  return (a && b && strcmp(a, b) == 0);
}

/* Names that codegen may add to blob.syms as extern placeholders; do NOT treat as local labels/data. */
static int is_codegen_extern_name(const char* name) {
  if (!name) return 0;
  return sym_is(name, "lembeh_guest_mem") || sym_is(name, "_lembeh_guest_mem") ||
         sym_is(name, "req_read") || sym_is(name, "_req_read") || sym_is(name, "_in") ||
         sym_is(name, "res_write") || sym_is(name, "_res_write") || sym_is(name, "_out") ||
         sym_is(name, "res_end") || sym_is(name, "_res_end") ||
         sym_is(name, "log") || sym_is(name, "_log") ||
         sym_is(name, "_alloc") || sym_is(name, "_free") || sym_is(name, "_ctl");
}

/* Resolve a relocation symbol name to a symbol-table index in this file's layout.
 * Indices:
 *   0=_lembeh_handle, 1=_lembeh_guest_mem,
 *   2=_req_read, 3=_res_write, 4=_res_end,
 *   5=_log, 6=_alloc, 7=_free, 8=_ctl,
 *   then local labels/data.
 */
static int resolve_sym_index(const cg_blob_t* blob, const char* rsym, uint32_t* sym_index_out) {
  if (!blob || !rsym || !sym_index_out) return 0;

  /* Fixed symbols / aliases */
  if (sym_is(rsym, "lembeh_handle") || sym_is(rsym, "_lembeh_handle")) {
    *sym_index_out = 0;
    return 1;
  }
  if (sym_is(rsym, "lembeh_guest_mem") || sym_is(rsym, "_lembeh_guest_mem")) {
    *sym_index_out = 1;
    return 1;
  }
  if (sym_is(rsym, "req_read") || sym_is(rsym, "_req_read") || sym_is(rsym, "_in")) {
    *sym_index_out = 2;
    return 1;
  }
  if (sym_is(rsym, "res_write") || sym_is(rsym, "_res_write") || sym_is(rsym, "_out")) {
    *sym_index_out = 3;
    return 1;
  }
  if (sym_is(rsym, "res_end") || sym_is(rsym, "_res_end")) {
    *sym_index_out = 4;
    return 1;
  }
  if (sym_is(rsym, "log") || sym_is(rsym, "_log")) {
    *sym_index_out = 5;
    return 1;
  }
  if (sym_is(rsym, "_alloc")) {
    *sym_index_out = 6;
    return 1;
  }
  if (sym_is(rsym, "_free")) {
    *sym_index_out = 7;
    return 1;
  }
  if (sym_is(rsym, "_ctl")) {
    *sym_index_out = 8;
    return 1;
  }

  /* Local labels/data from blob->syms, skipping handle + known extern-placeholder names. */
  uint32_t idx = 9;
  for (symtab_entry* s = blob->syms; s; s = s->next) {
    if (!s->name) continue;
    if (sym_is(s->name, "lembeh_handle")) continue;
    if (is_codegen_extern_name(s->name)) continue;
    if (sym_is(s->name, rsym)) {
      *sym_index_out = idx;
      return 1;
    }
    idx++;
  }

  return 0;
}

/* Map codegen reloc type to Mach-O ARM64 relocation type + pcrel bit. */
static int resolve_reloc_encoding(uint32_t cg_type, uint8_t* macho_r_type, uint8_t* macho_pcrel) {
  if (!macho_r_type || !macho_pcrel) return 0;
  switch (cg_type) {
    case 0: /* RELOC_ADRP_PAGE */
      *macho_r_type = ARM64_RELOC_PAGE21;
      *macho_pcrel = 1;
      return 1;
    case 1: /* RELOC_ADD_PAGEOFF */
      *macho_r_type = ARM64_RELOC_PAGEOFF12;
      *macho_pcrel = 0;
      return 1;
    case 2: /* RELOC_BRANCH26 */
      *macho_r_type = ARM64_RELOC_BRANCH26;
      *macho_pcrel = 1;
      return 1;
    default:
      return 0;
  }
}

static int run_cmd(char* const argv[]) {
  pid_t pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    execvp(argv[0], argv);
    _exit(127);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) return -1;
  return status;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <input.jsonl> [out.a]\n", argv[0]);
    return 1;
  }
  const char* in = argv[1];
  const char* out = (argc >= 3) ? argv[2] : "build/zingcc/libguest.a";

  /* Parse IR */
  ir_prog_t prog;
  ir_init(&prog);
  FILE* fp = fopen(in, "r");
  if (!fp) {
    log_errf("cannot open IR %s", in);
    return 1;
  }
  if (json_ir_read(fp, &prog) != 0) {
    log_err("failed to parse IR");
    fclose(fp);
    return 1;
  }
  fclose(fp);
  if (!prog.has_public_lembeh) {
    log_err("input missing PUBLIC lembeh_handle");
    ir_free(&prog);
    return 1;
  }

  char build_dir[] = "build/zingcc";
  struct stat st_dir;
  if (stat(build_dir, &st_dir) != 0) {
    if (mkdir(build_dir, 0777) != 0) {
      perror("mkdir build/zingcc");
      ir_free(&prog);
      return 1;
    }
  }

  const char* obj_path = "build/zingcc/guest.o";

  /* Emit code/data blobs. */
  log_info("codegen…");
  cg_blob_t blob;
  if (cg_emit_arm64(&prog, &blob) != 0) {
    fprintf(stderr, "codegen failed\n");
    ir_free(&prog);
    return 1;
  }
  ir_free(&prog);
  fprintf(stderr, "[zingcc] code_len=%zu data_len=%zu\n", blob.code_len, blob.data_len);
  /* Build a minimal Mach-O object in-memory and write to guest.o. */
  /* Section ordering: 1 = __text, 2 = __data */
  size_t header_size = sizeof(struct mach_header_64);
  size_t cmd_buildver_size = sizeof(struct build_version_command);
  size_t cmd_text_size = sizeof(struct segment_command_64) + sizeof(struct section_64);
  size_t cmd_data_size = sizeof(struct segment_command_64) + sizeof(struct section_64);
  size_t cmd_sym_size  = sizeof(struct symtab_command);
  size_t load_size = cmd_buildver_size + cmd_text_size + cmd_data_size + cmd_sym_size;

  size_t text_off = align_up(header_size + load_size, 4);
  size_t text_size = blob.code_len;

  /* Reserve a fixed 8-byte slot at the start of __data for the guest-mem pointer symbol. */
  const size_t guest_mem_slot = 8;

  size_t data_off = align_up(text_off + text_size, 4);
  size_t data_size = blob.data_len + guest_mem_slot;

  /* Relocations (text section only for ADRP/ADD) */
  size_t reloc_entry_size = sizeof(struct relocation_info);
  size_t reloc_count = 0;
  /* Count valid relocs (must match emission exactly). */
  struct cg_reloc *r = blob.relocs;
  while (r) {
    uint32_t sym_index = 0;
    uint8_t r_type = 0;
    uint8_t pcrel = 0;

    if (!resolve_sym_index(&blob, r->sym, &sym_index)) {
      fprintf(stderr, "[zingcc][ERR] unknown reloc symbol %s\n", r->sym ? r->sym : "(null)");
      cg_free(&blob);
      return 1;
    }

    if (!resolve_reloc_encoding(r->type, &r_type, &pcrel)) {
      fprintf(stderr, "[zingcc][ERR] unsupported reloc type=%u for %s\n", r->type, r->sym ? r->sym : "(null)");
      cg_free(&blob);
      return 1;
    }

    reloc_count++;
    fprintf(stderr, "[zingcc][RELOC] %s\n", r->sym);
    r = r->next;
  }
  size_t reloc_bytes = reloc_entry_size * reloc_count;
  size_t reloc_off = align_up(data_off + data_size, 4);

  /* Collect additional symbols from codegen symtab (labels/data), skipping lembeh_handle and codegen externs. */
  size_t label_count = 0;
  for (symtab_entry* s = blob.syms; s; s = s->next) {
    if (s->name && strcmp(s->name, "lembeh_handle") != 0 && !is_codegen_extern_name(s->name)) {
      label_count++;
    }
  }

  /* Symbols:
   * 0=_lembeh_handle (__text), 1=_lembeh_guest_mem (__data),
   * 2=_req_read (undef), 3=_res_write (undef), 4=_res_end (undef),
   * 5=_log (undef), 6=_alloc (undef), 7=_free (undef), 8=_ctl (undef),
   * then local labels/data.
   */
  uint32_t nsyms = 9 + (uint32_t)label_count;
  size_t symbytes = nsyms * sizeof(struct nlist_64);
  size_t symoff = align_up(reloc_off + reloc_bytes, 4);

  /* Build string table up front so we have deterministic offsets. */
  const char* name_handle = "_lembeh_handle";
  const char* name_mem    = "_lembeh_guest_mem";
  const char* name_req    = "_req_read";
  const char* name_resw   = "_res_write";
  const char* name_rese   = "_res_end";
  const char* name_log    = "_log";
  const char* name_alloc  = "_alloc";
  const char* name_free   = "_free";
  const char* name_ctl    = "_ctl";
  size_t strbuf_cap = 64 + strlen(name_handle) + strlen(name_mem) + strlen(name_req) +
                      strlen(name_resw) + strlen(name_rese) + strlen(name_log) +
                      strlen(name_alloc) + strlen(name_free) + strlen(name_ctl) + 1;
  uint32_t *label_strx = NULL;
  if (label_count) {
    label_strx = (uint32_t *)calloc(label_count, sizeof(uint32_t));
    if (!label_strx) { cg_free(&blob); return 1; }
  }
  for (symtab_entry* s = blob.syms; s; s = s->next) {
    if (s->name && strcmp(s->name, "lembeh_handle") != 0 && !is_codegen_extern_name(s->name)) {
      strbuf_cap += strlen(s->name) + 1;
    }
  }
  char *strbuf = (char *)calloc(1, strbuf_cap);
  if (!strbuf) { free(label_strx); cg_free(&blob); return 1; }
  size_t strbuf_len = 0;
  /* leading NUL */
  strbuf[strbuf_len++] = '\0';

  uint32_t strx_handle = (uint32_t)strbuf_len;
  memcpy(strbuf + strbuf_len, name_handle, strlen(name_handle) + 1);
  strbuf_len += strlen(name_handle) + 1;

  uint32_t strx_mem = (uint32_t)strbuf_len;
  memcpy(strbuf + strbuf_len, name_mem, strlen(name_mem) + 1);
  strbuf_len += strlen(name_mem) + 1;

  uint32_t strx_req = (uint32_t)strbuf_len;
  memcpy(strbuf + strbuf_len, name_req, strlen(name_req) + 1);
  strbuf_len += strlen(name_req) + 1;

  uint32_t strx_resw = (uint32_t)strbuf_len;
  memcpy(strbuf + strbuf_len, name_resw, strlen(name_resw) + 1);
  strbuf_len += strlen(name_resw) + 1;

  uint32_t strx_rese = (uint32_t)strbuf_len;
  memcpy(strbuf + strbuf_len, name_rese, strlen(name_rese) + 1);
  strbuf_len += strlen(name_rese) + 1;

  uint32_t strx_log = (uint32_t)strbuf_len;
  memcpy(strbuf + strbuf_len, name_log, strlen(name_log) + 1);
  strbuf_len += strlen(name_log) + 1;

  uint32_t strx_alloc = (uint32_t)strbuf_len;
  memcpy(strbuf + strbuf_len, name_alloc, strlen(name_alloc) + 1);
  strbuf_len += strlen(name_alloc) + 1;

  uint32_t strx_free = (uint32_t)strbuf_len;
  memcpy(strbuf + strbuf_len, name_free, strlen(name_free) + 1);
  strbuf_len += strlen(name_free) + 1;

  uint32_t strx_ctl = (uint32_t)strbuf_len;
  memcpy(strbuf + strbuf_len, name_ctl, strlen(name_ctl) + 1);
  strbuf_len += strlen(name_ctl) + 1;
  /* Append label/data names */
  {
    size_t idx = 0;
    for (symtab_entry* s = blob.syms; s; s = s->next) {
      if (s->name && strcmp(s->name, "lembeh_handle") != 0 && !is_codegen_extern_name(s->name)) {
        label_strx[idx++] = (uint32_t)strbuf_len;
        memcpy(strbuf + strbuf_len, s->name, strlen(s->name) + 1);
        strbuf_len += strlen(s->name) + 1;
      }
    }
  }
  uint32_t strsize = (uint32_t)strbuf_len;

  /* Sanity checks */
  if (strx_handle == 0 || strx_handle >= strsize) { log_err("invalid strx_handle"); free(strbuf); free(label_strx); cg_free(&blob); return 1; }
  if (strx_mem == 0 || strx_mem >= strsize) { log_err("invalid strx_mem"); free(strbuf); free(label_strx); cg_free(&blob); return 1; }
  if (strx_req == 0 || strx_req >= strsize) { log_err("invalid strx_req"); free(strbuf); free(label_strx); cg_free(&blob); return 1; }
  if (strx_resw == 0 || strx_resw >= strsize) { log_err("invalid strx_resw"); free(strbuf); free(label_strx); cg_free(&blob); return 1; }
  if (strx_rese == 0 || strx_rese >= strsize) { log_err("invalid strx_rese"); free(strbuf); free(label_strx); cg_free(&blob); return 1; }
  if (strx_log == 0 || strx_log >= strsize) { log_err("invalid strx_log"); free(strbuf); free(label_strx); cg_free(&blob); return 1; }
  if (strx_alloc == 0 || strx_alloc >= strsize) { log_err("invalid strx_alloc"); free(strbuf); free(label_strx); cg_free(&blob); return 1; }
  if (strx_free == 0 || strx_free >= strsize) { log_err("invalid strx_free"); free(strbuf); free(label_strx); cg_free(&blob); return 1; }
  if (strx_ctl == 0 || strx_ctl >= strsize) { log_err("invalid strx_ctl"); free(strbuf); free(label_strx); cg_free(&blob); return 1; }

  size_t stroff = align_up(symoff + symbytes, 4);
  size_t file_size = stroff + strsize;

  /* Build entire object in-memory for a single write. */
  uint8_t *buf = (uint8_t *)calloc(1, file_size);
  if (!buf) { free(strbuf); free(label_strx); cg_free(&blob); return 1; }
  uint8_t *p = buf;

  /* Header */
  struct mach_header_64 mh = {0};
  mh.magic = MH_MAGIC_64;
  mh.cputype = CPU_TYPE_ARM64;
  mh.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
  mh.filetype = MH_OBJECT;
  mh.ncmds = 4;
  mh.sizeofcmds = (uint32_t)load_size;
  mh.flags = 0;
  memcpy(p, &mh, sizeof mh); p += sizeof mh;

  /* LC_BUILD_VERSION to satisfy linker platform requirements. */
  struct build_version_command bvc = {0};
  bvc.cmd = LC_BUILD_VERSION;
  bvc.cmdsize = (uint32_t)cmd_buildver_size;
  bvc.platform = PLATFORM_MACOS;
  bvc.minos = 0x000C0000; /* 12.0.0 */
  bvc.sdk = 0x000C0000;   /* 12.0.0 */
  bvc.ntools = 0;
  memcpy(p, &bvc, sizeof bvc); p += sizeof bvc;

  /* __TEXT segment + __text section */
  struct segment_command_64 seg_text = {0};
  seg_text.cmd = LC_SEGMENT_64;
  seg_text.cmdsize = (uint32_t)cmd_text_size;
  strncpy(seg_text.segname, "__TEXT", sizeof seg_text.segname);
  seg_text.vmaddr = 0;
  seg_text.vmsize = align_up(text_size, 4);
  seg_text.fileoff = text_off;
  seg_text.filesize = text_size;
  seg_text.maxprot = VM_PROT_READ | VM_PROT_EXECUTE;
  seg_text.initprot = VM_PROT_READ | VM_PROT_EXECUTE;
  seg_text.nsects = 1;
  memcpy(p, &seg_text, sizeof seg_text); p += sizeof seg_text;

  struct section_64 sec_text = {0};
  strncpy(sec_text.sectname, "__text", sizeof sec_text.sectname);
  strncpy(sec_text.segname, "__TEXT", sizeof sec_text.segname);
  sec_text.addr = 0;
  sec_text.size = text_size;
  sec_text.offset = (uint32_t)text_off;
  sec_text.align = 2; /* 4-byte alignment (2^2) */
  sec_text.reloff = reloc_count ? (uint32_t)reloc_off : 0;
  sec_text.nreloc = (uint32_t)reloc_count;
  sec_text.flags = S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
  memcpy(p, &sec_text, sizeof sec_text); p += sizeof sec_text;

  /* __DATA segment + __data section */
  struct segment_command_64 seg_data = {0};
  seg_data.cmd = LC_SEGMENT_64;
  seg_data.cmdsize = (uint32_t)cmd_data_size;
  strncpy(seg_data.segname, "__DATA", sizeof seg_data.segname);
  seg_data.vmaddr = 0;
  seg_data.vmsize = align_up(data_size, 4);
  seg_data.fileoff = data_off;
  seg_data.filesize = data_size;
  seg_data.maxprot = VM_PROT_READ | VM_PROT_WRITE;
  seg_data.initprot = VM_PROT_READ | VM_PROT_WRITE;
  seg_data.nsects = 1;
  memcpy(p, &seg_data, sizeof seg_data); p += sizeof seg_data;

  struct section_64 sec_data = {0};
  strncpy(sec_data.sectname, "__data", sizeof sec_data.sectname);
  strncpy(sec_data.segname, "__DATA", sizeof sec_data.segname);
  sec_data.addr = 0;
  sec_data.size = data_size;
  sec_data.offset = (uint32_t)data_off;
  sec_data.align = 2; /* 4-byte alignment */
  sec_data.reloff = 0;
  sec_data.nreloc = 0;
  sec_data.flags = S_REGULAR;
  memcpy(p, &sec_data, sizeof sec_data); p += sizeof sec_data;

  /* LC_SYMTAB */
  struct symtab_command st_sym = {0};
  st_sym.cmd = LC_SYMTAB;
  st_sym.cmdsize = sizeof st_sym;
  st_sym.symoff = (uint32_t)symoff;
  st_sym.nsyms = nsyms;
  st_sym.stroff = (uint32_t)stroff;
  st_sym.strsize = strsize;
  memcpy(p, &st_sym, sizeof st_sym); p += sizeof st_sym;

  /* Pad to text_off */
  size_t curr = (size_t)(p - buf);
  if (curr > text_off) {
    fprintf(stderr, "[zingcc][ERR] text_off underflow\n");
    free(strbuf); free(label_strx); free(buf); cg_free(&blob);
    return 1;
  }
  memset(p, 0, text_off - curr);
  p += (text_off - curr);
  memcpy(p, blob.code, blob.code_len); p += blob.code_len;

  curr = (size_t)(p - buf);
  if (curr > data_off) {
    fprintf(stderr, "[zingcc][ERR] data_off underflow\n");
    free(strbuf); free(label_strx); free(buf); cg_free(&blob);
    return 1;
  }
  memset(p, 0, data_off - curr);
  p += (data_off - curr);
  /* First 8 bytes are the _lembeh_guest_mem slot (initialized to 0), followed by IR data bytes. */
  memset(p, 0, guest_mem_slot);
  p += guest_mem_slot;
  memcpy(p, blob.data, blob.data_len);
  p += blob.data_len;

  /* Pad to reloc_off and emit relocations (before the symbol table). */
  curr = (size_t)(p - buf);
  if (curr > reloc_off) {
    fprintf(stderr, "[zingcc][ERR] reloc_off underflow\n");
    free(strbuf); free(label_strx); free(buf); cg_free(&blob);
    return 1;
  }
  memset(p, 0, reloc_off - curr);
  p += (reloc_off - curr);

  if (reloc_count) {
    /* Symbol index lookup: 0 handle, 1 mem, 2 req_read, 3 res_write, 4 res_end, 5 log, 6 alloc, 7 free, 8 ctl, then labels/data. */
    struct cg_reloc *r = blob.relocs;
    while (r) {
      uint32_t sym_index = 0;
      uint8_t r_type = 0;
      uint8_t pcrel = 0;

      if (!resolve_sym_index(&blob, r->sym, &sym_index)) {
        fprintf(stderr, "[zingcc][ERR] unknown reloc symbol %s\n", r->sym ? r->sym : "(null)");
        free(strbuf);
        free(label_strx);
        free(buf);
        cg_free(&blob);
        return 1;
      }

      if (!resolve_reloc_encoding(r->type, &r_type, &pcrel)) {
        fprintf(stderr, "[zingcc][ERR] unsupported reloc type=%u for %s\n", r->type, r->sym ? r->sym : "(null)");
        free(strbuf);
        free(label_strx);
        free(buf);
        cg_free(&blob);
        return 1;
      }

      struct relocation_info ri = {0};
      ri.r_address = r->instr_off;          /* section-relative offset (text section starts at 0) */
      ri.r_extern = 1;                      /* use symbol table index */
      ri.r_symbolnum = sym_index;
      ri.r_pcrel = pcrel;
      ri.r_length = 2;                      /* 2^2 = 4 bytes */
      ri.r_type = r_type;
      memcpy(p, &ri, sizeof ri);
      p += sizeof ri;

      r = r->next;
    }
  }

  /* Pad to symoff (symbols must live after relocations). */
  curr = (size_t)(p - buf);
  if (curr > symoff) {
    fprintf(stderr, "[zingcc][ERR] symoff underflow\n");
    free(strbuf); free(label_strx); free(buf); cg_free(&blob);
    return 1;
  }
  memset(p, 0, symoff - curr);
  p += (symoff - curr);

  /* Emit symbols: fixed first nine. */
  /* Resolve lembeh_handle offset inside the generated __text. */
  size_t handle_off = 0;
  int have_handle_off = 0;
  for (symtab_entry* s = blob.syms; s; s = s->next) {
    if (s->name && strcmp(s->name, "lembeh_handle") == 0) {
      handle_off = s->off;
      have_handle_off = 1;
      break;
    }
  }
  if (!have_handle_off || handle_off >= blob.code_len) {
    fprintf(stderr, "[zingcc][ERR] codegen missing/invalid lembeh_handle offset\n");
    free(strbuf);
    free(label_strx);
    free(buf);
    cg_free(&blob);
    return 1;
  }
  struct nlist_64 n_handle = {0};
  n_handle.n_un.n_strx = strx_handle;
  n_handle.n_type = N_SECT | N_EXT;
  n_handle.n_sect = 1; /* __text */
  n_handle.n_desc = 0;
  n_handle.n_value = sec_text.addr + handle_off;

  struct nlist_64 n_mem = {0};
  n_mem.n_un.n_strx = strx_mem;
  n_mem.n_type = N_SECT | N_EXT;
  n_mem.n_sect = 2; /* __data */
  n_mem.n_desc = 0;
  n_mem.n_value = sec_data.addr;

  struct nlist_64 n_req = {0};
  n_req.n_un.n_strx = strx_req;
  n_req.n_type = N_EXT | N_UNDF;
  n_req.n_sect = 0;
  n_req.n_desc = 0;
  n_req.n_value = 0;

  struct nlist_64 n_resw = {0};
  n_resw.n_un.n_strx = strx_resw;
  n_resw.n_type = N_EXT | N_UNDF;
  n_resw.n_sect = 0;
  n_resw.n_desc = 0;
  n_resw.n_value = 0;

  struct nlist_64 n_rese = {0};
  n_rese.n_un.n_strx = strx_rese;
  n_rese.n_type = N_EXT | N_UNDF;
  n_rese.n_sect = 0;
  n_rese.n_desc = 0;
  n_rese.n_value = 0;

  struct nlist_64 n_log = {0};
  n_log.n_un.n_strx = strx_log;
  n_log.n_type = N_EXT | N_UNDF;
  n_log.n_sect = 0;
  n_log.n_desc = 0;
  n_log.n_value = 0;

  struct nlist_64 n_alloc = {0};
  n_alloc.n_un.n_strx = strx_alloc;
  n_alloc.n_type = N_EXT | N_UNDF;
  n_alloc.n_sect = 0;
  n_alloc.n_desc = 0;
  n_alloc.n_value = 0;

  struct nlist_64 n_free = {0};
  n_free.n_un.n_strx = strx_free;
  n_free.n_type = N_EXT | N_UNDF;
  n_free.n_sect = 0;
  n_free.n_desc = 0;
  n_free.n_value = 0;

  struct nlist_64 n_ctl = {0};
  n_ctl.n_un.n_strx = strx_ctl;
  n_ctl.n_type = N_EXT | N_UNDF;
  n_ctl.n_sect = 0;
  n_ctl.n_desc = 0;
  n_ctl.n_value = 0;

  memcpy(p, &n_handle, sizeof n_handle); p += sizeof n_handle;
  memcpy(p, &n_mem, sizeof n_mem); p += sizeof n_mem;
  memcpy(p, &n_req, sizeof n_req); p += sizeof n_req;
  memcpy(p, &n_resw, sizeof n_resw); p += sizeof n_resw;
  memcpy(p, &n_rese, sizeof n_rese); p += sizeof n_rese;
  memcpy(p, &n_log, sizeof n_log); p += sizeof n_log;
  memcpy(p, &n_alloc, sizeof n_alloc); p += sizeof n_alloc;
  memcpy(p, &n_free, sizeof n_free); p += sizeof n_free;
  memcpy(p, &n_ctl, sizeof n_ctl); p += sizeof n_ctl;

  /* Emit label symbols using recorded string offsets. */
  if (label_count > 0) {
    size_t lbl_idx = 0;
    for (symtab_entry* s = blob.syms; s; s = s->next) {
      if (!s->name || strcmp(s->name, "lembeh_handle") == 0 || is_codegen_extern_name(s->name)) continue;
      struct nlist_64 n = {0};
      n.n_un.n_strx = label_strx[lbl_idx++];
      n.n_type = N_SECT; /* local */
      if (s->off < blob.code_len) {
        n.n_sect = 1; /* __text */
        n.n_value = sec_text.addr + s->off;
      } else {
        n.n_sect = 2; /* __data */
        /* Data symbols are placed after the fixed guest-mem slot. */
        n.n_value = sec_data.addr + guest_mem_slot + (s->off - blob.code_len);
      }
      n.n_desc = 0;
      memcpy(p, &n, sizeof n); p += sizeof n;
    }
    free(label_strx);
  }

  /* Pad to stroff and emit string table. */
  curr = (size_t)(p - buf);
  if (curr > stroff) {
    fprintf(stderr, "[zingcc][ERR] stroff underflow\n");
    free(strbuf); free(buf); cg_free(&blob);
    return 1;
  }
  memset(p, 0, stroff - curr);
  p += (stroff - curr);
  memcpy(p, strbuf, strsize);
  p += strsize;
  free(strbuf);

  /* Validate invariants */
  if (stroff + strsize != file_size) {
    fprintf(stderr, "[zingcc][ERR] stroff + strsize != file_size\n");
    free(buf); cg_free(&blob);
    return 1;
  }
  if (symoff + nsyms * sizeof(struct nlist_64) > stroff) {
    fprintf(stderr, "[zingcc][ERR] symoff + symbytes > stroff\n");
    free(buf); cg_free(&blob);
    return 1;
  }
  if (reloc_off + reloc_count * sizeof(struct relocation_info) > symoff) {
    fprintf(stderr, "[zingcc][ERR] reloc_off + reloc_bytes > symoff\n");
    free(buf); cg_free(&blob);
    return 1;
  }

  /* Finalize: write buffer to file. */
  FILE* o = fopen(obj_path, "wb");
  if (!o) { perror("fopen guest.o"); free(buf); cg_free(&blob); return 1; }
  fwrite(buf, 1, file_size, o);
  fclose(o);
  free(buf);

  char* ar_argv[] = {"ar", "rcs", (char*)out, (char*)obj_path, NULL};
  if (run_cmd(ar_argv) != 0) {
    fprintf(stderr, "ar failed\n");
    cg_free(&blob);
    return 1;
  }
  printf("wrote %s\n", out);
  cg_free(&blob);
  return 0;
}
