#include "mach_o.h"
#include <errno.h>
#include <mach-o/arm64/reloc.h>
#include <mach-o/reloc.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#if defined(__GNUC__) || defined(__clang__)
#include <alloca.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void *xcalloc(size_t n, size_t sz) {
  void *p = calloc(n, sz);
  return p;
}

static size_t align_up(size_t x, size_t a) {
  size_t mask = a - 1;
  return (x + mask) & ~mask;
}

static int sym_is(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }
static uint32_t intern_str(char *strtab, size_t *strsz, const char *name) {
  size_t len = strlen(name);
  uint32_t off = (uint32_t)(*strsz);
  memcpy(strtab + *strsz, name, len + 1);
  *strsz += len + 1;
  return off;
}

static int sym_index_of(const ir_prog_t *ir, const cg_blob_t *blob, size_t local_count, size_t public_count, const char *name) {
  if (!name) return -1;
  size_t idx = 0;
  for (symtab_entry *s = blob->syms; s; s = s->next, idx++) {
    if (s->name && sym_is(s->name, name)) return (int)idx;
  }
  size_t base = local_count;
  idx = 0;
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_ENTRY_DIR && e->u.dir.dir_kind == IR_DIR_PUBLIC && e->u.dir.name) {
      if (sym_is(e->u.dir.name, name)) return (int)(base + idx);
      idx++;
    }
  }
  base += public_count;
  idx = 0;
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_ENTRY_DIR && e->u.dir.dir_kind == IR_DIR_EXTERN && e->u.dir.extern_as) {
      if (sym_is(e->u.dir.extern_as, name)) return (int)(base + idx);
      idx++;
    }
  }
  return -1;
}

static int resolve_reloc_encoding(uint32_t cg_type, uint8_t *macho_r_type, uint8_t *macho_pcrel) {
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

int macho_write_object(const ir_prog_t *ir, const cg_blob_t *blob, const char *out_path) {
  char err[256] = {0};
#define FAIL(...) do { snprintf(err, sizeof err, __VA_ARGS__); goto fail; } while (0)
  if (!ir || !blob || !out_path) return -1;

  /* Collect PUBLIC (exports) and EXTERN (imports). */
  size_t public_count = 0, extern_count = 0;
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_ENTRY_DIR && e->u.dir.dir_kind == IR_DIR_PUBLIC && e->u.dir.name) public_count++;
    if (e->kind == IR_ENTRY_DIR && e->u.dir.dir_kind == IR_DIR_EXTERN && e->u.dir.extern_as) extern_count++;
  }

  /* Collect locals from blob symtab (labels/data). */
  size_t local_count = 0;
  for (symtab_entry *s = blob->syms; s; s = s->next) {
    if (!s->name) continue;
    local_count++;
  }

  /* String table */
  size_t strcap = 1; /* leading NUL */
  for (symtab_entry *s = blob->syms; s; s = s->next) if (s->name) strcap += strlen(s->name) + 1;
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_ENTRY_DIR && e->u.dir.dir_kind == IR_DIR_PUBLIC && e->u.dir.name) strcap += strlen(e->u.dir.name) + 2;
    if (e->kind == IR_ENTRY_DIR && e->u.dir.dir_kind == IR_DIR_EXTERN && e->u.dir.extern_as) strcap += strlen(e->u.dir.extern_as) + 2;
  }
  char *strtab = (char *)xcalloc(strcap, 1);
  if (!strtab) return -1;
  size_t strsz = 1; /* strtab[0]=0 */

  /* Map locals to string offsets */
  uint32_t *local_strx = (uint32_t *)xcalloc(local_count ? local_count : 1, sizeof(uint32_t));
  size_t li = 0;
  for (symtab_entry *s = blob->syms; s; s = s->next) {
    local_strx[li++] = intern_str(strtab, &strsz, s->name ? s->name : "");
  }

  /* PUBLIC and EXTERN string offsets */
  uint32_t *public_strx = (uint32_t *)xcalloc(public_count ? public_count : 1, sizeof(uint32_t));
  uint32_t *extern_strx = (uint32_t *)xcalloc(extern_count ? extern_count : 1, sizeof(uint32_t));
  size_t pi = 0, ei = 0;
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_ENTRY_DIR && e->u.dir.dir_kind == IR_DIR_PUBLIC && e->u.dir.name) {
      /* prepend _ for Mach-O C symbols */
      size_t len = strlen(e->u.dir.name);
      char *tmp = (char *)alloca(len + 2);
      tmp[0] = '_';
      memcpy(tmp + 1, e->u.dir.name, len + 1);
      public_strx[pi++] = intern_str(strtab, &strsz, tmp);
    } else if (e->kind == IR_ENTRY_DIR && e->u.dir.dir_kind == IR_DIR_EXTERN && e->u.dir.extern_as) {
      size_t len = strlen(e->u.dir.extern_as);
      char *tmp = (char *)alloca(len + 2);
      tmp[0] = '_';
      memcpy(tmp + 1, e->u.dir.extern_as, len + 1);
      extern_strx[ei++] = intern_str(strtab, &strsz, tmp);
    }
  }

  /* Layout */
  size_t header_size = sizeof(struct mach_header_64);
  size_t cmd_buildver_size = sizeof(struct build_version_command);
  size_t cmd_text_size = sizeof(struct segment_command_64) + sizeof(struct section_64);
  size_t cmd_data_size = sizeof(struct segment_command_64) + sizeof(struct section_64);
  size_t cmd_sym_size = sizeof(struct symtab_command);
  size_t load_size = cmd_buildver_size + cmd_text_size + cmd_data_size + cmd_sym_size;

  size_t text_off = align_up(header_size + load_size, 4);
  size_t text_size = blob->code_len;
  size_t data_off = align_up(text_off + text_size, 4);
  size_t data_size = blob->data_len;

  /* Count relocs */
  size_t reloc_count = 0;
  for (cg_reloc_t *r = blob->relocs; r; r = r->next) {
    uint8_t t = 0, pcr = 0;
    if (!resolve_reloc_encoding(r->type, &t, &pcr)) FAIL("unsupported reloc type %u", r->type);
    reloc_count++;
  }
  size_t reloc_off = align_up(data_off + data_size, 4);

  uint32_t nsyms = (uint32_t)(local_count + public_count + extern_count);
  size_t symoff = align_up(reloc_off + reloc_count * (size_t)sizeof(struct relocation_info), 4);
  size_t stroff = align_up(symoff + nsyms * sizeof(struct nlist_64), 4);
  size_t file_size = stroff + strsz;
  if (file_size == 0 || text_off >= file_size || data_off >= file_size) FAIL("invalid layout (size/off overflow)");

  uint8_t *buf = (uint8_t *)xcalloc(file_size, 1);
  if (!buf) { free(strtab); free(local_strx); free(public_strx); free(extern_strx); return -1; }
  uint8_t *p = buf;

  struct mach_header_64 mh = {0};
  mh.magic = MH_MAGIC_64;
  mh.cputype = CPU_TYPE_ARM64;
  mh.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
  mh.filetype = MH_OBJECT;
  mh.ncmds = 4;
  mh.sizeofcmds = (uint32_t)load_size;
  memcpy(p, &mh, sizeof mh); p += sizeof mh;

  struct build_version_command bvc = {0};
  bvc.cmd = LC_BUILD_VERSION;
  bvc.cmdsize = (uint32_t)cmd_buildver_size;
  bvc.platform = PLATFORM_MACOS;
  bvc.minos = 0x000C0000; /* 12.0.0 */
  bvc.sdk = 0x000C0000;
  bvc.ntools = 0;
  memcpy(p, &bvc, sizeof bvc); p += sizeof bvc;

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
  sec_text.align = 2;
  sec_text.reloff = reloc_count ? (uint32_t)reloc_off : 0;
  sec_text.nreloc = (uint32_t)reloc_count;
  sec_text.flags = S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
  memcpy(p, &sec_text, sizeof sec_text); p += sizeof sec_text;

  struct segment_command_64 seg_data = {0};
  seg_data.cmd = LC_SEGMENT_64;
  seg_data.cmdsize = (uint32_t)cmd_data_size;
  strncpy(seg_data.segname, "__DATA", sizeof seg_data.segname);
  seg_data.vmaddr = align_up(text_size, 4);
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
  sec_data.addr = seg_data.vmaddr;
  sec_data.size = data_size;
  sec_data.offset = (uint32_t)data_off;
  sec_data.align = 2;
  sec_data.reloff = 0;
  sec_data.nreloc = 0;
  sec_data.flags = S_REGULAR;
  memcpy(p, &sec_data, sizeof sec_data); p += sizeof sec_data;

  struct symtab_command st_sym = {0};
  st_sym.cmd = LC_SYMTAB;
  st_sym.cmdsize = sizeof st_sym;
  st_sym.symoff = (uint32_t)symoff;
  st_sym.nsyms = nsyms;
  st_sym.stroff = (uint32_t)stroff;
  st_sym.strsize = (uint32_t)strsz;
  memcpy(p, &st_sym, sizeof st_sym); p += sizeof st_sym;

  /* Text */
  size_t curr = (size_t)(p - buf);
  if (curr > text_off) goto fail;
  memset(p, 0, text_off - curr);
  p += (text_off - curr);
  memcpy(p, blob->code, blob->code_len);
  p += blob->code_len;

  /* Data */
  curr = (size_t)(p - buf);
  if (curr > data_off) goto fail;
  memset(p, 0, data_off - curr);
  p += (data_off - curr);
  memcpy(p, blob->data, blob->data_len);
  p += blob->data_len;

  /* Relocations */
  curr = (size_t)(p - buf);
  if (curr > reloc_off) FAIL("reloc section overlaps data");
  memset(p, 0, reloc_off - curr);
  p += (reloc_off - curr);
  if (reloc_count) {
    /* Build symbol index map: locals first, then publics, then externs. */
    for (cg_reloc_t *r = blob->relocs; r; r = r->next) {
      uint8_t r_type = 0, pcr = 0;
      if (!resolve_reloc_encoding(r->type, &r_type, &pcr)) FAIL("unsupported reloc type %u (line %u)", r->type, r->line);
      int si = sym_index_of(ir, blob, local_count, public_count, r->sym);
      if (si < 0) FAIL("reloc against unknown symbol '%s' (line %u)", r->sym ? r->sym : "(null)", r->line);
      struct relocation_info ri = {0};
      ri.r_address = r->instr_off;
      ri.r_extern = 1;
      ri.r_symbolnum = si;
      ri.r_pcrel = pcr;
      ri.r_length = 2;
      ri.r_type = r_type;
      memcpy(p, &ri, sizeof ri);
      p += sizeof ri;
    }
  }

  /* Pad to symoff */
  curr = (size_t)(p - buf);
  if (curr > symoff) FAIL("symbol table overlaps relocs");
  memset(p, 0, symoff - curr);
  p += (symoff - curr);

  /* Symbols: locals, publics (extern | N_SECT), externs (N_UNDF). */
  struct nlist_64 *nl = (struct nlist_64 *)p;
  size_t sidx = 0;
  /* locals */
  for (symtab_entry *s = blob->syms; s; s = s->next) {
    if (s->off == (size_t)-1) FAIL("local symbol '%s' missing offset", s->name ? s->name : "(anon)");
    nl[sidx].n_un.n_strx = local_strx[sidx];
    nl[sidx].n_type = N_SECT;
    int is_data = (s->off >= blob->code_len);
    nl[sidx].n_sect = is_data ? 2 : 1; /* __DATA=2, __TEXT=1 */
    nl[sidx].n_desc = 0;
    nl[sidx].n_value = (uint64_t)s->off;
    sidx++;
  }
  /* publics */
  size_t pub_idx = 0;
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_ENTRY_DIR && e->u.dir.dir_kind == IR_DIR_PUBLIC && e->u.dir.name) {
      nl[sidx].n_un.n_strx = public_strx[pub_idx++];
      nl[sidx].n_type = N_SECT | N_EXT;
      /* find offset */
      uint64_t off = 0;
      int sect = 1;
      for (symtab_entry *s = blob->syms; s; s = s->next) {
        if (s->name && sym_is(s->name, e->u.dir.name)) {
          if (s->off == (size_t)-1) FAIL("PUBLIC symbol '%s' missing definition", s->name);
          off = s->off;
          sect = (s->off >= blob->code_len) ? 2 : 1;
          break;
        }
      }
      nl[sidx].n_sect = sect;
      nl[sidx].n_desc = 0;
      nl[sidx].n_value = off;
      sidx++;
    }
  }
  /* externs */
  size_t ext_idx = 0;
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_ENTRY_DIR && e->u.dir.dir_kind == IR_DIR_EXTERN && e->u.dir.extern_as) {
      nl[sidx].n_un.n_strx = extern_strx[ext_idx++];
      nl[sidx].n_type = N_UNDF | N_EXT;
      nl[sidx].n_sect = 0;
      nl[sidx].n_desc = 0;
      nl[sidx].n_value = 0;
      sidx++;
    }
  }
  p += nsyms * sizeof(struct nlist_64);

  /* String table */
  curr = (size_t)(p - buf);
  if (curr > stroff) FAIL("string table overlaps symbols");
  memset(p, 0, stroff - curr);
  p += (stroff - curr);
  memcpy(p, strtab, strsz);
  p += strsz;

  /* Write to disk */
  FILE *fp = fopen(out_path, "wb");
  if (!fp) FAIL("open '%s' failed: %s", out_path, strerror(errno));
  size_t nw = fwrite(buf, 1, file_size, fp);
  fclose(fp);
  if (nw != file_size) FAIL("short write to '%s'", out_path);

  free(strtab);
  free(local_strx);
  free(public_strx);
  free(extern_strx);
  free(buf);
  return 0;

fail:
  free(strtab);
  free(local_strx);
  free(public_strx);
  free(extern_strx);
  free(buf);
  if (err[0]) fprintf(stderr, "[lower] Mach-O emit: %s\n", err);
#undef FAIL
  return -1;
}
