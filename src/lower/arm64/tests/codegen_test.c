#include "codegen.h"
#include "json_ir.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static symtab_entry *find_sym(symtab_entry *root, const char *name) {
  for (symtab_entry *s = root; s; s = s->next) {
    if (s->name && strcmp(s->name, name) == 0) return s;
  }
  return NULL;
}

static int ir_has_label(const ir_prog_t *ir, const char *name) {
  for (ir_entry_t *e = ir->head; e; e = e->next) {
    if (e->kind == IR_ENTRY_LABEL && e->u.label.name && strcmp(e->u.label.name, name) == 0) return 1;
  }
  return 0;
}

static int run_file(const char *path){
  FILE *f = fopen(path,"r");
  if (!f) { perror("open"); return 1; }
  ir_prog_t ir={0};
  if (json_ir_read(f,&ir)!=0){fprintf(stderr,"parse failed\n"); fclose(f); return 1;}
  fclose(f);
  cg_blob_t blob={0};
  if (cg_emit_arm64(&ir,&blob)!=0){fprintf(stderr,"codegen failed\n"); ir_free(&ir); return 1;}

  /* Regression guard: if a stream begins with adjacent labels (e.g. main then loop)
   * and lowerer function prologue insertion happens at the first instruction rather
   * than at the function entry label, both labels can wind up with the same address.
   * Branching to the second label can then re-run the prologue and grow the stack.
   */
  if (ir_has_label(&ir, "main") && ir_has_label(&ir, "loop")) {
    symtab_entry *s_main = find_sym(blob.syms, "main");
    symtab_entry *s_loop = find_sym(blob.syms, "loop");
    if (s_main && s_loop && s_main->off != (size_t)-1 && s_loop->off != (size_t)-1) {
      if (s_loop->off <= s_main->off) {
        fprintf(stderr, "codegen regression: loop label (off=%zu) not after main (off=%zu)\n", s_loop->off, s_main->off);
        cg_free(&blob);
        ir_free(&ir);
        return 1;
      }
    }
  }

  printf("code %zu bytes, data %zu bytes, relocs %u\n", blob.code_len, blob.data_len, blob.reloc_count);
  cg_free(&blob);
  ir_free(&ir);
  return 0;
}

int main(int argc,char**argv){
  if (argc<2) return run_file("src/lower/arm64/tests/codegen_cases.jsonl");
  return run_file(argv[1]);
}
