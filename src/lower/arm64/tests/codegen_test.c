#include "codegen.h"
#include "json_ir.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int run_file(const char *path){
  FILE *f = fopen(path,"r");
  if (!f) { perror("open"); return 1; }
  ir_prog_t ir={0};
  if (json_ir_read(f,&ir)!=0){fprintf(stderr,"parse failed\n"); fclose(f); return 1;}
  fclose(f);
  cg_blob_t blob={0};
  if (cg_emit_arm64(&ir,&blob)!=0){fprintf(stderr,"codegen failed\n"); ir_free(&ir); return 1;}
  printf("code %zu bytes, data %zu bytes, relocs %u\n", blob.code_len, blob.data_len, blob.reloc_count);
  cg_free(&blob);
  ir_free(&ir);
  return 0;
}

int main(int argc,char**argv){
  if (argc<2) return run_file("src/lower/arm64/tests/codegen_cases.jsonl");
  return run_file(argv[1]);
}
