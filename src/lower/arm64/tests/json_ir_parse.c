#include "ir.h"
#include "json_ir.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *msg) {
  fprintf(stderr, "[json-ir-parse][FAIL] %s\n", msg);
  exit(1);
}

static FILE *open_fixture(void) {
  const char *paths[] = {
      "src/lower/arm64/fixtures/sample.zobj.jsonl",
      "../arm64/fixtures/sample.zobj.jsonl",
      "fixtures/sample.zobj.jsonl",
      NULL};
  for (int i = 0; paths[i]; i++) {
    FILE *f = fopen(paths[i], "r");
    if (f) return f;
  }
  fail("unable to open fixture sample.zobj.jsonl");
  return NULL;
}

int main(void) {
  FILE *fp = open_fixture();
  ir_prog_t prog;
  ir_init(&prog);
  if (json_ir_read(fp, &prog) != 0) {
    fclose(fp);
    fail("json_ir_read returned error");
  }
  fclose(fp);
  if (!prog.has_public_main) fail("PUBLIC main not detected");

  size_t labels = 0, instrs = 0, dirs = 0;
  int saw_db = 0, saw_dw = 0, saw_resb = 0, saw_str = 0, saw_equ = 0, saw_extern = 0;
  for (ir_entry_t *e = prog.head; e; e = e->next) {
    switch (e->kind) {
      case IR_ENTRY_LABEL:
        labels++;
        if (!e->u.label.name || strcmp(e->u.label.name, "start") != 0) fail("label mismatch");
        break;
      case IR_ENTRY_INSTR:
        instrs++;
        if (!e->u.instr.mnem || strcmp(e->u.instr.mnem, "CALL") != 0) fail("instr mnemonic mismatch");
        if (e->u.instr.op_count != 2) fail("instr operand count mismatch");
        break;
      case IR_ENTRY_DIR:
        dirs++;
        switch (e->u.dir.dir_kind) {
          case IR_DIR_DB:
            saw_db = 1;
            if (e->u.dir.data_len != 2 || e->u.dir.data[0] != 1 || e->u.dir.data[1] != 'A') fail("DB bytes mismatch");
            break;
          case IR_DIR_DW:
            saw_dw = 1;
            if (e->u.dir.data_len != 2 || e->u.dir.data[0] != 0x02 || e->u.dir.data[1] != 0x01) fail("DW bytes mismatch");
            break;
          case IR_DIR_RESB:
            saw_resb = (e->u.dir.reserve_len == 4);
            if (!saw_resb) fail("RESB reserve_len mismatch");
            break;
          case IR_DIR_STR:
            saw_str = 1;
            if (e->u.dir.data_len != 2 || e->u.dir.data[0] != 'h' || e->u.dir.data[1] != 'i') fail("STR data mismatch");
            if (!e->u.dir.has_equ_value || e->u.dir.equ_value != 2) fail("STR equ_value mismatch");
            break;
          case IR_DIR_EQU:
            saw_equ = (e->u.dir.has_equ_value && e->u.dir.equ_value == 42);
            if (!saw_equ) fail("EQU value mismatch");
            break;
          case IR_DIR_EXTERN:
            saw_extern = 1;
            if (!e->u.dir.extern_module || strcmp(e->u.dir.extern_module, "mod") != 0) fail("EXTERN module mismatch");
            if (!e->u.dir.extern_field || strcmp(e->u.dir.extern_field, "field") != 0) fail("EXTERN field mismatch");
            if (!e->u.dir.extern_as || strcmp(e->u.dir.extern_as, "alias") != 0) fail("EXTERN alias mismatch");
            break;
          case IR_DIR_PUBLIC:
          default:
            break;
        }
        break;
      default:
        fail("unknown entry kind");
    }
  }

  if (labels != 1 || instrs != 1 || dirs < 1) fail("entry count mismatch");
  if (!(saw_db && saw_dw && saw_resb && saw_str && saw_equ && saw_extern)) fail("missing directive coverage");

  ir_free(&prog);
  fprintf(stderr, "[json-ir-parse] ok\n");
  return 0;
}
