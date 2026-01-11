## lower — JSON IR (zasm-v1.0) → macOS arm64 Mach-O

`lower` consumes ZASM JSONL IR (`schema/ir/v1/record.schema.json`) and produces a Mach-O object suitable for linking with `clang` on macOS arm64. It also performs strict validation and line-aware diagnostics to help you debug IR generation.

### Usage

```
lower --input <input.jsonl> [--o <out.o>] [--debug]
lower --tool -o <out.o> <input.jsonl>... [--debug]
lower --help
lower --version
```

### Options

- `--input <path>`: Input JSONL IR (zasm-v1.0). Required in non-tool mode.
- `--o <path>`: Output Mach-O object path (default: `src/lower/arm64/out/out.o`).
- `--tool`: Filelist mode; allows multiple inputs but requires `-o`.
- `--debug` / `--trace`: Verbose debug output (symbol audits, counts, refs/decls).
- `--version`: Print version (read from `VERSION` in the repo).
- `--help`: Show help.

### Exit codes

- `0`: Success
- `2`: Parse/validation error
- `3`: Codegen error
- `4`: Mach-O emit error
- `1`: Usage/IO error

### Diagnostics

- Parser errors include line numbers and a snippet of the offending JSONL record.
- Codegen and Mach-O emit errors include line numbers where available and name the failing symbol or mnemonic.
- With `--debug`, a symbol audit reports refs minus decls and decls minus refs, plus counts of labels/data/extern/public.

### Examples

- Lower a single IR file:
  ```
  lower --input src/lower/arm64/golden/hello_world.zir.jsonl --o /tmp/hello.o
  clang /tmp/hello.o -o /tmp/hello && /tmp/hello
  ```

- Tool mode with multiple inputs:
  ```
  lower --tool -o src/lower/arm64/out/bundle.o src/lower/arm64/golden/*.zir.jsonl
  ```

- Debug run to inspect symbol mismatches:
  ```
  lower --debug --input bad.zir.jsonl --o /tmp/bad.o
  ```
