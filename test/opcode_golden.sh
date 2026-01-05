#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mnemonics_html="$root_dir/schema/ir/v1/mnemonics.html"
opcode_md="$root_dir/docs/spec/opcode_encoding.md"

python3 - "$mnemonics_html" "$opcode_md" <<'PY'
import sys
import re

mn_path, md_path = sys.argv[1], sys.argv[2]
mn_text = open(mn_path, "r", encoding="utf-8").read()
md_text = open(md_path, "r", encoding="utf-8").read()

mn_rows = re.findall(r'<td data-label="ZASM mnemonic">([^<]+)</td>\s*<td data-label="ZASM opcode \(hex\)">([^<]+)</td>', mn_text)
if not mn_rows:
    raise SystemExit("no mnemonic rows found")

mn_map = {}
for m, op in mn_rows:
    m = m.strip()
    op = op.strip().replace(" (pseudo)", "")
    if op == "—":
        continue
    if op in mn_map:
        raise SystemExit(f"opcode collision in mnemonics.html: {op} ({mn_map[op]} vs {m})")
    mn_map[op] = m

table = []
in_table = False
for line in md_text.splitlines():
    if line.startswith("### 6.1 Opcode Table (Hex)"):
        in_table = True
        continue
    if in_table:
        if line.startswith("## "):
            break
        if line.startswith("|") and "|" in line[1:]:
            table.append(line)

if not table:
    raise SystemExit("opcode table not found in opcode_encoding.md")

rows = []
for line in table:
    if line.startswith("|---"):
        continue
    parts = [p.strip() for p in line.strip().strip("|").split("|")]
    if len(parts) != 2:
        continue
    if parts[0] == "Mnemonic" and parts[1].startswith("Opcode"):
        continue
    rows.append((parts[0], parts[1]))

md_map = {}
for m, op in rows:
    if m.startswith("DB/"):
        continue
    op = op.replace(" (pseudo)", "").strip()
    if op in md_map:
        raise SystemExit(f"opcode collision in opcode_encoding.md: {op} ({md_map[op]} vs {m})")
    md_map[op] = m

if set(mn_map.items()) != set(md_map.items()):
    missing = set(mn_map.items()) - set(md_map.items())
    extra = set(md_map.items()) - set(mn_map.items())
    if missing:
        raise SystemExit(f"opcode table missing entries: {sorted(missing)}")
    if extra:
        raise SystemExit(f"opcode table has extra entries: {sorted(extra)}")

print("Opcode table matches mnemonics.html")
PY
