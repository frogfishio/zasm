<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Diagnostics (JSONL)

Most ZASM tools support `--json`, which emits **one JSON object per line** to **stderr** describing errors/warnings/info.
This format is intended to be stable and suitable for editor integration.

Note: this is the **diagnostics event schema** (e.g. `{"k":"diag","v":1,...}`), not the program IR schema/version (e.g. `"ir":"zasm-v1.1"`).

## Schema (v1)

A diagnostic record has:

- `k`: record kind (always `"diag"`)
- `v`: schema version (currently `1`)
- `tool`: tool name (`"zas"`, `"zld"`, `"zir"`, `"zlnt"`, `"zrun"`, ...)
- `level`: `"error"` | `"warn"` | `"info"`
- `message`: human-readable message
- `source` (optional): source identity
  - `name`: display name (usually basename)
  - `path`: full path or workspace-relative path
- `range` (optional): 1-based location range
  - `start.line`, `start.col`
  - `end.line`, `end.col`

Back-compat fields may also be present:

- `file`: same as `source.path`
- `line`: same as `range.start.line`

Example (one line in real output):

```json
{"k":"diag","v":1,"tool":"zas","level":"error","message":"unknown symbol: foo","source":{"name":"main.asm","path":"src/main.asm"},"range":{"start":{"line":12,"col":1},"end":{"line":12,"col":1}}}
```

## VS Code Problems integration (Task + matcher)

VS Code Tasks can only extract Problems via regex, so the recommended approach is:

1. Run the tool in `--json` mode (diagnostics on stderr).
2. Convert JSONL diagnostics into a stable, VS Code-friendly line format.

This repo includes a small converter:

- [tools/vscode/diag_to_problems.js](../tools/vscode/diag_to_problems.js)

### Example `tasks.json`

Create `.vscode/tasks.json`:

```jsonc
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "zas: lint (Problems)",
      "type": "shell",
      "command": "zsh",
      "args": [
        "-lc",
        "bin/zas --tool --lint --json \"${file}\" 2>&1 | node tools/vscode/diag_to_problems.js"
      ],
      "problemMatcher": [
        {
          "owner": "zasm",
          "fileLocation": ["autoDetect", "${workspaceFolder}"],
          "pattern": [
            {
              "regexp": "^(.*):(\\d+):(\\d+):\\s+(error|warning|info):\\s+(.*)$",
              "file": 1,
              "line": 2,
              "column": 3,
              "severity": 4,
              "message": 5
            }
          ]
        }
      ],
      "presentation": {"reveal": "never"}
    }
  ]
}
```

Notes:

- The task reads the current file via `${file}`.
- JSONL diagnostics are still emitted by the tool on stderr; the converter makes a stable text line stream for VS Code to match.
