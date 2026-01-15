<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# zem

ZASM IR v1.1 emulator + debugger.

This directory contains the `zem` implementation.

For user-facing usage, flags, and the machine-readable `dbg_stop` JSONL schema (including `--debug-events-only`), see:

- `docs/tools/zem.md`

Quick smoke:

```sh
make zem
bin/zem --help
bin/zem src/zem/testdata/001-main-zero.zir.jsonl
```

