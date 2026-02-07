<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ZASM Binary Container (.zasm.bin) — v2

This document defines the **normative** v2 container for `.zasm.bin` modules.

v2 is intended to be the embeddable, ship-able artifact for a “zero trust”
nanoservice runner:

- Fast, bounded parsing.
- Strict, deterministic validation.
- A stable boundary for a JIT that translates the contained opcodes to a host ISA
	(arm64 first), while the host enforces policy via the zingcore / zABI surface.

The opcode encoding itself is defined in `docs/spec/opcode_encoding.md`.

v1 is retired and preserved at `docs/spec/zasm_bin_v1.md`.

All integers are **little-endian**.

## High-level model

A `.zasm.bin` v2 file is a sectioned container:

- A fixed header.
- A fixed-width section directory.
- A set of sections (payloads) referenced by the directory.

The only **required** section is `CODE`.

## Header (40 bytes)

```
Offset  Size  Field              Description
------  ----  -----------------  --------------------------------------------
0       4     magic              ASCII "ZASB"
4       2     version            MUST be 2
6       2     flags              Reserved (MUST be 0)
8       4     file_len           Total file length in bytes
12      4     dir_off            Offset (bytes) of the section directory
16      4     dir_count          Number of directory entries
20      4     entry_pc_words     Default entrypoint PC in *words* (CODE-relative)
24      4     abi_id             ABI identifier (ASCII tag as u32), or 0
28      4     abi_version        ABI version (e.g. 0x00020005 for zABI 2.5), or 0
32      4     reserved0          MUST be 0
36      4     reserved1          MUST be 0
```

Notes:

- `abi_id` is an integration hint. For a zingcore/zABI host, `abi_id` SHOULD be
	the ASCII tag `"ZABI"` and `abi_version` SHOULD be the required zABI version.
- `entry_pc_words` is the “main entry” for runners that don’t use an export table.

## Section directory

The directory is a packed array of `dir_count` entries at byte offset `dir_off`.

Each directory entry is 20 bytes:

```
Offset  Size  Field     Description
------  ----  --------  ----------------------------------------------
0       4     tag       ASCII section tag (e.g. "CODE")
4       4     off       Section payload offset (bytes)
8       4     len       Section payload length (bytes)
12      4     flags     Section-specific flags (MUST be 0 unless defined)
16      4     reserved  MUST be 0
```

Validation rules (normative):

- Directory entries MUST NOT overlap each other or the header/directory region.
- `off` and `len` MUST describe a range fully contained in `[0, file_len)`.
- Unknown `tag` values MUST be ignored for forward-compat *only if* their
	`(flags,reserved)` are 0 and the payload range is valid.
- Duplicate `tag` values MUST be rejected (v2 keeps tags unique).

## Sections

### 1) `CODE` (required)

Payload: a raw opcode byte stream.

Normative constraints:

- `len` MUST be non-zero and a multiple of 4.
- The stream MUST validate against the encoding rules in `docs/spec/opcode_encoding.md`.
- All control-flow immediates MUST be in-range (see “Verifier checklist”).

Semantics:

- `JR` encodes a PC-relative displacement in *words*.
- `CALL` encodes a PC-relative displacement in *words*.

This matches the current `zir` encoder behavior (it emits `CALL`/`JR` as word
displacements and rejects targets that do not fit the signed 12-bit immediate).

### 2) `EXPT` (optional)

Exports table for locating entrypoints by name.

Payload format:

```
u32 count
repeat count times:
	u16 name_len
	u8  kind        (0 = func)
	u8  reserved    (MUST be 0)
	u32 pc_words    (CODE-relative)
	u8  name[name_len]
	padding to 4-byte alignment (0 bytes)
```

Normative constraints:

- Export names MUST be UTF-8 and MUST be unique.
- `pc_words` MUST be a valid instruction address within `CODE`.

If an export named `"main"` exists, `entry_pc_words` SHOULD equal its `pc_words`.

### 3) `IMPT` (optional)

Imports declaration for preflight.

This section does not change opcode semantics; it lets hosts fail-fast if a
module requires primitives/syscalls the host does not support.

Payload format (minimal v2):

```
u32 prim_mask
u32 reserved (MUST be 0)
```

Where `prim_mask` is a bitmask of required primitive operations.

Current primitive mapping used by `zir`/`zxc`:

- bit 0: `_in`
- bit 1: `_out`
- bit 2: `_log`
- bit 3: `_alloc`
- bit 4: `_free`
- bit 5: `_ctl`

Runtimes MAY additionally detect primitives directly from `CODE` (as `zxc` does).
If both are present, they MUST agree.

### 4) `MEM ` (optional)

Memory requirements hint for hosts.

Payload format:

```
u32 min_bytes
u32 max_bytes   (0 means “no maximum declared”)
```

Normative constraints:

- `min_bytes` MUST be >= 65536 (1 page) for zABI-style environments.
- Hosts MUST fail closed if they cannot satisfy `min_bytes`.

### 5) `DATA` (optional)

Static initialization data for the guest memory.

Payload format:

```
u32 seg_count
repeat seg_count times:
	u32 dst_off
	u32 byte_len
	u8  bytes[byte_len]
	padding to 4-byte alignment (0 bytes)
```

Normative constraints:

- Segments MUST be in-bounds of the provisioned guest memory.
- Segments MUST NOT overlap.

### 6) `NAME` (optional)

Debug/name metadata. This section MUST be ignored for correctness.
The payload format is intentionally left unspecified in v2.

## Verifier checklist (MVP, normative)

A conforming loader/JIT MUST reject the module if any check fails.

1) **Container integrity**
	 - Magic/version/flags valid.
	 - Directory ranges valid, non-overlapping, in-bounds.
	 - `CODE` exists exactly once.

2) **Opcode stream validity**
	 - `CODE.len % 4 == 0`.
	 - Every instruction word decodes to a known opcode.
	 - Unused fields for each opcode format are zero.
	 - Reserved register indices are rejected.
	 - Extension word arity matches the opcode’s requirements.

3) **Control-flow safety**
	 - For every `JR`, the computed target PC is within `CODE` and lands on an
		 instruction boundary.
	 - For every `CALL`, the computed target PC is within `CODE` and lands on an
		 instruction boundary.

4) **Host interface preflight**
	 - If `IMPT` is present, required primitives/syscalls are supported.
	 - If the runtime also scans `CODE` for primitives, the scan result MUST match `IMPT`.

5) **Resource limits**
	 - `CODE` size MUST be <= a host-defined cap.
	 - `DATA` total bytes MUST be <= a host-defined cap.
	 - `MEM ` requirements must be satisfiable (if present).

## Notes on “zero trust”

This container format is necessary but not sufficient for zero trust:

- The host must enforce memory/time limits and bounds checks.
- The host must police the zingcore/zABI interface and treat guest pointers as
	untrusted offsets.
- JIT code emission must follow W^X (write XOR execute) rules.
