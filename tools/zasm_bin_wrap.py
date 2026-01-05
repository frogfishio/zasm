#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import struct
import sys


def die(msg):
    sys.stderr.write(f"zasm_bin_wrap: error: {msg}\n")
    sys.exit(1)


def main():
    if len(sys.argv) != 3 or sys.argv[1] in ("-h", "--help"):
        sys.stdout.write(
            "zasm_bin_wrap — wrap raw opcode bytes in a .zasm.bin container\n"
            "\n"
            "Usage:\n"
            "  zasm_bin_wrap <input.bin> <output.zasm.bin>\n"
        )
        return 0

    in_path = sys.argv[1]
    out_path = sys.argv[2]

    try:
        with open(in_path, "rb") as f:
            data = f.read()
    except OSError as exc:
        die(f"failed to read input: {exc}")

    if len(data) == 0:
        die("input is empty")
    if len(data) % 4 != 0:
        die("input length must be a multiple of 4 bytes")

    header = b"ZASB" + struct.pack("<HHII", 1, 0, 0, len(data))
    tmp_path = out_path + ".tmp"
    try:
        with open(tmp_path, "wb") as f:
            f.write(header)
            f.write(data)
        os.replace(tmp_path, out_path)
    except OSError as exc:
        die(f"failed to write output: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
