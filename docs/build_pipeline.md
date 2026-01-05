<!-- SPDX-FileCopyrightText: 2025 Frogfish -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Build + Test Pipeline (Mac, Linux, Windows)

This document describes a practical build pipeline for producing release
artifacts and running tests across macOS, Linux, and Windows. It includes both
native and emulated options, with clear trade-offs.

## 1. Goals

- Produce release binaries for macOS, Linux, and Windows.
- Run unit/integration tests on each platform.
- Keep artifacts reproducible and auditable.
- Minimize platform-specific surprises by testing on the target OS.

## 2. Release Matrix (Recommended)

Native builds are the most reliable. A minimal matrix:

- macOS arm64 (Apple Silicon)
- Linux x86_64 (glibc)
- Windows x86_64 (MSVC or MinGW)

Optional additions:

- Linux arm64 (for native cloud/CI runners)
- Linux riscv64 (emulated via QEMU)

## 3. Tooling Assumptions

- Makefile is the primary build entry point.
- C toolchain for each target:
  - macOS: `clang`
  - Linux: `gcc` or `clang`
  - Windows: MSVC (`cl`) or MinGW (`x86_64-w64-mingw32-gcc`)

## 4. Build Strategy

### 4.1 macOS (native)

- Build and test natively on Apple Silicon.
- Use `make build`, `make test`, `make test-validation`.

### 4.2 Linux x86_64 (native)

- Preferred: native Linux runner (CI or local).
- Use `make build`, `make test`, `make test-validation`.

### 4.3 Windows x86_64 (native)

Two options:

1) MSVC (recommended for Windows-native):
   - Provide a small `make` wrapper or a `build.ps1`.
2) MinGW (fewer changes, easier CI):
   - Use `x86_64-w64-mingw32-gcc` and GNU Make.

Tests should run on actual Windows where possible to catch path/IO quirks.

## 5. Emulated Builds (Optional)

Emulation is good for smoke tests and determinism checks, but not a full
replacement for native testing.

### 5.1 Linux arm64 / riscv64 (QEMU)

- Build a static binary or use a minimal rootfs.
- Run test binaries in QEMU (`qemu-system-*`) or user-mode (`qemu-*-static`)
  if the host is not the same architecture.

### 5.2 Windows emulation

Windows emulation is possible with QEMU, but heavyweight. Prefer native
Windows runners for official release.

## 6. Suggested CI Stages

1) **Lint/Format** (fast, per-commit).
2) **Unit/Integration Tests** on:
   - macOS arm64
   - Linux x86_64
   - Windows x86_64
3) **Release Artifacts** build on each OS.
4) **Optional Emulated** runs (Linux arm64/riscv64).

## 7. Artifact Outputs

Recommended naming:

- `bin/macos-arm64/*`
- `bin/linux-x86_64/*`
- `bin/windows-x86_64/*`

Keep versioned archives under `dist/` if desired:

- `dist/zasm-macos-arm64-<version>.tar.gz`
- `dist/zasm-linux-x86_64-<version>.tar.gz`
- `dist/zasm-windows-x86_64-<version>.zip`

## 8. Test Targets

Define a consistent test surface:

- `make test` (core tests)
- `make test-validation` (schema + encoding)
- `make test-abi` (ABI conformance)
- `make test-zxc-*` (backend-specific tests)

All should pass on native targets. Emulated runs may skip long tests.

## 9. Versioning and Reproducibility

- Embed version strings at build time from `VERSION` or `dist/VERSION`.
- Pin toolchain versions in CI where possible.
- Avoid timestamps in artifacts unless explicitly desired.

## 10. Decision Summary

If simplicity is the priority:

- Build natively on macOS, Linux, Windows.
- Run full tests on each.
- Use emulation only for optional extra coverage.

If portability demos are a priority:

- Add QEMU-based Linux arm64/riscv64 smoke tests.
