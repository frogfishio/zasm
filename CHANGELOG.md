# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

- Added tool mode (`--tool` + `-o`) for `zas`, `zld`, and `zlnt` to support filelist workflows.
- Added diagnostic options: `--verbose` (where applicable) and `--json` for structured stderr output.
- Added `--help` and standardized usage banners for all tools.
- Centralized versioning in `VERSION` and embedded versions in tool binaries.
- Added `build`, `bump`, and `dist` targets; `dist` packages binaries to `dist/<platform>`.
- Reorganized test targets into grouped suites (`test-smoke`, `test-asm`, `test-runtime`, etc.).
- Added ABI linker conformance tests with verbose diagnostics checks and new `test-abi` target.
- Added ABI runtime tests for alloc/free semantics, stream I/O, log register requirements, entrypoint/res_end behavior, and import signature conformance.
- Added ABI test for `_out` behavior when stdout is closed (non-strict returns error, strict traps).
