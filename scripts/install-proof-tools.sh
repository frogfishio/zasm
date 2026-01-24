#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Installs optional tools used for checking emitted certificate proofs:
#   - cvc5 (SMT solver, used to produce Alethe proofs)
#   - carcara (Alethe proof checker)
#
# This script is best-effort and intentionally non-invasive.

uname_s="$(uname -s)"

have() { command -v "$1" >/dev/null 2>&1; }

note_installed() {
  echo "ok: $1 already installed ($2)"
}

install_macos() {
  if have cvc5; then
    note_installed "cvc5" "$(cvc5 --version 2>/dev/null | head -n 1 || echo cvc5)"
  else
    if have brew; then
      echo "installing cvc5 via Homebrew..."
      # cvc5 is not (always) available in homebrew/core; prefer core if present,
      # otherwise use the official tap.
      if brew info cvc5 >/dev/null 2>&1; then
        brew install cvc5
      else
        echo "Homebrew core has no 'cvc5' formula; using tap cvc5/cvc5..."
        brew tap cvc5/cvc5 >/dev/null
        brew install cvc5/cvc5/cvc5
      fi
    else
      echo "error: Homebrew not found; install cvc5 manually (https://cvc5.github.io/)" >&2
      echo "hint: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"" >&2
      exit 2
    fi
  fi

  if have carcara; then
    note_installed "carcara" "$(carcara --version 2>/dev/null | head -n 1 || echo carcara)"
  else
    if have cargo; then
      echo "installing carcara via cargo..."
      # Carcara isn't published on crates.io; install from the upstream repo.
      # Installs the `carcara` binary from the `carcara-cli` crate.
      cargo install --git https://github.com/ufmg-smite/carcara.git --locked --bin carcara carcara-cli
    else
      echo "error: cargo not found; install Rust first (https://rustup.rs/) then re-run" >&2
      exit 2
    fi
  fi
}

install_linux() {
  if have cvc5 && have carcara; then
    echo "ok: cvc5 and carcara already installed"
    exit 0
  fi

  echo "Linux install is distro-dependent." >&2
  echo "- Install cvc5 from your package manager, or build from source: https://github.com/cvc5/cvc5" >&2
  echo "- Install carcara with Rust: cargo install carcara" >&2
  exit 2
}

case "$uname_s" in
  Darwin) install_macos ;;
  Linux) install_linux ;;
  *)
    echo "Unsupported OS: $uname_s" >&2
    exit 2
    ;;
esac

echo "done"
