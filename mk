#!/usr/bin/env bash
set -euo pipefail

# Prefer Homebrew toolchain on macOS (Apple ships ancient bison/flex)
BREW_BISON_A="/opt/homebrew/opt/bison/bin/bison"
BREW_FLEX_A="/opt/homebrew/opt/flex/bin/flex"
BREW_BISON_I="/usr/local/opt/bison/bin/bison"
BREW_FLEX_I="/usr/local/opt/flex/bin/flex"

BISON_BIN="bison"
FLEX_BIN="flex"

if [[ -x "$BREW_BISON_A" ]]; then BISON_BIN="$BREW_BISON_A"
elif [[ -x "$BREW_BISON_I" ]]; then BISON_BIN="$BREW_BISON_I"
fi

if [[ -x "$BREW_FLEX_A" ]]; then FLEX_BIN="$BREW_FLEX_A"
elif [[ -x "$BREW_FLEX_I" ]]; then FLEX_BIN="$BREW_FLEX_I"
fi

echo "Using bison: $BISON_BIN"
"$BISON_BIN" --version | head -n 1 || true
echo "Using flex:  $FLEX_BIN"
"$FLEX_BIN" --version | head -n 1 || true
echo

exec make BISON="$BISON_BIN" FLEX="$FLEX_BIN" "$@"