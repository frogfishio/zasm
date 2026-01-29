#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Smoke test: `zem --caps` should succeed and print something.

out="$(bin/zem --caps)"

# Must include the header line.
echo "$out" | grep -q '^caps:'

# With zingcore25 linked, async/default + selectors should be present.
echo "$out" | grep -q '^\- async/default '
echo "$out" | grep -q '^async/default\.selectors:'
echo "$out" | grep -q 'async/default ping\.v1'

# sys/info@v1 is part of the 2.5 reference set.
echo "$out" | grep -q '^\- sys/info '

echo "ok"
