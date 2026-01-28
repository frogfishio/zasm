#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Smoke test: `zem --caps` should succeed and print something.

out="$(bin/zem --caps)"

# Must include the header line.
echo "$out" | grep -q '^caps:'

# With libzingcap_async linked, async/default should be registered.
echo "$out" | grep -q 'async/default'

# With libzingcap_exec linked, exec selectors should be present.
echo "$out" | grep -q '^exec\.selectors:'
echo "$out" | grep -q 'exec/run'

echo "ok"
