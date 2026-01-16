#!/usr/bin/env node

/*
 * Reads ZASM tool JSONL diagnostics from stdin and prints VS Code-friendly
 * problem lines to stdout.
 *
 * Input (one JSON object per line, on stderr from tools with --json):
 *   {"k":"diag","v":1,"tool":"zas","level":"error","message":"...","source":{"path":"..."},"range":{"start":{"line":1,"col":1}}}
 *
 * Output (one line per diagnostic):
 *   path:line:col: severity: message
 */

'use strict';

const fs = require('fs');

function toSeverity(level) {
  if (!level) return 'info';
  if (level === 'warn') return 'warning';
  return level;
}

function get(obj, path, fallback = undefined) {
  let cur = obj;
  for (const key of path) {
    if (cur == null || typeof cur !== 'object') return fallback;
    cur = cur[key];
  }
  return cur === undefined ? fallback : cur;
}

const input = fs.readFileSync(0, 'utf8');
for (const rawLine of input.split(/\r?\n/)) {
  const line = rawLine.trim();
  if (!line) continue;

  let diag;
  try {
    diag = JSON.parse(line);
  } catch {
    // Ignore non-JSON lines (e.g. accidental debug output).
    continue;
  }

  // Accept both the new shape and the older minimal shape.
  const k = diag.k;
  if (k && k !== 'diag') continue;

  const level = toSeverity(diag.level);
  const message = diag.message || '';

  const path = get(diag, ['source', 'path'], diag.file || '');
  const startLine = get(diag, ['range', 'start', 'line'], diag.line || 1);
  const startCol = get(diag, ['range', 'start', 'col'], 1);

  if (!path) {
    // VS Code problem matchers need a file; skip global diagnostics.
    continue;
  }

  process.stdout.write(`${path}:${startLine}:${startCol}: ${level}: ${message}\n`);
}
