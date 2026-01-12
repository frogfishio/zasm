#!/usr/bin/env node
/**
 * Validate a JSONL IR file against a schema (default: schema/ir/v1/record.schema.json) using AJV (draft 2020-12).
 *
 * Usage: node validate-ir.js --input path/to/file.jsonl [--schema path/to/schema.json]
 */

const fs = require("fs");
const path = require("path");
const Ajv = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

function die(msg) {
  console.error(msg);
  process.exit(1);
}

function main() {
  const args = process.argv.slice(2);
  let input = null;
  let schemaArg = null;
  for (let i = 0; i < args.length; i++) {
    if ((args[i] === "--input" || args[i] === "-i") && args[i + 1]) {
      input = args[i + 1];
      i++;
    } else if ((args[i] === "--schema" || args[i] === "-s") && args[i + 1]) {
      schemaArg = args[i + 1];
      i++;
    } else if (!input) {
      input = args[i];
    }
  }
  if (!input) {
    die("usage: node validate-ir.js --input path/to/file.jsonl [--schema path/to/schema.json]");
  }
  const irPath = path.resolve(process.cwd(), input);
  /* __dirname = src/lower/scripts; default schema lives at repo root /schema/ir/v1.1/record.schema.json */
  const schemaPath = schemaArg
    ? path.resolve(process.cwd(), schemaArg)
    : path.resolve(__dirname, "../../../schema/ir/v1.1/record.schema.json");

  let schema;
  try {
    schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
  } catch (err) {
    die(`failed to read schema: ${err.message}`);
  }

  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  let validate;
  try {
    validate = ajv.compile(schema);
  } catch (err) {
    die(`schema compile failed: ${err.message}`);
  }

  let contents;
  try {
    contents = fs.readFileSync(irPath, "utf8");
  } catch (err) {
    die(`cannot read input ${irPath}: ${err.message}`);
  }

  const lines = contents.split(/\r?\n/);
  let failures = 0;
  let checked = 0;

  lines.forEach((line, idx) => {
    if (!line.trim()) return;
    let obj;
    try {
      obj = JSON.parse(line);
    } catch (err) {
      console.error(`[line ${idx + 1}] invalid JSON: ${err.message}`);
      failures++;
      return;
    }
    checked++;
    const ok = validate(obj);
    if (!ok) {
      failures++;
      console.error(`[line ${idx + 1}] schema errors:`);
      for (const e of validate.errors || []) {
        console.error(`  - ${e.instancePath || "/"} ${e.message || ""}`);
      }
    }
  });

  if (checked === 0) {
    die("no records found to validate");
  }
  if (failures > 0) {
    die(`validation failed: ${failures} error(s) across ${checked} record(s)`);
  }
  console.log(`ok: ${checked} record(s) validated against schema`);
}

main();
