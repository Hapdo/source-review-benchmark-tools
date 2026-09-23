#!/usr/bin/env node
/**
 * The leak check, as CI runs it. The first thing this repository had, before it had anything else.
 *
 * Usage: node bin/leak-check.mjs [--hashes leak-hashes.json] [paths...]
 *
 * Exit 0 clean, 1 on a finding, 2 if the hash list is missing — which is a failure and not a skip.
 * A leak check that passes because it could not find its own list is the shape of every control
 * that reports on the machine rather than on the change.
 */
import fs from "node:fs";
import path from "node:path";
import { checkForLeaks } from "../src/leak-check.mjs";

const args = process.argv.slice(2);
const hashArg = args.indexOf("--hashes");
const hashPath = hashArg >= 0 ? args[hashArg + 1] : "leak-hashes.json";
// Only the argument after `--hashes` is its value. Without `--hashes`, `hashArg + 1` is 0 and the
// first path would be dropped — and the check would run over the defaults and report them clean.
const roots = args.filter((a, i) => !a.startsWith("--") && (hashArg < 0 || i !== hashArg + 1));

if (!fs.existsSync(hashPath)) {
  console.error(`leak-check: no hash list at ${hashPath}.`);
  console.error("Generate it in the private repository with buildLeakHashes() and commit it here.");
  process.exit(2);
}
const hashList = JSON.parse(fs.readFileSync(hashPath, "utf8"));

const SKIP = new Set([".git", "node_modules", "coverage", "dist"]);
const files = new Map();
for (const root of roots.length > 0 ? roots : ["test", "fixtures", "src", "bin"]) {
  if (!fs.existsSync(root)) continue;
  for (const rel of walk(root)) files.set(rel, fs.readFileSync(rel, "utf8"));
}

function* walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) continue;
    const rel = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(rel);
    else if (entry.isFile()) yield rel;
  }
}

const { ok, findings } = checkForLeaks(files, hashList);
if (ok) {
  console.log(`leak-check: ${files.size} files, ${hashList.hashes.length} hashes, clean.`);
  process.exit(0);
}
console.error(`leak-check: ${findings.length} line(s) match private content.`);
for (const f of findings) console.error(`  ${f.path}:${f.line}`);
console.error("\nA fixture may use only Juice Shop's already-public marked blocks.");
process.exit(1);
