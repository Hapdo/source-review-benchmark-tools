#!/usr/bin/env node
/**
 * The parse gate, as CI runs it — phase 4, property 1 of the repaired base tree.
 *
 * Usage: node bin/parse-check.mjs <tree-dir> [--all] [--files <list>] [--inventory <json>] [--json]
 *
 *   (default)            the scored files, derived from the marked blocks the tree itself carries
 *   --all                every file in the tree in a language this gate can check
 *   --files <list>       a file of newline-separated repository-relative paths, or `-` for stdin
 *   --inventory <json>   a published inventory's `filesWithBlocks`; use this for a stripped tree,
 *                        which carries no markers to derive the list from
 *   --json               the whole verdict, for a caller that wants the per-file rows
 *
 * Exit 0 every target parsed and was scanned, 1 on a finding, 2 when the gate could not run.
 * Two non-zero codes rather than one because they are different jobs: 1 is about the tree and 2 is
 * about the machine, and collapsing them is how a broken toolchain gets pasted into a pull request
 * as evidence about a change.
 */
import fs from "node:fs";
import { checkTree, formatVerdict } from "../src/parse-check.mjs";

/** Positional and valued flags kept apart by one pass, so `--files <path>` cannot be read as the tree. */
const VALUED = new Set(["--files", "--inventory"]);
const argv = process.argv.slice(2);
const opts = {};
const positional = [];
for (let i = 0; i < argv.length; i++) {
  if (VALUED.has(argv[i])) opts[argv[i]] = argv[++i];
  else if (argv[i].startsWith("--")) opts[argv[i]] = true;
  else positional.push(argv[i]);
}
const flag = (name) => (typeof opts[name] === "string" ? opts[name] : undefined);
const treeDir = positional[0];

if (!treeDir) {
  console.error("usage: parse-check.mjs <tree-dir> [--all] [--files <list>] [--inventory <json>] [--json]");
  process.exit(2);
}

const listPath = flag("--files");
let files;
try {
  files = listPath
    ? (listPath === "-" ? fs.readFileSync(0, "utf8") : fs.readFileSync(listPath, "utf8"))
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l !== "" && !l.startsWith("#"))
    : undefined;
} catch (err) {
  // Exit 2, not the 1 an uncaught throw would give: a list this process could not read is a fact
  // about the invocation, and reporting it with the code that means "the tree has a finding" is
  // the exact confusion the two codes exist to prevent.
  console.error(`parse-check: could not read the file list at ${listPath} — ${err.message}`);
  process.exit(2);
}

const verdict = checkTree(treeDir, { all: opts["--all"] === true, files, inventory: flag("--inventory") });

if (opts["--json"] === true) {
  // `files` carries Maps' contents already flattened by verdictFor, so this is plain JSON.
  console.log(JSON.stringify(verdict, null, 2));
} else {
  const out = formatVerdict(verdict);
  if (verdict.ok) console.log(out);
  else console.error(out);
}

// `ok` decides, not a string: "unavailable" and "fail" are both non-passing and neither is a skip.
process.exit(verdict.ok ? 0 : verdict.status === "fail" ? 1 : 2);
