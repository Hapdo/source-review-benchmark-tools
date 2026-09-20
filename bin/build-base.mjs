#!/usr/bin/env node
/**
 * Build the repaired base tree — upstream Juice Shop with every key's `_N_correct` fix applied.
 *
 * Usage: node bin/build-base.mjs <juice-shop-checkout> <out-dir> [manifest.json]
 *
 * The manifest defaults to `<out-dir>.manifest.json`, **beside** the tree rather than inside it,
 * because the tree is pushed as a branch and anything in it that upstream does not have is a diff
 * every generated pull request carries.
 *
 * Two refusals worth knowing about before reading the code:
 *
 * - **The output directory must be new or empty.** Writing into a populated one would leave files
 *   from an older build that this build did not produce, and the manifest would vouch for a tree
 *   that is partly something else.
 * - **Nothing is ever written into the checkout.** The corpus mirror is the pin; a tool that could
 *   modify it could invalidate every measurement taken against it, including the ones already
 *   published. The check is on resolved real paths, so a symlink does not get around it.
 */
import fs from "node:fs";
import path from "node:path";
import { readTree, readCodefixes } from "../src/corpus.mjs";
import { buildBaseTree, verifyBaseTree, sha256, unboundSymbolsIntroduced } from "../src/base-tree.mjs";

const [input, outDir, manifestArg] = process.argv.slice(2);
if (!input || !outDir) {
  console.error("usage: build-base.mjs <juice-shop-checkout> <out-dir> [manifest.json]");
  process.exit(2);
}

const checkout = path.resolve(input);
const target = path.resolve(outDir);
const manifestPath = manifestArg ? path.resolve(manifestArg) : `${target}.manifest.json`;

if (!fs.existsSync(path.join(checkout, "data/static/codefixes"))) {
  fail(`${checkout} is not a juice-shop checkout — it has no data/static/codefixes/`);
}
if (target === checkout || isInside(target, checkout) || isInside(checkout, target)) {
  fail(`the output directory and the checkout overlap. This never writes into the corpus.`);
}
if (fs.existsSync(target) && fs.readdirSync(target).length > 0) {
  fail(`${target} is not empty. The base tree is built into a fresh directory so that the manifest describes all of it.`);
}

const tree = readTree(checkout);
const codefixes = readCodefixes(checkout);
const sha = headSha(checkout);

let built;
let changed;
let manifest;
let report;
try {
  ({ tree: built, changed, manifest } = await buildBaseTree(tree, codefixes, { sha }));
  report = verifyBaseTree({ upstream: tree, built, codefixes });
} catch (error) {
  console.error(`build-base: ${error.name}: ${error.message}`);
  process.exit(1);
}

// Copy the checkout first — binaries and everything else the text map does not carry — and then
// overwrite the sixteen files that changed. Copying and then replacing, rather than writing the
// map, is what makes "every file that holds no block is byte-identical to upstream" true of the
// bytes on disk rather than only of the map in memory.
fs.mkdirSync(target, { recursive: true });
fs.cpSync(checkout, target, { recursive: true, filter: (src) => path.basename(src) !== ".git" });
for (const rel of changed) fs.writeFileSync(path.join(target, rel), built.get(rel));

manifest.files = hashTree(target);
manifest.verification = {
  keyStatus: report.keyStatus,
  counts: report.counts,
  ruled: report.ruled,
  handRepaired: report.handRepaired,
  mirroredSites: report.mirrors,
  unboundSymbolsIntroduced: unboundSymbolsIntroduced(tree, built),
};
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");

console.log(
  `build-base: ${report.counts.keys} keys over ${report.counts.blocks} blocks — ` +
    `${report.counts.spliced} spliced, ${report.counts.ruled} ruled, ` +
    `${report.counts.handRepaired} repaired by hand (${report.handRepaired.join(", ")}). ` +
    `${changed.length} files changed, ${Object.keys(manifest.files).length} written. ` +
    `Manifest: ${manifestPath}`,
);
if (manifest.upstream.matchesPin === false) {
  console.warn(`build-base: WARNING — built from ${sha}, not the pinned ${manifest.upstream.pinnedSha}.`);
}

/**
 * The checkout's SHA, read rather than shelled out for.
 *
 * `git rev-parse` would be the obvious call and this deliberately does not make it: the SHA is
 * being recorded *about* the corpus mirror, and a build step that runs git inside it is a build
 * step that can change it. A detached HEAD — which is what checking out a pin produces — holds the
 * SHA directly.
 */
function headSha(root) {
  const headPath = path.join(root, ".git/HEAD");
  if (!fs.existsSync(headPath)) return null;
  const head = fs.readFileSync(headPath, "utf8").trim();
  if (/^[0-9a-f]{40}$/.test(head)) return head;
  const ref = head.replace(/^ref:\s*/, "");
  const refPath = path.join(root, ".git", ref);
  if (fs.existsSync(refPath)) return fs.readFileSync(refPath, "utf8").trim();
  const packed = path.join(root, ".git/packed-refs");
  if (!fs.existsSync(packed)) return null;
  for (const line of fs.readFileSync(packed, "utf8").split("\n")) {
    const m = /^([0-9a-f]{40}) (.+)$/.exec(line);
    if (m && m[2] === ref) return m[1];
  }
  return null;
}

/** Every file in the written tree, by relative path, with its sha256. Sorted, so it diffs. */
function hashTree(root) {
  const out = {};
  const walk = (rel) => {
    const abs = rel === "" ? root : path.join(root, rel);
    for (const entry of fs.readdirSync(abs, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const childRel = rel === "" ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) walk(childRel);
      else if (entry.isFile()) out[childRel] = sha256(fs.readFileSync(path.join(root, childRel)));
    }
  };
  walk("");
  return out;
}

function isInside(child, parent) {
  const rel = path.relative(parent, child);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

function fail(message) {
  console.error(`build-base: ${message}`);
  process.exit(2);
}
