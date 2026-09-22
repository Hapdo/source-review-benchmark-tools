#!/usr/bin/env node
/**
 * Generate the benchmark's pull-request branches as a git repository.
 *
 * Usage: node bin/generate-branches.mjs <juice-shop-checkout> <out-repo> [manifest.json]
 *
 * It builds the repaired base tree, strips it, verifies the strip, commits it as `main`, and
 * then cuts every branch both planners describe — 144 splice-derived branches over three classes
 * and 35 controls over two — each from the commit its plan names, published as `pr/001`…`pr/179`
 * with a message naming only the paths it changes. The manifest defaults to
 * `<out-repo>.manifest.json`, **beside** the repository rather than inside it, for the reason
 * `bin/build-base.mjs` keeps its own manifest outside the tree: anything committed that upstream
 * does not have is a diff every generated pull request carries. It is also the only place that
 * says which `pr/NNN` is which class, so it is private and is never pushed with the refs.
 *
 * Three refusals worth knowing about before reading the code:
 *
 * - **The output repository must be new or empty.** A repository with refs from an earlier run has
 *   refs this manifest does not vouch for, and a reviewer cannot tell them apart.
 * - **Nothing is ever written into the checkout**, and no git command is run inside it. The corpus
 *   mirror is the pin; a tool that could modify it could invalidate every measurement already
 *   taken against it. The checkout's SHA is read out of `.git/HEAD` by hand, exactly as
 *   `bin/build-base.mjs` reads it and for the same reason.
 * - **Nothing pushes.** This writes objects and refs into a local bare repository and stops there.
 *   Where those refs go afterwards is a decision with a blast radius, and it is not this script's.
 */
import fs from "node:fs";
import path from "node:path";
import { PINNED_SHA_OF_CORPUS, generateBranchRepo } from "../src/branch-repo.mjs";

const [input, outArg, manifestArg] = process.argv.slice(2);
if (!input || !outArg) {
  console.error("usage: generate-branches.mjs <juice-shop-checkout> <out-repo> [manifest.json]");
  process.exit(2);
}

const checkout = path.resolve(input);
const outRepo = path.resolve(outArg);
const manifestPath = manifestArg ? path.resolve(manifestArg) : `${outRepo}.manifest.json`;

if (!fs.existsSync(path.join(checkout, "data/static/codefixes"))) {
  fail(`${checkout} is not a juice-shop checkout — it has no data/static/codefixes/`);
}
if (outRepo === checkout || isInside(outRepo, checkout) || isInside(checkout, outRepo)) {
  fail("the output repository and the checkout overlap. This never writes into the corpus.");
}
if (fs.existsSync(outRepo) && fs.readdirSync(outRepo).length > 0) {
  fail(`${outRepo} is not empty. The repository is generated fresh so that the manifest describes all of it.`);
}

let result;
try {
  result = await generateBranchRepo({ checkout, outRepo, corpusSha: headSha(checkout) });
} catch (error) {
  console.error(`generate-branches: ${error.name}: ${error.message}`);
  process.exit(1);
}

const { manifest } = result;
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");

const byClass = Object.entries(manifest.counts.byClass)
  .map(([cls, n]) => `${n} ${cls}`)
  .join(", ");
console.log(
  `generate-branches: ${manifest.counts.total} branches (${byClass}) over ` +
    `${manifest.counts.changedFiles} changed files, on ${manifest.base.branch} at ` +
    `${manifest.base.commit} (${manifest.base.files} files, ${manifest.base.rewritten} rewritten). ` +
    `Repository: ${outRepo}. Manifest: ${manifestPath}`,
);
if (manifest.corpus.matchesPin === false) {
  console.warn(`generate-branches: WARNING — built from ${manifest.corpus.sha}, not the pinned ${PINNED_SHA_OF_CORPUS}.`);
}

/**
 * The checkout's SHA, read rather than shelled out for.
 *
 * Lifted from `bin/build-base.mjs`, which explains why: the SHA is being recorded *about* the
 * corpus mirror, and a build step that runs git inside it is a build step that can change it.
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

function isInside(child, parent) {
  const rel = path.relative(parent, child);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

function fail(message) {
  console.error(`generate-branches: ${message}`);
  process.exit(2);
}
