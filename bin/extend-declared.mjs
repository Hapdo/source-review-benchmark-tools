#!/usr/bin/env node
/**
 * Add declared items to a repository `bin/generate-branches.mjs` wrote.
 *
 * Usage: node bin/extend-declared.mjs <repo.git> <declared.mjs> --first <N> [manifest.json]
 *
 * `<declared.mjs>` is the private answer-key repository's `src/declared.mjs`: it exports
 * `BASE_COMMIT` and `DECLARED_FIXES`. It is read from where it is and never copied, because it is
 * answer-key content — see `src/declared-items.mjs`. `--first` is the first published number the
 * new branches take, one past the highest `pr/NNN` already in the repository.
 *
 * This **changes the repository in place**: `main` moves forward one commit and new `pr/NNN` refs
 * appear. Run it on a copy of the repository that was published, so the published one stays as it
 * was read back. Nothing pushes.
 *
 * The manifest defaults to `<repo>.declared.manifest.json`, beside the repository, and is private
 * for the reason `bin/generate-branches.mjs` gives: it says which `pr/NNN` is which class.
 */
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { extendBranchRepo } from "../src/declared-items.mjs";

const args = process.argv.slice(2);
const firstAt = args.indexOf("--first");
const firstNumber = firstAt >= 0 ? Number(args[firstAt + 1]) : NaN;
const positional = args.filter((a, i) => !a.startsWith("--") && i !== firstAt + 1);
const [repoArg, declaredArg, manifestArg] = positional;

if (!repoArg || !declaredArg || !Number.isInteger(firstNumber)) {
  console.error("usage: extend-declared.mjs <repo.git> <declared.mjs> --first <N> [manifest.json]");
  process.exit(2);
}

const repo = path.resolve(repoArg);
const declaredPath = path.resolve(declaredArg);
const toolsRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const relToTools = path.relative(toolsRoot, declaredPath);
if (!relToTools.startsWith("..") && !path.isAbsolute(relToTools)) {
  fail(`${declaredPath} is inside this public repository. Declarations are answer-key content and live in the private one.`);
}
if (!fs.existsSync(path.join(repo, "HEAD"))) fail(`${repo} is not a bare git repository`);

const declared = await import(pathToFileURL(declaredPath).href);
if (typeof declared.BASE_COMMIT !== "string" || !Array.isArray(declared.DECLARED_FIXES)) {
  fail(`${declaredPath} does not export BASE_COMMIT and DECLARED_FIXES`);
}

const manifestPath = manifestArg ? path.resolve(manifestArg) : `${repo.replace(/\/$/, "")}.declared.manifest.json`;
const indexFile = path.join(repo, "hd56-declared.index");
let result;
try {
  result = extendBranchRepo(repo, { baseCommit: declared.BASE_COMMIT, fixes: declared.DECLARED_FIXES, firstNumber, indexFile });
} catch (error) {
  console.error(`extend-declared: ${error.name}: ${error.message}`);
  process.exit(1);
} finally {
  fs.rmSync(indexFile, { force: true });
}

const { manifest } = result;
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
const refs = manifest.branches.map((b) => b.ref).sort();
console.log(
  `extend-declared: main ${manifest.base.previous.slice(0, 8)} → ${manifest.base.commit.slice(0, 8)} ` +
    `(${manifest.base.changedPaths.length} files); ${manifest.counts.total} new branches, ${refs[0]}…${refs.at(-1)}. ` +
    `Manifest: ${manifestPath}`,
);

function fail(message) {
  console.error(`extend-declared: ${message}`);
  process.exit(2);
}
