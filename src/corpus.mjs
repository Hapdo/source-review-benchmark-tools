/**
 * Reading a corpus checkout into the `path -> contents` map every other module here takes.
 *
 * Everything else in this repository works on that map rather than on a directory. That is
 * deliberate: phase 4 verifies stripping **against the bytes the broker will fetch from GitHub**,
 * not against a local build, and a verifier that could only read a working copy would be verifying
 * the wrong thing. Keeping the filesystem in one small module is what makes the other one possible.
 */
import fs from "node:fs";
import path from "node:path";

/** Directories never worth walking, and never part of the corpus. */
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", "coverage"]);

/** Extensions read as binary and excluded — markers only ever live in text. */
const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".svg", ".pdf", ".zip", ".gz",
  ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".wav", ".bin", ".exe", ".jar",
]);

/**
 * Read a checkout into a `path -> contents` map, paths relative and POSIX-separated.
 *
 * @param {string} root
 * @returns {Map<string, string>}
 */
export function readTree(root) {
  /** @type {Map<string, string>} */
  const tree = new Map();
  walk(root, "", tree);
  return tree;
}

function walk(root, rel, tree) {
  const abs = rel === "" ? root : path.join(root, rel);
  for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
    const childRel = rel === "" ? entry.name : `${rel}/${entry.name}`;
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(root, childRel, tree);
      continue;
    }
    if (!entry.isFile()) continue;
    if (BINARY_EXT.has(path.extname(entry.name).toLowerCase())) continue;
    const buf = fs.readFileSync(path.join(root, childRel));
    if (buf.includes(0)) continue; // a NUL byte means it is not text, whatever the extension says
    tree.set(childRel, buf.toString("utf8"));
  }
}

/** Read `data/static/codefixes/` into a `filename -> contents` map. */
export function readCodefixes(root) {
  const dir = path.join(root, "data/static/codefixes");
  /** @type {Map<string, string>} */
  const fixes = new Map();
  for (const name of fs.readdirSync(dir)) {
    fixes.set(name, fs.readFileSync(path.join(dir, name), "utf8"));
  }
  return fixes;
}

/** Write a `path -> contents` map out as a tree. Used to materialise the stripped corpus. */
export function writeTree(root, tree) {
  for (const [rel, contents] of tree) {
    const target = path.join(root, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, contents);
  }
}
