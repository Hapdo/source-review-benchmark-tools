/**
 * The leak check: the gate that has to exist before this repository does.
 *
 * ## The rule it enforces
 *
 * This repository is public, because the method is where benchmarks are usually wrong and it
 * should be checkable. Its tests may therefore use only Juice Shop's **already-public marked
 * blocks** as fixtures — never a byte of the answer key, and never a held-out defect. A leaked
 * fixture retires a held-out generation somebody paid to write, and held-out generations are
 * single-use.
 *
 * ## Why it is a hash list and not a word list
 *
 * The forbidden content cannot be committed here to be searched for; that is what makes it
 * forbidden. So the check carries **hashes as data** and the content stays in the private
 * repository that generated them.
 *
 * The subtlety is that the private corpus is mostly *public* Juice Shop. A hash list built from
 * the private tree wholesale would ban the very fixtures the rule permits, and a check that fires
 * on legitimate use gets switched off. So {@link buildLeakHashes} subtracts the public corpus
 * first: a line is hashed only if it appears in the private artifact **and not** in upstream at
 * the pinned SHA. What remains is the part that is private because it is new — labels, held-out
 * defects, generated prose — which is exactly the population the rule is about.
 *
 * Short and structural lines (`});`, `}`) are dropped as well. They carry no information, they
 * collide with everything, and keeping them would make the check fire on brace style.
 */
import { createHash } from "node:crypto";

/** Below this many non-whitespace characters, a line is structure rather than content. */
export const MIN_SIGNIFICANT_CHARS = 24;

/**
 * Normalise a line so that the easy accidents do not defeat the check.
 *
 * Whitespace is collapsed, and a leading comment introducer is dropped. The second one is there
 * because the likely accident is not a verbatim copy of a source line — it is somebody pasting a
 * line of the answer key into a test as a comment explaining what the fixture is. Public lines go
 * through the same normalisation before being subtracted, so the two halves cannot disagree.
 */
export function normaliseLine(line) {
  return line
    .replace(/^\s*(\/\/+|#+|\*|<!--|--)\s*/, "")
    .replace(/\s+/g, " ")
    .trim();
}

/** Whether a line carries enough content to be worth hashing. */
export function isSignificant(line) {
  return normaliseLine(line).replace(/\s/g, "").length >= MIN_SIGNIFICANT_CHARS;
}

/** The hash a line is recorded under. Truncated: this is a tripwire, not a signature. */
export function hashLine(line) {
  return createHash("sha256").update(normaliseLine(line)).digest("hex").slice(0, 32);
}

/**
 * Build the hash list from the private artifacts, minus anything the public corpus already shows.
 *
 * Run in the **private** repository; commit only its output here.
 *
 * @param {Iterable<string>} privateTexts contents of the answer key and held-out sources
 * @param {Iterable<string>} publicTexts contents of upstream juice-shop at the pinned SHA
 * @returns {{version: number, minChars: number, hashes: string[]}}
 */
export function buildLeakHashes(privateTexts, publicTexts) {
  const publicHashes = new Set();
  for (const text of publicTexts) {
    for (const line of text.split(/\r?\n/)) {
      if (isSignificant(line)) publicHashes.add(hashLine(line));
    }
  }
  const hashes = new Set();
  for (const text of privateTexts) {
    for (const line of text.split(/\r?\n/)) {
      if (!isSignificant(line)) continue;
      const h = hashLine(line);
      if (!publicHashes.has(h)) hashes.add(h);
    }
  }
  return { version: 1, minChars: MIN_SIGNIFICANT_CHARS, hashes: [...hashes].sort() };
}

/**
 * Check a set of files against the hash list.
 *
 * @param {Map<string, string> | Record<string, string>} files path -> contents
 * @param {{hashes: string[]}} hashList
 * @returns {{ok: boolean, findings: {path: string, line: number}[]}}
 */
export function checkForLeaks(files, hashList) {
  const banned = new Set(hashList.hashes);
  const entries = files instanceof Map ? [...files] : Object.entries(files);
  const findings = [];
  for (const [path, text] of entries) {
    text.split(/\r?\n/).forEach((line, i) => {
      if (isSignificant(line) && banned.has(hashLine(line))) findings.push({ path, line: i + 1 });
    });
  }
  return { ok: findings.length === 0, findings };
}
