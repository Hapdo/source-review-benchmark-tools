/**
 * Stripping the scored tree, and the line map that survives the stripping.
 *
 * ## What leaves the tree, and why it is more than the markers
 *
 * `lib/insecurity.ts` carries `// vuln-code-snippet vuln-line <key>` beside the defect, so the
 * markers are an answer key written next to the answer. They are not the *largest* one.
 * `data/static/codefixes/<key>.info.yml` explains each defect in prose — the scoring rules make
 * that same prose the cited evidence for every CWE label, which is the admission that it is the
 * answer key — and `data/static/challenges.yml` describes all 116 challenges, several by attack
 * class in words. The match rule grades class agreement, so `challenges.yml` hands a model half
 * of the score.
 *
 * So three things leave every scored tree: the marker comments, `data/static/codefixes/`, and
 * `data/static/challenges.yml`.
 *
 * ## Markers are stripped, not deleted
 *
 * Four of the seven types are suffixes on live code (`models/user.ts:75` is `      }, // …end
 * weakPasswordChallenge`). Deleting those lines deletes working code. So the rule is: remove the
 * marker comment; drop the line only if nothing but whitespace was holding it up.
 *
 * `server.ts:59` is the case that says the rule has to be applied by grammar and not by block
 * membership — it carries a `hide-line` outside every block, where upstream's own parser never
 * looks. It is inert to Juice Shop and not inert to the leak check, which searches for the string.
 *
 * ## Why the line map exists
 *
 * Stripping shifts line numbers, and the scoring unit is (block, CWE) with containment decided by
 * line. A finding at line 131 of the *stripped* `lib/insecurity.ts` has to be resolved back to the
 * block that used to be at line 121–140 of the marked one. Nothing in the stripped tree records
 * that, by construction — that is the point of stripping it. So the map is generated **here**, as
 * a side-car, during the edit that makes it necessary, rather than recomputed afterwards from a
 * tree that no longer contains the evidence.
 */
import { MARKER_TOKEN, findBlocks, parseMarker, splitLines } from "./markers.mjs";
import { MARKER_VOCABULARY_NOT_CORPUS } from "./inventory.mjs";

/** Paths that leave every scored tree whole. Data, so a result can report what it ran against. */
export const STRIPPED_PATHS = Object.freeze([
  "data/static/codefixes/",
  "data/static/challenges.yml",
]);

/**
 * Strip one file's marker comments.
 *
 * @param {string} source
 * @returns {{source: string, lineMap: number[], removed: number}} `lineMap[i]` is the 1-based
 *   line in the original file that produced 1-based stripped line `i + 1`.
 */
export function stripMarkers(source) {
  const { lines, eol } = splitLines(source);
  const out = [];
  const lineMap = [];
  let removed = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const marker = parseMarker(line);
    if (marker == null) {
      out.push(line);
      lineMap.push(i + 1);
      continue;
    }
    removed++;
    const before = line.slice(0, marker.index).replace(/\s+$/, "");
    if (before === "") continue; // the marker was the whole line
    out.push(before);
    lineMap.push(i + 1);
  }

  return { source: out.join(eol), lineMap, removed };
}

/**
 * Strip a whole tree, and build the block line map against the stripped result.
 *
 * The tree is passed in and out as a plain `path -> contents` map rather than read from disk, so
 * that the same function serves the local build and the verification against the bytes actually
 * pushed. Phase 4 verifies against the pushed SHA, and a verifier that could only read a working
 * copy would be verifying the wrong thing.
 *
 * @param {Map<string, string> | Record<string, string>} tree
 * @returns {{tree: Map<string, string>, lineMap: object, dropped: string[]}}
 */
export function stripTree(tree) {
  const entries = tree instanceof Map ? [...tree] : Object.entries(tree);
  /** @type {Map<string, string>} */
  const stripped = new Map();
  const dropped = [];
  const blocks = [];

  for (const [path, source] of entries) {
    if (STRIPPED_PATHS.some((p) => (p.endsWith("/") ? path.startsWith(p) : path === p))) {
      dropped.push(path);
      continue;
    }
    if (!source.includes(MARKER_TOKEN)) {
      stripped.set(path, source);
      continue;
    }

    const { source: out, lineMap } = stripMarkers(source);
    stripped.set(path, out);

    // Stripping is by grammar and applies to every file, so that no marker survives anywhere. The
    // **line map** is narrower: it is the scorer's input, and a block in a file that carries the
    // vocabulary without carrying corpus is not a defect anybody can find. Phase 1 measured the
    // cost of conflating the two — counting these turns 16 files into 19 and 35 keys into 36 — and
    // here it would put five items in the map that no branch can ever introduce a defect into.
    if (MARKER_VOCABULARY_NOT_CORPUS.includes(path)) continue;
    const found = findBlocks(source);

    // Invert the map once per file: original line -> stripped line, or null where the line went.
    const toStripped = new Map();
    lineMap.forEach((orig, idx) => toStripped.set(orig, idx + 1));

    const { lines: markedLines } = splitLines(source);
    for (const block of found) {
      // The lines upstream marks as the defect itself, in stripped coordinates. Not part of the
      // match rule — containment is by block — but the scorer reports localization precision, and
      // recovering these after the fact is exactly what stripping makes impossible.
      const vulnLines = [];
      const neutralLines = [];
      for (let n = block.start; n <= block.end; n++) {
        const m = parseMarker(markedLines[n - 1] ?? "");
        if (m == null || !m.keys.some((k) => block.keys.includes(k))) continue;
        const at = toStripped.get(n) ?? null;
        if (m.type === "vuln-line") vulnLines.push(at);
        else if (m.type === "neutral-line") neutralLines.push(at);
      }
      blocks.push({
        file: path,
        keys: block.keys,
        markedStart: block.start,
        markedEnd: block.end,
        // A block's boundary markers are usually whole lines and so have no stripped counterpart.
        // The span that survives is the first and last *surviving* line inside the marked span.
        start: firstSurviving(toStripped, block.start, block.end),
        end: lastSurviving(toStripped, block.start, block.end),
        vulnLines,
        neutralLines,
      });
    }
  }

  return { tree: stripped, lineMap: { blocks }, dropped };
}

function firstSurviving(toStripped, from, to) {
  for (let n = from; n <= to; n++) if (toStripped.has(n)) return toStripped.get(n);
  return null;
}

function lastSurviving(toStripped, from, to) {
  for (let n = to; n >= from; n--) if (toStripped.has(n)) return toStripped.get(n);
  return null;
}

/**
 * Where the marker token appears in the corpus **without being a marker**, pinned by path and
 * count.
 *
 * The corpus doc asks for a check that "no scored tree contains the marker string". Measured
 * against the pin, seven lines in five files contain the string and are not markers: upstream's
 * own parser holds the grammar as regex source, `server.ts:278` strips markers out of files it
 * serves as plain text, and four lines of prose in `rsn/` and `.ai/skills/` tell a contributor to
 * re-run the safety net. None of them is an answer, and deleting them would edit application code
 * to make a checker quiet.
 *
 * So the check is by **grammar**: a marker fails, a mention is recorded. The allowlist is pinned
 * because the grammar is the weaker half of that pair — a marker type upstream adds later would
 * read as a mention and pass. Pinning the counts means a new one fails on the run that introduces
 * it rather than on run 400, which is the same argument phase 1 makes for recording upstream's
 * suppression count as a corpus constant.
 *
 * Upstream's parser and its unit test are **not** here, although both are about the grammar: they
 * split the token across a concatenation so that the parser does not find itself. This file does
 * the same, for the same reason, which is why {@link MARKER_TOKEN} is built rather than written.
 */
export const MARKER_MENTIONS = Object.freeze({
  /** `server.ts:278` strips markers out of files it serves as plain text. */
  "server.ts": 1,
  /** "Your changes affect code inside a vuln-code-snippet block." */
  "rsn/rsnOutput.ts": 1,
  ".ai/skills/verify-rsn-fix/SKILL.md": 3,
  ".ai/skills/write-tests/SKILL.md": 1,
  ".ai/skills/write-tests/checklists/testing-checklist.md": 1,
});

/**
 * Verify that a tree carries none of what stripping removes.
 *
 * Phase 4 runs this **against the bytes the broker will fetch**, not against the local build. A
 * stripper that silently half-worked inflates a score and errors nothing, which is the same
 * argument the corpus doc already makes for the parse check: the failure mode is a number, not a
 * crash.
 *
 * @param {Map<string, string> | Record<string, string>} tree
 * @param {{mentions?: Record<string, number>}} [options] the pinned mention allowlist; pass `{}`
 *   to require that the token appear nowhere at all.
 * @returns {{ok: boolean, findings: {path: string, line: number|null, reason: string}[], mentions: number}}
 */
export function verifyStripped(tree, options = {}) {
  const allowed = options.mentions ?? MARKER_MENTIONS;
  const entries = tree instanceof Map ? [...tree] : Object.entries(tree);
  const findings = [];
  const seen = {};

  for (const [path, source] of entries) {
    for (const p of STRIPPED_PATHS) {
      if (p.endsWith("/") ? path.startsWith(p) : path === p) {
        findings.push({ path, line: null, reason: `stripped path present: ${p}` });
      }
    }
    if (!source.includes(MARKER_TOKEN)) continue;
    const { lines } = splitLines(source);
    lines.forEach((line, i) => {
      if (!line.includes(MARKER_TOKEN)) return;
      if (parseMarker(line) != null) {
        findings.push({ path, line: i + 1, reason: "marker survived stripping" });
        return;
      }
      seen[path] = (seen[path] ?? 0) + 1;
    });
  }

  for (const [path, count] of Object.entries(seen)) {
    if (allowed[path] === count) continue;
    findings.push({
      path,
      line: null,
      reason:
        allowed[path] == null
          ? `unpinned mention of the marker token (${count}); a new marker type would look like this`
          : `mention count moved: pinned ${allowed[path]}, found ${count}`,
    });
  }
  for (const [path, count] of Object.entries(allowed)) {
    if (seen[path] == null && entries.some(([p]) => p === path)) {
      findings.push({ path, line: null, reason: `pinned ${count} mentions, found none` });
    }
  }

  return {
    ok: findings.length === 0,
    findings,
    mentions: Object.values(seen).reduce((a, b) => a + b, 0),
  };
}
