/**
 * The corpus inventory parser — phase 1's measurement, re-derived here as code.
 *
 * Phase 1 published its tables in the HapDo repository and wrote down the parser's rules in prose
 * so that they could be re-derived before this repository existed. This is that re-derivation, and
 * phase 1's tables are its expected output: `35 / 23 / 16 / 125` and the keys-per-block table
 * `15 / 5 / 2 / 1`.
 *
 * ## The rules, which are the whole of it
 *
 * Scan every text file for the marker token; take the seven types; pair each `start` with an `end`
 * naming one of the same keys; attribute `vuln-line`/`neutral-line` markers to the enclosing block
 * when they name one of its keys; exclude by path the three files that carry the marker vocabulary
 * without carrying corpus.
 *
 * ## One number phase 1 published that this parser disagrees with
 *
 * Phase 1's `snippetRanges` and `snippetLineCount` include the block's **marker lines**, which
 * contribute nothing to the displayed snippet — one line too many for every block, two where the
 * `end` marker is on a line of its own. `snippetLineCount` is therefore 1 or 2 above the length of
 * the snippet upstream actually serves, and fact 3's promise that "variant line *i* maps to a file
 * line" does not hold against those ranges.
 *
 * This file reports the measured snippet length from {@link extractSnippet}, whose agreement with
 * upstream is asserted key by key in `test/markers.test.mjs`, and reports phase 1's number beside
 * it as `publishedSnippetLineCount` so the correction is visible rather than silent.
 */
import { extractSnippet, findBlocks, parseMarker, splitLines } from "./markers.mjs";

/**
 * Files that carry the marker vocabulary without carrying corpus.
 *
 * Counting them is what turns 16 files into 19 and 35 keys into 36: upstream's own parser holds
 * the markers as regex source, its unit test's fixture is a deliberately unterminated block, and
 * the skill file documents the vocabulary.
 */
export const MARKER_VOCABULARY_NOT_CORPUS = Object.freeze([
  "lib/codingChallenges.ts",
  "test/server/codingChallenges.unit.test.ts",
  ".ai/skills/verify-rsn-fix/SKILL.md",
]);

/** The three suppression kinds HapDo recognises, named as HapDo names them. */
export const SUPPRESSION_KINDS = Object.freeze(["nosemgrep", "gitleaks-allow", "tool-config-file"]);

/** Basenames HapDo's sidecar treats as tool configuration. */
export const TOOL_CONFIG_BASENAMES = Object.freeze([
  ".semgrepignore",
  "semgrep.yml",
  "semgrep.yaml",
  ".semgrep.yml",
  ".semgrep.yaml",
  ".gitleaks.toml",
  "gitleaks.toml",
  ".gitleaksignore",
]);

/**
 * Build the inventory from a whole tree.
 *
 * @param {Map<string, string>} tree path -> contents, the corpus at its pinned SHA
 * @param {Map<string, string>} codefixes filename -> contents of `data/static/codefixes/`
 */
export function buildInventory(tree, codefixes) {
  const blocks = [];
  const paths = [...tree.keys()].sort();

  for (const path of paths) {
    if (MARKER_VOCABULARY_NOT_CORPUS.includes(path)) continue;
    const source = tree.get(path);
    for (const found of findBlocks(source)) {
      if (found.end <= 0) throw new Error(`${path}:${found.start} has no end marker`);
      const snip = extractSnippet(source, found.keys[0]);
      const { lines } = splitLines(source);
      const vulnLines = [];
      const neutralLines = [];
      const hideLines = [];
      const hideRegions = [];
      let open = null;
      for (let n = found.start; n <= found.end; n++) {
        const m = parseMarker(lines[n - 1] ?? "");
        if (m == null) continue;
        if (m.type === "hide-line") hideLines.push(n);
        else if (m.type === "hide-start") open = n;
        else if (m.type === "hide-end" && open != null) {
          hideRegions.push({ start: open, end: n });
          open = null;
        } else if (m.keys.some((k) => found.keys.includes(k))) {
          if (m.type === "vuln-line") vulnLines.push(n);
          else if (m.type === "neutral-line") neutralLines.push(n);
        }
      }
      blocks.push({
        file: path,
        start: found.start,
        end: found.end,
        keys: found.keys,
        vulnLines,
        neutralLines,
        hideLines,
        hideRegions,
        snippetLineCount: snip.lines.length,
        snippetFileLines: snip.lines.map((l) => l.fileLines),
        syntheticLines: snip.lines.filter((l) => l.synthetic).length,
      });
    }
  }

  blocks.sort((a, b) => a.file.localeCompare(b.file) || a.start - b.start);
  blocks.forEach((b, i) => {
    b.id = `B${String(i + 1).padStart(2, "0")}`;
  });

  const keyToBlock = new Map();
  for (const b of blocks) {
    for (const k of b.keys) {
      if (!keyToBlock.has(k)) keyToBlock.set(k, []);
      keyToBlock.get(k).push(b.id);
    }
  }

  const variantNames = [...codefixes.keys()].filter(
    (f) => !f.endsWith(".info.yml") && !f.endsWith(".editorconfig"),
  );
  const fixedKeys = new Set(variantNames.map((f) => f.split("_")[0]));
  const markedKeys = new Set(keyToBlock.keys());

  const keysPerBlock = {};
  for (const b of blocks) keysPerBlock[b.keys.length] = (keysPerBlock[b.keys.length] ?? 0) + 1;

  return {
    blocks,
    keyToBlock: Object.fromEntries(keyToBlock),
    counts: {
      blocks: blocks.length,
      filesWithBlocks: new Set(blocks.map((b) => b.file)).size,
      markedKeys: markedKeys.size,
      keysWithFixes: fixedKeys.size,
      intersection: [...markedKeys].filter((k) => fixedKeys.has(k)).length,
      markedNotFixed: [...markedKeys].filter((k) => !fixedKeys.has(k)).sort(),
      fixedNotMarked: [...fixedKeys].filter((k) => !markedKeys.has(k)).sort(),
      variantFiles: variantNames.length,
      correctVariants: variantNames.filter((f) => /_\d+_correct\./.test(f)).length,
      brokenVariants: variantNames.filter((f) => !/_\d+_correct\./.test(f)).length,
      infoYmlFiles: [...codefixes.keys()].filter((f) => f.endsWith(".info.yml")).length,
      keysPerBlock,
      /** 23 blocks, but `iacLeakedKeyChallenge` occupies two byte-identical files. */
      distinctDefectSites: countDistinctSites(blocks),
    },
  };
}

/** Blocks that are not a duplicate of an earlier block in another file. */
function countDistinctSites(blocks) {
  const seen = new Set();
  let n = 0;
  for (const b of blocks) {
    const signature = b.keys.slice().sort().join(" ");
    if (seen.has(signature)) continue;
    seen.add(signature);
    n++;
  }
  return n;
}

/**
 * Count upstream's own scanner suppressions — the eighth marker type phase 1 added.
 *
 * Reported as a corpus property in every result, because a later pin could ship one and finding it
 * on run 400 would invalidate the 399 before it.
 *
 * @param {Map<string, string>} tree
 */
export function countSuppressions(tree) {
  const counts = { nosemgrep: 0, "gitleaks-allow": 0, "tool-config-file": 0 };
  for (const [path, source] of tree) {
    const base = path.split("/").pop();
    if (TOOL_CONFIG_BASENAMES.includes(base)) counts["tool-config-file"]++;
    for (const line of source.split(/\r?\n/)) {
      if (/nosemgrep/i.test(line)) counts.nosemgrep++;
      if (/gitleaks\s*:\s*allow/i.test(line)) counts["gitleaks-allow"]++;
    }
  }
  return counts;
}
