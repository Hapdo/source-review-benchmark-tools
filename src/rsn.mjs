/**
 * A port of upstream's Refactoring Safety Net (`rsn/rsnUtil.ts#computeDiffs`).
 *
 * ## Why this is in a benchmark repository
 *
 * `rsn/cache.json` is the one artifact upstream ships that states, per variant, *where that
 * variant differs from the snippet it patches* — 125 entries, locked by upstream's own CI. It is
 * therefore the only fixture available that can tell the splicer it aligned a variant wrongly.
 * Inventory fact 4 is the reason it is needed: variants run 4 to 291 lines, are often shorter than
 * the snippet, and 46 of the 125 differ from it on unmarked lines, so alignment is a diff and not
 * a line-count swap. A splicer checked only against "it parses" would pass while putting 46
 * variants in the wrong place.
 *
 * Reproducing `cache.json` exactly from a locally computed snippet proves two things at once: the
 * snippet extraction matches upstream's, and the diff alignment matches upstream's. Neither is
 * provable from the corpus alone.
 *
 * ## The one thing worth knowing about the algorithm
 *
 * It records line numbers **in the snippet's coordinate system** and drops any line upstream
 * marked `vuln-line` or `neutral-line` — those are expected to differ, since that is what a fix
 * changes. So `cache.json` is a record of *incidental* drift, which is exactly what makes it a
 * safety net and not a fix inventory. The `norm` counter in the removal pass is upstream's way of
 * converting the diff's running offset back into snippet coordinates; it is reproduced rather
 * than rewritten, because a cleaner equivalent that disagreed on one variant would be worse than
 * useless here.
 */
import { diffLines } from "diff";

/** Upstream's `filterString`: CR is dropped before diffing, so line endings never register as drift. */
export function filterString(text) {
  return text.replace(/\r/g, "");
}

/**
 * Compute one variant's `{ added, removed }` entry, in snippet line coordinates.
 *
 * @param {string} variantText contents of the `data/static/codefixes/<key>_<n>[_correct].<ext>` file
 * @param {{snippet: string, vulnLines: number[], neutralLines: number[]}} snippet
 * @returns {{added: number[], removed: number[]}}
 */
export function computeVariantDiff(variantText, snippet) {
  const added = [];
  const removed = [];
  const diff = diffLines(filterString(variantText), filterString(snippet.snippet));

  let line = 0;
  for (const part of diff) {
    if (!part.count) continue;
    if (part.removed) continue;
    const prev = line;
    line += part.count;
    if (!part.added) continue;
    for (let i = 0; i < part.count; i++) {
      if (!snippet.vulnLines.includes(prev + i + 1) && !snippet.neutralLines.includes(prev + i + 1)) {
        added.push(prev + i + 1);
      }
    }
  }

  line = 0;
  let norm = 0;
  for (const part of diff) {
    if (!part.count) continue;
    if (part.added) {
      norm--;
      continue;
    }
    const prev = line;
    line += part.count;
    if (!part.removed) continue;
    let temp = norm;
    for (let i = 0; i < part.count; i++) {
      if (
        !snippet.vulnLines.includes(prev + i + 1 - norm) &&
        !snippet.neutralLines.includes(prev + i + 1 - norm)
      ) {
        removed.push(prev + i + 1 - norm);
      }
      temp++;
    }
    norm = temp;
  }

  return { added, removed };
}

/** The challenge key a codefix filename belongs to. Upstream's rule: everything before the first `_`. */
export function keyOfVariantFile(filename) {
  return filename.split("_")[0];
}

/** Whether a codefix filename is the challenge's correct fix. */
export function isCorrectVariant(filename) {
  return /_\d+_correct\.[^.]+$/.test(filename);
}
