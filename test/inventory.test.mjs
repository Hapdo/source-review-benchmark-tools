import { describe, expect, it } from "vitest";
import { buildInventory, countSuppressions } from "../src/inventory.mjs";
import { readCodefixes, readTree } from "../src/corpus.mjs";
import { corpusDir, haveCorpus, skipReason } from "./corpus.mjs";

/**
 * Phase 1's published tables are this parser's expected output.
 *
 * The parser was written in prose in the HapDo repository so that it could be re-derived before
 * this repository existed. These are the numbers it has to land on, and the reason a cheap model
 * could be trusted with phase 1 at all: the answer was already published, so the output is
 * checkable rather than taken on faith.
 */
describe.skipIf(!haveCorpus)(`phase 1's tables reproduce (${skipReason})`, () => {
  const inv = haveCorpus ? buildInventory(readTree(corpusDir), readCodefixes(corpusDir)) : null;

  it("lands on 35 challenges, 23 blocks, 16 files, 125 variants", () => {
    expect(inv.counts.blocks).toBe(23);
    expect(inv.counts.filesWithBlocks).toBe(16);
    expect(inv.counts.markedKeys).toBe(35);
    expect(inv.counts.variantFiles).toBe(125);
    expect(inv.counts.correctVariants).toBe(35);
    expect(inv.counts.brokenVariants).toBe(90);
    expect(inv.counts.infoYmlFiles).toBe(35);
  });

  it("intersects perfectly in both directions", () => {
    expect(inv.counts.intersection).toBe(35);
    expect(inv.counts.markedNotFixed).toEqual([]);
    expect(inv.counts.fixedNotMarked).toEqual([]);
  });

  it("reproduces the keys-per-block table", () => {
    expect(inv.counts.keysPerBlock).toEqual({ 1: 15, 2: 5, 3: 2, 5: 1 });
  });

  it("counts 23 blocks over 22 distinct defect sites", () => {
    // `iacLeakedKeyChallenge` occupies two byte-identical `networking.tf` files. The scoring unit
    // is (block, CWE), so labelling both would count one defect twice in the denominator.
    expect(inv.counts.distinctDefectSites).toBe(22);
    expect(inv.keyToBlock.iacLeakedKeyChallenge).toHaveLength(2);
    const [a, b] = inv.keyToBlock.iacLeakedKeyChallenge.map((id) =>
      inv.blocks.find((x) => x.id === id),
    );
    expect(a.file).toBe("infrastructure/terraform/networking.tf");
    expect(b.file).toBe("terraform/networking.tf");
  });

  it("finds no scanner suppressions of any of the three kinds", () => {
    // BM-11 expected a deliberately vulnerable teaching app to carry them so its own CI stays
    // green. It does not, and that is the better outcome: every `suppressed-by-branch` row a run
    // produces is one the generator introduced, so that channel starts clean.
    expect(countSuppressions(readTree(corpusDir))).toEqual({
      nosemgrep: 0,
      "gitleaks-allow": 0,
      "tool-config-file": 0,
    });
  });

  it("measures snippet lengths shorter than phase 1 published them", () => {
    // Phase 1's `snippetRanges` include the block's marker lines, which contribute nothing to the
    // displayed snippet: one line too many for every block, two where the `end` marker is on a
    // line of its own, three where a nested marker is glued to the line below it. Fact 3's promise
    // that "variant line i maps to a file line" does not hold against those ranges, which is why
    // the splicer takes its map from `extractSnippet` and not from the published JSON.
    const published = { B01: 30, B12: 8, B14: 12, B15: 38, B05: 202 };
    const measured = { B01: 28, B12: 7, B14: 11, B15: 36, B05: 199 };
    for (const [id, want] of Object.entries(measured)) {
      expect(inv.blocks.find((b) => b.id === id).snippetLineCount).toBe(want);
      expect(want).toBeLessThan(published[id]);
    }
  });

  it("records where upstream's stripping glued two file lines into one snippet line", () => {
    // Three blocks: the two that overlap in `app.routing.ts`, and the outer of the two in
    // `routes/chat.ts`. Only a *deletion* of such a line is ambiguous, and the splicer refuses it.
    const synthetic = inv.blocks.filter((b) => b.syntheticLines > 0).map((b) => b.id);
    expect(synthetic).toEqual(["B05", "B06", "B13"]);
  });
});
