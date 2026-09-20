/**
 * Locating the corpus for the conformance tests.
 *
 * The tests that matter here are conformance tests: they assert agreement with **upstream Juice
 * Shop at the pinned SHA**, which this repository does not and must not vendor. So they need a
 * checkout, and they say so rather than silently passing without one.
 *
 * `JUICE_SHOP_DIR` points at it. CI clones the pin; a contributor exports it. When it is absent
 * the conformance suites skip with a message naming what did not run — never a green tick for a
 * suite that did nothing, which is the shape HapDo's own issue #868 is about.
 */
import fs from "node:fs";
import path from "node:path";

export const PINNED_SHA = "1618a611b173b4bf114028e6e02549950606e29d";

export const corpusDir = process.env.JUICE_SHOP_DIR ?? "";

export const haveCorpus =
  corpusDir !== "" && fs.existsSync(path.join(corpusDir, "data/static/codefixes"));

export const skipReason =
  `set JUICE_SHOP_DIR to a juice-shop checkout at ${PINNED_SHA} to run the conformance suite`;

export function read(rel) {
  return fs.readFileSync(path.join(corpusDir, rel), "utf8");
}

export function codefix(name) {
  return read(`data/static/codefixes/${name}`);
}

export function variantNames() {
  return fs
    .readdirSync(path.join(corpusDir, "data/static/codefixes"))
    .filter((f) => !f.endsWith(".info.yml") && !f.endsWith(".editorconfig"))
    .sort();
}
