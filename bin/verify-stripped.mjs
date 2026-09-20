#!/usr/bin/env node
/**
 * Verify a tree carries no marker, no codefix and no challenges.yml.
 *
 * Usage: node bin/verify-stripped.mjs <checkout>
 *
 * Phase 4 runs this against a checkout of the **pushed SHA**, not against the local build. A
 * stripper that silently half-worked inflates a score and errors nothing.
 */
import { readTree } from "../src/corpus.mjs";
import { verifyStripped } from "../src/strip.mjs";

const root = process.argv[2];
if (!root) {
  console.error("usage: verify-stripped.mjs <checkout>");
  process.exit(2);
}
const { ok, findings, mentions } = verifyStripped(readTree(root));
if (ok) {
  console.log(`verify-stripped: clean (${mentions} pinned mentions of the marker token).`);
  process.exit(0);
}
for (const f of findings) console.error(`  ${f.path}${f.line ? ":" + f.line : ""} — ${f.reason}`);
process.exit(1);
