#!/usr/bin/env node
/**
 * Strip a tree for scoring, and write the side-car line map beside it.
 *
 * Usage: node bin/strip.mjs <in-checkout> <out-dir> <line-map.json>
 *
 * The map is generated here, from the stripped result, because stripping shifts the line numbers
 * that containment is decided by and the stripped tree no longer records where a block was.
 */
import fs from "node:fs";
import { readTree, writeTree } from "../src/corpus.mjs";
import { stripTree, verifyStripped } from "../src/strip.mjs";

const [input, outDir, mapPath] = process.argv.slice(2);
if (!input || !outDir || !mapPath) {
  console.error("usage: strip.mjs <in-checkout> <out-dir> <line-map.json>");
  process.exit(2);
}

const { tree, lineMap, dropped } = stripTree(readTree(input));
const verdict = verifyStripped(tree);
if (!verdict.ok) {
  console.error("strip: the stripped tree still carries what stripping removes:");
  for (const f of verdict.findings) console.error(`  ${f.path}${f.line ? ":" + f.line : ""} — ${f.reason}`);
  process.exit(1);
}

fs.mkdirSync(outDir, { recursive: true });
writeTree(outDir, tree);
fs.writeFileSync(mapPath, JSON.stringify(lineMap, null, 2) + "\n");
console.log(
  `strip: ${tree.size} files, ${dropped.length} dropped, ${lineMap.blocks.length} blocks mapped, ` +
    `${verdict.mentions} pinned mentions of the marker token left in place.`,
);
