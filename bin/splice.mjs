#!/usr/bin/env node
/**
 * Splice one codefix variant into one file, and prove it by re-extracting the block.
 *
 * Usage: node bin/splice.mjs <checkout> <challengeKey> <variant-filename> [--write]
 */
import fs from "node:fs";
import path from "node:path";
import { spliceVariantChecked } from "../src/splice.mjs";

const [root, key, variant, ...rest] = process.argv.slice(2);
if (!root || !key || !variant) {
  console.error("usage: splice.mjs <checkout> <challengeKey> <variant-filename> [--write]");
  process.exit(2);
}

const { findBlocks } = await import("../src/markers.mjs");
const { readTree } = await import("../src/corpus.mjs");
const tree = readTree(root);
const target = [...tree].find(([, src]) =>
  findBlocks(src).some((b) => b.keys.includes(key)),
);
if (!target) {
  console.error(`splice: no block for ${key}`);
  process.exit(1);
}

const variantText = fs.readFileSync(path.join(root, "data/static/codefixes", variant), "utf8");
try {
  const { source, stats } = spliceVariantChecked(target[1], key, variantText);
  if (rest.includes("--write")) fs.writeFileSync(path.join(root, target[0]), source);
  else process.stdout.write(source);
  console.error(`splice: ${target[0]} ${JSON.stringify(stats)}`);
} catch (error) {
  console.error(`splice: ${error.message}`);
  process.exit(1);
}
