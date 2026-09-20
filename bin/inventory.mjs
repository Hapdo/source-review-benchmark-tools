#!/usr/bin/env node
/**
 * Re-derive the corpus inventory. Phase 1's published tables are the expected output.
 *
 * Usage: node bin/inventory.mjs <juice-shop-checkout> [> inventory.json]
 */
import { readCodefixes, readTree } from "../src/corpus.mjs";
import { buildInventory, countSuppressions } from "../src/inventory.mjs";

const root = process.argv[2];
if (!root) {
  console.error("usage: inventory.mjs <juice-shop-checkout>");
  process.exit(2);
}
const tree = readTree(root);
const inventory = buildInventory(tree, readCodefixes(root));
process.stdout.write(
  JSON.stringify({ ...inventory, suppressions: countSuppressions(tree) }, null, 2) + "\n",
);
