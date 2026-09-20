# source-review-benchmark-tools

Corpus tooling for HapDo's source-review benchmark: the inventory parser, the splicer, the marker
stripper, the side-car line map, and the leak check.

This repository is **public on purpose**. The method is where benchmarks are usually wrong, so it
should be checkable. The corpus mirror, the CWE answer key and the held-out defects are private and
are not here.

It operates on [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) pinned at
`1618a611b173b4bf114028e6e02549950606e29d`. Juice Shop is not vendored; point `JUICE_SHOP_DIR` at a
checkout.

```sh
npm ci
git clone --filter=blob:none https://github.com/juice-shop/juice-shop.git /tmp/juice-shop
git -C /tmp/juice-shop checkout 1618a611b173b4bf114028e6e02549950606e29d
JUICE_SHOP_DIR=/tmp/juice-shop npm test
```

## What the tools do

| Command | Does |
|---|---|
| `bin/leak-check.mjs` | refuses any file here whose line matches private content by hash |
| `bin/inventory.mjs <checkout>` | re-derives the corpus inventory — blocks, keys, variants, suppressions |
| `bin/strip.mjs <in> <out> <map>` | writes the scored tree and the line map generated from it |
| `bin/verify-stripped.mjs <checkout>` | asserts a tree carries no marker, no codefix, no `challenges.yml` |
| `bin/splice.mjs <checkout> <key> <variant>` | splices one codefix variant back into its block |

## The five things worth knowing before reading the code

**1. The splice target is the displayed snippet, not the block.** A variant in
`data/static/codefixes/` is an edit of what Juice Shop's UI *shows*, which is a non-contiguous
subsequence of the block's file lines with the marker comments taken off. `models/user.ts` is a
40-line block whose snippet is 7 lines; the other 33 are live code the UI hides. Writing a variant
over the block's line range deletes working code. Writing it over the snippet's range does not
parse.

**2. Four of the seven marker types appear as suffixes on live code.** `start`, `end`, `hide-end`
and `hide-line` all do. A `start` suffix puts the code before it *outside* the snippet; an `end`
suffix puts the code before it *inside*, as the snippet's last line. The two are not symmetric, so
a block's line span is not its snippet's line span.

**3. Markers pair per key, never by nesting.** `routes/chat.ts:188` carries one `end` closing two
`start`s, and two blocks in `app.routing.ts` overlap across 24 lines. A stack-based pairer mis-pairs
all four.

**4. Correctness here is agreement with upstream, and it is asserted rather than assumed.**
`extractSnippetUpstream` is a literal regex-for-regex port of Juice Shop's own extractor and does no
work — it is the oracle the mapped extractor is tested against, on all 36 (key, block) pairs.
`src/rsn.mjs` ports upstream's Refactoring Safety Net so that all 125 entries of `rsn/cache.json`
are reproduced from locally computed snippets. Together those prove the snippet extraction *and*
the diff alignment match upstream's, neither of which the corpus alone can confirm.

**5. Every splice is proved by round trip.** Splice a variant in, re-display the block, and demand
the variant back. Nothing weaker separates a correct splice from one that is two lines off, because
both produce a file that parses — and a tree that parses wrongly is scored rather than reported.

## What the tools refuse to do

**121 of the 125 variants splice and round-trip exactly.** The four that do not all belong to
`chatbotGreedyInjectionChallenge`, and they are not edits of their block's displayed snippet at all:
they drop the `export function chat () {` wrapper and dedent the tool object by four spaces.
Upstream's own safety net records the drift — 126 to 132 lines, against a next-highest of 30 — and
tolerates it, because upstream only ever *displays* a variant. Splicing one would delete a live
function declaration from `routes/chat.ts`, so `spliceVariantChecked` throws and says why.

`test/splice.test.mjs` asserts the separation rather than the list: the least-drifted refusal is
more drifted than the most-drifted acceptance. If that stops holding, either the four are no longer
special or a new variant has drifted and needs the same treatment.

## Licence

MIT. See `LICENSE`, and `NOTICE` for the two ports of upstream code and their attribution.
