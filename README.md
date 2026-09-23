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
| `bin/build-base.mjs <checkout> <outdir> [manifest]` | composes all 35 correct variants into the repaired base tree |
| `bin/parse-check.mjs <tree>` | gates a tree on semgrep 1.99.0 parsing every scored file |
| `bin/generate-branches.mjs <checkout> <outrepo> [manifest]` | writes the 179 pull-request branches into a bare git repository |
| `bin/extend-declared.mjs <repo.git> <declared.mjs> --first N` | adds declared items: one new `main` commit and two branches per item |

## The branch repository

`bin/generate-branches.mjs` turns the two branch plans into refs. It commits the repaired,
stripped base tree as `main`, then cuts 144 splice-derived branches — 22 introduce-the-vuln,
87 broken-fix, 35 correct-fix — and 35 controls, 179 in all, each from the commit its plan names.
The fix classes are cut from the **introduce-the-vuln head for the same block**, because a fix
branch cut from the base would be a diff against code that was never vulnerable. Nothing pushes:
it writes a local bare repository and stops.

**What gets published says nothing the diff does not.** The plan names branches by class and
challenge — `hd85/broken-fix/accessLogDisclosureChallenge_2`, `control/marked/…` — and those names
are the answer key. So the repository holds only `main` and `pr/001`…`pr/179`, numbered by a digest
of each plan name so that no class sits in its own number range, and every commit message is
`Update <the paths it changes>`; the base commit says `Initial import`. Verification asserts both
against the repository, not the records. The mapping from `pr/NNN` back to class, block and variant
is in the manifest only, which is written beside the repository, is private, and is never pushed
with the refs.

**Every branch is its own commit.** Twelve branches make the same edit as another — several
challenge keys share one fix — and with neutral messages they would be the same commit. GitHub
attaches checks to a commit, so those pull requests would share one review. Each branch commit is
therefore dated the pinned date plus its `pr/NNN` number in seconds, and the manifest's
`sameChangeAs` names each group so the scorer does not count one change as several observations.

It writes no working tree at any point. Everything is plumbing over an explicit index —
`hash-object`, `update-index`, `write-tree`, `commit-tree` — because a working tree is where the
nondeterminism lives: `core.autocrlf` rewrites line endings on the way in, `.gitattributes`
filters run on `git add` (the corpus ships one), and hooks run on `git commit`.

**Two runs must produce the same SHAs, and that is asserted rather than intended.** A commit hashes
an author name, an author email, a committer name, a committer email and two timestamps, so all six
are pinned, the repository's own config is written rather than inherited, and every `git`
invocation runs with the machine's config pointed at `/dev/null`. `test/branch-repo.test.mjs`
generates the whole thing twice, into two repositories, and requires every ref and the entire
manifest to be byte-identical; a third fixture run does it with a hostile identity in the
environment. The base branch is at `26123d9fda6a6b9a1c3f2acc339ac4ae10dfe602`, pinned in the tests,
because the result contract cites a base SHA per class and a SHA that moves makes a result
unreproducible.

The order is splice-then-strip — splicing needs the markers, and the scored tree has none — so
every branch is verified **at the git level** after it is written: it changes exactly the paths the
plan lists, the bytes at those paths are the planner's bytes, the diff is non-empty, no line of it
mentions the marker token, and the lines `git diff` prints are the lines the edit makes. That last
one is compared as a multiset and not as a sequence, which is a ruling and not a shortcut: on six
branches, all of them `frontend/src/app/app.routing.ts`, git anchors its hunk one bare `  {`
earlier than `src/base-tree.mjs`'s `lineHunks` does. Both alignments are minimal and the file
repeats the line, so there is more than one minimal alignment. Asserting the sequence would be
asserting which Myers implementation ran.

## Declared items

Some defects are real but upstream never marked them, so nothing here can derive their site or
their fix. They are **declared** instead, in the private answer-key repository, because a declared
site and fix say which unmarked lines the benchmark scores. `bin/extend-declared.mjs` takes that
file by path and never copies it; it refuses a path inside this repository. `leak-hashes.json`
carries the fixes' lines, so a fixture here cannot contain one.

It extends a repository `bin/generate-branches.mjs` already wrote, **in place, without rewriting
anything**, because those refs may already be published and read back. `main` gains one commit on
top of the commit the declarations name, applying every declared fix, and fast-forwards. Every
existing branch keeps its SHA; for those branches the declared sites are code their base still
carries. Each item then gets an introduce-the-vuln branch from the new `main`, carrying every
other item's fix but not its own, and a correct-fix branch cut from that head. There is no
broken-fix class, because upstream wrote no broken variants for these. The new branches are
numbered on from `--first` in the same digest order, verified at the git level like the rest,
and recorded in a second private manifest beside the repository.

A declared fix is exact text to replace, with a count, not a line number: a line number that is
off by one still applies, to the wrong line. Run it on a copy of the published repository.

## The six things worth knowing before reading the code

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

**6. `spliceVariant` leaves a stray line behind on a multi-key `end` marker.** `extractSnippet`'s
boundary match stops at the key it was given, part-way along an `end` marker naming several; the
rest returns as `suffix`, which the splicer emits as its own line. Splicing `app.routing.ts` on
`adminSectionChallenge` appends a bare ` scoreBoardChallenge web3SandboxChallenge` — two juxtaposed
identifiers, in a file that then would not parse. **8 of 23 blocks** are affected, and the round
trip cannot see it: re-extracting on the same key stops at the same point, past which the stray line
sits. `src/base-tree.mjs` works around it by anchoring every splice on the *last* key its `end`
marker names, asserted as a property over all 23 blocks. The real fix is for the splicer to tell a
`start` marker's live-code suffix from an `end` marker's leftover keys.

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

The one the base tree needs — `_2_correct` — is therefore applied by hand, in
`src/b13-hand-repair.mjs`, and only after `chatbotPromptInjectionChallenge` has spliced. Upstream
marks the same `discount:` line `vuln-line` for both keys, so the other order overwrites the fix and
nothing errors. The repair refuses unless it finds B14 already applied, and refuses a second
application rather than no-opping: it is the one step with no round trip behind it, so a
double-apply has to be visible.

**The base tree parses and does not typecheck, on purpose.** Upstream's correct variants call
functions nobody has written — `validatePasswordHasAtLeastTenChar`, `security.isAdmin`,
`OrderStatus` — because upstream only ever displays them. `src/base-tree.mjs` declares each one in
`BASE_TREE_DEFECTS` and `verifyBaseTree` demands the line still be present, so a re-cut variant
retires the entry rather than the entry outliving the defect. Patching them would be inventing Juice
Shop code and would decouple the base from the correct-fix class, which lands these same variants.

## Licence

MIT. See `LICENSE`, and `NOTICE` for the two ports of upstream code and their attribution.
