/**
 * The repaired base tree — upstream Juice Shop with every challenge key's `_N_correct` codefix
 * applied, so that "introduce the vulnerability" has something non-vulnerable to start from.
 *
 * ## Why this is not 35 calls to `spliceVariantChecked`
 *
 * A variant is an edit of its **block's** displayed snippet, and a block may name several keys.
 * `data/static/securityQuestions.yml` is one block with five keys, so it has five `_N_correct`
 * variants, each a full rewrite of the same 28-line snippet. Splicing them one after another
 * would not compose them: the second splice diffs against the snippet the first one produced and
 * re-adds everything the first one took out. Four of the five fixes would be silently reverted,
 * and the tree would still parse.
 *
 * So composition is an **N-way merge onto the common snippet**, not a sequence of splices:
 *
 * 1. Diff each key's correct variant against the block's upstream snippet, with the same
 *    `diffLines` the splicer and upstream's own safety net use, giving a set of line hunks per key.
 * 2. Union the hunks. Identical hunks from different keys are one edit, not two.
 * 3. **Refuse** if two keys edit the same lines differently and no ruling covers it
 *    ({@link CompositionRefused}). Guessing here produces a tree that parses and is wrong for one
 *    of the two keys, which is the failure this whole repository is arranged around.
 * 4. Splice the *composed* snippet in once, and prove it by the splicer's own round trip.
 *
 * ## Order, where several blocks share a file
 *
 * `server.ts` holds five blocks, `app.routing.ts` two that overlap across 24 lines,
 * `search-result.component.ts` two, and `routes/chat.ts` two of which one contains the other.
 * Line numbers move as each splice lands, but nothing here carries a line number between steps:
 * every block is located by re-running upstream's boundary regex over the file *as it now stands*.
 *
 * What order does decide is whose diff sees whose edits. A block spliced second diffs its variant
 * against the snippet the first splice left behind, and any line the first splice changed inside
 * the second block's span reads as drift the second variant is about to revert. The rule is
 * therefore **contained blocks before the blocks that contain them, then by ascending start
 * line**, and it is not taken on trust: before every mechanical splice this module asserts the
 * block's snippet is still byte-identical to upstream's ({@link BaseTreeRefused}). Twenty-two of
 * the twenty-three blocks satisfy that assertion; the twenty-third is B13, below, which requires
 * the opposite and says so.
 *
 * ## Which key a block is spliced on, and why it is not the first one
 *
 * A block is addressed by any one of its keys, and the snippet is the same whichever is used —
 * upstream's four stripping regexes name no key. The *boundary* match does: it ends at the key it
 * was given, part-way along an `end` marker that names several. `extractSnippet` hands whatever
 * follows back as `suffix`, and `spliceVariant` re-emits a non-blank `suffix` as a line of its own,
 * because for a `start` suffix marker that text really is live code.
 *
 * For an `end` marker it never is. It is the rest of the key list. Splicing B05 on
 * `adminSectionChallenge` appends ` scoreBoardChallenge web3SandboxChallenge` to
 * `app.routing.ts` as a bare line — two juxtaposed identifiers, which does not parse — and the
 * splicer's own round trip cannot see it, because re-extracting on the same key stops at the same
 * point and the stray line is past it. Every one of the eight blocks whose `end` marker names more
 * than one key does this, in eight languages' worth of files.
 *
 * So each block is spliced on the **last key its `end` marker names**, which puts the boundary at
 * the end of the line and leaves `suffix` empty. That is a workaround and it is recorded as one:
 * the defect is in `src/splice.mjs`'s `suffix` handling, which should distinguish a `start`
 * marker's live-code suffix from an `end` marker's leftover key names. Phase 4 does not own that
 * file; see the phase note.
 *
 * ## The three things the corpus makes irreducibly specific
 *
 * **B13 does not splice, and is repaired by hand elsewhere.** `chatbotGreedyInjectionChallenge`'s
 * variants are not edits of their snippet at all — they drop the `export function chat () {`
 * wrapper and dedent by four — so `spliceVariantChecked` refuses all four by design.
 * `src/b13-hand-repair.mjs` owns the repair; this module imports `applyB13Correct` and depends on
 * nothing else from it. **That repair must run after `chatbotPromptInjectionChallenge` (B14) is
 * spliced**, because B14 lies inside B13 and its splice rewrites the one line B13's fix changes;
 * repair-then-splice drops the fix and errors nothing. {@link planSteps} guarantees the order and
 * {@link OVERLAP_EFFECTS} records the consequence.
 *
 * **B10 and B23 are two byte-identical `networking.tf` files sharing one key.** Phase 5 ruled
 * `iacLeakedKeyChallenge` is one scored item seated at B10 with B23 a mirrored site — but a base
 * tree that repaired only B10 would still be vulnerable at B23, and every branch cut from it would
 * inherit that. Both are repaired, and {@link verifyBaseTree} asserts the two outputs stay
 * byte-identical.
 *
 * **Three login keys disagree on how to fix one line.** `loginAdminChallenge` and
 * `loginJimChallenge` bind positionally, `loginBenderChallenge` binds by name; all three replace
 * the same snippet line. That is a conflict, the merge refuses it, and {@link CONFLICT_RULINGS}
 * is the one place a conflict may be resolved — by naming the keys, pinning the bytes, and saying
 * which spelling the tree takes and why.
 *
 * ## It parses; it does not typecheck
 *
 * The corpus doc asks this tree to parse and says in as many words that it need not run. It does
 * parse. It does not compile: four keys' correct variants name symbols the corpus binds nowhere,
 * one restates a tool entry that already exists outside its block, and one leaves a second,
 * unmarked registration of the route it guards. Every one of those is upstream's, because a
 * codefix is only ever *displayed* by Juice Shop and nothing has ever forced one to compile in the
 * file it claims to patch. {@link BASE_TREE_DEFECTS} names them line by line, and says why
 * hand-patching them was considered and rejected.
 *
 * ## What is emitted
 *
 * {@link buildBaseTree} returns the repaired tree, the per-step journal and a build manifest. The
 * manifest carries no clock and no filesystem path, so two builds of one checkout are
 * byte-identical — which is what lets phase 4's "pinned by SHA and rebuilt deliberately, never
 * regenerated silently" be checked rather than asserted.
 */
import crypto from "node:crypto";
import { diffLines } from "diff";
import { extractSnippet, findBlocks, parseMarker, splitLines } from "./markers.mjs";
import { MARKER_VOCABULARY_NOT_CORPUS } from "./inventory.mjs";
import { filterString, isCorrectVariant, keyOfVariantFile } from "./rsn.mjs";
import { spliceVariantChecked } from "./splice.mjs";

/** The corpus this module is written against. A build off any other SHA is reported, not assumed. */
export const PINNED_SHA = "1618a611b173b4bf114028e6e02549950606e29d";

/** Two keys want the same lines and disagree, and no ruling covers it. */
export class CompositionRefused extends Error {
  constructor(message) {
    super(message);
    this.name = "CompositionRefused";
  }
}

/** The build found the tree in a state it will not build on, or the result in a state it will not sign. */
export class BaseTreeRefused extends Error {
  constructor(message) {
    super(message);
    this.name = "BaseTreeRefused";
  }
}

/**
 * The keys whose correct fix does **not** arrive by splice, with the module that carries it.
 *
 * Named rather than counted, because "34 of 35 were mechanical" is only worth reading if the
 * remaining one is identified. {@link verifyBaseTree} asserts this list is exactly the set of keys
 * the build could not splice — a thirty-sixth key that started refusing would fail the build
 * rather than quietly joining the exception.
 */
export const HAND_REPAIRED_KEYS = Object.freeze(["chatbotGreedyInjectionChallenge"]);

/**
 * The one place two keys may edit the same lines differently and still produce a tree.
 *
 * Everything about an entry is pinned: the file, the exact key set, and the bytes being replaced.
 * If upstream re-cuts any of those variants, the ruling stops matching and the build refuses
 * instead of silently applying a decision made against different code.
 *
 * A ruled-out key's fix does **not** survive textually, and that is recorded rather than smoothed
 * over: {@link verifyBaseTree} reports it as `ruled` instead of `spliced`.
 */
export const CONFLICT_RULINGS = Object.freeze([
  Object.freeze({
    file: "routes/login.ts",
    keys: Object.freeze(["loginAdminChallenge", "loginBenderChallenge", "loginJimChallenge"]),
    /** The vulnerable line all three replace, pinned so the ruling expires if upstream moves it. */
    replaces:
      "    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' " +
      "AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, " +
      "{ model: UserModel, plain: true })",
    chosen: "loginAdminChallenge",
    ruledOut: Object.freeze(["loginBenderChallenge"]),
    /**
     * The corpus doc's own reading of this block: the three keys are **one** `sequelize.query`
     * template literal on one line — one defect, three gamification keys — and phase 5 collapses
     * them to a single scored item for that reason. So there is one line to fix and three
     * spellings of the fix, not three fixes. `loginAdminChallenge` and `loginJimChallenge` ship
     * byte-identical replacements binding positionally (`$1`/`$2`); `loginBenderChallenge` binds
     * by name (`$mail`/`$pass`). Both are parameterised and neither is vulnerable, so the choice
     * is between spellings and the majority spelling is taken.
     */
    reason:
      "one line, one defect, three keys (phase 5 scores it as one item); two of the three ship " +
      "the same positional-bind replacement and the third binds by name — both parameterised, " +
      "so the majority spelling is taken",
  }),
]);

/**
 * Where a later step is expected to change an earlier block's displayed snippet.
 *
 * Two blocks that share file lines cannot both end up showing upstream's text there. This table
 * says which, by whom, and what the later step is allowed to do — and {@link verifyBaseTree}
 * requires it to be *exhaustive in both directions*: an effect here that did not happen fails, and
 * an effect that happened without an entry fails. That is the whole point of writing it down. A
 * silent cross-block revert is the one failure mode a round trip per block cannot see, because
 * each block still round-trips to something.
 */
export const OVERLAP_EFFECTS = Object.freeze([
  Object.freeze({
    /** B05, `adminSectionChallenge scoreBoardChallenge web3SandboxChallenge`, lines 76–277. */
    block: "frontend/src/app/app.routing.ts:76",
    byKey: "tokenSaleChallenge",
    kind: "delete-run",
    /** The `token-sale` route, as B05 displays it — the four lines B06's correct fix removes. */
    run: Object.freeze([
      "  {",
      "    matcher: tokenMatcher,",
      "    component: TokenSaleComponent",
      "  },",
    ]),
    /**
     * B06 (254–322) overlaps B05 across 24 lines, and `tokenSaleChallenge`'s correct fix deletes
     * four of them — the `token-sale` route. B05 displays those lines too, so B05's snippet in the
     * finished tree is its own composition minus that route. Nothing of B05's three fixes touches
     * the overlap, which is why B05 can be spliced first and B06 second.
     */
    reason: "B06's correct fix deletes the token-sale route, and those four lines are inside B05",
  }),
  Object.freeze({
    /** B14, `chatbotPromptInjectionChallenge`, lines 175–188. */
    block: "routes/chat.ts:175",
    byKey: "chatbotGreedyInjectionChallenge",
    kind: "line-substitution",
    find: "z.number().describe(",
    replace: "z.number().max(10).describe(",
    /**
     * B14 is entirely inside B13, and upstream marks the `discount:` line `vuln-line` for **both**
     * keys. B14's splice rewrites that line (new trailing comma, new `orderId` sibling) without
     * capping the discount; B13's hand repair then adds the cap to whatever B14 left there. Run
     * the other way round the cap is overwritten and the tree still parses, which is why
     * `applyB13Correct` refuses an input B14 has not been applied to.
     */
    reason: "B13's fix is `.max(10)` on a line B14 rewrites; B14 splices first and B13 amends it",
  }),
]);

/**
 * What is wrong with the finished tree, on purpose.
 *
 * The corpus doc asks the base tree to **parse**; it says in as many words that it need not run.
 * It does not typecheck, and that is upstream's doing rather than this module's: a codefix variant
 * is only ever *displayed* by Juice Shop, so nothing has ever forced one to compile in the file it
 * claims to patch. Four keys' correct variants name symbols the tree does not bind, and one
 * restates a whole tool entry that already exists outside its block.
 *
 * They are carried verbatim, and the alternative was considered and rejected:
 *
 * - **Hand-patching them would stop the splice being mechanical**, which is one of the two
 *   properties the corpus doc requires of this tree. `validatePasswordHasAtLeastTenChar` is not a
 *   typo to correct — it is a function nobody has written, and writing one would be HapDo
 *   inventing Juice Shop code and then measuring reviewers against it.
 * - **It would decouple the base from the correct-fix class.** That class applies these same
 *   `_N_correct` variants to an introduce-the-vuln head. A patched base would disagree with every
 *   branch that lands the real variant, and the benchmark would be comparing two different fixes.
 *
 * The cost is real and belongs to phase 6 rather than to this module: a reviewer who flags
 * `OrderStatus` as undefined is right, and on a correct-fix pull request that would score as a
 * false positive. Phase 5 already has the shape of the answer for this — gitleaks hits on
 * untouched files and rule-7 detector rows are **corpus, not a false positive** — and these are
 * named here so that the ruling can be made against a list rather than against a surprise.
 *
 * Each entry pins a whole line, so a re-cut variant retires the entry instead of silently
 * outliving it. {@link unboundSymbolsIntroduced} re-derives the identifier ones from the tree.
 */
export const BASE_TREE_DEFECTS = Object.freeze([
  Object.freeze({
    file: "models/user.ts",
    key: "weakPasswordChallenge",
    variant: "weakPasswordChallenge_1_correct.ts",
    symbol: "validatePasswordHasAtLeastTenChar",
    kind: "undefined-symbol",
    line: "          validatePasswordHasAtLeastTenChar(clearTextPassword)",
    note: "bound nowhere in the corpus outside data/static/codefixes/",
  }),
  Object.freeze({
    file: "models/user.ts",
    key: "weakPasswordChallenge",
    variant: "weakPasswordChallenge_1_correct.ts",
    symbol: "validatePasswordIsNotInTopOneMillionCommonPasswordsList",
    kind: "undefined-symbol",
    line: "          validatePasswordIsNotInTopOneMillionCommonPasswordsList(clearTextPassword)",
    note: "bound nowhere in the corpus outside data/static/codefixes/",
  }),
  Object.freeze({
    file: "routes/chat.ts",
    key: "chatbotPromptInjectionChallenge",
    variant: "chatbotPromptInjectionChallenge_2_correct.ts",
    symbol: "OrderStatus",
    kind: "undefined-symbol",
    line:
      "          const order = await db.ordersCollection.findOne({ orderId, email: " +
      "authenticatedUser?.email, status: OrderStatus.DAMAGED })",
    note: "bound nowhere in the corpus outside data/static/codefixes/",
  }),
  Object.freeze({
    file: "routes/chat.ts",
    key: "chatbotPromptInjectionChallenge",
    variant: "chatbotPromptInjectionChallenge_2_correct.ts",
    symbol: "authenticatedUser",
    kind: "unschemaed-parameter",
    line: "        execute: async ({ discount, orderId, authenticatedUser }) => {",
    note: "destructured from the tool's input but absent from its inputSchema",
  }),
  Object.freeze({
    file: "routes/chat.ts",
    key: "chatbotPromptInjectionChallenge",
    variant: "chatbotPromptInjectionChallenge_2_correct.ts",
    symbol: "getOrderById",
    kind: "duplicate-object-key",
    line: "      getOrderById: tool({",
    /**
     * B14's span is 175–188 and upstream's `getOrderById` entry sits at 156–173, outside it. The
     * variant restates the entry anyway, so splicing it leaves `chatTools` with the key twice
     * (TS1117). The restatement is not idle — it drops the `maskedEmail` comparison — but it lands
     * beside the original rather than replacing it, because the original is not in the snippet the
     * variant is an edit of.
     */
    note: "the variant restates a tool entry that lives outside B14's span, so chatTools has it twice",
  }),
  Object.freeze({
    file: "server.ts",
    key: "exposedMetricsChallenge",
    variant: "exposedMetricsChallenge_3_correct.ts",
    symbol: "security.isAdmin",
    kind: "undefined-member",
    line: "app.get('/metrics', security.isAdmin(), utils.asyncHandler(metrics.serveMetrics()))",
    note: "`isAdmin` appears nowhere in the corpus outside data/static/codefixes/",
  }),
  Object.freeze({
    file: "server.ts",
    key: "exposedMetricsChallenge",
    variant: "exposedMetricsChallenge_3_correct.ts",
    symbol: "app.get('/metrics'",
    kind: "unrepaired-sibling-site",
    line: "  app.get('/metrics', utils.asyncHandler(metrics.serveMetrics()))",
    /**
     * Upstream registers `/metrics` **twice**: once inside the app setup, unguarded and outside
     * any block, and once inside B22 where the marker calls it the vulnerability.
     * `exposedMetricsChallenge_3_correct.ts` guards only the marked one, so the repaired tree
     * still serves metrics without an admin check from the earlier registration.
     *
     * Deleting it would be this module deciding what upstream's fix should have been, on a site
     * the corpus does not mark. It is recorded instead, because "the base is not vulnerable" is
     * the premise of the whole introduce-the-vuln class and this is the one measured place it is
     * not literally true.
     */
    note: "upstream registers /metrics a second time outside the block, and the correct fix leaves it",
  }),
]);

/**
 * The typo none of this may reintroduce.
 *
 * All four `chatbotGreedyInjectionChallenge` variants write `Number(Id)` where `routes/chat.ts`
 * writes `Number(id)`, and `Id` is bound nowhere. The hand repair keeps it out by applying only
 * the one line that is the security fix; this is the assertion that the composition path did not
 * find another way in.
 */
const REINTRODUCED_TYPO = "Number(Id)";

/* -------------------------------------------------------------------------- */
/* Line hunks — the unit the merge works in                                    */
/* -------------------------------------------------------------------------- */

/**
 * The key a block is addressed by: the last one its `end` marker names.
 *
 * See the note at the head of this file. Any key of the block yields the same snippet; only this
 * one yields an empty `suffix`, and a non-empty `suffix` on an `end` marker becomes a bare line of
 * key names in the spliced file.
 */
export function anchorKeyFor(source, block) {
  const { lines } = splitLines(source);
  if (block.end <= 0) throw new BaseTreeRefused(`block at line ${block.start} has no end marker`);
  const marker = parseMarker(lines[block.end - 1]);
  if (marker?.type !== "end") {
    throw new BaseTreeRefused(`line ${block.end} does not carry the end marker it was paired on`);
  }
  const mine = marker.keys.filter((k) => block.keys.includes(k));
  if (mine.length === 0) {
    throw new BaseTreeRefused(`the end marker on line ${block.end} names none of ${block.keys.join(", ")}`);
  }
  return mine[mine.length - 1];
}

/**
 * The edits that turn `from` into `to`, as line hunks in `from`'s coordinates.
 *
 * `{ start, end, remove, insert }` replaces `from` lines `[start, end)` with `insert`. A pure
 * insertion has `start === end`. Deletions and the insertion that follows them are one hunk, which
 * is what makes "these two keys changed the same line" a range comparison rather than a heuristic.
 *
 * `diffLines` is the same call `spliceVariant` and `computeVariantDiff` make, on `filterString`ed
 * text, so the alignment is upstream's — the one `rsn/cache.json` locks.
 */
export function lineHunks(from, to) {
  const parts = diffLines(filterString(from), filterString(to));
  const hunks = [];
  let i = 0;
  for (const part of parts) {
    if (!part.count) continue;
    const text = partLines(part.value);
    if (part.added) {
      const prev = hunks[hunks.length - 1];
      if (prev != null && prev.end === i) {
        prev.insert.push(...text);
        continue;
      }
      hunks.push({ start: i, end: i, remove: [], insert: text });
      continue;
    }
    if (part.removed) {
      hunks.push({ start: i, end: i + part.count, remove: text, insert: [] });
      i += part.count;
      continue;
    }
    i += part.count;
  }
  return hunks;
}

/** Split a diff part's value into lines without inventing a trailing empty one. */
function partLines(value) {
  const lines = value.split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

/** Two hunks are the same edit when they replace the same range with the same text. */
function sameHunk(a, b) {
  return a.start === b.start && a.end === b.end && a.insert.join("\n") === b.insert.join("\n");
}

/**
 * Whether two hunks contend for the same lines.
 *
 * Ranges that intersect contend. So do two insertions at one index, and an insertion that falls
 * strictly inside another hunk's range. An insertion sitting exactly at the start of a replacement
 * does not: it lands before it, unambiguously.
 */
function contend(a, b) {
  if (a.start === a.end && b.start === b.end) return a.start === b.start;
  if (a.start === a.end) return a.start > b.start && a.start < b.end;
  if (b.start === b.end) return b.start > a.start && b.start < a.end;
  return a.start < b.end && b.start < a.end;
}

/** Replay hunks over `lines`. Refuses rather than dropping an edit it cannot place. */
function applyHunks(lines, hunks) {
  const ordered = [...hunks].sort((a, b) => a.start - b.start || a.end - b.end);
  const out = [];
  let i = 0;
  for (const h of ordered) {
    if (h.start < i) {
      throw new CompositionRefused(
        `hunk [${h.start}, ${h.end}) starts inside the previous one, which ends at ${i}`,
      );
    }
    out.push(...lines.slice(i, h.start), ...h.insert);
    i = h.end;
  }
  out.push(...lines.slice(i));
  return out;
}

/* -------------------------------------------------------------------------- */
/* The N-way merge                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Compose one block's keys' correct variants onto the block's upstream snippet.
 *
 * @param {string} snippet the block's displayed snippet, upstream
 * @param {{key: string, file: string, text: string}[]} variants one per key of the block
 * @param {{file: string}} where the source file, used to find a ruling and to say where a refusal is
 * @returns {{snippet: string, byKey: object, applied: object[], ruledOut: string[], rulings: object[]}}
 */
export function composeSnippet(snippet, variants, where) {
  const lines = filterString(snippet).split("\n");
  const byKey = {};
  for (const v of variants) byKey[v.key] = lineHunks(snippet, v.text);

  // Each key's hunks, tautologically, reproduce its own variant. Asserted anyway: it is the cheap
  // proof that this module's hunk algebra agrees with the diff it was built from, and a failure
  // here would otherwise surface as a wrong tree rather than as an error.
  for (const v of variants) {
    const alone = applyHunks(lines, byKey[v.key]).join("\n");
    if (alone.trim() !== filterString(v.text).trim()) {
      throw new CompositionRefused(
        `${where.file}: replaying ${v.key}'s hunks over the snippet did not reproduce ` +
          `${v.file}. The hunk algebra disagrees with the diff it came from.`,
      );
    }
  }

  const ruling = findRuling(where.file, variants);
  const ruledOut = ruling == null ? [] : [...ruling.ruledOut];

  /** @type {{hunk: object, keys: string[]}[]} */
  const merged = [];
  for (const v of variants) {
    if (ruledOut.includes(v.key)) continue;
    for (const hunk of byKey[v.key]) {
      const twin = merged.find((m) => sameHunk(m.hunk, hunk));
      if (twin != null) {
        twin.keys.push(v.key);
        continue;
      }
      const clash = merged.find((m) => contend(m.hunk, hunk));
      if (clash != null) {
        throw new CompositionRefused(
          `${where.file}: ${v.key} and ${clash.keys.join(", ")} both edit snippet lines ` +
            `[${Math.min(hunk.start, clash.hunk.start)}, ${Math.max(hunk.end, clash.hunk.end)}) ` +
            `and disagree.\n  ${clash.keys[0]}: ${JSON.stringify(clash.hunk.insert)}\n  ` +
            `${v.key}: ${JSON.stringify(hunk.insert)}\n` +
            `Composing these would apply one fix and silently drop the other. Rule on it in ` +
            `CONFLICT_RULINGS, naming the keys and pinning the bytes, or re-cut the variants.`,
        );
      }
      merged.push({ hunk, keys: [v.key] });
    }
  }

  return {
    snippet: applyHunks(lines, merged.map((m) => m.hunk)).join("\n"),
    byKey,
    applied: merged.map((m) => ({ start: m.hunk.start, end: m.hunk.end, inserted: m.hunk.insert.length, keys: [...m.keys].sort() })),
    ruledOut,
    rulings: ruling == null ? [] : [ruling],
  };
}

/**
 * The ruling covering this block, if there is one, checked against the bytes it was written for.
 *
 * A ruling that no longer matches is worse than no ruling: it is a decision taken about code that
 * has since changed. So a partial match — right keys, wrong bytes — refuses rather than falls back
 * to the conflict message, which would read as though no one had ever considered it.
 */
function findRuling(file, variants) {
  const keys = variants.map((v) => v.key).sort();
  for (const ruling of CONFLICT_RULINGS) {
    if (ruling.file !== file) continue;
    if ([...ruling.keys].sort().join(" ") !== keys.join(" ")) continue;
    const carriers = variants.filter((v) => !v.text.includes(ruling.replaces));
    if (carriers.length !== variants.length) {
      throw new CompositionRefused(
        `${file}: the ruling for ${keys.join(", ")} pins a line that ` +
          `${carriers.map((v) => v.file).join(", ")} no longer replaces. Re-read the variants ` +
          `before trusting a decision taken about different code.`,
      );
    }
    return ruling;
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* Planning                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Every splice the build will make, in the order it will make them.
 *
 * Within a file: contained blocks first, then by ascending start line. Containment depth is
 * counted rather than compared pairwise, so the order is total and stable however deeply blocks
 * nest — `routes/chat.ts` nests one deep today and the rule does not care.
 *
 * @param {Map<string, string>} tree the corpus at its pin
 * @param {Map<string, string>} codefixes `data/static/codefixes/`
 */
export function planSteps(tree, codefixes) {
  const correctFor = new Map();
  for (const name of [...codefixes.keys()].sort()) {
    if (!isCorrectVariant(name)) continue;
    const key = keyOfVariantFile(name);
    if (correctFor.has(key)) {
      throw new BaseTreeRefused(
        `${key} has two correct variants (${correctFor.get(key)}, ${name}). Which one repairs the ` +
          `tree is not this module's decision to make.`,
      );
    }
    correctFor.set(key, name);
  }

  const steps = [];
  for (const file of [...tree.keys()].sort()) {
    if (MARKER_VOCABULARY_NOT_CORPUS.includes(file)) continue;
    const source = tree.get(file);
    const blocks = findBlocks(source);
    if (blocks.length === 0) continue;
    const depth = (b) =>
      blocks.filter((o) => o !== b && o.start <= b.start && o.end >= b.end && (o.start < b.start || o.end > b.end)).length;
    const ordered = [...blocks].sort((a, b) => depth(b) - depth(a) || a.start - b.start);
    for (const block of ordered) {
      const variants = block.keys.map((key) => {
        const name = correctFor.get(key);
        if (name == null) {
          throw new BaseTreeRefused(`${file}:${block.start} names ${key}, which has no correct variant`);
        }
        return { key, file: name, text: codefixes.get(name) };
      });
      steps.push({
        id: `${file}:${block.start}`,
        file,
        start: block.start,
        end: block.end,
        keys: [...block.keys],
        anchor: anchorKeyFor(source, block),
        variants,
        mode: block.keys.some((k) => HAND_REPAIRED_KEYS.includes(k)) ? "hand-repair" : "splice",
      });
    }
  }
  return steps;
}

/* -------------------------------------------------------------------------- */
/* The build                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Load the B13 hand repair.
 *
 * Dynamic, so that this module — and its tests — load in a checkout where
 * `src/b13-hand-repair.mjs` has not been written yet. Everything mechanical still runs there; only
 * a build that reaches B13 fails, and it fails saying which file is missing rather than failing to
 * parse this one.
 */
async function loadHandRepair() {
  try {
    const mod = await import("./b13-hand-repair.mjs");
    if (typeof mod.applyB13Correct !== "function") {
      throw new BaseTreeRefused("src/b13-hand-repair.mjs does not export applyB13Correct()");
    }
    return mod.applyB13Correct;
  } catch (err) {
    if (err instanceof BaseTreeRefused) throw err;
    throw new BaseTreeRefused(
      `${HAND_REPAIRED_KEYS.join(", ")} cannot be spliced and src/b13-hand-repair.mjs did not ` +
        `load (${err.message}). The base tree is not repaired without it.`,
    );
  }
}

/**
 * Build the repaired base tree.
 *
 * @param {Map<string, string>} tree the corpus at its pin, path -> contents
 * @param {Map<string, string>} codefixes `data/static/codefixes/`, filename -> contents
 * @param {{applyB13Correct?: (source: string) => {source: string, stats: object}, sha?: string}} options
 * @returns {Promise<{tree: Map<string, string>, changed: string[], steps: object[], manifest: object}>}
 */
export async function buildBaseTree(tree, codefixes, options = {}) {
  const applyB13Correct = options.applyB13Correct ?? (await loadHandRepair());
  const steps = planSteps(tree, codefixes);
  const out = new Map(tree);

  /** Per block, the snippet the tree is expected to display once every step has run. */
  const expected = new Map();
  /** Cross-block effects actually observed, to be reconciled against OVERLAP_EFFECTS. */
  const observedEffects = [];
  const journal = [];

  for (const step of steps) {
    const before = out.get(step.file);
    const anchor = step.anchor;

    if (step.mode === "splice") {
      // The invariant the ordering exists to protect: nothing spliced so far has touched this
      // block's display. A block that has already drifted would have its variant diffed against
      // the drift, and the earlier fix would come back out.
      const now = extractSnippet(before, anchor).snippet;
      const pristine = extractSnippet(tree.get(step.file), anchor).snippet;
      if (filterString(now) !== filterString(pristine)) {
        throw new BaseTreeRefused(
          `${step.id}: an earlier step already changed this block's displayed snippet, so ` +
            `splicing now would diff ${step.keys.join(", ")}'s variants against that change and ` +
            `revert it. Fix the step order, not this check.`,
        );
      }

      const composed = composeSnippet(pristine, step.variants, { file: step.file });
      const { source, stats } = spliceVariantChecked(before, anchor, composed.snippet);
      out.set(step.file, source);
      // Record what the tree now *displays*, not what was composed. The splicer's round trip has
      // just proved the two equal modulo the leading and trailing whitespace `trim()` takes, and
      // comparing a later step's effect against the composed string instead would report that
      // whitespace as the later step's doing.
      expected.set(step.id, extractSnippet(source, anchor).snippet);
      journal.push({
        id: step.id,
        file: step.file,
        span: [step.start, step.end],
        keys: step.keys,
        anchor,
        mode: "splice",
        variants: step.variants.map((v) => v.file),
        hunks: composed.applied,
        ruledOut: composed.ruledOut,
        rulings: composed.rulings.map((r) => ({ keys: [...r.keys], chosen: r.chosen, ruledOut: [...r.ruledOut], reason: r.reason })),
        stats,
      });
    } else {
      // The hand-repaired block. Its precondition is the opposite of the splice invariant above:
      // B14 sits inside it and must already be spliced, so its snippet is expected to have moved.
      const { source, stats } = applyB13Correct(before);
      if (typeof source !== "string" || source === before) {
        throw new BaseTreeRefused(`${step.id}: applyB13Correct() returned no change`);
      }
      out.set(step.file, source);
      expected.set(step.id, extractSnippet(source, anchor).snippet);
      journal.push({
        id: step.id,
        file: step.file,
        span: [step.start, step.end],
        keys: step.keys,
        anchor,
        mode: "hand-repair",
        variants: step.variants.map((v) => v.file),
        by: "src/b13-hand-repair.mjs#applyB13Correct",
        stats,
      });
    }

    // Whatever that step did, no earlier block in the same file may have quietly changed with it.
    for (const earlier of steps) {
      if (earlier === step) break;
      if (earlier.file !== step.file) continue;
      const was = expected.get(earlier.id);
      const is = extractSnippet(out.get(step.file), earlier.anchor).snippet;
      if (filterString(was) === filterString(is)) continue;
      observedEffects.push({ block: earlier.id, byKey: step.keys[0], from: was, to: is });
      expected.set(earlier.id, is);
    }
  }

  const changed = [...out.keys()].filter((p) => out.get(p) !== tree.get(p)).sort();
  reconcileEffects(observedEffects, steps);

  return {
    tree: out,
    changed,
    steps: journal,
    manifest: buildManifest({ tree, out, changed, journal, steps, options }),
  };
}

/**
 * Hold {@link OVERLAP_EFFECTS} to being exactly what happened — no more and no less.
 *
 * An entry that did not fire means the table describes a corpus this is not. An effect with no
 * entry means one block's fix has been rewritten by another's without anyone deciding that it
 * should be. Both are builds that produce a tree which parses, so both have to be errors.
 */
function reconcileEffects(observed, steps) {
  const inPlay = new Set([...steps.map((s) => s.id), ...steps.flatMap((s) => s.keys)]);
  for (const effect of observed) {
    const declared = OVERLAP_EFFECTS.find((e) => e.block === effect.block && e.byKey === effect.byKey);
    if (declared == null) {
      throw new BaseTreeRefused(
        `${effect.byKey}'s step changed what block ${effect.block} displays, and no entry in ` +
          `OVERLAP_EFFECTS says it may. One block's fix has been rewritten by another's. Decide ` +
          `what that means and write it down before building on this tree.`,
      );
    }
    const wanted = amendSnippet(effect.from, [declared], effect.block);
    if (filterString(wanted) !== filterString(effect.to)) {
      throw new BaseTreeRefused(
        `${effect.block}: ${effect.byKey} was declared to make one ${declared.kind} here and did ` +
          `something else.\n  declared: ${JSON.stringify(declared.find ?? declared.run)}\n  ` +
          `actual: ${JSON.stringify(lineHunks(effect.from, effect.to))}`,
      );
    }
  }
  for (const declared of OVERLAP_EFFECTS) {
    // Only an effect whose block and whose author were both in this build is owed. The table names
    // corpus paths; a test that builds three synthetic files is not evidence that the corpus moved.
    if (!inPlay.has(declared.block) || !inPlay.has(declared.byKey)) continue;
    if (observed.some((e) => e.block === declared.block && e.byKey === declared.byKey)) continue;
    throw new BaseTreeRefused(
      `OVERLAP_EFFECTS says ${declared.byKey} changes what ${declared.block} displays, and it did ` +
        `not. Either the corpus moved or a step did not run.`,
    );
  }
}

/**
 * Apply the declared effects of later steps to a block's composed snippet.
 *
 * Each amendment names the bytes it acts on and each must match **exactly once**, so an amendment
 * cannot quietly start hitting a second site. `delete-run` matches a contiguous run of whole lines
 * rather than a set of them, because every line of the run B06 deletes — `  {`, `  },` — occurs a
 * dozen times in `app.routing.ts` on its own and only once in that order.
 */
function amendSnippet(snippet, amendments, where) {
  let lines = filterString(snippet).split("\n");
  for (const a of amendments) {
    if (a.kind === "line-substitution") {
      const hits = lines.filter((l) => l.includes(a.find)).length;
      if (hits !== 1) {
        throw new BaseTreeRefused(
          `${where}: the declared substitution ${JSON.stringify(a.find)} matches ${hits} lines, ` +
            `not one. An amendment that is not unique is not an amendment.`,
        );
      }
      lines = lines.map((l) => l.split(a.find).join(a.replace));
      continue;
    }
    if (a.kind === "delete-run") {
      const at = [];
      for (let i = 0; i + a.run.length <= lines.length; i++) {
        if (a.run.every((r, k) => lines[i + k] === r)) at.push(i);
      }
      if (at.length !== 1) {
        throw new BaseTreeRefused(
          `${where}: the declared run of ${a.run.length} lines occurs ${at.length} times, not once.`,
        );
      }
      lines = [...lines.slice(0, at[0]), ...lines.slice(at[0] + a.run.length)];
      continue;
    }
    throw new BaseTreeRefused(`${where}: unknown overlap effect kind ${JSON.stringify(a.kind)}`);
  }
  return lines.join("\n");
}

/* -------------------------------------------------------------------------- */
/* Verification                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Prove the tree that was built is the tree that was meant, against the corpus rather than against
 * the build's own intermediate state.
 *
 * Four questions, and the first is the one a parse check cannot answer:
 *
 * 1. **Did every key's own fix survive?** Re-extract each block from the *finished* tree and
 *    demand that every hunk that key's correct variant makes against the upstream snippet is
 *    present. For a single-key block that is the splicer's round trip restated. For a five-key
 *    block it is the only honest form of it, because the composed snippet equals no single variant
 *    — it equals the snippet with all five keys' hunks applied, and containment of each key's
 *    hunks is what "all five fixes are in there" means.
 * 2. **Is every key accounted for?** 35 keys, each `spliced`, `ruled` or `hand-repaired`, with the
 *    latter two named lists rather than counts.
 * 3. **Did anything else move?** Every file with no block is byte-identical to upstream.
 * 4. **Are the mirrored `networking.tf` files still identical?** One key, two files, and repairing
 *    only the one upstream serves would leave the other vulnerable.
 *
 * @param {{upstream: Map<string, string>, built: Map<string, string>, codefixes: Map<string, string>}} input
 */
export function verifyBaseTree({ upstream, built, codefixes }) {
  const steps = planSteps(upstream, codefixes);
  /** @type {Record<string, string>} */
  const keyStatus = {};
  const blocks = [];

  for (const step of steps) {
    const before = extractSnippet(upstream.get(step.file), step.anchor).snippet;
    const after = extractSnippet(built.get(step.file), step.anchor).snippet;
    const actual = lineHunks(before, after);
    const amendments = OVERLAP_EFFECTS.filter((e) => e.block === step.id);

    if (step.mode === "hand-repair") {
      for (const key of step.keys) keyStatus[key] = "hand-repaired";
      if (filterString(before) === filterString(after)) {
        throw new BaseTreeRefused(`${step.id}: the hand-repaired block is unchanged from upstream`);
      }
      blocks.push({ id: step.id, keys: step.keys, mode: "hand-repair", hunks: actual.length });
      continue;
    }

    const composed = composeSnippet(before, step.variants, { file: step.file });

    // What the block ought to display: its keys' fixes composed, then whatever a later step was
    // declared to do to it. This is the round trip, stated for a block with more than one key —
    // the composed snippet equals no single variant, so demanding one back would be a check that
    // could only ever pass for fifteen of the twenty-three blocks.
    //
    // `trim()` is the splicer's own comparison, and it is needed for one reason: the snippet is
    // trimmed on extraction, so a variant line promoted to the block's first line loses the
    // indentation it carries in `data/static/codefixes/`.
    const expectedFinal = amendSnippet(composed.snippet, amendments, step.id);
    if (filterString(after).trim() !== filterString(expectedFinal).trim()) {
      throw new BaseTreeRefused(
        `${step.id}: the finished tree does not display its keys' composed fixes.\n` +
          JSON.stringify(lineHunks(expectedFinal, after), null, 2),
      );
    }

    const nowShown = splitLines(filterString(after)).lines;
    const wasShown = splitLines(filterString(before)).lines;
    const shown = new Set(nowShown);
    /** Present, allowing for the one line `trim()` can have re-indented: the block's first. */
    const displays = (line) => shown.has(line) || line.trim() === nowShown[0];
    const occurrences = (lines, line) => lines.filter((l) => l === line).length;

    for (const variant of step.variants) {
      if (composed.ruledOut.includes(variant.key)) {
        // A ruled-out key's spelling is not in the tree by construction. What must be true is that
        // the line it wanted changed did change — its defect is fixed, in the chosen spelling.
        const ruling = composed.rulings[0];
        if (after.includes(ruling.replaces)) {
          throw new BaseTreeRefused(
            `${step.id}: ${variant.key} was ruled out in favour of ${ruling.chosen}, and the ` +
              `vulnerable line it was ruling on is still in the tree.`,
          );
        }
        keyStatus[variant.key] = "ruled";
        continue;
      }
      // Per-key attribution. The equality above already pins the block byte for byte; this says
      // *which key* each part of it belongs to, so a block whose composition silently dropped one
      // of five fixes names the one it dropped instead of printing a 199-line diff.
      for (const hunk of composed.byKey[variant.key]) {
        for (const raw of hunk.insert) {
          const line = amendments.reduce((s, a) => (a.kind === "line-substitution" ? s.split(a.find).join(a.replace) : s), raw);
          if (line.trim() === "" || displays(line)) continue;
          throw new BaseTreeRefused(
            `${step.id}: ${variant.key}'s fix is not in the built tree — ${variant.file} adds ` +
              `${JSON.stringify(line)} and the block does not show it. A later step reverted it, ` +
              `or the composition dropped it.`,
          );
        }
        for (const raw of hunk.remove) {
          if (occurrences(nowShown, raw) < occurrences(wasShown, raw)) continue;
          // A fix may *move* a line rather than delete it — `web3WalletChallenge` fixes the
          // reentrancy by putting the balance decrement above the external call, and `diffLines`
          // records that as a removal here and an addition there. A line the same key re-adds has
          // not survived the fix; it has been relocated by it.
          // A line the same key puts back is relocated or re-indented, not surviving: the
          // reentrancy fix moves a statement, and a variant that opens the block re-emits its
          // first line with the indentation `trim()` took off the snippet.
          if (composed.byKey[variant.key].some((h) => h.insert.some((i) => i.trim() === raw.trim()))) continue;
          throw new BaseTreeRefused(
            `${step.id}: ${variant.key}'s fix did not land — ${variant.file} removes ` +
              `${JSON.stringify(raw)} and the block still shows it.`,
          );
        }
      }
      keyStatus[variant.key] = "spliced";
    }
    blocks.push({ id: step.id, keys: step.keys, mode: "splice", hunks: actual.length });
  }

  const missing = steps.flatMap((s) => s.keys).filter((k) => keyStatus[k] == null);
  if (missing.length > 0) throw new BaseTreeRefused(`keys with no verdict: ${missing.join(", ")}`);

  const handRepaired = Object.keys(keyStatus).filter((k) => keyStatus[k] === "hand-repaired").sort();
  if (handRepaired.join(" ") !== [...HAND_REPAIRED_KEYS].sort().join(" ")) {
    throw new BaseTreeRefused(
      `the keys repaired by hand are ${handRepaired.join(", ") || "(none)"}, and HAND_REPAIRED_KEYS ` +
        `names ${HAND_REPAIRED_KEYS.join(", ")}. The exception list has to be the exception.`,
    );
  }

  const blockFiles = new Set(steps.map((s) => s.file));
  const moved = [];
  for (const [path, contents] of built) {
    if (upstream.get(path) === contents) continue;
    moved.push(path);
    if (!blockFiles.has(path)) {
      throw new BaseTreeRefused(`${path} holds no block and is not byte-identical to upstream`);
    }
  }
  for (const path of blockFiles) {
    if (built.get(path) !== upstream.get(path)) continue;
    throw new BaseTreeRefused(`${path} holds a block and was not changed — its fix did not land`);
  }

  // The mirrored site. Phase 5 scores `iacLeakedKeyChallenge` once, at B10; the tree must repair
  // both, or a correct-fix branch cut from it still ships the key at B23.
  const mirrors = [...blockFiles].filter((p) => p.endsWith("networking.tf")).sort();
  if (mirrors.length !== 2) throw new BaseTreeRefused(`expected two networking.tf files, found ${mirrors.length}`);
  if (upstream.get(mirrors[0]) !== upstream.get(mirrors[1])) {
    throw new BaseTreeRefused(`the two networking.tf files are no longer byte-identical upstream`);
  }
  if (built.get(mirrors[0]) !== built.get(mirrors[1])) {
    throw new BaseTreeRefused(
      `${mirrors.join(" and ")} came out different. One key, two byte-identical files: repairing ` +
        `one leaves the other vulnerable and every branch cut from this tree inherits it.`,
    );
  }

  // The declared defects, held to being present. A table of known problems that has drifted out of
  // date is worse than none: it reads as though someone checked.
  for (const defect of BASE_TREE_DEFECTS) {
    const lines = splitLines(built.get(defect.file) ?? "").lines;
    if (!lines.includes(defect.line)) {
      throw new BaseTreeRefused(
        `BASE_TREE_DEFECTS says ${defect.file} carries ${JSON.stringify(defect.line)} and it does ` +
          `not. Either ${defect.variant} was re-cut — in which case retire the entry — or the ` +
          `composition no longer applies it.`,
      );
    }
  }
  for (const [path, contents] of built) {
    // `data/static/codefixes/` is where the typo lives upstream and it is still in the tree here;
    // the strip removes that directory from every scored tree. What must not happen is the typo
    // reaching application code.
    if (path.startsWith("data/static/codefixes/")) continue;
    if (!contents.includes(REINTRODUCED_TYPO)) continue;
    throw new BaseTreeRefused(
      `${path} contains ${JSON.stringify(REINTRODUCED_TYPO)}. All four ` +
        `chatbotGreedyInjectionChallenge variants carry that typo for upstream's ${"Number(id)"}, ` +
        `and applying one verbatim puts a reference to an unbound name into the base tree.`,
    );
  }

  return {
    keyStatus,
    blocks,
    defects: BASE_TREE_DEFECTS.map((d) => ({ file: d.file, key: d.key, symbol: d.symbol, kind: d.kind })),
    changedFiles: moved.sort(),
    counts: {
      keys: Object.keys(keyStatus).length,
      spliced: Object.values(keyStatus).filter((v) => v === "spliced").length,
      ruled: Object.values(keyStatus).filter((v) => v === "ruled").length,
      handRepaired: handRepaired.length,
      blocks: steps.length,
      changedFiles: moved.length,
      mirroredSites: mirrors.length,
    },
    ruled: Object.keys(keyStatus).filter((k) => keyStatus[k] === "ruled").sort(),
    handRepaired,
    mirrors,
    blockIds: steps.map((s) => s.id),
  };
}

/**
 * Names the composition introduced into a TypeScript file that the file never mentions upstream.
 *
 * A deliberately narrow sweep, and narrow is the point: it looks only at **bare call targets**
 * (`name(`) and **capitalised member roots** (`Name.`) on lines the composition added, with line
 * comments and string literals blanked first, and it reports a name only when the whole upstream
 * file never contains it. Those two shapes cannot be resolved by anything but a binding, so a hit
 * is a real unbound name rather than a guess about types.
 *
 * It is not a typechecker and does not pretend to be. `security.isAdmin()` and a duplicated object
 * key are both in {@link BASE_TREE_DEFECTS} and neither is findable this way, which is why that
 * table is written by hand and this function exists to keep the part of it that *can* be
 * re-derived honest.
 *
 * @param {Map<string, string>} upstream
 * @param {Map<string, string>} built
 * @returns {{file: string, symbol: string}[]} sorted
 */
export function unboundSymbolsIntroduced(upstream, built) {
  const found = new Set();
  for (const [path, after] of built) {
    if (!path.endsWith(".ts")) continue;
    const before = upstream.get(path);
    if (before === after) continue;
    const had = new Set(splitLines(before).lines);
    for (const raw of splitLines(after).lines) {
      if (had.has(raw)) continue;
      const line = raw
        .replace(/\/\/.*$/, "")
        .replace(/'[^']*'/g, "''")
        .replace(/"[^"]*"/g, '""')
        .replace(/`[^`]*`/g, "``");
      for (const m of line.matchAll(/(?:^|[^.\w$])([A-Za-z_$][\w$]*)\s*\(/g)) {
        if (JS_KEYWORDS.has(m[1])) continue;
        if (new RegExp(`\\b${m[1]}\\b`).test(before)) continue;
        found.add(`${path}\u0000${m[1]}`);
      }
      for (const m of line.matchAll(/(?:^|[^.\w$])([A-Z][\w$]*)\s*\./g)) {
        if (new RegExp(`\\b${m[1]}\\b`).test(before)) continue;
        found.add(`${path}\u0000${m[1]}`);
      }
    }
  }
  return [...found]
    .sort()
    .map((s) => ({ file: s.split("\u0000")[0], symbol: s.split("\u0000")[1] }));
}

/** Reserved words that take a parenthesis and are not calls. */
const JS_KEYWORDS = Object.freeze(
  new Set(["if", "for", "while", "switch", "catch", "return", "typeof", "await", "function", "super"]),
);

/* -------------------------------------------------------------------------- */
/* The manifest                                                                */
/* -------------------------------------------------------------------------- */

export function sha256(text) {
  return crypto.createHash("sha256").update(Buffer.isBuffer(text) ? text : Buffer.from(text, "utf8")).digest("hex");
}

/**
 * What was applied, to what, and what came out.
 *
 * No timestamp, no hostname, no absolute path: the manifest is a function of the checkout and this
 * module, so two builds of one pin are byte-identical. That is what "pinned by SHA and rebuilt
 * deliberately, never regenerated silently" needs in order to be a checkable claim — a manifest
 * carrying a clock can only ever say that a rebuild happened, never that it produced the same tree.
 */
function buildManifest({ tree, out, changed, journal, steps, options }) {
  const sha = options.sha ?? null;
  return {
    generatedBy: "HD-85 phase 4 repaired base tree",
    upstream: {
      repo: "juice-shop/juice-shop",
      sha,
      pinnedSha: PINNED_SHA,
      matchesPin: sha == null ? null : sha === PINNED_SHA,
    },
    counts: {
      keys: new Set(steps.flatMap((s) => s.keys)).size,
      /**
       * 36, not 35: `iacLeakedKeyChallenge` occupies two byte-identical `networking.tf` files, so
       * the corpus has 35 keys and 36 (key, block) pairs. Phase 3's extractor conformance is
       * asserted over the same 36.
       */
      keyBlockPairs: steps.flatMap((s) => s.keys).length,
      blocks: steps.length,
      filesChanged: changed.length,
      splicedBlocks: journal.filter((s) => s.mode === "splice").length,
      handRepairedBlocks: journal.filter((s) => s.mode === "hand-repair").length,
    },
    handRepairedKeys: [...HAND_REPAIRED_KEYS],
    conflictRulings: CONFLICT_RULINGS.map((r) => ({
      file: r.file,
      keys: [...r.keys],
      chosen: r.chosen,
      ruledOut: [...r.ruledOut],
      reason: r.reason,
    })),
    overlapEffects: OVERLAP_EFFECTS.map((e) => ({ block: e.block, byKey: e.byKey, kind: e.kind, reason: e.reason })),
    /**
     * The tree parses; it does not typecheck. Carried in the manifest rather than in a comment,
     * because phase 6 has to rule on findings that land on these lines and cannot do that against
     * a fact recorded only in this repository's source.
     */
    parsesButDoesNotTypecheck: {
      decision: "carry upstream's correct variants verbatim; do not hand-patch them to compile",
      basis: "the corpus doc requires the base tree to parse and says it need not run",
      defects: BASE_TREE_DEFECTS.map((d) => ({
        file: d.file,
        key: d.key,
        variant: d.variant,
        symbol: d.symbol,
        kind: d.kind,
        line: d.line,
        note: d.note,
      })),
    },
    steps: journal,
    changedFiles: changed.map((path) => ({
      path,
      upstreamSha256: sha256(tree.get(path)),
      baseSha256: sha256(out.get(path)),
    })),
  };
}
