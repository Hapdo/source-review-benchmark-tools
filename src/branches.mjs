/**
 * The three splice-derived pull-request classes, as a branch plan.
 *
 * Phase 6 turns the repaired base tree into pull requests. Three of the classes are derived from
 * the splicer and are this module's:
 *
 * | Class | What the branch does | What the scorer holds it to |
 * |---|---|---|
 * | `introduce-the-vuln` | reverts one block to upstream's vulnerable code | must be found, and blocked |
 * | `broken-fix` | applies a non-`_correct` variant to that block | must be found, and blocked |
 * | `correct-fix` | applies a `_N_correct` variant to that block | must produce **no** finding |
 *
 * Nothing here touches git or the filesystem, and nothing carries a clock, a hostname or an
 * absolute path. A plan is a pure function of (upstream tree, base tree, codefixes) and this
 * module, which is what lets "two runs produce byte-identical plans" be checked rather than
 * asserted — the same discipline phase 4's manifest is built on.
 *
 * ## Why a correct fix is cut from a vulnerable head and not from the base
 *
 * Re-applying `_N_correct` to the repaired base is an **empty diff**: the base already carries it.
 * An empty diff short-circuits the harness to `complete` over an empty target list, so 35 items of
 * the false-positive denominator would score clean without a byte being read. So a correct-fix
 * branch is cut from the introduce-the-vuln head for the same block, and the plan pins that base
 * per branch. Broken fixes are cut from the same head, for a different reason — see
 * {@link BROKEN_FIX_BASE}.
 *
 * ## The unit is the **item**, not the block
 *
 * There are 23 blocks and 22 scored items, because `iacLeakedKeyChallenge` sits in two
 * byte-identical `networking.tf` files. Phase 5 ruled that one item with one mirrored site;
 * {@link MIRRORED_ITEMS} records it, and every branch for that item edits **both** files. A branch
 * that edited one would leave the other vulnerable, and a correct-fix branch built on it would
 * inherit that — scoring a pull request that really did fix the defect as a true positive.
 *
 * That generalises to the rule this module applies everywhere: **a branch repairs, or introduces,
 * every site of its own item.** A site belonging to a *different* item that shares the block is
 * not the branch's to repair, and is declared instead — see "Residual defects" below.
 *
 * ## What is spliced, and what is amended before it is spliced
 *
 * Two blocks in the corpus have their displayed snippet rewritten by a *different* block's fix,
 * and phase 4 declares both in `OVERLAP_EFFECTS`. A branch that spliced upstream's snippet back
 * verbatim would undo the other block's fix as a side effect and nothing would error. So every
 * text this module splices — upstream's snippet for an introduce-the-vuln branch, a variant's text
 * for the other two — is first put through {@link applyAmendments}, which replays exactly those
 * declared effects. B14's variants are the case that makes this load-bearing: without the
 * amendment, every `chatbotPromptInjectionChallenge` branch would strip `.max(10)` back off the
 * `discount:` line and quietly delete B13's entire security fix.
 *
 * ## Residual defects, declared rather than smoothed over
 *
 * Eight blocks carry more than one key. For **five** of them, one key's correct variant does not
 * repair its siblings' defects: `adminSectionChallenge_1_correct.ts` comments out the admin route
 * and leaves the score-board and web3-sandbox routes exactly as upstream ships them. So a
 * correct-fix branch for one of those keys is a genuine, correct fix that still sits in a block
 * with another item's defect in it, and a reviewer who flags that defect is **right**.
 *
 * Those are recorded per branch as `residualKeys`, with the lines, so the scorer can exclude them
 * the way phase 5 already excludes gitleaks hits on untouched files: corpus, not a false positive.
 * They are not repaired here, because repairing them would mean this module deciding that a
 * correct-fix pull request should also contain another item's fix, which is not what upstream's
 * variant says and not what the class measures.
 *
 * ## The one place the base is not clean
 *
 * `server.ts` registers `/metrics` twice and only one registration is inside B22.
 * {@link DECLARED_RESIDUAL_SITES} carries it, and B22's branches say so in their expectation
 * rather than claiming a move from "safe" to "vulnerable" that the corpus does not support.
 *
 * ## Splice, then strip
 *
 * Splicing needs the markers; the scored tree has none. So the order is forced: splice, then
 * strip. Each branch therefore carries its changed files twice — `spliced` (markers present, the
 * intermediate) and `scored` (what is pushed) — and {@link verifyBranchPlan} proves that stripping
 * neither erases nor distorts any branch's edit, by diffing the scored branch against the scored
 * base and matching that diff against the marked one line for line.
 */
import { extractSnippet, parseMarker, splitLines } from "./markers.mjs";
import { spliceVariantChecked } from "./splice.mjs";
import { stripMarkers } from "./strip.mjs";
import { filterString, isCorrectVariant, keyOfVariantFile } from "./rsn.mjs";
import {
  BASE_TREE_DEFECTS,
  OVERLAP_EFFECTS,
  lineHunks,
  planSteps,
  sha256,
} from "./base-tree.mjs";
import { FIXED, OUTER_KEY as HAND_BUILT_KEY, UNFIXED, applyB13Correct } from "./b13-hand-repair.mjs";

/** The plan was asked to produce a branch it will not sign, or found one it will not sign. */
export class BranchRefused extends Error {
  constructor(message) {
    super(message);
    this.name = "BranchRefused";
  }
}

/** The three classes this module owns, in the order they are generated. */
export const CLASSES = Object.freeze(["introduce-the-vuln", "broken-fix", "correct-fix"]);

/** What the scorer does with each class. Data, so a plan can be read without reading this file. */
export const CLASS_EXPECTATIONS = Object.freeze({
  "introduce-the-vuln": Object.freeze({ verdict: "must-flag", scoredAs: "detection + blocking" }),
  "broken-fix": Object.freeze({ verdict: "must-flag", scoredAs: "detection + blocking" }),
  "correct-fix": Object.freeze({ verdict: "must-not-flag", scoredAs: "false-positive denominator" }),
});

/**
 * Where one key occupies more than one block, and every branch for it must edit every site.
 *
 * `infrastructure/terraform/networking.tf` and `terraform/networking.tf` are byte-identical at the
 * pin and carry the same key. Upstream's own `SNIPPET_PATHS` omits the top-level `terraform/`, so
 * phase 5 seats the item at the `infrastructure/` copy and calls the other a mirrored site — one
 * scored item, two places the same secret is written down.
 *
 * The consequence is this table rather than a comment, because the failure it prevents is
 * invisible: an introduce-the-vuln branch editing one file leaves the other vulnerable, the
 * correct-fix branch cut from it inherits that, and a pull request that really did fix the defect
 * scores as a true positive.
 */
export const MIRRORED_ITEMS = Object.freeze([
  Object.freeze({
    key: "iacLeakedKeyChallenge",
    /** The site phase 5 seats the item at — the copy upstream's snippet paths name. */
    primary: "infrastructure/terraform/networking.tf:1",
    mirrors: Object.freeze(["terraform/networking.tf:1"]),
    reason:
      "one key, two byte-identical files; upstream's SNIPPET_PATHS names only the " +
      "infrastructure/ copy, so phase 5 scores one item with the other as a mirrored site",
  }),
]);

/**
 * The block whose branches are built from one line, and the two operations that build them.
 *
 * `chatbotGreedyInjectionChallenge` — B13, `routes/chat.ts` 81–188 — has no variant that is an edit
 * of its displayed snippet: all four drop the `export function chat () {` wrapper and dedent by
 * four, so none of them can be spliced as written (see {@link EXCLUDED_VARIANTS}). What B13's fix
 * *is* was measured in phase 4 and is one literal substring on one line: `z.number()` becomes
 * `z.number().max(10)`. So its two branches are that substitution and its inverse.
 *
 * Each one is made twice, and the two must agree byte for byte. Once by hand, as a substitution
 * over the file, proved against `applyB13Correct`: introducing the vulnerability is refused unless
 * re-applying the hand repair returns the base tree's `routes/chat.ts`. And once by the splicer,
 * as the same substitution over the block's *displayed snippet*, spliced back on B13's own key and
 * held to `spliceVariantChecked`'s round trip and confinement check.
 *
 * Until HD-81 the second derivation did not exist. B13's `end` marker on line 188 reads
 * `end chatbotGreedyInjectionChallenge chatbotPromptInjectionChallenge`, B13's key is the first
 * name on it, and the splicer wrote the rest of that list back as a bare
 * ` chatbotPromptInjectionChallenge` line after the marker. Phase 4's workaround — anchor on the
 * last key — was unavailable, because that key is B14's. The splicer now keeps that text inside
 * the marker, so B13 splices like every other block and these are no longer the one step in the
 * corpus with no round trip behind it.
 */
export const HAND_BUILT_ITEMS = Object.freeze([
  Object.freeze({
    key: HAND_BUILT_KEY,
    block: "routes/chat.ts:81",
    file: "routes/chat.ts",
    introduce: Object.freeze({ find: FIXED, replace: UNFIXED }),
    repair: "src/b13-hand-repair.mjs#applyB13Correct",
    reason:
      "no variant of B13 is an edit of its displayed snippet; its fix is one literal substring, " +
      "applied by hand and by the splicer, and the two must agree byte for byte",
  }),
]);

/**
 * The variants this module refuses to make a branch from, with the measurement behind each.
 *
 * All three are `chatbotGreedyInjectionChallenge`'s broken variants. The exclusion is not a
 * preference; three independent things have to be decided to include them, and two of the three
 * would put a build break into a branch that is scored for security findings:
 *
 * 1. *(Retired by HD-81.)* Phase 6 recorded a first reason: B13's `end` marker names its own key
 *    first, so the splicer's stray-line defect fired on it and no anchor avoided it. The splicer
 *    is fixed and B13's block now splices; the two reasons below are why these three are still
 *    excluded, and either is sufficient.
 * 2. **They are not edits of their block's snippet.** They drop the `export function chat () {`
 *    wrapper and its `return async (req, res) => {`, and dedent the tool object by four. Splicing
 *    one deletes a live function declaration.
 * 3. **All three drop `export` from `buildSystemPrompt`, which `routes/verify.ts` imports.**
 *    `_1` also drops its `userName?: string` parameter. A branch carrying either would fail to
 *    compile, and a reviewer rejecting it would be rejecting a build break — a "detection" that
 *    measures nothing about the vulnerability.
 *
 * Re-cutting them would mean declaring, line by line, that `export` belongs back on a function the
 * variant says it does not export, and that `_1` takes a parameter the variant says it does not
 * take. That is a judgement about what a variant *means*, not a splice; phase 4's precedent for
 * such a judgement is `BASE_TREE_DEFECTS`, which carries upstream's text verbatim and declares the
 * consequence rather than editing the corpus to taste. The same precedent points at excluding
 * these, so they are excluded and the class is **87**, not 90.
 *
 * The key is not left uncovered: its introduce-the-vuln branch and its correct-fix branch are both
 * built, by hand, from the one line that is its whole security fix.
 */
export const EXCLUDED_VARIANTS = Object.freeze([
  Object.freeze({
    variant: "chatbotGreedyInjectionChallenge_1.ts",
    class: "broken-fix",
    signals: Object.freeze(["not-an-edit-of-its-snippet", "drops-export", "drops-parameter"]),
  }),
  Object.freeze({
    variant: "chatbotGreedyInjectionChallenge_3.ts",
    class: "broken-fix",
    signals: Object.freeze(["not-an-edit-of-its-snippet", "drops-export"]),
  }),
  Object.freeze({
    variant: "chatbotGreedyInjectionChallenge_4.ts",
    class: "broken-fix",
    signals: Object.freeze(["not-an-edit-of-its-snippet", "drops-export"]),
  }),
]);

/** The symbol whose `export` all three dropped, and the file that imports it. Pinned, so the
 * exclusion expires rather than outlives its reason if upstream re-cuts them. */
export const EXCLUSION_EVIDENCE = Object.freeze({
  exportedSymbol: "export function buildSystemPrompt",
  importedBy: "routes/verify.ts",
  importLine: "import { buildSystemPrompt } from './chat'",
});

/**
 * Sites where the tree is vulnerable **outside any branch's doing**, and every branch over the
 * block that owns them says so.
 *
 * `server.ts` registers `/metrics` twice: once at upstream line 695, outside every block and
 * unguarded, and once inside B22 where the marker calls it the vulnerability.
 * `exposedMetricsChallenge_3_correct.ts` guards only the marked one, so the repaired base is still
 * exposed at the unmarked site.
 *
 * What follows is the part worth writing down. B22's introduce-the-vuln branch does **not** move
 * the tree from "safe" to "vulnerable"; it moves it from "exposed at one site" to "exposed at
 * two". Telling the scorer otherwise would be telling it a falsehood about the only block where
 * the class's own premise is measurably not true. B22's correct-fix branch inherits the same site,
 * on a line its diff does not touch.
 */
export const DECLARED_RESIDUAL_SITES = Object.freeze([
  Object.freeze({
    block: "server.ts:746",
    key: "exposedMetricsChallenge",
    file: "server.ts",
    line: "  app.get('/metrics', utils.asyncHandler(metrics.serveMetrics()))",
    kind: "unrepaired-sibling-site",
    effect: "introduce-the-vuln moves this block from exposed-at-one-site to exposed-at-two-sites",
    reason:
      "upstream registers /metrics a second time outside every block and the correct fix leaves " +
      "it; deleting it would be this repository deciding what upstream's fix should have been",
  }),
]);

/**
 * The ruling on findings that land on phase 4's declared defect lines.
 *
 * `BASE_TREE_DEFECTS` names seven lines the repaired base carries that do not typecheck — three
 * functions nobody wrote (`validatePasswordHasAtLeastTenChar`,
 * `validatePasswordIsNotInTopOneMillionCommonPasswordsList`, `security.isAdmin`), a type nobody
 * declared (`OrderStatus`), a destructured parameter absent from its own schema, a duplicated
 * object key, and the unmarked `/metrics` site above. Every one of them is upstream's: a codefix
 * is only ever *displayed* by Juice Shop, so nothing has ever forced one to compile in the file it
 * claims to patch.
 *
 * They bite hardest in the correct-fix class, and they bite on the *diff* rather than on the
 * surroundings — `chatbotPromptInjectionChallenge_2_correct.ts` **adds** the `OrderStatus` line, so
 * a correct-fix branch's own changed lines contain it. A reviewer who flags it is right, and
 * scoring that as a false positive would penalise a correct review for a property of the corpus.
 *
 * **Ruling: a finding whose location resolves to a declared defect line is corpus, and is scored
 * as neither a true nor a false positive.** It is excluded from both numerators and from the
 * false-positive denominator. This is phase 5's existing treatment of gitleaks hits on untouched
 * files, applied to a set that is enumerated rather than inferred: every branch carries the exact
 * lines, so the exclusion is a lookup and not a judgement made per finding.
 *
 * The alternative — patching the lines so the tree typechecks — was rejected in phase 4 and is
 * rejected again here for the reason phase 4 gave: it would decouple the base from the correct-fix
 * class, which lands these same variants, and the benchmark would be comparing two different fixes.
 */
export const DEFECT_LINE_RULING = Object.freeze({
  ruling: "corpus, not the branch's: excluded from both numerators and from the FP denominator",
  basis: "phase 5 already treats gitleaks hits on untouched files this way",
  alternativeRejected: "hand-patching the lines would decouple the base from the correct-fix class",
  lines: Object.freeze(
    BASE_TREE_DEFECTS.map((d) =>
      Object.freeze({ file: d.file, key: d.key, variant: d.variant, symbol: d.symbol, kind: d.kind, line: d.line }),
    ),
  ),
});

/**
 * Which tree a broken-fix branch is cut from, and why it is not the repaired base.
 *
 * Both bases produce the same *file*: the block ends up displaying the broken variant either way.
 * They differ in what the pull request **means**, and for a multi-key block they differ in what it
 * contains.
 *
 * Cut from the repaired base, a broken-fix branch reads as a regression — someone replacing a
 * working fix with a broken one — and, worse, its diff is computed against the *composed* snippet.
 * For a block whose variants each rewrite the whole snippet, that diff reverts every sibling key's
 * fix as well: a broken fix for `resetPasswordJimChallenge` would silently introduce the other four
 * reset-password defects, and the item would be scored as one while carrying five.
 *
 * Cut from the introduce-the-vuln head, the diff is exactly "someone tried to fix this item and
 * got it wrong", which is what upstream's `info.yml` says each of these variants is, and it
 * introduces that item's defect and nothing else.
 */
export const BROKEN_FIX_BASE = Object.freeze({
  base: "the introduce-the-vuln head for the same block",
  reason:
    "cutting from the repaired base would diff against the composed snippet and revert every " +
    "sibling key's fix as a side effect, putting several items' defects into a one-item branch",
});

/* -------------------------------------------------------------------------- */
/* Declared cross-block amendments                                            */
/* -------------------------------------------------------------------------- */

/**
 * Replay phase 4's declared `OVERLAP_EFFECTS` over a snippet about to be spliced.
 *
 * This is deliberately a re-statement of the private `amendSnippet` in `src/base-tree.mjs` rather
 * than a call into it: that function is not exported, and phase 6 does not own that file. The two
 * are held together by {@link verifyBranchPlan}, which requires that amending upstream's snippet
 * and then composing gives back exactly what the finished base tree displays — so a divergence
 * between the two copies fails a plan rather than producing a branch.
 *
 * Each amendment must match **exactly once**, for the reason phase 4 gives: an amendment that is
 * not unique is not an amendment.
 */
export function applyAmendments(snippet, amendments, where) {
  let lines = filterString(snippet).split("\n");
  for (const a of amendments) {
    if (a.kind === "line-substitution") {
      const hits = lines.filter((l) => l.includes(a.find)).length;
      if (hits !== 1) {
        throw new BranchRefused(
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
        throw new BranchRefused(
          `${where}: the declared run of ${a.run.length} lines occurs ${at.length} times, not once.`,
        );
      }
      lines = [...lines.slice(0, at[0]), ...lines.slice(at[0] + a.run.length)];
      continue;
    }
    throw new BranchRefused(`${where}: unknown overlap effect kind ${JSON.stringify(a.kind)}`);
  }
  return lines.join("\n");
}

/** The declared effects later steps have on one block's displayed snippet. */
function amendmentsFor(blockId) {
  return OVERLAP_EFFECTS.filter((e) => e.block === blockId);
}

/* -------------------------------------------------------------------------- */
/* Items — the unit a branch is about                                          */
/* -------------------------------------------------------------------------- */

/**
 * A stable, filesystem-free name for a block. Used in branch names, so it may not contain
 * anything git would refuse or a shell would read as a path.
 */
export function slugFor(blockId) {
  return blockId
    .replace(/[^A-Za-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .toLowerCase();
}

/**
 * Group the 23 blocks into the scored items branches are cut for.
 *
 * One item per block, except that {@link MIRRORED_ITEMS} folds a key's mirrored sites into the
 * item its primary site seats. The fold is asserted rather than trusted: the declared primary and
 * mirrors must each be a real block, must all carry the same single key, and — since the whole
 * point is that they are copies — must be byte-identical upstream.
 *
 * @param {Map<string, string>} upstream the corpus at its pin
 * @param {Map<string, string>} codefixes `data/static/codefixes/`
 */
export function planItems(upstream, codefixes) {
  const steps = planSteps(upstream, codefixes);
  const byId = new Map(steps.map((s) => [s.id, s]));
  /** Block ids folded into another item, so they do not also become items of their own. */
  const folded = new Map();

  for (const mirror of MIRRORED_ITEMS) {
    const sites = [mirror.primary, ...mirror.mirrors];
    for (const id of sites) {
      const step = byId.get(id);
      if (step == null) throw new BranchRefused(`MIRRORED_ITEMS names block ${id}, which this corpus has no block at`);
      if (step.keys.length !== 1 || step.keys[0] !== mirror.key) {
        throw new BranchRefused(
          `MIRRORED_ITEMS says ${id} carries only ${mirror.key}, and it carries ${step.keys.join(", ")}.`,
        );
      }
    }
    const texts = new Set(sites.map((id) => upstream.get(byId.get(id).file)));
    if (texts.size !== 1) {
      throw new BranchRefused(
        `${sites.join(" and ")} are declared mirrors of one another and are not byte-identical ` +
          `upstream. A mirror that has drifted is two items, not one.`,
      );
    }
    for (const id of mirror.mirrors) folded.set(id, mirror.primary);
  }

  const items = [];
  for (const step of steps) {
    if (folded.has(step.id)) continue;
    const mirror = MIRRORED_ITEMS.find((m) => m.primary === step.id);
    const siteIds = mirror == null ? [step.id] : [step.id, ...mirror.mirrors];
    const sites = siteIds.map((id) => {
      const s = byId.get(id);
      return {
        block: s.id,
        file: s.file,
        span: [s.start, s.end],
        anchor: s.anchor,
        keys: [...s.keys],
        amendments: amendmentsFor(s.id).map((a) => ({ byKey: a.byKey, kind: a.kind })),
      };
    });
    if (new Set(sites.map((s) => s.file)).size !== sites.length) {
      throw new BranchRefused(`${step.id}: an item has two sites in one file, which this module does not splice`);
    }
    items.push({
      id: step.id,
      slug: slugFor(step.id),
      keys: [...step.keys],
      mode: step.mode,
      mirrored: mirror != null,
      sites,
      variants: step.variants.map((v) => ({ key: v.key, file: v.file })),
    });
  }
  return items;
}

/* -------------------------------------------------------------------------- */
/* Producing one branch's files                                                */
/* -------------------------------------------------------------------------- */

/**
 * The block's snippet as **upstream** displays it, amended by whatever a later phase-4 step was
 * declared to do to it.
 *
 * The amendment is the whole reason this is not `extractSnippet(upstream…)`. B05 is displayed
 * without the `token-sale` route because B06's fix deleted it, and B14 is displayed with
 * `.max(10)` because B13's hand repair added it. Reverting to the unamended upstream text would
 * put both back and silently undo another item's fix.
 */
function vulnerableSnippetFor(upstream, site) {
  const raw = extractSnippet(upstream.get(site.file), site.anchor).snippet;
  return applyAmendments(raw, amendmentsFor(site.block), `${site.block} (upstream snippet)`);
}

/**
 * Splice one text into one site of one file, and refuse a no-op.
 *
 * `spliceVariantChecked` already proves the text landed where the snippet was, by re-displaying
 * the block and demanding the text back. What it cannot notice is a splice that changed nothing —
 * which, for a branch, is the failure that matters: an empty diff scores clean over an empty
 * target list without a byte being read.
 */
function spliceInto(source, site, text, what) {
  const { source: out } = spliceVariantChecked(source, site.anchor, text);
  if (out === source) {
    throw new BranchRefused(
      `${site.block}: ${what} produced no change to ${site.file}. An empty diff short-circuits ` +
        `the harness to a clean verdict over an empty target list, so it is never a branch.`,
    );
  }
  return out;
}

/**
 * The files of the introduce-the-vuln head for one item.
 *
 * @returns {Map<string, string>} path -> marked contents, one entry per site
 */
function introduceVulnFiles(upstream, base, item) {
  if (item.mode === "hand-repair") return handBuiltVulnFiles(base, item);
  const files = new Map();
  for (const site of item.sites) {
    const before = base.get(site.file);
    if (before == null) throw new BranchRefused(`${site.block}: the base tree has no ${site.file}`);
    files.set(site.file, spliceInto(before, site, vulnerableSnippetFor(upstream, site), "reverting the block"));
  }
  assertMirrorsAgree(item, files, "introduce-the-vuln");
  return files;
}

/**
 * B13's introduce-the-vuln head: the inverse of the hand repair, proved by the hand repair.
 *
 * The substitution alone would be a text edit nothing checks. Re-applying `applyB13Correct` to the
 * result and demanding the base tree's `routes/chat.ts` back byte for byte is the round trip the
 * splicer would otherwise have provided — and it is stronger than a string comparison, because
 * `applyB13Correct` refuses an input that is not that file, or that B14 has not been spliced into.
 */
function handBuiltVulnFiles(base, item) {
  const declared = HAND_BUILT_ITEMS.find((h) => h.block === item.id);
  if (declared == null) {
    throw new BranchRefused(
      `${item.id} cannot be spliced and HAND_BUILT_ITEMS does not say how to build its branches.`,
    );
  }
  const before = base.get(declared.file);
  if (before == null) throw new BranchRefused(`${item.id}: the base tree has no ${declared.file}`);
  const occurrences = before.split(declared.introduce.find).length - 1;
  if (occurrences !== 1) {
    throw new BranchRefused(
      `${item.id}: the base tree's ${declared.file} carries ${JSON.stringify(declared.introduce.find)} ` +
        `${occurrences} times, not once. The hand-built branch edits one line and it has to be ` +
        `unambiguous.`,
    );
  }
  const after = before.split(declared.introduce.find).join(declared.introduce.replace);
  assertSpliceAgrees(item, before, after, declared.introduce.find, declared.introduce.replace, "introduce-the-vuln");
  const back = applyB13Correct(after);
  if (back.source !== before) {
    throw new BranchRefused(
      `${item.id}: re-applying ${declared.repair} to the vulnerable head did not give the base ` +
        `tree's ${declared.file} back. The hand-built revert is not the inverse of the repair.`,
    );
  }
  return new Map([[declared.file, after]]);
}

/**
 * The files of a branch that applies one variant to an introduce-the-vuln head.
 *
 * @param {Map<string, string>} head the head's changed files, path -> marked contents
 */
function applyVariantFiles(head, item, variantName, variantText) {
  if (item.mode === "hand-repair") return handBuiltFixFiles(head, item, variantName);
  const files = new Map();
  for (const site of item.sites) {
    const before = head.get(site.file);
    if (before == null) throw new BranchRefused(`${site.block}: the head has no ${site.file}`);
    const text = applyAmendments(variantText, amendmentsFor(site.block), `${site.block} (${variantName})`);
    files.set(site.file, spliceInto(before, site, text, `applying ${variantName}`));
  }
  assertMirrorsAgree(item, files, variantName);
  return files;
}

/** B13's correct fix is the hand repair itself, applied to the head the inverse produced. */
function handBuiltFixFiles(head, item, variantName) {
  const declared = HAND_BUILT_ITEMS.find((h) => h.block === item.id);
  const before = head.get(declared.file);
  const { source } = applyB13Correct(before);
  if (source === before) throw new BranchRefused(`${item.id}: ${variantName} by hand produced no change`);
  assertSpliceAgrees(item, before, source, declared.introduce.replace, declared.introduce.find, variantName);
  return new Map([[declared.file, source]]);
}

/**
 * Make a hand-built branch a second time, by the splicer, and refuse unless the two agree.
 *
 * The same one-line substitution is applied to the block's **displayed snippet** instead of to the
 * file, and spliced back on the block's own key, so the result carries `spliceVariantChecked`'s
 * round trip and its proof that nothing outside the block moved. A hand edit and a splice that
 * reach the same bytes by different routes are each other's check.
 */
function assertSpliceAgrees(item, before, byHand, find, replace, what) {
  const [site] = item.sites;
  const snippet = extractSnippet(before, site.anchor).snippet;
  const occurrences = snippet.split(find).length - 1;
  if (occurrences !== 1) {
    throw new BranchRefused(
      `${item.id}: the displayed snippet carries ${JSON.stringify(find)} ${occurrences} times, not ` +
        `once, so the splicer cannot make ${what} from it.`,
    );
  }
  const bySplice = spliceInto(before, site, snippet.split(find).join(replace), `${what} by the splicer`);
  if (bySplice !== byHand) {
    throw new BranchRefused(
      `${item.id}: ${what} by hand and by the splicer disagree on ${site.file}. One of the two ` +
        `routes is wrong, and the branch is not built until they agree.`,
    );
  }
}

/**
 * A mirrored item's sites are copies of one another, and a branch that leaves them different has
 * repaired or vulnerabilised one and not the other. That is exactly the failure
 * {@link MIRRORED_ITEMS} exists to prevent, so it is asserted on every branch rather than once.
 */
function assertMirrorsAgree(item, files, what) {
  if (!item.mirrored) return;
  const texts = new Set([...files.values()]);
  if (texts.size === 1) return;
  throw new BranchRefused(
    `${item.id}: ${what} left ${[...files.keys()].sort().join(" and ")} different. One key, two ` +
      `byte-identical files: a branch that edits one of them leaves the other as it was.`,
  );
}

/* -------------------------------------------------------------------------- */
/* Residual defects                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Which of a block's *other* keys are still vulnerable on this branch.
 *
 * The test is on what the sibling's correct fix **removes**, not on what it adds, and the
 * distinction is the whole of `loginBenderChallenge`. Three login keys replace one line;
 * `loginBenderChallenge_2_correct.ts` binds by name where `loginAdminChallenge_4_correct.ts` binds
 * positionally. Asking "are the sibling's added lines present?" reports the admin fix as missing
 * from the bender branch, which is true and irrelevant — both are parameterised and the vulnerable
 * line is gone from both. Asking "are the lines the sibling's fix deletes still displayed?"
 * answers the question that matters, and answers it right for both.
 *
 * A fix that deletes nothing falls back to the containment test, since for a pure insertion there
 * is nothing else to ask.
 *
 * `ownKeys` is the keys the branch is *about* — repaired on a correct fix, attempted and got wrong
 * on a broken fix. Either way they are the branch's own item and are never its residuals; what is
 * being looked for here is another item's defect sitting in the same block.
 */
export function residualKeysFor({ upstreamSnippet, branchSnippet, variants, ownKeys }) {
  const shown = new Set(splitLines(filterString(branchSnippet)).lines.map((l) => l.trim()));
  const residual = [];
  for (const variant of variants) {
    if (ownKeys.includes(variant.key)) continue;
    const hunks = lineHunks(upstreamSnippet, variant.text);
    const removes = hunks.flatMap((h) => h.remove).filter((l) => l.trim() !== "");
    const inserts = hunks.flatMap((h) => h.insert).filter((l) => l.trim() !== "");
    const stillThere =
      removes.length > 0
        ? removes.every((l) => shown.has(l.trim()))
        : !inserts.every((l) => shown.has(l.trim()));
    if (!stillThere) continue;
    residual.push({
      key: variant.key,
      variant: variant.file,
      lines: removes.length > 0 ? removes : inserts,
      basis: removes.length > 0 ? "its correct fix deletes these lines and the branch still shows them" : "its correct fix is a pure insertion and the branch does not carry it",
    });
  }
  return residual;
}

/* -------------------------------------------------------------------------- */
/* The plan                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Build the whole branch plan.
 *
 * @param {{upstream: Map<string, string>, base: Map<string, string>, codefixes: Map<string, string>}} input
 * @returns {{items: object[], branches: object[], counts: object, rulings: object, manifest: object}}
 */
export function planBranches({ upstream, base, codefixes }) {
  const items = planItems(upstream, codefixes);
  const excluded = new Set(EXCLUDED_VARIANTS.map((e) => e.variant));
  const variantsByKey = new Map();
  for (const name of [...codefixes.keys()].sort()) {
    if (name.endsWith(".info.yml") || name.endsWith(".editorconfig")) continue;
    const key = keyOfVariantFile(name);
    if (!variantsByKey.has(key)) variantsByKey.set(key, []);
    variantsByKey.get(key).push(name);
  }

  /** Per item, the upstream snippet and the block's correct variants — the residual test's input. */
  const context = new Map();
  for (const item of items) {
    const primary = item.sites[0];
    context.set(item.id, {
      primary,
      upstreamSnippet: vulnerableSnippetFor(upstream, primary),
      correctVariants: item.variants.map((v) => ({ key: v.key, file: v.file, text: codefixes.get(v.file) })),
    });
  }

  const branches = [];
  for (const item of items) {
    const ctx = context.get(item.id);
    const head = introduceVulnFiles(upstream, base, item);
    const introduce = makeBranch({
      cls: "introduce-the-vuln",
      name: `hd85/introduce/${item.slug}`,
      baseRef: "base",
      item,
      keys: item.keys,
      variant: null,
      files: head,
      base,
      upstream,
      ownKeys: [],
      ctx,
    });
    branches.push(introduce);

    for (const key of item.keys) {
      for (const name of variantsByKey.get(key) ?? []) {
        if (excluded.has(name)) continue;
        const cls = isCorrectVariant(name) ? "correct-fix" : "broken-fix";
        const files = applyVariantFiles(head, item, name, codefixes.get(name));
        branches.push(
          makeBranch({
            cls,
            name: `hd85/${cls}/${name.replace(/\.[^.]+$/, "")}`,
            baseRef: introduce.id,
            item,
            keys: [key],
            variant: name,
            files,
            base,
            upstream,
            ownKeys: [key],
            ctx,
            headFiles: head,
          }),
        );
      }
    }
  }

  branches.sort((a, b) => CLASSES.indexOf(a.class) - CLASSES.indexOf(b.class) || a.id.localeCompare(b.id));

  const counts = {};
  for (const cls of CLASSES) counts[cls] = branches.filter((b) => b.class === cls).length;
  counts.total = branches.length;
  counts.items = items.length;
  counts.blocks = items.reduce((n, i) => n + i.sites.length, 0);
  counts.keys = new Set(items.flatMap((i) => i.keys)).size;
  counts.excludedVariants = EXCLUDED_VARIANTS.length;

  return {
    items,
    branches,
    counts,
    rulings: {
      excludedVariants: EXCLUDED_VARIANTS.map((e) => ({ ...e, signals: [...e.signals] })),
      exclusionEvidence: { ...EXCLUSION_EVIDENCE },
      mirroredItems: MIRRORED_ITEMS.map((m) => ({ ...m, mirrors: [...m.mirrors] })),
      handBuiltItems: HAND_BUILT_ITEMS.map((h) => ({ key: h.key, block: h.block, file: h.file, repair: h.repair, reason: h.reason })),
      declaredResidualSites: DECLARED_RESIDUAL_SITES.map((s) => ({ ...s })),
      defectLines: { ...DEFECT_LINE_RULING, lines: DEFECT_LINE_RULING.lines.map((l) => ({ ...l })) },
      brokenFixBase: { ...BROKEN_FIX_BASE },
    },
    manifest: {
      generatedBy: "HD-85 phase 6 splice-derived branch classes",
      counts,
      classes: [...CLASSES],
      classExpectations: CLASS_EXPECTATIONS,
      branches: branches.map((b) => ({
        id: b.id,
        name: b.name,
        class: b.class,
        base: b.base,
        item: b.item,
        keys: [...b.keys],
        variant: b.variant,
        files: b.files.map((f) => ({ path: f.path, splicedSha256: f.splicedSha256, scoredSha256: f.scoredSha256 })),
      })),
    },
  };
}

/**
 * Assemble one branch record.
 *
 * `spliced` and `scored` are both carried because the order is splice-then-strip and both halves
 * have to be checkable: the splice needs the markers, the pushed tree must not have them, and
 * "the branch's diff against the stripped base is still the intended change" is a claim about the
 * second that can only be proved by holding the first beside it.
 */
function makeBranch({ cls, name, baseRef, item, keys, variant, files, base, upstream, ownKeys, ctx, headFiles }) {
  const primary = ctx.primary;
  const branchSnippet = extractSnippet(files.get(primary.file), primary.anchor).snippet;
  const against = headFiles ?? base;

  const changed = [...files.keys()].sort().map((path) => {
    const spliced = files.get(path);
    const baseline = against.get(path);
    const scored = stripMarkers(spliced).source;
    const scoredBaseline = stripMarkers(baseline).source;
    if (scored === scoredBaseline) {
      throw new BranchRefused(
        `${name}: ${path} differs from its base only in marker comments, so the edit does not ` +
          `survive stripping and the pushed branch is an empty diff.`,
      );
    }
    return {
      path,
      spliced,
      scored,
      splicedSha256: sha256(spliced),
      scoredSha256: sha256(scored),
      scoredHunks: lineHunks(scoredBaseline, scored).map((h) => ({
        start: h.start,
        end: h.end,
        removed: h.remove.length,
        inserted: h.insert.length,
      })),
    };
  });

  const residual =
    cls === "introduce-the-vuln"
      ? []
      : residualKeysFor({
          upstreamSnippet: ctx.upstreamSnippet,
          branchSnippet,
          variants: ctx.correctVariants,
          ownKeys,
        });

  const paths = new Set(changed.map((f) => f.path));
  const defectLines = DEFECT_LINE_RULING.lines.filter((d) => paths.has(d.file));
  const inDiff = new Set(
    changed.flatMap((f) => {
      const had = new Set(splitLines(against.get(f.path)).lines);
      return splitLines(f.spliced).lines.filter((l) => !had.has(l));
    }),
  );
  const residualSites = DECLARED_RESIDUAL_SITES.filter((s) => item.sites.some((site) => site.block === s.block));

  return {
    id: `${cls}/${variant ?? item.slug}`,
    name,
    class: cls,
    base: baseRef,
    item: item.id,
    itemSlug: item.slug,
    mirrored: item.mirrored,
    blocks: item.sites.map((s) => s.block),
    blockKeys: [...item.keys],
    keys: [...keys],
    variant,
    builtBy: item.mode === "hand-repair" ? HAND_BUILT_ITEMS.find((h) => h.block === item.id).repair : "spliceVariantChecked",
    files: changed,
    defectSites: defectSitesFor(upstream, item, keys, files),
    expectation: {
      ...CLASS_EXPECTATIONS[cls],
      item: item.id,
      keys: [...keys],
      exclude: {
        /** Findings on these lines are corpus, per {@link DEFECT_LINE_RULING}. */
        corpusDefectLines: defectLines.map((d) => ({ ...d, inThisDiff: inDiff.has(d.line) })),
        /** Other items' defects that share this block and that this branch does not repair. */
        residualKeys: residual,
        /** Sites the corpus leaves vulnerable outside any block. */
        residualSites: residualSites.map((s) => ({ ...s })),
      },
    },
  };
}

/**
 * Where the lines upstream marks as this branch's defect have ended up, in **scored** coordinates
 * — the coordinate system of the tree that is pushed.
 *
 * They are located **by content, from upstream's markers**, and not by reading markers out of the
 * branch, because the splicer does not carry a marker onto a line it emits from a diff addition.
 * `extractSnippet` strips the markers before the diff ever sees the text, so every line a splice
 * *replaces* arrives unmarked, and those are precisely the `vuln-line` lines. That is a property of
 * phase 3's splicer and of phase 4's base tree, not of this module — the repaired base loses the
 * same markers on the same lines — and it is worked around here rather than fixed, since
 * `src/splice.mjs` is out of phase 6's scope.
 *
 * `located` is reported rather than asserted. Three blocks legitimately cannot show upstream's
 * text: B13's `discount:` line was rewritten by B14's splice before B13's branch ever touched it,
 * and B05 and B14 are amended by a declared cross-block effect. A site that is not located is a
 * site whose line another item's fix has since changed, and the scorer is told so instead of being
 * handed a line number that is not there.
 */
function defectSitesFor(upstream, item, keys, files) {
  const out = [];
  for (const site of item.sites) {
    const branch = files.get(site.file);
    if (branch == null) continue;
    const scoredLines = splitLines(stripMarkers(branch).source).lines;
    const upstreamLines = splitLines(upstream.get(site.file)).lines;
    for (let n = site.span[0]; n <= site.span[1]; n++) {
      const marker = parseMarker(upstreamLines[n - 1] ?? "");
      if (marker?.type !== "vuln-line") continue;
      if (!marker.keys.some((k) => keys.includes(k))) continue;
      const text = upstreamLines[n - 1].slice(0, marker.index).replace(/\s+$/, "");
      const at = [];
      scoredLines.forEach((l, i) => {
        if (l === text) at.push(i + 1);
      });
      out.push({ file: site.file, upstreamLine: n, text, scoredLines: at, located: at.length > 0 });
    }
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* Verification                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Prove the plan is the plan that was meant, against the corpus rather than against its own
 * intermediate state.
 *
 * Seven questions, and the first three are the ones a parse gate cannot answer:
 *
 * 1. **Is every variant accounted for?** Every file in `data/static/codefixes/` is either a branch
 *    or a declared exclusion. A variant that quietly stopped producing a branch would otherwise
 *    shrink the denominator and nothing would say so.
 * 2. **Does every introduce-the-vuln branch really display upstream's vulnerable code?** Not "it
 *    changed" — the block's snippet, amended by the declared cross-block effects, byte for byte.
 * 3. **Does every correct-fix branch really display its variant?** Same question, other direction.
 * 4. **Is every branch cut from a base that exists?**
 * 5. **Does stripping preserve every branch's edit?** The scored diff's lines must be the marked
 *    diff's lines with the markers taken off — not merely non-empty.
 * 6. **Is every mirrored item's pair still identical on every branch?**
 * 7. **Does this module's copy of `amendSnippet` agree with phase 4's?** Amending upstream's
 *    snippet is how a vulnerable head is built; if the two copies disagree, every branch over an
 *    overlapping block is wrong in a way that parses.
 *
 * @param {{plan: object, upstream: Map<string, string>, base: Map<string, string>, codefixes: Map<string, string>}} input
 */
export function verifyBranchPlan({ plan, upstream, base, codefixes }) {
  const excluded = new Set(EXCLUDED_VARIANTS.map((e) => e.variant));
  const branchByName = new Map(plan.branches.map((b) => [b.id, b]));

  const wanted = [...codefixes.keys()]
    .filter((n) => !n.endsWith(".info.yml") && !n.endsWith(".editorconfig"))
    .sort();
  const built = new Set(plan.branches.filter((b) => b.variant != null).map((b) => b.variant));
  for (const name of wanted) {
    if (built.has(name) || excluded.has(name)) continue;
    throw new BranchRefused(
      `${name} produced no branch and is not in EXCLUDED_VARIANTS. A variant that silently stops ` +
        `producing a branch shrinks the denominator and says nothing.`,
    );
  }
  for (const entry of EXCLUDED_VARIANTS) {
    if (!wanted.includes(entry.variant)) {
      throw new BranchRefused(`EXCLUDED_VARIANTS names ${entry.variant}, which this corpus does not ship.`);
    }
    if (built.has(entry.variant)) {
      throw new BranchRefused(`${entry.variant} is declared excluded and a branch was built from it anyway.`);
    }
  }

  const itemById = new Map(plan.items.map((i) => [i.id, i]));
  for (const branch of plan.branches) {
    const item = itemById.get(branch.item);
    if (item == null) throw new BranchRefused(`${branch.name} names item ${branch.item}, which is not in the plan`);
    if (branch.base !== "base" && !branchByName.has(branch.base)) {
      throw new BranchRefused(`${branch.name} is cut from ${branch.base}, which is not a branch in this plan`);
    }
    if (branch.files.length !== item.sites.length) {
      throw new BranchRefused(
        `${branch.name} changes ${branch.files.length} file(s) and its item has ${item.sites.length} site(s). ` +
          `A branch repairs, or introduces, every site of its own item.`,
      );
    }

    const contents = new Map(branch.files.map((f) => [f.path, f.spliced]));
    if (item.mirrored && new Set(contents.values()).size !== 1) {
      throw new BranchRefused(`${branch.name} left its mirrored sites different from one another`);
    }

    // The displayed-snippet check, per class. Skipped for the hand-built block, which cannot be
    // displayed through the splicer at all — that is why it is hand-built — and whose two branches
    // are proved against `applyB13Correct` when they are made.
    if (item.mode !== "hand-repair") {
      for (const site of item.sites) {
        const shown = filterString(extractSnippet(contents.get(site.file), site.anchor).snippet).trim();
        if (branch.class === "introduce-the-vuln") {
          const want = filterString(vulnerableSnippetFor(upstream, site)).trim();
          if (shown !== want) {
            throw new BranchRefused(
              `${branch.name}: ${site.block} does not display upstream's vulnerable code.\n` +
                JSON.stringify(lineHunks(want, shown), null, 2),
            );
          }
          continue;
        }
        const want = filterString(
          applyAmendments(codefixes.get(branch.variant), amendmentsFor(site.block), site.block),
        ).trim();
        if (shown !== want) {
          throw new BranchRefused(
            `${branch.name}: ${site.block} does not display ${branch.variant}.\n` +
              JSON.stringify(lineHunks(want, shown), null, 2),
          );
        }
      }
    }

    // An introduce-the-vuln branch that cannot show upstream's own `vuln-line` text has not
    // introduced what the markers say the defect is. The only licensed exception is a block
    // caught up in a declared cross-block effect, where another item's fix has already rewritten
    // the line — so the exception is looked up in phase 4's table rather than listed again here.
    if (branch.class === "introduce-the-vuln") {
      const overlapped = OVERLAP_EFFECTS.some(
        (e) => item.sites.some((s) => s.block === e.block) || item.keys.includes(e.byKey),
      );
      const missing = branch.defectSites.filter((d) => !d.located);
      if (missing.length > 0 && !overlapped) {
        throw new BranchRefused(
          `${branch.name}: upstream marks ${missing.length} line(s) as this block's defect and ` +
            `the branch does not carry them.\n  ${missing.map((d) => JSON.stringify(d.text)).join("\n  ")}`,
        );
      }
    }

    // Stripping neither erases nor distorts the edit. The marked diff's lines, with their markers
    // taken off, must be the scored diff's lines: a stripper that dropped a spliced line would
    // otherwise show up only as a smaller diff, which nothing reads.
    const against = branch.base === "base" ? base : new Map(branchByName.get(branch.base).files.map((f) => [f.path, f.spliced]));
    for (const file of branch.files) {
      const baseline = against.get(file.path) ?? base.get(file.path);
      const markedHunks = lineHunks(baseline, file.spliced);
      const scoredHunks = lineHunks(stripMarkers(baseline).source, file.scored);
      if (scoredHunks.length === 0) {
        throw new BranchRefused(`${branch.name}: ${file.path} has an empty diff once stripped`);
      }
      const strip = (lines) =>
        lines
          .map((l) => {
            const m = parseMarker(l);
            return m == null ? l : l.slice(0, m.index).replace(/\s+$/, "");
          })
          .filter((l) => l.trim() !== "")
          .map((l) => l.trim())
          .sort();
      for (const side of ["insert", "remove"]) {
        const marked = strip(markedHunks.flatMap((h) => h[side]));
        const scored = strip(scoredHunks.flatMap((h) => h[side]));
        if (marked.join("\n") !== scored.join("\n")) {
          throw new BranchRefused(
            `${branch.name}: stripping ${file.path} changed what the branch ${side}s.\n` +
              `  marked: ${JSON.stringify(marked)}\n  scored: ${JSON.stringify(scored)}`,
          );
        }
      }
      if (file.splicedSha256 !== sha256(file.spliced) || file.scoredSha256 !== sha256(file.scored)) {
        throw new BranchRefused(`${branch.name}: ${file.path}'s recorded hashes do not match its contents`);
      }
    }
  }

  return {
    counts: { ...plan.counts },
    byClass: Object.fromEntries(CLASSES.map((c) => [c, plan.branches.filter((b) => b.class === c).length])),
    excluded: EXCLUDED_VARIANTS.map((e) => e.variant),
    itemsWithResidualKeys: plan.branches
      .filter((b) => b.expectation.exclude.residualKeys.length > 0)
      .map((b) => b.id)
      .sort(),
    branchesTouchingDefectLines: plan.branches
      .filter((b) => b.expectation.exclude.corpusDefectLines.some((d) => d.inThisDiff))
      .map((b) => b.id)
      .sort(),
    /** Marked defect lines a branch cannot show, because another item's fix rewrote them first. */
    unlocatedDefectSites: plan.branches
      .filter((b) => b.class === "introduce-the-vuln" && b.defectSites.some((d) => !d.located))
      .map((b) => ({ id: b.id, lines: b.defectSites.filter((d) => !d.located).map((d) => d.text) })),
  };
}

/**
 * The full scored tree for one branch: the stripped base with the branch's stripped files over it.
 *
 * Returned rather than written, for the reason `src/corpus.mjs` gives: phase 4 verifies against the
 * bytes the broker will fetch, and a function that could only produce a working copy would be
 * producing the wrong thing.
 *
 * @param {Map<string, string>} scoredBase the **stripped** base tree
 * @param {object} branch
 */
export function scoredTreeFor(scoredBase, branch) {
  const tree = new Map(scoredBase);
  for (const file of branch.files) {
    if (!tree.has(file.path)) {
      throw new BranchRefused(`${branch.name}: the scored base has no ${file.path} to place this branch's file over`);
    }
    tree.set(file.path, file.scored);
  }
  return tree;
}
