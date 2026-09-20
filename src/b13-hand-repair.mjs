/**
 * B13's hand repair — the one correct fix in the corpus that the splicer cannot apply.
 *
 * ## Why a hand repair exists at all
 *
 * The repaired base tree is upstream Juice Shop with every challenge key's `_N_correct` codefix
 * variant spliced in. 34 of the 35 keys splice mechanically and are proved by round trip.
 * `chatbotGreedyInjectionChallenge` — block B13, `routes/chat.ts` 81–188 — does not: its four
 * variants are not edits of the block's displayed snippet at all. They drop the wrapper (two
 * lines: `export function chat () {` and the `return async (req, res) => {` below it) and dedent
 * the tool object by four spaces. `spliceVariantChecked` throws `SpliceRefused` for all four on
 * purpose, because splicing one would delete a live function declaration from the tree.
 *
 * So B13's correct fix is applied here instead, as the smallest edit that carries it.
 *
 * ## What the fix is, measured rather than assumed
 *
 * `chatbotGreedyInjectionChallenge_2_correct.ts` differs from `_1`, `_3` and `_4` in exactly one
 * line of code, and it is the same line in all three diffs:
 *
 * ```
 * -      discount: z.number().describe('The discount percentage for the coupon (maximum 10)')
 * +      discount: z.number().max(10).describe('The discount percentage for the coupon (maximum 10)')
 * ```
 *
 * The other three "fix" the greedy-injection defect in the system prompt or the tool description —
 * prompt-side text the model is free to ignore — and upstream's own `info.yml` says so: fix 2 is
 * correct "because it does not rely on the LLM following instructions". `.max(10)` is server-side
 * schema enforcement, and it is the whole of the security fix. Everything else that separates
 * `_2_correct` from the pinned file is an artifact of how upstream cut the variant:
 *
 * | Difference from upstream's B13 snippet (after dedenting 4) | Kind |
 * |---|---|
 * | drops `export function chat () {` and `  return async (req: Request, res: Response) => {` | cut artifact — **not applied** |
 * | `const productId = Number(id)` becomes `Number(Id)` | **a defect the variant introduces** — not applied |
 * | `       generateCoupon: tool({` loses the nested-marker residue indentation | cut artifact — not applied |
 * | `z.number()` becomes `z.number().max(10)` | **the fix** — applied |
 *
 * The `Number(Id)` capital is in all four variants, and `Id` is bound nowhere in `routes/chat.ts`.
 * Applying the variant verbatim would put a reference error into the base tree that upstream never
 * ships. Neither the README nor the phase-3 design note records it; it is recorded here because a
 * hand repair that quietly imported it would be indistinguishable from one that did not.
 *
 * ## Ordering: this runs AFTER B14's splice, and the precondition is checked
 *
 * `chatbotPromptInjectionChallenge` — B14, 175–188 — lies **inside** B13, and its correct variant
 * does splice mechanically. The two overlap on the line this repair changes: upstream marks
 * `discount: z.number()...` `vuln-line` for *both* keys, and B14's splice rewrites it (adding a
 * trailing comma, dropping the marker suffix) without adding `.max(10)`.
 *
 * So the order is forced and it is not symmetric:
 *
 * - **B13 then B14** — the splice overwrites the repaired line and the fix is silently gone. The
 *   tree parses, and nothing reports it.
 * - **B14 then B13** — the repair lands on the line B14 produced, and both fixes stand.
 *
 * This function therefore **requires B14's correct variant to be applied already**, and refuses
 * with a message naming the key when it is not. It is a check, not a convention, because the
 * failure it guards is invisible in the output.
 *
 * The repair itself is marker-independent: it anchors on code, not on `vuln-code-snippet`
 * comments, so it runs equally before or after the strip. In practice the order is splice B14 →
 * repair B13 → strip, because splicing needs the markers.
 *
 * ## Idempotence: it refuses, it is not idempotent
 *
 * Applying twice throws `HandRepairRefused`. A silent second no-op would make a double-apply in a
 * build pipeline indistinguishable from a correct single one, and this is the one step of phase 4
 * with no round trip behind it. Applying once to the same input is deterministic: the transform is
 * a single literal substring replacement on a single located line, with no ordering, hashing or
 * clock in it.
 */
import { splitLines } from "./markers.mjs";

export class HandRepairRefused extends Error {
  constructor(message) {
    super(message);
    this.name = "HandRepairRefused";
  }
}

/** The block this repair fixes. */
export const OUTER_KEY = "chatbotGreedyInjectionChallenge";
/** The block nested inside it, whose splice must have run first. */
export const INNER_KEY = "chatbotPromptInjectionChallenge";
/** The variant whose security fix this reproduces. */
export const VARIANT_FILE = "chatbotGreedyInjectionChallenge_2_correct.ts";

/**
 * Whole lines that must be present for this to be the `routes/chat.ts` the repair was written
 * against. None of them carries a marker, so the check survives the strip.
 *
 * The first two are the wrapper all four variants drop. Requiring them is the point: if they are
 * missing, something has already applied a variant verbatim and the tree is wrong in the way this
 * module exists to avoid.
 */
const CHAT_ANCHORS = Object.freeze([
  "const botName = config.get<string>('application.chatBot.name')",
  "export function chat () {",
  "  return async (req: Request, res: Response) => {",
  "    const chatTools = {",
  "      generateCoupon: tool({",
]);

/**
 * Whole lines that only `chatbotPromptInjectionChallenge_2_correct.ts`, spliced, puts in the file.
 * Their presence is the precondition; their absence is the refusal.
 */
const B14_APPLIED_ANCHORS = Object.freeze([
  "          orderId: z.string().describe('The order ID of the damaged order (format: xxxx-xxxxxxxxxxxxxxxx)')",
  "        execute: async ({ discount, orderId, authenticatedUser }) => {",
]);

/**
 * The `generateCoupon` description upstream ships, marker suffix excluded. Present means B14's
 * block is still upstream's (or carries one of B14's three broken variants), which this refuses.
 */
const UPSTREAM_B14_DESCRIPTION =
  "'Generate a discount coupon for a customer. Only use this when the coupon policy conditions are fully met.'";

/** The defect, and the fix, as the literal bytes `_2_correct` uses. */
export const UNFIXED = "z.number().describe(";
export const FIXED = "z.number().max(10).describe(";

/** The one line the repair changes. Indentation is captured so it can be asserted unchanged. */
const TARGET_RE = /^(?<indent> *)discount: z\.number\(\)\.describe\(/;

/** A tool entry's opening line, used to prove the target sits in `generateCoupon` and nowhere else. */
const TOOL_OPENER_RE = /^\s*(?<name>[A-Za-z_$][\w$]*): tool\(\{/;

/**
 * Apply `chatbotGreedyInjectionChallenge_2_correct.ts`'s security fix to `routes/chat.ts`.
 *
 * **Precondition, enforced below:** `source` is `routes/chat.ts` at the pin with
 * `chatbotPromptInjectionChallenge_2_correct.ts` already spliced in. Markers may be present or
 * stripped; both work.
 *
 * @param {string} source whole contents of `routes/chat.ts`
 * @returns {{source: string, stats: {key: string, variant: string, requires: string,
 *   changedLines: number, fileLine: number, before: string, after: string}}}
 * @throws {HandRepairRefused} when the input is not that file, when B14 has not been applied,
 *   when the fix is already present, or when the line it changes is not uniquely located.
 */
export function applyB13Correct(source) {
  if (typeof source !== "string") {
    throw new HandRepairRefused(
      `${OUTER_KEY}: expected the contents of routes/chat.ts as a string, got ${typeof source}.`,
    );
  }

  const { lines, eol } = splitLines(source);

  for (const anchor of CHAT_ANCHORS) {
    if (!lines.includes(anchor)) {
      throw new HandRepairRefused(
        `${OUTER_KEY}: this does not look like routes/chat.ts at the pin — no line is exactly ` +
          `${JSON.stringify(anchor)}. This repair is written against one file and will not guess.`,
      );
    }
  }

  if (lines.some((l) => l.includes(UPSTREAM_B14_DESCRIPTION))) {
    throw new HandRepairRefused(
      `${OUTER_KEY}: ${INNER_KEY}'s correct variant has not been spliced yet — the file still ` +
        `carries upstream's generateCoupon description. B14 (175–188) lies inside B13 (81–188) ` +
        `and its splice rewrites the very line this repair changes, so repairing first and ` +
        `splicing second drops the fix without producing an error. Splice ${INNER_KEY} first.`,
    );
  }

  for (const anchor of B14_APPLIED_ANCHORS) {
    if (!lines.includes(anchor)) {
      throw new HandRepairRefused(
        `${OUTER_KEY}: cannot confirm ${INNER_KEY}'s correct variant is applied — no line is ` +
          `exactly ${JSON.stringify(anchor)}. Splice ${INNER_KEY} first; this repair edits a ` +
          `line inside its block and must run after it.`,
      );
    }
  }

  if (source.includes(FIXED)) {
    throw new HandRepairRefused(
      `${OUTER_KEY}: the fix ${JSON.stringify(FIXED)} is already in the file. This repair ` +
        `refuses a second application rather than being a silent no-op, so that a double-apply ` +
        `in a build is visible.`,
    );
  }

  const hits = [];
  for (let i = 0; i < lines.length; i++) if (TARGET_RE.test(lines[i])) hits.push(i);
  if (hits.length !== 1) {
    throw new HandRepairRefused(
      `${OUTER_KEY}: expected exactly one ${JSON.stringify(UNFIXED)} discount line to repair, ` +
        `found ${hits.length}${hits.length ? ` (lines ${hits.map((i) => i + 1).join(", ")})` : ""}. ` +
        `The fix is one line and it has to be unambiguous.`,
    );
  }

  const index = hits[0];
  const owner = enclosingTool(lines, index);
  if (owner !== "generateCoupon") {
    throw new HandRepairRefused(
      `${OUTER_KEY}: the discount line on ${index + 1} sits in ${owner ?? "no tool entry"}, not ` +
        `generateCoupon. The fix belongs to generateCoupon's input schema.`,
    );
  }

  const before = lines[index];
  const after = before.replace(UNFIXED, FIXED);
  if (after === before) {
    throw new HandRepairRefused(`${OUTER_KEY}: located line ${index + 1} but replacing in it was a no-op.`);
  }

  const out = [...lines];
  out[index] = after;
  const repaired = out.join(eol);
  assertStructure(source, repaired, before, after);

  return {
    source: repaired,
    stats: {
      key: OUTER_KEY,
      variant: VARIANT_FILE,
      requires: INNER_KEY,
      changedLines: 1,
      fileLine: index + 1,
      before,
      after,
    },
  };
}

/** The name of the `<name>: tool({` entry the line at `index` sits in, or null. */
function enclosingTool(lines, index) {
  for (let i = index - 1; i >= 0; i--) {
    const m = TOOL_OPENER_RE.exec(lines[i]);
    if (m?.groups) return m.groups.name;
  }
  return null;
}

/**
 * The local structural check this module owes.
 *
 * A real parse gate lives elsewhere; this is the cheap invariant that catches the shapes a
 * one-line text edit can actually break. `.max(10)` adds exactly one parenthesis pair and nothing
 * else, so bracket deltas are known ahead of time rather than merely "balanced". Absolute balance
 * is asserted only where the input already had it, so a caller handing in a file with an
 * unbalanced brace inside a string literal gets the delta check rather than a spurious refusal.
 */
function assertStructure(before, after, beforeLine, afterLine) {
  const PAIRS = [
    ["{", "}", 0],
    ["(", ")", 1],
    ["[", "]", 0],
  ];
  const count = (text, ch) => text.split(ch).length - 1;

  for (const [open, close, want] of PAIRS) {
    const dOpen = count(after, open) - count(before, open);
    const dClose = count(after, close) - count(before, close);
    if (dOpen !== want || dClose !== want) {
      throw new HandRepairRefused(
        `${OUTER_KEY}: the repair changed the ${open}${close} count by ${dOpen}/${dClose}, ` +
          `expected ${want}/${want}. The edit is ${JSON.stringify(FIXED)} and nothing else.`,
      );
    }
    if (count(before, open) === count(before, close) && count(after, open) !== count(after, close)) {
      throw new HandRepairRefused(`${OUTER_KEY}: the repair unbalanced ${open}${close}.`);
    }
  }

  if (splitLines(after).lines.length !== splitLines(before).lines.length) {
    throw new HandRepairRefused(`${OUTER_KEY}: the repair changed the file's line count.`);
  }

  const indent = (l) => l.slice(0, l.length - l.trimStart().length);
  if (indent(afterLine) !== indent(beforeLine)) {
    throw new HandRepairRefused(`${OUTER_KEY}: the repair changed the repaired line's indentation.`);
  }
  if (/^\s*$/.test(indent(afterLine)) === false) {
    throw new HandRepairRefused(`${OUTER_KEY}: the repaired line's indentation is not whitespace.`);
  }
  if (indent(afterLine).includes("\t")) {
    throw new HandRepairRefused(`${OUTER_KEY}: the repaired line is tab-indented; chat.ts is spaces.`);
  }
}
