import { describe, expect, it } from "vitest";
import { extractSnippet, parseMarker, splitLines } from "../src/markers.mjs";
import { spliceVariant, spliceVariantChecked } from "../src/splice.mjs";
import { filterString } from "../src/rsn.mjs";
import {
  FIXED,
  HandRepairRefused,
  INNER_KEY,
  OUTER_KEY,
  UNFIXED,
  VARIANT_FILE,
  applyB13Correct,
} from "../src/b13-hand-repair.mjs";
import { codefix, haveCorpus, read, skipReason } from "./corpus.mjs";

const T = "vuln-code" + "-snippet";

const CHAT_TS = "routes/chat.ts";
const B14_VARIANT = "chatbotPromptInjectionChallenge_2_correct.ts";

/** The repaired line, as `chatbotGreedyInjectionChallenge_2_correct.ts` writes it. */
const CORRECT_VARIANT_LINE =
  "discount: z.number().max(10).describe('The discount percentage for the coupon (maximum 10)')";

/**
 * A `routes/chat.ts` in the state the repair expects: B14's correct variant already spliced in.
 *
 * Small enough to read, and carrying every anchor the repair checks — including the two wrapper
 * lines all four B13 variants drop, which is the thing the whole module exists to keep.
 */
const AFTER_B14 = [
  "import { z } from 'zod'",
  "",
  "const botName = config.get<string>('application.chatBot.name')",
  "",
  "export function chat () {",
  "  return async (req: Request, res: Response) => {",
  "    const chatTools = {",
  "      getOrderById: tool({",
  "        inputSchema: z.object({",
  "          orderId: z.string().describe('The order ID to get details for (format: xxxx-xxxxxxxxxxxxxxxx)')",
  "        })",
  "      }),",
  "",
  "      generateCoupon: tool({",
  "        description: 'Generate a discount coupon for a customer with a verified damaged order. Requires a valid order ID.',",
  "        inputSchema: z.object({",
  "          discount: z.number().describe('The discount percentage for the coupon (maximum 10)'),",
  "          orderId: z.string().describe('The order ID of the damaged order (format: xxxx-xxxxxxxxxxxxxxxx)')",
  "        }),",
  "        execute: async ({ discount, orderId, authenticatedUser }) => {",
  "          const couponCode = security.generateCoupon(discount)",
  "          return { couponCode, discount }",
  "        }",
  "      })",
  "    }",
  "  }",
  "}",
].join("\n");

/** The same file before B14's splice: upstream's generateCoupon, which the repair must refuse. */
const BEFORE_B14 = AFTER_B14.replace(
  "        description: 'Generate a discount coupon for a customer with a verified damaged order. Requires a valid order ID.',\n",
  "        description: 'Generate a discount coupon for a customer. Only use this when the coupon policy conditions are fully met.',\n",
)
  .replace("          orderId: z.string().describe('The order ID of the damaged order (format: xxxx-xxxxxxxxxxxxxxxx)')\n", "")
  .replace("discount: z.number().describe('The discount percentage for the coupon (maximum 10)'),", "discount: z.number().describe('The discount percentage for the coupon (maximum 10)')")
  .replace("execute: async ({ discount, orderId, authenticatedUser }) => {", "execute: async ({ discount }) => {");

const changedLines = (a, b) => {
  const x = a.split("\n");
  const y = b.split("\n");
  expect(y).toHaveLength(x.length);
  return x.map((l, i) => (l === y[i] ? null : i)).filter((i) => i !== null);
};

const bracketCounts = (text) =>
  ["{", "}", "(", ")", "[", "]"].map((ch) => text.split(ch).length - 1);

describe("applyB13Correct", () => {
  it("adds .max(10) to generateCoupon's discount schema and changes nothing else", () => {
    const { source, stats } = applyB13Correct(AFTER_B14);
    const changed = changedLines(AFTER_B14, source);
    expect(changed).toHaveLength(1);
    expect(stats.changedLines).toBe(1);
    expect(stats.fileLine).toBe(changed[0] + 1);
    expect(stats.before).toContain(UNFIXED);
    expect(stats.after).toContain(FIXED);
    expect(stats.key).toBe(OUTER_KEY);
    expect(stats.requires).toBe(INNER_KEY);
    expect(source.split("\n")[changed[0]].trim()).toBe(`${CORRECT_VARIANT_LINE},`);
  });

  it("keeps the repaired line's indentation and the file's line count", () => {
    const { source } = applyB13Correct(AFTER_B14);
    const i = changedLines(AFTER_B14, source)[0];
    const indentOf = (l) => l.slice(0, l.length - l.trimStart().length);
    expect(indentOf(source.split("\n")[i])).toBe(indentOf(AFTER_B14.split("\n")[i]));
    expect(indentOf(source.split("\n")[i])).toBe("          ");
  });

  it("adds exactly one parenthesis pair and no braces or brackets", () => {
    // The local structural check. `.max(10)` is one call and nothing else, so the deltas are known
    // ahead of time rather than merely balanced — a stronger statement than "it still parses".
    const { source } = applyB13Correct(AFTER_B14);
    expect(bracketCounts(source)).toEqual(
      bracketCounts(AFTER_B14).map((n, i) => n + (i === 2 || i === 3 ? 1 : 0)),
    );
  });

  it("is deterministic", () => {
    expect(applyB13Correct(AFTER_B14).source).toBe(applyB13Correct(AFTER_B14).source);
  });

  it("refuses a second application rather than silently doing nothing", () => {
    // Idempotent-or-refusing, and the choice is refusing: a silent no-op would make a
    // double-apply in a build indistinguishable from a correct single one, and this is the one
    // step of phase 4 with no round trip behind it.
    const { source } = applyB13Correct(AFTER_B14);
    expect(() => applyB13Correct(source)).toThrow(HandRepairRefused);
    expect(() => applyB13Correct(source)).toThrow(/already in the file/);
  });

  it("refuses when chatbotPromptInjectionChallenge has not been spliced yet, and names it", () => {
    // The precondition is a check, not a convention: B14's splice rewrites the very line this
    // repair changes, so repairing first and splicing second drops the fix and nothing errors.
    expect(() => applyB13Correct(BEFORE_B14)).toThrow(HandRepairRefused);
    expect(() => applyB13Correct(BEFORE_B14)).toThrow(new RegExp(`${INNER_KEY}'s correct variant has not been spliced yet`));
  });

  it("refuses a file that is not routes/chat.ts", () => {
    expect(() => applyB13Correct("const a = 1\n")).toThrow(HandRepairRefused);
    expect(() => applyB13Correct("const a = 1\n")).toThrow(/does not look like routes\/chat\.ts/);
    expect(() => applyB13Correct(null)).toThrow(HandRepairRefused);
  });

  it("refuses when the wrapper the four variants drop is already missing", () => {
    // A tree that has had a B13 variant written over it verbatim has no `export function chat () {`.
    // That is the failure this module exists to avoid, so it is refused rather than repaired.
    const noWrapper = AFTER_B14.replace("export function chat () {\n", "");
    expect(() => applyB13Correct(noWrapper)).toThrow(/export function chat/);
  });

  it("refuses when the discount line is not unique", () => {
    const doubled = AFTER_B14.replace(
      "          discount: z.number().describe('The discount percentage for the coupon (maximum 10)'),\n",
      "          discount: z.number().describe('The discount percentage for the coupon (maximum 10)'),\n".repeat(2),
    );
    expect(() => applyB13Correct(doubled)).toThrow(/found 2/);
  });

  it("refuses when the discount line it found is in some other tool", () => {
    const misplaced = AFTER_B14.replace(
      "          discount: z.number().describe('The discount percentage for the coupon (maximum 10)'),\n",
      "",
    ).replace(
      "          orderId: z.string().describe('The order ID to get details for (format: xxxx-xxxxxxxxxxxxxxxx)')",
      "          discount: z.number().describe('The discount percentage for the coupon (maximum 10)')",
    );
    expect(() => applyB13Correct(misplaced)).toThrow(/not generateCoupon/);
  });
});

describe.skipIf(!haveCorpus)(`conformance with the corpus (${skipReason})`, () => {
  const upstream = haveCorpus ? read(CHAT_TS) : "";
  const afterB14 = haveCorpus
    ? spliceVariantChecked(upstream, INNER_KEY, codefix(B14_VARIANT)).source
    : "";

  /**
   * The 12 lines of upstream `routes/chat.ts` that do not survive into the repaired tree, in
   * order. They are generateCoupon's body — B14's block, which is also B13's tail. Named in full
   * rather than matched, so a pin that moves one of them fails here instead of silently widening
   * what the repair is allowed to touch.
   */
  const UPSTREAM_LINES_REPLACED = [
    `        description: 'Generate a discount coupon for a customer. Only use this when the coupon policy conditions are fully met.', // ${T} neutral-line chatbotPromptInjectionChallenge chatbotGreedyInjectionChallenge`,
    "        inputSchema: z.object({",
    `          discount: z.number().describe('The discount percentage for the coupon (maximum 10)') // ${T} vuln-line chatbotPromptInjectionChallenge chatbotGreedyInjectionChallenge`,
    "        }),",
    "        execute: async ({ discount }) => {",
    `          challengeUtils.solveIf(challenges.chatbotPromptInjectionChallenge, () => discount >= 10) // ${T} hide-line`,
    `          challengeUtils.solveIf(challenges.chatbotGreedyInjectionChallenge, () => discount >= 50) // ${T} hide-line`,
    `          const couponCode = security.generateCoupon(discount) // ${T} vuln-line chatbotPromptInjectionChallenge`,
    `          return { couponCode, discount } // ${T} neutral-line chatbotPromptInjectionChallenge`,
    "        }",
    "      })",
    `    } // ${T} end chatbotGreedyInjectionChallenge chatbotPromptInjectionChallenge`,
  ];

  it("the fix is the one line that separates _2_correct from _1, _3 and _4", () => {
    // Upstream's own info.yml says why: fix 2 is correct "because it does not rely on the LLM
    // following instructions". The other three move prompt text around.
    const correct = codefix(VARIANT_FILE);
    const withMax = correct.split("\n").filter((l) => l.includes(".max(10)"));
    expect(withMax).toHaveLength(1);
    expect(withMax[0].trim()).toBe(CORRECT_VARIANT_LINE);
    for (const broken of [
      "chatbotGreedyInjectionChallenge_1.ts",
      "chatbotGreedyInjectionChallenge_3.ts",
      "chatbotGreedyInjectionChallenge_4.ts",
    ]) {
      expect(codefix(broken)).not.toContain(".max(10)");
    }
  });

  it("repairs the pinned routes/chat.ts, and the repaired line is the variant's own bytes", () => {
    const { source, stats } = applyB13Correct(afterB14);
    const changed = changedLines(afterB14, source);
    expect(changed).toHaveLength(1);
    expect(stats.fileLine).toBe(179);
    // B14's splice left a trailing comma on the line; the rest is `_2_correct`'s line verbatim.
    expect(stats.after.trim().replace(/,$/, "")).toBe(codefix(VARIANT_FILE).split("\n").find((l) => l.includes(".max(10)")).trim());
  });

  it("differs from the pinned file only where B14's splice did, plus the one repaired line", () => {
    // The line-level accounting. 262 of upstream's 274 split lines survive byte-identical and in
    // order — everything above generateCoupon's description and everything below the block's end
    // marker. The 12 that do not are named above. Every line that is new is either one B14's own
    // splice produced, or the single line this module owns.
    const { source } = applyB13Correct(afterB14);
    const u = upstream.split("\n");
    const r = source.split("\n");
    let prefix = 0;
    while (prefix < Math.min(u.length, r.length) && u[prefix] === r[prefix]) prefix++;
    let suffix = 0;
    while (suffix < Math.min(u.length, r.length) - prefix && u[u.length - 1 - suffix] === r[r.length - 1 - suffix]) suffix++;

    expect(u).toHaveLength(274);
    expect(prefix).toBe(176);
    expect(suffix).toBe(86);
    expect(prefix + suffix).toBe(262);
    expect(u.slice(prefix, u.length - suffix)).toEqual(UPSTREAM_LINES_REPLACED);

    const fromB14Splice = new Set(afterB14.split("\n"));
    const mine = new Set([applyB13Correct(afterB14).stats.after]);
    for (const line of r.slice(prefix, r.length - suffix)) {
      expect(fromB14Splice.has(line) || mine.has(line)).toBe(true);
    }
  });

  it("does not import the Number(Id) typo all four variants carry", () => {
    // Every chatbotGreedyInjectionChallenge variant writes `Number(Id)` where upstream writes
    // `Number(id)`, and `Id` is bound nowhere in routes/chat.ts. Splicing a variant verbatim would
    // put a reference error into the base tree. Neither the README nor the phase-3 note records
    // this; the assertion is here so a future hand repair that widened its reach would fail.
    for (const name of [
      "chatbotGreedyInjectionChallenge_1.ts",
      VARIANT_FILE,
      "chatbotGreedyInjectionChallenge_3.ts",
      "chatbotGreedyInjectionChallenge_4.ts",
    ]) {
      expect(codefix(name)).toContain("const productId = Number(Id)");
    }
    const { source } = applyB13Correct(afterB14);
    expect(source).toContain("const productId = Number(id)");
    expect(source).not.toContain("Number(Id)");
  });

  it("leaves the live code the four variants drop", () => {
    const { source } = applyB13Correct(afterB14);
    for (const live of [
      "export function chat () {",
      "  return async (req: Request, res: Response) => {",
      "  const userIdentifier = userName ? `\\nThe customer you are currently chatting with is ${userName}.` : ''",
      `          challengeUtils.solveIf(challenges.chatbotPromptInjectionChallenge, () => discount >= 10) // ${T} hide-line`,
      `          challengeUtils.solveIf(challenges.chatbotGreedyInjectionChallenge, () => discount >= 50) // ${T} hide-line`,
    ]) {
      expect(source.split("\n")).toContain(live);
    }
  });

  it("keeps the pinned file's bracket balance", () => {
    const { source } = applyB13Correct(afterB14);
    const [ob, cb, op, cp, obr, cbr] = bracketCounts(source);
    expect(ob).toBe(cb);
    expect(op).toBe(cp);
    expect(obr).toBe(cbr);
  });

  it("refuses the pinned routes/chat.ts, because B14 has not been spliced into it", () => {
    expect(() => applyB13Correct(upstream)).toThrow(HandRepairRefused);
  });

  it("composes only in the order B14 then B13 — the other order loses the fix", () => {
    // The whole reason the precondition is checked. `discount: z.number()...` is marked
    // `vuln-line` for both keys, so it belongs to both blocks; B14's correct variant rewrites it
    // and does not add `.max(10)`.
    const b13First = upstream.replace(UNFIXED, FIXED);
    expect(b13First).toContain(FIXED);
    const thenB14 = spliceVariantChecked(b13First, INNER_KEY, codefix(B14_VARIANT)).source;
    expect(thenB14).not.toContain(FIXED);

    const b14First = applyB13Correct(afterB14).source;
    expect(b14First).toContain(FIXED);
    expect(b14First).toContain("status: OrderStatus.DAMAGED");
  });

  it("leaves B14's block displaying B14's variant, plus the one line the repair added", () => {
    // The composition proof, through the repo's own extractor: after the repair, re-displaying
    // the inner block gives back exactly what B14's splice round-tripped to, with `.max(10)` on
    // the line the two blocks share. Neither fix has undone the other.
    const { source } = applyB13Correct(afterB14);
    const shown = filterString(extractSnippet(source, INNER_KEY).snippet).trim();
    expect(shown).toBe(filterString(codefix(B14_VARIANT)).trim().replace(UNFIXED, FIXED));
  });
  /**
   * What re-cutting a B13 variant would take, measured rather than guessed — the open question
   * phase 6 inherits, since it must generate broken-fix branches from `_1`, `_3` and `_4`, which
   * have the same wrapper problem.
   *
   * Three mechanical steps turn a variant back into an edit of its snippet: put the two wrapper
   * lines back, indent everything from `const chatTools = {` down by four, and undo the
   * `Number(Id)` typo. Nothing here is a judgement call.
   */
  function recut(variantText) {
    const lines = variantText.split("\n");
    const at = lines.indexOf("const chatTools = {");
    expect(at).toBeGreaterThan(0);
    return [
      ...lines.slice(0, at),
      "export function chat () {",
      "  return async (req: Request, res: Response) => {",
      ...lines.slice(at).map((l) => (l === "" ? l : "    " + l)),
    ]
      .join("\n")
      .replace("Number(Id)", "Number(id)");
  }

  /** `routes/chat.ts` with B14's `start` marker lifted out, which is what spliceNestedBlock does. */
  function markerLifted() {
    const { lines, eol } = splitLines(upstream);
    const i = lines.findIndex((l) => {
      const m = parseMarker(l);
      return m?.type === "start" && m.keys.includes(INNER_KEY);
    });
    expect(i).toBeGreaterThan(0);
    return [...lines.slice(0, i), ...lines.slice(i + 1)].join(eol);
  }

  it("makes the same edit a re-cut variant would have spliced", () => {
    // The independent check on the hand repair: re-cut `_2_correct` and let the splicer place it.
    // It round-trips, it touches one line, and that line is the same substitution this module
    // makes. The hand repair is therefore not a judgement about what the fix is — the splicer
    // agrees, once the variant is an edit of its own snippet.
    const variant = recut(codefix(VARIANT_FILE));
    const lifted = markerLifted();
    const { source, stats } = spliceVariant(lifted, OUTER_KEY, variant);
    expect(extractSnippet(source, OUTER_KEY).snippet.trim()).toBe(variant.trim());
    expect({ kept: stats.kept, dropped: stats.dropped, added: stats.added }).toEqual({
      kept: 103,
      dropped: 1,
      added: 1,
    });

    // One snippet line dropped, one added, and they are the two sides of this module's
    // substitution. `spliceVariant` is used directly on the marker-lifted tree rather than
    // `spliceNestedBlock`, because re-attaching B14's marker re-creates the glued line and the
    // round trip can then never match a re-cut variant — see the report for phase 6.
    expect(source).toContain(FIXED);
    expect(source).not.toContain(`${UNFIXED}'The discount percentage`);
    const droppedLine = lifted.split("\n").find((l) => l.includes(`${UNFIXED}'The discount percentage`));
    const addedLine = source.split("\n").find((l) => l.includes(FIXED));
    expect(droppedLine.trim().split(" //")[0]).toBe(`${CORRECT_VARIANT_LINE.replace(".max(10)", "")}`);
    expect(addedLine.trim()).toBe(CORRECT_VARIANT_LINE);
  });

  it("re-cutting is mechanical for all four variants, which is phase 6's answer", () => {
    // All four round-trip once re-cut, so phase 6's broken-fix branches do not need a hand repair
    // each. What they do need is a decision this module cannot make: `_1`, `_3` and `_4` each drop
    // `export` from `buildSystemPrompt`, which `routes/verify.ts` imports, and `_1` also drops its
    // `userName` parameter, which `routes/chat.ts` passes. Spliced verbatim they break other files.
    const lifted = markerLifted();
    for (const name of [
      "chatbotGreedyInjectionChallenge_1.ts",
      VARIANT_FILE,
      "chatbotGreedyInjectionChallenge_3.ts",
      "chatbotGreedyInjectionChallenge_4.ts",
    ]) {
      const variant = recut(codefix(name));
      const { source } = spliceVariant(lifted, OUTER_KEY, variant);
      expect(extractSnippet(source, OUTER_KEY).snippet.trim()).toBe(variant.trim());
    }
    for (const name of [
      "chatbotGreedyInjectionChallenge_1.ts",
      "chatbotGreedyInjectionChallenge_3.ts",
      "chatbotGreedyInjectionChallenge_4.ts",
    ]) {
      expect(codefix(name)).not.toContain("export function buildSystemPrompt");
    }
    expect(codefix(VARIANT_FILE)).toContain("export function buildSystemPrompt (userName?: string) {");
    expect(codefix("chatbotGreedyInjectionChallenge_1.ts")).toContain("function buildSystemPrompt () {");
    expect(read("routes/verify.ts")).toContain("import { buildSystemPrompt } from './chat'");
  });
});
