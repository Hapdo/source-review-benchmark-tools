import { describe, expect, it } from "vitest";
import { extractSnippet, findBlocks, parseMarker, splitLines } from "../src/markers.mjs";
import { spliceVariantChecked } from "../src/splice.mjs";
import { filterString } from "../src/rsn.mjs";
import {
  BASE_TREE_DEFECTS,
  BaseTreeRefused,
  CONFLICT_RULINGS,
  CompositionRefused,
  HAND_REPAIRED_KEYS,
  OVERLAP_EFFECTS,
  addressKeyFor,
  buildBaseTree,
  composeSnippet,
  lineHunks,
  planSteps,
  unboundSymbolsIntroduced,
  verifyBaseTree,
} from "../src/base-tree.mjs";
import { readCodefixes, readTree } from "../src/corpus.mjs";
import { codefix, corpusDir, haveCorpus, read, skipReason, variantNames } from "./corpus.mjs";

/**
 * The corpus, built once. Top-level `await` rather than a `beforeAll`, so that the conformance
 * block below can be plain synchronous `it`s over a finished build — the build is the fixture, not
 * the thing under test in most of them.
 */
const tree = haveCorpus ? readTree(corpusDir) : new Map();
const codefixes = haveCorpus ? readCodefixes(corpusDir) : new Map();
const built = haveCorpus ? await buildBaseTree(tree, codefixes, { sha: null }) : null;
const report = haveCorpus ? verifyBaseTree({ upstream: tree, built: built.tree, codefixes }) : null;

const T = "vuln-code" + "-snippet";

/** A two-key block, so the merge has something to merge. */
const TWO_KEYS = [
  "before",
  `// ${T} start alphaChallenge betaChallenge`,
  "  const a = 1",
  "  const b = 2",
  "  const c = 3",
  `// ${T} end alphaChallenge betaChallenge`,
  "after",
].join("\n");

const snippetOf = (source, key) => extractSnippet(source, key).snippet;
const variant = (key, file, text) => ({ key, file, text });

describe("lineHunks", () => {
  it("makes a removal and the addition after it one hunk, so contention is a range test", () => {
    const hunks = lineHunks("a\nb\nc\n", "a\nB\nc\n");
    expect(hunks).toHaveLength(1);
    expect(hunks[0]).toMatchObject({ start: 1, end: 2, insert: ["B"] });
  });

  it("gives an insertion a zero-width range, so it can sit against a replacement", () => {
    const hunks = lineHunks("a\nc\n", "a\nb\nc\n");
    expect(hunks).toHaveLength(1);
    expect(hunks[0].start).toBe(hunks[0].end);
  });
});

describe("composeSnippet", () => {
  it("keeps both keys' fixes when they edit different lines", () => {
    const snippet = snippetOf(TWO_KEYS, "alphaChallenge");
    const composed = composeSnippet(
      snippet,
      [
        variant("alphaChallenge", "alphaChallenge_1_correct.ts", snippet.replace("const a = 1", "const a = FIXED")),
        variant("betaChallenge", "betaChallenge_1_correct.ts", snippet.replace("const c = 3", "const c = ALSO_FIXED")),
      ],
      { file: "fixture.ts" },
    );
    expect(composed.snippet).toContain("const a = FIXED");
    expect(composed.snippet).toContain("const c = ALSO_FIXED");
    expect(composed.snippet).toContain("const b = 2");
  });

  it("counts two keys' identical edits as one, not two", () => {
    const snippet = snippetOf(TWO_KEYS, "alphaChallenge");
    const same = snippet.replace("const b = 2", "const b = SHARED");
    const composed = composeSnippet(
      snippet,
      [
        variant("alphaChallenge", "alphaChallenge_1_correct.ts", same),
        variant("betaChallenge", "betaChallenge_1_correct.ts", same),
      ],
      { file: "fixture.ts" },
    );
    expect(composed.applied).toHaveLength(1);
    expect(composed.applied[0].keys).toEqual(["alphaChallenge", "betaChallenge"]);
    expect(composed.snippet.split("SHARED")).toHaveLength(2);
  });

  it("refuses two keys that edit one line differently, and names both", () => {
    // The failure this exists to stop: applying one and dropping the other produces a tree that
    // parses, and is unrepaired for whichever key lost.
    const snippet = snippetOf(TWO_KEYS, "alphaChallenge");
    let thrown;
    try {
      composeSnippet(
        snippet,
        [
          variant("alphaChallenge", "alphaChallenge_1_correct.ts", snippet.replace("const b = 2", "const b = ONE")),
          variant("betaChallenge", "betaChallenge_1_correct.ts", snippet.replace("const b = 2", "const b = TWO")),
        ],
        { file: "fixture.ts" },
      );
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(CompositionRefused);
    expect(thrown.message).toContain("alphaChallenge");
    expect(thrown.message).toContain("betaChallenge");
    expect(thrown.message).toContain("CONFLICT_RULINGS");
  });

  it("refuses a ruling whose pinned bytes are no longer the ones being replaced", () => {
    // A stale ruling is worse than none: it reads as though the disagreement had been considered.
    const ruling = CONFLICT_RULINGS[0];
    const source = [
      `// ${T} start ${ruling.keys.join(" ")}`,
      "  const untouched = 1",
      `// ${T} end ${ruling.keys.join(" ")}`,
    ].join("\n");
    const snippet = snippetOf(source, ruling.keys[0]);
    expect(() =>
      composeSnippet(
        snippet,
        ruling.keys.map((k, i) => variant(k, `${k}_1_correct.ts`, snippet.replace("1", String(i + 2)))),
        { file: ruling.file },
      ),
    ).toThrow(CompositionRefused);
  });
});

describe("addressKeyFor", () => {
  it("HD-81: addresses a block by the first key its start marker names", () => {
    const block = findBlocks(TWO_KEYS)[0];
    expect(addressKeyFor(TWO_KEYS, block)).toBe("alphaChallenge");
  });

  it("HD-81: splices a multi-key block to the same bytes whichever key addresses it", () => {
    // Phase 4 anchored on the last key because any other one left a bare line of key names after
    // the end marker. With the splicer fixed, the key is a name for the block and nothing more.
    const variant = (key) => snippetOf(TWO_KEYS, key).replace("const b = 2", "const b = FIXED");
    const onFirst = spliceVariantChecked(TWO_KEYS, "alphaChallenge", variant("alphaChallenge"));
    const onLast = spliceVariantChecked(TWO_KEYS, "betaChallenge", variant("betaChallenge"));
    expect(onFirst.source).toBe(onLast.source);
    expect(splitLines(onFirst.source).lines.some((l) => l.trim() === "betaChallenge")).toBe(false);
  });

  it("refuses a key whose boundary match lands on a different block", () => {
    // Upstream matches a key as a substring of the first start marker containing it.
    const source = [
      `// ${T} start fooBarChallenge`,
      "  const a = 1",
      `// ${T} end fooBarChallenge`,
      `// ${T} start barChallenge`,
      "  const b = 1",
      `// ${T} end barChallenge fooBarChallenge`,
    ].join("\n");
    const block = { start: 4, end: 6, keys: ["Bar"] };
    expect(() => addressKeyFor(source, block)).toThrow(BaseTreeRefused);
  });
});

describe("planSteps", () => {
  const NESTED_FILE = [
    `// ${T} start outerChallenge`,
    "  const head = 1",
    `  // ${T} start innerChallenge`,
    "  const inner = 2",
    `  // ${T} end outerChallenge innerChallenge`,
  ].join("\n");

  const fixes = new Map([
    ["outerChallenge_1_correct.ts", "  const head = 1"],
    ["innerChallenge_1_correct.ts", "  const inner = 2"],
  ]);

  it("splices a contained block before the block that contains it", () => {
    // Order is the whole of the B13/B14 problem: the inner block's splice rewrites a line the
    // outer block's fix also changes, and running the outer one second puts upstream's line back.
    const steps = planSteps(new Map([["nested.ts", NESTED_FILE]]), fixes);
    expect(steps.map((s) => s.keys[0])).toEqual(["innerChallenge", "outerChallenge"]);
  });

  it("refuses a key with two correct variants rather than choosing one", () => {
    const two = new Map([...fixes, ["outerChallenge_2_correct.ts", "  const head = 1"]]);
    expect(() => planSteps(new Map([["nested.ts", NESTED_FILE]]), two)).toThrow(BaseTreeRefused);
  });
});

describe("buildBaseTree", () => {
  const stubHandRepair = () => {
    throw new Error("the fixture has no hand-repaired block, so this must not be called");
  };

  it("refuses when one block's splice would silently revert another's", () => {
    // Two blocks sharing lines, spliced in an order where the second reverts the first. Nothing
    // about the output says so — it parses, and each block round-trips to something.
    const file = [
      `// ${T} start earlyChallenge`,
      "  const head = 0",
      `  // ${T} start lateChallenge`,
      "  const glued = 1",
      "  const shared = 'vulnerable'",
      `// ${T} end earlyChallenge`,
      "  const more = 2",
      `// ${T} end lateChallenge`,
    ].join("\n");
    const fixes = new Map([
      ["earlyChallenge_1_correct.ts", snippetOf(file, "earlyChallenge").replace("'vulnerable'", "'safe'")],
      ["lateChallenge_1_correct.ts", snippetOf(file, "lateChallenge")],
    ]);
    return expect(
      buildBaseTree(new Map([["overlap.ts", file]]), fixes, { applyB13Correct: stubHandRepair }),
    ).rejects.toThrow(BaseTreeRefused);
  });

  it("changes only the files that hold a block", async () => {
    const tree = new Map([
      ["with-block.ts", TWO_KEYS],
      ["without-block.ts", "const untouched = true\n"],
    ]);
    const snippet = snippetOf(TWO_KEYS, "betaChallenge");
    const fixes = new Map([
      ["alphaChallenge_1_correct.ts", snippet.replace("const a = 1", "const a = FIXED")],
      ["betaChallenge_1_correct.ts", snippet.replace("const c = 3", "const c = ALSO")],
    ]);
    const built = await buildBaseTree(tree, fixes, { applyB13Correct: stubHandRepair });
    expect(built.changed).toEqual(["with-block.ts"]);
    expect(built.tree.get("without-block.ts")).toBe(tree.get("without-block.ts"));
    expect(built.tree.get("with-block.ts")).toContain("const a = FIXED");
    expect(built.tree.get("with-block.ts")).toContain("const c = ALSO");
  });
});

describe.skipIf(!haveCorpus)(`conformance with the corpus (${skipReason})`, () => {
  it("accounts for all 35 keys, and names the ones that were not spliced", () => {
    expect(report.counts).toMatchObject({ keys: 35, blocks: 23, changedFiles: 16 });
    expect(report.counts.spliced + report.counts.ruled + report.counts.handRepaired).toBe(35);
    // The two exception lists, by name. A count alone would let a thirty-sixth exception hide.
    expect(report.handRepaired).toEqual(["chatbotGreedyInjectionChallenge"]);
    expect(report.ruled).toEqual(["loginBenderChallenge"]);
  });

  it("leaves every file that holds no block byte-identical to upstream", () => {
    const withBlocks = new Set(planSteps(tree, codefixes).map((s) => s.file));
    expect(new Set(built.changed)).toEqual(withBlocks);
    for (const [path, contents] of built.tree) {
      if (withBlocks.has(path)) continue;
      expect(contents).toBe(tree.get(path));
    }
  });

  it("builds the same bytes twice", async () => {
    // "Pinned by SHA and rebuilt deliberately, never regenerated silently" is only checkable if a
    // rebuild is comparable. The manifest carries no clock and no path for exactly this reason.
    const again = await buildBaseTree(readTree(corpusDir), readCodefixes(corpusDir), { sha: null });
    expect(again.changed).toEqual(built.changed);
    for (const path of again.changed) expect(again.tree.get(path)).toBe(built.tree.get(path));
    expect(JSON.stringify(again.manifest)).toBe(JSON.stringify(built.manifest));
  });

  it("round-trips every block: what the tree displays is what was composed", () => {
    // `verifyBaseTree` asserts this block by block and throws naming the block that failed. The
    // honest form for a block with more than one key is equality with the *composition*, since the
    // composed snippet equals no single variant.
    expect(() => verifyBaseTree({ upstream: tree, built: built.tree, codefixes })).not.toThrow();
    expect(report.blocks).toHaveLength(23);
  });

  it("gives back each key's own correct variant where the block has one key", () => {
    // Where composition is a no-op, the assertion collapses to the splicer's own round trip — so
    // the general form is checked against the specific one rather than replacing it.
    const single = planSteps(tree, codefixes).filter((s) => s.keys.length === 1 && s.mode === "splice");
    expect(single.length).toBeGreaterThan(10);
    for (const step of single) {
      const displayed = extractSnippet(built.tree.get(step.file), step.anchor).snippet;
      const amended = OVERLAP_EFFECTS.some((e) => e.block === step.id);
      if (amended) continue;
      expect(filterString(displayed).trim()).toBe(filterString(step.variants[0].text).trim());
    }
  });

  it("repairs both mirrored networking.tf files, not just the one upstream serves", () => {
    // Phase 5 scores `iacLeakedKeyChallenge` once, at B10. Repairing only B10 would leave B23
    // vulnerable and every branch cut from this tree would inherit it.
    expect(report.mirrors).toEqual(["infrastructure/terraform/networking.tf", "terraform/networking.tf"]);
    const [a, b] = report.mirrors;
    expect(tree.get(a)).toBe(tree.get(b));
    expect(built.tree.get(a)).toBe(built.tree.get(b));
    expect(built.tree.get(a)).not.toBe(tree.get(a));
  });

  it("finds the five securityQuestions variants byte-identical, so the merge is not a choice", () => {
    // The design expected five near-identical texts differing at each key's own vuln line. They
    // are the same four-line comment, and each replaces the whole 28-line snippet.
    const correct = variantNames().filter((n) => /^resetPassword(?!Morty).*_correct\.yml$/.test(n));
    expect(correct).toHaveLength(5);
    expect(new Set(correct.map(codefix)).size).toBe(1);
    const displayed = extractSnippet(built.tree.get("data/static/securityQuestions.yml"), "resetPasswordUvoginChallenge").snippet;
    expect(filterString(displayed).trim()).toBe(filterString(codefix(correct[0])).trim());
  });

  it("finds exactly one block whose keys disagree, and it is the one the ruling names", () => {
    // The separation rather than the list: every other multi-key block composes without a ruling.
    const conflicted = [];
    for (const step of planSteps(tree, codefixes)) {
      if (step.mode !== "splice" || step.keys.length < 2) continue;
      const snippet = extractSnippet(tree.get(step.file), step.anchor).snippet;
      const unruled = step.variants.map((v) => ({ ...v }));
      try {
        composeSnippet(snippet, unruled, { file: `${step.file}#unruled` });
      } catch {
        conflicted.push(step.file);
      }
    }
    expect(conflicted).toEqual(CONFLICT_RULINGS.map((r) => r.file));
  });

  it("finds the ruled-out login spelling really is a second spelling, not a second fix", () => {
    const admin = codefix("loginAdminChallenge_4_correct.ts");
    const jim = codefix("loginJimChallenge_1_correct.ts");
    const bender = codefix("loginBenderChallenge_2_correct.ts");
    expect(admin).toBe(jim);
    expect(bender).not.toBe(admin);
    // Both are parameterised; neither interpolates the request into the SQL.
    for (const text of [admin, bender]) expect(text).toContain("bind:");
    const displayed = extractSnippet(built.tree.get("routes/login.ts"), "loginJimChallenge").snippet;
    expect(displayed).not.toContain("${req.body.email");
    expect(displayed).toContain("$1");
  });

  it("puts B14 before B13, which is the order the hand repair requires", () => {
    const chat = planSteps(tree, codefixes).filter((s) => s.file === "routes/chat.ts");
    expect(chat.map((s) => s.keys[0])).toEqual([
      "chatbotPromptInjectionChallenge",
      "chatbotGreedyInjectionChallenge",
    ]);
    expect(chat[1].mode).toBe("hand-repair");
    expect(HAND_REPAIRED_KEYS).toEqual([chat[1].keys[0]]);
  });

  it("keeps both chat fixes, which the other order would not", () => {
    // B13's whole security fix is `.max(10)` on a line B14 rewrites. Whichever runs second wins,
    // and the loser's absence is invisible: the file parses either way.
    const chat = built.tree.get("routes/chat.ts");
    expect(chat).toContain("z.number().max(10).describe(");
    expect(chat).toContain("orderId: z.string().describe('The order ID of the damaged order");
    expect(chat).toContain("status: OrderStatus.DAMAGED");
  });

  it("shows B13's correct variant is one line of fix under a dedent, which is why it is by hand", () => {
    // The measurement `OVERLAP_EFFECTS`'s chat.ts entry rests on: strip the wrapper the variant
    // drops and the four spaces it dedents by, and three lines are left — one of them the fix, one
    // upstream's own typo, one the glued nested-marker line the splicer refuses to touch.
    const snippet = extractSnippet(read("routes/chat.ts"), "chatbotGreedyInjectionChallenge").snippet.split("\n");
    const text = codefix("chatbotGreedyInjectionChallenge_2_correct.ts").split("\n");
    const wrapper = snippet.findIndex((l) => l.includes("export function chat ()"));
    const normalised = snippet
      .filter((_, i) => i !== wrapper && i !== wrapper + 1)
      .map((l, i) => (i >= wrapper ? l.replace(/^ {4}/, "") : l));
    const differing = normalised.filter((l, i) => l !== text[i]);
    expect(normalised).toHaveLength(text.length);
    expect(differing).toHaveLength(3);
    expect(text.filter((l) => l.includes("z.number().max(10)"))).toHaveLength(1);
  });

  it("keeps upstream's Number(Id) typo out of the tree's application code", () => {
    // All four greedy variants carry it and `Id` is bound nowhere, so a verbatim apply would put a
    // reference error into every branch cut from this tree.
    const carriers = variantNames().filter((n) => n.startsWith("chatbotGreedyInjectionChallenge") && codefix(n).includes("Number(Id)"));
    expect(carriers).toHaveLength(4);
    for (const [path, contents] of built.tree) {
      if (path.startsWith("data/static/codefixes/")) continue;
      expect(contents).not.toContain("Number(Id)");
    }
  });

  it("parses but does not typecheck, and says which lines are why", () => {
    // The decision is to carry upstream's correct variants verbatim. Hand-patching them would stop
    // the splice being mechanical and would decouple the base from the correct-fix class, which
    // applies these same variants. `verifyBaseTree` already demands each declared line be present.
    expect(BASE_TREE_DEFECTS.length).toBeGreaterThan(0);
    for (const defect of BASE_TREE_DEFECTS) {
      expect(splitLines(built.tree.get(defect.file)).lines).toContain(defect.line);
      expect(codefix(defect.variant)).toBeTruthy();
    }
    // Every symbol the sweep can re-derive is declared; the sweep cannot see a duplicate key or a
    // member expression, which is why the table is wider than it is.
    const swept = unboundSymbolsIntroduced(tree, built.tree);
    const declared = new Set(BASE_TREE_DEFECTS.map((d) => `${d.file}\u0000${d.symbol}`));
    for (const hit of swept) expect(declared).toContain(`${hit.file}\u0000${hit.symbol}`);
    expect(swept.length).toBeGreaterThan(0);
  });

  it("leaves upstream's second, unmarked /metrics registration in place, and says so", () => {
    // The one measured place "the base is not vulnerable" is not literally true. Upstream
    // registers the route twice and the correct fix guards only the marked one.
    const registrations = splitLines(built.tree.get("server.ts")).lines.filter((l) => l.includes("app.get('/metrics'"));
    expect(registrations).toHaveLength(2);
    expect(registrations.filter((l) => l.includes("security.isAdmin()"))).toHaveLength(1);
    expect(BASE_TREE_DEFECTS.map((d) => d.kind)).toContain("unrepaired-sibling-site");
  });

  it("records every cross-block effect and no others", () => {
    // Each block round-trips to something even when a later step has rewritten part of it, so the
    // per-block check cannot see this on its own. `buildBaseTree` fails on an undeclared effect;
    // this asserts the declared ones are the corpus's two overlapping pairs and nothing else.
    expect(OVERLAP_EFFECTS.map((e) => e.block)).toEqual([
      "frontend/src/app/app.routing.ts:76",
      "routes/chat.ts:175",
    ]);
    const routing = extractSnippet(built.tree.get("frontend/src/app/app.routing.ts"), "web3SandboxChallenge").snippet;
    expect(routing).not.toContain("matcher: tokenMatcher");
    expect(routing).toContain("Must remain as is!");
  });

  it("emits a manifest that pins the upstream SHA and hashes every file it changed", () => {
    expect(built.manifest.upstream.pinnedSha).toMatch(/^[0-9a-f]{40}$/);
    expect(built.manifest.counts).toMatchObject({ keys: 35, keyBlockPairs: 36, blocks: 23, filesChanged: 16 });
    expect(built.manifest.changedFiles).toHaveLength(16);
    for (const entry of built.manifest.changedFiles) {
      expect(entry.upstreamSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.baseSha256).not.toBe(entry.upstreamSha256);
    }
    expect(built.manifest.handRepairedKeys).toEqual(["chatbotGreedyInjectionChallenge"]);
    expect(built.manifest.steps).toHaveLength(23);
    expect(JSON.stringify(built.manifest)).not.toContain(corpusDir);
  });

  it("HD-81: addresses every block by its own first key, including the eight whose end marker names several", () => {
    // Eight blocks carry an end marker naming more than one of their own keys. Phase 4 anchored
    // each on the last of them, because any other key left the rest of the list behind as a bare
    // line after the marker. That workaround is gone: every block is addressed by its first key,
    // and the build above spliced all of them and passed the splicer's confinement check.
    const multi = [];
    for (const step of planSteps(tree, codefixes)) {
      const lines = splitLines(tree.get(step.file)).lines;
      const endKeys = parseMarker(lines[step.end - 1]).keys.filter((k) => step.keys.includes(k));
      if (endKeys.length > 1) multi.push(step.id);
      expect(step.anchor).toBe(step.keys[0]);
    }
    expect(multi.length).toBe(8);
    const journal = new Map(built.steps.map((s) => [s.id, s]));
    for (const id of multi) {
      expect(journal.get(id).mode).toBe("splice");
      expect(journal.get(id).anchor).not.toBe(journal.get(id).keys.at(-1));
    }
  });
});
