import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { extractSnippet, parseMarker, splitLines } from "../src/markers.mjs";
import { filterString } from "../src/rsn.mjs";
import { stripMarkers, stripTree, verifyStripped } from "../src/strip.mjs";
import { availableRunner, checkTree, selectTargets } from "../src/parse-check.mjs";
import {
  BASE_TREE_DEFECTS,
  OVERLAP_EFFECTS,
  buildBaseTree,
  lineHunks,
  planSteps,
  sha256,
} from "../src/base-tree.mjs";
import { FIXED, UNFIXED } from "../src/b13-hand-repair.mjs";
import {
  BROKEN_FIX_BASE,
  BranchRefused,
  CLASSES,
  DECLARED_RESIDUAL_SITES,
  DEFECT_LINE_RULING,
  EXCLUDED_VARIANTS,
  EXCLUSION_EVIDENCE,
  HAND_BUILT_ITEMS,
  MIRRORED_ITEMS,
  applyAmendments,
  planBranches,
  planItems,
  residualKeysFor,
  scoredTreeFor,
  slugFor,
  verifyBranchPlan,
} from "../src/branches.mjs";
import { readCodefixes, readTree } from "../src/corpus.mjs";
import { codefix, corpusDir, haveCorpus, read, skipReason, variantNames } from "./corpus.mjs";

/**
 * The corpus, the base tree and the plan, built once. The plan is the fixture for almost
 * everything below; what is under test is whether it says true things about the corpus.
 */
const upstream = haveCorpus ? readTree(corpusDir) : new Map();
const codefixes = haveCorpus ? readCodefixes(corpusDir) : new Map();
const built = haveCorpus ? await buildBaseTree(upstream, codefixes, { sha: null }) : null;
const plan = haveCorpus ? planBranches({ upstream, base: built.tree, codefixes }) : null;
const report = haveCorpus ? verifyBranchPlan({ plan, upstream, base: built.tree, codefixes }) : null;

const byId = (id) => plan.branches.find((b) => b.id === id);
const ofClass = (cls) => plan.branches.filter((b) => b.class === cls);

describe("slugFor", () => {
  it("turns a block id into something a branch name may contain", () => {
    expect(slugFor("frontend/src/app/app.routing.ts:76")).toBe("frontend-src-app-app-routing-ts-76");
    expect(slugFor("server.ts:746")).toBe("server-ts-746");
  });
});

describe("applyAmendments", () => {
  it("refuses a substitution that is not unique, because an amendment that is not is not one", () => {
    // Phase 4's rule, restated here because this module carries its own copy of the replay.
    const amendment = { kind: "line-substitution", find: "a", replace: "b" };
    expect(() => applyAmendments("a\na\n", [amendment], "fixture")).toThrow(BranchRefused);
    expect(applyAmendments("a\nc\n", [amendment], "fixture")).toBe("b\nc\n");
  });

  it("refuses a declared run that occurs twice", () => {
    const amendment = { kind: "delete-run", run: ["x", "y"] };
    expect(() => applyAmendments("x\ny\nz\nx\ny\n", [amendment], "fixture")).toThrow(BranchRefused);
    expect(applyAmendments("x\ny\nz\n", [amendment], "fixture")).toBe("z\n");
  });

  it("refuses an effect kind it does not know rather than ignoring it", () => {
    expect(() => applyAmendments("a\n", [{ kind: "reword" }], "fixture")).toThrow(/unknown overlap effect kind/);
  });
});

describe("residualKeysFor", () => {
  it("asks what a sibling's fix deletes, not what it adds — which is the whole of loginBender", () => {
    // Two keys replace one line with different but equally safe text. The branch that takes one
    // spelling has not left the other key vulnerable, and a containment test on the *added* lines
    // would say it had.
    const upstreamSnippet = "keep\nvulnerable\nkeep2\n";
    const variants = [
      { key: "alphaChallenge", file: "alphaChallenge_1_correct.ts", text: "keep\nsafeOne\nkeep2\n" },
      { key: "betaChallenge", file: "betaChallenge_1_correct.ts", text: "keep\nsafeTwo\nkeep2\n" },
    ];
    const residual = residualKeysFor({
      upstreamSnippet,
      branchSnippet: "keep\nsafeTwo\nkeep2\n",
      variants,
      ownKeys: ["betaChallenge"],
    });
    expect(residual).toEqual([]);
  });

  it("reports a sibling whose vulnerable line the branch still shows", () => {
    const upstreamSnippet = "vulnA\nvulnB\n";
    const variants = [
      { key: "alphaChallenge", file: "alphaChallenge_1_correct.ts", text: "safeA\nvulnB\n" },
      { key: "betaChallenge", file: "betaChallenge_1_correct.ts", text: "vulnA\nsafeB\n" },
    ];
    const residual = residualKeysFor({
      upstreamSnippet,
      branchSnippet: "safeA\nvulnB\n",
      variants,
      ownKeys: ["alphaChallenge"],
    });
    expect(residual).toHaveLength(1);
    expect(residual[0]).toMatchObject({ key: "betaChallenge", lines: ["vulnB"] });
  });
});

describe.skipIf(!haveCorpus)(`the branch plan, against the pinned corpus (${skipReason})`, () => {
  it("produces 22 introduce-the-vuln, 87 broken-fix and 35 correct-fix branches", () => {
    // The design said 23/90/35. Two of the three moved, and both movements are declared:
    // `iacLeakedKeyChallenge`'s two blocks are one item, and three variants are excluded.
    expect(report.byClass).toEqual({
      "introduce-the-vuln": 22,
      "broken-fix": 87,
      "correct-fix": 35,
    });
    expect(plan.counts.total).toBe(144);
    expect(new Set(plan.branches.map((b) => b.class))).toEqual(new Set(CLASSES));
    expect(plan.counts.blocks).toBe(23);
    expect(plan.counts.items).toBe(22);
    expect(plan.counts.keys).toBe(35);
  });

  it("makes exactly one branch per block and per included variant, and nothing else", () => {
    expect(ofClass("introduce-the-vuln")).toHaveLength(plan.items.length);
    const variants = variantNames();
    expect(variants).toHaveLength(125);
    const built = plan.branches.filter((b) => b.variant != null).map((b) => b.variant).sort();
    const excluded = EXCLUDED_VARIANTS.map((e) => e.variant).sort();
    expect([...built, ...excluded].sort()).toEqual(variants);
    expect(new Set(built).size).toBe(built.length);
  });

  it("gives every branch a distinct, stable name that carries no path and no clock", () => {
    const names = plan.branches.map((b) => b.name);
    expect(new Set(names).size).toBe(names.length);
    for (const name of names) expect(name).toMatch(/^hd85\/(introduce|broken-fix|correct-fix)\/[A-Za-z0-9._-]+$/);
    expect(JSON.stringify(plan.manifest)).not.toContain(corpusDir);
    expect(JSON.stringify(plan.manifest)).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
  });

  it("plans the same bytes twice", async () => {
    // Phase 4's manifest discipline, one layer out: a plan that could not be compared to itself
    // could not be pinned by SHA and rebuilt deliberately.
    const again = planBranches({
      upstream: readTree(corpusDir),
      base: (await buildBaseTree(readTree(corpusDir), readCodefixes(corpusDir), { sha: null })).tree,
      codefixes: readCodefixes(corpusDir),
    });
    expect(JSON.stringify(again.manifest)).toBe(JSON.stringify(plan.manifest));
    expect(again.branches.map((b) => b.files.map((f) => f.scoredSha256).join(","))).toEqual(
      plan.branches.map((b) => b.files.map((f) => f.scoredSha256).join(",")),
    );
  });

  it("cuts every fix branch from an introduce-the-vuln head, never from the base", () => {
    // The reason the class exists in this shape: re-applying `_N_correct` to the repaired base is
    // an empty diff, and an empty diff scores 35 items of the FP denominator clean unread.
    for (const branch of plan.branches) {
      if (branch.class === "introduce-the-vuln") {
        expect(branch.base).toBe("base");
        continue;
      }
      const head = byId(branch.base);
      expect(head?.class).toBe("introduce-the-vuln");
      expect(head.item).toBe(branch.item);
    }
    expect(BROKEN_FIX_BASE.base).toContain("introduce-the-vuln head");
  });

  it("would have been an empty diff from the base, which is why it is not cut from there", () => {
    // Measured rather than argued: every correct-fix branch's file is byte-identical to the base
    // tree's, so a branch cut from the base would have had nothing in it at all.
    const identical = ofClass("correct-fix").filter((b) =>
      b.files.every((f) => f.spliced === built.tree.get(f.path)),
    );
    expect(identical.length).toBeGreaterThan(20);
    for (const branch of identical) {
      for (const file of branch.files) expect(file.scored).toBe(stripMarkers(built.tree.get(file.path)).source);
      // And against the head it is cut from, it is not empty.
      expect(branch.files.every((f) => f.scoredHunks.length > 0)).toBe(true);
    }
  });

  it("scores the two networking.tf files as one item and edits both on every branch", () => {
    // Obstacle 1. A branch that edited one would leave the other vulnerable, and the correct-fix
    // branch cut from it would score a real fix as a true positive.
    const item = plan.items.find((i) => i.mirrored);
    expect(item.sites.map((s) => s.file)).toEqual([
      "infrastructure/terraform/networking.tf",
      "terraform/networking.tf",
    ]);
    expect(MIRRORED_ITEMS[0].key).toBe("iacLeakedKeyChallenge");
    expect(upstream.get(item.sites[0].file)).toBe(upstream.get(item.sites[1].file));

    const mirrored = plan.branches.filter((b) => b.item === item.id);
    expect(mirrored).toHaveLength(4); // 1 introduce + 2 broken + 1 correct
    for (const branch of mirrored) {
      expect(branch.files.map((f) => f.path)).toEqual(item.sites.map((s) => s.file));
      expect(branch.files[0].scoredSha256).toBe(branch.files[1].scoredSha256);
    }
  });

  it("excludes three chatbotGreedyInjection variants, and says what each of the three reasons is", () => {
    // Obstacle 2, ruled: excluded, so the class is 87 rather than 90.
    expect(EXCLUDED_VARIANTS.map((e) => e.variant)).toEqual([
      "chatbotGreedyInjectionChallenge_1.ts",
      "chatbotGreedyInjectionChallenge_3.ts",
      "chatbotGreedyInjectionChallenge_4.ts",
    ]);
    for (const entry of EXCLUDED_VARIANTS) {
      expect(entry.class).toBe("broken-fix");
      const text = codefix(entry.variant);
      // Reason 2: not an edit of the block's snippet — the wrapper is gone.
      expect(text).not.toContain("export function chat () {");
      // Reason 3: `export` is gone from a symbol another route imports.
      expect(text).toContain("function buildSystemPrompt");
      expect(text).not.toContain(EXCLUSION_EVIDENCE.exportedSymbol);
    }
    // `_1` also drops the parameter, which is the fourth signal and only on that one.
    expect(codefix("chatbotGreedyInjectionChallenge_1.ts")).toContain("function buildSystemPrompt () {");
    expect(EXCLUDED_VARIANTS.filter((e) => e.signals.includes("drops-parameter")).map((e) => e.variant)).toEqual([
      "chatbotGreedyInjectionChallenge_1.ts",
    ]);
  });

  it("finds the importer the dropped export would break, so the exclusion is not a guess", () => {
    expect(read(EXCLUSION_EVIDENCE.importedBy)).toContain(EXCLUSION_EVIDENCE.importLine);
    expect(read("routes/chat.ts")).toContain(EXCLUSION_EVIDENCE.exportedSymbol);
    // The correct variant keeps it, which is why that one key is still covered by a correct fix.
    expect(codefix("chatbotGreedyInjectionChallenge_2_correct.ts")).toContain(EXCLUSION_EVIDENCE.exportedSymbol);
  });

  it("finds B13's own key first on its end marker, which is why no anchor can splice it", () => {
    // Reason 1 for the exclusion, and the reason B13's two branches are hand-built: phase 4's
    // anchor workaround needs the block's key to be *last* on the end marker, and B13's is first.
    const lines = splitLines(read("routes/chat.ts")).lines;
    const step = planSteps(upstream, codefixes).find((s) => s.id === "routes/chat.ts:81");
    const marker = parseMarker(lines[step.end - 1]);
    expect(marker.type).toBe("end");
    expect(marker.keys).toEqual(["chatbotGreedyInjectionChallenge", "chatbotPromptInjectionChallenge"]);
    expect(marker.keys[marker.keys.length - 1]).not.toBe(step.keys[0]);
    expect(extractSnippet(read("routes/chat.ts"), "chatbotGreedyInjectionChallenge").suffix.trim()).not.toBe("");
  });

  it("builds B13's two branches by hand and proves the revert is the repair's inverse", () => {
    const item = plan.items.find((i) => i.id === HAND_BUILT_ITEMS[0].block);
    expect(item.mode).toBe("hand-repair");
    const head = plan.branches.find((b) => b.class === "introduce-the-vuln" && b.item === item.id);
    const fix = plan.branches.find((b) => b.variant === "chatbotGreedyInjectionChallenge_2_correct.ts");
    expect(head.builtBy).toBe("src/b13-hand-repair.mjs#applyB13Correct");
    expect(head.files[0].spliced).toContain(UNFIXED);
    expect(head.files[0].spliced).not.toContain(FIXED);
    // The correct fix returns the base tree's file byte for byte — the round trip the splicer
    // would have given, obtained from the hand repair instead.
    expect(fix.files[0].spliced).toBe(built.tree.get("routes/chat.ts"));
    expect(fix.files[0].spliced).toContain(FIXED);
    expect(plan.branches.filter((b) => b.item === item.id)).toHaveLength(2);
  });

  it("keeps B13's fix on every chatbotPromptInjection branch, which the unamended splice would drop", () => {
    // B14 lies inside B13 and both mark the same `discount:` line. Splicing upstream's or a
    // variant's text verbatim rewrites that line without `.max(10)`, silently deleting B13's
    // whole security fix. `OVERLAP_EFFECTS` is replayed onto every text before it is spliced.
    const chat = plan.branches.filter((b) => b.item === "routes/chat.ts:175");
    expect(chat).toHaveLength(5); // 1 introduce + 3 broken + 1 correct
    for (const branch of chat) expect(branch.files[0].spliced).toContain(FIXED);
    expect(OVERLAP_EFFECTS.map((e) => e.block)).toContain("routes/chat.ts:175");
  });

  it("keeps B06's fix on every B05 branch, for the same reason", () => {
    // B06's correct fix deletes the token-sale route, and those four lines are inside B05.
    const b05 = plan.branches.filter((b) => b.item === "frontend/src/app/app.routing.ts:76");
    expect(b05.length).toBeGreaterThan(1);
    for (const branch of b05) expect(branch.files[0].spliced).not.toContain("matcher: tokenMatcher");
  });

  it("says B22 moves from exposed-at-one-site to exposed-at-two, not from safe to vulnerable", () => {
    // Obstacle 3. `server.ts` registers `/metrics` twice and only the second is inside B22;
    // `exposedMetricsChallenge_3_correct.ts` guards only that one. Telling the scorer the branch
    // makes a safe tree vulnerable would be telling it a falsehood.
    expect(splitLines(read("server.ts")).lines.filter((l) => l.includes("app.get('/metrics'"))).toHaveLength(2);
    const site = DECLARED_RESIDUAL_SITES[0];
    expect(site.block).toBe("server.ts:746");
    expect(site.effect).toContain("exposed-at-two-sites");
    // The base already carries it, which is what makes the claim measurable rather than a worry.
    expect(splitLines(built.tree.get("server.ts")).lines).toContain(site.line);

    const metrics = plan.branches.filter((b) => b.item === "server.ts:746");
    expect(metrics).toHaveLength(4); // 1 introduce + 2 broken + 1 correct
    for (const branch of metrics) {
      expect(branch.expectation.exclude.residualSites.map((s) => s.block)).toEqual(["server.ts:746"]);
      expect(splitLines(branch.files[0].spliced).lines).toContain(site.line);
    }
    // And no other item claims it.
    const others = plan.branches.filter((b) => b.item !== "server.ts:746");
    expect(others.every((b) => b.expectation.exclude.residualSites.length === 0)).toBe(true);
  });

  it("hands the scorer the seven declared defect lines, and flags the ones inside a diff", () => {
    // The ruling: a finding on one of these is corpus, and is excluded from both numerators and
    // from the false-positive denominator. It matters most where the line is in the branch's own
    // added lines, which is where a diff-scoped reviewer will see it.
    expect(DEFECT_LINE_RULING.lines).toHaveLength(BASE_TREE_DEFECTS.length);
    expect(DEFECT_LINE_RULING.ruling).toContain("corpus");
    const touching = report.branchesTouchingDefectLines;
    expect(touching).toContain("correct-fix/chatbotPromptInjectionChallenge_2_correct.ts");
    expect(touching).toContain("correct-fix/weakPasswordChallenge_1_correct.ts");
    expect(touching).toContain("correct-fix/exposedMetricsChallenge_3_correct.ts");

    const chatFix = byId("correct-fix/chatbotPromptInjectionChallenge_2_correct.ts");
    const orderStatus = chatFix.expectation.exclude.corpusDefectLines.find((d) => d.symbol === "OrderStatus");
    expect(orderStatus.inThisDiff).toBe(true);
    expect(splitLines(chatFix.files[0].spliced).lines).toContain(orderStatus.line);
  });

  it("declares every residual sibling key rather than repairing it or hiding it", () => {
    // Measured: for five of the eight multi-key blocks, one key's correct variant leaves its
    // siblings' defects exactly as upstream ships them. A reviewer flagging one of those is right.
    const residualCorrect = ofClass("correct-fix").filter((b) => b.expectation.exclude.residualKeys.length > 0);
    expect(residualCorrect.map((b) => b.variant).sort()).toEqual([
      "accessLogDisclosureChallenge_1_correct.ts",
      "adminSectionChallenge_1_correct.ts",
      "directoryListingChallenge_1_correct.ts",
      "forgedReviewChallenge_2_correct.ts",
      "noSqlReviewsChallenge_3_correct.ts",
      "redirectChallenge_4_correct.ts",
      "redirectCryptoCurrencyChallenge_3_correct.ts",
      "scoreBoardChallenge_1_correct.ts",
      "web3SandboxChallenge_1_correct.ts",
    ]);
    // And the lines are carried, so the exclusion is a lookup rather than a judgement per finding.
    const admin = byId("correct-fix/adminSectionChallenge_1_correct.ts");
    expect(admin.expectation.exclude.residualKeys.map((r) => r.key).sort()).toEqual([
      "scoreBoardChallenge",
      "web3SandboxChallenge",
    ]);
    for (const residual of admin.expectation.exclude.residualKeys) {
      expect(residual.lines.length).toBeGreaterThan(0);
      for (const line of residual.lines) expect(admin.files[0].scored).toContain(line.trim());
    }
  });

  it("does not call the three login spellings residuals, because one line is one defect", () => {
    // Obstacle 4. `loginBenderChallenge` binds by name where the other two bind positionally; the
    // base tree ruled for the majority spelling. On a branch the ruling is not needed at all —
    // the head is upstream's vulnerable line and each variant is a complete edit of it — so all
    // three correct-fix branches exist and none of them leaves a sibling vulnerable.
    const login = ofClass("correct-fix").filter((b) => b.item === "routes/login.ts:17");
    expect(login.map((b) => b.variant).sort()).toEqual([
      "loginAdminChallenge_4_correct.ts",
      "loginBenderChallenge_2_correct.ts",
      "loginJimChallenge_1_correct.ts",
    ]);
    for (const branch of login) {
      expect(branch.expectation.exclude.residualKeys).toEqual([]);
      expect(branch.files[0].scored).not.toContain("${req.body.email");
      expect(branch.files[0].scored).toContain("bind:");
    }
    // The bender branch keeps bender's own spelling, which the base tree does not.
    expect(byId("correct-fix/loginBenderChallenge_2_correct.ts").files[0].scored).toContain("$mail");
    expect(built.tree.get("routes/login.ts")).not.toContain("$mail");
  });

  it("makes every introduce-the-vuln branch display upstream's vulnerable code", () => {
    // `verifyBranchPlan` asserts this site by site and throws naming the block that failed.
    expect(() => verifyBranchPlan({ plan, upstream, base: built.tree, codefixes })).not.toThrow();
    for (const branch of ofClass("introduce-the-vuln")) {
      const item = plan.items.find((i) => i.id === branch.item);
      if (item.mode === "hand-repair") continue;
      for (const site of item.sites) {
        const file = branch.files.find((f) => f.path === site.file);
        const shown = extractSnippet(file.spliced, site.anchor).snippet;
        const want = applyAmendments(
          extractSnippet(upstream.get(site.file), site.anchor).snippet,
          OVERLAP_EFFECTS.filter((e) => e.block === site.block),
          site.block,
        );
        expect(filterString(shown).trim()).toBe(filterString(want).trim());
      }
    }
  });

  it("carries upstream's own vuln-line text on every introduce branch but the two overlapped ones", () => {
    // The splicer does not carry a marker onto a line it emits from a diff addition — the snippet
    // is marker-stripped before the diff sees it — so the defect sites are located by content.
    // Twenty of twenty-two locate every line. The two that do not are B13 and B14, whose shared
    // `discount:` line the other one's fix rewrote first, and the plan says so per site.
    expect(report.unlocatedDefectSites.map((u) => u.id).sort()).toEqual([
      "introduce-the-vuln/routes-chat-ts-175",
      "introduce-the-vuln/routes-chat-ts-81",
    ]);
    for (const entry of report.unlocatedDefectSites) {
      for (const line of entry.lines) expect(line).toContain("z.number()");
    }
    const clean = ofClass("introduce-the-vuln").filter((b) => b.defectSites.every((d) => d.located));
    expect(clean).toHaveLength(20);
    expect(clean.flatMap((b) => b.defectSites)).toHaveLength(36);
    // 39 marked lines over 23 blocks; the three the two chat branches cannot show are the rest.
    expect(plan.branches.filter((b) => b.class === "introduce-the-vuln").flatMap((b) => b.defectSites)).toHaveLength(39);
  });

  it("reverts a single-block file to upstream's scored file, byte for byte", () => {
    // The strongest form of "the revert is a revert", and the answer to whether losing the markers
    // costs anything: the tree that is *pushed* for a single-block file is upstream's own stripped
    // file. Only the marked intermediate differs, and it differs only where a marker was a suffix
    // on live code — `models/user.ts:75` — which `spliceVariant` deliberately splits onto a line
    // of its own and the strip then removes.
    const blocksPerFile = {};
    for (const step of planSteps(upstream, codefixes)) blocksPerFile[step.file] = (blocksPerFile[step.file] ?? 0) + 1;
    let checked = 0;
    for (const branch of ofClass("introduce-the-vuln")) {
      for (const file of branch.files) {
        if (blocksPerFile[file.path] !== 1) continue;
        expect(file.scored).toBe(stripMarkers(upstream.get(file.path)).source);
        checked++;
      }
    }
    expect(checked).toBe(12); // 16 files hold blocks; server.ts, app.routing.ts, search-result.component.ts and chat.ts hold several

    // A file holding several blocks cannot be, and is not: each branch reverts its own block only.
    const serverBranches = ofClass("introduce-the-vuln").filter((b) => b.files[0].path === "server.ts");
    expect(serverBranches).toHaveLength(5);
    for (const branch of serverBranches) {
      expect(branch.files[0].scored).not.toBe(stripMarkers(upstream.get("server.ts")).source);
      expect(lineHunks(built.tree.get("server.ts"), branch.files[0].spliced).length).toBeGreaterThan(0);
    }
  });

  it("gives every fix branch the variant it is named after, byte for byte", () => {
    for (const branch of plan.branches) {
      if (branch.variant == null) continue;
      const item = plan.items.find((i) => i.id === branch.item);
      if (item.mode === "hand-repair") continue;
      for (const site of item.sites) {
        const file = branch.files.find((f) => f.path === site.file);
        const shown = extractSnippet(file.spliced, site.anchor).snippet;
        const want = applyAmendments(
          codefix(branch.variant),
          OVERLAP_EFFECTS.filter((e) => e.block === site.block),
          site.block,
        );
        expect(filterString(shown).trim()).toBe(filterString(want).trim());
      }
    }
  });

  it("keeps upstream's Number(Id) typo out of every branch's application code", () => {
    // The same guard phase 4's base tree carries. All four greedy variants ship it and `Id` is
    // bound nowhere; the three that would have brought it in are excluded and the fourth is
    // applied by hand, one line at a time.
    for (const branch of plan.branches) {
      for (const file of branch.files) expect(file.scored).not.toContain("Number(Id)");
    }
  });

  it("survives stripping: the scored diff is the marked diff with the markers taken off", () => {
    // Splicing needs the markers and the scored tree has none, so the order is forced. What has to
    // be proved is that the strip does not erase or distort the edit — a smaller diff is not
    // something anything else would report.
    const token = "vuln-code" + "-snippet";
    for (const branch of plan.branches) {
      for (const file of branch.files) {
        expect(file.scoredHunks.length).toBeGreaterThan(0);
        expect(sha256(file.scored)).toBe(file.scoredSha256);
        expect(sha256(file.spliced)).toBe(file.splicedSha256);
        // By grammar, not by string: `server.ts:278` mentions the token in code that strips
        // markers out of files it serves, and phase 3 pins that mention rather than deleting it.
        for (const line of splitLines(file.scored).lines) {
          if (!line.includes(token)) continue;
          expect(parseMarker(line)).toBeNull();
        }
      }
    }
  });

  it("makes a scored tree per branch that carries no marker, no codefix and no challenges.yml", () => {
    // The whole tree, not just the changed files: a branch is pushed as a tree, and phase 3's
    // verifier is the thing that says a tree is safe to push.
    const scoredBase = stripTree(built.tree).tree;
    for (const id of [
      "introduce-the-vuln/server-ts-746",
      "broken-fix/loginBenderChallenge_1.ts",
      "correct-fix/chatbotPromptInjectionChallenge_2_correct.ts",
      "introduce-the-vuln/infrastructure-terraform-networking-tf-1",
    ]) {
      const tree = scoredTreeFor(scoredBase, byId(id));
      expect(verifyStripped(tree).ok).toBe(true);
      expect([...tree.keys()].some((p) => p.startsWith("data/static/codefixes/"))).toBe(false);
      expect(tree.has("data/static/challenges.yml")).toBe(false);
      // And the branch's files really are the ones in it.
      for (const file of byId(id).files) expect(tree.get(file.path)).toBe(file.scored);
    }
  });

  it("refuses to place a branch file over a scored base that does not have it", () => {
    expect(() => scoredTreeFor(new Map(), byId("introduce-the-vuln/models-user-ts-36"))).toThrow(BranchRefused);
  });

  it("names every changed path in a language the parse gate can read", () => {
    // Nothing falls off the end: an extension the gate cannot map would be a scored file nothing
    // ever parsed, which is the failure `src/parse-check.mjs` exists to prevent.
    const selected = selectTargets(plan.branches.flatMap((b) => b.files.map((f) => f.path)));
    expect(selected.findings).toEqual([]);
    expect(selected.targets).toHaveLength(16);
  });

  it("puts each item's sites in different files, so no branch splices twice into one file", () => {
    for (const item of plan.items) {
      expect(new Set(item.sites.map((s) => s.file)).size).toBe(item.sites.length);
    }
    // And ordering effects between blocks do not reach a branch: every branch is one item, and
    // every item's sites are in different files, so nothing is spliced after anything else.
    expect(plan.items.filter((i) => i.sites.length > 1)).toHaveLength(MIRRORED_ITEMS.length);
  });

  it("refuses a plan whose declared mirror has drifted", () => {
    // A mirror that is no longer a copy is two items, and a table that says otherwise is worse
    // than no table.
    const drifted = new Map(upstream);
    drifted.set("terraform/networking.tf", `${upstream.get("terraform/networking.tf")}\n# moved\n`);
    expect(() => planItems(drifted, codefixes)).toThrow(BranchRefused);
  });

  it("refuses a branch built from an excluded variant", () => {
    const tampered = { ...plan, branches: [...plan.branches] };
    tampered.branches[0] = { ...tampered.branches[0], variant: EXCLUDED_VARIANTS[0].variant };
    expect(() => verifyBranchPlan({ plan: tampered, upstream, base: built.tree, codefixes })).toThrow(
      /declared excluded and a branch was built from it anyway/,
    );
  });

  it("refuses a variant that produced no branch and is not declared excluded", () => {
    const tampered = { ...plan, branches: plan.branches.filter((b) => b.variant !== "redirectChallenge_1.ts") };
    expect(() => verifyBranchPlan({ plan: tampered, upstream, base: built.tree, codefixes })).toThrow(
      /produced no branch and is not in EXCLUDED_VARIANTS/,
    );
  });
});

/**
 * The parse gate over every branch.
 *
 * A tree that parses wrongly is scored rather than reported — Semgrep's tree-sitter front ends do
 * error recovery, so a mis-spliced file scans `reviewed` with `errors: []` while the rules never
 * read the damaged code. Every changed file of every branch is therefore handed to the gate, in
 * one run: each branch's files are written under a directory of their own, so 144 branches' worth
 * of `server.ts` can be checked in a single pass without colliding.
 *
 * When no runner can start, this reports UNAVAILABLE and does not run. It never passes on hope.
 */
const runner = availableRunner();
const parseSkipReason = "start Docker (or install uv) so semgrep 1.99.0 can run the parse gate";
let scratch = null;
afterAll(() => {
  if (scratch) fs.rmSync(scratch, { recursive: true, force: true });
});

describe.skipIf(!haveCorpus || !runner)(`every branch parses (${skipReason}; ${parseSkipReason})`, () => {
  it("parses and scans clean on all 148 changed files across all 144 branches", () => {
    // Measured 2026-09-20: 148 files, 105 ts / 20 yaml / 15 solidity / 8 terraform, ~15s wall.
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "branch-parse-"));
    const files = [];
    plan.branches.forEach((branch, i) => {
      const prefix = `b${String(i).padStart(3, "0")}`;
      for (const file of branch.files) {
        const rel = `${prefix}/${file.path}`;
        fs.mkdirSync(path.dirname(path.join(scratch, rel)), { recursive: true });
        fs.writeFileSync(path.join(scratch, rel), file.scored);
        files.push(rel);
      }
    });
    expect(files).toHaveLength(148);

    const verdict = checkTree(scratch, { files });
    expect(verdict.findings).toEqual([]);
    expect(verdict.incomplete).toEqual([]);
    expect(verdict.status).toBe("pass");
    expect(verdict.targets).toBe(148);
    expect(verdict.byLanguage).toEqual({ ts: 105, yaml: 20, solidity: 15, terraform: 8 });
  }, 600_000);
});
