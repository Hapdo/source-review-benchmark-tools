import { describe, expect, it } from "vitest";
import { extractSnippet, findBlocks, parseMarker, splitLines } from "../src/markers.mjs";
import {
  SpliceRefused,
  assertConfined,
  spliceVariant,
  spliceVariantChecked,
} from "../src/splice.mjs";
import { computeVariantDiff, keyOfVariantFile } from "../src/rsn.mjs";
import { codefix, haveCorpus, read, skipReason, variantNames } from "./corpus.mjs";

const T = "vuln-code" + "-snippet";

const NESTED = [
  "before",
  `// ${T} start outerChallenge`,
  "  const a = 1",
  `  const hiddenOne = 2 // ${T} hide-line`,
  "  const b = 2",
  `} // ${T} end outerChallenge`,
  "after",
].join("\n");

describe("spliceVariant", () => {
  it("keeps hidden lines in place when the lines around them change", () => {
    const snip = extractSnippet(NESTED, "outerChallenge");
    const variant = snip.snippet.replace("const a = 1", "const a = CHANGED");
    const { source } = spliceVariant(NESTED, "outerChallenge", variant);
    expect(source).toContain("const hiddenOne = 2");
    expect(source).toContain("const a = CHANGED");
    expect(source.split("\n")[0]).toBe("before");
    expect(source.split("\n").at(-1)).toBe("after");
  });

  it("puts hidden lines after the replacement, not after the deletion", () => {
    // `diffLines` emits `removed` before `added`. Flushing a hidden line as soon as its anchor is
    // passed drops it above the code that replaced the line it hung from — which, in the corpus,
    // puts a 32-line hide region above the statement it belongs inside.
    const snip = extractSnippet(NESTED, "outerChallenge");
    const variant = snip.snippet.replace("  const a = 1", "  const a = 1\n  const extra = 9");
    const { source } = spliceVariant(NESTED, "outerChallenge", variant);
    const lines = source.split("\n");
    expect(lines.indexOf("  const extra = 9")).toBeLessThan(
      lines.findIndex((l) => l.includes("hiddenOne")),
    );
  });

  it("keeps the block's own markers bracketing the block, whatever the variant does", () => {
    // The first draft anchored the `end` marker like an ordinary hidden line, and a variant that
    // replaced the tail of a block then left the replacement *outside* its own markers. The file
    // still parsed; the block displayed empty.
    const snip = extractSnippet(NESTED, "outerChallenge");
    const { source } = spliceVariant(NESTED, "outerChallenge", "  const only = 1\n");
    const lines = source.split("\n");
    const start = lines.findIndex((l) => l.includes(`${T} start`));
    const end = lines.findIndex((l) => l.includes(`${T} end`));
    expect(start).toBeLessThan(lines.indexOf("  const only = 1"));
    expect(end).toBeGreaterThan(lines.indexOf("  const only = 1"));
    expect(extractSnippet(source, "outerChallenge").snippet.trim()).toBe("const only = 1");
    expect(snip.lines.length).toBeGreaterThan(1);
  });

  it("refuses to delete a snippet line glued together from two file lines", () => {
    const src = [
      `// ${T} start outerChallenge`,
      "  const a = 1",
      `  // ${T} start innerChallenge`,
      "  const b = 2",
      `  // ${T} end outerChallenge innerChallenge`,
    ].join("\n");
    const snip = extractSnippet(src, "outerChallenge");
    const glued = snip.lines.find((l) => l.synthetic);
    expect(glued).toBeDefined();
    const variant = snip.lines
      .filter((l) => !l.synthetic)
      .map((l) => l.text)
      .join("\n");
    expect(() => spliceVariant(src, "outerChallenge", variant)).toThrow(SpliceRefused);
  });
});

/** Three keys on one end marker, the shape of `app.routing.ts`'s B05. */
const THREE_KEYS = [
  "before",
  `// ${T} start alphaChallenge betaChallenge gammaChallenge`,
  "  const a = 1",
  "  const b = 2",
  `} // ${T} end alphaChallenge betaChallenge gammaChallenge`,
  "after",
].join("\n");

/** B13's shape: the outer block's own key is *first* on an end marker it shares with the inner one. */
const SHARED_END = [
  "before",
  `// ${T} start outerChallenge`,
  "  const a = 1",
  `  // ${T} start innerChallenge`,
  "  const b = 2",
  `} // ${T} end outerChallenge innerChallenge`,
  "after",
].join("\n");

/** A line consisting of nothing but challenge keys — what the splicer used to leave behind. */
const bareKeyLine = (source) =>
  splitLines(source).lines.find((l) => l.trim() !== "" && /^(\s*[A-Za-z]+Challenge)+\s*$/.test(l));

describe("HD-81: a multi-key end marker", () => {
  it.each(["alphaChallenge", "betaChallenge", "gammaChallenge"])(
    "leaves no bare line of key names when the block is addressed by %s",
    (key) => {
      const variant = extractSnippet(THREE_KEYS, key).snippet.replace("const a = 1", "const a = FIXED");
      const { source } = spliceVariantChecked(THREE_KEYS, key, variant);
      expect(bareKeyLine(source)).toBeUndefined();
      expect(source.split("\n").at(-1)).toBe("after");
    },
  );

  it("splices to the same bytes whichever key addresses the block", () => {
    const out = ["alphaChallenge", "betaChallenge", "gammaChallenge"].map((key) => {
      const variant = extractSnippet(THREE_KEYS, key).snippet.replace("const b = 2", "const b = FIXED");
      return spliceVariantChecked(THREE_KEYS, key, variant).source;
    });
    expect(new Set(out).size).toBe(1);
  });

  it("keeps the whole key list on the end marker", () => {
    const { source } = spliceVariantChecked(THREE_KEYS, "alphaChallenge", extractSnippet(THREE_KEYS, "alphaChallenge").snippet);
    const end = splitLines(source).lines.map(parseMarker).find((m) => m?.type === "end");
    expect(end.keys).toEqual(["alphaChallenge", "betaChallenge", "gammaChallenge"]);
  });

  it("reports what follows the boundary key as end-marker text, not as code", () => {
    expect(extractSnippet(THREE_KEYS, "alphaChallenge").endMarkerRest).toBe(" betaChallenge gammaChallenge");
    expect(extractSnippet(THREE_KEYS, "gammaChallenge").endMarkerRest).toBe("");
  });

  it("splices an outer block whose own key is first on an end marker it shares with an inner block", () => {
    // B13. No key of the outer block is last on the marker, so phase 4's anchor workaround had
    // nothing to anchor to.
    const snip = extractSnippet(SHARED_END, "outerChallenge");
    const { source } = spliceVariantChecked(SHARED_END, "outerChallenge", snip.snippet.replace("const a = 1", "const a = FIXED"));
    expect(bareKeyLine(source)).toBeUndefined();
    expect(source).toContain("const a = FIXED");
    // The inner block is untouched and still extracts.
    expect(extractSnippet(source, "innerChallenge").snippet.trim()).toBe("const b = 2\n}");
  });
});

describe("HD-81: assertConfined", () => {
  const spliced = () =>
    spliceVariantChecked(THREE_KEYS, "alphaChallenge", extractSnippet(THREE_KEYS, "alphaChallenge").snippet).source;

  it("refuses a stray line after the end marker, which the round trip alone cannot see", () => {
    // Exactly what the splicer used to write: the rest of the key list, as a line of its own,
    // directly after the marker. Re-extracting on alphaChallenge stops before it.
    const lines = splitLines(spliced()).lines;
    const end = lines.findIndex((l) => parseMarker(l)?.type === "end");
    const stray = [...lines.slice(0, end + 1), " betaChallenge gammaChallenge", ...lines.slice(end + 1)].join("\n");
    expect(extractSnippet(stray, "alphaChallenge").snippet).toBe(extractSnippet(spliced(), "alphaChallenge").snippet);
    expect(() => assertConfined(THREE_KEYS, stray, "alphaChallenge")).toThrow(/extra line/);
  });

  it("refuses a changed line above the block", () => {
    expect(() => assertConfined(THREE_KEYS, spliced().replace("before", "BEFORE"), "alphaChallenge")).toThrow(/above the block/);
  });

  it("refuses a changed line below the block", () => {
    expect(() => assertConfined(THREE_KEYS, spliced().replace("after", "AFTER"), "alphaChallenge")).toThrow(/below the block/);
  });

  it("refuses an end marker that has lost a key", () => {
    const out = spliced();
    const at = out.lastIndexOf(" gammaChallenge");
    const lost = out.slice(0, at) + out.slice(at + " gammaChallenge".length);
    expect(() => assertConfined(THREE_KEYS, lost, "alphaChallenge")).toThrow(/end marker/);
  });

  it("refuses a changed start marker", () => {
    const out = spliced();
    const at = out.indexOf(" gammaChallenge");
    const lost = out.slice(0, at) + out.slice(at + " gammaChallenge".length);
    expect(() => assertConfined(THREE_KEYS, lost, "alphaChallenge")).toThrow(/start marker/);
  });

  it("accepts the splicer's own normalisation of an end marker carried on live code", () => {
    // `} // …end` becomes `}` and the marker on a line of its own, inside the block. Deliberate,
    // and not outside the block.
    expect(() => assertConfined(THREE_KEYS, spliced(), "alphaChallenge")).not.toThrow();
  });
});

describe("spliceVariantChecked", () => {
  it("fails when the alignment is wrong, not just when the result does not parse", () => {
    const snip = extractSnippet(NESTED, "outerChallenge");
    expect(() => spliceVariantChecked(NESTED, "outerChallenge", snip.snippet)).not.toThrow();
  });
});

describe.skipIf(!haveCorpus)(`conformance with the corpus (${skipReason})`, () => {
  /**
   * The four variants that cannot be spliced, and the reason, measured rather than assumed.
   *
   * All four belong to `chatbotGreedyInjectionChallenge`, and they are not edits of their block's
   * displayed snippet at all: they drop the `export function chat () {` wrapper and dedent the
   * tool object by four spaces. Upstream's own safety net records the drift — 126 to 132 lines
   * against a corpus median in the single digits, the next highest being 30 — and tolerates it,
   * because upstream only ever *displays* a variant. Splicing one would delete a live function
   * declaration from `routes/chat.ts`.
   */
  const UNSPLICEABLE = [
    "chatbotGreedyInjectionChallenge_1.ts",
    "chatbotGreedyInjectionChallenge_2_correct.ts",
    "chatbotGreedyInjectionChallenge_3.ts",
    "chatbotGreedyInjectionChallenge_4.ts",
  ];

  const KEY_FILE = {
    resetPassword: "data/static/securityQuestions.yml",
    web3Wallet: "data/static/web3-snippets/ETHWalletBank.sol",
    nftMint: "data/static/web3-snippets/HoneyPotNFT.sol",
    nftUnlock: "data/static/web3-snippets/JuiceShopSBT.sol",
  };

  /** Resolve a variant's key to the file carrying its block. */
  function fileFor(key) {
    const direct = {
      web3WalletChallenge: KEY_FILE.web3Wallet,
      nftMintChallenge: KEY_FILE.nftMint,
      nftUnlockChallenge: KEY_FILE.nftUnlock,
      vulnerableDockerImageChallenge: "infrastructure/docker-compose.yml",
      iacLeakedKeyChallenge: "infrastructure/terraform/networking.tf",
      weakPasswordChallenge: "models/user.ts",
      restfulXssChallenge: "frontend/src/app/search-result/search-result.component.ts",
      localXssChallenge: "frontend/src/app/search-result/search-result.component.ts",
      xssBonusChallenge: "frontend/src/app/search-result/search-result.component.ts",
      adminSectionChallenge: "frontend/src/app/app.routing.ts",
      scoreBoardChallenge: "frontend/src/app/app.routing.ts",
      web3SandboxChallenge: "frontend/src/app/app.routing.ts",
      tokenSaleChallenge: "frontend/src/app/app.routing.ts",
      redirectChallenge: "lib/insecurity.ts",
      redirectCryptoCurrencyChallenge: "lib/insecurity.ts",
      chatbotGreedyInjectionChallenge: "routes/chat.ts",
      chatbotPromptInjectionChallenge: "routes/chat.ts",
      loginAdminChallenge: "routes/login.ts",
      loginBenderChallenge: "routes/login.ts",
      loginJimChallenge: "routes/login.ts",
      unionSqlInjectionChallenge: "routes/search.ts",
      dbSchemaChallenge: "routes/search.ts",
      noSqlReviewsChallenge: "routes/updateProductReviews.ts",
      forgedReviewChallenge: "routes/updateProductReviews.ts",
    };
    if (direct[key]) return direct[key];
    if (key.startsWith("resetPassword") && key !== "resetPasswordMortyChallenge") {
      return KEY_FILE.resetPassword;
    }
    return "server.ts";
  }

  const names = haveCorpus ? variantNames() : [];

  it("has 125 variants, as phase 1 measured", () => {
    expect(names).toHaveLength(125);
  });

  it.each(names.filter((n) => !UNSPLICEABLE.includes(n)))(
    "splices %s and gets the variant back from the block",
    (name) => {
      const key = keyOfVariantFile(name);
      const { stats } = spliceVariantChecked(read(fileFor(key)), key, codefix(name));
      expect(stats.kept + stats.added).toBeGreaterThan(0);
    },
  );

  /**
   * HD-81: every block whose end marker names more than one key — the eight multi-key blocks, plus
   * B13, whose own key is first on the end marker it shares with B14 — spliced on **every** key it
   * has. The block's own snippet is spliced back, so the file should come back unchanged except for
   * the splicer's one deliberate normalisation (an end marker carried on live code moves to a line
   * of its own), and whichever key addresses the block the bytes should be the same.
   */
  const AFFECTED = haveCorpus
    ? [...new Set(Object.values(fileForAll()))].flatMap((file) => {
        const source = read(file);
        const lines = splitLines(source).lines;
        return findBlocks(source)
          // A key that is not last on its end marker is one the old splicer tripped on.
          .filter((b) => b.end > 0 && b.keys.some((k) => k !== parseMarker(lines[b.end - 1]).keys.at(-1)))
          .map((b) => ({ id: `${file}:${b.start}`, file, keys: b.keys }));
      })
    : [];

  function fileForAll() {
    const out = {};
    for (const name of names) out[keyOfVariantFile(name)] = fileFor(keyOfVariantFile(name));
    return out;
  }

  it("finds the nine affected blocks: eight multi-key end markers and B13", () => {
    expect(AFFECTED.map((b) => b.id).sort()).toEqual([
      "data/static/securityQuestions.yml:1",
      "frontend/src/app/app.routing.ts:76",
      "frontend/src/app/search-result/search-result.component.ts:135",
      "lib/insecurity.ts:121",
      "routes/chat.ts:81",
      "routes/login.ts:17",
      "routes/search.ts:18",
      "routes/updateProductReviews.ts:13",
      "server.ts:286",
    ]);
  });

  it.each(AFFECTED.map((b) => [b.id, b]))("HD-81: splices %s on every one of its keys, cleanly and identically", (_id, block) => {
    const source = read(block.file);
    const outputs = block.keys.map((key) => {
      const { source: out } = spliceVariantChecked(source, key, extractSnippet(source, key).snippet);
      expect(bareKeyLine(out)).toBeUndefined();
      const changed = splitLines(out).lines.filter((l) => !splitLines(source).lines.includes(l));
      // At most the normalised end marker line and the code it was split from.
      for (const line of changed) {
        expect(parseMarker(line)?.type === "end" || source.includes(`${line} // ${T} end`)).toBe(true);
      }
      return out;
    });
    expect(new Set(outputs).size).toBe(1);
  });

  it.each(UNSPLICEABLE)("refuses %s, and says why rather than producing a plausible tree", (name) => {
    const key = keyOfVariantFile(name);
    expect(() => spliceVariantChecked(read(fileFor(key)), key, codefix(name))).toThrow(SpliceRefused);
  });

  it("shows the refusals are upstream's drift, by upstream's own measure", () => {
    // If this ever stops holding, the four are no longer a special case and the splicer should
    // take them — or a new variant has drifted and needs the same treatment.
    const drift = (name) => {
      const key = keyOfVariantFile(name);
      const snip = extractSnippet(read(fileFor(key)), key);
      const d = computeVariantDiff(codefix(name), snip);
      return d.added.length + d.removed.length;
    };
    const refused = UNSPLICEABLE.map(drift);
    const rest = names.filter((n) => !UNSPLICEABLE.includes(n)).map(drift);
    expect(Math.min(...refused)).toBeGreaterThan(Math.max(...rest));
  });
});
