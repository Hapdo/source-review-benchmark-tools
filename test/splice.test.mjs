import { describe, expect, it } from "vitest";
import { extractSnippet } from "../src/markers.mjs";
import { SpliceRefused, spliceVariant, spliceVariantChecked } from "../src/splice.mjs";
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
