import { describe, expect, it } from "vitest";
import { extractSnippet } from "../src/markers.mjs";
import { computeVariantDiff, isCorrectVariant, keyOfVariantFile } from "../src/rsn.mjs";
import { codefix, haveCorpus, read, skipReason, variantNames } from "./corpus.mjs";

describe("variant filenames", () => {
  it("reads the key as everything before the first underscore, as upstream does", () => {
    expect(keyOfVariantFile("loginAdminChallenge_1_correct.ts")).toBe("loginAdminChallenge");
    expect(keyOfVariantFile("resetPasswordBjoernChallenge_2.yml")).toBe(
      "resetPasswordBjoernChallenge",
    );
  });

  it("distinguishes the correct variant from the deliberately broken ones", () => {
    expect(isCorrectVariant("loginAdminChallenge_1_correct.ts")).toBe(true);
    expect(isCorrectVariant("loginAdminChallenge_2.ts")).toBe(false);
  });
});

/**
 * The strongest check this repository can make against anything it did not write.
 *
 * `rsn/cache.json` is upstream's own locked record of where each variant differs from the snippet
 * it patches, excluding the lines upstream marked as the defect. Reproducing all 125 entries from
 * a locally computed snippet proves the snippet extraction *and* the diff alignment match
 * upstream's, neither of which the corpus alone can confirm.
 */
describe.skipIf(!haveCorpus)(`rsn/cache.json parity (${skipReason})`, () => {
  const cache = haveCorpus ? JSON.parse(read("rsn/cache.json")) : {};
  const names = haveCorpus ? variantNames() : [];

  // Upstream's `SNIPPET_PATHS` does not include the top-level `terraform/`, so the key that
  // appears in two files resolves to the `infrastructure/` copy — which is the one its variants
  // were cut against.
  const fileFor = (key) =>
    ({
      web3WalletChallenge: "data/static/web3-snippets/ETHWalletBank.sol",
      nftMintChallenge: "data/static/web3-snippets/HoneyPotNFT.sol",
      nftUnlockChallenge: "data/static/web3-snippets/JuiceShopSBT.sol",
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
    })[key] ??
    (key.startsWith("resetPassword") && key !== "resetPasswordMortyChallenge"
      ? "data/static/securityQuestions.yml"
      : "server.ts");

  it("locks all 125 variants", () => {
    expect(Object.keys(cache)).toHaveLength(125);
    expect(names).toHaveLength(125);
  });

  it.each(names)("reproduces upstream's locked diff for %s", (name) => {
    const key = keyOfVariantFile(name);
    const snip = extractSnippet(read(fileFor(key)), key);
    expect(computeVariantDiff(codefix(name), snip)).toEqual({
      added: cache[name].added,
      removed: cache[name].removed,
    });
  });
});
