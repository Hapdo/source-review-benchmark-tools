import { describe, expect, it } from "vitest";
import { extractSnippet, extractSnippetUpstream, findBlocks, parseMarker } from "../src/markers.mjs";
import { haveCorpus, read, skipReason } from "./corpus.mjs";

/**
 * A fixture exercising the four shapes the corpus actually contains, written out rather than
 * quoted from Juice Shop so that the unit tests run with no checkout. Every construction here has
 * a named counterpart in the corpus; the comment says which, so a reader can check the fixture is
 * not a convenient fiction.
 */
const T = "vuln-code" + "-snippet";
const FIXTURE = [
  "const outside = 1",
  `const wrap = () => { // ${T} start alphaChallenge`, //          models/user.ts:36 — start as suffix
  "  const kept = 1",
  `  const hidden = 2 // ${T} hide-line`, //                        routes/login.ts:20 — hidden live code
  `  const marked = unsafe() // ${T} vuln-line alphaChallenge`, //  lib/insecurity.ts — the defect
  "",
  `  const region = { // ${T} hide-start`, //                       models/user.ts:38 — hidden region
  "    deep: true",
  `  } // ${T} hide-end`, //                                        models/user.ts:69 — hide-end as suffix
  `  return kept // ${T} neutral-line alphaChallenge`,
  `} // ${T} end alphaChallenge`, //                                models/user.ts:75 — end as suffix
  "const after = 3",
].join("\n");

describe("parseMarker", () => {
  it("prefers the longer name where two marker types share a prefix", () => {
    // `hide-start` contains `start`. An alternation in the wrong order reports it as a block start
    // and the block then swallows the rest of the file.
    expect(parseMarker(`  // ${T} hide-start`).type).toBe("hide-start");
    expect(parseMarker(`  // ${T} hide-end`).type).toBe("hide-end");
    expect(parseMarker(`  // ${T} start k`).type).toBe("start");
    expect(parseMarker(`  // ${T} end k`).type).toBe("end");
  });

  it("reads the key list, and reads none from the three hide types", () => {
    expect(parseMarker(`// ${T} start aChallenge bChallenge`).keys).toEqual([
      "aChallenge",
      "bChallenge",
    ]);
    expect(parseMarker(`  x // ${T} hide-line`).keys).toEqual([]);
  });

  it("accepts the `#` comment form, which is how the YAML and Terraform corpus is marked", () => {
    expect(parseMarker(`# ${T} start kChallenge`).type).toBe("start");
  });
});

describe("extractSnippet", () => {
  const snip = extractSnippet(FIXTURE, "alphaChallenge");

  it("excludes code before a `start` suffix and includes code before an `end` suffix", () => {
    // Not symmetric, and it is upstream's asymmetry: the boundary match begins at the comment
    // introducer, so the arrow function's own line is outside the snippet, while the `}` that
    // closes it is the snippet's last line.
    expect(snip.lines[0].text).toBe("const kept = 1");
    expect(snip.lines.at(-1).text).toBe("}");
  });

  it("drops hidden lines from the snippet while keeping them in the map", () => {
    expect(snip.snippet).not.toContain("hidden = 2");
    expect(snip.snippet).not.toContain("deep: true");
    expect(snip.hidden.map((h) => h.reason)).toContain("hide-line");
    expect(snip.hidden.map((h) => h.reason)).toContain("hide-region");
  });

  it("strips the marker comment from a marked line but keeps the code and the line number", () => {
    const marked = snip.lines[snip.vulnLines[0] - 1];
    expect(marked.text).toBe("  const marked = unsafe()");
    expect(marked.marker).toContain("vuln-line");
    expect(marked.fileLines).toEqual([5]);
  });

  it("gives a blank line the provenance of its own terminator", () => {
    // Without this a blank line has no characters, so no provenance, so it reads as a line the
    // snippet never showed — and the splicer then re-inserts it as if it were hidden code.
    const blank = snip.lines.find((l) => l.text === "");
    expect(blank.fileLines).toEqual([6]);
    expect(snip.hidden.map((h) => h.fileLine)).not.toContain(6);
  });

  it("agrees with the upstream port on the fixture", () => {
    const up = extractSnippetUpstream(FIXTURE, "alphaChallenge");
    expect(snip.snippet).toBe(up.snippet);
    expect(snip.vulnLines).toEqual(up.vulnLines);
    expect(snip.neutralLines).toEqual(up.neutralLines);
  });
});

describe("findBlocks", () => {
  it("pairs per key rather than by nesting, so overlapping blocks both resolve", () => {
    // routes/chat.ts: one `end` on line 188 closes two `start`s. A stack-based pairer mis-pairs
    // all four of the corpus's overlapping blocks.
    const src = [
      `// ${T} start outerChallenge`,
      "a",
      `// ${T} start innerChallenge`,
      "b",
      `// ${T} end outerChallenge innerChallenge`,
    ].join("\n");
    expect(findBlocks(src)).toEqual([
      { start: 1, end: 5, keys: ["outerChallenge"] },
      { start: 3, end: 5, keys: ["innerChallenge"] },
    ]);
  });
});

describe.skipIf(!haveCorpus)(`conformance with upstream (${skipReason})`, () => {
  // The corpus's 35 keys across 23 blocks. `iacLeakedKeyChallenge` appears in two files, so the
  // (key, block) population is 36 rather than 35.
  const KEYS_AND_FILES = [
    ["resetPasswordBjoernOwaspChallenge", "data/static/securityQuestions.yml"],
    ["resetPasswordBjoernChallenge", "data/static/securityQuestions.yml"],
    ["resetPasswordJimChallenge", "data/static/securityQuestions.yml"],
    ["resetPasswordBenderChallenge", "data/static/securityQuestions.yml"],
    ["resetPasswordUvoginChallenge", "data/static/securityQuestions.yml"],
    ["web3WalletChallenge", "data/static/web3-snippets/ETHWalletBank.sol"],
    ["nftMintChallenge", "data/static/web3-snippets/HoneyPotNFT.sol"],
    ["nftUnlockChallenge", "data/static/web3-snippets/JuiceShopSBT.sol"],
    ["adminSectionChallenge", "frontend/src/app/app.routing.ts"],
    ["scoreBoardChallenge", "frontend/src/app/app.routing.ts"],
    ["web3SandboxChallenge", "frontend/src/app/app.routing.ts"],
    ["tokenSaleChallenge", "frontend/src/app/app.routing.ts"],
    ["restfulXssChallenge", "frontend/src/app/search-result/search-result.component.ts"],
    ["localXssChallenge", "frontend/src/app/search-result/search-result.component.ts"],
    ["xssBonusChallenge", "frontend/src/app/search-result/search-result.component.ts"],
    ["vulnerableDockerImageChallenge", "infrastructure/docker-compose.yml"],
    ["iacLeakedKeyChallenge", "infrastructure/terraform/networking.tf"],
    ["iacLeakedKeyChallenge", "terraform/networking.tf"],
    ["redirectCryptoCurrencyChallenge", "lib/insecurity.ts"],
    ["redirectChallenge", "lib/insecurity.ts"],
    ["weakPasswordChallenge", "models/user.ts"],
    ["chatbotGreedyInjectionChallenge", "routes/chat.ts"],
    ["chatbotPromptInjectionChallenge", "routes/chat.ts"],
    ["loginAdminChallenge", "routes/login.ts"],
    ["loginBenderChallenge", "routes/login.ts"],
    ["loginJimChallenge", "routes/login.ts"],
    ["unionSqlInjectionChallenge", "routes/search.ts"],
    ["dbSchemaChallenge", "routes/search.ts"],
    ["noSqlReviewsChallenge", "routes/updateProductReviews.ts"],
    ["forgedReviewChallenge", "routes/updateProductReviews.ts"],
    ["directoryListingChallenge", "server.ts"],
    ["accessLogDisclosureChallenge", "server.ts"],
    ["resetPasswordMortyChallenge", "server.ts"],
    ["changeProductChallenge", "server.ts"],
    ["registerAdminChallenge", "server.ts"],
    ["exposedMetricsChallenge", "server.ts"],
  ];

  it("covers every (key, block) pair in the corpus", () => {
    expect(KEYS_AND_FILES).toHaveLength(36);
    expect(new Set(KEYS_AND_FILES.map(([k]) => k)).size).toBe(35);
  });

  it.each(KEYS_AND_FILES)(
    "reproduces upstream's snippet for %s in %s, byte for byte",
    (key, file) => {
      const source = read(file);
      const mine = extractSnippet(source, key);
      const up = extractSnippetUpstream(source, key);
      expect(mine.snippet).toBe(up.snippet);
      expect(mine.vulnLines).toEqual(up.vulnLines);
      expect(mine.neutralLines).toEqual(up.neutralLines);
    },
  );

  it("maps every snippet line to at least one file line", () => {
    for (const [key, file] of KEYS_AND_FILES) {
      for (const line of extractSnippet(read(file), key).lines) {
        expect(line.fileLines.length).toBeGreaterThan(0);
      }
    }
  });
});
