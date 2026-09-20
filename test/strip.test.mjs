import { describe, expect, it } from "vitest";
import { MARKER_TOKEN } from "../src/markers.mjs";
import { MARKER_MENTIONS, STRIPPED_PATHS, stripMarkers, stripTree, verifyStripped } from "../src/strip.mjs";
import { readTree } from "../src/corpus.mjs";
import { corpusDir, haveCorpus, read, skipReason } from "./corpus.mjs";

const T = "vuln-code" + "-snippet";

describe("stripMarkers", () => {
  it("removes a standalone marker line entirely", () => {
    const { source } = stripMarkers([`// ${T} start kChallenge`, "code"].join("\n"));
    expect(source).toBe("code");
  });

  it("keeps the code on a line whose marker is a suffix", () => {
    // `models/user.ts:75` is `      }, // …end weakPasswordChallenge`. Dropping the line deletes a
    // closing brace and the file stops parsing — which Semgrep reports as `limited` coverage, not
    // as an error, so the run comes back `unverified` and the score is quietly about nothing.
    const { source } = stripMarkers(`      }, // ${T} end weakPasswordChallenge`);
    expect(source).toBe("      },");
  });

  it("keeps a YAML sequence dash whose only other content was the marker", () => {
    // `data/static/securityQuestions.yml:2` is `- # …neutral-line resetPasswordJimChallenge`. The
    // dash is a list item; the comment is not.
    const { source } = stripMarkers(`- # ${T} neutral-line resetPasswordJimChallenge`);
    expect(source).toBe("-");
  });

  it("removes a marker that sits outside every block", () => {
    // `server.ts:59` carries a `hide-line` where upstream's own parser never looks. It is inert to
    // Juice Shop and not inert to a leak check that searches for the string.
    const { source } = stripMarkers(`const x = 1 // ${T} hide-line`);
    expect(source).toBe("const x = 1");
  });

  it("reports the map from stripped line back to original line", () => {
    const { lineMap } = stripMarkers(
      ["a", `// ${T} start kChallenge`, "b", `c // ${T} vuln-line kChallenge`].join("\n"),
    );
    expect(lineMap).toEqual([1, 3, 4]);
  });
});

describe("stripTree", () => {
  const tree = new Map([
    ["lib/insecurity.ts", [`// ${T} start kChallenge`, "  const a = 1", `// ${T} end kChallenge`].join("\n")],
    ["data/static/codefixes/kChallenge_1_correct.ts", "the answer"],
    ["data/static/codefixes/kChallenge.info.yml", "prose explaining the defect"],
    ["data/static/challenges.yml", "116 challenges described in words"],
    ["README.md", "untouched"],
  ]);

  it("drops the prose answer key as well as the markers", () => {
    // The markers are not where most of the answer lives: `info.yml` explains each defect in
    // prose, and the scoring rules make that same prose the cited evidence for every CWE label.
    const { tree: out, dropped } = stripTree(tree);
    expect(dropped.sort()).toEqual([
      "data/static/challenges.yml",
      "data/static/codefixes/kChallenge.info.yml",
      "data/static/codefixes/kChallenge_1_correct.ts",
    ]);
    expect([...out.keys()].sort()).toEqual(["README.md", "lib/insecurity.ts"]);
  });

  it("maps each block into the stripped tree's own coordinates", () => {
    // Stripping shifts line numbers, and containment is decided by line. Nothing in the stripped
    // tree records where a block was, by construction — that is the point of stripping it.
    const { lineMap } = stripTree(tree);
    expect(lineMap.blocks).toEqual([
      {
        file: "lib/insecurity.ts",
        keys: ["kChallenge"],
        markedStart: 1,
        markedEnd: 3,
        start: 1,
        end: 1,
        vulnLines: [],
        neutralLines: [],
      },
    ]);
  });

  it("names the stripped paths as data, so a result can report what it ran against", () => {
    expect(STRIPPED_PATHS).toContain("data/static/codefixes/");
    expect(STRIPPED_PATHS).toContain("data/static/challenges.yml");
  });
});

describe("verifyStripped", () => {
  it("passes a tree with nothing left to find", () => {
    expect(verifyStripped({ "a.ts": "const a = 1" }, { mentions: {} }).ok).toBe(true);
  });

  it("distinguishes a mention of the token from a marker", () => {
    // The corpus contains seven of these and none of them is an answer: upstream's own parser
    // holds the grammar as regex source, and four lines of prose tell a contributor to re-run the
    // safety net. Failing on them would mean editing application code to quiet a checker.
    const mention = { "doc.md": "see the vuln-code" + "-snippet block for details of the thing" };
    expect(verifyStripped(mention, { mentions: { "doc.md": 1 } }).ok).toBe(true);
    expect(verifyStripped(mention, { mentions: {} }).findings[0].reason).toContain("unpinned");
  });

  it("fails when a pinned mention count moves, so a new marker type cannot arrive quietly", () => {
    const two = { "doc.md": ["a vuln-code" + "-snippet mention here", "and vuln-code" + "-snippet again"].join("\n") };
    expect(verifyStripped(two, { mentions: { "doc.md": 1 } }).findings[0].reason).toContain("moved");
  });

  it("names the file and line of a surviving marker", () => {
    const { ok, findings } = verifyStripped({ "a.ts": `x\ny // ${T} vuln-line kChallenge` }, { mentions: {} });
    expect(ok).toBe(false);
    expect(findings).toEqual([{ path: "a.ts", line: 2, reason: "marker survived stripping" }]);
  });

  it("catches a stripped path that came back", () => {
    const { findings } = verifyStripped({ "data/static/challenges.yml": "..." });
    expect(findings[0].reason).toContain("data/static/challenges.yml");
  });
});

describe.skipIf(!haveCorpus)(`the whole corpus strips clean (${skipReason})`, () => {
  it("leaves no marker, no codefix and no challenges.yml anywhere", () => {
    const { tree: stripped, dropped } = stripTree(readTree(corpusDir));
    expect(dropped.length).toBeGreaterThan(125);
    const result = verifyStripped(stripped);
    expect(result.findings).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("leaves exactly the pinned mentions of the token, and no marker", () => {
    const { tree: stripped } = stripTree(readTree(corpusDir));
    const total = Object.values(MARKER_MENTIONS).reduce((a, b) => a + b, 0);
    expect(verifyStripped(stripped).mentions).toBe(total);
  });

  it("maps 23 blocks over 16 files, and nothing from the vocabulary files", () => {
    // Stripping is by grammar and touches every file; the map is the scorer's input and takes
    // only corpus. Conflating the two put five blocks in the map that no branch can introduce a
    // defect into — three from upstream's own parser, one from its unit test's deliberately
    // unterminated fixture, one from a skill file.
    const { lineMap } = stripTree(readTree(corpusDir));
    expect(lineMap.blocks).toHaveLength(23);
    expect(lineMap.blocks.filter((b) => b.start === null)).toEqual([]);
    const files = new Set(lineMap.blocks.map((b) => b.file));
    expect(files.size).toBe(16);
    expect(files).not.toContain("lib/codingChallenges.ts");
    expect(files).not.toContain("test/server/codingChallenges.unit.test.ts");
    for (const f of [
      "server.ts",
      "routes/login.ts",
      "lib/insecurity.ts",
      "models/user.ts",
      "terraform/networking.tf",
      "data/static/securityQuestions.yml",
    ]) {
      expect(files).toContain(f);
    }
  });

  it("puts the login block's vuln line where the stripped tree actually has it", () => {
    // `routes/login.ts` marks the template-literal query. In the marked tree it is line 33; the
    // two marker lines above it go, so in the stripped tree it is where the map says and not
    // where the marked coordinates would put it.
    const { tree: stripped, lineMap } = stripTree(readTree(corpusDir));
    const block = lineMap.blocks.find((b) => b.file === "routes/login.ts");
    const line = stripped.get("routes/login.ts").split("\n")[block.vulnLines[0] - 1];
    expect(line).toContain("sequelize.query");
    expect(line).not.toContain(MARKER_TOKEN);
    expect(block.vulnLines[0]).toBeGreaterThanOrEqual(block.start);
    expect(block.vulnLines[0]).toBeLessThanOrEqual(block.end);
  });

  it("keeps the closing brace whose line carried an `end` marker", () => {
    const { tree: stripped } = stripTree(readTree(corpusDir));
    expect(read("models/user.ts")).toContain(`}, // ${MARKER_TOKEN} end weakPasswordChallenge`);
    expect(stripped.get("models/user.ts")).toContain("      },");
    expect(stripped.get("models/user.ts")).not.toContain(MARKER_TOKEN);
  });
});
