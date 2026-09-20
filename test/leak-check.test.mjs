import { describe, expect, it } from "vitest";
import {
  MIN_SIGNIFICANT_CHARS,
  MIN_SIGNIFICANT_WORDS,
  buildLeakHashes,
  checkForLeaks,
  hashLine,
  isSignificant,
} from "../src/leak-check.mjs";
import { haveCorpus, read, skipReason } from "./corpus.mjs";

/** Stand-ins for the two private artifacts. Neither exists in this repository, which is the point. */
const ANSWER_KEY_LINE =
  "B15 routes/login.ts CWE-89 the query is assembled by template literal interpolation";
const HELD_OUT_LINE =
  "const token = req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? 'anonymous'";
/** A line that is in the private tree *and* already public, because the corpus is mostly public. */
const PUBLIC_CORPUS_LINE =
  "  app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true }))";

describe("significance", () => {
  it("ignores lines too short to carry information", () => {
    // `});` and `}` collide with everything. A check that fired on them would fire on brace style,
    // and a check that fires on legitimate use gets switched off.
    expect(isSignificant("});")).toBe(false);
    expect(isSignificant("    }")).toBe(false);
    expect(isSignificant(ANSWER_KEY_LINE)).toBe(true);
  });

  it("normalises indentation and trailing whitespace before hashing", () => {
    expect(hashLine(`  ${ANSWER_KEY_LINE}  `)).toBe(hashLine(ANSWER_KEY_LINE));
    expect(hashLine(ANSWER_KEY_LINE.replace(/ /g, "   "))).toBe(hashLine(ANSWER_KEY_LINE));
  });

  it("ignores a long identifier on a line of its own", () => {
    // `"resetPasswordBjoernChallenge",` clears the character bar and carries nothing private:
    // challenge key names are in the corpus's own markers. The first real run of this check
    // flagged exactly that line in the public repository's own test, from the private key's
    // serialized JSON. A check that fires on a public identifier gets switched off.
    expect(isSignificant('      "resetPasswordBjoernChallenge",')).toBe(false);
    expect(isSignificant("chatbotGreedyInjectionChallenge_2_correct.ts")).toBe(false);
  });

  it("states both thresholds as data rather than hiding them in the hash list", () => {
    expect(MIN_SIGNIFICANT_CHARS).toBeGreaterThan(8);
    expect(MIN_SIGNIFICANT_WORDS).toBeGreaterThan(1);
  });
});

describe("buildLeakHashes", () => {
  const hashList = buildLeakHashes(
    [[ANSWER_KEY_LINE, PUBLIC_CORPUS_LINE].join("\n"), HELD_OUT_LINE],
    [PUBLIC_CORPUS_LINE],
  );

  it("hashes what is private because it is new", () => {
    expect(hashList.hashes).toContain(hashLine(ANSWER_KEY_LINE));
    expect(hashList.hashes).toContain(hashLine(HELD_OUT_LINE));
  });

  it("subtracts the public corpus, so the permitted fixtures stay permitted", () => {
    // The private corpus is mostly public Juice Shop. A hash list built from the private tree
    // wholesale bans the very fixtures the leak rule allows — `Juice Shop's already-public marked
    // blocks` — and then the check is in everybody's way for no gain.
    expect(hashList.hashes).not.toContain(hashLine(PUBLIC_CORPUS_LINE));
  });

  it("carries hashes and never the content", () => {
    const serialised = JSON.stringify(hashList);
    expect(serialised).not.toContain("routes/login.ts");
    expect(serialised).not.toContain("x-forwarded-for");
  });
});

describe("checkForLeaks", () => {
  const hashList = buildLeakHashes([ANSWER_KEY_LINE, HELD_OUT_LINE], [PUBLIC_CORPUS_LINE]);

  it("names the file and line of a leaked fixture", () => {
    const { ok, findings } = checkForLeaks(
      { "test/fixtures/a.mjs": ["const x = 1", `// ${ANSWER_KEY_LINE}`].join("\n") },
      hashList,
    );
    expect(ok).toBe(false);
    expect(findings).toEqual([{ path: "test/fixtures/a.mjs", line: 2 }]);
  });

  it("passes a fixture taken from the public corpus", () => {
    expect(checkForLeaks({ "test/fixtures/b.ts": PUBLIC_CORPUS_LINE }, hashList).ok).toBe(true);
  });

  it("catches a leak pasted in as a comment, which is the likely accident", () => {
    const { ok } = checkForLeaks({ "t.mjs": `  // ${HELD_OUT_LINE}` }, hashList);
    expect(ok).toBe(false);
  });

  it("catches a leak that was re-indented on the way in", () => {
    const { ok } = checkForLeaks({ "t.mjs": `        ${HELD_OUT_LINE}` }, hashList);
    expect(ok).toBe(false);
  });
});

describe.skipIf(!haveCorpus)(`this repository is clean (${skipReason})`, () => {
  it("would not flag a real marked block used as a fixture", () => {
    // The rule permits exactly this, and the check has to agree with the rule or it will be turned
    // off the first time somebody writes a legitimate test.
    const hashList = buildLeakHashes([read("routes/login.ts")], [read("routes/login.ts")]);
    expect(hashList.hashes).toEqual([]);
  });
});
