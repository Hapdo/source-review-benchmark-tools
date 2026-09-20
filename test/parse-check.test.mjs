import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  LANGUAGE_BY_EXTENSION,
  SEMGREP_VERSION,
  availableRunner,
  checkTree,
  coverageFromScan,
  formatVerdict,
  languageFor,
  parseDumpAstOutput,
  selectTargets,
  summariseParseError,
  toTargetPath,
  verdictFor,
} from "../src/parse-check.mjs";
import { corpusDir, haveCorpus, skipReason } from "./corpus.mjs";

// --------------------------------------------------------------------------------------------
// Pure tests. These run everywhere, including on a machine with no Docker — the properties they
// cover are the ones that decide what an absent toolchain is reported AS, so they may not
// themselves depend on a toolchain being present.

describe("languageFor", () => {
  it("maps all five corpus languages, and Compose onto yaml", () => {
    // Five corpus languages, four Semgrep languages: `semgrep show supported-languages` on 1.99.0
    // has no `docker-compose`, so `infrastructure/docker-compose.yml` is checked as YAML.
    expect(languageFor("routes/login.ts")).toBe("ts");
    expect(languageFor("data/static/web3-snippets/HoneyPotNFT.sol")).toBe("solidity");
    expect(languageFor("terraform/networking.tf")).toBe("terraform");
    expect(languageFor("data/static/securityQuestions.yml")).toBe("yaml");
    expect(languageFor("infrastructure/docker-compose.yml")).toBe("yaml");
    expect(new Set(Object.values(LANGUAGE_BY_EXTENSION))).toEqual(new Set(["ts", "solidity", "terraform", "yaml"]));
  });

  it("maps nothing else", () => {
    expect(languageFor("README.md")).toBeUndefined();
    expect(languageFor("Dockerfile")).toBeUndefined();
  });
});

describe("selectTargets", () => {
  it("reports a scored path it cannot check rather than dropping it", () => {
    // The failure this exists for: a gate that quietly covers only the TypeScript files while
    // being read as covering the tree.
    const { targets, findings } = selectTargets(["routes/login.ts", "docs/notes.md"]);
    expect(targets).toEqual([{ path: "routes/login.ts", language: "ts" }]);
    expect(findings).toEqual([
      { path: "docs/notes.md", language: null, signal: "unsupported-extension", detail: "no Semgrep language for .md" },
    ]);
  });

  it("refuses a path that is not a plain repository path", () => {
    const { targets, findings } = selectTargets(["../etc/passwd", "a b.ts", "/abs.ts", "a//b.ts", "./a.ts"]);
    expect(targets).toEqual([]);
    expect(findings.map((f) => f.signal)).toEqual(Array(5).fill("unsafe-path"));
  });

  it("accepts a dotfile path, which is ordinary and not traversal", () => {
    // The first cut of the safe-path regex demanded an alphanumeric first character and refused
    // 22 of upstream's own files on a whole-tree run — every `.github/workflows/*.yml`,
    // `.gitlab-ci.yml`, `.codeclimate.yml`. A gate whose own path filter eats real files is the
    // thing this file is otherwise about.
    const { targets, findings } = selectTargets([".github/workflows/ci.yml", ".codeclimate.yml"]);
    expect(findings).toEqual([]);
    expect(targets.map((t) => t.path)).toEqual([".codeclimate.yml", ".github/workflows/ci.yml"]);
  });
});

describe("summariseParseError", () => {
  // The three shapes measured against the pinned image on 2026-09-20.
  it("names the line of a raised syntax error", () => {
    const stderr =
      '[00.02][ERROR]: Error: exception Parsing_error.Syntax_error (/tree/routes/login.ts:1:0 ' +
      '"export const a: number = 1;\\nfunction f(x: string) { return x;\\n")';
    expect(summariseParseError(stderr, 2)).toBe("syntax error at line 1");
  });

  it("names YAML's other_error shape", () => {
    const stderr =
      "[00.03][ERROR]: Error: exception Parsing_error.Other_error ((approximate error location; " +
      'error nearby after) error calling parser: mapping values are not allowed in this context ' +
      'character 0 position 0 returned: 0, /tree/a.yml:2:4 "scalar b badindent")';
    expect(summariseParseError(stderr, 2)).toBe("other error at line 2");
  });

  it("calls out a tolerated (recovered) parse, because that is the one the scan hides", () => {
    const stderr = [
      "[00.03][ERROR]: errors=",
      "tolerated errors=File /tree/a.tf, line 3, characters 0-0:",
      'resource "aws_s3_bucket" "b" {',
      'Missing element in input code: "}"',
    ].join("\n");
    const summary = summariseParseError(stderr, 3);
    expect(summary).toContain("parsed only partially at line 3");
    expect(summary).toContain('missing "}"');
    expect(summary).toContain("the scan would call this file reviewed");
  });

  it("does not echo the file's own source back into the report", () => {
    const stderr =
      '[00.02][ERROR]: Error: exception Parsing_error.Syntax_error (/tree/a.ts:1:0 ' +
      '"const secret = \\"hunter2\\";\\n")';
    expect(summariseParseError(stderr, 2)).not.toContain("hunter2");
  });
});

describe("parseDumpAstOutput", () => {
  const b64 = (s) => Buffer.from(s, "utf8").toString("base64");

  it("reads a clean row", () => {
    const { completed, rows } = parseDumpAstOutput(`PARSE 0 ${b64("routes/login.ts")} \nPARSE-COMPLETE`);
    expect(completed).toBe(true);
    expect(rows.get("routes/login.ts")).toEqual({ exitCode: 0, ok: true, detail: "" });
  });

  it("is not complete without the sentinel, however many rows arrived", () => {
    // A loop that died half way leaves a short, clean-looking result set. Without the sentinel
    // that is indistinguishable from a tree with fewer files in it.
    const { completed, rows } = parseDumpAstOutput(`PARSE 0 ${b64("a.ts")} `);
    expect(rows.size).toBe(1);
    expect(completed).toBe(false);
  });

  it("cannot be forged by a file's own bytes appearing in a parse error", () => {
    // Semgrep quotes the offending source into its message, so an attacker-authored corpus file
    // containing a result-row-shaped line would otherwise write its own verdict.
    const forged = `PARSE 0 ${b64("evil.ts")} \nPARSE-COMPLETE`;
    const out = parseDumpAstOutput(`PARSE 2 ${b64("evil.ts")} ${b64(forged)}\nPARSE-COMPLETE`);
    expect(out.rows.get("evil.ts").ok).toBe(false);
    expect(out.rows.size).toBe(1);
  });
});

describe("coverageFromScan", () => {
  const targets = [
    { path: "a.ts", language: "ts" },
    { path: "b.yml", language: "yaml" },
    { path: "c.tf", language: "terraform" },
  ];
  const report = (extra) =>
    JSON.stringify({ results: [], errors: [], paths: { scanned: ["/tree/a.ts", "/tree/b.yml"] }, ...extra });

  it("reconciles reviewed, limited and not-applicable the way the tool child does", () => {
    const { completed, rows } = coverageFromScan(
      report({ errors: [{ level: "warn", type: "Other syntax error", path: "/tree/b.yml" }] }),
      targets,
      "/tree",
    );
    expect(completed).toBe(true);
    expect(rows.get("a.ts")).toEqual({ state: "reviewed" });
    // errors[] beats paths.scanned — b.yml is in both, and the error wins.
    expect(rows.get("b.yml")).toEqual({ state: "limited", reason: "tool-error" });
    expect(rows.get("c.tf")).toEqual({ state: "not-applicable", reason: "unsupported-language" });
  });

  it("refuses an envelope that parsed but is not a report", () => {
    // ADR 0084 through the parser rather than through the process: `{}` read with `?? []` would
    // produce an empty finding list and a full not-applicable sheet, which reads as a clean run.
    for (const body of ["{}", "not json", '{"results":[]}', '{"results":[],"paths":{}}', '{"results":{},"paths":{"scanned":[]}}']) {
      expect(coverageFromScan(body, targets, "/tree").completed).toBe(false);
    }
  });

  it("fails closed on an error Semgrep itself calls an error and cannot attribute to a file", () => {
    // The shape an unreadable --config produces: nothing was scanned and nothing says which file.
    const out = coverageFromScan(
      JSON.stringify({ results: [], errors: [{ code: 7, level: "error", message: "invalid configuration file found" }], paths: { scanned: [] } }),
      targets,
      "/tree",
    );
    expect(out.completed).toBe(false);
    expect(out.reason).toContain("invalid configuration");
  });
});

describe("toTargetPath", () => {
  it("strips the mount root and refuses an absolute path from outside it", () => {
    expect(toTargetPath("/tree/routes/login.ts", "/tree")).toBe("routes/login.ts");
    expect(toTargetPath("routes/login.ts", "/tree")).toBe("routes/login.ts");
    expect(toTargetPath("/etc/passwd", "/tree")).toBeUndefined();
  });
});

describe("verdictFor", () => {
  const targets = [{ path: "a.ts", language: "ts" }];
  const clean = { completed: true, rows: new Map([["a.ts", { exitCode: 0, ok: true, detail: "" }]]) };
  const scanned = { completed: true, rows: new Map([["a.ts", { state: "reviewed" }]]) };

  it("passes only when both passes completed and found nothing", () => {
    const v = verdictFor({ scope: "s", targets, runner: "docker", parse: clean, scan: scanned });
    expect(v).toMatchObject({ ok: true, status: "pass", targets: 1, byLanguage: { ts: 1 } });
  });

  it("is UNAVAILABLE and non-passing when a pass did not complete", () => {
    const v = verdictFor({
      scope: "s",
      targets,
      runner: null,
      parse: { completed: false, rows: new Map(), reason: "Docker is unavailable" },
      scan: { completed: false, rows: new Map(), reason: "Docker is unavailable" },
    });
    expect(v.ok).toBe(false);
    expect(v.status).toBe("unavailable");
    expect(v.incomplete.join(" ")).toContain("Docker is unavailable");
  });

  it("reports a finding even when the other pass could not run", () => {
    // Findings first, the order classifySemgrepRun uses in HapDo: a real finding reported as a
    // broken environment is a finding nobody looks at.
    const v = verdictFor({
      scope: "s",
      targets,
      runner: "docker",
      parse: { completed: true, rows: new Map([["a.ts", { exitCode: 2, ok: false, detail: "syntax error at line 1" }]]) },
      scan: { completed: false, rows: new Map(), reason: "malformed-output" },
    });
    expect(v.status).toBe("fail");
    expect(v.ok).toBe(false);
    expect(v.findings).toEqual([{ path: "a.ts", language: "ts", signal: "parse-error", detail: "syntax error at line 1" }]);
    expect(v.incomplete.join(" ")).toContain("scan pass did not complete");
  });

  it("treats a target the parse pass never reported on as a finding, not a pass", () => {
    const v = verdictFor({ scope: "s", targets, runner: "docker", parse: { completed: true, rows: new Map() }, scan: scanned });
    expect(v.findings.map((f) => f.signal)).toEqual(["parse-missing"]);
  });

  it("never reports an empty target set as a pass", () => {
    // "There was nothing to check" and "everything was filtered away" must not collapse onto one
    // green tick — HapDo's T-37 shape.
    const v = verdictFor({ scope: "s", targets: [], runner: "docker", parse: { completed: true, rows: new Map() }, scan: { completed: true, rows: new Map() } });
    expect(v.ok).toBe(false);
    expect(v.status).toBe("unavailable");
  });
});

describe("checkTree with no runner", () => {
  it("is UNAVAILABLE with a reason naming the missing tool, never a pass and never a skip", () => {
    // Requirement 1, and the one test in this file that must hold on every machine: an absent
    // toolchain is a statement about the machine, and it may not be reported as a result about
    // the tree. `ok` is the structural bit — a caller reading only `ok` cannot get this wrong.
    const v = checkTree(corpusDir || ".", { files: ["routes/login.ts"], runner: null });
    expect(v.ok).toBe(false);
    expect(v.status).toBe("unavailable");
    expect(v.status).not.toBe("skip");
    expect(v.incomplete.join(" ")).toMatch(/Docker|uvx/);
    expect(v.incomplete.join(" ")).toContain(SEMGREP_VERSION);
    expect(formatVerdict(v)).toContain("verdict: UNAVAILABLE");
  });

  it("refuses a tree it cannot derive a scored file list from", () => {
    // A stripped tree carries no markers. That is "I do not know what to check", which is not
    // "there is nothing to check" — see bin/parse-check.mjs's --inventory flag.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "parse-check-empty-"));
    try {
      fs.writeFileSync(path.join(dir, "a.ts"), "const a = 1;\n");
      const v = checkTree(dir, { runner: null });
      expect(v.ok).toBe(false);
      expect(v.incomplete.join(" ")).toContain("no marked block");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// --------------------------------------------------------------------------------------------
// The gate actually firing. A parse gate nobody has seen reject anything is an assumption, so
// these run it over a tree with one deliberately broken file per corpus language.
//
// They need Semgrep. Without it they skip with the reason in the suite name, exactly as the
// conformance suites do for a missing corpus — never a green tick for a suite that did nothing.

const runner = availableRunner();
const haveSemgrep = runner !== null;
const semgrepSkipReason = `start Docker (or install uv) so semgrep ${SEMGREP_VERSION} can run the parse gate`;

/** One deliberately broken file per corpus language, each broken the way a mis-landed splice is:
 *  the block's closing syntax left behind. Beside each, the same file intact. */
const FIXTURES = {
  "good.ts": "export const a: number = 1;\nexport function f (x: string) { return x; }\n",
  "bad.ts": "export const a: number = 1;\nexport function f (x: string) { return x;\n",
  "good.sol": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract C { uint256 public x; function f() public { x = 1; } }\n",
  "bad.sol": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract C { uint256 public x; function f() public { x = 1; \n",
  "good.tf": 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n',
  "bad.tf": 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n',
  "good.yml": "questions:\n  - id: 1\n    question: what\n",
  "bad.yml": "questions:\n  - id: 1\n   question: [what\n",
  "docker-compose.good.yml": "services:\n  web:\n    image: nginx\n",
  "docker-compose.bad.yml": "services:\n  web:\n    image: nginx\n  broken: [oops\n",
};

const BROKEN = Object.keys(FIXTURES).filter((f) => f.includes("bad"));
const GOOD = Object.keys(FIXTURES).filter((f) => !f.includes("bad"));

describe.skipIf(!haveSemgrep)(`the gate rejects broken input in all five languages (${semgrepSkipReason})`, () => {
  let dir;
  let verdict;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "parse-check-fixtures-"));
    for (const [name, body] of Object.entries(FIXTURES)) fs.writeFileSync(path.join(dir, name), body);
    // One call over good and broken together: the gate is two processes whatever the target count,
    // and asserting both halves of the same run is what proves the rejection is about the file.
    verdict = checkTree(dir, { files: Object.keys(FIXTURES) });
  }, 300_000);

  afterAll(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("fails, and names every broken file and no intact one", () => {
    expect(verdict.status).toBe("fail");
    expect(verdict.ok).toBe(false);
    expect([...new Set(verdict.findings.map((f) => f.path))].sort()).toEqual([...BROKEN].sort());
    for (const good of GOOD) expect(verdict.findings.map((f) => f.path)).not.toContain(good);
  });

  it.each([
    // Measured against returntocorp/semgrep:1.99.0 on 2026-09-20. Terraform is `parse-partial`
    // and the rest are `parse-error` because Semgrep's HCL front end recovers where the others
    // raise — exit 3 rather than exit 2. Both are non-zero and both are findings; the distinction
    // is pinned here so a change to it is visible when the image pin moves.
    ["bad.ts", "ts", "parse-error"],
    ["bad.sol", "solidity", "parse-error"],
    ["bad.tf", "terraform", "parse-partial"],
    ["bad.yml", "yaml", "parse-error"],
    ["docker-compose.bad.yml", "yaml", "parse-error"],
  ])("rejects %s (%s) with %s, naming the file", (file, language, signal) => {
    const finding = verdict.findings.find((f) => f.path === file && f.signal.startsWith("parse-"));
    expect(finding, `no parse finding for ${file}`).toBeDefined();
    expect(finding.language).toBe(language);
    expect(finding.signal).toBe(signal);
    expect(finding.detail).not.toBe("");
  });

  it("passes every intact fixture, so the rejections are about the damage and not the language", () => {
    for (const good of GOOD) {
      const row = verdict.files.find((f) => f.path === good);
      expect(row.parse.ok, `${good} did not parse`).toBe(true);
      expect(row.scan.state).toBe("reviewed");
    }
  });

  it("MEASURED: the tool child's scan is blind to broken TypeScript, Solidity and Terraform", () => {
    // The finding that decides this gate's shape, and the reason it does not rest on the scan
    // alone. The corpus doc says a tree that does not parse "will produce `limited` coverage under
    // `malformed-output` or `targets-unscanned`". Under semgrep 1.99.0 that holds for YAML and
    // Compose and DOES NOT HOLD for the other three: their tree-sitter front ends recover, the
    // damaged subtree is dropped, `errors[]` is empty, and the file is listed in `paths.scanned`.
    // Reconciled as the sidecar reconciles it, the file comes back `reviewed`.
    //
    // So the real harm is worse than the documented one: the run is not marked `unverified`, it
    // looks verified while the rules never see the code that was damaged. If this expectation ever
    // flips, Semgrep has become strict and this gate's parse pass has stopped being load-bearing —
    // which is worth a red test either way.
    for (const file of ["bad.ts", "bad.sol", "bad.tf"]) {
      expect(verdict.files.find((f) => f.path === file).scan.state, `${file} scan state`).toBe("reviewed");
    }
    for (const file of ["bad.yml", "docker-compose.bad.yml"]) {
      expect(verdict.files.find((f) => f.path === file).scan).toEqual({ state: "limited", reason: "tool-error" });
    }
  });

  it("reports the languages it covered, so a run that covered less says so", () => {
    expect(verdict.byLanguage).toEqual({ ts: 2, solidity: 2, terraform: 2, yaml: 4 });
    expect(formatVerdict(verdict)).toContain("languages: solidity 2, terraform 2, ts 2, yaml 4");
  });
});

describe.skipIf(!haveSemgrep || !haveCorpus)(
  `pinned upstream is the baseline the repaired tree is judged against (${skipReason}; ${semgrepSkipReason})`,
  () => {
    it("parses and scans clean on all 16 files carrying a marked block", () => {
      // The baseline, measured 2026-09-20: 16 files, 23 blocks, zero findings, ~2.9s wall.
      // Recorded rather than assumed — if upstream's own tree stopped coming back clean, that
      // would be the baseline and not something to fix.
      const v = checkTree(corpusDir);
      expect(v.findings).toEqual([]);
      expect(v.incomplete).toEqual([]);
      expect(v.status).toBe("pass");
      expect(v.targets).toBe(16);
      expect(v.byLanguage).toEqual({ ts: 9, solidity: 3, terraform: 2, yaml: 2 });
    }, 300_000);

    it("BASELINE: upstream ships one TypeScript file semgrep 1.99.0 cannot fully parse", () => {
      // `frontend/src/app/Services/user.service.ts:14` declares `new?: string` inside an
      // `interface`. That is valid TypeScript — `new` is a reserved word that is legal as a
      // property name — and Semgrep's tree-sitter grammar reads it as a construct signature and
      // produces an ERROR node. It recovers, so `semgrep scan` says nothing at all.
      //
      // It carries no marked block, so it is outside the scored set and the default scope above is
      // clean. It is pinned here because it is the baseline: a `--all` run over the repaired tree
      // will report it, and that finding is upstream's, not the splicer's. Recorded, not fixed —
      // editing upstream to quiet a checker is the one repair this corpus may never make.
      const v = checkTree(corpusDir, { files: ["frontend/src/app/Services/user.service.ts"] });
      expect(v.status).toBe("fail");
      expect(v.findings.map((f) => f.signal)).toEqual(["parse-partial"]);
      expect(v.findings[0].detail).toContain("line 14");
      // And the half of it that matters: the scan pass calls the same file fully reviewed.
      expect(v.files[0].scan).toEqual({ state: "reviewed" });
    }, 300_000);

    it("BASELINE: a codefix variant does not parse on its own, which is why it is not a scored file", () => {
      // README point 1 — a variant is an edit of a *displayed snippet*, a non-contiguous
      // subsequence of a block's lines. Standalone it is a fragment. `stripTree` drops the whole
      // of `data/static/codefixes/` from every scored tree, so this never reaches the gate's
      // default scope; a `--all` run over an unstripped checkout reports ~26 of them.
      const v = checkTree(corpusDir, { files: ["data/static/codefixes/loginJimChallenge_1_correct.ts"] });
      expect(v.status).toBe("fail");
      expect(v.findings[0].signal).toBe("parse-error");
    }, 300_000);
  },
);
