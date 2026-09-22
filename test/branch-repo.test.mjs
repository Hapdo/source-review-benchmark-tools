import fs from "node:fs";
import os from "node:os";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { MARKER_TOKEN } from "../src/markers.mjs";
import { lineHunks, sha256 } from "../src/base-tree.mjs";
import { STRIPPED_PATHS } from "../src/strip.mjs";
import {
  BASE_BRANCH,
  BASE_MESSAGE,
  NEUTRALISED_ENV,
  PINNED_DATE,
  PINNED_IDENTITY,
  PINNED_SHA_OF_CORPUS,
  RepoRefused,
  branchRecords,
  commitBranches,
  commitScoredBase,
  commitTree,
  diffCommits,
  fileAt,
  generateBranchRepo,
  git,
  gitEnv,
  initRepo,
  pathsAt,
  PUBLISHED_REF,
  publishedRefs,
  verifyBranchRepo,
  walkCheckout,
  writeTreeOver,
} from "../src/branch-repo.mjs";
import { corpusDir, haveCorpus, skipReason } from "./corpus.mjs";

/**
 * Everything this suite creates lives under one scratch directory and is removed at the end.
 *
 * Generating ~179 branches into a local repository is cheap and needs no network, which is the
 * whole point: phase 2's mirror does not exist yet, and a suite that could only run once somebody
 * had provisioned a remote would be a suite nobody runs. Nothing here pushes.
 */
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "branch-repo-"));
afterAll(() => fs.rmSync(scratch, { recursive: true, force: true }));

let made = 0;
const fresh = (name) => path.join(scratch, `${name}-${made++}`);

/* -------------------------------------------------------------------------- */
/* A hand-made corpus, so the mechanism can be tested without the corpus        */
/* -------------------------------------------------------------------------- */

/**
 * A four-file checkout: one text file, one executable script, one binary the text map never
 * carries, and one file under a stripped path.
 *
 * Small on purpose. The questions below — does the identity leak in, does an empty tree refuse,
 * does a stale index show up — are about the machinery, and asking them of 179 real branches
 * would make a fast test slow without making it a better question.
 */
function writeFixtureCheckout(dir) {
  const write = (rel, contents, mode) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), contents);
    if (mode) fs.chmodSync(path.join(dir, rel), mode);
  };
  write("a.ts", "one\ntwo\nthree\n");
  write("bin/run.sh", "#!/bin/sh\necho hi\n", 0o755);
  write("logo.png", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]));
  write("data/static/challenges.yml", "name: not in any scored tree\n");
  write("data/static/codefixes/x_1_correct.ts", "const x = 1\n");
  write("node_modules/junk.js", "module.exports = 1\n");
  return dir;
}

/** The scored map for that checkout: the text files only, `a.ts` rewritten as the repair would. */
const FIXTURE_SCORED = () =>
  new Map([
    ["a.ts", "one\ntwo repaired\nthree\n"],
    ["bin/run.sh", "#!/bin/sh\necho hi\n"],
  ]);

/** Two branches, the second cut from the first — the stack shape the fix classes use. */
const FIXTURE_RECORDS = () => {
  const one = "one\ntwo vulnerable\nthree\n";
  const two = "one\ntwo fixed again\nthree\n";
  return [
    {
      id: "introduce/a",
      name: "fixture/introduce/a",
      ref: "pr/001",
      class: "introduce-the-vuln",
      baseId: null,
      files: [{ path: "a.ts", content: one, sha256: sha256(one) }],
      about: { item: "a.ts:1" },
    },
    {
      id: "correct-fix/a",
      name: "fixture/correct-fix/a",
      ref: "pr/002",
      class: "correct-fix",
      baseId: "introduce/a",
      files: [{ path: "a.ts", content: two, sha256: sha256(two) }],
      about: { item: "a.ts:1" },
    },
  ];
};

/** Build the fixture repository end to end and hand back everything the assertions need. */
function buildFixtureRepo(checkout, repoDir, records = FIXTURE_RECORDS()) {
  const gitDir = initRepo(repoDir);
  const index = path.join(gitDir, "hd85.index");
  const base = commitScoredBase(gitDir, index, { checkout, scored: FIXTURE_SCORED() });
  const branches = commitBranches(gitDir, index, { baseCommit: base.commit, records });
  return { gitDir, index, base, branches, records };
}

/* -------------------------------------------------------------------------- */
/* The pinning                                                                 */
/* -------------------------------------------------------------------------- */

describe("what is pinned", () => {
  it("PINNED_DATE is midnight UTC, stated as an offset rather than parsed through a timezone", () => {
    const [epoch, offset] = PINNED_DATE.split(" ");
    expect(offset).toBe("+0000");
    expect(new Date(Number(epoch) * 1000).toISOString()).toBe("2026-01-01T00:00:00.000Z");
  });

  it("gitEnv removes every inherited git variable and states the identity itself", () => {
    const before = {};
    for (const name of NEUTRALISED_ENV) {
      before[name] = process.env[name];
      process.env[name] = "/somewhere/else";
    }
    try {
      const env = gitEnv();
      for (const name of NEUTRALISED_ENV) expect(env[name]).toBeUndefined();
      expect(env.GIT_AUTHOR_NAME).toBe(PINNED_IDENTITY.name);
      expect(env.GIT_COMMITTER_EMAIL).toBe(PINNED_IDENTITY.email);
      expect(env.GIT_AUTHOR_DATE).toBe(PINNED_DATE);
      expect(env.GIT_COMMITTER_DATE).toBe(PINNED_DATE);
      // Pointed at /dev/null rather than unset: unset means "look in the usual place".
      expect(env.GIT_CONFIG_GLOBAL).toBe("/dev/null");
      expect(env.GIT_CONFIG_SYSTEM).toBe("/dev/null");
      expect(env.TZ).toBe("UTC");
    } finally {
      for (const name of NEUTRALISED_ENV) {
        if (before[name] === undefined) delete process.env[name];
        else process.env[name] = before[name];
      }
    }
  });

  it("the created repository is bare, on the base branch, with the machine's config shut out", () => {
    const dir = initRepo(fresh("init"));
    expect(git(dir, ["rev-parse", "--is-bare-repository"]).trim()).toBe("true");
    expect(git(dir, ["symbolic-ref", "HEAD"]).trim()).toBe(`refs/heads/${BASE_BRANCH}`);
    expect(git(dir, ["config", "core.autocrlf"]).trim()).toBe("false");
    expect(git(dir, ["config", "commit.gpgsign"]).trim()).toBe("false");
  });

  it("refuses to generate into a directory that already holds something", () => {
    const dir = fresh("occupied");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "HEAD"), "ref: refs/heads/from-an-earlier-run\n");
    expect(() => initRepo(dir)).toThrow(RepoRefused);
  });
});

describe("bin/generate-branches.mjs", () => {
  const run = (args) =>
    spawnSync(process.execPath, [path.join(import.meta.dirname, "..", "bin", "generate-branches.mjs"), ...args], {
      encoding: "utf8",
    });

  it("refuses a directory that is not a juice-shop checkout", () => {
    const result = run([fresh("not-juice-shop"), fresh("repo")]);
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/no data\/static\/codefixes/);
  });

  it("refuses an output repository that overlaps the checkout, so nothing can write into the corpus", () => {
    const checkout = writeFixtureCheckout(fresh("checkout"));
    fs.mkdirSync(path.join(checkout, "data/static/codefixes"), { recursive: true });
    const result = run([checkout, path.join(checkout, "inside")]);
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/never writes into the corpus/);
  });
});

/* -------------------------------------------------------------------------- */
/* The walk                                                                    */
/* -------------------------------------------------------------------------- */

describe("walkCheckout", () => {
  const checkout = writeFixtureCheckout(fresh("checkout"));

  it("carries the binaries, keeps the executable bit, and drops what leaves every scored tree", () => {
    const files = walkCheckout(checkout);
    const byPath = new Map(files.map((f) => [f.path, f]));
    expect([...byPath.keys()]).toEqual(["a.ts", "bin/run.sh", "logo.png"]);
    expect(byPath.get("bin/run.sh").mode).toBe("100755");
    expect(byPath.get("a.ts").mode).toBe("100644");
    for (const stripped of STRIPPED_PATHS) {
      expect([...byPath.keys()].some((p) => p.startsWith(stripped) || p === stripped)).toBe(false);
    }
  });

  it("refuses a symlink rather than committing a tree entry nobody here has checked", () => {
    const dir = writeFixtureCheckout(fresh("symlinked"));
    fs.symlinkSync("a.ts", path.join(dir, "link.ts"));
    expect(() => walkCheckout(dir)).toThrow(/symlink/);
  });

  it("refuses a scored file the checkout does not have", () => {
    const gitDir = initRepo(fresh("missing"));
    const scored = FIXTURE_SCORED();
    scored.set("invented.ts", "// nothing on disk produced this\n");
    expect(() => commitScoredBase(gitDir, path.join(gitDir, "i"), { checkout, scored })).toThrow(
      /which is not in the checkout/,
    );
  });
});

/* -------------------------------------------------------------------------- */
/* Determinism, on the fixture                                                 */
/* -------------------------------------------------------------------------- */

describe("the same inputs give the same SHAs", () => {
  const checkout = writeFixtureCheckout(fresh("checkout"));
  const first = buildFixtureRepo(checkout, fresh("repo"));
  const second = buildFixtureRepo(checkout, fresh("repo"));

  it("two repositories built from one checkout agree on every commit and tree", () => {
    expect(second.base).toEqual(first.base);
    expect(second.branches).toEqual(first.branches);
  });

  it("an identity, a date and a GIT_DIR in the environment do not reach the commit", () => {
    // The failure this rules out is silent: a leaked identity produces a valid repository whose
    // SHAs simply are not the published ones, and only a second run on another machine says so.
    const hostile = {
      GIT_AUTHOR_NAME: "Someone Else",
      GIT_AUTHOR_EMAIL: "someone@example.com",
      GIT_COMMITTER_NAME: "Someone Else",
      GIT_COMMITTER_EMAIL: "someone@example.com",
      GIT_AUTHOR_DATE: "2001-02-03T04:05:06Z",
      GIT_COMMITTER_DATE: "2001-02-03T04:05:06Z",
      GIT_DIR: path.join(scratch, "not-a-repo"),
      GIT_INDEX_FILE: path.join(scratch, "not-an-index"),
      GIT_PAGER: "does-not-exist",
    };
    const before = {};
    for (const [k, v] of Object.entries(hostile)) {
      before[k] = process.env[k];
      process.env[k] = v;
    }
    try {
      const third = buildFixtureRepo(checkout, fresh("repo"));
      expect(third.base.commit).toBe(first.base.commit);
      expect(third.branches.map((b) => b.commit)).toEqual(first.branches.map((b) => b.commit));
    } finally {
      for (const [k, v] of Object.entries(before)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  it("commits under the pinned identity and date, and cuts the stack where the plan says", () => {
    const { gitDir, branches } = first;
    const shown = git(gitDir, ["log", "-1", "--format=%an|%ae|%at|%cn|%ce|%ct", branches[1].commit]).trim();
    const [an, ae, at, cn, ce, ct] = shown.split("|");
    expect([an, cn]).toEqual([PINNED_IDENTITY.name, PINNED_IDENTITY.name]);
    expect([ae, ce]).toEqual([PINNED_IDENTITY.email, PINNED_IDENTITY.email]);
    expect([at, ct]).toEqual([PINNED_DATE.split(" ")[0], PINNED_DATE.split(" ")[0]]);
    // The fix branch is cut from the introduce-the-vuln head, not from the base.
    expect(branches[1].baseCommit).toBe(branches[0].commit);
    expect(branches[0].baseCommit).toBe(first.base.commit);
  });

  it("the base branch holds the repaired bytes, the binary, and nothing that was stripped", () => {
    const { gitDir, base } = first;
    expect(pathsAt(gitDir, base.commit)).toEqual(["a.ts", "bin/run.sh", "logo.png"]);
    expect(fileAt(gitDir, base.commit, "a.ts")).toBe("one\ntwo repaired\nthree\n");
    expect(base.rewritten).toBe(1); // only a.ts differs from the checkout
  });
});

/* -------------------------------------------------------------------------- */
/* What the materialiser refuses                                               */
/* -------------------------------------------------------------------------- */

describe("commitBranches refuses", () => {
  const checkout = writeFixtureCheckout(fresh("checkout"));

  const build = (mutate) => {
    const records = FIXTURE_RECORDS();
    mutate(records);
    return () => buildFixtureRepo(checkout, fresh("repo"), records);
  };

  it("two branches with the same name, because the second would move the first", () => {
    expect(build((r) => (r[1].name = r[0].name))).toThrow(/two branches are named/);
  });

  it("a branch name that is a directory of another, because git cannot hold both refs", () => {
    expect(build((r) => (r[1].name = `${r[0].name}/again`))).toThrow(/one is a directory of the other/);
  });

  it("a branch cut from a base that has not been committed", () => {
    expect(build((r) => (r[1].baseId = "introduce/never-planned"))).toThrow(/has not been committed yet/);
  });

  it("a branch whose tree is its base's, because an empty diff is a pull request with nothing in it", () => {
    expect(build((r) => (r[1].files[0].content = r[0].files[0].content))).toThrow(/empty diff/);
  });
});

/* -------------------------------------------------------------------------- */
/* The git-level verification                                                  */
/* -------------------------------------------------------------------------- */

describe("verifyBranchRepo", () => {
  const checkout = writeFixtureCheckout(fresh("checkout"));
  const built = buildFixtureRepo(checkout, fresh("repo"));

  it("passes the repository it was given", () => {
    expect(verifyBranchRepo(built.gitDir, { baseCommit: built.base.commit, ...built })).toMatchObject({
      ok: true,
      findings: [],
    });
  });

  it("reports a branch whose bytes are not the planned bytes", () => {
    const records = FIXTURE_RECORDS();
    records[0].sha256 = sha256("something else");
    records[0].files[0].sha256 = sha256("something else");
    const report = verifyBranchRepo(built.gitDir, { baseCommit: built.base.commit, branches: built.branches, records });
    expect(report.ok).toBe(false);
    expect(report.findings[0].reason).toMatch(/is not the planned content/);
  });

  it("reports a branch that changes a file the plan does not list — the stale-index failure", () => {
    // Written deliberately the way a leaked index entry would write it: a second file, in a tree
    // that is perfectly valid, on a branch whose record mentions one file.
    const { gitDir, base } = built;
    const index = path.join(gitDir, "extra.index");
    const oid = git(gitDir, ["hash-object", "-w", "--no-filters", "--stdin"], { input: "leaked\n" }).trim();
    const changed = git(gitDir, ["hash-object", "-w", "--no-filters", "--stdin"], { input: "one\nchanged\nthree\n" }).trim();
    const tree = writeTreeOver(gitDir, index, base.commit, [
      { path: "a.ts", oid: changed },
      { path: "bin/run.sh", oid },
    ]);
    const commit = git(gitDir, ["commit-tree", tree, "-p", base.commit, "-m", "two files"]).trim();
    const records = [
      {
        id: "introduce/a",
        name: "fixture/leaky",
        class: "introduce-the-vuln",
        baseId: null,
        files: [{ path: "a.ts", content: "one\nchanged\nthree\n", sha256: sha256("one\nchanged\nthree\n") }],
      },
    ];
    const branches = [
      { id: "introduce/a", name: "fixture/leaky", class: "introduce-the-vuln", base: BASE_BRANCH, baseCommit: base.commit, commit, tree, files: [] },
    ];
    const report = verifyBranchRepo(gitDir, { baseCommit: base.commit, branches, records });
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.reason)).toContain("changes bin/run.sh, which the plan does not list");
  });
});

describe("what a reviewer reads besides the diff (HD-56)", () => {
  it("publishes only main and pr/NNN, and a message naming only the changed paths", () => {
    const { gitDir, base, branches } = buildFixtureRepo(writeFixtureCheckout(fresh("ref-co")), fresh("ref-repo"));
    const refs = git(gitDir, ["for-each-ref", "--format=%(refname:short)"]).trim().split("\n");
    expect(refs.sort()).toEqual(["main", "pr/001", "pr/002"]);
    expect(git(gitDir, ["log", "-1", "--format=%B", base.commit])).toBe(`${BASE_MESSAGE}\n`);
    for (const b of branches) expect(git(gitDir, ["log", "-1", "--format=%B", b.commit])).toBe("Update a.ts\n\n");
  });

  it("refuses a record with no published ref, rather than publishing its plan name", () => {
    const records = FIXTURE_RECORDS();
    delete records[0].ref;
    expect(() => buildFixtureRepo(writeFixtureCheckout(fresh("noref-co")), fresh("noref-repo"), records)).toThrow(/no published ref/);
  });

  it("reports a commit whose message says more than its paths, and a ref that is not pr/NNN", () => {
    const built = buildFixtureRepo(writeFixtureCheckout(fresh("leak-co")), fresh("leak-repo"));
    const { gitDir, base, records } = built;
    const tree = git(gitDir, ["rev-parse", `${built.branches[0].commit}^{tree}`]).trim();
    const leaky = commitTree(gitDir, { tree, parent: base.commit, message: "broken-fix: a.ts\n", branch: "hd85/broken-fix/a" });
    const branches = [{ ...built.branches[0], commit: leaky }];
    const report = verifyBranchRepo(gitDir, { baseCommit: base.commit, branches, records });
    const reasons = report.findings.map((f) => f.reason).join("\n");
    expect(reasons).toMatch(/says more than the paths its diff changes/);
    expect(reasons).toMatch(/neither the base nor pr\/NNN/);
  });

  it("numbers refs by digest, so no class sits in its own number range", () => {
    const names = [...Array(20)].map((_, i) => `hd85/${i < 10 ? "introduce" : "broken-fix"}/x${i}`);
    const refs = publishedRefs(names);
    const firstTen = [...refs].filter(([, ref]) => Number(ref.slice(3)) <= 10).map(([n]) => n);
    expect(firstTen.some((n) => n.includes("introduce"))).toBe(true);
    expect(firstTen.some((n) => n.includes("broken-fix"))).toBe(true);
    expect(publishedRefs(names)).toEqual(refs);
  });
});

describe("diffCommits", () => {
  const checkout = writeFixtureCheckout(fresh("checkout"));
  const built = buildFixtureRepo(checkout, fresh("repo"));

  it("reads back the added and removed lines, with no context between them", () => {
    const diff = diffCommits(built.gitDir, built.base.commit, built.branches[0].commit);
    expect([...diff.keys()]).toEqual(["a.ts"]);
    expect(diff.get("a.ts")).toMatchObject({ added: ["two vulnerable"], removed: ["two repaired"] });
  });
});

/* -------------------------------------------------------------------------- */
/* Conformance — the whole repository, over the pinned corpus                  */
/* -------------------------------------------------------------------------- */

/**
 * What a full generation produced on 2026-09-20, against the corpus at its pin.
 *
 * Pinned rather than recomputed, for the reason `test/controls.test.mjs` pins its own counts: a
 * corpus or a rule that moves them has to fail here and be read as a measurement, instead of
 * quietly becoming the new expectation. The base commit is in the list because the result contract
 * pins a base SHA per class — if this one moves, every result taken against it is unreproducible,
 * and that is exactly the thing this phase exists to make checkable.
 */
const MEASURED = Object.freeze({
  refs: 180,
  branches: 179,
  byClass: Object.freeze({
    "introduce-the-vuln": 22,
    "broken-fix": 87,
    "correct-fix": 35,
    "marked-file": 16,
    "unmarked-file": 19,
  }),
  changedFiles: 183,
  /**
   * Was `1bde2775…` until 2026-09-22 (HD-56), when the base commit's message stopped describing the
   * tree. The tree below did not move, which is the check that only the message did.
   */
  baseCommit: "26123d9fda6a6b9a1c3f2acc339ac4ae10dfe602",
  baseTree: "63d736beedd25f1de89722ff5b12738f01f620b5",
  /**
   * Three branch commits, one per shape: cut from the base, cut from an introduce-the-vuln head,
   * and a control. Pinned as well as the base because a commit hashes its message too — a change
   * to the message this module writes would move all 179 SHAs at once, and two runs of the changed
   * code would still agree with each other. Only a pinned SHA notices that.
   */
  commits: Object.freeze({
    "hd85/introduce/routes-login-ts-17": "e93badea2ab987e87906d29e50f4f1943c7703d6",
    "hd85/correct-fix/loginAdminChallenge_4_correct": "4fa5ff4de2f12476b5f2e6f75f7fc69c1138d9f4",
    "control/unmarked/config-7ms-yml": "cb2285e56ba7ae926bb4213d3bd9a992e14e6bb7",
  }),
  baseFiles: 1138,
  baseRewritten: 19,
  markerMentions: 7,
  /** Blocks in the side-car line map — 23, as phase 4 and phase 5 both measured. */
  blocks: 23,
  /**
   * Branches on which git's hunk anchoring differs from `lineHunks`'s while the lines are the
   * same. All six are `frontend/src/app/app.routing.ts`, which repeats a bare `  {`. See
   * `compareLines` in `src/branch-repo.mjs`: this is why the assertion is on the multiset.
   */
  reanchored: 6,
  /** Roughly eight seconds of wall clock per generation on a laptop, and this suite runs two. */
  generations: 2,
});

const full = haveCorpus ? await generateBranchRepo({ checkout: corpusDir, outRepo: fresh("corpus-repo") }) : null;

describe.skipIf(!haveCorpus)(`the generated repository, against the pinned corpus (${skipReason})`, () => {
  it("writes 179 branches over both planners, at the counts this phase measured", () => {
    expect(full.manifest.counts.total).toBe(MEASURED.branches);
    expect(full.manifest.counts.byClass).toEqual(MEASURED.byClass);
    expect(full.manifest.counts.splice).toBe(144);
    expect(full.manifest.counts.controls).toBe(35);
    expect(full.manifest.counts.changedFiles).toBe(MEASURED.changedFiles);
    const refs = git(full.gitDir, ["show-ref"]).trim().split("\n");
    expect(refs).toHaveLength(MEASURED.refs); // the branches, plus the base they are cut from
  });

  it("MEASURED: the base branch is at the SHA the result contract pins", () => {
    expect(full.manifest.base.commit).toBe(MEASURED.baseCommit);
    expect(full.manifest.base.tree).toBe(MEASURED.baseTree);
    expect(full.manifest.base.files).toBe(MEASURED.baseFiles);
    expect(full.manifest.base.rewritten).toBe(MEASURED.baseRewritten);
    expect(full.manifest.base.lineMap.blocks).toHaveLength(MEASURED.blocks);
  });

  it("MEASURED: three branch commits, one per shape, are at the SHAs this phase published", () => {
    const byName = new Map(full.branches.map((b) => [b.name, b.commit]));
    for (const [name, commit] of Object.entries(MEASURED.commits)) expect([name, byName.get(name)]).toEqual([name, commit]);
  });

  it("the base branch carries no marker, no codefix and no challenges.yml", () => {
    const paths = pathsAt(full.gitDir, full.manifest.base.commit);
    for (const stripped of STRIPPED_PATHS) {
      expect(paths.filter((p) => (stripped.endsWith("/") ? p.startsWith(stripped) : p === stripped))).toEqual([]);
    }
    // `git grep` over the committed tree, not over the map that was committed: the question is
    // what a clone contains. The seven hits are the pinned mentions — prose and a regex source,
    // none of them a marker — and `verifyStripped` has already refused anything else.
    const hits = git(full.gitDir, ["grep", "-c", MARKER_TOKEN, full.manifest.base.commit, "--"]).trim().split("\n");
    const total = hits.reduce((n, line) => n + Number(line.split(":").pop()), 0);
    expect(total).toBe(MEASURED.markerMentions);
  });

  it("holds every branch to its plan at the git level", () => {
    expect(verifyBranchRepo(full.gitDir, {
      baseCommit: full.manifest.base.commit,
      branches: full.branches,
      records: full.records,
    })).toMatchObject({ ok: true, findings: [] });
  });

  it("cuts each fix class from the introduce-the-vuln head for its own block, not from the base", () => {
    const heads = new Map(full.branches.filter((b) => b.class === "introduce-the-vuln").map((b) => [b.name, b.commit]));
    const fixes = full.branches.filter((b) => b.class === "broken-fix" || b.class === "correct-fix");
    expect(fixes).toHaveLength(122);
    for (const fix of fixes) {
      expect(heads.get(fix.base)).toBe(fix.baseCommit);
      expect(fix.baseCommit).not.toBe(full.manifest.base.commit);
    }
    for (const branch of full.branches.filter((b) => b.class.endsWith("-file"))) {
      expect(branch.baseCommit).toBe(full.manifest.base.commit); // controls are cut from the base
    }
  });

  it("shows no marker line in any branch's diff, which is where the answer key would leak", () => {
    for (const branch of full.branches) {
      for (const [, shown] of diffCommits(full.gitDir, branch.baseCommit, branch.commit)) {
        for (const line of [...shown.added, ...shown.removed]) expect(line).not.toContain(MARKER_TOKEN);
      }
    }
  });

  it("makes every control branch exactly one added comment line and nothing else", () => {
    // The control classes are the false-positive denominator. A control whose diff did anything
    // besides insert an inert comment would be measuring something other than nothing.
    for (const branch of full.branches.filter((b) => b.class.endsWith("-file"))) {
      const diff = diffCommits(full.gitDir, branch.baseCommit, branch.commit);
      expect([...diff.keys()]).toEqual(branch.files.map((f) => f.path));
      const shown = diff.get(branch.files[0].path);
      expect(shown.removed).toEqual([]);
      expect(shown.added).toHaveLength(1);
      expect(shown.added[0].trim().endsWith("Part of the OWASP Juice Shop application.")).toBe(true);
    }
  });

  it("MEASURED: six branches are anchored differently by git and carry the same lines anyway", () => {
    // The one disagreement phase 6 found between `git diff` and the `diff` package. Both
    // alignments are minimal; `app.routing.ts` repeats a bare `  {`, so there is more than one
    // minimal alignment and the two pick different ones. Recorded as a measurement because
    // asserting the sequence would be asserting which Myers implementation ran.
    const reanchored = [];
    for (const branch of full.branches) {
      for (const [file, shown] of diffCommits(full.gitDir, branch.baseCommit, branch.commit)) {
        const hunks = lineHunks(fileAt(full.gitDir, branch.baseCommit, file), fileAt(full.gitDir, branch.commit, file));
        const expected = { added: hunks.flatMap((h) => h.insert), removed: hunks.flatMap((h) => h.remove) };
        const sequence = expected.added.join("\n") === shown.added.join("\n") && expected.removed.join("\n") === shown.removed.join("\n");
        const multiset =
          [...expected.added].sort().join("\n") === [...shown.added].sort().join("\n") &&
          [...expected.removed].sort().join("\n") === [...shown.removed].sort().join("\n");
        expect(multiset).toBe(true);
        if (!sequence) reanchored.push({ branch: branch.name, file });
      }
    }
    expect(reanchored).toHaveLength(MEASURED.reanchored);
    expect([...new Set(reanchored.map((r) => r.file))]).toEqual(["frontend/src/app/app.routing.ts"]);
  });

  it("carries no clock, no absolute path and no machine fact in the manifest", () => {
    const json = JSON.stringify(full.manifest);
    expect(json).not.toContain(corpusDir);
    expect(json).not.toContain(os.tmpdir());
    expect(json).not.toContain(os.hostname());
    expect(json).not.toContain(scratch);
    // No ISO timestamp, and no epoch but the declared one.
    expect(json).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/);
    expect(full.manifest.identity.date).toBe(PINNED_DATE);
    expect(full.manifest.corpus.pinnedSha).toBe(PINNED_SHA_OF_CORPUS);
  });

  it("HD-56: every ref is main or pr/NNN, and every message is only the paths its diff changes", () => {
    const refs = git(full.gitDir, ["for-each-ref", "--format=%(refname:short)"]).trim().split("\n");
    expect(refs.filter((r) => r !== BASE_BRANCH && !PUBLISHED_REF.test(r))).toEqual([]);
    expect(git(full.gitDir, ["log", "-1", "--format=%B", full.manifest.base.commit])).toBe(`${BASE_MESSAGE}\n`);
    // Equality with a message built from the paths alone, rather than a scan for words that should
    // not be there: a scan only catches the words somebody thought of.
    const wrong = full.manifest.branches.filter(
      (b) => git(full.gitDir, ["log", "-1", "--format=%B", b.commit]) !== `Update ${b.files.map((f) => f.path).sort().join(", ")}\n\n`,
    );
    expect(wrong.map((b) => b.ref)).toEqual([]);
  });

  it("names the same plan both planners produce, by digest", () => {
    const records = branchRecords(full.plans.branches, full.plans.controls);
    expect(records.map((r) => r.name)).toEqual(full.records.map((r) => r.name));
    expect(full.manifest.planDigest.branches).toBe(sha256(JSON.stringify(full.plans.branches.manifest)));
  });
});

/**
 * The determinism assertion, as two whole generations.
 *
 * Deliberately not a cheaper comparison. Re-running the planners over the same Map would only
 * prove they do not mutate their input; re-committing the same blobs into the same repository
 * would only prove git hashes bytes. What a published result depends on is that a **second run,
 * from the checkout up, on another day** produces the same SHAs — so that is what is run. It costs
 * about eight seconds of wall clock, and it is the single most load-bearing check in this file.
 */
describe.skipIf(!haveCorpus)(`a second generation is byte-identical (${skipReason})`, () => {
  it("agrees on every ref and on the whole manifest", async () => {
    const again = await generateBranchRepo({ checkout: corpusDir, outRepo: fresh("corpus-repo") });
    expect(git(again.gitDir, ["show-ref"])).toBe(git(full.gitDir, ["show-ref"]));
    expect(JSON.stringify(again.manifest)).toBe(JSON.stringify(full.manifest));
    expect(again.manifest.base.commit).toBe(MEASURED.baseCommit);
  }, 120_000);
});
