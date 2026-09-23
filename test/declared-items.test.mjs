import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { BASE_BRANCH, PINNED_DATE, commitTree, diffCommits, fileAt, git, initRepo, writeBlob, writeTreeFrom } from "../src/branch-repo.mjs";
import { DeclaredRefused, applyEdits, extendBranchRepo, planDeclared } from "../src/declared-items.mjs";

/**
 * Everything here is synthetic. Real declarations are answer-key content and live in the private
 * repository; the leak check would refuse them in a fixture, and it would be right to.
 */
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "declared-items-"));
afterAll(() => fs.rmSync(scratch, { recursive: true, force: true }));
let made = 0;
const fresh = (name) => path.join(scratch, `${name}-${made++}`);

const FILES = {
  "lib/a.ts": "export const one = weakThing(1)\nexport const two = 2\nexport const key = 'literal-key-for-tests'\n",
  "lib/b.ts": "import { one } from './a'\ncall(one)\ncall(one)\n",
  "other.ts": "unrelated\n",
};

const FIXES = [
  {
    item: "X1",
    edits: [
      { file: "lib/a.ts", before: "weakThing(1)", after: "strongThing(1)" },
      { file: "lib/b.ts", before: "call(one)", after: "safeCall(one)", count: 2 },
    ],
  },
  {
    item: "X2",
    edits: [{ file: "lib/a.ts", pattern: /^export const key = '.*'\n/m, after: "export const key = process.env.KEY\n" }],
  },
];

/** A bare repository holding `main` and two published branches, as a generation would leave it. */
function seededRepo() {
  const gitDir = initRepo(fresh("repo"));
  const index = path.join(gitDir, "t.index");
  const entries = Object.entries(FILES).map(([p, c]) => ({ path: p, mode: "100644", oid: writeBlob(gitDir, c) }));
  const base = commitTree(gitDir, { tree: writeTreeFrom(gitDir, index, entries), parent: null, message: "Initial import\n", branch: BASE_BRANCH });
  for (const n of ["001", "002"]) {
    const tree = writeTreeFrom(gitDir, index, [...entries.filter((e) => e.path !== "other.ts"), { path: "other.ts", mode: "100644", oid: writeBlob(gitDir, `edit ${n}\n`) }]);
    commitTree(gitDir, { tree, parent: base, message: "Update other.ts\n", branch: `pr/${n}`, date: `${Number(PINNED_DATE.split(" ")[0]) + Number(n)} +0000` });
  }
  return { gitDir, index, base };
}

const refs = (gitDir) =>
  Object.fromEntries(
    git(gitDir, ["for-each-ref", "--format=%(refname:short) %(objectname)"]).trim().split("\n").map((l) => l.split(" ")),
  );

describe("applyEdits", () => {
  it("replaces exact text the stated number of times", () => {
    expect(applyEdits("a b a", [{ before: "a", after: "c", count: 2 }], "t")).toBe("c b c");
  });

  it("refuses text that occurs a different number of times than stated", () => {
    // A line number off by one still applies, to the wrong line. Exact text with a count does not.
    expect(() => applyEdits("a b a", [{ before: "a", after: "c" }], "t")).toThrow(/occurs 2 times, not 1/);
    expect(() => applyEdits("b", [{ before: "a", after: "c" }], "t")).toThrow(/occurs 0 times/);
  });

  it("refuses a pattern that does not match exactly once", () => {
    expect(() => applyEdits("x\nx\n", [{ pattern: /^x$/m, after: "y" }], "t")).toThrow(/matches 2 times/);
    expect(applyEdits("x\nz\n", [{ pattern: /^x$/m, after: "y" }], "t")).toBe("y\nz\n");
  });
});

describe("planDeclared", () => {
  const read = (p) => FILES[p];

  it("reintroduces only the item's own defect in a file two items share", () => {
    const plan = planDeclared({ read, fixes: FIXES });
    const x2 = plan.items.find((i) => i.item === "X2");
    // X1's fix stays applied on X2's introduce-the-vuln branch; only X2's key comes back.
    expect(x2.introduce.get("lib/a.ts")).toContain("strongThing(1)");
    expect(x2.introduce.get("lib/a.ts")).toContain("'literal-key-for-tests'");
    expect([...x2.introduce.keys()]).toEqual(["lib/a.ts"]);
  });

  it("makes every correct-fix branch the fully fixed file", () => {
    const plan = planDeclared({ read, fixes: FIXES });
    for (const item of plan.items) {
      for (const [p, content] of item.correct) expect(content).toBe(plan.fixed.get(p));
    }
  });

  it("refuses two fixes for one item", () => {
    expect(() => planDeclared({ read, fixes: [FIXES[0], { ...FIXES[1], item: "X1" }] })).toThrow(DeclaredRefused);
  });
});

describe("extendBranchRepo", () => {
  it("moves main forward one commit and leaves every existing branch where it was", () => {
    const { gitDir, index, base } = seededRepo();
    const before = refs(gitDir);
    const { manifest } = extendBranchRepo(gitDir, { baseCommit: base, fixes: FIXES, firstNumber: 3, indexFile: index });
    const after = refs(gitDir);

    expect(after["pr/001"]).toBe(before["pr/001"]);
    expect(after["pr/002"]).toBe(before["pr/002"]);
    expect(git(gitDir, ["rev-parse", `${after.main}^`]).trim()).toBe(base);
    expect(manifest.base).toMatchObject({ previous: base, commit: after.main, changedPaths: ["lib/a.ts", "lib/b.ts"] });
  });

  it("numbers the new branches on from firstNumber, an introduce and a correct fix per item", () => {
    const { gitDir, index, base } = seededRepo();
    const { manifest } = extendBranchRepo(gitDir, { baseCommit: base, fixes: FIXES, firstNumber: 3, indexFile: index });
    expect(manifest.branches.map((b) => b.ref).sort()).toEqual(["pr/003", "pr/004", "pr/005", "pr/006"]);
    expect(manifest.counts.byClass).toEqual({ "introduce-the-vuln": 2, "correct-fix": 2 });
  });

  it("cuts each correct fix from its introduce-the-vuln head, back to the new base's tree", () => {
    const { gitDir, index, base } = seededRepo();
    const { manifest } = extendBranchRepo(gitDir, { baseCommit: base, fixes: FIXES, firstNumber: 3, indexFile: index });
    const main = refs(gitDir).main;
    for (const fix of manifest.branches.filter((b) => b.class === "correct-fix")) {
      const intro = manifest.branches.find((b) => b.ref === fix.baseRef);
      expect(intro.class).toBe("introduce-the-vuln");
      expect(intro.baseCommit).toBe(main);
      expect(fix.baseCommit).toBe(intro.commit);
      for (const f of fix.files) expect(fileAt(gitDir, fix.commit, f.path)).toBe(fileAt(gitDir, main, f.path));
    }
  });

  it("shows a reviewer only the item's own lines, under a message naming only paths", () => {
    const { gitDir, index, base } = seededRepo();
    const { manifest } = extendBranchRepo(gitDir, { baseCommit: base, fixes: FIXES, firstNumber: 3, indexFile: index });
    const x1 = manifest.branches.find((b) => b.about.item === "X1" && b.class === "introduce-the-vuln");
    const diff = diffCommits(gitDir, x1.baseCommit, x1.commit);
    expect([...diff.keys()].sort()).toEqual(["lib/a.ts", "lib/b.ts"]);
    expect(diff.get("lib/a.ts").added).toEqual(["export const one = weakThing(1)"]);
    expect(git(gitDir, ["log", "-1", "--format=%B", x1.commit]).trim()).toBe("Update lib/a.ts, lib/b.ts");
    expect(git(gitDir, ["log", "-1", "--format=%B", manifest.base.commit]).trim()).toBe("Update lib/a.ts, lib/b.ts");
  });

  it("is deterministic: two runs on the same repository give the same SHAs", () => {
    const run = () => {
      const { gitDir, index, base } = seededRepo();
      extendBranchRepo(gitDir, { baseCommit: base, fixes: FIXES, firstNumber: 3, indexFile: index });
      return refs(gitDir);
    };
    expect(run()).toEqual(run());
  });

  it("refuses a repository whose main is not the commit the declarations were written against", () => {
    const { gitDir, index } = seededRepo();
    expect(() => extendBranchRepo(gitDir, { baseCommit: "0".repeat(40), fixes: FIXES, firstNumber: 3, indexFile: index })).toThrow(/not 0{40}/);
  });

  it("refuses to run twice, or to number into refs that exist", () => {
    const { gitDir, index, base } = seededRepo();
    expect(() => extendBranchRepo(gitDir, { baseCommit: base, fixes: FIXES, firstNumber: 2, indexFile: index })).toThrow(/pr\/002 already exists/);
    extendBranchRepo(gitDir, { baseCommit: base, fixes: FIXES, firstNumber: 3, indexFile: index });
    expect(() => extendBranchRepo(gitDir, { baseCommit: base, fixes: FIXES, firstNumber: 7, indexFile: index })).toThrow(DeclaredRefused);
  });

  it("refuses a declaration that does not apply to the base, before writing anything", () => {
    const { gitDir, index, base } = seededRepo();
    const before = refs(gitDir);
    const bad = [{ item: "X9", edits: [{ file: "lib/a.ts", before: "not in the file", after: "x" }] }];
    expect(() => extendBranchRepo(gitDir, { baseCommit: base, fixes: bad, firstNumber: 3, indexFile: index })).toThrow(DeclaredRefused);
    expect(refs(gitDir)).toEqual(before);
  });

});
