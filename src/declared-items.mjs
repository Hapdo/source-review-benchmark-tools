/**
 * Declared items: defects upstream never marked, added to a generated repository after the fact.
 *
 * ## What this is for
 *
 * Every other branch here is derived from Juice Shop's own markers and `codefixes/`. A declared
 * item has neither: its site and its fix were chosen by whoever labelled it, and together they say
 * which unmarked lines the benchmark scores. That is answer-key content, so **it is not in this
 * repository**. This module takes it from a file it is handed — the private answer-key
 * repository's `src/declared.mjs` — and knows nothing about any particular item.
 *
 * ## The shape it produces
 *
 * The repository already holds `main` and `pr/001`…, and those refs may already be published and
 * read back. So nothing existing is rewritten:
 *
 * - `main` gains **one commit** on top of the commit the declarations were written against, which
 *   applies every declared fix. It fast-forwards, and every existing branch keeps its SHA. For those
 *   branches the declared sites are simply code their base still carries.
 * - Each item gets an **introduce-the-vuln** branch cut from the new `main`, carrying every declared
 *   fix except its own, and a **correct-fix** branch cut from that head, putting its own fix back —
 *   the same two classes, cut the same way, as the splice-derived items. There is no broken-fix
 *   class: upstream wrote no broken variants for these, and inventing some would be inventing
 *   answers.
 * - The new branches are numbered on from `firstNumber` in {@link publishedOrder}, so their numbers
 *   say nothing about their class either.
 *
 * ## What a declared fix is
 *
 * `{ item, edits: [{ file, before | pattern, after, count? }] }`. `before` is exact text that must
 * occur exactly `count` times (default once) in the file at the base; `pattern` is a RegExp that
 * must match exactly once. Exact text rather than line numbers, because a line number that is off
 * by one still applies, and applies to the wrong line.
 */
import { sha256 } from "./base-tree.mjs";
import {
  BASE_BRANCH,
  PINNED_DATE,
  RepoRefused,
  commitBranches,
  commitTree,
  fileAt,
  git,
  neutralMessage,
  publishedOrder,
  verifyBranchRepo,
  writeBlob,
  writeTreeOver,
} from "./branch-repo.mjs";

export class DeclaredRefused extends Error {
  constructor(message) {
    super(message);
    this.name = "DeclaredRefused";
  }
}

/** Every occurrence of `needle` in `haystack`, by index. */
function occurrences(haystack, needle) {
  const at = [];
  for (let i = haystack.indexOf(needle); i !== -1; i = haystack.indexOf(needle, i + 1)) at.push(i);
  return at;
}

/**
 * Apply one item's edits to one file's content, refusing anything that does not match exactly.
 *
 * @param {string} content
 * @param {Array<{before?: string, pattern?: RegExp, after: string, count?: number}>} edits
 * @param {string} where for the error message
 */
export function applyEdits(content, edits, where) {
  let out = content;
  for (const [i, edit] of edits.entries()) {
    const label = `${where} edit ${i + 1}`;
    if (typeof edit.after !== "string") throw new DeclaredRefused(`${label} has no replacement text`);
    if (edit.pattern instanceof RegExp) {
      const flags = edit.pattern.flags.includes("g") ? edit.pattern.flags : `${edit.pattern.flags}g`;
      const matches = [...out.matchAll(new RegExp(edit.pattern.source, flags))];
      if (matches.length !== 1) throw new DeclaredRefused(`${label}: the pattern matches ${matches.length} times, not once`);
      out = out.slice(0, matches[0].index) + edit.after + out.slice(matches[0].index + matches[0][0].length);
      continue;
    }
    if (typeof edit.before !== "string" || edit.before === "") throw new DeclaredRefused(`${label} names no text to replace`);
    const want = edit.count ?? 1;
    const found = occurrences(out, edit.before).length;
    if (found !== want) throw new DeclaredRefused(`${label}: the text to replace occurs ${found} times, not ${want}`);
    out = out.split(edit.before).join(edit.after);
  }
  return out;
}

/** The files a set of fixes touches, in first-mention order. */
function filesOf(fixes) {
  return [...new Set(fixes.flatMap((f) => f.edits.map((e) => e.file)))];
}

/** Apply `fixes`, in order, to `path`'s content at the base. */
function applyFixes(read, fixes, path) {
  let content = read(path);
  for (const fix of fixes) {
    const edits = fix.edits.filter((e) => e.file === path);
    if (edits.length > 0) content = applyEdits(content, edits, `${fix.item} on ${path}`);
  }
  return content;
}

/**
 * Plan the declared items against a base: the fixed files, and each item's two branches.
 *
 * An item's introduce-the-vuln files are the base with **every other** item's fix applied, so an
 * item that shares a file with another reintroduces only its own defect. Its correct-fix files are
 * the fully fixed ones. The two are checked against each other: reapplying the item's own edits to
 * its introduce-the-vuln files must give the fixed files exactly, or the fixes do not commute and
 * the correct-fix branch would not be the fix.
 *
 * @param {{read: (path: string) => string, fixes: Array<{item: string, edits: object[]}>}} input
 */
export function planDeclared({ read, fixes }) {
  if (!Array.isArray(fixes) || fixes.length === 0) throw new DeclaredRefused("there are no declared fixes");
  const ids = fixes.map((f) => f.item);
  if (new Set(ids).size !== ids.length) throw new DeclaredRefused("two declared fixes name the same item");

  const fixed = new Map(filesOf(fixes).map((path) => [path, applyFixes(read, fixes, path)]));
  for (const [path, content] of fixed) {
    if (content === read(path)) throw new DeclaredRefused(`the declared fixes leave ${path} unchanged`);
  }

  const items = fixes.map((fix) => {
    const others = fixes.filter((f) => f !== fix);
    const introduce = new Map();
    for (const path of filesOf([fix])) {
      const vulnerable = applyFixes(read, others, path);
      const refixed = applyEdits(vulnerable, fix.edits.filter((e) => e.file === path), `${fix.item} on ${path}`);
      if (refixed !== fixed.get(path)) {
        throw new DeclaredRefused(`${fix.item}'s fix does not commute with the others on ${path}`);
      }
      if (vulnerable === fixed.get(path)) throw new DeclaredRefused(`${fix.item} does not change ${path}`);
      introduce.set(path, vulnerable);
    }
    const correct = new Map([...introduce.keys()].map((path) => [path, fixed.get(path)]));
    return { item: fix.item, introduce, correct };
  });
  return { fixed, items };
}

/** The refs a repository holds, as `short name → commit`. */
function refsOf(gitDir) {
  const out = new Map();
  for (const line of git(gitDir, ["for-each-ref", "--format=%(objectname) %(refname:short)"]).split("\n").filter(Boolean)) {
    const [commit, name] = line.split(" ");
    out.set(name, commit);
  }
  return out;
}

/**
 * Add the declared items to a generated repository, in place.
 *
 * Refuses unless `main` is exactly `baseCommit`, the commit the declarations were written against,
 * and unless no ref already carries a number from `firstNumber` up — so it cannot run twice, and it
 * cannot run on a repository it was not written for. Every ref that existed before is checked
 * afterwards to still be where it was.
 *
 * @param {string} gitDir a bare repository written by `generateBranchRepo`
 * @param {{baseCommit: string, fixes: object[], firstNumber: number, indexFile: string}} input
 */
export function extendBranchRepo(gitDir, { baseCommit, fixes, firstNumber, indexFile }) {
  const before = refsOf(gitDir);
  if (before.get(BASE_BRANCH) !== baseCommit) {
    throw new DeclaredRefused(`${BASE_BRANCH} is at ${before.get(BASE_BRANCH) ?? "nothing"}, not ${baseCommit}, which the declarations were written against`);
  }
  if (!Number.isInteger(firstNumber) || firstNumber < 1) throw new DeclaredRefused("firstNumber must be a positive integer");
  for (const name of before.keys()) {
    const m = /^pr\/(\d+)$/.exec(name);
    if (m && Number(m[1]) >= firstNumber) throw new DeclaredRefused(`${name} already exists, so numbering from ${firstNumber} would collide`);
  }

  const plan = planDeclared({ read: (path) => fileAt(gitDir, baseCommit, path), fixes });

  // The new base: one commit on the old one, carrying every declared fix.
  const changed = [...plan.fixed.keys()].sort();
  const baseTree = writeTreeOver(
    gitDir,
    indexFile,
    baseCommit,
    changed.map((path) => ({ path, oid: writeBlob(gitDir, plan.fixed.get(path)) })),
  );
  const baseMessage = neutralMessage(changed);
  const newBase = commitTree(gitDir, { tree: baseTree, parent: baseCommit, message: baseMessage, branch: BASE_BRANCH, date: PINNED_DATE });

  const records = [];
  for (const { item, introduce, correct } of plan.items) {
    const introduceId = `declared/introduce-the-vuln/${item}`;
    records.push({
      id: introduceId,
      name: introduceId,
      class: "introduce-the-vuln",
      baseId: null,
      files: [...introduce].map(([path, content]) => ({ path, content, sha256: sha256(content) })),
      about: { item, declared: true },
    });
    records.push({
      id: `declared/correct-fix/${item}`,
      name: `declared/correct-fix/${item}`,
      class: "correct-fix",
      baseId: introduceId,
      files: [...correct].map(([path, content]) => ({ path, content, sha256: sha256(content) })),
      about: { item, declared: true },
    });
  }
  const width = Math.max(3, String(firstNumber + records.length - 1).length);
  const numbered = new Map(publishedOrder(records.map((r) => r.name)).map((name, i) => [name, `pr/${String(firstNumber + i).padStart(width, "0")}`]));
  for (const record of records) record.ref = numbered.get(record.name);

  // Commit introduce-the-vuln heads before the fixes cut from them, whatever the published order.
  const branches = commitBranches(gitDir, indexFile, { baseCommit: newBase, records });
  const report = verifyBranchRepo(gitDir, { baseCommit: newBase, branches, records, baseMessage });

  const after = refsOf(gitDir);
  for (const [name, commit] of before) {
    if (name === BASE_BRANCH) continue;
    if (after.get(name) !== commit) report.findings.push({ branch: name, reason: `moved from ${commit} to ${after.get(name) ?? "nothing"}` });
  }
  const parents = git(gitDir, ["rev-list", "--parents", "-n", "1", newBase]).trim().split(" ");
  if (parents[1] !== baseCommit || parents.length !== 2) report.findings.push({ branch: BASE_BRANCH, reason: "the new base is not a single commit on the old one" });
  report.ok = report.findings.length === 0;
  if (!report.ok) {
    throw new RepoRefused(
      `${report.findings.length} problems with the declared branches: ` +
        report.findings.slice(0, 5).map((f) => `${f.branch} — ${f.reason}`).join("; "),
    );
  }

  return {
    manifest: {
      generatedBy: "HD-56 — declared items, on one new base commit",
      base: {
        branch: BASE_BRANCH,
        previous: baseCommit,
        commit: newBase,
        tree: baseTree,
        changedPaths: changed,
      },
      /** Ties this extension to the exact declarations it applied, without restating them. */
      declaredDigest: sha256(JSON.stringify(fixes, (_, v) => (v instanceof RegExp ? String(v) : v))),
      counts: {
        total: branches.length,
        byClass: Object.fromEntries(["introduce-the-vuln", "correct-fix"].map((c) => [c, branches.filter((b) => b.class === c).length])),
        changedFiles: branches.reduce((n, b) => n + b.files.length, 0),
      },
      branches: branches.map((b) => ({
        ref: b.ref,
        baseRef: b.baseRef,
        sameChangeAs: [],
        name: b.name,
        class: b.class,
        about: records.find((r) => r.id === b.id).about,
        base: b.base,
        baseCommit: b.baseCommit,
        commit: b.commit,
        tree: b.tree,
        files: b.files,
      })),
      verification: { ok: report.ok, branches: report.branches, findings: report.findings },
    },
    branches,
  };
}
