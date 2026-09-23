/**
 * Turning the branch plans into actual git branches, in a repository, reproducibly.
 *
 * `src/branches.mjs` and `src/controls.mjs` are planners: they take the corpus and emit branch
 * records — class, name, base, file contents, scorer expectations — with no git, no clock and no
 * absolute path anywhere in them, and both are asserted byte-identical across two independent
 * runs. This module is the other half. It takes those records and writes the objects and refs a
 * reviewer will actually fetch.
 *
 * ## Why determinism is harder here than in the planners
 *
 * A planner is a function of its input, so "same corpus, same plan" is nearly free. A git commit
 * is not: it embeds an author name, an author email, a committer name, a committer email and two
 * timestamps, and it hashes all of them. Left alone, every run produces different commit SHAs for
 * byte-identical trees — and the result contract pins **a base SHA per class**, so a SHA that
 * moves per run makes every result taken against it unreproducible. Worse, the leak is silent:
 * nothing errors, the branches all look right, and only a second run reveals it.
 *
 * So every one of those six fields is pinned ({@link PINNED_IDENTITY}, {@link PINNED_DATE}), and
 * the machine's own git configuration is not merely overridden but *removed* from the run
 * ({@link gitEnv}). The local machine this was written on is the argument for the second half:
 * its global config sets `user.name`, `core.pager=delta`, `interactive.difffilter` and
 * `init.defaultBranch=main`, and the corpus's own `.gitattributes` sets `eol=lf` on a directory.
 * Any of those reaching a `git` invocation here changes either what is committed or what a
 * verification reads back.
 *
 * ## Why this writes objects and never a working tree
 *
 * Everything below is git plumbing over an explicit index file: `hash-object`, `update-index`,
 * `write-tree`, `commit-tree`, `update-ref`. There is no checkout at any point, and the
 * repository is created bare. That is not an optimisation — a working tree is exactly where the
 * remaining nondeterminism lives. `core.autocrlf` rewrites line endings on the way in,
 * `core.fileMode` decides whether an executable bit is recorded, `.gitattributes` filters run on
 * `git add`, and hooks run on `git commit`. The index-level path touches none of them: the mode
 * is stated by this module, the bytes are the planner's bytes, and `commit-tree` runs no hook.
 *
 * ## The order is splice-then-strip, and it has to be
 *
 * Splicing needs the marker comments — they are how a block is located — and the scored tree has
 * none. So the base branch is the *repaired* tree with markers, `data/static/codefixes/` and
 * `data/static/challenges.yml` removed, and each branch's files are the planner's **scored**
 * bytes: spliced first, stripped second. {@link verifyBranchRepo} then asserts at the git level
 * what `src/branches.mjs` asserted per file — that the diff a reviewer sees is the intended edit
 * with the markers taken off, and not a diff that also reverts, moves or re-adds a marker line.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { MARKER_TOKEN } from "./markers.mjs";
import { PINNED_SHA, buildBaseTree, lineHunks, sha256 } from "./base-tree.mjs";
import { STRIPPED_PATHS, stripMarkers, stripTree, verifyStripped } from "./strip.mjs";
import { planBranches } from "./branches.mjs";
import { planControlBranches } from "./controls.mjs";
import { readCodefixes, readTree } from "./corpus.mjs";

/** Raised for anything that would produce a repository this module cannot vouch for. */
export class RepoRefused extends Error {
  constructor(message) {
    super(message);
    this.name = "RepoRefused";
  }
}

/* -------------------------------------------------------------------------- */
/* What is pinned                                                              */
/* -------------------------------------------------------------------------- */

/**
 * The branch the whole benchmark is cut from. Every other ref names it, directly or by parent.
 *
 * `main`, because this is the ref the mirror publishes and a reviewer is shown: a name like
 * `hd85/base` says the repository is a benchmark before a single line has been read. The plan's own
 * names survive in the manifest, which stays private; see {@link PUBLISHED_REF}.
 */
export const BASE_BRANCH = "main";

/**
 * Every published branch other than the base: `pr/001` to `pr/179`, and nothing else.
 *
 * **The reviewer reads ref names and commit messages, and the plan's names are the answer key.**
 * `hd85/broken-fix/accessLogDisclosureChallenge_2` names the class, the challenge and the variant;
 * `control/marked/…` says "expect nothing here"; and a fix branch's parent commit said
 * `introduce-the-vuln` in its subject. BM-04 ruled that the answer key leaves every scored tree,
 * and a ref name or a commit message is the same leak through the one channel the file-content
 * checks never read. Found on 2026-09-22 (HD-56), before anything was pushed.
 *
 * The number is the branch's position in {@link publishedOrder}, not in the plan, because the plan
 * is ordered by class and a sorted order would put each class in its own number range.
 */
export const PUBLISHED_REF = /^pr\/\d{3}$/;

/**
 * The author and committer of every commit here.
 *
 * `.invalid` is reserved by RFC 2606 and can never be delivered to, which is the point: these
 * commits are generated, nobody is reachable at their address, and an address that *could* be
 * delivered to would invite somebody to try.
 */
export const PINNED_IDENTITY = Object.freeze({
  name: "HapDo Benchmark",
  email: "benchmark@hapdo.invalid",
});

/**
 * The author and committer date of every commit, as git's raw `<epoch> <tz>` form.
 *
 * Raw rather than an ISO string on purpose: git parses a date string through the local timezone
 * and through `TZ`, so an ISO string without an offset is a machine fact wearing a constant's
 * clothes. `1767225600` is 2026-01-01T00:00:00Z, and `+0000` says so in the commit object itself.
 */
export const PINNED_DATE = "1767225600 +0000";

/**
 * A branch commit's date: {@link PINNED_DATE} plus the branch's published number, in seconds.
 *
 * **Every branch commit must be a different commit**, because GitHub attaches check runs to a
 * commit and not to a pull request: two pull requests with one head SHA share one `review/*`
 * check, and the benchmark cannot score them separately. Twelve branches are byte-identical to
 * another — several challenge keys' fixes are the same edit to one file — and once the messages
 * stopped naming the key (HD-56), identical tree, parent, message and date made identical SHAs.
 * The date is what differs now. It is derived from `pr/NNN`, which is already public and already
 * meaningless, so it says nothing a reviewer could use; and it is deterministic, so two runs agree.
 */
export function publishedDate(ref) {
  const n = Number(ref.slice(ref.lastIndexOf("/") + 1));
  if (!Number.isInteger(n) || n < 1) throw new RepoRefused(`${ref} carries no branch number to date it by`);
  return `${Number(PINNED_DATE.split(" ")[0]) + n} +0000`;
}

/**
 * Configuration forced into the created repository, each because of what it would otherwise take
 * from the machine. Written into the repository's own config so that a later `git` run by a human
 * in this repository sees the same settings the generation did.
 */
export const PINNED_CONFIG = Object.freeze({
  /** Line endings are the planner's bytes. Nothing rewrites them on the way in or out. */
  "core.autocrlf": "false",
  /** Modes are stated by {@link fileMode}, not discovered from a filesystem that may not carry them. */
  "core.fileMode": "false",
  /** `commit-tree` runs no hook, but a human in this repository later would. */
  "core.hooksPath": "/dev/null",
  /** A signature embeds a key and a time. Both are machine facts and both change the commit SHA. */
  "commit.gpgsign": "false",
  "tag.gpgsign": "false",
  /** Packing is not load-bearing here, and a background gc makes a run's timing unrepeatable. */
  "gc.auto": "0",
  /**
   * The diff this module reads back must be the diff the reviewer sees, not a rendered one. An
   * *empty* `diff.external` is not the way to say that and was tried first: git reads it as a
   * command named "" and every later `git diff` in the repository dies on the first file. The
   * generation passes `--no-ext-diff` per call instead, and this repository simply carries no
   * external differ, no pager and no move detection of its own.
   */
  "core.pager": "cat",
  "diff.noprefix": "false",
  "diff.colorMoved": "no",
});

/**
 * Environment variables emptied out of every `git` invocation.
 *
 * `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_ATTR_NOSYSTEM` and `GIT_PAGER` are not here
 * because they are *set* by {@link gitEnv} instead: `/dev/null` and `1` say "there is no such
 * file", where unset would say "look in the usual place", and a pager has to be named to be
 * replaced. The list and the assignments must not overlap — a variable in both would be cleared
 * and then set, and the test that walks this list would be asserting the opposite of what happens. The rest are cleared because a parent process that had them
 * set — a hook, a CI step, an editor's integrated terminal — would otherwise aim this at another
 * repository entirely, or hand it an identity, or wrap its diff in a pager.
 */
export const NEUTRALISED_ENV = Object.freeze([
  "GIT_DIR",
  "GIT_WORK_TREE",
  "GIT_INDEX_FILE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_NAMESPACE",
  "GIT_CEILING_DIRECTORIES",
  "GIT_PREFIX",
  "GIT_COMMON_DIR",
  "GIT_CONFIG",
  "GIT_CONFIG_COUNT",
  "GIT_EDITOR",
  "GIT_EXTERNAL_DIFF",
  "GIT_SSH",
  "GIT_SSH_COMMAND",
  "GIT_ASKPASS",
  "GIT_PROXY_COMMAND",
]);

/**
 * Directories that are never part of the repository, mirroring `src/corpus.mjs`'s own skip list.
 *
 * It is restated rather than imported because `corpus.mjs` does not export it, and the two lists
 * have to agree: a directory this walk copies but `readTree` skipped would reach the repository
 * as bytes no planner ever saw and no check ever read.
 */
export const NOT_IN_THE_REPOSITORY = Object.freeze([".git", "node_modules", "dist", "build", "coverage"]);

/**
 * The corpus pin, re-exported from `src/base-tree.mjs` rather than written out again, so that the
 * manifest's `pinnedSha` and the base tree's are provably the same string.
 */
export const PINNED_SHA_OF_CORPUS = PINNED_SHA;

/** Git's two file modes for a regular file. A tree here holds nothing else — see {@link walkCheckout}. */
const MODE_FILE = "100644";
const MODE_EXEC = "100755";

/* -------------------------------------------------------------------------- */
/* Running git                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * The environment every `git` here runs in: the caller's, minus everything in
 * {@link NEUTRALISED_ENV}, plus the pinned identity, dates, config isolation and a C locale.
 *
 * @param {Record<string, string>} [extra] per-call additions, e.g. `GIT_INDEX_FILE`
 */
export function gitEnv(extra = {}) {
  const env = { ...process.env };
  for (const name of NEUTRALISED_ENV) delete env[name];
  return {
    ...env,
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_AUTHOR_NAME: PINNED_IDENTITY.name,
    GIT_AUTHOR_EMAIL: PINNED_IDENTITY.email,
    GIT_COMMITTER_NAME: PINNED_IDENTITY.name,
    GIT_COMMITTER_EMAIL: PINNED_IDENTITY.email,
    GIT_AUTHOR_DATE: PINNED_DATE,
    GIT_COMMITTER_DATE: PINNED_DATE,
    GIT_TERMINAL_PROMPT: "0",
    GIT_PAGER: "cat",
    LC_ALL: "C",
    TZ: "UTC",
    ...extra,
  };
}

/**
 * Run one git command against a repository and return its stdout.
 *
 * Failure throws with git's own stderr attached. A silent nonzero here would leave a repository
 * missing a ref, which reads downstream as "the plan did not include that branch".
 *
 * @param {string} gitDir the repository directory
 * @param {string[]} args
 * @param {{input?: string|Buffer, encoding?: "utf8"|"buffer", indexFile?: string, env?: Record<string, string>}} [options]
 */
export function git(gitDir, args, options = {}) {
  const env = gitEnv({ ...(options.indexFile ? { GIT_INDEX_FILE: options.indexFile } : {}), ...(options.env ?? {}) });
  const result = spawnSync("git", ["--git-dir", gitDir, ...args], {
    env,
    input: options.input,
    encoding: options.encoding === "buffer" ? "buffer" : "utf8",
    maxBuffer: 512 * 1024 * 1024,
  });
  if (result.error) throw new RepoRefused(`git ${args[0]} could not start: ${result.error.message}`);
  if (result.status !== 0) {
    const stderr = (result.stderr ?? "").toString().trim();
    throw new RepoRefused(`git ${args.join(" ")} exited ${result.status}: ${stderr}`);
  }
  return result.stdout;
}

/**
 * Create the bare repository the branches are written into.
 *
 * Bare, and refusing a directory that already holds anything, for the reason `bin/build-base.mjs`
 * gives about its output directory: a run has to describe all of what it produced, and a
 * repository with refs from an earlier run has refs this manifest does not vouch for.
 *
 * `--initial-branch` is passed explicitly because `init.defaultBranch` is a per-machine setting,
 * and the default HEAD is what a clone checks out.
 */
export function initRepo(dir) {
  if (fs.existsSync(dir) && fs.readdirSync(dir).length > 0) {
    throw new RepoRefused(`${dir} is not empty; the branch repository is generated into a fresh directory`);
  }
  fs.mkdirSync(dir, { recursive: true });
  const env = gitEnv();
  const init = spawnSync("git", ["init", "--bare", "--quiet", "--object-format=sha1", `--initial-branch=${BASE_BRANCH}`, dir], {
    env,
    encoding: "utf8",
  });
  if (init.status !== 0) throw new RepoRefused(`git init failed: ${(init.stderr ?? "").trim()}`);
  for (const [key, value] of Object.entries(PINNED_CONFIG)) git(dir, ["config", key, value]);
  return dir;
}

/* -------------------------------------------------------------------------- */
/* Objects                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Write one blob from bytes this process holds, and return its object id.
 *
 * `--no-filters` on every hashing call in this module, including the batched one below: without
 * it git applies the target path's `.gitattributes` — the corpus ships one, setting `eol=lf` on a
 * directory — so the bytes committed would not be the bytes the planner hashed, and the two
 * digests in the manifest would disagree about the same file.
 */
export function writeBlob(gitDir, content) {
  const out = git(gitDir, ["hash-object", "-w", "--no-filters", "--stdin"], {
    input: Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8"),
  });
  return out.trim();
}

/**
 * Write many blobs straight from files on disk, in one git process.
 *
 * The base tree is about 1,100 files and all but a few dozen are byte-identical to the checkout,
 * so hashing those from their paths costs one process instead of eleven hundred. The order out
 * matches the order in, which is what makes the result usable as a parallel array.
 */
export function writeBlobsFromPaths(gitDir, absolutePaths) {
  if (absolutePaths.length === 0) return [];
  const out = git(gitDir, ["hash-object", "-w", "--no-filters", "--stdin-paths"], {
    input: `${absolutePaths.join("\n")}\n`,
  });
  const ids = out.trim().split("\n");
  if (ids.length !== absolutePaths.length) {
    throw new RepoRefused(`hash-object returned ${ids.length} ids for ${absolutePaths.length} paths`);
  }
  return ids;
}

/**
 * Build a tree from a complete list of `{path, mode, oid}` entries and return its object id.
 *
 * The index is an explicit file outside the repository's own, and it is written from scratch
 * (`--index-info` replaces nothing it is not given, so the caller states every entry). A stale
 * index entry is the failure this shape rules out: it would put a file from a previous branch into
 * the next branch's tree, and the tree would still be a valid tree.
 */
export function writeTreeFrom(gitDir, indexFile, entries) {
  fs.rmSync(indexFile, { force: true });
  git(gitDir, ["update-index", "--index-info"], {
    indexFile,
    input: entries.map((e) => `${e.mode} ${e.oid}\t${e.path}`).join("\n") + "\n",
  });
  return git(gitDir, ["write-tree"], { indexFile }).trim();
}

/**
 * Build a tree that is another commit's tree with a handful of files replaced.
 *
 * `read-tree` then `update-index` rather than a full entry list, because a branch changes one to
 * three files out of eleven hundred and restating the other eleven hundred would make this a
 * function of the base's contents rather than of the branch's edit.
 *
 * Each replaced file keeps **the mode the base gives it**, read back out of the index rather than
 * assumed to be `100644`. Every path any plan changes is source, and all of it is `100644` today —
 * but a branch that silently cleared an executable bit would show up in `git diff` as a mode line
 * and nowhere else, and a mode line is not an edit any plan asked for. A path the base does not
 * have is refused for the same reason: no class here adds a file, so a missing one is a bug in the
 * plan and not a new file to invent a mode for.
 */
export function writeTreeOver(gitDir, indexFile, baseCommit, files) {
  fs.rmSync(indexFile, { force: true });
  git(gitDir, ["read-tree", baseCommit], { indexFile });

  const staged = new Map();
  for (const line of git(gitDir, ["ls-files", "--stage", "--", ...files.map((f) => f.path)], { indexFile }).split("\n")) {
    const m = /^(\d{6}) [0-9a-f]+ \d\t(.*)$/.exec(line);
    if (m) staged.set(m[2], m[1]);
  }

  const entries = files.map((f) => {
    const mode = staged.get(f.path);
    if (mode === undefined) throw new RepoRefused(`${f.path} is not in the base tree, and no branch class adds a file`);
    return `${mode} ${f.oid}\t${f.path}`;
  });
  git(gitDir, ["update-index", "--index-info"], { indexFile, input: `${entries.join("\n")}\n` });
  return git(gitDir, ["write-tree"], { indexFile }).trim();
}

/**
 * The order the published refs are numbered in: by a digest of each plan name.
 *
 * Deterministic, because the SHAs and the numbers are pinned and two runs must agree. Not secret:
 * the salt and the names are both in this public repository, so anyone holding the tooling can
 * recompute the mapping. That is acceptable because the mapping is hidden from the **reviewer**,
 * which reads a pull request, not this code — and the mapping itself is recorded only in the
 * private manifest.
 */
export function publishedOrder(names) {
  const key = (name) => sha256(`hd85 published order\0${name}`);
  return [...names].sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
}

/** `pr/001`…, assigned over {@link publishedOrder}. */
export function publishedRefs(names) {
  const width = Math.max(3, String(names.length).length);
  return new Map(publishedOrder(names).map((name, i) => [name, `pr/${String(i + 1).padStart(width, "0")}`]));
}

/**
 * The only commit message a branch commit may carry: the paths its diff changes, and nothing more.
 *
 * A function of the diff and of nothing else, so that it cannot say anything the diff does not
 * already show — and {@link verifyBranchRepo} asserts exactly that equality against the paths git
 * reports, rather than scanning the message for words it should not contain.
 */
export function neutralMessage(paths) {
  return `Update ${[...paths].sort().join(", ")}\n`;
}

/** Commit a tree under the pinned identity and date, and point a branch at it. */
export function commitTree(gitDir, { tree, parent, message, branch, date }) {
  const args = ["commit-tree", tree];
  if (parent) args.push("-p", parent);
  args.push("-m", message);
  const env = date ? { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date } : {};
  const commit = git(gitDir, args, { env }).trim();
  git(gitDir, ["update-ref", `refs/heads/${branch}`, commit]);
  return commit;
}

/* -------------------------------------------------------------------------- */
/* The base branch                                                             */
/* -------------------------------------------------------------------------- */

/**
 * The repaired base tree, stripped, with the strip verified **before** anything is committed.
 *
 * Before, not after, because a commit is the thing that gets fetched: a marker that reached an
 * object is in the repository's history whatever a later check says, and the history is what the
 * reviewer clones. `verifyStripped` is the check that a half-working stripper does not pass
 * silently — its failure mode is an inflated score, not a crash.
 *
 * @param {Map<string, string>} upstream the corpus at its pin
 * @param {Map<string, string>} codefixes `data/static/codefixes/`
 */
export async function buildScoredBase(upstream, codefixes) {
  const built = await buildBaseTree(upstream, codefixes, { sha: null });
  const stripped = stripTree(built.tree);
  const verdict = verifyStripped(stripped.tree);
  if (!verdict.ok) {
    throw new RepoRefused(
      `the stripped base tree did not verify, so nothing was committed: ` +
        verdict.findings.map((f) => `${f.path}${f.line == null ? "" : `:${f.line}`} — ${f.reason}`).join("; "),
    );
  }
  return {
    marked: built.tree,
    scored: stripped.tree,
    lineMap: stripped.lineMap,
    dropped: stripped.dropped,
    changed: built.changed,
    mentions: verdict.mentions,
  };
}

/** `100755` when the checkout carries any execute bit, `100644` otherwise. Nothing else. */
function fileMode(stat) {
  return (stat.mode & 0o111) === 0 ? MODE_FILE : MODE_EXEC;
}

/** Whether a path leaves every scored tree, by {@link STRIPPED_PATHS}'s own file-or-prefix rule. */
function isStrippedPath(rel) {
  return STRIPPED_PATHS.some((p) => (p.endsWith("/") ? rel.startsWith(p) : rel === p));
}

/**
 * Every file the repository's base branch holds, as `{path, mode, abs}`, sorted.
 *
 * The walk is over the **checkout**, not over the scored map, so that the repository is Juice Shop
 * — images, fonts and all — rather than only the text `readTree` could carry. `bin/build-base.mjs`
 * does the same thing for the same reason, and by the same means: copy everything, then replace
 * what changed.
 *
 * Two refusals: a symlink, because a tree entry of mode `120000` has bytes nobody here has
 * checked; and a path carrying a tab or a newline, because `update-index --index-info` delimits on
 * a tab, so such a path would silently land somewhere else.
 */
export function walkCheckout(checkout) {
  const out = [];
  const walk = (rel) => {
    const abs = rel === "" ? checkout : path.join(checkout, rel);
    const entries = fs.readdirSync(abs, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const entry of entries) {
      const childRel = rel === "" ? entry.name : `${rel}/${entry.name}`;
      if (entry.isSymbolicLink()) throw new RepoRefused(`${childRel} is a symlink; the corpus is expected to hold none`);
      if (entry.isDirectory()) {
        if (NOT_IN_THE_REPOSITORY.includes(entry.name)) continue;
        walk(childRel);
        continue;
      }
      if (!entry.isFile()) throw new RepoRefused(`${childRel} is neither a regular file nor a directory`);
      if (/[\t\n]/.test(childRel)) throw new RepoRefused(`${childRel} carries a tab or newline and cannot be indexed`);
      if (isStrippedPath(childRel)) continue;
      const childAbs = path.join(checkout, childRel);
      out.push({ path: childRel, mode: fileMode(fs.statSync(childAbs)), abs: childAbs });
    }
  };
  walk("");
  return out.sort((a, b) => (a.path < b.path ? -1 : 1));
}

/**
 * Commit the scored base tree as {@link BASE_BRANCH}.
 *
 * Every file whose scored bytes are the checkout's bytes is hashed from its path in one batched
 * call; the few dozen the repair and the strip actually changed are hashed from memory. The split
 * is a speed one and it is also a check: a file the scored map holds but the walk never saw is a
 * path that would reach no branch, and it throws rather than being dropped.
 */
export function commitScoredBase(gitDir, indexFile, { checkout, scored }) {
  const files = walkCheckout(checkout);
  const seen = new Set(files.map((f) => f.path));
  for (const rel of scored.keys()) {
    if (!seen.has(rel)) throw new RepoRefused(`the scored tree holds ${rel}, which is not in the checkout`);
  }

  const fromDisk = [];
  const fromMemory = [];
  for (const file of files) {
    const planned = scored.get(file.path);
    if (planned === undefined) {
      fromDisk.push(file); // a binary, or anything else `readTree` does not carry
      continue;
    }
    const onDisk = fs.readFileSync(file.abs);
    if (onDisk.equals(Buffer.from(planned, "utf8"))) fromDisk.push(file);
    else fromMemory.push({ file, content: planned });
  }

  const diskIds = writeBlobsFromPaths(gitDir, fromDisk.map((f) => f.abs));
  const entries = [];
  fromDisk.forEach((f, i) => entries.push({ path: f.path, mode: f.mode, oid: diskIds[i] }));
  for (const { file, content } of fromMemory) {
    entries.push({ path: file.path, mode: file.mode, oid: writeBlob(gitDir, content) });
  }
  entries.sort((a, b) => (a.path < b.path ? -1 : 1));

  const tree = writeTreeFrom(gitDir, indexFile, entries);
  const commit = commitTree(gitDir, {
    tree,
    parent: null,
    message: BASE_MESSAGE,
    branch: BASE_BRANCH,
  });
  return { commit, tree, files: entries.length, rewritten: fromMemory.length, entries };
}

/**
 * The base branch's commit message. A constant, because a commit message is part of the SHA.
 *
 * Deliberately says nothing. It used to describe the tree — "every challenge key's correct codefix
 * applied, then stripped" — which tells a reviewer both that the repository is a benchmark and
 * where the defects were taken out. See {@link PUBLISHED_REF}.
 */
export const BASE_MESSAGE = "Initial import\n";

/* -------------------------------------------------------------------------- */
/* The branches                                                                */
/* -------------------------------------------------------------------------- */

/**
 * The two planners' records, normalised to the one shape this module commits.
 *
 * The planners answer different questions and so have different shapes — a splice branch carries
 * an item, keys and a variant, a control branch carries a path, an edit line and a pairing — and
 * neither shape is wrong. They are mapped here rather than in either planner because neither
 * planner knows that the other exists, and the thing that has to agree is the *repository*.
 *
 * The control planner works on the **marked** base tree, because "this edit clears every block by
 * four lines" is a claim about markers. What it ships is therefore stripped here, exactly as the
 * splice planner ships `file.scored`.
 *
 * @param {ReturnType<typeof planBranches>} branchPlan
 * @param {ReturnType<typeof planControlBranches>} controlPlan
 */
export function branchRecords(branchPlan, controlPlan) {
  const records = [];
  for (const branch of branchPlan.branches) {
    records.push({
      id: branch.id,
      name: branch.name,
      class: branch.class,
      baseId: branch.base === "base" ? null : branch.base,
      files: branch.files.map((f) => ({ path: f.path, content: f.scored, sha256: f.scoredSha256 })),
      // What the branch *is*. Recorded in the private manifest, never committed: see PUBLISHED_REF.
      about: {
        item: branch.item,
        keys: branch.keys,
        variant: branch.variant ? `data/static/codefixes/${branch.variant}` : null,
        builtBy: branch.builtBy,
      },
    });
  }
  for (const control of controlPlan.branches) {
    const scored = stripMarkers(control.content).source;
    records.push({
      id: control.branch,
      name: control.branch,
      class: control.class,
      baseId: null,
      files: [{ path: control.path, content: scored, sha256: sha256(scored) }],
      about: {
        editLine: control.editLine,
        pairedBlock: control.pairedBlock ?? null,
        expectedFindings: 0,
      },
    });
  }
  return records;
}

/**
 * Materialise every record as a branch, each cut from its own base.
 *
 * A record naming a base is committed on that base's **commit**, not on the base branch: the
 * correct-fix and broken-fix classes are cut from the introduce-the-vuln head for the same block,
 * which is the whole reason those classes mean anything — a fix branch that started from the
 * repaired base would be a diff against code that was never vulnerable.
 *
 * Records are committed in the order given and a base that has not been committed yet throws,
 * rather than being deferred. The plan already orders introduce-the-vuln first; an order that
 * stopped holding is a plan change, and it should say so here instead of being worked around.
 */
export function commitBranches(gitDir, indexFile, { baseCommit, records }) {
  const commits = new Map([["base", baseCommit]]);
  const out = [];
  const seenNames = new Set();
  const seenRefs = new Set();

  for (const record of records) {
    if (!record.ref || !PUBLISHED_REF.test(record.ref)) {
      throw new RepoRefused(`${record.name} has no published ref of the form pr/NNN, so its plan name would be published instead`);
    }
    if (seenRefs.has(record.ref)) throw new RepoRefused(`two branches are published as ${record.ref}`);
    seenRefs.add(record.ref);
    if (seenNames.has(record.name)) throw new RepoRefused(`two branches are named ${record.name}`);
    for (const other of seenNames) {
      if (other.startsWith(`${record.name}/`) || record.name.startsWith(`${other}/`)) {
        throw new RepoRefused(`${record.name} and ${other} cannot both be refs: one is a directory of the other`);
      }
    }
    seenNames.add(record.name);

    const parent = record.baseId == null ? baseCommit : commits.get(record.baseId);
    if (parent === undefined) {
      throw new RepoRefused(`${record.name} is cut from ${record.baseId}, which has not been committed yet`);
    }

    const files = record.files.map((f) => ({ path: f.path, oid: writeBlob(gitDir, f.content) }));
    const tree = writeTreeOver(gitDir, indexFile, parent, files);
    if (tree === git(gitDir, ["rev-parse", `${parent}^{tree}`]).trim()) {
      throw new RepoRefused(`${record.name} has the same tree as its base, so the branch is an empty diff`);
    }
    const commit = commitTree(gitDir, {
      tree,
      parent,
      message: neutralMessage(record.files.map((f) => f.path)),
      branch: record.ref,
      date: publishedDate(record.ref),
    });
    commits.set(record.id, commit);

    out.push({
      id: record.id,
      name: record.name,
      ref: record.ref,
      class: record.class,
      base: record.baseId == null ? BASE_BRANCH : nameOf(records, record.baseId),
      baseRef: record.baseId == null ? BASE_BRANCH : refOf(records, record.baseId),
      baseCommit: parent,
      commit,
      tree,
      files: record.files.map((f, i) => ({ path: f.path, sha256: f.sha256, blob: files[i].oid })),
    });
  }
  return out;
}

function refOf(records, id) {
  const found = records.find((r) => r.id === id);
  if (!found) throw new RepoRefused(`no record is named ${id}`);
  return found.ref;
}

function nameOf(records, id) {
  const found = records.find((r) => r.id === id);
  if (!found) throw new RepoRefused(`no record is named ${id}`);
  return found.name;
}

/* -------------------------------------------------------------------------- */
/* Reading the repository back                                                 */
/* -------------------------------------------------------------------------- */

/**
 * The diff between two commits, parsed into the lines a reviewer sees.
 *
 * `-U0` because context is not the claim — the added and removed lines are. `--no-renames`,
 * `--no-textconv` and `--no-ext-diff` because each would describe the same change differently, and
 * the description is what is being asserted against the plan.
 *
 * @returns {Map<string, {added: string[], removed: string[]}>} keyed by path
 */
export function diffCommits(gitDir, from, to) {
  const out = git(gitDir, [
    "diff",
    "--no-color",
    "--no-ext-diff",
    "--no-renames",
    "--no-textconv",
    "--unified=0",
    from,
    to,
  ]);
  const files = new Map();
  let current = null;
  for (const line of out.split("\n")) {
    const header = /^diff --git a\/(.*) b\/(.*)$/.exec(line);
    if (header) {
      current = { added: [], removed: [], noNewline: false };
      files.set(header[2], current);
      continue;
    }
    if (current == null) continue;
    if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("@@")) continue;
    if (line.startsWith("index ") || line.startsWith("new file") || line.startsWith("deleted file")) continue;
    if (line.startsWith("\\ No newline")) {
      current.noNewline = true;
      continue;
    }
    if (line.startsWith("+")) current.added.push(line.slice(1));
    else if (line.startsWith("-")) current.removed.push(line.slice(1));
  }
  return files;
}

/** One file's bytes at one commit. */
export function fileAt(gitDir, commit, rel) {
  return git(gitDir, ["show", `${commit}:${rel}`]);
}

/** Every path in a commit's tree. */
export function pathsAt(gitDir, commit) {
  return git(gitDir, ["ls-tree", "-r", "--name-only", commit]).split("\n").filter(Boolean);
}

/* -------------------------------------------------------------------------- */
/* Verification                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Hold the written repository to what the plan said, **at the git level**.
 *
 * `src/branches.mjs` already proves each file's edit survives stripping. That proof is about a
 * string in memory; this one is about what `git diff` prints, which is what the reviewer is shown
 * and what a scorer's `context_paths` are derived from. The two can disagree — a tree built from a
 * stale index, a base that is not the base the plan named, a blob written through a `.gitattributes`
 * filter — and every one of those disagreements produces a repository that looks right.
 *
 * Six questions:
 *
 * 1. **Does the branch change exactly the planned paths?** Nothing else may differ from its base.
 * 2. **Are the bytes at those paths the planner's bytes?** By digest, both sides.
 * 3. **Is the diff non-empty on every planned path?** An empty diff is a pull request with nothing
 *    to review, and it would still be a branch.
 * 4. **Is the diff the intended edit with the markers taken off?** The added and removed lines
 *    `git diff` prints must be the ones `lineHunks` computes over the same two scored files — not
 *    merely a subset, and not a diff that also moves marker lines. As a multiset and not as a
 *    sequence, for the reason {@link compareLines} gives.
 * 5. **Does any line of any diff mention the marker token?** The answer key must not be visible in
 *    the change under review, and this is the last place to ask before the refs exist.
 * 6. **Is the branch cut from the commit the plan named?** Checked as a parent, so a fix class
 *    whose introduce-the-vuln head was rebuilt cannot quietly be cut from the base tree instead.
 * 7. **Does anything the reviewer reads besides the diff say what the branch is?** Every ref in the
 *    repository is `main` or `pr/NNN`, the base commit carries {@link BASE_MESSAGE} (or, for a base
 *    commit added later, the neutral message of the paths it changes), and every
 *    branch commit's message is {@link neutralMessage} of the paths *git* says it changes. Asked
 *    of the repository rather than of the records, so a ref or a commit this module did not mean
 *    to write is caught too.
 * 8. **Is every branch its own commit?** Check runs attach to a commit, so two branches at one SHA
 *    are two pull requests with one review. See {@link publishedDate}.
 *
 * Findings rather than throws, so one run names everything that is wrong.
 */
export function verifyBranchRepo(gitDir, { baseCommit, branches, records, baseMessage = BASE_MESSAGE }) {
  const findings = [];
  const fail = (branch, reason) => findings.push({ branch, reason });
  const byId = new Map(records.map((r) => [r.id, r]));

  // 7. What the reviewer reads that is not the diff.
  for (const ref of git(gitDir, ["for-each-ref", "--format=%(refname)"]).split("\n").filter(Boolean)) {
    const short = ref.replace(/^refs\/heads\//, "");
    if (!ref.startsWith("refs/heads/") || (short !== BASE_BRANCH && !PUBLISHED_REF.test(short))) {
      fail(short, "is a ref a reviewer would see, and is neither the base nor pr/NNN");
    }
  }
  if (git(gitDir, ["log", "-1", "--format=%B", baseCommit]).replace(/\n+$/, "\n") !== baseMessage) {
    fail(BASE_BRANCH, "the base commit carries a message other than the pinned one");
  }

  // 8. One commit per branch.
  const byCommit = new Map();
  for (const branch of branches) byCommit.set(branch.commit, [...(byCommit.get(branch.commit) ?? []), branch.ref ?? branch.name]);
  for (const [commit, refs] of byCommit) {
    if (refs.length > 1) fail(refs.join(", "), `share commit ${commit}, so their pull requests would share one set of checks`);
  }

  for (const branch of branches) {
    const record = byId.get(branch.id);
    if (!record) {
      fail(branch.name, "the repository holds a branch with no record in the plan");
      continue;
    }

    const parent = git(gitDir, ["rev-list", "--parents", "-n", "1", branch.commit]).trim().split(" ");
    if (parent[1] !== branch.baseCommit) fail(branch.name, `is cut from ${parent[1] ?? "nothing"}, not ${branch.baseCommit}`);
    if (record.baseId == null && branch.baseCommit !== baseCommit) fail(branch.name, "claims the base branch and is cut elsewhere");

    const diff = diffCommits(gitDir, branch.baseCommit, branch.commit);
    const message = git(gitDir, ["log", "-1", "--format=%B", branch.commit]).replace(/\n+$/, "\n");
    if (message !== neutralMessage([...diff.keys()])) {
      fail(branch.name, `${branch.ref}'s commit message says more than the paths its diff changes`);
    }
    const planned = new Set(record.files.map((f) => f.path));
    for (const seen of diff.keys()) {
      if (!planned.has(seen)) fail(branch.name, `changes ${seen}, which the plan does not list`);
    }

    for (const file of record.files) {
      const shown = diff.get(file.path);
      if (!shown) {
        fail(branch.name, `${file.path} is planned as changed and does not appear in the diff`);
        continue;
      }
      if (shown.added.length === 0 && shown.removed.length === 0) {
        fail(branch.name, `${file.path} appears in the diff with no added or removed line`);
      }

      const after = fileAt(gitDir, branch.commit, file.path);
      if (sha256(after) !== file.sha256) fail(branch.name, `${file.path} at the branch is not the planned content`);
      const before = fileAt(gitDir, branch.baseCommit, file.path);

      // 4. The diff is the edit `lineHunks` describes over the same two files — the check the
      //    planner makes on strings, asked of git's own rendering of them.
      const hunks = lineHunks(before, after);
      const expected = {
        added: hunks.flatMap((h) => h.insert),
        removed: hunks.flatMap((h) => h.remove),
      };
      const added = compareLines(expected.added, shown.added);
      if (!added.same) fail(branch.name, `${file.path}: the added lines differ from the edit's — ${added.why}`);
      const removed = compareLines(expected.removed, shown.removed);
      if (!removed.same) fail(branch.name, `${file.path}: the removed lines differ from the edit's — ${removed.why}`);

      // 5. No marker anywhere in what the reviewer is shown, on either side of the diff.
      for (const line of [...shown.added, ...shown.removed]) {
        if (line.includes(MARKER_TOKEN)) fail(branch.name, `${file.path}: the diff shows a marker line: ${line.trim()}`);
      }
    }
  }

  return { ok: findings.length === 0, findings, branches: branches.length };
}

/**
 * Are these the same lines — as a multiset, deliberately, and not as a sequence?
 *
 * This is the one place phase 6 found the two diffs disagreeing, and the disagreement is real but
 * is not a difference in the edit. `git diff` and the `diff` package both produce a *minimal*
 * alignment, and where a file repeats a line there is more than one minimal alignment to pick.
 * `frontend/src/app/app.routing.ts` is full of bare `  {` lines, so on six branches — measured
 * 2026-09-20, and every one of them that file — git anchors its hunk one `  {` earlier than
 * `lineHunks` does: same lines added, same lines removed, same
 * resulting file, different order in the printout.
 *
 * Asserting the sequence would therefore be asserting which Myers implementation ran, which is a
 * fact about git's version and not about the branch. Asserting the multiset is still the property
 * that matters: a diff that "also silently reverts or moves marker lines" carries lines the edit
 * does not, and a diff that matched an extra pair of identical lines carries one line more on each
 * side. Both change the multiset. Only the anchoring does not.
 *
 * @returns {{same: boolean, why: string}}
 */
function compareLines(expected, shown) {
  const sortedExpected = [...expected].sort();
  const sortedShown = [...shown].sort();
  if (sortedExpected.length === sortedShown.length && sortedExpected.every((l, i) => l === sortedShown[i])) {
    return { same: true, why: "" };
  }
  const missing = surplus(sortedExpected, sortedShown);
  const extra = surplus(sortedShown, sortedExpected);
  return {
    same: false,
    why:
      `git shows ${shown.length} where the edit has ${expected.length}` +
      (extra.length ? `; git also shows ${JSON.stringify(extra.slice(0, 3))}` : "") +
      (missing.length ? `; git does not show ${JSON.stringify(missing.slice(0, 3))}` : ""),
  };
}

/** The lines of `a` that `b` does not also carry, counted with multiplicity. */
function surplus(a, b) {
  const left = [...b];
  const out = [];
  for (const line of a) {
    const at = left.indexOf(line);
    if (at === -1) out.push(line);
    else left.splice(at, 1);
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* The whole generation                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Generate the whole repository from a corpus checkout, and return the manifest.
 *
 * The manifest is the reproducibility contract: it names every branch, the commit it is at, the
 * commit it is cut from, the paths it changes and a digest of each path's bytes on both sides. It
 * carries **no clock, no absolute path and no machine fact**, which is phase 4's discipline and is
 * asserted in the tests rather than merely intended — a manifest that recorded when or where it
 * ran would make two correct runs differ, and the whole point of the SHAs below is that they do
 * not.
 *
 * `corpusSha` is a fact about the corpus, not about this machine, and it is passed in for the
 * reason `bin/build-base.mjs` reads `.git/HEAD` by hand: running git inside the corpus mirror is a
 * step that could change the thing being measured.
 *
 * @param {{checkout: string, outRepo: string, indexFile?: string, corpusSha?: string|null, upstream?: Map<string,string>, codefixes?: Map<string,string>}} input
 */
export async function generateBranchRepo({ checkout, outRepo, indexFile, corpusSha = null, upstream, codefixes }) {
  const tree = upstream ?? readTree(checkout);
  const fixes = codefixes ?? readCodefixes(checkout);

  const base = await buildScoredBase(tree, fixes);
  const branchPlan = planBranches({ upstream: tree, base: base.marked, codefixes: fixes });
  const controlPlan = planControlBranches(base.marked);
  const records = branchRecords(branchPlan, controlPlan);
  const refs = publishedRefs(records.map((r) => r.name));
  for (const record of records) record.ref = refs.get(record.name);

  const gitDir = initRepo(outRepo);
  const index = indexFile ?? path.join(gitDir, "hd85.index");
  const committedBase = commitScoredBase(gitDir, index, { checkout, scored: base.scored });
  const branches = commitBranches(gitDir, index, { baseCommit: committedBase.commit, records });
  const report = verifyBranchRepo(gitDir, { baseCommit: committedBase.commit, branches, records });
  fs.rmSync(index, { force: true });

  if (!report.ok) {
    throw new RepoRefused(
      `${report.findings.length} branches do not match the plan: ` +
        report.findings.slice(0, 5).map((f) => `${f.branch} — ${f.reason}`).join("; "),
    );
  }

  const byClass = {};
  for (const branch of branches) byClass[branch.class] = (byClass[branch.class] ?? 0) + 1;

  return {
    manifest: {
      generatedBy: "HD-85 phase 6 — the branch plans, materialised as git refs",
      identity: { ...PINNED_IDENTITY, date: PINNED_DATE },
      corpus: {
        pinnedSha: PINNED_SHA_OF_CORPUS,
        sha: corpusSha,
        matchesPin: corpusSha == null ? null : corpusSha === PINNED_SHA_OF_CORPUS,
      },
      /** Ties this repository to the exact plan it was cut from, without restating it. */
      planDigest: {
        branches: sha256(JSON.stringify(branchPlan.manifest)),
        controls: sha256(JSON.stringify(controlPlan)),
      },
      counts: {
        total: branches.length,
        byClass,
        splice: branchPlan.counts.total,
        controls: controlPlan.counts.total,
        changedFiles: branches.reduce((n, b) => n + b.files.length, 0),
      },
      base: {
        branch: BASE_BRANCH,
        commit: committedBase.commit,
        tree: committedBase.tree,
        files: committedBase.files,
        /** How many of those files the repair and the strip rewrote; the rest are the checkout's. */
        rewritten: committedBase.rewritten,
        droppedPaths: base.dropped.length,
        strippedPaths: [...STRIPPED_PATHS],
        markerMentions: base.mentions,
        /**
         * Where each marked block sits in **scored** coordinates. Recorded here because stripping
         * is what destroys the evidence for it, and this is the last moment it exists.
         */
        lineMap: base.lineMap,
      },
      /**
       * Every branch as published (`ref`, `baseRef`) and as planned (`name`, `class`, `about`).
       * **This mapping is the answer key for the ref names**, which is why the manifest is written
       * beside the repository and never into it, and why it is not pushed with the refs.
       */
      branches: branches.map((b) => ({
        ref: b.ref,
        baseRef: b.baseRef,
        /**
         * The other published branches whose change is byte-identical to this one — same base,
         * same tree. They are separate pull requests (see `publishedDate`), but they are one
         * observation, and a scorer that counts them as independent overstates its sample.
         */
        sameChangeAs: branches
          .filter((o) => o !== b && o.baseCommit === b.baseCommit && o.tree === b.tree)
          .map((o) => o.ref)
          .sort(),
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
    gitDir,
    records,
    branches,
    base: committedBase,
    plans: { branches: branchPlan, controls: controlPlan },
  };
}

