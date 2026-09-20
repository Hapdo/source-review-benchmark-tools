/**
 * The two control classes of phase 6 — the branches a correct reviewer must find **nothing** in.
 *
 * Three of the five pull-request classes introduce a defect. These two do not, and they are two
 * classes rather than one because the same non-edit is held to opposite expectations depending on
 * where it lands:
 *
 * | Class | Edits | On-diff expectation | Off-diff expectation |
 * |---|---|---|---|
 * | `unmarked-file` | a file carrying no marked block | nothing | no answer key; unscored |
 * | `marked-file` | a marked file, clear of its blocks | nothing | the file's blocks, as `off_diff` |
 *
 * The unmarked class's off-diff column is not "nothing", and saying so would overstate it: Juice
 * Shop is a deliberately vulnerable application and only 23 of its weaknesses are marked, so a
 * finding about code the branch did not change is neither confirmed nor refuted by this corpus.
 * The on-diff column is where the false-positive rate is read, and there the diff is one inert
 * comment.
 *
 * The first gives the false-positive rate a denominator that is not contaminated by an answer.
 * The second is the only way to observe off-diff behaviour at all: an `off_diff` finding requires
 * the file to be on a pass's `context_paths`, which only the context index populates, so the
 * marked-file class is a `review/deep` measurement and the unmarked one is a both-lanes
 * measurement. Running the controls means running both lanes.
 *
 * ## What "neutral" means here, and why it is defined rather than eyeballed
 *
 * A control edit's whole job is to be a real pull request that a correct reviewer finds nothing
 * in. That makes the definition load-bearing: a control that is *not* inert produces a finding
 * that is not a false positive, and it lands in the false-positive column anyway, so the number
 * the class exists to produce is wrong in the direction that flatters the harness.
 *
 * So a neutral edit is, exactly:
 *
 *   **the insertion of one whole line, at a pinned site, consisting of the file's line-comment
 *   introducer followed by {@link NEUTRAL_COMMENT_TEXT}, whose characters are drawn from
 *   {@link NEUTRAL_COMMENT_ALPHABET}.**
 *
 * Every clause is there to be checked mechanically rather than argued by eye:
 *
 * - **One whole line, inserted.** Deleting the inserted line from the result gives back the
 *   original file byte for byte ({@link verifyControlPlan} asserts this on every branch). So the
 *   edit provably modifies no existing line — the strongest statement available without a parser,
 *   and the one that rules out the whole family of "it only changed whitespace, except it didn't".
 * - **A line comment.** Comments are lexically ignored in all five corpus languages, so the token
 *   stream is unchanged. That is only true if the site is in **code context** and not inside a
 *   string, a template literal, a block comment, a YAML block scalar or an HCL heredoc, where the
 *   same characters are *content*. {@link codeContextAt} decides that by lexing the file prefix,
 *   and a site it cannot vouch for is skipped rather than used.
 * - **A pinned alphabet.** {@link NEUTRAL_COMMENT_TEXT} contains only letters, spaces and a final
 *   full stop. It therefore cannot open a string, close a block comment (`*​/`), open an
 *   interpolation (`${`), carry the marker token (which contains `-`), or match a
 *   scanner-suppression directive. It does **not** rule out a rule-7 instruction-injection
 *   phrase — "Ignore all previous instructions." is letters, spaces and a full stop, and
 *   `test/controls.test.mjs` asserts that the alphabet admits it. The alphabet is the lexical
 *   check; the rule-7 scan over the sentence and over every generated tree is the other one, and
 *   neither substitutes for the other.
 * - **One sentence, the same on every branch.** The comment's text is a controlled constant of the
 *   experiment. Varying it per branch would put 35 unreviewed strings into 35 pull requests and
 *   make every per-branch result partly about its own string.
 *
 * The empirical half of the argument is in `test/controls.test.mjs`: every edited file is put
 * through the phase-4 parse gate **beside its unedited original**, and the two verdicts are
 * required to agree file by file. That is what turns "comments are ignored" from a claim about
 * five languages into a measurement about these files, and it is why the lexer below is allowed to
 * be a conservative approximation.
 *
 * ## Why no tool-config file is ever edited
 *
 * Phase 1 measured that upstream ships **zero** scanner suppressions — no `nosemgrep`, no
 * gitleaks-allow directive, no tool-config file — and that number is re-measured here over the
 * repaired base tree and over every generated control tree. After HD-89 the judge is told which
 * `suppressed-by-branch` rows a run produced, so a manufactured one moves a verdict and not just a
 * count. {@link TOOL_CONFIG_BASENAMES} is the list, a basename on it is refused as a control
 * target, and the count over each generated tree is asserted to still be zero.
 *
 * ## Why the sites are measured against the blocks rather than chosen near them
 *
 * `findBlocks` is the authority on where a block is, because a block's line span is not its
 * snippet's line span: blocks in `app.routing.ts` overlap across 24 lines, `routes/chat.ts:188`
 * carries one `end` marker closing two `start`s, and four of the seven marker types appear as
 * suffixes on live code. "Outside the block" is therefore computed, and computed against **every**
 * block in the file rather than the one the branch is paired with.
 *
 * It is also computed with clearance. A site within {@link DIFF_CONTEXT_LINES} of a block would
 * put the block's own lines into the diff hunk's context, and a reviewer reporting them would be
 * reporting on-diff — which is the one thing this class asserts cannot happen. So the required gap
 * is {@link BLOCK_CLEARANCE}, one more than the context a diff carries.
 */
import { MARKER_TOKEN, findBlocks, parseMarker, splitLines } from "./markers.mjs";
import { TOOL_CONFIG_BASENAMES, buildInventory, countSuppressions } from "./inventory.mjs";
import { STRIPPED_PATHS, stripMarkers } from "./strip.mjs";
import { isSafeTarget, languageFor } from "./parse-check.mjs";
import { sha256 } from "./base-tree.mjs";

/** Raised when the corpus cannot support a control the design asks for. Never a silent shortfall. */
export class ControlRefused extends Error {
  constructor(message) {
    super(message);
    this.name = "ControlRefused";
  }
}

/* -------------------------------------------------------------------------- */
/* The declared tables                                                         */
/* -------------------------------------------------------------------------- */

/**
 * The two classes, with the expectation the scorer holds each branch to.
 *
 * Carried as data rather than as prose in a doc, because the scorer reads it and a reader of a
 * result needs to see which lane produced which half of the answer.
 */
export const CONTROL_CLASSES = Object.freeze({
  "unmarked-file": Object.freeze({
    /** A file with no marked block. Its on-diff findings are the false-positive numerator. */
    edits: "a file carrying no marked block",
    scoredAs: "false-positive baseline",
    lanes: Object.freeze(["review/quick", "review/deep"]),
  }),
  "marked-file": Object.freeze({
    /** A marked file, edited clear of every block in it. */
    edits: "a marked file, outside every block",
    scoredAs: "off-diff behaviour, scored separately",
    lanes: Object.freeze(["review/deep"]),
  }),
});

/**
 * The sentence every control edit adds. One sentence, the same everywhere — see the header.
 *
 * It states a fact about the file that is true of every file in the corpus and makes no claim
 * about behaviour, correctness or security, so it cannot itself be a finding: there is nothing in
 * it to be wrong about.
 */
export const NEUTRAL_COMMENT_TEXT = "Part of the OWASP Juice Shop application.";

/**
 * The alphabet {@link NEUTRAL_COMMENT_TEXT} is drawn from: letters, spaces, a closing full stop.
 *
 * This is the **lexical** half of "semantically inert". Absent from it, and therefore impossible
 * in a control comment: `/` and `*` (so no `*​/` closing a block comment and no regex), quotes and
 * backticks (no string can be opened), `$` and `{` (no interpolation), `#` and `-` (so neither a
 * second comment introducer nor the marker token, which contains `-`), and the `:` and `=` a
 * scanner-suppression directive needs.
 *
 * It says nothing about **meaning**, and must not be read as if it did: "Ignore all previous
 * instructions." is letters, spaces and a full stop, and this regex accepts it. That is asserted
 * in `test/controls.test.mjs` rather than left as a caveat, because the alphabet is the obvious
 * place for a later reader to believe the rule-7 problem has already been handled. It has not; the
 * rule-7 scan is what handles it.
 */
export const NEUTRAL_COMMENT_ALPHABET = /^[A-Za-z][A-Za-z ]*\.$/;

/**
 * Extension to line-comment introducer, for the five languages the corpus spans.
 *
 * Written out rather than inferred, the same choice `LANGUAGE_BY_EXTENSION` makes next door: an
 * extension arriving in a later pin selects nothing and is refused, rather than quietly acquiring
 * whichever introducer the fallback happened to be.
 */
export const COMMENT_INTRODUCER_BY_EXTENSION = Object.freeze({
  ".ts": "//",
  ".sol": "//",
  ".tf": "#",
  ".yml": "#",
  ".yaml": "#",
});

/**
 * The corpus languages, as the **mix of a sample** is counted rather than as Semgrep counts them.
 *
 * Semgrep has four languages here because Compose is YAML to it (`parse-check.mjs` says so, and is
 * right about the analyzer Compose gets). A false-positive baseline is a different question: a
 * Compose file and a Kubernetes manifest are different review problems whatever the parser thinks,
 * and a sample drawn "evenly across YAML" that happened to contain no Compose file would measure
 * less than it appears to. So Compose is counted apart, by basename.
 */
export const CORPUS_LANGUAGES = Object.freeze(["compose", "solidity", "terraform", "ts", "yaml"]);

/** Compose files, by the two basename shapes upstream and the wider ecosystem use. */
const COMPOSE_BASENAME = /^(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$/;

/**
 * Paths excluded from the unmarked sample, with the reason that is not "they are tests".
 *
 * Juice Shop's test and end-to-end trees are where its *deliberate* attack payloads live: SQL
 * injection strings, XSS vectors and stand-in credentials, written as test data. A reviewer that
 * reports one of those is not obviously wrong, so those files cannot serve as a clean
 * false-positive denominator — a hit there is unclassifiable rather than false. `rsn/` and
 * `.ai/skills/` are excluded for the reason phase 1 excludes them from the inventory: they carry
 * the vocabulary of the benchmark rather than corpus.
 *
 * The marked class does not consult this table. Its 16 files are whatever upstream marked.
 */
export const NOT_REVIEWABLE_AS_PRODUCTION_CODE = Object.freeze([
  /^test\//,
  /^cypress\//,
  /^rsn\//,
  /^\.ai\//,
  /^vagrant\//,
  /^screenshots\//,
  /\.spec\.ts$/,
  /\.test\.ts$/,
]);

/**
 * The lines of context a unified diff carries either side of a hunk. Git's default, and the number
 * that decides how far a control edit has to sit from a block.
 */
export const DIFF_CONTEXT_LINES = 3;

/**
 * The gap a marked-file control leaves between its edit and every block in the file.
 *
 * One more than {@link DIFF_CONTEXT_LINES}, so that no line of any block can appear in the hunk's
 * context. A block line in the context of the diff is a block line a reviewer can read as part of
 * the change, and an on-diff finding on it would be recorded against a class whose whole claim is
 * that it produces none.
 */
export const BLOCK_CLEARANCE = DIFF_CONTEXT_LINES + 1;

/**
 * How many unmarked files each corpus language contributes.
 *
 * A cap rather than a share, applied to a hash-ordered list, so the sample is neither a taste
 * judgement nor an artifact of directory order. Six is the smallest cap that reaches the design's
 * "~20" — it yields 19 after the duplicate-content rule below — and raising it to seven only adds
 * more `.ts` and `.yml`, because three of the five languages are already exhausted at their
 * available counts. The shortfall in a scarce language is **not** made up from an abundant one:
 * that would trade the mix for the total, and the mix is the thing this class is measuring with.
 */
export const UNMARKED_FILES_PER_LANGUAGE = 6;

/**
 * The anchor a control comment is inserted above, per Semgrep language.
 *
 * Every pattern is anchored at column 0 and names a **top-level declaration**. That is not
 * decoration: a comment inserted immediately above a top-level declaration is where a human would
 * put one, and column 0 is also what makes the YAML case provable — block scalar content must be
 * indented further than its parent key, so a line at indentation 0 is never inside one.
 *
 * Refusing to insert anywhere else is what makes "where in each file" reproducible by reading this
 * table, which is phase 4's manifest discipline applied to a site instead of to a splice.
 */
export const ANCHOR_PATTERNS = Object.freeze({
  ts: /^(?:import|export|const|let|function|async function|class|abstract class|interface|type|enum|declare)\b/,
  solidity: /^(?:pragma|import|contract|abstract contract|library|interface)\b/,
  terraform: /^(?:terraform|provider|resource|data|variable|output|module|locals)\b/,
  yaml: /^[A-Za-z_][A-Za-z0-9_.-]*:/,
});

/* -------------------------------------------------------------------------- */
/* Small, total helpers                                                        */
/* -------------------------------------------------------------------------- */

/** The extension of a POSIX repository path, lowercased, or `""`. */
function extensionOf(path) {
  const base = path.slice(path.lastIndexOf("/") + 1);
  const dot = base.lastIndexOf(".");
  return dot <= 0 ? "" : base.slice(dot).toLowerCase();
}

/** The basename of a POSIX repository path. */
function basenameOf(path) {
  return path.slice(path.lastIndexOf("/") + 1);
}

/**
 * The line-comment introducer for a path, or `null` where the table has none.
 *
 * `null` rather than a throw, because the caller's next move is to drop the file from the sample
 * and say so — an unknown extension is a fact about the pin, not an error in this module.
 */
export function commentIntroducerFor(path) {
  return COMMENT_INTRODUCER_BY_EXTENSION[extensionOf(path)] ?? null;
}

/** The corpus language a path counts as in the sample's mix, or `null`. See {@link CORPUS_LANGUAGES}. */
export function corpusLanguageOf(path) {
  const language = languageFor(path);
  if (!language) return null;
  if (language === "yaml" && COMPOSE_BASENAME.test(basenameOf(path))) return "compose";
  return language;
}

/** Is this path one of the two things every scored tree loses whole? */
function isStrippedPath(path) {
  return STRIPPED_PATHS.some((p) => (p.endsWith("/") ? path.startsWith(p) : path === p));
}

/* -------------------------------------------------------------------------- */
/* Lexical context — is this line a place a comment is a comment?              */
/* -------------------------------------------------------------------------- */

/**
 * Characters after which a `/` in TypeScript begins a regular expression rather than a division.
 *
 * The standard heuristic, and it is a heuristic: `return /x/` is a regex this table reads as a
 * division, because the previous significant character is `n`. That error is one-directional in
 * the way that matters — it leaves the scanner in `code` where it should have skipped a literal,
 * so at worst a candidate site inside a regex's own characters looks usable. Nothing in this
 * corpus puts a column-0 `import`/`export` inside a regex, and the test's paired parse-gate run is
 * the oracle that says so about these files rather than about the heuristic.
 */
const REGEX_MAY_FOLLOW = /[(,=:[!&|?{};+\-*%~^<>]/;

/**
 * Is the character offset `offset` of a `//`-commented source in ordinary code?
 *
 * A character-level scan, because the question is exactly "what lexical state is the file in when
 * it reaches this point", and there is no line-wise answer to it: a template literal, a block
 * comment and a multi-line string all carry ordinary-looking lines that are content.
 */
function slashStyleContextAt(source, offset) {
  let state = "code";
  /** `{kind:"template"}` and `{kind:"interp", depth:n}`, innermost last. */
  const stack = [];
  let previous = "";
  let inClass = false; // inside a regex character class

  for (let i = 0; i < offset; i++) {
    const c = source[i];
    const d = source[i + 1] ?? "";

    if (state === "line") {
      if (c === "\n") state = "code";
      continue;
    }
    if (state === "block") {
      if (c === "*" && d === "/") {
        state = "code";
        i++;
      }
      continue;
    }
    if (state === "single" || state === "double") {
      if (c === "\\") i++;
      else if (c === (state === "single" ? "'" : '"')) state = "code";
      else if (c === "\n") state = "code"; // an unterminated string is a mis-scan, not a state
      continue;
    }
    if (state === "template") {
      if (c === "\\") i++;
      else if (c === "$" && d === "{") {
        stack.push({ kind: "interp", depth: 0 });
        state = "code";
        i++;
      } else if (c === "`") {
        stack.pop(); // the template
        state = "code";
      }
      continue;
    }
    if (state === "regex") {
      if (c === "\\") i++;
      else if (c === "[") inClass = true;
      else if (c === "]") inClass = false;
      else if (c === "/" && !inClass) state = "code";
      else if (c === "\n") state = "code"; // as above: it was a division after all
      continue;
    }

    // state === "code"
    if (c === "/" && d === "/") {
      state = "line";
      i++;
      continue;
    }
    if (c === "/" && d === "*") {
      state = "block";
      i++;
      continue;
    }
    if (c === "/" && (previous === "" || REGEX_MAY_FOLLOW.test(previous))) {
      state = "regex";
      inClass = false;
      previous = c;
      continue;
    }
    if (c === "'") state = "single";
    else if (c === '"') state = "double";
    else if (c === "`") {
      stack.push({ kind: "template" });
      state = "template";
    } else if (c === "{") {
      const top = stack[stack.length - 1];
      if (top?.kind === "interp") top.depth++;
    } else if (c === "}") {
      const top = stack[stack.length - 1];
      if (top?.kind === "interp") {
        if (top.depth === 0) {
          stack.pop();
          state = "template";
        } else top.depth--;
      }
    }
    if (!/\s/.test(c)) previous = c;
  }

  return state === "code" && stack.length === 0;
}

/** HCL heredoc openers: `<<TAG`, `<<-TAG`, and the quoted forms Terraform also accepts. */
const HEREDOC_OPEN = /<<[-~]?\s*"?([A-Za-z_][A-Za-z0-9_]*)"?/g;

/**
 * Is line `line` of a `#`-commented source at document level?
 *
 * Line-wise rather than character-wise, because the constructs that would make a `#` into content
 * are line-structured in both languages:
 *
 * - **YAML** — a block scalar's content must be indented further than its parent key, so a line at
 *   indentation 0 is never inside one; block scalars cannot appear in flow context at all. What is
 *   left is a flow collection or a quoted scalar spanning lines, and both are tracked here.
 * - **Terraform** — a heredoc's content may reach column 0 under `<<-`, so heredocs are tracked by
 *   their tag. Ordinary HCL strings cannot span a line.
 *
 * The caller has already required indentation 0 via {@link ANCHOR_PATTERNS}; this decides the rest.
 */
function hashStyleContextAt(lines, line, language) {
  let flowDepth = 0;
  let quote = "";
  let heredoc = "";

  for (let i = 0; i < line - 1; i++) {
    const text = lines[i];

    if (heredoc !== "") {
      if (text.trim() === heredoc) heredoc = "";
      continue;
    }
    if (language === "terraform") {
      HEREDOC_OPEN.lastIndex = 0;
      const open = HEREDOC_OPEN.exec(text);
      if (open) {
        heredoc = open[1];
        continue;
      }
    }
    if (language !== "yaml") continue;

    for (let j = 0; j < text.length; j++) {
      const c = text[j];
      if (quote !== "") {
        if (c === "\\" && quote === '"') j++;
        else if (c === quote) quote = "";
        continue;
      }
      if (c === "#" && (j === 0 || /\s/.test(text[j - 1]))) break; // a comment to end of line
      if (c === "'" || c === '"') quote = c;
      else if (c === "[" || c === "{") flowDepth++;
      else if (c === "]" || c === "}") flowDepth = Math.max(0, flowDepth - 1);
    }
    // A plain scalar cannot carry an unterminated quote across a line break in any shape this
    // corpus uses; treating one as closed at end of line keeps a mis-scan from swallowing the file.
    if (flowDepth === 0) quote = "";
  }

  return flowDepth === 0 && quote === "" && heredoc === "";
}

/**
 * Is a line-comment introducer, inserted so that it becomes line `line`, actually a comment there?
 *
 * @param {string} source the file as it stands
 * @param {number} line 1-based; the line the inserted comment would occupy
 * @param {string} path the file's repository path, which decides the comment style
 */
export function codeContextAt(source, line, path) {
  const introducer = commentIntroducerFor(path);
  if (introducer == null) return false;
  const { lines, eol } = splitLines(source);
  if (line < 1 || line > lines.length + 1) return false;
  if (introducer === "#") return hashStyleContextAt(lines, line, languageFor(path));

  // The offset the inserted line would start at: every preceding line, plus its terminator.
  let offset = 0;
  for (let i = 0; i < line - 1; i++) offset += lines[i].length + eol.length;
  return slashStyleContextAt(source, offset);
}

/* -------------------------------------------------------------------------- */
/* Sites                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Every line at which a neutral comment may be inserted into this file, ascending.
 *
 * A site is a line number `L` such that the comment becomes line `L` and everything from the old
 * line `L` down shifts by one. The rule, in full:
 *
 * 1. the old line `L` matches this language's {@link ANCHOR_PATTERNS} — a top-level declaration at
 *    column 0;
 * 2. `L` clears every block in the file by {@link BLOCK_CLEARANCE} lines, on whichever side it
 *    falls;
 * 3. the old line `L` is not itself a marker line, so no site can ever split a marker from the
 *    code it annotates;
 * 4. {@link codeContextAt} vouches for `L` as code rather than as the inside of a string, a
 *    comment, a block scalar or a heredoc.
 *
 * @param {string} source
 * @param {string} path
 * @returns {number[]}
 */
export function neutralEditSites(source, path) {
  const language = languageFor(path);
  const anchor = ANCHOR_PATTERNS[language];
  if (!anchor) return [];
  const { lines } = splitLines(source);
  const blocks = findBlocks(source).filter((b) => b.end > 0);

  const sites = [];
  for (let n = 1; n <= lines.length; n++) {
    if (!anchor.test(lines[n - 1])) continue;
    if (parseMarker(lines[n - 1]) != null) continue;
    const clear = blocks.every((b) => n <= b.start - BLOCK_CLEARANCE || n >= b.end + 1 + BLOCK_CLEARANCE);
    if (!clear) continue;
    if (!codeContextAt(source, n, path)) continue;
    sites.push(n);
  }
  return sites;
}

/**
 * Pick the `index`-th of `count` sites, spread across what is available.
 *
 * Spread rather than "the first `count`", so that two branches editing one file are two places in
 * it rather than two adjacent imports. With `count === 1` this is the first site, which is why the
 * unmarked class needs no rule of its own.
 */
export function siteFor(sites, index, count) {
  if (sites.length < count) return null;
  return sites[Math.floor((index * sites.length) / count)];
}

/**
 * Apply the neutral edit: insert the comment so that it becomes line `line`.
 *
 * @param {string} source
 * @param {string} path
 * @param {number} line
 */
export function applyNeutralEdit(source, path, line) {
  const introducer = commentIntroducerFor(path);
  if (introducer == null) throw new ControlRefused(`no comment introducer is declared for ${path}`);
  const { lines, eol } = splitLines(source);
  if (line < 1 || line > lines.length + 1) {
    throw new ControlRefused(`${path}: line ${line} is outside the file`);
  }
  const out = lines.slice();
  out.splice(line - 1, 0, `${introducer} ${NEUTRAL_COMMENT_TEXT}`);
  return out.join(eol);
}

/** A branch name's slug: the repository path, lowercased, with every other character a hyphen. */
export function slugFor(path) {
  return path
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/* -------------------------------------------------------------------------- */
/* Selection                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * The unmarked sample: a hash-ordered, per-language capped draw from the files that carry no
 * marked block.
 *
 * Ordering by `sha256(path)` rather than by path is the whole of "not a taste judgement". A
 * path-sorted draw of six `.yml` files is six files from `.github/`, which is a sample of one
 * directory's conventions; a hash order is fixed, reproducible by anyone, and correlated with
 * nothing about the file.
 *
 * Eligibility, in order: a language the parse gate can check, a path it will accept, no marker
 * token anywhere in the file (which excludes both the 16 marked files and the five that mention
 * the vocabulary without carrying corpus), not a stripped path, not a tool-config basename, not in
 * {@link NOT_REVIEWABLE_AS_PRODUCTION_CODE}, and at least one site.
 *
 * Byte-identical files are collapsed. Two branches editing the same bytes under two paths are one
 * measurement reported twice — the reason `buildInventory` reports `distinctDefectSites` beside
 * its block count, applied to the sample.
 *
 * @param {Map<string, string>} tree the tree the branches are cut from
 */
export function selectUnmarkedFiles(tree) {
  /** @type {Map<string, {path: string, corpusLanguage: string, sites: number[], digest: string}[]>} */
  const byLanguage = new Map(CORPUS_LANGUAGES.map((l) => [l, []]));
  const rejected = [];

  for (const [path, source] of tree) {
    const corpusLanguage = corpusLanguageOf(path);
    if (corpusLanguage == null) continue;
    if (!isSafeTarget(path)) continue;
    if (isStrippedPath(path)) continue;
    if (source.includes(MARKER_TOKEN)) continue;
    if (TOOL_CONFIG_BASENAMES.includes(basenameOf(path))) {
      rejected.push({ path, reason: "tool-config basename" });
      continue;
    }
    if (NOT_REVIEWABLE_AS_PRODUCTION_CODE.some((r) => r.test(path))) continue;
    const sites = neutralEditSites(source, path);
    if (sites.length === 0) {
      rejected.push({ path, reason: "no site clears the anchor rule" });
      continue;
    }
    byLanguage.get(corpusLanguage).push({ path, corpusLanguage, sites, digest: sha256(source) });
  }

  const chosen = [];
  const available = {};
  for (const language of CORPUS_LANGUAGES) {
    const pool = byLanguage.get(language).slice().sort((a, b) => sha256(a.path).localeCompare(sha256(b.path)));
    available[language] = pool.length;
    const seen = new Set();
    for (const candidate of pool) {
      if (chosen.filter((c) => c.corpusLanguage === language).length >= UNMARKED_FILES_PER_LANGUAGE) break;
      if (seen.has(candidate.digest)) continue;
      seen.add(candidate.digest);
      chosen.push(candidate);
    }
  }

  return { chosen, available, rejected: rejected.sort((a, b) => a.path.localeCompare(b.path)) };
}

/**
 * The marked sample: one branch per block, in every marked file that can carry a site.
 *
 * The design asks for 23, one per block. What the corpus grants is measured here rather than
 * assumed, and it is less, for a reason that is a property of the corpus and not of this code:
 * **in seven of the sixteen marked files the block is substantially the whole file**, so no line
 * in them clears {@link BLOCK_CLEARANCE}. Those blocks are reported in `unreachable` with the
 * measurement that rules them out, never dropped.
 *
 * Where a file carries several blocks the branches are separate — one per block, at spread sites —
 * but they are not independent samples, and the plan says so: one edit puts the **file** on a
 * pass's `context_paths`, so every block in it is expected off-diff on every one of its branches.
 * `expect.offDiff.blocks` carries all of them; `pairedBlock` names the one the branch exists for.
 *
 * @param {Map<string, string>} tree
 */
export function selectMarkedBlocks(tree) {
  const inventory = buildInventory(tree, new Map());
  /** @type {Map<string, object[]>} */
  const byFile = new Map();
  for (const block of inventory.blocks) {
    if (!byFile.has(block.file)) byFile.set(block.file, []);
    byFile.get(block.file).push(block);
  }

  const chosen = [];
  const unreachable = [];
  const seenDigests = new Map();

  for (const file of [...byFile.keys()].sort()) {
    const blocks = byFile.get(file);
    const source = tree.get(file);
    const digest = sha256(source);

    if (seenDigests.has(digest)) {
      for (const block of blocks) {
        unreachable.push({
          block: block.id,
          file,
          reason: `byte-identical to ${seenDigests.get(digest)}, which already carries this block`,
        });
      }
      continue;
    }
    seenDigests.set(digest, file);

    const sites = neutralEditSites(source, file);
    if (sites.length < blocks.length) {
      const { lines } = splitLines(source);
      const covered = new Set();
      for (const b of blocks) for (let n = b.start; n <= b.end; n++) covered.add(n);
      for (const block of blocks) {
        unreachable.push({
          block: block.id,
          file,
          reason:
            `${sites.length} site(s) clear every block by ${BLOCK_CLEARANCE} lines, and the file ` +
            `needs ${blocks.length} — ${covered.size} of its ${lines.length} lines are inside a block`,
        });
      }
      continue;
    }

    blocks.forEach((block, index) => {
      chosen.push({
        block,
        file,
        blocksInFile: blocks,
        line: siteFor(sites, index, blocks.length),
        sites,
      });
    });
  }

  return {
    chosen,
    unreachable: unreachable.sort((a, b) => a.block.localeCompare(b.block)),
    blocks: inventory.blocks.length,
    files: byFile.size,
  };
}

/* -------------------------------------------------------------------------- */
/* The plan                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * A block's span after an insertion at `line`, in the edited file's own coordinates.
 *
 * Carried because the scorer resolves an off-diff finding to a block by line, and the branch it is
 * scoring is the edited file, not the base tree. Recomputing it downstream from "the base tree,
 * plus one" is the arithmetic this field exists to not have to trust.
 */
function shiftSpan(block, line) {
  return [block.start + (block.start >= line ? 1 : 0), block.end + (block.end >= line ? 1 : 0)];
}

/**
 * Build the control-branch plan.
 *
 * Pure and total: a `Map` in, a plain JSON-safe object out. No git, no filesystem, no clock, no
 * absolute path — two runs over the same tree produce byte-identical output, which
 * `test/controls.test.mjs` asserts rather than assumes, because "deterministic" is the property
 * that lets a result cite a branch plan by digest instead of shipping it.
 *
 * @param {Map<string, string>} tree the repaired base tree, markers still in place
 */
export function planControlBranches(tree) {
  if (!(tree instanceof Map)) throw new ControlRefused("planControlBranches takes the tree as a Map");

  const unmarked = selectUnmarkedFiles(tree);
  const marked = selectMarkedBlocks(tree);
  const branches = [];

  for (const candidate of unmarked.chosen) {
    const source = tree.get(candidate.path);
    const line = siteFor(candidate.sites, 0, 1);
    const content = applyNeutralEdit(source, candidate.path, line);
    branches.push({
      class: "unmarked-file",
      branch: `control/unmarked/${slugFor(candidate.path)}`,
      path: candidate.path,
      language: languageFor(candidate.path),
      corpusLanguage: candidate.corpusLanguage,
      editLine: line,
      comment: `${commentIntroducerFor(candidate.path)} ${NEUTRAL_COMMENT_TEXT}`,
      baseSha256: sha256(source),
      contentSha256: sha256(content),
      content,
      pairedBlock: null,
      expect: {
        lanes: CONTROL_CLASSES["unmarked-file"].lanes,
        onDiff: { findings: 0 },
        offDiff: { blocks: [], answerKey: "none" },
        rule7: { findings: 0 },
        suppressedByBranch: 0,
        note:
          "the diff is one inert comment, so every on-diff finding here is a false positive and " +
          "this branch is a denominator for that rate. An off-diff finding is not: Juice Shop is " +
          "a deliberately vulnerable application and only 23 of its weaknesses are marked, so a " +
          "finding about code this branch did not change has no answer key and is unscored",
      },
    });
  }

  for (const candidate of marked.chosen) {
    const source = tree.get(candidate.file);
    const content = applyNeutralEdit(source, candidate.file, candidate.line);
    branches.push({
      class: "marked-file",
      branch: `control/marked/${candidate.block.id.toLowerCase()}-${slugFor(candidate.file)}`,
      path: candidate.file,
      language: languageFor(candidate.file),
      corpusLanguage: corpusLanguageOf(candidate.file),
      editLine: candidate.line,
      comment: `${commentIntroducerFor(candidate.file)} ${NEUTRAL_COMMENT_TEXT}`,
      baseSha256: sha256(source),
      contentSha256: sha256(content),
      content,
      pairedBlock: candidate.block.id,
      expect: {
        lanes: CONTROL_CLASSES["marked-file"].lanes,
        onDiff: { findings: 0 },
        offDiff: {
          answerKey: "blocks",
          // Every block in the file, not just the paired one: one edit seats the whole file on the
          // pass's `context_paths`, and a scorer told to expect one block would read the others'
          // findings as unexplained.
          blocks: candidate.blocksInFile.map((b) => ({
            block: b.id,
            keys: [...b.keys],
            span: shiftSpan(b, candidate.line),
            paired: b.id === candidate.block.id,
          })),
        },
        rule7: { findings: 0 },
        suppressedByBranch: 0,
        note:
          "the edit clears every block in this file by at least " +
          `${BLOCK_CLEARANCE} lines, so no block line reaches the diff's ${DIFF_CONTEXT_LINES} ` +
          "lines of context; an on-diff finding here is a false positive and an off-diff finding " +
          "on a listed block is the measurement",
      },
    });
  }

  branches.sort((a, b) => a.branch.localeCompare(b.branch));

  const byCorpusLanguage = {};
  for (const b of branches) {
    byCorpusLanguage[b.class] ??= {};
    byCorpusLanguage[b.class][b.corpusLanguage] = (byCorpusLanguage[b.class][b.corpusLanguage] ?? 0) + 1;
  }

  return {
    classes: CONTROL_CLASSES,
    comment: { text: NEUTRAL_COMMENT_TEXT, introducers: COMMENT_INTRODUCER_BY_EXTENSION },
    branches,
    counts: {
      total: branches.length,
      byClass: {
        "unmarked-file": branches.filter((b) => b.class === "unmarked-file").length,
        "marked-file": branches.filter((b) => b.class === "marked-file").length,
      },
      byCorpusLanguage,
      unmarkedAvailable: unmarked.available,
      markedBlocks: marked.blocks,
      markedFiles: marked.files,
      markedBlocksCovered: marked.chosen.length,
      markedBlocksUnreachable: marked.unreachable.length,
      /** Distinct files the marked class reaches. Fewer than its branches, by design and by count. */
      markedFilesCovered: new Set(marked.chosen.map((c) => c.file)).size,
    },
    unreachable: marked.unreachable,
  };
}

/**
 * The tree one branch is cut to: the base tree with exactly one file replaced.
 *
 * Returned whole rather than as a patch because that is what the corpus-wide checks take — the
 * suppression count, the strip verifier and the parse gate all read a tree, and a check that read
 * a patch would be answering a smaller question than the one asked.
 *
 * @param {Map<string, string>} tree
 * @param {{path: string, content: string}} branch
 */
export function controlTree(tree, branch) {
  if (!tree.has(branch.path)) throw new ControlRefused(`${branch.path} is not in this tree`);
  const out = new Map(tree);
  out.set(branch.path, branch.content);
  return out;
}

/* -------------------------------------------------------------------------- */
/* The verifier                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Hold a plan to every clause of "neutral", branch by branch.
 *
 * Findings rather than throws, so one run names everything that is wrong instead of the first
 * thing. The parse gate is not here — it needs a container and a tree on disk, and a verifier that
 * could only run where Docker runs would be a verifier nobody runs. `test/controls.test.mjs` pairs
 * this with that.
 *
 * @param {Map<string, string>} tree
 * @param {ReturnType<typeof planControlBranches>} plan
 */
export function verifyControlPlan(tree, plan) {
  const findings = [];
  const fail = (branch, reason) => findings.push({ branch, reason });
  const seenBranches = new Set();
  const seenContent = new Map();

  if (!NEUTRAL_COMMENT_ALPHABET.test(NEUTRAL_COMMENT_TEXT)) {
    fail("(all)", "the control comment is not drawn from NEUTRAL_COMMENT_ALPHABET");
  }

  for (const branch of plan.branches) {
    const name = branch.branch;
    if (seenBranches.has(name)) fail(name, "duplicate branch name");
    seenBranches.add(name);
    if (!/^control\/(unmarked|marked)\/[a-z0-9-]+$/.test(name)) fail(name, "branch name is not a stable slug");

    const source = tree.get(branch.path);
    if (source === undefined) {
      fail(name, `${branch.path} is not in the tree`);
      continue;
    }
    if (sha256(source) !== branch.baseSha256) fail(name, "baseSha256 is not this tree's file");
    if (sha256(branch.content) !== branch.contentSha256) fail(name, "contentSha256 is not this content");

    // 1. a pure single-line insertion: take the line back out and the file must return.
    const { lines, eol } = splitLines(branch.content);
    const inserted = lines[branch.editLine - 1];
    const without = lines.slice();
    without.splice(branch.editLine - 1, 1);
    if (without.join(eol) !== source) fail(name, "removing the inserted line does not give the original file back");
    if (inserted !== branch.comment) fail(name, "the line at editLine is not the declared comment");

    // 2. the comment is a comment, from the pinned alphabet, in code context.
    const introducer = commentIntroducerFor(branch.path);
    if (introducer == null) fail(name, "no comment introducer is declared for this extension");
    else if (!inserted.startsWith(`${introducer} `)) fail(name, "the inserted line does not open with the introducer");
    if (!NEUTRAL_COMMENT_ALPHABET.test(inserted.slice((introducer ?? "").length + 1))) {
      fail(name, "the comment body is outside NEUTRAL_COMMENT_ALPHABET");
    }
    if (!codeContextAt(source, branch.editLine, branch.path)) fail(name, "the site is not in code context");

    // 3. never a tool-config file, never a stripped path, never an unsafe target.
    if (TOOL_CONFIG_BASENAMES.includes(basenameOf(branch.path))) fail(name, "edits a tool-config file");
    if (isStrippedPath(branch.path)) fail(name, "edits a path that leaves every scored tree");
    if (!isSafeTarget(branch.path)) fail(name, "edits a path the parse gate would refuse");

    // 4. it survives stripping: the comment is not a marker, and the file's marker mentions and
    //    surviving block spans are what they were.
    const strippedBefore = stripMarkers(source);
    const strippedAfter = stripMarkers(branch.content);
    if (parseMarker(inserted) != null) fail(name, "the comment parses as a marker");
    if (inserted.includes(MARKER_TOKEN)) fail(name, "the comment carries the marker token");
    if (strippedAfter.removed !== strippedBefore.removed) fail(name, "stripping removes a different number of markers");
    const strippedLines = splitLines(strippedAfter.source).lines;
    if (!strippedLines.includes(branch.comment)) fail(name, "the comment does not survive stripping");

    // 5. it manufactures no suppression.
    const suppressions = countSuppressions(new Map([[branch.path, branch.content]]));
    if (Object.values(suppressions).some((n) => n !== 0)) {
      fail(name, `the edited file carries a suppression: ${JSON.stringify(suppressions)}`);
    }

    // 6. the class's own claim about blocks.
    const blocks = findBlocks(source).filter((b) => b.end > 0);
    if (branch.class === "unmarked-file") {
      if (blocks.length !== 0) fail(name, "an unmarked-file control edits a file with a marked block");
      if (source.includes(MARKER_TOKEN)) fail(name, "an unmarked-file control edits a file mentioning the marker token");
      if (branch.expect.offDiff.blocks.length !== 0) fail(name, "an unmarked-file control expects an off-diff block");
    } else {
      if (blocks.length === 0) fail(name, "a marked-file control edits a file with no block");
      for (const b of blocks) {
        const clear = branch.editLine <= b.start - BLOCK_CLEARANCE || branch.editLine >= b.end + 1 + BLOCK_CLEARANCE;
        if (!clear) fail(name, `the site is within ${BLOCK_CLEARANCE} lines of the block at ${b.start}-${b.end}`);
      }
      const expected = branch.expect.offDiff.blocks;
      if (expected.length !== blocks.length) fail(name, "the expected off-diff blocks are not the file's blocks");
      if (expected.filter((b) => b.paired).length !== 1) fail(name, "exactly one expected block must be the paired one");
      // The spans are what the edited file actually carries, not the base tree's plus one.
      const after = findBlocks(branch.content).filter((b) => b.end > 0);
      const actual = after.map((b) => `${b.start}-${b.end}`).sort();
      const claimed = expected.map((b) => `${b.span[0]}-${b.span[1]}`).sort();
      if (actual.join(",") !== claimed.join(",")) fail(name, `block spans after the edit are ${actual} and the plan says ${claimed}`);
    }

    // 7. one measurement per branch: no two branches may ship the same bytes.
    const key = branch.contentSha256;
    if (seenContent.has(key)) fail(name, `ships the same bytes as ${seenContent.get(key)}`);
    seenContent.set(key, name);
  }

  return { ok: findings.length === 0, findings, branches: plan.branches.length };
}
