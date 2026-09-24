/**
 * Juice Shop's `vuln-code-snippet` marker grammar, and the two snippet extractors built on it.
 *
 * ## Why there are two extractors
 *
 * {@link extractSnippetUpstream} is a literal port of
 * `lib/codingChallenges.ts#getCodingChallengeFromFileContent`, regex for regex. It does no work.
 * It exists so that {@link extractSnippet} — which produces the same text *plus* the file-line map
 * the splicer needs — can be checked against the thing it imitates, on every key, in a test.
 *
 * That arrangement is the point of this file. A line map that is subtly wrong does not fail: it
 * splices a variant two lines off and produces a tree that still parses. The only cheap way to
 * know the map is right is to reconstruct upstream's string from it and demand equality.
 *
 * ## The grammar, as measured rather than as documented
 *
 * Seven marker types. The upstream guide describes them as line comments, and four of the seven
 * also appear **as suffixes on live code**, which is not a detail:
 *
 * - `models/user.ts:36` — `const UserModelInit = (sequelize: Sequelize) => { // …start weakPasswordChallenge`
 * - `models/user.ts:75` — `      }, // …end weakPasswordChallenge`
 * - `models/user.ts:69` — `      }, // …hide-end`
 * - `routes/chat.ts:188` — `    } // …end chatbotGreedyInjectionChallenge chatbotPromptInjectionChallenge`
 *
 * A `start` suffix puts the code *before* the marker outside the snippet, because upstream's
 * boundary match begins at the comment introducer rather than at the start of the line. An `end`
 * suffix puts the code before it *inside* the snippet, as the snippet's last line. So the two
 * shapes are not symmetric, and the block's line span is not the snippet's line span.
 *
 * ## Why this is character-level and not line-level
 *
 * Upstream strips markers with four global regexes over the whole matched region, and three of
 * them do things no line-wise reimplementation reproduces by accident:
 *
 * - `\s?` eats one character of indentation before the comment, so a removed standalone marker
 *   leaves a residue rather than nothing.
 * - `[\r\n]{0,2}` is greedy, so removing a marker line can also eat a following blank line.
 * - a `start` marker **nested inside another block's region** is removed by the outer block's
 *   pass, and its residue is then glued to the following line: `app.routing.ts`'s B05 snippet
 *   contains `   {` — three spaces — where the file has `  // …start tokenSaleChallenge` followed
 *   by `  {`.
 *
 * So the region is carried as a string with a parallel array giving the source file line of every
 * character, upstream's own regexes are applied to both together, and the line map falls out of
 * the survivors. Exactness is then a property of the construction rather than a claim.
 */

/** The seven marker types, in the order the inventory reports them. */
export const MARKER_TYPES = Object.freeze([
  "start",
  "end",
  "vuln-line",
  "neutral-line",
  "hide-start",
  "hide-end",
  "hide-line",
]);

/** The marker types that carry challenge keys. The three `hide` types do not. */
export const KEYED_MARKER_TYPES = Object.freeze(["start", "end", "vuln-line", "neutral-line"]);

/**
 * The token the leak check and the strip verifier look for.
 *
 * Split so that this file does not match its own search — the same trick, and for the same
 * reason, as `findFilesWithCodeChallenges` upstream.
 */
export const MARKER_TOKEN = "vuln-code" + "-snippet";

/**
 * Matches a marker anywhere on a line, capturing its type and its (possibly empty) key list.
 *
 * `hide-start` has to be tried before `start`, and `hide-end` before `end`, or the alternation
 * matches the shorter name inside the longer one and reports a `hide-start` as a `start`.
 */
const MARKER_RE = new RegExp(
  `[/#]{0,2} ?${MARKER_TOKEN} (?<type>hide-start|hide-end|hide-line|vuln-line|neutral-line|start|end)(?<keys>[^\\r\\n]*)`,
);

/**
 * Parse the marker on a line, if it carries one.
 *
 * @param {string} line
 * @returns {{type: string, keys: string[], index: number} | null}
 */
export function parseMarker(line) {
  const m = MARKER_RE.exec(line);
  if (m?.groups == null) return null;
  return {
    type: m.groups.type,
    keys: m.groups.keys.trim().split(/\s+/).filter(Boolean),
    index: m.index,
  };
}

/**
 * Split text into lines, remembering which newline convention it used.
 *
 * Upstream tries `\r\n`, then `\n`, then `\r`, and the corpus is `\n` throughout. Doing the same
 * here means a future pin that ships CRLF does not silently produce one-line snippets.
 *
 * @param {string} text
 */
export function splitLines(text) {
  for (const eol of ["\r\n", "\n", "\r"]) {
    if (text.includes(eol)) return { lines: text.split(eol), eol };
  }
  return { lines: [text], eol: "\n" };
}

export class BrokenBoundary extends Error {
  constructor(message) {
    super(message);
    this.name = "BrokenBoundary";
  }
}

/* -------------------------------------------------------------------------- */
/* The oracle                                                                  */
/* -------------------------------------------------------------------------- */

/** Upstream's four marker-stripping regexes, in upstream's order. Shared with {@link extractSnippet}. */
function upstreamStripRegexes() {
  return [
    new RegExp(`\\s?[/#]{0,2} ${MARKER_TOKEN} start.*[\\r\\n]{0,2}`, "g"),
    new RegExp(`\\s?[/#]{0,2} ${MARKER_TOKEN} end.*`, "g"),
    new RegExp(`.*[/#]{0,2} ${MARKER_TOKEN} hide-line[\\r\\n]{0,2}`, "g"),
    new RegExp(`.*[/#]{0,2} ${MARKER_TOKEN} hide-start([^])*[/#]{0,2} ${MARKER_TOKEN} hide-end[\\r\\n]{0,2}`, "g"),
  ];
}

/** Upstream's boundary match for one key. Greedy `([^])*`, so it runs to the *last* `end` naming the key. */
function upstreamBoundaryRegex(challengeKey) {
  return new RegExp(
    `[/#]{0,2} ${MARKER_TOKEN} start.*${challengeKey}([^])*${MARKER_TOKEN} end.*${challengeKey}`,
  );
}

/**
 * A literal port of upstream's `getCodingChallengeFromFileContent`. The oracle, not the tool.
 *
 * @param {string} source whole file contents
 * @param {string} challengeKey
 * @returns {{challengeKey: string, snippet: string, vulnLines: number[], neutralLines: number[]}}
 */
export function extractSnippetUpstream(source, challengeKey) {
  const snippets = source.match(upstreamBoundaryRegex(challengeKey));
  if (snippets == null) throw new BrokenBoundary("Broken code snippet boundaries for: " + challengeKey);
  let snippet = snippets[0];
  for (const re of upstreamStripRegexes()) snippet = snippet.replace(re, "");
  snippet = snippet.trim();

  let lines = snippet.split("\r\n");
  if (lines.length === 1) lines = snippet.split("\n");
  if (lines.length === 1) lines = snippet.split("\r");
  const vulnLines = [];
  const neutralLines = [];
  for (let i = 0; i < lines.length; i++) {
    if (new RegExp(`${MARKER_TOKEN} vuln-line.*${challengeKey}`).exec(lines[i]) != null) {
      vulnLines.push(i + 1);
    } else if (new RegExp(`${MARKER_TOKEN} neutral-line.*${challengeKey}`).exec(lines[i]) != null) {
      neutralLines.push(i + 1);
    }
  }
  snippet = snippet.replace(new RegExp(`\\s?[/#]{0,2} ${MARKER_TOKEN} vuln-line.*`, "g"), "");
  snippet = snippet.replace(new RegExp(`\\s?[/#]{0,2} ${MARKER_TOKEN} neutral-line.*`, "g"), "");
  return { challengeKey, snippet, vulnLines, neutralLines };
}

/* -------------------------------------------------------------------------- */
/* Provenance-carrying string                                                  */
/* -------------------------------------------------------------------------- */

/**
 * A string paired with, for every character, the 1-based source file line it came from.
 *
 * Every operation below deletes ranges from both halves at once, so the provenance can never
 * drift from the text.
 */
class TracedText {
  /** @param {string} text @param {Int32Array|number[]} origin */
  constructor(text, origin) {
    this.text = text;
    this.origin = origin;
  }

  /**
   * Build from whole-file content and an absolute character range.
   *
   * @param {string} source
   * @param {number} from inclusive character index
   * @param {number} to exclusive character index
   */
  static fromRange(source, from, to) {
    const origin = new Int32Array(to - from);
    let line = 1;
    for (let i = 0; i < from; i++) if (source[i] === "\n") line++;
    for (let i = from; i < to; i++) {
      origin[i - from] = line;
      if (source[i] === "\n") line++;
    }
    return new TracedText(source.slice(from, to), origin);
  }

  /** Apply one global regex, deleting every match from text and provenance together. */
  replaceAll(re) {
    const keep = [];
    let last = 0;
    re.lastIndex = 0;
    for (const m of this.text.matchAll(re)) {
      keep.push([last, m.index]);
      last = m.index + m[0].length;
      if (m[0].length === 0) last = m.index; // a zero-width match would loop; upstream has none
    }
    keep.push([last, this.text.length]);
    return this.#splice(keep);
  }

  /**
   * `String.prototype.trim`, carried through to the provenance.
   *
   * Also reports the whitespace it ate off the **first and last surviving lines** — not the whole
   * removed run, which may span blank lines. The splicer needs exactly that much: a variant line
   * promoted to first in the block has lost the indentation `trim()` took, and re-emitting it
   * without the indentation re-indents the head of every block it touches.
   */
  trim() {
    let a = 0;
    let b = this.text.length;
    while (a < b && /\s/.test(this.text[a])) a++;
    while (b > a && /\s/.test(this.text[b - 1])) b--;
    const lead = this.text.slice(0, a);
    const tail = this.text.slice(b);
    return {
      traced: this.#splice([[a, b]]),
      leadWs: lead.slice(lead.lastIndexOf("\n") + 1),
      tailWs: tail.includes("\n") ? tail.slice(0, tail.indexOf("\n")) : tail,
    };
  }

  #splice(ranges) {
    let text = "";
    const origin = [];
    for (const [a, b] of ranges) {
      text += this.text.slice(a, b);
      for (let i = a; i < b; i++) origin.push(this.origin[i]);
    }
    return new TracedText(text, origin);
  }

  /**
   * Split into lines, each carrying the distinct source file lines its characters came from.
   *
   * @param {string} eol
   * @returns {{text: string, fileLines: number[]}[]}
   */
  toLines(eol) {
    /** @type {{text: string, fileLines: number[]}[]} */
    const out = [];
    let text = "";
    /** @type {number[]} */
    let seen = [];
    const flush = () => {
      out.push({ text, fileLines: seen });
      text = "";
      seen = [];
    };
    for (let i = 0; i < this.text.length; i++) {
      const ch = this.text[i];
      const o = this.origin[i];
      // The terminator counts towards the line it ends. Without this a *blank* line has no
      // characters of its own and so no provenance at all — it then reads as a file line the
      // snippet never showed, which is the definition of a hidden line. Four variants spliced
      // one blank line out of place before this was `continue`.
      if (seen[seen.length - 1] !== o) seen.push(o);
      if (ch === "\n" || (eol === "\r" && ch === "\r")) {
        flush();
        continue;
      }
      if (ch === "\r" && eol === "\r\n") continue;
      text += ch;
    }
    flush();
    return out;
  }
}

/* -------------------------------------------------------------------------- */
/* The tool                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Upstream's snippet, plus the map from snippet line to source file line.
 *
 * ### What the map is for
 *
 * A variant in `data/static/codefixes/` is an edit of the *displayed snippet*, which is neither
 * the block's file lines nor a contiguous run of them. Splicing a variant back therefore needs to
 * know, for snippet line *i*, which file line it came from — and which file lines lie between
 * snippet lines, because those are the hidden ones and they are live code (inventory fact 3:
 * `models/user.ts` is a 40-line block whose snippet is 7 lines).
 *
 * ### The shape returned
 *
 * - `lines[i] = { text, fileLines, marker, synthetic }`. `fileLines` is every source line that
 *   contributed a character. It is normally one. It is more than one where upstream's marker
 *   removal glued two file lines into one snippet line, and `synthetic` says so — the splicer
 *   refuses to edit those rather than guessing which file line an edit belongs to.
 * - `marker` is the `vuln-line`/`neutral-line` comment taken off the line, so a splice that does
 *   not change the line can put it back.
 * - `hidden` — every file line in the block the snippet does not show, with the reason it is
 *   hidden. These are preserved verbatim by the splicer.
 * - `spanStart`/`spanEnd` — the file lines the splice may rewrite, being the marker lines' own
 *   span.
 * - `prefix` — live code on the `start` marker's line, before the marker. It is outside the
 *   snippet and must survive a splice.
 * - `endMarkerRest` — what follows the boundary key on the `end` marker's line. It is **never
 *   code**: upstream's `end.*` runs to the end of the line, so this is the rest of the marker
 *   comment — the other keys a multi-key `end` marker names, or nothing. It belongs to the
 *   marker, and a splice that keeps the marker keeps it. It used to be called `suffix`, sat
 *   beside `prefix` as if the two were the same kind of thing, and the splicer re-emitted it as a
 *   line of its own: a bare line of key names in every block whose `end` marker names several
 *   keys and was addressed by any key but the last (HD-81).
 *
 * @param {string} source whole file contents
 * @param {string} challengeKey
 */
export function extractSnippet(source, challengeKey) {
  const { eol } = splitLines(source);
  const m = upstreamBoundaryRegex(challengeKey).exec(source);
  if (m == null) throw new BrokenBoundary(`Broken code snippet boundaries for: ${challengeKey}`);

  const from = m.index;
  const to = m.index + m[0].length;

  let traced = TracedText.fromRange(source, from, to);
  for (const re of upstreamStripRegexes()) traced = traced.replaceAll(re);
  const trimmed = traced.trim();
  traced = trimmed.traced;

  const rawLines = traced.toLines(eol);

  // Index the marked lines before taking their comments off — upstream's order, and it matters:
  // the indices are positions in the trimmed snippet, not in the file.
  const vulnLines = [];
  const neutralLines = [];
  const suffixRe = new RegExp(`\\s?[/#]{0,2} ${MARKER_TOKEN} (?:vuln-line|neutral-line).*$`);
  const lines = rawLines.map((l, i) => {
    const marker = parseMarker(l.text);
    if (marker?.type === "vuln-line" && marker.keys.includes(challengeKey)) vulnLines.push(i + 1);
    else if (marker?.type === "neutral-line" && marker.keys.includes(challengeKey)) neutralLines.push(i + 1);
    const text = l.text.replace(suffixRe, "");
    return {
      text,
      fileLines: l.fileLines,
      marker: text === l.text ? null : l.text.slice(text.length),
      synthetic: l.fileLines.length > 1,
    };
  });

  const before = source.slice(0, from);
  const spanStart = before.split("\n").length;
  const spanEnd = source.slice(0, to).split("\n").length;
  const lineStarts = lineOffsets(source);

  return {
    challengeKey,
    lines,
    hidden: hiddenLines(source, spanStart, spanEnd, lines),
    spanStart,
    spanEnd,
    /** Code on the `start` marker's line that sits before the marker, and is not in the snippet. */
    prefix: source.slice(lineStarts[spanStart - 1], from),
    /** The rest of the `end` marker comment after the boundary key. Marker text, never code. */
    endMarkerRest: source.slice(to, lineStarts[spanEnd] == null ? source.length : lineStarts[spanEnd] - 1),
    /** Indentation `trim()` took off the snippet's first line, and whitespace off its last. */
    leadWs: trimmed.leadWs,
    tailWs: trimmed.tailWs,
    vulnLines,
    neutralLines,
    eol,
    snippet: lines.map((l) => l.text).join(eol),
  };
}

/** 0-based character offset of the start of every line. */
function lineOffsets(source) {
  const offsets = [0];
  for (let i = 0; i < source.length; i++) if (source[i] === "\n") offsets.push(i + 1);
  return offsets;
}

/**
 * The file lines inside the block's span that no snippet line drew a character from.
 *
 * Derived from the map rather than re-parsed, so "hidden" means exactly "not displayed" and
 * cannot disagree with the snippet it is the complement of.
 */
function hiddenLines(source, spanStart, spanEnd, lines) {
  const { lines: fileLines } = splitLines(source);
  const shown = new Set();
  for (const l of lines) for (const f of l.fileLines) shown.add(f);
  const hidden = [];
  for (let n = spanStart; n <= spanEnd; n++) {
    if (shown.has(n)) continue;
    const text = fileLines[n - 1];
    const marker = parseMarker(text);
    hidden.push({ fileLine: n, text, reason: marker ? marker.type : "hide-region" });
  }
  return hidden;
}

/**
 * Every distinct block in a file: one per `start` marker, carrying all the keys it names.
 *
 * Pairing is **per key**, never by nesting depth. Inventory fact 2: `routes/chat.ts` has one
 * `end` on line 188 closing two `start`s, and `app.routing.ts` has two blocks overlapping across
 * 24 lines. A stack-based pairer mis-pairs all four of those blocks.
 *
 * @param {string} source
 * @returns {{start: number, end: number, keys: string[]}[]}
 */
export function findBlocks(source) {
  const { lines } = splitLines(source);
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    const m = parseMarker(lines[i]);
    if (m?.type !== "start") continue;
    let end = -1;
    for (let j = i + 1; j < lines.length; j++) {
      const e = parseMarker(lines[j]);
      if (e?.type === "end" && e.keys.some((k) => m.keys.includes(k))) end = j;
    }
    blocks.push({ start: i + 1, end: end + 1, keys: m.keys });
  }
  return blocks;
}
