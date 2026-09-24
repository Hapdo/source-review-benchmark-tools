/**
 * Splicing a codefix variant back into the tree it was extracted from.
 *
 * ## The problem, in one sentence
 *
 * A variant is an edit of the **displayed snippet**, the snippet is a non-contiguous subsequence
 * of the block's file lines with marker comments taken off, and the lines it skips are live code —
 * so writing a variant over the block's line range deletes working code, and writing it over the
 * snippet's line range does not parse.
 *
 * `models/user.ts` is the case that makes this concrete: a 40-line block whose snippet is 7 lines,
 * because 32 lines sit in a `hide-start`..`hide-end` region and one more is the `start` marker's
 * own line, which carries the arrow function the other 39 lines live inside.
 *
 * ## How it works
 *
 * 1. Extract the snippet with its line map ({@link extractSnippet}).
 * 2. Diff snippet against variant with the same `diffLines` upstream's own safety net uses, so the
 *    alignment is the one `rsn/cache.json` locks.
 * 3. Replay the diff over *file* lines: a kept snippet line re-emits its original file line
 *    verbatim — preserving its `vuln-line`/`neutral-line` comment and its indentation for free —
 *    a dropped one emits nothing, and an added one emits the variant's text.
 * 4. Re-interleave the hidden lines, each anchored to the last snippet line above it.
 *
 * ## Two placement rules that are not obvious, and both were bugs first
 *
 * **The block's own `start` and `end` markers are brackets, not content.** Anchoring them like
 * ordinary hidden lines puts the `end` marker wherever the last surviving snippet line happens to
 * land — which, when a variant replaces the tail of a block, is *before* the replacement. The
 * first draft of this module produced a `securityQuestions.yml` whose entire block was outside its
 * own markers, and a `server.ts` whose `})` closed a `finale.resource({` from beyond the block
 * end. Both still parsed as YAML and TypeScript. Both had an empty snippet.
 *
 * An `end` marker may be a **suffix on live code** (`models/user.ts:75`, `routes/chat.ts:188`), so
 * bracketing it means splitting that line: the code part stays where the diff puts it, the marker
 * comment becomes a line of its own at the block end. That normalisation is deliberate — it is
 * snippet-preserving, it makes the bracket rule total, and the repaired tree is a generated
 * artifact where uniformity is worth more than resemblance to upstream's formatting.
 *
 * The marker comment is kept whole, to the end of its line, and nothing after it is re-emitted.
 * When the block is addressed by a key that is not the last one a multi-key `end` marker names,
 * the boundary match stops short of the line's end and the rest comes back as `endMarkerRest`.
 * That text is the other keys, not code, and it is already in the comment. Until HD-81 it was
 * called `suffix` and written out a second time as a line of its own, in 45 of the corpus's 121
 * variant splices, and the round trip could not see it — which is why {@link assertConfined}
 * exists.
 *
 * **Hidden lines anchored to a replaced line follow the replacement, not the deletion.** `diffLines`
 * emits `removed` before `added`, so flushing hidden lines as soon as their anchor is passed puts
 * a 32-line `hide` region *above* the code that replaced the line it hung from. Pending hidden
 * lines are therefore held across an immediately following `added` part.
 *
 * ## What it refuses to do
 *
 * Upstream's marker stripping can glue two file lines into one snippet line — `app.routing.ts`'s
 * B05 snippet contains `   {`, three spaces, made from a nested `start` marker's residue and the
 * `{` on the next line. A **kept** such line is fine and re-emits both file lines. A **dropped**
 * one has no single file line to delete, and this module throws rather than guess. That is not
 * hypothetical: it is what the four `chatbotGreedyInjectionChallenge` variants do, and
 * {@link spliceNestedBlock} is the supported way through it.
 */
import { diffLines } from "diff";
import { extractSnippet, parseMarker, splitLines } from "./markers.mjs";
import { filterString } from "./rsn.mjs";

export class SpliceRefused extends Error {
  constructor(message) {
    super(message);
    this.name = "SpliceRefused";
  }
}

/**
 * Splice one variant into one file.
 *
 * @param {string} source whole file contents
 * @param {string} challengeKey the block's key
 * @param {string} variantText contents of the codefix file
 * @returns {{source: string, stats: {kept: number, dropped: number, added: number, hidden: number, syntheticKept: number}}}
 */
export function spliceVariant(source, challengeKey, variantText) {
  const snip = extractSnippet(source, challengeKey);
  const { lines: fileLines, eol } = splitLines(source);

  const openLine = fileLines[snip.spanStart - 1];
  const closeRaw = fileLines[snip.spanEnd - 1];
  const closeMarker = parseMarker(closeRaw);
  if (closeMarker == null) {
    throw new SpliceRefused(`${challengeKey}: no end marker on line ${snip.spanEnd}`);
  }
  // Split the closing line into the code that precedes the marker and the marker comment itself.
  // The comment runs to the end of the line, so it carries every key the marker names — including
  // any the boundary match stopped short of, which is all `snip.endMarkerRest` is. Nothing on this
  // line after the marker is code, so nothing else is re-emitted.
  const closeCode = closeRaw.slice(0, closeMarker.index).replace(/\s+$/, "");
  const closeComment = indentOf(closeRaw) + closeRaw.slice(closeMarker.index);
  if (!closeComment.endsWith(snip.endMarkerRest)) {
    throw new SpliceRefused(
      `${challengeKey}: the end marker on line ${snip.spanEnd} does not carry what follows the ` +
        `boundary key (${JSON.stringify(snip.endMarkerRest)}). The line holds a second marker, and ` +
        `this module will not guess which one closes the block.`,
    );
  }

  // Hidden lines anchor to the last snippet line above them. The two bracket lines are excluded:
  // they are emitted first and last unconditionally.
  const interiorHidden = snip.hidden.filter(
    (h) => h.fileLine !== snip.spanStart && h.fileLine !== snip.spanEnd,
  );
  /** @type {Map<number, string[]>} */
  const hiddenByAnchor = new Map();
  for (const h of interiorHidden) {
    const a = anchorOf(snip, h.fileLine);
    if (!hiddenByAnchor.has(a)) hiddenByAnchor.set(a, []);
    hiddenByAnchor.get(a).push(h.text);
  }

  const out = [];
  const stats = { kept: 0, dropped: 0, added: 0, hidden: interiorHidden.length, syntheticKept: 0 };
  /** @type {string[]} */
  let pending = [...(hiddenByAnchor.get(-1) ?? [])];
  const flush = () => {
    out.push(...pending);
    pending = [];
  };

  let si = 0;
  const parts = diffLines(filterString(snip.snippet), filterString(variantText));
  for (let pi = 0; pi < parts.length; pi++) {
    const part = parts[pi];
    if (!part.count) continue;

    if (part.added) {
      for (const text of partLines(part.value, eol)) {
        // The snippet was `trim()`ed, so a variant line promoted to the block's first line has
        // lost the indentation the file line it replaces carried.
        out.push(si === 0 && out.length === 0 ? snip.leadWs + text : text);
        stats.added++;
      }
      flush();
      continue;
    }

    for (let k = 0; k < part.count; k++, si++) {
      const line = snip.lines[si];
      if (line == null) throw new SpliceRefused(`${challengeKey}: diff overran the snippet`);
      if (part.removed) {
        assertDroppable(line, challengeKey);
        stats.dropped++;
      } else {
        for (const f of line.fileLines) {
          out.push(f === snip.spanEnd ? closeCode : fileLines[f - 1]);
        }
        if (line.synthetic) stats.syntheticKept++;
        stats.kept++;
      }
      pending.push(...(hiddenByAnchor.get(si) ?? []));
      const heldForReplacement = k === part.count - 1 && parts[pi + 1]?.added;
      if (!heldForReplacement) flush();
    }
  }
  flush();

  const head = fileLines.slice(0, snip.spanStart - 1);
  const tail = fileLines.slice(snip.spanEnd);
  const body = [openLine, ...unshadowBlankLines(out), closeComment];
  return { source: [...head, ...body, ...tail].join(eol), stats };
}

/**
 * Move a blank line that has come to sit directly **after** a `hide-line` to directly before it.
 *
 * Upstream hides a marked line with `.*hide-line[\r\n]{0,2}`, and that quantifier is greedy: it
 * eats the marked line's own newline *and*, if the next line is empty, that line's newline too. In
 * the pinned corpus no `hide-line` is followed by a blank line, so the quantifier never fires. A
 * splice can create the adjacency — `accessLogDisclosureChallenge_3` deletes `server.ts:302`,
 * which leaves the `hide-line` on 301 against the blank line on 303 — and the block then *displays*
 * one line short of the variant that was spliced into it.
 *
 * The tree is correct either way; only the display is lossy, and the scored tree has no markers at
 * all. It is normalised anyway, because the round trip in {@link spliceVariantChecked} is the only
 * thing separating a correct splice from one that is two lines off, and an assertion with a
 * standing exception is not that. Swapping a statement with an adjacent blank line is inert in
 * every language the corpus uses.
 */
function unshadowBlankLines(lines) {
  const out = [...lines];
  for (let pass = 0; pass < out.length; pass++) {
    let moved = false;
    for (let i = 0; i < out.length - 1; i++) {
      if (parseMarker(out[i])?.type !== "hide-line") continue;
      if (out[i + 1].trim() !== "") continue;
      [out[i], out[i + 1]] = [out[i + 1], out[i]];
      moved = true;
    }
    if (!moved) break;
  }
  return out;
}

/** The last snippet line that sits entirely above `fileLine`, or -1 if none does. */
function anchorOf(snip, fileLine) {
  let anchor = -1;
  for (let i = 0; i < snip.lines.length; i++) {
    if (Math.max(...snip.lines[i].fileLines) < fileLine) anchor = i;
    else break;
  }
  return anchor;
}

function indentOf(line) {
  return line.slice(0, line.length - line.trimStart().length);
}

/** Split a diff part's value into lines without inventing a trailing empty one. */
function partLines(value, eol) {
  const lines = value.split(eol === "\r\n" ? /\r?\n/ : eol);
  if (lines.length > 0 && lines[lines.length -1] === "") lines.pop();
  return lines;
}

/**
 * Refuse the one drop that would produce a plausible, wrong tree.
 *
 * A synthetic line is one upstream's marker stripping glued together out of two file lines. There
 * is no single file line to delete, and a splicer that picked one would produce a tree that parses
 * and is wrong — the failure this module is arranged to avoid.
 */
function assertDroppable(line, challengeKey) {
  if (!line.synthetic) return;
  throw new SpliceRefused(
    `${challengeKey}: the variant deletes a snippet line glued together from file lines ` +
      `${line.fileLines.join(", ")} by upstream's marker stripping. There is no single file line ` +
      `to delete — this is an overlapping block, so splice it with spliceNestedBlock().`,
  );
}

/**
 * Splice, then prove it by re-extracting.
 *
 * The round trip is the acceptance test: if the variant really landed where the snippet was, then
 * re-displaying the block has to give the variant back. Nothing weaker separates a correct splice
 * from one that is two lines off, because both produce a file that parses.
 *
 * @returns {{source: string, stats: object}}
 */
export function spliceVariantChecked(source, challengeKey, variantText) {
  const result = spliceVariant(source, challengeKey, variantText);
  const round = extractSnippet(result.source, challengeKey).snippet;
  if (filterString(round).trim() !== filterString(variantText).trim()) {
    throw new SpliceRefused(
      `${challengeKey}: round trip failed — re-extracting the spliced block did not give the ` +
        `variant back. The alignment is wrong.`,
    );
  }
  assertConfined(source, result.source, challengeKey);
  return result;
}

/**
 * Prove a splice changed nothing outside the block it was aimed at.
 *
 * The round trip above re-displays the block, and the display ends where the boundary match ends
 * — on the key it was given. Anything a splice writes past that point is invisible to it. That is
 * not hypothetical: until HD-81 the splicer wrote the rest of a multi-key `end` marker's key list
 * as a bare line after the marker, in 8 of the corpus's 23 blocks, and every one of those splices
 * passed the round trip. So the round trip is half a proof, and this is the other half: every line
 * above the block, the `start` marker line itself, and every line after the `end` marker are
 * byte-identical to the source's, and the `end` marker names the same keys it did.
 *
 * Exported so a caller that splices by some other route can hold itself to the same standard.
 *
 * @param {string} before whole file contents the splice started from
 * @param {string} after whole file contents the splice produced
 * @param {string} challengeKey the key the splice addressed
 */
export function assertConfined(before, after, challengeKey) {
  const was = extractSnippet(before, challengeKey);
  const is = extractSnippet(after, challengeKey);
  const a = splitLines(before).lines;
  const b = splitLines(after).lines;
  const refuse = (what) => {
    throw new SpliceRefused(`${challengeKey}: the splice ${what}. A splice may only rewrite its own block.`);
  };
  if (is.spanStart !== was.spanStart) refuse(`moved the block's start marker from line ${was.spanStart} to ${is.spanStart}`);
  for (let i = 0; i < was.spanStart - 1; i++) {
    if (a[i] !== b[i]) refuse(`changed line ${i + 1}, above the block`);
  }
  if (a[was.spanStart - 1] !== b[is.spanStart - 1]) refuse(`changed the block's start marker line`);
  const tailA = a.slice(was.spanEnd);
  const tailB = b.slice(is.spanEnd);
  if (tailA.length !== tailB.length) {
    refuse(
      `left ${tailB.length - tailA.length} extra line(s) after the block's end marker ` +
        `(first: ${JSON.stringify(tailB[0] ?? "")})`,
    );
  }
  for (let i = 0; i < tailA.length; i++) {
    if (tailA[i] !== tailB[i]) refuse(`changed line ${was.spanEnd + 1 + i} of the source, below the block`);
  }
  const endWas = parseMarker(a[was.spanEnd - 1]);
  const endIs = parseMarker(b[is.spanEnd - 1]);
  if (endIs?.type !== "end" || endIs.keys.join(" ") !== endWas.keys.join(" ")) {
    refuse(`changed the end marker from ${JSON.stringify(endWas.keys)} to ${JSON.stringify(endIs?.keys ?? null)}`);
  }
}

/**
 * Splice a block that **contains another block**, by lifting the inner block's markers out of the
 * way, splicing, and putting them back.
 *
 * ### Why this exists
 *
 * Inventory fact 2: `routes/chat.ts` line 188 carries one `end` marker closing two `start`s, and
 * B13 (81–188) contains B14 (175–188). When B13's snippet is displayed, upstream's global `start`
 * regex removes B14's marker on line 175 and glues its residue to line 176, producing one snippet
 * line out of two file lines. All four `chatbotGreedyInjectionChallenge` variants delete that
 * line, so all four are unspliceable by the ordinary path — a quarter of the corpus's
 * chat-injection coverage, and both of the blocks phase 5 has to rule on for the rule-7 detector.
 *
 * ### What it does
 *
 * The inner `start` marker is removed from the tree, the outer block is spliced normally, and the
 * marker is re-attached to the line that now begins the inner block — located by content, since
 * the splice has moved it. If the inner block's opening line did not survive the splice, that is
 * reported rather than patched: a variant that deletes the inner block's first line has changed
 * what the inner block *is*, and phase 6 must decide that, not this function.
 *
 * @param {string} source
 * @param {string} outerKey the containing block's key
 * @param {string} innerKey the contained block's key
 * @param {string} variantText a variant of the **outer** block
 */
export function spliceNestedBlock(source, outerKey, innerKey, variantText) {
  const { lines, eol } = splitLines(source);
  const innerStartIdx = lines.findIndex((l) => {
    const m = parseMarker(l);
    return m?.type === "start" && m.keys.includes(innerKey);
  });
  if (innerStartIdx < 0) throw new SpliceRefused(`no start marker for inner key ${innerKey}`);

  const innerMarkerLine = lines[innerStartIdx];
  // The line the inner block opens on, which is what the marker has to end up above again.
  const innerOpensOn = lines[innerStartIdx + 1];

  const lifted = [...lines.slice(0, innerStartIdx), ...lines.slice(innerStartIdx + 1)].join(eol);
  const spliced = spliceVariant(lifted, outerKey, variantText);

  const splicedLines = splitLines(spliced.source).lines;
  const reattachAt = splicedLines.findIndex((l) => l === innerOpensOn);
  if (reattachAt < 0) {
    throw new SpliceRefused(
      `${outerKey}: the variant removed the line the inner block ${innerKey} opens on ` +
        `(${JSON.stringify(innerOpensOn.trim())}), so there is nowhere to re-attach its start ` +
        `marker. Decide what the inner block means under this variant before splicing it.`,
    );
  }

  const restored = [
    ...splicedLines.slice(0, reattachAt),
    innerMarkerLine,
    ...splicedLines.slice(reattachAt),
  ].join(eol);

  const round = extractSnippet(restored, outerKey).snippet;
  if (filterString(round).trim() !== filterString(variantText).trim()) {
    throw new SpliceRefused(`${outerKey}: round trip failed after re-attaching ${innerKey}`);
  }
  assertConfined(source, restored, outerKey);
  return { source: restored, stats: spliced.stats };
}
