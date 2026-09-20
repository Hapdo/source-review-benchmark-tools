/**
 * The parse gate — phase 4, property 1 of the repaired base tree.
 *
 * The corpus design gives the repaired tree two required properties, and this module is the first:
 *
 *   > **It parses.** It need not run — this is static review — but Semgrep in the tool child
 *   > parses, and a tree that does not will produce `limited` coverage under `malformed-output` or
 *   > `targets-unscanned`, which turns runs `unverified` and silently changes what is being
 *   > measured.
 *
 * A splice that lands two lines off produces a file that still *looks* fine. So the oracle is not
 * "a parser someone picked accepts this" — it is **the scanner the tool child actually runs**,
 * at the version it runs: `returntocorp/semgrep:1.99.0`, the same image
 * `scripts/lib/static-analysis.mjs` pins in the HapDo repository, with the same uvx fallback.
 *
 * ## Two passes, because one of them is not enough — measured, 2026-09-20
 *
 * The obvious gate is "run the tool child's scan and demand clean coverage". It was built, run,
 * and found to be **blind in three of the corpus's five languages**:
 *
 * | Language | Deliberately broken file, under `semgrep scan --json` |
 * |---|---|
 * | YAML | `errors[]` entry, `{code: 2, level: "warn", type: "Other syntax error", path}` |
 * | Docker Compose | the same — Compose is YAML to Semgrep; there is no `docker-compose` language |
 * | TypeScript | **nothing.** `errors: []`, and the file is listed in `paths.scanned` |
 * | Solidity | **nothing.** Same. |
 * | Terraform | **nothing.** Same. |
 *
 * The last three hold even for a file that is pure garbage (`}}} ))) ((( {{{ @@@ ###`). Semgrep's
 * tree-sitter front ends do error recovery: the damaged subtree is dropped, a partial AST is
 * matched against, and the run reports a clean scan of a file it only half read. Reconciled the
 * way the tool child reconciles it (`semgrep-sidecar/src/semgrep-staged.ts`), that file comes back
 * `state: "reviewed"`.
 *
 * So the documented harm is real but **understates the failure**. A mis-spliced `.ts` does not
 * make the run `unverified`; it makes the run *look* verified while the rules never see the code
 * that was damaged. That is a false negative the benchmark would score, and nothing would say so.
 *
 * Hence both passes, each answering a different question, and the verdict resting on both:
 *
 *   **parse** — `semgrep show dump-ast <language> <file>`, Semgrep's own parser entry point, which
 *     does **not** swallow recovery. Exit 0 is a clean parse; exit 2 is a raised syntax error;
 *     exit 3 is a *tolerated* error — the partial-parse case the scan hides. Both non-zero codes
 *     are findings. This pass is what makes the gate cover all five languages.
 *
 *   **scan** — the tool child's own invocation, reconciled exactly as `parseStagedSemgrep` does:
 *     an `errors[]` entry naming a file is `limited`; otherwise presence in `paths.scanned` is
 *     `reviewed`; otherwise `not-applicable(unsupported-language)`. This pass is what proves the
 *     named harm has not occurred *in the terms the harm is written in*, and it is the one that
 *     would catch a file Semgrep declines to open at all.
 *
 * The scan pass runs against a small probe ruleset carried in this file rather than against the
 * tool child's vendored rules (which live in the HapDo image, not here). That is deliberate and it
 * makes the pass *stronger*: {@link PROBE_RULES} has one rule per Semgrep language this corpus
 * uses, so every target's language certainly has an analyzer loaded. With a real ruleset, a
 * language it happens not to cover would come back `not-applicable(unsupported-language)` — a
 * clean-looking row meaning "nobody looked", which is precisely the shape a gate must not produce.
 *
 * ## What this gate is not
 *
 * It checks **grammar**, not schema. `infrastructure/docker-compose.yml` is validated as YAML; a
 * document that is well-formed YAML and nonsense Compose passes. Nothing in the corpus design asks
 * for more — the tree need not run — and a Compose schema check would be a different tool's claim.
 *
 * ## Reporting on the tree, never on the machine
 *
 * If neither Docker nor uvx can start Semgrep, the verdict is `status: "unavailable"` with
 * `ok: false` and a reason naming the tool. Never "pass", never "skipped" (ADR 0084: an unverified
 * control is not a passing one). `ok` is the structural bit — a caller that reads only `ok` cannot
 * mistake a broken toolchain for a clean tree — and `status` says which kind of non-passing it is.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { readTree } from "./corpus.mjs";
import { buildInventory } from "./inventory.mjs";

/** Kept in step with HapDo's `scripts/lib/static-analysis.mjs` and the tool child's image. */
export const SEMGREP_VERSION = "1.99.0";
export const SEMGREP_IMAGE = `returntocorp/semgrep:${SEMGREP_VERSION}`;

/**
 * Extension to Semgrep language, for the five languages the corpus spans.
 *
 * Five corpus languages, **four** Semgrep languages: Docker Compose is YAML to Semgrep —
 * `semgrep show supported-languages` on 1.99.0 lists `yaml`, `docker` and `dockerfile` and no
 * `docker-compose`. That is not a gap; it is the analyzer Compose actually gets, and a gate that
 * pretended otherwise would be claiming coverage nothing provides.
 *
 * Written out rather than inferred so an extension arriving later selects nothing and is
 * *reported* (see {@link selectTargets}) instead of quietly dropping out of the scored set.
 */
export const LANGUAGE_BY_EXTENSION = Object.freeze({
  ".ts": "ts",
  ".sol": "solidity",
  ".tf": "terraform",
  ".yml": "yaml",
  ".yaml": "yaml",
});

/** The Semgrep languages this gate can check — the distinct values of the map above. */
export const SUPPORTED_LANGUAGES = Object.freeze([...new Set(Object.values(LANGUAGE_BY_EXTENSION))].sort());

/** @param {string} relPath */
export function languageFor(relPath) {
  return LANGUAGE_BY_EXTENSION[path.extname(relPath).toLowerCase()];
}

/**
 * Paths this gate is willing to hand to a container.
 *
 * Deliberately narrow: every target travels into a shell loop's stdin and into an argv, and a
 * corpus path is a plain repository path. A path outside this set is refused as a **finding**
 * rather than normalised or skipped — refusing is a statement about the tree, skipping would be a
 * hole in the scored set.
 */
const SAFE_TARGET = /^[A-Za-z0-9._-][A-Za-z0-9._\-/]*$/;

/**
 * @param {string} relPath
 *
 * A leading dot is ordinary and must be allowed: the first cut of this regex demanded an
 * alphanumeric first character and refused 22 of upstream's own files — every
 * `.github/workflows/*.yml`, `.gitlab-ci.yml`, `.codeclimate.yml` — as `unsafe-path` on a
 * whole-tree run. The traversal check is the segment test below, not the first character.
 */
export function isSafeTarget(relPath) {
  if (!SAFE_TARGET.test(relPath)) return false;
  return relPath.split("/").every((s) => s !== "" && s !== "." && s !== "..");
}

/**
 * Splits a list of scored paths into checkable targets and findings about the rest.
 *
 * Nothing falls off the end. A scored path with an extension this gate cannot map is a finding —
 * `unsupported-extension` — because the alternative is a gate that silently covers only the
 * TypeScript files while being read as covering the tree.
 *
 * @param {readonly string[]} paths
 */
export function selectTargets(paths) {
  /** @type {{path: string, language: string}[]} */
  const targets = [];
  /** @type {{path: string, language: string|null, signal: string, detail: string}[]} */
  const findings = [];
  for (const p of [...new Set(paths)].sort()) {
    if (!isSafeTarget(p)) {
      findings.push({ path: p, language: null, signal: "unsafe-path", detail: "not a plain repository path" });
      continue;
    }
    const language = languageFor(p);
    if (!language) {
      findings.push({
        path: p,
        language: null,
        signal: "unsupported-extension",
        detail: `no Semgrep language for ${path.extname(p) || "(no extension)"}`,
      });
      continue;
    }
    targets.push({ path: p, language });
  }
  return { targets, findings };
}

/**
 * The probe ruleset for the scan pass: one rule per Semgrep language, each written so it cannot
 * match anything in the corpus.
 *
 * The rules exist only to make Semgrep *open* the file. Semgrep skips a target for which no loaded
 * rule declares its language, so without a rule per language the scan pass would report
 * `not-applicable(unsupported-language)` for Solidity, Terraform and YAML and call it a clean run.
 * The ruleset therefore is the thing that makes "all five languages" true rather than asserted.
 */
export const PROBE_RULES = `rules:
  - id: hapdo-parse-probe-ts
    languages: [ts]
    severity: INFO
    message: parse probe
    pattern: hapdoParseProbeNeverMatches(...)
  - id: hapdo-parse-probe-solidity
    languages: [solidity]
    severity: INFO
    message: parse probe
    pattern: hapdoParseProbeNeverMatches(...)
  - id: hapdo-parse-probe-terraform
    languages: [terraform]
    severity: INFO
    message: parse probe
    pattern: hapdo_parse_probe_never_matches = $X
  - id: hapdo-parse-probe-yaml
    languages: [yaml]
    severity: INFO
    message: parse probe
    pattern: "hapdo_parse_probe_never_matches: $X"
`;

/**
 * The shell loop the parse pass runs inside one container.
 *
 * One container for the whole target list, not one per file: a container start is ~0.9s and the
 * per-file parse is ~0.04s, so per-file containers would make the gate a hundred times its own
 * cost and the full-tree run unusable.
 *
 * Every field is base64 on the way out. Semgrep's parse errors quote the offending source back,
 * newlines and all, and a naive delimiter would let a *file's own bytes* forge a result row — the
 * file being, by construction, the thing the gate is suspicious of.
 *
 * `PARSE-COMPLETE` is liveness evidence, in the sense `gitleaksCompleted` and `semgrepCompleted`
 * are in HapDo: a loop that died half way through leaves a short, clean-looking result set, and
 * without the sentinel that is indistinguishable from a tree with fewer files.
 */
const PARSE_LOOP = [
  "while IFS='\t' read -r lang file; do",
  '  [ -n "$lang" ] || continue',
  '  semgrep show dump-ast "$lang" "/tree/$file" >/dev/null 2>/tmp/parse-err; rc=$?',
  `  printf 'PARSE %s %s %s\\n' "$rc" "$(printf %s "$file" | base64 | tr -d '\\n')" "$(base64 < /tmp/parse-err | tr -d '\\n')"`,
  "done",
  "printf 'PARSE-COMPLETE\\n'",
].join("\n");

/**
 * Turns Semgrep's parse stderr into one legible line.
 *
 * Two measured shapes on 1.99.0:
 *
 *   exit 2  `[..][ERROR]: Error: exception Parsing_error.Syntax_error (<path>:<line>:<col> "…")`
 *           and `Parsing_error.Other_error ((…), <path>:<line>:<col> "…")` for YAML;
 *   exit 3  `[..][ERROR]: errors=` / `tolerated errors=File <path>, line N, characters …` —
 *           tree-sitter recovered, which is the case `semgrep scan` never mentions.
 *
 * **The quoted source is dropped.** Both shapes echo the file's own bytes into the message, and a
 * gate's report is not a place to reproduce the contents of the file it is complaining about.
 *
 * @param {string} stderr
 * @param {number} exitCode
 */
export function summariseParseError(stderr, exitCode) {
  const text = stderr ?? "";
  const kind = /Parsing_error\.(\w+)/.exec(text)?.[1];
  const missing = /Missing element in input code: "([^"]*)"/.exec(text)?.[1];
  const line =
    /:(\d+):\d+ "/.exec(text)?.[1] ?? // "…(<path>:<line>:<col> "…"
    /,\s*line (\d+), characters/.exec(text)?.[1]; // "File <path>, line N, characters …"
  const where = line ? ` at line ${line}` : "";
  if (exitCode === 3) {
    // Exit 3 is the dangerous one and the summary says so, because this is exactly the file that
    // `semgrep scan` would have called `reviewed`.
    return `parsed only partially${where}${missing ? ` — missing ${JSON.stringify(missing)}` : ""} (tree-sitter recovered; the scan would call this file reviewed)`;
  }
  if (kind) return `${kind.replace(/_/g, " ").toLowerCase()}${where}`;
  const first = text.split("\n").find((l) => l.trim() !== "");
  return (first ?? `semgrep show dump-ast exited ${exitCode}`).slice(0, 200);
}

/**
 * Parses the loop's output.
 *
 * `completed` is false unless the sentinel arrived. A caller may not treat an incomplete pass as
 * evidence about any file, including the files it did report on — half a scan is not a scan.
 *
 * @param {string} stdout
 */
export function parseDumpAstOutput(stdout) {
  /** @type {Map<string, {exitCode: number, ok: boolean, detail: string}>} */
  const rows = new Map();
  let completed = false;
  for (const line of (stdout ?? "").split("\n")) {
    if (line.trim() === "PARSE-COMPLETE") {
      completed = true;
      continue;
    }
    const m = /^PARSE (\d+) ([A-Za-z0-9+/=]+) ?([A-Za-z0-9+/=]*)$/.exec(line);
    if (!m) continue;
    const exitCode = Number(m[1]);
    const file = Buffer.from(m[2], "base64").toString("utf8");
    const stderr = m[3] ? Buffer.from(m[3], "base64").toString("utf8") : "";
    rows.set(file, {
      exitCode,
      ok: exitCode === 0,
      detail: exitCode === 0 ? "" : summariseParseError(stderr, exitCode),
    });
  }
  return { completed, rows };
}

/**
 * Maps a path Semgrep reported back to a target path.
 *
 * The same job `toStagedPath` does in the sidecar, and for the same reason: the reconciliation is
 * between what the tool says it looked at and the list it was handed, and a mismatch in path shape
 * silently turns the former into the empty set.
 *
 * @param {string} reported
 * @param {string} root
 */
export function toTargetPath(reported, root) {
  if (typeof reported !== "string" || reported === "") return undefined;
  const prefix = root.endsWith("/") ? root : `${root}/`;
  if (reported.startsWith(prefix)) return reported.slice(prefix.length);
  if (!reported.startsWith("/")) return reported;
  return undefined;
}

/**
 * Reconciles a Semgrep `--json` report against the target list, exactly as the tool child does.
 *
 * Lifted from `semgrep-sidecar/src/semgrep-staged.ts` rather than reinvented, because the point of
 * the pass is to answer the question *in the terms the corpus doc states the harm in*. Same order,
 * same precedence: `errors[]` beats `paths.scanned`, and a target in neither is
 * `not-applicable(unsupported-language)`.
 *
 * `completed` is false when the envelope is not a report — unreadable JSON, a missing `results` or
 * `paths.scanned`, or a pathless entry Semgrep itself calls an `error` (the config-failed shape,
 * which is what an empty rules mount produces). ADR 0084: output we cannot read is not a clean
 * scan, and never an empty finding list.
 *
 * @param {string} stdout
 * @param {readonly {path: string, language: string}[]} targets
 * @param {string} root
 */
export function coverageFromScan(stdout, targets, root) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return { completed: false, reason: "malformed-output", rows: new Map() };
  }
  if (typeof parsed !== "object" || parsed === null) {
    return { completed: false, reason: "malformed-output", rows: new Map() };
  }
  if (!Array.isArray(parsed.results)) return { completed: false, reason: "results is missing or not an array", rows: new Map() };
  if (typeof parsed.paths !== "object" || parsed.paths === null) {
    return { completed: false, reason: "paths is missing", rows: new Map() };
  }
  if (!Array.isArray(parsed.paths.scanned)) {
    return { completed: false, reason: "paths.scanned is missing or not an array", rows: new Map() };
  }
  if (parsed.errors !== undefined && !Array.isArray(parsed.errors)) {
    return { completed: false, reason: "errors is present and not an array", rows: new Map() };
  }

  /** @type {Map<string, "timeout"|"tool-error">} */
  const failed = new Map();
  for (const error of parsed.errors ?? []) {
    const reported = error?.path ?? error?.location?.path;
    const file = reported ? toTargetPath(reported, root) : undefined;
    if (file === undefined) {
      // A pathless entry Semgrep calls an `error` leaves the report unreconcilable against the
      // target list — the shape an unreadable `--config` produces. It fails closed. A pathless
      // *warning* does not; measured, 1.99.0's syntax errors carry a path and `level: "warn"`.
      if (String(error?.level ?? "").toLowerCase() === "error") {
        return { completed: false, reason: String(error?.message ?? "unattributed semgrep error").slice(0, 200), rows: new Map() };
      }
      continue;
    }
    failed.set(file, String(error?.type ?? "").toLowerCase() === "timeout" ? "timeout" : "tool-error");
  }
  for (const skipped of parsed.paths.skipped ?? []) {
    const file = skipped?.path ? toTargetPath(skipped.path, root) : undefined;
    if (file !== undefined && !failed.has(file)) failed.set(file, "tool-error");
  }

  const scanned = new Set(
    parsed.paths.scanned.map((p) => toTargetPath(p, root)).filter((p) => p !== undefined),
  );

  /** @type {Map<string, {state: string, reason?: string}>} */
  const rows = new Map();
  for (const t of targets) {
    const failure = failed.get(t.path);
    if (failure) rows.set(t.path, { state: "limited", reason: failure });
    else if (scanned.has(t.path)) rows.set(t.path, { state: "reviewed" });
    else rows.set(t.path, { state: "not-applicable", reason: "unsupported-language" });
  }
  return { completed: true, rows };
}

/**
 * Combines the two passes into one verdict.
 *
 * Findings first, then incompleteness, then pass — the order `classifySemgrepRun` uses in HapDo,
 * and for its reason: a real finding reported as a broken environment is a finding nobody looks
 * at. So a tree with a mis-spliced file is FAIL even when the other pass could not run, and the
 * pass that could not run is still named.
 *
 * @param {{scope: string, targets: readonly {path: string, language: string}[], selectionFindings: readonly object[], runner: string|null, parse: {completed: boolean, rows: Map<string, any>, reason?: string}, scan: {completed: boolean, rows: Map<string, any>, reason?: string}}} input
 */
export function verdictFor({ scope, targets, selectionFindings = [], runner, parse, scan }) {
  const findings = [...selectionFindings];
  const incomplete = [];

  if (!parse.completed) incomplete.push(`parse pass did not complete${parse.reason ? ` — ${parse.reason}` : ""}`);
  if (!scan.completed) incomplete.push(`scan pass did not complete${scan.reason ? ` — ${scan.reason}` : ""}`);

  /** @type {{path: string, language: string, parse?: object, scan?: object}[]} */
  const files = [];
  for (const t of targets) {
    const p = parse.completed ? parse.rows.get(t.path) : undefined;
    const s = scan.completed ? scan.rows.get(t.path) : undefined;
    files.push({ path: t.path, language: t.language, parse: p, scan: s });

    if (parse.completed) {
      if (!p) {
        // A target the loop never reported on. Not a pass: the loop reached its sentinel, so the
        // absence is about this file, and a missing row read as "fine" is the fail-open the
        // sentinel exists to prevent one layer up.
        findings.push({ path: t.path, language: t.language, signal: "parse-missing", detail: "semgrep reported no parse result for this target" });
      } else if (!p.ok) {
        findings.push({
          path: t.path,
          language: t.language,
          signal: p.exitCode === 3 ? "parse-partial" : "parse-error",
          detail: p.detail,
        });
      }
    }
    if (scan.completed) {
      if (!s) {
        findings.push({ path: t.path, language: t.language, signal: "scan-missing", detail: "no coverage row was reconciled for this target" });
      } else if (s.state === "limited") {
        findings.push({ path: t.path, language: t.language, signal: "scan-limited", detail: `coverage limited — ${s.reason}` });
      } else if (s.state === "not-applicable") {
        // With a probe rule loaded for every language in {@link LANGUAGE_BY_EXTENSION}, Semgrep
        // declining to open a target is not "no rule applies" — it is Semgrep refusing the file.
        findings.push({ path: t.path, language: t.language, signal: "scan-not-applicable", detail: `semgrep did not scan this target — ${s.reason}` });
      }
    }
  }

  /** @type {Record<string, number>} */
  const byLanguage = {};
  for (const t of targets) byLanguage[t.language] = (byLanguage[t.language] ?? 0) + 1;

  const status = findings.length > 0 ? "fail" : incomplete.length > 0 ? "unavailable" : targets.length === 0 ? "unavailable" : "pass";
  if (targets.length === 0 && incomplete.length === 0 && findings.length === 0) {
    // An empty target set is never a pass. Same shape as HapDo's T-37 rule: "there was nothing to
    // check" and "everything was filtered away" must not collapse onto one green tick.
    incomplete.push("no target was selected — a gate that checked nothing is not a gate that passed");
  }
  return {
    ok: status === "pass",
    status,
    scope,
    runner,
    semgrepVersion: SEMGREP_VERSION,
    targets: targets.length,
    byLanguage,
    files,
    findings,
    incomplete,
  };
}

/** Renders a verdict as the block a human reads and a PR body can carry. */
export function formatVerdict(v) {
  const lines = [`parse gate @ semgrep ${v.semgrepVersion} via ${v.runner ?? "no runner"}`];
  lines.push(`- scope: ${v.scope} — ${v.targets} file(s)`);
  const langs = Object.entries(v.byLanguage).sort();
  lines.push(`- languages: ${langs.length ? langs.map(([l, n]) => `${l} ${n}`).join(", ") : "(none)"}`);
  for (const r of v.incomplete) lines.push(`- UNAVAILABLE: ${r}`);
  for (const f of v.findings) lines.push(`- ${f.signal}: ${f.path}${f.language ? ` [${f.language}]` : ""} — ${f.detail}`);
  if (v.findings.length === 0 && v.incomplete.length === 0) lines.push("- every target parsed, and every target was scanned");
  lines.push(`verdict: ${v.status === "pass" ? "PASS" : v.status === "fail" ? "FAIL" : "UNAVAILABLE"}`);
  return lines.join("\n");
}

// ---------------------------------------------------------------------------------------------
// Runners (side effects below this line; everything above is pure and unit-tested).

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...opts });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", error: r.error };
}

/**
 * Flags every Semgrep invocation here carries, and why each one is not optional.
 *
 *   --metrics off               this gate reaches nothing;
 *   --disable-version-check     **measured, and it is not cosmetic**: inside `--network none` the
 *                               version check stalls on DNS for a flat 45s per invocation, turning
 *                               a 1s gate into a 45s one. Without the flag the cost of the gate is
 *                               a property of the host's resolver rather than of the tree.
 */
const SEMGREP_COMMON = ["--metrics", "off", "--disable-version-check"];

/**
 * The tool child's scan argv, minus the bits that are its image's and not ours.
 *
 * `--disable-nosem` and `--max-target-bytes 0` are carried deliberately: the corpus ships
 * upstream's own `# nosemgrep` suppressions (phase 1 counted them) and a suppression must not be
 * able to decide whether a file counts as covered, which is the same argument spec 2-6 §3.9 makes.
 */
export function scanArgs(rulesPath, absoluteTargets) {
  return [
    "--config", rulesPath,
    ...SEMGREP_COMMON,
    "--json", "--quiet", "--error",
    "--jobs", "4",
    "--disable-nosem",
    "--max-target-bytes", "0",
    ...absoluteTargets,
  ];
}

/**
 * uvx's half of the fallback, pinned exactly as HapDo's is. setuptools >= 81 dropped
 * `pkg_resources`, which semgrep 1.99 still imports, so the pin below is load-bearing.
 */
const UVX_PREFIX = ["--python", "3.12", "--with", "setuptools<81", "--from", `semgrep==${SEMGREP_VERSION}`, "semgrep"];

/** Is the pinned image on this machine, pulling it once if it is not? */
function dockerImageReady(execute) {
  if (execute("docker", ["image", "inspect", SEMGREP_IMAGE], { stdio: "ignore" }).status === 0) return true;
  return execute("docker", ["pull", SEMGREP_IMAGE], { stdio: "ignore" }).status === 0;
}

/**
 * Picks the runner, Docker first and uvx second — the order and the fallback
 * `scripts/lib/static-analysis.mjs` already uses, so this gate and HapDo's own gate fail over the
 * same way on the same machine.
 *
 * Returns `null` when neither can run. That is the whole of requirement 1: the caller gets a
 * structural absence, not a string it has to interpret.
 */
export function availableRunner(execute = run) {
  if (execute("docker", ["info"], { stdio: "ignore" }).status === 0 && dockerImageReady(execute)) return "docker";
  if (execute("uvx", [...UVX_PREFIX, "--version"], { stdio: "ignore" }).status === 0) return "uvx";
  return null;
}

/** The parse pass. One process, whatever the target count. */
function runParsePass(runner, treeDir, targets, execute) {
  const stdin = targets.map((t) => `${t.language}\t${t.path}`).join("\n") + "\n";
  if (runner === "docker") {
    const r = execute("docker", [
      "run", "--rm", "-i",
      "--network", "none",
      "--volume", `${treeDir}:/tree:ro`,
      SEMGREP_IMAGE,
      "sh", "-c", PARSE_LOOP,
    ], { input: stdin });
    const out = parseDumpAstOutput(r.stdout);
    return out.completed ? out : { ...out, reason: lastLine(r.stderr || r.stdout) || `docker exited ${r.status}` };
  }
  // uvx has no container to loop inside, so the loop is here. Same rows, same sentinel — the
  // sentinel is set by reaching the end of the list rather than by a subprocess printing it.
  const rows = new Map();
  for (const t of targets) {
    const r = execute("uvx", [...UVX_PREFIX, "show", "dump-ast", t.language, path.join(treeDir, t.path)]);
    if (r.error) return { completed: false, rows, reason: String(r.error.message ?? r.error) };
    rows.set(t.path, {
      exitCode: r.status ?? 1,
      ok: r.status === 0,
      detail: r.status === 0 ? "" : summariseParseError(r.stderr, r.status ?? 1),
    });
  }
  return { completed: true, rows };
}

/** The scan pass. One process, targets on argv — no shell, so no quoting to get wrong. */
function runScanPass(runner, treeDir, targets, scratch, execute) {
  const rulesHost = path.join(scratch, "parse-probe.yml");
  fs.writeFileSync(rulesHost, PROBE_RULES);
  if (runner === "docker") {
    const r = execute("docker", [
      "run", "--rm",
      "--network", "none",
      "--volume", `${treeDir}:/tree:ro`,
      "--volume", `${scratch}:/rules:ro`,
      SEMGREP_IMAGE,
      "semgrep", ...scanArgs("/rules/parse-probe.yml", targets.map((t) => `/tree/${t.path}`)),
    ]);
    const out = coverageFromScan(r.stdout, targets, "/tree");
    return out.completed ? out : { ...out, reason: out.reason ?? lastLine(r.stderr) ?? `docker exited ${r.status}` };
  }
  const r = execute("uvx", [
    ...UVX_PREFIX,
    ...scanArgs(rulesHost, targets.map((t) => path.join(treeDir, t.path))),
  ]);
  const out = coverageFromScan(r.stdout, targets, treeDir);
  return out.completed ? out : { ...out, reason: out.reason ?? lastLine(r.stderr) ?? `uvx exited ${r.status}` };
}

function lastLine(text) {
  const lines = (text ?? "").trim().split("\n").filter((l) => l.trim() !== "");
  return lines.length ? lines[lines.length - 1].slice(0, 200) : undefined;
}

/**
 * Works out which files the gate checks, and says which way it decided.
 *
 * The default is the **scored** files — the ones carrying a marked block — because they are what
 * the splice touches and a full-tree pass is 760 files where 16 changed. That is the fast path,
 * and it is only allowed to be the default because the verdict carries `scope` and the per-language
 * counts: a run that covered less says so in the block a reader pastes.
 *
 * Deriving them from the tree rather than from a checked-in list is the same choice
 * `bin/inventory.mjs` makes — the corpus is the authority. A tree whose markers have been stripped
 * yields no blocks, and that is refused rather than treated as "nothing to check": pass
 * `--inventory` or `--files` for a stripped tree.
 *
 * @param {string} treeDir
 * @param {{all?: boolean, files?: readonly string[], inventory?: string}} opts
 */
export function resolveTargets(treeDir, opts = {}) {
  if (opts.files && opts.files.length > 0) return { scope: "explicit file list", paths: [...opts.files] };
  if (opts.inventory) {
    const inv = JSON.parse(fs.readFileSync(opts.inventory, "utf8"));
    const paths = Array.isArray(inv.filesWithBlocks)
      ? inv.filesWithBlocks
      : Array.isArray(inv.blocks)
        ? [...new Set(inv.blocks.map((b) => b.file))]
        : null;
    if (!paths) throw new Error(`${opts.inventory} carries neither filesWithBlocks nor blocks`);
    return { scope: `inventory ${path.basename(opts.inventory)}`, paths };
  }
  if (opts.all) {
    const tree = readTree(treeDir);
    const paths = [...tree.keys()].filter((p) => languageFor(p));
    return {
      scope: `whole tree (${tree.size - paths.length} file(s) in no checkable language)`,
      paths,
    };
  }
  const blocks = buildInventory(readTree(treeDir), new Map()).blocks;
  const paths = [...new Set(blocks.map((b) => b.file))];
  if (paths.length === 0) {
    throw new Error(
      "this tree carries no marked block, so the scored file list cannot be derived from it " +
        "(a stripped tree looks like this) — pass --inventory <json> or --files <list>",
    );
  }
  return { scope: `${blocks.length} marked block(s) in the tree`, paths };
}

/**
 * Checks a tree. The gate.
 *
 * @param {string} treeDir
 * @param {{all?: boolean, files?: readonly string[], inventory?: string, execute?: Function, runner?: string|null}} opts
 */
export function checkTree(treeDir, opts = {}) {
  const execute = opts.execute ?? run;
  const empty = { completed: false, rows: new Map() };

  let scope, paths;
  try {
    ({ scope, paths } = resolveTargets(treeDir, opts));
  } catch (err) {
    return verdictFor({
      scope: "unresolved",
      targets: [],
      runner: null,
      parse: { ...empty, reason: err instanceof Error ? err.message : String(err) },
      scan: { ...empty, reason: "not attempted" },
    });
  }

  const { targets, findings: selectionFindings } = selectTargets(paths);
  const runner = opts.runner === undefined ? availableRunner(execute) : opts.runner;
  if (!runner) {
    const reason =
      `neither Docker nor uvx could start semgrep ${SEMGREP_VERSION} — start Docker, or install ` +
      "uv; an unverified parse gate is not a passing one";
    return verdictFor({
      scope,
      targets,
      selectionFindings,
      runner: null,
      parse: { ...empty, reason },
      scan: { ...empty, reason },
    });
  }
  if (targets.length === 0) {
    return verdictFor({ scope, targets, selectionFindings, runner, parse: empty, scan: empty });
  }

  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "parse-check-"));
  try {
    const absoluteTree = path.resolve(treeDir);
    const parse = runParsePass(runner, absoluteTree, targets, execute);
    const scan = runScanPass(runner, absoluteTree, targets, scratch, execute);
    return verdictFor({ scope, targets, selectionFindings, runner, parse, scan });
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}
