// Shields.io endpoint badges from what CI measured on this commit.
//
// Usage (CI runs it after the tests and the WebAssembly build; see
// .github/workflows/ci.yml):
//   node scripts/badges.mjs --out <dir> --tests <output of `cargo test --release`> --wasm <pkg/*_bg.wasm>
//
// Each badge is one JSON file, {"schemaVersion":1,"label","message","color"},
// which CI commits to the `badges` branch for img.shields.io/endpoint to
// read. A value that cannot be read, or a run that did not pass, stops the
// script with an error: a badge is never written from a guess. No
// dependencies: Node 18 or later.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";

class BadgeError extends Error {}
const fail = (message) => {
  throw new BadgeError(message);
};

const readBytes = (path) => {
  try {
    return readFileSync(path);
  } catch (e) {
    return fail(`cannot read ${path}: ${e.message}`);
  }
};

const ANSI = /\x1b\[[0-9;]*[A-Za-z]/g;
const BINARY = /^\s*(Running|Doc-tests) (.+)$/;
const RESULT = /^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;/;

/** Test counts from `cargo test` output: one "test result" line for every
 * test binary and doc-test run that cargo announced. */
export function parseCargoTest(text) {
  let binaries = 0;
  const results = [];
  for (const raw of text.replace(ANSI, "").split(/\r?\n/)) {
    const line = raw.trim();
    if (BINARY.test(line)) binaries++;
    const m = RESULT.exec(line);
    if (m) results.push({ ok: m[1] === "ok", passed: +m[2], failed: +m[3], ignored: +m[4], filtered: +m[6] });
  }
  if (binaries === 0) fail("no test binary in the cargo test output");
  if (results.length !== binaries) fail(`cargo announced ${binaries} test runs but printed ${results.length} results`);
  const sum = (key) => results.reduce((n, r) => n + r[key], 0);
  if (results.some((r) => !r.ok) || sum("failed") > 0) fail(`${sum("failed")} test(s) failed`);
  if (sum("filtered") > 0) fail("tests were filtered out: not a full run");
  if (sum("passed") === 0) fail("no test passed");
  return { passed: sum("passed"), ignored: sum("ignored") };
}

export const gzipBytes = (path) => {
  const data = readBytes(path);
  if (data.length === 0) fail(`${path} is empty`);
  return gzipSync(data, { level: 9 }).length;
};
const kB = (bytes) => `${(bytes / 1000).toFixed(1)} kB`;

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    if (!key || argv[i + 1] === undefined) fail(`expected --name value pairs, got "${argv.slice(i).join(" ")}"`);
    args[key] = argv[i + 1];
  }
  for (const key of ["out", "tests", "wasm"]) if (!args[key]) fail(`--${key} is required`);
  return args;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    const args = parseArgs(process.argv.slice(2));
    const tests = parseCargoTest(readBytes(args.tests).toString("utf8"));
    const badges = {
      tests: { label: "tests", message: `${tests.passed} passed${tests.ignored ? `, ${tests.ignored} ignored` : ""}`, color: "brightgreen" },
      "wasm-size": { label: "wasm gzip", message: kB(gzipBytes(args.wasm)), color: "blue" },
    };
    mkdirSync(args.out, { recursive: true });
    for (const [name, { label, message, color }] of Object.entries(badges)) {
      const json = `${JSON.stringify({ schemaVersion: 1, label, message, color })}\n`;
      writeFileSync(join(args.out, `${name}.json`), json);
      process.stdout.write(`${name}.json ${json}`);
    }
  } catch (e) {
    if (!(e instanceof BadgeError)) throw e;
    console.error(`badges: ${e.message}`);
    process.exit(1);
  }
}
