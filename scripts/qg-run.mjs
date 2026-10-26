#!/usr/bin/env node
/**
 * QG 외부 실행기 — 테스트·공격 시나리오를 돌리고 결과를 <접두어>_qg_ingest 로 올린다(QG 키트 1.0, 원본 F-MATRIX scripts/qg-run.mjs).
 *
 *   node scripts/qg-run.mjs testing      [--files a.sql,b.sql] [--no-vitest] [--no-e2e] [--dry-run] [--via supabase|pg|psql|docker:<컨테이너>] [--prefix p]
 *   node scripts/qg-run.mjs adversarial  [--files adversarial_qg_core.sql] [--no-vitest] [--dry-run] [...]
 *   node scripts/qg-run.mjs e2e --suite <스위트 코드> --results <결과 JSON>   (또는 --passed N --failed M [--failures-file f.json])
 *
 * testing     : 테스트 스위트 카탈로그(<p>_qg_test_suites)에 등록된 supabase/tests/*.sql 을 하나씩 실행(모두 begin…rollback)하고
 *               마지막 결과의 SUMMARY passed=/failed= · ok 칸 · RESULT: 줄 · 'TEST RESULT' + 줄마다 PASS/FAIL 을 읽어 스위트별 통과/실패로 올린다.
 *               vitest 결과도 올린다. kind = 'e2e' 스위트는 path 의 결과 JSON(Playwright·vitest·{passed,failed})을 읽어 올린다(--no-e2e 로 끔).
 *               카탈로그에 없는 파일은 testing.suite_registry 로 알린다.
 * e2e         : E2E 스크립트가 끝난 뒤 그 결과를 한 스위트로 올린다(결과 파일 형식은 testing 과 같음).
 * adversarial : 시나리오 카탈로그(<p>_qg_scenarios)의 스크립트(supabase/tests/qg/adversarial_*.sql · vitest:…)를 실행하고
 *               시나리오별 PASS/FAIL 을 '기대 결과 vs 실제'로 올린다.
 * 올리기: 서버 증명키(ENV QG_SERVER_ATTEST_KEY, 없으면 GOS_SERVER_ATTEST_KEY, 없으면 .env.local)로 ingest 를 SQL 로 부른다. 키는 출력하지 않는다.
 * 종료 코드: 0 = 모두 통과, 1 = 실패·오류 있음, 2 = 실행 준비·올리기 실패.
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { IS_WIN, assertNoCommit, firstLine, makeDb, n, parseArgs, parseSmoke, resolveVia } from "./qg-lib.mjs";

const ROOT = process.cwd();
const a = parseArgs(process.argv.slice(2));
const engine = a._[0];
if (!["testing", "adversarial", "e2e"].includes(engine)) {
  console.error("사용법: node scripts/qg-run.mjs <testing|adversarial|e2e> [--files a,b] [--no-vitest] [--dry-run] [--via supabase|pg|psql|docker:<컨테이너>]");
  process.exit(2);
}
const kit = existsSync(path.join(ROOT, ".qg-kit.json")) ? JSON.parse(readFileSync(path.join(ROOT, ".qg-kit.json"), "utf8")) : {};
const P = String(a.prefix ?? kit.prefix ?? "");
if (!/^[a-z][a-z0-9]{1,11}$/.test(P)) { console.error("접두어를 알 수 없습니다(.qg-kit.json 또는 --prefix)."); process.exit(2); }
const TESTS = String(kit.tests_dir ?? "supabase/tests");
const db = makeDb(resolveVia(a, kit), { cwd: ROOT });
const fileFilter = String(a.files ?? "").split(",").map((s) => s.trim()).filter(Boolean);
const matchFilter = (p) => fileFilter.length === 0 || fileFilter.some((f) => p === f || path.basename(p) === f || p.endsWith(f));
const DRY = !!a["dry-run"];
const NO_VITEST = !!a["no-vitest"];
const MAX_FAILURES = 30;
const tmp = mkdtempSync(path.join(tmpdir(), "qg-run-"));
process.on("exit", () => { try { rmSync(tmp, { recursive: true, force: true }); } catch { /* 무시 */ } });

function run(cmd, args, timeoutMs = 20 * 60_000) {
  const t0 = Date.now();
  const r = spawnSync(cmd, args, { cwd: ROOT, encoding: "utf8", shell: IS_WIN, maxBuffer: 256 * 1024 * 1024, timeout: timeoutMs, env: process.env });
  return { code: r.status ?? -1, out: `${r.stdout ?? ""}\n${r.stderr ?? ""}`, ms: Date.now() - t0 };
}

function gitInfo() {
  const sha = run("git", ["rev-parse", "HEAD"], 20_000).out.trim().split(/\s+/)[0] || null;
  const dirty = run("git", ["status", "--porcelain"], 20_000).out.trim().length > 0;
  return { git_sha: sha && /^[0-9a-f]{40}$/.test(sha) ? sha : null, git_dirty: dirty };
}

function serverKey() {
  for (const k of ["QG_SERVER_ATTEST_KEY", "GOS_SERVER_ATTEST_KEY"]) if (process.env[k]) return process.env[k].trim();
  const envFile = path.join(ROOT, ".env.local");
  if (!existsSync(envFile)) return null;
  for (const line of readFileSync(envFile, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*(QG_SERVER_ATTEST_KEY|GOS_SERVER_ATTEST_KEY)\s*=\s*(.*)\s*$/);
    if (m) return m[2].replace(/^["']|["']$/g, "").trim() || null;
  }
  return null;
}

/** E2E 결과 파일 읽기 — Playwright JSON(stats·suites) · vitest/jest JSON(numPassedTests) · 단순 {passed, failed, failures?} */
function parseE2eResults(file) {
  const abs = path.isAbsolute(file) ? file : path.join(ROOT, file);
  if (!existsSync(abs)) return { error: `결과 파일이 없습니다: ${file} (E2E 를 먼저 돌려 결과 JSON 을 남기세요)` };
  let j;
  try { j = JSON.parse(readFileSync(abs, "utf8")); } catch (e) { return { error: `결과 파일을 읽지 못했습니다: ${String(e).slice(0, 200)}` }; }
  const at = statSync(abs).mtime.toISOString();
  if (j && j.stats && typeof j.stats.expected === "number") {
    const failures = [];
    const walk = (suite, trail) => {
      for (const sp of suite.specs ?? []) if (sp.ok === false) failures.push({ step: [...trail, sp.title].filter(Boolean).join(" › "), msg: String(sp.tests?.[0]?.results?.[0]?.error?.message ?? "").split("\n")[0].slice(0, 300) });
      for (const ch of suite.suites ?? []) walk(ch, [...trail, ch.title]);
    };
    for (const su of j.suites ?? []) walk(su, [su.title]);
    return { format: "playwright", passed: j.stats.expected + (j.stats.flaky ?? 0), failed: j.stats.unexpected, failures, at };
  }
  if (j && typeof j.numPassedTests === "number") {
    const failures = (j.testResults ?? []).flatMap((f) => (f.assertionResults ?? []).filter((x) => x.status === "failed").map((x) => ({ step: x.fullName ?? x.title ?? "", msg: String((x.failureMessages ?? [])[0] ?? "").split("\n")[0].slice(0, 300) })));
    return { format: "vitest", passed: j.numPassedTests, failed: j.numFailedTests ?? 0, failures, at };
  }
  if (j && typeof j.passed === "number" && typeof j.failed === "number") {
    return { format: "simple", passed: j.passed, failed: j.failed, failures: Array.isArray(j.failures) ? j.failures.map((f) => ({ step: String(f.step ?? f.name ?? ""), msg: String(f.msg ?? f.message ?? "").slice(0, 300) })) : [], at: j.finished_at ?? at };
  }
  return { error: "결과 파일 형식을 알 수 없습니다(Playwright JSON · vitest JSON · {passed, failed, failures?})." };
}

function e2eResult(s, p, file) {
  if (p.error) return { check_code: s.check_code, status: "error", fingerprint: "suite", title: `${s.name ?? s.code} — ${p.error}`, detail: { file, message: p.error } };
  const status = p.failed > 0 ? "fail" : p.passed > 0 ? "pass" : "error";
  const msg = `통과 ${n(p.passed)} · 실패 ${n(p.failed)}`;
  return { check_code: s.check_code, status, fingerprint: "suite", title: `${s.name ?? s.code} — ${msg}`,
    detail: { file, format: p.format, passed: p.passed, failed: p.failed, results_at: p.at, failures: p.failures.slice(0, MAX_FAILURES), message: msg } };
}

function runVitest(files) {
  const outFile = path.join(tmp, `vitest-${randomBytes(4).toString("hex")}.json`);
  const r = run(IS_WIN ? "npx.cmd" : "npx", ["vitest", "run", ...files, "--reporter=json", `--outputFile=${outFile}`]);
  if (!existsSync(outFile)) return { error: `vitest 실행 실패: ${firstLine(r.out)}`, ms: r.ms };
  try {
    const j = JSON.parse(readFileSync(outFile, "utf8"));
    const tests = (j.testResults ?? []).flatMap((f) => (f.assertionResults ?? []).map((x) => ({
      file: path.relative(ROOT, f.name ?? "").replace(/\\/g, "/"), name: x.fullName ?? x.title ?? "", status: x.status,
      message: (x.failureMessages ?? []).join("\n").split("\n")[0]?.slice(0, 300) ?? "" })));
    return { tests, passed: j.numPassedTests ?? 0, failed: j.numFailedTests ?? 0, total: j.numTotalTests ?? tests.length, ms: r.ms };
  } catch (e) { return { error: `vitest 결과를 읽지 못했습니다: ${String(e).slice(0, 200)}`, ms: r.ms }; }
}

function runTesting() {
  const suites = db.rows(`select code, name, kind, path, check_code from public.${P}_qg_test_suites where active order by sort, code`);
  const byPath = new Map(suites.map((s) => [s.path, s]));
  const dir = path.join(ROOT, TESTS);
  const files = existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith(".sql")).sort().map((f) => `${TESTS}/${f}`) : [];
  const results = [];
  for (const f of files.filter(matchFilter)) {
    const s = byPath.get(f);
    if (!s) continue;
    process.stdout.write(`▶ ${f} … `);
    const t0 = Date.now();
    const sqlText = readFileSync(path.join(ROOT, f), "utf8");
    try { assertNoCommit(sqlText, f); } catch (e) { console.log(`건너뜀 — ${e.message}`); results.push({ check_code: s.check_code, status: "error", fingerprint: "suite", title: `${path.basename(f)} — commit 이 있어 실행하지 않음`, detail: { file: f, message: e.message } }); continue; }
    const { rows, error, errorText } = db.script(sqlText);
    const p = parseSmoke(rows, errorText || error);
    let status; let detail;
    if (!p) { status = "error"; detail = { file: f, duration_ms: Date.now() - t0, message: `실행·결과 읽기 실패: ${error ?? "결과 없음"}` }; }
    else {
      status = p.failed > 0 ? "fail" : p.passed > 0 ? "pass" : "error";
      detail = { file: f, duration_ms: Date.now() - t0, format: p.format, passed: p.passed, failed: p.failed, failures: p.failures.slice(0, MAX_FAILURES), message: `통과 ${n(p.passed)} · 실패 ${n(p.failed)}` };
    }
    console.log(status === "pass" ? `통과 ${n(detail.passed)}` : status === "fail" ? `실패 ${n(detail.failed)} / 통과 ${n(detail.passed)}` : `오류 — ${detail.message}`);
    results.push({ check_code: s.check_code, status, fingerprint: "suite", title: `${path.basename(f)} — ${detail.message}`, detail });
  }
  for (const s of suites.filter((x) => x.kind === "sql" && !files.includes(x.path) && matchFilter(x.path))) {
    results.push({ check_code: s.check_code, status: "error", fingerprint: "missing_file", title: `등록된 테스트 파일이 없음: ${s.path}`, detail: { file: s.path, message: "카탈로그에는 있지만 저장소에 파일이 없습니다." } });
  }
  if (!a["no-e2e"]) {
    for (const s of suites.filter((x) => x.kind === "e2e" && matchFilter(x.path))) {
      process.stdout.write(`▶ E2E 결과 ${s.path} … `);
      const r = e2eResult(s, parseE2eResults(s.path), s.path);
      console.log(r.status === "pass" ? r.detail.message : r.status === "fail" ? `실패 — ${r.detail.message}` : `오류 — ${r.detail.message}`);
      results.push(r);
    }
  }
  const vs = suites.find((s) => s.kind === "vitest");
  if (vs && !NO_VITEST && matchFilter("vitest")) {
    process.stdout.write("▶ vitest … ");
    const v = runVitest([]);
    if (v.error) { console.log(`오류 — ${v.error}`); results.push({ check_code: vs.check_code, status: "error", fingerprint: "suite", title: "vitest — 실행 오류", detail: { message: v.error } }); }
    else {
      const failures = v.tests.filter((t) => t.status === "failed").map((t) => ({ step: `${t.file} › ${t.name}`, msg: t.message }));
      const status = v.failed > 0 ? "fail" : v.passed > 0 ? "pass" : "error";
      console.log(status === "pass" ? `통과 ${n(v.passed)}` : `실패 ${n(v.failed)} / 통과 ${n(v.passed)}`);
      results.push({ check_code: vs.check_code, status, fingerprint: "suite", title: `vitest — 통과 ${n(v.passed)} · 실패 ${n(v.failed)}`,
        detail: { passed: v.passed, failed: v.failed, total: v.total, duration_ms: v.ms, failures: failures.slice(0, MAX_FAILURES), message: `통과 ${n(v.passed)} · 실패 ${n(v.failed)}` } });
    }
  }
  if (fileFilter.length === 0) {
    const unregistered = files.filter((f) => !byPath.has(f));
    results.push(unregistered.length > 0
      ? { check_code: "testing.suite_registry", status: "warn", severity: "low", fingerprint: "unregistered", title: `등록 안 된 테스트 파일 ${unregistered.length}개`, detail: { files: unregistered } }
      : { check_code: "testing.suite_registry", status: "pass", detail: { files: files.length, message: `테스트 파일 ${files.length}개 모두 카탈로그에 등록되어 있습니다.` } });
  }
  return results;
}

function runAdversarial() {
  const scenarios = db.rows(`select code, name, script, check_code, expected from public.${P}_qg_scenarios where active order by sort, code`);
  const results = [];
  for (const script of [...new Set(scenarios.map((s) => s.script))].filter((s) => !s.startsWith("vitest:")).filter(matchFilter)) {
    const mine = scenarios.filter((s) => s.script === script);
    process.stdout.write(`▶ ${script} … `);
    if (!existsSync(path.join(ROOT, script))) {
      console.log("파일 없음");
      for (const s of mine) results.push({ check_code: s.check_code, status: "error", fingerprint: "scenario", title: `${s.name} — 스크립트 파일 없음`, detail: { script, expected: s.expected, message: "스크립트 파일이 저장소에 없습니다." } });
      continue;
    }
    const t0 = Date.now();
    const advText = readFileSync(path.join(ROOT, script), "utf8");
    try { assertNoCommit(advText, script); } catch (e) { console.log(e.message); for (const s of mine) results.push({ check_code: s.check_code, status: "error", fingerprint: "scenario", title: `${s.name} — commit 이 있어 실행하지 않음`, detail: { script, message: e.message } }); continue; }
    const { rows, error } = db.script(advText);
    const summary = [];
    for (const s of mine) {
      const row = rows.find((x) => x.scenario === s.code);
      if (!row) {
        results.push({ check_code: s.check_code, status: "error", fingerprint: "scenario", title: `${s.name} — 결과 없음`, detail: { script, expected: s.expected, actual: "결과 행 없음", message: error ?? "스크립트가 이 시나리오 결과를 내지 않았습니다." } });
        summary.push(`${s.code}=오류`); continue;
      }
      const pass = row.result === "PASS";
      results.push({ check_code: s.check_code, status: pass ? "pass" : "fail", fingerprint: "scenario", title: `${s.name} — ${pass ? "기대대로 막힘" : `기대와 다름(${n(row.failed)}단계)`}`,
        detail: { script, expected: s.expected, actual: pass ? "기대 결과와 같음" : "기대와 다른 단계가 있음", steps: row.steps, failed: row.failed, failures: (row.failures ?? []).slice(0, MAX_FAILURES), duration_ms: Date.now() - t0 } });
      summary.push(`${s.code}=${pass ? "PASS" : "FAIL"}`);
    }
    console.log(summary.join(" · "));
  }
  const vit = scenarios.filter((s) => s.script.startsWith("vitest:") && matchFilter(s.script.slice(7)));
  if (vit.length > 0 && !NO_VITEST) {
    const v = runVitest([...new Set(vit.map((s) => s.script.slice(7)))]);
    for (const s of vit) {
      if (v.error) { results.push({ check_code: s.check_code, status: "error", fingerprint: "scenario", title: `${s.name} — vitest 실행 오류`, detail: { message: v.error } }); continue; }
      const mine = v.tests.filter((t) => t.name.includes(`[${s.code}]`));
      const failed = mine.filter((t) => t.status !== "passed");
      const status = mine.length === 0 ? "error" : failed.length > 0 ? "fail" : "pass";
      results.push({ check_code: s.check_code, status, fingerprint: "scenario", title: `${s.name} — ${status === "pass" ? "기대대로 대체 동작" : status === "fail" ? `기대와 다름(${failed.length}건)` : "해당 테스트 없음"}`,
        detail: { script: s.script, expected: s.expected, steps: mine.length, failed: failed.length, failures: failed.map((t) => ({ step: t.name, msg: t.message })).slice(0, MAX_FAILURES) } });
    }
  }
  return results;
}

function runE2e() {
  const code = String(a.suite ?? "");
  if (!/^[a-z][a-z0-9_]{2,59}$/.test(code)) throw new Error("--suite <테스트 스위트 코드> 가 필요합니다(카탈로그 __qg_test_suites.code).");
  const [s] = db.rows(`select code, name, kind, path, check_code from public.${P}_qg_test_suites where code = '${code}' and active`);
  if (!s) throw new Error(`활성 테스트 스위트가 없습니다: ${code}`);
  let p;
  if (a.results) p = parseE2eResults(String(a.results));
  else if (a.passed !== undefined && a.failed !== undefined) {
    let failures = [];
    if (a["failures-file"]) { try { failures = JSON.parse(readFileSync(path.resolve(String(a["failures-file"])), "utf8")); } catch { failures = []; } }
    p = { format: "args", passed: Number(a.passed), failed: Number(a.failed), failures: Array.isArray(failures) ? failures : [], at: new Date().toISOString() };
  } else if (s.kind === "e2e") p = parseE2eResults(s.path);
  else throw new Error("--results <결과 JSON> 또는 --passed N --failed M 이 필요합니다.");
  const r = e2eResult(s, p, a.results ? String(a.results) : s.path);
  console.log(`▶ ${s.code}: ${r.detail.message}`);
  return [r];
}

const startedAt = new Date().toISOString();
let results;
try { results = engine === "testing" ? runTesting() : engine === "e2e" ? runE2e() : runAdversarial(); }
catch (e) { console.error(`실행 준비 실패: ${e instanceof Error ? e.message : String(e)}`); process.exit(2); }
const count = (s) => results.filter((r) => r.status === s).length;
console.log(`\n결과: 통과 ${count("pass")} · 주의 ${count("warn")} · 실패 ${count("fail")} · 오류 ${count("error")} (총 ${results.length})`);
for (const r of results.filter((x) => x.status === "fail" || x.status === "error")) {
  console.log(`  ✗ ${r.check_code}: ${r.title ?? ""}`);
  for (const f of (r.detail?.failures ?? []).slice(0, 5)) console.log(`      - ${f.step}: ${String(f.msg ?? "").slice(0, 160)}`);
}
if (results.length === 0) { console.log("올릴 결과가 없습니다(--files 조건을 확인하세요)."); process.exit(2); }
const anyBad = count("fail") + count("error") > 0;
if (DRY) { console.log("\n--dry-run: 결과를 올리지 않았습니다."); process.exit(anyBad ? 1 : 0); }

const key = serverKey();
if (!key) { console.error("\n서버 증명키(QG_SERVER_ATTEST_KEY · GOS_SERVER_ATTEST_KEY · .env.local)가 없어 결과를 올리지 못했습니다."); process.exit(2); }
const payload = { engine: engine === "e2e" ? "testing" : engine, trigger: "script", started_at: startedAt, context: { ...gitInfo(), runner: "scripts/qg-run.mjs", node: process.version, filter: fileFilter.length ? fileFilter : undefined }, results };
const json = JSON.stringify(payload);
let tag = `qg${randomBytes(6).toString("hex")}`;
while (json.includes(`$${tag}$`)) tag = `qg${randomBytes(6).toString("hex")}`;
let ktag = `k${randomBytes(6).toString("hex")}`;
while (key.includes(`$${ktag}$`)) ktag = `k${randomBytes(6).toString("hex")}`;
try {
  const [row] = db.rows(`select public.${P}_qg_ingest($${tag}$${json}$${tag}$::jsonb, $${ktag}$${key}$${ktag}$) as r`);
  const res = row?.r;
  if (!res?.ok) throw new Error("올리기 결과가 비었습니다.");
  console.log(`\n올림 완료 — 실행 ${res.run_id} · 상태 ${res.status} · 증거 ${res.evidence_id}`);
  console.log(`화면: ${kit.admin ?? "/admin"}/qg/runs/${res.run_id}`);
} catch (e) {
  console.error(`\n결과 올리기 실패: ${String(e instanceof Error ? e.message : e).split(key).join("***")}`);
  process.exit(2);
}
process.exit(anyBad ? 1 : 0);
