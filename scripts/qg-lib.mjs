/**
 * QG 키트 공용 도구 — 템플릿 렌더링 · DB 실행기(supabase CLI / psql / docker / node-pg) · 인자 읽기 · 시험 결과 읽기.
 * qg-install.mjs · qg-run.mjs · qg-verify.mjs 가 같이 쓴다(대상 저장소 scripts/ 에 함께 복사됨).
 * 비밀값(서버 증명키·DB 비밀번호)은 출력하지 않는다.
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
/** 동기 잠깐 쉬기(재시도 간격) */
export function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
/** 한국 날짜(YYYY-MM-DD) — 파일 이름·초안 날짜는 UTC 가 아니라 한국 시각으로 */
export function kstDate(d = new Date()) {
  return new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit" }).format(d);
}
/** 일시적 오류(게이트웨이 504·연결 끊김·임시 로그인 역할 경쟁 등) — 읽기·rollback 실행만 다시 시도한다 */
export const TRANSIENT_RE = /\b50[234]\b|gateway time-?out|bad gateway|service unavailable|timed? ?out|ECONNRESET|ETIMEDOUT|EAI_AGAIN|ECONNREFUSED|socket hang up|connection (refused|reset|terminated)|too many (clients|connections)|remaining connection slots|failed to connect|temporarily unavailable|password authentication failed for user "cli_login|circuit breaker/i;

export const IS_WIN = process.platform === "win32";

// ───────── 인자 ─────────
export function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) { out._.push(a); continue; }
    const eq = a.indexOf("=");
    if (eq > 0) { out[a.slice(2, eq)] = a.slice(eq + 1); continue; }
    const k = a.slice(2);
    const nx = argv[i + 1];
    if (nx !== undefined && !nx.startsWith("--")) { out[k] = nx; i++; } else out[k] = true;
  }
  return out;
}

// ───────── 렌더링 ─────────
export const PREFIX_RE = /^[a-z][a-z0-9]{1,11}$/;

/** 토큰 치환. 긴 토큰부터(겹침 방지). 남은 토큰이 있으면 오류. */
export function render(text, vars) {
  const keys = Object.keys(vars).sort((a, b) => b.length - a.length);
  let out = text;
  for (const k of keys) out = out.split(k).join(String(vars[k]));
  const left = out.match(/__(P|ADMIN|SMOKE_PATH|SMOKE_FILE|PROFILE_TABLE|ADMIN_COL|NAME_COL|LIB_ALIAS|ADV_FILE)__/g);
  if (left) throw new Error(`렌더링하지 못한 토큰이 남았습니다: ${[...new Set(left)].join(", ")}`);
  return out;
}

export function baseVars(o) {
  if (!PREFIX_RE.test(o.prefix)) throw new Error("접두어는 영문 소문자로 시작하는 영문 소문자·숫자 2~12자여야 합니다(예: svo, twh).");
  const admin = (o.admin ?? "/admin").replace(/\/+$/, "");
  if (!/^\/[a-z0-9/_-]*$/.test(admin) && admin !== "") throw new Error("관리자 경로는 /admin 처럼 / 로 시작하는 영문 소문자 경로여야 합니다.");
  return {
    __P__: o.prefix,
    __ADMIN__: admin,
    __SMOKE_PATH__: `supabase/tests/${o.smokeFile}`,
    __SMOKE_FILE__: o.smokeFile,
    __PROFILE_TABLE__: o.profileTable ?? "profiles",
    __ADMIN_COL__: o.adminColumn ?? "is_admin",
    __NAME_COL__: o.nameColumn ?? "display_name",
    __LIB_ALIAS__: o.libAlias ?? "@/lib/qg",
    __ADV_FILE__: "adversarial_qg_core.sql",
  };
}

// ───────── DB 실행기 ─────────
//  via=supabase      : supabase db query --linked -f <file>   (기본, 연결된 프로젝트 — supabase/.temp/project-ref 필요)
//  via=docker:<이름> : docker exec -i <이름> psql -U postgres  (로컬 컨테이너)
//  via=psql          : psql "$DATABASE_URL"                   (PATH 의 psql)
//  via=pg            : node-pg(저장소의 pg 패키지) — DATABASE_URL · QG_DB_URL · .env.db.local 의 SUPABASE_DB_PASSWORD(+프로젝트 ref → 세션 풀러)
//  읽기(rows)·스크립트(script, begin…rollback)는 일시적 오류에서 2·5·10초 쉬고 최대 3번 다시 시도한다. exec(적용)는 연결 실패만 다시 시도.
export function makeDb(via = "supabase", { cwd = process.cwd(), user = "postgres", database = "postgres", retries = 3 } = {}) {
  const tmp = mkdtempSync(path.join(tmpdir(), "qg-"));
  process.on("exit", () => { try { rmSync(tmp, { recursive: true, force: true }); } catch { /* 무시 */ } });
  const file = (sql) => {
    const f = path.join(tmp, `q-${randomBytes(6).toString("hex")}.sql`);
    writeFileSync(f, sql, { encoding: "utf8", mode: 0o600 });
    return f;
  };
  const spawn = (cmd, args, input) => {
    const r = spawnSync(cmd, args, { cwd, input, encoding: "utf8", shell: IS_WIN && cmd !== "docker" && cmd !== process.execPath, maxBuffer: 512 * 1024 * 1024, timeout: 20 * 60_000, env: process.env });
    return { code: r.status ?? -1, out: `${r.stdout ?? ""}`, err: `${r.stderr ?? ""}`, error: r.error };
  };
  /** 일시적 오류면 다시 시도(kind = 'read' 전부 · 'connect' 연결 실패만) */
  const withRetry = (kind, fn) => {
    const delays = [2000, 5000, 10000].slice(0, Math.max(0, retries));
    for (let i = 0; ; i++) {
      const r = fn();
      const text = `${r.err ?? ""}\n${r.out ?? ""}`;
      const transient = r.code !== 0 && (kind === "read" ? TRANSIENT_RE.test(text) : /failed to connect|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|password authentication failed for user "cli_login|DB 연결 실패/i.test(text));
      if (!transient || i >= delays.length) return r;
      process.stderr.write(`(일시 오류 — ${delays[i] / 1000}초 뒤 다시 시도 ${i + 1}/${delays.length})\n`);
      sleepSync(delays[i]);
    }
  };
  let checked = false;
  /** 연결 확인(처음 한 번) — 사람 말 안내 */
  function ensureLinked() {
    if (checked) return; checked = true;
    if (via === "supabase" && !existsSync(path.join(cwd, "supabase", ".temp", "project-ref"))) {
      throw new Error("supabase 실행기: 이 저장소가 Supabase 프로젝트에 연결되어 있지 않습니다(supabase/.temp/project-ref 없음). "
        + "`supabase link --project-ref <ref>` 를 먼저 하거나, --via pg(DATABASE_URL 또는 .env.db.local 의 SUPABASE_DB_PASSWORD) · --via psql 을 쓰세요.");
    }
  }
  /** node-pg 실행기(자식 프로세스) → {code, out, err, json} */
  function pgRun(sql) {
    const runner = path.join(HERE, "qg-pg-runner.mjs");
    if (!existsSync(runner)) throw new Error("--via pg: scripts/qg-pg-runner.mjs 가 없습니다(qg-install.mjs 로 다시 설치).");
    const r = spawn(process.execPath, [runner], JSON.stringify({ sql }));
    let j = null;
    try { j = JSON.parse(r.out.trim().split(/\r?\n/).pop() || "null"); } catch { j = null; }
    if (!j) return { code: 1, out: "", err: `pg 실행기 응답을 읽지 못했습니다: ${firstLine(r.err || r.out)}`, json: null };
    return { code: j.ok ? 0 : 1, out: "", err: j.ok ? "" : (j.connect ? String(j.error) : `ERROR: ${j.error}`), json: j };
  }

  /** 파일·문자열 SQL 실행(결과 행 없이) — 실패하면 예외 */
  function exec(sql, { label = "SQL" } = {}) {
    ensureLinked();
    if (via === "pg") {
      const r = withRetry("connect", () => pgRun(sql));
      if (r.code !== 0) throw new Error(`${label} 실패: ${firstLine(r.err)}`);
      return "";
    }
    if (via === "supabase") {
      const f = file(sql);
      try {
        const r = withRetry("connect", () => spawn("supabase", ["db", "query", "--linked", "-f", f]));
        if (r.code !== 0 || /ERROR/i.test(r.err) && !/new version/i.test(r.err)) throw new Error(`${label} 실패: ${firstLine(r.err || r.out)}`);
        return r.out;
      } finally { rmSync(f, { force: true }); }
    }
    const r = psqlRun(sql, ["-v", "ON_ERROR_STOP=1", "-q"]);
    if (r.code !== 0) throw new Error(`${label} 실패: ${firstLine(r.err || r.out)}`);
    return r.out + r.err;
  }

  /** 마지막 select 의 행들을 JSON 배열로 — sql 은 반드시 'select … ' 하나(세미콜론 없이)여야 한다 */
  function rows(selectSql) {
    const wrapped = `select coalesce(json_agg(t), '[]'::json)::text as j from (${selectSql}) t`;
    ensureLinked();
    if (via === "pg") {
      const r = withRetry("read", () => pgRun(`${wrapped};`));
      if (r.code !== 0) throw new Error(`DB 조회 실패: ${firstLine(r.err)}`);
      return JSON.parse(r.json.rows?.[0]?.j ?? "[]");
    }
    if (via === "supabase") {
      const f = file(`${wrapped};\n`);
      try {
        const r = withRetry("read", () => {
          const x = spawn("supabase", ["db", "query", "--linked", "-f", f]);
          return parseCliJson(x.out) ? x : { ...x, code: x.code === 0 ? 1 : x.code };
        });
        const j = parseCliJson(r.out);
        if (!j) throw new Error(`DB 조회 실패: ${firstLine(r.err || r.out)}`);
        return JSON.parse(j.rows?.[0]?.j ?? "[]");
      } finally { rmSync(f, { force: true }); }
    }
    const r = withRetry("read", () => psqlRun(`${wrapped};`, ["-v", "ON_ERROR_STOP=1", "-At", "-q"]));
    if (r.code !== 0) throw new Error(`DB 조회 실패: ${firstLine(r.err || r.out)}`);
    return JSON.parse(r.out.trim() || "[]");
  }

  /**
   * 스크립트(여러 문장, begin…rollback 포함 가능) 실행 → 마지막 결과 행들(객체 배열).
   *  supabase: CLI 가 마지막 결과를 JSON 으로 준다.
   *  psql/docker: 마지막 결과 문장 앞에서만 출력을 켜고(\o) CSV 로 받아 머리글로 객체를 만든다.
   */
  function script(sqlText) {
    ensureLinked();
    if (via === "pg") {
      const r = withRetry("read", () => {
        const x = pgRun(sqlText);
        // 연결·게이트웨이 오류만 다시 시도(시험 자체의 예외는 결과다)
        return x.code !== 0 && !TRANSIENT_RE.test(x.err) ? { ...x, code: 0, keep: true } : x;
      });
      const j = r.json;
      if (!j) return { rows: [], error: firstLine(r.err), errorText: r.err };
      if (!j.ok) return { rows: [], error: firstLine(`ERROR: ${j.error}`), errorText: `ERROR: ${j.error}` };
      return { rows: (j.rows ?? []).map(normalizeRow), error: null, errorText: "" };
    }
    if (via === "supabase") {
      const f = file(sqlText);
      try {
        const r = withRetry("read", () => {
          const x = spawn("supabase", ["db", "query", "--linked", "-f", f]);
          return !parseCliJson(x.out) && TRANSIENT_RE.test(`${x.err}\n${x.out}`) ? { ...x, code: x.code === 0 ? 1 : x.code } : { ...x, code: 0 };
        });
        const j = parseCliJson(r.out);
        if (!j) return { rows: [], error: firstLine(r.err || r.out), errorText: `${r.err}\n${r.out}` };
        return { rows: (j.rows ?? []).map(normalizeRow), error: null, errorText: "" };
      } finally { rmSync(f, { force: true }); }
    }
    const stmts = splitTopLevel(sqlText);
    // 마지막 결과 문장 = 끝에서부터 처음 만나는 select·with 문(rollback/commit 은 건너뜀)
    let idx = -1;
    for (let i = stmts.length - 1; i >= 0; i--) {
      const head = stmts[i].text.replace(/^(\s|--[^\n]*\n|;)+/, "").toLowerCase();   // 빈 문장(;)은 건너뜀
      if (/^(select|with|values|table)\b/.test(head)) { idx = i; break; }
      if (!/^(rollback|commit|end|abort)\b/.test(head) && head.length > 0) break;
    }
    const devnull = "/dev/null";
    const body = idx < 0 ? sqlText
      : `\\o ${devnull}\n${stmts.slice(0, idx).map((x) => x.text).join("")}\n\\o\n${stmts[idx].text}${stmts.slice(idx + 1).map((x) => x.text).join("")}`;
    const r = withRetry("read", () => {
      const x = psqlRun(body, ["-v", "ON_ERROR_STOP=1", "-q", "--csv"]);
      return TRANSIENT_RE.test(x.err) && parseCsv(x.out).length === 0 ? x : { ...x, code: 0, realCode: x.code };
    });
    const rows = parseCsv(r.out);
    if (rows.length === 0) return { rows: [], error: firstLine(r.err || r.out) || "결과가 없습니다.", errorText: `${r.err}\n${r.out}` };
    const [head, ...data] = rows;
    const bad = (r.realCode ?? r.code) !== 0;
    return { rows: data.map((d) => normalizeRow(Object.fromEntries(head.map((h, i) => [h, d[i] ?? null])))), error: bad ? firstLine(r.err || r.out) : null, errorText: bad ? r.err : "" };
  }

  function psqlRun(sql, extra) {
    if (via.startsWith("docker:")) {
      const name = via.slice(7);
      return spawn("docker", ["exec", "-i", name, "psql", "-U", user, "-d", database, ...extra, "-f", "-"], sql);
    }
    if (via === "psql") {
      const url = process.env.DATABASE_URL;
      if (!url) throw new Error("--via psql 은 DATABASE_URL 환경변수가 필요합니다.");
      return spawn("psql", [url, ...extra, "-f", "-"], sql);
    }
    throw new Error(`알 수 없는 실행 방법입니다: ${via} (supabase | pg | psql | docker:<컨테이너>)`);
  }

  /** 연결 확인(select 1) — 실패하면 사람 말 오류 */
  function ping() {
    const [x] = rows("select 1 as ok");
    if (Number(x?.ok) !== 1) throw new Error("DB 연결 확인 결과가 비었습니다.");
    return true;
  }

  return { exec, rows, script, ping, via };
}

/** .qg-kit.json 의 via(설치 때 기록) → 인자 --via 가 우선 */
export function resolveVia(a, kit) { return String(a.via ?? kit?.via ?? "supabase"); }

// ───────── 시험 결과 읽기(qg-run · qg-verify 공용) ─────────
/**
 * 형식: ① 마지막 결과에 step·ok·msg 행 + 'SUMMARY passed=N failed=M' 행 ② 모든 행에 ok ③ 예외 문구 'RESULT: A:OK | B:FAIL'
 *       ④ 예외 문구 'TEST RESULT …' 뒤에 줄마다 'PASS …' / 'FAIL …'(EKOS gos 계열 SQL 시험 — 끝에서 raise exception 으로 롤백)
 */
export function parseSmoke(rows, errText) {
  if (rows && rows.length > 0) {
    const sum = rows.find((r) => typeof r.step === "string" && r.step.startsWith("SUMMARY"));
    if (sum) {
      const m = sum.step.match(/passed=(\d+)\s+failed=(\d+)/);
      const failures = rows.filter((r) => r !== sum && r.ok !== true).map((r) => ({ step: String(r.step ?? ""), msg: String(r.msg ?? "").slice(0, 300) }));
      return { format: "summary", passed: m ? Number(m[1]) : 0, failed: m ? Number(m[2]) : failures.length, failures };
    }
    if (rows.every((r) => "ok" in r)) {
      const failures = rows.filter((r) => r.ok !== true).map((r) => ({ step: String(r.step ?? ""), msg: String(r.msg ?? "").slice(0, 300) }));
      return { format: "rows", passed: rows.length - failures.length, failed: failures.length, failures };
    }
  }
  const text = String(errText ?? "");
  const tr = text.indexOf("TEST RESULT");
  if (tr >= 0) {
    const failures = []; let passed = 0;
    let body = text.slice(tr);
    if (!/\n/.test(body)) body = body.replace(/\\n/g, "\n");   // CLI 가 오류 문구의 줄바꿈을 \n 글자로 줄 때
    for (const raw of body.split(/\r?\n/).slice(1)) {
      const line = raw.replace(/^(psql:[^:]*:\d+:\s*)?(DETAIL|CONTEXT|HINT):.*$/, "").trim();
      const m = line.match(/^(PASS|OK|FAIL|NG|ERROR)\b[\s:·-]*(.*)$/i);
      if (!m) continue;
      if (/^(PASS|OK)$/i.test(m[1])) passed++; else failures.push({ step: m[2].slice(0, 120) || `줄 ${passed + failures.length + 1}`, msg: m[2].slice(0, 300) });
    }
    if (passed + failures.length > 0) return { format: "test_result", passed, failed: failures.length, failures };
  }
  const m = text.match(/RESULT:\s*(.+)/);
  if (m) {
    const toks = m[1].split(/\s\|\s/).map((t) => t.trim()).filter(Boolean);
    const failures = []; let passed = 0;
    for (const t of toks) { const [name, ...rest] = t.split(":"); const v = rest.join(":").trim(); if (/^OK\b/.test(v)) passed++; else failures.push({ step: name, msg: v.slice(0, 300) }); }
    if (passed + failures.length > 0) return { format: "result_line", passed, failed: failures.length, failures };
  }
  return null;
}

// ───────── 한 트랜잭션 시험용 SQL 정리 ─────────
/** 마이그레이션의 최상위 begin/commit/end 문을 뺀다(바깥 begin…rollback 안에서 돌리기 위해). rollback 이 있으면 거부. */
export function stripTxControl(sql, label = "파일") {
  const out = [];
  for (const st of splitTopLevel(sql)) {
    const head = st.text.replace(/^(\s|--[^\n]*\n)+/, "").trim().toLowerCase().replace(/;$/, "").trim();
    if (/^(begin|commit|end|start transaction|begin transaction|begin work|commit work|commit transaction)$/.test(head)) { out.push(`-- (qg dry-apply: ${head} 뺌)\n`); continue; }
    if (/^(rollback|abort)\b/.test(head)) throw new Error(`${label}: 최상위 rollback 이 있어 한 트랜잭션 시험에 넣을 수 없습니다.`);
    out.push(st.text);
  }
  return out.join("");
}

/** 시험 파일에 최상위 commit 이 있으면 거부(운영 DB 를 바꿀 수 있음) */
export function assertNoCommit(sql, label = "시험 파일") {
  for (const st of splitTopLevel(sql)) {
    const head = st.text.replace(/^(\s|--[^\n]*\n)+/, "").trim().toLowerCase();
    if (/^(commit|end)\b\s*;?\s*$/.test(head) || /^commit\b/.test(head)) throw new Error(`${label}: 최상위 commit 이 있어 실행하지 않았습니다(시험은 항상 rollback).`);
  }
}

/** 아주 작은 glob(파일 이름 부분의 * ? 만) — 'supabase/migrations/911[3-9]_*.sql' 처럼 [] 도 지원 */
export function expandGlobs(root, patterns, readdir) {
  const out = [];
  for (const raw of patterns) {
    const pat = String(raw).trim().replace(/\\/g, "/");
    if (!pat) continue;
    if (!/[*?[]/.test(pat)) { out.push(pat); continue; }
    const dir = path.posix.dirname(pat); const base = path.posix.basename(pat);
    const re = new RegExp(`^${base.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`);
    let files = [];
    try { files = readdir(path.join(root, dir)); } catch { files = []; }
    for (const f of files.filter((x) => re.test(x)).sort()) out.push(`${dir}/${f}`);
  }
  return [...new Set(out)];
}

/** 결과 행 값 정리: ok = 참거짓, steps·failed = 숫자, failures = JSON */
function normalizeRow(row) {
  const out = { ...row };
  if ("ok" in out && typeof out.ok === "string") out.ok = out.ok === "t" || out.ok === "true";
  for (const k of ["steps", "failed", "n"]) if (k in out && typeof out[k] === "string" && /^-?\d+$/.test(out[k])) out[k] = Number(out[k]);
  if ("failures" in out && typeof out.failures === "string") { try { out.failures = JSON.parse(out.failures || "[]"); } catch { out.failures = []; } }
  return out;
}

/** SQL 을 최상위 세미콜론으로 나눈다(문자열·$태그$·주석 안의 ; 는 무시). 각 조각은 끝의 ; 까지 포함 */
export function splitTopLevel(sql) {
  const out = []; let i = 0; let start = 0; const n = sql.length;
  while (i < n) {
    const c = sql[i];
    if (c === "-" && sql[i + 1] === "-") { const e = sql.indexOf("\n", i); i = e < 0 ? n : e + 1; continue; }
    if (c === "/" && sql[i + 1] === "*") { const e = sql.indexOf("*/", i + 2); i = e < 0 ? n : e + 2; continue; }
    if (c === "'") { i++; while (i < n) { if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; } if (sql[i] === "'") { i++; break; } i++; } continue; }
    if (c === "$") {
      const m = sql.slice(i).match(/^\$([A-Za-z_][A-Za-z0-9_]*)?\$/);
      if (m) { const tag = m[0]; const e = sql.indexOf(tag, i + tag.length); i = e < 0 ? n : e + tag.length; continue; }
    }
    if (c === ";") { out.push({ text: sql.slice(start, i + 1) }); start = i + 1; }
    i++;
  }
  if (sql.slice(start).trim()) out.push({ text: sql.slice(start) });
  return out;
}

/** 간단한 CSV 파서(따옴표·줄바꿈 포함 칸 지원) */
export function parseCsv(text) {
  const rows = []; let row = []; let cur = ""; let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') q = false;
      else cur += c;
      continue;
    }
    if (c === '"') { q = true; continue; }
    if (c === ",") { row.push(cur); cur = ""; continue; }
    if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(cur); cur = "";
      if (!(row.length === 1 && row[0] === "")) rows.push(row);
      row = [];
      continue;
    }
    cur += c;
  }
  if (cur !== "" || row.length) { row.push(cur); rows.push(row); }
  return rows;
}

/** supabase db query 출력에서 JSON 덩어리 꺼내기 */
export function parseCliJson(out) {
  const lines = out.split(/\r?\n/);
  const s = lines.findIndex((l) => l === "{");
  if (s < 0) return null;
  const e = lines.findIndex((l, i) => i > s && l === "}");
  if (e < 0) return null;
  try { return JSON.parse(lines.slice(s, e + 1).join("\n")); } catch { return null; }
}

export function firstLine(out) {
  const l = String(out ?? "").split(/\r?\n/).find((x) => /ERROR|error:|failed/i.test(x) && !/new version/i.test(x));
  return (l ?? String(out ?? "").trim().split(/\r?\n/).slice(-1)[0] ?? "").slice(0, 600);
}

export const n = (v) => Number(v ?? 0).toLocaleString("ko-KR");
