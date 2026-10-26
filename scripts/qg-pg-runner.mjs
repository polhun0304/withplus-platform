#!/usr/bin/env node
/**
 * QG 키트 node-pg 실행기(qg-lib.mjs 가 --via pg 일 때 자식 프로세스로 부른다). 표준 입력 JSON {sql, mode} → 표준 출력 JSON.
 *  · pg 패키지는 대상 저장소(cwd)의 node_modules 에서 찾는다(키트는 의존성을 깔지 않는다).
 *  · 연결: QG_DB_URL → DATABASE_URL → SUPABASE_DB_URL → (SUPABASE_DB_PASSWORD + 프로젝트 ref → Supabase 세션 풀러)
 *          값은 환경변수 또는 저장소의 .env.db.local · .env.local 에서 읽는다. 비밀번호·연결 문자열은 출력하지 않는다.
 *  · 연결 실패는 호스트를 바꿔 가며 최대 3번(1·3·6초 쉬고) 다시 시도한다. 쿼리 중 오류는 다시 시도하지 않는다.
 */
import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const cwd = process.cwd();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function readEnvFile(f) {
  const p = path.join(cwd, f);
  if (!existsSync(p)) return {};
  const out = {};
  for (const line of readFileSync(p, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, "").trim();
  }
  return out;
}

function settings() {
  const env = { ...readEnvFile(".env.local"), ...readEnvFile(".env.db.local"), ...process.env };
  const secrets = [];
  for (const k of ["QG_DB_URL", "DATABASE_URL", "SUPABASE_DB_URL"]) {
    if (env[k]) { secrets.push(env[k]); return { urls: [env[k]], secrets, source: k }; }
  }
  const pw = env.SUPABASE_DB_PASSWORD;
  if (!pw) throw new Error("--via pg: 연결 정보가 없습니다. DATABASE_URL(또는 QG_DB_URL) 이나 .env.db.local 의 SUPABASE_DB_PASSWORD 를 넣어 주세요.");
  secrets.push(pw, encodeURIComponent(pw));
  let ref = env.QG_PROJECT_REF || env.SUPABASE_PROJECT_REF || "";
  if (!ref && existsSync(path.join(cwd, "supabase", ".temp", "project-ref"))) ref = readFileSync(path.join(cwd, "supabase", ".temp", "project-ref"), "utf8").trim();
  if (!ref) { const u = env.NEXT_PUBLIC_SUPABASE_URL || env.SUPABASE_URL || ""; const m = u.match(/^https:\/\/([a-z0-9]{20})\.supabase\.co/); if (m) ref = m[1]; }
  if (!/^[a-z0-9]{20}$/.test(ref)) throw new Error("--via pg: Supabase 프로젝트 ref 를 알 수 없습니다(QG_PROJECT_REF · supabase/.temp/project-ref · NEXT_PUBLIC_SUPABASE_URL 중 하나).");
  const hosts = (env.QG_POOLER_HOSTS || env.SUPABASE_POOLER_HOST || "aws-0-ap-northeast-2.pooler.supabase.com,aws-1-ap-northeast-2.pooler.supabase.com")
    .split(",").map((h) => h.trim()).filter(Boolean);
  return { urls: hosts.map((h) => `postgresql://postgres.${ref}:${encodeURIComponent(pw)}@${h}:5432/postgres`), secrets, source: "SUPABASE_DB_PASSWORD", ssl: true };
}

function scrub(msg, secrets) {
  let m = String(msg ?? "");
  for (const s of secrets) if (s && s.length >= 4) m = m.split(s).join("***");
  return m.replace(/postgres(ql)?:\/\/[^@\s]+@/g, "postgresql://***@");
}

async function main() {
  const input = JSON.parse(readFileSync(0, "utf8"));
  let pg;
  try { pg = createRequire(path.join(cwd, "package.json"))("pg"); }
  catch { throw new Error("--via pg: 이 저장소에 pg 패키지가 없습니다(npm i -D pg). 또는 --via supabase · --via psql 을 쓰세요."); }
  const cfg = settings();
  let client = null; let lastErr = null;
  const delays = [0, 1000, 3000, 6000];
  for (let attempt = 0; attempt < delays.length && !client; attempt++) {
    if (delays[attempt]) await sleep(delays[attempt]);
    const url = cfg.urls[attempt % cfg.urls.length];
    const c = new pg.Client({ connectionString: url, ssl: cfg.ssl || /supabase\.(co|com)/.test(url) ? { rejectUnauthorized: false } : undefined, connectionTimeoutMillis: 15000, statement_timeout: 0 });
    try { await c.connect(); client = c; } catch (e) { lastErr = e; try { await c.end(); } catch { /* 무시 */ } if (/password authentication failed/i.test(String(e?.message)) && !/cli_login/.test(String(e?.message))) break; }
  }
  if (!client) throw Object.assign(new Error(`DB 연결 실패: ${scrub(lastErr?.message ?? lastErr, cfg.secrets)}`), { connect: true });
  const notices = [];
  client.on("notice", (n) => { if (notices.length < 50) notices.push(String(n.message ?? "")); });
  try {
    const res = await client.query(input.sql);
    const list = Array.isArray(res) ? res : [res];
    let last = null;
    for (const r of list) if (r && Array.isArray(r.fields) && r.fields.length > 0) last = r;
    process.stdout.write(JSON.stringify({ ok: true, fields: last ? last.fields.map((f) => f.name) : [], rows: last ? last.rows : [], notices }));
  } catch (e) {
    try { await client.query("rollback"); } catch { /* 무시 */ }
    const msg = scrub([e.message, e.detail, e.hint].filter(Boolean).join("\n"), cfg.secrets);
    process.stdout.write(JSON.stringify({ ok: false, error: msg, notices }));
  } finally {
    try { await client.end(); } catch { /* 무시 */ }
  }
}

main().catch((e) => {
  process.stdout.write(JSON.stringify({ ok: false, error: String(e?.message ?? e), connect: !!e?.connect }));
});
