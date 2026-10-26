#!/usr/bin/env node
/**
 * QG 설치 검증 — 적용된 DB 를 읽어 완료 조건을 확인하고 요약 JSON 을 낸다(QG_KIT.md §10).
 *
 *   node scripts/qg-verify.mjs [--via supabase|pg|psql|docker:<컨테이너>] [--prefix p] [--json out.json]
 *        [--smoke]            스모크(rollback)도 실행해 SUMMARY failed=0 확인(+ .qg-kit.json extra_tests 의 플랫폼 시험)
 *        [--adversarial]      공격 시나리오(rollback)도 실행
 *        [--commit-runs]      엔진 실행 기록을 실제로 남김(기본은 begin…rollback 안에서 실행만 해 보고 되돌림)
 *        [--dry-apply]        적용 전: 시험 파일마다 begin → 키트 마이그레이션 + 플랫폼 확장 마이그레이션 → 그 시험 → rollback (DB 를 바꾸지 않음)
 *          [--extra-migrations "supabase/migrations/911[3-9]_*.sql,…"]  플랫폼 확장 마이그레이션(기본: .qg-kit.json extra_migrations)
 *          [--extra-tests "supabase/tests/9113_*.sql,…"]                플랫폼 시험(기본: .qg-kit.json extra_tests) — 형식은 qg-run 과 같음
 *        [--allowlist-draft]  익명 실행 DEFINER 실측 → supabase/qg-anon-allowlist-draft.sql 초안(사유는 사람이 채움, 날짜는 한국 시각)
 *  확인 항목: 표·함수 존재, QG 표 RLS, QG DEFINER search_path, 익명 실행 QG 함수 0, 내부 함수 로그인 실행 0,
 *            엔진 10·검사 항목, 엔진 실행(10종), 증거 체인, 어댑터 정보, pg_cron 등록, 강제 스위치 기본 false.
 *  종료 코드: 0 = 모두 통과, 1 = 실패 있음, 2 = 실행 준비 실패. 운영 데이터를 바꾸지 않는다(--commit-runs 제외).
 */
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { assertNoCommit, expandGlobs, kstDate, makeDb, parseArgs, parseSmoke, resolveVia, stripTxControl } from "./qg-lib.mjs";

const ROOT = process.cwd();
const a = parseArgs(process.argv.slice(2));
const kit = existsSync(path.join(ROOT, ".qg-kit.json")) ? JSON.parse(readFileSync(path.join(ROOT, ".qg-kit.json"), "utf8")) : {};
const P = String(a.prefix ?? kit.prefix ?? "");
if (!/^[a-z][a-z0-9]{1,11}$/.test(P)) { console.error("접두어를 알 수 없습니다(.qg-kit.json 또는 --prefix)."); process.exit(2); }
const db = makeDb(resolveVia(a, kit), { cwd: ROOT });
const list = (v) => (Array.isArray(v) ? v : String(v ?? "").split(",")).map((x) => String(x).trim()).filter(Boolean);
const EXTRA_MIGS = expandGlobs(ROOT, a["extra-migrations"] !== undefined ? list(a["extra-migrations"]) : list(kit.extra_migrations), readdirSync);
const EXTRA_TESTS = expandGlobs(ROOT, a["extra-tests"] !== undefined ? list(a["extra-tests"]) : list(kit.extra_tests), readdirSync);
const describeTest = (label, rows, error, errorText) => {
  const p = parseSmoke(rows, errorText || error);
  if (!p) return { ok: false, detail: `결과 없음: ${(error ?? "").slice(0, 600)}` };
  const bad = p.failures.map((f) => ` | ${f.step}: ${f.msg}`).join("");
  return { ok: p.failed === 0 && p.passed > 0, detail: `${label} 통과 ${p.passed} · 실패 ${p.failed}${bad}`.slice(0, 1500) };
};

const L = (s) => s.replace(/_/g, "\\_");   // LIKE 용
const checks = [];
const add = (name, ok, detail) => { checks.push({ name, ok: !!ok, detail }); console.log(`${ok ? "✔" : "✘"} ${name}${detail !== undefined ? ` — ${typeof detail === "string" ? detail : JSON.stringify(detail).slice(0, 300)}` : ""}`); };
const tryStep = (name, fn) => { try { fn(); } catch (e) { add(name, false, String(e instanceof Error ? e.message : e).slice(0, 500)); } };
// 연결 확인(처음) — 연결 안 되면 다른 점검을 하지 않고 사람 말로 멈춘다
try { db.ping(); add("DB 연결", true, db.via); }
catch (e) { add("DB 연결", false, String(e instanceof Error ? e.message : e).slice(0, 600)); finish(); }

const TABLES = ["settings", "engines", "checks", "anon_allowlist", "evidence", "runs", "issues", "findings", "risk_approvals", "issue_events",
  "risk_items", "test_suites", "scenarios", "banned_phrases", "required_clauses", "reviewers", "reviews", "review_verdicts",
  "regulations", "regulation_changes", "compliance_targets", "ai_models", "ai_tasks", "ai_calls", "ai_eval_sets", "ai_evals", "ai_model_approvals", "ai_model_events",
  "gate_policies", "releases", "release_events", "proposals", "proposal_events"];
const RPCS = ["run_engine(text,uuid)", "ingest(jsonb,text)", "issue_transition(uuid,text,text)", "issue_decide(uuid,text,text)", "dashboard()", "verify_evidence_chain()",
  "setting_set(text,jsonb)", "adapter_info()", "review_request(text,text,text,text,uuid,boolean)", "review_submit(uuid,text,jsonb)", "review_finalize(uuid)", "review_confirm(uuid,text,text)",
  "regulation_change_add(text,text,date,text,text,jsonb,uuid)", "regulation_mark_reviewed(text,text)", "ai_eval_record(text,text,text,text,integer,uuid,text,uuid)",
  "ai_model_set_status(text,text,text,text)", "ai_model_decide(text,text,text,text)", "ai_routing_policy(text)", "ai_call_record(text,text,text,integer,numeric,text,uuid,integer,integer)",
  "release_create(text,text,text,text,text)", "release_evaluate(uuid,boolean)", "release_decide(uuid,text,text)", "release_record_deploy(uuid,text,text,text,text,text)",
  "release_mark_released(uuid,text)", "release_gate_hook_internal(text,text)", "evolution_collect()", "proposal_transition(uuid,text,text,uuid)",
  "issue_bulk_transition(uuid[],text,text)", "review_candidates(text,integer)", "release_gate_require_internal(text,text)"];

// ───────── 적용 전 한 트랜잭션 시험 ─────────
if (a["dry-apply"]) {
  const kitMigs = (kit.migrations ?? []).filter((m) => !EXTRA_MIGS.includes(m));
  const smoke = kit.smoke ? path.join(ROOT, kit.smoke) : null;
  if (kitMigs.length === 0 || !smoke || !existsSync(smoke)) { console.error(".qg-kit.json 의 마이그레이션·스모크 경로를 찾을 수 없습니다(qg-install.mjs 로 먼저 설치)."); process.exit(2); }
  const missing = [...kitMigs, ...EXTRA_MIGS, ...EXTRA_TESTS].filter((f) => !existsSync(path.join(ROOT, f)));
  if (missing.length) { add("파일 확인", false, `없는 파일: ${missing.join(", ")}`); finish(); }
  let migSql;
  // 적용 순서 = 파일 이름 순(supabase 와 같음) — 업그레이드 파일이 플랫폼 확장 파일 뒤에 오는 운영 순서를 그대로 흉내 낸다
  const ordered = [...new Set([...kitMigs, ...EXTRA_MIGS])].sort((x, y) => { const bx = path.basename(x), by = path.basename(y); return bx < by ? -1 : bx > by ? 1 : 0; });
  try { migSql = ordered.map((f) => `-- ▼ ${f}\n${stripTxControl(readFileSync(path.join(ROOT, f), "utf8"), f)}`).join("\n;\n"); }
  catch (e) { add("마이그레이션 준비", false, e.message); finish(); }
  if (EXTRA_MIGS.length) add("플랫폼 확장 마이그레이션 포함", true, EXTRA_MIGS.join(", "));
  // 시험 파일마다 따로: begin → (키트 + 확장) 마이그레이션 → 시험(자기 rollback 또는 예외로 끝남). 앞 시험이 뒤 시험에 영향을 주지 않는다.
  for (const t of [path.relative(ROOT, smoke).replace(/\\/g, "/"), ...EXTRA_TESTS]) {
    const tsql = readFileSync(path.join(ROOT, t), "utf8");
    try { assertNoCommit(tsql, t); } catch (e) { add(`한 트랜잭션 시험: ${t}`, false, e.message); continue; }
    const { rows, error, errorText } = db.script(`begin;\n${migSql}\n;\n-- ▼ 시험 ${t}\n${tsql}\n;\nrollback;\n`);
    const d = describeTest(path.basename(t), rows, error, errorText);
    add(`한 트랜잭션 시험(begin → 마이그레이션 ${kitMigs.length + EXTRA_MIGS.length}개 → ${path.basename(t)} → rollback)`, d.ok, d.detail);
  }
  finish();
}

// ───────── anon 허용 목록 초안 ─────────
if (a["allowlist-draft"]) {
  const has = db.rows(`select to_regclass('public.${P}_qg_anon_allowlist') is not null as ok`)[0]?.ok;
  const rows = db.rows(`select p.oid::regprocedure::text as sig from pg_proc p where p.pronamespace = 'public'::regnamespace and p.prosecdef
      and has_function_privilege('anon', p.oid, 'execute') ${has ? `and p.oid::regprocedure::text not in (select signature from public.${P}_qg_anon_allowlist where active)` : ""} order by 1`);
  const out = path.join(ROOT, "supabase", "qg-anon-allowlist-draft.sql");
  const lines = [
    `-- QG 익명 실행 허용 목록 초안(${kstDate()} 실측 ${rows.length}개, 한국 날짜) — 그대로 적용하지 말 것.`,
    "-- 함수마다 ① 정말 로그인 없이 불러야 하는지 ② 보호 장치(서버 증명키·추측 불가 토큰·속도 제한·공개 정보만)를 확인해",
    "--   정당하면 'TODO' 를 실제 사유로 바꿔 남기고(사유가 TODO 면 표 제약이 거부함), 아니면 아래 revoke 줄을 쓰세요.",
    "",
    ...rows.flatMap((r) => [
      `insert into public.${P}_qg_anon_allowlist(signature, reason, protection) values ('${r.sig.replace(/'/g, "''")}', 'TODO: 공개 이유', 'TODO: 보호 장치') on conflict (signature) do nothing;`,
      `-- 또는: revoke all on function public.${r.sig} from public, anon;`,
    ]),
  ];
  writeFileSync(out, lines.join("\n") + "\n", "utf8");
  add("익명 실행 DEFINER 실측", true, `${rows.length}개 → ${path.relative(ROOT, out)}`);
  finish();
}

// ───────── 적용 뒤 점검(읽기 전용) ─────────
tryStep("표 존재", () => {
  const rows = db.rows(`select t as name, to_regclass('public.${P}_qg_' || t) is not null as ok from unnest(array[${TABLES.map((t) => `'${t}'`).join(",")}]) t`);
  const missing = rows.filter((r) => !r.ok).map((r) => r.name);
  add("표 존재", missing.length === 0, missing.length ? `없음: ${missing.join(", ")}` : `${TABLES.length}개`);
});
tryStep("RPC 존재", () => {
  const rows = db.rows(`select s as sig, to_regprocedure('public.${P}_qg_' || s) is not null as ok from unnest(array[${RPCS.map((s) => `'${s}'`).join(",")}]) s`);
  const missing = rows.filter((r) => !r.ok).map((r) => r.sig);
  add("RPC 존재", missing.length === 0, missing.length ? `없음: ${missing.join(", ")}` : `${RPCS.length}개`);
});
tryStep("보안 불변식", () => {
  const [x] = db.rows(`select
     (select count(*) from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and c.relname like '${L(P)}\\_qg\\_%' and not c.relrowsecurity) as rls_off,
     (select count(*) from pg_proc p where p.pronamespace = 'public'::regnamespace and (p.proname like '${L(P)}\\_qg\\_%' or p.proname like '${L(P)}\\_qga\\_%')
        and has_function_privilege('anon', p.oid, 'execute')) as anon_exec,
     (select count(*) from pg_proc p where p.pronamespace = 'public'::regnamespace and p.prosecdef and (p.proname like '${L(P)}\\_qg\\_%' or p.proname like '${L(P)}\\_qga\\_%')
        and not exists (select 1 from unnest(coalesce(p.proconfig, '{}'::text[])) c where c like 'search_path=%')) as no_search_path,
     (select count(*) from pg_proc p where p.pronamespace = 'public'::regnamespace
        and (p.proname like '${L(P)}\\_qg\\_%\\_internal' or p.proname like '${L(P)}\\_qg\\_probe\\_%' or (p.proname like '${L(P)}\\_qga\\_%' and p.proname not in ('${P}_qga_is_admin','${P}_qga_can_read_tenant')))
        and has_function_privilege('authenticated', p.oid, 'execute')) as internal_exec,
     (select count(*) from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and c.relname like '${L(P)}\\_qg\\_%'
        and has_table_privilege('anon', c.oid, 'select,insert,update,delete')) as anon_table`);
  add("QG 표 RLS 모두 켜짐", Number(x.rls_off) === 0, `꺼진 표 ${x.rls_off}`);
  add("익명 실행 가능한 QG 함수 0", Number(x.anon_exec) === 0, `${x.anon_exec}개`);
  add("QG DEFINER search_path 고정", Number(x.no_search_path) === 0, `없는 것 ${x.no_search_path}`);
  add("내부 함수 로그인 실행 0", Number(x.internal_exec) === 0, `${x.internal_exec}개`);
  add("QG 표 익명 권한 0", Number(x.anon_table) === 0, `${x.anon_table}개`);
});
tryStep("카탈로그", () => {
  const rows = db.rows(`select g.code, (select count(*) from public.${P}_qg_checks c where c.engine_code = g.code and c.active) as checks from public.${P}_qg_engines g order by g.sort`);
  const empty = rows.filter((r) => Number(r.checks) === 0).map((r) => r.code);
  add("엔진 10종", rows.length === 10, rows.map((r) => `${r.code}:${r.checks}`).join(" "));
  add("엔진마다 검사 항목", empty.length === 0, empty.length ? `없음: ${empty.join(", ")}` : undefined);
});
tryStep("강제 스위치", () => {
  const rows = db.rows(`select key, value from public.${P}_qg_settings where key like 'qg\\_enforce\\_%'`);
  const on = rows.filter((r) => r.value === true).map((r) => r.key);
  add("강제 스위치(qg_enforce_*) 상태", true, on.length ? `켜짐: ${on.join(", ")}` : `모두 꺼짐(기본) ${rows.length}개`);
});
tryStep("어댑터·cron", () => {
  const [x] = db.rows(`select public.${P}_qga_info() as info, exists (select 1 from pg_extension where extname = 'pg_cron') as cron`);
  add("어댑터 정보", !!x.info, x.info);
  if (x.cron) {
    const [j] = db.rows(`select count(*) as n from cron.job where jobname in ('${P}_qg_cron_hourly','${P}_qg_cron_daily')`);
    add("자동 실행 등록(pg_cron)", Number(j.n) === 2, `${j.n}/2`);
  } else add("자동 실행 등록(pg_cron)", true, "pg_cron 없음 — 건너뜀(지금 실행·외부 결과는 동작)");
});
tryStep("증거 체인", () => {
  const [x] = db.rows(`select public.${P}_qg_evidence_verify_rows_internal(public.${P}_qg_evidence_rows_internal()) as v`);
  add("증거 체인", x.v?.ok === true, x.v?.message);
});
tryStep("엔진 실행", () => {
  const engines = db.rows(`select code from public.${P}_qg_engines where enabled order by sort`).map((r) => r.code);
  const sql = `${a["commit-runs"] ? "" : "begin;\n"}create temp table qg_verify_out(engine text, status text, totals jsonb, err text);
do $$ declare e text; v uuid; begin
  foreach e in array array[${engines.map((e) => `'${e}'`).join(",")}] loop
    begin
      v := public.${P}_qg_run_engine_internal(e, null, 'script', null, null, '{"runner":"qg-verify"}'::jsonb);
      insert into qg_verify_out select e, r.status, r.totals, null from public.${P}_qg_runs r where r.id = v;
    exception when others then insert into qg_verify_out values (e, 'exception', null, left(sqlerrm, 300));
    end;
  end loop;
end $$;
select engine, status, totals::text as totals, err from qg_verify_out;
${a["commit-runs"] ? "commit;" : "rollback;"}\n`;
  const { rows, error } = db.script(a["commit-runs"] ? `begin;\n${sql}` : sql);
  const bad = rows.filter((r) => r.status === "exception");
  add(`엔진 실행 ${rows.length}종${a["commit-runs"] ? "(기록 남김)" : "(되돌림)"}`, rows.length === engines.length && bad.length === 0,
    rows.length ? rows.map((r) => `${r.engine}:${r.status}`).join(" ") : `결과 없음 ${error ?? ""}`);
});
if (a.smoke) tryStep("스모크", () => {
  const f = kit.smoke ? path.join(ROOT, kit.smoke) : null;
  if (!f || !existsSync(f)) throw new Error("스모크 파일을 찾을 수 없습니다.");
  for (const t of [path.relative(ROOT, f).replace(/\\/g, "/"), ...EXTRA_TESTS]) {
    const tsql = readFileSync(path.join(ROOT, t), "utf8");
    try { assertNoCommit(tsql, t); } catch (e) { add(`시험(rollback): ${t}`, false, e.message); continue; }
    const { rows, error, errorText } = db.script(tsql);
    const d = describeTest(path.basename(t), rows, error, errorText);
    add(t === EXTRA_TESTS.find((x) => x === t) ? `플랫폼 시험(rollback): ${path.basename(t)}` : "스모크(rollback)", d.ok, d.detail);
  }
});
if (a.adversarial) tryStep("공격 시나리오", () => {
  const f = kit.adversarial ? path.join(ROOT, kit.adversarial) : null;
  if (!f || !existsSync(f)) throw new Error("공격 시나리오 파일을 찾을 수 없습니다.");
  const { rows, error } = db.script(readFileSync(f, "utf8"));
  add("공격 시나리오(rollback)", rows.length > 0 && rows.every((r) => r.result === "PASS"), rows.length ? rows.map((r) => `${r.scenario}=${r.result}`).join(" ") : `결과 없음: ${error ?? ""}`);
});
finish();

function finish() {
  const summary = { kit: "QG_KIT", prefix: P, via: db.via, at: new Date().toISOString(), ok: checks.every((c) => c.ok), passed: checks.filter((c) => c.ok).length, failed: checks.filter((c) => !c.ok).length, checks };
  if (a.json) writeFileSync(path.resolve(String(a.json)), JSON.stringify(summary, null, 2), "utf8");
  console.log(`\n${summary.ok ? "통과" : "실패"} — 확인 ${summary.passed} · 실패 ${summary.failed}`);
  console.log(JSON.stringify({ ok: summary.ok, passed: summary.passed, failed: summary.failed }));
  process.exit(summary.ok ? 0 : 1);
}

