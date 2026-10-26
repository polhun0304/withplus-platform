-- QG 공격 시나리오 — QG 자신의 방어(키트 기본 6종). 항상 rollback(운영 데이터 무변경).
--  qg_anon_rpc · qg_forged_server_key · qg_evidence_tamper · qg_probe_injection · qg_self_approval · qg_oversized_ingest
--  결과: 시나리오마다 (scenario, result PASS|FAIL, steps, failed, failures) 한 행.
--  실행: node scripts/qg-run.mjs adversarial   (직접: supabase db query --linked -f supabase/tests/qg/adversarial_qg_core.sql)
begin;
create temp table r(n serial, scenario text, step text, ok boolean, msg text);
grant all on r to authenticated, anon; grant usage, select on sequence r_n_seq to authenticated, anon;
create temp table fx(k text primary key, v text);
grant all on fx to authenticated, anon;

-- 막혀야 하는 동작: 예외 또는 0행이면 ok
create function pg_temp.atk(p_sc text, p_step text, p_sql text) returns void language plpgsql as $f$
declare v_cnt int;
begin
  begin execute p_sql; get diagnostics v_cnt = row_count; insert into r(scenario, step, ok, msg) values (p_sc, p_step, v_cnt = 0, 'rows=' || v_cnt);
  exception when others then insert into r(scenario, step, ok, msg) values (p_sc, p_step, true, left(sqlerrm, 200)); end;
end $f$;
-- 참이어야 하는 조건
create function pg_temp.must(p_sc text, p_step text, p_sql text) returns void language plpgsql as $f$
declare v boolean;
begin
  begin execute p_sql into v; insert into r(scenario, step, ok, msg) values (p_sc, p_step, coalesce(v, false), 'got=' || coalesce(v::text, 'null'));
  exception when others then insert into r(scenario, step, ok, msg) values (p_sc, p_step, false, 'err: ' || left(sqlerrm, 200)); end;
end $f$;
create function pg_temp.as_user(p_uid uuid) returns void language plpgsql as $f$
begin perform set_config('request.jwt.claims', json_build_object('sub', p_uid, 'role', 'authenticated')::text, true);
      perform set_config('request.jwt.claim.sub', coalesce(p_uid::text, ''), true); execute 'set local role authenticated'; end $f$;
create function pg_temp.as_anon() returns void language plpgsql as $f$
begin perform set_config('request.jwt.claims', json_build_object('role', 'anon')::text, true);
      perform set_config('request.jwt.claim.sub', '', true); execute 'set local role anon'; end $f$;
create function pg_temp.as_pg() returns void language plpgsql as $f$
begin execute 'reset role'; perform set_config('request.jwt.claims', '', true); perform set_config('request.jwt.claim.sub', '', true); end $f$;
create function pg_temp.v(p_k text) returns text language sql as $f$ select v from fx where k = p_k $f$;
grant execute on all functions in schema pg_temp to authenticated, anon;

insert into fx select key, value from jsonb_each_text(public.wpl_qga_smoke_fixture()) where value is not null;

-- ───────── qg_anon_rpc ─────────
select pg_temp.as_anon();
select pg_temp.atk('qg_anon_rpc', 'run_engine', $q$select public.wpl_qg_run_engine('security')$q$);
select pg_temp.atk('qg_anon_rpc', 'dashboard', $q$select public.wpl_qg_dashboard()$q$);
select pg_temp.atk('qg_anon_rpc', 'setting_set', $q$select public.wpl_qg_setting_set('qg_cron_enabled', 'false'::jsonb)$q$);
select pg_temp.atk('qg_anon_rpc', 'issue_transition', $q$select public.wpl_qg_issue_transition(gen_random_uuid(), 'fixed', null)$q$);
select pg_temp.atk('qg_anon_rpc', 'release_create', $q$select public.wpl_qg_release_create('code_deploy', 'abcdef1', null, null, null)$q$);
select pg_temp.atk('qg_anon_rpc', 'read_runs', $q$select * from wpl_qg_runs$q$);
select pg_temp.atk('qg_anon_rpc', 'read_evidence', $q$select * from wpl_qg_evidence$q$);
select pg_temp.atk('qg_anon_rpc', 'read_issues', $q$select * from wpl_qg_issues$q$);
select pg_temp.atk('qg_anon_rpc', 'read_settings', $q$select * from wpl_qg_settings$q$);
select pg_temp.atk('qg_anon_rpc', 'insert_check', $q$insert into wpl_qg_checks(code, engine_code, name, probe) values ('evidence.adv_x', 'evidence', 'x', 'manual')$q$);

-- ───────── qg_forged_server_key ─────────
select pg_temp.as_user(pg_temp.v('outsider')::uuid);
select pg_temp.atk('qg_forged_server_key', 'no_key', $q$select public.wpl_qg_ingest('{"engine":"testing","results":[{"check_code":"testing.suite_qg_smoke","status":"pass"}]}'::jsonb, null)$q$);
select pg_temp.atk('qg_forged_server_key', 'forged_key', $q$select public.wpl_qg_ingest('{"engine":"testing","results":[{"check_code":"testing.suite_qg_smoke","status":"pass"}]}'::jsonb, 'forged-key-forged-key-0000')$q$);
select pg_temp.atk('qg_forged_server_key', 'record_deploy_forged', $q$select public.wpl_qg_release_record_deploy(gen_random_uuid(), 'dpl', 'READY', 'abcdef1', null, 'forged-key-forged-key-0000')$q$);
select pg_temp.as_anon();
select pg_temp.atk('qg_forged_server_key', 'anon_with_key', $q$select public.wpl_qg_ingest('{"engine":"testing","results":[{"check_code":"testing.suite_qg_smoke","status":"pass"}]}'::jsonb, 'forged-key-forged-key-0000')$q$);

-- ───────── qg_evidence_tamper ─────────
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select public.wpl_qg_run_engine('evidence');
select pg_temp.atk('qg_evidence_tamper', 'admin_update_evidence', $q$update wpl_qg_evidence set title = 'x'$q$);
select pg_temp.atk('qg_evidence_tamper', 'admin_delete_evidence', $q$delete from wpl_qg_evidence$q$);
select pg_temp.atk('qg_evidence_tamper', 'admin_insert_evidence', $q$insert into wpl_qg_evidence(kind, ref, payload, payload_sha256, prev_hash, hash) values ('document','x','{}', repeat('0',64), 'GENESIS', repeat('1',64))$q$);
select pg_temp.atk('qg_evidence_tamper', 'admin_update_runs', $q$update wpl_qg_runs set status = 'passed'$q$);
select pg_temp.as_pg();
select pg_temp.atk('qg_evidence_tamper', 'owner_update_evidence', $q$update wpl_qg_evidence set title = 'x'$q$);
select pg_temp.atk('qg_evidence_tamper', 'owner_truncate', $q$truncate wpl_qg_findings cascade$q$);
select pg_temp.must('qg_evidence_tamper', 'copy_tamper_detected', $q$select not (public.wpl_qg_evidence_verify_rows_internal(
   (select jsonb_agg(case when (e->>'seq')::int = (select max(seq) from wpl_qg_evidence) then jsonb_set(e, '{payload}', '{"forged":1}') else e end)
      from jsonb_array_elements(public.wpl_qg_evidence_rows_internal()) e))->>'ok')::boolean$q$);
select pg_temp.must('qg_evidence_tamper', 'chain_still_ok', $q$select (public.wpl_qg_evidence_verify_rows_internal(public.wpl_qg_evidence_rows_internal())->>'ok')::boolean$q$);

-- ───────── qg_probe_injection ─────────
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.atk('qg_probe_injection', 'sql_fragment', $q$insert into wpl_qg_checks(code, engine_code, name, probe) values ('evidence.adv_inj1', 'evidence', 'x', 'wpl_qg_probe_x(); drop table wpl_qg_runs; --')$q$);
select pg_temp.atk('qg_probe_injection', 'foreign_function', $q$insert into wpl_qg_checks(code, engine_code, name, probe) values ('evidence.adv_inj2', 'evidence', 'x', 'pg_sleep')$q$);
select pg_temp.atk('qg_probe_injection', 'path_traversal', $q$insert into wpl_qg_checks(code, engine_code, name, probe) values ('evidence.adv_inj3', 'evidence', 'x', 'scenario:../x')$q$);
select pg_temp.atk('qg_probe_injection', 'quote_injection', $q$insert into wpl_qg_checks(code, engine_code, name, probe) values ('evidence.adv_inj4', 'evidence', 'x', 'wpl_qg_probe_a"; select 1; --')$q$);
select pg_temp.as_pg();
select pg_temp.must('qg_probe_injection', 'resolver_rejects', $q$select (public.wpl_qg_probe_resolve_internal('pg_terminate_backend')->>'ok')::boolean is false$q$);

-- ───────── qg_self_approval ─────────
select pg_temp.as_pg();
create function public.wpl_qg_probe_zz_adv(p_check public.wpl_qg_checks, p_tenant uuid) returns jsonb language sql set search_path = public as $f$
  select '{"status":"fail","severity":"critical","fingerprint":"adv","title":"시험 치명 결함"}'::jsonb $f$;
revoke all on function public.wpl_qg_probe_zz_adv(public.wpl_qg_checks, uuid) from public, anon, authenticated;
insert into wpl_qg_checks(code, engine_code, name, probe, risk, schedule) values ('evidence.zz_adv', 'evidence', '시험 결함', 'wpl_qg_probe_zz_adv', 'critical', 'manual');
update wpl_qg_gate_policies set required_engines = '[]', block_severities = '[]', require_review = false where kind = 'policy_change';
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select public.wpl_qg_run_engine('evidence');
insert into fx select 'iss', id::text from wpl_qg_issues where check_code = 'evidence.zz_adv';
select public.wpl_qg_issue_transition(pg_temp.v('iss')::uuid, 'accepted_risk', '시험용 결함이라 위험을 받아들입니다');
insert into fx select 'appr', id::text from wpl_qg_risk_approvals where issue_id = pg_temp.v('iss')::uuid and status = 'pending';
select pg_temp.atk('qg_self_approval', 'risk_self_approve', $q$select public.wpl_qg_issue_decide(pg_temp.v('appr')::uuid, 'approved', null)$q$);
insert into fx select 'rel', (public.wpl_qg_release_create('policy_change', 'qg_review_quorum', null, null, null)->>'id');
select public.wpl_qg_release_evaluate(pg_temp.v('rel')::uuid, false);
select pg_temp.atk('qg_self_approval', 'release_self_approve', $q$select public.wpl_qg_release_decide(pg_temp.v('rel')::uuid, 'approved', null)$q$);
select pg_temp.atk('qg_self_approval', 'direct_status_update', $q$update wpl_qg_releases set status = 'approved'$q$);
select pg_temp.as_user(pg_temp.v('admin2')::uuid);
select pg_temp.must('qg_self_approval', 'other_admin_can_approve', $q$select (public.wpl_qg_release_decide(pg_temp.v('rel')::uuid, 'approved', '확인')->>'status') = 'approved'$q$);

-- ───────── qg_oversized_ingest ─────────
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.atk('qg_oversized_ingest', 'too_many_results', $q$select public.wpl_qg_ingest(jsonb_build_object('engine','testing','results',
   (select jsonb_agg(jsonb_build_object('check_code','testing.suite_qg_smoke','status','pass')) from generate_series(1, 2001))), null)$q$);
select pg_temp.atk('qg_oversized_ingest', 'huge_context', $q$select public.wpl_qg_ingest(jsonb_build_object('engine','testing','context', jsonb_build_object('x', repeat('a', 9000)),
   'results', '[{"check_code":"testing.suite_qg_smoke","status":"pass"}]'::jsonb), null)$q$);
select pg_temp.atk('qg_oversized_ingest', 'foreign_check', $q$select public.wpl_qg_ingest('{"engine":"testing","results":[{"check_code":"security.anon_definer","status":"pass"}]}'::jsonb, null)$q$);
select pg_temp.atk('qg_oversized_ingest', 'empty_results', $q$select public.wpl_qg_ingest('{"engine":"testing","results":[]}'::jsonb, null)$q$);
select pg_temp.as_pg();
select pg_temp.must('qg_oversized_ingest', 'big_detail_clipped', $q$select (public.wpl_qg_clip_detail_internal(jsonb_build_object('x', repeat('b', 50000)))->>'truncated')::boolean$q$);

select pg_temp.as_pg();
select scenario, case when bool_and(ok is true) then 'PASS' else 'FAIL' end as result, count(*) as steps,
       count(*) filter (where ok is distinct from true) as failed,
       coalesce(jsonb_agg(jsonb_build_object('step', step, 'msg', left(msg, 200)) order by n) filter (where ok is distinct from true), '[]'::jsonb) as failures
  from r group by scenario order by scenario;
rollback;
