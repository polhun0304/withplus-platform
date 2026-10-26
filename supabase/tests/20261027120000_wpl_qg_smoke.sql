-- =====================================================================
-- QG 키트 스모크 — 척추 + 엔진 10종 + 출시 훅 + 보안 불변식. 항상 rollback(운영 데이터 무변경).
--  픽스처는 어댑터 wpl_qga_smoke_fixture() 가 이 트랜잭션 안에서 만든다(관리자 2·외부인 1·(있으면) 구성원·테넌트 2).
--  결과: 단계마다 (step, ok, msg) 행 + 마지막 SUMMARY passed=N failed=M 행. failed=0 이어야 통과.
--  실행: node scripts/qg-verify.mjs --smoke   (또는 supabase db query --linked -f <이 파일>)
-- =====================================================================
begin;
create temp table r(n serial, step text, ok boolean, msg text);
grant all on r to authenticated, anon; grant usage, select on sequence r_n_seq to authenticated, anon;
create temp table fx(k text primary key, v text);
grant all on fx to authenticated, anon;
create function pg_temp.rej(p_step text, p_sql text, p_like text) returns void language plpgsql as $f$
begin
  begin execute p_sql; insert into r(step, ok, msg) values (p_step, false, 'no error');
  exception when others then insert into r(step, ok, msg) values (p_step, sqlerrm ilike p_like, left(sqlerrm, 300)); end;
end $f$;
create function pg_temp.chk(p_step text, p_sql text) returns void language plpgsql as $f$
declare v text;
begin
  begin execute p_sql into v; insert into r(step, ok, msg) values (p_step, v = 'true', 'got=' || coalesce(left(v, 300), 'null'));
  exception when others then insert into r(step, ok, msg) values (p_step, false, 'err: ' || left(sqlerrm, 300)); end;
end $f$;
create function pg_temp.put(p_k text, p_sql text) returns void language plpgsql as $f$
declare v text;
begin
  begin execute p_sql into v; insert into fx values (p_k, v) on conflict (k) do update set v = excluded.v;
  exception when others then insert into r(step, ok, msg) values ('put_' || p_k, false, 'err: ' || left(sqlerrm, 300)); end;
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
create function pg_temp.errmsg(p_sql text) returns text language plpgsql as $f$
begin begin execute p_sql; return 'no error'; exception when others then return sqlerrm; end; end $f$;
grant execute on all functions in schema pg_temp to authenticated, anon;

-- ───────── 픽스처 ─────────
insert into fx select key, value from jsonb_each_text(public.wpl_qga_smoke_fixture()) where value is not null;
select pg_temp.chk('fixture_ready', $q$select (pg_temp.v('admin1') is not null and pg_temp.v('admin2') is not null and pg_temp.v('outsider') is not null)::text$q$);
insert into fx values ('has_tenant', case when pg_temp.v('tenant') is not null and pg_temp.v('member') is not null then 'yes' else 'no' end);

-- 시험용 probe(되돌림)
create function public.wpl_qg_probe_zz_smoke(p_check public.wpl_qg_checks, p_tenant uuid) returns jsonb language plpgsql set search_path = public as $f$
begin
  if coalesce(current_setting('qg.smoke_fail', true), '') = 'on' then
    return jsonb_build_object('status', 'fail', 'severity', coalesce(nullif(current_setting('qg.smoke_sev', true), ''), 'high'),
      'fingerprint', coalesce(nullif(current_setting('qg.smoke_fp', true), ''), 'x'), 'title', '시험 결함', 'detail', jsonb_build_object('tenant', p_tenant));
  end if;
  return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('tenant', p_tenant));
end $f$;
create function public.wpl_qg_probe_zz_boom(p_check public.wpl_qg_checks, p_tenant uuid) returns jsonb language plpgsql set search_path = public as $f$
begin perform 1/0; return '{}'::jsonb; end $f$;
create function public.wpl_qg_probe_zz_badfmt(p_check public.wpl_qg_checks, p_tenant uuid) returns jsonb language sql set search_path = public as $f$
  select '[{"status":"maybe"}, 42]'::jsonb $f$;
create function public.wpl_qg_probe_zz_badsig(p text) returns jsonb language sql set search_path = public as $f$ select '{"status":"pass"}'::jsonb $f$;
revoke all on function public.wpl_qg_probe_zz_smoke(public.wpl_qg_checks, uuid), public.wpl_qg_probe_zz_boom(public.wpl_qg_checks, uuid),
  public.wpl_qg_probe_zz_badfmt(public.wpl_qg_checks, uuid), public.wpl_qg_probe_zz_badsig(text) from public, anon, authenticated;

-- ───────── A. 카탈로그 · 정책값 · cron · 계약 ─────────
select pg_temp.chk('A_engines_10', $q$select ((select count(*) from wpl_qg_engines where code in
   ('review','testing','adversarial','compliance','evidence','release','security','integrity','ai_model','evolution')) = 10)::text$q$);
select pg_temp.chk('A_engine_names_korean', $q$select (not exists (select 1 from wpl_qg_engines where name !~ '[가-힣]'))::text$q$);
select pg_temp.chk('A_every_engine_has_checks', $q$select (not exists (select 1 from wpl_qg_engines g where not exists
   (select 1 from wpl_qg_checks c where c.engine_code = g.code and c.active)))::text$q$);
select pg_temp.chk('A_all_db_probes_resolvable', $q$select (not exists (select 1 from wpl_qg_checks c where c.active and c.probe like 'wpl\_qg\_probe\_%'
   and not (public.wpl_qg_probe_resolve_internal(c.probe)->>'ok')::boolean))::text$q$);
select pg_temp.chk('A_settings_core', $q$select ((select count(*) from wpl_qg_settings where key in ('qg_cron_enabled','qg_issue_on_warn','qg_accept_risk_gate_severities',
   'qg_accept_note_min_len','qg_self_approval_when_sole_admin','qg_issue_sla_days','qg_server_attest_key_hash','qg_enforce_code_deploy','qg_enforce_policy_change')) = 9)::text$q$);
select pg_temp.chk('A_enforce_switches_boolean', $q$select (not exists (select 1 from wpl_qg_settings where key like 'qg\_enforce\_%' and jsonb_typeof(value) <> 'boolean'))::text$q$);
-- 시험 중에는 강제 스위치를 모두 끈 상태(설치 기본값)로 본다(rollback 이라 운영 설정은 그대로)
update wpl_qg_settings set value = 'false' where key like 'qg\_enforce\_%';
select pg_temp.chk('A_cron_registered_iff_pg_cron', $q$select (case when to_regclass('cron.job') is null then true
   else (xpath('/row/c/text()', query_to_xml('select count(*) as c from cron.job where jobname in (''wpl_qg_cron_hourly'',''wpl_qg_cron_daily'')', false, true, '')))[1]::text::int = 2 end)::text$q$);
select pg_temp.rej('A_probe_other_prefix_rejected', $q$insert into wpl_qg_checks(code, engine_code, name, probe) values ('evidence.zz_bad1', 'evidence', 'x', 'pg_sleep')$q$, '%probe_check%');
select pg_temp.rej('A_probe_sql_injection_rejected', $q$insert into wpl_qg_checks(code, engine_code, name, probe) values ('evidence.zz_bad2', 'evidence', 'x', 'wpl_qg_probe_x(); drop table wpl_qg_runs; --')$q$, '%probe_check%');
select pg_temp.rej('A_probe_path_traversal_rejected', $q$insert into wpl_qg_checks(code, engine_code, name, probe) values ('evidence.zz_bad3', 'evidence', 'x', 'suite:../../etc/passwd')$q$, '%probe_check%');
select pg_temp.chk('A_resolve_rejects_foreign', $q$select ((public.wpl_qg_probe_resolve_internal('pg_sleep')->>'reason') = 'probe_invalid_name'
   and (public.wpl_qg_probe_resolve_internal('wpl_qg_probe_evidence_chain')->>'ok')::boolean)::text$q$);
select pg_temp.rej('A_allowlist_todo_reason_rejected', $q$insert into wpl_qg_anon_allowlist(signature, reason) values ('zz_x()', 'TODO 나중에')$q$, '%check%');

insert into wpl_qg_checks(code, engine_code, name, probe, risk, scope, schedule, sort) values
  ('evidence.zz_smoke', 'evidence', '시험 결함 검사', 'wpl_qg_probe_zz_smoke', 'high', 'platform', 'manual', 900),
  ('evidence.zz_missing', 'evidence', '없는 함수', 'wpl_qg_probe_zz_does_not_exist', 'low', 'platform', 'manual', 901),
  ('evidence.zz_badsig', 'evidence', '시그니처 다름', 'wpl_qg_probe_zz_badsig', 'low', 'platform', 'manual', 902),
  ('evidence.zz_boom', 'evidence', '예외 내는 검사', 'wpl_qg_probe_zz_boom', 'low', 'platform', 'manual', 903),
  ('evidence.zz_badfmt', 'evidence', '형식 오류 검사', 'wpl_qg_probe_zz_badfmt', 'low', 'platform', 'manual', 904),
  ('evidence.zz_tenant', 'evidence', '테넌트 범위 시험 검사', 'wpl_qg_probe_zz_smoke', 'high', 'tenant', 'manual', 905);

-- ───────── B. 권한: 익명 · 외부인 ─────────
select pg_temp.as_anon();
select pg_temp.rej('B_anon_run', $q$select public.wpl_qg_run_engine('evidence')$q$, '%permission denied%');
select pg_temp.rej('B_anon_ingest', $q$select public.wpl_qg_ingest('{"engine":"evidence","results":[{"check_code":"evidence.zz_smoke","status":"pass"}]}'::jsonb, 'x')$q$, '%permission denied%');
select pg_temp.rej('B_anon_dashboard', $q$select public.wpl_qg_dashboard()$q$, '%permission denied%');
select pg_temp.rej('B_anon_setting_set', $q$select public.wpl_qg_setting_set('qg_cron_enabled', 'false'::jsonb)$q$, '%permission denied%');
select pg_temp.rej('B_anon_read_runs', $q$select count(*) from wpl_qg_runs$q$, '%permission denied%');
select pg_temp.rej('B_anon_read_evidence', $q$select count(*) from wpl_qg_evidence$q$, '%permission denied%');
select pg_temp.rej('B_anon_read_settings', $q$select count(*) from wpl_qg_settings$q$, '%permission denied%');
select pg_temp.as_user(pg_temp.v('outsider')::uuid);
select pg_temp.rej('B_outsider_run', $q$select public.wpl_qg_run_engine('evidence')$q$, '%관리자%');
select pg_temp.rej('B_outsider_dashboard', $q$select public.wpl_qg_dashboard()$q$, '%관리자%');
select pg_temp.rej('B_outsider_verify', $q$select public.wpl_qg_verify_evidence_chain()$q$, '%관리자%');
select pg_temp.rej('B_outsider_setting_set', $q$select public.wpl_qg_setting_set('qg_cron_enabled', 'false'::jsonb)$q$, '%관리자%');
select pg_temp.rej('B_outsider_ingest_forged_key', $q$select public.wpl_qg_ingest('{"engine":"evidence","results":[{"check_code":"evidence.zz_smoke","status":"pass"}]}'::jsonb, 'forged-key-0123456789')$q$, '%서버 증명키%');
select pg_temp.rej('B_outsider_insert_check', $q$insert into wpl_qg_checks(code, engine_code, name, probe) values ('evidence.zz_out', 'evidence', 'x', 'manual')$q$, '%row-level security%');
select pg_temp.chk('B_outsider_update_engine_0rows', $q$with u as (update wpl_qg_engines set enabled = false where code = 'evidence' returning 1) select (count(*) = 0)::text from u$q$);
select pg_temp.chk('B_outsider_settings_hidden', $q$select ((select count(*) from wpl_qg_settings) = 0)::text$q$);
select pg_temp.chk('B_outsider_catalog_hidden', $q$select ((select count(*) from wpl_qg_checks) = 0 and (select count(*) from wpl_qg_engines) = 0
   and (select count(*) from wpl_qg_reviewers) = 0)::text$q$);
select pg_temp.rej('B_outsider_insert_evidence', $q$insert into wpl_qg_evidence(kind, ref, payload, payload_sha256, prev_hash, hash) values ('document','x','{}', repeat('0',64), 'GENESIS', repeat('0',64))$q$, '%permission denied%');
select pg_temp.rej('B_outsider_call_internal', $q$select public.wpl_qg_run_engine_internal('evidence', null, 'manual', null, null, '{}'::jsonb)$q$, '%permission denied%');
select pg_temp.rej('B_outsider_call_probe', $q$select public.wpl_qg_probe_evidence_chain(null, null)$q$, '%permission denied%');
select pg_temp.rej('B_outsider_call_adapter', $q$select public.wpl_qga_admin_count_except(null)$q$, '%permission denied%');
select pg_temp.rej('B_outsider_allowlist_hidden', $q$select 1/(count(*))::int from wpl_qg_anon_allowlist$q$, '%division by zero%');
select pg_temp.rej('B_outsider_call_info', $q$select public.wpl_qga_info()$q$, '%permission denied%');
select pg_temp.chk('B_outsider_is_admin_false', $q$select (not public.wpl_qga_is_admin())::text$q$);

-- ───────── C. 관리자 실행 · 실행기 방어 ─────────
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.chk('C_admin_is_admin', $q$select public.wpl_qga_is_admin()::text$q$);
select pg_temp.put('run1', $q$select public.wpl_qg_run_engine('evidence')::text$q$);
select pg_temp.chk('C_run_recorded', $q$select (select engine_code = 'evidence' and trigger = 'manual' and evidence_id is not null and actor = pg_temp.v('admin1')::uuid
   from wpl_qg_runs where id = pg_temp.v('run1')::uuid)::text$q$);
select pg_temp.chk('C_spine_probes', $q$select ((select count(*) from wpl_qg_findings where run_id = pg_temp.v('run1')::uuid and status = 'pass'
   and check_code in ('evidence.chain_intact','evidence.run_has_evidence','evidence.zz_smoke')) = 3
   and (select status from wpl_qg_findings where run_id = pg_temp.v('run1')::uuid and check_code = 'evidence.audit_chain') in ('pass','skipped'))::text$q$);
select pg_temp.chk('C_missing_probe_error', $q$select (select status = 'error' and detail->>'reason' = 'probe_missing' from wpl_qg_findings where run_id = pg_temp.v('run1')::uuid and check_code = 'evidence.zz_missing')::text$q$);
select pg_temp.chk('C_badsig_probe_error', $q$select (select status = 'error' and detail->>'reason' = 'probe_bad_signature' from wpl_qg_findings where run_id = pg_temp.v('run1')::uuid and check_code = 'evidence.zz_badsig')::text$q$);
select pg_temp.chk('C_exception_probe_error', $q$select (select status = 'error' and detail->>'reason' = 'probe_exception' from wpl_qg_findings where run_id = pg_temp.v('run1')::uuid and check_code = 'evidence.zz_boom')::text$q$);
select pg_temp.chk('C_badfmt_two_errors', $q$select ((select count(*) from wpl_qg_findings where run_id = pg_temp.v('run1')::uuid and check_code = 'evidence.zz_badfmt' and status = 'error') = 2)::text$q$);
select pg_temp.chk('C_run_status_error', $q$select ((select status from wpl_qg_runs where id = pg_temp.v('run1')::uuid) = 'error')::text$q$);
select pg_temp.chk('C_findings_share_evidence', $q$select (not exists (select 1 from wpl_qg_findings f join wpl_qg_runs r on r.id = f.run_id where r.id = pg_temp.v('run1')::uuid and f.evidence_id is distinct from r.evidence_id))::text$q$);
select pg_temp.chk('C_dashboard_reads', $q$select ((public.wpl_qg_dashboard()->'totals'->>'evidence_count')::int >= 1 and jsonb_array_length(public.wpl_qg_dashboard()->'engines') = 10)::text$q$);
select pg_temp.chk('C_dashboard_four_eyes', $q$select ((public.wpl_qg_dashboard()->>'other_admins')::int >= 1 and public.wpl_qg_dashboard() ? 'sole_admin_self_approval')::text$q$);
select pg_temp.as_pg();
select pg_temp.chk('C_josa', $q$select (public.wpl_qg_josa_internal('광고 게재', '을/를') = '광고 게재를' and public.wpl_qg_josa_internal('정책값 변경', '을/를') = '정책값 변경을'
   and public.wpl_qg_josa_internal('출시', '이/가') = '출시가' and public.wpl_qg_josa_internal('서울', '으로/로') = '서울로')::text$q$);
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.chk('C_adapter_info', $q$select ((public.wpl_qg_adapter_info()->>'contract')::int = 1 and public.wpl_qg_adapter_info() ? 'server_key')::text$q$);
select pg_temp.chk('C_admin_reads_settings', $q$select ((select count(*) from wpl_qg_settings) >= 9)::text$q$);
select pg_temp.rej('C_unknown_engine', $q$select public.wpl_qg_run_engine('nope')$q$, '%알 수 없는 엔진%');

-- 결함 → 이슈
select set_config('qg.smoke_fail', 'on', true);
select set_config('qg.smoke_fp', 'x', true);
select pg_temp.put('run2', $q$select public.wpl_qg_run_engine('evidence')::text$q$);
select pg_temp.put('iss', $q$select id::text from wpl_qg_issues where check_code = 'evidence.zz_smoke' and fingerprint like '%|x'$q$);
select pg_temp.chk('C_issue_opened', $q$select (select status = 'open' and severity = 'high' and due_at > now() from wpl_qg_issues where id = pg_temp.v('iss')::uuid)::text$q$);
select pg_temp.chk('C_issue_event_open', $q$select exists (select 1 from wpl_qg_issue_events where issue_id = pg_temp.v('iss')::uuid and action = 'open')::text$q$);

-- ───────── D. 이슈 상태 머신 · 위험 수용 4-eyes ─────────
select pg_temp.rej('D_invalid_transition', $q$select public.wpl_qg_issue_transition(pg_temp.v('iss')::uuid, 'verified', null)$q$, '%바꿀 수 없습니다%');
select pg_temp.rej('D_accept_needs_reason', $q$select public.wpl_qg_issue_transition(pg_temp.v('iss')::uuid, 'accepted_risk', '짧음')$q$, '%사유%');
select pg_temp.chk('D_accept_high_needs_approval', $q$select ((public.wpl_qg_issue_transition(pg_temp.v('iss')::uuid, 'accepted_risk', '시험 환경에서만 생기는 결과라 운영 영향 없음')->>'pending')::boolean)::text$q$);
select pg_temp.put('appr', $q$select id::text from wpl_qg_risk_approvals where issue_id = pg_temp.v('iss')::uuid and status = 'pending'$q$);
select pg_temp.rej('D_transition_while_pending', $q$select public.wpl_qg_issue_transition(pg_temp.v('iss')::uuid, 'fixed', null)$q$, '%대기%');
select pg_temp.rej('D_self_approval_rejected', $q$select public.wpl_qg_issue_decide(pg_temp.v('appr')::uuid, 'approved', '내가 승인')$q$, '%스스로%');
select pg_temp.as_user(pg_temp.v('admin2')::uuid);
select pg_temp.rej('D_other_cannot_cancel', $q$select public.wpl_qg_issue_decide(pg_temp.v('appr')::uuid, 'cancelled', null)$q$, '%요청한 사람%');
select pg_temp.chk('D_other_admin_approves', $q$select ((public.wpl_qg_issue_decide(pg_temp.v('appr')::uuid, 'approved', '확인했습니다')->>'status') = 'accepted_risk')::text$q$);
select pg_temp.chk('D_decision_evidence', $q$select exists (select 1 from wpl_qg_evidence where kind = 'issue_decision' and ref = 'issue:' || pg_temp.v('iss'))::text$q$);
select pg_temp.as_user(pg_temp.v('outsider')::uuid);
select pg_temp.rej('D_outsider_transition', $q$select public.wpl_qg_issue_transition(pg_temp.v('iss')::uuid, 'open', null)$q$, '%관리자%');
select pg_temp.as_pg();
select pg_temp.rej('D_direct_issue_update_blocked', $q$update wpl_qg_issues set status = 'verified' where id = pg_temp.v('iss')::uuid$q$, '%절차%');
select pg_temp.rej('D_issue_delete_blocked', $q$delete from wpl_qg_issues where id = pg_temp.v('iss')::uuid$q$, '%지울 수 없습니다%');

-- 회귀: 고침 → 통과하면 자동 확인 → 다시 실패하면 다시 열림
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select set_config('qg.smoke_fp', 'y', true);
select pg_temp.put('run3', $q$select public.wpl_qg_run_engine('evidence')::text$q$);
select pg_temp.put('iss2', $q$select id::text from wpl_qg_issues where check_code = 'evidence.zz_smoke' and fingerprint like '%|y'$q$);
select pg_temp.chk('D_mark_fixed', $q$select ((public.wpl_qg_issue_transition(pg_temp.v('iss2')::uuid, 'fixed', '원인 수정')->>'status') = 'fixed')::text$q$);
select set_config('qg.smoke_fail', '', true);
select pg_temp.put('run4', $q$select public.wpl_qg_run_engine('evidence')::text$q$);
select pg_temp.chk('D_auto_verified', $q$select ((select status from wpl_qg_issues where id = pg_temp.v('iss2')::uuid) = 'verified')::text$q$);
select set_config('qg.smoke_fail', 'on', true);
select pg_temp.put('run5', $q$select public.wpl_qg_run_engine('evidence')::text$q$);
select pg_temp.chk('D_regression_reopened', $q$select ((select status from wpl_qg_issues where id = pg_temp.v('iss2')::uuid) = 'open'
   and exists (select 1 from wpl_qg_issue_events where issue_id = pg_temp.v('iss2')::uuid and action = 'reopen'))::text$q$);
select set_config('qg.smoke_fail', '', true);
-- v1.1: 열린 이슈가 다음 실행에서 통과하면 확인 대기(고침)로 자동 전환 → 일괄 해결 확인
select pg_temp.put('run6', $q$select public.wpl_qg_run_engine('evidence')::text$q$);
select pg_temp.chk('D_auto_fixed_on_pass', $q$select ((select status = 'fixed' and last_pass_at is not null from wpl_qg_issues where id = pg_temp.v('iss2')::uuid)
   and exists (select 1 from wpl_qg_issue_events where issue_id = pg_temp.v('iss2')::uuid and action = 'auto_verify' and from_status = 'open' and to_status = 'fixed'))::text$q$);
select pg_temp.chk('D_dashboard_fixed_passed', $q$select ((public.wpl_qg_dashboard()->'totals'->>'fixed_passed')::int >= 1)::text$q$);
select pg_temp.rej('D_bulk_accept_rejected', $q$select public.wpl_qg_issue_bulk_transition(array[pg_temp.v('iss2')::uuid], 'accepted_risk', '한꺼번에 위험 수용 시도')$q$, '%한 건씩%');
select pg_temp.chk('D_bulk_verify', $q$select ((public.wpl_qg_issue_bulk_transition(null, 'verified', '최신 실행 통과 확인')->>'changed')::int >= 1)::text$q$);
select pg_temp.chk('D_bulk_verified_status', $q$select ((select status from wpl_qg_issues where id = pg_temp.v('iss2')::uuid) = 'verified')::text$q$);
select pg_temp.as_user(pg_temp.v('outsider')::uuid);
select pg_temp.rej('D_outsider_bulk', $q$select public.wpl_qg_issue_bulk_transition(null, 'verified', null)$q$, '%관리자%');
select pg_temp.as_pg();
update wpl_qg_settings set value = 'false' where key = 'qg_issue_auto_fix_on_pass';
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select set_config('qg.smoke_fail', 'on', true);
select pg_temp.put('run7', $q$select public.wpl_qg_run_engine('evidence')::text$q$);
select set_config('qg.smoke_fail', '', true);
select pg_temp.put('run8', $q$select public.wpl_qg_run_engine('evidence')::text$q$);
select pg_temp.chk('D_auto_fix_off_stays_open', $q$select ((select status = 'open' and last_pass_at is not null from wpl_qg_issues where id = pg_temp.v('iss2')::uuid))::text$q$);
select pg_temp.as_pg();
update wpl_qg_settings set value = 'true' where key = 'qg_issue_auto_fix_on_pass';
select pg_temp.as_user(pg_temp.v('admin1')::uuid);

-- ───────── E. 증거 원장 ─────────
select pg_temp.chk('E_chain_ok', $q$select ((public.wpl_qg_verify_evidence_chain()->>'ok')::boolean)::text$q$);
select pg_temp.as_pg();
select pg_temp.chk('E_tamper_payload_detected', $q$select ((public.wpl_qg_evidence_verify_rows_internal(
   (select jsonb_agg(case when (e->>'seq')::int = 1 then jsonb_set(e, '{payload}', '{"forged":true}') else e end) from jsonb_array_elements(public.wpl_qg_evidence_rows_internal()) e))->>'reason') = 'payload')::text$q$);
select pg_temp.chk('E_tamper_hash_detected', $q$select ((public.wpl_qg_evidence_verify_rows_internal(
   (select jsonb_agg(case when (e->>'seq')::int = 1 then jsonb_set(e, '{ref}', '"forged"') else e end) from jsonb_array_elements(public.wpl_qg_evidence_rows_internal()) e))->>'reason') = 'hash')::text$q$);
select pg_temp.chk('E_gap_detected', $q$select ((public.wpl_qg_evidence_verify_rows_internal(
   (select jsonb_agg(e) from jsonb_array_elements(public.wpl_qg_evidence_rows_internal()) e where (e->>'seq')::int <> 2))->>'reason') = 'gap')::text$q$);
select pg_temp.chk('E_mixed_v1_v2_chain', $q$with a as (select public.wpl_qg_evidence_hash_internal('GENESIS', 'document', 'r1', repeat('a', 64), '2026-10-01 00:00:00+00') h1),
   b as (select h1, public.wpl_qg_evidence_hash2_internal(h1, 'document', 'r2', repeat('b', 64), '2026-10-02 00:00:00+00', '제목', null, null, null) h2 from a)
   select ((public.wpl_qg_evidence_verify_rows_internal(jsonb_build_array(
     jsonb_build_object('id', 'x1', 'seq', 1, 'kind', 'document', 'ref', 'r1', 'payload_sha256', repeat('a', 64), 'prev_hash', 'GENESIS', 'hash', h1, 'created_at', '2026-10-01 00:00:00+00', 'title', '바뀐 제목도 v1 은 해시 밖'),
     jsonb_build_object('id', 'x2', 'seq', 2, 'kind', 'document', 'ref', 'r2', 'payload_sha256', repeat('b', 64), 'prev_hash', h1, 'hash', h2, 'created_at', '2026-10-02 00:00:00+00', 'hash_v', 2, 'title', '제목')))->>'ok')::boolean)::text from b$q$);
select pg_temp.chk('E_new_rows_hash_v2', $q$select ((select hash_v from wpl_qg_evidence order by seq desc limit 1) = 2)::text$q$);
select pg_temp.chk('E_tamper_title_detected', $q$select ((public.wpl_qg_evidence_verify_rows_internal(
   (select jsonb_agg(case when (e->>'seq')::bigint = (select max(seq) from wpl_qg_evidence) then jsonb_set(e, '{title}', '"바꾼 제목"') else e end)
      from jsonb_array_elements(public.wpl_qg_evidence_rows_internal()) e))->>'reason') = 'hash')::text$q$);
select pg_temp.chk('E_tamper_tenant_detected', $q$select ((public.wpl_qg_evidence_verify_rows_internal(
   (select jsonb_agg(case when (e->>'seq')::bigint = (select max(seq) from wpl_qg_evidence) then jsonb_set(e, '{tenant_id}', to_jsonb(gen_random_uuid()::text)) else e end)
      from jsonb_array_elements(public.wpl_qg_evidence_rows_internal()) e))->>'reason') = 'hash')::text$q$);
select pg_temp.chk('E_admin_log_append_only', $q$select (to_regclass('public.wpl_qg_admin_log') is null or (
   pg_temp.errmsg('select public.wpl_qga_audit(null, ''system'', ''qg.smoke'', ''x'', ''y'', ''{}''::jsonb)') = 'no error'
   and pg_temp.errmsg('update public.wpl_qg_admin_log set title = ''x'' where id = (select max(id) from public.wpl_qg_admin_log)') like '%추가만%'
   and pg_temp.errmsg('delete from public.wpl_qg_admin_log where id = (select max(id) from public.wpl_qg_admin_log)') like '%추가만%'))::text$q$);
select pg_temp.rej('E_evidence_update_blocked', $q$update wpl_qg_evidence set title = 'x' where seq = 1$q$, '%추가만%');
select pg_temp.rej('E_evidence_delete_blocked', $q$delete from wpl_qg_evidence where seq = 1$q$, '%추가만%');
select pg_temp.rej('E_runs_update_blocked', $q$update wpl_qg_runs set status = 'passed' where id = pg_temp.v('run1')::uuid$q$, '%추가만%');
select pg_temp.rej('E_findings_delete_blocked', $q$delete from wpl_qg_findings where run_id = pg_temp.v('run1')::uuid$q$, '%추가만%');
select pg_temp.rej('E_evidence_truncate_blocked', $q$truncate wpl_qg_evidence cascade$q$, '%추가만%');
select pg_temp.put('ev_doc', $q$select public.wpl_qg_evidence_append('document', 'zz', '{"a":1}'::jsonb)::text$q$);
select pg_temp.chk('E_db_sets_chain_fields', $q$select (select prev_hash <> '' and hash ~ '^[0-9a-f]{64}$' and seq = (select max(seq) from wpl_qg_evidence)
   from wpl_qg_evidence where id = pg_temp.v('ev_doc')::uuid)::text$q$);

-- ───────── F. 외부 결과 올리기 ─────────
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.chk('F_admin_ingest', $q$select ((public.wpl_qg_ingest('{"engine":"testing","trigger":"ci","context":{"git_sha":"abc"},"results":[{"check_code":"testing.suite_qg_smoke","status":"pass","fingerprint":"suite"}]}'::jsonb, null)->>'ok')::boolean)::text$q$);
select pg_temp.rej('F_unknown_check', $q$select public.wpl_qg_ingest('{"engine":"testing","results":[{"check_code":"security.anon_definer","status":"pass"}]}'::jsonb, null)$q$, '%없는 검사%');
select pg_temp.rej('F_bad_trigger', $q$select public.wpl_qg_ingest('{"engine":"testing","trigger":"cron","results":[{"check_code":"testing.suite_qg_smoke","status":"pass"}]}'::jsonb, null)$q$, '%trigger%');
select pg_temp.rej('F_big_context', $q$select public.wpl_qg_ingest(jsonb_build_object('engine','testing','context', jsonb_build_object('x', repeat('a', 9000)),'results', '[{"check_code":"testing.suite_qg_smoke","status":"pass"}]'::jsonb), null)$q$, '%너무 큽니다%');
select pg_temp.as_pg();
update wpl_qg_settings set value = '2' where key = 'qg_ingest_max_results';
update wpl_qg_settings set value = to_jsonb(encode(sha256(convert_to('smoke-key-0123456789abcdef', 'UTF8')), 'hex')) where key = 'qg_server_attest_key_hash';
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.rej('F_too_many', $q$select public.wpl_qg_ingest('{"engine":"testing","results":[{"check_code":"testing.suite_qg_smoke","status":"pass"},{"check_code":"testing.suite_qg_smoke","status":"pass"},{"check_code":"testing.suite_qg_smoke","status":"pass"}]}'::jsonb, null)$q$, '%너무 많습니다%');
select pg_temp.as_user(pg_temp.v('outsider')::uuid);
select pg_temp.chk('F_server_key_ok', $q$select ((public.wpl_qg_ingest('{"engine":"testing","results":[{"check_code":"testing.suite_qg_smoke","status":"pass"}]}'::jsonb, 'smoke-key-0123456789abcdef')->>'ok')::boolean)::text$q$);
select pg_temp.rej('F_server_key_wrong', $q$select public.wpl_qg_ingest('{"engine":"testing","results":[{"check_code":"testing.suite_qg_smoke","status":"pass"}]}'::jsonb, 'smoke-key-0123456789abcdeX')$q$, '%서버 증명키%');
select pg_temp.as_anon();
select pg_temp.rej('F_anon_with_key_denied', $q$select public.wpl_qg_ingest('{"engine":"testing","results":[{"check_code":"testing.suite_qg_smoke","status":"pass"}]}'::jsonb, 'smoke-key-0123456789abcdef')$q$, '%permission denied%');
select pg_temp.as_pg();
update wpl_qg_settings set value = '2000' where key = 'qg_ingest_max_results';

-- ───────── G. 보안 엔진(심은 결함을 잡는가) ─────────
create function public.zz_qg_smoke_anon() returns int language sql security definer as $f$ select 1 $f$;
grant execute on function public.zz_qg_smoke_anon() to anon;
create table public.zz_qg_smoke_open(id int);
alter table public.zz_qg_smoke_open disable row level security;   -- RLS 를 자동으로 켜는 플랫폼(이벤트 트리거)도 있어 명시적으로 끈다
grant select on public.zz_qg_smoke_open to anon, authenticated;
create function public.zz_qg_smoke_internal() returns int language sql security definer set search_path = public as $f$ select 1 $f$;
grant execute on function public.zz_qg_smoke_internal() to authenticated;
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.put('sec', $q$select public.wpl_qg_run_engine('security')::text$q$);
select pg_temp.chk('G_anon_definer_caught', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('sec')::uuid and check_code = 'security.anon_definer'
   and status = 'fail' and severity = 'critical' and fingerprint like '%zz_qg_smoke_anon()')::text$q$);
select pg_temp.chk('G_rls_disabled_caught', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('sec')::uuid and check_code = 'security.rls_disabled'
   and status = 'fail' and fingerprint like '%table:zz_qg_smoke_open')::text$q$);
select pg_temp.chk('G_search_path_caught', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('sec')::uuid and check_code = 'security.definer_search_path'
   and status = 'fail' and fingerprint like '%zz_qg_smoke_anon()')::text$q$);
select pg_temp.chk('G_internal_exec_caught', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('sec')::uuid and check_code = 'security.internal_exec'
   and status = 'fail' and fingerprint like '%zz_qg_smoke_internal()')::text$q$);
select pg_temp.chk('G_qg_itself_clean', $q$select (not exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('sec')::uuid and status in ('fail','error')
   and (fingerprint like '%\_\_P\_\_\_qg%' escape '\' or fingerprint like '%wpl_qg\_%' or fingerprint like '%wpl_qga\_%')))::text$q$);
select pg_temp.chk('G_issue_has_remediation', $q$select exists (select 1 from wpl_qg_issues i join wpl_qg_checks c on c.code = i.check_code
   where i.check_code = 'security.anon_definer' and i.status = 'open' and c.remediation like '%revoke%')::text$q$);
-- 공유 DB 범위(include_prefixes): 다른 제품 함수는 빼고 QG 자신은 계속 본다
select pg_temp.as_pg();
update wpl_qg_checks set params = params || '{"include_prefixes":["zzz_other_product_"]}'::jsonb where code in ('security.anon_definer','security.definer_search_path');
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.put('sec2', $q$select public.wpl_qg_run_engine('security')::text$q$);
select pg_temp.chk('G_scope_excludes_other_product', $q$select (not exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('sec2')::uuid
   and check_code in ('security.anon_definer','security.definer_search_path') and fingerprint like '%zz_qg_smoke_anon()'))::text$q$);
select pg_temp.as_pg();
select pg_temp.chk('G_scope_ok_helper', $q$select (public.wpl_qg_scope_ok_internal('wpl_qg_x', '{"include_prefixes":["nope_"]}')
   and not public.wpl_qg_scope_ok_internal('ekos_x', '{"include_prefixes":["gos_"]}') and public.wpl_qg_scope_ok_internal('gos_x', '{"include_prefixes":["gos_"]}')
   and not public.wpl_qg_scope_ok_internal('gos_x', '{"exclude_prefixes":["gos_"]}') and public.wpl_qg_scope_ok_internal('any_x', '{}'))::text$q$);
update wpl_qg_checks set params = params - 'include_prefixes' where code in ('security.anon_definer','security.definer_search_path');

-- ───────── H. 정합성 엔진(일반 probe) ─────────
select pg_temp.as_pg();
create table public.zz_qg_ledger(id int primary key, amount int);
alter table public.zz_qg_ledger enable row level security;
create table public.zz_qg_parent(id uuid primary key, tenant_id uuid);
create table public.zz_qg_child(id uuid primary key, tenant_id uuid, parent_id uuid references public.zz_qg_parent(id), soft_ref uuid);
alter table public.zz_qg_parent enable row level security; alter table public.zz_qg_child enable row level security;
insert into public.zz_qg_parent values ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000000a');
insert into public.zz_qg_child values ('00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-0000000000a1', gen_random_uuid());
update wpl_qg_checks set params = jsonb_set(params, '{tables}', (params->'tables') || '["zz_qg_ledger"]'::jsonb) where code = 'integrity.append_only_guards';
update wpl_qg_checks set params = params || jsonb_build_object('table_prefixes', '["zz_qg_"]'::jsonb) where code = 'integrity.cross_tenant_fk';
update wpl_qg_checks set params = params || jsonb_build_object('soft_refs', '[{"table":"zz_qg_child","column":"soft_ref","ref":"zz_qg_parent"}]'::jsonb) where code = 'integrity.orphans';
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.put('int', $q$select public.wpl_qg_run_engine('integrity')::text$q$);
select pg_temp.chk('H_append_only_missing_guard_caught', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('int')::uuid and check_code = 'integrity.append_only_guards'
   and status = 'fail' and fingerprint like '%table:zz_qg_ledger')::text$q$);
select pg_temp.chk('H_qg_tables_guarded', $q$select (not exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('int')::uuid and check_code = 'integrity.append_only_guards'
   and status = 'fail' and fingerprint like '%table:wpl_qg%'))::text$q$);
select pg_temp.chk('H_cross_tenant_caught', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('int')::uuid and check_code = 'integrity.cross_tenant_fk'
   and status = 'fail' and fingerprint like '%zz_qg_child.parent_id')::text$q$);
select pg_temp.chk('H_orphan_caught', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('int')::uuid and check_code = 'integrity.orphans'
   and status = 'fail' and fingerprint like '%ref:zz_qg_child.soft_ref')::text$q$);
select pg_temp.as_pg();
update wpl_qg_checks set params = params || '{"allowed_fks":{"zz_qg_child.parent_id":"수요 조직과 처리 조직이 다른 협업 참조(시험)"}}'::jsonb where code = 'integrity.cross_tenant_fk';
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.put('int_allow', $q$select public.wpl_qg_run_engine('integrity')::text$q$);
select pg_temp.chk('H_allowed_fk_not_failed', $q$select (select status = 'pass' and jsonb_array_length(detail->'allowed_cross') = 1 from wpl_qg_findings
   where run_id = pg_temp.v('int_allow')::uuid and check_code = 'integrity.cross_tenant_fk')::text$q$);
select pg_temp.as_pg();
update wpl_qg_checks set params = params - 'allowed_fks' where code = 'integrity.cross_tenant_fk';
select pg_temp.as_pg();
create trigger zz_qg_ledger_guard before update or delete on public.zz_qg_ledger for each row execute function public.wpl_qg_forbid_mutation();
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.put('int2', $q$select public.wpl_qg_run_engine('integrity')::text$q$);
select pg_temp.chk('H_guard_added_passes', $q$select (not exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('int2')::uuid and check_code = 'integrity.append_only_guards'
   and status = 'fail' and fingerprint like '%table:zz_qg_ledger'))::text$q$);

-- ───────── I. 테스트 엔진 ─────────
select pg_temp.as_pg();
insert into wpl_qg_risk_items(code, name, target_kind, target_ref, impact, likelihood) values ('zz_money', '시험 돈 계산', 'rpc', 'zz_pay', 5, 4);
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.put('tst', $q$select public.wpl_qg_run_engine('testing')::text$q$);
select pg_temp.chk('I_coverage_gap_caught', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('tst')::uuid and check_code = 'testing.coverage_gap'
   and status = 'fail' and severity = 'critical' and fingerprint like '%item:zz_money')::text$q$);
select pg_temp.chk('I_last_failed_ran', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('tst')::uuid and check_code = 'testing.last_failed' and status in ('pass','fail'))::text$q$);
select pg_temp.as_pg();
select pg_temp.chk('I_grade', $q$select (public.wpl_qg_risk_grade_internal(5, 4) = 'critical' and public.wpl_qg_risk_grade_internal(2, 2) = 'low')::text$q$);
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.rej('I_suite_guard', $q$insert into wpl_qg_test_suites(code, name, kind, path, depths, check_code) values ('zz_s', 'x', 'sql', 'supabase/tests/x.sql', '["bogus"]', 'testing.suite_qg_smoke')$q$, '%깊이%');

-- ───────── J. 공격·장애 시뮬레이션 엔진 ─────────
select pg_temp.chk('J_scenarios_linked', $q$select ((select count(*) from wpl_qg_scenarios s join wpl_qg_checks c on c.code = s.check_code and c.probe = 'scenario:' || s.code where s.active) >= 6)::text$q$);
select pg_temp.put('adv', $q$select public.wpl_qg_run_engine('adversarial')::text$q$);
select pg_temp.chk('J_freshness_ran', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('adv')::uuid and check_code = 'adversarial.freshness' and status in ('pass','warn'))::text$q$);
select pg_temp.chk('J_ingest_scenario', $q$select ((public.wpl_qg_ingest('{"engine":"adversarial","results":[{"check_code":"adversarial.qg_anon_rpc","status":"pass","fingerprint":"scenario"}]}'::jsonb, null)->>'ok')::boolean)::text$q$);

-- ───────── K. 다중 독립 검토 ─────────
select pg_temp.put('rv1', $q$select (public.wpl_qg_review_request('document', null, '가입하면 월 매출 500만원을 보장합니다. 담당자 주민번호 900101-1234567', '광고 시안', null, false)->>'review_id')$q$);
select pg_temp.chk('K_reviewers_assigned', $q$select ((select cardinality(reviewers) from wpl_qg_reviews where id = pg_temp.v('rv1')::uuid) = 6)::text$q$);
select pg_temp.chk('K_submit_all_rules', $q$select (select bool_and((public.wpl_qg_review_submit(pg_temp.v('rv1')::uuid, c, null)->>'ok')::boolean)
   from unnest((select reviewers from wpl_qg_reviews where id = pg_temp.v('rv1')::uuid)) c)::text$q$);
select pg_temp.rej('K_double_submit', $q$select public.wpl_qg_review_submit(pg_temp.v('rv1')::uuid, 'privacy', null)$q$, '%이미 판정%');
select pg_temp.rej('K_fake_ai_run', $q$select public.wpl_qg_review_submit((public.wpl_qg_review_request('document', null, '안녕하세요', 't', null, true)->>'review_id')::uuid, 'ux',
   '{"verdict":"approve","run_id":"00000000-0000-0000-0000-000000000000"}'::jsonb)$q$, '%실행 기록%');
select pg_temp.chk('K_blocked_by_veto', $q$select ((public.wpl_qg_review_finalize(pg_temp.v('rv1')::uuid)->>'outcome') = 'blocked')::text$q$);
select pg_temp.chk('K_privacy_rejected', $q$select ((select verdict from wpl_qg_review_verdicts where review_id = pg_temp.v('rv1')::uuid and reviewer_code = 'privacy') = 'reject')::text$q$);
select pg_temp.chk('K_pii_not_stored_in_reasons', $q$select (not exists (select 1 from wpl_qg_review_verdicts where review_id = pg_temp.v('rv1')::uuid and reasons::text like '%1234567%'))::text$q$);
select pg_temp.rej('K_self_unblock_rejected', $q$select public.wpl_qg_review_confirm(pg_temp.v('rv1')::uuid, 'approved', '시험용 문서라 통과시킵니다(사유)')$q$, '%스스로%');
select pg_temp.as_user(pg_temp.v('admin2')::uuid);
select pg_temp.rej('K_unblock_needs_reason', $q$select public.wpl_qg_review_confirm(pg_temp.v('rv1')::uuid, 'approved', '짧음')$q$, '%사유%');
select pg_temp.chk('K_other_admin_confirms', $q$select ((public.wpl_qg_review_confirm(pg_temp.v('rv1')::uuid, 'rejected', '개인정보 포함으로 반려')->>'ok')::boolean)::text$q$);
select pg_temp.put('rv2', $q$select (public.wpl_qg_review_request('document', null, '안녕하세요. 서비스 이용 안내입니다. 궁금한 점은 고객센터로 문의해 주세요.', '안내문', null, false)->>'review_id')$q$);
select pg_temp.chk('K_clean_submits', $q$select (select bool_and((public.wpl_qg_review_submit(pg_temp.v('rv2')::uuid, c, null)->>'ok')::boolean) from unnest((select reviewers from wpl_qg_reviews where id = pg_temp.v('rv2')::uuid)) c)::text$q$);
select pg_temp.chk('K_clean_passes', $q$select ((public.wpl_qg_review_finalize(pg_temp.v('rv2')::uuid)->>'outcome') = 'passed')::text$q$);
select pg_temp.chk('K_candidates_list', $q$select (jsonb_typeof(public.wpl_qg_review_candidates(null, 50)) = 'array')::text$q$);
select pg_temp.as_user(pg_temp.v('outsider')::uuid);
select pg_temp.rej('K_outsider_request_denied', $q$select public.wpl_qg_review_request('document', null, '안녕', 't', null, false)$q$, '%권한%');
select pg_temp.rej('K_outsider_candidates_denied', $q$select public.wpl_qg_review_candidates(null, 50)$q$, '%관리자%');
select pg_temp.as_pg();
select pg_temp.rej('K_review_snapshot_immutable', $q$update wpl_qg_reviews set snapshot_text = 'x' where id = pg_temp.v('rv2')::uuid$q$, '%절차%');

-- ───────── L. 법령·정책 변경 분석 ─────────
insert into wpl_qg_compliance_targets(kind, code, name, description, tenants) values ('policy', 'zz_marketing', '광고성 문자 수신 동의 정책', '야간 발송 제한', 3);
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.chk('L_impact_preview', $q$select ((public.wpl_qg_regulation_impact('network_act', '광고성 정보 전송 기준 변경')->>'target_count')::int >= 1)::text$q$);
select pg_temp.put('chg', $q$select (public.wpl_qg_regulation_change_add('network_act', '광고성 정보 야간 전송 기준이 바뀜', current_date + 10, '광고성 정보는 야간 전송 시 별도 동의', null, null, null)->>'change_id')$q$);
select pg_temp.chk('L_followup_issue', $q$select exists (select 1 from wpl_qg_issues where check_code = 'compliance.change_followup' and fingerprint like '%change:' || pg_temp.v('chg') || ':policy' and severity = 'high')::text$q$);
select pg_temp.chk('L_change_evidence', $q$select exists (select 1 from wpl_qg_evidence where kind = 'regulation_change' and ref = 'regulation:network_act')::text$q$);
select pg_temp.put('cmp', $q$select public.wpl_qg_run_engine('compliance')::text$q$);
select pg_temp.chk('L_review_overdue_ran', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('cmp')::uuid and check_code = 'compliance.review_overdue' and status in ('pass','warn','fail'))::text$q$);
select pg_temp.chk('L_effective_soon', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('cmp')::uuid and check_code = 'compliance.effective_soon' and status = 'warn')::text$q$);
select pg_temp.chk('L_mark_reviewed', $q$select ((public.wpl_qg_regulation_mark_reviewed('network_act', null)->>'ok')::boolean)::text$q$);
select pg_temp.as_pg();
select pg_temp.rej('L_changes_append_only', $q$update wpl_qg_regulation_changes set summary = 'xxxxx' where id = pg_temp.v('chg')::uuid$q$, '%추가만%');

-- ───────── M. AI 모델 평가·승인 ─────────
select pg_temp.as_pg();
select set_config('wpl.qg_write', 'on', true);
update wpl_qg_ai_model_approvals set status = 'candidate', pending_to = null, pending_by = null, pending_at = null, pending_note = null
 where model_code = 'default_ai' and task_code = 'qg_review';
select set_config('wpl.qg_write', '', true);
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.rej('M_approve_needs_eval', $q$select public.wpl_qg_ai_model_set_status('default_ai', 'qg_review', 'approved', '평가 없이 승인 시도')$q$, '%평가%');
select pg_temp.chk('M_rules_eval_pass', $q$select ((public.wpl_qg_ai_eval_record('review_legal_json', 'rules', 'ran', null, null, null, null, null)->>'status') = 'pass')::text$q$);
select pg_temp.put('call', $q$select public.wpl_qg_ai_call_record('qg_review', 'default_ai', 'ok', 1200, 10, null, null, 100, 50)::text$q$);
select pg_temp.chk('M_ai_eval_pass', $q$select ((public.wpl_qg_ai_eval_record('review_legal_json', 'default_ai', 'ran',
   '{"verdict":"reject","reasons":[{"message":"보장 표현"}],"summary":"거부"}', 900, pg_temp.v('call')::uuid, null, null)->>'status') = 'pass')::text$q$);
select pg_temp.chk('M_ai_eval_fail_new_number', $q$select ((public.wpl_qg_ai_eval_record('review_legal_json', 'default_ai', 'ran',
   '{"verdict":"reject","reasons":[{"message":"매출 777만원"}]}', 900, pg_temp.v('call')::uuid, null, null)->>'status') = 'fail')::text$q$);
select pg_temp.chk('M_ai_eval_pass_again', $q$select ((public.wpl_qg_ai_eval_record('review_legal_json', 'default_ai', 'ran',
   '{"verdict":"reject","reasons":[{"message":"보장 표현"}],"summary":"거부"}', 900, pg_temp.v('call')::uuid, null, null)->>'status') = 'pass')::text$q$);
select pg_temp.rej('M_fake_eval_run', $q$select public.wpl_qg_ai_eval_record('review_legal_json', 'default_ai', 'ran', '{}', 1, gen_random_uuid(), null, null)$q$, '%호출 기록%');
select pg_temp.chk('M_request_approval', $q$select ((public.wpl_qg_ai_model_set_status('default_ai', 'qg_review', 'approved', '평가 통과 확인')->>'pending')::boolean)::text$q$);
select pg_temp.rej('M_self_decide_rejected', $q$select public.wpl_qg_ai_model_decide('default_ai', 'qg_review', 'approved', null)$q$, '%스스로%');
select pg_temp.as_user(pg_temp.v('admin2')::uuid);
select pg_temp.chk('M_other_decides', $q$select ((public.wpl_qg_ai_model_decide('default_ai', 'qg_review', 'approved', '확인')->>'status') = 'approved')::text$q$);
select pg_temp.chk('M_routing_policy', $q$select ((public.wpl_qg_ai_routing_policy('qg_review')->'approved') ? 'default_ai' and not (public.wpl_qg_ai_routing_policy('qg_review')->>'require')::boolean)::text$q$);
select pg_temp.put('aim', $q$select public.wpl_qg_run_engine('ai_model')::text$q$);
select pg_temp.chk('M_unapproved_use_pass', $q$select exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('aim')::uuid and check_code = 'ai_model.unapproved_use' and status = 'pass')::text$q$);
select pg_temp.chk('M_matrix', $q$select (jsonb_array_length(public.wpl_qg_ai_matrix()->'cells') >= 6)::text$q$);
select pg_temp.as_pg();
select pg_temp.rej('M_approval_direct_update_blocked', $q$update wpl_qg_ai_model_approvals set status = 'approved' where model_code = 'default_ai'$q$, '%절차%');

-- ───────── N. 출시 승인·차단 + 훅(강제 스위치) ─────────
select pg_temp.as_pg();
select set_config('wpl.qg_write', 'on', true);
update wpl_qg_releases set status = 'rejected' where status in ('candidate','checking','passed','blocked','approved')
   and ((kind = 'code_deploy' and target_ref = 'abcdef1234567') or (kind = 'policy_change' and target_ref in ('qg_review_quorum','qg_cron_enabled')));
select set_config('wpl.qg_write', '', true);
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.put('rel_cd', $q$select (public.wpl_qg_release_create('code_deploy', 'abcdef1234567', null, null, null)->>'id')$q$);
select pg_temp.chk('N_code_deploy_blocked', $q$select ((public.wpl_qg_release_evaluate(pg_temp.v('rel_cd')::uuid, false)->>'result') = 'blocked')::text$q$);
select pg_temp.rej('N_approve_blocked_rejected', $q$select public.wpl_qg_release_decide(pg_temp.v('rel_cd')::uuid, 'approved', null)$q$, '%관문을 통과한 후보만%');
select pg_temp.rej('N_deploy_unapproved_rejected', $q$select public.wpl_qg_release_record_deploy(pg_temp.v('rel_cd')::uuid, 'dpl_1', 'READY', 'abcdef1234567', null, null)$q$, '%승인된 후보만%');
select pg_temp.rej('N_duplicate_active_rejected', $q$select public.wpl_qg_release_create('code_deploy', 'abcdef1234567', null, null, null)$q$, '%진행 중인 출시 후보%');
select pg_temp.as_pg();
update wpl_qg_gate_policies set required_engines = '[]', block_severities = '[]', require_review = false where kind in ('code_deploy','policy_change');
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.chk('N_code_deploy_passes', $q$select ((public.wpl_qg_release_evaluate(pg_temp.v('rel_cd')::uuid, false)->>'result') = 'passed')::text$q$);
select pg_temp.rej('N_self_approve_rejected', $q$select public.wpl_qg_release_decide(pg_temp.v('rel_cd')::uuid, 'approved', null)$q$, '%스스로%');
select pg_temp.as_user(pg_temp.v('admin2')::uuid);
select pg_temp.chk('N_other_approves', $q$select ((public.wpl_qg_release_decide(pg_temp.v('rel_cd')::uuid, 'approved', '확인')->>'status') = 'approved')::text$q$);
select pg_temp.rej('N_deploy_not_ready', $q$select public.wpl_qg_release_record_deploy(pg_temp.v('rel_cd')::uuid, 'dpl_1', 'BUILDING', 'abcdef1234567', null, null)$q$, '%READY%');
select pg_temp.rej('N_deploy_sha_mismatch', $q$select public.wpl_qg_release_record_deploy(pg_temp.v('rel_cd')::uuid, 'dpl_1', 'READY', '1234567abcdef', null, null)$q$, '%다릅니다%');
select pg_temp.chk('N_deploy_recorded', $q$select ((public.wpl_qg_release_record_deploy(pg_temp.v('rel_cd')::uuid, 'dpl_1', 'READY', 'abcdef1234567aa', 'https://example.com', null)->>'status') = 'released')::text$q$);
select pg_temp.put('rel_pc', $q$select (public.wpl_qg_release_create('policy_change', 'qg_review_quorum', null, null, null)->>'id')$q$);
select pg_temp.chk('N_policy_change_passes', $q$select ((public.wpl_qg_release_evaluate(pg_temp.v('rel_pc')::uuid, false)->>'result') = 'passed')::text$q$);
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.chk('N_policy_change_approved', $q$select ((public.wpl_qg_release_decide(pg_temp.v('rel_pc')::uuid, 'approved', '확인')->>'status') = 'approved')::text$q$);
select pg_temp.rej('N_unknown_kind_rejected', $q$select public.wpl_qg_release_create('no_such_kind', 'x', null, null, null)$q$, '%종류%');

-- 훅: 플랫폼 출시 함수(시험용) — 강제 스위치 false 면 원래 결과와 같고, true 면 승인 없는 대상 거부
select pg_temp.as_pg();
create function public.zz_qg_platform_release(p text) returns text language plpgsql security definer set search_path = public as $f$
begin
  perform public.wpl_qg_release_gate_hook_internal('policy_change', p);   -- [QG 훅]
  return 'ok:' || p;
end $f$;
revoke all on function public.zz_qg_platform_release(text) from public, anon, authenticated;
select pg_temp.chk('N_hook_off_same_result', $q$select (public.zz_qg_platform_release('qg_cron_enabled') = 'ok:qg_cron_enabled')::text$q$);
select pg_temp.chk('N_hook_off_returns_same', $q$select (public.zz_qg_platform_release('qg_review_quorum') = 'ok:qg_review_quorum')::text$q$);
select pg_temp.chk('N_hook_off_consumes_approved', $q$select (select status = 'released' and released_via = 'hook' from wpl_qg_releases where id = pg_temp.v('rel_pc')::uuid)::text$q$);
update wpl_qg_settings set value = 'true' where key = 'qg_enforce_policy_change';
select pg_temp.rej('N_hook_on_blocks_unapproved', $q$select public.zz_qg_platform_release('qg_cron_enabled')$q$, '%출시 관문%');
select pg_temp.chk('N_denied_msg_human', $q$select (pg_temp.errmsg('select public.zz_qg_platform_release(''qg_cron_enabled'')') not like '%qg\_enforce%'
   and pg_temp.errmsg('select public.zz_qg_platform_release(''qg_cron_enabled'')') not like '%을(를)%'
   and pg_temp.errmsg('select public.zz_qg_platform_release(''qg_cron_enabled'')') like '%강제 스위치 「%')::text$q$);
select pg_temp.chk('N_require_blocks_when_on', $q$select (pg_temp.errmsg('select public.wpl_qg_release_gate_require_internal(''policy_change'', ''qg_cron_enabled'')') like '%출시 관문%')::text$q$);
select pg_temp.chk('N_gate_open_helper', $q$select (not public.wpl_qg_release_gate_open_internal('policy_change', 'qg_cron_enabled')
   and public.wpl_qg_release_gate_open_internal('policy_change', 'qg_review_quorum'))::text$q$);
update wpl_qg_settings set value = 'false' where key = 'qg_enforce_policy_change';
select pg_temp.chk('N_hook_off_again_same', $q$select (public.zz_qg_platform_release('qg_cron_enabled') = 'ok:qg_cron_enabled')::text$q$);
select pg_temp.chk('N_require_noop_when_off', $q$select (pg_temp.errmsg('select public.wpl_qg_release_gate_require_internal(''policy_change'', ''qg_cron_enabled'')') = 'no error')::text$q$);
insert into wpl_qg_gate_policies(kind, name, required_engines, block_severities) values ('zz_feature', '시험 기능 출시', '[]', '[]');
select pg_temp.chk('N_new_kind_switch_auto', $q$select ((select value from wpl_qg_settings where key = 'qg_enforce_zz_feature') = 'false'::jsonb)::text$q$);
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.put('relrun', $q$select public.wpl_qg_run_engine('release')::text$q$);
select pg_temp.chk('N_release_probes_clean', $q$select (not exists (select 1 from wpl_qg_findings where run_id = pg_temp.v('relrun')::uuid and check_code in ('release.approved_before_release','release.deploy_sha_match') and status <> 'pass'))::text$q$);
select pg_temp.as_pg();
select pg_temp.rej('N_release_direct_update_blocked', $q$update wpl_qg_releases set status = 'released' where id = pg_temp.v('rel_cd')::uuid$q$, '%절차%');

-- ───────── O. 개선 제안 ─────────
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select set_config('qg.smoke_fail', 'on', true);
select set_config('qg.smoke_fp', 'z', true);
select public.wpl_qg_run_engine('evidence'); select public.wpl_qg_run_engine('evidence'); select public.wpl_qg_run_engine('evidence');
select set_config('qg.smoke_fail', '', true);
select pg_temp.chk('O_collect_creates', $q$select ((public.wpl_qg_evolution_collect()->>'created')::int >= 1)::text$q$);
select pg_temp.put('prop', $q$select id::text from wpl_qg_proposals where source = 'recurring_issue' order by priority_score desc limit 1$q$);
select pg_temp.chk('O_proposal_priority', $q$select ((select priority_score > 0 and status = 'proposed' from wpl_qg_proposals where id = pg_temp.v('prop')::uuid))::text$q$);
select pg_temp.rej('O_decline_needs_reason', $q$select public.wpl_qg_proposal_transition(pg_temp.v('prop')::uuid, 'declined', null, null)$q$, '%사유%');
select pg_temp.chk('O_accept', $q$select ((public.wpl_qg_proposal_transition(pg_temp.v('prop')::uuid, 'accepted', null, null)->>'status') = 'accepted')::text$q$);
select pg_temp.chk('O_collect_again_no_dup', $q$select ((public.wpl_qg_evolution_collect()->>'created')::int = 0)::text$q$);
select pg_temp.chk('O_manual_proposal', $q$select ((public.wpl_qg_proposal_create('{"title":"수동 제안","problem":"문제 설명","impact":4,"effort":2}'::jsonb)->>'ok')::boolean)::text$q$);
select pg_temp.chk('O_signal_not_in_issues', $q$select (not exists (select 1 from wpl_qg_issues where engine_code = 'evolution'))::text$q$);

-- ───────── P. 테넌트 범위(어댑터에 테넌트가 있을 때만) ─────────
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.chk('P_tenant_ingest', $q$select (case when pg_temp.v('has_tenant') = 'yes' then
   ((public.wpl_qg_ingest(jsonb_build_object('engine','testing','tenant_id', pg_temp.v('tenant'),'results','[{"check_code":"testing.suite_qg_smoke","status":"fail","fingerprint":"t"}]'::jsonb), null)->>'ok')::boolean)
   else true end)::text$q$);
select pg_temp.put('trun', $q$select case when pg_temp.v('has_tenant') = 'yes' then public.wpl_qg_run_engine('evidence', pg_temp.v('tenant')::uuid)::text else '' end$q$);
select pg_temp.chk('P_tenant_run', $q$select (case when pg_temp.v('has_tenant') = 'yes' then
   (select count(*) from wpl_qg_findings f where f.run_id = pg_temp.v('trun')::uuid and f.check_code = 'evidence.zz_tenant' and f.tenant_id = pg_temp.v('tenant')::uuid) = 1
   and (select tenant_id from wpl_qg_runs where id = pg_temp.v('trun')::uuid) = pg_temp.v('tenant')::uuid
   else true end)::text$q$);
select pg_temp.as_user(coalesce(pg_temp.v('member'), pg_temp.v('outsider'))::uuid);
select pg_temp.chk('P_member_reads_own_tenant', $q$select (case when pg_temp.v('has_tenant') = 'yes' then
   (select count(*) from wpl_qg_runs where tenant_id = pg_temp.v('tenant')::uuid) >= 1 and (select count(*) from wpl_qg_runs where tenant_id is null) = 0
   else true end)::text$q$);
select pg_temp.chk('P_member_not_other_tenant', $q$select (case when pg_temp.v('has_tenant') = 'yes' and pg_temp.v('tenant2') is not null then
   (select count(*) from wpl_qg_issues where tenant_id = pg_temp.v('tenant2')::uuid) = 0 else true end)::text$q$);
select pg_temp.rej('P_member_cannot_run', $q$select public.wpl_qg_run_engine('evidence')$q$, '%관리자%');
select pg_temp.chk('P_member_catalog_hidden', $q$select ((select count(*) from wpl_qg_checks) = 0 and (select count(*) from wpl_qg_reviewers) = 0)::text$q$);

-- ───────── Z. 보안 불변식(QG 자신) ─────────
select pg_temp.as_pg();
drop function public.zz_qg_smoke_anon(); drop function public.zz_qg_smoke_internal();
select pg_temp.chk('Z_no_anon_exec_qg', $q$select (not exists (select 1 from pg_proc p where p.pronamespace = 'public'::regnamespace
   and (p.proname like 'wpl\_qg\_%' or p.proname like 'wpl\_qga\_%') and has_function_privilege('anon', p.oid, 'execute')))::text$q$);
select pg_temp.chk('Z_definer_search_path', $q$select (not exists (select 1 from pg_proc p where p.pronamespace = 'public'::regnamespace and p.prosecdef
   and (p.proname like 'wpl\_qg\_%' or p.proname like 'wpl\_qga\_%')
   and not exists (select 1 from unnest(coalesce(p.proconfig, '{}'::text[])) c where c like 'search_path=%')))::text$q$);
select pg_temp.chk('Z_rls_all_qg_tables', $q$select (not exists (select 1 from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r'
   and c.relname like 'wpl\_qg\_%' and not c.relrowsecurity))::text$q$);
select pg_temp.chk('Z_internal_not_executable', $q$select (not exists (select 1 from pg_proc p where p.pronamespace = 'public'::regnamespace
   and (p.proname like 'wpl\_qg\_%\_internal' or p.proname like 'wpl\_qg\_probe\_%' or p.proname like 'wpl\_qg\_%\_trg' or p.proname like 'wpl\_qg\_%guard'
        or (p.proname like 'wpl\_qga\_%' and p.proname not in ('wpl_qga_is_admin','wpl_qga_can_read_tenant')))
   and has_function_privilege('authenticated', p.oid, 'execute')))::text$q$);
select pg_temp.chk('Z_no_qg_table_anon_privilege', $q$select (not exists (select 1 from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r'
   and c.relname like 'wpl\_qg\_%' and has_table_privilege('anon', c.oid, 'select,insert,update,delete')))::text$q$);
select pg_temp.chk('Z_evidence_chain_final', $q$select ((public.wpl_qg_evidence_verify_rows_internal(public.wpl_qg_evidence_rows_internal())->>'ok')::boolean)::text$q$);

insert into r(step, ok, msg) select 'SUMMARY passed=' || count(*) filter (where ok) || ' failed=' || count(*) filter (where not ok), count(*) filter (where not ok) = 0, null from r;
select step, ok, msg from r order by (step like 'SUMMARY%'), n;
rollback;
