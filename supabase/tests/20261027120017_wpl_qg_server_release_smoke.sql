-- =====================================================================
-- QG 서버 코드 출시 관문 스모크(WITH+ · LIVE+, 접두어 wpl) — 20261027120017 종류 3개(입점 승인·도매 승인·라이브 공개 시작). 항상 rollback(운영 데이터 무변경).
--  ① 정책·강제 스위치(기본 false) ② 대상 확인 어댑터(사이트 구분·모르는 값 null) ③ 대상 목록(관리자만) ④ 서버 확인: 꺼짐 = 허용 + 관찰만,
--  켜짐 = 승인 없으면 사람 말로 거부 ⑤ 후보 → 판정 → 다른 관리자 승인 → 허용 → 성공 뒤 출시 완료 연결 ⑥ 다시 끄면 원래대로.
--  결과: 단계마다 (step, ok, msg) + 마지막 SUMMARY passed=N failed=M.
-- =====================================================================
begin;
create temp table r(n serial, step text, ok boolean, msg text);
create temp table fx(k text primary key, v text);
create function pg_temp.chk(p_step text, p_sql text) returns void language plpgsql as $f$
declare v text;
begin
  begin execute p_sql into v; insert into r(step, ok, msg) values (p_step, v = 'true', 'got=' || coalesce(left(v, 300), 'null'));
  exception when others then insert into r(step, ok, msg) values (p_step, false, 'err: ' || left(sqlerrm, 300)); end;
end $f$;
create function pg_temp.rej(p_step text, p_sql text, p_like text) returns void language plpgsql as $f$
begin
  begin execute p_sql; insert into r(step, ok, msg) values (p_step, false, 'no error');
  exception when others then insert into r(step, ok, msg) values (p_step, sqlerrm ilike p_like, left(sqlerrm, 300)); end;
end $f$;
create function pg_temp.put(p_k text, p_sql text) returns void language plpgsql as $f$
declare v text;
begin
  begin execute p_sql into v; insert into fx values (p_k, v) on conflict (k) do update set v = excluded.v;
  exception when others then insert into r(step, ok, msg) values ('put_' || p_k, false, 'err: ' || left(sqlerrm, 300)); end;
end $f$;
create function pg_temp.v(p_k text) returns text language sql as $f$ select v from fx where k = p_k $f$;
create function pg_temp.as_user(p_uid uuid) returns void language plpgsql as $f$
begin perform set_config('request.jwt.claims', json_build_object('sub', p_uid, 'role', 'authenticated')::text, true);
      perform set_config('request.jwt.claim.sub', coalesce(p_uid::text, ''), true); execute 'set local role authenticated'; end $f$;
create function pg_temp.as_service() returns void language plpgsql as $f$
begin perform set_config('request.jwt.claims', json_build_object('role', 'service_role')::text, true);
      perform set_config('request.jwt.claim.sub', '', true); execute 'set local role service_role'; end $f$;
create function pg_temp.as_pg() returns void language plpgsql as $f$
begin execute 'reset role'; perform set_config('request.jwt.claims', '', true); perform set_config('request.jwt.claim.sub', '', true); end $f$;
grant all on r to authenticated, service_role; grant usage, select on sequence r_n_seq to authenticated, service_role; grant all on fx to authenticated, service_role;
grant execute on all functions in schema pg_temp to authenticated, anon, service_role;

insert into fx select key, value from jsonb_each_text(public.wpl_qga_smoke_fixture()) where value is not null;
insert into fx values ('W', 'a17e0000-0000-4000-8000-000000000001'), ('L', 'a17e0000-0000-4000-8000-000000000002'), ('tag', 'qgr' || substr(md5(clock_timestamp()::text), 1, 8));

-- ① 정책·스위치
select pg_temp.chk('policies_registered', $q$select (count(*) = 3 and bool_and(active))::text from public.wpl_qg_gate_policies where kind in ('supplier_approve','wholesale_approve','live_go_live')$q$);
select pg_temp.chk('switches_default_false', $q$select (count(*) = 3 and bool_and((value #>> '{}') = 'false'))::text from public.wpl_qg_settings
   where key in ('qg_enforce_supplier_approve','qg_enforce_wholesale_approve','qg_enforce_live_go_live')$q$);

-- 시험 대상(이 트랜잭션 안에서만): 입점·도매 신청 각 1건(대기), 사이트마다 채널·예정 세션 1개
select pg_temp.put('sa', $q$insert into public.supplier_applications_with(applicant_id, company_name, business_number, status) values (pg_temp.v('outsider')::uuid, pg_temp.v('tag') || ' 상사', '0000000000', 'pending') returning id::text$q$);
select pg_temp.put('wa', $q$insert into public.wholesale_applications_with(applicant_id, company_name, business_number, status) values (pg_temp.v('outsider')::uuid, pg_temp.v('tag') || ' 도매', '0000000000', 'pending') returning id::text$q$);
select pg_temp.put('chw', $q$insert into public.channels_with(slug, name, channel_type) values (pg_temp.v('tag') || '-w', 'QG 출시 W', 'brand') returning id::text$q$);
select pg_temp.put('chl', $q$insert into public.channels_live(slug, name, channel_type) values (pg_temp.v('tag') || '-l', 'QG 출시 L', 'brand') returning id::text$q$);
select pg_temp.put('sw', $q$insert into public.live_sessions_with(channel_id, title, status) values (pg_temp.v('chw')::uuid, 'QG 공개 W', 'scheduled') returning id::text$q$);
select pg_temp.put('sl', $q$insert into public.live_sessions_live(channel_id, title, status) values (pg_temp.v('chl')::uuid, 'QG 공개 L', 'scheduled') returning id::text$q$);

-- ② 대상 확인 어댑터
select pg_temp.chk('target_supplier', $q$select ((public.wpl_qga_release_target('supplier_approve', pg_temp.v('sa'))->>'ref') = pg_temp.v('sa')
   and (public.wpl_qga_release_target('supplier_approve', pg_temp.v('sa'))->>'label') like '입점 신청: %상사')::text$q$);
select pg_temp.chk('target_wholesale', $q$select ((public.wpl_qga_release_target('wholesale_approve', pg_temp.v('wa'))->>'ref') = pg_temp.v('wa'))::text$q$);
select pg_temp.chk('target_live_with_site', $q$select ((public.wpl_qga_release_target('live_go_live', pg_temp.v('sw'))->>'tenant_id') = pg_temp.v('W')
   and (public.wpl_qga_release_target('live_go_live', pg_temp.v('sw'))->>'label') like 'WITH+ 라이브: QG 출시 W · QG 공개 W')::text$q$);
select pg_temp.chk('target_live_live_site', $q$select ((public.wpl_qga_release_target('live_go_live', pg_temp.v('sl'))->>'tenant_id') = pg_temp.v('L'))::text$q$);
select pg_temp.chk('target_uppercase_ref_normalized', $q$select ((public.wpl_qga_release_target('supplier_approve', upper(pg_temp.v('sa')))->>'ref') = pg_temp.v('sa'))::text$q$);
select pg_temp.chk('target_wrong_kind_table_null', $q$select (public.wpl_qga_release_target('wholesale_approve', pg_temp.v('sa')) is null)::text$q$);
select pg_temp.chk('target_bad_ref_null', $q$select (public.wpl_qga_release_target('supplier_approve', 'not-a-uuid') is null and public.wpl_qga_release_target('live_go_live', gen_random_uuid()::text) is null
   and public.wpl_qga_release_target('other_kind', pg_temp.v('sa')) is null)::text$q$);
select pg_temp.chk('target_fn_not_user_executable', $q$select (not has_function_privilege('authenticated', 'public.wpl_qga_release_target(text,text)', 'execute')
   and not has_function_privilege('anon', 'public.wpl_qga_release_target(text,text)', 'execute'))::text$q$);

-- ③ 대상 목록(관리자만)
select pg_temp.as_user(pg_temp.v('outsider')::uuid);
select pg_temp.rej('list_outsider_denied', $q$select count(*) from public.wpl_qg_release_target_list('supplier_approve', 10)$q$, '%관리자%');
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.chk('list_supplier_pending', $q$select exists (select 1 from public.wpl_qg_release_target_list('supplier_approve', 300) where ref = pg_temp.v('sa'))::text$q$);
select pg_temp.chk('list_wholesale_pending', $q$select exists (select 1 from public.wpl_qg_release_target_list('wholesale_approve', 300) where ref = pg_temp.v('wa'))::text$q$);
select pg_temp.chk('list_live_both_sites', $q$select ((select count(*) from public.wpl_qg_release_target_list('live_go_live', 300) where ref in (pg_temp.v('sw'), pg_temp.v('sl'))) = 2
   and exists (select 1 from public.wpl_qg_release_target_list('live_go_live', 300) where ref = pg_temp.v('sl') and tenant_id = pg_temp.v('L')::uuid))::text$q$);
select pg_temp.chk('list_unknown_kind_empty', $q$select ((select count(*) from public.wpl_qg_release_target_list('nope', 10)) = 0)::text$q$);
select pg_temp.put('rel_l', $q$select public.wpl_qg_release_create('live_go_live', pg_temp.v('sl'), null, null, null)->>'id'$q$);
select pg_temp.chk('create_live_candidate_site', $q$select ((select tenant_id from public.wpl_qg_releases where id = pg_temp.v('rel_l')::uuid) = pg_temp.v('L')::uuid)::text$q$);

-- ④ 서버 확인: 꺼짐 = 허용 + 관찰만
select pg_temp.as_service();
select pg_temp.put('off', $q$select public.wpl_qg_release_gate_check_server('supplier_approve', pg_temp.v('sa'), null, null, 'x')::text$q$);
select pg_temp.chk('off_allows_observes', $q$select ((pg_temp.v('off')::jsonb->>'allowed')::boolean and not (pg_temp.v('off')::jsonb->>'enforced')::boolean
   and (pg_temp.v('off')::jsonb->>'would_block')::boolean and pg_temp.v('off')::jsonb->>'reason' = 'no_approved' and pg_temp.v('off')::jsonb->>'message' is null
   and (pg_temp.v('off')::jsonb->>'observation_id') is not null)::text$q$);
select pg_temp.chk('off_unknown_ref_allows', $q$select ((public.wpl_qg_release_gate_check_server('live_go_live', 'junk-ref', null, null, null)->>'allowed')::boolean)::text$q$);
select pg_temp.chk('off_mark_not_linked', $q$select (not (public.wpl_qg_release_mark_server('wholesale_approve', pg_temp.v('wa'), null, null, null, null)->>'linked')::boolean)::text$q$);
select pg_temp.put('obs_w', $q$select public.wpl_qg_release_gate_check_server('live_go_live', pg_temp.v('sw'), null, null, null)->>'observation_id'$q$);
select pg_temp.chk('observation_tenant_live', $q$select ((select tenant_id from public.wpl_qg_release_observations where id = pg_temp.v('obs_w')::bigint) = pg_temp.v('W')::uuid)::text$q$);

-- 켜짐 = 승인 없으면 사람 말로 거부
select pg_temp.as_pg();
update public.wpl_qg_settings set value = 'true' where key in ('qg_enforce_supplier_approve', 'qg_enforce_live_go_live');
select pg_temp.as_service();
select pg_temp.put('on', $q$select public.wpl_qg_release_gate_check_server('supplier_approve', pg_temp.v('sa'), null, null, null)::text$q$);
select pg_temp.chk('on_blocks_human_msg', $q$select (not (pg_temp.v('on')::jsonb->>'allowed')::boolean and pg_temp.v('on')::jsonb->>'message' like '%판매자 입점 승인을 진행할 수 없습니다%'
   and pg_temp.v('on')::jsonb->>'message' not like '%qg\_enforce%' and pg_temp.v('on')::jsonb->>'message' not like '%을(를)%')::text$q$);
select pg_temp.chk('on_live_blocks', $q$select (not (public.wpl_qg_release_gate_check_server('live_go_live', pg_temp.v('sw'), null, null, null)->>'allowed')::boolean)::text$q$);
select pg_temp.chk('on_other_kind_still_off', $q$select ((public.wpl_qg_release_gate_check_server('wholesale_approve', pg_temp.v('wa'), null, null, null)->>'allowed')::boolean)::text$q$);

-- ⑤ 후보 → 판정 → 다른 관리자 승인 → 허용 → 성공 뒤 출시 완료
select pg_temp.as_pg();
update public.wpl_qg_gate_policies set required_engines = '[]', block_severities = '[]' where kind = 'supplier_approve';   -- 이 트랜잭션 안에서만(엔진 실행 없이 승인 흐름만 시험)
select pg_temp.as_user(pg_temp.v('admin1')::uuid);
select pg_temp.put('rel', $q$select (public.wpl_qg_release_create('supplier_approve', upper(pg_temp.v('sa')), null, null, null)->>'id')$q$);
select pg_temp.chk('candidate_ref_normalized', $q$select ((select target_ref from public.wpl_qg_releases where id = pg_temp.v('rel')::uuid) = pg_temp.v('sa'))::text$q$);
select pg_temp.put('ev', $q$select public.wpl_qg_release_evaluate(pg_temp.v('rel')::uuid, false)->>'result'$q$);
select pg_temp.as_user(pg_temp.v('admin2')::uuid);
select pg_temp.put('dc', $q$select public.wpl_qg_release_decide(pg_temp.v('rel')::uuid, 'approved', '확인')->>'status'$q$);
select pg_temp.chk('candidate_approved', $q$select (pg_temp.v('dc') = 'approved')::text$q$);
select pg_temp.as_service();
select pg_temp.chk('on_allows_approved', $q$select ((public.wpl_qg_release_gate_check_server('supplier_approve', pg_temp.v('sa'), null, null, null)->>'reason') = 'approved')::text$q$);
select pg_temp.chk('mark_links', $q$select ((public.wpl_qg_release_mark_server('supplier_approve', pg_temp.v('sa'), null, null, null, '입점 승인 성공')->>'linked')::boolean)::text$q$);
select pg_temp.chk('candidate_released', $q$select ((select status from public.wpl_qg_releases where id = pg_temp.v('rel')::uuid) = 'released')::text$q$);
select pg_temp.chk('on_blocks_after_consumed', $q$select (not (public.wpl_qg_release_gate_check_server('supplier_approve', pg_temp.v('sa'), null, null, null)->>'allowed')::boolean)::text$q$);

-- ⑥ 다시 끄면 원래대로
select pg_temp.as_pg();
update public.wpl_qg_settings set value = 'false' where key in ('qg_enforce_supplier_approve', 'qg_enforce_live_go_live');
select pg_temp.as_service();
select pg_temp.chk('off_again_allows', $q$select ((public.wpl_qg_release_gate_check_server('supplier_approve', pg_temp.v('sa'), null, null, null)->>'allowed')::boolean
   and (public.wpl_qg_release_gate_check_server('live_go_live', pg_temp.v('sw'), null, null, null)->>'allowed')::boolean)::text$q$);
select pg_temp.as_pg();
select pg_temp.chk('business_rows_untouched', $q$select ((select status from public.supplier_applications_with where id = pg_temp.v('sa')::uuid) = 'pending'
   and (select status from public.live_sessions_with where id = pg_temp.v('sw')::uuid) = 'scheduled')::text$q$);

select step, ok, msg from (
  select n, step, ok, msg from r
  union all
  select 100000, format('SUMMARY passed=%s failed=%s', count(*) filter (where ok), count(*) filter (where not ok or ok is null)), bool_and(coalesce(ok, false)), null from r
) z order by n;
rollback;
