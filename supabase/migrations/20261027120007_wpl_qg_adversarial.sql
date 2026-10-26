-- QG 키트 1.1.0 · 접두어 wpl · adversarial — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
-- =====================================================================
-- QG 키트 23 — 공격·장애 시뮬레이션 엔진(adversarial) (원본: F-MATRIX 2913)
--  · wpl_qg_scenarios  카탈로그: 공격·장애·오입력 시나리오(코드·설명·기대 결과·심각도·스크립트·연결 위험 항목)
--  · 실행: node scripts/qg-run.mjs adversarial → supabase/tests/qg/adversarial_*.sql(항상 rollback, 시나리오별 PASS/FAIL 행) → wpl_qg_ingest
--  · 키트 기본 시나리오 6종은 QG 자신의 방어(익명·위조 키·증거 변조·probe 주입·자기 승인·대용량)를 시험한다(adversarial_qg_core.sql).
--    플랫폼 업무 시나리오(교차 테넌트·금액 조작·숙고기간 우회…)는 같은 형식으로 플랫폼 파일에 더한다(QG_KIT.md §5.5).
--  두 번 적용해도 같은 결과.
-- =====================================================================

create table if not exists public.wpl_qg_scenarios (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{2,59}$'),
  name text not null check (char_length(name) between 1 and 120),
  category text not null check (category in ('attack','failure','misinput')),
  description text not null,
  expected text not null,
  severity text not null check (severity in ('critical','high','medium','low')),
  script text not null check (script ~ '^(supabase/tests/qg/adversarial_[a-z0-9_]+\.sql|vitest:src/[A-Za-z0-9_./-]+\.test\.ts)$' and script !~ '\.\.'),
  check_code text not null unique references public.wpl_qg_checks(code) on update cascade,
  risk_items jsonb not null default '[]'::jsonb check (jsonb_typeof(risk_items) = 'array'),
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.wpl_qg_scenarios_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_bad text;
begin
  select string_agg(x, ', ') into v_bad from jsonb_array_elements_text(new.risk_items) x
   where not exists (select 1 from public.wpl_qg_risk_items r where r.code = x);
  if v_bad is not null then raise exception '없는 위험 항목 코드입니다: %', left(v_bad, 200); end if;
  if not exists (select 1 from public.wpl_qg_checks c where c.code = new.check_code and c.engine_code = 'adversarial' and c.probe = 'scenario:' || new.code) then
    raise exception '시나리오는 같은 코드의 공격·장애 시뮬레이션 검사 항목(scenario:%)에 연결해야 합니다.', new.code;
  end if;
  return new;
end $$;
revoke all on function public.wpl_qg_scenarios_guard() from public, anon, authenticated;
drop trigger if exists wpl_qg_scenarios_guard_biu on public.wpl_qg_scenarios;
create trigger wpl_qg_scenarios_guard_biu before insert or update on public.wpl_qg_scenarios for each row execute function public.wpl_qg_scenarios_guard();
drop trigger if exists wpl_qg_scenarios_touch on public.wpl_qg_scenarios;
create trigger wpl_qg_scenarios_touch before update on public.wpl_qg_scenarios for each row execute function public.wpl_qg_touch();

alter table public.wpl_qg_scenarios enable row level security;
drop policy if exists wpl_qg_scenarios_read on public.wpl_qg_scenarios;
create policy wpl_qg_scenarios_read on public.wpl_qg_scenarios for select to authenticated using (public.wpl_qga_is_admin());
drop policy if exists wpl_qg_scenarios_admin_ins on public.wpl_qg_scenarios;
create policy wpl_qg_scenarios_admin_ins on public.wpl_qg_scenarios for insert to authenticated with check (public.wpl_qga_is_admin());
drop policy if exists wpl_qg_scenarios_admin_upd on public.wpl_qg_scenarios;
create policy wpl_qg_scenarios_admin_upd on public.wpl_qg_scenarios for update to authenticated using (public.wpl_qga_is_admin()) with check (public.wpl_qga_is_admin());
drop policy if exists wpl_qg_scenarios_no_delete on public.wpl_qg_scenarios;
create policy wpl_qg_scenarios_no_delete on public.wpl_qg_scenarios as restrictive for delete to authenticated, anon using (false);
revoke all on public.wpl_qg_scenarios from anon;
revoke delete, truncate on public.wpl_qg_scenarios from authenticated;
grant select, insert, update on public.wpl_qg_scenarios to authenticated;

-- 시드(검사 항목 먼저 — 시나리오 가드가 검사 항목 존재를 확인)
drop table if exists pg_temp.wpl_qg_sc_seed;
create temp table wpl_qg_sc_seed(code text, name text, category text, description text, expected text, severity text, script text, risk_items jsonb, ord int);
insert into pg_temp.wpl_qg_sc_seed(code, name, category, description, expected, severity, script, risk_items, ord) values
 ('qg_anon_rpc', '익명 QG 호출·표 읽기', 'attack',
  '로그인 없이(anon) QG 실행·결과 올리기·대시보드·설정 바꾸기를 부르고, 실행·증거·이슈 표를 직접 읽어 봅니다.',
  '모든 호출 거부, 모든 표 접근 거부', 'critical', 'supabase/tests/qg/adversarial_qg_core.sql', '["qg_anon_surface"]'::jsonb, 10),
 ('qg_forged_server_key', '서버 증명키 위조', 'attack',
  '관리자가 아닌 로그인 사용자가 지어낸 서버 증명키로 테스트 결과를 올려 출시 관문을 속이려 합니다.',
  '거부(결과가 기록되지 않음)', 'critical', 'supabase/tests/qg/adversarial_qg_core.sql', '["qg_anon_surface","qg_center"]'::jsonb, 20),
 ('qg_evidence_tamper', '증거·결과 변조', 'attack',
  '관리자 세션으로 증거·실행·결과 행을 고치거나 지우고(표 권한·가드), 내려받은 증거 사본의 내용을 바꿔 체인 검증을 속이려 합니다.',
  '수정·삭제 거부, 변조한 사본은 체인 검증에서 끊김으로 잡힘', 'critical', 'supabase/tests/qg/adversarial_qg_core.sql', '["qg_center"]'::jsonb, 30),
 ('qg_probe_injection', '검사 항목 주입', 'attack',
  '검사 항목의 실행 방법(probe)에 SQL 조각·다른 접두어 함수·경로 이탈을 넣어 실행기가 임의 SQL 을 돌리게 하려 합니다.',
  '저장 거부, 허용 목록 밖 함수는 실행하지 않음', 'high', 'supabase/tests/qg/adversarial_qg_core.sql', '["qg_center"]'::jsonb, 40),
 ('qg_self_approval', '자기 승인', 'attack',
  '높음·치명 이슈의 위험 수용을 요청한 관리자가 스스로 승인하고, 자기가 만든 출시 후보를 스스로 승인합니다.',
  '모두 거부(다른 관리자만 승인)', 'critical', 'supabase/tests/qg/adversarial_qg_core.sql', '["qg_center"]'::jsonb, 50),
 ('qg_oversized_ingest', '대용량 결과 올리기', 'misinput',
  '한도보다 많은 결과·8KB 넘는 맥락·엔진에 없는 검사 코드를 올립니다.',
  '모두 거부', 'medium', 'supabase/tests/qg/adversarial_qg_core.sql', '["qg_anon_surface"]'::jsonb, 60);

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort)
  select 'adversarial.' || s.code, 'adversarial', s.name, s.description, 'scenario:' || s.code, s.severity, 'platform', 'release', '{}'::jsonb, s.expected,
         '① 실행 결과에서 실패한 단계(step)와 메시지를 보고, 막혀야 할 동작이 통과한 경로(RLS 정책·DEFINER 권한 확인·트리거 가드)를 찾으세요. ② 고친 뒤 '
           || case when s.script like 'vitest:%' then 'npx vitest run ' || substr(s.script, 8) else 'node scripts/qg-run.mjs adversarial --files ' || regexp_replace(s.script, '^.*/', '') end
           || ' 로 다시 실행해 PASS 를 확인하세요. ③ 기대 결과 자체가 바뀐 것이면 시나리오 카탈로그의 기대 결과와 스크립트를 함께 고치세요.',
         s.ord
    from pg_temp.wpl_qg_sc_seed s
  on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
    schedule = excluded.schedule, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort, engine_code = excluded.engine_code;

insert into public.wpl_qg_scenarios(code, name, category, description, expected, severity, script, check_code, risk_items, sort)
select s.code, s.name, s.category, s.description, s.expected, s.severity, s.script, 'adversarial.' || s.code, s.risk_items, s.ord
  from pg_temp.wpl_qg_sc_seed s
on conflict (code) do update set name = excluded.name, category = excluded.category, description = excluded.description, expected = excluded.expected,
  severity = excluded.severity, script = excluded.script, risk_items = excluded.risk_items, sort = excluded.sort;
drop table if exists pg_temp.wpl_qg_sc_seed;

create or replace function public.wpl_qg_probe_adversarial_freshness(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_days int := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_testing_stale_days', '7'::jsonb) #>> '{}')::int, 7));
        v_out jsonb := '[]'::jsonb; r record; v_last jsonb; v_n int := 0; v_never jsonb := '[]'::jsonb; v_stale jsonb := '[]'::jsonb;
begin
  for r in select sc.* from public.wpl_qg_scenarios sc where sc.active order by sc.sort, sc.code loop
    v_n := v_n + 1;
    v_last := public.wpl_qg_check_last_internal(r.check_code);
    if v_last->>'at' is null then
      v_never := v_never || to_jsonb(r.code);
    elsif (v_last->>'at')::timestamptz < now() - make_interval(days => v_days) then
      v_stale := v_stale || jsonb_build_object('code', r.code, 'last_at', v_last->'at');
    end if;
  end loop;
  if jsonb_array_length(v_never) > 0 then
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', 'never_run',
      'title', format('한 번도 실행되지 않은 시나리오 %s개', jsonb_array_length(v_never)), 'detail', jsonb_build_object('scenarios', v_never)));
  end if;
  if jsonb_array_length(v_stale) > 0 then
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', 'stale',
      'title', format('%s일 넘게 실행하지 않은 시나리오 %s개', v_days, jsonb_array_length(v_stale)), 'detail', jsonb_build_object('scenarios', v_stale, 'days', v_days)));
  end if;
  for r in select c.code from public.wpl_qg_checks c where c.engine_code = 'adversarial' and c.active and c.probe like 'scenario:%'
              and not exists (select 1 from public.wpl_qg_scenarios s where s.check_code = c.code and s.active) loop
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'low', 'fingerprint', 'orphan_check:' || r.code,
      'title', '시나리오 카탈로그에 없는 검사 항목: ' || r.code, 'detail', jsonb_build_object('check', r.code)));
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('scenarios', v_n, 'days', v_days,
      'message', format('시나리오 %s개 모두 %s일 안에 실행되었습니다.', v_n, v_days)));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_adversarial_freshness(public.wpl_qg_checks, uuid) from public, anon, authenticated;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('adversarial.freshness', 'adversarial', '시나리오 실행 신선도',
  '사용 중인 공격·장애 시나리오마다 결과가 올라왔는지, 정책값(qg_testing_stale_days)보다 오래되지 않았는지, 시나리오 없는 시나리오형 검사 항목이 없는지 확인합니다.',
  'wpl_qg_probe_adversarial_freshness', 'medium', 'platform', 'daily', '{}'::jsonb,
  '실행 안 됨·오래됨 0개',
  '터미널에서 node scripts/qg-run.mjs adversarial 을 실행하세요(운영 데이터를 바꾸지 않는 rollback 스크립트). 배포 전마다, 최소 주 1회.', 5)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk,
  schedule = excluded.schedule, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort;
