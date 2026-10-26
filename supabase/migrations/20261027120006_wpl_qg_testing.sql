-- QG 키트 1.1.0 · 접두어 wpl · testing — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
-- =====================================================================
-- QG 키트 22 — 위험도별 테스트 엔진(testing) (원본: F-MATRIX 2912)
--  · wpl_qg_risk_items   카탈로그: 기능 위험 항목(대상 종류·ref·영향 1~5·가능성 1~5) → 등급(qg_risk_grade_thresholds)·필요 깊이(qg_risk_required_depth)
--  · wpl_qg_test_suites  카탈로그: 테스트 스위트(supabase/tests/*.sql · vitest) ↔ 검사 항목(suite:…) ↔ 연결 위험 항목
--  · 결과는 scripts/qg-run.mjs testing 이 wpl_qg_ingest 로 올린다(서버 증명키). 마지막 결과는 결과 원장에서 계산(진실의 원천).
--  · probe(매일): 고위험인데 테스트 없음 · 필요 깊이 부족 · 마지막 통과가 N일 지남/한 번도 없음 · 마지막 실행 실패
--  플랫폼의 위험 항목·스위트는 설치 뒤 카탈로그에 더한다(QG_KIT.md §5.4). 두 번 적용해도 같은 결과.
-- =====================================================================

insert into public.wpl_qg_settings(key, value, label, description) values
 ('qg_risk_grade_thresholds', '{"critical":15,"high":10,"medium":5}', '품질·거버넌스(테스트): 위험 등급 기준(영향×가능성)',
  '위험 점수(영향 1~5 × 가능성 1~5)가 critical 이상이면 치명, high 이상이면 높음, medium 이상이면 보통, 그 밖은 낮음입니다. JSON 객체.'),
 ('qg_risk_required_depth', '{"critical":["smoke","attack","e2e"],"high":["smoke","attack"],"medium":["smoke"],"low":["unit"]}',
  '품질·거버넌스(테스트): 등급별 필요한 테스트 깊이',
  '위험 등급마다 갖춰야 하는 테스트 종류입니다(unit=단위, smoke=DB 스모크, attack=공격 시나리오, e2e=화면 끝까지). JSON 객체.'),
 ('qg_testing_stale_days', '7', '품질·거버넌스(테스트): 마지막 통과 후 허용 일수',
  '치명·높음 위험 항목에 연결된 테스트가 이 일수보다 오래 통과 기록이 없으면 ''오래됨''으로 알려 줍니다.')
on conflict (key) do nothing;

create table if not exists public.wpl_qg_risk_items (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{2,59}$'),
  name text not null check (char_length(name) between 1 and 120),
  description text,
  target_kind text not null check (target_kind in ('module','route','rpc','capability','table')),
  target_ref text not null check (char_length(target_ref) between 1 and 200),
  impact int not null check (impact between 1 and 5),
  likelihood int not null check (likelihood between 1 and 5),
  note text,
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_test_suites (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{2,59}$'),
  name text not null check (char_length(name) between 1 and 160),
  kind text not null check (kind in ('sql','vitest','e2e','manual')),
  path text not null check (path ~ '^[A-Za-z0-9_./-]{1,200}$' and path !~ '\.\.'),
  depths jsonb not null default '["smoke"]'::jsonb check (jsonb_typeof(depths) = 'array' and jsonb_array_length(depths) between 1 and 4),
  check_code text not null unique references public.wpl_qg_checks(code) on update cascade,
  risk_items jsonb not null default '[]'::jsonb check (jsonb_typeof(risk_items) = 'array'),
  description text,
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.wpl_qg_test_suites_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_bad text;
begin
  select string_agg(x, ', ') into v_bad from jsonb_array_elements_text(new.depths) x where x not in ('unit','smoke','attack','e2e');
  if v_bad is not null then raise exception '테스트 깊이는 unit·smoke·attack·e2e 중에서 고르세요(잘못된 값: %).', v_bad; end if;
  select string_agg(x, ', ') into v_bad from jsonb_array_elements_text(new.risk_items) x
   where not exists (select 1 from public.wpl_qg_risk_items r where r.code = x);
  if v_bad is not null then raise exception '없는 위험 항목 코드입니다: %', left(v_bad, 200); end if;
  if not exists (select 1 from public.wpl_qg_checks c where c.code = new.check_code and c.engine_code = 'testing' and c.probe like 'suite:%') then
    raise exception '테스트 스위트는 위험도별 테스트 엔진의 suite: 검사 항목에 연결해야 합니다.';
  end if;
  return new;
end $$;
revoke all on function public.wpl_qg_test_suites_guard() from public, anon, authenticated;
drop trigger if exists wpl_qg_test_suites_guard_biu on public.wpl_qg_test_suites;
create trigger wpl_qg_test_suites_guard_biu before insert or update on public.wpl_qg_test_suites for each row execute function public.wpl_qg_test_suites_guard();
drop trigger if exists wpl_qg_risk_items_touch on public.wpl_qg_risk_items;
create trigger wpl_qg_risk_items_touch before update on public.wpl_qg_risk_items for each row execute function public.wpl_qg_touch();
drop trigger if exists wpl_qg_test_suites_touch on public.wpl_qg_test_suites;
create trigger wpl_qg_test_suites_touch before update on public.wpl_qg_test_suites for each row execute function public.wpl_qg_touch();

do $$ declare t text; begin
  foreach t in array array['wpl_qg_risk_items','wpl_qg_test_suites'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists %I on public.%I', t || '_read', t);
    execute format('create policy %I on public.%I for select to authenticated using (public.wpl_qga_is_admin())', t || '_read', t);
    execute format('drop policy if exists %I on public.%I', t || '_admin_ins', t);
    execute format('create policy %I on public.%I for insert to authenticated with check (public.wpl_qga_is_admin())', t || '_admin_ins', t);
    execute format('drop policy if exists %I on public.%I', t || '_admin_upd', t);
    execute format('create policy %I on public.%I for update to authenticated using (public.wpl_qga_is_admin()) with check (public.wpl_qga_is_admin())', t || '_admin_upd', t);
    execute format('drop policy if exists %I on public.%I', t || '_no_delete', t);
    execute format('create policy %I on public.%I as restrictive for delete to authenticated, anon using (false)', t || '_no_delete', t);
    execute format('revoke all on public.%I from anon', t);
    execute format('revoke delete, truncate on public.%I from authenticated', t);
    execute format('grant select, insert, update on public.%I to authenticated', t);
  end loop;
end $$;

create or replace function public.wpl_qg_risk_grade_internal(p_impact int, p_likelihood int) returns text
language plpgsql stable security definer set search_path = public as $$
declare t jsonb := public.wpl_qg_setting_internal('qg_risk_grade_thresholds', '{"critical":15,"high":10,"medium":5}'::jsonb); v int := coalesce(p_impact, 0) * coalesce(p_likelihood, 0);
begin
  if v >= coalesce((t->>'critical')::int, 15) then return 'critical'; end if;
  if v >= coalesce((t->>'high')::int, 10) then return 'high'; end if;
  if v >= coalesce((t->>'medium')::int, 5) then return 'medium'; end if;
  return 'low';
end $$;
revoke all on function public.wpl_qg_risk_grade_internal(int, int) from public, anon, authenticated;

-- 검사 항목의 마지막 결과(결과 원장에서): {status, at, run_id, last_pass_at}
create or replace function public.wpl_qg_check_last_internal(p_check text) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('status', l.status, 'at', l.finished_at, 'run_id', l.run_id,
    'last_pass_at', (select max(r2.finished_at) from public.wpl_qg_findings f2 join public.wpl_qg_runs r2 on r2.id = f2.run_id
                      where f2.check_code = p_check and f2.status = 'pass'))
    from (select 1) one
    left join lateral (select f.status, r.finished_at, f.run_id from public.wpl_qg_findings f join public.wpl_qg_runs r on r.id = f.run_id
                        where f.check_code = p_check
                        order by r.finished_at desc,
                                 case f.status when 'fail' then 0 when 'error' then 1 when 'warn' then 2 when 'skipped' then 3 else 4 end
                        limit 1) l on true
$$;
revoke all on function public.wpl_qg_check_last_internal(text) from public, anon, authenticated;

-- 적용 범위: 위험 항목마다 연결된 테스트 출처 — 스위트 + (23 이 만든) 공격 시나리오(깊이 attack)
create or replace function public.wpl_qg_testing_coverage_internal()
returns table(item_code text, source_kind text, source_code text, check_code text, depths jsonb)
language plpgsql stable security definer set search_path = public as $$
begin
  return query
    select x.code, 'suite'::text, s.code, s.check_code, s.depths
      from public.wpl_qg_test_suites s
      cross join lateral jsonb_array_elements_text(s.risk_items) ri(code)
      join public.wpl_qg_risk_items x on x.code = ri.code and x.active
     where s.active;
  if to_regclass('public.wpl_qg_scenarios') is not null then
    return query execute
      'select x.code, ''scenario''::text, sc.code, sc.check_code, ''["attack"]''::jsonb
         from public.wpl_qg_scenarios sc
         cross join lateral jsonb_array_elements_text(sc.risk_items) ri(code)
         join public.wpl_qg_risk_items x on x.code = ri.code and x.active
        where sc.active';
  end if;
end $$;
revoke all on function public.wpl_qg_testing_coverage_internal() from public, anon, authenticated;

create or replace function public.wpl_qg_probe_testing_coverage_gap(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; r record; v_grades jsonb := coalesce(p_check.params->'grades', '["critical","high"]'::jsonb); v_n int := 0;
begin
  for r in select i.code, i.name, i.target_kind, i.target_ref, i.impact, i.likelihood, public.wpl_qg_risk_grade_internal(i.impact, i.likelihood) g
             from public.wpl_qg_risk_items i where i.active order by i.impact * i.likelihood desc, i.code loop
    if not (v_grades ? r.g) then continue; end if;
    v_n := v_n + 1;
    if not exists (select 1 from public.wpl_qg_testing_coverage_internal() c where c.item_code = r.code) then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', r.g, 'fingerprint', 'item:' || r.code,
        'title', '테스트 없는 고위험 기능: ' || r.name,
        'detail', jsonb_build_object('item', r.code, 'target', r.target_kind || ':' || r.target_ref, 'impact', r.impact, 'likelihood', r.likelihood, 'grade', r.g,
          'message', '이 기능을 검증하는 스위트·시나리오가 연결되어 있지 않습니다.')));
    end if;
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('high_risk_items', v_n, 'message', format('고위험 기능 %s개 모두 테스트가 연결되어 있습니다.', v_n)));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_testing_coverage_gap(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_testing_depth_gap(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare req jsonb := public.wpl_qg_setting_internal('qg_risk_required_depth', '{"critical":["smoke","attack","e2e"],"high":["smoke","attack"],"medium":["smoke"],"low":["unit"]}'::jsonb);
        r record; v_have jsonb; v_missing jsonb; v_list jsonb := '[]'::jsonb; v_n int := 0;
begin
  for r in select i.code, i.name, public.wpl_qg_risk_grade_internal(i.impact, i.likelihood) g from public.wpl_qg_risk_items i where i.active order by i.impact * i.likelihood desc, i.code loop
    v_n := v_n + 1;
    select coalesce(jsonb_agg(distinct d), '[]'::jsonb) into v_have
      from public.wpl_qg_testing_coverage_internal() c cross join lateral jsonb_array_elements_text(c.depths) d where c.item_code = r.code;
    select coalesce(jsonb_agg(x), '[]'::jsonb) into v_missing from jsonb_array_elements_text(coalesce(req->r.g, '[]'::jsonb)) x where not (v_have ? x);
    if jsonb_array_length(v_missing) > 0 then
      v_list := v_list || jsonb_build_array(jsonb_build_object('item', r.code, 'name', r.name, 'grade', r.g, 'have', v_have, 'missing', v_missing));
    end if;
  end loop;
  if jsonb_array_length(v_list) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('items', v_n, 'message', format('위험 항목 %s개 모두 등급별 필요한 테스트 깊이를 갖췄습니다.', v_n)));
  end if;
  return jsonb_build_object('status', 'warn', 'severity', 'low', 'fingerprint', 'depth_gap',
    'title', format('테스트 깊이가 부족한 위험 항목 %s개', jsonb_array_length(v_list)),
    'detail', jsonb_build_object('items', v_n, 'gaps', v_list, 'required', req, 'message', '등급별로 갖춰야 할 테스트 종류 중 빠진 것이 있습니다.'));
end $$;
revoke all on function public.wpl_qg_probe_testing_depth_gap(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_testing_stale_pass(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_days int := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_testing_stale_days', '7'::jsonb) #>> '{}')::int, 7));
        v_out jsonb := '[]'::jsonb; r record; v_last jsonb; v_n int := 0;
begin
  for r in select c.source_kind, c.source_code, c.check_code, max(public.wpl_qg_sev_rank_internal(public.wpl_qg_risk_grade_internal(i.impact, i.likelihood))) as rk,
                  jsonb_agg(distinct i.code) as items
             from public.wpl_qg_testing_coverage_internal() c join public.wpl_qg_risk_items i on i.code = c.item_code
            group by 1, 2, 3 order by 3 loop
    if r.rk < 3 then continue; end if;
    v_n := v_n + 1;
    v_last := public.wpl_qg_check_last_internal(r.check_code);
    if v_last->>'at' is null then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', 'never:' || r.check_code,
        'title', '한 번도 실행되지 않은 고위험 테스트: ' || r.source_code,
        'detail', jsonb_build_object('check', r.check_code, 'source', r.source_kind, 'items', r.items, 'message', '실행 결과가 아직 올라온 적이 없습니다.')));
    elsif v_last->>'last_pass_at' is null or (v_last->>'last_pass_at')::timestamptz < now() - make_interval(days => v_days) then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', 'stale:' || r.check_code,
        'title', format('%s일 넘게 통과 기록이 없는 고위험 테스트: %s', v_days, r.source_code),
        'detail', jsonb_build_object('check', r.check_code, 'source', r.source_kind, 'items', r.items, 'last_pass_at', v_last->'last_pass_at', 'last_at', v_last->'at', 'days', v_days)));
    end if;
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('tests', v_n, 'days', v_days, 'message', format('고위험 테스트 %s개 모두 %s일 안에 통과했습니다.', v_n, v_days)));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_testing_stale_pass(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_testing_last_failed(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; r record; v_last jsonb; v_n int := 0; v_sev text;
begin
  for r in select c.source_kind, c.source_code, c.check_code, max(public.wpl_qg_sev_rank_internal(public.wpl_qg_risk_grade_internal(i.impact, i.likelihood))) as rk,
                  jsonb_agg(distinct i.code) as items
             from public.wpl_qg_testing_coverage_internal() c join public.wpl_qg_risk_items i on i.code = c.item_code
            group by 1, 2, 3 order by 3 loop
    v_last := public.wpl_qg_check_last_internal(r.check_code);
    if v_last->>'at' is null then continue; end if;
    v_n := v_n + 1;
    if v_last->>'status' in ('fail','error') then
      v_sev := case r.rk when 4 then 'critical' when 3 then 'high' when 2 then 'medium' else 'low' end;
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', v_sev, 'fingerprint', 'failed:' || r.check_code,
        'title', '마지막 실행이 실패한 테스트: ' || r.source_code,
        'detail', jsonb_build_object('check', r.check_code, 'source', r.source_kind, 'items', r.items, 'last_status', v_last->'status', 'last_at', v_last->'at', 'run_id', v_last->'run_id')));
    end if;
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('tests_with_results', v_n, 'message', format('결과가 있는 테스트 %s개 모두 마지막 실행이 통과입니다.', v_n)));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_testing_last_failed(public.wpl_qg_checks, uuid) from public, anon, authenticated;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('testing.coverage_gap', 'testing', '테스트 없는 고위험 기능',
  '위험 등급이 치명·높음인 기능(위험 항목)마다 검증하는 테스트 스위트나 공격 시나리오가 하나라도 연결되어 있는지 확인합니다.',
  'wpl_qg_probe_testing_coverage_gap', 'high', 'platform', 'daily', '{"grades":["critical","high"]}'::jsonb,
  '테스트 없는 고위험 기능 0개',
  '① 그 기능을 검증하는 스모크(supabase/tests/<번호>_<이름>_smoke.sql, 항상 rollback, 마지막에 SUMMARY passed=/failed= 행)를 만들고 ② 테스트 스위트 카탈로그에 등록하면서 위험 항목 코드를 연결하세요(검사 항목 suite:<파일> 도 함께). ③ node scripts/qg-run.mjs testing --files <파일> 로 결과를 올리세요.', 10),
 ('testing.depth_gap', 'testing', '등급별 테스트 깊이 부족',
  '위험 등급마다 필요한 테스트 종류(치명 = 스모크+공격+E2E, 높음 = 스모크+공격, 보통 = 스모크, 낮음 = 단위)를 연결된 스위트·시나리오가 갖췄는지 확인합니다.',
  'wpl_qg_probe_testing_depth_gap', 'medium', 'platform', 'daily', '{}'::jsonb,
  '깊이 부족 항목 0개',
  '결과 상세의 항목별 ''missing'' 종류를 채우세요: attack → supabase/tests/qg/adversarial_*.sql 시나리오, smoke → DB 스모크, unit → vitest, e2e → 화면 끝까지 테스트.', 20),
 ('testing.stale_pass', 'testing', '오래된 고위험 테스트',
  '치명·높음 위험 항목에 연결된 테스트마다 마지막 통과가 정책값(qg_testing_stale_days)보다 오래되었거나 한 번도 실행되지 않았는지 확인합니다.',
  'wpl_qg_probe_testing_stale_pass', 'medium', 'platform', 'daily', '{}'::jsonb,
  '오래되거나 실행 안 된 고위험 테스트 0개',
  'node scripts/qg-run.mjs testing 과 node scripts/qg-run.mjs adversarial 을 실행해 결과를 올리세요. 배포 전마다, 최소 주 1회.', 30),
 ('testing.last_failed', 'testing', '마지막 실행이 실패한 테스트',
  '위험 항목에 연결된 테스트 스위트·시나리오 중 마지막으로 올라온 결과가 실패·오류인 것을 찾습니다.',
  'wpl_qg_probe_testing_last_failed', 'high', 'platform', 'daily', '{}'::jsonb,
  '마지막 실행 실패 0개',
  '① 실행 결과 화면에서 실패한 단계(step)와 메시지를 확인하세요. ② 기능 회귀면 코드를 고치고, 기대값 변화면 스모크 기대값을 사유와 함께 갱신하세요. ③ 다시 실행해 통과하면 다음 매일 실행에서 자동 확인됩니다.', 40),
 ('testing.suite_qg_smoke', 'testing', 'QG 스모크(품질·거버넌스 척추·엔진)',
  'QG 키트 스모크(항상 rollback): 권한·추가 전용·probe 허용 목록·이슈 상태 머신·증거 체인·엔진 10종·출시 관문·보안 불변식.',
  'suite:supabase/tests/20261027120000_wpl_qg_smoke.sql', 'high', 'platform', 'release', '{}'::jsonb, '모든 단계 통과(failed=0)',
  '실행 결과의 실패 단계와 메시지를 확인해 원인을 고치세요. 다시 실행: node scripts/qg-run.mjs testing --files 20261027120000_wpl_qg_smoke.sql', 100),
 ('testing.suite_vitest', 'testing', '단위 테스트(vitest)',
  'src/**/*.test.ts 전체(화면 문구·규칙·계산·외부 장애 대체 동작). 저장소에 vitest 가 없으면 이 항목을 끄세요.',
  'suite:vitest', 'medium', 'platform', 'release', '{}'::jsonb, '모든 테스트 통과',
  'npx vitest run 으로 실패한 테스트를 확인해 고치세요.', 110),
 ('testing.suite_registry', 'testing', '등록 안 된 테스트 파일',
  'scripts/qg-run.mjs testing 이 supabase/tests 폴더의 *.sql 과 테스트 스위트 카탈로그를 대조해, 등록되지 않아 위험 항목과 연결되지 않은 파일을 알려 줍니다.',
  'suite:supabase/tests', 'low', 'platform', 'release', '{}'::jsonb, '등록 안 된 파일 0개',
  '검사 항목 testing.suite_<코드>(실행 방법 suite:supabase/tests/<파일>)를 추가하고 테스트 스위트 카탈로그에 같은 파일을 등록해 위험 항목을 연결하세요.', 99)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
  schedule = excluded.schedule, params = excluded.params, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort, engine_code = excluded.engine_code;

-- 시드: QG 자신의 위험 항목(플랫폼 위험 항목은 설치 뒤 카탈로그에 더한다)
insert into public.wpl_qg_risk_items(code, name, description, target_kind, target_ref, impact, likelihood, sort) values
 ('qg_center', '품질·거버넌스 센터', '실행기·이슈 상태 머신·증거 체인·외부 결과 올리기·출시 관문.', 'module', 'qg', 4, 2, 900),
 ('qg_anon_surface', '익명 공격면(QG 입구)', '로그인 없이 QG 함수·표에 닿을 수 있는지(익명 실행·서버 증명키 위조·대용량 입력).', 'capability', 'anon', 4, 3, 910)
on conflict (code) do nothing;

insert into public.wpl_qg_test_suites(code, name, kind, path, depths, check_code, risk_items, description, sort) values
 ('qg_smoke', 'QG 스모크(품질·거버넌스 척추·엔진)', 'sql', 'supabase/tests/20261027120000_wpl_qg_smoke.sql', '["smoke","attack"]', 'testing.suite_qg_smoke', '["qg_center","qg_anon_surface"]', null, 900),
 ('vitest', '단위 테스트(vitest)', 'vitest', 'vitest', '["unit"]', 'testing.suite_vitest', '["qg_center"]', null, 910)
on conflict (code) do nothing;
