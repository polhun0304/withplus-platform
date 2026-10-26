-- QG 키트 1.1.0 · 접두어 wpl · evolution — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
-- =====================================================================
-- QG 키트 41 — 개선사항 분석·개발 제안 엔진(evolution) (원본: F-MATRIX 2932)
--  신호 수집 probe → 결과(finding.detail.proposal) → 트리거가 개선 제안(wpl_qg_proposals)을 지문으로 중복 없이 만들거나 신호를 더한다.
--  · 우선순위 = 도달^a × 영향^b × (확신/100)^c ÷ 노력^d × 10 (계수 = QG 설정 qg_evo_weights)
--  · 상태: proposed → accepted → in_progress → shipped → verified / declined(사유) — 전이는 RPC 만, 이력은 추가 전용
--  · 키트 기본 신호 2종(반복 이슈·실패 테스트)은 QG 표만 본다. 플랫폼 업무 신호(요청 취소·점수 하락·미사용 메뉴 등)는
--    같은 규약으로 플랫폼 파일에 더한다(QG_KIT.md §5.6). 신호 결과는 status 'pass' + detail.signal = true(이슈함에 안 올라감).
--  · 개발 지시서(마크다운)는 화면(lib/qg/evolution.ts)에서 만든다.
-- =====================================================================

insert into public.wpl_qg_settings(key, value, label, description) values
 ('qg_evo_weights', '{"reach":1,"impact":1,"confidence":1,"effort":1}', '품질·거버넌스: 개선 제안 우선순위 계수',
  '우선순위 = 도달^reach × 영향^impact × (확신/100)^confidence ÷ 노력^effort × 10. 값을 키우면 그 요소가 더 크게 작용합니다(0 이면 무시). JSON 객체.'),
 ('qg_evo_signal_defaults', '{"recurring_issue":{"impact":3,"confidence":80,"effort":3},"failing_test":{"impact":3,"confidence":70,"effort":2},"manual":{"impact":3,"confidence":50,"effort":3}}',
  '품질·거버넌스: 신호 종류별 기본 영향·확신·노력',
  '자동으로 만든 개선 제안의 처음 값(영향 1~5, 확신 0~100%, 노력 = 사람·일). 플랫폼 신호 종류를 더하면 여기에도 기본값을 넣으세요. JSON 객체.'),
 ('qg_evo_severity_impact', '{"critical":5,"high":4,"medium":3,"low":2}', '품질·거버넌스: 이슈 심각도 → 제안 영향(1~5)', '반복 이슈에서 만든 개선 제안의 영향 점수입니다. JSON 객체.'),
 ('qg_evo_recurring_min', '3', '품질·거버넌스: 반복 이슈로 볼 최소 발견 횟수', '같은 지문의 이슈가 이 횟수 이상 발견되면 근본 해결 제안을 만듭니다.'),
 ('qg_evo_test_window_days', '7', '품질·거버넌스: 실패 테스트 신호 기간(일)', '최근 이 기간 안에 실패·오류가 난 테스트·시나리오로 개선 제안을 만듭니다.'),
 ('qg_evo_decline_min_len', '5', '품질·거버넌스: 개선 제안 거절 사유 최소 글자 수', '개선 제안을 거절할 때 적어야 하는 사유의 최소 글자 수입니다.')
on conflict (key) do nothing;

create table if not exists public.wpl_qg_proposals (
  id uuid primary key default gen_random_uuid(),
  prop_no bigint generated always as identity unique,
  fingerprint text not null unique check (char_length(fingerprint) between 3 and 300),
  source text not null check (source ~ '^[a-z][a-z0-9_]{1,39}$'),
  title text not null check (char_length(title) between 2 and 200),
  problem text not null check (char_length(problem) between 2 and 4000),
  scope text check (scope is null or char_length(scope) <= 4000),
  acceptance text check (acceptance is null or char_length(acceptance) <= 4000),
  verification text check (verification is null or char_length(verification) <= 4000),
  signals jsonb not null default '[]'::jsonb check (jsonb_typeof(signals) = 'array'),
  signal_count int not null default 1 check (signal_count >= 0),
  first_signal_at timestamptz not null default now(),
  last_signal_at timestamptz not null default now(),
  reach numeric not null default 1 check (reach >= 0 and reach <= 1000000),
  impact int not null default 3 check (impact between 1 and 5),
  confidence int not null default 50 check (confidence between 0 and 100),
  effort numeric not null default 3 check (effort > 0 and effort <= 1000),
  priority_score numeric not null default 0,
  status text not null default 'proposed' check (status in ('proposed','accepted','in_progress','shipped','verified','declined')),
  decline_reason text,
  linked_issue_ids uuid[] not null default '{}',
  linked_release_id uuid references public.wpl_qg_releases(id),
  tenant_id uuid,
  engine_code text,
  check_code text,
  created_by uuid,
  status_changed_at timestamptz not null default now(),
  status_changed_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists wpl_qg_proposals_status_idx on public.wpl_qg_proposals(status, priority_score desc);

create table if not exists public.wpl_qg_proposal_events (
  id bigint generated always as identity primary key,
  proposal_id uuid not null references public.wpl_qg_proposals(id),
  action text not null check (action in ('create','signal','transition','edit')),
  from_status text,
  to_status text,
  note text,
  detail jsonb,
  actor uuid,
  created_at timestamptz not null default now()
);
create index if not exists wpl_qg_proposal_events_idx on public.wpl_qg_proposal_events(proposal_id, id desc);

drop trigger if exists wpl_qg_proposals_guard on public.wpl_qg_proposals;
create trigger wpl_qg_proposals_guard before update or delete on public.wpl_qg_proposals for each row execute function public.wpl_qg_state_guard();
drop trigger if exists wpl_qg_proposal_events_no_mutation on public.wpl_qg_proposal_events;
create trigger wpl_qg_proposal_events_no_mutation before update or delete on public.wpl_qg_proposal_events for each row execute function public.wpl_qg_forbid_mutation();
drop trigger if exists wpl_qg_proposal_events_no_truncate on public.wpl_qg_proposal_events;
create trigger wpl_qg_proposal_events_no_truncate before truncate on public.wpl_qg_proposal_events for each statement execute function public.wpl_qg_forbid_mutation();

do $$ declare t text; begin
  foreach t in array array['wpl_qg_proposals','wpl_qg_proposal_events'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists %I on public.%I', t || '_read', t);
    execute format('create policy %I on public.%I for select to authenticated using (public.wpl_qga_is_admin())', t || '_read', t);
    execute format('drop policy if exists %I on public.%I', t || '_no_delete', t);
    execute format('create policy %I on public.%I as restrictive for delete to authenticated, anon using (false)', t || '_no_delete', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
  end loop;
end $$;

create or replace function public.wpl_qg_evo_priority_internal(p_reach numeric, p_impact int, p_conf int, p_effort numeric) returns numeric
language plpgsql stable security definer set search_path = public as $$
declare w jsonb := public.wpl_qg_setting_internal('qg_evo_weights', '{"reach":1,"impact":1,"confidence":1,"effort":1}'::jsonb);
        a numeric := coalesce((w->>'reach')::numeric, 1); b numeric := coalesce((w->>'impact')::numeric, 1);
        c numeric := coalesce((w->>'confidence')::numeric, 1); d numeric := coalesce((w->>'effort')::numeric, 1);
begin
  return round((power(greatest(coalesce(p_reach, 1), 1), a) * power(greatest(coalesce(p_impact, 1), 1), b)
                * power(greatest(coalesce(p_conf, 0), 1) / 100.0, c)) / power(greatest(coalesce(p_effort, 1), 0.5), d) * 10, 2);
exception when others then
  return round(greatest(coalesce(p_reach, 1), 1) * greatest(coalesce(p_impact, 1), 1) * greatest(coalesce(p_conf, 0), 1) / 100.0 / greatest(coalesce(p_effort, 1), 0.5) * 10, 2);
end $$;
revoke all on function public.wpl_qg_evo_priority_internal(numeric, int, int, numeric) from public, anon, authenticated;

create or replace function public.wpl_qg_evo_default_internal(p_source text, p_key text, p_default numeric) returns numeric
language sql stable security definer set search_path = public as $$
  select coalesce((public.wpl_qg_setting_internal('qg_evo_signal_defaults', '{}'::jsonb) -> p_source ->> p_key)::numeric, p_default)
$$;
revoke all on function public.wpl_qg_evo_default_internal(text, text, numeric) from public, anon, authenticated;

create or replace function public.wpl_qg_evo_num_setting_internal(p_key text, p_default numeric) returns numeric
language sql stable security definer set search_path = public as $$
  select coalesce((public.wpl_qg_setting_internal(p_key, to_jsonb(p_default)) #>> '{}')::numeric, p_default)
$$;
revoke all on function public.wpl_qg_evo_num_setting_internal(text, numeric) from public, anon, authenticated;

create or replace function public.wpl_qg_proposal_status_ko_internal(p text) returns text
language sql immutable set search_path = public as $$
  select case p when 'proposed' then '제안' when 'accepted' then '채택' when 'in_progress' then '진행 중' when 'shipped' then '출시됨'
                when 'verified' then '효과 확인' when 'declined' then '거절' else coalesce(p, '-') end
$$;
revoke all on function public.wpl_qg_proposal_status_ko_internal(text) from public, anon, authenticated;

create or replace function public.wpl_qg_proposal_allowed_internal(p_from text, p_to text) returns boolean
language sql immutable set search_path = public as $$
  select case p_from
    when 'proposed' then p_to in ('accepted','declined')
    when 'accepted' then p_to in ('in_progress','declined','proposed')
    when 'in_progress' then p_to in ('shipped','accepted','declined')
    when 'shipped' then p_to in ('verified','in_progress')
    when 'verified' then p_to = 'in_progress'
    when 'declined' then p_to = 'proposed'
    else false end
$$;
revoke all on function public.wpl_qg_proposal_allowed_internal(text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_proposal_event_internal(p_id uuid, p_action text, p_from text, p_to text, p_note text, p_detail jsonb)
returns void language sql security definer set search_path = public as $$
  insert into public.wpl_qg_proposal_events(proposal_id, action, from_status, to_status, note, detail, actor)
  values (p_id, p_action, p_from, p_to, left(p_note, 2000), p_detail, auth.uid())
$$;
revoke all on function public.wpl_qg_proposal_event_internal(uuid, text, text, text, text, jsonb) from public, anon, authenticated;

-- p: {fingerprint, source, title, problem, scope?, acceptance?, verification?, reach?, impact?, confidence?, effort?, tenant_id?, engine_code?, check_code?, issue_ids?[], signal?{…}}
create or replace function public.wpl_qg_proposal_upsert_internal(p jsonb, p_run uuid, p_finding uuid, p_evidence uuid)
returns uuid language plpgsql security definer set search_path = public as $$
declare pr public.wpl_qg_proposals; v_src text := coalesce(nullif(p->>'source', ''), 'manual'); v_fp text := left(nullif(p->>'fingerprint', ''), 300);
        v_sig jsonb; v_prev text := coalesce(current_setting('wpl.qg_write', true), ''); v_issues uuid[]; v_reach numeric; v_imp int; v_conf int; v_eff numeric; v_tenant uuid;
begin
  if v_fp is null or char_length(v_fp) < 3 then return null; end if;
  if v_src !~ '^[a-z][a-z0-9_]{1,39}$' then v_src := 'manual'; end if;
  v_sig := jsonb_build_object('at', now(), 'run_id', p_run, 'finding_id', p_finding, 'evidence_id', p_evidence, 'summary', coalesce(p->'signal', '{}'::jsonb));
  select coalesce(array_agg(distinct x::uuid), '{}') into v_issues from jsonb_array_elements_text(coalesce(p->'issue_ids', '[]'::jsonb)) x where x ~* '^[0-9a-f-]{36}$';
  begin
    v_reach := greatest(0, least(1000000, coalesce((p->>'reach')::numeric, 1)));
    v_imp := greatest(1, least(5, coalesce((p->>'impact')::int, public.wpl_qg_evo_default_internal(v_src, 'impact', 3)::int)));
    v_conf := greatest(0, least(100, coalesce((p->>'confidence')::int, public.wpl_qg_evo_default_internal(v_src, 'confidence', 50)::int)));
    v_eff := greatest(0.5, least(1000, coalesce((p->>'effort')::numeric, public.wpl_qg_evo_default_internal(v_src, 'effort', 3))));
  exception when others then
    v_reach := 1; v_imp := 3; v_conf := 50; v_eff := 3;
  end;
  begin v_tenant := nullif(p->>'tenant_id', '')::uuid; exception when others then v_tenant := null; end;

  perform set_config('wpl.qg_write', 'on', true);
  select * into pr from public.wpl_qg_proposals where fingerprint = v_fp for update;
  if pr.id is null then
    insert into public.wpl_qg_proposals(fingerprint, source, title, problem, scope, acceptance, verification, signals, signal_count, reach, impact, confidence, effort,
                                        priority_score, linked_issue_ids, tenant_id, engine_code, check_code, created_by)
    values (v_fp, v_src, left(coalesce(nullif(p->>'title', ''), '개선 제안'), 200), left(coalesce(nullif(p->>'problem', ''), '(신호에서 자동 생성)'), 4000),
            left(p->>'scope', 4000), left(p->>'acceptance', 4000), left(p->>'verification', 4000), jsonb_build_array(v_sig), 1, v_reach, v_imp, v_conf, v_eff,
            public.wpl_qg_evo_priority_internal(v_reach, v_imp, v_conf, v_eff), v_issues, v_tenant, nullif(p->>'engine_code', ''), nullif(p->>'check_code', ''), auth.uid())
    returning * into pr;
    perform public.wpl_qg_proposal_event_internal(pr.id, 'create', null, 'proposed', null, jsonb_build_object('run_id', p_run, 'source', v_src));
  else
    update public.wpl_qg_proposals
       set signals = (select coalesce(jsonb_agg(e order by o), '[]'::jsonb) from (select e, o from jsonb_array_elements(signals || jsonb_build_array(v_sig)) with ordinality t(e, o)
                                                                                   order by o desc limit 20) z),
           signal_count = signal_count + 1, last_signal_at = now(),
           linked_issue_ids = (select coalesce(array_agg(distinct x), '{}') from unnest(linked_issue_ids || v_issues) x),
           reach = case when status = 'proposed' then greatest(reach, v_reach) else reach end,
           problem = case when status = 'proposed' and nullif(p->>'problem', '') is not null then left(p->>'problem', 4000) else problem end,
           priority_score = public.wpl_qg_evo_priority_internal(case when status = 'proposed' then greatest(reach, v_reach) else reach end, impact, confidence, effort)
     where id = pr.id;
    perform public.wpl_qg_proposal_event_internal(pr.id, 'signal', pr.status, pr.status, null, jsonb_build_object('run_id', p_run, 'finding_id', p_finding));
  end if;
  perform set_config('wpl.qg_write', v_prev, true);
  return pr.id;
end $$;
revoke all on function public.wpl_qg_proposal_upsert_internal(jsonb, uuid, uuid, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_findings_evolution_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.engine_code = 'evolution' and jsonb_typeof(new.detail->'proposal') = 'object' then
    perform public.wpl_qg_proposal_upsert_internal(new.detail->'proposal', new.run_id, new.id, new.evidence_id);
  end if;
  return null;
end $$;
revoke all on function public.wpl_qg_findings_evolution_trg() from public, anon, authenticated;
drop trigger if exists wpl_qg_findings_evolution_ai on public.wpl_qg_findings;
create trigger wpl_qg_findings_evolution_ai after insert on public.wpl_qg_findings for each row
  when (new.engine_code = 'evolution') execute function public.wpl_qg_findings_evolution_trg();

-- 신호 (a) 같은 지문 이슈가 N회↑ 발견
create or replace function public.wpl_qg_probe_evo_recurring_issue(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb; v_min int := greatest(2, public.wpl_qg_evo_num_setting_internal('qg_evo_recurring_min', 3)::int);
        v_lim int := greatest(1, coalesce((p_check.params->>'limit')::int, 50));
        v_sevmap jsonb := public.wpl_qg_setting_internal('qg_evo_severity_impact', '{"critical":5,"high":4,"medium":3,"low":2}'::jsonb);
begin
  select coalesce(jsonb_agg(jsonb_build_object('status', 'pass', 'fingerprint', 'recurring:' || md5(i.fingerprint),
    'title', '개선 신호: 반복 이슈 ' || i.occurrences || '회 — ' || left(i.title, 120),
    'detail', jsonb_build_object('signal', true, 'issue_id', i.id, 'occurrences', i.occurrences,
      'proposal', jsonb_build_object(
        'fingerprint', 'recurring_issue:' || md5(i.fingerprint), 'source', 'recurring_issue',
        'title', left('반복되는 문제 근본 해결: ' || i.title, 200),
        'problem', format('같은 문제가 %s번 발견됐습니다(처음 %s, 마지막 %s, 지금 상태: %s, 심각도: %s). 고쳐도 다시 나오거나, 처리되지 않은 채 계속 쌓이고 있습니다.',
                          i.occurrences, to_char(i.first_seen at time zone 'Asia/Seoul', 'YYYY-MM-DD'), to_char(i.last_seen at time zone 'Asia/Seoul', 'YYYY-MM-DD'),
                          public.wpl_qg_status_ko_internal(i.status), case i.severity when 'critical' then '치명' when 'high' then '높음' when 'medium' then '보통' else '낮음' end),
        'scope', '검사 ' || i.check_code || '(' || coalesce(c.name, '') || ')가 잡는 원인 지점. ' || coalesce('조치 안내: ' || c.remediation, ''),
        'acceptance', '같은 검사를 다시 실행했을 때 이 문제가 나오지 않고(이슈가 ''확인됨''), 이후 7일 동안 다시 나오지 않는다.',
        'verification', '품질·거버넌스 센터에서 ''' || coalesce(g.name, i.engine_code) || ''' 엔진 지금 실행 → 이슈함에서 이 이슈가 ''확인됨''인지 확인.',
        'reach', i.occurrences, 'impact', coalesce((v_sevmap->>i.severity)::int, 3),
        'tenant_id', i.tenant_id, 'engine_code', i.engine_code, 'check_code', i.check_code, 'issue_ids', jsonb_build_array(i.id),
        'signal', jsonb_build_object('kind', 'recurring_issue', 'issue_id', i.id, 'occurrences', i.occurrences, 'status', i.status, 'severity', i.severity))))
    order by i.occurrences desc), '[]'::jsonb)
    into v
    from (select * from public.wpl_qg_issues q where q.occurrences >= v_min and q.status <> 'false_positive' and q.engine_code <> 'evolution'
           order by q.occurrences desc, q.last_seen desc limit v_lim) i
    left join public.wpl_qg_checks c on c.code = i.check_code
    left join public.wpl_qg_engines g on g.code = i.engine_code;
  return v;
end $$;
revoke all on function public.wpl_qg_probe_evo_recurring_issue(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 신호 (b) 최근 N일 실패·오류가 난 테스트·시나리오
create or replace function public.wpl_qg_probe_evo_failing_test(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb; v_days int := greatest(1, public.wpl_qg_evo_num_setting_internal('qg_evo_test_window_days', 7)::int);
        v_engines text[] := coalesce((select array_agg(x) from jsonb_array_elements_text(p_check.params->'engines') x), array['testing','adversarial']);
begin
  select coalesce(jsonb_agg(jsonb_build_object('status', 'pass', 'fingerprint', 'failing:' || f.check_code,
    'title', '개선 신호: 최근 ' || v_days || '일 실패 ' || f.n || '건 — ' || coalesce(c.name, f.check_code),
    'detail', jsonb_build_object('signal', true, 'check_code', f.check_code, 'failures', f.n,
      'proposal', jsonb_build_object(
        'fingerprint', 'failing_test:' || f.check_code, 'source', 'failing_test',
        'title', left('실패하는 테스트 바로잡기: ' || coalesce(c.name, f.check_code), 200),
        'problem', format('최근 %s일 동안 ''%s'' 검사가 실패·오류 %s건(실행 %s번)을 냈습니다. 마지막 실패: %s. 기능 결함이거나 테스트 기대값이 낡았을 수 있습니다.',
                          v_days, coalesce(c.name, f.check_code), f.n, f.runs, to_char(f.last_at at time zone 'Asia/Seoul', 'YYYY-MM-DD HH24:MI')),
        'scope', '검사 ' || f.check_code || coalesce(' (실행 방법: ' || c.probe || ')', '') || ' 가 확인하는 기능과 그 테스트. ' || coalesce('조치 안내: ' || c.remediation, ''),
        'acceptance', '같은 테스트·시나리오를 다시 실행해 실패·오류 0건, 다음 7일 동안 실패 0건.',
        'verification', coalesce(case when c.probe like 'suite:%' then substr(c.probe, 7) || ' 를 rollback 으로 실행 → SUMMARY failed=0 확인 후 scripts/qg-run.mjs 로 결과 올리기' end,
                                 '품질·거버넌스 센터에서 해당 엔진 지금 실행 → 실행 결과에서 이 검사 통과 확인'),
        'reach', f.n, 'engine_code', c.engine_code, 'check_code', f.check_code,
        'issue_ids', coalesce(f.issue_ids, '[]'::jsonb),
        'signal', jsonb_build_object('kind', 'failing_test', 'check_code', f.check_code, 'failures', f.n, 'runs', f.runs, 'last_at', f.last_at))))
    order by f.n desc), '[]'::jsonb)
    into v
    from (select x.check_code, count(*) n, count(distinct x.run_id) runs, max(x.created_at) last_at,
                 jsonb_agg(distinct x.issue_id) filter (where x.issue_id is not null) issue_ids
            from public.wpl_qg_findings x
           where x.created_at > now() - make_interval(days => v_days) and x.status in ('fail','error') and x.engine_code = any(v_engines)
           group by x.check_code) f
    left join public.wpl_qg_checks c on c.code = f.check_code;
  return v;
end $$;
revoke all on function public.wpl_qg_probe_evo_failing_test(public.wpl_qg_checks, uuid) from public, anon, authenticated;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('evolution.recurring_issue', 'evolution', '반복 이슈 신호', '같은 지문의 이슈가 정해진 횟수(qg_evo_recurring_min) 이상 발견된 것을 근본 해결 제안으로 만듭니다.',
  'wpl_qg_probe_evo_recurring_issue', 'low', 'platform', 'daily', '{"limit":50}'::jsonb, '신호는 개선 제안 보드로 갑니다(이슈 아님)',
  '개선 제안 보드에서 우선순위를 보고 채택·거절하세요. 채택하면 개발 지시서를 내보내 작업을 맡깁니다.', 10),
 ('evolution.failing_test', 'evolution', '실패 테스트 신호', '최근 7일(qg_evo_test_window_days) 위험도별 테스트·공격 시뮬레이션에서 실패·오류가 난 검사를 개선 제안으로 만듭니다.',
  'wpl_qg_probe_evo_failing_test', 'low', 'platform', 'daily', '{"engines":["testing","adversarial"]}'::jsonb, '신호는 개선 제안 보드로 갑니다(이슈 아님)',
  '개선 제안 보드에서 채택하고 지시서를 내보내세요.', 20)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
  schedule = excluded.schedule, params = excluded.params, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort;

-- ───────── RPC(관리자) ─────────
create or replace function public.wpl_qg_evolution_collect()
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_run uuid; v_new int; v_upd int;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '개선 신호 모으기는 관리자만 할 수 있습니다.'; end if;
  v_run := public.wpl_qg_run_engine_internal('evolution', null, 'manual', null, auth.uid(), '{}'::jsonb);
  select count(*) filter (where action = 'create'), count(*) filter (where action = 'signal') into v_new, v_upd
    from public.wpl_qg_proposal_events where detail->>'run_id' = v_run::text;
  perform public.wpl_qga_audit(null, 'user', 'qg.evolution.collect', 'wpl_qg_runs', v_run::text, jsonb_build_object('created', v_new, 'updated', v_upd));
  return jsonb_build_object('ok', true, 'run_id', v_run, 'created', v_new, 'updated', v_upd);
end $$;
revoke all on function public.wpl_qg_evolution_collect() from public, anon, authenticated;
grant execute on function public.wpl_qg_evolution_collect() to authenticated;

create or replace function public.wpl_qg_proposal_create(p jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_id uuid; v_title text := trim(coalesce(p->>'title', '')); v_problem text := trim(coalesce(p->>'problem', ''));
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '개선 제안은 관리자만 추가할 수 있습니다.'; end if;
  if char_length(v_title) < 2 or char_length(v_title) > 200 then raise exception '제목을 2~200자로 적어 주세요.'; end if;
  if char_length(v_problem) < 2 then raise exception '어떤 문제인지 적어 주세요.'; end if;
  v_id := public.wpl_qg_proposal_upsert_internal(jsonb_build_object('fingerprint', 'manual:' || gen_random_uuid()::text, 'source', 'manual',
            'title', v_title, 'problem', v_problem, 'scope', nullif(trim(coalesce(p->>'scope', '')), ''), 'acceptance', nullif(trim(coalesce(p->>'acceptance', '')), ''),
            'verification', nullif(trim(coalesce(p->>'verification', '')), ''), 'reach', p->'reach', 'impact', p->'impact', 'confidence', p->'confidence', 'effort', p->'effort',
            'signal', jsonb_build_object('kind', 'manual', 'by', auth.uid())), null, null, null);
  perform public.wpl_qga_audit(null, 'user', 'qg.proposal.create', 'wpl_qg_proposals', v_id::text, jsonb_build_object('title', v_title));
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;
revoke all on function public.wpl_qg_proposal_create(jsonb) from public, anon, authenticated;
grant execute on function public.wpl_qg_proposal_create(jsonb) to authenticated;

create or replace function public.wpl_qg_proposal_update(p_id uuid, p_patch jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare pr public.wpl_qg_proposals; v_reach numeric; v_imp int; v_conf int; v_eff numeric; k text;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '개선 제안은 관리자만 고칠 수 있습니다.'; end if;
  if p_patch is null or jsonb_typeof(p_patch) <> 'object' then raise exception '고칠 값이 없습니다.'; end if;
  for k in select jsonb_object_keys(p_patch) loop
    if k not in ('title','problem','scope','acceptance','verification','reach','impact','confidence','effort') then raise exception '고칠 수 없는 칸입니다: %', left(k, 40); end if;
  end loop;
  select * into pr from public.wpl_qg_proposals where id = p_id for update;
  if pr.id is null then raise exception '개선 제안을 찾을 수 없습니다.'; end if;
  if pr.status not in ('proposed','accepted','in_progress') then raise exception '지금 상태(%)에서는 고칠 수 없습니다.', public.wpl_qg_proposal_status_ko_internal(pr.status); end if;
  begin
    v_reach := coalesce((p_patch->>'reach')::numeric, pr.reach); v_imp := coalesce((p_patch->>'impact')::int, pr.impact);
    v_conf := coalesce((p_patch->>'confidence')::int, pr.confidence); v_eff := coalesce((p_patch->>'effort')::numeric, pr.effort);
  exception when others then raise exception '도달·영향·확신·노력은 숫자로 넣어 주세요.'; end;
  if v_reach < 0 or v_reach > 1000000 then raise exception '도달은 0 이상으로 넣어 주세요.'; end if;
  if v_imp not between 1 and 5 then raise exception '영향은 1~5 중에서 골라 주세요.'; end if;
  if v_conf not between 0 and 100 then raise exception '확신은 0~100%% 사이로 넣어 주세요.'; end if;
  if v_eff <= 0 or v_eff > 1000 then raise exception '노력(사람·일)은 0보다 크게 넣어 주세요.'; end if;
  if p_patch ? 'title' and char_length(trim(coalesce(p_patch->>'title', ''))) not between 2 and 200 then raise exception '제목을 2~200자로 적어 주세요.'; end if;
  if p_patch ? 'problem' and char_length(trim(coalesce(p_patch->>'problem', ''))) < 2 then raise exception '문제 설명을 적어 주세요.'; end if;
  perform set_config('wpl.qg_write', 'on', true);
  update public.wpl_qg_proposals set
    title = case when p_patch ? 'title' then trim(p_patch->>'title') else title end,
    problem = case when p_patch ? 'problem' then left(trim(p_patch->>'problem'), 4000) else problem end,
    scope = case when p_patch ? 'scope' then left(nullif(trim(coalesce(p_patch->>'scope', '')), ''), 4000) else scope end,
    acceptance = case when p_patch ? 'acceptance' then left(nullif(trim(coalesce(p_patch->>'acceptance', '')), ''), 4000) else acceptance end,
    verification = case when p_patch ? 'verification' then left(nullif(trim(coalesce(p_patch->>'verification', '')), ''), 4000) else verification end,
    reach = v_reach, impact = v_imp, confidence = v_conf, effort = v_eff,
    priority_score = public.wpl_qg_evo_priority_internal(v_reach, v_imp, v_conf, v_eff)
   where id = pr.id;
  perform public.wpl_qg_proposal_event_internal(pr.id, 'edit', pr.status, pr.status, null, p_patch);
  perform set_config('wpl.qg_write', '', true);
  return jsonb_build_object('ok', true, 'priority_score', public.wpl_qg_evo_priority_internal(v_reach, v_imp, v_conf, v_eff));
end $$;
revoke all on function public.wpl_qg_proposal_update(uuid, jsonb) from public, anon, authenticated;
grant execute on function public.wpl_qg_proposal_update(uuid, jsonb) to authenticated;

create or replace function public.wpl_qg_proposal_transition(p_id uuid, p_to text, p_note text default null, p_release uuid default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare pr public.wpl_qg_proposals; v_note text := nullif(trim(coalesce(p_note, '')), ''); v_min int;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '개선 제안 상태는 관리자만 바꿀 수 있습니다.'; end if;
  select * into pr from public.wpl_qg_proposals where id = p_id for update;
  if pr.id is null then raise exception '개선 제안을 찾을 수 없습니다.'; end if;
  if p_to is null or not public.wpl_qg_proposal_allowed_internal(pr.status, p_to) then
    raise exception '지금 상태(%)에서 ''%''(으)로 바꿀 수 없습니다.', public.wpl_qg_proposal_status_ko_internal(pr.status), public.wpl_qg_proposal_status_ko_internal(p_to);
  end if;
  if v_note is not null and char_length(v_note) > 2000 then raise exception '메모는 2,000자 이하로 적어 주세요.'; end if;
  if p_to = 'declined' then
    v_min := greatest(1, public.wpl_qg_evo_num_setting_internal('qg_evo_decline_min_len', 5)::int);
    if char_length(coalesce(v_note, '')) < v_min then raise exception '거절하려면 사유를 %자 이상 적어 주세요(왜 하지 않는지).', v_min; end if;
  end if;
  if p_release is not null and not exists (select 1 from public.wpl_qg_releases where id = p_release) then raise exception '연결할 출시 후보를 찾을 수 없습니다.'; end if;
  perform set_config('wpl.qg_write', 'on', true);
  update public.wpl_qg_proposals set status = p_to, status_changed_at = now(), status_changed_by = auth.uid(),
         decline_reason = case when p_to = 'declined' then v_note when p_to = 'proposed' then null else decline_reason end,
         linked_release_id = coalesce(p_release, linked_release_id)
   where id = pr.id;
  perform public.wpl_qg_proposal_event_internal(pr.id, 'transition', pr.status, p_to, v_note, case when p_release is null then null else jsonb_build_object('release_id', p_release) end);
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(pr.tenant_id, 'user', 'qg.proposal.transition', 'wpl_qg_proposals', pr.id::text,
    jsonb_build_object('from', pr.status, 'to', p_to, 'note', v_note, 'release_id', p_release));
  return jsonb_build_object('ok', true, 'status', p_to);
end $$;
revoke all on function public.wpl_qg_proposal_transition(uuid, text, text, uuid) from public, anon, authenticated;
grant execute on function public.wpl_qg_proposal_transition(uuid, text, text, uuid) to authenticated;
