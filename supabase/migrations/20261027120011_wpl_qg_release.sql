-- QG 키트 1.1.0 · 접두어 wpl · release — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
-- =====================================================================
-- QG 키트 40 — 출시 승인·차단 엔진(release) (원본: F-MATRIX 2930·2931)
--  출시 후보 → 관문 정책(카탈로그)으로 조건별 판정(passed/blocked) → 다른 관리자 승인(요청자 본인 불가) → 출시
--  (코드 배포 = 배포 READY·SHA 일치 기록 / 플랫폼 출시 함수 = 훅이 자동 연결 / 그 밖 = 출시 완료 기록).
--
--  · wpl_qg_gate_policies  카탈로그: 출시 종류(kind)별 필수 조건. 기본 종류 code_deploy·policy_change.
--                            플랫폼 종류(예: pack_release·tenant_golive)는 행을 더하면 되고, 강제 스위치 qg_enforce_<종류>(false)가 자동으로 생긴다.
--  · wpl_qg_releases       상태 표: candidate → checking → passed/blocked → approved/rejected → released (RPC 만, 지우기 금지)
--  · wpl_qg_release_events 추가 전용(이력)
--  · 대상 확인: code_deploy = 커밋 SHA, 그 밖은 어댑터 wpl_qga_release_target(kind, ref) → 없으면 policy_change = QG 설정 키.
--  · 훅: 플랫폼 출시 함수의 권한 확인 바로 뒤에 한 줄 — perform public.wpl_qg_release_gate_hook_internal('<종류>', <대상 ref>);
--        qg_enforce_<종류> = false(기본)면 승인된 후보가 있으면 출시 완료로 연결만 하고(실패해도 무시) 원래 동작 그대로.
--        true 면 승인된(유효한) 후보가 없을 때 사람 말로 거부.
--  두 번 적용해도 같은 결과.
-- =====================================================================

insert into public.wpl_qg_settings(key, value, label, description) values
 ('qg_release_approval_valid_hours', '168', '품질·거버넌스: 출시 승인 유효 시간(시간)',
  '출시 후보를 승인한 뒤 이 시간이 지나면 승인이 만료되어 다시 판정·승인해야 출시로 기록할 수 있습니다.')
on conflict (key) do nothing;

create table if not exists public.wpl_qg_gate_policies (
  kind text primary key check (kind ~ '^[a-z][a-z0-9_]{2,39}$'),
  name text not null check (char_length(name) between 1 and 80),
  description text,
  required_engines jsonb not null default '[]'::jsonb check (jsonb_typeof(required_engines) = 'array'),
  max_age_hours int not null default 24 check (max_age_hours between 1 and 8760),
  block_severities jsonb not null default '["critical","high"]'::jsonb check (jsonb_typeof(block_severities) = 'array'),
  issue_scope text not null default 'all' check (issue_scope in ('all','platform','target')),
  require_review boolean not null default false,
  required_suites jsonb not null default '[]'::jsonb check (jsonb_typeof(required_suites) = 'array'),
  require_deploy_evidence boolean not null default false,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
drop trigger if exists wpl_qg_gate_policies_touch on public.wpl_qg_gate_policies;
create trigger wpl_qg_gate_policies_touch before update on public.wpl_qg_gate_policies for each row execute function public.wpl_qg_touch();

-- 새 출시 종류가 생기면 강제 스위치(qg_enforce_<종류>, 기본 false)를 함께 만든다
create or replace function public.wpl_qg_gate_policy_switch_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.wpl_qg_settings(key, value, label, description)
  values ('qg_enforce_' || new.kind, 'false', '출시 관문 강제: ' || new.name,
          '켜면 ''' || new.name || ''' 출시 함수(훅이 걸린 함수)가 그 대상의 ''출시 관문 통과·승인'' 기록이 있을 때만 됩니다. 끄면(기본) 지금처럼 바로 됩니다(승인된 기록이 있으면 출시로 연결만 함).')
  on conflict (key) do nothing;
  return new;
end $$;
revoke all on function public.wpl_qg_gate_policy_switch_trg() from public, anon, authenticated;
drop trigger if exists wpl_qg_gate_policies_switch_ai on public.wpl_qg_gate_policies;
create trigger wpl_qg_gate_policies_switch_ai after insert on public.wpl_qg_gate_policies for each row execute function public.wpl_qg_gate_policy_switch_trg();

alter table public.wpl_qg_gate_policies enable row level security;
drop policy if exists wpl_qg_gate_policies_read on public.wpl_qg_gate_policies;
create policy wpl_qg_gate_policies_read on public.wpl_qg_gate_policies for select to authenticated using (public.wpl_qga_is_admin());
drop policy if exists wpl_qg_gate_policies_admin_ins on public.wpl_qg_gate_policies;
create policy wpl_qg_gate_policies_admin_ins on public.wpl_qg_gate_policies for insert to authenticated with check (public.wpl_qga_is_admin());
drop policy if exists wpl_qg_gate_policies_admin_upd on public.wpl_qg_gate_policies;
create policy wpl_qg_gate_policies_admin_upd on public.wpl_qg_gate_policies for update to authenticated using (public.wpl_qga_is_admin()) with check (public.wpl_qga_is_admin());
drop policy if exists wpl_qg_gate_policies_no_delete on public.wpl_qg_gate_policies;
create policy wpl_qg_gate_policies_no_delete on public.wpl_qg_gate_policies as restrictive for delete to authenticated, anon using (false);
revoke all on public.wpl_qg_gate_policies from anon;
revoke delete, truncate on public.wpl_qg_gate_policies from authenticated;
grant select, insert, update on public.wpl_qg_gate_policies to authenticated;

insert into public.wpl_qg_gate_policies(kind, name, description, required_engines, max_age_hours, block_severities, issue_scope, require_review, required_suites, require_deploy_evidence) values
 ('code_deploy', '코드 배포', '운영(main) 배포 전: 보안·정합성·증거 엔진이 24시간 안에 통과, 치명·높음 열린 이슈 0, 커밋 SHA 필수. 배포 뒤 READY·배포 SHA 일치를 기록해야 출시 완료.',
  '["security","integrity","evidence"]', 24, '["critical","high"]', 'all', false, '[]', true),
 ('policy_change', '정책값 변경', '중요 정책값 변경 전: 치명 열린 이슈 0, 다중 검토 통과.',
  '[]', 72, '["critical"]', 'all', true, '[]', false)
on conflict (kind) do nothing;

create table if not exists public.wpl_qg_releases (
  id uuid primary key default gen_random_uuid(),
  rel_no bigint generated always as identity unique,
  kind text not null references public.wpl_qg_gate_policies(kind) on update cascade,
  target_ref text not null check (char_length(target_ref) between 1 and 200),
  target_label text,
  tenant_id uuid,
  title text not null check (char_length(title) between 2 and 200),
  note text check (note is null or char_length(note) <= 2000),
  git_sha text check (git_sha is null or git_sha ~ '^[0-9a-f]{7,40}$'),
  status text not null default 'candidate' check (status in ('candidate','checking','passed','blocked','approved','rejected','released')),
  verdict jsonb,
  evaluated_at timestamptz,
  evaluated_by uuid,
  approved_by uuid,
  approved_at timestamptz,
  decided_by uuid,
  decided_at timestamptz,
  decision_note text,
  deploy_id text check (deploy_id is null or char_length(deploy_id) <= 200),
  deploy_state text,
  deploy_sha text check (deploy_sha is null or deploy_sha ~ '^[0-9a-f]{7,40}$'),
  deploy_url text check (deploy_url is null or deploy_url ~ '^https://'),
  released_at timestamptz,
  released_by uuid,
  released_via text,
  evidence_id uuid references public.wpl_qg_evidence(id),
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists wpl_qg_releases_status_idx on public.wpl_qg_releases(status, created_at desc);
create index if not exists wpl_qg_releases_target_idx on public.wpl_qg_releases(kind, target_ref, status);
create unique index if not exists wpl_qg_releases_one_active on public.wpl_qg_releases(kind, target_ref)
  where status in ('candidate','checking','passed','blocked','approved');

create table if not exists public.wpl_qg_release_events (
  id bigint generated always as identity primary key,
  release_id uuid not null references public.wpl_qg_releases(id),
  action text not null check (action in ('create','evaluate','approve','reject','release','deploy')),
  from_status text,
  to_status text,
  note text,
  detail jsonb,
  evidence_id uuid references public.wpl_qg_evidence(id),
  actor uuid,
  created_at timestamptz not null default now()
);
create index if not exists wpl_qg_release_events_rel_idx on public.wpl_qg_release_events(release_id, id desc);

drop trigger if exists wpl_qg_releases_guard on public.wpl_qg_releases;
create trigger wpl_qg_releases_guard before update or delete on public.wpl_qg_releases for each row execute function public.wpl_qg_state_guard();
drop trigger if exists wpl_qg_release_events_no_mutation on public.wpl_qg_release_events;
create trigger wpl_qg_release_events_no_mutation before update or delete on public.wpl_qg_release_events for each row execute function public.wpl_qg_forbid_mutation();
drop trigger if exists wpl_qg_release_events_no_truncate on public.wpl_qg_release_events;
create trigger wpl_qg_release_events_no_truncate before truncate on public.wpl_qg_release_events for each statement execute function public.wpl_qg_forbid_mutation();

do $$ declare t text; begin
  foreach t in array array['wpl_qg_releases','wpl_qg_release_events'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists %I on public.%I', t || '_read', t);
    execute format('create policy %I on public.%I for select to authenticated using (public.wpl_qga_is_admin())', t || '_read', t);
    execute format('drop policy if exists %I on public.%I', t || '_no_delete', t);
    execute format('create policy %I on public.%I as restrictive for delete to authenticated, anon using (false)', t || '_no_delete', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
  end loop;
end $$;

-- ───────── 도우미 ─────────
create or replace function public.wpl_qg_release_kind_ko_internal(p text) returns text
language sql stable security definer set search_path = public as $$
  select coalesce((select name from public.wpl_qg_gate_policies where kind = p), p, '-')
$$;
revoke all on function public.wpl_qg_release_kind_ko_internal(text) from public, anon, authenticated;

create or replace function public.wpl_qg_release_status_ko_internal(p text) returns text
language sql immutable set search_path = public as $$
  select case p when 'candidate' then '후보' when 'checking' then '판정 중' when 'passed' then '관문 통과' when 'blocked' then '차단'
                when 'approved' then '승인' when 'rejected' then '반려' when 'released' then '출시 완료' else coalesce(p, '-') end
$$;
revoke all on function public.wpl_qg_release_status_ko_internal(text) from public, anon, authenticated;

create or replace function public.wpl_qg_sha_match_internal(a text, b text) returns boolean
language sql immutable set search_path = public as $$
  select a is not null and b is not null and least(char_length(a), char_length(b)) >= 7
     and left(lower(a), least(char_length(a), char_length(b))) = left(lower(b), least(char_length(a), char_length(b)))
$$;
revoke all on function public.wpl_qg_sha_match_internal(text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_release_event_internal(p_rel uuid, p_action text, p_from text, p_to text, p_note text, p_detail jsonb, p_ev uuid)
returns void language sql security definer set search_path = public as $$
  insert into public.wpl_qg_release_events(release_id, action, from_status, to_status, note, detail, evidence_id, actor)
  values (p_rel, p_action, p_from, p_to, left(p_note, 2000), p_detail, p_ev, auth.uid())
$$;
revoke all on function public.wpl_qg_release_event_internal(uuid, text, text, text, text, jsonb, uuid) from public, anon, authenticated;

-- 대상 확인 → {ref, label, tenant_id}
create or replace function public.wpl_qg_release_target_internal(p_kind text, p_ref text)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_ref text := nullif(trim(coalesce(p_ref, '')), ''); v jsonb; v_label text;
begin
  if not exists (select 1 from public.wpl_qg_gate_policies where kind = p_kind) then
    raise exception '출시 종류를 골라 주세요(관문 정책에 있는 종류만 됩니다).';
  end if;
  if p_kind = 'code_deploy' then
    v_ref := lower(coalesce(v_ref, ''));
    if v_ref !~ '^[0-9a-f]{7,40}$' then raise exception '커밋 SHA 를 7~40자리 16진수로 넣어 주세요(예: git rev-parse HEAD 결과).'; end if;
    return jsonb_build_object('ref', v_ref, 'label', '커밋 ' || left(v_ref, 7), 'tenant_id', null);
  end if;
  if v_ref is null then raise exception '출시 대상을 골라 주세요.'; end if;
  v := public.wpl_qga_release_target(p_kind, v_ref);
  if v is not null and jsonb_typeof(v) = 'object' and nullif(v->>'ref', '') is not null then
    return jsonb_build_object('ref', v->>'ref', 'label', coalesce(v->>'label', v->>'ref'), 'tenant_id', nullif(v->>'tenant_id', ''));
  end if;
  if p_kind = 'policy_change' then
    select coalesce(nullif(label, ''), key) into v_label from public.wpl_qg_settings where key = v_ref;
    if v_label is null then raise exception '정책값을 찾을 수 없습니다. 목록에서 골라 주세요.'; end if;
    return jsonb_build_object('ref', v_ref, 'label', v_label || ' (' || v_ref || ')', 'tenant_id', null);
  end if;
  raise exception '''%'' 대상을 찾을 수 없습니다. 목록에서 골라 주세요(어댑터 wpl_qga_release_target 이 이 종류를 알아야 합니다).', public.wpl_qg_release_kind_ko_internal(p_kind);
end $$;
revoke all on function public.wpl_qg_release_target_internal(text, text) from public, anon, authenticated;

-- ───────── 판정(읽기 전용 계산) ─────────
create or replace function public.wpl_qg_release_evaluate_internal(r public.wpl_qg_releases)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare
  p public.wpl_qg_gate_policies; v_conds jsonb := '[]'::jsonb; e text; ru public.wpl_qg_runs; v_ok boolean; v_detail text; v_age numeric;
  v_n int; v_titles jsonb; v_ids jsonb; v_rv jsonb; v_res text; s text; c public.wpl_qg_checks; v_last uuid; v_bad int; v_pass int; v_at timestamptz;
  v_sev text[];
begin
  select * into p from public.wpl_qg_gate_policies where kind = r.kind;
  if p.kind is null or not p.active then
    return jsonb_build_object('result', 'blocked', 'evaluated_at', now(), 'policy', null,
      'conditions', jsonb_build_array(jsonb_build_object('code', 'policy', 'label', '관문 정책', 'pass', false,
        'detail', case when p.kind is null then '이 출시 종류의 관문 정책이 없습니다.' else '이 출시 종류의 관문 정책이 꺼져 있습니다. 관문 정책에서 켜 주세요.' end)));
  end if;
  select array_agg(x) into v_sev from jsonb_array_elements_text(p.block_severities) x;

  for e in select x from jsonb_array_elements_text(p.required_engines) x loop
    ru := null;
    select * into ru from public.wpl_qg_runs where engine_code = e and (tenant_id is null or (r.tenant_id is not null and tenant_id = r.tenant_id))
     order by finished_at desc limit 1;
    if ru.id is null then
      v_ok := false; v_detail := '실행 기록이 없습니다. 이 엔진을 지금 실행한 뒤 다시 판정하세요.';
    else
      v_age := round(extract(epoch from (now() - ru.finished_at)) / 3600.0, 1);
      if ru.finished_at < now() - make_interval(hours => p.max_age_hours) then
        v_ok := false; v_detail := format('마지막 실행이 %s시간 전입니다(기준 %s시간 이내). 다시 실행하세요.', v_age, p.max_age_hours);
      elsif ru.status in ('failed','error') then
        v_ok := false; v_detail := format('마지막 실행(%s시간 전)에 실패 %s건 · 실행 오류 %s건이 있습니다.', v_age, coalesce(ru.totals->>'fail', '0'), coalesce(ru.totals->>'error', '0'));
      elsif ru.status = 'empty' then
        v_ok := false; v_detail := '마지막 실행에 검사 항목이 없었습니다(엔진 검사 항목을 등록해야 판정할 수 있음).';
      else
        v_ok := true; v_detail := format('마지막 실행 %s시간 전 · %s', v_age, case ru.status when 'passed' then '모두 통과' else '주의만 있음(실패 없음)' end);
      end if;
    end if;
    v_conds := v_conds || jsonb_build_array(jsonb_build_object('code', 'engine:' || e, 'label', '필수 엔진: ' || coalesce((select name from public.wpl_qg_engines where code = e), e),
      'pass', v_ok, 'detail', v_detail, 'run_id', ru.id, 'evidence_id', ru.evidence_id, 'finished_at', ru.finished_at));
  end loop;

  select count(*), coalesce(jsonb_agg(q.title order by public.wpl_qg_sev_rank_internal(q.severity) desc, q.last_seen desc) filter (where q.rn <= 5), '[]'::jsonb),
         coalesce(jsonb_agg(q.id) filter (where q.rn <= 20), '[]'::jsonb)
    into v_n, v_titles, v_ids
    from (select i.*, row_number() over (order by public.wpl_qg_sev_rank_internal(i.severity) desc, i.last_seen desc) rn
            from public.wpl_qg_issues i
           where i.status in ('open','acknowledged') and i.severity = any(coalesce(v_sev, '{}'))
             and (p.issue_scope = 'all' or (p.issue_scope = 'platform' and i.tenant_id is null)
                  or (p.issue_scope = 'target' and (i.tenant_id is null or i.tenant_id = r.tenant_id)))) q;
  v_conds := v_conds || jsonb_build_array(jsonb_build_object('code', 'issues', 'label', '열린 이슈(' || array_to_string(
      array(select case x when 'critical' then '치명' when 'high' then '높음' when 'medium' then '보통' else '낮음' end from unnest(coalesce(v_sev, '{}')) x), '·') || ') 0건'
      || case p.issue_scope when 'platform' then ' — 전체 범위' when 'target' then ' — 전체 + 이 테넌트' else ' — 모든 테넌트 포함' end,
    'pass', v_n = 0, 'detail', case when v_n = 0 then '막는 이슈가 없습니다.' else format('열린 이슈 %s건: %s', v_n, (select string_agg(t #>> '{}', ' / ') from jsonb_array_elements(v_titles) t)) end,
    'count', v_n, 'issue_ids', v_ids));

  if p.require_review then
    v_rv := null;
    if to_regprocedure('public.wpl_qg_review_outcome_internal(text,text)') is not null then
      begin
        execute 'select public.wpl_qg_review_outcome_internal($1, $2)' into v_rv using 'qg_release', r.id::text;
      exception when others then v_rv := jsonb_build_object('result', 'error', 'message', left(sqlerrm, 200));
      end;
    end if;
    if v_rv is null or coalesce(v_rv->>'result', 'none') = 'none' then
      select jsonb_build_object('result', ev.payload->>'result', 'evidence_id', ev.id, 'at', ev.created_at) into v_rv
        from public.wpl_qg_evidence ev where ev.kind = 'review' and ev.ref = 'qg_release:' || r.id::text order by ev.seq desc limit 1;
    end if;
    v_res := coalesce(v_rv->>'result', 'none');
    v_conds := v_conds || jsonb_build_array(jsonb_build_object('code', 'review', 'label', '다중 독립 검토 통과', 'pass', v_res = 'passed',
      'detail', case v_res when 'passed' then '검토 정족수를 채워 통과했고 사람이 확정했습니다.'
                           when 'blocked' then '검토에서 반려로 확정됐습니다.'
                           when 'pending' then '검토가 진행 중이거나, 결과가 나왔지만 아직 사람이 확정하지 않았습니다.'
                           when 'error' then '검토 결과를 읽지 못했습니다: ' || coalesce(v_rv->>'message', '')
                           else '이 출시 후보의 검토 기록이 없습니다. 다중 AI 독립 검토에서 이 후보(대상 종류: 출시 후보) 검토를 요청하세요.' end,
      'review', v_rv));
  end if;

  for s in select x from jsonb_array_elements_text(p.required_suites) x loop
    select * into c from public.wpl_qg_checks where code = s;
    if c.code is null then
      v_conds := v_conds || jsonb_build_array(jsonb_build_object('code', 'suite:' || s, 'label', '필수 테스트: ' || s, 'pass', false,
        'detail', '등록되지 않은 검사 항목입니다. 관문 정책의 필수 스위트 목록을 고쳐 주세요.'));
      continue;
    end if;
    select f.run_id, f.created_at into v_last, v_at from public.wpl_qg_findings f
     where f.check_code = s and (f.tenant_id is null or (r.tenant_id is not null and f.tenant_id = r.tenant_id)) order by f.created_at desc limit 1;
    if v_last is null then
      v_ok := false; v_detail := '결과가 없습니다. 스위트를 실행해 결과를 올려 주세요(scripts/qg-run.mjs).';
    else
      select count(*) filter (where status in ('fail','error')), count(*) filter (where status = 'pass') into v_bad, v_pass
        from public.wpl_qg_findings where run_id = v_last and check_code = s;
      if v_at < now() - make_interval(hours => p.max_age_hours) then
        v_ok := false; v_detail := format('마지막 결과가 %s시간 전입니다(기준 %s시간).', round(extract(epoch from (now() - v_at)) / 3600.0, 1), p.max_age_hours);
      elsif v_bad > 0 then v_ok := false; v_detail := format('마지막 결과에 실패·오류 %s건.', v_bad);
      elsif v_pass = 0 then v_ok := false; v_detail := '마지막 결과에 통과가 없습니다.';
      else v_ok := true; v_detail := format('통과 %s건.', v_pass); end if;
    end if;
    v_conds := v_conds || jsonb_build_array(jsonb_build_object('code', 'suite:' || s, 'label', '필수 테스트: ' || c.name, 'pass', v_ok, 'detail', v_detail, 'run_id', v_last));
    v_last := null; v_at := null;
  end loop;

  if p.require_deploy_evidence then
    v_conds := v_conds || jsonb_build_array(jsonb_build_object('code', 'deploy_sha', 'label', '배포할 커밋 SHA', 'pass', r.git_sha is not null,
      'detail', case when r.git_sha is null then '커밋 SHA 가 없습니다.' else '커밋 ' || left(r.git_sha, 12) || ' — 승인 뒤 배포가 끝나면 ''배포 확인 기록''에 READY·배포 SHA 를 남겨야 출시 완료입니다.' end));
  end if;

  if jsonb_array_length(v_conds) = 0 then
    v_conds := jsonb_build_array(jsonb_build_object('code', 'none', 'label', '조건 없음', 'pass', true, 'detail', '관문 정책에 조건이 없어 통과합니다.'));
  end if;
  return jsonb_build_object('result', case when exists (select 1 from jsonb_array_elements(v_conds) x where not (x->>'pass')::boolean) then 'blocked' else 'passed' end,
    'evaluated_at', now(),
    'policy', jsonb_build_object('kind', p.kind, 'name', p.name, 'required_engines', p.required_engines, 'max_age_hours', p.max_age_hours, 'block_severities', p.block_severities,
                                 'issue_scope', p.issue_scope, 'require_review', p.require_review, 'required_suites', p.required_suites, 'require_deploy_evidence', p.require_deploy_evidence),
    'conditions', v_conds);
end $$;
revoke all on function public.wpl_qg_release_evaluate_internal(public.wpl_qg_releases) from public, anon, authenticated;

create or replace function public.wpl_qg_release_judge_internal(p_rel uuid, p_note text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r public.wpl_qg_releases; v jsonb; v_ev uuid; v_from text;
begin
  select * into r from public.wpl_qg_releases where id = p_rel for update;
  v_from := r.status;
  perform set_config('wpl.qg_write', 'on', true);
  update public.wpl_qg_releases set status = 'checking' where id = r.id returning * into r;
  v := public.wpl_qg_release_evaluate_internal(r);
  v_ev := public.wpl_qg_evidence_append('release_decision', 'qg_release:' || r.id::text,
    jsonb_build_object('action', 'evaluate', 'release_id', r.id, 'rel_no', r.rel_no, 'kind', r.kind, 'target_ref', r.target_ref, 'git_sha', r.git_sha,
                       'verdict', v, 'actor', auth.uid(), 'actor_label', public.wpl_qg_actor_label_internal(), 'note', p_note),
    '출시 판정 #' || r.rel_no || ' ' || public.wpl_qg_release_kind_ko_internal(r.kind) || ': ' || case when v->>'result' = 'passed' then '통과' else '차단' end,
    r.tenant_id, null);
  update public.wpl_qg_releases set status = v->>'result', verdict = v, evaluated_at = now(), evaluated_by = auth.uid(), evidence_id = v_ev where id = r.id;
  perform public.wpl_qg_release_event_internal(r.id, 'evaluate', v_from, v->>'result', p_note,
    jsonb_build_object('failed', (select coalesce(jsonb_agg(x->>'code'), '[]'::jsonb) from jsonb_array_elements(v->'conditions') x where not (x->>'pass')::boolean)), v_ev);
  perform set_config('wpl.qg_write', '', true);
  return v || jsonb_build_object('evidence_id', v_ev);
end $$;
revoke all on function public.wpl_qg_release_judge_internal(uuid, text) from public, anon, authenticated;

-- ───────── RPC(관리자) ─────────
create or replace function public.wpl_qg_release_create(p_kind text, p_target text, p_title text default null, p_git_sha text default null, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare t jsonb; v_sha text := nullif(lower(trim(coalesce(p_git_sha, ''))), ''); v_title text; v_id uuid; v_no bigint; v_dup bigint;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '출시 후보는 관리자만 만들 수 있습니다.'; end if;
  t := public.wpl_qg_release_target_internal(p_kind, p_target);
  if p_kind = 'code_deploy' then v_sha := t->>'ref'; end if;
  if v_sha is not null and v_sha !~ '^[0-9a-f]{7,40}$' then raise exception '커밋 SHA 는 7~40자리 16진수입니다.'; end if;
  if p_note is not null and char_length(p_note) > 2000 then raise exception '메모는 2,000자 이하로 적어 주세요.'; end if;
  select rel_no into v_dup from public.wpl_qg_releases where kind = p_kind and target_ref = t->>'ref' and status in ('candidate','checking','passed','blocked','approved');
  if v_dup is not null then raise exception '이 대상에 이미 진행 중인 출시 후보(#%)가 있습니다. 그 후보를 판정·승인하거나 반려한 뒤 새로 만드세요.', v_dup; end if;
  v_title := coalesce(nullif(trim(coalesce(p_title, '')), ''), public.wpl_qg_release_kind_ko_internal(p_kind) || ' — ' || (t->>'label'));
  if char_length(v_title) > 200 then v_title := left(v_title, 200); end if;
  if char_length(v_title) < 2 then v_title := v_title || ' 출시'; end if;
  insert into public.wpl_qg_releases(kind, target_ref, target_label, tenant_id, title, note, git_sha, created_by)
  values (p_kind, t->>'ref', t->>'label', nullif(t->>'tenant_id', '')::uuid, v_title, nullif(trim(coalesce(p_note, '')), ''), v_sha, auth.uid())
  returning id, rel_no into v_id, v_no;
  perform public.wpl_qg_release_event_internal(v_id, 'create', null, 'candidate', p_note, jsonb_build_object('kind', p_kind, 'target', t), null);
  perform public.wpl_qga_audit(nullif(t->>'tenant_id', '')::uuid, 'user', 'qg.release.create', 'wpl_qg_releases', v_id::text,
    jsonb_build_object('kind', p_kind, 'target_ref', t->>'ref', 'git_sha', v_sha));
  return jsonb_build_object('ok', true, 'id', v_id, 'rel_no', v_no, 'status', 'candidate');
end $$;
revoke all on function public.wpl_qg_release_create(text, text, text, text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_release_create(text, text, text, text, text) to authenticated;

create or replace function public.wpl_qg_release_evaluate(p_release uuid, p_run_engines boolean default false)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r public.wpl_qg_releases; p public.wpl_qg_gate_policies; e text; v jsonb; v_runs jsonb := '[]'::jsonb; v_run uuid;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '출시 판정은 관리자만 할 수 있습니다.'; end if;
  select * into r from public.wpl_qg_releases where id = p_release for update;
  if r.id is null then raise exception '출시 후보를 찾을 수 없습니다.'; end if;
  if r.status not in ('candidate','passed','blocked') then
    raise exception '지금 상태(%)에서는 다시 판정할 수 없습니다.', public.wpl_qg_release_status_ko_internal(r.status);
  end if;
  if coalesce(p_run_engines, false) then
    select * into p from public.wpl_qg_gate_policies where kind = r.kind and active;
    for e in select x from jsonb_array_elements_text(coalesce(p.required_engines, '[]'::jsonb)) x loop
      begin
        v_run := public.wpl_qg_run_engine_internal(e, null, 'release', null, auth.uid(), jsonb_build_object('release_id', r.id, 'rel_no', r.rel_no));
        v_runs := v_runs || jsonb_build_array(jsonb_build_object('engine', e, 'run_id', v_run));
      exception when others then
        v_runs := v_runs || jsonb_build_array(jsonb_build_object('engine', e, 'error', left(sqlerrm, 300)));
      end;
    end loop;
  end if;
  v := public.wpl_qg_release_judge_internal(r.id, null);
  perform public.wpl_qga_audit(r.tenant_id, 'user', 'qg.release.evaluate', 'wpl_qg_releases', r.id::text, jsonb_build_object('result', v->>'result', 'engines_run', v_runs));
  return jsonb_build_object('ok', true, 'result', v->>'result', 'verdict', v, 'engines_run', v_runs);
end $$;
revoke all on function public.wpl_qg_release_evaluate(uuid, boolean) from public, anon, authenticated;
grant execute on function public.wpl_qg_release_evaluate(uuid, boolean) to authenticated;

create or replace function public.wpl_qg_release_decide(p_release uuid, p_decision text, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r public.wpl_qg_releases; v jsonb; v_ev uuid; v_note text := nullif(trim(coalesce(p_note, '')), '');
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '출시 승인·반려는 관리자만 할 수 있습니다.'; end if;
  select * into r from public.wpl_qg_releases where id = p_release for update;
  if r.id is null then raise exception '출시 후보를 찾을 수 없습니다.'; end if;
  if p_decision is null or p_decision not in ('approved','rejected') then raise exception '알 수 없는 결정입니다.'; end if;
  if v_note is not null and char_length(v_note) > 1000 then raise exception '메모는 1,000자 이하로 적어 주세요.'; end if;

  if p_decision = 'rejected' then
    if r.status not in ('candidate','passed','blocked') then raise exception '지금 상태(%)에서는 반려할 수 없습니다.', public.wpl_qg_release_status_ko_internal(r.status); end if;
    if char_length(coalesce(v_note, '')) < 2 then raise exception '반려 사유를 적어 주세요.'; end if;
    perform set_config('wpl.qg_write', 'on', true);
    v_ev := public.wpl_qg_evidence_append('release_decision', 'qg_release:' || r.id::text,
      jsonb_build_object('action', 'reject', 'release_id', r.id, 'rel_no', r.rel_no, 'kind', r.kind, 'target_ref', r.target_ref, 'from', r.status,
                         'decided_by', auth.uid(), 'decided_by_label', public.wpl_qg_actor_label_internal(), 'note', v_note),
      '출시 반려 #' || r.rel_no, r.tenant_id, null);
    update public.wpl_qg_releases set status = 'rejected', decided_by = auth.uid(), decided_at = now(), decision_note = v_note, evidence_id = v_ev where id = r.id;
    perform public.wpl_qg_release_event_internal(r.id, 'reject', r.status, 'rejected', v_note, null, v_ev);
    perform set_config('wpl.qg_write', '', true);
    perform public.wpl_qga_audit(r.tenant_id, 'user', 'qg.release.reject', 'wpl_qg_releases', r.id::text, jsonb_build_object('note', v_note));
    return jsonb_build_object('ok', true, 'status', 'rejected', 'evidence_id', v_ev);
  end if;

  if r.status <> 'passed' then
    raise exception '관문을 통과한 후보만 승인할 수 있습니다(지금: %). 먼저 판정하세요.', public.wpl_qg_release_status_ko_internal(r.status);
  end if;
  if not public.wpl_qg_self_approval_ok_internal(r.created_by) then
    raise exception '자기가 만든 출시 후보는 스스로 승인할 수 없습니다. 다른 관리자에게 맡겨 주세요.';
  end if;
  v := public.wpl_qg_release_judge_internal(r.id, '승인 직전 다시 판정');
  if v->>'result' <> 'passed' then
    perform public.wpl_qga_audit(r.tenant_id, 'user', 'qg.release.approve_blocked', 'wpl_qg_releases', r.id::text, jsonb_build_object('verdict', v));
    return jsonb_build_object('ok', false, 'status', 'blocked', 'verdict', v,
      'message', '판정 이후 상태가 바뀌어 관문을 통과하지 못합니다(차단으로 바꿨습니다). 조건을 채운 뒤 다시 판정하세요.');
  end if;
  perform set_config('wpl.qg_write', 'on', true);
  v_ev := public.wpl_qg_evidence_append('release_decision', 'qg_release:' || r.id::text,
    jsonb_build_object('action', 'approve', 'release_id', r.id, 'rel_no', r.rel_no, 'kind', r.kind, 'target_ref', r.target_ref, 'git_sha', r.git_sha,
                       'requested_by', r.created_by, 'decided_by', auth.uid(), 'decided_by_label', public.wpl_qg_actor_label_internal(), 'note', v_note, 'verdict', v),
    '출시 승인 #' || r.rel_no, r.tenant_id, null);
  update public.wpl_qg_releases set status = 'approved', approved_by = auth.uid(), approved_at = now(), decided_by = auth.uid(), decided_at = now(),
         decision_note = v_note, evidence_id = v_ev where id = r.id;
  perform public.wpl_qg_release_event_internal(r.id, 'approve', 'passed', 'approved', v_note, null, v_ev);
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(r.tenant_id, 'user', 'qg.release.approve', 'wpl_qg_releases', r.id::text, jsonb_build_object('note', v_note, 'evidence_id', v_ev));
  return jsonb_build_object('ok', true, 'status', 'approved', 'evidence_id', v_ev);
end $$;
revoke all on function public.wpl_qg_release_decide(uuid, text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_release_decide(uuid, text, text) to authenticated;

create or replace function public.wpl_qg_release_approval_fresh_internal(r public.wpl_qg_releases) returns boolean
language sql stable security definer set search_path = public as $$
  select r.approved_at is not null and r.approved_at >= now() - make_interval(hours => greatest(1,
    coalesce((public.wpl_qg_setting_internal('qg_release_approval_valid_hours', '168'::jsonb) #>> '{}')::int, 168)))
$$;
revoke all on function public.wpl_qg_release_approval_fresh_internal(public.wpl_qg_releases) from public, anon, authenticated;

-- 코드 배포: 배포 상태 READY · 배포 SHA = 승인된 커밋 → 출시 완료(증거 deploy). 관리자 세션 또는 서버 증명키(배포 스크립트).
create or replace function public.wpl_qg_release_record_deploy(p_release uuid, p_deploy_id text, p_state text, p_deploy_sha text, p_url text default null, p_server_key text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r public.wpl_qg_releases; v_hq boolean := auth.uid() is not null and public.wpl_qga_is_admin();
        v_state text := upper(trim(coalesce(p_state, ''))); v_sha text := lower(trim(coalesce(p_deploy_sha, ''))); v_ev uuid; v_url text := nullif(trim(coalesce(p_url, '')), '');
begin
  if not v_hq and not coalesce(public.wpl_qga_server_key_ok(p_server_key), false) then
    raise exception '배포 기록은 관리자(또는 서버 증명키를 가진 배포 스크립트)만 남길 수 있습니다.';
  end if;
  select * into r from public.wpl_qg_releases where id = p_release for update;
  if r.id is null then raise exception '출시 후보를 찾을 수 없습니다.'; end if;
  if r.kind <> 'code_deploy' then raise exception '배포 확인 기록은 ''코드 배포'' 후보에만 남깁니다.'; end if;
  if r.status <> 'approved' then raise exception '승인된 후보만 출시로 기록할 수 있습니다(지금: %).', public.wpl_qg_release_status_ko_internal(r.status); end if;
  if not public.wpl_qg_release_approval_fresh_internal(r) then raise exception '승인한 지 너무 오래되어 승인이 만료되었습니다. 다시 판정·승인해 주세요.'; end if;
  if nullif(trim(coalesce(p_deploy_id, '')), '') is null or char_length(p_deploy_id) > 200 then raise exception '배포 id(예: dpl_…)를 넣어 주세요.'; end if;
  if v_state <> 'READY' then raise exception '배포 상태가 READY 가 아닙니다(지금: %). 배포가 끝나 READY 가 된 뒤 기록하세요.', coalesce(nullif(v_state, ''), '없음'); end if;
  if v_sha !~ '^[0-9a-f]{7,40}$' then raise exception '배포 SHA 를 7~40자리 16진수로 넣어 주세요.'; end if;
  if not public.wpl_qg_sha_match_internal(v_sha, r.git_sha) then
    raise exception '배포 SHA(%)가 승인된 커밋(%)과 다릅니다. 승인받지 않은 코드가 배포됐을 수 있어 출시로 기록하지 않았습니다.', left(v_sha, 12), left(r.git_sha, 12);
  end if;
  if v_url is not null and v_url !~ '^https://' then raise exception '배포 주소는 https:// 로 시작해야 합니다.'; end if;
  perform set_config('wpl.qg_write', 'on', true);
  v_ev := public.wpl_qg_evidence_append('deploy', 'qg_release:' || r.id::text,
    jsonb_build_object('release_id', r.id, 'rel_no', r.rel_no, 'git_sha', r.git_sha, 'deploy_id', trim(p_deploy_id), 'state', v_state, 'deploy_sha', v_sha, 'url', v_url,
                       'sha_match', true, 'approved_by', r.approved_by, 'recorded_by', auth.uid(), 'via', case when v_hq then 'admin_session' else 'server_key' end),
    '배포 확인 #' || r.rel_no || ' ' || left(v_sha, 7) || ' READY', r.tenant_id, null);
  update public.wpl_qg_releases set status = 'released', deploy_id = trim(p_deploy_id), deploy_state = v_state, deploy_sha = v_sha, deploy_url = v_url,
         released_at = now(), released_by = auth.uid(), released_via = 'deploy', evidence_id = v_ev where id = r.id;
  perform public.wpl_qg_release_event_internal(r.id, 'deploy', 'approved', 'released', null, jsonb_build_object('deploy_id', trim(p_deploy_id), 'deploy_sha', v_sha), v_ev);
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(r.tenant_id, case when v_hq then 'user' else 'system' end, 'qg.release.deploy', 'wpl_qg_releases', r.id::text,
    jsonb_build_object('deploy_id', trim(p_deploy_id), 'deploy_sha', v_sha, 'git_sha', r.git_sha));
  return jsonb_build_object('ok', true, 'status', 'released', 'evidence_id', v_ev);
end $$;
revoke all on function public.wpl_qg_release_record_deploy(uuid, text, text, text, text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_release_record_deploy(uuid, text, text, text, text, text) to authenticated, service_role;

-- 코드 배포가 아닌 종류: 승인 뒤 실제로 바꿨으면 '출시 완료'로 기록(훅이 걸린 종류는 그 함수가 자동으로 기록)
create or replace function public.wpl_qg_release_mark_released(p_release uuid, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r public.wpl_qg_releases; v_ev uuid; v_note text := nullif(trim(coalesce(p_note, '')), '');
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '출시 완료 기록은 관리자만 할 수 있습니다.'; end if;
  select * into r from public.wpl_qg_releases where id = p_release for update;
  if r.id is null then raise exception '출시 후보를 찾을 수 없습니다.'; end if;
  if r.kind = 'code_deploy' then raise exception '코드 배포는 ''배포 확인 기록''(READY·배포 SHA 일치)으로 출시를 기록합니다.'; end if;
  if r.status <> 'approved' then raise exception '승인된 후보만 출시로 기록할 수 있습니다(지금: %).', public.wpl_qg_release_status_ko_internal(r.status); end if;
  if not public.wpl_qg_release_approval_fresh_internal(r) then raise exception '승인한 지 너무 오래되어 승인이 만료되었습니다. 다시 판정·승인해 주세요.'; end if;
  perform set_config('wpl.qg_write', 'on', true);
  v_ev := public.wpl_qg_evidence_append('release_decision', 'qg_release:' || r.id::text,
    jsonb_build_object('action', 'released', 'release_id', r.id, 'rel_no', r.rel_no, 'kind', r.kind, 'target_ref', r.target_ref,
                       'setting_value', case when r.kind = 'policy_change' then (select value from public.wpl_qg_settings where key = r.target_ref) end, 'by', auth.uid(), 'note', v_note),
    '출시 완료 #' || r.rel_no, r.tenant_id, null);
  update public.wpl_qg_releases set status = 'released', released_at = now(), released_by = auth.uid(), released_via = 'manual', evidence_id = v_ev where id = r.id;
  perform public.wpl_qg_release_event_internal(r.id, 'release', 'approved', 'released', v_note, null, v_ev);
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(r.tenant_id, 'user', 'qg.release.released', 'wpl_qg_releases', r.id::text, jsonb_build_object('note', v_note));
  return jsonb_build_object('ok', true, 'status', 'released', 'evidence_id', v_ev);
end $$;
revoke all on function public.wpl_qg_release_mark_released(uuid, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_release_mark_released(uuid, text) to authenticated;

-- ───────── 플랫폼 출시 함수 훅 ─────────
-- 거부 문구(사람 말·조사 처리·설정 키 노출 없음)
create or replace function public.wpl_qg_release_denied_msg_internal(p_kind text) returns text
language sql stable security definer set search_path = public as $$
  select '품질·거버넌스 출시 관문을 통과·승인한 기록이 없어 ' || public.wpl_qg_josa_internal(public.wpl_qg_release_kind_ko_internal(p_kind), '을/를')
      || ' 진행할 수 없습니다. 품질·거버넌스 → 출시 승인·차단에서 이 대상의 출시 후보를 만들고 판정·승인(다른 관리자)을 받은 뒤 다시 해 주세요. '
      || '(설정 → 출시 관문 강제 스위치 「' || public.wpl_qg_release_kind_ko_internal(p_kind) || '」가 켜져 있습니다)'
$$;
revoke all on function public.wpl_qg_release_denied_msg_internal(text) from public, anon, authenticated;

create or replace function public.wpl_qg_release_consume_internal(p_kind text, p_ref text, p_required boolean)
returns uuid language plpgsql security definer set search_path = public as $$
declare r public.wpl_qg_releases; v_ev uuid; v_label text := public.wpl_qg_release_kind_ko_internal(p_kind); v_prev text := coalesce(current_setting('wpl.qg_write', true), '');
begin
  select * into r from public.wpl_qg_releases where kind = p_kind and target_ref = p_ref and status = 'approved' order by approved_at desc limit 1 for update;
  if r.id is null then
    if p_required then
      raise exception '%', public.wpl_qg_release_denied_msg_internal(p_kind);
    end if;
    return null;
  end if;
  if not public.wpl_qg_release_approval_fresh_internal(r) then
    if p_required then
      raise exception '출시 후보 #%의 승인이 만료되었습니다(승인 유효 시간 초과). 출시 승인·차단에서 다시 판정·승인해 주세요.', r.rel_no;
    end if;
    return null;
  end if;
  perform set_config('wpl.qg_write', 'on', true);
  v_ev := public.wpl_qg_evidence_append('release_decision', 'qg_release:' || r.id::text,
    jsonb_build_object('action', 'released', 'release_id', r.id, 'rel_no', r.rel_no, 'kind', r.kind, 'target_ref', r.target_ref,
                       'via', 'hook', 'enforced', p_required, 'by', auth.uid()),
    '출시 완료 #' || r.rel_no || ' ' || v_label, r.tenant_id, null);
  update public.wpl_qg_releases set status = 'released', released_at = now(), released_by = auth.uid(), released_via = 'hook', evidence_id = v_ev where id = r.id;
  perform public.wpl_qg_release_event_internal(r.id, 'release', 'approved', 'released', v_label || ' 실행과 함께 출시 완료', jsonb_build_object('enforced', p_required), v_ev);
  perform set_config('wpl.qg_write', v_prev, true);
  return r.id;
end $$;
revoke all on function public.wpl_qg_release_consume_internal(text, text, boolean) from public, anon, authenticated;

-- 플랫폼 출시 함수에 넣는 한 줄: perform public.wpl_qg_release_gate_hook_internal('<종류>', <대상 ref>);   -- [QG 훅]
create or replace function public.wpl_qg_release_gate_hook_internal(p_kind text, p_ref text)
returns void language plpgsql security definer set search_path = public as $$
declare v_enforce boolean;
begin
  v_enforce := coalesce((public.wpl_qg_setting_internal('qg_enforce_' || coalesce(p_kind, '-'), 'false'::jsonb) #>> '{}')::boolean, false);
  if not v_enforce then
    begin
      perform public.wpl_qg_release_consume_internal(p_kind, p_ref, false);
    exception when others then null;   -- 강제가 아니면 관문 기록 문제로 원래 흐름을 절대 막지 않는다
    end;
    return;
  end if;
  perform public.wpl_qg_release_consume_internal(p_kind, p_ref, true);
end $$;
revoke all on function public.wpl_qg_release_gate_hook_internal(text, text) from public, anon, authenticated;

-- 두 단계 훅(v1.1) — 출시 함수가 예외 없이 '일부 실패'를 돌려줄 수 있을 때:
--   ① 권한 확인 바로 뒤: perform public.wpl_qg_release_gate_require_internal('<종류>', <ref>);   (강제 꺼짐 → 아무것도 안 함, 켜짐 → 승인 없으면 거부. 기록하지 않음)
--   ② 실제로 성공한 경로 끝: perform public.wpl_qg_release_gate_hook_internal('<종류>', <ref>);  (승인 후보 → 출시됨으로 연결)
create or replace function public.wpl_qg_release_gate_require_internal(p_kind text, p_ref text)
returns void language plpgsql stable security definer set search_path = public as $$
declare r public.wpl_qg_releases;
begin
  if not coalesce((public.wpl_qg_setting_internal('qg_enforce_' || coalesce(p_kind, '-'), 'false'::jsonb) #>> '{}')::boolean, false) then return; end if;
  select * into r from public.wpl_qg_releases where kind = p_kind and target_ref = p_ref and status = 'approved' order by approved_at desc limit 1;
  if r.id is null then raise exception '%', public.wpl_qg_release_denied_msg_internal(p_kind); end if;
  if not public.wpl_qg_release_approval_fresh_internal(r) then
    raise exception '출시 후보 #%의 승인이 만료되었습니다(승인 유효 시간 초과). 출시 승인·차단에서 다시 판정·승인해 주세요.', r.rel_no;
  end if;
end $$;
revoke all on function public.wpl_qg_release_gate_require_internal(text, text) from public, anon, authenticated;

-- 읽기 전용 경로용(출시를 기록하지 않음): 강제 스위치 꺼짐 → 항상 true, 켜짐 → 승인·출시된 후보가 있을 때만 true
create or replace function public.wpl_qg_release_gate_open_internal(p_kind text, p_ref text) returns boolean
language sql stable security definer set search_path = public as $$
  select not coalesce((public.wpl_qg_setting_internal('qg_enforce_' || coalesce(p_kind, '-'), 'false'::jsonb) #>> '{}')::boolean, false)
      or exists (select 1 from public.wpl_qg_releases r where r.kind = p_kind and r.target_ref = p_ref and r.status in ('approved','released'))
$$;
revoke all on function public.wpl_qg_release_gate_open_internal(text, text) from public, anon, authenticated;

-- ───────── release 엔진 probe ─────────
create or replace function public.wpl_qg_probe_release_unapproved(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb;
begin
  select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', 'rel:' || r.id::text,
           'title', '승인 없이 출시됨: #' || r.rel_no || ' ' || left(r.title, 120),
           'detail', jsonb_build_object('release_id', r.id, 'rel_no', r.rel_no, 'kind', r.kind, 'target_ref', r.target_ref, 'released_at', r.released_at,
                                        'approved_by', r.approved_by, 'has_approve_event', exists (select 1 from public.wpl_qg_release_events e where e.release_id = r.id and e.action = 'approve')))), '[]'::jsonb)
    into v
    from public.wpl_qg_releases r
   where r.status = 'released'
     and (r.approved_by is null or r.approved_at is null
          or (r.approved_by is not distinct from r.created_by and public.wpl_qga_admin_count_except(r.created_by) > 0)
          or not exists (select 1 from public.wpl_qg_release_events e where e.release_id = r.id and e.action = 'approve')
          or not exists (select 1 from public.wpl_qg_evidence ev where ev.kind = 'release_decision' and ev.ref = 'qg_release:' || r.id::text and ev.payload->>'action' = 'approve'));
  return v;
end $$;
revoke all on function public.wpl_qg_probe_release_unapproved(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_release_deploy_sha(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb;
begin
  select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', 'rel:' || r.id::text,
           'title', '배포 SHA·상태 불일치: #' || r.rel_no || ' (' || coalesce(left(r.deploy_sha, 7), '없음') || ' ≠ ' || coalesce(left(r.git_sha, 7), '없음') || ')',
           'detail', jsonb_build_object('release_id', r.id, 'rel_no', r.rel_no, 'git_sha', r.git_sha, 'deploy_sha', r.deploy_sha, 'deploy_state', r.deploy_state, 'deploy_id', r.deploy_id))), '[]'::jsonb)
    into v
    from public.wpl_qg_releases r
   where r.kind = 'code_deploy' and r.status = 'released'
     and (not public.wpl_qg_sha_match_internal(r.deploy_sha, r.git_sha) or coalesce(r.deploy_state, '') <> 'READY');
  return v;
end $$;
revoke all on function public.wpl_qg_probe_release_deploy_sha(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_release_new_critical(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb; v_days int := greatest(1, coalesce((p_check.params->>'days')::int, 14));
begin
  select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', 'rel:' || x.id::text,
           'title', '관문 통과 뒤 새 치명 이슈 ' || x.n || '건: #' || x.rel_no || ' ' || left(x.title, 100),
           'detail', jsonb_build_object('release_id', x.id, 'rel_no', x.rel_no, 'status', x.status, 'evaluated_at', x.evaluated_at, 'issues', x.issues))), '[]'::jsonb)
    into v
    from (select r.id, r.rel_no, r.title, r.status, r.evaluated_at, count(i.id) n,
                 jsonb_agg(jsonb_build_object('id', i.id, 'title', i.title, 'first_seen', i.first_seen) order by i.first_seen desc) issues
            from public.wpl_qg_releases r
            join public.wpl_qg_gate_policies gp on gp.kind = r.kind
            join public.wpl_qg_issues i on i.severity = 'critical' and i.status in ('open','acknowledged')
                                       and greatest(i.first_seen, i.status_changed_at) > r.evaluated_at
                                       and (gp.issue_scope = 'all' or (gp.issue_scope = 'platform' and i.tenant_id is null)
                                            or (gp.issue_scope = 'target' and (i.tenant_id is null or i.tenant_id = r.tenant_id)))
           where r.status in ('passed','approved','released') and r.evaluated_at is not null
             and coalesce(r.released_at, r.evaluated_at) > now() - make_interval(days => v_days)
           group by r.id, r.rel_no, r.title, r.status, r.evaluated_at) x;
  return v;
end $$;
revoke all on function public.wpl_qg_probe_release_new_critical(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_release_gate_policy(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb := '[]'::jsonb; p public.wpl_qg_gate_policies; k text; x text;
begin
  for k in select jsonb_array_elements_text(coalesce(p_check.params->'required_kinds', '["code_deploy"]'::jsonb)) loop
    if not exists (select 1 from public.wpl_qg_gate_policies where kind = k and active) then
      v := v || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', 'policy_missing:' || k,
        'title', '관문 정책 없음·꺼짐: ' || k, 'detail', jsonb_build_object('kind', k)));
    end if;
  end loop;
  for p in select * from public.wpl_qg_gate_policies where active loop
    for x in select e from jsonb_array_elements_text(p.required_engines) e loop
      if not exists (select 1 from public.wpl_qg_engines where code = x and enabled) then
        v := v || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', 'engine:' || p.kind || ':' || x,
          'title', '관문 정책(' || p.name || ')의 필수 엔진이 없거나 꺼짐: ' || x, 'detail', jsonb_build_object('kind', p.kind, 'engine', x)));
      end if;
    end loop;
    for x in select e from jsonb_array_elements_text(p.required_suites) e loop
      if not exists (select 1 from public.wpl_qg_checks where code = x and active) then
        v := v || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', 'suite:' || p.kind || ':' || x,
          'title', '관문 정책(' || p.name || ')의 필수 스위트가 없거나 꺼짐: ' || x, 'detail', jsonb_build_object('kind', p.kind, 'suite', x)));
      end if;
    end loop;
    for x in select e from jsonb_array_elements_text(p.block_severities) e loop
      if x not in ('critical','high','medium','low') then
        v := v || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', 'sev:' || p.kind || ':' || left(x, 30),
          'title', '관문 정책(' || p.name || ')의 막는 심각도 값이 잘못됨: ' || left(x, 30), 'detail', jsonb_build_object('kind', p.kind, 'value', left(x, 30))));
      end if;
    end loop;
    if p.kind = 'code_deploy' and not p.require_deploy_evidence then
      v := v || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', 'deploy_evidence_off',
        'title', '코드 배포 관문에 배포 증거(SHA)가 꺼져 있음', 'detail', jsonb_build_object('kind', p.kind)));
    end if;
  end loop;
  return v;
end $$;
revoke all on function public.wpl_qg_probe_release_gate_policy(public.wpl_qg_checks, uuid) from public, anon, authenticated;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('release.approved_before_release', 'release', '승인 없이 출시된 기록',
  '출시 완료인데 승인자·승인 이력·승인 증거 중 하나라도 없거나, 다른 관리자가 있는데 만든 사람이 스스로 승인한 출시를 찾습니다.',
  'wpl_qg_probe_release_unapproved', 'critical', 'platform', 'daily', '{}'::jsonb, '0건',
  '출시 승인·차단 화면에서 그 후보의 이력을 확인하세요. 앱 경로로는 승인 없이 출시로 바꿀 수 없으므로 DB 를 직접 고친 흔적입니다. 책임자에게 보고하고 출시 내용을 다시 검토하세요.', 10),
 ('release.deploy_sha_match', 'release', '배포 SHA·READY 일치',
  '코드 배포 출시 기록마다 배포 상태가 READY 이고 배포 SHA 가 승인된 커밋 SHA 와 같은지 다시 확인합니다.',
  'wpl_qg_probe_release_deploy_sha', 'critical', 'platform', 'daily', '{}'::jsonb, '불일치 0건',
  '배포 플랫폼에서 그 배포의 커밋 SHA 를 확인하세요. 승인받지 않은 커밋이 배포됐다면 승인된 커밋으로 다시 배포(롤백)하고 새 출시 후보로 판정·승인을 받으세요.', 20),
 ('release.critical_after_gate', 'release', '관문 통과 뒤 새 치명 이슈',
  '최근 14일 안에 관문을 통과·승인·출시한 후보마다, 판정 시각 이후 새로 생기거나 다시 열린 치명 이슈가 있는지 봅니다.',
  'wpl_qg_probe_release_new_critical', 'high', 'platform', 'daily', '{"days":14}'::jsonb, '0건',
  '이슈함에서 해당 치명 이슈를 먼저 처리하세요. 아직 출시 전이면 다시 판정하면 차단됩니다. 이미 출시됐다면 되돌리기를 검토하세요.', 30),
 ('release.gate_policy_valid', 'release', '관문 정책 점검',
  '필수 출시 종류(params.required_kinds)에 켜진 관문 정책이 있는지, 정책이 가리키는 엔진·필수 스위트가 실제로 있고 켜져 있는지, 막는 심각도 값이 올바른지 확인합니다.',
  'wpl_qg_probe_release_gate_policy', 'high', 'platform', 'daily', '{"required_kinds":["code_deploy"]}'::jsonb, '문제 0건',
  '관문 정책 카탈로그(wpl_qg_gate_policies)에서 해당 종류의 정책을 켜거나 필수 엔진·스위트 목록을 고치세요.', 40)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
  schedule = excluded.schedule, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort;
