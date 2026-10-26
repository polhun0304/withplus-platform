-- QG 키트 1.1.0 · 접두어 wpl · compliance — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
-- =====================================================================
-- QG 키트 31 — 법령·정책 변경 분석 엔진(compliance) (원본: F-MATRIX 2921)
--  · wpl_qg_regulations           카탈로그: 법령·고시·정책(이름·조문·시행일·출처 URL·요지·마지막 검토일·검토 주기·연결 대상·키워드)
--  · wpl_qg_regulation_changes    추가 전용: 변경 요지·시행일·원문·영향 분석 결과·만든 할 일 이슈
--  · wpl_qg_compliance_targets    카탈로그: 영향 분석 대상(종류·코드·이름·설명·걸린 테넌트 수) — 플랫폼 규칙·정책·템플릿·문서를 여기에 등록하거나
--                                   어댑터 wpl_qga_compliance_targets() 가 플랫폼 표에서 바로 돌려준다(둘을 합침). 금칙어(banned)는 자동 포함.
--  영향 분석 = 연결(links: {"<종류>":[코드…]}) + 법령 이름·조문이 대상 설명에 나옴 + 변경 원문 키워드가 대상 이름·설명에 나옴(규칙 대체)
--             → 종류별 걸린 대상·테넌트 수 + 할 일 이슈(척추 이슈함). AI 분석은 '제안'으로만 붙는다.
--  조문은 요지만(법률 자문 아님). 업종 법령 시드는 설치 때 넣는다(QG_KIT.md §6.2). 두 번 적용해도 같은 결과.
-- =====================================================================

insert into public.wpl_qg_settings(key, value, label, description) values
 ('qg_compliance_effective_window_days', '30', '품질·거버넌스: 법령 시행일 도래 알림(일)', '법령·변경 기록의 시행일이 오늘부터 이 일수 안에 들어오면 ''시행일 도래''로 알립니다.'),
 ('qg_compliance_default_cycle_days', '180', '품질·거버넌스: 법령 기본 검토 주기(일)', '새 법령·정책을 등록할 때 쓰는 기본 검토 주기입니다.'),
 ('qg_compliance_urgent_days', '30', '품질·거버넌스: 변경 할 일을 ''높음''으로 올리는 기준(일)',
  '변경 기록의 시행일이 이미 지났거나 이 일수 안이면 할 일 이슈의 심각도를 ''높음''으로, 아니면 ''보통''으로 만듭니다.')
on conflict (key) do nothing;

create table if not exists public.wpl_qg_regulations (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{1,59}$'),
  name text not null check (char_length(name) between 1 and 160),
  law_name text not null check (char_length(law_name) between 1 and 120),
  article text check (article is null or char_length(article) <= 120),
  kind text not null default 'law' check (kind in ('law','decree','notice','guideline','policy')),
  summary text not null check (char_length(summary) between 5 and 2000),
  source_url text check (source_url is null or source_url ~ '^https://'),
  effective_date date,
  last_reviewed_at date,
  review_cycle_days int not null default 180 check (review_cycle_days between 7 and 1095),
  links jsonb not null default '{}'::jsonb check (jsonb_typeof(links) = 'object'),
  keywords text[] not null default '{}',
  note text,
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_regulation_changes (
  id uuid primary key default gen_random_uuid(),
  regulation_code text not null references public.wpl_qg_regulations(code) on update cascade,
  summary text not null check (char_length(summary) between 5 and 2000),
  effective_date date,
  source_text text check (source_text is null or char_length(source_text) <= 50000),
  source_sha256 text,
  source_url text check (source_url is null or source_url ~ '^https://'),
  impact jsonb not null default '{}'::jsonb,
  ai_suggestion jsonb,
  analysis_mode text not null default 'rules' check (analysis_mode in ('rules','ai')),
  ai_model text,
  ai_run_id uuid,
  issue_ids uuid[] not null default '{}',
  evidence_id uuid references public.wpl_qg_evidence(id),
  created_by uuid,
  created_at timestamptz not null default now()
);
create index if not exists wpl_qg_regulation_changes_reg_idx on public.wpl_qg_regulation_changes(regulation_code, created_at desc);

create table if not exists public.wpl_qg_compliance_targets (
  kind text not null check (kind ~ '^[a-z][a-z0-9_]{1,39}$'),
  code text not null check (char_length(code) between 1 and 120),
  name text not null check (char_length(name) between 1 and 200),
  description text,
  tenants int not null default 0 check (tenants >= 0),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (kind, code)
);

do $$ declare t text; begin
  foreach t in array array['wpl_qg_regulations','wpl_qg_compliance_targets'] loop
    execute format('drop trigger if exists %I on public.%I', t || '_touch', t);
    execute format('create trigger %I before update on public.%I for each row execute function public.wpl_qg_touch()', t || '_touch', t);
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
drop trigger if exists wpl_qg_regulation_changes_no_mutation on public.wpl_qg_regulation_changes;
create trigger wpl_qg_regulation_changes_no_mutation before update or delete on public.wpl_qg_regulation_changes for each row execute function public.wpl_qg_forbid_mutation();
drop trigger if exists wpl_qg_regulation_changes_no_truncate on public.wpl_qg_regulation_changes;
create trigger wpl_qg_regulation_changes_no_truncate before truncate on public.wpl_qg_regulation_changes for each statement execute function public.wpl_qg_forbid_mutation();
alter table public.wpl_qg_regulation_changes enable row level security;
drop policy if exists wpl_qg_regulation_changes_read on public.wpl_qg_regulation_changes;
create policy wpl_qg_regulation_changes_read on public.wpl_qg_regulation_changes for select to authenticated using (public.wpl_qga_is_admin());
drop policy if exists wpl_qg_regulation_changes_no_delete on public.wpl_qg_regulation_changes;
create policy wpl_qg_regulation_changes_no_delete on public.wpl_qg_regulation_changes as restrictive for delete to authenticated, anon using (false);
revoke all on public.wpl_qg_regulation_changes from anon, authenticated;
grant select on public.wpl_qg_regulation_changes to authenticated;

-- ───────── 영향 분석 ─────────
create or replace function public.wpl_qg_compliance_kind_ko_internal(p text) returns text
language sql immutable set search_path = public as $$
  select case p when 'rule' then '준법 규칙' when 'policy' then '정책값' when 'template' then '업종·서비스 템플릿' when 'document' then '문서 템플릿'
                when 'banned' then '금칙어·문구 가드' when 'feature' then '기능' when 'screen' then '화면' when 'process' then '업무 절차' else coalesce(p, '-') end
$$;
revoke all on function public.wpl_qg_compliance_kind_ko_internal(text) from public, anon, authenticated;

-- 모든 대상(카탈로그 + 어댑터 + 금칙어)
create or replace function public.wpl_qg_compliance_all_targets_internal()
returns table(kind text, code text, name text, description text, tenants int)
language sql stable security definer set search_path = public as $$
  select t.kind, t.code, t.name, t.description, t.tenants from public.wpl_qg_compliance_targets t where t.active
  union
  select a.kind, a.code, a.name, a.description, coalesce(a.tenants, 0) from public.wpl_qga_compliance_targets() a where a.kind is not null and a.code is not null
  union
  select 'banned', b.code, b.reason, b.pattern, 0 from public.wpl_qg_banned_phrases b where b.active
$$;
revoke all on function public.wpl_qg_compliance_all_targets_internal() from public, anon, authenticated;

create or replace function public.wpl_qg_regulation_impact_internal(p_reg public.wpl_qg_regulations, p_text text)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare
  l jsonb := coalesce(p_reg.links, '{}'::jsonb); v_kw text[]; v_txt text := coalesce(p_text, ''); v_hits jsonb; v_broken jsonb := '[]'::jsonb; e record; c text;
  v_totals jsonb := '{}'::jsonb; v_linked boolean;
begin
  select coalesce(array_agg(kw), '{}') into v_kw from unnest(p_reg.keywords) kw where char_length(kw) >= 2 and v_txt <> '' and position(kw in v_txt) > 0;
  select coalesce(jsonb_agg(jsonb_build_object('kind', t.kind, 'code', t.code, 'name', t.name, 'tenants', t.tenants,
           'via', case when jsonb_typeof(l->t.kind) = 'array' and (l->t.kind) ? t.code then 'link'
                       when position(p_reg.law_name in coalesce(t.description, '') || ' ' || t.name) > 0 then 'law_ref' else 'keyword' end)
           order by t.kind, t.code), '[]'::jsonb)
    into v_hits
    from public.wpl_qg_compliance_all_targets_internal() t
   where (jsonb_typeof(l->t.kind) = 'array' and (l->t.kind) ? t.code)
      or position(p_reg.law_name in coalesce(t.description, '') || ' ' || t.name) > 0
      or exists (select 1 from unnest(v_kw) kw where position(kw in coalesce(t.name, '') || ' ' || coalesce(t.description, '')) > 0);
  -- 깨진 연결(대상에 없는 코드)
  for e in select key, value from jsonb_each(l) loop
    if jsonb_typeof(e.value) <> 'array' then continue; end if;
    for c in select jsonb_array_elements_text(e.value) loop
      if not exists (select 1 from public.wpl_qg_compliance_all_targets_internal() t where t.kind = e.key and t.code = c) then
        v_broken := v_broken || jsonb_build_array(jsonb_build_object('kind', e.key, 'code', c));
      end if;
    end loop;
  end loop;
  select coalesce(jsonb_object_agg(k, jsonb_build_object('label', public.wpl_qg_compliance_kind_ko_internal(k), 'count', n, 'tenants', tn)), '{}'::jsonb)
    into v_totals
    from (select h->>'kind' k, count(*) n, sum(coalesce((h->>'tenants')::int, 0)) tn from jsonb_array_elements(v_hits) h group by 1) s;
  v_linked := exists (select 1 from jsonb_each(l) x where jsonb_typeof(x.value) = 'array' and jsonb_array_length(x.value) > 0);
  return jsonb_build_object('regulation', p_reg.code, 'law_name', p_reg.law_name, 'article', p_reg.article,
    'targets', v_hits, 'totals', v_totals, 'target_count', jsonb_array_length(v_hits),
    'tenant_count', coalesce((select sum(coalesce((h->>'tenants')::int, 0)) from jsonb_array_elements(v_hits) h), 0),
    'keyword_hits', to_jsonb(v_kw), 'broken_links', v_broken, 'linked', v_linked);
end $$;
revoke all on function public.wpl_qg_regulation_impact_internal(public.wpl_qg_regulations, text) from public, anon, authenticated;

create or replace function public.wpl_qg_regulation_impact(p_code text, p_text text default null)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare g public.wpl_qg_regulations;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '법령 영향 분석은 관리자만 볼 수 있습니다.'; end if;
  select * into g from public.wpl_qg_regulations where code = p_code;
  if g.code is null then raise exception '법령·정책을 찾을 수 없습니다.'; end if;
  return public.wpl_qg_regulation_impact_internal(g, p_text);
end $$;
revoke all on function public.wpl_qg_regulation_impact(text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_regulation_impact(text, text) to authenticated;

-- 관리자: 변경 기록 추가 → 영향 분석 + 할 일 이슈 + 증거. p_ai = AI 제안(선택, 판정에 쓰지 않음; 실행 기록이 확인될 때만 남김)
create or replace function public.wpl_qg_regulation_change_add(p_code text, p_summary text, p_effective date default null, p_source_text text default null,
  p_source_url text default null, p_ai jsonb default null, p_ai_run uuid default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  g public.wpl_qg_regulations; v_id uuid := gen_random_uuid(); v_imp jsonb; v_sev text; v_urgent int; v_issues uuid[] := '{}'; v_list jsonb := '[]'::jsonb;
  v_ev uuid; v_iid uuid; v_title text; x record; v_model text; v_mode text := 'rules';
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '법령 변경 기록은 관리자만 남길 수 있습니다.'; end if;
  select * into g from public.wpl_qg_regulations where code = p_code;
  if g.code is null then raise exception '법령·정책을 목록에서 골라 주세요.'; end if;
  if char_length(btrim(coalesce(p_summary, ''))) < 5 then raise exception '변경 요지를 5자 이상 적어 주세요.'; end if;
  if char_length(p_summary) > 2000 then raise exception '변경 요지는 2,000자 이하로 적어 주세요.'; end if;
  if p_source_text is not null and char_length(p_source_text) > 50000 then raise exception '원문은 50,000자 이하로 붙여 넣어 주세요.'; end if;
  if p_source_url is not null and p_source_url !~ '^https://' then raise exception '출처 주소는 https:// 로 시작해야 합니다.'; end if;
  if p_ai is not null then
    if jsonb_typeof(p_ai) <> 'object' or octet_length(p_ai::text) > 20000 then raise exception 'AI 제안 형식이 올바르지 않습니다.'; end if;
    select r.model_code into v_model from public.wpl_qga_ai_runs(now() - interval '1 hour') r
     where r.id = p_ai_run and r.task_code = 'qg_regulation_impact' and r.status = 'ok' and r.created_by = auth.uid();
    if v_model is null then p_ai := null; else v_mode := 'ai'; end if;
  end if;

  v_imp := public.wpl_qg_regulation_impact_internal(g, coalesce(p_source_text, '') || E'\n' || p_summary);
  v_urgent := greatest(0, coalesce((public.wpl_qg_setting_internal('qg_compliance_urgent_days', '30'::jsonb) #>> '{}')::int, 30));
  v_sev := case when p_effective is not null and p_effective <= current_date + v_urgent then 'high' else 'medium' end;

  perform set_config('wpl.qg_write', 'on', true);
  for x in select key k, (value->>'count')::int n, coalesce((value->>'tenants')::int, 0) tn, value->>'label' lbl from jsonb_each(v_imp->'totals') where (value->>'count')::int > 0 loop
    v_title := left('법령 변경 반영: ' || g.name || ' — ' || x.lbl || ' ' || x.n || '개' || case when x.tn > 0 then '(테넌트 ' || x.tn || '곳)' else '' end || '가 바뀐 기준에 맞는지 확인', 300);
    v_iid := public.wpl_qg_issue_upsert_internal('compliance', 'compliance.change_followup', null,
               'compliance.change_followup|*|change:' || v_id::text || ':' || x.k, v_sev, v_title,
               jsonb_build_object('change_id', v_id, 'regulation', g.code, 'area', x.k, 'count', x.n, 'effective_date', p_effective, 'summary', left(p_summary, 500),
                                  'targets', (select jsonb_agg(h) from jsonb_array_elements(v_imp->'targets') h where h->>'kind' = x.k)), null, null);
    v_issues := v_issues || v_iid;
    v_list := v_list || jsonb_build_array(jsonb_build_object('id', v_iid, 'area', x.k, 'title', v_title, 'severity', v_sev));
  end loop;
  if cardinality(v_issues) = 0 then
    v_title := left('법령 변경 영향 확인 필요: ' || g.name || ' — 연결된 대상이 없어 사람이 영향 범위를 정해야 합니다', 300);
    v_iid := public.wpl_qg_issue_upsert_internal('compliance', 'compliance.change_followup', null,
               'compliance.change_followup|*|change:' || v_id::text || ':unlinked', v_sev, v_title,
               jsonb_build_object('change_id', v_id, 'regulation', g.code, 'area', 'unlinked', 'effective_date', p_effective, 'summary', left(p_summary, 500)), null, null);
    v_issues := v_issues || v_iid;
    v_list := v_list || jsonb_build_array(jsonb_build_object('id', v_iid, 'area', 'unlinked', 'title', v_title, 'severity', v_sev));
  end if;
  perform set_config('wpl.qg_write', '', true);

  v_ev := public.wpl_qg_evidence_append('regulation_change', 'regulation:' || g.code,
    jsonb_build_object('change_id', v_id, 'regulation', g.code, 'name', g.name, 'summary', p_summary, 'effective_date', p_effective, 'source_url', p_source_url,
      'source_sha256', case when p_source_text is not null then encode(sha256(convert_to(p_source_text, 'UTF8')), 'hex') end,
      'impact_totals', v_imp->'totals', 'issues', v_list, 'analysis_mode', v_mode, 'ai_model', v_model, 'by', auth.uid(), 'by_label', public.wpl_qg_actor_label_internal()),
    '법령 변경: ' || left(g.name, 200), null, null);

  insert into public.wpl_qg_regulation_changes(id, regulation_code, summary, effective_date, source_text, source_sha256, source_url, impact, ai_suggestion,
    analysis_mode, ai_model, ai_run_id, issue_ids, evidence_id, created_by)
  values (v_id, g.code, btrim(p_summary), p_effective, p_source_text,
          case when p_source_text is not null then encode(sha256(convert_to(p_source_text, 'UTF8')), 'hex') end, p_source_url, v_imp, p_ai,
          v_mode, v_model, case when v_mode = 'ai' then p_ai_run end, v_issues, v_ev, auth.uid());
  perform public.wpl_qga_audit(null, 'user', 'qg.regulation.change', 'wpl_qg_regulation_changes', v_id::text,
    jsonb_build_object('regulation', g.code, 'effective_date', p_effective, 'issues', to_jsonb(v_issues), 'totals', v_imp->'totals', 'mode', v_mode));
  return jsonb_build_object('ok', true, 'change_id', v_id, 'impact', v_imp, 'issues', v_list, 'evidence_id', v_ev, 'analysis_mode', v_mode);
end $$;
revoke all on function public.wpl_qg_regulation_change_add(text, text, date, text, text, jsonb, uuid) from public, anon, authenticated;
grant execute on function public.wpl_qg_regulation_change_add(text, text, date, text, text, jsonb, uuid) to authenticated;

create or replace function public.wpl_qg_regulation_mark_reviewed(p_code text, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare g public.wpl_qg_regulations; v_today date := (now() at time zone 'Asia/Seoul')::date;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '법령 검토 기록은 관리자만 남길 수 있습니다.'; end if;
  select * into g from public.wpl_qg_regulations where code = p_code for update;
  if g.code is null then raise exception '법령·정책을 찾을 수 없습니다.'; end if;
  if p_note is not null and char_length(p_note) > 1000 then raise exception '메모는 1,000자 이하로 적어 주세요.'; end if;
  update public.wpl_qg_regulations set last_reviewed_at = v_today where code = g.code;
  perform public.wpl_qga_audit(null, 'user', 'qg.regulation.reviewed', 'wpl_qg_regulations', g.code,
    jsonb_build_object('previous', g.last_reviewed_at, 'reviewed_on', v_today, 'note', nullif(btrim(coalesce(p_note, '')), '')));
  return jsonb_build_object('ok', true, 'reviewed_on', v_today, 'next_due', v_today + g.review_cycle_days);
end $$;
revoke all on function public.wpl_qg_regulation_mark_reviewed(text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_regulation_mark_reviewed(text, text) to authenticated;

-- ───────── probe ─────────
create or replace function public.wpl_qg_probe_compliance_review_overdue(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; r record; v_today date := (now() at time zone 'Asia/Seoul')::date; v_never jsonb;
begin
  for r in select g.code, g.name, g.last_reviewed_at, g.review_cycle_days, g.last_reviewed_at + g.review_cycle_days due
             from public.wpl_qg_regulations g where g.active and g.last_reviewed_at is not null and g.last_reviewed_at + g.review_cycle_days < v_today order by g.sort loop
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'fingerprint', 'overdue:' || r.code,
      'title', '법령 검토 기한 초과: ' || r.name || ' (' || (v_today - r.due) || '일 지남)',
      'detail', jsonb_build_object('regulation', r.code, 'last_reviewed_at', r.last_reviewed_at, 'cycle_days', r.review_cycle_days, 'due', r.due, 'overdue_days', v_today - r.due)));
  end loop;
  select coalesce(jsonb_agg(jsonb_build_object('code', g.code, 'name', g.name) order by g.sort), '[]'::jsonb) into v_never
    from public.wpl_qg_regulations g where g.active and g.last_reviewed_at is null;
  if jsonb_array_length(v_never) > 0 then
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'low', 'fingerprint', 'never_reviewed',
      'title', '검토 기록이 없는 법령·정책 ' || jsonb_array_length(v_never) || '개', 'detail', jsonb_build_object('count', jsonb_array_length(v_never), 'items', v_never)));
  end if;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('message', '모든 법령·정책이 검토 주기 안에 있습니다.'));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_compliance_review_overdue(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_compliance_effective_soon(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_today date := (now() at time zone 'Asia/Seoul')::date; v_out jsonb := '[]'::jsonb; r record;
        v_days int := greatest(1, coalesce((p_check.params->>'days')::int, (public.wpl_qg_setting_internal('qg_compliance_effective_window_days', '30'::jsonb) #>> '{}')::int, 30));
begin
  for r in select 'reg' src, g.code, g.name, g.effective_date d, null::uuid change_id from public.wpl_qg_regulations g
            where g.active and g.effective_date between v_today and v_today + v_days
           union all
           select 'change', g.code, g.name || ' — ' || left(c.summary, 80), c.effective_date, c.id from public.wpl_qg_regulation_changes c
             join public.wpl_qg_regulations g on g.code = c.regulation_code
            where c.effective_date between v_today and v_today + v_days order by 4 loop
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', case when r.d - v_today <= 7 then 'high' else 'medium' end,
      'fingerprint', 'effective:' || r.code || ':' || r.d::text || coalesce(':' || r.change_id::text, ''),
      'title', '시행일 ' || (r.d - v_today) || '일 남음: ' || r.name,
      'detail', jsonb_build_object('regulation', r.code, 'effective_date', r.d, 'days_left', r.d - v_today, 'change_id', r.change_id, 'source', r.src)));
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('days', v_days, 'message', v_days || '일 안에 시행되는 법령·변경이 없습니다.'));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_compliance_effective_soon(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_compliance_unlinked(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; g public.wpl_qg_regulations; v jsonb;
begin
  for g in select * from public.wpl_qg_regulations where active order by sort, code loop
    v := public.wpl_qg_regulation_impact_internal(g, null);
    if not (v->>'linked')::boolean and (v->>'target_count')::int = 0 then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'low', 'fingerprint', 'unlinked:' || g.code,
        'title', '연결 대상이 없는 법령·정책: ' || g.name, 'detail', jsonb_build_object('regulation', g.code)));
    end if;
    if jsonb_array_length(v->'broken_links') > 0 then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'medium', 'fingerprint', 'broken_link:' || g.code,
        'title', '없는 코드에 연결된 법령·정책: ' || g.name, 'detail', jsonb_build_object('regulation', g.code, 'broken', v->'broken_links')));
    end if;
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('message', '모든 법령·정책이 실제 대상에 연결되어 있습니다.'));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_compliance_unlinked(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ───────── 시드: 대부분의 한국 온라인 플랫폼에 걸리는 공통 법령(요지만) — 업종 법령은 설치 때 더한다 ─────────
insert into public.wpl_qg_regulations(code, name, law_name, article, kind, summary, source_url, review_cycle_days, links, keywords, sort) values
 ('pipa_consent', '개인정보 보호법 — 수집·이용 동의·처리 위탁', '개인정보 보호법', '제15조·제26조', 'law',
  '개인정보는 목적을 알리고 동의를 받거나 법이 허용한 경우에만 수집·이용하고, 처리를 맡길 때는 위탁 사실을 공개하고 관리·감독해야 한다. 주민등록번호는 법령 근거 없이 처리할 수 없다.',
  'https://www.law.go.kr/법령/개인정보보호법/제15조', 180, '{}'::jsonb, array['개인정보','동의','위탁','주민등록번호','처리'], 10),
 ('fair_labeling_ads', '표시광고법 제3조 — 부당한 표시·광고 금지', '표시광고법', '제3조', 'law',
  '거짓·과장, 기만적, 부당 비교, 비방 표시·광고를 금지한다. 최상급·최초·보장·검증 안 된 수치 같은 표현은 근거가 없으면 쓸 수 없다.',
  'https://www.law.go.kr/법령/표시ㆍ광고의공정화에관한법률/제3조', 180,
  '{"banned":["guarantee_profit","guarantee_100","no_side_effect","superlative","first_only","absolute","urgency"]}'::jsonb, array['광고','표시','과장','최고','보장'], 20),
 ('ecommerce_consumer', '전자상거래법 — 사업자 정보 표시·청약철회·중개자 고지', '전자상거래법', '제13조·제17조·제20조', 'law',
  '통신판매업 신고·사업자 정보 표시, 청약철회(환불) 보장, 통신판매중개자는 자신이 거래 당사자가 아님을 고지하고 판매자 정보를 제공해야 한다.',
  'https://www.law.go.kr/법령/전자상거래등에서의소비자보호에관한법률/제17조', 180, '{"banned":["no_refund"]}'::jsonb, array['통신판매','중개','청약철회','환불','사업자 정보'], 30),
 ('network_act', '정보통신망법 — 광고성 정보 전송 제한·야간 수신 동의', '정보통신망법', '제50조', 'law',
  '영리 목적 광고성 정보는 수신자의 사전 동의를 받아야 하고, 야간(21시~08시) 전송은 별도 동의가 필요하며, 수신 거부 방법을 알려야 한다.',
  'https://www.law.go.kr/법령/정보통신망이용촉진및정보보호등에관한법률/제50조', 180, '{}'::jsonb, array['광고성','수신','야간','동의','문자'], 40),
 ('efta_payment', '전자금융거래법 — 전자지급결제대행·선불전자지급수단', '전자금융거래법', '제2조·제28조', 'law',
  '다른 사람의 결제를 대신 받아 정산하거나 포인트·충전금을 발행하면 등록 대상이 될 수 있다. 등록 PG 와 계약하고 고객 자금을 직접 보유하지 않는 구조가 기본이다.',
  'https://www.law.go.kr/법령/전자금융거래법/제28조', 180, '{}'::jsonb, array['결제','PG','정산','포인트','충전'], 50),
 ('location_info', '위치정보법 — 위치기반서비스 신고·위치정보 동의', '위치정보법', '제9조·제18조', 'law',
  '개인위치정보를 이용한 서비스를 하려면 사업 신고가 필요하고, 위치정보 수집·이용에 별도 동의를 받아야 한다.',
  'https://www.law.go.kr/법령/위치정보의보호및이용등에관한법률/제9조', 365, '{}'::jsonb, array['위치정보','위치기반','GPS','지오펜스'], 60)
on conflict (code) do update set name = excluded.name, law_name = excluded.law_name, article = excluded.article, kind = excluded.kind, summary = excluded.summary,
  source_url = excluded.source_url, keywords = excluded.keywords, sort = excluded.sort;
  -- links·last_reviewed_at·review_cycle_days·effective_date 는 사람이 정한 값을 덮지 않는다

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('compliance.review_overdue', 'compliance', '법령 검토 기한 초과',
  '법령·정책마다 마지막 검토일 + 검토 주기가 지났는지 확인합니다. 검토 기록이 아예 없는 것은 모아서 ''주의'' 1건으로 알립니다.',
  'wpl_qg_probe_compliance_review_overdue', 'medium', 'platform', 'daily', '{}'::jsonb,
  '기한 초과 0건',
  '품질·거버넌스 → 법령·정책 변경 분석에서 해당 법령의 최신 원문(국가법령정보센터)을 확인하고, 바뀐 것이 있으면 ''변경 기록 추가'', 없으면 ''검토 완료''를 누르세요.', 10),
 ('compliance.effective_soon', 'compliance', '시행일 도래',
  '법령·변경 기록의 시행일이 오늘부터 정해진 일수 안에 들어오는지 확인합니다. 7일 안이면 심각도 높음.',
  'wpl_qg_probe_compliance_effective_soon', 'medium', 'platform', 'daily', '{}'::jsonb,
  '시행 전 할 일 없음',
  '시행일 전에 연결된 규칙·정책값·템플릿·문서를 바뀐 법에 맞게 고치고, 변경 기록의 할 일 이슈를 처리하세요.', 20),
 ('compliance.unlinked', 'compliance', '연결 대상 없는 법령·깨진 연결',
  '법령·정책이 어느 대상에도 연결되지 않았거나(주의), 없는 코드에 연결되어 있으면(실패) 알립니다.',
  'wpl_qg_probe_compliance_unlinked', 'low', 'platform', 'weekly', '{}'::jsonb,
  '연결 없음 0 · 깨진 연결 0',
  '법령 카탈로그의 연결 대상(links)에 영향 분석 대상(wpl_qg_compliance_targets 또는 어댑터)의 실제 종류·코드를 넣으세요.', 30),
 ('compliance.change_followup', 'compliance', '법령 변경 후속 할 일',
  '법령 변경 기록을 추가하면 영향 분석 결과에 따라 종류별 할 일이 이 항목의 이슈로 만들어집니다. 자동 실행되지 않습니다(수동).',
  'manual', 'medium', 'platform', 'manual', '{}'::jsonb,
  '할 일을 처리하고 ''고쳤음''으로 바꿈',
  '이슈의 상세에서 변경 기록과 걸린 대상을 확인하고 고친 뒤 ''고쳤음''으로 바꾸세요.', 40)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
  schedule = excluded.schedule, params = excluded.params, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort;
