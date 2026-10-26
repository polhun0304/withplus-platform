-- QG 키트 1.1.0 · 접두어 wpl · ai_model — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
-- =====================================================================
-- QG 키트 32 — AI 모델 평가·승인·추적 엔진(ai_model) (원본: F-MATRIX 2922)
--  · wpl_qg_ai_models / wpl_qg_ai_tasks  카탈로그: 모델(공급자 rules = 외부 호출 없는 규칙 엔진)·작업(기본·대체 모델)
--  · wpl_qg_ai_calls          추가 전용: AI 실행 기록(플랫폼에 AI 실행 표가 없을 때의 자체 기록). 사용 추적·검토·평가는
--                               어댑터 wpl_qga_ai_runs(since) 를 읽는다(플랫폼 표 + 이 표를 합쳐 돌려주게 만들 수 있음).
--  · wpl_qg_ai_eval_sets      카탈로그: 작업별 평가 입력 + 합격 규칙(JSON·필수 키·금칙어 없음·길이·원문에 없는 숫자 금지) + 규칙 기준 답
--  · wpl_qg_ai_evals          추가 전용: 평가 결과(합격 판정은 DB 가 다시 계산)
--  · wpl_qg_ai_model_approvals 모델×작업 상태 candidate → approved → suspended → retired (승인은 4-eyes, 자기 승인 불가)
--  · wpl_qg_ai_model_events   추가 전용: 상태 이력
--  · 라우터 스위치 qg_ai_require_approved(기본 false) — wpl_qg_ai_routing_policy(task) 로 읽어 승인 안 된 모델을 건너뛴다.
--    꺼져 있으면 기존 동작과 완전히 같다.
-- =====================================================================

insert into public.wpl_qg_settings(key, value, label, description) values
 ('qg_ai_require_approved', 'false', 'AI 라우터: 승인된 모델만 쓰기',
  '켜면 AI 호출이 ''AI 모델 평가·승인''에서 그 작업에 승인된 모델만 씁니다(승인 안 된 모델은 건너뛰고 규칙 기반). 기본은 꺼짐.'),
 ('qg_ai_window_days', '7', 'AI 모델 추적: 사용 추세 계산 기간(일)', 'AI 실패율·비용·지연 이상을 계산하는 최근 기간입니다.'),
 ('qg_ai_max_failure_rate', '0.2', 'AI 모델 추적: 실패율 기준(0~1)', '모델별 최근 기간 실패(error) 비율이 이 값을 넘으면 품질 이슈가 됩니다.'),
 ('qg_ai_min_runs', '10', 'AI 모델 추적: 판정에 필요한 최소 호출 수', '호출 수가 이보다 적으면 실패율은 판정하지 않습니다(표본 부족).'),
 ('qg_ai_max_avg_latency_ms', '20000', 'AI 모델 추적: 평균 응답 시간 기준(ms)', '모델별 최근 기간 평균 응답 시간이 이 값을 넘으면 품질 이슈(주의)가 됩니다.'),
 ('qg_ai_max_cost_krw_window', '300000', 'AI 모델 추적: 기간 비용 기준(원)', '모델별 최근 기간 AI 원가 합계가 이 금액을 넘으면 품질 이슈(주의)가 됩니다.'),
 ('qg_ai_approval_requires_eval', 'true', 'AI 모델 승인: 최근 평가 통과 필요', '켜면 모델×작업을 ''승인''하려면 기간 안에 그 작업 평가를 통과한 기록이 있어야 합니다(규칙 모델 제외).'),
 ('qg_ai_approval_eval_days', '30', 'AI 모델 승인: 평가 유효 기간(일)', '승인 요청·결정 때 이 일수 안의 평가 결과만 인정합니다.'),
 ('qg_ai_status_note_min_len', '5', 'AI 모델 승인: 상태 변경 사유 최소 글자 수', '모델×작업 상태를 바꿀 때 적어야 하는 사유의 최소 글자 수입니다.')
on conflict (key) do nothing;

-- ───────── 1) 표 ─────────
create table if not exists public.wpl_qg_ai_models (
  code text primary key check (code ~ '^[a-z][a-z0-9_.-]{1,59}$'),
  provider text not null check (provider ~ '^[a-z][a-z0-9_]{1,29}$'),
  label text not null check (char_length(label) between 1 and 120),
  model_id text,
  tier text,
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_ai_tasks (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{1,59}$'),
  name text not null check (char_length(name) between 1 and 120),
  description text,
  risk_level text not null default 'medium' check (risk_level in ('low','medium','high')),
  default_model text references public.wpl_qg_ai_models(code) on update cascade,
  fallback_model text references public.wpl_qg_ai_models(code) on update cascade,
  max_output_tokens int not null default 1000 check (max_output_tokens between 50 and 32000),
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_ai_calls (
  id uuid primary key default gen_random_uuid(),
  task_code text not null,
  model_code text not null,
  tenant_id uuid,
  status text not null check (status in ('ok','error','fallback_rules','blocked')),
  cache_hit boolean not null default false,
  latency_ms int,
  input_tokens int not null default 0,
  output_tokens int not null default 0,
  cost_krw numeric(14,2) not null default 0,
  ref_id text,
  created_by uuid,
  created_at timestamptz not null default now()
);
create index if not exists wpl_qg_ai_calls_time_idx on public.wpl_qg_ai_calls(created_at desc);

create table if not exists public.wpl_qg_ai_eval_sets (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{1,59}$'),
  task_code text not null references public.wpl_qg_ai_tasks(code) on update cascade,
  name text not null check (char_length(name) between 1 and 120),
  description text,
  system_prompt text not null default '' check (char_length(system_prompt) <= 4000),
  input text not null check (char_length(input) between 1 and 8000),
  context text check (context is null or char_length(context) <= 8000),
  rules jsonb not null default '{}'::jsonb check (jsonb_typeof(rules) = 'object'),
  rules_output text check (rules_output is null or char_length(rules_output) <= 8000),
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_ai_evals (
  id uuid primary key default gen_random_uuid(),
  batch_id uuid,
  eval_set_code text not null references public.wpl_qg_ai_eval_sets(code) on update cascade,
  task_code text not null,
  model_code text not null,
  status text not null check (status in ('pass','fail','skipped','error')),
  checks jsonb not null default '[]'::jsonb,
  reason text,
  output_excerpt text,
  output_sha256 text,
  latency_ms int,
  cost_krw numeric not null default 0,
  ai_run_id uuid,
  created_by uuid,
  created_at timestamptz not null default now()
);
create index if not exists wpl_qg_ai_evals_mt_idx on public.wpl_qg_ai_evals(model_code, task_code, created_at desc);

create table if not exists public.wpl_qg_ai_model_approvals (
  model_code text not null references public.wpl_qg_ai_models(code) on update cascade,
  task_code text not null references public.wpl_qg_ai_tasks(code) on update cascade,
  status text not null default 'candidate' check (status in ('candidate','approved','suspended','retired')),
  note text,
  pending_to text check (pending_to is null or pending_to = 'approved'),
  pending_by uuid,
  pending_at timestamptz,
  pending_note text,
  status_changed_by uuid,
  status_changed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (model_code, task_code)
);

create table if not exists public.wpl_qg_ai_model_events (
  id bigint generated always as identity primary key,
  model_code text not null,
  task_code text not null,
  action text not null check (action in ('request','approve','reject','cancel','transition')),
  from_status text,
  to_status text,
  note text,
  evidence_id uuid references public.wpl_qg_evidence(id),
  actor uuid,
  created_at timestamptz not null default now()
);
create index if not exists wpl_qg_ai_model_events_mt_idx on public.wpl_qg_ai_model_events(model_code, task_code, id desc);

do $$ declare t text; begin
  foreach t in array array['wpl_qg_ai_models','wpl_qg_ai_tasks','wpl_qg_ai_eval_sets'] loop
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
  foreach t in array array['wpl_qg_ai_calls','wpl_qg_ai_evals','wpl_qg_ai_model_events'] loop
    execute format('drop trigger if exists %I on public.%I', t || '_no_mutation', t);
    execute format('create trigger %I before update or delete on public.%I for each row execute function public.wpl_qg_forbid_mutation()', t || '_no_mutation', t);
    execute format('drop trigger if exists %I on public.%I', t || '_no_truncate', t);
    execute format('create trigger %I before truncate on public.%I for each statement execute function public.wpl_qg_forbid_mutation()', t || '_no_truncate', t);
  end loop;
  foreach t in array array['wpl_qg_ai_calls','wpl_qg_ai_evals','wpl_qg_ai_model_approvals','wpl_qg_ai_model_events'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists %I on public.%I', t || '_read', t);
    execute format('create policy %I on public.%I for select to authenticated using (public.wpl_qga_is_admin())', t || '_read', t);
    execute format('drop policy if exists %I on public.%I', t || '_no_delete', t);
    execute format('create policy %I on public.%I as restrictive for delete to authenticated, anon using (false)', t || '_no_delete', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
  end loop;
end $$;

create or replace function public.wpl_qg_ai_approval_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'DELETE' then raise exception 'AI 모델 승인 기록은 지울 수 없습니다(퇴역으로 바꿔 주세요).'; end if;
  if coalesce(current_setting('wpl.qg_write', true), '') <> 'on' then
    raise exception 'AI 모델 승인 상태는 ''AI 모델 평가·승인'' 화면의 절차로만 바꿀 수 있습니다.';
  end if;
  if tg_op = 'UPDATE' then
    if new.model_code is distinct from old.model_code or new.task_code is distinct from old.task_code then raise exception '모델·작업은 바꿀 수 없습니다.'; end if;
    new.updated_at := now();
  end if;
  return new;
end $$;
revoke all on function public.wpl_qg_ai_approval_guard() from public, anon, authenticated;
drop trigger if exists wpl_qg_ai_model_approvals_guard on public.wpl_qg_ai_model_approvals;
create trigger wpl_qg_ai_model_approvals_guard before insert or update or delete on public.wpl_qg_ai_model_approvals for each row execute function public.wpl_qg_ai_approval_guard();
drop trigger if exists wpl_qg_ai_model_approvals_no_truncate on public.wpl_qg_ai_model_approvals;
create trigger wpl_qg_ai_model_approvals_no_truncate before truncate on public.wpl_qg_ai_model_approvals for each statement execute function public.wpl_qg_forbid_mutation();

-- ───────── 2) AI 실행 기록(서버 액션이 AI 를 부른 뒤 남김) — 관리자 또는 그 테넌트 구성원 ─────────
create or replace function public.wpl_qg_ai_call_record(p_task text, p_model text, p_status text, p_latency int default null, p_cost numeric default 0,
  p_ref text default null, p_tenant uuid default null, p_input_tokens int default 0, p_output_tokens int default 0)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  if auth.uid() is null then raise exception '로그인이 필요합니다.'; end if;
  if not public.wpl_qga_is_admin() and not (p_tenant is not null and public.wpl_qga_can_read_tenant(p_tenant)) then raise exception 'AI 실행을 기록할 권한이 없습니다.'; end if;
  if not exists (select 1 from public.wpl_qg_ai_tasks where code = p_task) then raise exception '알 수 없는 AI 작업입니다.'; end if;
  if not exists (select 1 from public.wpl_qg_ai_models where code = p_model) then raise exception '알 수 없는 AI 모델입니다.'; end if;
  if p_status not in ('ok','error','fallback_rules','blocked') then raise exception 'AI 실행 상태가 올바르지 않습니다.'; end if;
  insert into public.wpl_qg_ai_calls(task_code, model_code, tenant_id, status, latency_ms, input_tokens, output_tokens, cost_krw, ref_id, created_by)
  values (p_task, p_model, p_tenant, p_status, greatest(0, least(coalesce(p_latency, 0), 3600000)), greatest(0, coalesce(p_input_tokens, 0)), greatest(0, coalesce(p_output_tokens, 0)),
          greatest(0, coalesce(p_cost, 0)), left(p_ref, 200), auth.uid())
  returning id into v_id;
  return v_id;
end $$;
revoke all on function public.wpl_qg_ai_call_record(text, text, text, int, numeric, text, uuid, int, int) from public, anon, authenticated;
grant execute on function public.wpl_qg_ai_call_record(text, text, text, int, numeric, text, uuid, int, int) to authenticated;

-- ───────── 3) 평가 판정(합격 규칙) ─────────
create or replace function public.wpl_qg_ai_eval_check_internal(p_rules jsonb, p_output text, p_context text)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare
  o text := coalesce(p_output, ''); r jsonb := coalesce(p_rules, '{}'::jsonb); v jsonb := '[]'::jsonb; j jsonb; body text; k text; v_ok boolean; n text;
  v_bad text[] := '{}'; v_hits text[];
begin
  if (r->>'json')::boolean is true or jsonb_typeof(r->'required_keys') = 'array' then
    body := coalesce((regexp_match(o, '```(?:json)?\s*([\s\S]*?)```'))[1],
                     case when position('{' in o) > 0 and position('}' in o) > 0
                          then substr(o, position('{' in o), (length(o) - position('}' in reverse(o)) + 1) - position('{' in o) + 1) end);
    begin j := body::jsonb; exception when others then j := null; end;
    v := v || jsonb_build_array(jsonb_build_object('code', 'json', 'ok', j is not null and jsonb_typeof(j) = 'object',
           'message', case when j is not null and jsonb_typeof(j) = 'object' then 'JSON 객체로 읽힘' else 'JSON 객체로 읽을 수 없음' end));
    if jsonb_typeof(r->'required_keys') = 'array' then
      for k in select jsonb_array_elements_text(r->'required_keys') loop
        v_ok := j is not null and jsonb_typeof(j) = 'object' and j ? k;
        v := v || jsonb_build_array(jsonb_build_object('code', 'key:' || k, 'ok', v_ok, 'message', case when v_ok then '필수 키 ' || k || ' 있음' else '필수 키 ' || k || ' 없음' end));
      end loop;
    end if;
  end if;
  if r ? 'min_len' then
    v_ok := char_length(btrim(o)) >= (r->>'min_len')::int;
    v := v || jsonb_build_array(jsonb_build_object('code', 'min_len', 'ok', v_ok, 'message', '길이 ' || char_length(btrim(o)) || '자(최소 ' || (r->>'min_len') || ')'));
  end if;
  if r ? 'max_len' then
    v_ok := char_length(o) <= (r->>'max_len')::int;
    v := v || jsonb_build_array(jsonb_build_object('code', 'max_len', 'ok', v_ok, 'message', '길이 ' || char_length(o) || '자(최대 ' || (r->>'max_len') || ')'));
  end if;
  if (r->>'no_banned')::boolean is true then
    select coalesce(array_agg(b.reason), '{}') into v_hits
      from (select q.pattern, q.reason, q.industry from public.wpl_qg_banned_phrases q where q.active
            union all select a.pattern, a.reason, a.industry from public.wpl_qga_banned_phrases() a) b
     where (b.industry is null or b.industry = r->>'industry') and public.wpl_qg_regex_hit_internal(o, b.pattern);
    v := v || jsonb_build_array(jsonb_build_object('code', 'no_banned', 'ok', cardinality(v_hits) = 0,
           'message', case when cardinality(v_hits) = 0 then '금칙어 없음' else '금칙어: ' || left(array_to_string(v_hits, ' / '), 300) end));
  end if;
  if (r->>'no_new_numbers')::boolean is true then
    for n in select distinct m[1] from regexp_matches(o, '([0-9][0-9,.]*[0-9]|[0-9])', 'g') m loop
      if position(replace(n, ',', '') in replace(coalesce(p_context, ''), ',', '')) = 0 then v_bad := v_bad || n; end if;
    end loop;
    v := v || jsonb_build_array(jsonb_build_object('code', 'no_new_numbers', 'ok', cardinality(v_bad) = 0,
           'message', case when cardinality(v_bad) = 0 then '원문에 없는 숫자 없음' else '원문에 없는 숫자: ' || left(array_to_string(v_bad[1:10], ', '), 200) end));
  end if;
  return jsonb_build_object('pass', not exists (select 1 from jsonb_array_elements(v) e where not (e->>'ok')::boolean), 'checks', v);
end $$;
revoke all on function public.wpl_qg_ai_eval_check_internal(jsonb, text, text) from public, anon, authenticated;

-- 관리자: 평가 결과 1건 기록. p_kind = ran(출력 있음)·skipped(키 없음 등)·error(호출 실패). 규칙 모델은 세트의 기준 답으로 평가.
create or replace function public.wpl_qg_ai_eval_record(p_set text, p_model text, p_kind text, p_output text default null, p_latency int default null,
  p_run uuid default null, p_reason text default null, p_batch uuid default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare s public.wpl_qg_ai_eval_sets; m public.wpl_qg_ai_models; v_status text; v_chk jsonb := '[]'::jsonb; v_out text; v_cost numeric := 0; v_id uuid;
        v_reason text := left(p_reason, 500); v_ok boolean;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception 'AI 모델 평가는 관리자만 할 수 있습니다.'; end if;
  select * into s from public.wpl_qg_ai_eval_sets where code = p_set;
  if s.code is null then raise exception '평가 세트를 찾을 수 없습니다.'; end if;
  select * into m from public.wpl_qg_ai_models where code = p_model;
  if m.code is null then raise exception '모델을 찾을 수 없습니다.'; end if;
  if p_kind not in ('ran','skipped','error') then raise exception '평가 결과 종류가 올바르지 않습니다.'; end if;

  if m.provider = 'rules' then
    if s.rules_output is null then v_status := 'skipped'; v_reason := '규칙 기준 답이 없는 평가 세트입니다(rules_output 을 넣으면 평가됩니다).';
    else v_out := s.rules_output; end if;
  elsif p_kind = 'ran' then
    select true, coalesce(r.cost_krw, 0) into v_ok, v_cost from public.wpl_qga_ai_runs(now() - interval '1 hour') r
     where r.id = p_run and r.task_code = s.task_code and r.model_code = m.code and r.created_by = auth.uid();
    if not coalesce(v_ok, false) then raise exception '평가 호출 기록을 확인할 수 없습니다.'; end if;
    v_out := coalesce(p_output, '');
  else
    v_status := p_kind;
    if v_reason is null then v_reason := case when p_kind = 'skipped' then '키 필요' else '호출 실패' end; end if;
  end if;

  if v_out is not null then
    v_chk := public.wpl_qg_ai_eval_check_internal(s.rules, v_out, coalesce(s.input, '') || E'\n' || coalesce(s.context, ''));
    v_status := case when (v_chk->>'pass')::boolean then 'pass' else 'fail' end;
    v_chk := v_chk->'checks';
  end if;
  insert into public.wpl_qg_ai_evals(batch_id, eval_set_code, task_code, model_code, status, checks, reason, output_excerpt, output_sha256, latency_ms, cost_krw, ai_run_id, created_by, created_at)
  values (p_batch, s.code, s.task_code, m.code, v_status, v_chk, v_reason, left(v_out, 1000),
          case when v_out is not null then encode(sha256(convert_to(v_out, 'UTF8')), 'hex') end, p_latency, v_cost,
          case when m.provider <> 'rules' then p_run end, auth.uid(), clock_timestamp())
  returning id into v_id;
  return jsonb_build_object('id', v_id, 'status', v_status, 'checks', v_chk, 'reason', v_reason);
end $$;
revoke all on function public.wpl_qg_ai_eval_record(text, text, text, text, int, uuid, text, uuid) from public, anon, authenticated;
grant execute on function public.wpl_qg_ai_eval_record(text, text, text, text, int, uuid, text, uuid) to authenticated;

-- ───────── 4) 승인 상태 머신 ─────────
create or replace function public.wpl_qg_ai_allowed_internal(p_from text, p_to text) returns boolean
language sql immutable set search_path = public as $$
  select case p_from
    when 'candidate' then p_to in ('approved','retired')
    when 'approved' then p_to in ('suspended','retired')
    when 'suspended' then p_to in ('approved','candidate','retired')
    when 'retired' then p_to = 'candidate'
    else false end
$$;
revoke all on function public.wpl_qg_ai_allowed_internal(text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_ai_status_ko_internal(p text) returns text
language sql immutable set search_path = public as $$
  select case p when 'candidate' then '후보' when 'approved' then '승인' when 'suspended' then '정지' when 'retired' then '퇴역' else coalesce(p, '-') end
$$;
revoke all on function public.wpl_qg_ai_status_ko_internal(text) from public, anon, authenticated;

create or replace function public.wpl_qg_ai_eval_gate_internal(p_model text, p_task text) returns text
language plpgsql stable security definer set search_path = public as $$
declare v_days int; v_last text;
begin
  if (select provider from public.wpl_qg_ai_models where code = p_model) = 'rules' then return null; end if;
  if not coalesce((public.wpl_qg_setting_internal('qg_ai_approval_requires_eval', 'true'::jsonb) #>> '{}')::boolean, true) then return null; end if;
  v_days := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_ai_approval_eval_days', '30'::jsonb) #>> '{}')::int, 30));
  select e.status into v_last from public.wpl_qg_ai_evals e
   where e.model_code = p_model and e.task_code = p_task and e.status in ('pass','fail') and e.created_at > now() - make_interval(days => v_days)
   order by e.created_at desc limit 1;
  if v_last is null then return '최근 ' || v_days || '일 안에 이 작업의 평가 기록이 없습니다. 먼저 평가를 실행해 통과해야 승인할 수 있습니다.'; end if;
  if v_last <> 'pass' then return '이 작업의 마지막 평가가 불합격입니다. 평가를 통과한 뒤 승인할 수 있습니다.'; end if;
  return null;
end $$;
revoke all on function public.wpl_qg_ai_eval_gate_internal(text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_ai_model_event_internal(p_model text, p_task text, p_action text, p_from text, p_to text, p_note text, p_ev uuid)
returns void language sql security definer set search_path = public as $$
  insert into public.wpl_qg_ai_model_events(model_code, task_code, action, from_status, to_status, note, evidence_id, actor)
  values (p_model, p_task, p_action, p_from, p_to, left(p_note, 2000), p_ev, auth.uid())
$$;
revoke all on function public.wpl_qg_ai_model_event_internal(text, text, text, text, text, text, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_ai_model_set_status(p_model text, p_task text, p_to text, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare a public.wpl_qg_ai_model_approvals; v_note text := nullif(btrim(coalesce(p_note, '')), ''); v_min int; v_gate text; v_ev uuid;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception 'AI 모델 승인 상태는 관리자만 바꿀 수 있습니다.'; end if;
  if not exists (select 1 from public.wpl_qg_ai_models where code = p_model) then raise exception '모델을 찾을 수 없습니다.'; end if;
  if not exists (select 1 from public.wpl_qg_ai_tasks where code = p_task) then raise exception '작업을 찾을 수 없습니다.'; end if;
  perform set_config('wpl.qg_write', 'on', true);
  insert into public.wpl_qg_ai_model_approvals(model_code, task_code, status) values (p_model, p_task, 'candidate') on conflict do nothing;
  select * into a from public.wpl_qg_ai_model_approvals where model_code = p_model and task_code = p_task for update;
  if a.pending_to is not null then raise exception '승인 요청이 대기 중입니다. 먼저 결정하거나 요청을 취소해 주세요.'; end if;
  if p_to is null or not public.wpl_qg_ai_allowed_internal(a.status, p_to) then
    raise exception '지금 상태(%)에서 ''%''(으)로 바꿀 수 없습니다.', public.wpl_qg_ai_status_ko_internal(a.status), public.wpl_qg_ai_status_ko_internal(p_to);
  end if;
  if v_note is not null and char_length(v_note) > 2000 then raise exception '사유는 2,000자 이하로 적어 주세요.'; end if;
  v_min := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_ai_status_note_min_len', '5'::jsonb) #>> '{}')::int, 5));
  if char_length(coalesce(v_note, '')) < v_min then raise exception '사유를 %자 이상 적어 주세요.', v_min; end if;

  if p_to = 'approved' then
    v_gate := public.wpl_qg_ai_eval_gate_internal(p_model, p_task);
    if v_gate is not null then raise exception '%', v_gate; end if;
    update public.wpl_qg_ai_model_approvals set pending_to = 'approved', pending_by = auth.uid(), pending_at = now(), pending_note = v_note
     where model_code = p_model and task_code = p_task;
    perform public.wpl_qg_ai_model_event_internal(p_model, p_task, 'request', a.status, 'approved', v_note, null);
    perform set_config('wpl.qg_write', '', true);
    perform public.wpl_qga_audit(null, 'user', 'qg.ai_model.request', 'wpl_qg_ai_model_approvals', p_model || ':' || p_task, jsonb_build_object('from', a.status, 'to', 'approved', 'note', v_note));
    return jsonb_build_object('ok', true, 'pending', true, 'status', a.status, 'message', '승인 요청을 만들었습니다. 다른 관리자가 결정해야 바뀝니다.');
  end if;

  v_ev := public.wpl_qg_evidence_append('ai_model_decision', 'ai_model:' || p_model || ':' || p_task,
    jsonb_build_object('model', p_model, 'task', p_task, 'from', a.status, 'to', p_to, 'note', v_note, 'by', auth.uid(), 'by_label', public.wpl_qg_actor_label_internal()),
    'AI 모델 상태: ' || p_model || ' × ' || p_task || ' → ' || public.wpl_qg_ai_status_ko_internal(p_to), null, null);
  update public.wpl_qg_ai_model_approvals set status = p_to, note = v_note, status_changed_by = auth.uid(), status_changed_at = now()
   where model_code = p_model and task_code = p_task;
  perform public.wpl_qg_ai_model_event_internal(p_model, p_task, 'transition', a.status, p_to, v_note, v_ev);
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(null, 'user', 'qg.ai_model.transition', 'wpl_qg_ai_model_approvals', p_model || ':' || p_task,
    jsonb_build_object('from', a.status, 'to', p_to, 'note', v_note, 'evidence_id', v_ev));
  return jsonb_build_object('ok', true, 'pending', false, 'status', p_to, 'evidence_id', v_ev);
end $$;
revoke all on function public.wpl_qg_ai_model_set_status(text, text, text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_ai_model_set_status(text, text, text, text) to authenticated;

create or replace function public.wpl_qg_ai_model_decide(p_model text, p_task text, p_decision text, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare a public.wpl_qg_ai_model_approvals; v_note text := nullif(btrim(coalesce(p_note, '')), ''); v_gate text; v_ev uuid;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception 'AI 모델 승인은 관리자만 결정할 수 있습니다.'; end if;
  select * into a from public.wpl_qg_ai_model_approvals where model_code = p_model and task_code = p_task for update;
  if a.model_code is null or a.pending_to is null then raise exception '대기 중인 승인 요청이 없습니다.'; end if;
  if p_decision is null or p_decision not in ('approved','rejected','cancelled') then raise exception '알 수 없는 결정입니다.'; end if;
  if p_decision = 'rejected' and char_length(coalesce(v_note, '')) < 2 then raise exception '반려 사유를 적어 주세요.'; end if;
  if p_decision = 'cancelled' and a.pending_by is distinct from auth.uid() then raise exception '요청 취소는 요청한 사람만 할 수 있습니다.'; end if;
  if p_decision = 'approved' then
    if not public.wpl_qg_self_approval_ok_internal(a.pending_by) then
      raise exception '자기가 요청한 모델 승인은 스스로 결정할 수 없습니다. 다른 관리자에게 맡겨 주세요.';
    end if;
    v_gate := public.wpl_qg_ai_eval_gate_internal(p_model, p_task);
    if v_gate is not null then raise exception '%', v_gate; end if;
  end if;
  perform set_config('wpl.qg_write', 'on', true);
  if p_decision = 'approved' then
    v_ev := public.wpl_qg_evidence_append('ai_model_decision', 'ai_model:' || p_model || ':' || p_task,
      jsonb_build_object('model', p_model, 'task', p_task, 'from', a.status, 'to', 'approved', 'request_note', a.pending_note, 'requested_by', a.pending_by,
        'requested_at', a.pending_at, 'decided_by', auth.uid(), 'decided_by_label', public.wpl_qg_actor_label_internal(), 'decision_note', v_note,
        'last_evals', (select jsonb_agg(jsonb_build_object('set', e.eval_set_code, 'status', e.status, 'at', e.created_at) order by e.created_at desc)
                         from (select * from public.wpl_qg_ai_evals e where e.model_code = p_model and e.task_code = p_task order by e.created_at desc limit 5) e)),
      'AI 모델 승인: ' || p_model || ' × ' || p_task, null, null);
    update public.wpl_qg_ai_model_approvals set status = 'approved', note = a.pending_note, pending_to = null, pending_by = null, pending_at = null, pending_note = null,
           status_changed_by = auth.uid(), status_changed_at = now() where model_code = p_model and task_code = p_task;
    perform public.wpl_qg_ai_model_event_internal(p_model, p_task, 'approve', a.status, 'approved', v_note, v_ev);
  else
    update public.wpl_qg_ai_model_approvals set pending_to = null, pending_by = null, pending_at = null, pending_note = null where model_code = p_model and task_code = p_task;
    perform public.wpl_qg_ai_model_event_internal(p_model, p_task, case when p_decision = 'rejected' then 'reject' else 'cancel' end, a.status, a.status, v_note, null);
  end if;
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(null, 'user', 'qg.ai_model.' || p_decision, 'wpl_qg_ai_model_approvals', p_model || ':' || p_task, jsonb_build_object('note', v_note, 'evidence_id', v_ev));
  return jsonb_build_object('ok', true, 'decision', p_decision, 'status', case when p_decision = 'approved' then 'approved' else a.status end, 'evidence_id', v_ev);
end $$;
revoke all on function public.wpl_qg_ai_model_decide(text, text, text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_ai_model_decide(text, text, text, text) to authenticated;

-- ───────── 5) 라우터 스위치 · 화면 읽기 ─────────
create or replace function public.wpl_qg_ai_routing_policy(p_task text)
returns jsonb language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'require', coalesce((public.wpl_qg_setting_internal('qg_ai_require_approved', 'false'::jsonb) #>> '{}')::boolean, false),
    'approved', coalesce((select jsonb_agg(a.model_code order by a.model_code) from public.wpl_qg_ai_model_approvals a where a.task_code = p_task and a.status = 'approved'), '[]'::jsonb))
$$;
revoke all on function public.wpl_qg_ai_routing_policy(text) from public, anon, authenticated;
grant execute on function public.wpl_qg_ai_routing_policy(text) to authenticated, service_role;

create or replace function public.wpl_qg_ai_matrix()
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_days int := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_ai_window_days', '7'::jsonb) #>> '{}')::int, 7));
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception 'AI 모델 승인 표는 관리자만 볼 수 있습니다.'; end if;
  return jsonb_build_object(
    'require_approved', coalesce((public.wpl_qg_setting_internal('qg_ai_require_approved', 'false'::jsonb) #>> '{}')::boolean, false),
    'window_days', v_days,
    'eval_required', coalesce((public.wpl_qg_setting_internal('qg_ai_approval_requires_eval', 'true'::jsonb) #>> '{}')::boolean, true),
    'models', coalesce((select jsonb_agg(jsonb_build_object('code', m.code, 'provider', m.provider, 'label', m.label, 'model_id', m.model_id, 'tier', m.tier, 'active', m.active) order by m.sort, m.code)
                          from public.wpl_qg_ai_models m), '[]'::jsonb),
    'tasks', coalesce((select jsonb_agg(jsonb_build_object('code', t.code, 'name', t.name, 'risk', t.risk_level, 'default_model', t.default_model,
                          'fallback_model', t.fallback_model, 'active', t.active,
                          'eval_sets', (select count(*) from public.wpl_qg_ai_eval_sets s where s.task_code = t.code and s.active)) order by t.sort, t.code)
                         from public.wpl_qg_ai_tasks t), '[]'::jsonb),
    'eval_sets', coalesce((select jsonb_agg(jsonb_build_object('code', s.code, 'task', s.task_code, 'name', s.name) order by s.sort, s.code)
                         from public.wpl_qg_ai_eval_sets s where s.active), '[]'::jsonb),
    'cells', coalesce((select jsonb_agg(jsonb_build_object('model', m.code, 'task', t.code,
                          'status', coalesce(a.status, 'candidate'), 'pending_to', a.pending_to, 'pending_by', a.pending_by, 'pending_at', a.pending_at, 'pending_note', a.pending_note,
                          'note', a.note, 'changed_at', a.status_changed_at,
                          'routed', m.code in (coalesce(t.default_model, ''), coalesce(t.fallback_model, '')),
                          'last_eval', (select jsonb_build_object('status', e.status, 'at', e.created_at, 'set', e.eval_set_code, 'reason', e.reason)
                                          from public.wpl_qg_ai_evals e where e.model_code = m.code and e.task_code = t.code order by e.created_at desc limit 1),
                          'used_window', (select count(*) from public.wpl_qga_ai_runs(now() - make_interval(days => v_days)) r where r.model_code = m.code and r.task_code = t.code)))
                         from public.wpl_qg_ai_tasks t cross join public.wpl_qg_ai_models m
                         left join public.wpl_qg_ai_model_approvals a on a.model_code = m.code and a.task_code = t.code), '[]'::jsonb));
end $$;
revoke all on function public.wpl_qg_ai_matrix() from public, anon, authenticated;
grant execute on function public.wpl_qg_ai_matrix() to authenticated;

create or replace function public.wpl_qg_ai_usage(p_days int default null)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_days int := least(180, greatest(1, coalesce(p_days, (public.wpl_qg_setting_internal('qg_ai_window_days', '7'::jsonb) #>> '{}')::int, 7)));
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception 'AI 사용 추세는 관리자만 볼 수 있습니다.'; end if;
  return jsonb_build_object('days', v_days,
    'models', coalesce((select jsonb_agg(x order by x->>'model') from (
        select jsonb_build_object('model', coalesce(r.model_code, '(없음)'), 'runs', count(*),
          'ok', count(*) filter (where r.status = 'ok' and not r.cache_hit), 'cache', count(*) filter (where r.cache_hit),
          'error', count(*) filter (where r.status = 'error'), 'fallback', count(*) filter (where r.status = 'fallback_rules'), 'blocked', count(*) filter (where r.status = 'blocked'),
          'failure_rate', case when count(*) filter (where r.status in ('ok','error') and not r.cache_hit) > 0
                               then round(count(*) filter (where r.status = 'error')::numeric / count(*) filter (where r.status in ('ok','error') and not r.cache_hit), 4) end,
          'avg_latency_ms', round(avg(r.latency_ms) filter (where r.status = 'ok' and not r.cache_hit)),
          'cost_krw', coalesce(round(sum(r.cost_krw)), 0)) x
          from public.wpl_qga_ai_runs(now() - make_interval(days => v_days)) r group by r.model_code) q), '[]'::jsonb),
    'daily', coalesce((select jsonb_agg(jsonb_build_object('day', d.d, 'runs', d.runs, 'error', d.err, 'cost_krw', d.cost) order by d.d) from (
        select (r.created_at at time zone 'Asia/Seoul')::date d, count(*) runs, count(*) filter (where r.status = 'error') err, coalesce(round(sum(r.cost_krw)), 0) cost
          from public.wpl_qga_ai_runs(now() - make_interval(days => v_days)) r group by 1) d), '[]'::jsonb));
end $$;
revoke all on function public.wpl_qg_ai_usage(int) from public, anon, authenticated;
grant execute on function public.wpl_qg_ai_usage(int) to authenticated;

-- ───────── 6) probe ─────────
create or replace function public.wpl_qg_probe_ai_usage_thresholds(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare
  v_days int := greatest(1, coalesce((p_check.params->>'days')::int, (public.wpl_qg_setting_internal('qg_ai_window_days', '7'::jsonb) #>> '{}')::int, 7));
  v_rate numeric := coalesce((public.wpl_qg_setting_internal('qg_ai_max_failure_rate', '0.2'::jsonb) #>> '{}')::numeric, 0.2);
  v_min int := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_ai_min_runs', '10'::jsonb) #>> '{}')::int, 10));
  v_lat numeric := coalesce((public.wpl_qg_setting_internal('qg_ai_max_avg_latency_ms', '20000'::jsonb) #>> '{}')::numeric, 20000);
  v_cost numeric := coalesce((public.wpl_qg_setting_internal('qg_ai_max_cost_krw_window', '300000'::jsonb) #>> '{}')::numeric, 300000);
  v_out jsonb := '[]'::jsonb; r record;
begin
  for r in select g.model_code m, count(*) filter (where g.status in ('ok','error') and not g.cache_hit) n, count(*) filter (where g.status = 'error') err,
                  avg(g.latency_ms) filter (where g.status = 'ok' and not g.cache_hit) lat, coalesce(sum(g.cost_krw), 0) cost
             from public.wpl_qga_ai_runs(now() - make_interval(days => v_days)) g
             join public.wpl_qg_ai_models m on m.code = g.model_code and m.provider <> 'rules'
            where (p_tenant is null or g.tenant_id = p_tenant)
            group by g.model_code loop
    if r.n >= v_min and r.err::numeric / r.n > v_rate then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'medium', 'fingerprint', 'failure_rate:' || r.m,
        'title', 'AI 모델 실패율 높음: ' || r.m || ' (' || round(r.err::numeric * 100 / r.n, 1) || '%)',
        'detail', jsonb_build_object('model', r.m, 'calls', r.n, 'errors', r.err, 'rate', round(r.err::numeric / r.n, 4), 'limit', v_rate, 'days', v_days)));
    end if;
    if r.lat is not null and r.lat > v_lat then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'low', 'fingerprint', 'latency:' || r.m,
        'title', 'AI 모델 응답 느림: ' || r.m || ' (평균 ' || to_char(round(r.lat), 'FM999,999,999') || 'ms)',
        'detail', jsonb_build_object('model', r.m, 'avg_latency_ms', round(r.lat), 'limit', v_lat, 'days', v_days)));
    end if;
    if r.cost > v_cost then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', 'cost:' || r.m,
        'title', 'AI 모델 비용 기준 초과: ' || r.m || ' (' || to_char(round(r.cost), 'FM999,999,999') || '원)',
        'detail', jsonb_build_object('model', r.m, 'cost_krw', round(r.cost), 'limit', v_cost, 'days', v_days)));
    end if;
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('days', v_days, 'message', '최근 기간 실패율·지연·비용이 모두 기준 안입니다.'));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_ai_usage_thresholds(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_ai_unapproved_use(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare
  v_days int := greatest(1, coalesce((p_check.params->>'days')::int, (public.wpl_qg_setting_internal('qg_ai_window_days', '7'::jsonb) #>> '{}')::int, 7));
  v_on boolean := coalesce((public.wpl_qg_setting_internal('qg_ai_require_approved', 'false'::jsonb) #>> '{}')::boolean, false);
  v_out jsonb := '[]'::jsonb; r record;
begin
  for r in select g.model_code m, g.task_code t, count(*) n, max(g.created_at) last_at
             from public.wpl_qga_ai_runs(now() - make_interval(days => v_days)) g
             left join public.wpl_qg_ai_models md on md.code = g.model_code
            where g.status = 'ok' and not g.cache_hit and coalesce(md.provider, '') <> 'rules' and (p_tenant is null or g.tenant_id = p_tenant)
              and not exists (select 1 from public.wpl_qg_ai_model_approvals a where a.model_code = g.model_code and a.task_code = g.task_code and a.status = 'approved')
            group by 1, 2 order by 3 desc loop
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', case when v_on then 'fail' else 'warn' end, 'severity', case when v_on then 'high' else 'medium' end,
      'fingerprint', 'unapproved:' || r.m || ':' || r.t,
      'title', '승인 안 된 AI 모델 사용: ' || r.m || ' × ' || r.t || ' (' || r.n || '회)',
      'detail', jsonb_build_object('model', r.m, 'task', r.t, 'runs', r.n, 'last_at', r.last_at, 'days', v_days, 'switch_on', v_on)));
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('days', v_days, 'switch_on', v_on, 'message', '최근 기간에 승인 안 된 모델이 쓰이지 않았습니다.'));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_ai_unapproved_use(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_ai_rules_only_tasks(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_on boolean := coalesce((public.wpl_qg_setting_internal('qg_ai_require_approved', 'false'::jsonb) #>> '{}')::boolean, false); v_list jsonb;
begin
  if not v_on then return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('switch_on', false, 'message', '스위치가 꺼져 있어 작업 라우팅대로 동작합니다.')); end if;
  select coalesce(jsonb_agg(t.code order by t.sort), '[]'::jsonb) into v_list from public.wpl_qg_ai_tasks t
   join public.wpl_qg_ai_models dm on dm.code = t.default_model and dm.provider <> 'rules'
   where t.active and not exists (select 1 from public.wpl_qg_ai_model_approvals a join public.wpl_qg_ai_models m on m.code = a.model_code and m.provider <> 'rules'
                                   where a.task_code = t.code and a.status = 'approved' and a.model_code in (t.default_model, coalesce(t.fallback_model, '')));
  if jsonb_array_length(v_list) = 0 then return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('switch_on', true)); end if;
  return jsonb_build_object('status', 'warn', 'severity', 'low', 'fingerprint', 'rules_only_tasks', 'title', '승인된 AI 모델이 없어 규칙으로만 도는 작업 ' || jsonb_array_length(v_list) || '개',
    'detail', jsonb_build_object('switch_on', true, 'tasks', v_list));
end $$;
revoke all on function public.wpl_qg_probe_ai_rules_only_tasks(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ───────── 7) 시드 ─────────
insert into public.wpl_qg_ai_models(code, provider, label, model_id, tier, sort) values
 ('rules', 'rules', '규칙 엔진(외부 호출 없음)', null, 'rules', 10),
 ('default_ai', 'anthropic', 'AI 기본 모델(환경변수 QG_AI_MODEL)', null, 'standard', 20)
on conflict (code) do nothing;

insert into public.wpl_qg_ai_tasks(code, name, description, risk_level, default_model, fallback_model, max_output_tokens, sort) values
 ('qg_review', '품질: 다중 독립 검토', '검토자 한 명의 관점에서 문서를 독립적으로 판정합니다(approve/concern/reject + 근거). AI 판정은 규칙 판정보다 느슨해질 수 없고, 사람이 최종 확정합니다.', 'high', 'default_ai', 'rules', 800, 10),
 ('qg_regulation_impact', '품질: 법령 변경 영향 분석', '바뀐 법령 원문을 읽고 어느 규칙·정책·템플릿에 영향이 있는지 제안합니다. 결과는 제안일 뿐이고 할 일은 규칙으로 만듭니다.', 'high', 'default_ai', 'rules', 1200, 20),
 ('qg_directive_polish', '품질: 개발 지시서 문장 다듬기', '개선 제안의 개발 지시서를 더 분명한 문장으로 다듬는 제안 — 사실·숫자·경로·링크는 바꾸지 않습니다.', 'low', 'default_ai', 'rules', 3000, 30)
on conflict (code) do nothing;

do $$ begin
  perform set_config('wpl.qg_write', 'on', true);
  insert into public.wpl_qg_ai_model_approvals(model_code, task_code, status, note)
  select m.code, t.code, case when m.provider = 'rules' then 'approved' else 'candidate' end,
         case when m.provider = 'rules' then '규칙 기반(외부 호출 없음) — 시작 시 승인' else null end
    from public.wpl_qg_ai_tasks t cross join public.wpl_qg_ai_models m
  on conflict (model_code, task_code) do nothing;
  perform set_config('wpl.qg_write', '', true);
end $$;

insert into public.wpl_qg_ai_eval_sets(code, task_code, name, description, system_prompt, input, context, rules, rules_output, sort) values
 ('review_legal_json', 'qg_review', '다중 검토 — 수익 보장 문구 판정(JSON)', '법무 검토자가 수익 보장 표현을 거부로 판정하고 JSON 형식을 지키는지 봅니다.',
  '너는 한국 법무 검토자다. 아래 문서를 검토해 JSON 하나로만 답한다: {"verdict":"approve|concern|reject","reasons":[{"message":"..."}],"summary":"..."}',
  '검토할 문서: 지금 가입하면 월 매출 500만원을 보장합니다. 지금 신청하세요.', null,
  '{"json":true,"required_keys":["verdict","reasons"],"max_len":2000,"min_len":10,"no_new_numbers":true}'::jsonb,
  '{"verdict":"reject","reasons":[{"message":"수익(매출) 보장 표현은 표시광고법·유사수신행위법 위험이 있습니다."}],"summary":"수익 보장 문구로 거부"}', 10),
 ('regulation_impact_json', 'qg_regulation_impact', '법령 영향 분석 — JSON 형식', '법령 변경 영향 분석이 요약·영향 목록을 JSON 으로 내는지 봅니다.',
  '너는 준법 분석가다. 바뀐 법령 원문을 읽고 JSON 하나로 답한다: {"summary":"...","affected":[{"kind":"rule|policy|template","code":"...","why":"..."}],"actions":["..."]}',
  '변경 원문: 광고성 정보는 수신자의 사전 동의를 받아야 하고 야간 전송은 별도 동의가 필요하다. 연결 대상: policy marketing_consent', null,
  '{"json":true,"required_keys":["summary","affected"],"max_len":4000,"min_len":20,"no_new_numbers":true}'::jsonb,
  '{"summary":"광고성 정보 사전 동의·야간 별도 동의","affected":[{"kind":"policy","code":"marketing_consent","why":"수신 동의 정책"}],"actions":["야간 발송 동의 확인"]}', 20),
 ('directive_polish_keep', 'qg_directive_polish', '지시서 다듬기 — 사실 보존', '다듬은 지시서가 길이·금칙어·새 숫자 규칙을 지키는지 봅니다.',
  '너는 기술 문서 편집자다. 아래 지시서를 더 분명하게 다듬되 사실·숫자·경로·링크는 바꾸지 않는다.',
  '# 개발 지시서 — 개선 제안 #1: 반복 이슈 근본 해결\n## 1. 배경\n같은 문제가 3번 발견됐습니다.', null,
  '{"min_len":20,"max_len":6000,"no_banned":true,"no_new_numbers":true}'::jsonb,
  '# 개발 지시서 — 개선 제안 #1: 반복 이슈 근본 해결\n## 1. 배경\n같은 문제가 3번 발견됐습니다.', 30)
on conflict (code) do update set task_code = excluded.task_code, name = excluded.name, description = excluded.description, system_prompt = excluded.system_prompt,
  input = excluded.input, context = excluded.context, rules = excluded.rules, rules_output = excluded.rules_output, sort = excluded.sort;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('ai_model.usage_thresholds', 'ai_model', 'AI 실패율·지연·비용 기준',
  '최근 기간 모델별 실패율·평균 응답 시간·비용이 기준(QG 설정 qg_ai_*)을 넘는지 봅니다(어댑터 wpl_qga_ai_runs).',
  'wpl_qg_probe_ai_usage_thresholds', 'medium', 'platform', 'daily', '{}'::jsonb,
  '기준 초과 0건',
  'AI 모델 평가·승인 화면에서 사용 추세를 보고, 실패가 많으면 공급자 장애·키·요금 한도를 확인하세요. 계속되면 그 모델을 정지하고 대체 모델·규칙으로 돌리세요.', 10),
 ('ai_model.unapproved_use', 'ai_model', '승인 안 된 AI 모델 사용',
  '최근 기간 실제로 성공한 AI 호출 중 그 작업에 승인되지 않은 모델이 쓰였는지 봅니다. ''승인된 모델만'' 스위치가 켜져 있으면 높음, 꺼져 있으면 보통.',
  'wpl_qg_probe_ai_unapproved_use', 'high', 'platform', 'daily', '{}'::jsonb,
  '승인 안 된 사용 0건',
  '평가를 실행해 통과하면 승인 요청 → 다른 관리자 승인. 쓰지 않을 모델이면 작업 라우팅에서 빼고, 필요하면 ''승인된 모델만'' 스위치를 켜세요.', 20),
 ('ai_model.rules_only_tasks', 'ai_model', '규칙으로만 도는 AI 작업',
  '''승인된 모델만'' 스위치가 켜져 있을 때, 기본·대체 모델 중 승인된 AI 모델이 없어 규칙으로만 동작하는 작업을 찾습니다.',
  'wpl_qg_probe_ai_rules_only_tasks', 'low', 'platform', 'weekly', '{}'::jsonb,
  '0개(또는 의도한 작업만)',
  '그 작업의 평가를 실행해 통과한 모델을 승인하거나, 규칙으로만 도는 것이 의도라면 이슈를 ''위험 수용''으로 닫으세요.', 30)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
  schedule = excluded.schedule, params = excluded.params, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort;
