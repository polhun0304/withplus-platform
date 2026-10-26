-- QG 키트 1.1.0 · 접두어 wpl · spine — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
-- =====================================================================
-- QG 키트 10 — 품질·거버넌스(QG) 공통 척추 (원본: F-MATRIX OS 2900, 2026-10-14 검증)
--  엔진(10) → 검사 항목(카탈로그) → 실행(run, 추가 전용) → 결과(finding, 추가 전용) → 이슈(사람이 분류·처리)
--  → 증거(해시체인, 추가 전용). 모든 엔진이 같은 표·같은 실행기·같은 증거 원장을 쓴다. 엔진별 차이는 probe 뿐.
--
--  · wpl_qg_settings        QG 정책값(업무 값은 여기 — 코드 상수 금지). 쓰기는 wpl_qg_setting_set(관리자) 만.
--  · wpl_qg_engines         카탈로그(10행, 11 시드)
--  · wpl_qg_checks          카탈로그: probe = 허용 목록 함수 이름(wpl_qg_probe_*) | suite:<파일> | scenario:<코드> | manual
--  · wpl_qg_runs            추가 전용
--  · wpl_qg_findings        추가 전용
--  · wpl_qg_issues          상태 표 — 바꾸기는 RPC(wpl_qg_issue_transition·wpl_qg_issue_decide)와 실행기만
--  · wpl_qg_issue_events    추가 전용(이슈 이력)
--  · wpl_qg_risk_approvals  위험 수용·오탐 확정 승인 요청(high/critical) — 4-eyes
--  · wpl_qg_evidence        추가 전용·해시체인: 방식 2(v1.1~) hash = sha256('v2|'prev|kind|ref|payload_sha256|created_at(UTC)|title|tenant_id|run_id|created_by)
--                              방식 1(v1.0 기록) hash = sha256(prev_hash|kind|ref|payload_sha256|created_at(UTC)) — 행마다 hash_v 로 구분
--  · wpl_qg_anon_allowlist  카탈로그: anon 실행이 허용된 SECURITY DEFINER 함수(설치 때 실측해서 채움 — QG_KIT.md §4.3)
--
--  플랫폼 의존은 어댑터(wpl_qga_*)만 부른다. pgcrypto 를 쓰지 않는다(내장 sha256·gen_random_uuid).
--  불변식: 카탈로그 문자열을 SQL 로 실행하지 않는다. probe 는 이름 정규식 + 존재 + 시그니처 확인 후 format('%I') 로만 호출.
--          모든 표 RLS · DEFINER 는 search_path 고정 + revoke … from public, anon, authenticated · anon 실행 함수 추가 0.
--  두 번 적용해도 같은 결과.
-- =====================================================================

-- ───────── 0) 공용 트리거 함수(플랫폼 코어 것을 빌리지 않는다) ─────────
create or replace function public.wpl_qg_forbid_mutation() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  raise exception '품질·거버넌스 기록은 추가만 할 수 있습니다(고치거나 지울 수 없음): %', tg_table_name;
end $$;
revoke all on function public.wpl_qg_forbid_mutation() from public, anon, authenticated;

-- 최소 어댑터의 자체 기록 표(wpl_qg_admin_log)도 추가 전용으로 막는다(v1.1 — 어댑터가 척추보다 먼저 만들어져 여기서 붙임)
do $$ begin
  if to_regclass('public.wpl_qg_admin_log') is not null then
    execute 'drop trigger if exists wpl_qg_admin_log_no_mutation on public.wpl_qg_admin_log';
    execute 'create trigger wpl_qg_admin_log_no_mutation before update or delete on public.wpl_qg_admin_log for each row execute function public.wpl_qg_forbid_mutation()';
    execute 'drop trigger if exists wpl_qg_admin_log_no_truncate on public.wpl_qg_admin_log';
    execute 'create trigger wpl_qg_admin_log_no_truncate before truncate on public.wpl_qg_admin_log for each statement execute function public.wpl_qg_forbid_mutation()';
  end if;
end $$;

-- 한국어 조사(받침 유무) — 사람 말 오류 문구용. p_pair 예: '을/를', '이/가', '은/는', '와/과', '으로/로'
create or replace function public.wpl_qg_josa_internal(p_word text, p_pair text) returns text
language plpgsql immutable set search_path = public as $$
declare c int; a text := split_part(p_pair, '/', 1); b text := split_part(p_pair, '/', 2); w text := btrim(coalesce(p_word, ''));
begin
  if w = '' then return coalesce(p_word, '') || a || '(' || b || ')'; end if;
  c := ascii(right(w, 1));
  if c between 44032 and 55203 then
    if (c - 44032) % 28 = 0 then return p_word || b; end if;
    if a = '으로' and (c - 44032) % 28 = 8 then return p_word || b; end if;   -- ㄹ 받침 + 로
    return p_word || a;
  end if;
  if right(w, 1) ~ '[0-9]' then return p_word || case when right(w, 1) in ('2','4','5','9') then b else a end; end if;
  return p_word || a || '(' || b || ')';
end $$;
revoke all on function public.wpl_qg_josa_internal(text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_touch() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.updated_at := now();
  return new;
end $$;
revoke all on function public.wpl_qg_touch() from public, anon, authenticated;

-- ───────── 1) 정책값 표 ─────────
create table if not exists public.wpl_qg_settings (
  key text primary key check (key ~ '^qg_[a-z0-9_]{2,60}$'),
  value jsonb not null,
  label text not null check (char_length(label) between 1 and 120),
  description text,
  updated_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
drop trigger if exists wpl_qg_settings_touch on public.wpl_qg_settings;
create trigger wpl_qg_settings_touch before update on public.wpl_qg_settings for each row execute function public.wpl_qg_touch();
alter table public.wpl_qg_settings enable row level security;
drop policy if exists wpl_qg_settings_read on public.wpl_qg_settings;
create policy wpl_qg_settings_read on public.wpl_qg_settings for select to authenticated using (public.wpl_qga_is_admin());
drop policy if exists wpl_qg_settings_no_delete on public.wpl_qg_settings;
create policy wpl_qg_settings_no_delete on public.wpl_qg_settings as restrictive for delete to authenticated, anon using (false);
revoke all on public.wpl_qg_settings from anon, authenticated;
grant select on public.wpl_qg_settings to authenticated;

insert into public.wpl_qg_settings(key, value, label, description) values
 ('qg_cron_enabled', 'true', '품질·거버넌스: 자동 실행(매시·매일) 켜기',
  '끄면 품질·거버넌스 엔진의 매시·매일 자동 실행이 멈춥니다(지금 실행 버튼은 계속 됨). 플랫폼 전역 긴급정지가 켜져 있어도 멈춥니다.'),
 ('qg_automation_kill', 'false', '품질·거버넌스: 자동 실행 긴급정지',
  '플랫폼에 전역 긴급정지 스위치가 없을 때 쓰는 QG 자체 긴급정지입니다(어댑터가 플랫폼 스위치를 쓰면 이 값은 보지 않을 수 있음).'),
 ('qg_issue_on_warn', 'true', '품질·거버넌스: 경고(warn)도 이슈로 만들기',
  '켜면 검사 결과가 ''주의''인 것도 이슈함에 올립니다(심각도는 검사가 정한 값, 없으면 낮음). 끄면 실패·오류만 이슈가 됩니다.'),
 ('qg_accept_risk_gate_severities', '["critical","high"]', '품질·거버넌스: 위험 수용·오탐 확정에 승인이 필요한 심각도',
  '이 심각도의 이슈를 ''위험 수용''이나 ''오탐''으로 닫으려면 다른 관리자의 승인이 필요합니다(요청자 본인 승인 불가). JSON 배열.'),
 ('qg_accept_note_min_len', '10', '품질·거버넌스: 위험 수용·오탐 사유 최소 글자 수',
  '''위험 수용''·''오탐''으로 바꿀 때 적어야 하는 사유의 최소 글자 수입니다.'),
 ('qg_self_approval_when_sole_admin', 'false', '품질·거버넌스: 관리자가 혼자일 때 자기 승인 허용',
  '기본은 꺼짐(자기가 요청한 위험 수용·출시·모델 승인은 스스로 승인할 수 없음). 켜면 다른 관리자가 아무도 없을 때만 예외로 허용합니다.'),
 ('qg_issue_sla_days', '{"critical":1,"high":3,"medium":14,"low":30}', '품질·거버넌스: 심각도별 처리 기한(일)',
  '이슈가 열리거나 다시 열릴 때 처리 기한 = 지금 + 이 일수. 기한이 지나면 이슈함·센터에 ''기한 넘김''으로 표시됩니다. JSON 객체.'),
 ('qg_hq_alert_severities', '["critical","high"]', '품질·거버넌스: 관리자 알림을 띄울 심각도',
  '이 심각도의 이슈가 새로 열리거나 다시 열리면 관리자 알림을 남깁니다(어댑터 wpl_qga_alert). JSON 배열.'),
 ('qg_max_findings_per_check', '200', '품질·거버넌스: 검사 1개가 한 번에 남길 수 있는 결과 수',
  '검사 함수가 이보다 많은 결과를 돌려주면 앞의 것만 기록하고 ''잘림'' 결과를 하나 더 남깁니다.'),
 ('qg_ingest_max_results', '2000', '품질·거버넌스: 외부 결과 올리기 1회 최대 건수',
  '스크립트·CI 가 테스트·시나리오 결과를 한 번에 올릴 수 있는 최대 결과 수입니다.'),
 ('qg_pass_rate_window_days', '7', '품질·거버넌스: 통과율 계산 기간(일)',
  '센터의 엔진 카드에 보이는 ''최근 통과율''을 계산하는 기간입니다.'),
 ('qg_detail_max_bytes', '8000', '품질·거버넌스: 결과 상세(JSON) 최대 크기(바이트)',
  '검사 결과 상세가 이보다 크면 앞부분만 남기고 잘렸다고 표시합니다(증거 원장 크기 보호).'),
 ('qg_issue_auto_fix_on_pass', 'true', '품질·거버넌스: 다시 통과하면 이슈를 확인 대기로',
  '켜면 열림·확인함 이슈가 같은 검사·대상의 다음 실행에서 나오지 않을 때 자동으로 ''고침(확인 대기)''으로 바뀌고, 그다음 실행에서도 통과하면 ''확인됨(해결)''이 됩니다. 끄면 마지막 통과 시각만 적습니다.'),
 ('qg_server_attest_key_hash', '""', '품질·거버넌스: 서버 증명키 해시(SHA-256)',
  '스크립트·CI 가 결과를 올릴 때 쓰는 서버 증명키(ENV QG_SERVER_ATTEST_KEY)의 SHA-256 16진수. 원문은 넣지 마세요. 비어 있으면 키 경로는 항상 거부됩니다(어댑터가 플랫폼 키를 쓰면 이 값은 보지 않을 수 있음).')
on conflict (key) do nothing;

-- 정책값 읽기(내부)
create or replace function public.wpl_qg_setting_internal(p_key text, p_default jsonb) returns jsonb
language sql stable security definer set search_path = public as $$
  select coalesce((select value from public.wpl_qg_settings where key = p_key), p_default)
$$;
revoke all on function public.wpl_qg_setting_internal(text, jsonb) from public, anon, authenticated;

-- 관리자: 정책값 바꾸기(있는 키만, 감사 기록). 서버 증명키 해시는 64자리 16진수 또는 빈 문자열만.
create or replace function public.wpl_qg_setting_set(p_key text, p_value jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare s public.wpl_qg_settings;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '품질·거버넌스 설정은 관리자만 바꿀 수 있습니다.'; end if;
  select * into s from public.wpl_qg_settings where key = p_key for update;
  if s.key is null then raise exception '없는 설정입니다.'; end if;
  if p_value is null then raise exception '값을 넣어 주세요.'; end if;
  if jsonb_typeof(p_value) is distinct from jsonb_typeof(s.value) then
    raise exception '설정 ''%''의 값 형식이 다릅니다(원래 %, 넣은 값 %).', s.label, jsonb_typeof(s.value), jsonb_typeof(p_value);
  end if;
  if p_key = 'qg_server_attest_key_hash' and (p_value #>> '{}') !~ '^([0-9a-f]{64})?$' then
    raise exception '서버 증명키 해시는 SHA-256 16진수 64자리(소문자)여야 합니다. 키 원문은 넣지 마세요.';
  end if;
  update public.wpl_qg_settings set value = p_value, updated_by = auth.uid() where key = p_key;
  perform public.wpl_qga_audit(null, 'user', 'qg.setting.set', 'wpl_qg_settings', p_key,
    jsonb_build_object('from', case when p_key = 'qg_server_attest_key_hash' then to_jsonb('(해시 감춤)'::text) else s.value end,
                       'to', case when p_key = 'qg_server_attest_key_hash' then to_jsonb('(해시 감춤)'::text) else p_value end));
  return jsonb_build_object('ok', true, 'key', p_key);
end $$;
revoke all on function public.wpl_qg_setting_set(text, jsonb) from public, anon, authenticated;
grant execute on function public.wpl_qg_setting_set(text, jsonb) to authenticated;

-- ───────── 2) 카탈로그: 엔진 · 검사 항목 · anon 허용 목록 ─────────
create table if not exists public.wpl_qg_engines (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{1,29}$'),
  name text not null check (char_length(name) between 1 and 60),
  purpose text,
  route text not null check (route ~ '^/[a-z0-9/_-]*qg(/[a-z0-9-]+)*$'),
  icon text not null default '🧪',
  enabled boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_checks (
  code text primary key check (code ~ '^[a-z][a-z0-9_.]{2,79}$'),
  engine_code text not null references public.wpl_qg_engines(code) on update cascade,
  name text not null check (char_length(name) between 1 and 120),
  description text,
  probe text not null constraint wpl_qg_checks_probe_check
    check (probe ~ '^(wpl_qg_probe_[a-z0-9_]{1,50}|suite:[A-Za-z0-9_./-]{1,200}|scenario:[a-z0-9_]{1,80}|manual)$' and probe !~ '\.\.'),
  risk text not null default 'medium' check (risk in ('critical','high','medium','low')),
  scope text not null default 'platform' check (scope in ('platform','tenant')),
  schedule text not null default 'manual' check (schedule in ('manual','hourly','daily','weekly','release')),
  params jsonb not null default '{}'::jsonb check (jsonb_typeof(params) = 'object'),
  expect text,
  remediation text,
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists wpl_qg_checks_engine_idx on public.wpl_qg_checks(engine_code, active, sort);

create table if not exists public.wpl_qg_anon_allowlist (
  signature text primary key check (signature ~ '^[a-z_][a-z0-9_]*\([a-z0-9_ ,\[\]]*\)$'),
  reason text not null check (char_length(reason) between 5 and 500 and reason !~* '^\s*(todo|tbd|xxx)'),
  protection text,
  active boolean not null default true,
  added_on date not null default current_date,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

drop trigger if exists wpl_qg_engines_touch on public.wpl_qg_engines;
create trigger wpl_qg_engines_touch before update on public.wpl_qg_engines for each row execute function public.wpl_qg_touch();
drop trigger if exists wpl_qg_checks_touch on public.wpl_qg_checks;
create trigger wpl_qg_checks_touch before update on public.wpl_qg_checks for each row execute function public.wpl_qg_touch();
drop trigger if exists wpl_qg_anon_allowlist_touch on public.wpl_qg_anon_allowlist;
create trigger wpl_qg_anon_allowlist_touch before update on public.wpl_qg_anon_allowlist for each row execute function public.wpl_qg_touch();

-- 카탈로그(엔진·검사·허용 목록)는 관리자만 읽는다(v1.1 — 검사 params 에 보안 예외 사유·내부 함수 목록이 들어가므로). 쓰기는 관리자만, 지우기 금지.
--  구성원 화면이 검사 이름을 보여 줘야 하면 결과(findings.title)나 화면 라벨을 쓴다(QG_KIT.md §8.4).
alter table public.wpl_qg_engines enable row level security;
alter table public.wpl_qg_checks enable row level security;
alter table public.wpl_qg_anon_allowlist enable row level security;
do $$ declare t text; begin
  foreach t in array array['wpl_qg_engines','wpl_qg_checks','wpl_qg_anon_allowlist'] loop
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

-- ───────── 3) 실행 · 결과 · 이슈 · 증거 ─────────
create table if not exists public.wpl_qg_evidence (
  id uuid primary key default gen_random_uuid(),
  seq bigint not null unique,
  kind text not null check (kind ~ '^[a-z][a-z0-9_]{1,39}$'),
  ref text not null check (char_length(ref) between 1 and 300),
  title text check (title is null or char_length(title) <= 300),
  tenant_id uuid,
  run_id uuid,
  payload jsonb,
  payload_sha256 text not null check (payload_sha256 ~ '^[0-9a-f]{64}$'),
  storage_url text check (storage_url is null or storage_url ~ '^https://'),
  prev_hash text not null,
  hash text not null unique check (hash ~ '^[0-9a-f]{64}$'),
  created_by uuid,
  created_at timestamptz not null default now(),
  check (payload is not null or storage_url is not null)
);
create index if not exists wpl_qg_evidence_kind_idx on public.wpl_qg_evidence(kind, seq desc);
create index if not exists wpl_qg_evidence_tenant_idx on public.wpl_qg_evidence(tenant_id, seq desc) where tenant_id is not null;
create index if not exists wpl_qg_evidence_run_idx on public.wpl_qg_evidence(run_id) where run_id is not null;
-- v1.1: 해시 방식 2 = 메타데이터(title·tenant_id·run_id·created_by)까지 덮음. 이전 기록은 방식 1 그대로(체인은 이어짐)
alter table public.wpl_qg_evidence add column if not exists hash_v smallint not null default 1;
do $$ begin
  if not exists (select 1 from pg_constraint where conrelid = 'public.wpl_qg_evidence'::regclass and conname = 'wpl_qg_evidence_hash_v_check') then
    alter table public.wpl_qg_evidence add constraint wpl_qg_evidence_hash_v_check check (hash_v in (1, 2));
  end if;
end $$;

create table if not exists public.wpl_qg_runs (
  id uuid primary key,
  engine_code text not null references public.wpl_qg_engines(code) on update cascade,
  tenant_id uuid,
  trigger text not null check (trigger in ('manual','cron','release','script','ci')),
  schedule text check (schedule is null or schedule in ('hourly','daily','weekly','release')),
  context jsonb not null default '{}'::jsonb,
  started_at timestamptz not null,
  finished_at timestamptz not null,
  duration_ms int not null default 0,
  checks_run int not null default 0,
  totals jsonb not null default '{}'::jsonb,
  status text not null check (status in ('passed','warned','failed','error','empty')),
  actor uuid,
  actor_label text,
  evidence_id uuid references public.wpl_qg_evidence(id),
  created_at timestamptz not null default now()
);
create index if not exists wpl_qg_runs_engine_idx on public.wpl_qg_runs(engine_code, finished_at desc);
create index if not exists wpl_qg_runs_tenant_idx on public.wpl_qg_runs(tenant_id, finished_at desc) where tenant_id is not null;

create table if not exists public.wpl_qg_issues (
  id uuid primary key default gen_random_uuid(),
  fingerprint text not null unique check (char_length(fingerprint) between 3 and 400),
  engine_code text not null references public.wpl_qg_engines(code) on update cascade,
  check_code text not null references public.wpl_qg_checks(code) on update cascade,
  tenant_id uuid,
  severity text not null check (severity in ('critical','high','medium','low')),
  title text not null,
  status text not null default 'open' check (status in ('open','acknowledged','fixed','verified','accepted_risk','false_positive')),
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  last_pass_at timestamptz,
  occurrences int not null default 1 check (occurrences >= 1),
  last_run_id uuid,
  last_finding_id uuid,
  last_detail jsonb,
  due_at timestamptz,
  owner uuid,
  note text,
  approval_id uuid,
  status_changed_at timestamptz not null default now(),
  status_changed_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists wpl_qg_issues_status_idx on public.wpl_qg_issues(status, severity, last_seen desc);
create index if not exists wpl_qg_issues_engine_idx on public.wpl_qg_issues(engine_code, status);
create index if not exists wpl_qg_issues_check_idx on public.wpl_qg_issues(check_code, tenant_id);

create table if not exists public.wpl_qg_findings (
  id uuid primary key,
  run_id uuid not null references public.wpl_qg_runs(id),
  engine_code text not null,
  check_code text not null references public.wpl_qg_checks(code) on update cascade,
  tenant_id uuid,
  status text not null check (status in ('pass','warn','fail','error','skipped')),
  severity text check (severity is null or severity in ('critical','high','medium','low')),
  fingerprint text,
  title text,
  detail jsonb not null default '{}'::jsonb,
  issue_id uuid references public.wpl_qg_issues(id),
  evidence_id uuid references public.wpl_qg_evidence(id),
  created_at timestamptz not null default now()
);
create index if not exists wpl_qg_findings_run_idx on public.wpl_qg_findings(run_id);
create index if not exists wpl_qg_findings_issue_idx on public.wpl_qg_findings(issue_id) where issue_id is not null;
create index if not exists wpl_qg_findings_check_idx on public.wpl_qg_findings(check_code, created_at desc);

create table if not exists public.wpl_qg_risk_approvals (
  id uuid primary key default gen_random_uuid(),
  issue_id uuid not null references public.wpl_qg_issues(id),
  tenant_id uuid,
  to_status text not null check (to_status in ('accepted_risk','false_positive')),
  severity text not null,
  request_note text not null,
  requested_by uuid,
  requested_at timestamptz not null default now(),
  status text not null default 'pending' check (status in ('pending','approved','rejected','cancelled')),
  decided_by uuid,
  decided_at timestamptz,
  decision_note text,
  evidence_id uuid references public.wpl_qg_evidence(id)
);
create unique index if not exists wpl_qg_risk_approvals_one_pending on public.wpl_qg_risk_approvals(issue_id) where status = 'pending';

create table if not exists public.wpl_qg_issue_events (
  id bigint generated always as identity primary key,
  issue_id uuid not null references public.wpl_qg_issues(id),
  tenant_id uuid,
  action text not null check (action in ('open','reopen','seen','transition','request','approve','reject','cancel','auto_verify','escalate')),
  from_status text,
  to_status text,
  note text,
  run_id uuid,
  approval_id uuid,
  actor uuid,
  created_at timestamptz not null default now()
);
create index if not exists wpl_qg_issue_events_issue_idx on public.wpl_qg_issue_events(issue_id, id desc);

-- 추가 전용 가드(행 단위 UPDATE/DELETE + 문장 단위 TRUNCATE)
do $$ declare t text; begin
  foreach t in array array['wpl_qg_runs','wpl_qg_findings','wpl_qg_evidence','wpl_qg_issue_events'] loop
    execute format('drop trigger if exists %I on public.%I', t || '_no_mutation', t);
    execute format('create trigger %I before update or delete on public.%I for each row execute function public.wpl_qg_forbid_mutation()', t || '_no_mutation', t);
    execute format('drop trigger if exists %I on public.%I', t || '_no_truncate', t);
    execute format('create trigger %I before truncate on public.%I for each statement execute function public.wpl_qg_forbid_mutation()', t || '_no_truncate', t);
  end loop;
end $$;

-- 상태 표 가드: 실행기·전이 RPC 안에서만 바꿀 수 있다(트랜잭션 로컬 표시 wpl.qg_write = on), 지우기 금지
create or replace function public.wpl_qg_state_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'DELETE' then raise exception '품질·거버넌스 기록은 지울 수 없습니다.'; end if;
  if coalesce(current_setting('wpl.qg_write', true), '') <> 'on' then
    raise exception '이 상태는 품질·거버넌스 화면의 절차(상태 바꾸기·판정·승인)로만 바꿀 수 있습니다.';
  end if;
  if tg_table_name = 'wpl_qg_issues' then
    if new.fingerprint is distinct from old.fingerprint or new.check_code is distinct from old.check_code
       or new.tenant_id is distinct from old.tenant_id or new.first_seen is distinct from old.first_seen then
      raise exception '이슈의 지문·검사·테넌트·처음 발견 시각은 바꿀 수 없습니다.';
    end if;
  end if;
  if to_jsonb(new) ? 'updated_at' then
    new := jsonb_populate_record(new, jsonb_build_object('updated_at', now()));
  end if;
  return new;
end $$;
revoke all on function public.wpl_qg_state_guard() from public, anon, authenticated;
drop trigger if exists wpl_qg_issues_guard on public.wpl_qg_issues;
create trigger wpl_qg_issues_guard before update or delete on public.wpl_qg_issues for each row execute function public.wpl_qg_state_guard();
drop trigger if exists wpl_qg_risk_approvals_guard on public.wpl_qg_risk_approvals;
create trigger wpl_qg_risk_approvals_guard before update or delete on public.wpl_qg_risk_approvals for each row execute function public.wpl_qg_state_guard();

-- RLS: 관리자 전부, 테넌트 구성원은 내 테넌트(tenant_id) 범위만 읽기(어댑터 can_read_tenant). 쓰기는 DEFINER RPC 로만.
do $$ declare t text; begin
  foreach t in array array['wpl_qg_runs','wpl_qg_findings','wpl_qg_issues','wpl_qg_evidence','wpl_qg_issue_events'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists %I on public.%I', t || '_read', t);
    execute format('create policy %I on public.%I for select to authenticated using (public.wpl_qga_is_admin() or (tenant_id is not null and public.wpl_qga_can_read_tenant(tenant_id)))', t || '_read', t);
    execute format('drop policy if exists %I on public.%I', t || '_no_delete', t);
    execute format('create policy %I on public.%I as restrictive for delete to authenticated, anon using (false)', t || '_no_delete', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
  end loop;
end $$;
alter table public.wpl_qg_risk_approvals enable row level security;
drop policy if exists wpl_qg_risk_approvals_read on public.wpl_qg_risk_approvals;
create policy wpl_qg_risk_approvals_read on public.wpl_qg_risk_approvals for select to authenticated using (public.wpl_qga_is_admin());
drop policy if exists wpl_qg_risk_approvals_no_delete on public.wpl_qg_risk_approvals;
create policy wpl_qg_risk_approvals_no_delete on public.wpl_qg_risk_approvals as restrictive for delete to authenticated, anon using (false);
revoke all on public.wpl_qg_risk_approvals from anon, authenticated;
grant select on public.wpl_qg_risk_approvals to authenticated;

-- ───────── 4) 작은 도우미 ─────────
create or replace function public.wpl_qg_sev_rank_internal(p text) returns int
language sql immutable set search_path = public as $$
  select case p when 'critical' then 4 when 'high' then 3 when 'medium' then 2 when 'low' then 1 else 0 end
$$;
revoke all on function public.wpl_qg_sev_rank_internal(text) from public, anon, authenticated;

create or replace function public.wpl_qg_actor_label_internal() returns text
language sql stable security definer set search_path = public as $$
  select coalesce(public.wpl_qga_user_label(auth.uid()), case when auth.uid() is null then '시스템' else '사용자' end)
$$;
revoke all on function public.wpl_qg_actor_label_internal() from public, anon, authenticated;

-- 자기 승인 금지 판정: 요청자 = 결정자이면, 다른 관리자가 없고 설정이 켜졌을 때만 허용
create or replace function public.wpl_qg_self_approval_ok_internal(p_requested_by uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select p_requested_by is distinct from auth.uid()
      or (public.wpl_qga_admin_count_except(auth.uid()) = 0
          and coalesce((public.wpl_qg_setting_internal('qg_self_approval_when_sole_admin', 'false'::jsonb) #>> '{}')::boolean, false))
$$;
revoke all on function public.wpl_qg_self_approval_ok_internal(uuid) from public, anon, authenticated;

-- ───────── 5) 증거 원장(해시체인) ─────────
create or replace function public.wpl_qg_evidence_hash_internal(p_prev text, p_kind text, p_ref text, p_payload_sha text, p_at timestamptz)
returns text language sql immutable set search_path = public as $$
  select encode(sha256(convert_to(coalesce(p_prev, '') || '|' || coalesce(p_kind, '') || '|' || coalesce(p_ref, '') || '|' || coalesce(p_payload_sha, '') || '|'
    || to_char(p_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'), 'UTF8')), 'hex')
$$;
revoke all on function public.wpl_qg_evidence_hash_internal(text, text, text, text, timestamptz) from public, anon, authenticated;

-- 방식 2: 방식 1 의 입력 + 제목·테넌트·실행·작성자(내려받은 묶음에서 메타데이터를 바꿔도 검증이 잡는다)
create or replace function public.wpl_qg_evidence_hash2_internal(p_prev text, p_kind text, p_ref text, p_payload_sha text, p_at timestamptz,
  p_title text, p_tenant text, p_run text, p_by text)
returns text language sql immutable set search_path = public as $$
  select encode(sha256(convert_to('v2|' || coalesce(p_prev, '') || '|' || coalesce(p_kind, '') || '|' || coalesce(p_ref, '') || '|' || coalesce(p_payload_sha, '') || '|'
    || to_char(p_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') || '|' || coalesce(p_title, '') || '|' || coalesce(lower(p_tenant), '') || '|'
    || coalesce(lower(p_run), '') || '|' || coalesce(lower(p_by), ''), 'UTF8')), 'hex')
$$;
revoke all on function public.wpl_qg_evidence_hash2_internal(text, text, text, text, timestamptz, text, text, text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_payload_sha_internal(p jsonb) returns text
language sql immutable set search_path = public as $$
  select encode(sha256(convert_to(p::text, 'UTF8')), 'hex')
$$;
revoke all on function public.wpl_qg_payload_sha_internal(jsonb) from public, anon, authenticated;

-- 넣을 때 순번·이전 해시·해시·시각을 DB가 직접 정한다(넣는 쪽이 준 값은 무시)
create or replace function public.wpl_qg_evidence_chain_trg() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_prev text; v_seq bigint;
begin
  perform pg_advisory_xact_lock(hashtext('wpl_qg_evidence_chain'));
  select e.seq, e.hash into v_seq, v_prev from public.wpl_qg_evidence e order by e.seq desc limit 1;
  new.seq := coalesce(v_seq, 0) + 1;
  new.prev_hash := coalesce(v_prev, 'GENESIS');
  new.created_at := now();
  if new.payload is not null then
    new.payload_sha256 := public.wpl_qg_payload_sha_internal(new.payload);
  elsif coalesce(new.payload_sha256, '') !~ '^[0-9a-f]{64}$' then
    raise exception '외부 저장 증거는 내용의 SHA-256 을 함께 넣어야 합니다.';
  end if;
  new.hash_v := 2;
  new.hash := public.wpl_qg_evidence_hash2_internal(new.prev_hash, new.kind, new.ref, new.payload_sha256, new.created_at,
                new.title, new.tenant_id::text, new.run_id::text, new.created_by::text);
  return new;
end $$;
revoke all on function public.wpl_qg_evidence_chain_trg() from public, anon, authenticated;
drop trigger if exists wpl_qg_evidence_chain_bi on public.wpl_qg_evidence;
create trigger wpl_qg_evidence_chain_bi before insert on public.wpl_qg_evidence for each row execute function public.wpl_qg_evidence_chain_trg();

create or replace function public.wpl_qg_evidence_append(p_kind text, p_ref text, p_payload jsonb, p_title text default null,
  p_tenant uuid default null, p_run uuid default null, p_storage_url text default null, p_payload_sha text default null)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  insert into public.wpl_qg_evidence(kind, ref, title, tenant_id, run_id, payload, payload_sha256, storage_url, prev_hash, hash, created_by)
  values (p_kind, left(p_ref, 300), left(p_title, 300), p_tenant, p_run, p_payload, lower(p_payload_sha), p_storage_url, null, null, auth.uid())
  returning id into v_id;
  return v_id;
end $$;
revoke all on function public.wpl_qg_evidence_append(text, text, jsonb, text, uuid, uuid, text, text) from public, anon, authenticated;

-- 행 묶음(JSON 배열, seq 오름차순)의 체인 검증 — 표의 행이든, 내려받은 묶음이든, 손댄 사본이든 같은 규칙
create or replace function public.wpl_qg_evidence_verify_rows_internal(p_rows jsonb)
returns jsonb language plpgsql stable set search_path = public as $$
declare x jsonb; v_prev text := 'GENESIS'; v_prev_seq bigint := 0; v_n bigint := 0; v_sha text; v_calc text;
begin
  for x in select e from jsonb_array_elements(coalesce(p_rows, '[]'::jsonb)) e order by (e->>'seq')::bigint loop
    v_n := v_n + 1;
    if (x->>'seq')::bigint <> v_prev_seq + 1 then
      return jsonb_build_object('ok', false, 'checked', v_n, 'broken_seq', (x->>'seq')::bigint, 'broken_id', x->>'id', 'reason', 'gap',
        'message', format('%s번 앞에 빠진 기록이 있습니다(%s번 다음이 %s번).', x->>'seq', v_prev_seq, x->>'seq'));
    end if;
    if x->>'prev_hash' is distinct from v_prev then
      return jsonb_build_object('ok', false, 'checked', v_n, 'broken_seq', (x->>'seq')::bigint, 'broken_id', x->>'id', 'reason', 'prev_hash',
        'message', format('%s번의 이전 해시가 앞 기록과 이어지지 않습니다.', x->>'seq'));
    end if;
    if x->'payload' is not null and jsonb_typeof(x->'payload') <> 'null' then
      v_sha := public.wpl_qg_payload_sha_internal(x->'payload');
      if v_sha is distinct from x->>'payload_sha256' then
        return jsonb_build_object('ok', false, 'checked', v_n, 'broken_seq', (x->>'seq')::bigint, 'broken_id', x->>'id', 'reason', 'payload',
          'message', format('%s번의 내용이 기록 당시 지문(SHA-256)과 다릅니다.', x->>'seq'));
      end if;
    end if;
    if coalesce(x->>'hash_v', '1') = '2' then
      v_calc := public.wpl_qg_evidence_hash2_internal(x->>'prev_hash', x->>'kind', x->>'ref', x->>'payload_sha256', (x->>'created_at')::timestamptz,
                  x->>'title', x->>'tenant_id', x->>'run_id', x->>'created_by');
    else
      v_calc := public.wpl_qg_evidence_hash_internal(x->>'prev_hash', x->>'kind', x->>'ref', x->>'payload_sha256', (x->>'created_at')::timestamptz);
    end if;
    if v_calc is distinct from x->>'hash' then
      return jsonb_build_object('ok', false, 'checked', v_n, 'broken_seq', (x->>'seq')::bigint, 'broken_id', x->>'id', 'reason', 'hash',
        'message', format('%s번의 해시가 다시 계산한 값과 다릅니다(종류·대상·시각·지문%s 중 하나가 바뀜).', x->>'seq',
                          case when coalesce(x->>'hash_v', '1') = '2' then '·제목·테넌트·실행·작성자' else '' end));
    end if;
    v_prev := x->>'hash';
    v_prev_seq := (x->>'seq')::bigint;
  end loop;
  return jsonb_build_object('ok', true, 'checked', v_n, 'broken_seq', null, 'broken_id', null, 'reason', null, 'last_hash', v_prev,
    'message', case when v_n = 0 then '아직 증거가 없습니다.' else format('증거 %s건의 체인이 처음부터 끝까지 이어집니다.', v_n) end);
end $$;
revoke all on function public.wpl_qg_evidence_verify_rows_internal(jsonb) from public, anon, authenticated;

create or replace function public.wpl_qg_evidence_rows_internal(p_limit int default 1000000)
returns jsonb language sql stable security definer set search_path = public as $$
  select coalesce(jsonb_agg(jsonb_build_object('id', e.id, 'seq', e.seq, 'kind', e.kind, 'ref', e.ref, 'payload', e.payload, 'payload_sha256', e.payload_sha256,
           'prev_hash', e.prev_hash, 'hash', e.hash, 'created_at', e.created_at, 'hash_v', e.hash_v, 'title', e.title, 'tenant_id', e.tenant_id,
           'run_id', e.run_id, 'created_by', e.created_by) order by e.seq), '[]'::jsonb)
    from (select * from public.wpl_qg_evidence order by seq limit greatest(1, p_limit)) e
$$;
revoke all on function public.wpl_qg_evidence_rows_internal(int) from public, anon, authenticated;

-- 관리자: 증거 체인 검증(끊긴 위치 반환) — 감사 기록도 남긴다
create or replace function public.wpl_qg_verify_evidence_chain()
returns jsonb language plpgsql security definer set search_path = public as $$
declare v jsonb;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '증거 체인 검증은 관리자만 할 수 있습니다.'; end if;
  v := public.wpl_qg_evidence_verify_rows_internal(public.wpl_qg_evidence_rows_internal()) || jsonb_build_object('verified_at', now());
  perform public.wpl_qga_audit(null, 'user', 'qg.evidence.verify', 'wpl_qg_evidence', v->>'broken_id',
    jsonb_build_object('ok', v->'ok', 'checked', v->'checked', 'broken_seq', v->'broken_seq', 'reason', v->'reason'));
  return v;
end $$;
revoke all on function public.wpl_qg_verify_evidence_chain() from public, anon, authenticated;
grant execute on function public.wpl_qg_verify_evidence_chain() to authenticated;

-- ───────── 6) probe 허용 목록 확인 · 호출 ─────────
create or replace function public.wpl_qg_probe_resolve_internal(p_name text)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_oid oid;
begin
  if p_name is null or p_name !~ '^wpl_qg_probe_[a-z0-9_]+$' or char_length(p_name) > 63 then
    return jsonb_build_object('ok', false, 'reason', 'probe_invalid_name', 'message', '검사 함수 이름이 허용 규칙(wpl_qg_probe_…)에 맞지 않아 실행하지 않았습니다.');
  end if;
  select p.oid into v_oid from pg_proc p
   where p.pronamespace = 'public'::regnamespace and p.proname = p_name and p.prokind = 'f' and p.pronargs = 2
     and p.proargtypes[0] = 'public.wpl_qg_checks'::regtype and p.proargtypes[1] = 'uuid'::regtype and p.prorettype = 'jsonb'::regtype
     and not p.proretset;
  if v_oid is null then
    if exists (select 1 from pg_proc p where p.pronamespace = 'public'::regnamespace and p.proname = p_name) then
      return jsonb_build_object('ok', false, 'reason', 'probe_bad_signature', 'message', '검사 함수의 모양이 규약((wpl_qg_checks, uuid) returns jsonb)과 달라 실행하지 않았습니다.');
    end if;
    return jsonb_build_object('ok', false, 'reason', 'probe_missing', 'message', '검사 함수가 아직 없습니다(담당 엔진이 만들 예정이거나 이름이 틀림).');
  end if;
  return jsonb_build_object('ok', true, 'name', p_name);
end $$;
revoke all on function public.wpl_qg_probe_resolve_internal(text) from public, anon, authenticated;

create or replace function public.wpl_qg_clip_detail_internal(p jsonb) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_max int := greatest(500, coalesce((public.wpl_qg_setting_internal('qg_detail_max_bytes', '8000'::jsonb) #>> '{}')::int, 8000)); v_txt text;
begin
  if p is null or jsonb_typeof(p) = 'null' then return '{}'::jsonb; end if;
  v_txt := p::text;
  if octet_length(v_txt) <= v_max then
    return case when jsonb_typeof(p) = 'object' then p else jsonb_build_object('value', p) end;
  end if;
  return jsonb_build_object('truncated', true, 'bytes', octet_length(v_txt), 'preview', left(v_txt, v_max / 2));
end $$;
revoke all on function public.wpl_qg_clip_detail_internal(jsonb) from public, anon, authenticated;

create or replace function public.wpl_qg_norm_finding_internal(p jsonb, p_risk text)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_status text; v_sev text; v_fp text; v_title text; v_detail jsonb;
begin
  if p is null or jsonb_typeof(p) <> 'object' then
    return jsonb_build_object('status', 'error', 'severity', 'medium', 'fingerprint', 'bad_result', 'title', '검사 결과 형식 오류',
      'detail', jsonb_build_object('message', '검사 함수가 객체가 아닌 값을 돌려줬습니다.', 'got', left(coalesce(p::text, 'null'), 300)));
  end if;
  v_status := p->>'status';
  if v_status is null or v_status not in ('pass','warn','fail','error','skipped') then
    return jsonb_build_object('status', 'error', 'severity', 'medium', 'fingerprint', 'bad_status', 'title', '검사 결과 형식 오류',
      'detail', jsonb_build_object('message', '상태(status)는 pass·warn·fail·error·skipped 중 하나여야 합니다.', 'got', left(coalesce(p->>'status', 'null'), 50)));
  end if;
  v_sev := nullif(p->>'severity', '');
  if v_sev is not null and v_sev not in ('critical','high','medium','low') then v_sev := null; end if;
  v_sev := case v_status when 'fail' then coalesce(v_sev, p_risk, 'medium')
                         when 'error' then coalesce(v_sev, 'medium')
                         when 'warn' then coalesce(v_sev, 'low')
                         else null end;
  v_fp := nullif(left(regexp_replace(coalesce(p->>'fingerprint', ''), '[[:cntrl:]]', '', 'g'), 200), '');
  v_title := nullif(left(coalesce(p->>'title', ''), 300), '');
  v_detail := public.wpl_qg_clip_detail_internal(case when p ? 'detail' then p->'detail' else p - array['status','severity','fingerprint','title'] end);
  return jsonb_build_object('status', v_status, 'severity', v_sev, 'fingerprint', v_fp, 'title', v_title, 'detail', v_detail);
end $$;
revoke all on function public.wpl_qg_norm_finding_internal(jsonb, text) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_call_internal(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_res jsonb; v_out jsonb := '[]'::jsonb; v_r jsonb; x jsonb; v_n int := 0;
        v_max int := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_max_findings_per_check', '200'::jsonb) #>> '{}')::int, 200));
begin
  v_r := public.wpl_qg_probe_resolve_internal(p_check.probe);
  if not (v_r->>'ok')::boolean then
    return jsonb_build_array(jsonb_build_object('status', 'error', 'severity', 'medium', 'fingerprint', v_r->>'reason', 'title', '검사 함수를 실행하지 않음',
      'detail', jsonb_build_object('reason', v_r->>'reason', 'message', v_r->>'message', 'probe', left(p_check.probe, 120))));
  end if;
  begin
    execute format('select public.%I($1, $2)', v_r->>'name') into v_res using p_check, p_tenant;
  exception when others then
    return jsonb_build_array(jsonb_build_object('status', 'error', 'severity', 'medium', 'fingerprint', 'probe_exception', 'title', '검사 함수 실행 중 오류',
      'detail', jsonb_build_object('reason', 'probe_exception', 'message', left(sqlerrm, 500), 'sqlstate', sqlstate)));
  end;
  if v_res is null or jsonb_typeof(v_res) = 'null' then
    return jsonb_build_array(jsonb_build_object('status', 'error', 'severity', 'medium', 'fingerprint', 'probe_null', 'title', '검사 함수가 결과를 돌려주지 않음',
      'detail', jsonb_build_object('reason', 'probe_null')));
  end if;
  if jsonb_typeof(v_res) = 'object' then v_res := jsonb_build_array(v_res); end if;
  if jsonb_typeof(v_res) <> 'array' then
    return jsonb_build_array(public.wpl_qg_norm_finding_internal(v_res, p_check.risk));
  end if;
  if jsonb_array_length(v_res) = 0 then
    return jsonb_build_array(jsonb_build_object('status', 'pass', 'severity', null, 'fingerprint', null, 'title', null, 'detail', jsonb_build_object('message', '문제 없음')));
  end if;
  for x in select e from jsonb_array_elements(v_res) e loop
    v_n := v_n + 1;
    if v_n > v_max then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'low', 'fingerprint', 'truncated', 'title', '결과가 너무 많아 잘림',
        'detail', jsonb_build_object('total', jsonb_array_length(v_res), 'kept', v_max)));
      exit;
    end if;
    v_out := v_out || jsonb_build_array(public.wpl_qg_norm_finding_internal(x, p_check.risk));
  end loop;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_call_internal(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ───────── 7) 이슈 갱신(실행기 내부) ─────────
create or replace function public.wpl_qg_issue_event_internal(p_issue uuid, p_tenant uuid, p_action text, p_from text, p_to text, p_note text, p_run uuid, p_approval uuid)
returns void language sql security definer set search_path = public as $$
  insert into public.wpl_qg_issue_events(issue_id, tenant_id, action, from_status, to_status, note, run_id, approval_id, actor)
  values (p_issue, p_tenant, p_action, p_from, p_to, left(p_note, 2000), p_run, p_approval, auth.uid())
$$;
revoke all on function public.wpl_qg_issue_event_internal(uuid, uuid, text, text, text, text, uuid, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_issue_due_internal(p_sev text) returns timestamptz
language sql stable security definer set search_path = public as $$
  select now() + make_interval(days => greatest(0, coalesce((public.wpl_qg_setting_internal('qg_issue_sla_days', '{"critical":1,"high":3,"medium":14,"low":30}'::jsonb) ->> p_sev)::int,
                                                            case p_sev when 'critical' then 1 when 'high' then 3 when 'medium' then 14 else 30 end)))
$$;
revoke all on function public.wpl_qg_issue_due_internal(text) from public, anon, authenticated;

create or replace function public.wpl_qg_issue_alert_internal(i public.wpl_qg_issues, p_reopen boolean)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not (public.wpl_qg_setting_internal('qg_hq_alert_severities', '["critical","high"]'::jsonb) ? i.severity) then return; end if;
  begin
    perform public.wpl_qga_alert(case when i.severity in ('critical','high') then 'high' else 'medium' end,
      case when p_reopen then '품질 이슈 다시 열림: ' else '새 품질 이슈: ' end || left(i.title, 150),
      '심각도 ' || case i.severity when 'critical' then '치명' when 'high' then '높음' when 'medium' then '보통' else '낮음' end
        || ' · 검사 ' || i.check_code || ' · 처리 기한 ' || coalesce(to_char(i.due_at at time zone 'Asia/Seoul', 'YYYY-MM-DD HH24:MI'), '-'),
      '/admin/qg/issues?issue=' || i.id::text,
      'qg_issue:' || i.id::text || ':' || to_char(now() at time zone 'Asia/Seoul', 'YYYY-MM-DD"T"HH24'));
  exception when others then null;   -- 알림 실패가 검사 기록을 막지 않는다
  end;
end $$;
revoke all on function public.wpl_qg_issue_alert_internal(public.wpl_qg_issues, boolean) from public, anon, authenticated;

-- 실패 결과 → 이슈 열기/다시 열기/누적. 이슈 id 반환. 호출 전에 wpl.qg_write = on.
create or replace function public.wpl_qg_issue_upsert_internal(p_engine text, p_check text, p_tenant uuid, p_fp text, p_sev text, p_title text,
  p_detail jsonb, p_run uuid, p_finding uuid)
returns uuid language plpgsql security definer set search_path = public as $$
declare i public.wpl_qg_issues; v_from text;
begin
  select * into i from public.wpl_qg_issues where fingerprint = p_fp for update;
  if i.id is null then
    insert into public.wpl_qg_issues(fingerprint, engine_code, check_code, tenant_id, severity, title, status, last_run_id, last_finding_id, last_detail, due_at)
    values (p_fp, p_engine, p_check, p_tenant, p_sev, p_title, 'open', p_run, p_finding, p_detail, public.wpl_qg_issue_due_internal(p_sev))
    returning * into i;
    perform public.wpl_qg_issue_event_internal(i.id, i.tenant_id, 'open', null, 'open', null, p_run, null);
    perform public.wpl_qg_issue_alert_internal(i, false);
    return i.id;
  end if;
  v_from := i.status;
  if i.status in ('fixed','verified')
     or (i.status in ('accepted_risk','false_positive') and public.wpl_qg_sev_rank_internal(p_sev) > public.wpl_qg_sev_rank_internal(i.severity)) then
    update public.wpl_qg_issues set status = 'open', severity = case when public.wpl_qg_sev_rank_internal(p_sev) > public.wpl_qg_sev_rank_internal(severity) then p_sev else severity end,
           title = p_title, last_seen = now(), occurrences = occurrences + 1, last_run_id = p_run, last_finding_id = p_finding, last_detail = p_detail,
           due_at = public.wpl_qg_issue_due_internal(p_sev), status_changed_at = now(), status_changed_by = null, approval_id = null
     where id = i.id returning * into i;
    perform public.wpl_qg_issue_event_internal(i.id, i.tenant_id, 'reopen', v_from, 'open',
      case when v_from in ('fixed','verified') then '고친 뒤 같은 문제가 다시 발견됨' else '수용한 위험보다 심각도가 올라감' end, p_run, null);
    perform public.wpl_qg_issue_alert_internal(i, true);
  else
    if public.wpl_qg_sev_rank_internal(p_sev) > public.wpl_qg_sev_rank_internal(i.severity) then
      perform public.wpl_qg_issue_event_internal(i.id, i.tenant_id, 'escalate', i.status, i.status, '심각도 ' || i.severity || ' → ' || p_sev, p_run, null);
    end if;
    update public.wpl_qg_issues set severity = case when public.wpl_qg_sev_rank_internal(p_sev) > public.wpl_qg_sev_rank_internal(severity) then p_sev else severity end,
           title = p_title, last_seen = now(), occurrences = occurrences + 1, last_run_id = p_run, last_finding_id = p_finding, last_detail = p_detail
     where id = i.id;
  end if;
  return i.id;
end $$;
revoke all on function public.wpl_qg_issue_upsert_internal(text, text, uuid, text, text, text, jsonb, uuid, uuid) from public, anon, authenticated;

-- ───────── 8) 실행 기록(실행기·외부 결과 공통) ─────────
create or replace function public.wpl_qg_record_run_internal(p_engine text, p_tenant uuid, p_trigger text, p_schedule text, p_context jsonb,
  p_findings jsonb, p_actor uuid, p_started timestamptz, p_checks_run int)
returns uuid language plpgsql security definer set search_path = public as $$
declare
  v_run uuid := gen_random_uuid(); v_ev uuid; v_list jsonb := '[]'::jsonb; x jsonb; c public.wpl_qg_checks; v_fp text; v_tenant uuid; v_title text;
  v_totals jsonb; v_status text; v_issue uuid; v_fid uuid; v_warn boolean := coalesce((public.wpl_qg_setting_internal('qg_issue_on_warn', 'true'::jsonb) #>> '{}')::boolean, true);
  v_failing text[] := '{}'; k record; i record; v_label text := public.wpl_qg_actor_label_internal();
  v_prev text := coalesce(current_setting('wpl.qg_write', true), '');
  v_autofix boolean := coalesce((public.wpl_qg_setting_internal('qg_issue_auto_fix_on_pass', 'true'::jsonb) #>> '{}')::boolean, true);
begin
  for x in select e from jsonb_array_elements(coalesce(p_findings, '[]'::jsonb)) e loop
    select * into c from public.wpl_qg_checks where code = x->>'check_code';
    if c.code is null then raise exception '알 수 없는 검사 항목입니다: %', left(x->>'check_code', 80); end if;
    v_tenant := coalesce(nullif(x->>'tenant_id', '')::uuid, p_tenant);
    v_fp := c.code || '|' || coalesce(v_tenant::text, '*') || '|' || coalesce(nullif(x->>'fingerprint', ''), '-');
    if char_length(v_fp) > 400 then v_fp := c.code || '|' || coalesce(v_tenant::text, '*') || '|sha:' || md5(v_fp); end if;
    v_title := coalesce(nullif(x->>'title', ''), c.name);
    v_list := v_list || jsonb_build_array(jsonb_build_object('id', gen_random_uuid(), 'check_code', c.code, 'engine_code', c.engine_code, 'tenant_id', v_tenant,
      'status', x->>'status', 'severity', x->>'severity', 'fingerprint', v_fp, 'title', v_title, 'detail', coalesce(x->'detail', '{}'::jsonb)));
  end loop;

  select jsonb_build_object('pass', count(*) filter (where e->>'status' = 'pass'), 'warn', count(*) filter (where e->>'status' = 'warn'),
                            'fail', count(*) filter (where e->>'status' = 'fail'), 'error', count(*) filter (where e->>'status' = 'error'),
                            'skipped', count(*) filter (where e->>'status' = 'skipped'), 'total', count(*))
    into v_totals from jsonb_array_elements(v_list) e;
  v_status := case when (v_totals->>'fail')::int > 0 then 'failed' when (v_totals->>'error')::int > 0 then 'error'
                   when (v_totals->>'warn')::int > 0 then 'warned' when (v_totals->>'pass')::int > 0 then 'passed' else 'empty' end;

  v_ev := public.wpl_qg_evidence_append('run_report', 'run:' || v_run::text,
    jsonb_build_object('run_id', v_run, 'engine', p_engine, 'tenant_id', p_tenant, 'trigger', p_trigger, 'schedule', p_schedule,
      'context', coalesce(p_context, '{}'::jsonb), 'started_at', p_started, 'finished_at', clock_timestamp(), 'status', v_status, 'totals', v_totals,
      'actor', p_actor, 'actor_label', v_label,
      'findings', coalesce((select jsonb_agg(jsonb_build_object('id', e->>'id', 'check_code', e->>'check_code', 'tenant_id', e->>'tenant_id', 'status', e->>'status',
                              'severity', e->>'severity', 'fingerprint', e->>'fingerprint', 'title', e->>'title', 'detail', e->'detail'))
                            from jsonb_array_elements(v_list) e), '[]'::jsonb)),
    (select name from public.wpl_qg_engines where code = p_engine) || ' 실행 보고서', p_tenant, v_run);

  insert into public.wpl_qg_runs(id, engine_code, tenant_id, trigger, schedule, context, started_at, finished_at, duration_ms, checks_run, totals, status, actor, actor_label, evidence_id)
  values (v_run, p_engine, p_tenant, p_trigger, p_schedule, coalesce(p_context, '{}'::jsonb), p_started, clock_timestamp(),
          greatest(0, (extract(epoch from (clock_timestamp() - p_started)) * 1000)::int), coalesce(p_checks_run, 0), v_totals, v_status, p_actor, v_label, v_ev);

  perform set_config('wpl.qg_write', 'on', true);
  for x in select e from jsonb_array_elements(v_list) e loop
    v_issue := null; v_fid := (x->>'id')::uuid;
    if x->>'status' in ('fail','error') or (x->>'status' = 'warn' and v_warn) then
      v_issue := public.wpl_qg_issue_upsert_internal(x->>'engine_code', x->>'check_code', nullif(x->>'tenant_id', '')::uuid, x->>'fingerprint',
                   coalesce(x->>'severity', 'medium'), x->>'title', x->'detail', v_run, v_fid);
      v_failing := v_failing || (x->>'fingerprint');
    end if;
    insert into public.wpl_qg_findings(id, run_id, engine_code, check_code, tenant_id, status, severity, fingerprint, title, detail, issue_id, evidence_id)
    values (v_fid, v_run, x->>'engine_code', x->>'check_code', nullif(x->>'tenant_id', '')::uuid, x->>'status', x->>'severity', x->>'fingerprint',
            x->>'title', coalesce(x->'detail', '{}'::jsonb), v_issue, v_ev);
  end loop;

  -- 이번에 판정된(오류·건너뜀 아닌) 검사×대상에서 다시 나오지 않은 이슈: 고침 → 확인됨(자동),
  --  열림·확인함 → 고침(확인 대기, 설정 qg_issue_auto_fix_on_pass — 승인 요청 대기 중이면 그대로) / 설정이 꺼져 있으면 마지막 통과 시각만
  for k in select distinct e->>'check_code' cc, nullif(e->>'tenant_id', '')::uuid tid from jsonb_array_elements(v_list) e
            where not exists (select 1 from jsonb_array_elements(v_list) z where z->>'check_code' = e->>'check_code'
                                and z->>'tenant_id' is not distinct from e->>'tenant_id' and z->>'status' in ('error','skipped')) loop
    for i in select * from public.wpl_qg_issues q where q.check_code = k.cc and q.tenant_id is not distinct from k.tid
                and not (q.fingerprint = any(v_failing)) and q.status in ('fixed','open','acknowledged') for update loop
      if i.status = 'fixed' then
        update public.wpl_qg_issues set status = 'verified', last_pass_at = now(), status_changed_at = now(), status_changed_by = null where id = i.id;
        perform public.wpl_qg_issue_event_internal(i.id, i.tenant_id, 'auto_verify', 'fixed', 'verified', '다시 실행한 검사에서 문제가 나오지 않아 자동 확인', v_run, null);
      elsif v_autofix and not exists (select 1 from public.wpl_qg_risk_approvals a where a.issue_id = i.id and a.status = 'pending') then
        update public.wpl_qg_issues set status = 'fixed', last_pass_at = now(), status_changed_at = now(), status_changed_by = null where id = i.id;
        perform public.wpl_qg_issue_event_internal(i.id, i.tenant_id, 'auto_verify', i.status, 'fixed',
          '최신 실행에서 같은 문제가 나오지 않아 확인 대기(고침)로 자동 전환 — 다음 실행에서도 통과하면 확인됨', v_run, null);
      else
        update public.wpl_qg_issues set last_pass_at = now() where id = i.id;
      end if;
    end loop;
  end loop;
  perform set_config('wpl.qg_write', v_prev, true);
  return v_run;
end $$;
revoke all on function public.wpl_qg_record_run_internal(text, uuid, text, text, jsonb, jsonb, uuid, timestamptz, int) from public, anon, authenticated;

-- ───────── 9) 실행기 ─────────
create or replace function public.wpl_qg_run_engine_internal(p_engine text, p_tenant uuid, p_trigger text, p_schedule text, p_actor uuid, p_context jsonb default '{}'::jsonb)
returns uuid language plpgsql security definer set search_path = public as $$
declare g public.wpl_qg_engines; c public.wpl_qg_checks; v_started timestamptz := clock_timestamp(); v_all jsonb := '[]'::jsonb; v_res jsonb; t uuid; v_n int := 0;
begin
  select * into g from public.wpl_qg_engines where code = p_engine;
  if g.code is null then raise exception '알 수 없는 엔진입니다.'; end if;
  if not g.enabled then raise exception '사용 중지된 엔진입니다(카탈로그에서 켜 주세요).'; end if;
  if p_tenant is not null and not public.wpl_qga_tenant_exists(p_tenant) then raise exception '테넌트를 찾을 수 없습니다.'; end if;
  for c in select * from public.wpl_qg_checks
            where engine_code = p_engine and active and probe like 'wpl\_qg\_probe\_%'
              and (p_schedule is null or schedule = p_schedule)
              and (p_tenant is null or scope = 'tenant')
            order by sort, code loop
    v_n := v_n + 1;
    for t in select x from (select null::uuid x where c.scope = 'platform'
                            union all select p_tenant where c.scope = 'tenant' and p_tenant is not null
                            union all select distinct q.id from public.wpl_qga_tenants() q(id) where c.scope = 'tenant' and p_tenant is null) z loop
      v_res := public.wpl_qg_probe_call_internal(c, t);
      select v_all || coalesce(jsonb_agg(e || jsonb_build_object('check_code', c.code, 'tenant_id', t)), '[]'::jsonb) into v_all from jsonb_array_elements(v_res) e;
    end loop;
  end loop;
  return public.wpl_qg_record_run_internal(p_engine, p_tenant, p_trigger, p_schedule, p_context, v_all, p_actor, v_started, v_n);
end $$;
revoke all on function public.wpl_qg_run_engine_internal(text, uuid, text, text, uuid, jsonb) from public, anon, authenticated;

-- 관리자: 지금 실행
create or replace function public.wpl_qg_run_engine(p_engine text, p_tenant uuid default null)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_run uuid; r public.wpl_qg_runs;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '품질·거버넌스 엔진 실행은 관리자만 할 수 있습니다.'; end if;
  v_run := public.wpl_qg_run_engine_internal(p_engine, p_tenant, 'manual', null, auth.uid(), '{}'::jsonb);
  select * into r from public.wpl_qg_runs where id = v_run;
  perform public.wpl_qga_audit(p_tenant, 'user', 'qg.run', 'wpl_qg_runs', v_run::text, jsonb_build_object('engine', p_engine, 'status', r.status, 'totals', r.totals));
  return v_run;
end $$;
revoke all on function public.wpl_qg_run_engine(text, uuid) from public, anon, authenticated;
grant execute on function public.wpl_qg_run_engine(text, uuid) to authenticated;

-- ───────── 10) 외부 결과 올리기(스크립트·CI) ─────────
-- p_payload = {engine, tenant_id?, trigger?(script|ci|release|manual), context?{git_sha,…}, started_at?, results:[{check_code, status, severity?, fingerprint?, title?, detail?, tenant_id?}]}
-- 권한: 관리자 세션, 또는 서버 증명키(어댑터 wpl_qga_server_key_ok). anon 불가.
create or replace function public.wpl_qg_ingest(p_payload jsonb, p_server_key text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_hq boolean := auth.uid() is not null and public.wpl_qga_is_admin(); v_engine text; v_tenant uuid; v_trigger text;
  v_max int := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_ingest_max_results', '2000'::jsonb) #>> '{}')::int, 2000));
  x jsonb; c public.wpl_qg_checks; v_norm jsonb := '[]'::jsonb; v_bad text[] := '{}'; v_run uuid; r public.wpl_qg_runs; v_t uuid; v_started timestamptz;
begin
  if not v_hq then
    if not coalesce(public.wpl_qga_server_key_ok(p_server_key), false) then
      raise exception '서버 증명키가 없거나 맞지 않습니다. 결과를 받지 않았습니다(관리자 로그인으로 올리거나 서버 증명키를 설정해 주세요).';
    end if;
  end if;
  if p_payload is null or jsonb_typeof(p_payload) <> 'object' then raise exception '올릴 내용(JSON 객체)이 필요합니다.'; end if;
  v_engine := p_payload->>'engine';
  if not exists (select 1 from public.wpl_qg_engines where code = v_engine and enabled) then raise exception '알 수 없거나 사용 중지된 엔진입니다: %', left(coalesce(v_engine, ''), 40); end if;
  v_trigger := coalesce(nullif(p_payload->>'trigger', ''), 'script');
  if v_trigger not in ('script','ci','release','manual') then raise exception '실행 계기(trigger)는 script·ci·release·manual 중 하나여야 합니다.'; end if;
  if (p_payload->>'tenant_id') is not null then
    begin v_tenant := (p_payload->>'tenant_id')::uuid; exception when others then raise exception '테넌트 id 형식이 올바르지 않습니다.'; end;
    if not public.wpl_qga_tenant_exists(v_tenant) then raise exception '테넌트를 찾을 수 없습니다.'; end if;
  end if;
  if jsonb_typeof(p_payload->'results') is distinct from 'array' or jsonb_array_length(p_payload->'results') = 0 then raise exception '결과(results) 배열이 비어 있습니다.'; end if;
  if jsonb_array_length(p_payload->'results') > v_max then raise exception '결과가 너무 많습니다(최대 %건).', v_max; end if;
  if p_payload ? 'context' and jsonb_typeof(p_payload->'context') <> 'object' then raise exception '맥락(context)은 JSON 객체여야 합니다.'; end if;
  if octet_length(coalesce(p_payload->'context', '{}'::jsonb)::text) > 8000 then raise exception '맥락(context)이 너무 큽니다(8KB 이하).'; end if;

  for x in select e from jsonb_array_elements(p_payload->'results') e loop
    select * into c from public.wpl_qg_checks where code = x->>'check_code' and engine_code = v_engine;
    if c.code is null then v_bad := v_bad || left(coalesce(x->>'check_code', '(없음)'), 80); continue; end if;
    v_t := v_tenant;
    if (x->>'tenant_id') is not null then
      begin v_t := (x->>'tenant_id')::uuid; exception when others then raise exception '결과의 테넌트 id 형식이 올바르지 않습니다.'; end;
      if not public.wpl_qga_tenant_exists(v_t) then raise exception '결과의 테넌트를 찾을 수 없습니다.'; end if;
    end if;
    v_norm := v_norm || jsonb_build_array(public.wpl_qg_norm_finding_internal(x - 'check_code' - 'tenant_id', c.risk) || jsonb_build_object('check_code', c.code, 'tenant_id', v_t));
  end loop;
  if cardinality(v_bad) > 0 then raise exception '이 엔진(%)에 없는 검사 항목이 있어 받지 않았습니다: %', v_engine, array_to_string(v_bad[1:10], ', '); end if;

  begin v_started := coalesce((p_payload->>'started_at')::timestamptz, now()); exception when others then v_started := now(); end;
  if v_started > now() + interval '5 minutes' or v_started < now() - interval '7 days' then v_started := now(); end if;
  v_run := public.wpl_qg_record_run_internal(v_engine, v_tenant, v_trigger, null,
             coalesce(p_payload->'context', '{}'::jsonb) || jsonb_build_object('via', case when v_hq then 'admin_session' else 'server_key' end),
             v_norm, auth.uid(), v_started, (select count(distinct e->>'check_code') from jsonb_array_elements(v_norm) e)::int);
  select * into r from public.wpl_qg_runs where id = v_run;
  perform public.wpl_qga_audit(v_tenant, case when v_hq then 'user' else 'system' end, 'qg.ingest', 'wpl_qg_runs', v_run::text,
    jsonb_build_object('engine', v_engine, 'trigger', v_trigger, 'status', r.status, 'totals', r.totals));
  return jsonb_build_object('ok', true, 'run_id', v_run, 'status', r.status, 'totals', r.totals, 'evidence_id', r.evidence_id);
end $$;
revoke all on function public.wpl_qg_ingest(jsonb, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_ingest(jsonb, text) to authenticated, service_role;

-- ───────── 11) 이슈 상태 머신 ─────────
--  open → acknowledged · fixed · accepted_risk · false_positive        acknowledged → open · fixed · accepted_risk · false_positive
--  fixed → verified · open      verified → open      accepted_risk → open      false_positive → open
create or replace function public.wpl_qg_issue_allowed_internal(p_from text, p_to text) returns boolean
language sql immutable set search_path = public as $$
  select case p_from
    when 'open' then p_to in ('acknowledged','fixed','accepted_risk','false_positive')
    when 'acknowledged' then p_to in ('open','fixed','accepted_risk','false_positive')
    when 'fixed' then p_to in ('verified','open')
    when 'verified' then p_to = 'open'
    when 'accepted_risk' then p_to = 'open'
    when 'false_positive' then p_to = 'open'
    else false end
$$;
revoke all on function public.wpl_qg_issue_allowed_internal(text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_status_ko_internal(p text) returns text
language sql immutable set search_path = public as $$
  select case p when 'open' then '열림' when 'acknowledged' then '확인함' when 'fixed' then '고침' when 'verified' then '확인됨(해결)'
                when 'accepted_risk' then '위험 수용' when 'false_positive' then '오탐' else coalesce(p, '-') end
$$;
revoke all on function public.wpl_qg_status_ko_internal(text) from public, anon, authenticated;

create or replace function public.wpl_qg_issue_transition(p_issue uuid, p_to text, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare i public.wpl_qg_issues; v_note text := nullif(trim(coalesce(p_note, '')), ''); v_min int; v_gate boolean; v_req uuid;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '이슈 상태는 관리자만 바꿀 수 있습니다.'; end if;
  select * into i from public.wpl_qg_issues where id = p_issue for update;
  if i.id is null then raise exception '이슈를 찾을 수 없습니다.'; end if;
  if exists (select 1 from public.wpl_qg_risk_approvals where issue_id = i.id and status = 'pending') then
    raise exception '위험 수용·오탐 승인 요청이 대기 중입니다. 먼저 결정하거나 요청을 취소해 주세요.';
  end if;
  if p_to is null or not public.wpl_qg_issue_allowed_internal(i.status, p_to) then
    raise exception '지금 상태(%)에서 ''%''(으)로 바꿀 수 없습니다.', public.wpl_qg_status_ko_internal(i.status), public.wpl_qg_status_ko_internal(p_to);
  end if;
  if v_note is not null and char_length(v_note) > 2000 then raise exception '메모는 2,000자 이하로 적어 주세요.'; end if;

  perform set_config('wpl.qg_write', 'on', true);
  if p_to in ('accepted_risk','false_positive') then
    v_min := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_accept_note_min_len', '10'::jsonb) #>> '{}')::int, 10));
    if char_length(coalesce(v_note, '')) < v_min then
      raise exception '''%''(으)로 바꾸려면 사유를 %자 이상 적어 주세요(왜 고치지 않아도 되는지, 언제 다시 볼지).', public.wpl_qg_status_ko_internal(p_to), v_min;
    end if;
    v_gate := public.wpl_qg_setting_internal('qg_accept_risk_gate_severities', '["critical","high"]'::jsonb) ? i.severity;
    if v_gate then
      insert into public.wpl_qg_risk_approvals(issue_id, tenant_id, to_status, severity, request_note, requested_by)
      values (i.id, i.tenant_id, p_to, i.severity, v_note, auth.uid()) returning id into v_req;
      update public.wpl_qg_issues set approval_id = v_req where id = i.id;
      perform public.wpl_qg_issue_event_internal(i.id, i.tenant_id, 'request', i.status, p_to, v_note, null, v_req);
      perform set_config('wpl.qg_write', '', true);
      perform public.wpl_qga_audit(i.tenant_id, 'user', 'qg.issue.request', 'wpl_qg_issues', i.id::text, jsonb_build_object('to', p_to, 'severity', i.severity, 'request_id', v_req));
      return jsonb_build_object('ok', true, 'pending', true, 'approval_id', v_req, 'status', i.status,
        'message', '심각도가 ' || case i.severity when 'critical' then '치명' when 'high' then '높음' when 'medium' then '보통' else '낮음' end
                   || '이라 다른 관리자의 승인이 필요합니다. 승인 요청을 만들었습니다.');
    end if;
  end if;

  update public.wpl_qg_issues set status = p_to, note = coalesce(v_note, note), status_changed_at = now(), status_changed_by = auth.uid(), approval_id = null,
         due_at = case when p_to = 'open' then public.wpl_qg_issue_due_internal(severity) else due_at end
   where id = i.id;
  perform public.wpl_qg_issue_event_internal(i.id, i.tenant_id, 'transition', i.status, p_to, v_note, null, null);
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(i.tenant_id, 'user', 'qg.issue.transition', 'wpl_qg_issues', i.id::text, jsonb_build_object('from', i.status, 'to', p_to, 'note', v_note));
  return jsonb_build_object('ok', true, 'pending', false, 'status', p_to);
end $$;
revoke all on function public.wpl_qg_issue_transition(uuid, text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_issue_transition(uuid, text, text) to authenticated;

-- 관리자: 여러 이슈를 한 번에 바꾸기(확인함·고침·확인됨만 — 위험 수용·오탐은 한 건씩 사유와 승인을 거친다)
--  p_ids 가 null 이면 p_to = 'verified' 일 때 '고침(확인 대기)' 이슈 중 마지막 통과가 마지막 발견보다 나중인 것 전부(최대 500건)
create or replace function public.wpl_qg_issue_bulk_transition(p_ids uuid[], p_to text, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_id uuid; v_ids uuid[]; v_ok int := 0; v_skip jsonb := '[]'::jsonb;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '이슈 상태는 관리자만 바꿀 수 있습니다.'; end if;
  if p_to is null or p_to not in ('acknowledged','fixed','verified') then
    raise exception '한꺼번에는 ''확인함''·''고침''·''확인됨''으로만 바꿀 수 있습니다(위험 수용·오탐은 한 건씩).';
  end if;
  if p_ids is null then
    if p_to <> 'verified' then raise exception '바꿀 이슈를 골라 주세요.'; end if;
    select coalesce(array_agg(q.id order by q.last_seen), '{}') into v_ids
      from (select id, last_seen from public.wpl_qg_issues where status = 'fixed' and last_pass_at is not null and last_pass_at >= last_seen order by last_seen limit 500) q;
  else
    v_ids := p_ids;
  end if;
  if cardinality(v_ids) > 500 then raise exception '한 번에 500건까지 바꿀 수 있습니다.'; end if;
  foreach v_id in array coalesce(v_ids, '{}') loop
    begin
      perform public.wpl_qg_issue_transition(v_id, p_to, coalesce(nullif(btrim(coalesce(p_note, '')), ''), '한꺼번에 처리'));
      v_ok := v_ok + 1;
    exception when others then
      v_skip := v_skip || jsonb_build_array(jsonb_build_object('id', v_id, 'reason', left(sqlerrm, 200)));
    end;
  end loop;
  return jsonb_build_object('ok', true, 'changed', v_ok, 'skipped', jsonb_array_length(v_skip), 'skipped_items', v_skip, 'status', p_to);
end $$;
revoke all on function public.wpl_qg_issue_bulk_transition(uuid[], text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_issue_bulk_transition(uuid[], text, text) to authenticated;

-- 위험 수용·오탐 승인 결정(승인·반려·취소). 요청자 본인은 승인 불가(설정으로만 '혼자일 때' 예외). 취소는 요청자 본인만.
create or replace function public.wpl_qg_issue_decide(p_approval uuid, p_decision text, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare a public.wpl_qg_risk_approvals; i public.wpl_qg_issues; v_note text := nullif(trim(coalesce(p_note, '')), ''); v_ev uuid;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '위험 수용 승인은 관리자만 결정할 수 있습니다.'; end if;
  select * into a from public.wpl_qg_risk_approvals where id = p_approval for update;
  if a.id is null then raise exception '승인 요청을 찾을 수 없습니다.'; end if;
  if a.status <> 'pending' then raise exception '이미 처리된 요청입니다.'; end if;
  if p_decision is null or p_decision not in ('approved','rejected','cancelled') then raise exception '알 수 없는 결정입니다.'; end if;
  if p_decision = 'rejected' and char_length(coalesce(v_note, '')) < 2 then raise exception '반려 사유를 적어 주세요.'; end if;
  if p_decision = 'cancelled' and a.requested_by is distinct from auth.uid() then raise exception '요청 취소는 요청한 사람만 할 수 있습니다.'; end if;
  if p_decision = 'approved' and not public.wpl_qg_self_approval_ok_internal(a.requested_by) then
    raise exception '자기가 요청한 위험 수용은 스스로 승인할 수 없습니다. 다른 관리자에게 맡겨 주세요.';
  end if;
  select * into i from public.wpl_qg_issues where id = a.issue_id for update;

  perform set_config('wpl.qg_write', 'on', true);
  if p_decision = 'approved' then
    v_ev := public.wpl_qg_evidence_append('issue_decision', 'issue:' || i.id::text,
      jsonb_build_object('issue_id', i.id, 'fingerprint', i.fingerprint, 'check_code', i.check_code, 'tenant_id', i.tenant_id, 'severity', i.severity,
        'from', i.status, 'to', a.to_status, 'request_note', a.request_note, 'requested_by', a.requested_by, 'requested_at', a.requested_at,
        'decided_by', auth.uid(), 'decided_by_label', public.wpl_qg_actor_label_internal(), 'decision_note', v_note),
      '위험 수용 승인: ' || left(i.title, 200), i.tenant_id, null);
    update public.wpl_qg_issues set status = a.to_status, note = a.request_note, status_changed_at = now(), status_changed_by = auth.uid(), approval_id = a.id
     where id = i.id;
    perform public.wpl_qg_issue_event_internal(i.id, i.tenant_id, 'approve', i.status, a.to_status, v_note, null, a.id);
  else
    update public.wpl_qg_issues set approval_id = null where id = i.id;
    perform public.wpl_qg_issue_event_internal(i.id, i.tenant_id, case when p_decision = 'rejected' then 'reject' else 'cancel' end, i.status, i.status, v_note, null, a.id);
  end if;
  update public.wpl_qg_risk_approvals set status = p_decision, decided_by = auth.uid(), decided_at = now(), decision_note = v_note, evidence_id = v_ev where id = a.id;
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(i.tenant_id, 'user', 'qg.issue.' || p_decision, 'wpl_qg_issues', i.id::text,
    jsonb_build_object('request_id', a.id, 'to', a.to_status, 'note', v_note, 'evidence_id', v_ev));
  return jsonb_build_object('ok', true, 'decision', p_decision, 'status', case when p_decision = 'approved' then a.to_status else i.status end, 'evidence_id', v_ev);
end $$;
revoke all on function public.wpl_qg_issue_decide(uuid, text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_issue_decide(uuid, text, text) to authenticated;

-- ───────── 12) 센터 대시보드 ─────────
create or replace function public.wpl_qg_dashboard()
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_days int := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_pass_rate_window_days', '7'::jsonb) #>> '{}')::int, 7));
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '품질·거버넌스 센터는 관리자만 볼 수 있습니다.'; end if;
  return jsonb_build_object(
    'window_days', v_days,
    'generated_at', now(),
    'cron_enabled', coalesce((public.wpl_qg_setting_internal('qg_cron_enabled', 'true'::jsonb) #>> '{}')::boolean, true)
                    and not coalesce(public.wpl_qga_automation_stopped(), false)
                    and exists (select 1 from pg_extension where extname = 'pg_cron'),
    'cron_installed', exists (select 1 from pg_extension where extname = 'pg_cron'),
    -- 4-eyes: 다른 관리자가 없으면 출시·위험 수용·AI 승인을 맡길 사람이 없다(설정이 켜져 있으면 자기 승인 예외로 내려감)
    'other_admins', public.wpl_qga_admin_count_except(auth.uid()),
    'sole_admin_self_approval', coalesce((public.wpl_qg_setting_internal('qg_self_approval_when_sole_admin', 'false'::jsonb) #>> '{}')::boolean, false),
    'totals', jsonb_build_object(
      'open_issues', (select count(*) from public.wpl_qg_issues where status in ('open','acknowledged')),
      'critical_open', (select count(*) from public.wpl_qg_issues where status in ('open','acknowledged') and severity = 'critical'),
      'high_open', (select count(*) from public.wpl_qg_issues where status in ('open','acknowledged') and severity = 'high'),
      'overdue', (select count(*) from public.wpl_qg_issues where status in ('open','acknowledged') and due_at < now()),
      'fixed_waiting', (select count(*) from public.wpl_qg_issues where status = 'fixed'),
      'fixed_passed', (select count(*) from public.wpl_qg_issues where status = 'fixed' and last_pass_at is not null and last_pass_at >= last_seen),
      'pending_approvals', (select count(*) from public.wpl_qg_risk_approvals where status = 'pending'),
      'evidence_count', (select count(*) from public.wpl_qg_evidence),
      'last_evidence_at', (select max(created_at) from public.wpl_qg_evidence),
      'runs_window', (select count(*) from public.wpl_qg_runs where finished_at > now() - make_interval(days => v_days))),
    'engines', coalesce((select jsonb_agg(jsonb_build_object(
        'code', g.code, 'name', g.name, 'purpose', g.purpose, 'route', g.route, 'icon', g.icon, 'enabled', g.enabled, 'sort', g.sort,
        'checks_active', (select count(*) from public.wpl_qg_checks c where c.engine_code = g.code and c.active),
        'checks_db', (select count(*) from public.wpl_qg_checks c where c.engine_code = g.code and c.active and c.probe like 'wpl\_qg\_probe\_%'),
        'last_run', (select jsonb_build_object('id', r.id, 'status', r.status, 'totals', r.totals, 'trigger', r.trigger, 'finished_at', r.finished_at, 'tenant_id', r.tenant_id)
                       from public.wpl_qg_runs r where r.engine_code = g.code order by r.finished_at desc limit 1),
        'pass_rate_window', (select case when sum((r.totals->>'total')::int - coalesce((r.totals->>'skipped')::int, 0)) > 0
                                         then round(sum((r.totals->>'pass')::int)::numeric * 100 / sum((r.totals->>'total')::int - coalesce((r.totals->>'skipped')::int, 0)), 1) end
                               from public.wpl_qg_runs r where r.engine_code = g.code and r.finished_at > now() - make_interval(days => v_days)),
        'runs_window', (select count(*) from public.wpl_qg_runs r where r.engine_code = g.code and r.finished_at > now() - make_interval(days => v_days)),
        'open_issues', jsonb_build_object(
          'critical', (select count(*) from public.wpl_qg_issues q where q.engine_code = g.code and q.status in ('open','acknowledged') and q.severity = 'critical'),
          'high', (select count(*) from public.wpl_qg_issues q where q.engine_code = g.code and q.status in ('open','acknowledged') and q.severity = 'high'),
          'medium', (select count(*) from public.wpl_qg_issues q where q.engine_code = g.code and q.status in ('open','acknowledged') and q.severity = 'medium'),
          'low', (select count(*) from public.wpl_qg_issues q where q.engine_code = g.code and q.status in ('open','acknowledged') and q.severity = 'low'),
          'total', (select count(*) from public.wpl_qg_issues q where q.engine_code = g.code and q.status in ('open','acknowledged'))),
        'overdue', (select count(*) from public.wpl_qg_issues q where q.engine_code = g.code and q.status in ('open','acknowledged') and q.due_at < now()),
        'trend', coalesce((select jsonb_agg(jsonb_build_object('id', t.id, 'at', t.finished_at, 'status', t.status,
                             'pass_rate', case when (t.totals->>'total')::int - coalesce((t.totals->>'skipped')::int, 0) > 0
                                               then round((t.totals->>'pass')::numeric * 100 / ((t.totals->>'total')::int - coalesce((t.totals->>'skipped')::int, 0)), 1) end)
                             order by t.finished_at)
                           from (select * from public.wpl_qg_runs r where r.engine_code = g.code order by r.finished_at desc limit 10) t), '[]'::jsonb)
      ) order by g.sort, g.code) from public.wpl_qg_engines g), '[]'::jsonb));
end $$;
revoke all on function public.wpl_qg_dashboard() from public, anon, authenticated;
grant execute on function public.wpl_qg_dashboard() to authenticated;

-- 관리자: 어댑터·환경 정보(설정 화면 표시용)
create or replace function public.wpl_qg_adapter_info()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '품질·거버넌스 설정은 관리자만 볼 수 있습니다.'; end if;
  return coalesce(public.wpl_qga_info(), '{}'::jsonb) || jsonb_build_object(
    'pg_cron', exists (select 1 from pg_extension where extname = 'pg_cron'),
    'server_version', current_setting('server_version'),
    'tenants_count', (select count(*) from public.wpl_qga_tenants()),
    'automation_stopped', coalesce(public.wpl_qga_automation_stopped(), false));
end $$;
revoke all on function public.wpl_qg_adapter_info() from public, anon, authenticated;
grant execute on function public.wpl_qg_adapter_info() to authenticated;

-- ───────── 13) 척추용 probe(evidence 엔진) ─────────
create or replace function public.wpl_qg_probe_evidence_chain(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb;
begin
  v := public.wpl_qg_evidence_verify_rows_internal(public.wpl_qg_evidence_rows_internal(coalesce((p_check.params->>'limit')::int, 1000000)));
  if (v->>'ok')::boolean then
    return jsonb_build_object('status', 'pass', 'detail', v);
  end if;
  return jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', 'evidence_chain_broken',
    'title', '증거 원장 해시체인이 끊김(' || coalesce(v->>'broken_seq', '?') || '번)', 'detail', v);
end $$;
revoke all on function public.wpl_qg_probe_evidence_chain(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 플랫폼 감사 로그 해시체인(어댑터가 계산). 지원하지 않는 플랫폼은 '건너뜀'.
create or replace function public.wpl_qg_probe_audit_chain(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb := public.wpl_qga_audit_chain_check(coalesce((p_check.params->>'tail')::int, 0));
begin
  if not coalesce((v->>'supported')::boolean, false) then
    return jsonb_build_object('status', 'skipped', 'detail', v);
  end if;
  if coalesce((v->>'ok')::boolean, false) then
    return jsonb_build_object('status', 'pass', 'detail', v);
  end if;
  return jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', 'audit_chain_broken',
    'title', '감사 로그 해시체인이 끊김(' || coalesce(v->>'broken_at', '?') || ')', 'detail', v);
end $$;
revoke all on function public.wpl_qg_probe_audit_chain(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_run_evidence_link(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_days int := greatest(1, coalesce((p_check.params->>'days')::int, 30)); v_runs int; v_bad_runs int; v_bad_findings int;
begin
  select count(*), count(*) filter (where r.evidence_id is null or not exists (select 1 from public.wpl_qg_evidence e where e.id = r.evidence_id and e.run_id = r.id))
    into v_runs, v_bad_runs from public.wpl_qg_runs r where r.finished_at > now() - make_interval(days => v_days);
  select count(*) into v_bad_findings from public.wpl_qg_findings f join public.wpl_qg_runs r on r.id = f.run_id
   where r.finished_at > now() - make_interval(days => v_days) and f.evidence_id is distinct from r.evidence_id;
  if v_bad_runs = 0 and v_bad_findings = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('runs', v_runs, 'days', v_days));
  end if;
  return jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', 'run_evidence_missing', 'title', '증거가 없거나 어긋난 실행 기록이 있음',
    'detail', jsonb_build_object('runs', v_runs, 'runs_without_evidence', v_bad_runs, 'findings_mismatch', v_bad_findings, 'days', v_days));
end $$;
revoke all on function public.wpl_qg_probe_run_evidence_link(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ───────── 14) 자동 실행(pg_cron — 없으면 건너뜀) ─────────
create or replace function public.wpl_qg_cron_internal(p_schedule text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare g record; v_out jsonb := '[]'::jsonb; v_run uuid; v_sched text[]; v_s text;
begin
  if coalesce(public.wpl_qga_automation_stopped(), false) then return jsonb_build_object('skipped', 'automation_stopped'); end if;
  if not coalesce((public.wpl_qg_setting_internal('qg_cron_enabled', 'true'::jsonb) #>> '{}')::boolean, true) then return jsonb_build_object('skipped', 'qg_cron_enabled'); end if;
  v_sched := case when p_schedule = 'daily' and extract(isodow from now() at time zone 'Asia/Seoul') = 1 then array['daily','weekly'] else array[p_schedule] end;
  for g in select e.code from public.wpl_qg_engines e
            where e.enabled and exists (select 1 from public.wpl_qg_checks c where c.engine_code = e.code and c.active and c.schedule = any(v_sched)
                                          and c.probe like 'wpl\_qg\_probe\_%')
            order by e.sort, e.code loop
    foreach v_s in array v_sched loop
      if not exists (select 1 from public.wpl_qg_checks c where c.engine_code = g.code and c.active and c.schedule = v_s and c.probe like 'wpl\_qg\_probe\_%') then continue; end if;
      begin
        v_run := public.wpl_qg_run_engine_internal(g.code, null, 'cron', v_s, null, jsonb_build_object('cron', v_s));
        v_out := v_out || jsonb_build_array(jsonb_build_object('engine', g.code, 'schedule', v_s, 'run_id', v_run));
      exception when others then
        v_out := v_out || jsonb_build_array(jsonb_build_object('engine', g.code, 'schedule', v_s, 'error', left(sqlerrm, 300)));
      end;
    end loop;
  end loop;
  return jsonb_build_object('ok', true, 'runs', v_out);
end $$;
revoke all on function public.wpl_qg_cron_internal(text) from public, anon, authenticated;

create or replace function public.wpl_qg_cron_hourly() returns jsonb language plpgsql security definer set search_path = public as $$
begin return public.wpl_qg_cron_internal('hourly'); end $$;
revoke all on function public.wpl_qg_cron_hourly() from public, anon, authenticated;
create or replace function public.wpl_qg_cron_daily() returns jsonb language plpgsql security definer set search_path = public as $$
begin return public.wpl_qg_cron_internal('daily'); end $$;
revoke all on function public.wpl_qg_cron_daily() from public, anon, authenticated;
-- pg_cron 이 없는 DB 의 외부 크론(서비스 키 라우트·Render Cron)이 부를 수 있게 이 두 함수만 service_role 에 연다(있을 때만)
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    execute 'grant execute on function public.wpl_qg_cron_hourly() to service_role';
    execute 'grant execute on function public.wpl_qg_cron_daily() to service_role';
  end if;
end $$;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.unschedule(jobid) from cron.job where jobname = 'wpl_qg_cron_hourly';
    perform cron.schedule('wpl_qg_cron_hourly', '17 * * * *', 'select public.wpl_qg_cron_hourly()');
    perform cron.unschedule(jobid) from cron.job where jobname = 'wpl_qg_cron_daily';
    perform cron.schedule('wpl_qg_cron_daily', '40 18 * * *', 'select public.wpl_qg_cron_daily()');   -- 한국 03:40
  else
    raise notice 'QG: pg_cron 이 없어 자동 실행 등록을 건너뜁니다(지금 실행·외부 결과 올리기는 그대로 됩니다).';
  end if;
end $$;
