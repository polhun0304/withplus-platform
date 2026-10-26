-- QG 키트 1.2.0 업그레이드 · 접두어 wpl — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말 것)
-- 이전 키트 마이그레이션 위에 다시 적용해도 안전(create or replace · if not exists · on conflict). 어댑터·플랫폼 확장 파일은 건드리지 않음.

-- ══════════ contract ══════════
-- =====================================================================
-- QG 키트 00 — 어댑터 계약 검사(이 파일은 아무것도 만들지 않는다)
--  척추·엔진 SQL 은 플랫폼 코어(gos_*·fmx_*·is_platform_admin 등)를 직접 부르지 않고 아래 어댑터 함수만 부른다.
--  어댑터(adapters/*.sql 을 렌더링한 파일)가 먼저 적용되어 있어야 하며, 하나라도 없거나 모양이 다르면 여기서 사람 말로 중단한다.
--  계약 원본: QG_KIT.md §3. 접두어 wpl.
-- =====================================================================
do $$
declare
  v_missing text[] := '{}';
  v_bad text[] := '{}';
  r record;
begin
  -- PostgreSQL 13 이상: gen_random_uuid()·sha256() 기본 내장(pgcrypto 스키마 차이와 무관하게 동작)
  if current_setting('server_version_num')::int < 130000 then
    raise exception 'QG 키트는 PostgreSQL 13 이상이 필요합니다(지금 %).', current_setting('server_version');
  end if;
  if to_regprocedure('pg_catalog.sha256(bytea)') is null then
    raise exception 'QG 키트: 내장 sha256(bytea) 함수를 찾을 수 없습니다.';
  end if;
  if to_regprocedure('auth.uid()') is null then
    raise exception 'QG 키트: auth.uid() 가 없습니다(Supabase 가 아니면 같은 이름의 함수 — 현재 사용자 id 를 돌려주는 — 를 먼저 만드세요).';
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') or not exists (select 1 from pg_roles where rolname = 'anon') then
    raise exception 'QG 키트: anon·authenticated 역할이 없습니다(Supabase 기본 역할 필요, 비-Supabase 는 QG_KIT.md §9 참고).';
  end if;

  for r in select * from (values
    ('wpl_qga_is_admin()', 'boolean'),
    ('wpl_qga_can_read_tenant(uuid)', 'boolean'),
    ('wpl_qga_admin_count_except(uuid)', 'integer'),
    ('wpl_qga_user_label(uuid)', 'text'),
    ('wpl_qga_tenants()', 'uuid'),
    ('wpl_qga_tenant_exists(uuid)', 'boolean'),
    ('wpl_qga_tenant_label(uuid)', 'text'),
    ('wpl_qga_audit(uuid,text,text,text,text,jsonb)', 'void'),
    ('wpl_qga_alert(text,text,text,text,text)', 'void'),
    ('wpl_qga_automation_stopped()', 'boolean'),
    ('wpl_qga_server_key_ok(text)', 'boolean'),
    ('wpl_qga_audit_chain_check(integer)', 'jsonb'),
    ('wpl_qga_release_target(text,text)', 'jsonb'),
    ('wpl_qga_review_target(text,text)', 'jsonb'),
    ('wpl_qga_ai_runs(timestamp with time zone)', 'record'),
    ('wpl_qga_compliance_targets()', 'record'),
    ('wpl_qga_banned_phrases()', 'record'),
    ('wpl_qga_smoke_fixture()', 'jsonb'),
    ('wpl_qga_info()', 'jsonb')) t(sig, ret) loop
    if to_regprocedure('public.' || r.sig) is null then
      v_missing := v_missing || r.sig;
    elsif (select format_type(p.prorettype, null) from pg_proc p where p.oid = to_regprocedure('public.' || r.sig)) <> r.ret then
      v_bad := v_bad || (r.sig || ' → ' || r.ret || ' 이어야 함');
    elsif not (select p.prosecdef from pg_proc p where p.oid = to_regprocedure('public.' || r.sig)) then
      v_bad := v_bad || (r.sig || ' 는 SECURITY DEFINER 여야 함');
    elsif not exists (select 1 from pg_proc p, unnest(coalesce(p.proconfig, '{}'::text[])) c
                       where p.oid = to_regprocedure('public.' || r.sig) and c like 'search_path=%') then
      v_bad := v_bad || (r.sig || ' 에 search_path 고정이 없음');
    elsif r.sig not in ('wpl_qga_is_admin()', 'wpl_qga_can_read_tenant(uuid)')
          and has_function_privilege('authenticated', to_regprocedure('public.' || r.sig), 'execute') then
      v_bad := v_bad || (r.sig || ' 를 로그인 사용자가 실행할 수 있음(revoke … from public, anon, authenticated 필요)');
    elsif has_function_privilege('anon', to_regprocedure('public.' || r.sig), 'execute') then
      v_bad := v_bad || (r.sig || ' 를 익명 사용자가 실행할 수 있음');
    end if;
  end loop;

  if cardinality(v_missing) > 0 then
    raise exception 'QG 어댑터가 준비되지 않아 설치를 멈췄습니다. 없는 함수 %개: %. 먼저 adapters/<플랫폼>.sql 을 렌더링해 적용하세요(QG_KIT.md §3).',
      cardinality(v_missing), array_to_string(v_missing, ', ');
  end if;
  if cardinality(v_bad) > 0 then
    raise exception 'QG 어댑터 함수 모양·권한이 계약과 다릅니다: %', array_to_string(v_bad, ' / ');
  end if;
end $$;


-- ══════════ spine ══════════
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
create policy wpl_qg_settings_no_delete on public.wpl_qg_settings as restrictive for delete to authenticated using (false);
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
    execute format('create policy %I on public.%I as restrictive for delete to authenticated using (false)', t || '_no_delete', t);
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
    execute format('create policy %I on public.%I as restrictive for delete to authenticated using (false)', t || '_no_delete', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
  end loop;
end $$;
alter table public.wpl_qg_risk_approvals enable row level security;
drop policy if exists wpl_qg_risk_approvals_read on public.wpl_qg_risk_approvals;
create policy wpl_qg_risk_approvals_read on public.wpl_qg_risk_approvals for select to authenticated using (public.wpl_qga_is_admin());
drop policy if exists wpl_qg_risk_approvals_no_delete on public.wpl_qg_risk_approvals;
create policy wpl_qg_risk_approvals_no_delete on public.wpl_qg_risk_approvals as restrictive for delete to authenticated using (false);
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


-- ══════════ seed ══════════
-- =====================================================================
-- QG 키트 11 — 시드: 엔진 10행 · evidence 엔진 검사 항목 · anon 허용 목록 실측 절차
--  · 엔진 화면 주소는 관리자 경로(/admin) 아래 /qg/… (설치 스크립트가 채움)
--  · anon 허용 목록은 여기서 넣지 않는다 — 플랫폼마다 다르므로 설치 직후 실측해 사람이 사유와 함께 넣는다(QG_KIT.md §4.3,
--    `node scripts/qg-verify.mjs --allowlist-draft` 가 초안 SQL 을 만들어 줌). 사유 없이(TODO) 넣으면 표 제약이 거부한다.
--  두 번 적용해도 같은 결과(on conflict).
-- =====================================================================

insert into public.wpl_qg_engines(code, name, purpose, route, icon, sort) values
 ('review',      '다중 AI 독립 검토',        '법무·개인정보·보안·UX·사업·소비자 관점의 검토자가 서로의 판정을 보지 않고 독립적으로 판정하고, 정족수·거부권 규칙으로 합의합니다. AI 키가 없으면 규칙 검토자(금칙어·숫자 검증·필수 조항·개인정보·비밀값 패턴)로 동작합니다.', '/admin/qg/review', '🧑‍⚖️', 10),
 ('testing',     '위험도별 테스트',          '기능마다 영향×가능성으로 위험 등급을 매기고 등급별로 필요한 테스트 깊이를 정합니다. 고위험인데 테스트가 없거나 오래된 기능을 찾아 보여 줍니다.', '/admin/qg/testing', '🧪', 20),
 ('adversarial', '공격·장애 시뮬레이션',     '교차 테넌트·익명 호출·금액 조작·자기 승인·폭주·외부 API 장애 같은 시나리오를 되돌리기(rollback) 전용으로 실행하고 기대 결과(거부·0행·대체 동작)와 비교합니다.', '/admin/qg/adversarial', '🥷', 30),
 ('compliance',  '법령·정책 변경 분석',      '법령·고시·정책 레지스트리와 변경 기록을 관리하고, 바뀐 내용이 어느 규칙·정책·템플릿·테넌트에 걸리는지 영향 분석과 할 일을 만듭니다.', '/admin/qg/compliance', '⚖️', 40),
 ('evidence',    '테스트 증거 보존',         '모든 실행·검토·출시 결정을 추가 전용 증거 원장에 SHA-256 해시체인으로 남기고, 체인이 끊기지 않았는지 검증하며 증거 묶음을 내려받습니다.', '/admin/qg/evidence', '🧾', 50),
 ('release',     '출시 승인·차단',           '코드 배포·정책 변경·플랫폼 고유 출시 후보를 관문 정책(필수 엔진 통과·치명 이슈 0·검토 정족수)으로 판정하고, 다른 관리자가 승인해야 출시합니다.', '/admin/qg/releases', '🚦', 60),
 ('security',    '보안 위협 탐지·대응',      '허용 목록 밖 익명 실행 함수·RLS 꺼진 표·정책 없는 표·search_path 없는 함수·내부 함수 실행 권한·서버 증명키·감사 체인을 매시 점검하고 조치 안내를 붙입니다.', '/admin/qg/security', '🛡️', 70),
 ('integrity',   '데이터 정합성 검증',       '추가 전용 표 변조 가드·감사 체인·고아 행·교차 테넌트 참조 같은 일반 정합성과, 플랫폼별 업무 정합성(결제·정산·예약…)을 매일 확인합니다.', '/admin/qg/integrity', '🧮', 80),
 ('ai_model',    'AI 모델 평가·승인·추적',   '작업별 평가 세트로 모델을 평가하고 모델×작업 승인 상태(후보→승인→퇴역)를 관리하며, 실패율·비용·지연 추세에서 이상을 찾습니다.', '/admin/qg/ai-models', '🤖', 90),
 ('evolution',   '개선사항 분석·개발 제안',  '반복 이슈·실패 테스트·플랫폼 업무 신호를 모아 우선순위가 매겨진 개선 제안을 만들고, 개발 지시서(마크다운)로 내보냅니다.', '/admin/qg/evolution', '🌱', 100)
on conflict (code) do update set name = excluded.name, purpose = excluded.purpose, route = excluded.route, icon = excluded.icon, sort = excluded.sort;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('evidence.chain_intact', 'evidence', '증거 원장 해시체인 무결성',
  '증거 원장의 모든 기록을 처음부터 다시 계산해 순번이 빠지지 않았는지, 이전 해시가 이어지는지, 내용 지문(SHA-256)과 해시가 기록 당시와 같은지 확인합니다.',
  'wpl_qg_probe_evidence_chain', 'critical', 'platform', 'daily', '{}'::jsonb,
  '끊긴 곳 0건',
  '끊긴 순번의 기록과 그 앞뒤를 확인하세요. 추가 전용 가드가 있어 앱 경로로는 바꿀 수 없으므로, 끊김은 DB 관리자 권한으로 직접 손댄 흔적입니다. 즉시 DB 접근 기록을 확인하고 책임자에게 보고하세요.', 10),
 ('evidence.audit_chain', 'evidence', '플랫폼 감사 로그 해시체인 무결성',
  '플랫폼 감사 기록의 해시체인을 다시 계산해 끊긴 곳이 없는지 확인합니다(어댑터 wpl_qga_audit_chain_check). 감사 체인이 없는 플랫폼은 건너뜁니다.',
  'wpl_qg_probe_audit_chain', 'critical', 'platform', 'daily', '{"tail":0}'::jsonb,
  '끊긴 곳 0건(없는 플랫폼은 건너뜀)',
  '플랫폼의 감사 체인 검증 화면·RPC 로 끊긴 위치를 확인하고, 그 시각 전후의 DB 접근 기록을 살펴 책임자에게 보고하세요. 감사 기록은 되돌리지 말고 사건 기록으로 남깁니다.', 20),
 ('evidence.run_has_evidence', 'evidence', '실행마다 증거 연결',
  '최근 30일 실행 기록마다 실행 보고서 증거가 붙어 있고, 결과들이 같은 증거를 가리키는지 확인합니다.',
  'wpl_qg_probe_run_evidence_link', 'high', 'platform', 'daily', '{"days":30}'::jsonb,
  '증거 없는 실행 0건 · 어긋난 결과 0건',
  '실행기(wpl_qg_record_run_internal)를 거치지 않고 실행·결과를 넣은 경로가 있는지 확인하세요. 실행·결과는 실행기와 외부 결과 올리기(wpl_qg_ingest)로만 기록해야 합니다.', 30)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
  schedule = excluded.schedule, params = excluded.params, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort;

-- ───────── anon 허용 목록: 설치 직후 실측(이 블록은 안내만 남기고 넣지 않는다) ─────────
do $$
declare v_n int; v_list text;
begin
  select count(*), string_agg(p.oid::regprocedure::text, ', ' order by 1)
    into v_n, v_list
    from pg_proc p
   where p.pronamespace = 'public'::regnamespace and p.prosecdef and has_function_privilege('anon', p.oid, 'execute')
     and p.oid::regprocedure::text not in (select signature from public.wpl_qg_anon_allowlist where active);
  if v_n > 0 then
    raise notice 'QG: 익명(anon)이 실행할 수 있는 SECURITY DEFINER 함수 %개가 허용 목록에 없습니다. 정당한 공개 함수만 사유·보호 장치와 함께 wpl_qg_anon_allowlist 에 넣고, 나머지는 실행 권한을 회수하세요: %', v_n, left(v_list, 3000);
  end if;
end $$;


-- ══════════ security ══════════
-- =====================================================================
-- QG 키트 20 — 보안 위협 탐지·대응 엔진(security) (원본: F-MATRIX 2910)
--  시스템 카탈로그(pg_proc·pg_class·pg_policy)만 보므로 어느 플랫폼에서나 그대로 동작한다.
--  · 허용 목록 밖 익명 실행 SECURITY DEFINER                 security.anon_definer        치명
--  · RLS 꺼진 public 표 · RLS 를 우회하는 공개 뷰              security.rls_disabled        치명/높음
--  · RLS 켜졌는데 정책 0개(의도일 수 있음 → 주의)              security.no_policies         보통(주의)
--  · search_path 없는 DEFINER                                  security.definer_search_path 높음
--  · 내부 함수(*_internal·probe·어댑터)의 앱 사용자 실행 권한  security.internal_exec       높음
--  · 서버 증명키 해시 형식                                     security.server_key_hash     보통
--  · 감사 로그 해시체인(최근 N건, 매시, 어댑터)                security.audit_chain_tail    치명
--  · 실패 로그인·재설정 급증(auth 감사 로그 접근 가능할 때)    security.login_spike         높음
--  플랫폼 고유 위협(공개 접수 폭주 등)은 같은 규약의 probe 를 플랫폼 파일에 추가한다(QG_KIT.md §5).
--  공유 DB(여러 제품이 한 public 스키마): 각 검사 params 에 include_prefixes·exclude_prefixes(v1.1) — QG 자신은 항상 포함.
--  두 번 적용해도 같은 결과.
-- =====================================================================

insert into public.wpl_qg_settings(key, value, label, description) values
 ('qg_sec_login_thresholds', '{"window_minutes":60,"auth_fail":30}',
  '품질·거버넌스(보안): 로그인 공격 의심 기준',
  '최근 window_minutes 분 동안 인증 감사 로그의 실패성 기록이 auth_fail 건을 넘으면 보안 이슈를 올립니다. 인증 감사 로그를 읽을 수 없으면 건너뜁니다. JSON 객체.'),
 ('qg_audit_unsealed_grace_minutes', '10',
  '품질·거버넌스(감사 체인): 봉인 대기 허용 시간(분)',
  '커밋 직전에 해시를 받는(봉인) 감사 로그 플랫폼에서, 해시가 비어 있는 감사 기록이 이 시간보다 오래되면 봉인이 멈춘 것으로 보고 감사 체인 검사를 실패로 올립니다. 넣을 때 해시하는 플랫폼에는 영향이 없습니다(어댑터 audit_chain_check 계약 v1.2).')
on conflict (key) do nothing;

-- 0) 공유 DB(한 DB 에 여러 제품) 범위: params.include_prefixes(비어 있으면 전체) · params.exclude_prefixes 로 이름 접두어를 거른다.
--    QG 자신(wpl_qg_·wpl_qga_)과 키트 스모크 시험 객체(zz_qg_ — 항상 rollback 안에서만 생김, v1.2)는 항상 검사한다.
--    예: {"include_prefixes":["gos_"],"exclude_prefixes":["ekos_"]} — 공유 DB 에서 include_prefixes 를 써도 키트 스모크 G 구역이 그대로 통과한다.
create or replace function public.wpl_qg_scope_ok_internal(p_name text, p_params jsonb) returns boolean
language sql immutable set search_path = public as $$
  select p_name like 'wpl\_qg\_%' or p_name like 'wpl\_qga\_%' or p_name like 'zz\_qg\_%'
      or ((case when jsonb_typeof(p_params->'include_prefixes') = 'array' and jsonb_array_length(p_params->'include_prefixes') > 0
                then exists (select 1 from jsonb_array_elements_text(p_params->'include_prefixes') x where x <> '' and left(p_name, length(x)) = x)
                else true end)
          and not exists (select 1 from jsonb_array_elements_text(case when jsonb_typeof(p_params->'exclude_prefixes') = 'array' then p_params->'exclude_prefixes' else '[]'::jsonb end) x
                           where x <> '' and left(p_name, length(x)) = x))
$$;
revoke all on function public.wpl_qg_scope_ok_internal(text, jsonb) from public, anon, authenticated;

-- 1) 허용 목록 밖 익명 실행 SECURITY DEFINER(치명) + 사라진 허용 목록 항목(낮음)
create or replace function public.wpl_qg_probe_security_anon_definer(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; r record; v_total int; v_allowed int;
begin
  select count(*) into v_total from pg_proc p
   where p.pronamespace = 'public'::regnamespace and p.prosecdef and has_function_privilege('anon', p.oid, 'execute')
     and public.wpl_qg_scope_ok_internal(p.proname, p_check.params);
  select count(*) into v_allowed from public.wpl_qg_anon_allowlist where active;
  for r in select p.oid::regprocedure::text sig from pg_proc p
            where p.pronamespace = 'public'::regnamespace and p.prosecdef and has_function_privilege('anon', p.oid, 'execute')
              and public.wpl_qg_scope_ok_internal(p.proname, p_check.params)
              and p.oid::regprocedure::text not in (select a.signature from public.wpl_qg_anon_allowlist a where a.active)
            order by 1 loop
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', r.sig,
      'title', '로그인 없이 실행되는 권한 상승 함수(허용 목록 밖): ' || left(r.sig, 200),
      'detail', jsonb_build_object('signature', r.sig,
        'message', '로그인하지 않은 사람(anon)이 이 SECURITY DEFINER 함수를 실행할 수 있습니다. DEFINER 는 함수 주인 권한으로 돌아 RLS 를 건너뜁니다.')));
  end loop;
  for r in select a.signature from public.wpl_qg_anon_allowlist a
            where a.active and public.wpl_qg_scope_ok_internal(split_part(a.signature, '(', 1), p_check.params)
              and not exists (select 1 from pg_proc p where p.pronamespace = 'public'::regnamespace and p.oid::regprocedure::text = a.signature)
            order by 1 loop
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'low', 'fingerprint', 'stale:' || r.signature,
      'title', '허용 목록에 있지만 DB 에 없는 함수: ' || left(r.signature, 200),
      'detail', jsonb_build_object('signature', r.signature,
        'message', '함수가 지워졌거나 인자 모양이 바뀌었습니다. 허용 목록에서 이 항목을 끄거나 새 시그니처로 고치세요.')));
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('anon_definer_total', v_total, 'allowlisted', v_allowed,
      'message', format('익명 실행 가능한 DEFINER %s개가 모두 허용 목록(%s개)에 있습니다.', v_total, v_allowed)));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_security_anon_definer(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 2) RLS 꺼진 public 표(익명·로그인 사용자에게 권한이 있으면 치명, 없으면 주의) + RLS 우회 공개 뷰(높음)
create or replace function public.wpl_qg_probe_security_rls_disabled(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; r record; v_ex jsonb := coalesce(p_check.params->'exclude', '[]'::jsonb); v_tables int; v_exposed boolean;
begin
  select count(*) into v_tables from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind in ('r','p');
  for r in select c.oid, c.relname from pg_class c
            where c.relnamespace = 'public'::regnamespace and c.relkind in ('r','p') and not c.relrowsecurity
              and not (v_ex ? c.relname) and public.wpl_qg_scope_ok_internal(c.relname, p_check.params)
            order by c.relname loop
    v_exposed := has_table_privilege('anon', r.oid, 'select,insert,update,delete') or has_table_privilege('authenticated', r.oid, 'select,insert,update,delete');
    v_out := v_out || jsonb_build_array(jsonb_build_object(
      'status', case when v_exposed then 'fail' else 'warn' end, 'severity', case when v_exposed then 'critical' else 'medium' end,
      'fingerprint', 'table:' || r.relname,
      'title', 'RLS 꺼진 표: ' || r.relname || case when v_exposed then '(익명·로그인 사용자에게 권한 있음)' else '' end,
      'detail', jsonb_build_object('table', r.relname, 'exposed', v_exposed,
        'anon_select', has_table_privilege('anon', r.oid, 'select'), 'authenticated_write', has_table_privilege('authenticated', r.oid, 'insert,update,delete'),
        'message', case when v_exposed then 'Supabase REST 로 누구나(또는 로그인한 누구나) 이 표의 모든 행을 읽거나 쓸 수 있습니다.'
                        else 'RLS 가 꺼져 있지만 지금은 익명·로그인 사용자 권한이 없습니다. 권한이 생기는 순간 전부 노출됩니다.' end)));
  end loop;
  for r in select c.oid, c.relname from pg_class c
            where c.relnamespace = 'public'::regnamespace and c.relkind in ('v','m')
              and (has_table_privilege('anon', c.oid, 'select') or has_table_privilege('authenticated', c.oid, 'select'))
              and not coalesce(c.reloptions, '{}'::text[]) && array['security_invoker=true','security_invoker=on']
              and not (v_ex ? c.relname) and public.wpl_qg_scope_ok_internal(c.relname, p_check.params)
            order by c.relname loop
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', 'view:' || r.relname,
      'title', 'RLS 를 우회하는 공개 뷰: ' || r.relname,
      'detail', jsonb_build_object('view', r.relname, 'anon_select', has_table_privilege('anon', r.oid, 'select'),
        'message', '이 뷰는 만든 사람(주인) 권한으로 실행되어 아래 표의 RLS 를 건너뜁니다.')));
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('tables', v_tables, 'excluded', v_ex,
      'message', format('public 표 %s개 모두 RLS 가 켜져 있고, 공개 뷰는 모두 호출자 권한(security_invoker)입니다.', v_tables)));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_security_rls_disabled(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 3) RLS 켜졌는데 정책 0개 — params.intended = {표: 사유} 는 의도로 보고 통과
create or replace function public.wpl_qg_probe_security_no_policies(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; r record; v_int jsonb := coalesce(p_check.params->'intended', '{}'::jsonb); v_ok int := 0;
begin
  for r in select c.relname from pg_class c
            where c.relnamespace = 'public'::regnamespace and c.relkind in ('r','p') and c.relrowsecurity
              and not exists (select 1 from pg_policy p where p.polrelid = c.oid)
              and public.wpl_qg_scope_ok_internal(c.relname, p_check.params)
            order by c.relname loop
    if jsonb_typeof(v_int) = 'object' and v_int ? r.relname then v_ok := v_ok + 1; continue; end if;
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', 'table:' || r.relname,
      'title', '정책이 하나도 없는 표: ' || r.relname,
      'detail', jsonb_build_object('table', r.relname,
        'message', 'RLS 는 켜져 있지만 정책이 없어 앱 사용자는 이 표를 전혀 읽고 쓸 수 없습니다(DEFINER 함수·service_role 만 가능). 의도라면 검사 항목 params.intended 에 사유와 함께 적으세요.')));
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('intended', v_ok,
      'message', case when v_ok > 0 then format('정책 없는 표 %s개는 모두 의도된 것(내부 함수 전용)으로 등록되어 있습니다.', v_ok) else 'RLS 를 켠 표마다 정책이 있습니다.' end));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_security_no_policies(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 4) search_path 없는 SECURITY DEFINER(높음)
create or replace function public.wpl_qg_probe_security_definer_search_path(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; r record; v_total int;
begin
  select count(*) into v_total from pg_proc p where p.pronamespace = 'public'::regnamespace and p.prosecdef;
  for r in select p.oid::regprocedure::text sig from pg_proc p
            where p.pronamespace = 'public'::regnamespace and p.prosecdef and public.wpl_qg_scope_ok_internal(p.proname, p_check.params)
              and not exists (select 1 from unnest(coalesce(p.proconfig, '{}'::text[])) c where c like 'search_path=%')
            order by 1 loop
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', r.sig,
      'title', '실행 경로(search_path)가 고정되지 않은 권한 상승(DEFINER) 함수: ' || left(r.sig, 200),
      'detail', jsonb_build_object('signature', r.sig,
        'message', '호출자가 search_path 를 바꿔 같은 이름의 가짜 표·함수를 먼저 찾게 만들면 주인 권한으로 실행됩니다(권한 상승).')));
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('definer_total', v_total, 'message', format('DEFINER 함수 %s개 모두 search_path 가 고정되어 있습니다.', v_total)));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_security_definer_search_path(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 5) 내부 함수 실행 권한(이름 패턴) · 트리거 함수 실행 권한(낮음). 어댑터 중 RLS 용 2개(is_admin·can_read_tenant)는 예외.
create or replace function public.wpl_qg_probe_security_internal_exec(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; r record;
        v_pat jsonb := coalesce(p_check.params->'name_patterns', '["%\\_internal","wpl\\_qg\\_probe\\_%","wpl\\_qga\\_%"]'::jsonb);
        v_allow jsonb := coalesce(p_check.params->'allow', '["wpl_qga_is_admin()","wpl_qga_can_read_tenant(uuid)"]'::jsonb);
        v_pats text[]; v_trig int := 0; v_trig_list text[] := '{}';
begin
  select coalesce(array_agg(x), '{}') into v_pats from jsonb_array_elements_text(case when jsonb_typeof(v_pat) = 'array' then v_pat else '[]'::jsonb end) x;
  for r in select p.oid::regprocedure::text sig, has_function_privilege('anon', p.oid, 'execute') a from pg_proc p
            where p.pronamespace = 'public'::regnamespace and p.prorettype <> 'trigger'::regtype and p.proname like any (v_pats)
              and public.wpl_qg_scope_ok_internal(p.proname, p_check.params)
              and (has_function_privilege('authenticated', p.oid, 'execute') or has_function_privilege('anon', p.oid, 'execute'))
            order by 1 loop
    if v_allow ? r.sig and not r.a then continue; end if;
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', case when r.a then 'critical' else 'high' end, 'fingerprint', r.sig,
      'title', '내부 함수를 앱 사용자가 직접 실행할 수 있음: ' || left(r.sig, 200),
      'detail', jsonb_build_object('signature', r.sig, 'anon', r.a,
        'message', '내부 함수는 권한 확인을 바깥 RPC 가 대신 한다는 전제로 만들어져, 직접 부르면 권한 확인 없이 실행됩니다.')));
  end loop;
  for r in select p.oid::regprocedure::text sig from pg_proc p
            where p.pronamespace = 'public'::regnamespace and p.prorettype = 'trigger'::regtype
              and public.wpl_qg_scope_ok_internal(p.proname, p_check.params)
              and (has_function_privilege('authenticated', p.oid, 'execute') or has_function_privilege('anon', p.oid, 'execute'))
            order by 1 loop
    v_trig := v_trig + 1;
    if v_trig <= 50 then v_trig_list := v_trig_list || r.sig; end if;
  end loop;
  if v_trig > 0 then
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'low', 'fingerprint', 'trigger_functions',
      'title', format('실행 권한이 남은 트리거 함수 %s개', v_trig),
      'detail', jsonb_build_object('count', v_trig, 'functions', to_jsonb(v_trig_list),
        'message', '트리거 함수는 직접 호출할 수 없어 당장 위험은 없지만, 최소 권한 원칙대로 실행 권한을 회수하세요.')));
  end if;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('patterns', v_pat, 'message', '내부 함수·트리거 함수를 앱 사용자가 실행할 수 없습니다.'));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_security_internal_exec(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 6) 서버 증명키 해시 — params.managed_by_platform = true 면 플랫폼 어댑터가 자기 키를 쓰므로 통과
create or replace function public.wpl_qg_probe_security_server_key_hash(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v text := public.wpl_qg_setting_internal('qg_server_attest_key_hash', '""'::jsonb) #>> '{}';
begin
  if coalesce((p_check.params->>'managed_by_platform')::boolean, false) or coalesce(public.wpl_qga_info()->>'server_key', 'qg') = 'platform' then
    return jsonb_build_object('status', 'skipped', 'detail', jsonb_build_object('message', '이 플랫폼은 어댑터가 플랫폼 설정의 서버 증명키를 씁니다(플랫폼 보안 점검에서 확인).',
      'adapter', public.wpl_qga_info()->>'adapter'));
  end if;
  if coalesce(v, '') ~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('message', '서버 증명키 해시(SHA-256)가 설정되어 있습니다.', 'hash_prefix', left(v, 6)));
  end if;
  return jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', case when coalesce(v, '') = '' then 'empty' else 'malformed' end,
    'title', case when coalesce(v, '') = '' then '서버 증명키 해시가 비어 있음' else '서버 증명키 해시 형식이 잘못됨' end,
    'detail', jsonb_build_object('message', '스크립트·CI 의 결과 올리기(키 경로)가 모두 거부됩니다. 관리자 로그인으로만 결과를 올릴 수 있습니다.'));
end $$;
revoke all on function public.wpl_qg_probe_security_server_key_hash(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 7) 감사 로그 해시체인(최근 N건) — 어댑터 계산. 없는 플랫폼은 건너뜀
create or replace function public.wpl_qg_probe_security_audit_chain_tail(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb := public.wpl_qga_audit_chain_check(greatest(0, coalesce((p_check.params->>'tail')::int, 2000)));
begin
  if not coalesce((v->>'supported')::boolean, false) then return jsonb_build_object('status', 'skipped', 'detail', v); end if;
  if coalesce((v->>'ok')::boolean, false) then return jsonb_build_object('status', 'pass', 'detail', v); end if;
  return jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', 'audit_chain_broken',
    'title', '감사 로그 해시체인이 끊김(' || coalesce(v->>'broken_at', '?') || ')',
    'detail', v || jsonb_build_object('message', '감사 기록이 앱 경로가 아닌 방법(DB 직접 수정)으로 바뀌었거나 지워졌습니다.'));
end $$;
revoke all on function public.wpl_qg_probe_security_audit_chain_tail(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 8) 로그인 공격 의심 — auth.audit_log_entries 를 읽을 수 있을 때만
create or replace function public.wpl_qg_probe_security_login_spike(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare
  t jsonb := public.wpl_qg_setting_internal('qg_sec_login_thresholds', '{"window_minutes":60,"auth_fail":30}'::jsonb);
  v_win int := greatest(5, coalesce((t->>'window_minutes')::int, 60)); v_since timestamptz;
  v_pat jsonb := coalesce(p_check.params->'fail_action_patterns', '["%fail%","%invalid%","user_repeated_signup"]'::jsonb); v_pats text[];
  v_fail int := 0; v_logins int := 0; v_counts jsonb;
begin
  if to_regclass('auth.audit_log_entries') is null or not has_table_privilege(current_user, 'auth.audit_log_entries', 'select') then
    return jsonb_build_object('status', 'skipped', 'detail', jsonb_build_object('message', '인증 감사 로그(auth.audit_log_entries)를 읽을 수 없어 건너뛰었습니다.'));
  end if;
  v_since := now() - make_interval(mins => v_win);
  select coalesce(array_agg(x), '{}') into v_pats from jsonb_array_elements_text(case when jsonb_typeof(v_pat) = 'array' then v_pat else '[]'::jsonb end) x;
  execute 'select count(*) filter (where coalesce(payload->>''action'', '''') like any ($2)), count(*) filter (where payload->>''action'' = ''login'')
             from auth.audit_log_entries where created_at > $1'
    into v_fail, v_logins using v_since, v_pats;
  v_counts := jsonb_build_object('window_minutes', v_win, 'auth_fail', v_fail, 'logins', v_logins, 'limit', t->'auth_fail');
  if v_fail > coalesce((t->>'auth_fail')::int, 30) then
    return jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', 'auth_fail',
      'title', format('최근 %s분 인증 실패성 기록 급증(%s건)', v_win, v_fail), 'detail', v_counts);
  end if;
  return jsonb_build_object('status', 'pass', 'detail', v_counts || jsonb_build_object('message', format('최근 %s분 로그인 %s건 · 실패성 %s건(기준 이내).', v_win, v_logins, v_fail)));
end $$;
revoke all on function public.wpl_qg_probe_security_login_spike(public.wpl_qg_checks, uuid) from public, anon, authenticated;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('security.anon_definer', 'security', '허용 목록 밖 익명 실행 함수',
  '로그인하지 않은 사람(anon)이 실행할 수 있는 SECURITY DEFINER 함수를 실제 DB 에서 모두 찾아 익명 실행 허용 목록과 대조합니다.',
  'wpl_qg_probe_security_anon_definer', 'critical', 'platform', 'hourly', '{}'::jsonb,
  '허용 목록 밖 익명 실행 함수 0개',
  '① 의도하지 않은 공개라면 즉시 실행 권한을 회수하세요: revoke all on function public.<함수>(<인자>) from public, anon; (Supabase 는 anon·authenticated 에 EXECUTE 를 직접 주므로 from public 만으로는 부족) ② 정말 공개해야 하는 함수라면 서버 증명키·토큰·속도 제한 같은 보호 장치를 확인한 뒤 허용 목록(wpl_qg_anon_allowlist)에 사유·보호 장치와 함께 등록하세요. ③ 고친 뒤 이슈를 ''고쳤음''으로 바꾸면 다음 매시 실행에서 자동 확인됩니다.', 10),
 ('security.rls_disabled', 'security', 'RLS 꺼진 표 · RLS 우회 공개 뷰',
  'public 스키마의 모든 표에서 행 수준 보안(RLS)이 꺼진 표를 찾고, 익명·로그인 사용자 권한을 함께 봅니다. 주인 권한으로 실행되어 RLS 를 건너뛰는 공개 뷰도 찾습니다.',
  'wpl_qg_probe_security_rls_disabled', 'critical', 'platform', 'hourly', '{"exclude":[]}'::jsonb,
  'RLS 꺼진 표 0개 · RLS 우회 공개 뷰 0개',
  '① 표: alter table public.<표> enable row level security; 후 필요한 정책을 만들고 revoke all on public.<표> from anon; ② 뷰: alter view public.<뷰> set (security_invoker = true); ③ 정말 예외라면 params.exclude 에 이름을 넣고 이슈 메모에 사유를 남기세요.', 20),
 ('security.no_policies', 'security', '정책이 하나도 없는 표',
  'RLS 는 켜졌지만 정책이 하나도 없는 표를 찾습니다. 내부 함수 전용 표는 params.intended 에 사유와 함께 등록해 두면 통과합니다.',
  'wpl_qg_probe_security_no_policies', 'medium', 'platform', 'hourly', '{"intended":{}}'::jsonb,
  '의도되지 않은 정책 없는 표 0개',
  '① 앱 화면이 이 표를 읽어야 한다면 정책을 만드세요. ② 내부 함수 전용이 맞다면 검사 항목 security.no_policies 의 params.intended 에 "<표>": "<사유>" 를 넣으세요.', 30),
 ('security.definer_search_path', 'security', 'search_path 고정 안 된 DEFINER 함수',
  'SECURITY DEFINER 함수마다 search_path 가 고정되어 있는지 확인합니다.',
  'wpl_qg_probe_security_definer_search_path', 'high', 'platform', 'hourly', '{}'::jsonb,
  '고정 안 된 DEFINER 0개',
  '함수 정의에 set search_path = public 을 붙이거나 alter function public.<함수>(<인자>) set search_path = public; 을 실행하세요.', 40),
 ('security.internal_exec', 'security', '내부 함수 실행 권한',
  '이름이 *_internal·품질 검사 함수(wpl_qg_probe_*)·QG 어댑터(wpl_qga_*)인 내부 함수를 로그인·익명 사용자가 직접 실행할 수 있는지, 트리거 함수에 실행 권한이 남아 있는지 확인합니다(어댑터 중 RLS 용 2개는 예외).',
  'wpl_qg_probe_security_internal_exec', 'high', 'platform', 'hourly',
  '{"name_patterns":["%\\_internal","wpl\\_qg\\_probe\\_%","wpl\\_qga\\_%"],"allow":["wpl_qga_is_admin()","wpl_qga_can_read_tenant(uuid)"]}'::jsonb,
  '앱 사용자가 실행 가능한 내부 함수 0개',
  'revoke all on function public.<함수>(<인자>) from public, anon, authenticated; 를 실행하세요(새 함수를 만들 때마다 같은 줄을 마이그레이션에 넣는 것이 규칙).', 50),
 ('security.server_key_hash', 'security', '서버 증명키 설정',
  '스크립트·CI 가 결과를 올릴 때 쓰는 서버 증명키 해시(QG 설정 qg_server_attest_key_hash)가 SHA-256 형식인지 확인합니다. 플랫폼 어댑터가 자기 키를 쓰면 params.managed_by_platform = true.',
  'wpl_qg_probe_security_server_key_hash', 'medium', 'platform', 'hourly', '{"managed_by_platform":false}'::jsonb,
  'SHA-256(64자리 16진수) 해시가 설정됨',
  '① 서버 ENV QG_SERVER_ATTEST_KEY 에 긴 무작위 값을 넣고 ② 그 SHA-256 을 품질·거버넌스 설정 화면의 서버 증명키 해시에 넣으세요. 키 원문은 DB·채팅·로그에 남기지 마세요.', 60),
 ('security.audit_chain_tail', 'security', '감사 로그 해시체인(최근 기록)',
  '플랫폼 감사 로그의 최근 기록(params.tail 건)의 해시를 다시 계산해 체인이 이어지는지 매시 확인합니다(어댑터 계산, 없는 플랫폼은 건너뜀).',
  'wpl_qg_probe_security_audit_chain_tail', 'critical', 'platform', 'hourly', '{"tail":2000}'::jsonb,
  '끊긴 곳 0건',
  '① 플랫폼 감사 체인 검증으로 끊긴 위치를 확인하세요. ② 그 시각 전후 DB 접근 기록을 확인해 누가 직접 수정했는지 찾으세요. ③ DB 비밀번호·service_role 키를 교체하고 책임자에게 보고하세요.', 70),
 ('security.login_spike', 'security', '로그인 공격 의심',
  '최근 1시간(설정값) 동안 인증 감사 로그의 실패성 기록 수를 기준과 비교합니다. 인증 감사 로그를 읽을 수 없으면 건너뜁니다.',
  'wpl_qg_probe_security_login_spike', 'high', 'platform', 'hourly', '{"fail_action_patterns":["%fail%","%invalid%","user_repeated_signup"]}'::jsonb,
  '기준 이내(읽을 수 없으면 건너뜀)',
  '① Supabase 대시보드 Authentication → Logs 에서 같은 IP·이메일의 반복 시도를 확인하세요. ② 공격이면 Auth 속도 제한을 낮추고 방화벽에서 IP 를 막으세요. ③ 표적 계정은 비밀번호 재설정을 안내하세요.', 80)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
  schedule = excluded.schedule, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort, engine_code = excluded.engine_code;
  -- params 는 설치 뒤 사람이 고친 값(exclude·intended·allow)을 덮지 않는다


-- ══════════ integrity ══════════
-- =====================================================================
-- QG 키트 21 — 데이터 정합성 엔진(integrity): 업무 표와 무관한 일반 검사 (원본: F-MATRIX 2911 의 일반 부분)
--  · 추가 전용 표 수정·삭제 가드 존재·켜짐(목록 + 꺼진 가드 전수)        integrity.append_only_guards  치명
--  · 플랫폼 감사 로그 해시체인(어댑터)                                  integrity.audit_chain         치명
--  · 고아 행 표본: 외래키 없는 테넌트 칸·이름으로만 가리키는 칸(soft_refs) integrity.orphans             보통/치명
--  · 교차 테넌트 참조 표본: 외래키 양쪽 tenant 칸이 다른 행               integrity.cross_tenant_fk     치명
--  업무 정합성(결제 합·정산·예약·재고…)은 플랫폼 파일에서 같은 규약으로 추가한다(QG_KIT.md §6 예시 10종).
--  동적 SQL 은 pg_catalog 에서 확인한 식별자만 format('%I') 로 쓴다(카탈로그 문자열을 SQL 로 실행하지 않음).
--  임계·표 목록·예외는 검사 항목 params(카탈로그). 두 번 적용해도 같은 결과.
-- =====================================================================

-- 식별자 확인(public 표·칸 존재 + 이름 규칙)
create or replace function public.wpl_qg_ident_ok_internal(p_table text, p_column text default null)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce(p_table, '') ~ '^[a-z_][a-z0-9_]{0,62}$'
     and (p_column is null or p_column ~ '^[a-z_][a-z0-9_]{0,62}$')
     and exists (select 1 from pg_class c where c.relnamespace = 'public'::regnamespace and c.relname = p_table and c.relkind in ('r','p'))
     and (p_column is null or exists (select 1 from pg_attribute a where a.attrelid = to_regclass('public.' || quote_ident(p_table))
                                        and a.attname = p_column and a.attnum > 0 and not a.attisdropped))
$$;
revoke all on function public.wpl_qg_ident_ok_internal(text, text) from public, anon, authenticated;

-- 1) 추가 전용 표 가드 — params: tables(추가 전용이어야 하는 표), guard_functions(가드로 인정하는 트리거 함수 이름)
create or replace function public.wpl_qg_probe_integrity_append_only_guards(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; t text; v_oid oid; v_upd boolean; v_del boolean; v_n int := 0; r record;
        v_fns text[]; v_tabs jsonb := coalesce(p_check.params->'tables', '[]'::jsonb);
begin
  select coalesce(array_agg(x), array['wpl_qg_forbid_mutation'])
    into v_fns
    from jsonb_array_elements_text(case when jsonb_typeof(p_check.params->'guard_functions') = 'array' then p_check.params->'guard_functions' else '["wpl_qg_forbid_mutation"]'::jsonb end) x;
  for t in select jsonb_array_elements_text(case when jsonb_typeof(v_tabs) = 'array' then v_tabs else '[]'::jsonb end) loop
    v_n := v_n + 1;
    if not public.wpl_qg_ident_ok_internal(t) then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'low', 'fingerprint', 'missing:' || left(t, 80),
        'title', '목록의 추가 전용 표가 DB 에 없음: ' || left(t, 80), 'detail', jsonb_build_object('table', left(t, 80), 'message', '표 이름이 바뀌었으면 검사 항목 params.tables 를 고치세요.')));
      continue;
    end if;
    v_oid := ('public.' || quote_ident(t))::regclass;
    -- tgtype 비트: 1=행 단위, 2=BEFORE, 8=DELETE, 16=UPDATE. tgenabled 'D' = 꺼짐
    select bool_or((tg.tgtype & 1) = 1 and (tg.tgtype & 2) = 2 and (tg.tgtype & 16) = 16),
           bool_or((tg.tgtype & 1) = 1 and (tg.tgtype & 2) = 2 and (tg.tgtype & 8) = 8)
      into v_upd, v_del
      from pg_trigger tg join pg_proc f on f.oid = tg.tgfoid
     where tg.tgrelid = v_oid and not tg.tgisinternal and tg.tgenabled <> 'D' and f.proname = any (v_fns);
    if not coalesce(v_upd, false) or not coalesce(v_del, false) then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', 'table:' || t,
        'title', '추가 전용 표에 ' || case when not coalesce(v_upd, false) and not coalesce(v_del, false) then '수정·삭제' when not coalesce(v_upd, false) then '수정' else '삭제' end || ' 가드가 없음: ' || t,
        'detail', jsonb_build_object('table', t, 'update_guard', coalesce(v_upd, false), 'delete_guard', coalesce(v_del, false),
          'message', '원장·감사 기록을 앱이나 관리자가 고치거나 지울 수 있습니다.')));
    end if;
  end loop;
  for r in select tg.tgrelid::regclass::text as tbl, tg.tgname from pg_trigger tg join pg_proc f on f.oid = tg.tgfoid
            join pg_class c on c.oid = tg.tgrelid and c.relnamespace = 'public'::regnamespace
            where not tg.tgisinternal and tg.tgenabled = 'D' and f.proname = any (v_fns) loop
    v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', 'disabled:' || r.tbl || '.' || r.tgname,
      'title', '꺼진 추가 전용 가드: ' || r.tbl || ' (' || r.tgname || ')', 'detail', jsonb_build_object('table', r.tbl, 'trigger', r.tgname,
        'message', 'alter table … disable trigger 로 가드가 꺼져 있습니다. 누가 왜 껐는지 확인하고 다시 켜세요.')));
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('tables', v_n, 'message', format('추가 전용 표 %s개 모두 수정·삭제 가드가 켜져 있습니다.', v_n)));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_integrity_append_only_guards(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 2) 고아 행 표본
--  (a) params.tenant_table(예: tenants) 이 있으면: 테넌트 칸(params.tenant_column, 기본 tenant_id)이 그 표에 외래키 없이 있는 표에서 사라진 테넌트를 가리키는 행
--      (params.history_tables 는 이력 보존이라 제외, params.table_prefixes 로 대상 표 제한)
--  (b) params.soft_refs: [{table, column, ref, ref_column?(기본 id), same_tenant?}] — 외래키 없이 이름으로만 가리키는 칸
create or replace function public.wpl_qg_probe_integrity_orphans(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; r record; x jsonb; v_cnt bigint; v_cnt2 bigint; v_hist jsonb := coalesce(p_check.params->'history_tables', '[]'::jsonb);
        v_checked int := 0; v_t text; v_c text; v_ref text; v_rc text; v_same boolean; v_tt text := p_check.params->>'tenant_table';
        v_tc text := coalesce(nullif(p_check.params->>'tenant_column', ''), 'tenant_id'); v_pre text[]; v_lim int := greatest(100, coalesce((p_check.params->>'sample_rows')::int, 50000));
begin
  select coalesce(array_agg(x2 || '%'), array['%']) into v_pre
    from jsonb_array_elements_text(case when jsonb_typeof(p_check.params->'table_prefixes') = 'array' then p_check.params->'table_prefixes' else '[]'::jsonb end) x2;
  if v_tt is not null and public.wpl_qg_ident_ok_internal(v_tt, 'id') and v_tc ~ '^[a-z_][a-z0-9_]{0,62}$' then
    for r in select c.relname from pg_class c join pg_attribute a on a.attrelid = c.oid and a.attname = v_tc and not a.attisdropped and a.atttypid = 'uuid'::regtype
              where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and c.relname like any (v_pre) and c.relname <> v_tt
                and c.relname not like 'wpl\_qg\_%' and not (v_hist ? c.relname)
                and not exists (select 1 from pg_constraint k where k.conrelid = c.oid and k.contype = 'f' and k.conkey = array[a.attnum]
                                  and k.confrelid = ('public.' || quote_ident(v_tt))::regclass)
              order by 1 loop
      v_checked := v_checked + 1;
      execute format('select count(*) from (select x.%I from public.%I x where x.%I is not null limit %s) x where not exists (select 1 from public.%I t where t.id = x.%I)',
                     v_tc, r.relname, v_tc, v_lim, v_tt, v_tc) into v_cnt;
      if v_cnt > 0 then
        v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'medium', 'fingerprint', 'tenant:' || r.relname,
          'title', format('사라진 테넌트를 가리키는 행: %s (%s행, 표본 %s)', r.relname, v_cnt, v_lim), 'detail', jsonb_build_object('table', r.relname, 'rows', v_cnt, 'sample_rows', v_lim)));
      end if;
    end loop;
  end if;
  for x in select e from jsonb_array_elements(case when jsonb_typeof(p_check.params->'soft_refs') = 'array' then p_check.params->'soft_refs' else '[]'::jsonb end) e loop
    v_t := x->>'table'; v_c := x->>'column'; v_ref := x->>'ref'; v_rc := coalesce(nullif(x->>'ref_column', ''), 'id'); v_same := coalesce((x->>'same_tenant')::boolean, false);
    if not public.wpl_qg_ident_ok_internal(v_t, v_c) or not public.wpl_qg_ident_ok_internal(v_ref, v_rc)
       or (v_same and (not public.wpl_qg_ident_ok_internal(v_t, v_tc) or not public.wpl_qg_ident_ok_internal(v_ref, v_tc))) then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'low', 'fingerprint', 'config:' || left(coalesce(v_t, '') || '.' || coalesce(v_c, ''), 120),
        'title', '고아 행 검사 설정의 표·칸이 DB 에 없음', 'detail', jsonb_build_object('entry', x)));
      continue;
    end if;
    v_checked := v_checked + 1;
    execute format('select count(*) filter (where p.%I is null), count(*) filter (where p.%I is not null and %s) from (select * from public.%I x where x.%I is not null %s limit %s) x left join public.%I p on p.%I = x.%I',
                   v_rc, v_rc, case when v_same then format('p.%I is distinct from x.%I', v_tc, v_tc) else 'false' end, v_t, v_c,
                   case when p_tenant is not null and public.wpl_qg_ident_ok_internal(v_t, v_tc) then format('and x.%I = %L', v_tc, p_tenant) else '' end,
                   v_lim, v_ref, v_rc, v_c)
      into v_cnt, v_cnt2;
    if v_cnt > 0 then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'medium', 'fingerprint', 'ref:' || v_t || '.' || v_c,
        'title', format('없는 대상을 가리키는 행: %s.%s → %s (%s행)', v_t, v_c, v_ref, v_cnt), 'detail', jsonb_build_object('table', v_t, 'column', v_c, 'ref', v_ref, 'rows', v_cnt)));
    end if;
    if v_cnt2 > 0 then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', 'xref:' || v_t || '.' || v_c,
        'title', format('다른 테넌트 대상을 가리키는 행: %s.%s → %s (%s행)', v_t, v_c, v_ref, v_cnt2), 'detail', jsonb_build_object('table', v_t, 'column', v_c, 'ref', v_ref, 'rows', v_cnt2)));
    end if;
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('checked', v_checked,
      'message', case when v_checked = 0 then '검사할 참조가 설정되지 않았습니다(params.tenant_table·soft_refs 를 넣으면 검사합니다).' else format('고아 행 0건(살펴본 참조 %s개).', v_checked) end));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_integrity_orphans(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 3) 교차 테넌트 참조 표본 — 외래키(단일 칸)의 양쪽 표에 테넌트 칸이 있을 때 참조 행과 대상 행의 테넌트가 다른 경우
--  params: tenant_column(기본 tenant_id), table_prefixes(기본 전체), exclude_tables, sample_rows(외래키 1개당), max_fks,
--          allowed_fks(v1.1) = {"표.칸": "사유"} — 조직 간 협업이 본질인 참조(수요 조직 ≠ 처리 조직 등). 결과는 통과 상세에 건수만 남긴다.
create or replace function public.wpl_qg_probe_integrity_cross_tenant_fk(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_out jsonb := '[]'::jsonb; k record; v_cnt bigint; v_fks int := 0; v_sample int := greatest(100, coalesce((p_check.params->>'sample_rows')::int, 20000));
        v_maxfk int := greatest(1, coalesce((p_check.params->>'max_fks')::int, 1000)); v_tc text := coalesce(nullif(p_check.params->>'tenant_column', ''), 'tenant_id');
        v_pre text[]; v_ex jsonb := coalesce(p_check.params->'exclude_tables', '[]'::jsonb); v_sql text;
        v_allow jsonb := case jsonb_typeof(p_check.params->'allowed_fks') when 'object' then p_check.params->'allowed_fks'
                              when 'array' then (select coalesce(jsonb_object_agg(x, '사유 없음'::text), '{}'::jsonb) from jsonb_array_elements_text(p_check.params->'allowed_fks') x)
                              else '{}'::jsonb end;
        v_allowed jsonb := '[]'::jsonb;
begin
  if v_tc !~ '^[a-z_][a-z0-9_]{0,62}$' then
    return jsonb_build_object('status', 'error', 'severity', 'low', 'fingerprint', 'config', 'title', '테넌트 칸 이름 설정이 올바르지 않음', 'detail', jsonb_build_object('tenant_column', left(v_tc, 80)));
  end if;
  select coalesce(array_agg(x || '%'), array['%']) into v_pre
    from jsonb_array_elements_text(case when jsonb_typeof(p_check.params->'table_prefixes') = 'array' then p_check.params->'table_prefixes' else '[]'::jsonb end) x;
  for k in
    select c.relname as child, ca.attname as col, pc.relname as parent, pa.attname as pcol
      from pg_constraint con
      join pg_class c on c.oid = con.conrelid and c.relnamespace = 'public'::regnamespace and c.relkind in ('r','p')
      join pg_class pc on pc.oid = con.confrelid and pc.relnamespace = 'public'::regnamespace
      join pg_attribute ca on ca.attrelid = c.oid and ca.attnum = con.conkey[1]
      join pg_attribute pa on pa.attrelid = pc.oid and pa.attnum = con.confkey[1]
     where con.contype = 'f' and array_length(con.conkey, 1) = 1 and ca.attname <> v_tc
       and c.relname like any (v_pre) and c.relname not like 'wpl\_qg\_%' and not (v_ex ? c.relname)
       and exists (select 1 from pg_attribute a where a.attrelid = c.oid and a.attname = v_tc and a.atttypid = 'uuid'::regtype and not a.attisdropped)
       and exists (select 1 from pg_attribute a where a.attrelid = pc.oid and a.attname = v_tc and a.atttypid = 'uuid'::regtype and not a.attisdropped)
     order by 1, 2
     limit v_maxfk
  loop
    v_fks := v_fks + 1;
    v_sql := format('select count(*) from (select x.%I as tid, x.%I as ref from public.%I x where x.%I is not null %s limit %s) c join public.%I p on p.%I = c.ref where p.%I is not null and p.%I is distinct from c.tid',
                    v_tc, k.col, k.child, k.col, case when p_tenant is null then '' else format('and x.%I = %L', v_tc, p_tenant) end, v_sample, k.parent, k.pcol, v_tc, v_tc);
    execute v_sql into v_cnt;
    if v_cnt > 0 and v_allow ? (k.child || '.' || k.col) then
      v_allowed := v_allowed || jsonb_build_array(jsonb_build_object('fk', k.child || '.' || k.col, 'references', k.parent, 'rows', v_cnt, 'reason', v_allow->>(k.child || '.' || k.col)));
    elsif v_cnt > 0 then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', k.child || '.' || k.col,
        'title', format('다른 조직(테넌트) 자료를 가리키는 행 %s건 — 표 %s 의 %s 칸이 표 %s 를 가리킴', v_cnt, k.child, k.col, k.parent),
        'detail', jsonb_build_object('table', k.child, 'column', k.col, 'references', k.parent, 'rows', v_cnt, 'sample_rows', v_sample)));
    end if;
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('foreign_keys', v_fks, 'sample_rows', v_sample, 'allowed_cross', v_allowed,
      'message', format('테넌트 경계를 넘는 참조 0건(외래키 %s개, 키마다 최대 %s행 표본%s).', v_fks, v_sample,
                        case when jsonb_array_length(v_allowed) > 0 then format(' · 허용된 협업 참조 %s개는 제외', jsonb_array_length(v_allowed)) else '' end)));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_integrity_cross_tenant_fk(public.wpl_qg_checks, uuid) from public, anon, authenticated;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('integrity.append_only_guards', 'integrity', '추가 전용 표 수정·삭제 가드',
  '원장·감사·증거 같은 추가 전용 표마다 행 수정·삭제를 막는 가드 트리거가 있고 켜져 있는지 확인합니다. 꺼진 가드 트리거는 목록과 상관없이 모두 잡습니다. 플랫폼 원장 표와 그 가드 함수 이름을 params 에 더하세요.',
  'wpl_qg_probe_integrity_append_only_guards', 'critical', 'platform', 'daily',
  '{"tables":["wpl_qg_runs","wpl_qg_findings","wpl_qg_evidence","wpl_qg_issue_events"],"guard_functions":["wpl_qg_forbid_mutation"]}'::jsonb,
  '가드 없는 추가 전용 표 0개 · 꺼진 가드 0개',
  '① 가드 추가: create trigger <표>_no_mutation before update or delete on public.<표> for each row execute function public.<가드 함수>(); ② 꺼진 가드: alter table public.<표> enable trigger <트리거>; 후 누가 껐는지(DB 로그) 확인해 보고하세요. ③ 새 추가 전용 표를 만들면 이 검사 항목 params.tables 에도 넣으세요.', 10),
 ('integrity.audit_chain', 'integrity', '플랫폼 감사 체인',
  '플랫폼 감사 로그 해시체인 전체를 다시 계산합니다(어댑터 계산, 없는 플랫폼은 건너뜀).',
  'wpl_qg_probe_audit_chain', 'critical', 'platform', 'daily', '{"tail":0}'::jsonb,
  '끊긴 곳 0건',
  '감사 체인 검증 화면에서 끊긴 위치를 확인하고, 그 시각 전후 DB 접근 기록을 살펴 책임자에게 보고하세요.', 20),
 ('integrity.orphans', 'integrity', '고아 행(표본)',
  '외래키 없이 테넌트를 가리키는 표에서 사라진 테넌트를 가리키는 행(params.tenant_table), 외래키 없이 이름으로만 가리키는 칸(params.soft_refs)에서 없는 대상이나 다른 테넌트 대상을 가리키는 행을 표본으로 찾습니다.',
  'wpl_qg_probe_integrity_orphans', 'medium', 'platform', 'daily',
  '{"tenant_table":null,"tenant_column":"tenant_id","table_prefixes":[],"history_tables":[],"soft_refs":[],"sample_rows":50000}'::jsonb,
  '고아 행 0건',
  '① 결과의 표·칸으로 대상 없는 행을 찾으세요: select x.* from <표> x left join <참조표> p on p.id = x.<칸> where x.<칸> is not null and p.id is null; ② 대상을 지운 경로를 찾아 참조도 함께 정리하거나 지우기를 막으세요. ③ 가능하면 그 칸에 외래키를 추가하세요.', 30),
 ('integrity.cross_tenant_fk', 'integrity', '교차 테넌트 참조(외래키 표본)',
  '외래키를 DB 에서 모두 찾아, 참조하는 행과 참조되는 행의 테넌트 칸이 다른 경우가 있는지 키마다 표본으로 확인합니다. 공용 행(테넌트 칸이 비어 있음)은 제외합니다. 테넌트 칸이 없는 플랫폼은 검사할 외래키가 0개로 통과합니다.',
  'wpl_qg_probe_integrity_cross_tenant_fk', 'critical', 'platform', 'daily',
  '{"tenant_column":"tenant_id","table_prefixes":[],"exclude_tables":[],"allowed_fks":{},"sample_rows":20000,"max_fks":1000}'::jsonb,
  '테넌트 경계를 넘는 참조 0건',
  '① 어긋난 행 찾기: select x.* from <표> x join <참조표> p on p.id = x.<칸> where p.tenant_id is distinct from x.tenant_id; ② 그 표에 같은 테넌트 확인 트리거가 있는지 확인하고 없으면 추가하세요. ③ 이미 들어간 행은 해당 테넌트와 확인한 뒤 바로잡으세요. ④ 조직 간 협업이 본질인 참조(수요 조직 ≠ 처리 조직)라면 params.allowed_fks 에 "표.칸": "사유" 로 등록하세요.', 40)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
  schedule = excluded.schedule, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort, engine_code = excluded.engine_code;


-- ══════════ testing ══════════
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
    execute format('create policy %I on public.%I as restrictive for delete to authenticated using (false)', t || '_no_delete', t);
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


-- ══════════ adversarial ══════════
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
create policy wpl_qg_scenarios_no_delete on public.wpl_qg_scenarios as restrictive for delete to authenticated using (false);
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


-- ══════════ review ══════════
-- =====================================================================
-- QG 키트 30 — 다중 AI 독립 검토 엔진(review) (원본: F-MATRIX 2920)
--  · wpl_qg_reviewers         카탈로그: 관점별 검토자(법무·개인정보·보안·UX·사업·소비자), 지시문, 규칙 검사 목록, 거부권
--  · wpl_qg_reviews           검토 요청(대상 종류·대상 id·스냅샷·SHA-256) — 상태는 RPC 로만(가드 트리거)
--  · wpl_qg_review_verdicts   추가 전용: 검토자별 독립 판정(approve/concern/reject)·근거·AI/규칙
--  · wpl_qg_banned_phrases    카탈로그: 금칙어(정규식·block/warn·사유·대안·업종) — 어댑터 wpl_qga_banned_phrases() 결과와 합쳐 쓴다
--  · wpl_qg_required_clauses  카탈로그: 대상 종류별 필수 조항(이름이 본문에 있어야 함)
--  독립성: 서버 액션이 검토자마다 따로 AI 를 부르고(다른 판정을 입력에 넣지 않음) 순서는 DB 가 무작위로 정한다.
--  규칙 바닥선: AI 판정도 DB 가 같은 검토자의 규칙 판정을 함께 계산해 더 엄한 쪽을 남긴다.
--  대상 종류: document(붙여 넣은 글)·release(출시 후보)는 QG 가 해석, 그 밖(copy·ad_material·contract_template·notice)은 어댑터
--  wpl_qga_review_target(kind, ref) 가 {tenant_id,label,text,context,industry,target_id} 로 해석(모르면 붙여 넣기만 가능).
-- =====================================================================

insert into public.wpl_qg_settings(key, value, label, description) values
 ('qg_review_quorum', '3', '품질·거버넌스: 다중 검토 통과에 필요한 승인 수',
  '검토자 중 이 수 이상이 ''승인''하고 아무도 ''거부''하지 않아야 통과입니다. 거부권 검토자가 거부하면 승인 수와 관계없이 차단됩니다.'),
 ('qg_review_max_chars', '30000', '품질·거버넌스: 다중 검토 문서 최대 글자 수', '검토를 요청할 수 있는 문서의 최대 글자 수입니다.'),
 ('qg_review_sentence_max', '180', '품질·거버넌스: UX 검토 — 한 문장 최대 글자 수', 'UX 관점 규칙 검토자가 이보다 긴 문장을 ''읽기 어려움''으로 지적합니다.'),
 ('qg_review_override_note_min_len', '10', '품질·거버넌스: 차단·사람 판단 검토를 통과시킬 때 사유 최소 글자 수',
  '합의 결과가 ''차단''이나 ''사람 판단 필요''인 검토를 사람이 ''통과''로 확정할 때 적어야 하는 사유의 최소 글자 수입니다. 차단을 통과시키는 것은 관리자만, 요청자 본인은 불가입니다.'),
 ('qg_review_stale_days', '3', '품질·거버넌스: 검토 확정 대기 알림(일)', '검토를 요청하고 이 일수가 지나도록 사람이 확정하지 않으면 품질 이슈(주의)로 알립니다.')
on conflict (key) do nothing;

-- ───────── 1) 표 ─────────
create table if not exists public.wpl_qg_banned_phrases (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{1,59}$'),
  pattern text not null check (char_length(pattern) between 1 and 300),
  severity text not null default 'warn' check (severity in ('block','warn')),
  reason text not null check (char_length(reason) between 2 and 300),
  suggestion text,
  industry text,
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_required_clauses (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{1,59}$'),
  target_kind text not null check (target_kind ~ '^[a-z][a-z0-9_]{1,39}$'),
  name text not null check (char_length(name) between 1 and 120),
  law_ref text,
  required boolean not null default true,
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_reviewers (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{1,39}$'),
  name text not null check (char_length(name) between 1 and 60),
  perspective text not null check (char_length(perspective) between 1 and 200),
  instructions text not null check (char_length(instructions) between 10 and 4000),
  rule_checks text[] not null default '{}'
    check (rule_checks <@ array['banned_phrases','unverified_number','required_clauses','pii','secrets','readability','markup']::text[]),
  veto boolean not null default false,
  applies_to text[] not null default array['document','copy','ad_material','contract_template','notice','release']::text[]
    check (cardinality(applies_to) >= 1),
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_reviews (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid,
  target_kind text not null check (target_kind ~ '^[a-z][a-z0-9_]{1,39}$'),
  target_id text check (target_id is null or char_length(target_id) between 1 and 200),
  target_label text not null check (char_length(target_label) between 1 and 300),
  snapshot_text text not null,
  context_text text,
  snapshot_sha256 text not null check (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
  industry_code text,
  use_ai boolean not null default false,
  reviewers text[] not null check (cardinality(reviewers) >= 1),
  status text not null default 'reviewing' check (status in ('reviewing','decided','confirmed')),
  outcome text check (outcome is null or outcome in ('passed','blocked','needs_human')),
  outcome_detail jsonb,
  decided_at timestamptz,
  final_decision text check (final_decision is null or final_decision in ('approved','rejected')),
  final_note text,
  confirmed_by uuid,
  confirmed_at timestamptz,
  evidence_id uuid references public.wpl_qg_evidence(id),
  decision_evidence_id uuid references public.wpl_qg_evidence(id),
  requested_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists wpl_qg_reviews_tenant_idx on public.wpl_qg_reviews(tenant_id, created_at desc);
create index if not exists wpl_qg_reviews_status_idx on public.wpl_qg_reviews(status, created_at desc);
create index if not exists wpl_qg_reviews_target_idx on public.wpl_qg_reviews(target_kind, target_id);

create table if not exists public.wpl_qg_review_verdicts (
  id uuid primary key default gen_random_uuid(),
  review_id uuid not null references public.wpl_qg_reviews(id),
  tenant_id uuid,
  reviewer_code text not null references public.wpl_qg_reviewers(code) on update cascade,
  verdict text not null check (verdict in ('approve','concern','reject')),
  ai_verdict text check (ai_verdict is null or ai_verdict in ('approve','concern','reject')),
  rules_verdict text not null check (rules_verdict in ('approve','concern','reject')),
  reasons jsonb not null default '[]'::jsonb check (jsonb_typeof(reasons) = 'array'),
  summary text,
  mode text not null check (mode in ('ai','rules')),
  model text,
  ai_run_id uuid,
  position int not null default 1,
  created_by uuid,
  created_at timestamptz not null default now(),
  unique (review_id, reviewer_code)
);
create index if not exists wpl_qg_review_verdicts_review_idx on public.wpl_qg_review_verdicts(review_id);

do $$ declare t text; begin
  foreach t in array array['wpl_qg_banned_phrases','wpl_qg_required_clauses','wpl_qg_reviewers'] loop
    execute format('drop trigger if exists %I on public.%I', t || '_touch', t);
    execute format('create trigger %I before update on public.%I for each row execute function public.wpl_qg_touch()', t || '_touch', t);
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists %I on public.%I', t || '_read', t);
    -- v1.1: 검토자 표도 관리자만(지시문=프롬프트가 들어 있음). 구성원 검토 요청은 DEFINER RPC 가 처리한다.
    execute format('create policy %I on public.%I for select to authenticated using (public.wpl_qga_is_admin())', t || '_read', t);
    execute format('drop policy if exists %I on public.%I', t || '_admin_ins', t);
    execute format('create policy %I on public.%I for insert to authenticated with check (public.wpl_qga_is_admin())', t || '_admin_ins', t);
    execute format('drop policy if exists %I on public.%I', t || '_admin_upd', t);
    execute format('create policy %I on public.%I for update to authenticated using (public.wpl_qga_is_admin()) with check (public.wpl_qga_is_admin())', t || '_admin_upd', t);
    execute format('drop policy if exists %I on public.%I', t || '_no_delete', t);
    execute format('create policy %I on public.%I as restrictive for delete to authenticated using (false)', t || '_no_delete', t);
    execute format('revoke all on public.%I from anon', t);
    execute format('revoke delete, truncate on public.%I from authenticated', t);
    execute format('grant select, insert, update on public.%I to authenticated', t);
  end loop;
end $$;

drop trigger if exists wpl_qg_review_verdicts_no_mutation on public.wpl_qg_review_verdicts;
create trigger wpl_qg_review_verdicts_no_mutation before update or delete on public.wpl_qg_review_verdicts for each row execute function public.wpl_qg_forbid_mutation();
drop trigger if exists wpl_qg_review_verdicts_no_truncate on public.wpl_qg_review_verdicts;
create trigger wpl_qg_review_verdicts_no_truncate before truncate on public.wpl_qg_review_verdicts for each statement execute function public.wpl_qg_forbid_mutation();

create or replace function public.wpl_qg_review_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'DELETE' then raise exception '검토 기록은 지울 수 없습니다.'; end if;
  if coalesce(current_setting('wpl.qg_write', true), '') <> 'on' then
    raise exception '검토 상태는 다중 검토 화면의 절차(판정·합의·확정)로만 바꿀 수 있습니다.';
  end if;
  if new.snapshot_text is distinct from old.snapshot_text or new.snapshot_sha256 is distinct from old.snapshot_sha256
     or new.context_text is distinct from old.context_text or new.target_kind is distinct from old.target_kind
     or new.target_id is distinct from old.target_id or new.tenant_id is distinct from old.tenant_id
     or new.reviewers is distinct from old.reviewers or new.requested_by is distinct from old.requested_by
     or new.created_at is distinct from old.created_at then
    raise exception '검토 대상·스냅샷·검토자 목록은 바꿀 수 없습니다(새 검토를 요청해 주세요).';
  end if;
  new.updated_at := now();
  return new;
end $$;
revoke all on function public.wpl_qg_review_guard() from public, anon, authenticated;
drop trigger if exists wpl_qg_reviews_guard on public.wpl_qg_reviews;
create trigger wpl_qg_reviews_guard before update or delete on public.wpl_qg_reviews for each row execute function public.wpl_qg_review_guard();
drop trigger if exists wpl_qg_reviews_no_truncate on public.wpl_qg_reviews;
create trigger wpl_qg_reviews_no_truncate before truncate on public.wpl_qg_reviews for each statement execute function public.wpl_qg_forbid_mutation();

do $$ declare t text; begin
  foreach t in array array['wpl_qg_reviews','wpl_qg_review_verdicts'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists %I on public.%I', t || '_read', t);
    execute format('create policy %I on public.%I for select to authenticated using (public.wpl_qga_is_admin() or (tenant_id is not null and public.wpl_qga_can_read_tenant(tenant_id)))', t || '_read', t);
    execute format('drop policy if exists %I on public.%I', t || '_no_delete', t);
    execute format('create policy %I on public.%I as restrictive for delete to authenticated using (false)', t || '_no_delete', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
  end loop;
end $$;

-- ───────── 2) 규칙 검사(허용 목록) ─────────
-- 결과: [{check, level: reject|concern, code, message}] — 개인정보·비밀값은 원문을 남기지 않고 건수만 남긴다.
create or replace function public.wpl_qg_review_check_internal(p_check text, p_text text, p_context text, p_kind text, p_target text, p_industry text)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare
  t text := coalesce(p_text, ''); v jsonb := '[]'::jsonb; n text; v_norm text; v_cnt int; v_max int; r record; v_n int := 0;
begin
  if p_check = 'banned_phrases' then
    select coalesce(jsonb_agg(jsonb_build_object('check', 'banned_phrases', 'level', case when b.severity = 'block' then 'reject' else 'concern' end,
             'code', 'banned_' || b.severity, 'message', b.reason || coalesce(' — 대안: ' || nullif(b.suggestion, ''), ''))
             order by b.severity, b.reason), '[]'::jsonb)
      into v
      from (select q.pattern, q.severity, q.reason, q.suggestion, q.industry from public.wpl_qg_banned_phrases q where q.active
            union all
            select a.pattern, case when a.severity in ('block','reject') then 'block' else 'warn' end, a.reason, a.suggestion, a.industry
              from public.wpl_qga_banned_phrases() a) b
     where (b.industry is null or b.industry = p_industry)
       and public.wpl_qg_regex_hit_internal(t, b.pattern);

  elsif p_check = 'unverified_number' then
    if coalesce(btrim(p_context), '') = '' then return '[]'::jsonb; end if;
    for n in select distinct m[1] from regexp_matches(t, '([0-9][0-9,.]*[0-9]|[0-9])', 'g') m loop
      if position(replace(n, ',', '') in replace(p_context, ',', '')) = 0 then
        v_n := v_n + 1;
        exit when v_n > 20;
        v := v || jsonb_build_array(jsonb_build_object('check', 'unverified_number', 'level', 'concern', 'code', 'unverified_number',
               'message', '원문·자료에 없는 숫자(' || left(n, 30) || ')입니다. 근거 없는 수치는 쓸 수 없습니다.'));
      end if;
    end loop;

  elsif p_check = 'required_clauses' then
    v_norm := regexp_replace(t, '\s', '', 'g');
    for r in select c.name, c.law_ref, c.required from public.wpl_qg_required_clauses c where c.active and c.target_kind = p_kind order by c.sort, c.code loop
      if position(regexp_replace(r.name, '\s', '', 'g') in v_norm) = 0 then
        v := v || jsonb_build_array(jsonb_build_object('check', 'required_clauses', 'level', case when r.required then 'reject' else 'concern' end, 'code', 'missing_clause',
               'message', '필수 항목 ''' || r.name || '''이(가) 본문에 없습니다' || coalesce('(' || r.law_ref || ')', '') || '.'));
      end if;
    end loop;

  elsif p_check = 'pii' then
    select count(*) into v_cnt from regexp_matches(t, '(^|[^0-9])[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[- ]?[1-8][0-9]{6}([^0-9]|$)', 'g');
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'pii', 'level', 'reject', 'code', 'pii_rrn',
      'message', '주민등록번호로 보이는 값 ' || v_cnt || '건 — 법상 받거나 남기면 안 되는 정보입니다. 지우고 다시 요청하세요.')); end if;
    select count(*) into v_cnt from regexp_matches(t, '(^|[^0-9])[3-6][0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{3,4}([^0-9]|$)', 'g');
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'pii', 'level', 'reject', 'code', 'pii_card',
      'message', '카드번호로 보이는 값 ' || v_cnt || '건 — 결제 정보는 문서에 넣지 마세요.')); end if;
    select count(*) into v_cnt from regexp_matches(t, '(계좌|입금|account)[^0-9]{0,12}[0-9]{2,6}-[0-9]{2,6}-[0-9]{2,8}', 'gi');
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'pii', 'level', 'concern', 'code', 'pii_account',
      'message', '계좌번호로 보이는 값 ' || v_cnt || '건 — 공개 문서라면 지우세요.')); end if;
    select count(*) into v_cnt from regexp_matches(t, '(^|[^0-9])01[016789][- ]?[0-9]{3,4}[- ]?[0-9]{4}([^0-9]|$)', 'g');
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'pii', 'level', 'concern', 'code', 'pii_phone',
      'message', '휴대폰 번호 ' || v_cnt || '건 — 대표 번호가 아니면 지우세요.')); end if;
    select count(*) into v_cnt from regexp_matches(t, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', 'g');
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'pii', 'level', 'concern', 'code', 'pii_email',
      'message', '이메일 주소 ' || v_cnt || '건 — 대표 주소가 아니면 지우세요.')); end if;

  elsif p_check = 'secrets' then
    if t ~ '(sk-[A-Za-z0-9_-]{16,}|sk_live_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.)' then
      v := v || jsonb_build_array(jsonb_build_object('check', 'secrets', 'level', 'reject', 'code', 'secret_key',
             'message', 'API 키·비밀키·토큰으로 보이는 값이 있습니다. 즉시 지우고, 이미 공유했다면 키를 바꾸세요.'));
    end if;
    if t ~* '(password|passwd|비밀번호|비번)\s*[:=]\s*\S{4,}' then
      v := v || jsonb_build_array(jsonb_build_object('check', 'secrets', 'level', 'reject', 'code', 'secret_password',
             'message', '비밀번호로 보이는 값이 있습니다. 문서에 비밀번호를 적지 마세요.'));
    end if;

  elsif p_check = 'markup' then
    if t ~* '(<\s*script|javascript\s*:|<\s*iframe|\son(error|load|click|mouseover)\s*=)' then
      v := v || jsonb_build_array(jsonb_build_object('check', 'markup', 'level', 'reject', 'code', 'script_markup',
             'message', '스크립트·이벤트 속성 같은 실행 코드가 들어 있습니다.'));
    end if;

  elsif p_check = 'readability' then
    if char_length(btrim(t)) = 0 then
      return jsonb_build_array(jsonb_build_object('check', 'readability', 'level', 'reject', 'code', 'empty', 'message', '내용이 비어 있습니다.'));
    end if;
    v_max := greatest(40, coalesce((public.wpl_qg_setting_internal('qg_review_sentence_max', '180'::jsonb) #>> '{}')::int, 180));
    select count(*) into v_cnt from regexp_split_to_table(t, '[.!?。]\s+|\n+') x where char_length(btrim(x)) > v_max;
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'readability', 'level', 'concern', 'code', 'long_sentence',
      'message', v_max || '자보다 긴 문장 ' || v_cnt || '개 — 나눠 쓰면 읽기 쉽습니다.')); end if;
    if t ~ '[ㄱ-ㅎㅏ-ㅣ]{3,}' then v := v || jsonb_build_array(jsonb_build_object('check', 'readability', 'level', 'concern', 'code', 'jamo',
      'message', '자음·모음만 이어진 부분(오타·축약)이 있습니다.')); end if;
  end if;
  return coalesce(v, '[]'::jsonb);
end $$;

-- 정규식 맞춤(잘못된 패턴은 맞지 않음으로 — 카탈로그 오타가 검토를 멈추지 않게)
create or replace function public.wpl_qg_regex_hit_internal(p_text text, p_pattern text) returns boolean
language plpgsql immutable set search_path = public as $$
begin
  return coalesce(p_text, '') ~* p_pattern;
exception when others then return false;
end $$;
revoke all on function public.wpl_qg_regex_hit_internal(text, text) from public, anon, authenticated;
revoke all on function public.wpl_qg_review_check_internal(text, text, text, text, text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_review_worst_internal(a text, b text) returns text
language sql immutable set search_path = public as $$
  select case when 'reject' in (a, b) then 'reject' when 'concern' in (a, b) then 'concern' else 'approve' end
$$;
revoke all on function public.wpl_qg_review_worst_internal(text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_review_rules_internal(p_review public.wpl_qg_reviews, p_reviewer public.wpl_qg_reviewers)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_hits jsonb := '[]'::jsonb; c text; v_rej int; v_con int; v_verdict text;
begin
  foreach c in array coalesce(p_reviewer.rule_checks, '{}'::text[]) loop
    v_hits := v_hits || public.wpl_qg_review_check_internal(c, p_review.snapshot_text, p_review.context_text, p_review.target_kind, p_review.target_id, p_review.industry_code);
  end loop;
  select count(*) filter (where e->>'level' = 'reject'), count(*) filter (where e->>'level' = 'concern') into v_rej, v_con from jsonb_array_elements(v_hits) e;
  v_verdict := case when v_rej > 0 then 'reject' when v_con > 0 then 'concern' else 'approve' end;
  return jsonb_build_object('verdict', v_verdict, 'reasons', v_hits,
    'summary', case when v_rej + v_con = 0 then '규칙 검사(' || coalesce(nullif(array_to_string(p_reviewer.rule_checks, '·'), ''), '-') || ')에서 문제를 찾지 못했습니다.'
                    else '규칙 검사 결과: 거부 사유 ' || v_rej || '건 · 주의 ' || v_con || '건' end);
end $$;
revoke all on function public.wpl_qg_review_rules_internal(public.wpl_qg_reviews, public.wpl_qg_reviewers) from public, anon, authenticated;

-- ───────── 3) 대상 해석 ─────────
create or replace function public.wpl_qg_review_target_internal(p_kind text, p_target text, p_text text, p_title text)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb;
begin
  if p_kind is null or p_kind !~ '^[a-z][a-z0-9_]{1,39}$' then raise exception '검토 대상 종류를 골라 주세요.'; end if;
  if nullif(btrim(coalesce(p_target, '')), '') is null then
    if char_length(btrim(coalesce(p_text, ''))) = 0 then raise exception '검토할 대상을 고르거나 글을 붙여 넣어 주세요.'; end if;
    return jsonb_build_object('tenant_id', null, 'label', coalesce(nullif(left(btrim(p_title), 300), ''), '붙여 넣은 문서'), 'text', p_text, 'context', null, 'industry', null, 'target_id', null);
  end if;
  if p_kind = 'document' then raise exception '붙여 넣은 문서는 대상 id 없이 요청합니다.'; end if;
  if p_kind = 'release' then
    if to_regclass('public.wpl_qg_releases') is null then raise exception '출시 후보 기능이 아직 없습니다. 출시 내용을 붙여 넣어 요청해 주세요.'; end if;
    execute 'select to_jsonb(x) from public.wpl_qg_releases x where x.id::text = $1' into v using p_target;
    if v is null then raise exception '출시 후보를 찾을 수 없습니다.'; end if;
    return jsonb_build_object('tenant_id', v->>'tenant_id', 'label', '출시 후보 #' || coalesce(v->>'rel_no', '?') || ': ' || coalesce(v->>'title', p_target),
      'text', coalesce(nullif(btrim(coalesce(p_text, '')), ''), jsonb_pretty(v - 'verdict')), 'context', null, 'industry', null, 'target_id', p_target);
  end if;
  v := public.wpl_qga_review_target(p_kind, p_target);
  if v is null or jsonb_typeof(v) <> 'object' then
    raise exception '이 플랫폼에서는 ''%'' 대상을 목록에서 고를 수 없습니다. 내용을 붙여 넣어 요청해 주세요.', p_kind;
  end if;
  return jsonb_build_object('tenant_id', v->>'tenant_id', 'label', coalesce(v->>'label', p_kind || ' ' || p_target), 'text', coalesce(v->>'text', ''),
    'context', v->>'context', 'industry', v->>'industry', 'target_id', coalesce(v->>'target_id', p_target));
end $$;
revoke all on function public.wpl_qg_review_target_internal(text, text, text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_review_can_internal(p public.wpl_qg_reviews) returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and (public.wpl_qga_is_admin() or (p.tenant_id is not null and public.wpl_qga_can_read_tenant(p.tenant_id)))
$$;
revoke all on function public.wpl_qg_review_can_internal(public.wpl_qg_reviews) from public, anon, authenticated;

-- 관리자: 화면에서 고를 검토 대상 목록(UUID 손입력 없이) — [{kind, ref, label, tenant_id?, kind_label?}]
--  QG 출시 후보(release) + 선택 어댑터 함수 wpl_qga_review_candidates(p_kind text, p_limit int)
--  returns table(kind text, ref text, label text, tenant_id uuid, kind_label text) 가 있으면 그 결과(계약 v1 필수 함수 아님).
create or replace function public.wpl_qg_review_candidates(p_kind text default null, p_limit int default 200)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb := '[]'::jsonb; v_lim int := least(500, greatest(1, coalesce(p_limit, 200))); v_more jsonb;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '검토 대상 목록은 관리자만 볼 수 있습니다.'; end if;
  if (p_kind is null or p_kind = 'release') and to_regclass('public.wpl_qg_releases') is not null then
    execute 'select coalesce(jsonb_agg(jsonb_build_object(''kind'', ''release'', ''ref'', x.id::text, ''label'', ''#'' || x.rel_no || '' '' || x.title, ''tenant_id'', x.tenant_id)
               order by x.created_at desc), ''[]''::jsonb)
               from (select * from public.wpl_qg_releases where status in (''candidate'',''checking'',''passed'',''blocked'',''approved'') order by created_at desc limit $1) x'
      into v using v_lim;
  end if;
  if to_regprocedure('public.wpl_qga_review_candidates(text,integer)') is not null then
    begin
      execute 'select coalesce(jsonb_agg(jsonb_build_object(''kind'', c.kind, ''ref'', c.ref, ''label'', c.label, ''tenant_id'', c.tenant_id, ''kind_label'', c.kind_label)), ''[]''::jsonb)
                 from public.wpl_qga_review_candidates($1, $2) c where c.kind ~ ''^[a-z][a-z0-9_]{1,39}$'' and c.ref is not null'
        into v_more using p_kind, v_lim;
      v := v || coalesce(v_more, '[]'::jsonb);
    exception when others then
      v := v || jsonb_build_array(jsonb_build_object('kind', '_error', 'ref', '-', 'label', left(sqlerrm, 200)));
    end;
  end if;
  return v;
end $$;
revoke all on function public.wpl_qg_review_candidates(text, int) from public, anon, authenticated;
grant execute on function public.wpl_qg_review_candidates(text, int) to authenticated;

-- ───────── 4) RPC: 요청 → 판정 → 합의 → 사람 확정 ─────────
-- 요청: 관리자는 모든 종류, 테넌트 구성원(can_read_tenant)은 자기 테넌트의 document·copy·ad_material 만.
create or replace function public.wpl_qg_review_request(p_kind text, p_target text default null, p_text text default null, p_title text default null,
  p_tenant uuid default null, p_use_ai boolean default false)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_hq boolean := auth.uid() is not null and public.wpl_qga_is_admin(); t jsonb; v_tenant uuid; v_txt text; v_max int; v_codes text[]; v_id uuid;
begin
  if auth.uid() is null then raise exception '로그인이 필요합니다.'; end if;
  if not v_hq then
    if p_tenant is null or not public.wpl_qga_can_read_tenant(p_tenant) then raise exception '다중 검토를 요청할 권한이 없습니다.'; end if;
    if p_kind not in ('document','copy','ad_material') then raise exception '테넌트에서는 붙여 넣은 문서·문구·광고 자료만 검토를 요청할 수 있습니다.'; end if;
  end if;
  if p_tenant is not null and not public.wpl_qga_tenant_exists(p_tenant) then raise exception '테넌트를 찾을 수 없습니다.'; end if;
  t := public.wpl_qg_review_target_internal(p_kind, p_target, p_text, p_title);
  v_tenant := coalesce(nullif(t->>'tenant_id', '')::uuid, p_tenant);
  if not v_hq and v_tenant is distinct from p_tenant then raise exception '다른 테넌트의 자료는 검토를 요청할 수 없습니다.'; end if;
  v_txt := t->>'text';
  v_max := greatest(1000, coalesce((public.wpl_qg_setting_internal('qg_review_max_chars', '30000'::jsonb) #>> '{}')::int, 30000));
  if char_length(btrim(coalesce(v_txt, ''))) = 0 then raise exception '검토할 내용이 비어 있습니다.'; end if;
  if char_length(v_txt) > v_max then raise exception '문서가 너무 깁니다(최대 %자). 나눠서 요청해 주세요.', to_char(v_max, 'FM999,999,999'); end if;
  select array_agg(r.code order by random()) into v_codes from public.wpl_qg_reviewers r where r.active and p_kind = any(r.applies_to);
  if coalesce(cardinality(v_codes), 0) = 0 then raise exception '이 대상 종류를 검토할 검토자가 없습니다(카탈로그에서 검토자를 켜 주세요).'; end if;

  insert into public.wpl_qg_reviews(tenant_id, target_kind, target_id, target_label, snapshot_text, context_text, snapshot_sha256, industry_code, use_ai, reviewers, requested_by)
  values (v_tenant, p_kind, t->>'target_id', t->>'label', v_txt, nullif(t->>'context', ''), encode(sha256(convert_to(v_txt, 'UTF8')), 'hex'),
          nullif(t->>'industry', ''), coalesce(p_use_ai, false), v_codes, auth.uid())
  returning id into v_id;
  perform public.wpl_qga_audit(v_tenant, 'user', 'qg.review.request', 'wpl_qg_reviews', v_id::text,
    jsonb_build_object('kind', p_kind, 'target', t->>'target_id', 'reviewers', to_jsonb(v_codes), 'use_ai', coalesce(p_use_ai, false)));
  return jsonb_build_object('review_id', v_id, 'kind', p_kind, 'label', t->>'label', 'tenant_id', v_tenant, 'text', v_txt, 'context', t->>'context',
    'reviewers', (select jsonb_agg(jsonb_build_object('code', r.code, 'name', r.name, 'perspective', r.perspective,
                                    'instructions', case when v_hq then r.instructions end, 'veto', r.veto) order by x.ord)
                    from unnest(v_codes) with ordinality x(code, ord) join public.wpl_qg_reviewers r on r.code = x.code));
end $$;
revoke all on function public.wpl_qg_review_request(text, text, text, text, uuid, boolean) from public, anon, authenticated;
grant execute on function public.wpl_qg_review_request(text, text, text, text, uuid, boolean) to authenticated;

-- 판정 1건 기록. p_ai 가 null 이면 규칙 판정. AI 판정은 {verdict, reasons:[{message}], summary, run_id} —
-- run_id 는 이 검토를 대상으로 같은 사람이 방금 남긴 성공한 AI 실행(작업 qg_review)이어야 하고, 규칙 판정보다 느슨해질 수 없다.
create or replace function public.wpl_qg_review_submit(p_review uuid, p_reviewer text, p_ai jsonb default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  rv public.wpl_qg_reviews; rr public.wpl_qg_reviewers; v_rules jsonb; v_ai text; v_final text; v_mode text := 'rules'; v_run uuid; v_model text;
  v_reasons jsonb := '[]'::jsonb; x jsonb; v_pos int; v_summary text; v_done int;
begin
  select * into rv from public.wpl_qg_reviews where id = p_review for update;
  if rv.id is null then raise exception '검토를 찾을 수 없습니다.'; end if;
  if not public.wpl_qg_review_can_internal(rv) then raise exception '이 검토를 다룰 권한이 없습니다.'; end if;
  if rv.status <> 'reviewing' then raise exception '이미 합의가 끝난 검토입니다.'; end if;
  if not (p_reviewer = any(rv.reviewers)) then raise exception '이 검토에 배정되지 않은 검토자입니다.'; end if;
  if exists (select 1 from public.wpl_qg_review_verdicts where review_id = rv.id and reviewer_code = p_reviewer) then raise exception '이 검토자는 이미 판정했습니다.'; end if;
  select * into rr from public.wpl_qg_reviewers where code = p_reviewer;

  v_rules := public.wpl_qg_review_rules_internal(rv, rr);
  v_final := v_rules->>'verdict';
  v_summary := v_rules->>'summary';
  if p_ai is not null and jsonb_typeof(p_ai) = 'object' then
    v_ai := p_ai->>'verdict';
    if v_ai is null or v_ai not in ('approve','concern','reject') then raise exception 'AI 판정 형식이 올바르지 않습니다.'; end if;
    begin v_run := (p_ai->>'run_id')::uuid; exception when others then v_run := null; end;
    select g.model_code into v_model from public.wpl_qga_ai_runs(now() - interval '1 hour') g
     where g.id = v_run and g.task_code = 'qg_review' and g.ref_id = rv.id::text and g.status = 'ok' and g.created_by = auth.uid();
    if v_run is null or v_model is null then
      raise exception 'AI 판정의 실행 기록을 확인할 수 없습니다(규칙 판정으로 다시 요청해 주세요).';
    end if;
    v_mode := 'ai';
    for x in select e from jsonb_array_elements(case when jsonb_typeof(p_ai->'reasons') = 'array' then p_ai->'reasons' else '[]'::jsonb end) e limit 10 loop
      v_reasons := v_reasons || jsonb_build_array(jsonb_build_object('check', 'ai', 'level', case when v_ai = 'approve' then 'note' else v_ai end,
        'code', 'ai', 'message', left(coalesce(case when jsonb_typeof(x) = 'string' then x #>> '{}' else x->>'message' end, ''), 500)));
    end loop;
    v_final := public.wpl_qg_review_worst_internal(v_ai, v_rules->>'verdict');
    v_summary := left(coalesce(nullif(btrim(p_ai->>'summary'), ''), 'AI 판정'), 500)
      || case when v_final <> v_ai then ' · 규칙 바닥선으로 ''' || case v_final when 'reject' then '거부' else '주의' end || '''(으)로 올림' else '' end;
  end if;
  v_reasons := v_reasons || coalesce(v_rules->'reasons', '[]'::jsonb);
  select count(*) + 1 into v_pos from public.wpl_qg_review_verdicts where review_id = rv.id;

  insert into public.wpl_qg_review_verdicts(review_id, tenant_id, reviewer_code, verdict, ai_verdict, rules_verdict, reasons, summary, mode, model, ai_run_id, position, created_by)
  values (rv.id, rv.tenant_id, p_reviewer, v_final, v_ai, v_rules->>'verdict', v_reasons, v_summary, v_mode, coalesce(v_model, case when v_mode = 'rules' then 'rules' end), v_run, v_pos, auth.uid());
  select count(*) into v_done from public.wpl_qg_review_verdicts where review_id = rv.id;
  return jsonb_build_object('ok', true, 'reviewer', p_reviewer, 'verdict', v_final, 'ai_verdict', v_ai, 'rules_verdict', v_rules->>'verdict', 'mode', v_mode,
    'done', v_done, 'total', cardinality(rv.reviewers));
end $$;
revoke all on function public.wpl_qg_review_submit(uuid, text, jsonb) from public, anon, authenticated;
grant execute on function public.wpl_qg_review_submit(uuid, text, jsonb) to authenticated;

-- 합의: 거부권 검토자 거부 → blocked · 승인 ≥ 정족수이고 거부 0 → passed · 그 밖 → needs_human
create or replace function public.wpl_qg_review_finalize(p_review uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  rv public.wpl_qg_reviews; v_quorum int; v_app int; v_con int; v_rej int; v_veto text[]; v_missing text[]; v_outcome text; v_detail jsonb; v_ev uuid;
begin
  select * into rv from public.wpl_qg_reviews where id = p_review for update;
  if rv.id is null then raise exception '검토를 찾을 수 없습니다.'; end if;
  if not public.wpl_qg_review_can_internal(rv) then raise exception '이 검토를 다룰 권한이 없습니다.'; end if;
  if rv.status <> 'reviewing' then raise exception '이미 합의가 끝난 검토입니다.'; end if;
  if not exists (select 1 from public.wpl_qg_review_verdicts where review_id = rv.id) then raise exception '아직 판정이 하나도 없습니다.'; end if;
  v_quorum := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_review_quorum', '3'::jsonb) #>> '{}')::int, 3));
  select count(*) filter (where v.verdict = 'approve'), count(*) filter (where v.verdict = 'concern'), count(*) filter (where v.verdict = 'reject'),
         coalesce(array_agg(v.reviewer_code) filter (where v.verdict = 'reject' and r.veto), '{}')
    into v_app, v_con, v_rej, v_veto
    from public.wpl_qg_review_verdicts v join public.wpl_qg_reviewers r on r.code = v.reviewer_code where v.review_id = rv.id;
  select coalesce(array_agg(c), '{}') into v_missing from unnest(rv.reviewers) c
   where not exists (select 1 from public.wpl_qg_review_verdicts v where v.review_id = rv.id and v.reviewer_code = c);
  v_outcome := case when cardinality(v_veto) > 0 then 'blocked' when v_rej = 0 and v_app >= v_quorum then 'passed' else 'needs_human' end;
  v_detail := jsonb_build_object('quorum', v_quorum, 'approve', v_app, 'concern', v_con, 'reject', v_rej, 'veto_rejects', to_jsonb(v_veto),
    'missing', to_jsonb(v_missing), 'total', cardinality(rv.reviewers),
    'reason', case v_outcome when 'blocked' then '거부권 검토자(' || array_to_string(v_veto, ', ') || ')가 거부했습니다.'
                             when 'passed' then '승인 ' || v_app || '명(정족수 ' || v_quorum || ') · 거부 0명.'
                             else case when v_rej > 0 then '거부 ' || v_rej || '명이 있어 사람이 판단해야 합니다.'
                                       else '승인 ' || v_app || '명으로 정족수(' || v_quorum || ')에 못 미칩니다.' end end);
  v_ev := public.wpl_qg_evidence_append('review', 'review:' || rv.id::text,
    jsonb_build_object('review_id', rv.id, 'kind', rv.target_kind, 'target_id', rv.target_id, 'label', rv.target_label, 'tenant_id', rv.tenant_id,
      'snapshot_sha256', rv.snapshot_sha256, 'reviewers', to_jsonb(rv.reviewers), 'outcome', v_outcome, 'detail', v_detail,
      'verdicts', (select jsonb_agg(jsonb_build_object('reviewer', v.reviewer_code, 'verdict', v.verdict, 'ai_verdict', v.ai_verdict, 'rules_verdict', v.rules_verdict,
                     'mode', v.mode, 'model', v.model, 'ai_run_id', v.ai_run_id, 'position', v.position, 'summary', v.summary, 'reasons', v.reasons) order by v.position)
                     from public.wpl_qg_review_verdicts v where v.review_id = rv.id),
      'finalized_by', auth.uid(), 'finalized_by_label', public.wpl_qg_actor_label_internal()),
    '다중 검토 합의: ' || left(rv.target_label, 200), rv.tenant_id, null);
  perform set_config('wpl.qg_write', 'on', true);
  update public.wpl_qg_reviews set status = 'decided', outcome = v_outcome, outcome_detail = v_detail, decided_at = now(), evidence_id = v_ev where id = rv.id;
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(rv.tenant_id, 'user', 'qg.review.finalize', 'wpl_qg_reviews', rv.id::text, jsonb_build_object('outcome', v_outcome, 'detail', v_detail, 'evidence_id', v_ev));
  return jsonb_build_object('ok', true, 'outcome', v_outcome, 'detail', v_detail, 'evidence_id', v_ev);
end $$;
revoke all on function public.wpl_qg_review_finalize(uuid) from public, anon, authenticated;
grant execute on function public.wpl_qg_review_finalize(uuid) to authenticated;

-- 사람 최종 확정. '차단'을 통과시키는 것은 관리자만·요청자 본인 불가·사유 필수. '사람 판단 필요'를 통과시킬 때도 사유 필수.
create or replace function public.wpl_qg_review_confirm(p_review uuid, p_decision text, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare rv public.wpl_qg_reviews; v_note text := nullif(btrim(coalesce(p_note, '')), ''); v_min int; v_ev uuid;
begin
  select * into rv from public.wpl_qg_reviews where id = p_review for update;
  if rv.id is null then raise exception '검토를 찾을 수 없습니다.'; end if;
  if not public.wpl_qg_review_can_internal(rv) then raise exception '이 검토를 다룰 권한이 없습니다.'; end if;
  if rv.status = 'reviewing' then raise exception '먼저 검토자 판정을 모아 합의를 내야 합니다.'; end if;
  if rv.status = 'confirmed' then raise exception '이미 확정된 검토입니다.'; end if;
  if p_decision is null or p_decision not in ('approved','rejected') then raise exception '통과 또는 반려를 골라 주세요.'; end if;
  if v_note is not null and char_length(v_note) > 2000 then raise exception '메모는 2,000자 이하로 적어 주세요.'; end if;
  v_min := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_review_override_note_min_len', '10'::jsonb) #>> '{}')::int, 10));
  if p_decision = 'approved' and rv.outcome <> 'passed' then
    if char_length(coalesce(v_note, '')) < v_min then
      raise exception '합의 결과가 ''%''인 검토를 통과시키려면 사유를 %자 이상 적어 주세요.', case rv.outcome when 'blocked' then '차단' else '사람 판단 필요' end, v_min;
    end if;
    if rv.outcome = 'blocked' then
      if not public.wpl_qga_is_admin() then raise exception '차단된 검토는 관리자만 통과시킬 수 있습니다.'; end if;
      if not public.wpl_qg_self_approval_ok_internal(rv.requested_by) then
        raise exception '자기가 요청한 검토의 차단은 스스로 풀 수 없습니다. 다른 관리자에게 맡겨 주세요.';
      end if;
    end if;
  end if;
  v_ev := public.wpl_qg_evidence_append('review_decision', 'review:' || rv.id::text,
    jsonb_build_object('review_id', rv.id, 'snapshot_sha256', rv.snapshot_sha256, 'outcome', rv.outcome, 'decision', p_decision, 'note', v_note,
      'override', p_decision = 'approved' and rv.outcome <> 'passed', 'requested_by', rv.requested_by, 'decided_by', auth.uid(),
      'decided_by_label', public.wpl_qg_actor_label_internal(), 'consensus_evidence_id', rv.evidence_id),
    '다중 검토 확정(' || case p_decision when 'approved' then '통과' else '반려' end || '): ' || left(rv.target_label, 200), rv.tenant_id, null);
  perform set_config('wpl.qg_write', 'on', true);
  update public.wpl_qg_reviews set status = 'confirmed', final_decision = p_decision, final_note = v_note, confirmed_by = auth.uid(), confirmed_at = now(),
         decision_evidence_id = v_ev where id = rv.id;
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(rv.tenant_id, 'user', 'qg.review.confirm', 'wpl_qg_reviews', rv.id::text,
    jsonb_build_object('decision', p_decision, 'outcome', rv.outcome, 'note', v_note, 'evidence_id', v_ev));
  return jsonb_build_object('ok', true, 'decision', p_decision, 'evidence_id', v_ev);
end $$;
revoke all on function public.wpl_qg_review_confirm(uuid, text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_review_confirm(uuid, text, text) to authenticated;

-- 출시 관문이 읽는 검토 결과(대상 종류 'qg_release' → 출시 후보 id): 사람 확정 approved = passed, rejected = blocked, 그 밖 = pending
create or replace function public.wpl_qg_review_outcome_internal(p_target_kind text, p_target_ref text)
returns jsonb language sql stable security definer set search_path = public as $$
  select coalesce((select jsonb_build_object('result', case when x.final_decision = 'approved' then 'passed' when x.final_decision = 'rejected' then 'blocked' else 'pending' end,
                                             'review_id', x.id, 'outcome', x.outcome, 'status', x.status, 'at', x.created_at)
                     from public.wpl_qg_reviews x
                    where x.target_kind = case when p_target_kind = 'qg_release' then 'release' else p_target_kind end and x.target_id = p_target_ref
                    order by x.created_at desc limit 1),
                  jsonb_build_object('result', 'none'))
$$;
revoke all on function public.wpl_qg_review_outcome_internal(text, text) from public, anon, authenticated;

-- ───────── 5) probe ─────────
create or replace function public.wpl_qg_probe_review_stale(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_days int := greatest(1, coalesce((p_check.params->>'days')::int, (public.wpl_qg_setting_internal('qg_review_stale_days', '3'::jsonb) #>> '{}')::int, 3));
        v_n int; v_list jsonb;
begin
  select count(*), coalesce(jsonb_agg(jsonb_build_object('id', x.id, 'label', x.target_label, 'status', x.status, 'outcome', x.outcome, 'created_at', x.created_at)) filter (where x.rn <= 20), '[]'::jsonb)
    into v_n, v_list
    from (select r.*, row_number() over (order by r.created_at) rn from public.wpl_qg_reviews r
           where r.status in ('reviewing','decided') and r.created_at < now() - make_interval(days => v_days)
             and (p_tenant is null or r.tenant_id = p_tenant)) x;
  if v_n = 0 then return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('days', v_days, 'message', '오래 걸리는 검토가 없습니다.')); end if;
  return jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', 'review_stale', 'title', v_days || '일 넘게 확정되지 않은 다중 검토 ' || v_n || '건',
    'detail', jsonb_build_object('days', v_days, 'count', v_n, 'reviews', v_list));
end $$;
revoke all on function public.wpl_qg_probe_review_stale(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_review_catalog(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_quorum int := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_review_quorum', '3'::jsonb) #>> '{}')::int, 3)); v_out jsonb := '[]'::jsonb; k text; v_n int; v_veto int;
        v_kinds text[];
begin
  select coalesce(array_agg(distinct k2 order by k2), array['document']) into v_kinds from public.wpl_qg_reviewers r, unnest(r.applies_to) k2 where r.active;
  foreach k in array v_kinds loop
    select count(*), count(*) filter (where veto) into v_n, v_veto from public.wpl_qg_reviewers where active and k = any(applies_to);
    if v_n < v_quorum then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', 'quorum_unreachable:' || k,
        'title', '다중 검토 정족수를 채울 수 없음(' || k || ')', 'detail', jsonb_build_object('kind', k, 'reviewers', v_n, 'quorum', v_quorum)));
    end if;
    if v_veto = 0 then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', 'no_veto:' || k,
        'title', '거부권 검토자가 없음(' || k || ')', 'detail', jsonb_build_object('kind', k, 'reviewers', v_n)));
    end if;
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('quorum', v_quorum, 'kinds', to_jsonb(v_kinds), 'message', '모든 대상 종류에서 정족수를 채울 수 있고 거부권 검토자가 있습니다.'));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_review_catalog(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ───────── 6) 시드 ─────────
insert into public.wpl_qg_reviewers(code, name, perspective, instructions, rule_checks, veto, sort) values
 ('legal', '법무 검토자', '표시광고법·전자상거래법·개인정보보호법·업종 법령 위반 위험',
  '너는 한국 법무 검토자다. 문서가 표시광고법(과장·단정·보장·검증 안 된 수치), 전자상거래법(청약철회·사업자 정보·중개자 고지), 개인정보보호법, 이 플랫폼 업종 법령에 어긋나는지 본다. 위반이 분명하면 reject, 애매하면 concern, 문제가 없으면 approve. 법률 자문이 아니라 위험 신호를 짚는 것이다.',
  array['banned_phrases','required_clauses'], true, 10),
 ('privacy', '개인정보 검토자', '개인정보보호법 — 주민등록번호·카드번호·계좌·연락처 노출',
  '너는 개인정보 보호 검토자다. 문서에 주민등록번호·카드번호·계좌번호·개인 연락처·이메일 같은 개인정보가 노출되는지, 수집·이용 목적 없이 개인정보를 요구하는지 본다. 주민등록번호·카드번호가 있으면 반드시 reject. 개인 연락처는 concern.',
  array['pii'], true, 20),
 ('security', '보안 검토자', 'API 키·비밀번호·토큰·실행 코드 노출',
  '너는 보안 검토자다. 문서에 API 키·비밀키·비밀번호·토큰·스크립트 같은 실행 코드가 들어 있는지, 권한 우회·내부 주소 노출이 있는지 본다. 비밀값이나 실행 코드가 있으면 reject.',
  array['secrets','markup'], false, 30),
 ('ux', 'UX 검토자', '처음 보는 사람이 3분 안에 이해하는지(문장 길이·용어·오타)',
  '너는 UX 라이터다. 처음 보는 사람이 바로 이해할 수 있는지(문장이 너무 길지 않은지, 전문 용어·영어 약어를 풀어 썼는지, 오타가 없는지, 다음에 무엇을 하면 되는지) 본다. 읽기 어려우면 concern, 내용이 비었으면 reject.',
  array['readability'], false, 40),
 ('business', '사업 검토자', '근거 없는 수치·실적 주장·과장 약속으로 인한 사업 위험',
  '너는 사업 검토자다. 원문·자료에 없는 숫자(매출·수익·고객 수·만족도), 근거 없는 실적·인증·수상 주장, 지킬 수 없는 약속이 있는지 본다. 근거 없는 수치나 과장이 있으면 concern, 수익 보장처럼 사업을 위태롭게 하면 reject.',
  array['unverified_number','banned_phrases'], false, 50),
 ('consumer', '소비자 보호 검토자', '소비자가 오해하거나 압박받는 표현(긴박감·단정·환불 제한)',
  '너는 소비자 보호 검토자다. 소비자를 오해하게 하거나 압박하는 표현(오늘만·마감 임박·무조건·부작용 없음·환불 불가), 중요한 조건(가격·환불·위약금)을 숨기는지 본다. 금칙어에 해당하면 reject, 오해 소지가 있으면 concern.',
  array['banned_phrases'], false, 60)
on conflict (code) do update set name = excluded.name, perspective = excluded.perspective, instructions = excluded.instructions,
  rule_checks = excluded.rule_checks, veto = excluded.veto, sort = excluded.sort;

-- 금칙어(표시광고법·유사수신 공통 — 업종별은 설치 뒤 더한다)
insert into public.wpl_qg_banned_phrases(code, pattern, severity, reason, suggestion, sort) values
 ('guarantee_profit', '(수익|매출|원금|이자)[^.\n]{0,12}보장', 'block', '수익·원금 보장 표현(표시광고법·유사수신행위법 위험)', '예상치는 근거와 함께 범위로, 보장 표현은 빼세요', 10),
 ('guarantee_100', '100\s*%\s*(보장|환불|성공|효과)', 'block', '100% 보장·성공 단정(표시광고법)', '조건과 예외를 함께 적으세요', 20),
 ('no_side_effect', '부작용\s*(이|은)?\s*(전혀\s*)?없', 'block', '부작용 없음 단정(표시광고법·업종 광고 규제)', '개인차가 있음을 알리세요', 30),
 ('superlative', '(업계|국내|세계)?\s*(최고|최상|1\s*위|넘버\s*원|No\.?\s*1)', 'warn', '최상급·순위 표현은 객관적 근거가 있어야 합니다(표시광고법)', '근거(출처·기간)를 함께 적거나 빼세요', 40),
 ('first_only', '(최초|유일|독보적)', 'warn', '최초·유일 표현은 근거가 있어야 합니다(표시광고법)', '근거를 함께 적거나 빼세요', 50),
 ('absolute', '(무조건|절대|반드시\s*(성공|효과))', 'warn', '단정 표현(표시광고법)', '조건을 함께 적으세요', 60),
 ('urgency', '(오늘\s*만|마감\s*임박|단\s*하루|지금\s*안\s*하면)', 'warn', '소비자를 압박하는 긴박감 표현', '기간을 사실대로 적으세요', 70),
 ('no_refund', '(환불\s*(불가|안\s*됨)|청약\s*철회\s*불가)', 'block', '청약철회 제한 표시(전자상거래법 — 법정 예외 외 불가)', '청약철회 기간·예외를 정확히 적으세요', 80)
on conflict (code) do nothing;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('review.stale_pending', 'review', '오래 확정되지 않은 다중 검토',
  '검토를 요청하고 정해진 일수(qg_review_stale_days)가 지나도록 사람이 통과·반려를 확정하지 않은 검토를 찾습니다.',
  'wpl_qg_probe_review_stale', 'medium', 'platform', 'daily', '{}'::jsonb,
  '확정 대기 0건',
  '품질·거버넌스 → 다중 AI 독립 검토에서 해당 검토를 열어 검토자 판정과 합의 결과를 보고 통과 또는 반려로 확정하세요.', 10),
 ('review.catalog_quorum', 'review', '검토자 카탈로그 합의 가능성',
  '대상 종류마다 켜진 검토자 수가 정족수(qg_review_quorum) 이상인지, 거부권 검토자가 1명 이상인지 확인합니다.',
  'wpl_qg_probe_review_catalog', 'high', 'platform', 'daily', '{}'::jsonb,
  '모든 종류에서 정족수 충족 · 거부권 검토자 있음',
  '검토자 카탈로그(wpl_qg_reviewers)에서 검토자를 켜거나 적용 대상을 넓히고, 정족수 설정을 확인하세요.', 20)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
  schedule = excluded.schedule, params = excluded.params, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort;


-- ══════════ compliance ══════════
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
    execute format('create policy %I on public.%I as restrictive for delete to authenticated using (false)', t || '_no_delete', t);
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
create policy wpl_qg_regulation_changes_no_delete on public.wpl_qg_regulation_changes as restrictive for delete to authenticated using (false);
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


-- ══════════ ai_model ══════════
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
    execute format('create policy %I on public.%I as restrictive for delete to authenticated using (false)', t || '_no_delete', t);
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
    execute format('create policy %I on public.%I as restrictive for delete to authenticated using (false)', t || '_no_delete', t);
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


-- ══════════ release ══════════
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
create policy wpl_qg_gate_policies_no_delete on public.wpl_qg_gate_policies as restrictive for delete to authenticated using (false);
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
    execute format('create policy %I on public.%I as restrictive for delete to authenticated using (false)', t || '_no_delete', t);
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

-- =====================================================================
-- v1.2 — 서버 코드용 출시 관문(공개·승인·발행을 DB 함수가 아니라 TS 서버 액션·라우트가 service_role 로 하는 플랫폼)
--  TS 헬퍼(lib/qg/release-gate.ts)가 두 단계로 부른다(iagwe 7317 의 require → 성공 뒤 released 기록 패턴을 서버 코드로 옮김):
--   ① 바꾸기 전: wpl_qg_release_gate_check_server(kind, ref, …)  — 강제 꺼짐(기본) → 항상 허용 + '관찰 기록'만. 켜짐 → 승인 후보 없으면 allowed=false(사람 말 message)
--   ② 실제로 성공한 뒤: wpl_qg_release_mark_server(kind, ref, …) — 승인 후보가 있으면 출시 완료로 연결(없으면 관찰 기록만). 절대 예외를 내지 않는다(이미 바뀐 뒤라서).
--  서버 전용: 실행 권한은 service_role 에만. 함수 안에서도 service_role 이거나 서버 증명키가 맞을 때만 받는다(pg 직접 연결·자체 로그인 역할 플랫폼 = 서버 증명키).
--  관찰 기록 wpl_qg_release_observations(추가 전용): 강제 스위치를 켜기 전에 '켰다면 막혔을 출시(would_block)'가 몇 건인지 화면에서 본다.
--  대상 확인은 기존과 같다: 관문 정책(wpl_qg_gate_policies)의 kind + 어댑터 wpl_qga_release_target(kind, ref) 가 정한 ref(후보와 같은 값).
--  두 번 적용해도 같은 결과(v1.1 DB 위 업그레이드 포함).
-- =====================================================================
create table if not exists public.wpl_qg_release_observations (
  id bigint generated always as identity primary key,
  phase text not null check (phase in ('check','released')),
  kind text not null check (char_length(kind) between 1 and 60),
  target_ref text not null check (char_length(target_ref) between 1 and 200),
  target_label text check (target_label is null or char_length(target_label) <= 200),
  tenant_id uuid,
  enforced boolean not null default false,
  allowed boolean not null default true,
  would_block boolean not null default false,
  reason text check (reason is null or char_length(reason) <= 300),
  release_id uuid references public.wpl_qg_releases(id),
  via text not null check (via in ('service_role','server_key')),
  detail jsonb,
  created_at timestamptz not null default now()
);
create index if not exists wpl_qg_release_observations_kind_idx on public.wpl_qg_release_observations(kind, target_ref, id desc);
create index if not exists wpl_qg_release_observations_at_idx on public.wpl_qg_release_observations(created_at desc);
drop trigger if exists wpl_qg_release_observations_no_mutation on public.wpl_qg_release_observations;
create trigger wpl_qg_release_observations_no_mutation before update or delete on public.wpl_qg_release_observations for each row execute function public.wpl_qg_forbid_mutation();
drop trigger if exists wpl_qg_release_observations_no_truncate on public.wpl_qg_release_observations;
create trigger wpl_qg_release_observations_no_truncate before truncate on public.wpl_qg_release_observations for each statement execute function public.wpl_qg_forbid_mutation();
alter table public.wpl_qg_release_observations enable row level security;
drop policy if exists wpl_qg_release_observations_read on public.wpl_qg_release_observations;
create policy wpl_qg_release_observations_read on public.wpl_qg_release_observations for select to authenticated using (public.wpl_qga_is_admin());
drop policy if exists wpl_qg_release_observations_no_delete on public.wpl_qg_release_observations;
create policy wpl_qg_release_observations_no_delete on public.wpl_qg_release_observations as restrictive for delete to authenticated using (false);
revoke all on public.wpl_qg_release_observations from anon, authenticated;
grant select on public.wpl_qg_release_observations to authenticated;

-- 부른 쪽 확인: 'service_role'(Supabase 서비스 키 요청) · 'server_key'(서버 증명키) · null(거부)
create or replace function public.wpl_qg_server_caller_internal(p_server_key text) returns text
language plpgsql stable security definer set search_path = public as $$
declare v_claims text := nullif(current_setting('request.jwt.claims', true), ''); v_role text;
begin
  begin v_role := v_claims::jsonb->>'role'; exception when others then v_role := null; end;
  if coalesce(v_role, nullif(current_setting('request.jwt.claim.role', true), ''), '') = 'service_role' or coalesce(current_setting('role', true), '') = 'service_role' then
    return 'service_role';
  end if;
  if p_server_key is not null and coalesce(public.wpl_qga_server_key_ok(p_server_key), false) then return 'server_key'; end if;
  return null;
end $$;
revoke all on function public.wpl_qg_server_caller_internal(text) from public, anon, authenticated;

-- 관찰 기록 한 줄(실패해도 부른 쪽을 막지 않도록 호출부가 감싼다)
create or replace function public.wpl_qg_release_observe_internal(p_phase text, p_kind text, p_ref text, p_label text, p_tenant uuid, p_enforced boolean,
  p_allowed boolean, p_would boolean, p_reason text, p_release uuid, p_via text, p_detail jsonb)
returns bigint language sql security definer set search_path = public as $$
  insert into public.wpl_qg_release_observations(phase, kind, target_ref, target_label, tenant_id, enforced, allowed, would_block, reason, release_id, via, detail)
  values (p_phase, left(p_kind, 60), left(p_ref, 200), left(p_label, 200), p_tenant, coalesce(p_enforced, false), coalesce(p_allowed, true), coalesce(p_would, false),
          left(p_reason, 300), p_release, p_via, p_detail)
  returning id
$$;
revoke all on function public.wpl_qg_release_observe_internal(text, text, text, text, uuid, boolean, boolean, boolean, text, uuid, text, jsonb) from public, anon, authenticated;

-- 대상 정규화: 어댑터·QG 대상 확인이 되면 그 ref·이름·테넌트, 안 되면 받은 값 그대로(강제 꺼짐에서 절대 막지 않기 위해 예외를 삼킨다)
create or replace function public.wpl_qg_release_server_target_internal(p_kind text, p_ref text, p_tenant uuid, p_label text)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare t jsonb; v_ref text := left(coalesce(nullif(trim(coalesce(p_ref, '')), ''), '-'), 200);
        v_label text := nullif(left(trim(coalesce(p_label, '')), 200), '');
begin
  begin
    t := public.wpl_qg_release_target_internal(p_kind, v_ref);
  exception when others then
    return jsonb_build_object('ref', v_ref, 'label', v_label, 'tenant_id', p_tenant, 'resolved', false, 'resolve_error', left(sqlerrm, 200));
  end;
  return jsonb_build_object('ref', coalesce(nullif(t->>'ref', ''), v_ref), 'label', coalesce(v_label, t->>'label'),
    'tenant_id', coalesce(p_tenant, nullif(t->>'tenant_id', '')::uuid), 'resolved', true);
end $$;
revoke all on function public.wpl_qg_release_server_target_internal(text, text, uuid, text) from public, anon, authenticated;

-- ① 바꾸기 전 확인(서버 전용) → {ok, allowed, enforced, would_block, reason, release_id, rel_no, observation_id, message, kind_label, target_ref}
--   reason: approved(승인 후보 있음) · no_approved(정책은 있는데 승인 후보 없음) · expired(승인 만료) · no_policy(관문 정책 없는 종류)
create or replace function public.wpl_qg_release_gate_check_server(p_kind text, p_ref text, p_server_key text default null, p_tenant uuid default null, p_label text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_via text := public.wpl_qg_server_caller_internal(p_server_key);
  v_kind text := left(coalesce(nullif(trim(coalesce(p_kind, '')), ''), '-'), 60);
  t jsonb; v_ref text; v_enforce boolean := false; r public.wpl_qg_releases; v_reason text; v_allowed boolean; v_would boolean; v_obs bigint; v_msg text; v_tenant uuid;
begin
  if v_via is null then raise exception '출시 관문 서버 확인은 서버(service_role 또는 서버 증명키)만 부를 수 있습니다.'; end if;
  begin
    v_enforce := coalesce((public.wpl_qg_setting_internal('qg_enforce_' || v_kind, 'false'::jsonb) #>> '{}')::boolean, false);
  exception when others then v_enforce := false;
  end;
  t := public.wpl_qg_release_server_target_internal(v_kind, p_ref, p_tenant, p_label);
  v_ref := t->>'ref'; v_tenant := nullif(t->>'tenant_id', '')::uuid;
  select * into r from public.wpl_qg_releases where kind = v_kind and target_ref = v_ref and status = 'approved' order by approved_at desc limit 1;
  if r.id is null then
    v_reason := case when exists (select 1 from public.wpl_qg_gate_policies where kind = v_kind and active) then 'no_approved' else 'no_policy' end;
  elsif not public.wpl_qg_release_approval_fresh_internal(r) then v_reason := 'expired';
  else v_reason := 'approved';
  end if;
  v_would := v_reason <> 'approved';
  v_allowed := not v_enforce or not v_would;
  if not v_allowed then
    v_msg := case when v_reason = 'expired'
                  then format('출시 후보 #%s의 승인이 만료되었습니다(승인 유효 시간 초과). 출시 승인·차단에서 다시 판정·승인해 주세요.', r.rel_no)
                  else public.wpl_qg_release_denied_msg_internal(v_kind) end;
  end if;
  begin
    v_obs := public.wpl_qg_release_observe_internal('check', v_kind, v_ref, t->>'label', v_tenant, v_enforce, v_allowed, v_would, v_reason, r.id, v_via,
      jsonb_strip_nulls(jsonb_build_object('resolved', t->'resolved', 'rel_no', r.rel_no)));
    if not v_allowed then
      perform public.wpl_qga_audit(v_tenant, 'system', 'qg.release.server_denied', 'wpl_qg_release_observations', v_obs::text,
        jsonb_build_object('kind', v_kind, 'target_ref', v_ref, 'reason', v_reason));
    end if;
  exception when others then
    if v_enforce then raise; end if;   -- 강제 꺼짐이면 기록 실패로 원래 흐름을 막지 않는다
    v_obs := null;
  end;
  return jsonb_build_object('ok', true, 'allowed', v_allowed, 'enforced', v_enforce, 'would_block', v_would, 'reason', v_reason,
    'release_id', r.id, 'rel_no', r.rel_no, 'observation_id', v_obs, 'message', v_msg, 'kind_label', public.wpl_qg_release_kind_ko_internal(v_kind), 'target_ref', v_ref);
end $$;
revoke all on function public.wpl_qg_release_gate_check_server(text, text, text, uuid, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_release_gate_check_server(text, text, text, uuid, text) to service_role;

-- ② 실제로 성공한 뒤(서버 전용): 승인 후보 → 출시 완료로 연결(없으면 관찰 기록만). 예외를 내지 않는다(부른 쪽 권한 오류만 예외).
--   code_deploy 는 연결하지 않는다(배포 READY·SHA 일치 기록 wpl_qg_release_record_deploy 로만 출시 완료).
create or replace function public.wpl_qg_release_mark_server(p_kind text, p_ref text, p_server_key text default null, p_tenant uuid default null, p_label text default null, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_via text := public.wpl_qg_server_caller_internal(p_server_key);
  v_kind text := left(coalesce(nullif(trim(coalesce(p_kind, '')), ''), '-'), 60);
  t jsonb; v_ref text; v_tenant uuid; v_enforce boolean := false; v_rel uuid; v_no bigint; v_err text; v_obs bigint; v_reason text;
begin
  if v_via is null then raise exception '출시 완료 서버 기록은 서버(service_role 또는 서버 증명키)만 부를 수 있습니다.'; end if;
  begin
    v_enforce := coalesce((public.wpl_qg_setting_internal('qg_enforce_' || v_kind, 'false'::jsonb) #>> '{}')::boolean, false);
  exception when others then v_enforce := false;
  end;
  t := public.wpl_qg_release_server_target_internal(v_kind, p_ref, p_tenant, p_label);
  v_ref := t->>'ref'; v_tenant := nullif(t->>'tenant_id', '')::uuid;
  if v_kind = 'code_deploy' then
    v_reason := 'code_deploy_use_record_deploy';
  else
    begin
      v_rel := public.wpl_qg_release_consume_internal(v_kind, v_ref, false);
    exception when others then v_rel := null; v_err := left(sqlerrm, 300);
    end;
    v_reason := case when v_rel is not null then 'linked' when v_err is not null then 'link_error' else 'no_approved' end;
  end if;
  if v_rel is not null then select rel_no into v_no from public.wpl_qg_releases where id = v_rel; end if;
  begin
    v_obs := public.wpl_qg_release_observe_internal('released', v_kind, v_ref, t->>'label', v_tenant, v_enforce, true, v_rel is null and v_kind <> 'code_deploy', v_reason, v_rel, v_via,
      jsonb_strip_nulls(jsonb_build_object('note', left(nullif(trim(coalesce(p_note, '')), ''), 500), 'error', v_err, 'rel_no', v_no)));
    if v_rel is not null then
      perform public.wpl_qga_audit(v_tenant, 'system', 'qg.release.server_released', 'wpl_qg_releases', v_rel::text,
        jsonb_build_object('kind', v_kind, 'target_ref', v_ref, 'via', v_via, 'observation_id', v_obs));
    end if;
  exception when others then v_obs := null;
  end;
  return jsonb_build_object('ok', true, 'linked', v_rel is not null, 'release_id', v_rel, 'rel_no', v_no, 'enforced', v_enforce, 'reason', v_reason, 'observation_id', v_obs, 'target_ref', v_ref);
end $$;
revoke all on function public.wpl_qg_release_mark_server(text, text, text, uuid, text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_release_mark_server(text, text, text, uuid, text, text) to service_role;


-- ══════════ evolution ══════════
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
    execute format('create policy %I on public.%I as restrictive for delete to authenticated using (false)', t || '_no_delete', t);
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
