-- QG 키트 1.1.0 · 접두어 wpl · adapter (adapter-wpl.sql) — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
-- =====================================================================
-- QG 키트 어댑터 — WITH+ · LIVE+ (접두어 wpl, 공유 운영 DB xgdkdofteoezrfluaymv)
--  minimal 어댑터를 바탕으로 이 플랫폼에 맞춘 것:
--   · 중앙 관리자 = profiles.role 이 admin·super_admin 이고 is_active 인 사람(두 서버의 isAdminRole 과 같은 기준).
--     profiles 는 GMWOS 와 함께 쓰는 표라 읽기만 한다(역할을 바꾸지 않는다).
--   · '테넌트' = 사이트 2개(고정 id): WITH+ = a17e0000-0000-4000-8000-000000000001, LIVE+ = a17e0000-0000-4000-8000-000000000002.
--     사이트별 표(_with/_live)를 보는 검사는 scope='tenant' 로 두 사이트에 한 번씩 돈다. 구성원 읽기(can_read_tenant)는 없음(false).
--   · 감사·알림 = QG 자체 기록 표(wpl_qg_admin_log, 추가 전용). 서버 증명키 = QG 설정 해시.
--  모든 함수: SECURITY DEFINER · search_path 고정 · 실행 권한 회수. RLS 에서 쓰는 2개(is_admin·can_read_tenant)만 authenticated 에 grant.
-- =====================================================================

do $$
begin
  if to_regclass('public.profiles') is null then
    raise exception 'QG 어댑터(wpl): public.profiles 표가 없습니다.';
  end if;
  if not exists (select 1 from pg_attribute where attrelid = 'public.profiles'::regclass and attname = 'role' and not attisdropped)
     or not exists (select 1 from pg_attribute where attrelid = 'public.profiles'::regclass and attname = 'is_active' and not attisdropped) then
    raise exception 'QG 어댑터(wpl): public.profiles 에 role·is_active 열이 없습니다.';
  end if;
end $$;

create table if not exists public.wpl_qg_admin_log (
  id bigint generated always as identity primary key,
  kind text not null check (kind in ('audit','alert')),
  tenant_id uuid,
  actor uuid,
  actor_kind text,
  action text not null,
  entity text,
  entity_id text,
  severity text,
  title text,
  body text,
  link text,
  dedupe_key text unique,
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
alter table public.wpl_qg_admin_log enable row level security;
revoke all on public.wpl_qg_admin_log from anon, authenticated;

-- 자체 기록 표는 추가 전용(고치기·지우기 거부)
create or replace function public.wpl_qg_admin_log_append_only() returns trigger
language plpgsql set search_path = public as $$
begin
  raise exception 'QG 기록(wpl_qg_admin_log)은 추가만 할 수 있습니다(고치기·지우기 불가).';
end $$;
revoke all on function public.wpl_qg_admin_log_append_only() from public, anon, authenticated;
drop trigger if exists wpl_qg_admin_log_append_only on public.wpl_qg_admin_log;
create trigger wpl_qg_admin_log_append_only before update or delete on public.wpl_qg_admin_log
  for each row execute function public.wpl_qg_admin_log_append_only();

-- 1) 중앙 관리자(현재 로그인 사용자)
create or replace function public.wpl_qga_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and exists (
    select 1 from public.profiles p where p.id = auth.uid() and p.is_active and p.role::text in ('admin', 'super_admin'))
$$;

-- 2) 사이트 구성원 읽기 — 이 플랫폼은 사이트 운영자 화면이 따로 없으므로 false(관리자만 읽음)
create or replace function public.wpl_qga_can_read_tenant(p_tenant uuid) returns boolean
language sql stable security definer set search_path = public as $$ select false $$;

-- 3) p_user 말고 다른 중앙 관리자 수
create or replace function public.wpl_qga_admin_count_except(p_user uuid) returns int
language sql stable security definer set search_path = public as $$
  select count(*)::int from public.profiles p where p.is_active and p.role::text in ('admin', 'super_admin') and p.id is distinct from p_user
$$;

-- 4) 사람 이름
create or replace function public.wpl_qga_user_label(p_user uuid) returns text
language sql stable security definer set search_path = public as $$
  select coalesce(nullif(p.full_name, ''), split_part(p.email, '@', 1)) from public.profiles p where p.id = p_user
$$;

-- 5)~7) 사이트 2개
create or replace function public.wpl_qga_tenants() returns setof uuid
language sql stable security definer set search_path = public as $$
  select x::uuid from unnest(array['a17e0000-0000-4000-8000-000000000001', 'a17e0000-0000-4000-8000-000000000002']) x
$$;
create or replace function public.wpl_qga_tenant_exists(p_tenant uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select p_tenant in ('a17e0000-0000-4000-8000-000000000001'::uuid, 'a17e0000-0000-4000-8000-000000000002'::uuid)
$$;
create or replace function public.wpl_qga_tenant_label(p_tenant uuid) returns text
language sql stable security definer set search_path = public as $$
  select case p_tenant when 'a17e0000-0000-4000-8000-000000000001'::uuid then 'WITH+'
                       when 'a17e0000-0000-4000-8000-000000000002'::uuid then 'LIVE+' end
$$;

-- 8) 감사 기록(QG 자체 표)
create or replace function public.wpl_qga_audit(p_tenant uuid, p_actor_kind text, p_action text, p_entity text, p_entity_id text, p_detail jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  insert into public.wpl_qg_admin_log(kind, tenant_id, actor, actor_kind, action, entity, entity_id, detail)
  values ('audit', p_tenant, auth.uid(), coalesce(p_actor_kind, 'user'), left(p_action, 120), left(p_entity, 120), left(p_entity_id, 200), coalesce(p_detail, '{}'::jsonb));
end $$;

-- 9) 관리자 알림(같은 dedupe_key 는 한 번만)
create or replace function public.wpl_qga_alert(p_severity text, p_title text, p_body text, p_link text, p_dedupe_key text)
returns void language plpgsql security definer set search_path = public as $$
begin
  insert into public.wpl_qg_admin_log(kind, action, severity, title, body, link, dedupe_key)
  values ('alert', 'qg.alert', p_severity, left(p_title, 300), left(p_body, 2000), left(p_link, 500), left(p_dedupe_key, 300))
  on conflict (dedupe_key) do nothing;
end $$;

-- 10) 긴급정지 = QG 설정 qg_automation_kill
create or replace function public.wpl_qga_automation_stopped() returns boolean
language plpgsql stable security definer set search_path = public as $$
declare v jsonb;
begin
  if to_regclass('public.wpl_qg_settings') is null then return false; end if;
  execute 'select value from public.wpl_qg_settings where key = ''qg_automation_kill''' into v;
  return coalesce((v #>> '{}')::boolean, false);
exception when others then return false;
end $$;

-- 11) 서버 증명키(빈 해시 = 항상 거부)
create or replace function public.wpl_qga_server_key_ok(p_key text) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare v_hash text;
begin
  if p_key is null or char_length(p_key) < 16 or to_regclass('public.wpl_qg_settings') is null then return false; end if;
  execute 'select value #>> ''{}'' from public.wpl_qg_settings where key = ''qg_server_attest_key_hash''' into v_hash;
  return coalesce(v_hash, '') ~ '^[0-9a-f]{64}$' and encode(sha256(convert_to(p_key, 'UTF8')), 'hex') = v_hash;
end $$;

-- 12) 플랫폼 감사 해시체인 없음
create or replace function public.wpl_qga_audit_chain_check(p_tail int) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('supported', false, 'ok', true, 'checked', 0, 'message', 'WITH+·LIVE+ 관리자 감사로그(admin_audit_logs_with)는 해시체인이 아닙니다(QG 증거 원장은 따로 해시체인).')
$$;

-- 13)~17) 기본(플랫폼 확장 파일에서 필요하면 다시 정의)
create or replace function public.wpl_qga_release_target(p_kind text, p_ref text) returns jsonb
language sql stable security definer set search_path = public as $$ select null::jsonb $$;
create or replace function public.wpl_qga_review_target(p_kind text, p_ref text) returns jsonb
language sql stable security definer set search_path = public as $$ select null::jsonb $$;
create or replace function public.wpl_qga_ai_runs(p_since timestamptz)
returns table(id uuid, model_code text, task_code text, tenant_id uuid, status text, cache_hit boolean, latency_ms int, cost_krw numeric,
              ref_id text, created_by uuid, created_at timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  if to_regclass('public.wpl_qg_ai_calls') is null then return; end if;
  return query execute 'select c.id, c.model_code, c.task_code, c.tenant_id, c.status, c.cache_hit, c.latency_ms, c.cost_krw, c.ref_id, c.created_by, c.created_at
                          from public.wpl_qg_ai_calls c where c.created_at > $1' using p_since;
end $$;
create or replace function public.wpl_qga_compliance_targets()
returns table(kind text, code text, name text, description text, tenants int)
language sql stable security definer set search_path = public as $$ select null::text, null::text, null::text, null::text, null::int where false $$;
create or replace function public.wpl_qga_banned_phrases()
returns table(pattern text, severity text, reason text, suggestion text, industry text)
language sql stable security definer set search_path = public as $$ select null::text, null::text, null::text, null::text, null::text where false $$;

-- 18) 스모크 전용 픽스처(항상 rollback 되는 트랜잭션 안에서만 불림): 관리자 2·외부인 1, 사이트 2
create or replace function public.wpl_qga_smoke_fixture() returns jsonb
language plpgsql security definer set search_path = public as $$
declare a1 uuid := gen_random_uuid(); a2 uuid := gen_random_uuid(); o uuid := gen_random_uuid(); u uuid;
begin
  foreach u in array array[a1, a2, o] loop
    execute 'insert into auth.users(id, email, aud, role, raw_app_meta_data, raw_user_meta_data, created_at, updated_at) values ($1, $2, ''authenticated'', ''authenticated'', ''{}'', ''{}'', now(), now()) on conflict (id) do nothing'
      using u, 'qg-smoke-' || u || '@example.com';
    execute 'insert into public.profiles(id, email, full_name, role, is_active) values ($1, $2, $3, $4::user_role, true) on conflict (id) do nothing'
      using u, 'qg-smoke-' || u || '@example.com', 'QG 시험 ' || left(u::text, 8), case when u = o then 'member' else 'admin' end;
  end loop;
  return jsonb_build_object('admin1', a1, 'admin2', a2, 'outsider', o, 'member', null,
                            'tenant', 'a17e0000-0000-4000-8000-000000000001', 'tenant2', 'a17e0000-0000-4000-8000-000000000002');
end $$;

-- 19) 어댑터 정보
create or replace function public.wpl_qga_info() returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('adapter', 'wpl', 'label', 'WITH+·LIVE+(공유 DB, 사이트 2개를 테넌트로)', 'server_key', 'qg', 'audit_chain', false, 'tenants', true, 'contract', 1)
$$;

do $$ declare f text; begin
  foreach f in array array[
    'public.wpl_qga_is_admin()', 'public.wpl_qga_can_read_tenant(uuid)', 'public.wpl_qga_admin_count_except(uuid)', 'public.wpl_qga_user_label(uuid)',
    'public.wpl_qga_tenants()', 'public.wpl_qga_tenant_exists(uuid)', 'public.wpl_qga_tenant_label(uuid)',
    'public.wpl_qga_audit(uuid, text, text, text, text, jsonb)', 'public.wpl_qga_alert(text, text, text, text, text)',
    'public.wpl_qga_automation_stopped()', 'public.wpl_qga_server_key_ok(text)', 'public.wpl_qga_audit_chain_check(int)',
    'public.wpl_qga_release_target(text, text)', 'public.wpl_qga_review_target(text, text)', 'public.wpl_qga_ai_runs(timestamptz)',
    'public.wpl_qga_compliance_targets()', 'public.wpl_qga_banned_phrases()', 'public.wpl_qga_smoke_fixture()', 'public.wpl_qga_info()'] loop
    execute format('revoke all on function %s from public, anon, authenticated', f);
  end loop;
end $$;
grant execute on function public.wpl_qga_is_admin() to authenticated;
grant execute on function public.wpl_qga_can_read_tenant(uuid) to authenticated;

drop policy if exists wpl_qg_admin_log_read on public.wpl_qg_admin_log;
create policy wpl_qg_admin_log_read on public.wpl_qg_admin_log for select to authenticated using (public.wpl_qga_is_admin());
grant select on public.wpl_qg_admin_log to authenticated;
