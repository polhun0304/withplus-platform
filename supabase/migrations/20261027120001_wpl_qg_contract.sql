-- QG 키트 1.1.0 · 접두어 wpl · contract — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
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
