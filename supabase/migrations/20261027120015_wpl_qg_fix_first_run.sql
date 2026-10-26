-- =====================================================================
-- QG 첫 실행(2026-10-27) 결과 정리 — 추가 전용
--  1) 실제 결함: 사이트 표 2개가 '모든 역할 · 조건 없음(true)' 정책으로 익명도 읽기·쓰기·지우기가 가능했다
--     (wholesale_applications_with = 도매 회원 신청서(사업자 정보), live_flash_sales_live = LIVE+ 라이브 타임세일).
--     두 표 모두 서버(서비스 키, RLS 우회)만 쓰고 화면이 직접 읽지 않는다 → 기존 정책은 그대로 두고
--     익명·로그인 역할을 막는 RESTRICTIVE 정책을 더한다(서비스 키는 RLS 를 우회하므로 서버 동작은 같다).
--  2) 사이트 보안 probe: RESTRICTIVE 거부 정책이 덮고 있으면 열린 정책으로 세지 않는다.
--  3) 준법: 키트 공통 법령 중 이 플랫폼에 걸리는 것을 준법 대상에 연결(개인정보·정보통신망·전자금융). 위치정보법은 회원 위치를 쓰지 않아 연결하지 않음(형님 확인).
--  4) 위험도별 테스트: 역할·권한 항목에 플랫폼 스모크(가드 시험) 연결.
-- =====================================================================

-- 1) 익명·로그인 역할 차단(RESTRICTIVE — 기존 허용 정책과 AND 로 묶여 anon·authenticated 는 0행)
do $$ declare t text; begin
  foreach t in array array['wholesale_applications_with', 'live_flash_sales_live'] loop
    if to_regclass('public.' || t) is not null and not exists (select 1 from pg_policies where schemaname = 'public' and tablename = t and policyname = t || '_wpl_deny_clients') then
      execute format('create policy %I on public.%I as restrictive for all to anon, authenticated using (false) with check (false)', t || '_wpl_deny_clients', t);
    end if;
  end loop;
end $$;

-- 2) 사이트 보안 probe 다시 정의: 같은 표에 anon 을 덮는 RESTRICTIVE false 정책이 있으면 그 표의 열린 정책은 막힌 것으로 본다
create or replace function public.wpl_qg_probe_security_site_tables(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb; v_ex jsonb := coalesce(p_check.params->'exclude', '{}'::jsonb);
begin
  select coalesce(jsonb_agg(x), '[]'::jsonb) into v from (
    select jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', 'rls:' || c.relname,
             'title', '사이트 표 RLS 꺼짐: ' || c.relname, 'detail', jsonb_build_object('table', c.relname)) x
      from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and c.relname ~ '_(with|live)$' and not c.relrowsecurity and not (v_ex ? c.relname)
    union all
    select jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', 'pol:' || p.tablename || ':' || p.policyname,
             'title', format('사이트 표 %s 에 익명도 조건 없이 쓸 수 있는 정책(%s)', p.tablename, p.policyname),
             'detail', jsonb_build_object('table', p.tablename, 'policy', p.policyname, 'cmd', p.cmd, 'roles', p.roles, 'qual', p.qual, 'with_check', p.with_check))
      from pg_policies p
     where p.schemaname = 'public' and p.tablename ~ '_(with|live)$' and p.permissive = 'PERMISSIVE' and not (v_ex ? p.tablename)
       and p.cmd in ('INSERT', 'UPDATE', 'DELETE', 'ALL') and (p.roles && array['anon', 'public']::name[])
       and (coalesce(nullif(trim(p.with_check), ''), nullif(trim(p.qual), ''), 'true') in ('true', '(true)'))
       and not exists (select 1 from pg_policies d
                        where d.schemaname = 'public' and d.tablename = p.tablename and d.permissive = 'RESTRICTIVE' and d.cmd = 'ALL'
                          and (d.roles && array['anon', 'public']::name[]) and trim(coalesce(d.qual, '')) in ('false', '(false)'))
  ) q;
  return v;
end $$;
revoke all on function public.wpl_qg_probe_security_site_tables(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 3) 준법 대상 하나 더 + 키트 공통 법령 연결(사람이 정한 links 가 이미 있으면 건드리지 않음)
insert into public.wpl_qg_compliance_targets(kind, code, name, description, tenants) values
 ('feature', 'wpl_member_signup', '회원가입·개인정보 수집', '회원가입·소셜 로그인·배송지·마케팅 수신 동의(profiles·shipping_addresses_with·social_identities_with)', 2)
on conflict (kind, code) do nothing;
update public.wpl_qg_regulations set links = '{"feature":["wpl_member_signup"]}'::jsonb where code = 'pipa_consent' and links = '{}'::jsonb;
update public.wpl_qg_regulations set links = '{"feature":["wpl_marketing_push"]}'::jsonb where code = 'network_act' and links = '{}'::jsonb;
update public.wpl_qg_regulations set links = '{"feature":["wpl_order_checkout","wpl_mileage"]}'::jsonb where code = 'efta_payment' and links = '{}'::jsonb;

-- 4) 역할·권한 위험 항목 ← 플랫폼 스모크(대표자·수수료율 자기 수정 가드 시험 포함)
update public.wpl_qg_test_suites
   set risk_items = (select jsonb_agg(distinct x) from jsonb_array_elements_text(risk_items || '["wpl_profile_role"]'::jsonb) x)
 where code = 'sql_wpl_platform';
