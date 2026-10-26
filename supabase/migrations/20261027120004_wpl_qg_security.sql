-- QG 키트 1.1.0 · 접두어 wpl · security — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
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
  '최근 window_minutes 분 동안 인증 감사 로그의 실패성 기록이 auth_fail 건을 넘으면 보안 이슈를 올립니다. 인증 감사 로그를 읽을 수 없으면 건너뜁니다. JSON 객체.')
on conflict (key) do nothing;

-- 0) 공유 DB(한 DB 에 여러 제품) 범위: params.include_prefixes(비어 있으면 전체) · params.exclude_prefixes 로 이름 접두어를 거른다.
--    QG 자신(wpl_qg_·wpl_qga_)은 항상 검사한다. 예: {"include_prefixes":["gos_"],"exclude_prefixes":["ekos_"]}
create or replace function public.wpl_qg_scope_ok_internal(p_name text, p_params jsonb) returns boolean
language sql immutable set search_path = public as $$
  select p_name like 'wpl\_qg\_%' or p_name like 'wpl\_qga\_%'
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
