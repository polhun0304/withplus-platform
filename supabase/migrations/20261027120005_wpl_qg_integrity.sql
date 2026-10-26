-- QG 키트 1.1.0 · 접두어 wpl · integrity — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
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
