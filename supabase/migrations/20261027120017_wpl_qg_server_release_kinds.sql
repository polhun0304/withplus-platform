-- =====================================================================
-- QG 플랫폼 확장(WITH+ · LIVE+, 접두어 wpl) — 서버 코드 출시 관문 연결(QG_KIT v1.2 §7.2)
--  WITH+·LIVE+ 는 공개·승인을 DB 함수가 아니라 Express 서버(server.js, service_role)에서 한다 → 그 라우트에 두 단계 헬퍼(qg/release-gate.js)를 넣고,
--  여기서는 출시 종류(kind) 3개의 관문 정책 + 대상 확인 어댑터(wpl_qga_release_target) + 관리자 화면용 대상 목록을 더한다.
--   · supplier_approve  판매자 입점 승인   PUT /api/admin/supplier-applications/:id/approve   (회원 → 판매자 권한, 표 supplier_applications_with = 두 사이트 공유)
--   · wholesale_approve 도매 회원 승인     PUT /api/admin/wholesale-applications/:id/approve  (회원 → 도매가 주문 권한, 표 wholesale_applications_with = 두 사이트 공유)
--   · live_go_live      라이브 방송 공개 시작 PATCH /api/admin/live/channels/:id/sessions/:sessionId {status:'live'} (WITH+ live_sessions_with · LIVE+ live_sessions_live)
--  강제 스위치 qg_enforce_<종류> 는 정책 행을 넣을 때 자동으로 false 로 생긴다(기존 트리거) — 꺼져 있으면 서버 동작·응답·DB 변화는 이전과 같고 관찰 기록만 남는다.
--  추가 전용(정책 행·함수 정의만). 업무 표는 바꾸지 않는다. 두 번 적용해도 같은 결과.
-- =====================================================================

insert into public.wpl_qg_gate_policies(kind, name, description, required_engines, max_age_hours, block_severities, issue_scope, require_review)
values
 ('supplier_approve', '판매자 입점 승인',
  '회원을 판매자(상품 등록 권한)로 올리기 전: 보안·정합성 엔진이 24시간 안에 통과, 치명 열린 이슈 0. 대상 = 입점 신청 1건(관리자 화면 → 입점 신청).',
  '["security","integrity"]', 24, '["critical"]', 'all', false),
 ('wholesale_approve', '도매 회원 승인',
  '회원을 도매 회원(도매가 주문 권한)으로 올리기 전: 보안·정합성 엔진이 24시간 안에 통과, 치명 열린 이슈 0. 대상 = 도매몰 입점 신청 1건.',
  '["security","integrity"]', 24, '["critical"]', 'all', false),
 ('live_go_live', '라이브 방송 공개 시작',
  '라이브 세션을 방송 중(시청자 공개·가입자 알림 발송)으로 바꾸기 전: 보안 엔진이 24시간 안에 통과, 그 사이트 치명 열린 이슈 0. 대상 = 예정된 라이브 세션 1건.',
  '["security"]', 24, '["critical"]', 'target', false)
on conflict (kind) do nothing;

-- 대상 확인 어댑터(키트 기본은 null) — 출시 후보를 만들 때(화면)와 서버 확인(release_gate_check_server) 때 같은 ref 로 해석한다.
--  ref = 행 id(소문자 uuid 문자열). 반환 {ref, label, tenant_id}, 모르면 null.
create or replace function public.wpl_qga_release_target(p_kind text, p_ref text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_id uuid; a record; s record; v_site uuid; v_ch text;
begin
  if p_kind not in ('supplier_approve', 'wholesale_approve', 'live_go_live') then return null; end if;
  begin v_id := trim(p_ref)::uuid; exception when others then return null; end;
  if p_kind = 'supplier_approve' then
    select id, company_name, status into a from public.supplier_applications_with where id = v_id;
    if a.id is null then return null; end if;
    return jsonb_build_object('ref', a.id::text, 'label', '입점 신청: ' || left(coalesce(a.company_name, '-'), 120), 'tenant_id', null);
  elsif p_kind = 'wholesale_approve' then
    select id, company_name, status into a from public.wholesale_applications_with where id = v_id;
    if a.id is null then return null; end if;
    return jsonb_build_object('ref', a.id::text, 'label', '도매 신청: ' || left(coalesce(a.company_name, '-'), 120), 'tenant_id', null);
  end if;
  -- live_go_live: WITH+ 세션(live_sessions_with) → LIVE+ 세션(live_sessions_live) 순서로 찾는다(uuid 라 겹치지 않음)
  select id, channel_id, title into s from public.live_sessions_with where id = v_id;
  if s.id is not null then
    v_site := 'a17e0000-0000-4000-8000-000000000001';
    if to_regclass('public.channels_with') is not null then
      execute 'select name from public.channels_with where id = $1' into v_ch using s.channel_id;
    end if;
  else
    select id, channel_id, title into s from public.live_sessions_live where id = v_id;
    if s.id is null then return null; end if;
    v_site := 'a17e0000-0000-4000-8000-000000000002';
    if to_regclass('public.channels_live') is not null then
      execute 'select name from public.channels_live where id = $1' into v_ch using s.channel_id;
    end if;
  end if;
  return jsonb_build_object('ref', s.id::text,
    'label', case v_site when 'a17e0000-0000-4000-8000-000000000001'::uuid then 'WITH+' else 'LIVE+' end || ' 라이브: '
             || left(coalesce(nullif(v_ch, '') || ' · ', '') || coalesce(nullif(s.title, ''), '(제목 없음)'), 150),
    'tenant_id', v_site);
end $$;
revoke all on function public.wpl_qga_release_target(text, text) from public, anon, authenticated;

-- 관리자 화면 '출시 후보 만들기' 대상 고르기(UUID 손입력 없음): 심사 대기 입점·도매 신청, 예정된 라이브 세션
create or replace function public.wpl_qg_release_target_list(p_kind text, p_limit int default 100)
returns table(kind text, ref text, label text, tenant_id uuid, detail text)
language plpgsql stable security definer set search_path = public as $$
declare v_lim int := least(greatest(coalesce(p_limit, 100), 1), 300);
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '출시 대상 목록은 관리자만 볼 수 있습니다.'; end if;
  if p_kind = 'supplier_approve' then
    return query select 'supplier_approve'::text, a.id::text, '입점 신청: ' || left(coalesce(a.company_name, '-'), 120), null::uuid,
                        '신청 ' || to_char(a.created_at at time zone 'Asia/Seoul', 'YYYY-MM-DD HH24:MI')
                   from public.supplier_applications_with a where a.status = 'pending' order by a.created_at desc limit v_lim;
  elsif p_kind = 'wholesale_approve' then
    return query select 'wholesale_approve'::text, a.id::text, '도매 신청: ' || left(coalesce(a.company_name, '-'), 120), null::uuid,
                        '신청 ' || to_char(a.created_at at time zone 'Asia/Seoul', 'YYYY-MM-DD HH24:MI')
                   from public.wholesale_applications_with a where a.status = 'pending' order by a.created_at desc limit v_lim;
  elsif p_kind = 'live_go_live' then
    return query select 'live_go_live'::text, x.id::text, (public.wpl_qga_release_target('live_go_live', x.id::text))->>'label', x.site,
                        case when x.scheduled_at is null then '예정 시각 없음' else '예정 ' || to_char(x.scheduled_at at time zone 'Asia/Seoul', 'YYYY-MM-DD HH24:MI') end
                   from (select w.id, w.scheduled_at, w.created_at, 'a17e0000-0000-4000-8000-000000000001'::uuid site from public.live_sessions_with w where w.status = 'scheduled'
                         union all
                         select l.id, l.scheduled_at, l.created_at, 'a17e0000-0000-4000-8000-000000000002'::uuid from public.live_sessions_live l where l.status = 'scheduled') x
                  order by x.scheduled_at nulls last, x.created_at desc limit v_lim;
  end if;
  return;
end $$;
revoke all on function public.wpl_qg_release_target_list(text, int) from public, anon, authenticated;
grant execute on function public.wpl_qg_release_target_list(text, int) to authenticated;
