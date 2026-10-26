-- =====================================================================
-- QG 플랫폼 확장(WITH+ · LIVE+, 접두어 wpl) — 키트가 렌더링한 20261027120000~012 는 그대로 두고 이 플랫폼 것만 더한다(QG_KIT.md §6.4).
--  공유 운영 DB(xgdkdofteoezrfluaymv = GMWOS 스테이징 + WITH+ + LIVE+)에 한 번만 설치. 사이트는 '테넌트' 2개(고정 id)로 구분:
--    WITH+ = a17e0000-0000-4000-8000-000000000001 (표 접미사 _with) · LIVE+ = a17e0000-0000-4000-8000-000000000002 (표 접미사 _live)
--  1) 사이트 도우미 · 어댑터 재정의(검토 대상: 상품 상세 문구)
--  2) 일반 검사 params(공유 DB 범위·추가 전용 표·교차 테넌트 범위)
--  3) 업무 정합성 probe 8종(돈·상태·소유·중복·기한) + 사이트 보안 probe 2종 + 개선 신호 probe 2종
--  4) 준법 대상 → 업종 법령(검토 필요) · 위험 항목 · 테스트 스위트 · 공격 시나리오 카탈로그
--  추가 전용(읽기 전용 probe, 카탈로그 행 추가). 두 번 적용해도 같은 결과. 업무 표는 바꾸지 않는다.
-- =====================================================================

-- ───────── 1) 사이트 도우미 ─────────
create or replace function public.wpl_qg_site_suffix_internal(p_tenant uuid) returns text
language sql immutable security definer set search_path = public as $$
  select case p_tenant when 'a17e0000-0000-4000-8000-000000000001'::uuid then '_with'
                       when 'a17e0000-0000-4000-8000-000000000002'::uuid then '_live' end
$$;
revoke all on function public.wpl_qg_site_suffix_internal(uuid) from public, anon, authenticated;

-- 검토 대상: copy = 상품 상세 문구(products_with 의 이름·설명·상세 설명) — 표시광고법·전자상거래법 금칙어 검토
create or replace function public.wpl_qga_review_target(p_kind text, p_ref text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_id uuid; p record;
begin
  if p_kind <> 'copy' then return null; end if;
  begin v_id := p_ref::uuid; exception when others then return null; end;
  select id, name, description, long_description, category into p from public.products_with where id = v_id and deleted_at is null;
  if p.id is null then return null; end if;
  return jsonb_build_object('tenant_id', null, 'label', '상품 문구: ' || left(p.name, 80),
    'text', left(concat_ws(E'\n\n', p.name, p.description, p.long_description), 20000),
    'context', jsonb_build_object('category', p.category, 'product_id', p.id), 'industry', 'commerce', 'target_id', p.id::text);
end $$;
revoke all on function public.wpl_qga_review_target(text, text) from public, anon, authenticated;

-- 검토 화면 '대상 고르기' — 최근 판매중 상품(UUID 손입력 없음)
create or replace function public.wpl_qga_review_candidates(p_kind text, p_limit int)
returns table(kind text, ref text, label text, tenant_id uuid, kind_label text)
language sql stable security definer set search_path = public as $$
  select 'copy'::text, p.id::text, left(p.name, 120), null::uuid, '상품 문구'::text
    from public.products_with p
   where coalesce(p_kind, 'copy') = 'copy' and p.deleted_at is null and p.status = 'active'
   order by p.created_at desc
   limit least(greatest(coalesce(p_limit, 50), 1), 200)
$$;
revoke all on function public.wpl_qga_review_candidates(text, int) from public, anon, authenticated;

-- ───────── 2) 일반 검사 params ─────────
-- 공유 DB: 보안 5종은 QG 자신(wpl_)과 키트 스모크가 rollback 안에서 심는 zz_qg_ 시험 객체만 보고, WITH+·LIVE+ 표·함수(접미사 _with/_live)는 아래 사이트 보안 probe 가 본다(키트는 접두어만 지원).
update public.wpl_qg_checks set params = params || '{"include_prefixes":["wpl_","zz_qg_"]}'::jsonb
 where code in ('security.anon_definer','security.rls_disabled','security.no_policies','security.definer_search_path','security.internal_exec');
-- 추가 전용 표: QG 자체 기록 + 플랫폼 감사 로그(가드가 없으면 첫 실행에 '실패'로 드러난다 — 시험 스크립트가 감사 행을 지우므로 가드 추가는 형님 결정)
update public.wpl_qg_checks
   set params = params || jsonb_build_object(
     'tables', (select coalesce(jsonb_agg(distinct x), '[]'::jsonb) from jsonb_array_elements_text(coalesce(params->'tables', '[]'::jsonb) || '["wpl_qg_admin_log","admin_audit_logs_with","cost_access_audit_log_with"]'::jsonb) x),
     'guard_functions', (select coalesce(jsonb_agg(distinct x), '[]'::jsonb) from jsonb_array_elements_text(coalesce(params->'guard_functions', '["wpl_qg_forbid_mutation"]'::jsonb) || '["wpl_qg_admin_log_append_only"]'::jsonb) x))
 where code = 'integrity.append_only_guards';
-- 교차 테넌트 참조·고아 행: 이 플랫폼 업무 표에는 tenant_id 칸이 없다(사이트는 표 이름으로 나뉨) → QG 표만
update public.wpl_qg_checks set params = params || '{"table_prefixes":["wpl_"]}'::jsonb where code in ('integrity.cross_tenant_fk', 'integrity.orphans');

-- ───────── 3) 업무 정합성 probe(읽기 전용, QG_KIT §5.1) ─────────

-- ① 돈: 주문 결제 금액 = 상품 합계 − 할인 − 마일리지 사용 + 배송비, 상품 합계 = 줄(가격×수량) 합, 음수 금지  (server.js 주문 생성과 같은 식)
create or replace function public.wpl_qg_probe_order_amount(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb; v_tol numeric := coalesce((p_check.params->>'tolerance')::numeric, 0);
        v_lim int := least(greatest(coalesce((p_check.params->>'limit')::int, 200), 1), 2000);
        v_days int := greatest(1, coalesce((p_check.params->>'days')::int, 3650));
begin
  select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', q.id::text,
           'title', format('주문 %s 금액 불일치: %s', q.order_number, array_to_string(q.reasons, ', ')),
           'detail', jsonb_build_object('order_id', q.id, 'order_number', q.order_number, 'status', q.status, 'total_price', q.total_price,
             'discount_amount', q.discount_amount, 'used_mileage', q.used_mileage, 'shipping_fee', q.shipping_fee, 'final_price', q.final_price,
             'expected_final', q.expected_final, 'items_sum', q.items_sum, 'reasons', to_jsonb(q.reasons)))), '[]'::jsonb)
    into v
    from (select o.*, e.expected_final, i.items_sum,
                 array_remove(array[
                   case when abs(o.final_price - e.expected_final) > v_tol then format('결제 금액 %s원 ≠ 계산 %s원', o.final_price, e.expected_final) end,
                   case when i.items_sum is not null and abs(o.total_price - i.items_sum) > v_tol then format('상품 합계 %s원 ≠ 줄 합 %s원', o.total_price, i.items_sum) end,
                   case when o.final_price < 0 or o.total_price < 0 or coalesce(o.discount_amount, 0) < 0 or coalesce(o.used_mileage, 0) < 0 or coalesce(o.shipping_fee, 0) < 0 then '음수 금액' end
                 ], null) reasons
            from public.orders_with o
            cross join lateral (select o.total_price - coalesce(o.discount_amount, 0) - coalesce(o.used_mileage, 0) + coalesce(o.shipping_fee, 0) expected_final) e
            cross join lateral (select case when jsonb_typeof(o.items) = 'array' and jsonb_array_length(o.items) > 0
                                       then (select sum(coalesce((x->>'price')::numeric, 0) * coalesce((x->>'quantity')::numeric, 1)) from jsonb_array_elements(o.items) x) end items_sum) i
           where o.created_at > now() - make_interval(days => v_days)) q
   where cardinality(q.reasons) > 0
   limit v_lim;
  return v;
exception when invalid_text_representation then
  return jsonb_build_array(jsonb_build_object('status', 'error', 'title', '주문 줄(items)의 가격·수량이 숫자가 아닌 행이 있습니다', 'detail', jsonb_build_object('message', sqlerrm)));
end $$;
revoke all on function public.wpl_qg_probe_order_amount(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ② 상태: 결제 이후 상태(결제 완료·처리 중·배송·배송 완료)인데 결제 수단이 비었거나 '대기'로 남음
create or replace function public.wpl_qg_probe_order_paid_state(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb; v_ok jsonb := coalesce(p_check.params->'allowed_methods', '[]'::jsonb);
begin
  select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', o.id::text,
           'title', format('주문 %s: %s 상태인데 결제 수단 기록이 %s', o.order_number,
                           case o.status when 'paid' then '결제 완료' when 'processing' then '처리 중' when 'shipped' then '배송 중' else '배송 완료' end,
                           coalesce(nullif(o.payment_method, ''), '비어 있음')),
           'detail', jsonb_build_object('order_id', o.id, 'order_number', o.order_number, 'status', o.status, 'payment_method', o.payment_method, 'final_price', o.final_price))), '[]'::jsonb)
    into v
    from (select * from public.orders_with
           where status in ('paid', 'processing', 'shipped', 'delivered')
             and (nullif(payment_method, '') is null or payment_method = 'pending')
             and not (v_ok ? coalesce(payment_method, ''))
           order by created_at desc
           limit least(greatest(coalesce((p_check.params->>'limit')::int, 200), 1), 2000)) o;
  return v;
end $$;
revoke all on function public.wpl_qg_probe_order_paid_state(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ③ 상태·소유·기한: 시리얼 쿠폰 사용 상태 — 사용됨인데 사용자·시각 없음 / 사용 안 됨인데 사용자 있음 / 유효기간 지나 사용
create or replace function public.wpl_qg_probe_serial_coupon_state(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb;
begin
  select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', q.id::text,
           'title', format('시리얼 쿠폰(%s) %s', q.batch_name, q.reason),
           'detail', jsonb_build_object('serial_coupon_id', q.id, 'batch_name', q.batch_name, 'is_redeemed', q.is_redeemed,
             'redeemed_by', q.redeemed_by, 'redeemed_at', q.redeemed_at, 'expires_at', q.expires_at, 'reward_mileage', q.reward_mileage, 'reason', q.reason))), '[]'::jsonb)
    into v
    from (select s.*, case
                 when s.is_redeemed and (s.redeemed_by is null or s.redeemed_at is null) then '사용됨인데 사용자·사용 시각이 비어 있음'
                 when not s.is_redeemed and (s.redeemed_by is not null or s.redeemed_at is not null) then '사용 안 됨인데 사용자·사용 시각이 기록됨'
                 when s.is_redeemed and s.expires_at is not null and s.redeemed_at > s.expires_at then '유효기간이 지난 뒤 사용됨'
                 when coalesce(s.reward_mileage, 0) < 0 then '적립 마일리지가 음수' end reason
            from public.serial_coupons_with s) q
   where q.reason is not null
   limit least(greatest(coalesce((p_check.params->>'limit')::int, 200), 1), 2000);
  return v;
end $$;
revoke all on function public.wpl_qg_probe_serial_coupon_state(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ④ 중복(사이트별): 같은 회원이 같은 라이브 세션·상품에 열린 예약(장바구니·결제 중)을 2건 이상 — 재고 이중 선점
create or replace function public.wpl_qg_probe_live_reservation_dup(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb; v_s text := public.wpl_qg_site_suffix_internal(p_tenant); v_t text;
begin
  v_t := 'live_session_reservations' || coalesce(v_s, '');
  if v_s is null or to_regclass('public.' || v_t) is null then
    return jsonb_build_array(jsonb_build_object('status', 'skipped', 'title', '사이트 라이브 예약 표가 없습니다', 'detail', jsonb_build_object('table', v_t)));
  end if;
  execute format($s$
    select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', d.live_session_id || ':' || d.product_id || ':' || d.user_id,
             'title', format('같은 회원이 같은 라이브 상품에 열린 예약 %%s건(수량 합 %%s)', d.n, d.qty),
             'detail', jsonb_build_object('table', %L, 'live_session_id', d.live_session_id, 'product_id', d.product_id, 'user_id', d.user_id,
               'count', d.n, 'quantity', d.qty, 'reservation_ids', d.ids))), '[]'::jsonb)
      from (select live_session_id, product_id, user_id, count(*) n, sum(quantity) qty, jsonb_agg(id order by created_at) ids
              from public.%I where status in ('cart', 'checkout') group by 1, 2, 3 having count(*) > 1 limit $1) d$s$, v_t, v_t)
    into v using least(greatest(coalesce((p_check.params->>'limit')::int, 200), 1), 2000);
  return v;
end $$;
revoke all on function public.wpl_qg_probe_live_reservation_dup(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ⑤ 기한(사이트별): 라이브 예약이 만료 시각을 넘겼는데 장바구니·결제 중 상태로 남아 재고를 잡고 있음
create or replace function public.wpl_qg_probe_live_reservation_stale(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb; v_s text := public.wpl_qg_site_suffix_internal(p_tenant); v_t text;
        v_grace int := greatest(0, coalesce((p_check.params->>'grace_minutes')::int, 60));
begin
  v_t := 'live_session_reservations' || coalesce(v_s, '');
  if v_s is null or to_regclass('public.' || v_t) is null then
    return jsonb_build_array(jsonb_build_object('status', 'skipped', 'title', '사이트 라이브 예약 표가 없습니다', 'detail', jsonb_build_object('table', v_t)));
  end if;
  execute format($s$
    select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'medium', 'fingerprint', r.id::text,
             'title', format('만료된 라이브 예약이 %%s 상태로 남음(수량 %%s, 만료 %%s)', r.status, r.quantity, to_char(r.expires_at at time zone 'Asia/Seoul', 'YYYY-MM-DD HH24:MI')),
             'detail', jsonb_build_object('table', %L, 'reservation_id', r.id, 'live_session_id', r.live_session_id, 'product_id', r.product_id,
               'status', r.status, 'quantity', r.quantity, 'expires_at', r.expires_at))), '[]'::jsonb)
      from (select * from public.%I where status in ('cart', 'checkout') and expires_at < now() - make_interval(mins => $1) order by expires_at limit $2) r$s$, v_t, v_t)
    into v using v_grace, least(greatest(coalesce((p_check.params->>'limit')::int, 200), 1), 2000);
  return v;
end $$;
revoke all on function public.wpl_qg_probe_live_reservation_stale(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ⑥ 재고(사이트별): 라이브 세션 배정 재고보다 예약+판매가 많음(초과 판매)
create or replace function public.wpl_qg_probe_live_inventory_oversell(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb; v_s text := public.wpl_qg_site_suffix_internal(p_tenant); v_t text;
        v_safety boolean := coalesce((p_check.params->>'include_safety')::boolean, false);
begin
  v_t := 'live_session_inventory' || coalesce(v_s, '');
  if v_s is null or to_regclass('public.' || v_t) is null then
    return jsonb_build_array(jsonb_build_object('status', 'skipped', 'title', '사이트 라이브 재고 표가 없습니다', 'detail', jsonb_build_object('table', v_t)));
  end if;
  execute format($s$
    select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', i.id::text,
             'title', format('라이브 재고 초과: 배정 %%s · 예약 %%s · 판매 %%s', i.allocated_qty, i.reserved_qty, i.sold_qty),
             'detail', jsonb_build_object('table', %L, 'inventory_id', i.id, 'live_session_id', i.live_session_id, 'product_id', i.product_id,
               'allocated_qty', i.allocated_qty, 'reserved_qty', i.reserved_qty, 'sold_qty', i.sold_qty, 'safety_stock', i.safety_stock))), '[]'::jsonb)
      from (select * from public.%I where reserved_qty + sold_qty > allocated_qty - case when $1 then safety_stock else 0 end limit $2) i$s$, v_t, v_t)
    into v using v_safety, least(greatest(coalesce((p_check.params->>'limit')::int, 200), 1), 2000);
  return v;
end $$;
revoke all on function public.wpl_qg_probe_live_inventory_oversell(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ⑦ 돈: 정산서(분양 조직·크리에이터) 실지급액 = 수수료 − 원천징수, 지급 완료면 지급 시각, 음수 금지
create or replace function public.wpl_qg_probe_settlement_amount(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb; v_tol numeric := coalesce((p_check.params->>'tolerance')::numeric, 0);
begin
  select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', q.kind || ':' || q.id,
           'title', format('%s 정산서 %s', case q.kind when 'community' then '분양 조직' else '크리에이터' end, q.reason),
           'detail', jsonb_build_object('kind', q.kind, 'settlement_id', q.id, 'status', q.status, 'commission_amount', q.commission_amount,
             'withholding_tax_amount', q.withholding_tax_amount, 'net_payment_amount', q.net_payment_amount, 'paid_at', q.paid_at, 'reason', q.reason))), '[]'::jsonb)
    into v
    from (select z.*, case
                 when z.net_payment_amount is not null and abs(z.net_payment_amount - (coalesce(z.commission_amount, 0) - coalesce(z.withholding_tax_amount, 0))) > v_tol
                   then format('실지급액 %s원 ≠ 수수료 %s원 − 원천징수 %s원', z.net_payment_amount, coalesce(z.commission_amount, 0), coalesce(z.withholding_tax_amount, 0))
                 when z.status = 'paid' and z.paid_at is null then '지급 완료인데 지급 시각이 없음'
                 when coalesce(z.commission_amount, 0) < 0 or coalesce(z.withholding_tax_amount, 0) < 0 or coalesce(z.net_payment_amount, 0) < 0 then '음수 금액' end reason
            from (select 'community'::text kind, id, status, commission_amount, withholding_tax_amount, net_payment_amount, paid_at from public.community_settlements_with
                  union all
                  select 'creator', id, status, commission_amount, withholding_tax_amount, net_payment_amount, paid_at from public.creator_settlements_with) z) q
   where q.reason is not null
   limit least(greatest(coalesce((p_check.params->>'limit')::int, 200), 1), 2000);
  return v;
end $$;
revoke all on function public.wpl_qg_probe_settlement_amount(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ⑧ 재고·돈: 타임딜 한정 수량보다 잡힘(held)+결제(paid) 수량이 많음
create or replace function public.wpl_qg_probe_flash_deal_oversell(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb;
begin
  select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', q.id::text,
           'title', format('타임딜 한정 %s개인데 %s개가 잡히거나 팔림', q.limit_qty, q.taken),
           'detail', jsonb_build_object('deal_id', q.id, 'site', q.site, 'product_id', q.product_id, 'limit_qty', q.limit_qty, 'taken', q.taken))), '[]'::jsonb)
    into v
    from (select d.id, d.site, d.product_id, d.limit_qty, coalesce(sum(c.quantity), 0) taken
            from public.flash_deals_with d left join public.flash_deal_claims_with c on c.deal_id = d.id and c.status in ('held', 'paid')
           where d.limit_qty is not null
           group by d.id, d.site, d.product_id, d.limit_qty
          having coalesce(sum(c.quantity), 0) > d.limit_qty
           limit least(greatest(coalesce((p_check.params->>'limit')::int, 200), 1), 2000)) q;
  return v;
end $$;
revoke all on function public.wpl_qg_probe_flash_deal_oversell(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 사이트 보안 ①: WITH+·LIVE+ 표(접미사 _with/_live) — RLS 꺼짐, 익명·공개 역할에 조건 없는(true) 쓰기 정책
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
  ) q;
  return v;
end $$;
revoke all on function public.wpl_qg_probe_security_site_tables(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- 사이트 보안 ②: 익명이 실행할 수 있는 사이트 SECURITY DEFINER 함수(접미사 _with/_live, 다른 제품 이름은 params.exclude_prefixes 로 제외)
create or replace function public.wpl_qg_probe_security_site_anon_definer(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb; v_allow jsonb := coalesce(p_check.params->'allowed', '{}'::jsonb);
begin
  select coalesce(jsonb_agg(jsonb_build_object('status', 'fail', 'severity', 'critical', 'fingerprint', p.oid::regprocedure::text,
           'title', '익명이 실행할 수 있는 사이트 DEFINER 함수: ' || p.oid::regprocedure::text,
           'detail', jsonb_build_object('function', p.oid::regprocedure::text))), '[]'::jsonb)
    into v
    from pg_proc p
   where p.pronamespace = 'public'::regnamespace and p.prosecdef and p.proname ~ '_(with|live)$'
     and has_function_privilege('anon', p.oid, 'execute') and not (v_allow ? p.proname)
     and not exists (select 1 from jsonb_array_elements_text(coalesce(p_check.params->'exclude_prefixes', '[]'::jsonb)) e where left(p.proname, length(e)) = e);
  return v;
end $$;
revoke all on function public.wpl_qg_probe_security_site_anon_definer(public.wpl_qg_checks, uuid) from public, anon, authenticated;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('integrity.wpl_order_amount', 'integrity', '주문 금액 정합성',
  '주문마다 결제 금액 = 상품 합계 − 쿠폰 할인 − 마일리지 사용 + 배송비, 상품 합계 = 주문 줄(가격×수량) 합인지, 음수 금액이 없는지 봅니다(주문 생성 서버 계산과 같은 식).',
  'wpl_qg_probe_order_amount', 'critical', 'platform', 'daily', '{"tolerance":0,"limit":200,"days":3650}'::jsonb, '0건',
  '① 관리자 → 주문 관리에서 그 주문의 결제 기록(PG 승인 금액)과 비교하세요. ② 실제 결제 금액이 맞으면 주문 기록을 바로잡는 사유와 함께 처리하고, 계산식이 바뀐 것이면 이 검사 params 를 고치세요.', 900),
 ('integrity.wpl_order_paid_state', 'integrity', '결제 상태·결제 수단 정합성',
  '결제 완료·처리 중·배송 중·배송 완료 주문인데 결제 수단이 비었거나 대기(pending)로 남은 주문을 찾습니다(PG 승인 없이 상태만 바뀐 주문 신호).',
  'wpl_qg_probe_order_paid_state', 'high', 'platform', 'daily', '{"limit":200,"allowed_methods":[]}'::jsonb, '0건',
  '① 관리자 → 주문 관리에서 그 주문의 PG 승인 내역을 확인하세요. ② 무통장·수기 결제면 결제 수단을 기록하고, 시험 주문이면 사유와 함께 취소하세요.', 905),
 ('integrity.wpl_serial_coupon_state', 'integrity', '시리얼 쿠폰 사용 상태',
  '시리얼 쿠폰의 사용 여부와 사용자·사용 시각이 서로 맞는지, 유효기간 뒤에 사용된 쿠폰이 없는지 봅니다(마일리지 지급과 연결).',
  'wpl_qg_probe_serial_coupon_state', 'high', 'platform', 'daily', '{"limit":200}'::jsonb, '0건',
  '① 관리자 → 시리얼 쿠폰에서 그 쿠폰의 마일리지 지급 기록(mileage_adjustments_with)을 확인하세요. ② 지급됐으면 사용자·시각을 채우고, 안 됐으면 사용 표시를 되돌리는 사유를 남기세요.', 910),
 ('integrity.wpl_live_reservation_dup', 'integrity', '라이브 예약 이중 선점(사이트별)',
  '같은 회원이 같은 라이브 세션·상품에 열린 예약(장바구니·결제 중)을 2건 이상 가지고 있는지 사이트(WITH+·LIVE+)마다 봅니다(서버는 1건만 허용).',
  'wpl_qg_probe_live_reservation_dup', 'high', 'tenant', 'daily', '{"limit":200}'::jsonb, '0건',
  '① 남는 예약을 만료 처리하고 세션 재고(reserved_qty)를 되돌리세요. ② 동시 요청에서 예약이 두 번 생기지 않게 (세션, 상품, 회원) 부분 유일 색인을 검토하세요.', 915),
 ('integrity.wpl_live_reservation_stale', 'integrity', '만료된 라이브 예약 방치(사이트별)',
  '라이브 예약이 만료 시각(params.grace_minutes 여유)을 넘겼는데 장바구니·결제 중 상태로 남아 세션 재고를 잡고 있는지 봅니다.',
  'wpl_qg_probe_live_reservation_stale', 'medium', 'tenant', 'daily', '{"grace_minutes":60,"limit":200}'::jsonb, '0건',
  '① 그 세션 상품을 다시 열면 서버가 만료 예약을 정리합니다(expireStaleLiveReservations). ② 방송이 끝난 세션이면 관리자 → 라이브에서 예약을 만료 처리하고 재고를 되돌리세요.', 920),
 ('integrity.wpl_live_inventory_oversell', 'integrity', '라이브 재고 초과 판매(사이트별)',
  '라이브 세션 배정 재고보다 예약+판매 수량이 많은지 봅니다(params.include_safety=true 면 안전 재고까지).',
  'wpl_qg_probe_live_inventory_oversell', 'high', 'tenant', 'daily', '{"include_safety":false,"limit":200}'::jsonb, '0건',
  '① 초과된 만큼 주문 배송이 가능한지 창고 재고를 확인하세요. ② 배정 수량을 줄인 기록이 있으면 되돌리거나 초과 주문 고객에게 안내하세요.', 925),
 ('integrity.wpl_settlement_amount', 'integrity', '정산 실지급액 정합성',
  '분양 조직·크리에이터 정산서의 실지급액 = 수수료 − 원천징수인지, 지급 완료 정산서에 지급 시각이 있는지, 음수 금액이 없는지 봅니다.',
  'wpl_qg_probe_settlement_amount', 'critical', 'platform', 'daily', '{"tolerance":0,"limit":200}'::jsonb, '0건',
  '① 관리자 → 정산에서 그 정산서의 원천징수 계산을 다시 확인하세요(3.3%). ② 이미 지급됐으면 차액을 다음 정산에 반영하고 사유를 남기세요.', 930),
 ('integrity.wpl_flash_deal_oversell', 'integrity', '타임딜 한정 수량 초과',
  '타임딜마다 잡힘(held)+결제(paid) 수량 합이 한정 수량보다 많은지 봅니다.',
  'wpl_qg_probe_flash_deal_oversell', 'high', 'platform', 'daily', '{"limit":200}'::jsonb, '0건',
  '① 초과 주문을 확인해 배송 가능 여부를 정하세요. ② claim_flash_deal_with 의 수량 잠금을 점검하세요.', 935),
 ('security.wpl_site_tables', 'security', '사이트 표 RLS·익명 쓰기 정책',
  'WITH+·LIVE+ 표(이름 끝 _with·_live)에 RLS 가 꺼져 있거나, 익명·공개 역할이 조건 없이(true) 쓸 수 있는 정책이 있는지 봅니다(공유 DB 라 키트 보안 검사는 QG 자신만 봄).',
  'wpl_qg_probe_security_site_tables', 'critical', 'platform', 'hourly', '{"exclude":{}}'::jsonb, '0건',
  '① alter table public.<표> enable row level security; ② 익명 쓰기 정책은 지우고 서버(서비스 키) 경유로 바꾸세요. 의도된 공개 표면 params.exclude 에 사유와 함께 넣으세요.', 900),
 ('security.wpl_site_anon_definer', 'security', '익명 실행 사이트 DEFINER 함수',
  '이름이 _with·_live 로 끝나는 SECURITY DEFINER 함수를 익명이 실행할 수 있는지 봅니다(다른 제품 이름은 params.exclude_prefixes).',
  'wpl_qg_probe_security_site_anon_definer', 'critical', 'platform', 'hourly',
  '{"exclude_prefixes":["pg_","bz_"],"allowed":{}}'::jsonb, '0건',
  '① revoke all on function public.<함수> from public, anon; ② 정당한 공개 함수면 params.allowed 에 {"함수 이름":"사유"}로 넣으세요.', 905)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk,
  scope = excluded.scope, schedule = excluded.schedule, expect = excluded.expect, remediation = excluded.remediation, engine_code = excluded.engine_code, sort = excluded.sort;

-- ───────── 개선 신호 probe(evolution) ─────────
-- ① 최근 주문 취소율이 높음(결제 이탈·품절·가격 문제 신호)
create or replace function public.wpl_qg_probe_evo_order_cancel_rate(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_days int := greatest(7, coalesce((p_check.params->>'days')::int, 90)); v_min int := greatest(1, coalesce((p_check.params->>'min')::int, 20));
        v_rate numeric := coalesce((p_check.params->>'rate')::numeric, 0.3); v_tot int; v_cxl int; v_pending int;
begin
  select count(*), count(*) filter (where status = 'cancelled'), count(*) filter (where status = 'cancelled' and coalesce(payment_method, 'pending') = 'pending')
    into v_tot, v_cxl, v_pending
    from public.orders_with where created_at > now() - make_interval(days => v_days);
  if v_tot < v_min or v_cxl::numeric / v_tot < v_rate then return '[]'::jsonb; end if;
  return jsonb_build_array(jsonb_build_object('status', 'pass', 'fingerprint', 'order_cancel_rate',
    'title', format('개선 신호: 최근 %s일 주문 취소 %s%%', v_days, round(v_cxl * 100.0 / v_tot)),
    'detail', jsonb_build_object('signal', true, 'orders', v_tot, 'cancelled', v_cxl, 'cancelled_before_payment', v_pending,
      'proposal', jsonb_build_object('fingerprint', 'order_cancel_rate', 'source', 'order_cancel',
        'title', '주문 취소(결제 전 이탈) 줄이기',
        'problem', format('최근 %s일 주문 %s건 중 %s건(%s%%)이 취소됐고, 그중 %s건은 결제 전에 취소됐습니다. 결제 단계 이탈·가격·배송비 안내를 점검할 필요가 있습니다.', v_days, v_tot, v_cxl, round(v_cxl * 100.0 / v_tot), v_pending),
        'scope', '주문서·결제 화면(cart.html·결제 연동), 배송비 안내, 장바구니 리마인드',
        'acceptance', format('다음 %s일 주문 취소율이 %s%% 미만', v_days, round(v_rate * 100)),
        'verification', '품질·거버넌스 → 개선 엔진 지금 실행 후 이 신호가 사라졌는지 확인',
        'reach', v_cxl, 'impact', 3, 'confidence', 2, 'effort', 3))));
end $$;
revoke all on function public.wpl_qg_probe_evo_order_cancel_rate(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ② 라이브 예약 이탈(만료·취소) 비율(사이트별)
create or replace function public.wpl_qg_probe_evo_live_cart_abandon(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_s text := public.wpl_qg_site_suffix_internal(p_tenant); v_t text; v_days int := greatest(7, coalesce((p_check.params->>'days')::int, 90));
        v_min int := greatest(1, coalesce((p_check.params->>'min')::int, 10)); v_rate numeric := coalesce((p_check.params->>'rate')::numeric, 0.4);
        v_tot int; v_drop int; v_label text := public.wpl_qga_tenant_label(p_tenant);
begin
  v_t := 'live_session_reservations' || coalesce(v_s, '');
  if v_s is null or to_regclass('public.' || v_t) is null then return '[]'::jsonb; end if;
  execute format('select count(*), count(*) filter (where status in (''expired'',''cancelled'')) from public.%I where created_at > now() - make_interval(days => $1)', v_t)
    into v_tot, v_drop using v_days;
  if v_tot < v_min or v_drop::numeric / v_tot < v_rate then return '[]'::jsonb; end if;
  return jsonb_build_array(jsonb_build_object('status', 'pass', 'fingerprint', 'live_cart_abandon',
    'title', format('개선 신호: %s 라이브 예약 이탈 %s%%', v_label, round(v_drop * 100.0 / v_tot)),
    'detail', jsonb_build_object('signal', true, 'reservations', v_tot, 'dropped', v_drop,
      'proposal', jsonb_build_object('fingerprint', 'live_cart_abandon_' || v_s, 'source', 'live_cart_abandon', 'tenant_id', p_tenant,
        'title', v_label || ' 라이브 예약 → 주문 전환 높이기',
        'problem', format('최근 %s일 라이브 예약 %s건 중 %s건(%s%%)이 만료·취소됐습니다. 예약 시간(장바구니 유지)·결제 동선을 점검할 필요가 있습니다.', v_days, v_tot, v_drop, round(v_drop * 100.0 / v_tot)),
        'scope', '라이브 시청 화면 예약·결제 동선, 예약 유지 시간, 만료 직전 알림',
        'acceptance', format('다음 %s일 라이브 예약 이탈 비율 %s%% 미만', v_days, round(v_rate * 100)),
        'verification', '품질·거버넌스 → 개선 엔진 지금 실행 후 신호 확인',
        'reach', v_drop, 'impact', 3, 'confidence', 2, 'effort', 2))));
end $$;
revoke all on function public.wpl_qg_probe_evo_live_cart_abandon(public.wpl_qg_checks, uuid) from public, anon, authenticated;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('evolution.wpl_order_cancel_rate', 'evolution', '주문 취소율 신호', '최근 기간(params.days) 주문 중 취소 비율이 기준(params.rate) 이상이면 개선 제안을 만듭니다.',
  'wpl_qg_probe_evo_order_cancel_rate', 'low', 'platform', 'daily', '{"days":90,"min":20,"rate":0.3}'::jsonb, '신호는 개선 제안 보드로 갑니다(이슈 아님)',
  '개선 제안 보드에서 채택·거절하고, 채택하면 개발 지시서를 내보내세요.', 900),
 ('evolution.wpl_live_cart_abandon', 'evolution', '라이브 예약 이탈 신호(사이트별)', '최근 기간 라이브 예약 중 만료·취소 비율이 기준 이상이면 그 사이트의 개선 제안을 만듭니다.',
  'wpl_qg_probe_evo_live_cart_abandon', 'low', 'tenant', 'daily', '{"days":90,"min":10,"rate":0.4}'::jsonb, '신호는 개선 제안 보드로 갑니다(이슈 아님)',
  '개선 제안 보드에서 채택·거절하세요.', 910)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk,
  scope = excluded.scope, schedule = excluded.schedule, expect = excluded.expect, remediation = excluded.remediation, engine_code = excluded.engine_code, sort = excluded.sort;

-- ───────── 4) 준법 대상 먼저 → 업종 법령(검토 필요: last_reviewed_at 비움) ─────────
insert into public.wpl_qg_compliance_targets(kind, code, name, description, tenants) values
 ('feature', 'wpl_live_commerce', '라이브 커머스 방송 판매', 'WITH+·LIVE+ 라이브 방송 중 상품 예약·주문(live_sessions_*)', 2),
 ('feature', 'wpl_order_checkout', '주문·결제·청약철회', '주문서·PG 결제(토스·카카오·네이버)·취소·반품(orders_with)', 2),
 ('feature', 'wpl_flash_deal', '타임딜·할인 표시', '한정 수량 타임딜·할인가 표시(flash_deals_with)', 1),
 ('feature', 'wpl_marketing_push', '마케팅 알림·이메일', '광고성 이메일·푸시·알림톡 발송(marketing_campaigns_with·push_subscriptions_with)', 2),
 ('feature', 'wpl_mileage', '마일리지·시리얼 쿠폰', '마일리지 적립·사용·시리얼 쿠폰 마일리지 지급', 1),
 ('policy', 'wpl_withholding_tax', '정산 원천징수 3.3%', '분양 조직·크리에이터 정산의 사업소득 원천징수(computeSettlementTaxFields)', 1),
 ('feature', 'wpl_subscription', '정기배송', '상품 정기배송 구독(product_subscriptions_with)', 1)
on conflict (kind, code) do nothing;

insert into public.wpl_qg_regulations(code, name, law_name, article, kind, summary, source_url, review_cycle_days, links, keywords, note, sort) values
 ('wpl_ecommerce_withdrawal', '전자상거래법 제17조 — 청약철회(7일)', '전자상거래 등에서의 소비자보호에 관한 법률', '제17조', 'law',
  '통신판매로 산 소비자는 원칙적으로 받은 날부터 7일 안에 청약을 철회할 수 있다. 라이브 방송 주문·정기배송도 같이 적용된다. 반품·취소 화면과 안내 문구가 영향을 받는다.',
  'https://www.law.go.kr/법령/전자상거래등에서의소비자보호에관한법률', 365, '{"feature":["wpl_order_checkout","wpl_live_commerce","wpl_subscription"]}'::jsonb,
  array['청약철회','반품','취소','7일'], '검토 필요: 동생 초안 — 예외(훼손·맞춤 제작 등)와 화면 문구는 형님 확인 전', 100),
 ('wpl_ecommerce_disclosure', '전자상거래법 제13조 — 신원·거래조건 표시', '전자상거래 등에서의 소비자보호에 관한 법률', '제13조', 'law',
  '통신판매업자는 상호·대표자·주소·사업자등록번호·통신판매업 신고번호와 거래조건(배송·환불)을 표시해야 한다. 하단 사업자정보·상품 상세 거래조건이 영향을 받는다.',
  'https://www.law.go.kr/법령/전자상거래등에서의소비자보호에관한법률', 365, '{"feature":["wpl_order_checkout","wpl_live_commerce"]}'::jsonb,
  array['사업자정보','통신판매업','거래조건'], '검토 필요: 동생 초안 — WITH+·LIVE+ 사업자정보 키가 다름(platform_business_info / _live)', 110),
 ('wpl_fair_labeling_discount', '표시광고법 제3조 — 부당한 표시·광고(할인·한정 표시)', '표시·광고의 공정화에 관한 법률', '제3조', 'law',
  '거짓·과장된 할인율, 실제와 다른 한정 수량·마감 표시는 부당 표시·광고가 될 수 있다. 타임딜·라이브 할인가 표시가 영향을 받는다.',
  'https://www.law.go.kr/법령/표시ㆍ광고의공정화에관한법률', 365, '{"feature":["wpl_flash_deal","wpl_live_commerce"]}'::jsonb,
  array['할인','한정','타임딜','과장 광고'], '검토 필요: 동생 초안', 120),
 ('wpl_network_ad_consent', '정보통신망법 제50조 — 광고성 정보 전송 제한', '정보통신망 이용촉진 및 정보보호 등에 관한 법률', '제50조', 'law',
  '광고성 정보는 미리 받은 수신 동의가 있어야 보낼 수 있고, (광고) 표시·수신거부 방법을 넣어야 하며 야간(21시~8시) 전송은 별도 동의가 필요하다. 마케팅 이메일·푸시·알림톡이 영향을 받는다.',
  'https://www.law.go.kr/법령/정보통신망이용촉진및정보보호등에관한법률', 365, '{"feature":["wpl_marketing_push"]}'::jsonb,
  array['광고성 정보','수신 동의','야간','수신거부'], '검토 필요: 동생 초안 — profiles.marketing_consent 와 발송 대상 조건 확인 전', 130),
 ('wpl_income_tax_withholding', '소득세법 제127조·제129조 — 사업소득 원천징수(3%)', '소득세법', '제127조, 제129조', 'law',
  '개인에게 사업소득(수수료)을 지급할 때 지급액의 3%(지방소득세 포함 3.3%)를 원천징수해 신고·납부해야 한다. 분양 조직·크리에이터 정산 실지급액 계산이 영향을 받는다.',
  'https://www.law.go.kr/법령/소득세법', 365, '{"policy":["wpl_withholding_tax"]}'::jsonb,
  array['원천징수','3.3%','사업소득','정산'], '검토 필요: 동생 초안 — 세율·신고 주기는 세무 확인 전', 140),
 ('wpl_efinance_prepaid', '전자금융거래법 — 선불전자지급수단 해당 여부(마일리지)', '전자금융거래법', '제2조·제28조', 'law',
  '현금처럼 쓰이는 적립금이 일정 요건을 넘으면 선불전자지급수단 규제(등록·발행 한도)가 문제될 수 있다. 마일리지 적립·사용·시리얼 쿠폰 지급 방식이 영향을 받는다.',
  'https://www.law.go.kr/법령/전자금융거래법', 365, '{"feature":["wpl_mileage"]}'::jsonb,
  array['마일리지','선불전자지급수단','적립금'], '검토 필요: 동생 초안 — 해당 여부 자체가 전문가 판단 사항', 150)
on conflict (code) do nothing;

-- ───────── 위험 항목·테스트 스위트·공격 시나리오 ─────────
insert into public.wpl_qg_risk_items(code, name, description, target_kind, target_ref, impact, likelihood, sort) values
 ('wpl_order_payment', '주문 금액·결제', '쿠폰·마일리지·배송비가 섞인 결제 금액 계산과 PG 승인 연결', 'table', 'orders_with', 5, 3, 100),
 ('wpl_settlement', '분양·크리에이터 정산', '수수료·원천징수·실지급액 계산과 지급 기록', 'table', 'community_settlements_with', 5, 2, 110),
 ('wpl_live_inventory', '라이브 예약·재고', '라이브 세션 재고 선점·확정·만료 해제(사이트별)', 'table', 'live_session_inventory_live', 4, 3, 120),
 ('wpl_coupon_mileage', '쿠폰·마일리지', '쿠폰 수령·시리얼 쿠폰 마일리지 지급(돈과 같은 가치)', 'table', 'serial_coupons_with', 4, 3, 130),
 ('wpl_profile_role', '역할·권한(공유 profiles)', 'GMWOS·WITH+·LIVE+ 가 함께 쓰는 profiles.role·is_owner', 'table', 'profiles', 5, 2, 140)
on conflict (code) do nothing;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('testing.suite_sql_wpl_platform', 'testing', 'WITH+·LIVE+ 업무 정합성 probe 스모크',
  '업무 표에 결함 행을 심어(rollback) 정합성 probe 8종·사이트 보안 2종·개선 신호 2종이 실제로 잡는지, 정상 행·다른 사이트는 안 잡는지 확인합니다.',
  'suite:supabase/tests/20261027120013_wpl_qg_platform_smoke.sql', 'high', 'platform', 'release', '{}'::jsonb, '모든 단계 통과(failed=0)',
  'node scripts/qg-run.mjs testing 로 다시 돌려 실패 단계를 확인하세요.', 950),
 ('adversarial.wpl_anon_business', 'adversarial', '익명 업무 표 공격', '로그인 없이 주문·쿠폰·재고·시리얼 쿠폰을 읽거나 바꾸려는 시도가 모두 막히는지 봅니다.',
  'scenario:wpl_anon_business', 'critical', 'platform', 'release', '{}'::jsonb, 'PASS', '실패 단계의 표 RLS·함수 권한을 고치세요.', 960),
 ('adversarial.wpl_money_tamper', 'adversarial', '금액·마일리지 조작', '로그인 회원이 자기 주문 금액·마일리지·시리얼 쿠폰·정산을 직접 바꾸려는 시도가 막히는지 봅니다.',
  'scenario:wpl_money_tamper', 'critical', 'platform', 'release', '{}'::jsonb, 'PASS', '실패 단계의 표 RLS 를 고치세요(돈은 서버 경유만).', 961),
 ('adversarial.wpl_privilege_escalation', 'adversarial', '역할·권한 상승', '회원이 공유 profiles 의 역할·대표자 표시를 스스로 올리거나 QG 관리 기능을 쓰려는 시도가 막히는지 봅니다.',
  'scenario:wpl_privilege_escalation', 'critical', 'platform', 'release', '{}'::jsonb, 'PASS', 'profiles 가드 트리거(guard_role_change)·QG 권한을 확인하세요.', 962),
 ('adversarial.wpl_cross_user_site', 'adversarial', '다른 회원·다른 사이트 침범', '회원이 다른 회원의 주문·라이브 예약을 읽거나, 다른 사이트(LIVE+) 쿠폰 수령 기록을 남에게 넣으려는 시도가 막히는지 봅니다.',
  'scenario:wpl_cross_user_site', 'high', 'platform', 'release', '{}'::jsonb, 'PASS', '실패 단계의 표 RLS 를 고치세요.', 963)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk,
  scope = excluded.scope, schedule = excluded.schedule, expect = excluded.expect, remediation = excluded.remediation, engine_code = excluded.engine_code, sort = excluded.sort;

insert into public.wpl_qg_test_suites(code, name, kind, path, depths, check_code, risk_items, description, sort) values
 ('sql_wpl_platform', 'WITH+·LIVE+ 업무 정합성 probe 스모크', 'sql', 'supabase/tests/20261027120013_wpl_qg_platform_smoke.sql', '["smoke","attack"]'::jsonb,
  'testing.suite_sql_wpl_platform', '["wpl_order_payment","wpl_settlement","wpl_live_inventory","wpl_coupon_mileage"]'::jsonb,
  '결함 심기 → 정합성 엔진 → 잡힘·안 잡힘·경계값·다른 사이트 확인(rollback)', 100)
on conflict (code) do nothing;

insert into public.wpl_qg_scenarios(code, name, category, description, expected, severity, script, check_code, risk_items, sort) values
 ('wpl_anon_business', '익명 업무 표 공격', 'attack', '익명(anon)으로 주문·시리얼 쿠폰 읽기, 상품 가격·재고 바꾸기, 쿠폰 수령 넣기, 라이브 재고 함수 호출',
  '모두 거부되거나 0행, 심은 재고 수량 그대로', 'critical', 'supabase/tests/qg/adversarial_wpl_platform.sql', 'adversarial.wpl_anon_business', '["wpl_order_payment","wpl_live_inventory"]'::jsonb, 100),
 ('wpl_money_tamper', '금액·마일리지 조작', 'attack', '회원이 자기 주문 결제 금액 낮추기, 마일리지 적립 넣기, 시리얼 쿠폰 사용 표시 바꾸기, 정산서 금액 바꾸기',
  '모두 거부되거나 0행, 금액 그대로', 'critical', 'supabase/tests/qg/adversarial_wpl_platform.sql', 'adversarial.wpl_money_tamper', '["wpl_order_payment","wpl_coupon_mileage","wpl_settlement"]'::jsonb, 110),
 ('wpl_privilege_escalation', '역할·권한 상승', 'attack', '회원이 자기 profiles.role 을 super_admin 으로, is_owner 를 true 로 바꾸기, QG 엔진 실행·카탈로그 읽기',
  '역할·대표자 표시 그대로, QG 거부·0행', 'critical', 'supabase/tests/qg/adversarial_wpl_platform.sql', 'adversarial.wpl_privilege_escalation', '["wpl_profile_role"]'::jsonb, 120),
 ('wpl_cross_user_site', '다른 회원·다른 사이트 침범', 'attack', '회원 A 가 회원 B 의 주문·LIVE+ 라이브 예약 읽기, 회원 B 이름으로 LIVE+ 쿠폰 수령 넣기',
  '0행·거부', 'high', 'supabase/tests/qg/adversarial_wpl_platform.sql', 'adversarial.wpl_cross_user_site', '["wpl_order_payment","wpl_live_inventory"]'::jsonb, 130)
on conflict (code) do nothing;
