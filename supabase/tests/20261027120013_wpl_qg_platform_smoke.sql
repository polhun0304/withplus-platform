-- =====================================================================
-- QG 플랫폼 스모크(WITH+ · LIVE+, 접두어 wpl) — 업무 정합성 probe 8종·사이트 보안 2종·개선 신호 2종·어댑터 확장. 항상 rollback(운영 데이터 무변경).
--  결함 행을 이 트랜잭션 안에서 심고 → 엔진 실행 → ① 결함은 '실패'로 잡힘 ② 같은 사이트 정상 행은 안 잡힘 ③ 경계값(같음 통과·1 초과 실패) ④ 다른 사이트 범위 분리.
--  결과: 단계마다 (step, ok, msg) + 마지막 SUMMARY passed=N failed=M.  실행: node scripts/qg-run.mjs testing
-- =====================================================================
begin;
create temp table r(n serial, step text, ok boolean, msg text);
create temp table fx(k text primary key, v text);
create function pg_temp.chk(p_step text, p_sql text) returns void language plpgsql as $f$
declare v text;
begin
  begin execute p_sql into v; insert into r(step, ok, msg) values (p_step, v = 'true', 'got=' || coalesce(left(v, 300), 'null'));
  exception when others then insert into r(step, ok, msg) values (p_step, false, 'err: ' || left(sqlerrm, 300)); end;
end $f$;
create function pg_temp.put(p_k text, p_sql text) returns void language plpgsql as $f$
declare v text;
begin
  begin execute p_sql into v; insert into fx values (p_k, v) on conflict (k) do update set v = excluded.v;
  exception when others then insert into r(step, ok, msg) values ('put_' || p_k, false, 'err: ' || left(sqlerrm, 300)); end;
end $f$;
create function pg_temp.v(p_k text) returns text language sql as $f$ select v from fx where k = p_k $f$;
-- 결과 지문: '검사코드|테넌트(또는 *)|probe 지문'
create function pg_temp.st(p_run text, p_check text, p_tenant text, p_fp text) returns text language sql as $f$
  select f.status from public.wpl_qg_findings f
   where f.run_id = pg_temp.v(p_run)::uuid and f.check_code = p_check and f.fingerprint = p_check || '|' || coalesce(p_tenant, '*') || '|' || p_fp
   limit 1
$f$;

insert into fx select key, value from jsonb_each_text(public.wpl_qga_smoke_fixture()) where value is not null;
insert into fx values ('W', 'a17e0000-0000-4000-8000-000000000001'), ('L', 'a17e0000-0000-4000-8000-000000000002'), ('tag', 'qgs' || substr(md5(clock_timestamp()::text), 1, 8));
select pg_temp.put('prod', $q$select id::text from public.products_with order by created_at limit 1$q$);

-- ───────── 결함·정상 행 심기 ─────────
-- 주문: o_ok(정상·경계: 결제 = 10000 − 1000 − 500 + 3000 = 11500), o_bad(1원 차이), o_items(줄 합 ≠ 상품 합계), o_paidnull(결제 완료인데 결제 수단 없음), o_paidcard(정상)
select pg_temp.put('o_ok', $q$insert into public.orders_with(order_number, user_id, items, total_price, discount_amount, used_mileage, shipping_fee, final_price, status, payment_method)
  values (pg_temp.v('tag') || '-ok', pg_temp.v('outsider')::uuid, '[{"price":5000,"quantity":2}]', 10000, 1000, 500, 3000, 11500, 'paid', 'card') returning id::text$q$);
select pg_temp.put('o_bad', $q$insert into public.orders_with(order_number, user_id, items, total_price, discount_amount, used_mileage, shipping_fee, final_price, status, payment_method)
  values (pg_temp.v('tag') || '-bad', pg_temp.v('outsider')::uuid, '[{"price":5000,"quantity":2}]', 10000, 1000, 500, 3000, 11499, 'paid', 'card') returning id::text$q$);
select pg_temp.put('o_items', $q$insert into public.orders_with(order_number, user_id, items, total_price, discount_amount, used_mileage, shipping_fee, final_price, status, payment_method)
  values (pg_temp.v('tag') || '-it', pg_temp.v('outsider')::uuid, '[{"price":5000,"quantity":1}]', 10000, 0, 0, 0, 10000, 'paid', 'card') returning id::text$q$);
select pg_temp.put('o_paidnull', $q$insert into public.orders_with(order_number, user_id, items, total_price, final_price, status, payment_method)
  values (pg_temp.v('tag') || '-pn', pg_temp.v('outsider')::uuid, '[{"price":7000,"quantity":1}]', 7000, 7000, 'shipped', 'pending') returning id::text$q$);
select pg_temp.put('o_cxl', $q$insert into public.orders_with(order_number, user_id, items, total_price, final_price, status, payment_method)
  values (pg_temp.v('tag') || '-cx', pg_temp.v('outsider')::uuid, '[{"price":7000,"quantity":1}]', 7000, 7000, 'cancelled', 'pending') returning id::text$q$);

-- 시리얼 쿠폰: 정상 미사용 · 정상 사용 · 사용됨인데 사용자 없음 · 유효기간 뒤 사용 · 경계(만료 시각과 같은 시각 사용 = 통과)
select pg_temp.put('sc_ok', $q$insert into public.serial_coupons_with(batch_name, code, reward_mileage) values ('QG 스모크', pg_temp.v('tag') || 'A', 1000) returning id::text$q$);
select pg_temp.put('sc_used', $q$insert into public.serial_coupons_with(batch_name, code, reward_mileage, is_redeemed, redeemed_by, redeemed_at, expires_at)
  values ('QG 스모크', pg_temp.v('tag') || 'B', 1000, true, pg_temp.v('outsider')::uuid, now() - interval '1 day', now()) returning id::text$q$);
select pg_temp.put('sc_noby', $q$insert into public.serial_coupons_with(batch_name, code, reward_mileage, is_redeemed, redeemed_at) values ('QG 스모크', pg_temp.v('tag') || 'C', 1000, true, now()) returning id::text$q$);
select pg_temp.put('sc_late', $q$insert into public.serial_coupons_with(batch_name, code, reward_mileage, is_redeemed, redeemed_by, redeemed_at, expires_at)
  values ('QG 스모크', pg_temp.v('tag') || 'D', 1000, true, pg_temp.v('outsider')::uuid, now() - interval '1 day' + interval '1 second', now() - interval '1 day') returning id::text$q$);
select pg_temp.put('sc_edge', $q$insert into public.serial_coupons_with(batch_name, code, reward_mileage, is_redeemed, redeemed_by, redeemed_at, expires_at)
  values ('QG 스모크', pg_temp.v('tag') || 'E', 1000, true, pg_temp.v('outsider')::uuid, now() - interval '2 day', now() - interval '2 day') returning id::text$q$);

-- 라이브: 사이트마다 채널·세션 2개
select pg_temp.put('chw', $q$insert into public.channels_with(slug, name, channel_type) values (pg_temp.v('tag') || '-w', 'QG 스모크 W', 'brand') returning id::text$q$);
select pg_temp.put('chl', $q$insert into public.channels_live(slug, name, channel_type) values (pg_temp.v('tag') || '-l', 'QG 스모크 L', 'brand') returning id::text$q$);
select pg_temp.put('sw1', $q$insert into public.live_sessions_with(channel_id, title) values (pg_temp.v('chw')::uuid, 'QG W1') returning id::text$q$);
select pg_temp.put('sw2', $q$insert into public.live_sessions_with(channel_id, title) values (pg_temp.v('chw')::uuid, 'QG W2') returning id::text$q$);
select pg_temp.put('sl1', $q$insert into public.live_sessions_live(channel_id, title) values (pg_temp.v('chl')::uuid, 'QG L1') returning id::text$q$);
-- 재고: W1 경계(배정 10 = 예약 4 + 판매 6 → 통과), W2 초과(배정 5 < 예약 3 + 판매 3), L1 초과
select pg_temp.put('iw1', $q$insert into public.live_session_inventory_with(live_session_id, product_id, allocated_qty, reserved_qty, sold_qty) values (pg_temp.v('sw1')::uuid, pg_temp.v('prod')::uuid, 10, 4, 6) returning id::text$q$);
select pg_temp.put('iw2', $q$insert into public.live_session_inventory_with(live_session_id, product_id, allocated_qty, reserved_qty, sold_qty) values (pg_temp.v('sw2')::uuid, pg_temp.v('prod')::uuid, 5, 3, 3) returning id::text$q$);
select pg_temp.put('il1', $q$insert into public.live_session_inventory_live(live_session_id, product_id, allocated_qty, reserved_qty, sold_qty) values (pg_temp.v('sl1')::uuid, pg_temp.v('prod')::uuid, 1, 1, 1) returning id::text$q$);
-- 예약: W 만료 2시간 지난 장바구니(잡힘) · W 만료 30분 지난 장바구니(유예 60분 안 — 안 잡힘) · W 오래전 만료된 확정(안 잡힘) · L 만료 3시간 지난 결제 중(LIVE+ 에서만 잡힘)
select pg_temp.put('rw_stale', $q$insert into public.live_session_reservations_with(live_session_id, product_id, user_id, quantity, status, expires_at) values (pg_temp.v('sw1')::uuid, pg_temp.v('prod')::uuid, pg_temp.v('outsider')::uuid, 1, 'cart', now() - interval '2 hours') returning id::text$q$);
select pg_temp.put('rw_grace', $q$insert into public.live_session_reservations_with(live_session_id, product_id, user_id, quantity, status, expires_at) values (pg_temp.v('sw2')::uuid, pg_temp.v('prod')::uuid, pg_temp.v('admin1')::uuid, 1, 'cart', now() - interval '30 minutes') returning id::text$q$);
select pg_temp.put('rw_conf', $q$insert into public.live_session_reservations_with(live_session_id, product_id, user_id, quantity, status, expires_at) values (pg_temp.v('sw2')::uuid, pg_temp.v('prod')::uuid, pg_temp.v('admin2')::uuid, 1, 'confirmed', now() - interval '10 days') returning id::text$q$);
select pg_temp.put('rl_stale', $q$insert into public.live_session_reservations_live(live_session_id, product_id, user_id, quantity, status, expires_at) values (pg_temp.v('sl1')::uuid, pg_temp.v('prod')::uuid, pg_temp.v('outsider')::uuid, 2, 'checkout', now() - interval '3 hours') returning id::text$q$);
-- 이중 선점: W1 에서 outsider 가 열린 예약 2건(rw_stale + rw_dup) → 잡힘. W2 의 admin1 열린 1건 + admin2 확정 1건 → 안 잡힘
select pg_temp.put('rw_dup', $q$insert into public.live_session_reservations_with(live_session_id, product_id, user_id, quantity, status, expires_at) values (pg_temp.v('sw1')::uuid, pg_temp.v('prod')::uuid, pg_temp.v('outsider')::uuid, 1, 'checkout', now() + interval '10 minutes') returning id::text$q$);

-- 정산: 분양 조직(정상 10000−330=9670 · 1원 차이 · 지급 완료인데 지급 시각 없음), 크리에이터(1원 차이)
select pg_temp.put('cm', $q$insert into public.communities(name, slug) values ('QG 스모크 조직', pg_temp.v('tag') || '-c') returning id::text$q$);
select pg_temp.put('cs_ok', $q$insert into public.community_settlements_with(community_id, period_start, period_end, commission_amount, withholding_tax_amount, net_payment_amount, status)
  values (pg_temp.v('cm')::uuid, date '2020-01-01', date '2020-01-31', 10000, 330, 9670, 'pending') returning id::text$q$);
select pg_temp.put('cs_bad', $q$insert into public.community_settlements_with(community_id, period_start, period_end, commission_amount, withholding_tax_amount, net_payment_amount, status)
  values (pg_temp.v('cm')::uuid, date '2020-02-01', date '2020-02-29', 10000, 330, 9671, 'pending') returning id::text$q$);
select pg_temp.put('cs_paid', $q$insert into public.community_settlements_with(community_id, period_start, period_end, commission_amount, withholding_tax_amount, net_payment_amount, status, paid_at)
  values (pg_temp.v('cm')::uuid, date '2020-03-01', date '2020-03-31', 10000, 330, 9670, 'paid', null) returning id::text$q$);
select pg_temp.put('cr', $q$insert into public.creators_with(display_name) values ('QG 스모크 크리에이터') returning id::text$q$);
select pg_temp.put('crs_bad', $q$insert into public.creator_settlements_with(creator_id, period_start, period_end, commission_rate, commission_amount, withholding_tax_amount, net_payment_amount, status)
  values (pg_temp.v('cr')::uuid, date '2020-01-01', date '2020-01-31', 10, 5000, 165, 4836, 'pending') returning id::text$q$);

-- 타임딜: fd_edge 한정 2 = 잡힘 1 + 결제 1(통과) · fd_over 한정 2 < 3(실패) · 풀린(released) 수량은 세지 않음
select pg_temp.put('fd_edge', $q$insert into public.flash_deals_with(product_id, deal_price, limit_qty, starts_at, ends_at) values (pg_temp.v('prod')::uuid, 1000, 2, now() - interval '1 hour', now() + interval '1 hour') returning id::text$q$);
select pg_temp.put('fd_over', $q$insert into public.flash_deals_with(product_id, deal_price, limit_qty, starts_at, ends_at) values (pg_temp.v('prod')::uuid, 1000, 2, now() - interval '1 hour', now() + interval '1 hour') returning id::text$q$);
select pg_temp.put('fdc1', $q$insert into public.flash_deal_claims_with(deal_id, order_id, product_id, quantity, status) values (pg_temp.v('fd_edge')::uuid, gen_random_uuid(), pg_temp.v('prod')::uuid, 1, 'held') returning id::text$q$);
select pg_temp.put('fdc2', $q$insert into public.flash_deal_claims_with(deal_id, order_id, product_id, quantity, status) values (pg_temp.v('fd_edge')::uuid, gen_random_uuid(), pg_temp.v('prod')::uuid, 1, 'paid') returning id::text$q$);
select pg_temp.put('fdc3', $q$insert into public.flash_deal_claims_with(deal_id, order_id, product_id, quantity, status) values (pg_temp.v('fd_edge')::uuid, gen_random_uuid(), pg_temp.v('prod')::uuid, 5, 'released') returning id::text$q$);
select pg_temp.put('fdc4', $q$insert into public.flash_deal_claims_with(deal_id, order_id, product_id, quantity, status) values (pg_temp.v('fd_over')::uuid, gen_random_uuid(), pg_temp.v('prod')::uuid, 3, 'held') returning id::text$q$);

select pg_temp.chk('fixture_rows_planted', $q$select (select count(*) from fx where v is not null and k in ('prod','o_ok','o_bad','o_items','o_paidnull','o_cxl','sc_ok','sc_used','sc_noby','sc_late','sc_edge','chw','chl','sw1','sw2','sl1','iw1','iw2','il1',
  'rw_stale','rw_grace','rw_conf','rl_stale','rw_dup','cm','cs_ok','cs_bad','cs_paid','cr','crs_bad','fd_edge','fd_over','fdc1','fdc2','fdc3','fdc4')) = 36$q$);

-- ───────── 정합성 엔진 실행(플랫폼 + 사이트 2개) ─────────
select pg_temp.put('run', $q$select public.wpl_qg_run_engine_internal('integrity', null, 'manual', null, null, '{"smoke":"wpl_platform"}'::jsonb)::text$q$);

-- ① 주문 금액
select pg_temp.chk('order_amount_caught_1won', $q$select pg_temp.st('run', 'integrity.wpl_order_amount', null, pg_temp.v('o_bad')) = 'fail'$q$);
select pg_temp.chk('order_amount_caught_items', $q$select pg_temp.st('run', 'integrity.wpl_order_amount', null, pg_temp.v('o_items')) = 'fail'$q$);
select pg_temp.chk('order_amount_edge_equal_not_caught', $q$select pg_temp.st('run', 'integrity.wpl_order_amount', null, pg_temp.v('o_ok')) is null$q$);
select pg_temp.chk('order_amount_issue_opened', $q$select exists (select 1 from public.wpl_qg_issues where check_code = 'integrity.wpl_order_amount' and tenant_id is null and fingerprint like '%|' || pg_temp.v('o_bad'))$q$);
-- ② 결제 상태
select pg_temp.chk('paid_state_caught', $q$select pg_temp.st('run', 'integrity.wpl_order_paid_state', null, pg_temp.v('o_paidnull')) = 'fail'$q$);
select pg_temp.chk('paid_state_card_not_caught', $q$select pg_temp.st('run', 'integrity.wpl_order_paid_state', null, pg_temp.v('o_ok')) is null$q$);
select pg_temp.chk('paid_state_cancelled_not_caught', $q$select pg_temp.st('run', 'integrity.wpl_order_paid_state', null, pg_temp.v('o_cxl')) is null$q$);
-- ③ 시리얼 쿠폰
select pg_temp.chk('serial_noby_caught', $q$select pg_temp.st('run', 'integrity.wpl_serial_coupon_state', null, pg_temp.v('sc_noby')) = 'fail'$q$);
select pg_temp.chk('serial_late_caught_1sec', $q$select pg_temp.st('run', 'integrity.wpl_serial_coupon_state', null, pg_temp.v('sc_late')) = 'fail'$q$);
select pg_temp.chk('serial_edge_equal_not_caught', $q$select pg_temp.st('run', 'integrity.wpl_serial_coupon_state', null, pg_temp.v('sc_edge')) is null$q$);
select pg_temp.chk('serial_ok_not_caught', $q$select pg_temp.st('run', 'integrity.wpl_serial_coupon_state', null, pg_temp.v('sc_ok')) is null and pg_temp.st('run', 'integrity.wpl_serial_coupon_state', null, pg_temp.v('sc_used')) is null$q$);
-- ④ 라이브 예약 이중 선점(사이트별)
select pg_temp.chk('resv_dup_caught_with', $q$select pg_temp.st('run', 'integrity.wpl_live_reservation_dup', pg_temp.v('W'), pg_temp.v('sw1') || ':' || pg_temp.v('prod') || ':' || pg_temp.v('outsider')) = 'fail'$q$);
select pg_temp.chk('resv_dup_single_not_caught', $q$select pg_temp.st('run', 'integrity.wpl_live_reservation_dup', pg_temp.v('W'), pg_temp.v('sw2') || ':' || pg_temp.v('prod') || ':' || pg_temp.v('admin1')) is null$q$);
select pg_temp.chk('resv_dup_not_in_live', $q$select not exists (select 1 from public.wpl_qg_findings where run_id = pg_temp.v('run')::uuid and check_code = 'integrity.wpl_live_reservation_dup'
   and tenant_id = pg_temp.v('L')::uuid and fingerprint like '%' || pg_temp.v('sw1') || '%')$q$);
-- ⑤ 만료 예약 방치(사이트별 · 유예 경계)
select pg_temp.chk('resv_stale_caught_with', $q$select pg_temp.st('run', 'integrity.wpl_live_reservation_stale', pg_temp.v('W'), pg_temp.v('rw_stale')) = 'fail'$q$);
select pg_temp.chk('resv_stale_grace_not_caught', $q$select pg_temp.st('run', 'integrity.wpl_live_reservation_stale', pg_temp.v('W'), pg_temp.v('rw_grace')) is null$q$);
select pg_temp.chk('resv_stale_confirmed_not_caught', $q$select pg_temp.st('run', 'integrity.wpl_live_reservation_stale', pg_temp.v('W'), pg_temp.v('rw_conf')) is null$q$);
select pg_temp.chk('resv_stale_caught_live_only', $q$select pg_temp.st('run', 'integrity.wpl_live_reservation_stale', pg_temp.v('L'), pg_temp.v('rl_stale')) = 'fail'
   and pg_temp.st('run', 'integrity.wpl_live_reservation_stale', pg_temp.v('W'), pg_temp.v('rl_stale')) is null$q$);
-- ⑥ 라이브 재고 초과(사이트별 · 경계)
select pg_temp.chk('inv_over_caught_with', $q$select pg_temp.st('run', 'integrity.wpl_live_inventory_oversell', pg_temp.v('W'), pg_temp.v('iw2')) = 'fail'$q$);
select pg_temp.chk('inv_edge_equal_not_caught', $q$select pg_temp.st('run', 'integrity.wpl_live_inventory_oversell', pg_temp.v('W'), pg_temp.v('iw1')) is null$q$);
select pg_temp.chk('inv_over_live_separate', $q$select pg_temp.st('run', 'integrity.wpl_live_inventory_oversell', pg_temp.v('L'), pg_temp.v('il1')) = 'fail'
   and pg_temp.st('run', 'integrity.wpl_live_inventory_oversell', pg_temp.v('L'), pg_temp.v('iw2')) is null$q$);
-- ⑦ 정산
select pg_temp.chk('settle_caught_1won', $q$select pg_temp.st('run', 'integrity.wpl_settlement_amount', null, 'community:' || pg_temp.v('cs_bad')) = 'fail'$q$);
select pg_temp.chk('settle_paid_without_time', $q$select pg_temp.st('run', 'integrity.wpl_settlement_amount', null, 'community:' || pg_temp.v('cs_paid')) = 'fail'$q$);
select pg_temp.chk('settle_creator_caught', $q$select pg_temp.st('run', 'integrity.wpl_settlement_amount', null, 'creator:' || pg_temp.v('crs_bad')) = 'fail'$q$);
select pg_temp.chk('settle_ok_not_caught', $q$select pg_temp.st('run', 'integrity.wpl_settlement_amount', null, 'community:' || pg_temp.v('cs_ok')) is null$q$);
-- ⑧ 타임딜
select pg_temp.chk('flash_over_caught', $q$select pg_temp.st('run', 'integrity.wpl_flash_deal_oversell', null, pg_temp.v('fd_over')) = 'fail'$q$);
select pg_temp.chk('flash_edge_equal_not_caught', $q$select pg_temp.st('run', 'integrity.wpl_flash_deal_oversell', null, pg_temp.v('fd_edge')) is null$q$);

-- ───────── 사이트 보안 probe ─────────
create table public.qgsmoke_tmp_open_with(id int);
alter table public.qgsmoke_tmp_open_with disable row level security;
create table public.qgsmoke_tmp_pol_live(id int);
alter table public.qgsmoke_tmp_pol_live enable row level security;
create policy qgsmoke_anon_insert on public.qgsmoke_tmp_pol_live for insert to anon with check (true);
create table public.qgsmoke_tmp_safe_with(id int);
alter table public.qgsmoke_tmp_safe_with enable row level security;
create policy qgsmoke_owner_insert on public.qgsmoke_tmp_safe_with for insert to authenticated with check (auth.uid() is not null);
create function public.qgsmoke_open_fn_with() returns int language sql security definer set search_path = public as $$ select 1 $$;
grant execute on function public.qgsmoke_open_fn_with() to anon;
create function public.qgsmoke_closed_fn_with() returns int language sql security definer set search_path = public as $$ select 1 $$;
revoke all on function public.qgsmoke_closed_fn_with() from public, anon, authenticated;
select pg_temp.put('srun', $q$select public.wpl_qg_run_engine_internal('security', null, 'manual', null, null, '{"smoke":"wpl_platform"}'::jsonb)::text$q$);
select pg_temp.chk('sec_rls_off_caught', $q$select pg_temp.st('srun', 'security.wpl_site_tables', null, 'rls:qgsmoke_tmp_open_with') = 'fail'$q$);
select pg_temp.chk('sec_anon_policy_caught', $q$select pg_temp.st('srun', 'security.wpl_site_tables', null, 'pol:qgsmoke_tmp_pol_live:qgsmoke_anon_insert') = 'fail'$q$);
select pg_temp.chk('sec_safe_table_not_caught', $q$select not exists (select 1 from public.wpl_qg_findings where run_id = pg_temp.v('srun')::uuid and check_code = 'security.wpl_site_tables' and fingerprint like '%qgsmoke_tmp_safe_with%')$q$);
select pg_temp.chk('sec_anon_definer_caught', $q$select pg_temp.st('srun', 'security.wpl_site_anon_definer', null, 'qgsmoke_open_fn_with()') = 'fail'$q$);
select pg_temp.chk('sec_closed_definer_not_caught', $q$select pg_temp.st('srun', 'security.wpl_site_anon_definer', null, 'qgsmoke_closed_fn_with()') is null$q$);
select pg_temp.chk('sec_generic_scoped_to_wpl', $q$select bool_and((params->'include_prefixes') = '["wpl_","zz_qg_"]'::jsonb) from public.wpl_qg_checks where code in ('security.anon_definer','security.rls_disabled','security.no_policies','security.definer_search_path','security.internal_exec')$q$);

-- ───────── 개선 신호(기준값을 이 트랜잭션 안에서만 바꿔 결정적으로) ─────────
update public.wpl_qg_checks set params = params || '{"min":1,"rate":0.000001}'::jsonb where code in ('evolution.wpl_order_cancel_rate','evolution.wpl_live_cart_abandon');
select pg_temp.put('rw_cxl', $q$insert into public.live_session_reservations_with(live_session_id, product_id, user_id, quantity, status, expires_at) values (pg_temp.v('sw2')::uuid, pg_temp.v('prod')::uuid, pg_temp.v('outsider')::uuid, 1, 'cancelled', now()) returning id::text$q$);
select pg_temp.put('erun', $q$select public.wpl_qg_run_engine_internal('evolution', null, 'manual', null, null, '{"smoke":"wpl_platform"}'::jsonb)::text$q$);
select pg_temp.chk('evo_cancel_signal', $q$select exists (select 1 from public.wpl_qg_findings where run_id = pg_temp.v('erun')::uuid and check_code = 'evolution.wpl_order_cancel_rate' and status = 'pass' and (detail->>'signal')::boolean)$q$);
select pg_temp.chk('evo_cancel_proposal', $q$select exists (select 1 from public.wpl_qg_proposals where fingerprint = 'order_cancel_rate')$q$);
select pg_temp.chk('evo_live_abandon_with_signal', $q$select exists (select 1 from public.wpl_qg_findings where run_id = pg_temp.v('erun')::uuid and check_code = 'evolution.wpl_live_cart_abandon' and tenant_id = pg_temp.v('W')::uuid and (detail->>'signal')::boolean)$q$);
select pg_temp.chk('evo_live_abandon_proposal', $q$select exists (select 1 from public.wpl_qg_proposals where fingerprint = 'live_cart_abandon__with')$q$);
update public.wpl_qg_checks set params = params || '{"min":1,"rate":1.01}'::jsonb where code in ('evolution.wpl_order_cancel_rate','evolution.wpl_live_cart_abandon');
select pg_temp.put('erun2', $q$select public.wpl_qg_run_engine_internal('evolution', null, 'manual', null, null, '{"smoke":"wpl_platform"}'::jsonb)::text$q$);
select pg_temp.chk('evo_below_threshold_no_signal', $q$select not exists (select 1 from public.wpl_qg_findings where run_id = pg_temp.v('erun2')::uuid and check_code in ('evolution.wpl_order_cancel_rate','evolution.wpl_live_cart_abandon') and coalesce((detail->>'signal')::boolean, false))$q$);

-- ───────── 공유 profiles 돈·대표자 칸 자기 수정 가드(0014) · 열린 사이트 표 차단(0015) ─────────
create function pg_temp.try_as(p_uid uuid, p_sql text) returns text language plpgsql as $f$
declare v int; res text;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', p_uid, 'role', 'authenticated')::text, true);
  perform set_config('request.jwt.claim.sub', p_uid::text, true);
  execute 'set local role authenticated';
  begin execute p_sql; get diagnostics v = row_count; res := 'rows=' || v;
  exception when others then res := 'blocked'; end;
  execute 'reset role';
  perform set_config('request.jwt.claims', '', true); perform set_config('request.jwt.claim.sub', '', true);
  return res;
end $f$;
select pg_temp.chk('guard_owner_self_blocked', format($q$select pg_temp.try_as(%L::uuid, 'update public.profiles set is_owner = true where id = auth.uid()') = 'blocked'$q$, pg_temp.v('outsider')));
select pg_temp.chk('guard_commission_self_blocked', format($q$select pg_temp.try_as(%L::uuid, 'update public.profiles set commission_rate = 0 where id = auth.uid()') = 'blocked'$q$, pg_temp.v('outsider')));
select pg_temp.chk('guard_taxmethod_self_blocked', format($q$select pg_temp.try_as(%L::uuid, 'update public.profiles set settlement_tax_method = ''none'' where id = auth.uid()') = 'blocked'$q$, pg_temp.v('outsider')));
select pg_temp.chk('guard_own_name_still_allowed', format($q$select pg_temp.try_as(%L::uuid, 'update public.profiles set full_name = ''QG 이름 변경'' where id = auth.uid()') = 'rows=1'$q$, pg_temp.v('outsider')));
select pg_temp.chk('guard_server_role_allowed', $q$with u as (update public.profiles set commission_rate = 7, settlement_tax_method = 'tax_invoice' where id = pg_temp.v('outsider')::uuid returning 1) select (count(*) = 1)::text from u$q$);
select pg_temp.chk('deny_clients_policies_present', $q$select count(*) = 2 from pg_policies where schemaname = 'public' and policyname in ('wholesale_applications_with_wpl_deny_clients', 'live_flash_sales_live_wpl_deny_clients') and permissive = 'RESTRICTIVE'$q$);
select pg_temp.chk('deny_clients_anon_zero_rows', format($q$select pg_temp.try_as(%L::uuid, 'delete from public.wholesale_applications_with') in ('rows=0', 'blocked')$q$, pg_temp.v('outsider')));
select pg_temp.chk('sec_open_tables_now_covered', $q$select not exists (select 1 from public.wpl_qg_findings where run_id = pg_temp.v('srun')::uuid and check_code = 'security.wpl_site_tables'
   and (fingerprint like '%pol:wholesale_applications_with:%' or fingerprint like '%pol:live_flash_sales_live:%'))$q$);

-- ───────── 어댑터 확장·카탈로그 ─────────
select pg_temp.chk('adapter_sites_two', $q$select (select count(*) from public.wpl_qga_tenants()) = 2 and public.wpl_qga_tenant_label(pg_temp.v('L')::uuid) = 'LIVE+'$q$);
select pg_temp.chk('adapter_review_target_copy', $q$select (public.wpl_qga_review_target('copy', pg_temp.v('prod'))->>'text') is not null and public.wpl_qga_review_target('copy', 'not-a-uuid') is null$q$);
select pg_temp.chk('adapter_is_admin_by_role', $q$select public.wpl_qga_admin_count_except(pg_temp.v('admin1')::uuid) >= 1 and public.wpl_qga_admin_count_except(null) >= 2$q$);
select pg_temp.chk('probes_not_executable_by_users', $q$select not bool_or(has_function_privilege('authenticated', p.oid, 'execute') or has_function_privilege('anon', p.oid, 'execute'))
   from pg_proc p where p.pronamespace = 'public'::regnamespace and (p.proname like 'wpl\_qg\_probe\_%' or p.proname = 'wpl_qg_site_suffix_internal' or p.proname like 'wpl\_qga\_review%')$q$);
select pg_temp.chk('regulations_seeded_need_review', $q$select count(*) = 6 and bool_and(last_reviewed_at is null) from public.wpl_qg_regulations where code like 'wpl\_%'$q$);
select pg_temp.chk('compliance_links_resolve', $q$select not exists (select 1 from public.wpl_qg_regulations g, jsonb_each(g.links) k, jsonb_array_elements_text(k.value) c
   where g.code like 'wpl\_%' and not exists (select 1 from public.wpl_qg_compliance_targets t where t.kind = k.key and t.code = c))$q$);
select pg_temp.chk('scenarios_registered', $q$select count(*) = 4 from public.wpl_qg_scenarios where code like 'wpl\_%' and active$q$);
select pg_temp.chk('enforce_switches_default_false', $q$select coalesce(bool_and((value #>> '{}') = 'false'), true) from public.wpl_qg_settings where key like 'qg\_enforce\_%'$q$);

select step, ok, msg from (
  select n, step, ok, msg from r
  union all
  select 100000, format('SUMMARY passed=%s failed=%s', count(*) filter (where ok), count(*) filter (where not ok or ok is null)), bool_and(coalesce(ok, false)), null from r
) z order by n;
rollback;
