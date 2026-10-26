-- QG 공격 시나리오 — WITH+·LIVE+ 업무 표 기준 4종. 항상 rollback(운영 데이터 무변경).
--  wpl_anon_business · wpl_money_tamper · wpl_privilege_escalation · wpl_cross_user_site
--  결과: 시나리오마다 (scenario, result PASS|FAIL, steps, failed, failures) 한 행(형식은 adversarial_qg_core.sql 과 같음).
--  실행: node scripts/qg-run.mjs adversarial   (직접: supabase db query --linked -f supabase/tests/qg/adversarial_wpl_platform.sql)
begin;
create temp table r(n serial, scenario text, step text, ok boolean, msg text);
grant all on r to authenticated, anon; grant usage, select on sequence r_n_seq to authenticated, anon;
create temp table fx(k text primary key, v text);
grant all on fx to authenticated, anon;

-- 막혀야 하는 동작: 예외 또는 0행이면 ok
create function pg_temp.atk(p_sc text, p_step text, p_sql text) returns void language plpgsql as $f$
declare v_cnt int;
begin
  begin execute p_sql; get diagnostics v_cnt = row_count; insert into r(scenario, step, ok, msg) values (p_sc, p_step, v_cnt = 0, 'rows=' || v_cnt);
  exception when others then insert into r(scenario, step, ok, msg) values (p_sc, p_step, true, left(sqlerrm, 200)); end;
end $f$;
-- 참이어야 하는 조건
create function pg_temp.must(p_sc text, p_step text, p_sql text) returns void language plpgsql as $f$
declare v boolean;
begin
  begin execute p_sql into v; insert into r(scenario, step, ok, msg) values (p_sc, p_step, coalesce(v, false), 'got=' || coalesce(v::text, 'null'));
  exception when others then insert into r(scenario, step, ok, msg) values (p_sc, p_step, false, 'err: ' || left(sqlerrm, 200)); end;
end $f$;
-- 시도만 하고(오류 무시) 결과는 뒤의 must 로 확인
create function pg_temp.try(p_sql text) returns void language plpgsql as $f$
begin begin execute p_sql; exception when others then null; end; end $f$;
create function pg_temp.as_user(p_uid uuid) returns void language plpgsql as $f$
begin perform set_config('request.jwt.claims', json_build_object('sub', p_uid, 'role', 'authenticated')::text, true);
      perform set_config('request.jwt.claim.sub', coalesce(p_uid::text, ''), true); execute 'set local role authenticated'; end $f$;
create function pg_temp.as_anon() returns void language plpgsql as $f$
begin perform set_config('request.jwt.claims', json_build_object('role', 'anon')::text, true);
      perform set_config('request.jwt.claim.sub', '', true); execute 'set local role anon'; end $f$;
create function pg_temp.as_pg() returns void language plpgsql as $f$
begin execute 'reset role'; perform set_config('request.jwt.claims', '', true); perform set_config('request.jwt.claim.sub', '', true); end $f$;
create function pg_temp.v(p_k text) returns text language sql as $f$ select v from fx where k = p_k $f$;
grant execute on all functions in schema pg_temp to authenticated, anon;

-- 픽스처: 관리자 2·회원 A(outsider)·회원 B(새로) + 업무 행(postgres 로, 이 트랜잭션 안에서만)
insert into fx select key, value from jsonb_each_text(public.wpl_qga_smoke_fixture()) where value is not null;
insert into fx values ('tag', 'qga' || substr(md5(clock_timestamp()::text), 1, 8)), ('memB', gen_random_uuid()::text);
insert into auth.users(id, email, aud, role, raw_app_meta_data, raw_user_meta_data, created_at, updated_at)
  values (pg_temp.v('memB')::uuid, 'qg-adv-' || pg_temp.v('memB') || '@example.com', 'authenticated', 'authenticated', '{}', '{}', now(), now());
insert into public.profiles(id, email, full_name, role, is_active) values (pg_temp.v('memB')::uuid, 'qg-adv-' || pg_temp.v('memB') || '@example.com', 'QG 공격 B', 'member', true);
insert into fx select 'prod', id::text from public.products_with order by created_at limit 1;
insert into fx select 'price', price::text from public.products_with where id = pg_temp.v('prod')::uuid;
with x as (insert into public.orders_with(order_number, user_id, items, total_price, final_price, status, payment_method)
  values (pg_temp.v('tag') || '-A', pg_temp.v('outsider')::uuid, '[{"price":10000,"quantity":1}]', 10000, 10000, 'paid', 'card') returning id)
insert into fx select 'ordA', id::text from x;
with x as (insert into public.orders_with(order_number, user_id, items, total_price, final_price, status, payment_method)
  values (pg_temp.v('tag') || '-B', pg_temp.v('memB')::uuid, '[{"price":20000,"quantity":1}]', 20000, 20000, 'paid', 'card') returning id)
insert into fx select 'ordB', id::text from x;
with x as (insert into public.serial_coupons_with(batch_name, code, reward_mileage) values ('QG 공격', pg_temp.v('tag') || 'S', 50000) returning id)
insert into fx select 'serial', id::text from x;
with x as (insert into public.coupons(code, label, discount_type, discount_value) values (pg_temp.v('tag') || 'CP', 'QG 공격 쿠폰', 'fixed', 1000) returning id)
insert into fx select 'coupon', id::text from x;
with x as (insert into public.channels_live(slug, name, channel_type) values (pg_temp.v('tag') || '-l', 'QG 공격', 'brand') returning id)
insert into fx select 'chl', id::text from x;
with x as (insert into public.live_sessions_live(channel_id, title) values (pg_temp.v('chl')::uuid, 'QG 공격 세션') returning id)
insert into fx select 'sl', id::text from x;
with x as (insert into public.live_session_inventory_live(live_session_id, product_id, allocated_qty, reserved_qty, sold_qty) values (pg_temp.v('sl')::uuid, pg_temp.v('prod')::uuid, 10, 0, 0) returning id)
insert into fx select 'inv', id::text from x;
with x as (insert into public.live_session_reservations_live(live_session_id, product_id, user_id, quantity, status, expires_at)
  values (pg_temp.v('sl')::uuid, pg_temp.v('prod')::uuid, pg_temp.v('memB')::uuid, 1, 'cart', now() + interval '10 minutes') returning id)
insert into fx select 'resB', id::text from x;
with x as (insert into public.communities(name, slug) values ('QG 공격 조직', pg_temp.v('tag') || '-c') returning id)
insert into fx select 'cm', id::text from x;
with x as (insert into public.community_settlements_with(community_id, period_start, period_end, commission_amount, withholding_tax_amount, net_payment_amount, status)
  values (pg_temp.v('cm')::uuid, date '2020-01-01', date '2020-01-31', 10000, 330, 9670, 'pending') returning id)
insert into fx select 'cs', id::text from x;

-- ───────── wpl_anon_business(익명) ─────────
select pg_temp.as_anon();
select pg_temp.must('wpl_anon_business', 'orders_hidden', $q$select count(*) = 0 from public.orders_with where id in (pg_temp.v('ordA')::uuid, pg_temp.v('ordB')::uuid)$q$);
select pg_temp.must('wpl_anon_business', 'serial_codes_hidden', $q$select count(*) = 0 from public.serial_coupons_with where id = pg_temp.v('serial')::uuid$q$);
select pg_temp.atk('wpl_anon_business', 'product_price_update', $q$update public.products_with set price = 1 where id = pg_temp.v('prod')::uuid$q$);
select pg_temp.atk('wpl_anon_business', 'product_stock_update', $q$update public.products_with set stock = 999999 where id = pg_temp.v('prod')::uuid$q$);
select pg_temp.atk('wpl_anon_business', 'coupon_claim_insert', $q$insert into public.coupon_claims_with(coupon_id, user_id) values (pg_temp.v('coupon')::uuid, pg_temp.v('outsider')::uuid)$q$);
select pg_temp.atk('wpl_anon_business', 'order_insert', $q$insert into public.orders_with(order_number, user_id, total_price, final_price, status) values (pg_temp.v('tag') || '-X', pg_temp.v('outsider')::uuid, 1, 1, 'paid')$q$);
select pg_temp.try($q$select public.reserve_live_session_inventory(pg_temp.v('inv')::uuid, 5)$q$);
select pg_temp.try($q$select public.confirm_live_session_inventory(pg_temp.v('inv')::uuid, 5)$q$);
select pg_temp.as_pg();
select pg_temp.must('wpl_anon_business', 'live_inventory_unchanged', $q$select reserved_qty = 0 and sold_qty = 0 from public.live_session_inventory_live where id = pg_temp.v('inv')::uuid$q$);
select pg_temp.must('wpl_anon_business', 'product_price_unchanged', $q$select price::text = pg_temp.v('price') from public.products_with where id = pg_temp.v('prod')::uuid$q$);

-- ───────── wpl_money_tamper(회원 A 가 돈 관련 값 조작) ─────────
select pg_temp.as_user(pg_temp.v('outsider')::uuid);
select pg_temp.atk('wpl_money_tamper', 'own_order_final_price', $q$update public.orders_with set final_price = 1 where id = pg_temp.v('ordA')::uuid$q$);
select pg_temp.atk('wpl_money_tamper', 'own_order_status_refund', $q$update public.orders_with set status = 'refunded' where id = pg_temp.v('ordA')::uuid$q$);
select pg_temp.atk('wpl_money_tamper', 'mileage_self_credit', $q$insert into public.mileage_adjustments_with(user_id, amount, reason) values (pg_temp.v('outsider')::uuid, 1000000, 'QG 공격')$q$);
select pg_temp.atk('wpl_money_tamper', 'serial_redeem_direct', $q$update public.serial_coupons_with set is_redeemed = true, redeemed_by = pg_temp.v('outsider')::uuid, redeemed_at = now() where id = pg_temp.v('serial')::uuid$q$);
select pg_temp.atk('wpl_money_tamper', 'settlement_amount', $q$update public.community_settlements_with set net_payment_amount = 99999999 where id = pg_temp.v('cs')::uuid$q$);
select pg_temp.atk('wpl_money_tamper', 'live_inventory_direct', $q$update public.live_session_inventory_live set sold_qty = 0, allocated_qty = 999 where id = pg_temp.v('inv')::uuid$q$);
select pg_temp.as_pg();
select pg_temp.must('wpl_money_tamper', 'order_amount_unchanged', $q$select final_price = 10000 and status = 'paid' from public.orders_with where id = pg_temp.v('ordA')::uuid$q$);
select pg_temp.must('wpl_money_tamper', 'serial_unchanged', $q$select not is_redeemed from public.serial_coupons_with where id = pg_temp.v('serial')::uuid$q$);

-- ───────── wpl_privilege_escalation(공유 profiles 역할·대표자·수수료율 올리기 · QG 관리 기능) ─────────
insert into fx select 'orig', row(role::text, is_owner, commission_rate, settlement_tax_method)::text from public.profiles where id = pg_temp.v('outsider')::uuid;
select pg_temp.as_user(pg_temp.v('outsider')::uuid);
select pg_temp.try($q$update public.profiles set role = 'super_admin' where id = pg_temp.v('outsider')::uuid$q$);
select pg_temp.try($q$update public.profiles set is_owner = true where id = pg_temp.v('outsider')::uuid$q$);
select pg_temp.try($q$update public.profiles set commission_rate = 0 where id = pg_temp.v('outsider')::uuid$q$);
select pg_temp.try($q$update public.profiles set settlement_tax_method = 'none' where id = pg_temp.v('outsider')::uuid$q$);
select pg_temp.try($q$update public.profiles set owner_granted_at = now() where id = pg_temp.v('outsider')::uuid$q$);
select pg_temp.atk('wpl_privilege_escalation', 'other_profile_role', $q$update public.profiles set role = 'member' where id = pg_temp.v('admin1')::uuid$q$);
select pg_temp.atk('wpl_privilege_escalation', 'qg_run_engine', $q$select public.wpl_qg_run_engine('integrity')$q$);
select pg_temp.atk('wpl_privilege_escalation', 'qg_setting_set', $q$select public.wpl_qg_setting_set('qg_enforce_code_deploy', 'true'::jsonb)$q$);
select pg_temp.must('wpl_privilege_escalation', 'qg_catalog_hidden', $q$select (select count(*) from public.wpl_qg_checks) = 0 and (select count(*) from public.wpl_qg_findings) = 0$q$);
select pg_temp.must('wpl_privilege_escalation', 'not_qg_admin', $q$select not public.wpl_qga_is_admin()$q$);
select pg_temp.as_pg();
select pg_temp.must('wpl_privilege_escalation', 'role_unchanged', $q$select role::text = 'member' from public.profiles where id = pg_temp.v('outsider')::uuid$q$);
select pg_temp.must('wpl_privilege_escalation', 'owner_flag_unchanged', $q$select not is_owner and owner_granted_at is null from public.profiles where id = pg_temp.v('outsider')::uuid$q$);
select pg_temp.must('wpl_privilege_escalation', 'commission_tax_unchanged', $q$select row(role::text, is_owner, commission_rate, settlement_tax_method)::text = pg_temp.v('orig') from public.profiles where id = pg_temp.v('outsider')::uuid$q$);
select pg_temp.must('wpl_privilege_escalation', 'admin_role_unchanged', $q$select role::text = 'admin' from public.profiles where id = pg_temp.v('admin1')::uuid$q$);

-- ───────── wpl_cross_user_site(회원 A → 회원 B · LIVE+ 사이트 표) ─────────
select pg_temp.as_user(pg_temp.v('outsider')::uuid);
select pg_temp.must('wpl_cross_user_site', 'own_order_visible', $q$select count(*) = 1 from public.orders_with where id = pg_temp.v('ordA')::uuid$q$);
select pg_temp.must('wpl_cross_user_site', 'other_order_hidden', $q$select count(*) = 0 from public.orders_with where id = pg_temp.v('ordB')::uuid$q$);
select pg_temp.must('wpl_cross_user_site', 'other_live_reservation_hidden', $q$select count(*) = 0 from public.live_session_reservations_live where id = pg_temp.v('resB')::uuid$q$);
select pg_temp.atk('wpl_cross_user_site', 'other_reservation_cancel', $q$update public.live_session_reservations_live set status = 'cancelled' where id = pg_temp.v('resB')::uuid$q$);
select pg_temp.atk('wpl_cross_user_site', 'live_coupon_claim_for_other', $q$insert into public.coupon_claims_live(coupon_id, user_id) values (pg_temp.v('coupon')::uuid, pg_temp.v('memB')::uuid)$q$);
select pg_temp.atk('wpl_cross_user_site', 'other_profile_read', $q$select 1 from public.profiles where id = pg_temp.v('memB')::uuid$q$);
select pg_temp.as_pg();
select pg_temp.must('wpl_cross_user_site', 'reservation_unchanged', $q$select status = 'cart' from public.live_session_reservations_live where id = pg_temp.v('resB')::uuid$q$);

select pg_temp.as_pg();
select scenario, case when bool_and(ok is true) then 'PASS' else 'FAIL' end as result, count(*) as steps,
       count(*) filter (where ok is distinct from true) as failed,
       coalesce(jsonb_agg(jsonb_build_object('step', step, 'msg', left(msg, 200)) order by n) filter (where ok is distinct from true), '[]'::jsonb) as failures
  from r group by scenario order by scenario;
rollback;
