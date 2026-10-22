-- ============================================================================
-- 2026-10-22  WITH+ 라이브커머스 이식 — WITH+ 전용(_with) 라이브 테이블·RPC·정책
-- ----------------------------------------------------------------------------
-- 배경: LIVE+(라이브플러스)의 라이브 기능을 WITH+(위드플러스)에도 이식하되, 데이터는 WITH+ 전용으로
-- 완전히 분리한다("WITH+ 전용으로 분리"). 두 사이트는 같은 Supabase DB를 쓰므로 LIVE+의 *_live 테이블과
-- 같은 모양의 *_with 테이블을 새로 만든다. 상품·주문·회원(products_with·orders_with·profiles·coupons…)처럼
-- 원래 두 사이트가 함께 쓰는 테이블은 그대로 공유한다.
--
-- 원칙
--  * 추가 전용(additive only): 기존 *_live 테이블·데이터·RPC는 읽지도 바꾸지도 않는다(LIKE로 모양만 복제).
--  * LIKE ... INCLUDING ALL 은 기본값·CHECK·NOT NULL·인덱스·주석은 복제하지만 외래키·RLS 정책은 복제하지
--    않는다 → 외래키는 *_with 테이블을 가리키도록 아래에서 다시 건다(정책도 다시 만든다).
--  * 시퀀스(serial) 기본값을 쓰는 컬럼은 없어(전부 gen_random_uuid) LIVE+와 시퀀스를 공유하지 않는다.
--  * omnicast_* 처럼 LIVE+에서 접미사 없이 쓰던 전역 테이블도 WITH+ 전용 *_with 를 따로 만든다
--    (WITH+와 LIVE+의 유튜브/페이스북 OAuth 연결·키가 서로 섞이지 않게).
--  * LIVE+의 크리에이터 제휴 테이블은 이름이 이미 creators_with 등이라(LIVE+ 전용으로 쓰는 중) WITH+는
--    live_creators_with / live_creator_referral_codes_with / live_creator_settlements_with 를 새로 쓴다.
--  * orders_with(공유)의 channel_id·live_session_id·creator_id 는 LIVE+ 테이블을 가리키는 외래키라
--    WITH+ 라이브 주문은 새 컬럼 live_channel_id_with·live_session_id_with·live_creator_id_with 에 기록한다.
--  * RPC 는 <원래이름>_with 로 만들고 *_with 테이블만 다룬다. 서버(service_role)만 호출하도록 anon/
--    authenticated 실행 권한은 회수한다.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1) 테이블 (모양만 복제 — 데이터는 복사하지 않는다)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.channels_with                           (LIKE public.channels_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.channel_membership_tiers_with           (LIKE public.channel_membership_tiers_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.channel_members_with                    (LIKE public.channel_members_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.channel_fan_activity_with               (LIKE public.channel_fan_activity_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.channel_ledger_with                     (LIKE public.channel_ledger_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.channel_products_with                   (LIKE public.channel_products_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.channel_licenses_with                   (LIKE public.channel_licenses_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.channel_license_status_history_with     (LIKE public.channel_license_status_history_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_sessions_with                      (LIKE public.live_sessions_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_session_inventory_with             (LIKE public.live_session_inventory_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_session_reservations_with          (LIKE public.live_session_reservations_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_session_inventory_log_with         (LIKE public.live_session_inventory_log_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_session_chat_messages_with         (LIKE public.live_session_chat_messages_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_session_viewers_with               (LIKE public.live_session_viewers_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_session_guests_with                (LIKE public.live_session_guests_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_channel_broadcast_destinations_with (LIKE public.live_channel_broadcast_destinations_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_session_broadcast_targets_with     (LIKE public.live_session_broadcast_targets_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_flash_sales_with                   (LIKE public.live_flash_sales_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_quizzes_with                       (LIKE public.live_quizzes_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_quiz_winners_with                  (LIKE public.live_quiz_winners_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_auctions_with                      (LIKE public.live_auctions_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_auction_bids_with                  (LIKE public.live_auction_bids_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_gifts_with                         (LIKE public.live_gifts_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_share_links_with                   (LIKE public.live_share_links_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_share_redemptions_with             (LIKE public.live_share_redemptions_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.coupon_claims_with                      (LIKE public.coupon_claims_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.kakao_alimtalk_configs_with             (LIKE public.kakao_alimtalk_configs_live INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.omnicast_platform_configs_with          (LIKE public.omnicast_platform_configs INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.omnicast_pending_facebook_selections_with (LIKE public.omnicast_pending_facebook_selections INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_creators_with                      (LIKE public.creators_with INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_creator_referral_codes_with        (LIKE public.creator_referral_codes_with INCLUDING ALL);
CREATE TABLE IF NOT EXISTS public.live_creator_settlements_with           (LIKE public.creator_settlements_with INCLUDING ALL);

-- ---------------------------------------------------------------------------
-- 2) 외래키 — 원본과 같은 동작(ON DELETE …)으로, 대상만 *_with 로 바꿔 다시 건다
-- ---------------------------------------------------------------------------
DO $fk$
DECLARE s text;
BEGIN
  FOREACH s IN ARRAY ARRAY[
    'ALTER TABLE public.channels_with ADD CONSTRAINT channels_with_owner_user_id_fkey FOREIGN KEY (owner_user_id) REFERENCES public.profiles(id)',
    'ALTER TABLE public.channel_membership_tiers_with ADD CONSTRAINT channel_membership_tiers_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.channel_members_with ADD CONSTRAINT channel_members_with_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE',
    'ALTER TABLE public.channel_members_with ADD CONSTRAINT channel_members_with_tier_id_fkey FOREIGN KEY (tier_id) REFERENCES public.channel_membership_tiers_with(id)',
    'ALTER TABLE public.channel_members_with ADD CONSTRAINT channel_members_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.channel_fan_activity_with ADD CONSTRAINT channel_fan_activity_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.channel_fan_activity_with ADD CONSTRAINT channel_fan_activity_with_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE',
    'ALTER TABLE public.channel_ledger_with ADD CONSTRAINT channel_ledger_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.channel_products_with ADD CONSTRAINT channel_products_with_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.channel_products_with ADD CONSTRAINT channel_products_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.channel_licenses_with ADD CONSTRAINT channel_licenses_with_verified_by_fkey FOREIGN KEY (verified_by) REFERENCES public.profiles(id)',
    'ALTER TABLE public.channel_licenses_with ADD CONSTRAINT channel_licenses_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.channel_license_status_history_with ADD CONSTRAINT channel_license_status_history_with_license_id_fkey FOREIGN KEY (license_id) REFERENCES public.channel_licenses_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.channel_license_status_history_with ADD CONSTRAINT channel_license_status_history_with_changed_by_fkey FOREIGN KEY (changed_by) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_sessions_with ADD CONSTRAINT live_sessions_with_pinned_product_id_fkey FOREIGN KEY (pinned_product_id) REFERENCES public.products_with(id)',
    'ALTER TABLE public.live_sessions_with ADD CONSTRAINT live_sessions_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_session_inventory_with ADD CONSTRAINT live_session_inventory_with_live_session_id_fkey FOREIGN KEY (live_session_id) REFERENCES public.live_sessions_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_session_inventory_with ADD CONSTRAINT live_session_inventory_with_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_session_reservations_with ADD CONSTRAINT live_session_reservations_with_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_session_reservations_with ADD CONSTRAINT live_session_reservations_with_live_session_id_fkey FOREIGN KEY (live_session_id) REFERENCES public.live_sessions_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_session_reservations_with ADD CONSTRAINT live_session_reservations_with_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_session_reservations_with ADD CONSTRAINT live_session_reservations_with_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders_with(id)',
    'ALTER TABLE public.live_session_inventory_log_with ADD CONSTRAINT live_session_inventory_log_with_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_session_inventory_log_with ADD CONSTRAINT live_session_inventory_log_with_inventory_id_fkey FOREIGN KEY (inventory_id) REFERENCES public.live_session_inventory_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_session_inventory_log_with ADD CONSTRAINT live_session_inventory_log_with_reservation_id_fkey FOREIGN KEY (reservation_id) REFERENCES public.live_session_reservations_with(id)',
    'ALTER TABLE public.live_session_chat_messages_with ADD CONSTRAINT live_session_chat_messages_with_hidden_by_fkey FOREIGN KEY (hidden_by) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_session_chat_messages_with ADD CONSTRAINT live_session_chat_messages_with_live_session_id_fkey FOREIGN KEY (live_session_id) REFERENCES public.live_sessions_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_session_chat_messages_with ADD CONSTRAINT live_session_chat_messages_with_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE SET NULL',
    'ALTER TABLE public.live_session_chat_messages_with ADD CONSTRAINT live_session_chat_messages_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_session_guests_with ADD CONSTRAINT live_session_guests_with_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.profiles(id) ON DELETE SET NULL',
    'ALTER TABLE public.live_session_guests_with ADD CONSTRAINT live_session_guests_with_pinned_product_id_fkey FOREIGN KEY (pinned_product_id) REFERENCES public.products_with(id) ON DELETE SET NULL',
    'ALTER TABLE public.live_session_guests_with ADD CONSTRAINT live_session_guests_with_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE SET NULL',
    'ALTER TABLE public.live_session_guests_with ADD CONSTRAINT live_session_guests_with_live_session_id_fkey FOREIGN KEY (live_session_id) REFERENCES public.live_sessions_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_channel_broadcast_destinations_with ADD CONSTRAINT live_channel_broadcast_destinations_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_channel_broadcast_destinations_with ADD CONSTRAINT live_channel_broadcast_destinations_with_connected_by_fkey FOREIGN KEY (connected_by) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_session_broadcast_targets_with ADD CONSTRAINT live_session_broadcast_targets_with_live_session_id_fkey FOREIGN KEY (live_session_id) REFERENCES public.live_sessions_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_session_broadcast_targets_with ADD CONSTRAINT live_session_broadcast_targets_with_destination_id_fkey FOREIGN KEY (destination_id) REFERENCES public.live_channel_broadcast_destinations_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_flash_sales_with ADD CONSTRAINT live_flash_sales_with_live_session_id_fkey FOREIGN KEY (live_session_id) REFERENCES public.live_sessions_with(id)',
    'ALTER TABLE public.live_flash_sales_with ADD CONSTRAINT live_flash_sales_with_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_flash_sales_with ADD CONSTRAINT live_flash_sales_with_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products_with(id)',
    'ALTER TABLE public.live_quizzes_with ADD CONSTRAINT live_quizzes_with_live_session_id_fkey FOREIGN KEY (live_session_id) REFERENCES public.live_sessions_with(id)',
    'ALTER TABLE public.live_quizzes_with ADD CONSTRAINT live_quizzes_with_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_quiz_winners_with ADD CONSTRAINT live_quiz_winners_with_chat_message_id_fkey FOREIGN KEY (chat_message_id) REFERENCES public.live_session_chat_messages_with(id)',
    'ALTER TABLE public.live_quiz_winners_with ADD CONSTRAINT live_quiz_winners_with_quiz_id_fkey FOREIGN KEY (quiz_id) REFERENCES public.live_quizzes_with(id)',
    'ALTER TABLE public.live_quiz_winners_with ADD CONSTRAINT live_quiz_winners_with_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_auctions_with ADD CONSTRAINT live_auctions_with_winner_id_fkey FOREIGN KEY (winner_id) REFERENCES public.profiles(id) ON DELETE SET NULL',
    'ALTER TABLE public.live_auctions_with ADD CONSTRAINT live_auctions_with_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products_with(id) ON DELETE SET NULL',
    'ALTER TABLE public.live_auctions_with ADD CONSTRAINT live_auctions_with_current_bidder_id_fkey FOREIGN KEY (current_bidder_id) REFERENCES public.profiles(id) ON DELETE SET NULL',
    'ALTER TABLE public.live_auctions_with ADD CONSTRAINT live_auctions_with_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.profiles(id) ON DELETE SET NULL',
    'ALTER TABLE public.live_auctions_with ADD CONSTRAINT live_auctions_with_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.live_sessions_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_auction_bids_with ADD CONSTRAINT live_auction_bids_with_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_auction_bids_with ADD CONSTRAINT live_auction_bids_with_auction_id_fkey FOREIGN KEY (auction_id) REFERENCES public.live_auctions_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_gifts_with ADD CONSTRAINT live_gifts_with_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES public.profiles(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_gifts_with ADD CONSTRAINT live_gifts_with_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.live_sessions_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_gifts_with ADD CONSTRAINT live_gifts_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_gifts_with ADD CONSTRAINT live_gifts_with_chat_message_id_fkey FOREIGN KEY (chat_message_id) REFERENCES public.live_session_chat_messages_with(id) ON DELETE SET NULL',
    'ALTER TABLE public.live_share_links_with ADD CONSTRAINT live_share_links_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_share_links_with ADD CONSTRAINT live_share_links_with_sharer_user_id_fkey FOREIGN KEY (sharer_user_id) REFERENCES public.profiles(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_share_links_with ADD CONSTRAINT live_share_links_with_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.live_sessions_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_share_redemptions_with ADD CONSTRAINT live_share_redemptions_with_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.live_sessions_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_share_redemptions_with ADD CONSTRAINT live_share_redemptions_with_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders_with(id) ON DELETE SET NULL',
    'ALTER TABLE public.live_share_redemptions_with ADD CONSTRAINT live_share_redemptions_with_referred_user_id_fkey FOREIGN KEY (referred_user_id) REFERENCES public.profiles(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_share_redemptions_with ADD CONSTRAINT live_share_redemptions_with_sharer_user_id_fkey FOREIGN KEY (sharer_user_id) REFERENCES public.profiles(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_share_redemptions_with ADD CONSTRAINT live_share_redemptions_with_share_link_id_fkey FOREIGN KEY (share_link_id) REFERENCES public.live_share_links_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.coupon_claims_with ADD CONSTRAINT coupon_claims_with_coupon_id_fkey FOREIGN KEY (coupon_id) REFERENCES public.coupons(id) ON DELETE CASCADE',
    'ALTER TABLE public.omnicast_pending_facebook_selections_with ADD CONSTRAINT omnicast_pending_facebook_selections_with_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.channels_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.omnicast_pending_facebook_selections_with ADD CONSTRAINT omnicast_pending_facebook_selections_with_admin_user_id_fkey FOREIGN KEY (admin_user_id) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_creators_with ADD CONSTRAINT live_creators_with_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_creators_with ADD CONSTRAINT live_creators_with_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_creator_referral_codes_with ADD CONSTRAINT live_creator_referral_codes_with_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.profiles(id)',
    'ALTER TABLE public.live_creator_referral_codes_with ADD CONSTRAINT live_creator_referral_codes_with_creator_id_fkey FOREIGN KEY (creator_id) REFERENCES public.live_creators_with(id) ON DELETE CASCADE',
    'ALTER TABLE public.live_creator_settlements_with ADD CONSTRAINT live_creator_settlements_with_creator_id_fkey FOREIGN KEY (creator_id) REFERENCES public.live_creators_with(id)',
    'ALTER TABLE public.live_creator_settlements_with ADD CONSTRAINT live_creator_settlements_with_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.profiles(id)'
  ] LOOP
    BEGIN
      EXECUTE s;
    EXCEPTION WHEN duplicate_object THEN NULL; -- 재실행 안전
    END;
  END LOOP;
END
$fk$;

-- ---------------------------------------------------------------------------
-- 3) 공유 주문 테이블(orders_with)에 WITH+ 라이브 출처 컬럼 추가
--    (기존 channel_id/live_session_id/creator_id 는 LIVE+ 테이블을 가리키는 FK 라 WITH+ 가 쓸 수 없다)
-- ---------------------------------------------------------------------------
ALTER TABLE public.orders_with ADD COLUMN IF NOT EXISTS live_channel_id_with uuid;
ALTER TABLE public.orders_with ADD COLUMN IF NOT EXISTS live_session_id_with uuid;
ALTER TABLE public.orders_with ADD COLUMN IF NOT EXISTS live_creator_id_with uuid;
DO $ofk$
BEGIN
  BEGIN
    ALTER TABLE public.orders_with ADD CONSTRAINT orders_with_live_channel_id_with_fkey FOREIGN KEY (live_channel_id_with) REFERENCES public.channels_with(id);
  EXCEPTION WHEN duplicate_object THEN NULL; END;
  BEGIN
    ALTER TABLE public.orders_with ADD CONSTRAINT orders_with_live_session_id_with_fkey FOREIGN KEY (live_session_id_with) REFERENCES public.live_sessions_with(id);
  EXCEPTION WHEN duplicate_object THEN NULL; END;
  BEGIN
    ALTER TABLE public.orders_with ADD CONSTRAINT orders_with_live_creator_id_with_fkey FOREIGN KEY (live_creator_id_with) REFERENCES public.live_creators_with(id);
  EXCEPTION WHEN duplicate_object THEN NULL; END;
END
$ofk$;
CREATE INDEX IF NOT EXISTS orders_with_live_channel_id_with_idx ON public.orders_with (live_channel_id_with) WHERE live_channel_id_with IS NOT NULL;
CREATE INDEX IF NOT EXISTS orders_with_live_session_id_with_idx ON public.orders_with (live_session_id_with) WHERE live_session_id_with IS NOT NULL;
CREATE INDEX IF NOT EXISTS orders_with_live_creator_id_with_idx ON public.orders_with (live_creator_id_with) WHERE live_creator_id_with IS NOT NULL;
COMMENT ON COLUMN public.orders_with.live_channel_id_with IS 'WITH+ 라이브 채널 출처(channels_with). LIVE+ 주문은 channel_id(channels_live)를 쓴다.';
COMMENT ON COLUMN public.orders_with.live_session_id_with IS 'WITH+ 라이브 세션 출처(live_sessions_with). LIVE+ 주문은 live_session_id를 쓴다.';
COMMENT ON COLUMN public.orders_with.live_creator_id_with IS 'WITH+ 크리에이터 제휴(live_creators_with). LIVE+ 주문은 creator_id(creators_with)를 쓴다.';

-- ---------------------------------------------------------------------------
-- 4) RLS — 모두 켜고, 원본과 같은 공개 읽기 정책만 다시 만든다(쓰기는 서버 service_role 전용)
-- ---------------------------------------------------------------------------
DO $rls$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['channels_with','channel_membership_tiers_with','channel_members_with','channel_fan_activity_with','channel_ledger_with','channel_products_with','channel_licenses_with','channel_license_status_history_with','live_sessions_with','live_session_inventory_with','live_session_reservations_with','live_session_inventory_log_with','live_session_chat_messages_with','live_session_viewers_with','live_session_guests_with','live_channel_broadcast_destinations_with','live_session_broadcast_targets_with','live_flash_sales_with','live_quizzes_with','live_quiz_winners_with','live_auctions_with','live_auction_bids_with','live_gifts_with','live_share_links_with','live_share_redemptions_with','coupon_claims_with','kakao_alimtalk_configs_with','omnicast_platform_configs_with','omnicast_pending_facebook_selections_with','live_creators_with','live_creator_referral_codes_with','live_creator_settlements_with'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
  END LOOP;
END
$rls$;

DROP POLICY IF EXISTS channels_with_public_read ON public.channels_with;
CREATE POLICY channels_with_public_read ON public.channels_with FOR SELECT USING (status = 'active');
DROP POLICY IF EXISTS channel_tiers_with_public_read ON public.channel_membership_tiers_with;
CREATE POLICY channel_tiers_with_public_read ON public.channel_membership_tiers_with FOR SELECT USING (true);
DROP POLICY IF EXISTS channel_members_with_self_read ON public.channel_members_with;
CREATE POLICY channel_members_with_self_read ON public.channel_members_with FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS channel_fan_activity_with_self_read ON public.channel_fan_activity_with;
CREATE POLICY channel_fan_activity_with_self_read ON public.channel_fan_activity_with FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS channel_products_with_public_read ON public.channel_products_with;
CREATE POLICY channel_products_with_public_read ON public.channel_products_with FOR SELECT USING (true);
DROP POLICY IF EXISTS live_sessions_with_public_read ON public.live_sessions_with;
CREATE POLICY live_sessions_with_public_read ON public.live_sessions_with FOR SELECT USING (status = ANY (ARRAY['live'::text, 'ended'::text]));
-- 원본(live_flash_sales_live)은 USING(true) 전체 허용 정책이었으나 WITH+ 쪽은 service_role 전용으로 좁힌다
DROP POLICY IF EXISTS service_role_all ON public.live_flash_sales_with;
CREATE POLICY service_role_all ON public.live_flash_sales_with FOR ALL USING (auth.role() = 'service_role') WITH CHECK (auth.role() = 'service_role');
DROP POLICY IF EXISTS service_role_all ON public.live_quizzes_with;
CREATE POLICY service_role_all ON public.live_quizzes_with FOR ALL USING (auth.role() = 'service_role') WITH CHECK (auth.role() = 'service_role');
DROP POLICY IF EXISTS service_role_all ON public.live_quiz_winners_with;
CREATE POLICY service_role_all ON public.live_quiz_winners_with FOR ALL USING (auth.role() = 'service_role') WITH CHECK (auth.role() = 'service_role');
DROP POLICY IF EXISTS service_role_all ON public.live_session_guests_with;
CREATE POLICY service_role_all ON public.live_session_guests_with FOR ALL USING (auth.role() = 'service_role') WITH CHECK (auth.role() = 'service_role');

-- ---------------------------------------------------------------------------
-- 5) RPC — 원본과 같은 로직, *_with 테이블만 다룬다
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.reserve_live_session_inventory_with(p_inventory_id uuid, p_qty integer)
 RETURNS public.live_session_inventory_with
 LANGUAGE plpgsql
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE result live_session_inventory_with;
BEGIN
  UPDATE live_session_inventory_with
  SET reserved_qty = reserved_qty + p_qty, updated_at = now()
  WHERE id = p_inventory_id
    AND (allocated_qty - safety_stock - reserved_qty - sold_qty) >= p_qty
  RETURNING * INTO result;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN result;
END; $function$;

CREATE OR REPLACE FUNCTION public.release_live_session_inventory_with(p_inventory_id uuid, p_qty integer)
 RETURNS public.live_session_inventory_with
 LANGUAGE plpgsql
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE result live_session_inventory_with;
BEGIN
  UPDATE live_session_inventory_with
  SET reserved_qty = GREATEST(reserved_qty - p_qty, 0), updated_at = now()
  WHERE id = p_inventory_id
  RETURNING * INTO result;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN result;
END; $function$;

CREATE OR REPLACE FUNCTION public.confirm_live_session_inventory_with(p_inventory_id uuid, p_qty integer)
 RETURNS public.live_session_inventory_with
 LANGUAGE plpgsql
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE result live_session_inventory_with;
BEGIN
  UPDATE live_session_inventory_with
  SET reserved_qty = GREATEST(reserved_qty - p_qty, 0), sold_qty = sold_qty + p_qty, updated_at = now()
  WHERE id = p_inventory_id
  RETURNING * INTO result;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN result;
END; $function$;

CREATE OR REPLACE FUNCTION public.award_quiz_win_with(p_quiz_id uuid, p_user_id uuid, p_chat_message_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
  v_quiz record;
  v_winner_count int;
  v_new_id uuid;
begin
  -- 이 퀴즈 행을 잠가 동시 요청을 직렬화한다.
  select id, status, winner_limit into v_quiz
  from live_quizzes_with
  where id = p_quiz_id
  for update;

  if not found then
    return jsonb_build_object('success', false, 'reason', 'quiz_not_found');
  end if;

  if v_quiz.status <> 'open' then
    return jsonb_build_object('success', false, 'reason', 'quiz_closed');
  end if;

  select count(*) into v_winner_count
  from live_quiz_winners_with
  where quiz_id = p_quiz_id;

  if v_winner_count >= v_quiz.winner_limit then
    update live_quizzes_with set status = 'closed', closed_at = coalesce(closed_at, now())
    where id = p_quiz_id and status = 'open';
    return jsonb_build_object('success', false, 'reason', 'limit_reached');
  end if;

  insert into live_quiz_winners_with (quiz_id, user_id, chat_message_id)
  values (p_quiz_id, p_user_id, p_chat_message_id)
  on conflict (quiz_id, user_id) do nothing
  returning id into v_new_id;

  if v_new_id is null then
    return jsonb_build_object('success', false, 'reason', 'already_won');
  end if;

  if v_winner_count + 1 >= v_quiz.winner_limit then
    update live_quizzes_with set status = 'closed', closed_at = now() where id = p_quiz_id;
  end if;

  return jsonb_build_object('success', true, 'winner_id', v_new_id, 'winner_count', v_winner_count + 1);
end;
$function$;

CREATE OR REPLACE FUNCTION public.place_auction_bid_with(p_auction_id uuid, p_user_id uuid, p_amount numeric)
 RETURNS jsonb
 LANGUAGE plpgsql
 SET search_path TO 'public', 'pg_temp'
AS $function$
declare
  v_auction live_auctions_with%rowtype;
  v_min_next numeric;
  v_now timestamptz := now();
  v_new_ends_at timestamptz;
begin
  select * into v_auction from live_auctions_with where id = p_auction_id for update;
  if not found then
    return jsonb_build_object('success', false, 'reason', 'not_found');
  end if;
  if v_auction.status <> 'open' then
    return jsonb_build_object('success', false, 'reason', 'not_open');
  end if;
  if v_now >= v_auction.ends_at then
    return jsonb_build_object('success', false, 'reason', 'ended');
  end if;
  if v_auction.current_bidder_id = p_user_id then
    return jsonb_build_object('success', false, 'reason', 'already_highest');
  end if;
  v_min_next := v_auction.current_price + v_auction.bid_increment;
  if p_amount < v_min_next then
    return jsonb_build_object('success', false, 'reason', 'bid_too_low', 'min_next', v_min_next);
  end if;

  insert into live_auction_bids_with (auction_id, user_id, amount) values (p_auction_id, p_user_id, p_amount);

  v_new_ends_at := case when v_auction.ends_at - v_now < make_interval(secs => v_auction.soft_close_seconds)
                        then v_now + make_interval(secs => v_auction.soft_close_seconds)
                        else v_auction.ends_at end;

  update live_auctions_with
  set current_price = p_amount, current_bidder_id = p_user_id, bid_count = bid_count + 1, ends_at = v_new_ends_at
  where id = p_auction_id;

  return jsonb_build_object('success', true, 'current_price', p_amount, 'ends_at', v_new_ends_at, 'bid_count', v_auction.bid_count + 1, 'extended', v_new_ends_at > v_auction.ends_at);
end;
$function$;

CREATE OR REPLACE FUNCTION public.claim_auction_finalization_with(p_auction_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SET search_path TO 'public', 'pg_temp'
AS $function$
declare
  v_auction live_auctions_with%rowtype;
begin
  select * into v_auction from live_auctions_with where id = p_auction_id for update;
  if not found or v_auction.status <> 'open' or now() < v_auction.ends_at then
    return jsonb_build_object('claimed', false);
  end if;
  update live_auctions_with set status = 'finalizing' where id = p_auction_id;
  return jsonb_build_object('claimed', true, 'current_bidder_id', v_auction.current_bidder_id, 'current_price', v_auction.current_price, 'product_id', v_auction.product_id);
end;
$function$;

CREATE OR REPLACE FUNCTION public.claim_public_coupon_with(p_coupon_id uuid, p_user_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  v_coupon coupons%ROWTYPE;
  v_already boolean;
BEGIN
  SELECT * INTO v_coupon FROM coupons WHERE id = p_coupon_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('claimed', false, 'reason', '존재하지 않는 쿠폰입니다');
  END IF;
  IF NOT v_coupon.is_active THEN
    RETURN jsonb_build_object('claimed', false, 'reason', '더 이상 받을 수 없는 쿠폰입니다');
  END IF;
  IF v_coupon.claim_limit IS NULL THEN
    RETURN jsonb_build_object('claimed', false, 'reason', '다운로드 대상 쿠폰이 아닙니다');
  END IF;
  IF v_coupon.valid_until IS NOT NULL AND v_coupon.valid_until < now() THEN
    RETURN jsonb_build_object('claimed', false, 'reason', '유효기간이 지난 쿠폰입니다');
  END IF;

  SELECT EXISTS(SELECT 1 FROM coupon_claims_with WHERE coupon_id = p_coupon_id AND user_id = p_user_id) INTO v_already;
  IF v_already THEN
    RETURN jsonb_build_object('claimed', false, 'reason', '이미 다운로드한 쿠폰입니다', 'already_claimed', true);
  END IF;

  IF v_coupon.claimed_count >= v_coupon.claim_limit THEN
    RETURN jsonb_build_object('claimed', false, 'reason', '선착순 수량이 모두 소진되었습니다', 'sold_out', true);
  END IF;

  INSERT INTO coupon_claims_with (coupon_id, user_id) VALUES (p_coupon_id, p_user_id);
  UPDATE coupons SET claimed_count = claimed_count + 1 WHERE id = p_coupon_id;

  RETURN jsonb_build_object('claimed', true, 'coupon_code', v_coupon.code, 'claimed_count', v_coupon.claimed_count + 1, 'claim_limit', v_coupon.claim_limit);
END;
$function$;

-- 서버(service_role)만 호출 — 브라우저(anon/authenticated)에서 직접 실행 불가
REVOKE ALL ON FUNCTION public.reserve_live_session_inventory_with(uuid, integer) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.release_live_session_inventory_with(uuid, integer) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.confirm_live_session_inventory_with(uuid, integer) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.award_quiz_win_with(uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.place_auction_bid_with(uuid, uuid, numeric) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.claim_auction_finalization_with(uuid) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.claim_public_coupon_with(uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.reserve_live_session_inventory_with(uuid, integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.release_live_session_inventory_with(uuid, integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.confirm_live_session_inventory_with(uuid, integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.award_quiz_win_with(uuid, uuid, uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.place_auction_bid_with(uuid, uuid, numeric) TO service_role;
GRANT EXECUTE ON FUNCTION public.claim_auction_finalization_with(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.claim_public_coupon_with(uuid, uuid) TO service_role;

-- ---------------------------------------------------------------------------
-- 6) OmniCast 플랫폼 기본 행(키 없음·꺼짐) — WITH+ 전용 리다이렉트 URI.
--    키(client/secret)는 WITH+ 관리자 화면에서 WITH+ 전용 앱 키로 입력한다(LIVE+ 키를 재사용하지 않음).
-- ---------------------------------------------------------------------------
INSERT INTO public.omnicast_platform_configs_with (provider_key, provider_name, redirect_uri, enabled, extra_config)
VALUES
  ('youtube',   '유튜브 라이브',   'https://withplus-api.onrender.com/api/admin/live/omnicast/youtube/callback',  false, '{}'::jsonb),
  ('facebook',  '페이스북 라이브', 'https://withplus-api.onrender.com/api/admin/live/omnicast/facebook/callback', false, '{}'::jsonb),
  ('instagram', '인스타그램',      NULL, false, '{}'::jsonb),
  ('tiktok',    '틱톡',            NULL, false, '{}'::jsonb),
  ('x',         'X (트위터)',      NULL, false, '{}'::jsonb)
ON CONFLICT (provider_key) DO NOTHING;

COMMENT ON TABLE public.channels_with IS 'WITH+ 전용 라이브 채널(FAN+/CREATOR+/BRAND+ 공용 구조). LIVE+는 channels_live를 쓴다.';
COMMENT ON TABLE public.omnicast_platform_configs_with IS 'WITH+ 전용 OmniCast 플랫폼 앱 키(유튜브/페이스북 등). LIVE+는 omnicast_platform_configs를 쓴다.';

-- ---------------------------------------------------------------------------
-- 7) coupons.source 허용값 확장(기존 값은 전부 그대로 허용 — 상위집합으로 넓히기만 함)
--    라이브 쿠폰(선착순 쿠폰함·퀴즈 보상·경매 낙찰·바이럴 공유쿠폰)은 source 값이 CHECK 에 없어 발급이 실패하던
--    문제(LIVE+ 원본에도 있던 버그)를 막는다. coupons 는 두 사이트 공유 테이블이라 LIVE+ 쪽 발급도 함께 고쳐진다.
--    (apply_migration 이름: coupons_source_live_values)
-- ---------------------------------------------------------------------------
ALTER TABLE public.coupons
  DROP CONSTRAINT IF EXISTS coupons_source_check,
  ADD CONSTRAINT coupons_source_check CHECK (source = ANY (ARRAY['manual'::text, 'segment_campaign'::text, 'auto_grade'::text, 'auto_milestone'::text, 'live_coupon_drop'::text, 'live_quiz_reward'::text, 'live_auction_win'::text, 'live_share_viral_sharer'::text, 'live_share_viral_referred'::text]));
