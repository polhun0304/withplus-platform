-- 결제사 자동 환불 기록 — LIVE+ / WITH+ 두 Supabase 프로젝트 모두에 적용
alter table public.order_payments drop constraint if exists order_payments_status_check;
alter table public.order_payments add constraint order_payments_status_check check (status = any (array['requested','approved','failed','refunded','refund_failed']));
alter table public.order_payments add column if not exists refunded_at timestamptz;
alter table public.order_payments add column if not exists refund_response jsonb;
