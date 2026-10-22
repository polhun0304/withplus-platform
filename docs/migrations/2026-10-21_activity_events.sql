-- 홈 "지금 이 순간, WITH+" 실시간 활동 피드용 가벼운 추가 전용(append-only) 이벤트 기록
-- - 장바구니 담기는 cart_snapshots_*가 사용자당 1행을 덮어쓰므로(시점 정보가 사라짐) 담은 순간을 따로 남긴다.
-- - 결제완료(orders_*.payment_at)·후기(product_reviews)·밴드 후기(band_posts_*)는 원본 테이블에서 바로 읽는다.
-- - 서버(service role)만 읽고 쓴다: RLS 켜고 정책 없음 → anon/authenticated 직접 접근 불가.
-- - 추가만 하는 변경(기존 데이터·테이블 변경 없음). LIVE+ 이식용 _live 테이블도 같은 구조로 함께 만든다.
create table if not exists public.activity_events_with (
  id bigint generated always as identity primary key,
  event_type text not null check (event_type in ('cart_add', 'order_paid', 'review', 'band_review')),
  user_id uuid,
  product_id uuid,
  created_at timestamptz not null default now()
);
create index if not exists activity_events_with_created_idx on public.activity_events_with (created_at desc);
create index if not exists activity_events_with_dedupe_idx on public.activity_events_with (user_id, product_id, event_type, created_at desc);
alter table public.activity_events_with enable row level security;
revoke all on public.activity_events_with from anon, authenticated;

create table if not exists public.activity_events_live (
  id bigint generated always as identity primary key,
  event_type text not null check (event_type in ('cart_add', 'order_paid', 'review', 'band_review')),
  user_id uuid,
  product_id uuid,
  created_at timestamptz not null default now()
);
create index if not exists activity_events_live_created_idx on public.activity_events_live (created_at desc);
create index if not exists activity_events_live_dedupe_idx on public.activity_events_live (user_id, product_id, event_type, created_at desc);
alter table public.activity_events_live enable row level security;
revoke all on public.activity_events_live from anon, authenticated;
