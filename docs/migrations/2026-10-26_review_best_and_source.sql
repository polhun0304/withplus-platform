-- 리뷰 관리: 베스트 리뷰(상위 노출) + 후기 출처 표시 (LIVE+/WITH+ 공통, 같은 DB)
-- 모두 기본값이 있는 컬럼 추가만 하므로 기존 데이터·동작은 그대로다.

-- 구매 후기
alter table public.product_reviews
  add column if not exists is_best boolean not null default false,
  add column if not exists best_at timestamptz,
  -- member: 실제 구매 회원 / admin: 관리자가 직접 등록 / granted: 관리자가 작성 권한을 준 회원(체험 후기)
  add column if not exists review_source text not null default 'member',
  -- 관리자 등록 후기에 표시할 작성자 이름(예: 전화·오프라인 주문 고객) - 화면에서는 가운데를 가려서 보인다
  add column if not exists author_display text;

do $$ begin
  alter table public.product_reviews
    add constraint product_reviews_review_source_check check (review_source in ('member', 'admin', 'granted'));
exception when duplicate_object then null; end $$;

create index if not exists product_reviews_best_idx on public.product_reviews (is_best, best_at desc) where is_best;

-- 밴드 후기
alter table public.band_posts_with
  add column if not exists is_best boolean not null default false,
  add column if not exists best_at timestamptz;

create index if not exists band_posts_with_best_idx on public.band_posts_with (is_best, best_at desc) where is_best;
