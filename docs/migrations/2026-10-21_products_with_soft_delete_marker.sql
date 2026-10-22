-- 2026-10-21 상품 "영구 삭제" 종결 상태 표시 (Supabase apply_migration: products_with_soft_delete_marker)
-- 주문 이력(orders_with.items JSONB)·LIVE+ 판매·리뷰 등 이력이 남아 있어 행을 지울 수 없는 상품은
-- status='inactive' + deleted_at 으로 표시해 손님·관리자 목록 모두에서 숨기고 복구할 수 없게 한다.
-- (status CHECK 제약 active/inactive/discontinued 는 LIVE+와 공유하므로 건드리지 않는다 — 추가 컬럼만)
ALTER TABLE public.products_with ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
ALTER TABLE public.products_with ADD COLUMN IF NOT EXISTS deleted_by uuid;
COMMENT ON COLUMN public.products_with.deleted_at IS '영구 삭제 처리 시각(주문 이력 보존 때문에 행을 남긴 경우). 값이 있으면 손님·관리자 목록 모두에서 숨기고 복구 불가';
COMMENT ON COLUMN public.products_with.deleted_by IS '영구 삭제 처리한 관리자/공급자 id';
