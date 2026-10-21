-- 구매수량별 가격 옵션 (2026-10-21)
-- 상품마다 "N개 구매 시 총액" 묶음 가격을 선택적으로 지정한다. 비어있으면(null/[]) 기존과 동일하게 1개 가격 x 수량.
-- 형식: [{ "qty": 2, "price": 52920, "label": "2세트", "badge": "구매많음" }, ...]
-- 순수 추가(additive) 변경 - 기존 데이터는 건드리지 않는다.
ALTER TABLE public.products_with
  ADD COLUMN IF NOT EXISTS quantity_price_options jsonb;

COMMENT ON COLUMN public.products_with.quantity_price_options IS
  '구매수량별 가격 옵션 [{qty, price(총액), label, badge}] - null/빈배열이면 단일가(1개 가격 x 수량)';
