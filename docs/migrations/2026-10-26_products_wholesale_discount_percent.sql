-- 상품별 도매 할인율(%) — 비어 있으면(null) 카테고리별 → 공통 도매 할인율을 쓴다 (LIVE+/WITH+ 공통, 같은 DB)
-- 도매가 우선순위: 상품별 도매채널가(고정 금액) > 상품별 도매 할인율 > 카테고리별 할인율 > 공통 할인율
alter table public.products_with
  add column if not exists wholesale_discount_percent numeric(5,2);

do $$ begin
  alter table public.products_with
    add constraint products_with_wholesale_discount_percent_check
    check (wholesale_discount_percent is null or (wholesale_discount_percent >= 0 and wholesale_discount_percent <= 90));
exception when duplicate_object then null; end $$;
