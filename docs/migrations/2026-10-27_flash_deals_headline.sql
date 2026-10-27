-- 한정수량 초특가 /deals 한 줄 목록용 문구 — LIVE+ / WITH+ 두 Supabase 프로젝트 모두에 적용
-- headline: 카테고리 옆 홍보 문구(예: 홈쇼핑 완판템! N사 실시간검색 1위), subtitle: 한 줄 설명(비우면 상품 요약 설명)
alter table public.flash_deals_with add column if not exists headline text;
alter table public.flash_deals_with add column if not exists subtitle text;
alter table public.flash_deals_with drop constraint if exists flash_deals_with_headline_len;
alter table public.flash_deals_with add constraint flash_deals_with_headline_len check (headline is null or char_length(headline) <= 40);
alter table public.flash_deals_with drop constraint if exists flash_deals_with_subtitle_len;
alter table public.flash_deals_with add constraint flash_deals_with_subtitle_len check (subtitle is null or char_length(subtitle) <= 80);
