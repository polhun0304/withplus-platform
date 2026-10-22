-- ============================================================================
-- 2026-10-22  분양 영업 리스트(community_prospects) 로고 관리
-- ----------------------------------------------------------------------------
-- 고객 요청: "분양영업리스트에 자신들의 로고를 입력할 수 있는 기능 — 입력·삭제·수정 모두 관리"
--  * logo_url          : 후보(교회·성당·사찰 등)의 로고 공개 주소. 업로드 파일 또는 관리자가 붙여넣은 https 주소.
--  * logo_storage_path : 이 기능으로 Storage(product-images 버킷, <사이트>/prospect-logos/<후보ID>/…)에 올린
--                        파일의 경로. 교체·삭제 시 이 경로의 파일만 지운다(외부 주소는 지우지 않음). 외부 주소면 NULL.
-- 원칙: 추가 전용(additive only). 기존 컬럼·데이터는 건드리지 않는다(WITH+·LIVE+ 공유 DB).
-- ============================================================================
ALTER TABLE public.community_prospects ADD COLUMN IF NOT EXISTS logo_url text;
ALTER TABLE public.community_prospects ADD COLUMN IF NOT EXISTS logo_storage_path text;

COMMENT ON COLUMN public.community_prospects.logo_url IS '후보 로고 공개 URL(업로드 또는 https 주소). 공개 전환 시 communities.logo_url로 복사';
COMMENT ON COLUMN public.community_prospects.logo_storage_path IS '이 기능으로 product-images 버킷에 올린 로고 파일 경로(교체·삭제 시 정리). 외부 주소면 NULL';
