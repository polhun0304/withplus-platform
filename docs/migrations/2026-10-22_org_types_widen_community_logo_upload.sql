-- ============================================================================
-- 2026-10-22  조직 유형 확장(종교시설 → 일반회사·단체 등) + 분양 조직 로고·직인 파일 업로드
-- ----------------------------------------------------------------------------
-- 고객 요청: "검색에서 전체 종교가 아닌 일반회사, 단체 등 모든 것이 입력될 수 있도록 '전체'라고 수정"
--  * community_prospects.org_type / communities.org_type CHECK 허용값을 넓힌다(기존 4종 유지 + 6종 추가).
--      church(교회) catholic(성당) buddhist(사찰) other(기타)                       ← 기존
--      company(일반회사) association(협회·단체) school(학교·학원)
--      apartment(아파트·주민모임) club(동호회·모임) nonprofit(비영리·복지기관)        ← 추가
--  * 기존 행은 모두 기존 4종 안에 있으므로 새 제약을 그대로 통과한다(데이터 변경 없음).
--
-- 분양 조직 관리 로고·직인: "주소 붙여넣기" 외에 "컴퓨터에서 파일 올리기"를 함께 제공
--  * communities.logo_storage_path / stamp_storage_path : 이 기능으로 product-images 버킷
--    (<사이트>/community-logos/<조직ID>/…)에 올린 파일 경로. 교체·삭제 시 이 경로의 파일만 지운다.
--    외부 주소(https)를 붙여넣은 경우는 NULL(외부 파일은 지우지 않음).
-- 원칙: 추가·확장 전용(additive / widening only). WITH+·LIVE+ 공유 DB.
-- ============================================================================
ALTER TABLE public.community_prospects DROP CONSTRAINT IF EXISTS community_prospects_org_type_check;
ALTER TABLE public.community_prospects ADD CONSTRAINT community_prospects_org_type_check
  CHECK (org_type = ANY (ARRAY['church','catholic','buddhist','other','company','association','school','apartment','club','nonprofit']::text[]));

ALTER TABLE public.communities DROP CONSTRAINT IF EXISTS communities_org_type_check;
ALTER TABLE public.communities ADD CONSTRAINT communities_org_type_check
  CHECK (org_type = ANY (ARRAY['church','catholic','buddhist','other','company','association','school','apartment','club','nonprofit']::text[]));

ALTER TABLE public.communities ADD COLUMN IF NOT EXISTS logo_storage_path text;
ALTER TABLE public.communities ADD COLUMN IF NOT EXISTS stamp_storage_path text;

COMMENT ON COLUMN public.communities.logo_storage_path IS '분양 조직 관리에서 올린 로고 파일 경로(product-images 버킷, <사이트>/community-logos/<조직ID>/). 외부 주소면 NULL';
COMMENT ON COLUMN public.communities.stamp_storage_path IS '분양 조직 관리에서 올린 직인 파일 경로(product-images 버킷, <사이트>/community-logos/<조직ID>/). 외부 주소면 NULL';
