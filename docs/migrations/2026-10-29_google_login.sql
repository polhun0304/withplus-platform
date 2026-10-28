-- 구글 로그인(서버 직접 처리) — 키 저장 행 추가 + 소셜 회원 연결에 google 허용 (WITH+/LIVE+ 각 DB에 적용)
insert into oauth_configs (provider_key, provider_name, enabled) values ('google', '구글', false)
  on conflict (provider_key) do nothing;
alter table social_identities_with drop constraint if exists social_identities_with_provider_check;
alter table social_identities_with add constraint social_identities_with_provider_check check (provider = any (array['kakao'::text, 'naver'::text, 'google'::text]));
