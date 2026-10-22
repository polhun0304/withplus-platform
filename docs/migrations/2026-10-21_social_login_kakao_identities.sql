-- 2026-10-21 카카오·네이버 로그인 서버 직접 처리(추가 전용 변경 - 기존 데이터 수정/삭제 없음)
-- 1) oauth_configs에 카카오 행 추가(네이버와 같은 방식: 관리자 > 설정 탭에서 REST API 키/Client Secret 등록)
--    WITH+와 LIVE+가 같은 DB를 쓰지만 키는 사이트 공용(한 카카오/네이버 앱에 두 사이트의 Redirect URI를
--    모두 등록) - 같은 앱이어야 두 사이트에서 같은 카카오/네이버 회원번호(=같은 회원)로 인식된다.
-- 2) social_identities_with: 소셜 제공자 회원번호 ↔ Supabase 사용자 연결 대장.
--    이메일 미제공/미인증 사용자도 두 번째 로그인부터 같은 계정으로 들어오게 하고, 이메일이 바뀌어도 유지된다.
--    서버(service_role)만 접근 - RLS 켜고 정책 없음(anon/authenticated 접근 불가).

insert into public.oauth_configs (provider_key, provider_name, enabled)
values ('kakao', '카카오 로그인', false)
on conflict (provider_key) do nothing;

create table if not exists public.social_identities_with (
  id uuid primary key default gen_random_uuid(),
  provider text not null check (provider in ('kakao', 'naver')),
  provider_user_id text not null,
  user_id uuid not null references auth.users(id) on delete cascade,
  email text,
  email_verified boolean not null default false,
  linked_by text not null default 'created' check (linked_by in ('created', 'email_match', 'existing')),
  site text,
  created_at timestamptz not null default now(),
  last_login_at timestamptz not null default now(),
  unique (provider, provider_user_id)
);
create index if not exists social_identities_with_user_idx on public.social_identities_with(user_id);

alter table public.social_identities_with enable row level security;
revoke all on public.social_identities_with from anon, authenticated;
