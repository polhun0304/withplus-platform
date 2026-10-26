-- =====================================================================
-- QG 첫 실행이 찾은 실제 결함 수정(공격 시나리오 wpl_privilege_escalation 실패) — 공유 profiles 의 돈·대표자 칸 자기 수정 차단
--  문제: profiles 의 'p_update_own' 정책(id = auth.uid())으로 로그인 회원 누구나 Supabase 공개 키 + 자기 토큰으로
--        is_owner(대표자) · owner_granted_at · commission_rate(공급자 수수료율) · settlement_tax_method(정산 세무 방식)를 직접 바꿀 수 있었다.
--        role 은 guard_role_change, 개인정보 칸은 gmw_profiles_guard_sensitive 가 막지만 이 4칸은 빠져 있었다.
--        commission_rate 는 공급자 정산(rateMap)에, is_owner 는 대표자 전용 2단계 인증 화면 진입에 쓰인다.
--  수정(추가 전용): 새 트리거 하나. 기존 트리거·정책·함수는 건드리지 않는다.
--   · 서버(서비스 키, auth.uid() 없음)는 그대로 허용 — WITH+·LIVE+ 서버의 관리자 화면은 모두 서버 경유.
--   · is_owner·owner_granted_at: 로그인 세션에서는 super_admin 만.
--   · commission_rate·settlement_tax_method: 로그인 세션에서는 관리자(admin·super_admin) 또는 GMWOS 관리자(is_admin()) 만.
-- =====================================================================
create or replace function public.wpl_profiles_guard_commerce() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_role text;
begin
  if auth.uid() is null then
    return new;
  end if;
  select p.role::text into v_role from public.profiles p where p.id = auth.uid();
  if (new.is_owner is distinct from old.is_owner or new.owner_granted_at is distinct from old.owner_granted_at)
     and coalesce(v_role, '') <> 'super_admin' then
    raise exception '대표자 지정은 최고 관리자만 바꿀 수 있습니다.' using errcode = '42501';
  end if;
  if (new.commission_rate is distinct from old.commission_rate or new.settlement_tax_method is distinct from old.settlement_tax_method)
     and coalesce(v_role, '') not in ('admin', 'super_admin') and not coalesce(public.is_admin(), false) then
    raise exception '수수료율·정산 세무 방식은 관리자만 바꿀 수 있습니다.' using errcode = '42501';
  end if;
  return new;
end $$;
revoke all on function public.wpl_profiles_guard_commerce() from public, anon, authenticated;

drop trigger if exists wpl_profiles_guard_commerce on public.profiles;
create trigger wpl_profiles_guard_commerce before update of is_owner, owner_granted_at, commission_rate, settlement_tax_method on public.profiles
  for each row execute function public.wpl_profiles_guard_commerce();
