-- ⚡ 한정수량 초특가 (WITH+ / LIVE+ 공용 DB — site 컬럼으로 사이트별 분리, 기본값 WITH+)
-- 추가 전용(additive) 마이그레이션: 새 테이블 2개 + 원자적 RPC 2개. 기존 데이터는 건드리지 않는다.

create table if not exists public.flash_deals_with (
  id uuid primary key default gen_random_uuid(),
  site text not null default 'withplus',
  product_id uuid not null references public.products_with(id) on delete cascade,
  deal_price numeric not null check (deal_price >= 0),
  limit_qty integer not null check (limit_qty > 0),
  sold_count integer not null default 0 check (sold_count >= 0),
  starts_at timestamptz not null,
  ends_at timestamptz not null,
  sort_order integer not null default 0,
  is_active boolean not null default true,
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint flash_deals_with_period_chk check (ends_at > starts_at),
  constraint flash_deals_with_sold_chk check (sold_count <= limit_qty)
);
create index if not exists flash_deals_with_site_period_idx on public.flash_deals_with (site, ends_at, starts_at);
create index if not exists flash_deals_with_product_idx on public.flash_deals_with (product_id);

-- 주문별 초특가 수량 점유 기록(주문 생성 시 held → 결제 완료 시 paid → 취소/환불/미결제 자동취소 시 released)
create table if not exists public.flash_deal_claims_with (
  id uuid primary key default gen_random_uuid(),
  deal_id uuid not null references public.flash_deals_with(id) on delete cascade,
  order_id uuid not null,
  product_id uuid not null,
  quantity integer not null check (quantity > 0),
  status text not null default 'held' check (status in ('held', 'paid', 'released')),
  created_at timestamptz not null default now(),
  paid_at timestamptz,
  released_at timestamptz,
  constraint flash_deal_claims_with_uniq unique (deal_id, order_id)
);
create index if not exists flash_deal_claims_with_order_idx on public.flash_deal_claims_with (order_id);

alter table public.flash_deals_with enable row level security;
alter table public.flash_deal_claims_with enable row level security;
-- 정책 없음 = anon/authenticated 직접 접근 차단. 서버(service_role)만 읽고 쓴다.

-- 원자적 수량 점유: 진행중 + 잔여 수량 이내일 때만 sold_count를 올리고 점유 기록을 남긴다(동시 주문 레이스 방지)
create or replace function public.claim_flash_deal_with(p_deal_id uuid, p_order_id uuid, p_product_id uuid, p_qty integer)
returns boolean
language plpgsql
set search_path = public
as $$
declare
  v_ok boolean;
begin
  if p_qty is null or p_qty <= 0 then
    return false;
  end if;
  update public.flash_deals_with
     set sold_count = sold_count + p_qty, updated_at = now()
   where id = p_deal_id
     and product_id = p_product_id
     and is_active
     and starts_at <= now() and ends_at > now()
     and sold_count + p_qty <= limit_qty
  returning true into v_ok;
  if not coalesce(v_ok, false) then
    return false;
  end if;
  insert into public.flash_deal_claims_with (deal_id, order_id, product_id, quantity)
  values (p_deal_id, p_order_id, p_product_id, p_qty);
  return true;
end;
$$;

-- 주문 취소/환불/실패 시 점유 수량 반환(멱등 — 이미 released면 아무것도 안 함). 반환값 = 반환한 점유 건수
create or replace function public.release_flash_deal_claims_with(p_order_id uuid)
returns integer
language plpgsql
set search_path = public
as $$
declare
  v_count integer;
begin
  with rel as (
    update public.flash_deal_claims_with
       set status = 'released', released_at = now()
     where order_id = p_order_id and status in ('held', 'paid')
    returning deal_id, quantity
  ), agg as (
    select deal_id, sum(quantity)::int as q from rel group by deal_id
  ), upd as (
    update public.flash_deals_with d
       set sold_count = greatest(0, d.sold_count - agg.q), updated_at = now()
      from agg
     where d.id = agg.deal_id
    returning d.id
  )
  select count(*) into v_count from rel;
  return coalesce(v_count, 0);
end;
$$;

revoke all on function public.claim_flash_deal_with(uuid, uuid, uuid, integer) from public, anon, authenticated;
revoke all on function public.release_flash_deal_claims_with(uuid) from public, anon, authenticated;
grant execute on function public.claim_flash_deal_with(uuid, uuid, uuid, integer) to service_role;
grant execute on function public.release_flash_deal_claims_with(uuid) to service_role;
