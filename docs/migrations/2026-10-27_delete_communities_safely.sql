-- 분양 조직 일괄 삭제를 DB 안에서 한 번에(원자적으로) 처리한다 — LIVE+ / WITH+ 두 Supabase 프로젝트 모두에 적용
-- communities 를 지우면 orders_with·community_points·회원 연결 등이 CASCADE 로 함께 지워진다.
-- 1) 조직 행을 FOR UPDATE 로 잠근다 → 동시에 그 조직으로 주문을 넣는 트랜잭션(FK 의 KEY SHARE 잠금)과 서로 기다리게 되어,
--    확인과 삭제 사이에 새 주문이 끼어들어 함께 지워지는 일이 없다(잠근 뒤 끝난 주문은 아래 확인에서 보이고, 잠근 뒤 시작한 주문은 삭제 후 FK 오류로 실패).
-- 2) 조직마다 EXISTS 로 확인 → 결과 개수 제한으로 다른 조직 기록이 빠지는 일이 없다.
-- 3) 주문·정산·헌금 기록이 있으면 지우지 않고 사유와 함께 돌려준다.
-- 4) 공개 전환했던 영업 후보는 연결을 풀고 미공개(prospect)로 되돌린다(기존 '공개 취소'와 같은 상태).
create or replace function public.delete_communities_safely(p_ids uuid[])
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  r record;
  v_reasons text[];
  v_deleted jsonb := '[]'::jsonb;
  v_skipped jsonb := '[]'::jsonb;
begin
  for r in
    select c.id, c.name from public.communities c where c.id = any(p_ids) order by c.id for update
  loop
    v_reasons := array[]::text[];
    if exists (select 1 from public.orders_with o where o.community_id = r.id) then v_reasons := array_append(v_reasons, '주문'); end if;
    if exists (select 1 from public.community_settlements_with s where s.community_id = r.id) then v_reasons := array_append(v_reasons, '정산'); end if;
    if exists (select 1 from public.offerings f where f.community_id = r.id) then v_reasons := array_append(v_reasons, '헌금'); end if;

    if coalesce(array_length(v_reasons, 1), 0) > 0 then
      v_skipped := v_skipped || jsonb_build_array(jsonb_build_object('id', r.id, 'name', r.name, 'reasons', to_jsonb(v_reasons)));
    else
      update public.community_prospects
         set promoted_community_id = null,
             status = case when status = 'converted' then 'prospect' else status end,
             updated_at = now()
       where promoted_community_id = r.id;
      delete from public.communities where id = r.id;
      v_deleted := v_deleted || jsonb_build_array(jsonb_build_object('id', r.id, 'name', r.name));
    end if;
  end loop;
  return jsonb_build_object('deleted', v_deleted, 'skipped', v_skipped);
end;
$$;

revoke all on function public.delete_communities_safely(uuid[]) from public, anon, authenticated;
grant execute on function public.delete_communities_safely(uuid[]) to service_role;
