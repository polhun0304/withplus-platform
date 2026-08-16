const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
const API = 'http://localhost:3003';

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌', msg); }
}

async function loginAs(email, password) {
  const res = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: anonKey },
    body: JSON.stringify({ email, password })
  });
  const json = await res.json();
  return json.access_token;
}

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const adminEmail = `test-catvis-admin-${ts}@withplus-test.local`;
  const memberEmail = `test-catvis-member-${ts}@withplus-test.local`;

  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: memberData } = await admin.auth.admin.createUser({ email: memberEmail, password, email_confirm: true });
  const adminId = adminData.user.id;
  const memberId = memberData.user.id;
  const { error: profileErr } = await admin.from('profiles').upsert([
    { id: adminId, email: adminEmail, full_name: 'CatVisTestAdmin', role: 'admin' },
    { id: memberId, email: memberEmail, full_name: 'CatVisTestMember', role: 'member' }
  ]);
  if (profileErr) { console.error('profile upsert failed', profileErr); process.exit(1); }

  const adminToken = await loginAs(adminEmail, password);
  const memberToken = await loginAs(memberEmail, password);
  assert(!!adminToken && !!memberToken, '테스트 관리자/일반회원 로그인 성공');

  // 실제 카테고리 목록 확보 (2개만 골라서 curated 테스트에 사용)
  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  assert(catJson.success && catJson.data.length >= 2, `기존 카테고리가 2개 이상 존재함 (실제: ${catJson.data.length})`);
  const totalCategoryCount = catJson.data.length;
  const pickedCategories = catJson.data.slice(0, 2);
  const pickedIds = pickedCategories.map(c => c.id);

  // 테스트용 분양 조직 생성 (기본값 category_visibility='all' 이어야 함)
  const communityRes = await fetch(`${API}/api/admin/communities`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ name: `카테고리노출테스트조직-${ts}`, slug: `cattest-${ts}` })
  });
  const communityJson = await communityRes.json();
  assert(communityRes.status === 201, `테스트 분양 조직 생성 성공 (실제: ${communityRes.status})`);
  const communityId = communityJson.data.id;
  const communitySlug = communityJson.data.slug;
  assert(communityJson.data.category_visibility === 'all', `분양 조직 생성 시 category_visibility 기본값은 'all' (실제: ${communityJson.data.category_visibility})`);

  // ============================================
  // 1) 기본값(all)일 때 ?community=슬러그로 조회해도 전체 카테고리가 그대로 보임
  // ============================================
  const allModeRes = await fetch(`${API}/api/categories?community=${communitySlug}`);
  const allModeJson = await allModeRes.json();
  assert(allModeJson.data.length === totalCategoryCount, `전체노출(all) 모드에서는 이 조직으로 조회해도 전체 카테고리가 그대로 보임 (기대: ${totalCategoryCount}, 실제: ${allModeJson.data.length})`);

  // ============================================
  // 2) 관리자 권한 없이 설정 조회/변경 시도 -> 401/403
  // ============================================
  const noAuthRes = await fetch(`${API}/api/admin/communities/${communityId}/categories`);
  assert(noAuthRes.status === 401, `인증 없이 카테고리 노출 설정 조회 시 401 (실제: ${noAuthRes.status})`);
  const memberRes = await fetch(`${API}/api/admin/communities/${communityId}/categories`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert(memberRes.status === 403, `일반회원 권한으로 카테고리 노출 설정 조회 시 403 (실제: ${memberRes.status})`);

  // ============================================
  // 3) 관리자가 초기 설정 조회 -> all, category_ids 빈 배열
  // ============================================
  const getInitialRes = await fetch(`${API}/api/admin/communities/${communityId}/categories`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const getInitialJson = await getInitialRes.json();
  assert(getInitialRes.status === 200 && getInitialJson.data.category_visibility === 'all' && getInitialJson.data.category_ids.length === 0, `관리자로 초기 카테고리 노출 설정 조회 성공 (all, 빈 목록)`);

  // ============================================
  // 4) 잘못된 category_visibility 값 -> 400
  // ============================================
  const badRes = await fetch(`${API}/api/admin/communities/${communityId}/categories`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ category_visibility: 'nonsense', category_ids: [] })
  });
  assert(badRes.status === 400, `잘못된 category_visibility 값 저장 시도 시 400 (실제: ${badRes.status})`);

  // ============================================
  // 5) 존재하지 않는 카테고리 id 포함 -> 400
  // ============================================
  const invalidIdRes = await fetch(`${API}/api/admin/communities/${communityId}/categories`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ category_visibility: 'curated', category_ids: ['00000000-0000-0000-0000-000000000000'] })
  });
  assert(invalidIdRes.status === 400, `존재하지 않는 카테고리 id로 저장 시도 시 400 (실제: ${invalidIdRes.status})`);

  // ============================================
  // 6) 정상적으로 curated + 2개 카테고리 저장
  // ============================================
  const saveRes = await fetch(`${API}/api/admin/communities/${communityId}/categories`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ category_visibility: 'curated', category_ids: pickedIds })
  });
  const saveJson = await saveRes.json();
  assert(saveRes.status === 200 && saveJson.data.category_visibility === 'curated' && saveJson.data.category_ids.length === 2, `curated 모드 + 카테고리 2개 저장 성공 (실제 저장된 개수: ${saveJson.data?.category_ids?.length})`);

  // ============================================
  // 7) 저장 후 공개 API로 이 조직 기준 조회 시 딱 2개만 보임
  // ============================================
  const curatedModeRes = await fetch(`${API}/api/categories?community=${communitySlug}`);
  const curatedModeJson = await curatedModeRes.json();
  assert(curatedModeJson.data.length === 2, `curated 저장 후 이 조직 기준 조회 시 정확히 2개만 보임 (실제: ${curatedModeJson.data.length})`);
  const returnedIds = new Set(curatedModeJson.data.map(c => c.id));
  assert(pickedIds.every(id => returnedIds.has(id)), 'curated 응답에 선택한 카테고리 2개가 정확히 포함됨');

  // ============================================
  // 8) 이 조직을 거치지 않은 일반 조회(?community 없음)는 여전히 전체 카테고리
  // ============================================
  const generalRes = await fetch(`${API}/api/categories`);
  const generalJson = await generalRes.json();
  assert(generalJson.data.length === totalCategoryCount, `커뮤니티 파라미터 없는 일반 조회는 curated 설정과 무관하게 전체 카테고리 그대로 (실제: ${generalJson.data.length})`);

  // ============================================
  // 9) curated인데 카테고리를 0개 선택하면 정직하게 빈 결과 (전체로 조용히 돌아가지 않음)
  // ============================================
  const saveEmptyRes = await fetch(`${API}/api/admin/communities/${communityId}/categories`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ category_visibility: 'curated', category_ids: [] })
  });
  assert(saveEmptyRes.status === 200, `curated + 빈 목록 저장 성공 (실제: ${saveEmptyRes.status})`);
  const emptyModeRes = await fetch(`${API}/api/categories?community=${communitySlug}`);
  const emptyModeJson = await emptyModeRes.json();
  assert(emptyModeJson.data.length === 0, `curated인데 선택한 카테고리가 0개면 빈 결과를 정직하게 반환함 (실제: ${emptyModeJson.data.length})`);

  // ============================================
  // 10) 다시 all로 되돌리면 원래대로 전체 카테고리
  // ============================================
  await fetch(`${API}/api/admin/communities/${communityId}/categories`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ category_visibility: 'all', category_ids: [] })
  });
  const backToAllRes = await fetch(`${API}/api/categories?community=${communitySlug}`);
  const backToAllJson = await backToAllRes.json();
  assert(backToAllJson.data.length === totalCategoryCount, `다시 all로 되돌리면 전체 카테고리로 복구됨 (실제: ${backToAllJson.data.length})`);

  // 정리
  await admin.from('community_categories_with').delete().eq('community_id', communityId);
  await admin.from('communities').delete().eq('id', communityId);
  await admin.from('profiles').delete().in('id', [adminId, memberId]);
  await admin.auth.admin.deleteUser(adminId);
  await admin.auth.admin.deleteUser(memberId);
  console.log('정리 완료: 조직/계정 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
