// 분양 조직별 상품 노출 범위("전체 노출"/"선택한 상품만 노출") 기능 검증용 임시 테스트.
// - 기본값이 all(전체 노출)인지, 이 경우 지금까지처럼 전체 카탈로그가 그대로 보이는지
// - curated로 바꾸고 상품 몇 개만 지정하면 ?community=슬러그로 조회했을 때 딱 그 상품들만 나오는지
// - 지정하지 않은 다른 조직/일반 홈 화면(커뮤니티 파라미터 없음)은 여전히 전체 카탈로그가 보이는지(회귀 없음)
// - curated인데 상품을 하나도 안 골랐으면 빈 목록을 정직하게 반환하는지(전체로 조용히 안 돌아감)
// - 존재하지 않는 상품 id를 넣으면 400으로 거부되는지, 일반 회원은 변경할 수 없는지(403)
// 검증 후 생성한 조직/설정을 모두 정리한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const HQ_EMAIL = `withplus.cpv.hq.${stamp}@withplus.test`;
const MEMBER_EMAIL = `withplus.cpv.member.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';
let createdUserIds = [];
let createdCommunityIds = [];

async function createTestUser(email, role) {
  const { data, error } = await admin.auth.admin.createUser({ email, password: PASSWORD, email_confirm: true });
  if (error) throw new Error(`계정 생성 실패(${email}): ${error.message}`);
  createdUserIds.push(data.user.id);
  const { error: profErr } = await admin.from('profiles').upsert({ id: data.user.id, email, role: role || 'member' });
  if (profErr) throw new Error(`profiles 생성 실패(${email}): ${profErr.message}`);
  const client = createClient(supabaseUrl, anonKey);
  const { data: signIn, error: signInErr } = await client.auth.signInWithPassword({ email, password: PASSWORD });
  if (signInErr) throw new Error(`로그인 실패(${email}): ${signInErr.message}`);
  return { id: data.user.id, token: signIn.session.access_token };
}

async function api(path, token, options = {}) {
  const res = await fetch(BASE + path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(options.headers || {}) }
  });
  const json = await res.json();
  return { status: res.status, ok: res.ok, json };
}

function assert(cond, msg) {
  if (!cond) throw new Error('❌ 검증 실패: ' + msg);
  console.log('✅ ' + msg);
}

async function cleanup() {
  console.log('\n--- 정리 시작 ---');
  for (const id of createdCommunityIds) await admin.from('communities').delete().eq('id', id);
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 준비 ===');
  const hq = await createTestUser(HQ_EMAIL, 'super_admin');
  const member = await createTestUser(MEMBER_EMAIL, 'member');

  const fullCatalog = await api('/api/products', null);
  assert(fullCatalog.ok && fullCatalog.json.data.length >= 2, `전체 카탈로그에 상품이 2개 이상 있음 (실제=${fullCatalog.json.data.length})`);
  const [productA, productB, ...rest] = fullCatalog.json.data;

  console.log('\n=== 1. 새 조직은 기본적으로 product_visibility=all - 전체 카탈로그와 개수가 같음 ===');
  const createRes = await api('/api/admin/communities', hq.token, {
    method: 'POST',
    body: JSON.stringify({ name: `상품노출테스트-${stamp}`, slug: `cpv-test-${stamp}` })
  });
  assert(createRes.ok, `테스트 조직 생성 성공 (status=${createRes.status})`);
  const communityId = createRes.json.data.id;
  const communitySlug = createRes.json.data.slug;
  createdCommunityIds.push(communityId);
  assert(createRes.json.data.product_visibility === 'all', `기본값은 all (실제=${createRes.json.data.product_visibility})`);

  const scopedDefault = await api('/api/products?community=' + communitySlug, null);
  assert(scopedDefault.json.data.length === fullCatalog.json.data.length, `all 상태에서는 ?community= 를 줘도 전체 카탈로그와 개수가 같음 (전체=${fullCatalog.json.data.length}, 조회=${scopedDefault.json.data.length})`);

  console.log('\n=== 2. 일반 회원은 상품 노출 설정을 변경할 수 없음 (403) ===');
  const memberAttempt = await api('/api/admin/communities/' + communityId + '/products', member.token, {
    method: 'PUT', body: JSON.stringify({ product_visibility: 'curated', product_ids: [productA.id] })
  });
  assert(memberAttempt.status === 403, `일반 회원의 변경 시도는 403 (실제=${memberAttempt.status})`);

  console.log('\n=== 3. curated로 바꾸고 상품 2개만 지정 - 그 조직 조회 결과는 딱 그 2개만 ===');
  const updateRes = await api('/api/admin/communities/' + communityId + '/products', hq.token, {
    method: 'PUT', body: JSON.stringify({ product_visibility: 'curated', product_ids: [productA.id, productB.id] })
  });
  assert(updateRes.ok, `curated 설정 저장 성공 (status=${updateRes.status})`);
  assert(updateRes.json.data.product_ids.length === 2, `저장 응답에 상품 2개 포함`);

  const scopedCurated = await api('/api/products?community=' + communitySlug, null);
  assert(scopedCurated.ok, `curated 상태 조회 성공 (status=${scopedCurated.status})`);
  assert(scopedCurated.json.data.length === 2, `curated 조회 결과가 정확히 2개 (실제=${scopedCurated.json.data.length})`);
  const scopedIds = scopedCurated.json.data.map(p => p.id).sort();
  assert(JSON.stringify(scopedIds) === JSON.stringify([productA.id, productB.id].sort()), '조회된 상품이 지정한 바로 그 2개와 정확히 일치');

  console.log('\n=== 4. 다른(커뮤니티 파라미터 없는) 일반 조회는 여전히 전체 카탈로그 - 회귀 없음 ===');
  const generalRes = await api('/api/products', null);
  assert(generalRes.json.data.length === fullCatalog.json.data.length, `커뮤니티 파라미터 없는 일반 조회는 여전히 전체 카탈로그 (실제=${generalRes.json.data.length})`);

  console.log('\n=== 5. 관리자 조회 API로 지금 설정을 다시 확인할 수 있는지 ===');
  const settingsRes = await api('/api/admin/communities/' + communityId + '/products', hq.token);
  assert(settingsRes.ok && settingsRes.json.data.product_visibility === 'curated', '관리자 조회 시 curated로 확인됨');
  assert(settingsRes.json.data.product_ids.length === 2, '관리자 조회 시 상품 2개로 확인됨');

  console.log('\n=== 6. curated인데 상품을 하나도 지정하지 않으면 - 전체로 조용히 되돌아가지 않고 빈 목록 ===');
  const emptyRes = await api('/api/admin/communities/' + communityId + '/products', hq.token, {
    method: 'PUT', body: JSON.stringify({ product_visibility: 'curated', product_ids: [] })
  });
  assert(emptyRes.ok, `빈 목록으로 저장 성공 (status=${emptyRes.status})`);
  const scopedEmpty = await api('/api/products?community=' + communitySlug, null);
  assert(scopedEmpty.json.data.length === 0, `상품을 하나도 안 고르면 조회 결과가 0개 (실제=${scopedEmpty.json.data.length}) - 전체로 몰래 되돌아가지 않음`);

  console.log('\n=== 7. 존재하지 않는 상품 id는 400으로 거부되고, 기존 설정은 그대로 유지됨 ===');
  const invalidRes = await api('/api/admin/communities/' + communityId + '/products', hq.token, {
    method: 'PUT', body: JSON.stringify({ product_visibility: 'curated', product_ids: ['00000000-0000-0000-0000-000000000099'] })
  });
  assert(invalidRes.status === 400, `존재하지 않는 상품 id는 400 (실제=${invalidRes.status})`);
  const afterInvalid = await api('/api/admin/communities/' + communityId + '/products', hq.token);
  assert(afterInvalid.json.data.product_ids.length === 0, '거부된 시도 이후에도 기존 값(빈 목록)이 그대로 유지됨');

  console.log('\n=== 8. 허용되지 않은 product_visibility 값은 400 ===');
  const invalidVisibility = await api('/api/admin/communities/' + communityId + '/products', hq.token, {
    method: 'PUT', body: JSON.stringify({ product_visibility: 'weird-mode', product_ids: [] })
  });
  assert(invalidVisibility.status === 400, `허용되지 않은 visibility 값은 400 (실제=${invalidVisibility.status})`);

  console.log('\n=== 9. 다시 all로 되돌리면 전체 카탈로그가 다시 보임 ===');
  const revertRes = await api('/api/admin/communities/' + communityId + '/products', hq.token, {
    method: 'PUT', body: JSON.stringify({ product_visibility: 'all', product_ids: [] })
  });
  assert(revertRes.ok, `all로 되돌리기 성공`);
  const scopedReverted = await api('/api/products?community=' + communitySlug, null);
  assert(scopedReverted.json.data.length === fullCatalog.json.data.length, `all로 되돌린 후 다시 전체 카탈로그가 보임 (실제=${scopedReverted.json.data.length})`);

  console.log('\n🎉 모든 검증 통과');
}

main()
  .catch(err => { console.error('\n💥 테스트 실패:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
