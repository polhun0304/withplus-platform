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
  const adminEmail = `test-cathier-admin-${ts}@withplus-test.local`;

  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const adminId = adminData.user.id;
  await admin.from('profiles').upsert([{ id: adminId, email: adminEmail, full_name: 'CatHierTestAdmin', role: 'admin' }]);
  const adminToken = await loginAs(adminEmail, password);
  assert(!!adminToken, '테스트 관리자 로그인 성공');

  const createdIds = [];
  async function createCategory(body) {
    const res = await fetch(`${API}/api/admin/categories`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` }, body: JSON.stringify(body)
    });
    const json = await res.json();
    if (json.data && json.data.id) createdIds.push(json.data.id);
    return { res, json };
  }

  // ============================================
  // 1) 대분류 생성 (parent_id 없음)
  // ============================================
  const { res: parentRes, json: parentJson } = await createCategory({
    label: `계층테스트대분류-${ts}`, emoji: '🧪', slug: `cathier-parent-${ts}`, db_category: `cathier-parent-${ts}`
  });
  assert(parentRes.status === 201 && parentJson.data.parent_id === null, `대분류 생성 성공, parent_id는 null (실제: ${parentRes.status})`);

  // ============================================
  // 2) 존재하지 않는 parent_id로 생성 시도 -> 400
  // ============================================
  const { res: badParentRes, json: badParentJson } = await createCategory({
    label: '존재안하는상위', emoji: '🧪', slug: `cathier-badparent-${ts}`, db_category: `cathier-badparent-${ts}`,
    parent_id: '00000000-0000-0000-0000-000000000000'
  });
  assert(badParentRes.status === 400, `존재하지 않는 상위 카테고리로 생성 시도 시 400 (실제: ${badParentRes.status})`);

  // ============================================
  // 3) 중분류 생성 (parent_id = 대분류)
  // ============================================
  const { res: childRes, json: childJson } = await createCategory({
    label: `계층테스트중분류-${ts}`, emoji: '🧪', slug: `cathier-child-${ts}`, db_category: `cathier-child-${ts}`,
    parent_id: parentJson.data.id
  });
  assert(childRes.status === 201 && childJson.data.parent_id === parentJson.data.id, `중분류 생성 성공, parent_id가 대분류로 지정됨 (실제: ${childRes.status})`);

  // ============================================
  // 4) 중분류의 하위에 또 카테고리를 만들려는 시도(3단 계층) -> 400
  // ============================================
  const { res: grandchildRes, json: grandchildJson } = await createCategory({
    label: '3단계층시도', emoji: '🧪', slug: `cathier-grandchild-${ts}`, db_category: `cathier-grandchild-${ts}`,
    parent_id: childJson.data.id
  });
  assert(grandchildRes.status === 400, `이미 중분류인 카테고리를 상위로 지정해 3단 계층을 만들려는 시도 시 400 (실제: ${grandchildRes.status})`);

  // ============================================
  // 5) GET /api/admin/categories 응답에 parent_id가 정확히 내려오는지 확인
  // ============================================
  const listRes = await fetch(`${API}/api/admin/categories`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const listJson = await listRes.json();
  const listedChild = listJson.data.find(c => c.id === childJson.data.id);
  assert(!!listedChild && listedChild.parent_id === parentJson.data.id, '카테고리 목록 조회 시 parent_id가 정확히 포함됨');

  // ============================================
  // 6) 수정(PUT) - 자기 자신을 상위로 지정 시도 -> 400
  // ============================================
  const selfParentRes = await fetch(`${API}/api/admin/categories/${parentJson.data.id}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ parent_id: parentJson.data.id })
  });
  assert(selfParentRes.status === 400, `자기 자신을 상위 카테고리로 지정 시도 시 400 (실제: ${selfParentRes.status})`);

  // ============================================
  // 7) 수정(PUT) - 이미 하위 카테고리를 가진 대분류를 다른 카테고리의 하위로 지정 시도 -> 400
  // ============================================
  const { res: otherParentRes, json: otherParentJson } = await createCategory({
    label: `계층테스트다른대분류-${ts}`, emoji: '🧪', slug: `cathier-other-${ts}`, db_category: `cathier-other-${ts}`
  });
  assert(otherParentRes.status === 201, '비교용 다른 대분류 생성 성공');
  const makeParentAChildRes = await fetch(`${API}/api/admin/categories/${parentJson.data.id}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ parent_id: otherParentJson.data.id })
  });
  assert(makeParentAChildRes.status === 400, `이미 하위 카테고리를 가진 대분류를 다른 카테고리의 하위로 지정 시도 시 400 (실제: ${makeParentAChildRes.status})`);

  // ============================================
  // 8) 대분류 삭제 시, 하위 중분류는 삭제되지 않고 대분류로 승격되는지 확인 (FK ON DELETE SET NULL)
  // ============================================
  const deleteParentRes = await fetch(`${API}/api/admin/categories/${parentJson.data.id}`, {
    method: 'DELETE', headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert(deleteParentRes.status === 200, `대분류 삭제 성공 (실제: ${deleteParentRes.status})`);
  const afterDeleteListRes = await fetch(`${API}/api/admin/categories`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const afterDeleteListJson = await afterDeleteListRes.json();
  const promotedChild = afterDeleteListJson.data.find(c => c.id === childJson.data.id);
  assert(!!promotedChild && promotedChild.parent_id === null, '상위 대분류가 삭제되면 하위 중분류는 삭제되지 않고 대분류로 승격됨');
  createdIds.splice(createdIds.indexOf(parentJson.data.id), 1); // 이미 삭제됨

  // ============================================
  // 9) bulk-create에 parent_id를 지정하면 생성되는 카테고리들이 모두 그 하위로 들어가는지 확인
  // ============================================
  const bulkParentRes = await createCategory({
    label: `계층테스트벌크대분류-${ts}`, emoji: '🧪', slug: `cathier-bulkparent-${ts}`, db_category: `cathier-bulkparent-${ts}`
  });
  const bulkParentId = bulkParentRes.json.data.id;
  const bulkCreateRes = await fetch(`${API}/api/admin/categories/bulk-create`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({
      parent_id: bulkParentId,
      categories: [
        { label: `벌크중분류1-${ts}`, emoji: '🧪', slug: `cathier-bulk1-${ts}` },
        { label: `벌크중분류2-${ts}`, emoji: '🧪', slug: `cathier-bulk2-${ts}` }
      ]
    })
  });
  const bulkCreateJson = await bulkCreateRes.json();
  assert(bulkCreateRes.status === 201 && bulkCreateJson.data.length === 2, `bulk-create로 중분류 2개 생성 성공 (실제: ${bulkCreateRes.status})`);
  assert(bulkCreateJson.data.every(c => c.parent_id === bulkParentId), 'bulk-create로 생성된 카테고리가 모두 지정한 상위 카테고리 하위로 들어감');
  bulkCreateJson.data.forEach(c => createdIds.push(c.id));

  // ============================================
  // 정리
  // ============================================
  for (const id of createdIds) {
    await fetch(`${API}/api/admin/categories/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${adminToken}` } });
  }
  await admin.from('profiles').delete().eq('id', adminId);
  await admin.auth.admin.deleteUser(adminId);
  console.log('정리 완료: 테스트 카테고리/유저 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
