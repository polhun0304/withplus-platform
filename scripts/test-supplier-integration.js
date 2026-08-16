// 📥 외부 도매/사입 사이트(도매매) 연동 기능 검증용 임시 테스트.
// 주의: 실제 도매매 판매회원 API 키가 없으므로, "실제 도매매 서버에서 정확한 상품 데이터가 오는지"까지는
// 이 테스트로 검증할 수 없다(정직하게 이 부분은 검증 범위 밖). 대신 우리가 실제로 만든 부분 —
// 권한 체크, 설정 저장/조회, 키 없을 때의 안내, import 파이프라인(중복 방지/DB 저장/실패 처리) — 은 전부 실제로 검증한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const ADMIN_EMAIL = `withplus.supint.admin.${stamp}@withplus.test`;
const MEMBER_EMAIL = `withplus.supint.member.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';
let createdUserIds = [];
let createdProductIds = [];

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
  for (const id of createdProductIds) await admin.from('products_with').delete().eq('id', id);
  await admin.from('supplier_integrations').update({ api_key: null, enabled: false, last_tested_at: null, last_test_status: null, last_test_message: null }).eq('supplier_key', 'domeggook');
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 준비 ===');
  const adminUser = await createTestUser(ADMIN_EMAIL, 'super_admin');
  const member = await createTestUser(MEMBER_EMAIL, 'member');
  // 이전 라운드 잔여 설정이 있을 수 있으니 시작 전 초기화
  await admin.from('supplier_integrations').update({ api_key: null, enabled: false, last_tested_at: null, last_test_status: null, last_test_message: null }).eq('supplier_key', 'domeggook');

  console.log('\n=== 1. 목록 조회: 인증 없으면 401, 일반 회원은 403 ===');
  const noAuth = await api('/api/admin/integrations', null);
  assert(noAuth.status === 401, `인증 없는 요청은 401 (실제=${noAuth.status})`);
  const memberList = await api('/api/admin/integrations', member.token);
  assert(memberList.status === 403, `일반 회원 요청은 403 (실제=${memberList.status})`);

  console.log('\n=== 2. 관리자는 목록을 볼 수 있고, 도매매가 등록되어 있으며 API 키 원문은 절대 노출 안 됨 ===');
  const listRes = await api('/api/admin/integrations', adminUser.token);
  assert(listRes.ok, `관리자 목록 조회 성공 (status=${listRes.status})`);
  const dome = listRes.json.data.find(i => i.supplier_key === 'domeggook');
  assert(!!dome, '목록에 도매매(domeggook) 항목이 존재함');
  assert(dome.has_key === false, `초기 상태는 키 미설정 (has_key=${dome.has_key})`);
  assert(!('api_key' in dome), '응답 어디에도 api_key 원문 필드가 없음(마스킹 확인)');

  console.log('\n=== 3. 키가 없는 상태에서 연결 테스트를 하면 400으로 명확히 안내 ===');
  const testNoKey = await api('/api/admin/integrations/domeggook/test', adminUser.token, { method: 'POST' });
  assert(testNoKey.status === 400, `키 없이 테스트하면 400 (실제=${testNoKey.status})`);

  console.log('\n=== 4. 키가 없는 상태에서 검색을 하면 400으로 명확히 안내 ===');
  const searchNoKey = await api('/api/admin/integrations/domeggook/search?keyword=텀블러', adminUser.token);
  assert(searchNoKey.status === 400, `키 없이 검색하면 400 (실제=${searchNoKey.status})`);

  console.log('\n=== 5. 일반 회원은 API 키를 저장할 수 없음(403) ===');
  const memberSave = await api('/api/admin/integrations/domeggook', member.token, { method: 'PATCH', body: JSON.stringify({ api_key: 'fake-key-123' }) });
  assert(memberSave.status === 403, `일반 회원의 키 저장 시도는 403 (실제=${memberSave.status})`);

  console.log('\n=== 6. 관리자는 API 키를 저장할 수 있고, 저장 후에도 원문은 응답에 없음 ===');
  const saveRes = await api('/api/admin/integrations/domeggook', adminUser.token, { method: 'PATCH', body: JSON.stringify({ api_key: 'fake-key-for-test-123', enabled: true }) });
  assert(saveRes.ok, `키 저장 성공 (status=${saveRes.status})`);
  assert(saveRes.json.data.has_key === true, 'has_key가 true로 바뀜');
  assert(!('api_key' in saveRes.json.data), '저장 응답에도 api_key 원문 없음');

  console.log('\n=== 7. (가짜 키로) 연결 테스트 - 실제 도매매 서버에 실시간으로 요청을 보내되, 실패를 정상적으로 처리하는지 ===');
  const testWithFakeKey = await api('/api/admin/integrations/domeggook/test', adminUser.token, { method: 'POST' });
  assert(testWithFakeKey.ok, `테스트 요청 자체는 200으로 처리됨(서버가 죽지 않음, status=${testWithFakeKey.status})`);
  assert(['success', 'failed'].includes(testWithFakeKey.json.data.status), `테스트 결과 status가 success/failed 중 하나 (실제=${testWithFakeKey.json.data.status})`);
  console.log(`   ℹ️  실제 도매매 서버 응답 메시지: ${testWithFakeKey.json.data.message.slice(0, 150)}`);

  console.log('\n=== 8. import 파이프라인: 카테고리 없이 요청하면 400 ===');
  const importNoCat = await api('/api/admin/integrations/domeggook/import', adminUser.token, {
    method: 'POST', body: JSON.stringify({ items: [{ external_id: 'ext-1', name: '테스트상품', price: 10000, stock: 5 }] })
  });
  assert(importNoCat.status === 400, `카테고리 없이 import하면 400 (실제=${importNoCat.status})`);

  console.log('\n=== 9. import 파이프라인: 정상 항목은 실제로 products_with에 생성됨 ===');
  const extId = 'test-ext-' + stamp;
  const importRes = await api('/api/admin/integrations/domeggook/import', adminUser.token, {
    method: 'POST',
    body: JSON.stringify({ items: [{ external_id: extId, name: `도매매테스트상품-${stamp}`, price: 12000, stock: 7, image_url: '' }], category: '기타' })
  });
  assert(importRes.ok, `import 요청 성공 (status=${importRes.status})`);
  assert(importRes.json.data.imported.length === 1, `1건 정상 등록됨 (실제=${importRes.json.data.imported.length})`);
  const newProductId = importRes.json.data.imported[0].product_id;
  createdProductIds.push(newProductId);
  const { data: checkProduct } = await admin.from('products_with').select('*').eq('id', newProductId).single();
  assert(!!checkProduct && checkProduct.name.includes('도매매테스트상품'), '실제 DB에 해당 상품이 정확한 이름으로 생성됨');
  assert(checkProduct.price === 12000, `가격이 정확히 저장됨 (실제=${checkProduct.price})`);

  console.log('\n=== 10. 같은 external_id로 다시 import하면 중복으로 건너뜀(재수입 방지) ===');
  const importAgain = await api('/api/admin/integrations/domeggook/import', adminUser.token, {
    method: 'POST',
    body: JSON.stringify({ items: [{ external_id: extId, name: `도매매테스트상품-${stamp}`, price: 12000, stock: 7 }], category: '기타' })
  });
  assert(importAgain.ok, `재요청 자체는 성공 (status=${importAgain.status})`);
  assert(importAgain.json.data.skipped_duplicate.length === 1, `중복이라 건너뜀 확인 (실제=${importAgain.json.data.skipped_duplicate.length})`);
  assert(importAgain.json.data.imported.length === 0, `중복 건은 다시 생성되지 않음 (실제 신규 생성=${importAgain.json.data.imported.length})`);

  console.log('\n=== 11. 필수 정보(가격 0 이하 등)가 잘못된 항목은 실패로 분류되고 생성되지 않음 ===');
  const importBad = await api('/api/admin/integrations/domeggook/import', adminUser.token, {
    method: 'POST',
    body: JSON.stringify({ items: [{ external_id: 'bad-' + stamp, name: '', price: -1 }], category: '기타' })
  });
  assert(importBad.ok && importBad.json.data.failed.length === 1, `잘못된 항목은 failed로 분류됨 (실제 failed=${importBad.json.data.failed?.length})`);

  console.log('\n🎉 모든 검증 통과 (단, 도매매 실제 서버와의 정확한 데이터 교환 자체는 실제 API 키 확보 후 별도 확인 필요)');
}

main()
  .catch(err => { console.error('\n💥 테스트 실패:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
