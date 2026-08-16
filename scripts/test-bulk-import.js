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

async function main() {
  const email = `test-bulkimport-${Date.now()}@withplus-test.local`;
  const password = 'TestPass123!';

  const { data: userData, error: createErr } = await admin.auth.admin.createUser({
    email, password, email_confirm: true
  });
  if (createErr) { console.error('user create failed', createErr); process.exit(1); }
  const userId = userData.user.id;

  // profiles_with row + admin role 부여 (스키마 확인 후 role 컬럼에 맞게)
  await admin.from('profiles').upsert([{ id: userId, email, full_name: 'BulkImportTester', role: 'admin' }]);

  const loginRes = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: anonKey },
    body: JSON.stringify({ email, password })
  });
  const loginJson = await loginRes.json();
  const token = loginJson.access_token;
  assert(!!token, '테스트 관리자 로그인 성공');

  // 카테고리 하나 조회
  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;

  // 1) 정상 항목 2건 등록
  const items1 = [
    { name: `벌크임포트테스트상품A-${Date.now()}`, price: 15000, discount_price: 12000, stock: 10, image_url: '', sku: 'BULK-A' },
    { name: `벌크임포트테스트상품B-${Date.now()}`, price: 9900, stock: 5 }
  ];
  const r1 = await fetch(`${API}/api/admin/products/bulk-import`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ items: items1, category })
  });
  const j1 = await r1.json();
  assert(r1.status === 200 && j1.success, '정상 2건 요청이 200으로 성공');
  assert(j1.data.imported.length === 2, `2건 모두 등록됨 (실제: ${j1.data.imported.length})`);
  assert(j1.data.failed.length === 0, `실패 0건 (실제: ${j1.data.failed.length})`);

  // 2) 같은 이름으로 재등록 시도 -> 중복 스킵
  const r2 = await fetch(`${API}/api/admin/products/bulk-import`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ items: items1, category })
  });
  const j2 = await r2.json();
  assert(j2.data.skipped_duplicate.length === 2, `재등록 시 2건 모두 중복 스킵됨 (실제: ${j2.data.skipped_duplicate.length})`);
  assert(j2.data.imported.length === 0, '재등록 시 신규 등록 0건');

  // 3) 같은 파일 안에서 중복된 이름 -> 두번째는 skipped
  const dupName = `벌크임포트테스트상품C-${Date.now()}`;
  const r3 = await fetch(`${API}/api/admin/products/bulk-import`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ items: [{ name: dupName, price: 5000 }, { name: dupName, price: 5000 }], category })
  });
  const j3 = await r3.json();
  assert(j3.data.imported.length === 1 && j3.data.skipped_duplicate.length === 1, `같은 파일 내 중복 이름도 1건만 등록, 1건 스킵 (실제: imported=${j3.data.imported.length}, skipped=${j3.data.skipped_duplicate.length})`);

  // 4) 필수값 누락(가격없음) -> failed
  const r4 = await fetch(`${API}/api/admin/products/bulk-import`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ items: [{ name: '가격없는상품' }], category })
  });
  const j4 = await r4.json();
  assert(j4.data.failed.length === 1, `가격 없는 행은 failed 처리됨 (실제: ${j4.data.failed.length})`);

  // 5) category 누락 -> 400
  const r5 = await fetch(`${API}/api/admin/products/bulk-import`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ items: [{ name: 'x', price: 1000 }] })
  });
  assert(r5.status === 400, `카테고리 누락 시 400 (실제: ${r5.status})`);

  // 6) items 빈 배열 -> 400
  const r6 = await fetch(`${API}/api/admin/products/bulk-import`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ items: [], category })
  });
  assert(r6.status === 400, `items 빈 배열이면 400 (실제: ${r6.status})`);

  // 7) 인증 없이 요청 -> 401
  const r7 = await fetch(`${API}/api/admin/products/bulk-import`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ items: items1, category })
  });
  assert(r7.status === 401, `인증 없으면 401 (실제: ${r7.status})`);

  // 8) 501건 초과 -> 400
  const many = Array.from({ length: 501 }, (_, i) => ({ name: `bulk-many-${i}-${Date.now()}`, price: 1000 }));
  const r8 = await fetch(`${API}/api/admin/products/bulk-import`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ items: many, category })
  });
  assert(r8.status === 400, `501건 초과 시 400 (실제: ${r8.status})`);

  // 정리: 생성된 테스트 상품 + 테스트 유저 삭제
  const { data: createdProducts } = await admin.from('products_with').select('id,name').ilike('name', '%벌크임포트테스트%');
  const { data: manyProducts } = await admin.from('products_with').select('id,name').ilike('name', 'bulk-many-%');
  const allIds = [...(createdProducts || []), ...(manyProducts || [])].map(p => p.id);
  if (allIds.length) await admin.from('products_with').delete().in('id', allIds);
  console.log(`정리: 상품 ${allIds.length}건 삭제`);

  await admin.from('profiles').delete().eq('id', userId);
  await admin.auth.admin.deleteUser(userId);
  console.log('정리: 테스트 유저 삭제 완료');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
