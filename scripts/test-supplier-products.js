const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);
const API = 'http://localhost:3003';

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌', msg); }
}

async function main() {
  const ts = Date.now();
  const createdProductIds = [];
  const createdUserIds = [];

  // ============================================
  // 0) 상품상세 화면의 "이 공급사의 다른 상품" 기능 검증용 데이터 준비
  //    - 공급자 A: 판매중 상품 3개(그 중 1개는 이번에 상세를 보는 기준 상품) + 판매중지 상품 1개(노출되면 안 됨)
  //    - 공급자 B: 판매중 상품 1개(A의 상품 상세에는 절대 섞여 나오면 안 됨)
  //    - 공급자 없음(관리자가 직접 등록한 것처럼) 상품 1개(공급사 섹션 자체가 안 떠야 함)
  // ============================================
  const supplierAEmail = `test-suppprod-a-${ts}@withplus-test.local`;
  const { data: supplierAUser } = await admin.auth.admin.createUser({ email: supplierAEmail, password: 'TestPass123!', email_confirm: true });
  const supplierAId = supplierAUser.user.id;
  createdUserIds.push(supplierAId);
  await admin.from('profiles').upsert([{ id: supplierAId, email: supplierAEmail, full_name: '테스트공급사A', role: 'provider' }]);

  const supplierBEmail = `test-suppprod-b-${ts}@withplus-test.local`;
  const { data: supplierBUser } = await admin.auth.admin.createUser({ email: supplierBEmail, password: 'TestPass123!', email_confirm: true });
  const supplierBId = supplierBUser.user.id;
  createdUserIds.push(supplierBId);
  await admin.from('profiles').upsert([{ id: supplierBId, email: supplierBEmail, full_name: null, role: 'provider' }]); // full_name 없을 때 "공급사" 기본값으로 대체되는지도 함께 검증

  async function makeProduct(name, supplierId, status) {
    const { data, error } = await admin.from('products_with').insert([{
      name, slug: `test-suppprod-${ts}-${Math.random().toString(36).slice(2, 8)}`,
      description: 'x', price: 10000, category: 'diet', stock: 10,
      images_urls: [], supplier_id: supplierId, status
    }]).select().single();
    if (error) throw error;
    createdProductIds.push(data.id);
    return data;
  }

  const mainProduct = await makeProduct(`공급사A상품-기준-${ts}`, supplierAId, 'active');
  const otherActiveA = await makeProduct(`공급사A상품-다른상품-${ts}`, supplierAId, 'active');
  const inactiveA = await makeProduct(`공급사A상품-판매중지-${ts}`, supplierAId, 'inactive');
  const productB = await makeProduct(`공급사B상품-${ts}`, supplierBId, 'active');
  const noSupplierProduct = await makeProduct(`공급자없음상품-${ts}`, null, 'active');

  // ============================================
  // 1) 공급자가 있는 상품 - 같은 공급자의 다른 판매중 상품만 정확히 노출
  // ============================================
  const resA = await fetch(`${API}/api/products/${mainProduct.id}/supplier-products`);
  const jsonA = await resA.json();
  assert(resA.status === 200 && jsonA.success, '공급자가 있는 상품의 supplier-products API가 정상 응답함');
  assert(jsonA.supplier && jsonA.supplier.name === '테스트공급사A', '응답에 공급자 이름(full_name)이 정확히 포함됨');
  assert(jsonA.supplier.product_count === 2, '공급자의 전체 판매중 상품 수(기준상품+다른상품, 판매중지 제외)가 정확히 2로 집계됨');
  const idsA = jsonA.data.map(p => p.id);
  assert(idsA.includes(otherActiveA.id), '같은 공급자의 판매중인 다른 상품이 목록에 포함됨');
  assert(!idsA.includes(mainProduct.id), '기준이 된 상품 자기 자신은 목록에서 제외됨');
  assert(!idsA.includes(inactiveA.id), '같은 공급자라도 판매중지(inactive) 상품은 목록에서 제외됨');
  assert(!idsA.includes(productB.id), '다른 공급자(B)의 상품은 절대 섞여 나오지 않음');

  // ============================================
  // 2) 공급자가 없는 상품(관리자가 직접 등록한 것처럼) - 정직하게 supplier: null, 빈 목록
  // ============================================
  const resNo = await fetch(`${API}/api/products/${noSupplierProduct.id}/supplier-products`);
  const jsonNo = await resNo.json();
  assert(resNo.status === 200 && jsonNo.success, '공급자 없는 상품도 API 자체는 정상 응답함(에러 아님)');
  assert(jsonNo.supplier === null, '공급자가 없으면 supplier가 정직하게 null로 내려옴');
  assert(Array.isArray(jsonNo.data) && jsonNo.data.length === 0, '공급자가 없으면 다른 상품 목록도 빈 배열로 내려옴');

  // ============================================
  // 3) full_name이 없는 공급자는 "공급사" 기본값으로 표시됨(개인정보 유출 없이)
  // ============================================
  const resB = await fetch(`${API}/api/products/${productB.id}/supplier-products`);
  const jsonB = await resB.json();
  assert(jsonB.supplier && jsonB.supplier.name === '공급사', 'full_name이 없는 공급자는 이메일 대신 "공급사" 기본값으로 표시됨(개인정보 비노출)');
  assert(jsonB.data.length === 0, '공급자 B는 다른 판매중 상품이 없으므로 빈 목록(자기 자신 제외)');
  assert(!JSON.stringify(jsonB).includes(supplierBEmail), '응답 어디에도 공급자의 이메일이 노출되지 않음');

  // ============================================
  // 4) limit 파라미터 동작
  // ============================================
  const resLimit = await fetch(`${API}/api/products/${mainProduct.id}/supplier-products?limit=1`);
  const jsonLimit = await resLimit.json();
  assert(jsonLimit.data.length === 1, 'limit 파라미터가 정확히 반영됨');
  assert(jsonLimit.supplier.product_count === 2, 'limit을 줄여도 product_count(전체 개수)는 그대로 정확히 유지됨');

  // ============================================
  // 5) 존재하지 않는 상품 id
  // ============================================
  const resMissing = await fetch(`${API}/api/products/00000000-0000-0000-0000-000000000000/supplier-products`);
  const jsonMissing = await resMissing.json();
  assert(resMissing.status === 200 && jsonMissing.supplier === null && jsonMissing.data.length === 0, '존재하지 않는 상품 id도 에러 없이 정직하게 빈 결과로 응답함');

  // ============================================
  // 6) 상품 상세 화면(product.html) 자체가 여전히 정상 응답하는지 (신규 fetch 추가로 화면이 깨지지 않았는지)
  // ============================================
  const detailPageRes = await fetch(`${API}/product/${mainProduct.id}`);
  assert(detailPageRes.status === 200, '상품 상세 화면(/product/:id)이 여전히 200 정상 응답함');

  // ============================================
  // 정리
  // ============================================
  for (const id of createdProductIds) {
    await admin.from('products_with').delete().eq('id', id);
  }
  for (const id of createdUserIds) {
    await admin.from('profiles').delete().eq('id', id);
    await admin.auth.admin.deleteUser(id).catch(() => {});
  }

  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => { console.error('테스트 실행 중 오류:', err); process.exit(1); });
