// 회원 등급/혜택 시스템 검증용 임시 테스트.
// - 신규 회원은 기본(일반) 등급인지
// - 누적 구매액에 따라 등급이 올라가는지, 등급 보너스 적립율이 개인 마일리지에 반영되는지
// - 취소/환불 주문은 누적액에서 제외되는지
// - 관리자 등급 설정 API(GET/PATCH)가 정상 동작하는지
// 검증 후 생성한 데이터는 모두 정리한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const SUPER_EMAIL = `withplus.grade.admin.${stamp}@withplus.test`;
const SUPPLIER_EMAIL = `withplus.grade.supplier.${stamp}@withplus.test`;
const BUYER_EMAIL = `withplus.grade.buyer.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';

let createdUserIds = [];
let createdProductIds = [];
let createdOrderIds = [];

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
  for (const id of createdOrderIds) {
    await admin.from('stock_adjustments_with').delete().eq('order_id', id);
    await admin.from('orders_with').delete().eq('id', id);
  }
  for (const id of createdProductIds) await admin.from('products_with').delete().eq('id', id);
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function placeOrder(buyer, productId, price, status) {
  const order = await api('/api/orders', buyer.token, {
    method: 'POST',
    body: JSON.stringify({ items: [{ product_id: productId, name: 'grade-test-product', price, quantity: 1 }] })
  });
  if (!order.ok) throw new Error('주문 생성 실패: ' + JSON.stringify(order.json));
  createdOrderIds.push(order.json.data.id);
  if (status) {
    const { error } = await admin.from('orders_with').update({ status }).eq('id', order.json.data.id);
    if (error) throw error;
  }
  return order;
}

async function main() {
  console.log('=== 테스트 계정 준비 ===');
  const superAdmin = await createTestUser(SUPER_EMAIL, 'super_admin');
  const supplier = await createTestUser(SUPPLIER_EMAIL, 'provider');
  const buyer = await createTestUser(BUYER_EMAIL, null);

  console.log('\n=== 1. 등급 설정 공개 조회(GET /api/settings/member-grades) ===');
  const gradesRes = await api('/api/settings/member-grades', null);
  assert(gradesRes.ok, `등급 설정 조회 성공 (status=${gradesRes.status})`);
  assert(gradesRes.json.data.some(g => g.key === 'general' && Number(g.min_spent) === 0), '기본(일반) 등급이 존재하고 min_spent=0');

  console.log('\n=== 2. 신규 회원은 기본(일반) 등급, 누적 구매액 0 ===');
  const myGrade0 = await api('/api/me/grade', buyer.token);
  assert(myGrade0.ok, `내 등급 조회 성공 (status=${myGrade0.status})`);
  assert(myGrade0.json.data.current.key === 'general', `신규 회원은 일반 등급 (실제=${myGrade0.json.data.current.key})`);
  assert(myGrade0.json.data.totalSpent === 0, `신규 회원 누적 구매액은 0 (실제=${myGrade0.json.data.totalSpent})`);

  console.log('\n=== 3. 테스트용 상품 생성 ===');
  // 🔒 주문 금액은 이제 서버가 DB의 실제 판매가로 재계산하므로(가격조작 방지 수정 이후), 아래 시나리오별로
  // 필요한 금액(400,000 / 100,000 / 3,000,000원)마다 실제로 그 가격의 상품을 따로 만든다
  // (예전에는 상품 하나를 만들어두고 주문 요청의 price 값만 바꿔서 보내는 방식으로 충분했지만,
  // 이제 그 방식은 더 이상 통하지 않는다 - 통한다면 오히려 그게 취약점이다).
  async function createProductWithPrice(price) {
    const res = await api('/api/products', supplier.token, {
      method: 'POST',
      body: JSON.stringify({ name: `등급테스트상품-${price}-${stamp}`, price, category: 'fashion', stock: 100 })
    });
    assert(res.ok, `상품 생성 성공(가격 ${price}원, status=${res.status})`);
    createdProductIds.push(res.json.data.id);
    return res.json.data.id;
  }
  const productId = await createProductWithPrice(400000);

  console.log('\n=== 4. 400,000원 구매 후 실버 등급으로 승급(기준 300,000원) ===');
  const order1 = await placeOrder(buyer, productId, 400000);
  assert(order1.json.memberGrade.key === 'general', `구매 시점(누적 이전 기준)에는 아직 일반 등급 적립 적용 (실제=${order1.json.memberGrade.key})`);
  const myGrade1 = await api('/api/me/grade', buyer.token);
  assert(myGrade1.json.data.current.key === 'silver', `누적 400,000원 이후 실버 등급으로 승급 (실제=${myGrade1.json.data.current.key})`);
  assert(myGrade1.json.data.totalSpent === 400000, `누적 구매액이 정확히 반영됨 (실제=${myGrade1.json.data.totalSpent})`);

  console.log('\n=== 5. 실버 등급 상태에서 추가 구매 시 등급 보너스가 개인 적립율에 반영됨 ===');
  const ratesRes = await api('/api/settings/mileage-rates', null);
  const basePersonalRate = Number(ratesRes.json.data.personal);
  const product100k = await createProductWithPrice(100000);
  const order2 = await placeOrder(buyer, product100k, 100000);
  assert(order2.json.memberGrade.key === 'silver', `두 번째 주문은 실버 등급으로 적립됨 (실제=${order2.json.memberGrade.key})`);
  const expectedRate = basePersonalRate + Number(order2.json.memberGrade.bonusPersonalRate || 0);
  const expectedPoints = Math.floor(100000 * expectedRate);
  assert(order2.json.mileage.personal === expectedPoints, `등급 보너스가 반영된 적립 포인트 계산이 정확함 (기대=${expectedPoints}, 실제=${order2.json.mileage.personal})`);

  console.log('\n=== 6. 취소된 주문은 누적 구매액에서 제외됨 ===');
  const product3m = await createProductWithPrice(3000000);
  const order3 = await placeOrder(buyer, product3m, 3000000, 'cancelled');
  const myGrade2 = await api('/api/me/grade', buyer.token);
  assert(myGrade2.json.data.totalSpent === 500000, `취소 주문(300만원)은 누적액에서 제외됨 (실제=${myGrade2.json.data.totalSpent})`);
  assert(myGrade2.json.data.current.key === 'silver', `취소 주문 제외 시 여전히 실버 등급 (실제=${myGrade2.json.data.current.key})`);

  console.log('\n=== 7. 로그인 없이 /api/me/grade 접근 불가 ===');
  const noAuth = await api('/api/me/grade', null);
  assert(noAuth.status === 401 || noAuth.status === 403, `인증 없이 접근 시 401/403 (실제=${noAuth.status})`);

  console.log('\n=== 8. 관리자 등급 설정 변경(PATCH) ===');
  const originalGrades = gradesRes.json.data;
  const patchRes = await api('/api/admin/settings/member-grades', superAdmin.token, {
    method: 'PATCH',
    body: JSON.stringify({ grades: [
      { key: 'general', label: '일반', min_spent: 0, bonus_personal_rate: 0 },
      { key: 'silver', label: '실버', min_spent: 200000, bonus_personal_rate: 0.005 },
      { key: 'gold', label: '골드', min_spent: 1000000, bonus_personal_rate: 0.01 },
      { key: 'vip', label: 'VIP', min_spent: 3000000, bonus_personal_rate: 0.02 }
    ] })
  });
  assert(patchRes.ok, `등급 설정 변경(관리자) 성공 (status=${patchRes.status})`);
  const gradesAfterPatch = await api('/api/settings/member-grades', null);
  assert(Number(gradesAfterPatch.json.data.find(g => g.key === 'silver').min_spent) === 200000, `변경된 실버 기준(200,000원)이 반영됨`);

  console.log('\n=== 9. 관리자가 아니면 등급 설정 변경 불가 ===');
  const forbiddenPatch = await api('/api/admin/settings/member-grades', buyer.token, {
    method: 'PATCH',
    body: JSON.stringify({ grades: originalGrades })
  });
  assert(forbiddenPatch.status === 403, `일반 회원의 등급 설정 변경 시도는 403 (실제=${forbiddenPatch.status})`);

  console.log('\n=== 10. 최하위 등급 min_spent가 0이 아니면 거부됨 ===');
  const badPatch = await api('/api/admin/settings/member-grades', superAdmin.token, {
    method: 'PATCH',
    body: JSON.stringify({ grades: [{ key: 'general', label: '일반', min_spent: 100, bonus_personal_rate: 0 }] })
  });
  assert(badPatch.status === 400, `최하위 등급 min_spent!=0 이면 400 (실제=${badPatch.status})`);

  console.log('\n=== 11. 설정을 원래대로 복구 ===');
  const restorePatch = await api('/api/admin/settings/member-grades', superAdmin.token, {
    method: 'PATCH',
    body: JSON.stringify({ grades: originalGrades })
  });
  assert(restorePatch.ok, `등급 설정 원복 성공 (status=${restorePatch.status})`);

  console.log('\n🎉 모든 검증 통과');
}

main()
  .catch(err => { console.error('\n💥 테스트 실패:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
