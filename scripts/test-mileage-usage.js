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
  const custEmail = `test-mileagecust-${ts}@withplus-test.local`;
  const adminEmail = `test-mileageadmin-${ts}@withplus-test.local`;
  const password = 'TestPass123!';

  const { data: custData } = await admin.auth.admin.createUser({ email: custEmail, password, email_confirm: true });
  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const custId = custData.user.id;
  const adminId = adminData.user.id;
  const { error: profileErr } = await admin.from('profiles').upsert([
    { id: custId, email: custEmail, full_name: 'MileageTestCustomer', role: 'member' },
    { id: adminId, email: adminEmail, full_name: 'MileageTestAdmin', role: 'admin' }
  ]);
  if (profileErr) { console.error('profile upsert failed', profileErr); process.exit(1); }

  const custToken = await loginAs(custEmail, password);
  assert(!!custToken, '테스트 고객 로그인 성공');

  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;

  const { data: prod, error: prodErr } = await admin.from('products_with').insert({
    name: `마일리지테스트상품-${ts}`, slug: `mileage-test-${ts}`, description: '테스트 상품입니다', price: 50000, stock: 20,
    category, supplier_id: adminId, status: 'active'
  }).select().single();
  if (prodErr) { console.error('product create failed', prodErr); process.exit(1); }

  // ============================================
  // 0) 마일리지 잔액 없을 때 사용 시도 -> 차단
  // ============================================
  const zeroBalanceRes = await fetch(`${API}/api/me/mileage-balance`, { headers: { Authorization: `Bearer ${custToken}` } });
  const zeroBalanceJson = await zeroBalanceRes.json();
  assert(zeroBalanceJson.success && zeroBalanceJson.data.balance === 0, `초기 마일리지 잔액 0 (실제: ${zeroBalanceJson.data?.balance})`);

  const blockedUseRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: prod.id, name: prod.name, price: prod.price, quantity: 1 }], use_mileage: 1000 })
  });
  assert(blockedUseRes.status === 400, `잔액 없이 마일리지 사용 시도 시 400 (실제: ${blockedUseRes.status})`);

  // ============================================
  // 1) 주문A 생성(마일리지 미사용) -> 개인 마일리지 적립 확인
  // ============================================
  const orderARes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: prod.id, name: prod.name, price: prod.price, quantity: 1 }] })
  });
  const orderAJson = await orderARes.json();
  assert(orderARes.status === 201, `주문A 생성 성공 (실제: ${orderARes.status})`);
  const orderA = orderAJson.data;
  assert(Number(orderA.personal_earned_points) > 0, `주문A에서 개인 마일리지 적립됨 (실제: ${orderA.personal_earned_points})`);
  assert(Number(orderA.used_mileage) === 0, `주문A는 마일리지 미사용 (실제: ${orderA.used_mileage})`);

  const balanceAfterARes = await fetch(`${API}/api/me/mileage-balance`, { headers: { Authorization: `Bearer ${custToken}` } });
  const balanceAfterAJson = await balanceAfterARes.json();
  const balanceAfterA = balanceAfterAJson.data.balance;
  assert(balanceAfterA === Number(orderA.personal_earned_points), `주문A 이후 잔액 = 주문A 적립액 (실제: ${balanceAfterA} vs ${orderA.personal_earned_points})`);

  // ============================================
  // 2) 잔액보다 많은 마일리지 사용 시도 -> 400
  // ============================================
  const overUseRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: prod.id, name: prod.name, price: prod.price, quantity: 1 }], use_mileage: balanceAfterA + 1000 })
  });
  assert(overUseRes.status === 400, `잔액 초과 마일리지 사용 시도 시 400 (실제: ${overUseRes.status})`);

  // ============================================
  // 3) 주문B: 보유 마일리지 일부 사용 -> 결제금액에서 정확히 차감되는지 확인
  // ============================================
  const useAmount = Math.floor(balanceAfterA / 2);
  const orderBRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: prod.id, name: prod.name, price: prod.price, quantity: 1 }], use_mileage: useAmount })
  });
  const orderBJson = await orderBRes.json();
  assert(orderBRes.status === 201, `주문B(마일리지 일부사용) 생성 성공 (실제: ${orderBRes.status})`);
  const orderB = orderBJson.data;
  assert(Number(orderB.used_mileage) === useAmount, `주문B used_mileage 정확히 반영됨 (실제: ${orderB.used_mileage} / 기대: ${useAmount})`);
  assert(Number(orderB.final_price) === prod.price - useAmount, `주문B 최종 결제금액 = 상품가 - 사용마일리지 (실제: ${orderB.final_price} / 기대: ${prod.price - useAmount})`);

  const balanceAfterBRes = await fetch(`${API}/api/me/mileage-balance`, { headers: { Authorization: `Bearer ${custToken}` } });
  const balanceAfterBJson = await balanceAfterBRes.json();
  const expectedBalanceAfterB = balanceAfterA - useAmount + Number(orderB.personal_earned_points);
  assert(balanceAfterBJson.data.balance === expectedBalanceAfterB, `주문B 이후 잔액 정확히 계산됨 (실제: ${balanceAfterBJson.data.balance} / 기대: ${expectedBalanceAfterB})`);

  // ============================================
  // 4) 보유 마일리지가 상품 금액(100원)보다 많을 때 -> 자동으로 상품 금액만큼만 사용(상품값은 0원), 초과분은 쓰지 않음
  //    단, 배송비 정책(기본 3,000원, 30,000원 이상 무료)이 새로 생겨서 마일리지는 배송비에는 적용되지 않는다 -
  //    이 테스트는 배송지를 보내지 않으므로 도서산간 추가금액 없이 기본 배송비만 최종 결제금액에 남는다.
  // ============================================
  // 🔒 주문 금액은 서버가 DB의 실제 판매가로 재계산하므로(가격조작 방지 수정 이후), 클라이언트가 price를 100원으로
  // 보내는 것만으로는 더 이상 저렴한 주문을 만들 수 없다. 이 하위 테스트만을 위해 실제로 100원짜리 상품을 DB에 만든다.
  const cheapItemPrice = 100;
  const { data: cheapProd } = await admin.from('products_with').insert({
    name: `마일리지테스트저가상품-${ts}`, slug: `mileage-test-cheap-${ts}`, description: '테스트 상품입니다', price: cheapItemPrice, stock: 20,
    category, supplier_id: adminId, status: 'active'
  }).select().single();
  const balanceBeforeHuge = balanceAfterBJson.data.balance; // 이 시점 잔액이 100원보다 크다는 전제(주문A/B 적립액 규모상 항상 성립)
  const hugeUseRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: cheapProd.id, name: cheapProd.name, price: cheapItemPrice, quantity: 1 }], use_mileage: balanceBeforeHuge })
  });
  const hugeUseJson = await hugeUseRes.json();
  assert(hugeUseRes.status === 201, `마일리지로 결제금액 전액 커버 시도 성공 (실제: ${hugeUseRes.status})`);
  assert(Number(hugeUseJson.data.shipping_fee) === 3000, `배송비 정책의 기본 배송비(3,000원)가 배송지 없이도 부과됨 (실제: ${hugeUseJson.data.shipping_fee})`);
  assert(Number(hugeUseJson.data.final_price) === 3000, `마일리지는 상품값(100원)만 커버하고 배송비(3,000원)는 최종 결제금액에 남음 (실제: ${hugeUseJson.data.final_price})`);
  assert(Number(hugeUseJson.data.used_mileage) === cheapItemPrice, `사용된 마일리지가 상품금액(${cheapItemPrice}원)으로 캡핑됨 (실제: ${hugeUseJson.data.used_mileage})`);

  // ============================================
  // 5) 마일리지 사용한 주문(주문B)을 취소하면 사용한 마일리지가 잔액에 복구되는지 확인
  // ============================================
  const adminToken = await loginAs(adminEmail, password);
  const cancelReqRes = await fetch(`${API}/api/orders/${orderB.id}/return-request`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ request_type: 'cancel', reason: '마일리지 복구 테스트용 취소' })
  });
  const cancelReqJson = await cancelReqRes.json();
  assert(cancelReqRes.status === 201, `주문B 취소 신청 성공 (실제: ${cancelReqRes.status})`);

  const approveRes = await fetch(`${API}/api/admin/return-requests/${cancelReqJson.data.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'completed' })
  });
  assert(approveRes.status === 200, `주문B 취소 승인 성공 (실제: ${approveRes.status})`);

  const balanceAfterCancelRes = await fetch(`${API}/api/me/mileage-balance`, { headers: { Authorization: `Bearer ${custToken}` } });
  const balanceAfterCancelJson = await balanceAfterCancelRes.json();
  // 취소 직전 잔액 = 주문B 이후 잔액 - (0원결제 주문에서 사용한 마일리지) + (0원결제 주문의 적립분, 이번엔 0)
  const balanceBeforeCancel = balanceBeforeHuge - Number(hugeUseJson.data.used_mileage) + Number(hugeUseJson.data.personal_earned_points);
  // 주문B를 취소하면 주문B의 적립분은 빠지고(-), 주문B에서 썼던 마일리지는 다시 돌아온다(+)
  const expectedAfterCancel = balanceBeforeCancel - Number(orderB.personal_earned_points) + useAmount;
  assert(balanceAfterCancelJson.data.balance === expectedAfterCancel, `취소 후 마일리지 잔액이 정확히 복구됨 (실제: ${balanceAfterCancelJson.data.balance} / 기대: ${expectedAfterCancel})`);

  // 정리
  const { data: allOrders } = await admin.from('orders_with').select('id').eq('user_id', custId);
  const orderIds = (allOrders || []).map(o => o.id);
  await admin.from('return_requests').delete().in('order_id', orderIds);
  await admin.from('orders_with').delete().in('id', orderIds);
  await admin.from('products_with').delete().in('id', [prod.id, cheapProd.id]);
  await admin.from('profiles').delete().in('id', [custId, adminId]);
  await admin.auth.admin.deleteUser(custId);
  await admin.auth.admin.deleteUser(adminId);
  console.log('정리 완료: 주문/상품/유저 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
