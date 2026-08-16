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
  const custEmail = `test-shipcust-${ts}@withplus-test.local`;
  const adminEmail = `test-shipadmin-${ts}@withplus-test.local`;
  const password = 'TestPass123!';

  const { data: custData } = await admin.auth.admin.createUser({ email: custEmail, password, email_confirm: true });
  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const custId = custData.user.id;
  const adminId = adminData.user.id;
  const { error: profileErr } = await admin.from('profiles').upsert([
    { id: custId, email: custEmail, full_name: 'ShippingTestCustomer', role: 'member' },
    { id: adminId, email: adminEmail, full_name: 'ShippingTestAdmin', role: 'admin' }
  ]);
  if (profileErr) { console.error('profile upsert failed', profileErr); process.exit(1); }

  const custToken = await loginAs(custEmail, password);
  const adminToken = await loginAs(adminEmail, password);
  assert(!!custToken && !!adminToken, '테스트 고객/관리자 로그인 성공');

  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;

  const { data: cheapProd } = await admin.from('products_with').insert({
    name: `배송비테스트저가상품-${ts}`, slug: `ship-test-cheap-${ts}`, description: '테스트', price: 10000, stock: 20,
    category, supplier_id: adminId, status: 'active'
  }).select().single();

  const { data: expensiveProd } = await admin.from('products_with').insert({
    name: `배송비테스트고가상품-${ts}`, slug: `ship-test-expensive-${ts}`, description: '테스트', price: 40000, stock: 20,
    category, supplier_id: adminId, status: 'active'
  }).select().single();

  // 기존 배송비 정책을 스냅샷해두고, 테스트가 끝나면 정확히 원상복구한다 (플랫폼 공용 설정이므로)
  const originalPolicyRes = await fetch(`${API}/api/settings/shipping-policy`);
  const originalPolicyJson = await originalPolicyRes.json();
  const originalPolicy = originalPolicyJson.data;

  // ============================================
  // 1) 공개 조회 - 기본 정책 (제주 우편번호 구간이 기본으로 들어있음)
  // ============================================
  assert(originalPolicyRes.status === 200 && originalPolicyJson.success, `배송비 정책 공개 조회 성공 (실제: ${originalPolicyRes.status})`);
  assert(typeof originalPolicy.base_fee === 'number' && typeof originalPolicy.free_shipping_threshold === 'number', '기본배송비/무료배송기준 필드가 숫자로 내려옴');
  assert(Array.isArray(originalPolicy.surcharge_zones), 'surcharge_zones가 배열로 내려옴');

  // ============================================
  // 2) 관리자 권한 검증
  // ============================================
  const noAuthPatchRes = await fetch(`${API}/api/admin/settings/shipping-policy`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ base_fee: 1000 })
  });
  assert(noAuthPatchRes.status === 401, `인증 없이 배송비 정책 변경 시도 시 401 (실제: ${noAuthPatchRes.status})`);

  const custPatchRes = await fetch(`${API}/api/admin/settings/shipping-policy`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` }, body: JSON.stringify({ base_fee: 1000 })
  });
  assert(custPatchRes.status === 403, `일반 회원이 배송비 정책 변경 시도 시 403 (실제: ${custPatchRes.status})`);

  // ============================================
  // 3) 관리자가 테스트용 정책으로 변경 (기본배송비 2,500원 / 무료배송 20,000원 이상 / 테스트 전용 우편번호 구간 추가배송비 4,000원)
  // ============================================
  const testZonePostalStart = '99000', testZonePostalEnd = '99099';
  const patchRes = await fetch(`${API}/api/admin/settings/shipping-policy`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({
      base_fee: 2500,
      free_shipping_threshold: 20000,
      surcharge_zones: [{ label: '배송비테스트지역', postal_start: testZonePostalStart, postal_end: testZonePostalEnd, fee: 4000 }]
    })
  });
  const patchJson = await patchRes.json();
  assert(patchRes.status === 200 && patchJson.success, `관리자가 배송비 정책 변경 성공 (실제: ${patchRes.status})`);
  assert(Number(patchJson.data.base_fee) === 2500, '변경된 기본배송비가 응답에 반영됨');
  assert(patchJson.data.surcharge_zones.length === 1 && patchJson.data.surcharge_zones[0].fee === 4000, '추가배송비 구간이 응답에 반영됨');

  const afterPatchRes = await fetch(`${API}/api/settings/shipping-policy`);
  const afterPatchJson = await afterPatchRes.json();
  assert(Number(afterPatchJson.data.free_shipping_threshold) === 20000, '공개 조회에도 변경된 무료배송 기준이 즉시 반영됨');

  // ============================================
  // 4) 주문 생성 시 서버가 실제로 배송비를 계산해 부과하는지 확인
  // ============================================
  // 4-1) 저가 상품(10,000원) + 배송지 없음 -> 무료배송 기준(20,000원) 미달이므로 기본배송비(2,500원)만 부과
  const order1Res = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: cheapProd.id, name: cheapProd.name, price: cheapProd.price, quantity: 1 }] })
  });
  const order1Json = await order1Res.json();
  assert(order1Res.status === 201, `저가 상품 주문 생성 성공 (실제: ${order1Res.status})`);
  assert(Number(order1Json.data.shipping_fee) === 2500, `무료배송 기준 미달 시 기본배송비(2,500원)만 부과됨 (실제: ${order1Json.data.shipping_fee})`);
  assert(!order1Json.data.shipping_surcharge_label, '배송지가 없으면 추가배송비 라벨이 없음');
  assert(Number(order1Json.data.final_price) === cheapProd.price + 2500, `최종 결제금액 = 상품가 + 기본배송비 (실제: ${order1Json.data.final_price})`);

  // 4-2) 고가 상품(40,000원) -> 무료배송 기준(20,000원) 이상이므로 배송비 0원
  const order2Res = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: expensiveProd.id, name: expensiveProd.name, price: expensiveProd.price, quantity: 1 }] })
  });
  const order2Json = await order2Res.json();
  assert(Number(order2Json.data.shipping_fee) === 0, `무료배송 기준 이상 구매 시 배송비 0원 (실제: ${order2Json.data.shipping_fee})`);

  // 4-3) 고가 상품(40,000원) + 테스트 추가배송비 구간 우편번호 -> 무료배송 기준을 넘었어도 추가배송비는 별도로 부과됨
  const order3Res = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({
      items: [{ product_id: expensiveProd.id, name: expensiveProd.name, price: expensiveProd.price, quantity: 1 }],
      shipping_address: { name: '테스터', phone: '010-0000-0000', address: '테스트 주소', postal_code: '99050' }
    })
  });
  const order3Json = await order3Res.json();
  assert(Number(order3Json.data.shipping_fee) === 4000, `무료배송 기준을 넘어도 도서산간 성격의 추가배송비(4,000원)는 별도 부과됨 (실제: ${order3Json.data.shipping_fee})`);
  assert(order3Json.data.shipping_surcharge_label === '배송비테스트지역', '추가배송비 라벨이 정확히 기록됨');

  // 4-4) 저가 상품(10,000원) + 테스트 추가배송비 구간 우편번호 -> 기본배송비 + 추가배송비 합산
  const order4Res = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({
      items: [{ product_id: cheapProd.id, name: cheapProd.name, price: cheapProd.price, quantity: 1 }],
      shipping_address: { name: '테스터', phone: '010-0000-0000', address: '테스트 주소', postal_code: '99099' }
    })
  });
  const order4Json = await order4Res.json();
  assert(Number(order4Json.data.shipping_fee) === 2500 + 4000, `기본배송비 미달 + 추가배송비 구간 -> 합산 부과됨 (실제: ${order4Json.data.shipping_fee})`);

  // 4-5) 구간 밖 우편번호 -> 추가배송비 없음
  const order5Res = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({
      items: [{ product_id: expensiveProd.id, name: expensiveProd.name, price: expensiveProd.price, quantity: 1 }],
      shipping_address: { name: '테스터', phone: '010-0000-0000', address: '테스트 주소', postal_code: '10000' }
    })
  });
  const order5Json = await order5Res.json();
  assert(Number(order5Json.data.shipping_fee) === 0, `추가배송비 구간 밖 우편번호는 부과되지 않음 (실제: ${order5Json.data.shipping_fee})`);

  // ============================================
  // 5) 택배사 목록 + 운송장 조회 링크 자동 생성
  // ============================================
  const couriersRes = await fetch(`${API}/api/couriers`);
  const couriersJson = await couriersRes.json();
  assert(couriersRes.status === 200 && Array.isArray(couriersJson.data) && couriersJson.data.includes('CJ대한통운'), `택배사 목록 조회 성공, CJ대한통운 포함 (실제 개수: ${couriersJson.data.length})`);

  const trackingSetRes = await fetch(`${API}/api/admin/orders/${order1Json.data.id}/status`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ courier_name: 'CJ대한통운', tracking_number: '123456789012' })
  });
  const trackingSetJson = await trackingSetRes.json();
  assert(trackingSetRes.status === 200, `택배사/운송장번호 저장 성공 (실제: ${trackingSetRes.status})`);
  assert(!!trackingSetJson.data.tracking_url && trackingSetJson.data.tracking_url.includes('123456789012'), `운송장 조회 링크가 자동 생성됨 (실제: ${trackingSetJson.data.tracking_url})`);

  // 운송장번호만 바꿔도(택배사는 그대로) 조회 링크가 새 번호로 다시 계산되는지 확인
  const trackingUpdateRes = await fetch(`${API}/api/admin/orders/${order1Json.data.id}/status`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ tracking_number: '999888777666' })
  });
  const trackingUpdateJson = await trackingUpdateRes.json();
  assert(trackingUpdateJson.data.tracking_url.includes('999888777666') && trackingUpdateJson.data.courier_name === 'CJ대한통운', '운송장번호만 변경해도 기존 택배사 기준으로 조회 링크가 재계산됨');

  // "기타"(목록에 없는 임의 값)로 지정하면 조회 링크는 만들지 않음(정직하게 null)
  const etcRes = await fetch(`${API}/api/admin/orders/${order2Json.data.id}/status`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ courier_name: '동네택배아저씨', tracking_number: '111' })
  });
  const etcJson = await etcRes.json();
  assert(etcJson.data.tracking_url === null, '목록에 없는 임의 택배사명은 조회 링크를 만들지 않고 정직하게 null로 남김');

  // ============================================
  // 정리: 정책 원상복구 + 테스트 데이터 삭제
  // ============================================
  await fetch(`${API}/api/admin/settings/shipping-policy`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify(originalPolicy)
  });
  const restoredRes = await fetch(`${API}/api/settings/shipping-policy`);
  const restoredJson = await restoredRes.json();
  assert(Number(restoredJson.data.base_fee) === Number(originalPolicy.base_fee), '테스트 종료 후 배송비 정책이 원래 값으로 복구됨');

  await admin.from('orders_with').delete().in('id', [order1Json.data.id, order2Json.data.id, order3Json.data.id, order4Json.data.id, order5Json.data.id]);
  await admin.from('products_with').delete().in('id', [cheapProd.id, expensiveProd.id]);
  await admin.from('profiles').delete().in('id', [custId, adminId]);
  await admin.auth.admin.deleteUser(custId);
  await admin.auth.admin.deleteUser(adminId);
  console.log('정리 완료: 정책 복구 + 주문/상품/유저 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
