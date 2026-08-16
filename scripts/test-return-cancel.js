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
  const custEmail = `test-returncust-${ts}@withplus-test.local`;
  const adminEmail = `test-returnadmin-${ts}@withplus-test.local`;
  const password = 'TestPass123!';

  const { data: custData } = await admin.auth.admin.createUser({ email: custEmail, password, email_confirm: true });
  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const custId = custData.user.id;
  const adminId = adminData.user.id;
  const { error: profileErr } = await admin.from('profiles').upsert([
    { id: custId, email: custEmail, full_name: 'ReturnTestCustomer', role: 'member' },
    { id: adminId, email: adminEmail, full_name: 'ReturnTestAdmin', role: 'admin' }
  ]);
  if (profileErr) { console.error('profile upsert failed', profileErr); process.exit(1); }

  const custToken = await loginAs(custEmail, password);
  const adminToken = await loginAs(adminEmail, password);
  assert(!!custToken && !!adminToken, '테스트 고객/관리자 로그인 성공');

  // 카테고리 하나
  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;

  // 테스트 상품 2개 생성 (재고 확인용), supplier_id는 admin 계정으로
  const { data: prod1, error: p1err } = await admin.from('products_with').insert({
    name: `취소테스트상품-${ts}`, slug: `cancel-test-${ts}`, description: '테스트 상품입니다', price: 10000, stock: 5,
    category, supplier_id: adminId, status: 'active'
  }).select().single();
  const { data: prod2, error: p2err } = await admin.from('products_with').insert({
    name: `반품테스트상품-${ts}`, slug: `return-test-${ts}`, description: '테스트 상품입니다', price: 20000, stock: 3,
    category, supplier_id: adminId, status: 'active'
  }).select().single();
  if (p1err || p2err) { console.error('상품 생성 실패', p1err, p2err); process.exit(1); }

  // ============================================
  // 1) 취소 플로우: pending 주문 -> 취소 신청 -> 관리자 완료 처리 -> 재고 복구 + 주문상태 cancelled
  // ============================================
  const order1Res = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: prod1.id, name: prod1.name, price: prod1.price, quantity: 2 }] })
  });
  const order1Json = await order1Res.json();
  assert(order1Res.status === 201 || order1Res.status === 200, `주문1 생성 성공 (실제: ${order1Res.status})`);
  const order1 = order1Json.data;

  const { data: stockAfterOrder1 } = await admin.from('products_with').select('stock').eq('id', prod1.id).single();
  assert(Number(stockAfterOrder1.stock) === 3, `주문1 생성 후 재고 5->3으로 차감됨 (실제: ${stockAfterOrder1.stock})`);

  // pending 상태에서 반품(return) 신청 시도 -> 실패해야 함
  const wrongTypeRes = await fetch(`${API}/api/orders/${order1.id}/return-request`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ request_type: 'return', reason: '테스트' })
  });
  assert(wrongTypeRes.status === 400, `pending 주문에 반품 신청 시 400 (실제: ${wrongTypeRes.status})`);

  // pending 상태에서 취소(cancel) 신청 -> 성공해야 함
  const cancelReqRes = await fetch(`${API}/api/orders/${order1.id}/return-request`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ request_type: 'cancel', reason: '단순 변심으로 취소합니다' })
  });
  const cancelReqJson = await cancelReqRes.json();
  assert(cancelReqRes.status === 201 && cancelReqJson.success, `pending 주문에 취소 신청 성공 (실제: ${cancelReqRes.status})`);
  const cancelRequestId = cancelReqJson.data.id;

  // 관리자가 취소 신청을 completed로 처리
  const approveCancelRes = await fetch(`${API}/api/admin/return-requests/${cancelRequestId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'completed' })
  });
  const approveCancelJson = await approveCancelRes.json();
  assert(approveCancelRes.status === 200 && approveCancelJson.success, `관리자 취소 승인(completed) 성공 (실제: ${approveCancelRes.status})`);
  assert(approveCancelJson.sideEffect && approveCancelJson.sideEffect.order_status === 'cancelled', `sideEffect.order_status === 'cancelled' (실제: ${JSON.stringify(approveCancelJson.sideEffect)})`);

  const { data: order1After } = await admin.from('orders_with').select('status').eq('id', order1.id).single();
  assert(order1After.status === 'cancelled', `주문1 상태가 cancelled로 변경됨 (실제: ${order1After.status})`);

  const { data: stockAfterCancel } = await admin.from('products_with').select('stock').eq('id', prod1.id).single();
  assert(Number(stockAfterCancel.stock) === 5, `취소 승인 후 재고 3->5로 복구됨 (실제: ${stockAfterCancel.stock})`);

  // ============================================
  // 2) 반품 플로우: delivered 주문 -> 반품 신청 -> 관리자 완료 처리 -> 재고 복구 + 주문상태 refunded
  // ============================================
  const order2Res = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: prod2.id, name: prod2.name, price: prod2.price, quantity: 1 }] })
  });
  const order2Json = await order2Res.json();
  const order2 = order2Json.data;

  // 배송완료 상태로 강제 전환 (관리자가 실제로 배송 처리했다고 가정)
  await admin.from('orders_with').update({ status: 'delivered' }).eq('id', order2.id);

  // delivered 상태에서 취소(cancel) 신청 시도 -> 실패해야 함
  const wrongCancelRes = await fetch(`${API}/api/orders/${order2.id}/return-request`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ request_type: 'cancel', reason: '테스트' })
  });
  assert(wrongCancelRes.status === 400, `delivered 주문에 취소 신청 시 400 (실제: ${wrongCancelRes.status})`);

  const returnReqRes = await fetch(`${API}/api/orders/${order2.id}/return-request`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ request_type: 'return', reason: '상품이 파손되어 반품합니다' })
  });
  const returnReqJson = await returnReqRes.json();
  assert(returnReqRes.status === 201 && returnReqJson.success, `delivered 주문에 반품 신청 성공 (실제: ${returnReqRes.status})`);
  const returnRequestId = returnReqJson.data.id;

  const { data: stockBeforeReturn } = await admin.from('products_with').select('stock').eq('id', prod2.id).single();
  assert(Number(stockBeforeReturn.stock) === 2, `주문2 생성 후 재고 3->2 (실제: ${stockBeforeReturn.stock})`);

  const approveReturnRes = await fetch(`${API}/api/admin/return-requests/${returnRequestId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'completed' })
  });
  const approveReturnJson = await approveReturnRes.json();
  assert(approveReturnJson.sideEffect && approveReturnJson.sideEffect.order_status === 'refunded', `sideEffect.order_status === 'refunded' (실제: ${JSON.stringify(approveReturnJson.sideEffect)})`);

  const { data: order2After } = await admin.from('orders_with').select('status').eq('id', order2.id).single();
  assert(order2After.status === 'refunded', `주문2 상태가 refunded로 변경됨 (실제: ${order2After.status})`);

  const { data: stockAfterReturn } = await admin.from('products_with').select('stock').eq('id', prod2.id).single();
  assert(Number(stockAfterReturn.stock) === 3, `반품 승인 후 재고 2->3으로 복구됨 (실제: ${stockAfterReturn.stock})`);

  // ============================================
  // 3) 교환 플로우: delivered 주문 -> 교환 신청 -> 관리자 완료 처리해도 재고/주문상태 자동 변경 없음 (의도된 설계)
  // ============================================
  const order3Res = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: prod2.id, name: prod2.name, price: prod2.price, quantity: 1 }] })
  });
  const order3Json = await order3Res.json();
  const order3 = order3Json.data;
  await admin.from('orders_with').update({ status: 'delivered' }).eq('id', order3.id);

  const exchangeReqRes = await fetch(`${API}/api/orders/${order3.id}/return-request`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ request_type: 'exchange', reason: '사이즈를 교환하고 싶습니다' })
  });
  const exchangeReqJson = await exchangeReqRes.json();
  assert(exchangeReqRes.status === 201, `delivered 주문에 교환 신청 성공 (실제: ${exchangeReqRes.status})`);
  const exchangeRequestId = exchangeReqJson.data.id;

  const approveExchangeRes = await fetch(`${API}/api/admin/return-requests/${exchangeRequestId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'completed' })
  });
  const approveExchangeJson = await approveExchangeRes.json();
  assert(approveExchangeJson.sideEffect === null, `교환 승인 시 sideEffect 없음 (실제: ${JSON.stringify(approveExchangeJson.sideEffect)})`);

  const { data: order3After } = await admin.from('orders_with').select('status').eq('id', order3.id).single();
  assert(order3After.status === 'delivered', `교환 승인해도 주문상태는 delivered 그대로 유지됨 (실제: ${order3After.status})`);

  // ============================================
  // 4) /api/me/return-requests 로 본인 신청내역 조회 확인
  // ============================================
  const meReturnsRes = await fetch(`${API}/api/me/return-requests`, { headers: { Authorization: `Bearer ${custToken}` } });
  const meReturnsJson = await meReturnsRes.json();
  assert(meReturnsJson.success && meReturnsJson.data.length === 3, `본인 신청내역 3건 조회됨 (실제: ${meReturnsJson.data?.length})`);

  // 정리
  await admin.from('return_requests').delete().in('order_id', [order1.id, order2.id, order3.id]);
  await admin.from('orders_with').delete().in('id', [order1.id, order2.id, order3.id]);
  await admin.from('products_with').delete().in('id', [prod1.id, prod2.id]);
  await admin.from('profiles').delete().in('id', [custId, adminId]);
  await admin.auth.admin.deleteUser(custId);
  await admin.auth.admin.deleteUser(adminId);
  console.log('정리 완료: 주문/신청/상품/유저 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
