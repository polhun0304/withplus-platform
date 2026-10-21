// WITH+ 라이브(LIVE+에서 이식) 세션별 재고예약 - "지금 방송 중인 세션"에 한해서만 새 예약을 만들 수 있어야 한다는 규칙의 회귀 테스트.
// 이전에는 세션의 status(scheduled/live/ended)를 전혀 확인하지 않아, 방송 시작 전이나 이미 끝난 세션의
// 오래된 딥링크로 들어와도 예약(POST .../reservations)이 그대로 성립되는 구멍이 있었다.
// 반대로 "방송 중일 때 이미 만든 예약"은 방송이 끝난 뒤에도 결제까지 완주할 수 있어야 한다(나쁜 UX 방지) -
// 이 두 규칙이 서로 충돌하지 않는지 함께 확인한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-session-status-guard.js
const API = process.env.API || process.env.TEST_API || 'http://localhost:3140';

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌', msg); }
}

async function loginAs(email, password) {
  const res = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', apikey: anonKey },
    body: JSON.stringify({ email, password })
  });
  return (await res.json()).access_token;
}

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const adminEmail = `test-lssg-admin-${ts}@withplus-test.local`;
  const buyerEmail = `test-lssg-buyer-${ts}@withplus-test.local`;

  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: bData } = await admin.auth.admin.createUser({ email: buyerEmail, password, email_confirm: true });
  await admin.from('profiles').upsert([
    { id: aData.user.id, email: adminEmail, role: 'admin', member_type: 'general' },
    { id: bData.user.id, email: buyerEmail, role: 'member', member_type: 'general' }
  ]);
  const adminToken = await loginAs(adminEmail, password);
  const buyerToken = await loginAs(buyerEmail, password);
  const slug = `test-lssg-channel-${ts}`;

  const { data: product } = await admin.from('products_with').insert([{
    name: `LSSG 테스트 상품 ${ts}`, slug: `lssg-test-product-${ts}`, description: '테스트', price: 5000, stock: 20, status: 'active', category: '테스트'
  }]).select().single();

  const createChannelRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: 'LSSG 테스트 채널', channel_type: 'creator' })
  });
  const channel = (await createChannelRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'active' })
  });

  // 재고 배정은 먼저 채널에 큐레이션되어 있는 상품에만 가능하다
  await fetch(`${API}/api/admin/live/channels/${channel.id}/products`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ product_id: product.id, is_featured: true })
  });

  const sessionRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ title: 'LSSG 테스트 방송' })
  });
  const session = (await sessionRes.json()).data;
  assert(session.status === 'scheduled', `세션은 처음엔 scheduled로 생성됨 (실제: ${session.status})`);

  await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/inventory`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ product_id: product.id, allocated_qty: 10, safety_stock: 0 })
  });

  // 1) scheduled(방송 시작 전) 상태에서는 예약이 거부되어야 한다
  const beforeLiveRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ product_id: product.id, quantity: 1, stage: 'cart' })
  });
  assert(beforeLiveRes.status === 409, `scheduled 세션에는 예약 불가 (실제: ${beforeLiveRes.status})`);

  // 2) live로 전환하면 예약이 성립해야 한다
  await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'live' })
  });
  const duringLiveRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ product_id: product.id, quantity: 2, stage: 'checkout' })
  });
  const duringLiveJson = await duringLiveRes.json();
  assert(duringLiveRes.status === 201, `live 세션에서는 예약 성립 (실제: ${duringLiveRes.status})`);
  const reservationId = duringLiveJson.data.id;

  // 3) 방송 종료(ended) 후에는 "새" 예약이 거부되어야 한다
  await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'ended' })
  });
  const afterEndRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ product_id: product.id, quantity: 1, stage: 'cart' })
  });
  assert(afterEndRes.status === 409, `ended 세션에는 새 예약 불가 (실제: ${afterEndRes.status})`);

  // 4) 그러나 "방송 중일 때 이미 만든" 예약(2번)은 방송이 끝난 뒤에도 결제 진행 단계로 전환하고 주문까지
  //    완주할 수 있어야 한다 - 이미 정당하게 확보한 재고를 방송 종료 타이밍 때문에 날려버리면 안 된다.
  const upgradeAfterEndRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations/${reservationId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ stage: 'checkout' })
  });
  assert(upgradeAfterEndRes.status === 200, `방송 종료 후에도 기존 예약의 단계 전환은 허용됨 (실제: ${upgradeAfterEndRes.status})`);

  const orderRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({
      items: [{ product_id: product.id, name: product.name, price: product.price, quantity: 2 }],
      channel_id: channel.id, live_session_id: session.id, reservation_ids: [reservationId],
      shipping_address: { name: '홍길동', phone: '010-1234-5678', address: '서울시 강남구 테스트로 1' },
      payment_method: 'pending'
    })
  });
  const orderJson = await orderRes.json();
  assert(orderRes.status === 201, `방송 종료 후에도 기존 예약으로 주문 완주 가능 (실제: ${orderRes.status}, ${orderJson.message || ''})`);

  await new Promise(r => setTimeout(r, 400));
  const { data: reservationRow } = await admin.from('live_session_reservations_with').select('status, order_id').eq('id', reservationId).single();
  assert(reservationRow.status === 'confirmed' && reservationRow.order_id === orderJson.data.id, `예약이 confirmed로 전환되고 주문에 연결됨 (실제: ${JSON.stringify(reservationRow)})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
