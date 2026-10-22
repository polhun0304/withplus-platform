// WITH+ 라이브(LIVE+에서 이식) 세션별 재고예약 + 딥링크·QR 출처 추적 회귀 테스트.
// 배정재고 → 장바구니 예약 → 결제진행 전환 → 재고부족(동시주문 방지) → 주문으로 확정(sold 차감) →
// 취소 시 복원 → 딥링크에 채널/세션/상품/호스트/캠페인/추천인/쿠폰이 포함되는지 → 주문·정산원장까지
// 출처가 보존되는지 확인한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-session-inventory.js
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
  const adminEmail = `test-lsi-admin-${ts}@withplus-test.local`;
  const buyerAEmail = `test-lsi-buyerA-${ts}@withplus-test.local`;
  const buyerBEmail = `test-lsi-buyerB-${ts}@withplus-test.local`;

  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: bAData } = await admin.auth.admin.createUser({ email: buyerAEmail, password, email_confirm: true });
  const { data: bBData } = await admin.auth.admin.createUser({ email: buyerBEmail, password, email_confirm: true });
  await admin.from('profiles').upsert([
    { id: aData.user.id, email: adminEmail, role: 'admin', member_type: 'general' },
    { id: bAData.user.id, email: buyerAEmail, role: 'member', member_type: 'general' },
    { id: bBData.user.id, email: buyerBEmail, role: 'member', member_type: 'general' }
  ]);
  const adminToken = await loginAs(adminEmail, password);
  const buyerAToken = await loginAs(buyerAEmail, password);
  const buyerBToken = await loginAs(buyerBEmail, password);
  const slug = `test-lsi-channel-${ts}`;

  const { data: product, error: productErr } = await admin.from('products_with').insert([{
    name: `LSI 테스트 상품 ${ts}`, slug: `lsi-test-product-${ts}`, description: 'LSI 테스트 상품', price: 20000, stock: 999, status: 'active', category: '테스트'
  }]).select().single();
  if (productErr) throw productErr;

  const createChannelRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: 'LSI 테스트 채널', channel_type: 'creator', owner_user_id: aData.user.id })
  });
  const channel = (await createChannelRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'active' })
  });
  await fetch(`${API}/api/admin/live/channels/${channel.id}/products`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ product_id: product.id })
  });
  const sessionRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ title: 'LSI 테스트 방송' })
  });
  const session = (await sessionRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'live', pinned_product_id: product.id })
  });

  // 1) 재고 배정 전에는 예약 불가
  const preAllocRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerAToken}` },
    body: JSON.stringify({ product_id: product.id, quantity: 1 })
  });
  assert(preAllocRes.status === 400, `재고 미배정 상태에서 예약 시도 시 400 (실제: ${preAllocRes.status})`);

  // 2) 관리자가 세션에 재고 5개, 안전재고 1개 배정 → 가용 4개
  const allocRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/inventory`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    // 계정당 예약 상한(배정재고의 30%, 보안 수정 c85f581) 안에서 3개를 예약할 수 있도록 배정 10·안전재고 6 → 가용 4
    body: JSON.stringify({ product_id: product.id, allocated_qty: 10, safety_stock: 6 })
  });
  const allocJson = await allocRes.json();
  assert(allocRes.status === 201 && allocJson.data?.available_qty === 4, `배정재고 10, 안전재고 6 → 가용 4 (실제: ${allocJson.data?.available_qty})`);

  const publicInvRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/inventory`);
  const publicInvJson = await publicInvRes.json();
  assert(publicInvJson.data?.[0]?.available_qty === 4, `공개 조회에도 가용 4로 노출 (실제: ${publicInvJson.data?.[0]?.available_qty})`);

  // 3) 구매자A가 3개 장바구니 예약 → 가용 1
  const reserveARes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerAToken}` },
    body: JSON.stringify({ product_id: product.id, quantity: 3 })
  });
  const reserveAJson = await reserveARes.json();
  assert(reserveARes.status === 201 && reserveAJson.data?.status === 'cart' && reserveAJson.data?.available_qty === 1, `구매자A 3개 장바구니 예약, 가용 1로 감소 (실제: status=${reserveAJson.data?.status}, available=${reserveAJson.data?.available_qty})`);
  const reservationAId = reserveAJson.data.id;

  // 4) 구매자B가 2개 예약 시도 → 가용 1개뿐이므로 409 (동시주문/오버셀 방지)
  const reserveBRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerBToken}` },
    body: JSON.stringify({ product_id: product.id, quantity: 2 })
  });
  assert(reserveBRes.status === 409, `가용 수량 초과 예약 시도 시 409 (실제: ${reserveBRes.status})`);

  // 5) 구매자A: 장바구니 → 결제진행 단계로 전환
  const upgradeRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations/${reservationAId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerAToken}` },
    body: JSON.stringify({ stage: 'checkout' })
  });
  const upgradeJson = await upgradeRes.json();
  assert(upgradeRes.status === 200 && upgradeJson.data?.status === 'checkout', `장바구니→결제진행 전환 성공 (실제: ${upgradeJson.data?.status})`);

  // 6) 다른 사람(구매자B)은 구매자A의 예약을 취소할 수 없다
  const forbiddenCancelRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations/${reservationAId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerBToken}` },
    body: JSON.stringify({ action: 'cancel' })
  });
  assert(forbiddenCancelRes.status === 403, `타인의 예약은 취소 불가 (실제: ${forbiddenCancelRes.status})`);

  // 7) 딥링크 조회: 채널/세션/상품/호스트/캠페인/추천인/쿠폰 식별자 포함 확인
  const deepLinkRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/deep-link?platform=youtube&campaign=summer2026&ref=REF123&coupon=WELCOME10`);
  const deepLinkJson = await deepLinkRes.json();
  const link = deepLinkJson.data?.deep_link || '';
  assert(link.includes(`session=${session.id}`) && link.includes(`product=${product.id}`) && link.includes(`host=${aData.user.id}`), `딥링크에 세션/상품/호스트 포함 (실제: ${link})`);
  assert(link.includes('platform=youtube') && link.includes('campaign=summer2026') && link.includes('ref=REF123') && link.includes('coupon=WELCOME10'), `딥링크에 유입플랫폼/캠페인/추천인/쿠폰 포함 (실제: ${link})`);

  // 8) 구매자A가 이 예약을 근거로 실제 주문 생성 → 재고 sold로 확정 + 주문/정산원장에 출처 보존
  await fetch(`${API}/api/live/channels/${slug}/join`, { method: 'POST', headers: { Authorization: `Bearer ${buyerAToken}` } });
  const orderRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerAToken}` },
    body: JSON.stringify({
      items: [{ product_id: product.id, quantity: 3 }],
      shipping_address: { postal_code: '06236', address: '서울시 강남구 테스트로 1' },
      payment_method: 'card',
      channel_id: channel.id, live_session_id: session.id,
      reservation_ids: [reservationAId],
      live_attribution: { source_platform: 'youtube', campaign: 'summer2026', referrer_code: 'REF123', coupon_code: 'WELCOME10' }
    })
  });
  const orderJson = await orderRes.json();
  assert(orderRes.status === 201, `예약 기반 주문 생성 성공 (실제: ${orderRes.status})`);
  assert(orderJson.data?.attribution_source_platform === 'youtube' && orderJson.data?.attribution_campaign === 'summer2026' && orderJson.data?.attribution_referrer_code === 'REF123' && orderJson.data?.attribution_coupon_code === 'WELCOME10', `주문에 출처정보 보존됨 (실제: ${JSON.stringify({p:orderJson.data?.attribution_source_platform, c:orderJson.data?.attribution_campaign, r:orderJson.data?.attribution_referrer_code, cp:orderJson.data?.attribution_coupon_code})})`);

  await new Promise(r => setTimeout(r, 800));

  const { data: invAfterOrder } = await admin.from('live_session_inventory_with').select('*').eq('live_session_id', session.id).eq('product_id', product.id).single();
  assert(invAfterOrder.sold_qty === 3 && invAfterOrder.reserved_qty === 0, `주문 확정 후 sold=3, reserved=0으로 이동 (실제: sold=${invAfterOrder.sold_qty}, reserved=${invAfterOrder.reserved_qty})`);

  const { data: reservationAfter } = await admin.from('live_session_reservations_with').select('*').eq('id', reservationAId).single();
  assert(reservationAfter.status === 'confirmed' && reservationAfter.order_id === orderJson.data.id, `예약 상태 confirmed로 전환 + 주문 연결됨 (실제: status=${reservationAfter.status})`);

  const { data: ledgerRows } = await admin.from('channel_ledger_with').select('*').eq('order_ref', orderJson.data.order_number);
  assert(ledgerRows?.[0]?.source_platform === 'youtube' && ledgerRows?.[0]?.campaign === 'summer2026' && ledgerRows?.[0]?.referrer_code === 'REF123' && ledgerRows?.[0]?.coupon_code === 'WELCOME10', `정산원장까지 출처정보 보존됨 (실제: ${JSON.stringify(ledgerRows?.[0])})`);

  // 9) 이제 가용 재고가 회복되어(주문 확정으로 reserved 소진) 구매자B가 1개는 예약 가능
  const reserveBAfterRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerBToken}` },
    body: JSON.stringify({ product_id: product.id, quantity: 1 })
  });
  const reserveBAfterJson = await reserveBAfterRes.json();
  assert(reserveBAfterRes.status === 201, `주문 확정 후 남은 가용재고로 구매자B 예약 성공 (실제: ${reserveBAfterRes.status})`);

  // 10) 구매자B가 예약을 취소하면 재고가 복원된다
  const cancelBRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations/${reserveBAfterJson.data.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerBToken}` },
    body: JSON.stringify({ action: 'cancel' })
  });
  const cancelBJson = await cancelBRes.json();
  assert(cancelBRes.status === 200 && cancelBJson.data?.status === 'cancelled', `취소 성공 (실제: ${cancelBJson.data?.status})`);
  const { data: invAfterCancel } = await admin.from('live_session_inventory_with').select('reserved_qty').eq('live_session_id', session.id).eq('product_id', product.id).single();
  assert(invAfterCancel.reserved_qty === 0, `취소 후 reserved_qty 복원됨 (실제: ${invAfterCancel.reserved_qty})`);

  // 11) 재고 변경 로그가 append-only로 쌓였는지 확인 (allocate/reserve/extend/confirm/reserve/cancel 등 다건)
  const { data: invFinal } = await admin.from('live_session_inventory_with').select('id').eq('live_session_id', session.id).eq('product_id', product.id).single();
  const { data: logs } = await admin.from('live_session_inventory_log_with').select('change_type').eq('inventory_id', invFinal.id).order('created_at', { ascending: true });
  assert(logs.length >= 5, `재고 변경 로그가 여러 건 누적됨 (실제: ${logs.length}건, ${logs.map(l => l.change_type).join(',')})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
