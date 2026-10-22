// WITH+ 라이브(LIVE+에서 이식) 고객용 시청 페이지(public/live-channel.html)가 실제로 사용하는 API 호출 순서를 그대로 재현하는
// 엔드투엔드 회귀 테스트. 특히 페이지가 딥링크 쿼리스트링(?platform=...&campaign=...&ref=...&coupon=...)을
// live_attribution 객체로 바꿔 POST /api/orders에 실어보낼 때, 서버가 읽는 필드명(source_platform)과
// 클라이언트가 만드는 필드명이 실제로 일치하는지를 확인하는 것이 이 테스트의 핵심 목적이다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-channel-page-flow.js
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
  const adminEmail = `test-lcpf-admin-${ts}@withplus-test.local`;
  const buyerEmail = `test-lcpf-buyer-${ts}@withplus-test.local`;

  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: bData } = await admin.auth.admin.createUser({ email: buyerEmail, password, email_confirm: true });
  await admin.from('profiles').upsert([
    { id: aData.user.id, email: adminEmail, role: 'admin', member_type: 'general' },
    { id: bData.user.id, email: buyerEmail, role: 'member', member_type: 'general' }
  ]);
  const adminToken = await loginAs(adminEmail, password);
  const buyerToken = await loginAs(buyerEmail, password);
  const slug = `test-lcpf-channel-${ts}`;

  const { data: product, error: productErr } = await admin.from('products_with').insert([{
    name: `LCPF 테스트 상품 ${ts}`, slug: `lcpf-test-product-${ts}`, description: '테스트', price: 8000, stock: 50, status: 'active', category: '테스트'
  }]).select().single();
  if (productErr) throw productErr;

  // 채널 생성 후 곧바로 active로 전환 - 페이지는 활성 채널만 대상으로 하는 공개 API를 사용한다
  const createChannelRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: 'LCPF 테스트 채널', channel_type: 'creator' })
  });
  const channel = (await createChannelRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'active' })
  });

  await fetch(`${API}/api/admin/live/channels/${channel.id}/products`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ product_id: product.id, is_featured: true })
  });

  const sessionRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ title: 'LCPF 테스트 방송' })
  });
  const session = (await sessionRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'live', pinned_product_id: product.id })
  });
  await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/inventory`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ product_id: product.id, allocated_qty: 10, safety_stock: 0 })
  });

  // ===== 여기서부터 live-channel.html이 실제로 밟는 순서 =====

  // 1) 페이지 로드: 채널/라이브세션/상품 목록 조회 (모두 공개 API)
  const chRes = await fetch(`${API}/api/live/channels/${slug}`);
  const chJson = await chRes.json();
  assert(chRes.status === 200 && chJson.data.id === channel.id, `채널 상세 조회 성공 (실제: ${chRes.status})`);

  const sessLiveRes = await fetch(`${API}/api/live/channels/${slug}/sessions/live`);
  const sessLiveJson = await sessLiveRes.json();
  assert(sessLiveJson.data && sessLiveJson.data.id === session.id, `라이브 세션 조회 성공 (실제: ${JSON.stringify(sessLiveJson.data?.id)})`);

  const prodListRes = await fetch(`${API}/api/live/channels/${slug}/products`);
  const prodListJson = await prodListRes.json();
  assert(prodListJson.data.length === 1 && prodListJson.data[0].id === product.id, `큐레이션 상품 목록 조회 성공 (실제: ${prodListJson.data?.length})`);

  const invRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/inventory`);
  const invJson = await invRes.json();
  assert(invJson.data[0].available_qty === 10, `초기 가용재고 10 (실제: ${invJson.data[0]?.available_qty})`);

  // 2) 장바구니 예약 (stage: cart) - "장바구니 예약" 버튼
  const reserveRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ product_id: product.id, quantity: 2, stage: 'cart' })
  });
  const reserveJson = await reserveRes.json();
  assert(reserveRes.status === 201 && reserveJson.data.status === 'cart', `장바구니 예약 성공 (실제: ${reserveRes.status}, status=${reserveJson.data?.status}`);
  assert(reserveJson.data.available_qty === 8, `예약 2개 후 가용재고 8 (실제: ${reserveJson.data?.available_qty})`);
  const reservationId = reserveJson.data.id;

  // 3) "결제 진행" 클릭 시 cart→checkout 단계 전환
  const upgradeRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/reservations/${reservationId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ stage: 'checkout' })
  });
  const upgradeJson = await upgradeRes.json();
  assert(upgradeRes.status === 200 && upgradeJson.data.status === 'checkout', `결제진행 단계 전환 성공 (실제: ${upgradeJson.data?.status})`);

  // 4) 딥링크 쿼리스트링(?platform=kakao&campaign=summer&ref=influencer1&coupon=WELCOME10)을 그대로
  //    live-channel.html의 attribution 객체(source_platform/campaign/referrer_code/coupon_code)로 변환해 주문 생성
  const attribution = { source_platform: 'kakao', campaign: 'summer', referrer_code: 'influencer1', coupon_code: undefined };
  const orderRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({
      items: [{ product_id: product.id, name: product.name, price: product.price, quantity: 2 }],
      channel_id: channel.id,
      live_session_id: session.id,
      reservation_ids: [reservationId],
      live_attribution: attribution,
      shipping_address: { name: '홍길동', phone: '010-1234-5678', address: '서울시 강남구 테스트로 1' },
      payment_method: 'pending'
    })
  });
  const orderJson = await orderRes.json();
  assert(orderRes.status === 201 && orderJson.success, `주문 생성 성공 (실제: ${orderRes.status}, ${orderJson.message || ''})`);
  assert(orderJson.data.attribution_source_platform === 'kakao' && orderJson.data.attribution_campaign === 'summer' && orderJson.data.attribution_referrer_code === 'influencer1',
    `주문 응답에 딥링크 출처정보가 필드명 그대로 반영됨 (실제: ${JSON.stringify({ p: orderJson.data.attribution_source_platform, c: orderJson.data.attribution_campaign, r: orderJson.data.attribution_referrer_code })})`);

  // 5) 예약이 확정되고(재고가 예약→판매로 이동) 정산 원장에도 출처정보가 그대로 남았는지 확인
  await new Promise(r => setTimeout(r, 400)); // confirmLiveSessionReservations는 주문 성공 후 비동기(catch-only)로 처리됨
  const { data: reservationRow } = await admin.from('live_session_reservations_with').select('status, order_id').eq('id', reservationId).single();
  assert(reservationRow.status === 'confirmed' && reservationRow.order_id === orderJson.data.id, `예약이 confirmed로 전환되고 주문에 연결됨 (실제: ${JSON.stringify(reservationRow)})`);

  const { data: invRow } = await admin.from('live_session_inventory_with').select('reserved_qty, sold_qty').eq('live_session_id', session.id).eq('product_id', product.id).single();
  assert(invRow.reserved_qty === 0 && invRow.sold_qty === 2, `재고가 reserved→sold로 이동함 (실제: ${JSON.stringify(invRow)})`);

  const { data: ledgerRow } = await admin.from('channel_ledger_with').select('source_platform, campaign, referrer_code').eq('order_ref', orderJson.data.order_number).maybeSingle();
  assert(ledgerRow && ledgerRow.source_platform === 'kakao' && ledgerRow.campaign === 'summer' && ledgerRow.referrer_code === 'influencer1',
    `정산 원장에도 출처정보 그대로 기록됨 (실제: ${JSON.stringify(ledgerRow)})`);

  // 6) 공유 버튼이 사용하는 딥링크 생성 API도 같은 파라미터로 정상 동작하는지 확인
  const deepLinkRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/deep-link?platform=kakao&campaign=summer&ref=influencer1`);
  const deepLinkJson = await deepLinkRes.json();
  assert(deepLinkRes.status === 200 && deepLinkJson.data.deep_link.includes(`session=${session.id}`) && deepLinkJson.data.deep_link.includes('platform=kakao'),
    `공유용 딥링크 생성 성공 (실제: ${deepLinkJson.data?.deep_link})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
