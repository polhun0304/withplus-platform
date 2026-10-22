// WITH+ 라이브(LIVE+에서 이식) 채널-상품 판매 연동 회귀 테스트: 채널 상품 큐레이션, 라이브 세션/상품핀, 주문 출처 추적,
// 정산 원장·팬 활동점수 연결까지 전체 흐름을 검증한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-channel-products.js
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
  const adminEmail = `test-lcp-admin-${ts}@withplus-test.local`;
  const buyerEmail = `test-lcp-buyer-${ts}@withplus-test.local`;

  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: bData } = await admin.auth.admin.createUser({ email: buyerEmail, password, email_confirm: true });
  const adminId = aData.user.id;
  const buyerId = bData.user.id;
  await admin.from('profiles').upsert([
    { id: adminId, email: adminEmail, role: 'admin', member_type: 'general' },
    { id: buyerId, email: buyerEmail, role: 'member', member_type: 'general' }
  ]);

  const adminToken = await loginAs(adminEmail, password);
  const buyerToken = await loginAs(buyerEmail, password);
  const slug = `test-lcp-channel-${ts}`;

  // 판매용 상품 하나 준비 (기존 products_with 그대로 재사용)
  const { data: product, error: productErr } = await admin.from('products_with').insert([{
    name: `LCP 테스트 상품 ${ts}`, slug: `lcp-test-product-${ts}`, description: 'LCP 테스트 상품', price: 10000, stock: 50, status: 'active', category: '테스트'
  }]).select().single();
  if (productErr) throw productErr;

  // 채널 생성 + active 전환
  const createRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: 'LCP 테스트 채널', channel_type: 'creator' })
  });
  const channel = (await createRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'active' })
  });

  // 1) 상품을 채널에 등록
  const attachRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/products`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ product_id: product.id, is_featured: true })
  });
  assert(attachRes.status === 201, `채널에 상품 등록 성공 (실제: ${attachRes.status})`);

  const channelProductsRes = await fetch(`${API}/api/live/channels/${slug}/products`);
  const channelProductsJson = await channelProductsRes.json();
  assert(channelProductsJson.data?.some(p => p.id === product.id), '채널 상품 목록에 노출됨');

  // 2) 라이브 세션 생성 - 아직 live 상태가 아니므로 공개 조회는 null
  const sessionRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ title: 'LCP 테스트 방송' })
  });
  const session = (await sessionRes.json()).data;
  assert(session.status === 'scheduled', `새 세션은 scheduled로 시작 (실제: ${session.status})`);

  const noLiveRes = await fetch(`${API}/api/live/channels/${slug}/sessions/live`);
  const noLiveJson = await noLiveRes.json();
  assert(noLiveJson.data === null, 'live 상태 세션이 없으면 null 반환');

  // 3) 채널에 등록되지 않은 상품은 고정 불가
  const { data: otherProduct, error: otherProductErr } = await admin.from('products_with').insert([{ name: `미등록상품 ${ts}`, slug: `lcp-other-product-${ts}`, description: '미등록 테스트 상품', price: 5000, stock: 10, status: 'active', category: '테스트' }]).select().single();
  if (otherProductErr) throw otherProductErr;
  const badPinRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ pinned_product_id: otherProduct.id })
  });
  assert(badPinRes.status === 400, `채널 미등록 상품은 고정 불가 (실제: ${badPinRes.status})`);

  // 4) 세션을 live로 전환 + 등록된 상품 고정
  const startRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'live', pinned_product_id: product.id })
  });
  const startedSession = (await startRes.json()).data;
  assert(startedSession.status === 'live' && startedSession.pinned_product_id === product.id, `세션 live 전환 + 상품핀 반영 (실제: status=${startedSession.status}, pinned=${startedSession.pinned_product_id})`);

  const liveRes = await fetch(`${API}/api/live/channels/${slug}/sessions/live`);
  const liveJson = await liveRes.json();
  assert(liveJson.data?.id === session.id && liveJson.data?.products_with?.id === product.id, '공개 조회로 현재 방송·고정상품 확인');
  assert(liveJson.data?.deep_link === `/live/${slug}?session=${session.id}`, `딥링크 형식 확인 (실제: ${liveJson.data?.deep_link})`);

  // 5) 팬이 채널에 가입 (구매 전 - 활동점수 적립 대상이 되기 위함)
  await fetch(`${API}/api/live/channels/${slug}/join`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` }
  });

  // 6) 채널 출처로 주문 생성
  const orderRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({
      items: [{ product_id: product.id, quantity: 1 }],
      shipping_address: { postal_code: '06236', address: '서울시 강남구 테스트로 1' },
      payment_method: 'card',
      channel_id: channel.id,
      live_session_id: session.id
    })
  });
  const orderJson = await orderRes.json();
  assert(orderRes.status === 201 && orderJson.data?.live_channel_id_with === channel.id, `채널 출처 주문 생성 성공 (실제: ${orderRes.status}, live_channel_id_with=${orderJson.data?.live_channel_id_with})`);

  // 7) 존재하지 않는(비활성) 채널로 주문 시도하면 거부
  const badOrderRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({
      items: [{ product_id: product.id, quantity: 1 }],
      shipping_address: { postal_code: '06236', address: '서울시 강남구 테스트로 1' },
      payment_method: 'card',
      channel_id: '00000000-0000-0000-0000-000000000000'
    })
  });
  assert(badOrderRes.status === 400, `유효하지 않은 채널로 주문 시도 시 400 (실제: ${badOrderRes.status})`);

  // 8) 정산 원장에 반영됐는지 확인 (fire-and-forget이므로 약간의 지연 허용)
  await new Promise(r => setTimeout(r, 800));
  const { data: ledgerRows } = await admin.from('channel_ledger_with').select('*').eq('order_ref', orderJson.data.order_number);
  assert(ledgerRows?.length === 1 && Number(ledgerRows[0].amount) === Number(orderJson.data.final_price), `정산 원장에 채널 매출 기록됨 (실제: ${JSON.stringify(ledgerRows?.[0])})`);

  // 9) 가입 상태였으므로 구매 활동점수(10점)도 함께 적립됐는지 확인
  const myChannelsRes = await fetch(`${API}/api/me/live/channels`, { headers: { Authorization: `Bearer ${buyerToken}` } });
  const myChannelsJson = await myChannelsRes.json();
  const membership = myChannelsJson.data?.find(m => m.channels_live?.slug === slug);
  assert(membership?.fan_activity_score === 10, `구매로 팬 활동점수 10점 적립 (실제: ${membership?.fan_activity_score})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
