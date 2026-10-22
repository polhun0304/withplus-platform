// WITH+ 라이브(LIVE+에서 이식) 호스트용 방송 진행 화면 회귀 테스트.
// 이 화면은 새 엔드포인트를 추가하지 않고 기존 세션/재고/채팅 관리자 API를 그대로 재사용하므로,
// (1) 정적 페이지 라우트가 정상적으로 응답하는지 (2) 화면이 실제로 호출하는 흐름(시작→핀 변경→
// 재고 조회→종료)이 순서대로 끊김 없이 동작하는지 (3) 일반회원은 여전히 해당 API들을 호출할 수 없는지를 확인한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-host-control.js
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
  const adminEmail = `test-lhost-admin-${ts}@withplus-test.local`;
  const memberEmail = `test-lhost-member-${ts}@withplus-test.local`;

  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: mData } = await admin.auth.admin.createUser({ email: memberEmail, password, email_confirm: true });
  await admin.from('profiles').upsert([
    { id: aData.user.id, email: adminEmail, role: 'admin', member_type: 'general', full_name: '관리자테스트' },
    { id: mData.user.id, email: memberEmail, role: 'member', member_type: 'general', full_name: '일반회원테스트' }
  ]);
  const adminToken = await loginAs(adminEmail, password);
  const memberToken = await loginAs(memberEmail, password);
  const slug = `test-lhost-channel-${ts}`;

  // 1) 정적 페이지 라우트 자체는 누구나 200으로 응답한다 (실제 권한 확인은 클라이언트에서 /api/me로 수행)
  const pageRes = await fetch(`${API}/admin/live-host/some-channel-id`);
  assert(pageRes.status === 200, `호스트 화면 라우트는 200으로 응답 (실제: ${pageRes.status})`);
  const pageHtml = await pageRes.text();
  assert(pageHtml.includes('방송 진행'), `응답 HTML에 방송 진행 화면 내용이 포함됨`);

  // 채널/세션/상품 준비
  const createChannelRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: 'LHOST 테스트 채널', channel_type: 'creator' })
  });
  const channel = (await createChannelRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'active' })
  });

  const { data: supplier } = await admin.from('profiles').select('id').eq('role', 'supplier').limit(1).maybeSingle();
  const supplierId = supplier ? supplier.id : aData.user.id;
  const { data: category } = await admin.from('categories').select('db_category').eq('is_active', true).limit(1).maybeSingle();
  const { data: product } = await admin.from('products_with').insert({
    name: `LHOST 테스트 상품 ${ts}`, slug: `lhost-test-${ts}`, description: 'LHOST 테스트용 상품입니다.',
    price: 10000, stock: 100, status: 'active', category: category ? category.db_category : 'etc', supplier_id: supplierId
  }).select().single();

  await fetch(`${API}/api/admin/live/channels/${channel.id}/products`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ product_id: product.id })
  });

  const sessionRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ title: 'LHOST 테스트 방송' })
  });
  const liveSession = (await sessionRes.json()).data;
  assert(liveSession.status === 'scheduled', `새 세션은 scheduled로 시작 (실제: ${liveSession.status})`);

  // 2) 화면의 "방송 시작" 버튼 = PATCH status:live
  const startRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${liveSession.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'live' })
  });
  const startJson = await startRes.json();
  assert(startRes.status === 200 && startJson.data.status === 'live' && !!startJson.data.started_at,
    `방송 시작 버튼 → status=live, started_at 기록 (실제: ${startJson.data?.status}, ${startJson.data?.started_at})`);

  // 3) 재고 배정 후, 화면의 재고 현황 조회가 available_qty를 포함해 정확히 내려온다
  await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${liveSession.id}/inventory`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ product_id: product.id, allocated_qty: 30, safety_stock: 5 })
  });
  const invRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${liveSession.id}/inventory`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const invJson = await invRes.json();
  assert(invJson.data.length === 1 && invJson.data[0].available_qty === 25,
    `재고 현황 카드가 표시할 available_qty 계산 정상 (실제: ${invJson.data[0]?.available_qty})`);

  // 4) 화면의 "지금 고정할 상품" 드롭다운 = PATCH pinned_product_id
  const pinRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${liveSession.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ pinned_product_id: product.id })
  });
  const pinJson = await pinRes.json();
  assert(pinRes.status === 200 && pinJson.data.pinned_product_id === product.id, `상품핀 변경 성공 (실제: ${pinJson.data?.pinned_product_id})`);

  // 5) 채팅 하나를 남기고, 화면의 채팅 패널(관리자 조회)에 표시된다
  const chatSendRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${liveSession.id}/chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ message: '호스트 화면 테스트 채팅' })
  });
  assert(chatSendRes.status === 201, `채팅 전송 성공 (실제: ${chatSendRes.status})`);
  const hostChatRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${liveSession.id}/chat`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const hostChatJson = await hostChatRes.json();
  assert(hostChatJson.data.length === 1 && hostChatJson.data[0].message === '호스트 화면 테스트 채팅',
    `호스트 화면 채팅 패널에 방금 온 메시지가 표시됨 (실제: ${JSON.stringify(hostChatJson.data[0])})`);

  // 6) 일반회원은 이 화면이 호출하는 관리자 API를 그대로 사용할 수 없다 (페이지가 열려도 데이터는 못 봄)
  const forbidden1 = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, { headers: { Authorization: `Bearer ${memberToken}` } });
  const forbidden2 = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${liveSession.id}/inventory`, { headers: { Authorization: `Bearer ${memberToken}` } });
  const forbidden3 = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${liveSession.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` }, body: JSON.stringify({ status: 'ended' })
  });
  assert(forbidden1.status === 403 && forbidden2.status === 403 && forbidden3.status === 403,
    `일반회원은 세션 목록/재고/상태변경 API 모두 403 (실제: ${forbidden1.status}, ${forbidden2.status}, ${forbidden3.status})`);

  // 7) 화면의 "방송 종료" 버튼 = PATCH status:ended, 종료 후에도 지나간 세션은 목록에 남는다
  const endRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${liveSession.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'ended' })
  });
  const endJson = await endRes.json();
  assert(endRes.status === 200 && endJson.data.status === 'ended' && !!endJson.data.ended_at,
    `방송 종료 버튼 → status=ended, ended_at 기록 (실제: ${endJson.data?.status}, ${endJson.data?.ended_at})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
