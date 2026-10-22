// WITH+ 라이브(LIVE+에서 이식) 관리자용 채널 상품 큐레이션/세션 목록 조회 회귀 테스트.
// 세션/재고 관리 admin.html 모달이 새로 의존하는 두 엔드포인트(GET .../products, GET .../sessions)를
// 검증한다 - 특히 draft(비공개) 채널에서도 관리자가 미리 큐레이션/세션을 조회할 수 있어야 한다는 점.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-channel-admin-curation.js
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
  const adminEmail = `test-lcadm-admin-${ts}@withplus-test.local`;
  const memberEmail = `test-lcadm-member-${ts}@withplus-test.local`;

  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: mData } = await admin.auth.admin.createUser({ email: memberEmail, password, email_confirm: true });
  await admin.from('profiles').upsert([
    { id: aData.user.id, email: adminEmail, role: 'admin', member_type: 'general' },
    { id: mData.user.id, email: memberEmail, role: 'member', member_type: 'general' }
  ]);
  const adminToken = await loginAs(adminEmail, password);
  const memberToken = await loginAs(memberEmail, password);
  const slug = `test-lcadm-channel-${ts}`;

  const { data: product, error: productErr } = await admin.from('products_with').insert([{
    name: `LCADM 테스트 상품 ${ts}`, slug: `lcadm-test-product-${ts}`, description: '테스트', price: 5000, stock: 10, status: 'active', category: '테스트'
  }]).select().single();
  if (productErr) throw productErr;

  // 채널은 draft 상태 그대로 유지(활성화하지 않음) - 관리자는 이 상태에서도 큐레이션/세션을 미리 준비할 수 있어야 한다.
  const createChannelRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: 'LCADM 테스트 채널', channel_type: 'creator' })
  });
  const channel = (await createChannelRes.json()).data;
  assert(channel.status === 'draft', `채널이 draft 상태로 생성됨 (실제: ${channel.status})`);

  // 1) draft 채널에서 공개 API로는 큐레이션 상품이 보이지 않는다(기존 동작 확인)
  const publicRes = await fetch(`${API}/api/live/channels/${slug}/products`);
  assert(publicRes.status === 404, `draft 채널은 공개 API에서 404 (실제: ${publicRes.status})`);

  // 2) 일반회원은 관리자용 큐레이션 조회 불가
  const forbiddenRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/products`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert(forbiddenRes.status === 403, `일반회원은 관리자용 큐레이션 조회 불가 (실제: ${forbiddenRes.status})`);

  // 3) 관리자는 draft 채널이어도 큐레이션 조회 가능(처음엔 비어있음)
  const emptyRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/products`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const emptyJson = await emptyRes.json();
  assert(emptyRes.status === 200 && emptyJson.data.length === 0, `관리자는 draft 채널에서도 큐레이션 조회 가능, 초기엔 비어있음 (실제: ${emptyRes.status}, ${emptyJson.data?.length})`);

  // 4) 상품 큐레이션 추가 후 관리자 API에 반영, products_with 상세정보 join 포함
  await fetch(`${API}/api/admin/live/channels/${channel.id}/products`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ product_id: product.id, is_featured: true })
  });
  const afterAddRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/products`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const afterAddJson = await afterAddRes.json();
  assert(afterAddJson.data.length === 1 && afterAddJson.data[0].products_with?.name === product.name && afterAddJson.data[0].is_featured === true,
    `큐레이션 추가 후 상품 상세(join)와 함께 반영됨 (실제: ${JSON.stringify(afterAddJson.data[0])})`);

  // 5) 세션 목록 조회 - 처음엔 비어있음
  const emptySessionsRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const emptySessionsJson = await emptySessionsRes.json();
  assert(emptySessionsRes.status === 200 && emptySessionsJson.data.length === 0, `세션 목록 초기엔 비어있음 (실제: ${emptySessionsJson.data?.length})`);

  // 6) 세션 생성 후 목록에 반영, 상품핀 지정 시 products_with join 포함
  const sessionRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ title: 'LCADM 테스트 방송' })
  });
  const session = (await sessionRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ pinned_product_id: product.id })
  });
  const afterSessionRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const afterSessionJson = await afterSessionRes.json();
  assert(afterSessionJson.data.length === 1 && afterSessionJson.data[0].products_with?.name === product.name,
    `세션 목록에 반영 + 고정상품 상세(join) 포함 (실제: ${JSON.stringify(afterSessionJson.data[0]?.products_with)})`);

  // 7) 일반회원은 세션 목록도 조회 불가
  const forbiddenSessionsRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert(forbiddenSessionsRes.status === 403, `일반회원은 세션 목록 조회 불가 (실제: ${forbiddenSessionsRes.status})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
