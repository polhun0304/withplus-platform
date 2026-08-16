// 장바구니 "커뮤니티 선택"이 실제 가입한 커뮤니티만 보여주는지, 그리고 서버가 가입하지 않은
// 커뮤니티로는 주문을 막는지(무단 API 호출 방어) 검증하는 임시 테스트. 실행 후 생성 데이터는 모두 정리한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const HQ_EMAIL = `withplus.member.hq.${stamp}@withplus.test`;
const BUYER_EMAIL = `withplus.member.buyer.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';

let createdUserIds = [];
let createdCommunityIds = [];
let createdOrderIds = [];
let createdProductIds = [];

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
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {}),
      ...(options.headers || {})
    }
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
  for (const id of createdOrderIds) await admin.from('orders_with').delete().eq('id', id);
  for (const id of createdProductIds) await admin.from('products_with').delete().eq('id', id);
  for (const id of createdCommunityIds) {
    await admin.from('community_members').delete().eq('community_id', id);
    await admin.from('communities').delete().eq('id', id);
  }
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 계정/조직 준비 ===');
  const hq = await createTestUser(HQ_EMAIL, 'super_admin');
  const buyer = await createTestUser(BUYER_EMAIL, null);

  // 주문 API가 실제 상품 존재/재고를 검증하므로(옵션/재고관리 고도화), 테스트용 실제 상품을 만들어둔다
  const productRes = await api('/api/products', hq.token, {
    method: 'POST',
    body: JSON.stringify({ name: `커뮤니티주문테스트상품-${stamp}`, price: 10000, category: 'fashion', stock: 100 })
  });
  assert(productRes.ok, `테스트 상품 생성 성공 (status=${productRes.status})`);
  const testProductId = productRes.json.data.id;
  createdProductIds.push(testProductId);

  const createJoined = await api('/api/admin/communities', hq.token, {
    method: 'POST',
    body: JSON.stringify({ name: `가입할교회-${stamp}`, slug: `joined-church-${stamp}`, logo_url: 'https://example.com/joined-logo.png' })
  });
  assert(createJoined.ok, `가입 대상 조직 생성 성공 (status=${createJoined.status})`);
  const joinedCommunity = createJoined.json.data;
  createdCommunityIds.push(joinedCommunity.id);

  const createUnjoined = await api('/api/admin/communities', hq.token, {
    method: 'POST',
    body: JSON.stringify({ name: `미가입교회-${stamp}`, slug: `unjoined-church-${stamp}` })
  });
  assert(createUnjoined.ok, `미가입 조직 생성 성공 (status=${createUnjoined.status})`);
  const unjoinedCommunity = createUnjoined.json.data;
  createdCommunityIds.push(unjoinedCommunity.id);

  console.log('\n=== 1. 아직 아무 커뮤니티도 가입하지 않은 상태 - /api/my/communities는 빈 배열 ===');
  const beforeJoin = await api('/api/my/communities', buyer.token);
  assert(beforeJoin.ok, `조회 성공 (status=${beforeJoin.status})`);
  assert(Array.isArray(beforeJoin.json.data) && beforeJoin.json.data.length === 0, '가입한 커뮤니티 없음 -> 빈 배열');

  console.log('\n=== 2. 커뮤니티 하나에 가입 ===');
  const joinRes = await api(`/api/communities/${joinedCommunity.slug}/join`, buyer.token, { method: 'POST' });
  assert(joinRes.ok, `가입 API 성공 (status=${joinRes.status})`);

  console.log('\n=== 3. 가입 후 /api/my/communities에 그 커뮤니티만 나타나는지 (미가입 조직은 안 보임) ===');
  const afterJoin = await api('/api/my/communities', buyer.token);
  assert(afterJoin.json.data.length === 1, `가입한 커뮤니티 1개만 조회됨 (실제=${afterJoin.json.data.length})`);
  assert(afterJoin.json.data[0].id === joinedCommunity.id, '조회된 커뮤니티가 실제 가입한 조직과 일치');
  assert(afterJoin.json.data[0].logo_url === 'https://example.com/joined-logo.png', '로고 URL도 함께 내려옴');
  assert(!afterJoin.json.data.some(c => c.id === unjoinedCommunity.id), '미가입 조직은 목록에 없음');

  console.log('\n=== 4. 가입한 커뮤니티로는 정상 주문 + 적립 가능 ===');
  const goodOrder = await api('/api/orders', buyer.token, {
    method: 'POST',
    body: JSON.stringify({
      community_id: joinedCommunity.id,
      items: [{ product_id: testProductId, name: '테스트상품', price: 10000, quantity: 1 }],
      shipping_address: { name: '테스터', phone: '010-0000-0000', address: '테스트 주소' },
      payment_method: 'test'
    })
  });
  assert(goodOrder.ok, `가입한 커뮤니티로 주문 성공 (status=${goodOrder.status}, msg=${goodOrder.json.message})`);
  createdOrderIds.push(goodOrder.json.data.id);
  assert(goodOrder.json.data.community_earned_points > 0, '커뮤니티 적립금이 정상적으로 붙음');

  console.log('\n=== 5. 가입하지 않은 커뮤니티 id로 직접 API를 호출하면 서버가 차단하는지 (화면 조작/API 직접호출 방어) ===');
  const badOrder = await api('/api/orders', buyer.token, {
    method: 'POST',
    body: JSON.stringify({
      community_id: unjoinedCommunity.id,
      items: [{ product_id: testProductId, name: '테스트상품', price: 10000, quantity: 1 }],
      shipping_address: { name: '테스터', phone: '010-0000-0000', address: '테스트 주소' },
      payment_method: 'test'
    })
  });
  assert(badOrder.status === 400, `미가입 커뮤니티로 주문 시 400 차단 (status=${badOrder.status})`);
  assert(!badOrder.json.data, '차단된 주문은 실제로 생성되지 않음');

  console.log('\n=== 6. 커뮤니티 없이 주문(개인 구매)은 원래대로 정상 동작 ===');
  const noCommunityOrder = await api('/api/orders', buyer.token, {
    method: 'POST',
    body: JSON.stringify({
      items: [{ product_id: testProductId, name: '테스트상품', price: 5000, quantity: 1 }],
      shipping_address: { name: '테스터', phone: '010-0000-0000', address: '테스트 주소' },
      payment_method: 'test'
    })
  });
  assert(noCommunityOrder.ok, `커뮤니티 없는 개인 주문 성공 (status=${noCommunityOrder.status})`);
  createdOrderIds.push(noCommunityOrder.json.data.id);
  assert(noCommunityOrder.json.data.community_earned_points === 0, '커뮤니티 미선택 시 커뮤니티 적립 0원');

  console.log('\n🎉 모든 검증 통과');
}

main()
  .catch(err => {
    console.error('\n💥 테스트 실패:', err.message);
    process.exitCode = 1;
  })
  .finally(async () => {
    await cleanup();
  });
