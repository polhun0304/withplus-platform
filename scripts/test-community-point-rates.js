// 분양 조직별 적립율(개인/커뮤니티) 동적 조정 기능 + 로고 필드 저장 검증용 임시 테스트
// 실행 후 생성한 테스트 계정/데이터는 모두 정리(clean up)한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const HQ_EMAIL = `withplus.rate.hq.${stamp}@withplus.test`;
const ORG_EMAIL = `withplus.rate.org.${stamp}@withplus.test`;
const BUYER_EMAIL = `withplus.rate.buyer.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';

let createdUserIds = [];
let createdCommunityId = null;
let createdOrderIds = [];
let createdProductIds = [];

async function createTestUser(email, role) {
  const { data, error } = await admin.auth.admin.createUser({ email, password: PASSWORD, email_confirm: true });
  if (error) throw new Error(`계정 생성 실패(${email}): ${error.message}`);
  createdUserIds.push(data.user.id);
  // profiles 행은 auth.users 생성 시 자동으로 만들어지지 않으므로(트리거 없음) 직접 만들어준다
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
  for (const id of createdOrderIds) {
    await admin.from('orders_with').delete().eq('id', id);
  }
  if (createdCommunityId) {
    await admin.from('community_members').delete().eq('community_id', createdCommunityId);
    await admin.from('communities').delete().eq('id', createdCommunityId);
  }
  for (const id of createdProductIds) {
    await admin.from('products_with').delete().eq('id', id);
  }
  for (const id of createdUserIds) {
    await admin.auth.admin.deleteUser(id).catch(() => {});
  }
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 계정 준비 ===');
  const hq = await createTestUser(HQ_EMAIL, 'super_admin');
  const orgAdmin = await createTestUser(ORG_EMAIL, null); // 일반 회원으로 가입 후 조직 관리자로 지정
  const buyer = await createTestUser(BUYER_EMAIL, null);
  console.log('HQ:', HQ_EMAIL, '/ ORG:', ORG_EMAIL, '/ BUYER:', BUYER_EMAIL);

  console.log('\n=== 1. HQ 관리자가 로고 + 커스텀 적립율(3%/5%)로 조직 생성 ===');
  const createRes = await api('/api/admin/communities', hq.token, {
    method: 'POST',
    body: JSON.stringify({
      name: `테스트교회-${stamp}`,
      slug: `test-church-${stamp}`,
      description: '적립율/로고 테스트용',
      logo_url: 'https://example.com/test-logo.png',
      admin_email: ORG_EMAIL,
      personal_point_rate: 0.03,
      community_point_rate: 0.05
    })
  });
  assert(createRes.ok, `조직 생성 API 200 OK (status=${createRes.status}, msg=${createRes.json.message})`);
  createdCommunityId = createRes.json.data.id;
  assert(createRes.json.data.logo_url === 'https://example.com/test-logo.png', '생성 응답에 logo_url 저장됨');
  assert(Number(createRes.json.data.personal_point_rate) === 0.03, '생성 응답 personal_point_rate=0.03');
  assert(Number(createRes.json.data.community_point_rate) === 0.05, '생성 응답 community_point_rate=0.05');

  // 주문 생성 시 서버가 "실제 가입한 커뮤니티인지" 검증하므로, 주문 테스트를 위해 buyer를 이 조직에 가입시켜둔다
  const joinRes = await api(`/api/communities/${createRes.json.data.slug}/join`, buyer.token, { method: 'POST' });
  assert(joinRes.ok, `buyer가 테스트 조직에 가입 성공 (status=${joinRes.status})`);

  // 주문 API가 실제 상품 존재/재고를 검증하므로(옵션/재고관리 고도화), 테스트용 실제 상품을 만들어둔다
  const productRes = await api('/api/products', hq.token, {
    method: 'POST',
    body: JSON.stringify({ name: `적립율테스트상품-${stamp}`, price: 10000, category: 'fashion', stock: 100 })
  });
  assert(productRes.ok, `테스트 상품 생성 성공 (status=${productRes.status})`);
  const testProductId = productRes.json.data.id;
  createdProductIds.push(testProductId);

  console.log('\n=== 2. HQ 관리자 목록 조회에도 로고/적립율/담당자 이메일이 반영되는지 ===');
  const listRes = await api('/api/admin/communities', hq.token);
  const found = listRes.json.data.find(c => c.id === createdCommunityId);
  assert(!!found, '목록에서 방금 만든 조직을 찾음');
  assert(found.logo_url === 'https://example.com/test-logo.png', '목록 응답에도 logo_url 포함');
  assert(found.admin_email === ORG_EMAIL, '목록 응답에 admin_email 정상 연결');

  console.log('\n=== 3. 조직 담당 관리자가 자기 조직 적립율을 조회 (커스텀값 확인) ===');
  const caRatesRes = await api('/api/community-admin/point-rates', orgAdmin.token);
  assert(caRatesRes.ok, `조직 관리자 적립율 조회 200 OK (status=${caRatesRes.status})`);
  assert(caRatesRes.json.data.is_custom_personal === true, 'is_custom_personal=true');
  assert(caRatesRes.json.data.is_custom_community === true, 'is_custom_community=true');
  assert(caRatesRes.json.data.personal === 0.03, '조회된 personal=0.03');
  assert(caRatesRes.json.data.community === 0.05, '조회된 community=0.05');

  console.log('\n=== 4. 조직 담당 관리자가 개인 적립율만 4%로 직접 변경 (커뮤니티 적립율은 그대로 5% 유지되어야 함) ===');
  const putRes = await api('/api/community-admin/point-rates', orgAdmin.token, {
    method: 'PUT',
    body: JSON.stringify({ personal: 0.04 })
  });
  assert(putRes.ok, `적립율 변경 200 OK (status=${putRes.status})`);
  assert(putRes.json.data.personal === 0.04, '변경 후 personal=0.04');
  assert(putRes.json.data.community === 0.05, '변경하지 않은 community는 그대로 0.05 유지');

  console.log('\n=== 5. 다른 조직 관리자(=아무 조직도 담당하지 않는 buyer)는 이 API에 접근 불가(404) ===');
  const buyerRatesRes = await api('/api/community-admin/point-rates', buyer.token);
  assert(buyerRatesRes.status === 404, `담당 조직 없는 계정은 404 (status=${buyerRatesRes.status})`);

  console.log('\n=== 6. 실제 주문 생성 시 조직의 커스텀 적립율(4%/5%)이 그대로 적용되는지 ===');
  const orderRes = await api('/api/orders', buyer.token, {
    method: 'POST',
    body: JSON.stringify({
      community_id: createdCommunityId,
      items: [{ product_id: testProductId, name: '테스트상품', price: 10000, quantity: 1 }],
      shipping_address: { name: '테스터', phone: '010-0000-0000', address: '테스트 주소' },
      payment_method: 'test'
    })
  });
  assert(orderRes.ok, `주문 생성 200 OK (status=${orderRes.status}, msg=${orderRes.json.message})`);
  createdOrderIds.push(orderRes.json.data.id);
  // finalPrice = 10000, personal 4% = 400, community 5% = 500
  assert(orderRes.json.data.personal_earned_points === 400, `개인 적립 400원 (실제=${orderRes.json.data.personal_earned_points})`);
  assert(orderRes.json.data.community_earned_points === 500, `커뮤니티 적립 500원 (실제=${orderRes.json.data.community_earned_points})`);

  console.log('\n=== 7. 조직 관리자가 "플랫폼 기본값으로 되돌리기" (personal/community 모두 null) ===');
  const resetRes = await api('/api/community-admin/point-rates', orgAdmin.token, {
    method: 'PUT',
    body: JSON.stringify({ personal: null, community: null })
  });
  assert(resetRes.ok, `초기화 200 OK (status=${resetRes.status})`);
  assert(resetRes.json.data.is_custom_personal === false, '초기화 후 is_custom_personal=false');
  assert(resetRes.json.data.is_custom_community === false, '초기화 후 is_custom_community=false');

  const platformRes = await api('/api/settings/mileage-rates', null);
  assert(resetRes.json.data.personal === platformRes.json.data.personal, '초기화 후 personal이 플랫폼 기본값과 동일');
  assert(resetRes.json.data.community === platformRes.json.data.community, '초기화 후 community가 플랫폼 기본값과 동일');

  console.log('\n=== 8. 초기화 이후 주문 생성 시 플랫폼 기본 적립율이 적용되는지 ===');
  const orderRes2 = await api('/api/orders', buyer.token, {
    method: 'POST',
    body: JSON.stringify({
      community_id: createdCommunityId,
      // 🔒 상품 실제 판매가는 10,000원(서버가 재검증) - 20,000원 결제를 재현하려면 price를 조작하는 대신
      // quantity를 2로 보낸다(가격조작 방지 수정 이후 item.price는 더 이상 서버가 신뢰하지 않는다).
      items: [{ product_id: testProductId, name: '테스트상품2', price: 20000, quantity: 2 }],
      shipping_address: { name: '테스터', phone: '010-0000-0000', address: '테스트 주소' },
      payment_method: 'test'
    })
  });
  assert(orderRes2.ok, `2차 주문 생성 200 OK (status=${orderRes2.status})`);
  createdOrderIds.push(orderRes2.json.data.id);
  const expectedPersonal = Math.floor(20000 * platformRes.json.data.personal);
  const expectedCommunity = Math.floor(20000 * platformRes.json.data.community);
  assert(orderRes2.json.data.personal_earned_points === expectedPersonal, `초기화 후 개인 적립 = 플랫폼 기본값 기준 (${expectedPersonal})`);
  assert(orderRes2.json.data.community_earned_points === expectedCommunity, `초기화 후 커뮤니티 적립 = 플랫폼 기본값 기준 (${expectedCommunity})`);

  console.log('\n=== 9. HQ 관리자가 PUT으로 다른 조직(=이 조직)의 로고/적립율을 다시 수정 가능한지 ===');
  const hqPutRes = await api('/api/admin/communities/' + createdCommunityId, hq.token, {
    method: 'PUT',
    body: JSON.stringify({ logo_url: 'https://example.com/new-logo.png', personal_point_rate: 0.02 })
  });
  assert(hqPutRes.ok, `HQ의 PUT 200 OK (status=${hqPutRes.status})`);
  assert(hqPutRes.json.data.logo_url === 'https://example.com/new-logo.png', 'HQ가 로고를 새 값으로 수정');
  assert(Number(hqPutRes.json.data.personal_point_rate) === 0.02, 'HQ가 개인 적립율을 0.02로 수정');

  console.log('\n=== 10. 잘못된 적립율(범위 초과) 입력 시 400 에러 ===');
  const badRes = await api('/api/community-admin/point-rates', orgAdmin.token, {
    method: 'PUT',
    body: JSON.stringify({ personal: 0.9 })
  });
  assert(badRes.status === 400, `범위 초과(90%) 적립율은 400 (status=${badRes.status})`);

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
