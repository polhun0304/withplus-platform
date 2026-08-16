const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
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
    headers: { 'Content-Type': 'application/json', apikey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY },
    body: JSON.stringify({ email, password })
  });
  const json = await res.json();
  return json.access_token;
}

async function main() {
  const ts = Date.now();

  // 테스트 시작 전, 현재 pg_configs 상태를 백업해두고 테스트가 끝나면 그대로 복구한다(다른 테스트/실서비스에 영향 없도록)
  const { data: backupRows } = await admin.from('pg_configs').select('*').in('provider_key', ['kakaopay', 'naverpay']);
  const backupMap = {};
  (backupRows || []).forEach(r => { backupMap[r.provider_key] = r; });

  // ============================================
  // 0) 관리자 계정 준비 (관리자 전용 API 테스트용)
  // ============================================
  const adminEmail = `test-kknpadmin-${ts}@withplus-test.local`;
  const { data: adminUser } = await admin.auth.admin.createUser({ email: adminEmail, password: 'TestPass123!', email_confirm: true });
  const adminId = adminUser.user.id;
  await admin.from('profiles').upsert([{ id: adminId, email: adminEmail, full_name: 'KkNpTestAdmin', role: 'admin' }]);
  const adminToken = await loginAs(adminEmail, 'TestPass123!');

  const buyerEmail = `test-kknpbuyer-${ts}@withplus-test.local`;
  const { data: buyerUser } = await admin.auth.admin.createUser({ email: buyerEmail, password: 'TestPass123!', email_confirm: true });
  const buyerId = buyerUser.user.id;
  await admin.from('profiles').upsert([{ id: buyerId, email: buyerEmail, full_name: 'KkNpTestBuyer', role: 'member' }]);
  const buyerToken = await loginAs(buyerEmail, 'TestPass123!');

  // ============================================
  // 1) 공개 config 엔드포인트 - 비활성 상태에서는 항상 enabled:false만 노출 (시크릿 유출 없음)
  // ============================================
  for (const provider of ['kakaopay', 'naverpay']) {
    await admin.from('pg_configs').update({ enabled: false, client_key: null, secret_key: null, extra_config: {} }).eq('provider_key', provider);
    const res = await fetch(`${API}/api/payments/${provider}/config`);
    const json = await res.json();
    assert(res.status === 200 && json.success && json.data.enabled === false, `${provider}: 키가 없으면 공개 config가 정직하게 enabled:false를 반환함`);
  }
  assert((await fetch(`${API}/api/payments/naverpay-typo/config`)).status === 404, '지원하지 않는 provider는 config 조회 시 404를 반환함');

  // ============================================
  // 2) 관리자 GET/PATCH - secret_key 원문은 절대 응답에 포함되지 않음
  // ============================================
  for (const provider of ['kakaopay', 'naverpay']) {
    const getRes = await fetch(`${API}/api/admin/payment-gateway/${provider}`, { headers: { Authorization: 'Bearer ' + adminToken } });
    const getJson = await getRes.json();
    assert(getRes.status === 200 && getJson.success && getJson.data.provider_key === provider, `${provider}: 관리자 GET이 정상 응답함`);
    assert(getJson.data.has_secret_key === false && !('secret_key' in getJson.data), `${provider}: has_secret_key만 노출하고 secret_key 원문은 응답에 없음`);

    const patchBody = provider === 'kakaopay'
      ? { client_key: 'TC0ONETIME', secret_key: `fake-secret-${ts}`, mode: 'test', enabled: true }
      : { client_key: `fake-clientid-${ts}`, secret_key: `fake-secret-${ts}`, mode: 'test', enabled: true, extra_config: { partner_id: `fake-partner-${ts}` } };
    const patchRes = await fetch(`${API}/api/admin/payment-gateway/${provider}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + adminToken }, body: JSON.stringify(patchBody) });
    const patchJson = await patchRes.json();
    assert(patchRes.status === 200 && patchJson.success && patchJson.data.has_secret_key === true, `${provider}: 관리자 PATCH로 키 저장이 정상 처리됨`);
    if (provider === 'naverpay') {
      assert(patchJson.data.extra_config && patchJson.data.extra_config.partner_id === `fake-partner-${ts}`, '네이버페이: extra_config(파트너ID)가 정확히 저장됨');
    }
  }

  // 일반 회원은 관리자 API에 접근할 수 없음
  const memberPatchRes = await fetch(`${API}/api/admin/payment-gateway/kakaopay`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + buyerToken }, body: JSON.stringify({ enabled: true }) });
  assert(memberPatchRes.status === 403, '일반 회원은 결제 연동 설정을 변경할 수 없음(403)');

  // 활성화되었으니 이제 공개 config가 enabled:true를 반환해야 함
  const kakaoConfigRes = await fetch(`${API}/api/payments/kakaopay/config`);
  const kakaoConfigJson = await kakaoConfigRes.json();
  assert(kakaoConfigJson.data.enabled === true, '카카오페이 활성화 후 공개 config가 enabled:true로 바뀜(client_key/secret_key는 노출 안 함)');
  assert(!('client_key' in kakaoConfigJson.data) && !('secret_key' in kakaoConfigJson.data), '공개 config 응답에 client_key/secret_key가 전혀 포함되지 않음');

  // ============================================
  // 3) 연결 테스트 - 가짜 키로는 정직하게 실패해야 한다(성공을 꾸며내지 않음)
  // ============================================
  const kakaoTestRes = await fetch(`${API}/api/admin/payment-gateway/kakaopay/test`, { method: 'POST', headers: { Authorization: 'Bearer ' + adminToken } });
  const kakaoTestJson = await kakaoTestRes.json();
  assert(kakaoTestRes.status === 200 && kakaoTestJson.data.status === 'failed', '카카오페이: 가짜 SECRET_KEY로는 연결 테스트가 정직하게 실패로 나옴(성공 조작 없음)');

  const naverTestRes = await fetch(`${API}/api/admin/payment-gateway/naverpay/test`, { method: 'POST', headers: { Authorization: 'Bearer ' + adminToken } });
  const naverTestJson = await naverTestRes.json();
  assert(naverTestRes.status === 200 && naverTestJson.data.status === 'failed', '네이버페이: 가짜 Client-Id/Secret으로는 연결 테스트가 정직하게 실패로 나옴(성공 조작 없음)');

  // 키가 아예 없으면 테스트 자체를 거부(400)해야 한다
  await admin.from('pg_configs').update({ secret_key: null }).eq('provider_key', 'kakaopay');
  const noKeyTestRes = await fetch(`${API}/api/admin/payment-gateway/kakaopay/test`, { method: 'POST', headers: { Authorization: 'Bearer ' + adminToken } });
  assert(noKeyTestRes.status === 400, '카카오페이: 시크릿 키가 없으면 연결 테스트 자체를 400으로 정직하게 거부함');
  await admin.from('pg_configs').update({ secret_key: `fake-secret-${ts}` }).eq('provider_key', 'kakaopay');

  // ============================================
  // 4) 실제 주문 생성 후 결제 준비/예약 API - PG 비활성 상태에서는 정직하게 400
  // ============================================
  const { data: supplier } = await admin.from('profiles').select('id').eq('role', 'supplier').limit(1).maybeSingle();
  const supplierId = supplier ? supplier.id : adminId;
  const { data: category } = await admin.from('categories').select('db_category').eq('is_active', true).limit(1).maybeSingle();
  const { data: product } = await admin.from('products_with').insert({
    name: `간편결제테스트상품${ts}`, slug: `pay-test-${ts}`, description: '간편결제 연동 테스트용 상품입니다.',
    price: 9900, stock: 5, category: category ? category.db_category : 'etc', supplier_id: supplierId, status: 'active'
  }).select().single();

  const orderRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + buyerToken },
    body: JSON.stringify({ items: [{ product_id: product.id, name: product.name, price: 9900, quantity: 1 }], shipping_address: { name: '테스터', phone: '01000000000', address: '서울시 테스트구' }, payment_method: 'pending' })
  });
  const orderJson = await orderRes.json();
  assert(orderRes.ok && orderJson.success, '간편결제 테스트용 주문이 정상 생성됨');
  const order = orderJson.data;

  // 아직 비활성화 상태(카카오페이는 위에서 enabled:true로 저장했으니 잠시 꺼둔다)
  await admin.from('pg_configs').update({ enabled: false }).eq('provider_key', 'kakaopay');
  const readyDisabledRes = await fetch(`${API}/api/orders/${order.id}/kakaopay/ready`, { method: 'POST', headers: { Authorization: 'Bearer ' + buyerToken } });
  assert(readyDisabledRes.status === 400, '카카오페이 비활성 상태에서는 결제 준비 요청이 정직하게 400으로 거부됨');

  const reserveDisabledRes = await fetch(`${API}/api/orders/${order.id}/naverpay/reserve`, { method: 'POST', headers: { Authorization: 'Bearer ' + buyerToken } });
  assert(reserveDisabledRes.status === 400, '네이버페이 비활성 상태에서는 결제 예약 요청이 정직하게 400으로 거부됨');

  // 다시 켠 뒤(가짜 키) - 카카오페이 서버 실제 호출은 가짜 키라 실패하지만, 우리 서버가 그 실패를 그대로 정직하게 전달하는지 확인
  await admin.from('pg_configs').update({ enabled: true }).eq('provider_key', 'kakaopay');
  const readyEnabledRes = await fetch(`${API}/api/orders/${order.id}/kakaopay/ready`, { method: 'POST', headers: { Authorization: 'Bearer ' + buyerToken } });
  const readyEnabledJson = await readyEnabledRes.json();
  assert(readyEnabledRes.status === 400 && readyEnabledJson.error === 'Payment Ready Failed', '카카오페이 활성 상태에서 가짜 키로 실제 호출 시, 카카오 서버의 실패를 그대로 정직하게 전달함(가짜 성공 없음)');

  // 다른 사람 주문에 대해서는 결제 준비를 요청할 수 없음(주문 소유자 검증)
  const otherOrderReadyRes = await fetch(`${API}/api/orders/${order.id}/kakaopay/ready`, { method: 'POST', headers: { Authorization: 'Bearer ' + adminToken } });
  assert(otherOrderReadyRes.status === 404, '본인 소유가 아닌 주문에는 결제 준비 요청이 거부됨(404)');

  // ============================================
  // 5) 결제 승인 콜백 - 준비 세션 없이 접근하면 결제창이 아니라 결과 페이지로 정직하게 안내(서버 에러가 아님)
  // ============================================
  const approveNoSessionRes = await fetch(`${API}/api/payments/kakaopay/approve?order_id=${order.id}&pg_token=fake-token`, { redirect: 'manual' });
  assert([301, 302, 303, 307].includes(approveNoSessionRes.status), '카카오페이 승인 콜백은 준비 세션이 있든 없든 항상 결과 페이지로 리다이렉트됨(서버 500 없음)');
  const location = approveNoSessionRes.headers.get('location') || '';
  assert(location.includes('/payment-result.html') && location.includes('status=fail'), '준비 세션과 매칭되는 tid가 없으면 결제 결과 페이지로 실패 상태를 정직하게 안내함');

  // ============================================
  // 6) payment-result.html이 실제로 존재하고 정상 응답함 (토스/카카오/네이버 공통 착지 페이지 - 기존에 없던 것을 이번에 만듦)
  // ============================================
  const resultPageRes = await fetch(`${API}/payment-result.html`);
  const resultPageHtml = await resultPageRes.text();
  assert(resultPageRes.status === 200 && resultPageHtml.includes('결제 결과'), 'payment-result.html이 실제로 존재하고 정상 응답함');

  // ============================================
  // 7) 관리자 모듈 카탈로그에 새 모듈이 노출됨
  // ============================================
  const modulesRes = await fetch(`${API}/api/admin/modules`, { headers: { Authorization: 'Bearer ' + adminToken } });
  const modulesJson = await modulesRes.json();
  const moduleKeys = (modulesJson.data || []).map(m => m.key);
  assert(moduleKeys.includes('kakaopay') && moduleKeys.includes('naverpay'), '관리자 "기능 모듈" 카탈로그에 카카오페이/네이버페이가 노출됨');

  // ============================================
  // 정리
  // ============================================
  await admin.from('order_payments').delete().eq('order_id', order.id);
  await admin.from('orders_with').delete().eq('id', order.id);
  await admin.from('products_with').delete().eq('id', product.id);
  await admin.from('profiles').delete().in('id', [adminId, buyerId]);
  await admin.auth.admin.deleteUser(adminId);
  await admin.auth.admin.deleteUser(buyerId);

  // pg_configs를 테스트 이전 상태로 정확히 복구
  for (const provider of ['kakaopay', 'naverpay']) {
    const original = backupMap[provider];
    if (original) {
      await admin.from('pg_configs').update({
        client_key: original.client_key, secret_key: original.secret_key, mode: original.mode,
        enabled: original.enabled, extra_config: original.extra_config
      }).eq('provider_key', provider);
    }
  }
  console.log('정리 완료: 테스트 상품/주문/계정 삭제 및 pg_configs 원상복구');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
