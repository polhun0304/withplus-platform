// 💳 결제(PG) 연동(토스페이먼츠) 기능 검증용 임시 테스트.
// 주의: 실제 토스페이먼츠 테스트/실서비스 키가 없으므로, "실제 카드 결제 승인이 정확히 되는지"까지는
// 이 테스트로 검증할 수 없다(정직하게 이 부분은 검증 범위 밖 - 형님이 키를 넣고 실제로 눌러봐야 최종 확인됨).
// 대신 우리가 실제로 만든 부분 — 권한 체크, 설정 저장/조회(시크릿 키 비노출), 결제 승인 전 금액/소유자/상태 검증,
// 연동이 꺼져있을 때의 안전한 기본 동작 — 은 전부 실제로 검증한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const ADMIN_EMAIL = `withplus.pgtest.admin.${stamp}@withplus.test`;
const MEMBER_EMAIL = `withplus.pgtest.member.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';
let createdUserIds = [];
let createdOrderIds = [];

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
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(options.headers || {}) }
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
  await admin.from('pg_configs').update({ client_key: null, secret_key: null, enabled: false, mode: 'test', last_tested_at: null, last_test_status: null, last_test_message: null }).eq('provider_key', 'toss');
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 준비 ===');
  const adminUser = await createTestUser(ADMIN_EMAIL, 'super_admin');
  const member = await createTestUser(MEMBER_EMAIL, 'member');
  await admin.from('pg_configs').update({ client_key: null, secret_key: null, enabled: false, mode: 'test', last_tested_at: null, last_test_status: null, last_test_message: null }).eq('provider_key', 'toss');

  console.log('\n=== 1. 연동이 꺼져있을 때 공개 설정 조회는 enabled:false만 안전하게 반환(시크릿 노출 없음) ===');
  const publicCfg = await api('/api/payments/toss/config', null);
  assert(publicCfg.ok && publicCfg.json.data.enabled === false, `공개 설정 조회 시 enabled:false (실제=${publicCfg.json.data.enabled})`);
  assert(!('clientKey' in publicCfg.json.data), '연동이 꺼져있으면 clientKey 필드조차 내려주지 않음');

  console.log('\n=== 2. 관리자 조회: 인증 없으면 401, 일반 회원은 403 ===');
  const noAuth = await api('/api/admin/payment-gateway', null);
  assert(noAuth.status === 401, `인증 없는 요청은 401 (실제=${noAuth.status})`);
  const memberGet = await api('/api/admin/payment-gateway', member.token);
  assert(memberGet.status === 403, `일반 회원 요청은 403 (실제=${memberGet.status})`);

  console.log('\n=== 3. 관리자는 조회 가능, secret_key 원문은 절대 노출 안 됨 ===');
  const adminGet = await api('/api/admin/payment-gateway', adminUser.token);
  assert(adminGet.ok, `관리자 조회 성공 (status=${adminGet.status})`);
  assert(!('secret_key' in adminGet.json.data), '응답 어디에도 secret_key 원문 필드가 없음');
  assert(adminGet.json.data.has_secret_key === false, '초기 상태는 시크릿 키 미설정');

  console.log('\n=== 4. 일반 회원은 저장 불가(403) ===');
  const memberSave = await api('/api/admin/payment-gateway', member.token, { method: 'PATCH', body: JSON.stringify({ client_key: 'x', secret_key: 'y' }) });
  assert(memberSave.status === 403, `일반 회원의 저장 시도는 403 (실제=${memberSave.status})`);

  console.log('\n=== 5. 관리자는 키 저장 가능, 저장 후에도 secret_key 원문 없음, client_key는 그대로 보임(원래 공개값) ===');
  const saveRes = await api('/api/admin/payment-gateway', adminUser.token, {
    method: 'PATCH', body: JSON.stringify({ client_key: 'test_ck_fake_for_test', secret_key: 'test_sk_fake_for_test', mode: 'test', enabled: true })
  });
  assert(saveRes.ok, `키 저장 성공 (status=${saveRes.status})`);
  assert(saveRes.json.data.client_key === 'test_ck_fake_for_test', 'client_key가 저장한 값 그대로 반환됨');
  assert(saveRes.json.data.has_secret_key === true, 'has_secret_key가 true로 바뀜');
  assert(!('secret_key' in saveRes.json.data), '저장 응답에도 secret_key 원문 없음');

  console.log('\n=== 6. 연동을 켠 뒤에는 공개 설정 조회에 clientKey가 나옴(결제위젯 초기화에 필요) ===');
  const publicCfgOn = await api('/api/payments/toss/config', null);
  assert(publicCfgOn.json.data.enabled === true, `공개 설정 조회 시 enabled:true (실제=${publicCfgOn.json.data.enabled})`);
  assert(publicCfgOn.json.data.clientKey === 'test_ck_fake_for_test', 'clientKey가 정상적으로 내려옴');

  console.log('\n=== 7. (가짜 키로) 연결 테스트 - 실제 토스 서버에 실시간 요청을 보내되, 인증 실패를 정상적으로 처리하는지 ===');
  const testRes = await api('/api/admin/payment-gateway/test', adminUser.token, { method: 'POST' });
  assert(testRes.ok, `테스트 요청 자체는 200으로 처리됨 (status=${testRes.status})`);
  assert(testRes.json.data.status === 'failed', `가짜 시크릿 키는 실제 토스 서버에서 인증 실패로 판정됨 (실제=${testRes.json.data.status})`);
  console.log(`   ℹ️  실제 토스페이먼츠 서버 응답 메시지: ${testRes.json.data.message.slice(0, 150)}`);

  console.log('\n=== 8. 결제 승인: 존재하지 않는 주문번호면 404 ===');
  const confirmNoOrder = await api('/api/payments/toss/confirm', member.token, {
    method: 'POST', body: JSON.stringify({ paymentKey: 'pk', orderId: 'ORD-NOT-EXIST-' + stamp, amount: 1000 })
  });
  assert(confirmNoOrder.status === 404, `존재하지 않는 주문은 404 (실제=${confirmNoOrder.status})`);

  console.log('\n=== 9. 결제 승인: 실제 주문을 만들고, 금액이 다르면 400으로 거부(위변조 방지) ===');
  const { data: testOrder, error: orderErr } = await admin.from('orders_with').insert([{
    order_number: 'ORD-PGTEST-' + stamp,
    user_id: member.id,
    items: [{ product_id: null, name: '테스트상품', price: 10000, quantity: 1 }],
    total_price: 10000,
    final_price: 10000,
    status: 'pending',
    payment_method: 'pending'
  }]).select().single();
  if (orderErr) throw orderErr;
  createdOrderIds.push(testOrder.id);

  const confirmWrongAmount = await api('/api/payments/toss/confirm', member.token, {
    method: 'POST', body: JSON.stringify({ paymentKey: 'pk', orderId: testOrder.order_number, amount: 999 })
  });
  assert(confirmWrongAmount.status === 400, `주문 금액과 다르면 400 (실제=${confirmWrongAmount.status})`);

  console.log('\n=== 10. 결제 승인: 다른 사람의 주문은 404(본인 주문만 승인 가능) ===');
  const confirmOtherUser = await api('/api/payments/toss/confirm', adminUser.token, {
    method: 'POST', body: JSON.stringify({ paymentKey: 'pk', orderId: testOrder.order_number, amount: 10000 })
  });
  assert(confirmOtherUser.status === 404, `본인 소유가 아닌 주문은 404 (실제=${confirmOtherUser.status})`);

  console.log('\n=== 11. 결제 승인: 금액이 맞으면 실제 토스 서버까지 요청이 가고(가짜 결제키라 최종 승인은 실패), 주문은 pending으로 안전하게 유지됨 ===');
  const confirmRealAttempt = await api('/api/payments/toss/confirm', member.token, {
    method: 'POST', body: JSON.stringify({ paymentKey: 'fake-payment-key', orderId: testOrder.order_number, amount: 10000 })
  });
  assert(!confirmRealAttempt.ok, `가짜 결제키로는 승인되지 않음 (status=${confirmRealAttempt.status})`);
  const { data: afterOrder } = await admin.from('orders_with').select('status').eq('id', testOrder.id).single();
  assert(afterOrder.status === 'pending', `승인 실패 후에도 주문 상태는 여전히 pending으로 안전하게 유지됨 (실제=${afterOrder.status})`);
  const { data: paymentLog } = await admin.from('order_payments').select('*').eq('order_id', testOrder.id).eq('status', 'failed');
  assert(paymentLog && paymentLog.length === 1, '실패한 결제 시도가 order_payments에 failed로 기록됨(감사 로그)');

  console.log('\n🎉 모든 검증 통과 (단, 토스페이먼츠 실제 서버와의 최종 결제 승인 자체는 실제 키 확보 후 형님이 직접 확인 필요)');
}

main()
  .catch(err => { console.error('\n💥 테스트 실패:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
