const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
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
    headers: { 'Content-Type': 'application/json', apikey: anonKey },
    body: JSON.stringify({ email, password })
  });
  const json = await res.json();
  return json.access_token;
}

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const custEmail = `test-emailcust-${ts}@withplus-test.local`;
  const adminEmail = `test-emailadmin-${ts}@withplus-test.local`;

  const { data: custData } = await admin.auth.admin.createUser({ email: custEmail, password, email_confirm: true });
  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const custId = custData.user.id;
  const adminId = adminData.user.id;
  await admin.from('profiles').upsert([
    { id: custId, email: custEmail, full_name: 'EmailTestCustomer', role: 'member' },
    { id: adminId, email: adminEmail, full_name: 'EmailTestAdmin', role: 'admin' }
  ]);
  const custToken = await loginAs(custEmail, password);
  const adminToken = await loginAs(adminEmail, password);
  assert(!!custToken, '테스트 고객 로그인 성공');
  assert(!!adminToken, '테스트 관리자 로그인 성공');

  // 기존 email_configs_with 상태를 백업해뒀다가 테스트 종료 후 복원 (다른 세션에 영향 주지 않기 위함)
  const { data: originalConfig } = await admin.from('email_configs_with').select('*').eq('provider_key', 'smtp').maybeSingle();

  // ============================================
  // 0) 권한 체크 - 일반 회원은 이메일 설정 API에 접근할 수 없음
  // ============================================
  const custGetRes = await fetch(`${API}/api/admin/email-config`, { headers: { Authorization: `Bearer ${custToken}` } });
  assert(custGetRes.status === 403, `일반 회원이 이메일 설정 조회 시 403 (실제: ${custGetRes.status})`);

  const custPatchRes = await fetch(`${API}/api/admin/email-config`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` }, body: JSON.stringify({ enabled: true })
  });
  assert(custPatchRes.status === 403, `일반 회원이 이메일 설정 변경 시 403 (실제: ${custPatchRes.status})`);

  const custTestRes = await fetch(`${API}/api/admin/email-config/test`, { method: 'POST', headers: { Authorization: `Bearer ${custToken}` } });
  assert(custTestRes.status === 403, `일반 회원이 연결 테스트 시도 시 403 (실제: ${custTestRes.status})`);

  const noAuthRes = await fetch(`${API}/api/admin/email-config`);
  assert(noAuthRes.status === 401, `인증 없이 이메일 설정 조회 시 401 (실제: ${noAuthRes.status})`);

  // ============================================
  // 1) 관리자 - 설정 조회 시 비밀번호 원문이 노출되지 않음
  // ============================================
  const adminGetRes = await fetch(`${API}/api/admin/email-config`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const adminGetJson = await adminGetRes.json();
  assert(adminGetRes.status === 200 && adminGetJson.success, `관리자 이메일 설정 조회 성공 (실제: ${adminGetRes.status})`);
  assert(adminGetJson.data.smtp_pass === undefined, '조회 응답에 smtp_pass 원문 필드가 없음');
  assert(typeof adminGetJson.data.has_smtp_pass === 'boolean', 'has_smtp_pass 불리언 플래그가 내려옴');

  // ============================================
  // 2) 가짜 SMTP 정보로 설정 저장 (실제로는 연결 불가능한 값) - 정직하게 실패를 기록하는지 확인할 목적
  // ============================================
  const fakeHost = `smtp.nonexistent-test-domain-${ts}.invalid`;
  const patchRes = await fetch(`${API}/api/admin/email-config`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({
      smtp_host: fakeHost, smtp_port: 587, smtp_secure: false,
      smtp_user: 'test@example.com', smtp_pass: 'fake-password-123',
      from_name: 'WITH+ 테스트', from_email: 'noreply@example.com', enabled: true
    })
  });
  const patchJson = await patchRes.json();
  assert(patchRes.status === 200 && patchJson.success, `가짜 SMTP 설정 저장 성공 (실제: ${patchRes.status})`);
  assert(patchJson.data.has_smtp_pass === true, '저장 후 has_smtp_pass가 true로 표시됨');
  assert(patchJson.data.smtp_pass === undefined, '저장 응답에도 smtp_pass 원문이 없음');

  // ============================================
  // 3) 부분 업데이트 시 비밀번호를 보내지 않으면 기존 비밀번호가 유지되는지 확인
  // ============================================
  const partialPatchRes = await fetch(`${API}/api/admin/email-config`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ from_name: 'WITH+ 이름만변경' })
  });
  const partialPatchJson = await partialPatchRes.json();
  assert(partialPatchRes.status === 200 && partialPatchJson.data.has_smtp_pass === true, '비밀번호 없이 부분 수정해도 기존 비밀번호가 유지됨(has_smtp_pass 계속 true)');
  // PATCH 응답은 (PG/AI 연동과 동일한 컨벤션으로) 비밀 필드를 노출하지 않는 최소 정보만 내려주므로,
  // from_name이 실제로 반영됐는지는 GET으로 다시 조회해 확인한다.
  const afterPartialGetRes = await fetch(`${API}/api/admin/email-config`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const afterPartialGetJson = await afterPartialGetRes.json();
  assert(afterPartialGetJson.data.from_name === 'WITH+ 이름만변경', '부분 수정 필드(from_name)만 반영됨 (GET으로 재확인)');
  assert(afterPartialGetJson.data.smtp_host === fakeHost, '부분 수정 시 지정하지 않은 필드(smtp_host)는 기존 값 그대로 유지됨');

  // ============================================
  // 4) 연결 테스트 - 존재하지 않는 SMTP 호스트이므로 정직하게 실패로 기록되어야 함 (가짜로 성공 처리하지 않음)
  // ============================================
  const connTestRes = await fetch(`${API}/api/admin/email-config/test`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
  const connTestJson = await connTestRes.json();
  assert(connTestRes.status === 200 && connTestJson.success, `연결 테스트 API 자체는 정상 응답 (실제: ${connTestRes.status})`);
  assert(connTestJson.data.status === 'failed', `존재하지 않는 SMTP 호스트이므로 테스트 결과가 정직하게 failed로 기록됨 (실제: ${connTestJson.data.status})`);

  const afterTestGetRes = await fetch(`${API}/api/admin/email-config`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const afterTestGetJson = await afterTestGetRes.json();
  assert(afterTestGetJson.data.last_test_status === 'failed', '설정 재조회 시 last_test_status가 failed로 저장되어 있음');
  assert(!!afterTestGetJson.data.last_tested_at, 'last_tested_at 시각이 기록됨');

  // ============================================
  // 5) enabled + 실패할 SMTP 설정 상태에서 실제 주문 생성 -> 주문은 정상 성공하고, email_logs_with에 failed로 기록되는지 확인
  //    (주문 생성 자체가 이메일 발송 실패로 막히면 안 된다는 것이 핵심 - 실제 SMTP 계정이 없으므로 이 경로가 정직한 테스트 방법)
  // ============================================
  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;
  const { data: prod, error: prodErr } = await admin.from('products_with').insert({
    name: `이메일테스트상품-${ts}`, slug: `email-test-${ts}`, description: '테스트 상품입니다', price: 10000, stock: 20,
    category, supplier_id: adminId, status: 'active'
  }).select().single();
  if (prodErr) { console.error('product create failed', prodErr); process.exit(1); }

  const orderRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({
      items: [{ product_id: prod.id, name: prod.name, price: prod.price, quantity: 1 }],
      shipping_address: { postal_code: '06134', address: '서울시 강남구' },
      payment_method: 'pending'
    })
  });
  const orderJson = await orderRes.json();
  assert(orderRes.status === 201 && orderJson.success, `SMTP가 실패 상태여도 주문 생성 자체는 정상 성공 (실제: ${orderRes.status})`);

  // 이메일 발송(비동기 이후 로그 기록)까지 잠깐 대기 후 로그 확인
  await new Promise(r => setTimeout(r, 1500));
  const { data: logRows } = await admin.from('email_logs_with').select('*').eq('related_order_id', orderJson.data.id);
  assert(!!logRows && logRows.length === 1, `주문 생성 시 email_logs_with에 로그 1건 기록됨 (실제: ${logRows ? logRows.length : 0}건)`);
  if (logRows && logRows.length === 1) {
    assert(logRows[0].status === 'failed', `가짜 SMTP 호스트이므로 정직하게 status=failed로 기록됨 (실제: ${logRows[0].status})`);
    assert(logRows[0].to_email === custEmail, '로그의 수신자 이메일이 실제 주문자 이메일과 일치함');
    assert(logRows[0].template === 'order_confirmation', "로그의 template이 'order_confirmation'으로 기록됨");
  }

  // ============================================
  // 6) 주문 상태를 shipped로 변경 -> 상태변경 알림 이메일도 시도되고 로그가 남는지 확인
  // ============================================
  const statusRes = await fetch(`${API}/api/admin/orders/${orderJson.data.id}/status`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'shipped', courier_name: 'CJ대한통운', tracking_number: '123456789012' })
  });
  assert(statusRes.status === 200, `주문 상태를 shipped로 변경 성공 (실제: ${statusRes.status})`);
  await new Promise(r => setTimeout(r, 1500));
  const { data: statusLogRows } = await admin.from('email_logs_with').select('*').eq('related_order_id', orderJson.data.id).eq('template', 'order_status_shipped').order('created_at', { ascending: false });
  assert(!!statusLogRows && statusLogRows.length >= 1, `배송중 상태변경 시 email_logs_with에 상태변경 알림 로그가 기록됨 (실제: ${statusLogRows ? statusLogRows.length : 0}건)`);

  // ============================================
  // 7) 비활성화(enabled=false) 상태에서는 주문 생성 시 'skipped'로 기록되는지 확인
  // ============================================
  await fetch(`${API}/api/admin/email-config`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ enabled: false })
  });
  const { data: prod2, error: prod2Err } = await admin.from('products_with').insert({
    name: `이메일테스트상품2-${ts}`, slug: `email-test2-${ts}`, description: '테스트 상품입니다', price: 10000, stock: 20,
    category, supplier_id: adminId, status: 'active'
  }).select().single();
  if (prod2Err) { console.error('product2 create failed', prod2Err); process.exit(1); }

  const order2Res = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({
      items: [{ product_id: prod2.id, name: prod2.name, price: prod2.price, quantity: 1 }],
      shipping_address: { postal_code: '06134', address: '서울시 강남구' },
      payment_method: 'pending'
    })
  });
  const order2Json = await order2Res.json();
  assert(order2Res.status === 201, `이메일 비활성화 상태에서도 주문 생성 정상 성공 (실제: ${order2Res.status})`);
  await new Promise(r => setTimeout(r, 1500));
  const { data: skippedLogRows } = await admin.from('email_logs_with').select('*').eq('related_order_id', order2Json.data.id);
  assert(!!skippedLogRows && skippedLogRows.length === 1 && skippedLogRows[0].status === 'skipped', `이메일 알림 비활성화 상태에서는 status=skipped로 정직하게 기록됨 (실제: ${skippedLogRows && skippedLogRows[0] ? skippedLogRows[0].status : 'none'})`);

  // ============================================
  // 8) 관리자용 이메일 발송 로그 조회 API
  // ============================================
  const logsRes = await fetch(`${API}/api/admin/email-logs`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const logsJson = await logsRes.json();
  assert(logsRes.status === 200 && logsJson.success && Array.isArray(logsJson.data), `관리자 이메일 로그 목록 조회 성공 (실제: ${logsRes.status})`);
  assert(logsJson.data.some(l => l.related_order_id === orderJson.data.id), '로그 목록에 방금 생성한 주문의 로그가 포함됨');

  // ============================================
  // 정리 - 원래 설정 복원 + 테스트 데이터 삭제
  // ============================================
  if (originalConfig) {
    await admin.from('email_configs_with').update({
      smtp_host: originalConfig.smtp_host, smtp_port: originalConfig.smtp_port, smtp_secure: originalConfig.smtp_secure,
      smtp_user: originalConfig.smtp_user, smtp_pass: originalConfig.smtp_pass,
      from_name: originalConfig.from_name, from_email: originalConfig.from_email, enabled: originalConfig.enabled,
      last_tested_at: originalConfig.last_tested_at, last_test_status: originalConfig.last_test_status, last_test_message: originalConfig.last_test_message
    }).eq('provider_key', 'smtp');
  } else {
    await admin.from('email_configs_with').update({
      smtp_host: null, smtp_port: null, smtp_secure: true, smtp_user: null, smtp_pass: null,
      from_name: 'WITH+', from_email: null, enabled: false, last_tested_at: null, last_test_status: null, last_test_message: null
    }).eq('provider_key', 'smtp');
  }
  await admin.from('email_logs_with').delete().in('related_order_id', [orderJson.data.id, order2Json.data.id]);
  await admin.from('orders_with').delete().in('id', [orderJson.data.id, order2Json.data.id]);
  await admin.from('products_with').delete().in('id', [prod.id, prod2.id]);
  await admin.from('profiles').delete().in('id', [custId, adminId]);
  await admin.auth.admin.deleteUser(custId);
  await admin.auth.admin.deleteUser(adminId);
  console.log('정리 완료: 테스트 설정 복원, 주문/상품/유저 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
