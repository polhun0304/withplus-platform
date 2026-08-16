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

function addDays(dateStr, days) {
  const d = new Date(dateStr + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}
function todayStr() { return new Date().toISOString().slice(0, 10); }

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const adminEmail = `test-sub-admin-${ts}@withplus-test.local`;
  const memberEmail = `test-sub-member-${ts}@withplus-test.local`;
  const otherMemberEmail = `test-sub-other-${ts}@withplus-test.local`;

  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: memberData } = await admin.auth.admin.createUser({ email: memberEmail, password, email_confirm: true });
  const { data: otherData } = await admin.auth.admin.createUser({ email: otherMemberEmail, password, email_confirm: true });
  const adminId = adminData.user.id;
  const memberId = memberData.user.id;
  const otherId = otherData.user.id;

  await admin.from('profiles').upsert([
    { id: adminId, email: adminEmail, full_name: 'SubTestAdmin', role: 'admin' },
    { id: memberId, email: memberEmail, full_name: 'SubTestMember', role: 'member' },
    { id: otherId, email: otherMemberEmail, full_name: 'SubTestOther', role: 'member' }
  ]);

  const adminToken = await loginAs(adminEmail, password);
  const memberToken = await loginAs(memberEmail, password);
  const otherToken = await loginAs(otherMemberEmail, password);
  assert(adminToken && memberToken && otherToken, '테스트 계정 3개 로그인 성공');

  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;

  const { data: subProduct } = await admin.from('products_with').insert({
    name: `정기배송테스트상품-${ts}`, slug: `sub-test-${ts}`, description: '테스트', price: 20000, stock: 50,
    category, supplier_id: adminId, status: 'active', subscription_available: true
  }).select().single();

  const { data: normalProduct } = await admin.from('products_with').insert({
    name: `정기배송미지원상품-${ts}`, slug: `sub-test-nosubs-${ts}`, description: '테스트', price: 15000, stock: 50,
    category, supplier_id: adminId, status: 'active', subscription_available: false
  }).select().single();

  // ============================================
  // 신청 (POST /api/subscriptions)
  // ============================================
  const noAuthRes = await fetch(`${API}/api/subscriptions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ product_id: subProduct.id, quantity: 1, cycle_days: 14, recipient_name: '홍길동', recipient_phone: '010-1111-2222', address: '서울시 강남구' })
  });
  assert(noAuthRes.status === 401, `인증 없이 정기배송 신청 시도 시 401 (실제: ${noAuthRes.status})`);

  const notSubscribableRes = await fetch(`${API}/api/subscriptions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ product_id: normalProduct.id, quantity: 1, cycle_days: 14, recipient_name: '홍길동', recipient_phone: '010-1111-2222', address: '서울시 강남구' })
  });
  assert(notSubscribableRes.status === 400, `정기배송 미지원 상품 신청 시도 시 400 (실제: ${notSubscribableRes.status})`);

  const badCycleRes = await fetch(`${API}/api/subscriptions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ product_id: subProduct.id, quantity: 1, cycle_days: 999, recipient_name: '홍길동', recipient_phone: '010-1111-2222', address: '서울시 강남구' })
  });
  assert(badCycleRes.status === 400, `허용되지 않은 배송주기(999일) 신청 시 400 (실제: ${badCycleRes.status})`);

  const badQtyRes = await fetch(`${API}/api/subscriptions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ product_id: subProduct.id, quantity: 0, cycle_days: 14, recipient_name: '홍길동', recipient_phone: '010-1111-2222', address: '서울시 강남구' })
  });
  assert(badQtyRes.status === 400, `수량 0으로 신청 시 400 (실제: ${badQtyRes.status})`);

  const noAddrRes = await fetch(`${API}/api/subscriptions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ product_id: subProduct.id, quantity: 1, cycle_days: 14 })
  });
  assert(noAddrRes.status === 400, `배송지 정보 없이 신청 시 400 (실제: ${noAddrRes.status})`);

  const createRes = await fetch(`${API}/api/subscriptions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ product_id: subProduct.id, quantity: 2, cycle_days: 14, recipient_name: '홍길동', recipient_phone: '010-1111-2222', address: '서울시 강남구 테헤란로 1', address_detail: '101동 101호' })
  });
  const createJson = await createRes.json();
  const expectedFirstDate = addDays(todayStr(), 14);
  assert(
    createRes.status === 201 && createJson.data.status === 'active' && createJson.data.next_delivery_date === expectedFirstDate && createJson.data.quantity === 2,
    `정기배송 신청 성공, 다음배송일 정확히 계산됨 (실제: status=${createJson.data?.status}, next=${createJson.data?.next_delivery_date}, 기대=${expectedFirstDate})`
  );
  const subId = createJson.data.id;

  // 저장된 배송지로 신청하는 경로도 확인
  const addrCreateRes = await fetch(`${API}/api/me/addresses`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ label: '집', receiver_name: '김철수', receiver_phone: '010-3333-4444', postal_code: '06236', address: '서울시 강남구 테헤란로 99', address_detail: '5층' })
  });
  const addrCreateJson = await addrCreateRes.json();
  const savedAddressId = addrCreateJson.data.id;

  const createWithAddrRes = await fetch(`${API}/api/subscriptions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ product_id: subProduct.id, quantity: 1, cycle_days: 30, shipping_address_id: savedAddressId })
  });
  const createWithAddrJson = await createWithAddrRes.json();
  assert(
    createWithAddrRes.status === 201 && createWithAddrJson.data.recipient_name === '김철수' && createWithAddrJson.data.address === '서울시 강남구 테헤란로 99',
    `저장된 배송지로 신청 시 배송정보가 정확히 스냅샷 복사됨 (실제: ${createWithAddrJson.data?.recipient_name}, ${createWithAddrJson.data?.address})`
  );
  const subId2 = createWithAddrJson.data.id;

  const invalidAddrRes = await fetch(`${API}/api/subscriptions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ product_id: subProduct.id, quantity: 1, cycle_days: 30, shipping_address_id: '00000000-0000-0000-0000-000000000000' })
  });
  assert(invalidAddrRes.status === 400, `존재하지 않는 배송지 id로 신청 시 400 (실제: ${invalidAddrRes.status})`);

  // ============================================
  // 내 정기배송 조회/수정/취소
  // ============================================
  const listRes = await fetch(`${API}/api/me/subscriptions`, { headers: { Authorization: `Bearer ${memberToken}` } });
  const listJson = await listRes.json();
  assert(listRes.status === 200 && listJson.count === 2 && listJson.data[0].product, `내 정기배송 목록 조회 성공, 2건 + 상품정보 포함 (실제 건수: ${listJson.count})`);

  const otherPatchRes = await fetch(`${API}/api/me/subscriptions/${subId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${otherToken}` },
    body: JSON.stringify({ quantity: 5 })
  });
  assert(otherPatchRes.status === 404, `다른 회원이 남의 정기배송을 수정하려 하면 404 (실제: ${otherPatchRes.status})`);

  const updateQtyRes = await fetch(`${API}/api/me/subscriptions/${subId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ quantity: 5, cycle_days: 7 })
  });
  const updateQtyJson = await updateQtyRes.json();
  assert(updateQtyRes.status === 200 && updateQtyJson.data.quantity === 5 && updateQtyJson.data.cycle_days === 7, `수량/주기 수정 성공 (실제: qty=${updateQtyJson.data?.quantity}, cycle=${updateQtyJson.data?.cycle_days})`);

  const pauseRes = await fetch(`${API}/api/me/subscriptions/${subId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ status: 'paused' })
  });
  const pauseJson = await pauseRes.json();
  assert(pauseRes.status === 200 && pauseJson.data.status === 'paused', `일시중지 처리 성공 (실제: ${pauseJson.data?.status})`);

  // ============================================
  // 관리자 목록/발송 처리
  // ============================================
  const adminListNoAuthRes = await fetch(`${API}/api/admin/subscriptions`);
  assert(adminListNoAuthRes.status === 401, `관리자 목록 - 인증 없이 조회 시 401 (실제: ${adminListNoAuthRes.status})`);

  const adminListMemberRes = await fetch(`${API}/api/admin/subscriptions`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert(adminListMemberRes.status === 403, `관리자 목록 - 일반회원 권한으로 조회 시 403 (실제: ${adminListMemberRes.status})`);

  const adminListRes = await fetch(`${API}/api/admin/subscriptions`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const adminListJson = await adminListRes.json();
  const foundSub2 = adminListJson.data.find(s => s.id === subId2);
  assert(adminListRes.status === 200 && !!foundSub2 && foundSub2.member_email === memberEmail, `관리자 전체 목록 조회 성공, 회원 이메일 함께 표시됨 (실제: ${foundSub2?.member_email})`);

  const processPausedRes = await fetch(`${API}/api/admin/subscriptions/${subId}/process`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
  assert(processPausedRes.status === 400, `일시중지된 정기배송은 발송 처리 시도 시 400 (실제: ${processPausedRes.status})`);

  const beforeProcess = adminListJson.data.find(s => s.id === subId2);
  const processRes = await fetch(`${API}/api/admin/subscriptions/${subId2}/process`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
  const processJson = await processRes.json();
  const expectedNextDate = addDays(beforeProcess.next_delivery_date, beforeProcess.cycle_days);
  assert(
    processRes.status === 200 && processJson.data.next_delivery_date === expectedNextDate && !!processJson.data.last_delivered_at,
    `발송 처리 성공, 다음 배송일이 주기만큼 정확히 밀림 (실제: ${processJson.data?.next_delivery_date}, 기대: ${expectedNextDate})`
  );

  const logsRes = await fetch(`${API}/api/admin/subscriptions/${subId2}/logs`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const logsJson = await logsRes.json();
  assert(logsRes.status === 200 && logsJson.data.length === 1 && logsJson.data[0].scheduled_date === beforeProcess.next_delivery_date, `발송 이력 1건 정확히 기록됨 (실제 건수: ${logsJson.data?.length})`);

  const dueFilterRes = await fetch(`${API}/api/admin/subscriptions?due=true`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const dueFilterJson = await dueFilterRes.json();
  const dueIncludesSub2 = dueFilterJson.data.some(s => s.id === subId2);
  assert(dueFilterRes.status === 200 && !dueIncludesSub2, `발송 처리로 다음 배송일이 미래로 밀린 건은 "오늘 발송 필요" 필터에서 제외됨 (실제 포함여부: ${dueIncludesSub2})`);

  // ============================================
  // 취소
  // ============================================
  const resumeRes = await fetch(`${API}/api/me/subscriptions/${subId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ status: 'active' })
  });
  assert(resumeRes.status === 200, `일시중지된 정기배송 재개 성공 (실제: ${resumeRes.status})`);

  const cancelRes = await fetch(`${API}/api/me/subscriptions/${subId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${memberToken}` } });
  assert(cancelRes.status === 200, `정기배송 취소 성공 (실제: ${cancelRes.status})`);

  const cancelAgainRes = await fetch(`${API}/api/me/subscriptions/${subId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${memberToken}` } });
  assert(cancelAgainRes.status === 400, `이미 취소된 정기배송을 다시 취소 시도 시 400 (실제: ${cancelAgainRes.status})`);

  const patchCancelledRes = await fetch(`${API}/api/me/subscriptions/${subId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ quantity: 1 })
  });
  assert(patchCancelledRes.status === 400, `취소된 정기배송은 수정 시도 시 400 (실제: ${patchCancelledRes.status})`);

  const processCancelledRes = await fetch(`${API}/api/admin/subscriptions/${subId}/process`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
  assert(processCancelledRes.status === 400, `취소된 정기배송은 발송 처리 시도 시 400 (실제: ${processCancelledRes.status})`);

  // 정리
  await admin.from('subscription_delivery_logs_with').delete().in('subscription_id', [subId, subId2]);
  await admin.from('product_subscriptions_with').delete().in('id', [subId, subId2]);
  await admin.from('shipping_addresses_with').delete().eq('id', savedAddressId);
  await admin.from('products_with').delete().in('id', [subProduct.id, normalProduct.id]);
  await admin.from('profiles').delete().in('id', [adminId, memberId, otherId]);
  await admin.auth.admin.deleteUser(adminId);
  await admin.auth.admin.deleteUser(memberId);
  await admin.auth.admin.deleteUser(otherId);
  console.log('정리 완료: 정기배송/발송이력/배송지/상품/계정 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
