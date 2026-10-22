// WITH+ 라이브(LIVE+에서 이식) 채널 자격정보 상태모델 분리 회귀 테스트.
// "입력됨"과 "검증완료"는 절대 같은 상태가 아니어야 한다 - 생성 직후 자동으로 verified가 되지 않는지,
// 증빙(document_ref) 없이는 verified 전환이 막히는지, 모든 상태 변경이 이력에 남는지 확인한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-channel-license-status.js
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
  const adminEmail = `test-lcls-admin-${ts}@withplus-test.local`;
  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  await admin.from('profiles').upsert([{ id: aData.user.id, email: adminEmail, role: 'admin', member_type: 'general' }]);
  const adminToken = await loginAs(adminEmail, password);
  const slug = `test-lcls-channel-${ts}`;

  const createChannelRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: 'LCLS 테스트 채널', channel_type: 'supplier' })
  });
  const channel = (await createChannelRes.json()).data;

  // 1) 생성 직후 status는 submitted(입력됨)이지 verified가 아니다 - verified_by/verified_at도 비어있어야 함
  const createRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ license_type: 'real_estate_broker', license_number: `RE-${ts}`, license_holder_name: '홍길동' })
  });
  const createJson = await createRes.json();
  assert(createRes.status === 201 && createJson.data?.status === 'submitted', `생성 직후 status=submitted (실제: ${createJson.data?.status})`);
  assert(createJson.data?.verified_by === null && createJson.data?.verified_at === null, '생성 직후 verified_by/verified_at은 비어있음');
  assert(createJson.data?.expiry_state === 'none', `만료일 미지정 시 expiry_state=none (실제: ${createJson.data?.expiry_state})`);
  const licenseId = createJson.data.id;

  // 2) 증빙(document_ref) 없이는 verified 전환 불가
  const badVerifyRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses/${licenseId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'verified' })
  });
  assert(badVerifyRes.status === 400, `증빙 없이 verified 전환 시도 시 400 (실제: ${badVerifyRes.status})`);

  // 3) 증빙과 함께라면 verified 전환 가능, verified_by/verified_at 자동 기록
  const goodVerifyRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses/${licenseId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'verified', document_ref: `DOC-${ts}`, status_note: '증빙 확인 완료' })
  });
  const goodVerifyJson = await goodVerifyRes.json();
  assert(goodVerifyRes.status === 200 && goodVerifyJson.data?.status === 'verified' && goodVerifyJson.data?.verified_by, `증빙과 함께 verified 전환 성공 (실제: status=${goodVerifyJson.data?.status}, verified_by=${goodVerifyJson.data?.verified_by})`);

  // 4) 유효하지 않은 status 값은 거부 (구 값인 'active'도 이제는 무효)
  const badStatusRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses/${licenseId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'active' })
  });
  assert(badStatusRes.status === 400, `구버전 상태값('active')은 이제 거부됨 (실제: ${badStatusRes.status})`);

  // 5) needs_more_info로 전환하면 verified_by/verified_at이 다시 비워진다(최신 상태와 과거 검증 흔적 혼동 방지)
  const revertRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses/${licenseId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'needs_more_info', status_note: '주소 증빙 보완 필요' })
  });
  const revertJson = await revertRes.json();
  assert(revertRes.status === 200 && revertJson.data?.status === 'needs_more_info' && revertJson.data?.verified_by === null, `보완요청 전환 시 verified_by 초기화 (실제: status=${revertJson.data?.status}, verified_by=${revertJson.data?.verified_by})`);

  // 6) 상태 변경 이력이 append-only로 쌓였는지 확인 (최초등록 + verified + needs_more_info = 3건)
  const historyRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses/${licenseId}/history`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const historyJson = await historyRes.json();
  assert(historyJson.data?.length === 3, `상태 변경 이력 3건 기록됨 (실제: ${historyJson.data?.length})`);
  assert(historyJson.data?.[0].to_status === 'needs_more_info' && historyJson.data?.[0].note === '주소 증빙 보완 필요', '최신 이력 항목의 내용 정확함(최신순 정렬)');

  // 7) 만료예정/만료는 저장되지 않고 expires_at 기준으로 계산되어 표시된다
  const soon = new Date(); soon.setDate(soon.getDate() + 5);
  const past = new Date(); past.setDate(past.getDate() - 5);
  const soonRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses/${licenseId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ expires_at: soon.toISOString().slice(0, 10) })
  });
  const soonJson = await soonRes.json();
  assert(soonJson.data?.expiry_state === 'expiring_soon', `5일 후 만료 시 expiry_state=expiring_soon (실제: ${soonJson.data?.expiry_state})`);

  const pastRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses/${licenseId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ expires_at: past.toISOString().slice(0, 10) })
  });
  const pastJson = await pastRes.json();
  assert(pastJson.data?.expiry_state === 'expired', `지난 만료일이면 expiry_state=expired (실제: ${pastJson.data?.expiry_state})`);
  assert(pastJson.data?.status === 'needs_more_info', `expiry_state 계산이 저장된 status 값 자체는 바꾸지 않음 (실제: ${pastJson.data?.status})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
