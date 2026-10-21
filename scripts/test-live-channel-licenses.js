// WITH+ 라이브(LIVE+에서 이식) 채널 자격/등록정보(라이선스) 관리 회귀 테스트.
// "법적 검토는 이미 끝났다고 가정, 관리자페이지에 자격정보 입력만" 요구사항에 따라
// 이 테이블/엔드포인트는 어떤 자동 규제 판단도 하지 않는다 - 단순 CRUD와 유효성 검증(license_type, 관리자 전용)만 확인한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-channel-licenses.js
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
  const adminEmail = `test-lcl-admin-${ts}@withplus-test.local`;
  const memberEmail = `test-lcl-member-${ts}@withplus-test.local`;

  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: mData } = await admin.auth.admin.createUser({ email: memberEmail, password, email_confirm: true });
  const adminId = aData.user.id;
  const memberId = mData.user.id;
  await admin.from('profiles').upsert([
    { id: adminId, email: adminEmail, role: 'admin', member_type: 'general' },
    { id: memberId, email: memberEmail, role: 'member', member_type: 'general' }
  ]);

  const adminToken = await loginAs(adminEmail, password);
  const memberToken = await loginAs(memberEmail, password);
  const slug = `test-lcl-channel-${ts}`;

  // 자격정보를 붙일 채널 하나 준비
  const createRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: 'LCL 테스트 채널(상조)', channel_type: 'supplier' })
  });
  const channel = (await createRes.json()).data;

  // 1) 일반 회원은 자격정보를 조회/추가할 수 없다
  const forbiddenGetRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses`, {
    headers: { Authorization: `Bearer ${memberToken}` }
  });
  assert(forbiddenGetRes.status === 403, `일반회원은 자격정보 조회 불가 (실제: ${forbiddenGetRes.status})`);

  // 2) 처음에는 자격정보가 없다
  const emptyRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const emptyJson = await emptyRes.json();
  assert(emptyRes.status === 200 && emptyJson.data.length === 0, `초기 자격정보 목록 비어있음 (실제: ${emptyJson.data?.length})`);

  // 3) 유효하지 않은 license_type은 거부
  const badTypeRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ license_type: 'nonexistent_type' })
  });
  assert(badTypeRes.status === 400, `유효하지 않은 자격유형은 400 (실제: ${badTypeRes.status})`);

  // 4) 상조(선불식 할부거래) 등록정보 추가
  const createLicenseRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({
      license_type: 'prepaid_funeral_registration',
      license_number: `제2026-테스트-${ts}호`,
      license_holder_name: '(주)LCL테스트상조',
      issuing_authority: '서울특별시 강남구청',
      issued_at: '2026-01-15',
      document_ref: `DOC-REF-${ts}`,
      notes: '테스트 등록'
    })
  });
  const createLicenseJson = await createLicenseRes.json();
  // 입력됨(submitted)과 검증완료(verified)는 서로 다른 상태여야 한다 - 생성 직후 자동으로 검증되지 않는다.
  // (이 구분에 대한 상세 회귀 테스트는 test-live-channel-license-status.js 참고)
  assert(createLicenseRes.status === 201 && createLicenseJson.data?.status === 'submitted',
    `자격정보 생성 성공, status=submitted(입력됨)로 시작 (실제: ${createLicenseRes.status}, status=${createLicenseJson.data?.status}`);
  assert(createLicenseJson.data?.verified_by === null, `생성 직후에는 verified_by가 비어있음(자동 검증 아님) (실제: ${createLicenseJson.data?.verified_by})`);
  const licenseId = createLicenseJson.data.id;

  // 5) 목록 조회에 반영됨
  const listRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const listJson = await listRes.json();
  assert(listJson.data.length === 1 && listJson.data[0].id === licenseId, '목록 조회에 새 자격정보 반영됨');

  // 6) 수정 - 만료일 추가, 상태를 보완요청으로 변경
  const patchRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses/${licenseId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ expires_at: '2027-01-14', status: 'needs_more_info' })
  });
  const patchJson = await patchRes.json();
  assert(patchRes.status === 200 && patchJson.data?.status === 'needs_more_info' && patchJson.data?.expires_at === '2027-01-14',
    `자격정보 수정 성공 (실제: status=${patchJson.data?.status}, expires_at=${patchJson.data?.expires_at})`);

  // 7) 유효하지 않은 status는 거부
  const badStatusRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses/${licenseId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'nonexistent_status' })
  });
  assert(badStatusRes.status === 400, `유효하지 않은 상태값은 400 (실제: ${badStatusRes.status})`);

  // 8) 다른 채널의 자격정보 ID로는 접근 불가(channel_id 스코프 확인)
  const otherCreateRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug: `test-lcl-other-${ts}`, name: '다른 채널', channel_type: 'creator' })
  });
  const otherChannel = (await otherCreateRes.json()).data;
  const crossScopeRes = await fetch(`${API}/api/admin/live/channels/${otherChannel.id}/licenses/${licenseId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ notes: '다른 채널에서 수정 시도' })
  });
  assert(crossScopeRes.status === 500 || crossScopeRes.status === 404,
    `다른 채널 소속 자격정보는 수정되지 않음 (실제: ${crossScopeRes.status})`);
  const { data: unchanged } = await admin.from('channel_licenses_with').select('notes').eq('id', licenseId).single();
  assert(unchanged.notes === '테스트 등록', `실제로 notes가 변경되지 않았음 확인 (실제: ${unchanged.notes})`);

  // 9) 삭제
  const deleteRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses/${licenseId}`, {
    method: 'DELETE', headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert(deleteRes.status === 200, `자격정보 삭제 성공 (실제: ${deleteRes.status})`);
  const afterDeleteRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/licenses`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const afterDeleteJson = await afterDeleteRes.json();
  assert(afterDeleteJson.data.length === 0, `삭제 후 목록 비어있음 (실제: ${afterDeleteJson.data?.length})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
