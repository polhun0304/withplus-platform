// WITH+ 라이브(LIVE+에서 이식) 공식 채널(FAN+/CREATOR+/BRAND+ 공용) 구조 회귀 테스트.
// "구조부터 먼저 만들기" 방향에 따라, 실제 스타 계약 없이도 가상 채널로 전체 흐름(채널 생성 → 등급 →
// 가입 → 팬 활동 점수 적립 → 공식 인증은 계약 참조 없이는 불가능함)이 정상 동작하는지 검증한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-channels.js
const API = process.env.API || process.env.TEST_API || 'http://localhost:3140';

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
  const adminEmail = `test-live-admin-${ts}@withplus-test.local`;
  const fanEmail = `test-live-fan-${ts}@withplus-test.local`;

  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: fData } = await admin.auth.admin.createUser({ email: fanEmail, password, email_confirm: true });
  const adminId = aData.user.id;
  const fanId = fData.user.id;
  await admin.from('profiles').upsert([
    { id: adminId, email: adminEmail, role: 'admin', member_type: 'general' },
    { id: fanId, email: fanEmail, role: 'member', member_type: 'general' }
  ]);

  const adminToken = await loginAs(adminEmail, password);
  const fanToken = await loginAs(fanEmail, password);
  const slug = `test-creator-${ts}`;

  // 1) 일반 회원은 채널을 만들 수 없다
  const forbiddenRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${fanToken}` },
    body: JSON.stringify({ slug, name: '테스트 크리에이터', channel_type: 'creator' })
  });
  assert(forbiddenRes.status === 403, `일반회원은 채널 생성 불가 (실제: ${forbiddenRes.status})`);

  // 2) 관리자는 채널을 만들 수 있고, 새 채널은 항상 draft + unofficial/unverified로 시작한다
  const createRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: '테스트 크리에이터', channel_type: 'creator', tagline: '가상 파일럿 채널' })
  });
  const createJson = await createRes.json();
  assert(createRes.status === 201, `채널 생성 성공 (실제: ${createRes.status})`);
  assert(createJson.data?.status === 'draft' && createJson.data?.is_official === false && createJson.data?.verification_status === 'unverified',
    `새 채널은 draft/unofficial/unverified로 시작 (실제: status=${createJson.data?.status}, is_official=${createJson.data?.is_official}, verification_status=${createJson.data?.verification_status})`);
  const channelId = createJson.data.id;

  // 3) 계약 참조번호 없이는 공식/검증 상태로 못 바꾼다
  const badVerifyRes = await fetch(`${API}/api/admin/live/channels/${channelId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ verification_status: 'verified' })
  });
  assert(badVerifyRes.status === 400, `계약참조 없이 verified 전환 시도 시 400 (실제: ${badVerifyRes.status})`);

  // 4) 채널을 active로 전환 + 계약참조와 함께 verified로 전환
  await fetch(`${API}/api/admin/live/channels/${channelId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'active' })
  });
  const goodVerifyRes = await fetch(`${API}/api/admin/live/channels/${channelId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ verification_status: 'verified', is_official: true, rights_contract_ref: 'PILOT-CONTRACT-001' })
  });
  const goodVerifyJson = await goodVerifyRes.json();
  assert(goodVerifyRes.status === 200 && goodVerifyJson.data?.is_official === true, `계약참조와 함께 공식/검증 전환 성공 (실제: ${goodVerifyRes.status}, is_official=${goodVerifyJson.data?.is_official})`);

  // 5) 멤버십 등급 생성
  const tierRes = await fetch(`${API}/api/admin/live/channels/${channelId}/tiers`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ tier_key: 'fan_plus', tier_name: 'FAN+', tier_order: 2, is_paid: true, price_monthly: 4900 })
  });
  const tierJson = await tierRes.json();
  assert(tierRes.status === 201, `멤버십 등급 생성 성공 (실제: ${tierRes.status})`);
  const tierId = tierJson.data.id;

  // 6) 공개 목록/상세 조회 - active 채널만 노출, 등급 포함
  const listRes = await fetch(`${API}/api/live/channels?channel_type=creator`);
  const listJson = await listRes.json();
  assert(listJson.data?.some(c => c.slug === slug), '공개 채널 목록에 새 채널이 노출됨');

  const detailRes = await fetch(`${API}/api/live/channels/${slug}`);
  const detailJson = await detailRes.json();
  assert(detailJson.data?.tiers?.length === 1 && detailJson.data?.member_count === 0, `채널 상세에 등급 포함, 가입 전 멤버 수 0 (실제: tiers=${detailJson.data?.tiers?.length}, member_count=${detailJson.data?.member_count})`);

  // 7) 가입 전에는 팬 활동을 기록해도 점수가 쌓이지 않는다(가입은 명시적 행동이어야 함)
  const preJoinActivityRes = await fetch(`${API}/api/live/channels/${slug}/fan-activity`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${fanToken}` },
    body: JSON.stringify({ action_type: 'live_view' })
  });
  const preJoinActivityJson = await preJoinActivityRes.json();
  assert(preJoinActivityJson.data?.awarded === false && preJoinActivityJson.data?.reason === 'not_a_member', `가입 전 활동은 점수 미적립 (실제: ${JSON.stringify(preJoinActivityJson.data)})`);

  // 8) 유료 등급으로는 결제 기능 없이 가입할 수 없다(보안 수정 c85f581 - 무료 가입 경로로 우회 차단) → 무료(기본) 가입
  const paidJoinRes = await fetch(`${API}/api/live/channels/${slug}/join`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${fanToken}` },
    body: JSON.stringify({ tier_id: tierId })
  });
  assert(paidJoinRes.status === 403, `유료 등급 가입은 결제 준비 전까지 403 (실제: ${paidJoinRes.status})`);
  const joinRes = await fetch(`${API}/api/live/channels/${slug}/join`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${fanToken}` },
    body: JSON.stringify({})
  });
  const joinJson = await joinRes.json();
  assert(joinRes.status === 200 && joinJson.data?.joined === true, `팬 가입 성공 (실제: ${joinRes.status})`);

  const detailAfterJoinRes = await fetch(`${API}/api/live/channels/${slug}`);
  const detailAfterJoinJson = await detailAfterJoinRes.json();
  assert(detailAfterJoinJson.data?.member_count === 1, `가입 후 멤버 수 1로 반영 (실제: ${detailAfterJoinJson.data?.member_count})`);

  // 9) 가입 후에는 팬 활동이 점수로 쌓인다(라이브시청 5점 + 공유 3점 = 8점)
  await fetch(`${API}/api/live/channels/${slug}/fan-activity`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${fanToken}` },
    body: JSON.stringify({ action_type: 'live_view' })
  });
  const shareRes = await fetch(`${API}/api/live/channels/${slug}/fan-activity`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${fanToken}` },
    body: JSON.stringify({ action_type: 'share' })
  });
  const shareJson = await shareRes.json();
  assert(shareJson.data?.awarded === true && shareJson.data?.points === 3, `공유 활동 3점 적립 (실제: ${JSON.stringify(shareJson.data)})`);

  const myChannelsRes = await fetch(`${API}/api/me/live/channels`, { headers: { Authorization: `Bearer ${fanToken}` } });
  const myChannelsJson = await myChannelsRes.json();
  const myMembership = myChannelsJson.data?.find(m => m.channels_live?.slug === slug);
  assert(myMembership?.fan_activity_score === 8, `누적 팬 활동점수 8점 반영 (실제: ${myMembership?.fan_activity_score})`);

  // 10) 알 수 없는 활동 유형은 거부
  const badActivityRes = await fetch(`${API}/api/live/channels/${slug}/fan-activity`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${fanToken}` },
    body: JSON.stringify({ action_type: 'nonexistent_action' })
  });
  assert(badActivityRes.status === 400, `알 수 없는 활동 유형은 400 (실제: ${badActivityRes.status})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
