// WITH+ 라이브(LIVE+에서 이식) OmniCast(동시송출, 목적지 연결 관리형 MVP) 회귀 테스트.
// 유튜브/페이스북은 실제 Google/Meta 개발자 앱 인증정보 없이는 끝까지 검증할 수 없으므로(형님이 관리자
// 설정에 실제 클라이언트ID/시크릿을 등록해야만 동작), 이 테스트는 (1) 커스텀 RTMP는 외부 의존성이 없어
// 전체 생애주기를 완전히 검증하고 (2) 유튜브/페이스북/틱톡 등은 "연동 설정 필요" 시점까지 정직하게
// 거부되는지, 관리자 권한/시크릿 마스킹이 올바른지를 검증한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-omnicast.js
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
  // omnicast_platform_configs는 채널별이 아니라 전역 설정이라(모든 채널이 공유), 이 테스트가 유튜브
  // 설정을 건드리고 정리하지 않은 채 이전에 중단됐을 수 있다 - 매 실행마다 깨끗한 상태에서 시작하도록
  // 먼저 리셋해둔다(운영 데이터를 건드리는 게 아니라 테스트가 자기 자신의 이전 실행 흔적을 지우는 것).
  await admin.from('omnicast_platform_configs_with').update({ client_key: null, secret_key: null, redirect_uri: null, enabled: false }).eq('provider_key', 'youtube');

  const ts = Date.now();
  const password = 'TestPass123!';
  const adminEmail = `test-omnicast-admin-${ts}@withplus-test.local`;
  const memberEmail = `test-omnicast-member-${ts}@withplus-test.local`;

  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: mData } = await admin.auth.admin.createUser({ email: memberEmail, password, email_confirm: true });
  await admin.from('profiles').upsert([
    { id: aData.user.id, email: adminEmail, role: 'admin', member_type: 'general', full_name: '관리자테스트' },
    { id: mData.user.id, email: memberEmail, role: 'member', member_type: 'general', full_name: '일반회원테스트' }
  ]);
  const adminToken = await loginAs(adminEmail, password);
  const memberToken = await loginAs(memberEmail, password);
  const slug = `test-omnicast-channel-${ts}`;

  const createChannelRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: 'OmniCast 테스트 채널', channel_type: 'creator' })
  });
  const channel = (await createChannelRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'active' })
  });
  const sessionRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ title: 'OmniCast 테스트 방송' })
  });
  const session = (await sessionRes.json()).data;

  // ============================================
  // 1) 플랫폼 연동 설정 (관리자 전용, 시크릿 마스킹)
  // ============================================
  const platformsRes = await fetch(`${API}/api/admin/live/omnicast/platforms`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const platformsJson = await platformsRes.json();
  assert(platformsRes.status === 200 && platformsJson.data.length === 5, `플랫폼 설정 5개(유튜브/페이스북/틱톡/인스타/X) 조회 (실제: ${platformsJson.data?.length})`);
  const ytEntry = platformsJson.data.find(p => p.provider_key === 'youtube');
  assert(ytEntry && ytEntry.enabled === false && ytEntry.has_secret_key === false, `초기 상태의 유튜브 설정은 비활성+시크릿 없음 (실제: ${JSON.stringify(ytEntry)})`);

  const forbiddenPlatformsRes = await fetch(`${API}/api/admin/live/omnicast/platforms`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert(forbiddenPlatformsRes.status === 403, `일반회원은 플랫폼 설정 조회 불가 (실제: ${forbiddenPlatformsRes.status})`);

  const patchYtRes = await fetch(`${API}/api/admin/live/omnicast/platforms/youtube`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ client_key: 'fake-client-id', secret_key: 'fake-secret', redirect_uri: 'https://example.com/callback', enabled: true })
  });
  const patchYtJson = await patchYtRes.json();
  assert(patchYtRes.status === 200 && patchYtJson.data.client_key === 'fake-client-id' && patchYtJson.data.has_secret_key === true && patchYtJson.data.secret_key === undefined,
    `유튜브 설정 저장 성공, 시크릿 원문은 응답에 없음 (실제: ${JSON.stringify(patchYtJson.data)})`);

  const patchTiktokRes = await fetch(`${API}/api/admin/live/omnicast/platforms/tiktok`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ enabled: true })
  });
  assert(patchTiktokRes.status === 400, `틱톡은 아직 미지원이라 설정 저장 자체가 거부됨 (실제: ${patchTiktokRes.status})`);

  // 유튜브를 다시 비활성화해서 이후 connect 테스트가 "설정 필요" 경로를 타도록 정리
  await fetch(`${API}/api/admin/live/omnicast/platforms/youtube`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ enabled: false })
  });

  // ============================================
  // 2) 유튜브/페이스북/틱톡 연결 시도 - 설정 전이므로 정직하게 막힘
  // ============================================
  const ytConnectRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/omnicast/youtube/connect`, { headers: { Authorization: `Bearer ${adminToken}` } });
  assert(ytConnectRes.status === 400, `유튜브 연동 미설정 상태에서 연결 시도 시 400 (실제: ${ytConnectRes.status})`);
  const tiktokConnectRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/omnicast/tiktok/connect`, { headers: { Authorization: `Bearer ${adminToken}` } });
  assert(tiktokConnectRes.status === 400, `틱톡은 애초에 미지원이라 연결 시도 자체가 400 (실제: ${tiktokConnectRes.status})`);

  // ============================================
  // 3) 커스텀 RTMP 목적지 - 외부 의존성 없이 전체 생애주기 검증
  // ============================================
  const addDestRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/omnicast/destinations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ label: '트위치 테스트', rtmp_url: 'rtmp://live.twitch.tv/app', stream_key: 'live_secret_key_12345' })
  });
  const addDestJson = await addDestRes.json();
  assert(addDestRes.status === 201 && addDestJson.data.platform === 'custom_rtmp' && addDestJson.data.rtmp_url === 'rtmp://live.twitch.tv/app',
    `커스텀 RTMP 목적지 추가 성공 (실제: ${JSON.stringify(addDestJson.data)})`);
  assert(addDestJson.data.stream_key === undefined, `목적지 추가 응답에도 stream_key 원문이 포함되지 않음`);
  const destId = addDestJson.data.id;

  const missingFieldRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/omnicast/destinations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ label: '', rtmp_url: '', stream_key: '' })
  });
  assert(missingFieldRes.status === 400, `필수 필드 누락 시 400 (실제: ${missingFieldRes.status})`);

  const listDestRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/omnicast/destinations`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const listDestJson = await listDestRes.json();
  assert(listDestJson.data.length === 1 && listDestJson.data[0].stream_key === undefined,
    `목적지 목록 조회 시에도 stream_key 원문이 내려오지 않음 (실제: ${JSON.stringify(listDestJson.data[0])})`);

  const revealRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/omnicast/destinations/${destId}/reveal`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const revealJson = await revealRes.json();
  assert(revealRes.status === 200 && revealJson.data.stream_key === 'live_secret_key_12345',
    `별도 reveal 엔드포인트로는 실제 스트림 키를 확인 가능 (실제: ${revealJson.data?.stream_key})`);

  const forbiddenRevealRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/omnicast/destinations/${destId}/reveal`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert(forbiddenRevealRes.status === 403, `일반회원은 reveal 엔드포인트 접근 불가 (실제: ${forbiddenRevealRes.status})`);

  // ============================================
  // 4) 세션에 송출 대상으로 추가 - custom_rtmp는 즉시 status:created + ingest 정보가 목적지 값 그대로 복사됨
  // ============================================
  const addTargetRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/omnicast/targets`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ destination_id: destId })
  });
  const addTargetJson = await addTargetRes.json();
  assert(addTargetRes.status === 201 && addTargetJson.data.status === 'created' && addTargetJson.data.ingest_rtmp_url === 'rtmp://live.twitch.tv/app' && addTargetJson.data.ingest_stream_key === 'live_secret_key_12345',
    `커스텀 RTMP 목적지를 세션에 추가하면 즉시 준비완료 + ingest 정보 복사 (실제: ${JSON.stringify(addTargetJson.data)})`);
  const targetId = addTargetJson.data.id;

  const dupTargetRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/omnicast/targets`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ destination_id: destId })
  });
  assert(dupTargetRes.status === 409, `같은 목적지를 같은 세션에 중복 추가 시 409 (실제: ${dupTargetRes.status})`);

  const listTargetsRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/omnicast/targets`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const listTargetsJson = await listTargetsRes.json();
  assert(listTargetsJson.data.length === 1 && listTargetsJson.data[0].live_channel_broadcast_destinations_live?.label === '트위치 테스트',
    `세션 송출 목록에 목적지 이름까지 조인되어 표시됨 (실제: ${JSON.stringify(listTargetsJson.data[0]?.live_channel_broadcast_destinations_live)})`);

  const forbiddenAddTargetRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/omnicast/targets`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
    body: JSON.stringify({ destination_id: destId })
  });
  assert(forbiddenAddTargetRes.status === 403, `일반회원은 송출 대상 추가 불가 (실제: ${forbiddenAddTargetRes.status})`);

  // ============================================
  // 5) 종료 - custom_rtmp는 원격 API 호출이 없으므로 그냥 로컬 상태만 ended로 바뀐다
  // ============================================
  const endTargetRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/omnicast/targets/${targetId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'ended' })
  });
  const endTargetJson = await endTargetRes.json();
  assert(endTargetRes.status === 200 && endTargetJson.data.status === 'ended' && !!endTargetJson.data.ended_at,
    `송출 종료 처리 성공 (실제: ${endTargetJson.data?.status}, ${endTargetJson.data?.ended_at})`);

  const removeTargetRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/omnicast/targets/${targetId}`, {
    method: 'DELETE', headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert(removeTargetRes.status === 200, `종료된 송출 대상은 삭제 가능 (실제: ${removeTargetRes.status})`);

  // ============================================
  // 6) 목적지 삭제
  // ============================================
  const deleteDestRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/omnicast/destinations/${destId}`, {
    method: 'DELETE', headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert(deleteDestRes.status === 200, `목적지 삭제 성공 (실제: ${deleteDestRes.status})`);
  const listAfterDeleteRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/omnicast/destinations`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const listAfterDeleteJson = await listAfterDeleteRes.json();
  assert(listAfterDeleteJson.data.length === 0, `삭제 후 목적지 목록이 비어있음 (실제: ${listAfterDeleteJson.data?.length})`);

  // ============================================
  // 7) 유튜브 access_token 만료 시 자동 갱신 경로가 예외 없이 정상적으로 "실패 처리"까지 이어지는지
  //    (진짜 구글 인증정보가 없어 실제 갱신 성공까지는 검증 불가 - refresh_token이 있어도/없어도
  //     서버가 죽지 않고 항상 status:'error' 행을 만들어내는지가 핵심)
  // ============================================
  const yt2ChannelRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug: `test-omnicast-yt-${ts}`, name: 'OmniCast 유튜브 만료 테스트 채널', channel_type: 'creator' })
  });
  const yt2Channel = (await yt2ChannelRes.json()).data;
  const yt2SessionRes = await fetch(`${API}/api/admin/live/channels/${yt2Channel.id}/sessions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ title: '유튜브 만료 테스트 방송' })
  });
  const yt2Session = (await yt2SessionRes.json()).data;

  // refresh_token 없이 만료된 access_token만 있는 목적지 - 갱신을 시도조차 못하고 원래 값으로 바로
  // 시도하다 구글 서버에서 401을 받아 status:'error'로 정직하게 남아야 한다(서버가 죽으면 안 됨)
  const { data: expiredDest } = await admin.from('live_channel_broadcast_destinations_with').insert({
    channel_id: yt2Channel.id, platform: 'youtube', label: '만료된 유튜브 연결',
    external_account_id: 'fake-channel-id', access_token: 'expired-fake-token', refresh_token: null,
    token_expires_at: new Date(Date.now() - 3600 * 1000).toISOString(), status: 'connected'
  }).select().single();

  const expiredTargetRes = await fetch(`${API}/api/admin/live/channels/${yt2Channel.id}/sessions/${yt2Session.id}/omnicast/targets`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ destination_id: expiredDest.id })
  });
  const expiredTargetJson = await expiredTargetRes.json();
  assert(expiredTargetRes.status === 502 && expiredTargetJson.data?.status === 'error',
    `refresh_token 없이 만료된 유튜브 토큰 → 서버가 죽지 않고 status:'error'로 정직하게 기록 (실제: ${expiredTargetRes.status}, ${expiredTargetJson.data?.status})`);
  assert(typeof expiredTargetJson.data?.error_message === 'string' && expiredTargetJson.data.error_message.includes('유튜브'),
    `오류 메시지에 유튜브 관련 실패 사유가 담김 (실제: ${expiredTargetJson.data?.error_message})`);

  // ============================================
  // 8) 페이스북 계정이 여러 페이지를 관리 중일 때 임의로 첫 페이지를 골라버리지 않고 관리자가 직접
  //    고르게 하는 흐름 - 실제 페이스북 OAuth 없이도 pending 테이블/선택 API 계약만으로 검증 가능
  // ============================================
  const { data: pending } = await admin.from('omnicast_pending_facebook_selections_with').insert({
    channel_id: channel.id, admin_user_id: aData.user.id,
    pages: [
      { id: 'fake-page-1', name: '가짜 페이지 A', access_token: 'fake-page-token-a' },
      { id: 'fake-page-2', name: '가짜 페이지 B', access_token: 'fake-page-token-b' }
    ]
  }).select().single();

  const listPendingRes = await fetch(`${API}/api/admin/live/omnicast/facebook/pending/${pending.id}`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const listPendingJson = await listPendingRes.json();
  assert(listPendingRes.status === 200 && listPendingJson.data.pages.length === 2 && listPendingJson.data.pages[0].access_token === undefined,
    `대기 중인 페이스북 페이지 목록 조회 - access_token은 내려주지 않음 (실제: ${JSON.stringify(listPendingJson.data)})`);

  const forbiddenListPendingRes = await fetch(`${API}/api/admin/live/omnicast/facebook/pending/${pending.id}`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert(forbiddenListPendingRes.status === 403, `일반회원은 대기 목록도 조회 불가 (실제: ${forbiddenListPendingRes.status})`);

  const wrongPageRes = await fetch(`${API}/api/admin/live/omnicast/facebook/pending/${pending.id}/choose`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ page_id: 'not-in-the-list' })
  });
  assert(wrongPageRes.status === 400, `목록에 없는 page_id 선택 시 400 (실제: ${wrongPageRes.status})`);

  const chooseRes = await fetch(`${API}/api/admin/live/omnicast/facebook/pending/${pending.id}/choose`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ page_id: 'fake-page-2' })
  });
  const chooseJson = await chooseRes.json();
  assert(chooseRes.status === 201 && chooseJson.data.platform === 'facebook' && chooseJson.data.label === '가짜 페이지 B' && chooseJson.data.external_account_id === 'fake-page-2',
    `선택한 페이지(B)로 목적지가 정확히 생성됨 (실제: ${JSON.stringify(chooseJson.data)})`);

  const { data: afterChooseCheck } = await admin.from('omnicast_pending_facebook_selections_with').select('id').eq('id', pending.id).maybeSingle();
  assert(!afterChooseCheck, `선택 확정 후 대기 레코드는 삭제됨 (실제: ${JSON.stringify(afterChooseCheck)})`);

  const reuseAfterDeleteRes = await fetch(`${API}/api/admin/live/omnicast/facebook/pending/${pending.id}/choose`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ page_id: 'fake-page-1' })
  });
  assert(reuseAfterDeleteRes.status === 404, `이미 선택을 마친 요청은 재사용 불가(404) (실제: ${reuseAfterDeleteRes.status})`);

  const { data: expiredPending } = await admin.from('omnicast_pending_facebook_selections_with').insert({
    channel_id: channel.id, admin_user_id: aData.user.id,
    pages: [{ id: 'fake-page-3', name: '만료 테스트 페이지', access_token: 'x' }],
    expires_at: new Date(Date.now() - 60 * 1000).toISOString()
  }).select().single();
  const expiredListRes = await fetch(`${API}/api/admin/live/omnicast/facebook/pending/${expiredPending.id}`, { headers: { Authorization: `Bearer ${adminToken}` } });
  assert(expiredListRes.status === 404, `15분이 지나 만료된 선택 요청은 조회 시점에 걸러짐 (실제: ${expiredListRes.status})`);

  // 전역 설정을 건드렸으니 다음 실행(및 실제 운영 화면)을 위해 깨끗하게 되돌려둔다
  await admin.from('omnicast_platform_configs_with').update({ client_key: null, secret_key: null, redirect_uri: null, enabled: false }).eq('provider_key', 'youtube');

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
