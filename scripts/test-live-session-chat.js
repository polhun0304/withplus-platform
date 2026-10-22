// WITH+ 라이브(LIVE+에서 이식) 세션별 실시간 채팅 회귀 테스트.
// 핵심 규칙: (1) 보내기는 방송 중(live)일 때만, 읽기는 언제든 가능 (2) 도배 방지 레이트리밋
// (3) 공개 조회에서는 실명이 그대로 노출되지 않고 마스킹된다 (4) 관리자는 숨기기/다시보이기로 모더레이션 가능
// (5) 숨겨진 메시지는 공개 조회에서 빠진다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-session-chat.js
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
  const adminEmail = `test-lchat-admin-${ts}@withplus-test.local`;
  const buyerEmail = `test-lchat-buyer-${ts}@withplus-test.local`;

  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: bData } = await admin.auth.admin.createUser({ email: buyerEmail, password, email_confirm: true });
  await admin.from('profiles').upsert([
    { id: aData.user.id, email: adminEmail, role: 'admin', member_type: 'general', full_name: '관리자테스트' },
    { id: bData.user.id, email: buyerEmail, role: 'member', member_type: 'general', full_name: '홍길동' }
  ]);
  const adminToken = await loginAs(adminEmail, password);
  const buyerToken = await loginAs(buyerEmail, password);
  const slug = `test-lchat-channel-${ts}`;

  const createChannelRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: 'LCHAT 테스트 채널', channel_type: 'creator' })
  });
  const channel = (await createChannelRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'active' })
  });
  const sessionRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ title: 'LCHAT 테스트 방송' })
  });
  const session = (await sessionRes.json()).data;

  // 1) scheduled(방송 시작 전)에는 채팅 전송이 거부되어야 한다
  const beforeLiveRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ message: '아직 시작 전인데 보내봄' })
  });
  assert(beforeLiveRes.status === 409, `scheduled 세션에는 채팅 전송 불가 (실제: ${beforeLiveRes.status})`);

  // 2) live로 전환 후 전송 성공, 마스킹된 이름으로 돌아온다
  await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'live' })
  });
  await new Promise(r => setTimeout(r, 2100)); // 채팅 도배 방지 rate limit(사용자당 2초 1회, liveChatLimiter) 대기
  const sendRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ message: '안녕하세요! 첫 채팅입니다' })
  });
  const sendJson = await sendRes.json();
  assert(sendRes.status === 201 && sendJson.data.is_mine === true, `live 세션에서 채팅 전송 성공, is_mine=true (실제: ${sendRes.status}, ${sendJson.data?.is_mine})`);
  assert(sendJson.data.display_name === '홍*동', `보낸 사람 응답에도 실명이 아니라 마스킹된 이름으로 옴 (실제: ${sendJson.data.display_name})`);
  const firstMessageId = sendJson.data.id;

  // 3) 빈 메시지/너무 긴 메시지는 거부
  await new Promise(r => setTimeout(r, 2100)); // 채팅 도배 방지 rate limit(사용자당 2초 1회, liveChatLimiter) 대기
  const emptyRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ message: '   ' })
  });
  assert(emptyRes.status === 400, `빈 메시지는 400 (실제: ${emptyRes.status})`);
  await new Promise(r => setTimeout(r, 2100)); // 채팅 도배 방지 rate limit(사용자당 2초 1회, liveChatLimiter) 대기
  const tooLongRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ message: 'a'.repeat(201) })
  });
  assert(tooLongRes.status === 400, `200자 초과 메시지는 400 (실제: ${tooLongRes.status})`);

  // 4) 도배 방지 - 방금 보낸 사용자가 바로 다시 보내면 429
  const rapidRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ message: '연속으로 바로 또 보냄' })
  });
  assert(rapidRes.status === 429, `연속 전송은 429로 거부 (실제: ${rapidRes.status})`);

  // 5) 비로그인(익명) 조회 - 마스킹된 이름, is_mine 항상 false
  const anonReadRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat`);
  const anonReadJson = await anonReadRes.json();
  assert(anonReadRes.status === 200 && anonReadJson.data.length === 1, `비로그인도 채팅 목록 조회 가능 (실제: ${anonReadJson.data?.length})`);
  assert(anonReadJson.data[0].display_name === '홍*동' && anonReadJson.data[0].is_mine === false,
    `비로그인 조회는 마스킹된 이름 + is_mine=false (실제: ${JSON.stringify(anonReadJson.data[0])})`);

  // 6) 본인이 로그인해서 조회하면 자기 메시지는 is_mine=true로 표시된다 (optionalAuth 확인)
  const ownReadRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat`, {
    headers: { Authorization: `Bearer ${buyerToken}` }
  });
  const ownReadJson = await ownReadRes.json();
  assert(ownReadJson.data[0].is_mine === true, `로그인 상태로 다시 조회하면 자기 메시지가 is_mine=true (실제: ${ownReadJson.data[0]?.is_mine})`);

  // 7) 관리자 조회 - 실명 그대로 노출(모더레이션 목적), 숨김 여부 필드 포함
  const adminListRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/chat`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const adminListJson = await adminListRes.json();
  assert(adminListJson.data.length === 1 && adminListJson.data[0].sender_name === '홍길동' && adminListJson.data[0].is_hidden === false,
    `관리자 조회는 실명 그대로 + is_hidden=false (실제: ${JSON.stringify(adminListJson.data[0])})`);

  // 8) 일반회원은 관리자 채팅 조회 불가
  const forbiddenAdminRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/chat`, {
    headers: { Authorization: `Bearer ${buyerToken}` }
  });
  assert(forbiddenAdminRes.status === 403, `일반회원은 관리자 채팅 조회 불가 (실제: ${forbiddenAdminRes.status})`);

  // 9) 관리자가 메시지 숨기면 공개 조회에서 사라진다
  const hideRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/chat/${firstMessageId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ is_hidden: true })
  });
  const hideJson = await hideRes.json();
  assert(hideRes.status === 200 && hideJson.data.is_hidden === true && hideJson.data.hidden_by === aData.user.id,
    `관리자가 메시지 숨김 처리 성공 (실제: ${JSON.stringify({ ok: hideRes.status, hidden: hideJson.data?.is_hidden })})`);
  const afterHideReadRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat`);
  const afterHideReadJson = await afterHideReadRes.json();
  assert(afterHideReadJson.data.length === 0, `숨긴 메시지는 공개 조회에서 제외됨 (실제: ${afterHideReadJson.data?.length})`);

  // 10) 다시 보이기
  const unhideRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/chat/${firstMessageId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ is_hidden: false })
  });
  const unhideJson = await unhideRes.json();
  assert(unhideRes.status === 200 && unhideJson.data.is_hidden === false && unhideJson.data.hidden_by === null,
    `관리자가 다시 보이기 처리 성공 (실제: ${JSON.stringify(unhideJson.data)})`);

  // 11) 세션 종료(ended) 후에는 새 채팅 전송이 거부된다 (재고예약과 동일한 규칙)
  await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'ended' })
  });
  await new Promise(r => setTimeout(r, 2100)); // 채팅 도배 방지 rate limit(사용자당 2초 1회, liveChatLimiter) 대기
  const afterEndSendRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${buyerToken}` },
    body: JSON.stringify({ message: '방송 끝난 뒤 전송' })
  });
  assert(afterEndSendRes.status === 409, `ended 세션에는 새 채팅 전송 불가 (실제: ${afterEndSendRes.status})`);

  // 12) 그러나 지나간 채팅 로그는 방송 종료 후에도 계속 조회 가능해야 한다
  const afterEndReadRes = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat`);
  const afterEndReadJson = await afterEndReadRes.json();
  assert(afterEndReadRes.status === 200 && afterEndReadJson.data.length === 1, `방송 종료 후에도 지나간 채팅 로그는 조회 가능 (실제: ${afterEndReadJson.data?.length})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
