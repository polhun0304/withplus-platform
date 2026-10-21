// WITH+ 라이브(LIVE+에서 이식) 세션별 채팅 로그 페이지네이션 회귀 테스트.
// 공개 GET(before로 "이전 메시지 더 보기")과 관리자 GET(before로 "이전 채팅 더 보기") 둘 다 확인.
// has_more는 "요청한 개수만큼 꽉 찼다"는 근사치이므로, 정확히 경계에 걸치는 케이스(정확히 limit개만 더
// 남은 경우 등)까지는 검증하지 않고 "충분히 여러 페이지를 넘겨서 결국 false가 되고, 전체 개수가 맞는지"로 확인한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-session-chat-pagination.js
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
  const adminEmail = `test-lchatp-admin-${ts}@withplus-test.local`;
  const buyerEmail = `test-lchatp-buyer-${ts}@withplus-test.local`;

  const { data: aData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: bData } = await admin.auth.admin.createUser({ email: buyerEmail, password, email_confirm: true });
  await admin.from('profiles').upsert([
    { id: aData.user.id, email: adminEmail, role: 'admin', member_type: 'general', full_name: '관리자테스트' },
    { id: bData.user.id, email: buyerEmail, role: 'member', member_type: 'general', full_name: '김테스트' }
  ]);
  const adminToken = await loginAs(adminEmail, password);
  const buyerToken = await loginAs(buyerEmail, password);
  const slug = `test-lchatp-channel-${ts}`;

  const createChannelRes = await fetch(`${API}/api/admin/live/channels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ slug, name: 'LCHATP 테스트 채널', channel_type: 'creator' })
  });
  const channel = (await createChannelRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'active' })
  });
  const sessionRes = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ title: 'LCHATP 테스트 방송' })
  });
  const session = (await sessionRes.json()).data;
  await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'live' })
  });

  // 레이트리밋(2초)에 걸리지 않도록 매번 다른 사용자를 새로 만들어 12개의 메시지를 순서대로 심는다.
  // (직접 DB에 insert하면 실제 API 계약을 검증하는 게 아니게 되므로, 실제로 여러 사용자가 보낸 것처럼 구성)
  const totalMessages = 12;
  const senderTokens = [];
  for (let i = 0; i < totalMessages; i++) {
    const email = `test-lchatp-sender${i}-${ts}@withplus-test.local`;
    const { data: uData } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
    await admin.from('profiles').upsert([{ id: uData.user.id, email, role: 'member', member_type: 'general', full_name: `발신자${i}` }]);
    senderTokens.push(await loginAs(email, password));
  }
  for (let i = 0; i < totalMessages; i++) {
    const res = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${senderTokens[i]}` },
      body: JSON.stringify({ message: `메시지 ${i + 1}번` })
    });
    if (res.status !== 201) throw new Error(`메시지 ${i} 삽입 실패: ${res.status}`);
  }

  // 1) 공개 조회 - limit=5로 최초 로드하면 has_more=true, 가장 최근 5개(8~12번)를 시간순으로 반환
  const page1Res = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat?limit=5`);
  const page1Json = await page1Res.json();
  assert(page1Json.data.length === 5 && page1Json.has_more === true, `공개 최초 로드 limit=5 → 5건 + has_more=true (실제: ${page1Json.data?.length}, ${page1Json.has_more})`);
  assert(page1Json.data[0].message === '메시지 8번' && page1Json.data[4].message === '메시지 12번',
    `최초 로드는 가장 최근 5개를 시간순으로 반환 (실제: ${page1Json.data[0]?.message} ~ ${page1Json.data[4]?.message})`);

  // 2) "이전 메시지 더 보기" - before=가장 오래된 메시지(8번)의 created_at → 3~7번 반환, has_more=true(1~2번 남음)
  const oldest1 = page1Json.data[0].created_at;
  const page2Res = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat?limit=5&before=${encodeURIComponent(oldest1)}`);
  const page2Json = await page2Res.json();
  assert(page2Json.data.length === 5 && page2Json.has_more === true, `이전 페이지(5건) + has_more=true (실제: ${page2Json.data?.length}, ${page2Json.has_more})`);
  assert(page2Json.data[0].message === '메시지 3번' && page2Json.data[4].message === '메시지 7번',
    `이전 페이지는 3~7번 (실제: ${page2Json.data[0]?.message} ~ ${page2Json.data[4]?.message})`);

  // 3) 마지막 페이지 - before=3번의 created_at → 1~2번만(2건), has_more=false(정확히 limit 미만이라 확실히 false)
  const oldest2 = page2Json.data[0].created_at;
  const page3Res = await fetch(`${API}/api/live/channels/${slug}/sessions/${session.id}/chat?limit=5&before=${encodeURIComponent(oldest2)}`);
  const page3Json = await page3Res.json();
  assert(page3Json.data.length === 2 && page3Json.has_more === false, `마지막 페이지 2건 + has_more=false (실제: ${page3Json.data?.length}, ${page3Json.has_more})`);
  assert(page3Json.data[0].message === '메시지 1번' && page3Json.data[1].message === '메시지 2번',
    `마지막 페이지는 1~2번 (실제: ${page3Json.data[0]?.message}, ${page3Json.data[1]?.message})`);

  // 4) 세 페이지를 합치면 12개 전부, 중복 없이 시간순으로 이어진다
  const merged = [...page3Json.data, ...page2Json.data, ...page1Json.data].map(m => m.message);
  const expected = Array.from({ length: 12 }, (_, i) => `메시지 ${i + 1}번`);
  assert(JSON.stringify(merged) === JSON.stringify(expected), `세 페이지를 합치면 1~12번이 정확히 시간순으로 이어짐 (실제: ${JSON.stringify(merged)})`);

  // 5) 관리자 조회도 동일한 before/has_more 페이지네이션을 지원한다
  const adminPage1Res = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/chat?limit=5`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const adminPage1Json = await adminPage1Res.json();
  assert(adminPage1Json.data.length === 5 && adminPage1Json.has_more === true && adminPage1Json.data[0].message === '메시지 12번',
    `관리자 최초 로드(최신순) 5건 + has_more=true, 첫 항목은 최신(12번) (실제: ${adminPage1Json.data?.length}, ${adminPage1Json.has_more}, ${adminPage1Json.data[0]?.message})`);

  const adminOldest = adminPage1Json.data[adminPage1Json.data.length - 1].created_at; // 최신순이므로 마지막 항목이 이 페이지의 가장 오래된 것
  const adminPage2Res = await fetch(`${API}/api/admin/live/channels/${channel.id}/sessions/${session.id}/chat?limit=100&before=${encodeURIComponent(adminOldest)}`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const adminPage2Json = await adminPage2Res.json();
  assert(adminPage2Json.data.length === 7 && adminPage2Json.has_more === false,
    `관리자 다음 페이지(limit=100)는 남은 7건 전부 + has_more=false (실제: ${adminPage2Json.data?.length}, ${adminPage2Json.has_more})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리(WITH+ 전용 *_with 라이브 테이블 · 테스트 회원/상품/주문/쿠폰) - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
