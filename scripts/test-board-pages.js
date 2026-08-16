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
  const createdPostIds = [];
  const createdUserIds = [];

  // ============================================
  // 0) 관리자/일반회원 계정 준비
  // ============================================
  const adminEmail = `test-board-admin-${ts}@withplus-test.local`;
  const { data: adminUser } = await admin.auth.admin.createUser({ email: adminEmail, password: 'TestPass123!', email_confirm: true });
  const adminId = adminUser.user.id;
  createdUserIds.push(adminId);
  await admin.from('profiles').upsert([{ id: adminId, email: adminEmail, full_name: 'BoardTestAdmin', role: 'admin' }]);
  const adminToken = await loginAs(adminEmail, 'TestPass123!');

  const memberEmail = `test-board-member-${ts}@withplus-test.local`;
  const { data: memberUser } = await admin.auth.admin.createUser({ email: memberEmail, password: 'TestPass123!', email_confirm: true });
  const memberId = memberUser.user.id;
  createdUserIds.push(memberId);
  await admin.from('profiles').upsert([{ id: memberId, email: memberEmail, full_name: 'BoardTestMember', role: 'member' }]);
  const memberToken = await loginAs(memberEmail, 'TestPass123!');

  const otherEmail = `test-board-other-${ts}@withplus-test.local`;
  const { data: otherUser } = await admin.auth.admin.createUser({ email: otherEmail, password: 'TestPass123!', email_confirm: true });
  const otherId = otherUser.user.id;
  createdUserIds.push(otherId);
  await admin.from('profiles').upsert([{ id: otherId, email: otherEmail, full_name: 'BoardTestOther', role: 'member' }]);
  const otherToken = await loginAs(otherEmail, 'TestPass123!');

  // ============================================
  // 1) 회원용 게시판 화면 라우트가 실제로 존재하고 200을 반환하는지
  //    (이 기능이 만들어지기 전에는 board.html/board-detail.html 파일 자체가 없어 500 오류가 나던 것을 고친 부분)
  // ============================================
  const noticeListRes = await fetch(`${API}/notice`);
  assert(noticeListRes.status === 200, 'GET /notice (공지사항 목록 화면)가 200 반환');
  const qaListRes = await fetch(`${API}/board/qa`);
  assert(qaListRes.status === 200, 'GET /board/qa (Q&A 목록 화면)가 200 반환');
  const reviewListRes = await fetch(`${API}/board/review`);
  assert(reviewListRes.status === 200, 'GET /board/review (이용후기 목록 화면)가 200 반환');
  const freeListRes = await fetch(`${API}/board/free`);
  assert(freeListRes.status === 200, 'GET /board/free (자유게시판 목록 화면)가 200 반환');
  const noticeListHtml = await noticeListRes.text();
  assert(noticeListHtml.includes('<!DOCTYPE html>') && noticeListHtml.includes('</html>'), '/notice 응답이 유효한 HTML 문서 구조를 갖춤');

  // ============================================
  // 2) 자유게시판 글쓰기 (일반 회원)
  // ============================================
  const noAuthPostRes = await fetch(`${API}/api/boards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ board_type: 'free', title: 'x', content: 'x' })
  });
  assert(noAuthPostRes.status === 401, '로그인 없이는 게시글 작성이 거부됨(401)');

  const freeTitle = `테스트 자유글 ${ts}`;
  const createFreeRes = await fetch(`${API}/api/boards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + memberToken },
    body: JSON.stringify({ board_type: 'free', title: freeTitle, content: '테스트 내용입니다.' })
  });
  const createFreeJson = await createFreeRes.json();
  assert(createFreeRes.status === 201 && createFreeJson.data && createFreeJson.data.id, '일반 회원이 자유게시판 글을 정상적으로 작성함');
  const freePostId = createFreeJson.data.id;
  createdPostIds.push(freePostId);

  // 목록 API에 방금 쓴 글이 실제로 노출되는지
  const listAfterCreateRes = await fetch(`${API}/api/boards?type=free&search=${encodeURIComponent(freeTitle)}`);
  const listAfterCreateJson = await listAfterCreateRes.json();
  assert(listAfterCreateJson.data.some(p => p.id === freePostId), '방금 작성한 글이 목록(검색) API에 정확히 노출됨');

  // 상세 화면 라우트가 200을 반환하는지 (board-detail.html)
  const detailPageRes = await fetch(`${API}/board/free/${freePostId}`);
  assert(detailPageRes.status === 200, `GET /board/free/${freePostId} (게시글 상세 화면)가 200 반환`);
  const detailHtml = await detailPageRes.text();
  assert(detailHtml.includes('<!DOCTYPE html>') && detailHtml.includes('</html>'), '게시글 상세 화면 응답이 유효한 HTML 문서 구조를 갖춤');

  // 상세 API로 내용이 정확히 조회되는지
  const detailApiRes = await fetch(`${API}/api/boards/${freePostId}`);
  const detailApiJson = await detailApiRes.json();
  assert(detailApiJson.data.title === freeTitle, '게시글 상세 API가 실제로 작성한 제목을 정확히 반환함');

  // ============================================
  // 3) 공지사항은 관리자만 작성 가능
  // ============================================
  const memberNoticeRes = await fetch(`${API}/api/boards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + memberToken },
    body: JSON.stringify({ board_type: 'notice', title: '일반회원공지시도', content: 'x' })
  });
  assert(memberNoticeRes.status === 403, '일반 회원은 공지사항을 작성할 수 없음(403)');

  const adminNoticeRes = await fetch(`${API}/api/boards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + adminToken },
    body: JSON.stringify({ board_type: 'notice', title: `테스트 공지 ${ts}`, content: '관리자 공지 테스트' })
  });
  const adminNoticeJson = await adminNoticeRes.json();
  assert(adminNoticeRes.status === 201, '관리자는 공지사항을 정상적으로 작성할 수 있음');
  const noticePostId = adminNoticeJson.data.id;
  createdPostIds.push(noticePostId);

  // ============================================
  // 4) Q&A 댓글(답변) — 관리자가 답하면 is_admin_reply=true + is_answered=true 로 전환
  // ============================================
  const createQaRes = await fetch(`${API}/api/boards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + memberToken },
    body: JSON.stringify({ board_type: 'qa', title: `테스트 문의 ${ts}`, content: '배송이 언제 오나요?' })
  });
  const createQaJson = await createQaRes.json();
  const qaPostId = createQaJson.data.id;
  createdPostIds.push(qaPostId);
  assert(createQaJson.data.is_answered === false, '새로 작성한 Q&A는 정직하게 답변대기(is_answered=false) 상태로 시작함');

  const noAuthCommentRes = await fetch(`${API}/api/boards/${qaPostId}/comments`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content: 'x' })
  });
  assert(noAuthCommentRes.status === 401, '로그인 없이는 댓글 작성이 거부됨(401)');

  const adminCommentRes = await fetch(`${API}/api/boards/${qaPostId}/comments`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + adminToken },
    body: JSON.stringify({ content: '내일 오전 중 발송될 예정입니다.' })
  });
  const adminCommentJson = await adminCommentRes.json();
  assert(adminCommentRes.status === 201 && adminCommentJson.data.is_admin_reply === true, '관리자가 남긴 댓글은 is_admin_reply=true로 정확히 표시됨');

  const qaAfterAnswerRes = await fetch(`${API}/api/boards/${qaPostId}`);
  const qaAfterAnswerJson = await qaAfterAnswerRes.json();
  assert(qaAfterAnswerJson.data.is_answered === true, '관리자 답변 후 Q&A 상태가 자동으로 답변완료(is_answered=true)로 전환됨');
  assert(qaAfterAnswerJson.data.comments.length === 1, '상세 API 응답에 댓글이 함께 포함되어 내려옴');
  const commentId = qaAfterAnswerJson.data.comments[0].id;

  // ============================================
  // 5) 권한 검증 — 본인/관리자만 수정·삭제 가능
  // ============================================
  const otherEditRes = await fetch(`${API}/api/boards/${freePostId}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + otherToken },
    body: JSON.stringify({ title: '무단수정시도' })
  });
  assert(otherEditRes.status === 403, '타인은 남의 게시글을 수정할 수 없음(403)');

  const otherDeletePostRes = await fetch(`${API}/api/boards/${freePostId}`, { method: 'DELETE', headers: { Authorization: 'Bearer ' + otherToken } });
  assert(otherDeletePostRes.status === 403, '타인은 남의 게시글을 삭제할 수 없음(403)');

  const otherDeleteCommentRes = await fetch(`${API}/api/boards/${qaPostId}/comments/${commentId}`, { method: 'DELETE', headers: { Authorization: 'Bearer ' + otherToken } });
  assert(otherDeleteCommentRes.status === 403, '타인은 남의 댓글을 삭제할 수 없음(403)');

  const ownerEditRes = await fetch(`${API}/api/boards/${freePostId}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + memberToken },
    body: JSON.stringify({ title: freeTitle + ' (수정됨)' })
  });
  assert(ownerEditRes.status === 200, '작성자 본인은 자신의 게시글을 수정할 수 있음');

  // ============================================
  // 6) 존재하지 않는 게시글
  // ============================================
  const notFoundRes = await fetch(`${API}/api/boards/00000000-0000-0000-0000-000000000000`);
  assert(notFoundRes.status === 404, '존재하지 않는 게시글 id는 404를 반환함');
  const notFoundPageRes = await fetch(`${API}/board/free/00000000-0000-0000-0000-000000000000`);
  assert(notFoundPageRes.status === 200, '존재하지 않는 글이어도 상세 화면 자체(board-detail.html)는 정상 응답하고, 화면 안에서 안내를 처리함');

  // ============================================
  // 정리 — 테스트로 만든 댓글/게시글/계정 전부 삭제
  // ============================================
  await admin.from('board_comments').delete().eq('post_id', qaPostId);
  for (const id of createdPostIds) {
    await admin.from('board_posts').delete().eq('id', id);
  }
  for (const id of createdUserIds) {
    await admin.auth.admin.deleteUser(id).catch(() => {});
  }

  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => { console.error('테스트 실행 중 오류:', err); process.exit(1); });
