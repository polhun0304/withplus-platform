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
  const adminEmail = `test-catmgmt-admin-${ts}@withplus-test.local`;
  const memberEmail = `test-catmgmt-member-${ts}@withplus-test.local`;

  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: memberData } = await admin.auth.admin.createUser({ email: memberEmail, password, email_confirm: true });
  const adminId = adminData.user.id;
  const memberId = memberData.user.id;
  await admin.from('profiles').upsert([
    { id: adminId, email: adminEmail, full_name: 'CatMgmtTestAdmin', role: 'admin' },
    { id: memberId, email: memberEmail, full_name: 'CatMgmtTestMember', role: 'member' }
  ]);
  const adminToken = await loginAs(adminEmail, password);
  const memberToken = await loginAs(memberEmail, password);
  assert(!!adminToken && !!memberToken, '테스트 관리자/일반회원 로그인 성공');

  // ============================================
  // 순서 드래그 저장 (reorder)
  // ============================================
  const beforeRes = await fetch(`${API}/api/admin/categories`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const beforeJson = await beforeRes.json();
  const originalOrderIds = beforeJson.data.map(c => c.id); // display_order 오름차순으로 이미 정렬되어 있음
  assert(originalOrderIds.length >= 2, `기존 카테고리가 2개 이상 존재함 (실제: ${originalOrderIds.length})`);

  const noAuthReorderRes = await fetch(`${API}/api/admin/categories/reorder`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: originalOrderIds })
  });
  assert(noAuthReorderRes.status === 401, `인증 없이 순서 변경 시도 시 401 (실제: ${noAuthReorderRes.status})`);

  const memberReorderRes = await fetch(`${API}/api/admin/categories/reorder`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` }, body: JSON.stringify({ ids: originalOrderIds })
  });
  assert(memberReorderRes.status === 403, `일반회원 권한으로 순서 변경 시도 시 403 (실제: ${memberReorderRes.status})`);

  const partialIds = originalOrderIds.slice(0, -1); // 하나 빠뜨림
  const partialReorderRes = await fetch(`${API}/api/admin/categories/reorder`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` }, body: JSON.stringify({ ids: partialIds })
  });
  assert(partialReorderRes.status === 400, `일부 카테고리가 빠진 순서 목록으로 저장 시도 시 400 (실제: ${partialReorderRes.status})`);

  const invalidIdReorderRes = await fetch(`${API}/api/admin/categories/reorder`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ ids: [...originalOrderIds.slice(1), '00000000-0000-0000-0000-000000000000'] })
  });
  assert(invalidIdReorderRes.status === 400, `존재하지 않는 id가 포함된 순서 목록으로 저장 시도 시 400 (실제: ${invalidIdReorderRes.status})`);

  const reversedIds = [...originalOrderIds].reverse();
  const reorderRes = await fetch(`${API}/api/admin/categories/reorder`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` }, body: JSON.stringify({ ids: reversedIds })
  });
  const reorderJson = await reorderRes.json();
  const afterOrderIds = reorderJson.data.map(c => c.id);
  assert(reorderRes.status === 200 && JSON.stringify(afterOrderIds) === JSON.stringify(reversedIds), `순서를 뒤집어 저장하면 실제로 반대 순서로 반영됨 (실제 일치 여부: ${JSON.stringify(afterOrderIds) === JSON.stringify(reversedIds)})`);

  // 운영 중인 실제 카테고리 순서이므로 테스트 후 반드시 원래대로 복구
  const restoreRes = await fetch(`${API}/api/admin/categories/reorder`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` }, body: JSON.stringify({ ids: originalOrderIds })
  });
  const restoreJson = await restoreRes.json();
  assert(restoreRes.status === 200 && JSON.stringify(restoreJson.data.map(c => c.id)) === JSON.stringify(originalOrderIds), '테스트 후 원래 카테고리 순서로 정상 복구됨');

  // ============================================
  // 🤖 AI 카테고리 추천 설정
  // ============================================
  const { data: originalAiConfig } = await admin.from('ai_configs_with').select('*').eq('provider_key', 'anthropic').maybeSingle();

  const noAuthAiGetRes = await fetch(`${API}/api/admin/ai-category-recommender`);
  assert(noAuthAiGetRes.status === 401, `인증 없이 AI 설정 조회 시 401 (실제: ${noAuthAiGetRes.status})`);

  const memberAiGetRes = await fetch(`${API}/api/admin/ai-category-recommender`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert(memberAiGetRes.status === 403, `일반회원 권한으로 AI 설정 조회 시 403 (실제: ${memberAiGetRes.status})`);

  const adminAiGetRes = await fetch(`${API}/api/admin/ai-category-recommender`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const adminAiGetJson = await adminAiGetRes.json();
  assert(adminAiGetRes.status === 200 && typeof adminAiGetJson.data.has_api_key === 'boolean' && typeof adminAiGetJson.data.enabled === 'boolean', `관리자 권한으로 AI 설정 조회 성공 (실제: has_api_key=${adminAiGetJson.data?.has_api_key}, enabled=${adminAiGetJson.data?.enabled})`);

  const memberAiPatchRes = await fetch(`${API}/api/admin/ai-category-recommender`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` }, body: JSON.stringify({ enabled: true })
  });
  assert(memberAiPatchRes.status === 403, `일반회원 권한으로 AI 설정 변경 시도 시 403 (실제: ${memberAiPatchRes.status})`);

  const fakeKey = `sk-ant-faketestkey-${ts}`;
  const setKeyRes = await fetch(`${API}/api/admin/ai-category-recommender`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ api_key: fakeKey, enabled: true })
  });
  const setKeyJson = await setKeyRes.json();
  assert(setKeyRes.status === 200 && setKeyJson.data.has_api_key === true && setKeyJson.data.enabled === true, `가짜 API 키 저장 + 활성화 성공 (실제: has_api_key=${setKeyJson.data?.has_api_key}, enabled=${setKeyJson.data?.enabled})`);

  const afterSetGetRes = await fetch(`${API}/api/admin/ai-category-recommender`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const afterSetGetJson = await afterSetGetRes.json();
  assert(!('api_key' in afterSetGetJson.data), `저장 후 조회 응답에 api_key 원문이 절대 포함되지 않음`);

  const testWithFakeKeyRes = await fetch(`${API}/api/admin/ai-category-recommender/test`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
  const testWithFakeKeyJson = await testWithFakeKeyRes.json();
  assert(testWithFakeKeyRes.status === 200 && testWithFakeKeyJson.data.status === 'failed', `가짜 키로 연결 테스트 시 실제 Anthropic 서버에서 인증 실패로 정확히 판정됨 (실제: ${testWithFakeKeyJson.data?.status})`);

  const memberSuggestRes = await fetch(`${API}/api/admin/categories/suggest`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` }, body: JSON.stringify({ direction: '건강기능식품' })
  });
  assert(memberSuggestRes.status === 403, `일반회원 권한으로 AI 추천 시도 시 403 (실제: ${memberSuggestRes.status})`);

  const noDirectionRes = await fetch(`${API}/api/admin/categories/suggest`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` }, body: JSON.stringify({ direction: '' })
  });
  assert(noDirectionRes.status === 400, `방향을 입력하지 않고 추천 시도 시 400 (실제: ${noDirectionRes.status})`);

  const suggestWithFakeKeyRes = await fetch(`${API}/api/admin/categories/suggest`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` }, body: JSON.stringify({ direction: '건강기능식품 전문몰' })
  });
  assert(suggestWithFakeKeyRes.status === 502, `가짜 키로는 실제 추천 호출 시 AI 서버 인증 실패로 502 반환됨 (실제: ${suggestWithFakeKeyRes.status})`);

  const disableAiRes = await fetch(`${API}/api/admin/ai-category-recommender`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` }, body: JSON.stringify({ enabled: false })
  });
  assert(disableAiRes.status === 200, `AI 카테고리 추천 비활성화 성공 (실제: ${disableAiRes.status})`);

  const suggestWhileDisabledRes = await fetch(`${API}/api/admin/categories/suggest`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` }, body: JSON.stringify({ direction: '건강기능식품 전문몰' })
  });
  assert(suggestWhileDisabledRes.status === 400, `비활성화 상태에서는 추천 시도 시 400으로 안내됨 (실제: ${suggestWhileDisabledRes.status})`);

  // 테스트 전 상태로 복구 (실제 운영 설정을 건드리지 않기 위함)
  if (originalAiConfig) {
    await admin.from('ai_configs_with').update({
      api_key: originalAiConfig.api_key,
      enabled: originalAiConfig.enabled,
      last_tested_at: originalAiConfig.last_tested_at,
      last_test_status: originalAiConfig.last_test_status,
      last_test_message: originalAiConfig.last_test_message
    }).eq('provider_key', 'anthropic');
  }

  // ============================================
  // 선택한 카테고리 일괄 추가 (bulk-create)
  // ============================================
  const noAuthBulkRes = await fetch(`${API}/api/admin/categories/bulk-create`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ categories: [] })
  });
  assert(noAuthBulkRes.status === 401, `인증 없이 일괄 추가 시도 시 401 (실제: ${noAuthBulkRes.status})`);

  const emptyBulkRes = await fetch(`${API}/api/admin/categories/bulk-create`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` }, body: JSON.stringify({ categories: [] })
  });
  assert(emptyBulkRes.status === 400, `빈 배열로 일괄 추가 시도 시 400 (실제: ${emptyBulkRes.status})`);

  const dupSlug = beforeJson.data[0].slug; // 이미 존재하는 실제 카테고리 슬러그
  const dupBulkRes = await fetch(`${API}/api/admin/categories/bulk-create`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ categories: [{ label: '중복테스트', emoji: '🔁', slug: dupSlug }] })
  });
  assert(dupBulkRes.status === 400, `이미 존재하는 슬러그만 있으면 전부 건너뛰어져 400 (실제: ${dupBulkRes.status})`);

  const newSlug = `test-bulk-cat-${ts}`;
  const okBulkRes = await fetch(`${API}/api/admin/categories/bulk-create`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ categories: [{ label: 'AI추천테스트카테고리', emoji: '✨', slug: newSlug }, { label: '중복테스트2', emoji: '🔁', slug: dupSlug }] })
  });
  const okBulkJson = await okBulkRes.json();
  assert(okBulkRes.status === 201 && okBulkJson.data.length === 1 && okBulkJson.skipped.length === 1, `새 슬러그 1개는 추가되고 중복 슬러그 1개는 건너뜀 (실제: 추가 ${okBulkJson.data?.length}, 건너뜀 ${okBulkJson.skipped?.length})`);

  // 정리
  await admin.from('categories').delete().eq('slug', newSlug);
  await admin.from('profiles').delete().in('id', [adminId, memberId]);
  await admin.auth.admin.deleteUser(adminId);
  await admin.auth.admin.deleteUser(memberId);
  console.log('정리 완료: 테스트 카테고리/AI설정 복구/계정 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
