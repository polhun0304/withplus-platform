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
  const createdUserIds = [];

  const providerEmail = `test-aidesc-provider-${ts}@withplus-test.local`;
  const { data: providerUser } = await admin.auth.admin.createUser({ email: providerEmail, password: 'TestPass123!', email_confirm: true });
  createdUserIds.push(providerUser.user.id);
  await admin.from('profiles').upsert([{ id: providerUser.user.id, email: providerEmail, full_name: 'AiDescTestProvider', role: 'provider' }]);
  const providerToken = await loginAs(providerEmail, 'TestPass123!');

  const memberEmail = `test-aidesc-member-${ts}@withplus-test.local`;
  const { data: memberUser } = await admin.auth.admin.createUser({ email: memberEmail, password: 'TestPass123!', email_confirm: true });
  createdUserIds.push(memberUser.user.id);
  await admin.from('profiles').upsert([{ id: memberUser.user.id, email: memberEmail, full_name: 'AiDescTestMember', role: 'member' }]);
  const memberToken = await loginAs(memberEmail, 'TestPass123!');

  // AI 설정을 테스트 시작 전 상태로 기억해두고, 끝나면 원상복구한다 (다른 AI 기능 테스트/실운영 설정에 영향 주지 않기 위함)
  const { data: originalConfig } = await admin.from('ai_configs_with').select('*').eq('provider_key', 'anthropic').maybeSingle();

  // ============================================
  // 1) 인증/권한 검증
  // ============================================
  const noAuthRes = await fetch(`${API}/api/admin/ai-product-description`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'x', features: 'x' })
  });
  assert(noAuthRes.status === 401, '로그인 없이는 접근 차단(401)');

  const memberRes = await fetch(`${API}/api/admin/ai-product-description`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + memberToken },
    body: JSON.stringify({ name: 'x', features: 'x' })
  });
  assert(memberRes.status === 403, '일반 회원(provider/admin이 아님)은 접근 차단(403)');

  // ============================================
  // 2) 입력값 검증
  // ============================================
  const noNameRes = await fetch(`${API}/api/admin/ai-product-description`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + providerToken },
    body: JSON.stringify({ features: '유기농' })
  });
  assert(noNameRes.status === 400, '상품명 없이 요청하면 400');

  const noFeaturesRes = await fetch(`${API}/api/admin/ai-product-description`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + providerToken },
    body: JSON.stringify({ name: '유기농 벌꿀' })
  });
  assert(noFeaturesRes.status === 400, '상품 특징 없이 요청하면 400');

  // ============================================
  // 3) AI 연동이 비활성화/미설정 상태일 때 - 정직하게 400 + 안내 메시지 (실제 API 키가 없는 이 테스트 환경 기준)
  // ============================================
  await admin.from('ai_configs_with').upsert([{ provider_key: 'anthropic', enabled: false }], { onConflict: 'provider_key' });
  const disabledRes = await fetch(`${API}/api/admin/ai-product-description`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + providerToken },
    body: JSON.stringify({ name: '유기농 벌꿀', category: 'diet', features: '국내산, 무설탕' })
  });
  const disabledJson = await disabledRes.json();
  assert(disabledRes.status === 400, 'AI 연동이 비활성화 상태면 400');
  assert(disabledJson.message.includes('Anthropic API 키'), '비활성화 상태일 때 설정 안내 메시지가 정확히 내려옴');

  // ============================================
  // 4) 잘못된 API 키로 활성화했을 때 - describeAnthropicError가 실제로 동작해서
  //    "API 키 인증에 실패했습니다" 같은 한국어 안내 + Anthropic 원문 메시지가 함께 내려오는지 확인
  //    (이번에 마무리한 "실질적인 에러메시지가 보이도록" 작업이 이 신규 기능에도 그대로 적용됐는지 검증)
  // ============================================
  await admin.from('ai_configs_with').upsert([{ provider_key: 'anthropic', enabled: true, api_key: 'sk-ant-invalid-test-key-0000000000' }], { onConflict: 'provider_key' });
  const invalidKeyRes = await fetch(`${API}/api/admin/ai-product-description`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + providerToken },
    body: JSON.stringify({ name: '유기농 벌꿀', category: 'diet', features: '국내산, 무설탕' })
  });
  const invalidKeyJson = await invalidKeyRes.json();
  assert(invalidKeyRes.status === 502, '잘못된 API 키면 502로 정직하게 실패함');
  assert(invalidKeyJson.message.includes('API 키 인증에 실패했습니다'), '한국어 안내 문구가 포함됨(개선된 에러 메시지)');
  assert(invalidKeyJson.message.includes('[Anthropic 응답]'), 'Anthropic이 실제로 보낸 원문 메시지도 [Anthropic 응답] 형태로 함께 내려옴(형님이 요청한 개선사항)');
  console.log('   (참고용) 실제 응답 메시지:', invalidKeyJson.message);

  // 같은 개선(describeAnthropicError)이 기존 AI 카테고리 추천 연결테스트에도 그대로 적용됐는지 회귀 확인
  const adminEmail = `test-aidesc-admin-${ts}@withplus-test.local`;
  const { data: adminUser } = await admin.auth.admin.createUser({ email: adminEmail, password: 'TestPass123!', email_confirm: true });
  createdUserIds.push(adminUser.user.id);
  await admin.from('profiles').upsert([{ id: adminUser.user.id, email: adminEmail, full_name: 'AiDescTestAdmin', role: 'admin' }]);
  const adminToken = await loginAs(adminEmail, 'TestPass123!');

  const catTestRes = await fetch(`${API}/api/admin/ai-category-recommender/test`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + adminToken }
  });
  const catTestJson = await catTestRes.json();
  assert(catTestJson.data.status === 'failed' && catTestJson.data.message.includes('API 키 인증에 실패했습니다') && catTestJson.data.message.includes('[Anthropic 응답]'), 'AI 카테고리 추천 연결 테스트에도 개선된 에러 메시지가 동일하게 적용됨(회귀 확인)');

  // ============================================
  // 정리 - AI 설정을 테스트 시작 전 상태로 정확히 복구
  // ============================================
  if (originalConfig) {
    const { provider_key, ...rest } = originalConfig;
    await admin.from('ai_configs_with').update(rest).eq('provider_key', 'anthropic');
  } else {
    await admin.from('ai_configs_with').delete().eq('provider_key', 'anthropic');
  }
  for (const id of createdUserIds) {
    await admin.from('profiles').delete().eq('id', id);
    await admin.auth.admin.deleteUser(id).catch(() => {});
  }

  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => { console.error('테스트 실행 중 오류:', err); process.exit(1); });
