// 디자인 부품 갤러리(카페24 "모듈리스트" 참고 - 화면 구성요소별 디자인 템플릿 선택) 기능 검증용 임시 테스트.
// - 공개 조회 API가 기본값과 선택 가능한 옵션 목록을 정확히 반환하는지
// - 관리자가 값을 변경하면 즉시(캐시 TTL 내) 공개 조회에도 반영되는지
// - 허용되지 않은 컴포넌트/값은 400으로 거부되는지, 일반 회원은 변경할 수 없는지(403)
// - 일부 컴포넌트만 보내면 나머지는 기존 값이 유지되는지
// 검증 후 원래 기본값(classic/grid 등)으로 되돌려두고 종료한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const ADMIN_EMAIL = `withplus.pagetpl.admin.${stamp}@withplus.test`;
const MEMBER_EMAIL = `withplus.pagetpl.member.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';
let createdUserIds = [];

async function createTestUser(email, role) {
  const { data, error } = await admin.auth.admin.createUser({ email, password: PASSWORD, email_confirm: true });
  if (error) throw new Error(`계정 생성 실패(${email}): ${error.message}`);
  createdUserIds.push(data.user.id);
  const { error: profErr } = await admin.from('profiles').upsert({ id: data.user.id, email, role: role || 'member' });
  if (profErr) throw new Error(`profiles 생성 실패(${email}): ${profErr.message}`);
  const client = createClient(supabaseUrl, anonKey);
  const { data: signIn, error: signInErr } = await client.auth.signInWithPassword({ email, password: PASSWORD });
  if (signInErr) throw new Error(`로그인 실패(${email}): ${signInErr.message}`);
  return { id: data.user.id, token: signIn.session.access_token };
}

async function api(path, token, options = {}) {
  const res = await fetch(BASE + path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(options.headers || {}) }
  });
  const json = await res.json();
  return { status: res.status, ok: res.ok, json };
}

function assert(cond, msg) {
  if (!cond) throw new Error('❌ 검증 실패: ' + msg);
  console.log('✅ ' + msg);
}

async function cleanup() {
  console.log('\n--- 정리 시작 ---');
  // 원래 기본값으로 되돌린다 (다른 테스트/실제 화면에 영향 남기지 않기 위해)
  await admin.from('platform_settings').upsert({
    key: 'page_design_templates',
    value: { product_list: 'grid', cart: 'classic', login: 'classic', mypage: 'classic' },
    updated_at: new Date().toISOString()
  }, { onConflict: 'key' });
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 계정 준비 ===');
  const adminUser = await createTestUser(ADMIN_EMAIL, 'super_admin');
  const memberUser = await createTestUser(MEMBER_EMAIL, 'member');

  console.log('\n=== 1. 공개 조회 - 기본값과 컴포넌트별 옵션 목록이 정확히 내려오는지 ===');
  const initial = await api('/api/settings/page-templates', null);
  assert(initial.ok, `공개 조회 성공 (status=${initial.status})`);
  assert(initial.json.data.selected.product_list === 'grid', `상품목록 기본값은 grid (실제=${initial.json.data.selected.product_list})`);
  assert(initial.json.data.selected.cart === 'classic', `장바구니 기본값은 classic (실제=${initial.json.data.selected.cart})`);
  assert(initial.json.data.selected.login === 'classic', `로그인 기본값은 classic (실제=${initial.json.data.selected.login})`);
  assert(initial.json.data.selected.mypage === 'classic', `마이페이지 기본값은 classic (실제=${initial.json.data.selected.mypage})`);
  assert(Array.isArray(initial.json.data.components.product_list.options) && initial.json.data.components.product_list.options.length === 2, '상품목록 컴포넌트에 옵션 2개가 내려옴');

  console.log('\n=== 2. 일반 회원은 변경할 수 없음 (403) ===');
  const memberAttempt = await api('/api/admin/settings/page-templates', memberUser.token, {
    method: 'PATCH', body: JSON.stringify({ product_list: 'list' })
  });
  assert(memberAttempt.status === 403, `일반 회원의 변경 시도는 403 (실제=${memberAttempt.status})`);

  console.log('\n=== 3. 인증 없이 변경 시도하면 401 ===');
  const noAuthAttempt = await api('/api/admin/settings/page-templates', null, {
    method: 'PATCH', body: JSON.stringify({ product_list: 'list' })
  });
  assert(noAuthAttempt.status === 401, `인증 없는 변경 시도는 401 (실제=${noAuthAttempt.status})`);

  console.log('\n=== 4. 관리자가 일부 컴포넌트만 변경 - 나머지는 기존 값 유지 ===');
  const partialUpdate = await api('/api/admin/settings/page-templates', adminUser.token, {
    method: 'PATCH', body: JSON.stringify({ product_list: 'list', cart: 'compact' })
  });
  assert(partialUpdate.ok, `일부만 변경 성공 (status=${partialUpdate.status})`);
  assert(partialUpdate.json.data.product_list === 'list', `상품목록이 list로 변경됨 (실제=${partialUpdate.json.data.product_list})`);
  assert(partialUpdate.json.data.cart === 'compact', `장바구니가 compact로 변경됨 (실제=${partialUpdate.json.data.cart})`);
  assert(partialUpdate.json.data.login === 'classic', `건드리지 않은 로그인은 여전히 classic (실제=${partialUpdate.json.data.login})`);
  assert(partialUpdate.json.data.mypage === 'classic', `건드리지 않은 마이페이지는 여전히 classic (실제=${partialUpdate.json.data.mypage})`);

  console.log('\n=== 5. 변경 직후 공개 조회에도 즉시 반영되는지 ===');
  const afterUpdate = await api('/api/settings/page-templates', null);
  assert(afterUpdate.json.data.selected.product_list === 'list', `공개 조회에도 상품목록=list 반영 (실제=${afterUpdate.json.data.selected.product_list})`);
  assert(afterUpdate.json.data.selected.cart === 'compact', `공개 조회에도 장바구니=compact 반영 (실제=${afterUpdate.json.data.selected.cart})`);

  console.log('\n=== 6. 허용되지 않은 컴포넌트 키는 400 ===');
  const invalidComponent = await api('/api/admin/settings/page-templates', adminUser.token, {
    method: 'PATCH', body: JSON.stringify({ nonexistent_component: 'foo' })
  });
  assert(invalidComponent.status === 400, `존재하지 않는 컴포넌트 키는 400 (실제=${invalidComponent.status})`);

  console.log('\n=== 7. 허용되지 않은 옵션 값은 400이고, 기존 값은 그대로 유지됨 (부분 실패 없음) ===');
  const invalidValue = await api('/api/admin/settings/page-templates', adminUser.token, {
    method: 'PATCH', body: JSON.stringify({ login: 'fancy-3d-login' })
  });
  assert(invalidValue.status === 400, `허용되지 않은 값은 400 (실제=${invalidValue.status})`);
  const afterInvalid = await api('/api/settings/page-templates', null);
  assert(afterInvalid.json.data.selected.login === 'classic', `거부된 시도 이후에도 로그인 값은 그대로 classic (실제=${afterInvalid.json.data.selected.login})`);
  assert(afterInvalid.json.data.selected.product_list === 'list', `거부된 시도가 다른 컴포넌트(product_list)에도 영향 주지 않음 (실제=${afterInvalid.json.data.selected.product_list})`);

  console.log('\n=== 8. 나머지 두 컴포넌트(login/mypage)도 변경 가능한지 ===');
  const secondUpdate = await api('/api/admin/settings/page-templates', adminUser.token, {
    method: 'PATCH', body: JSON.stringify({ login: 'split', mypage: 'tabs' })
  });
  assert(secondUpdate.ok, `login/mypage 변경 성공 (status=${secondUpdate.status})`);
  assert(secondUpdate.json.data.login === 'split', `로그인이 split으로 변경됨`);
  assert(secondUpdate.json.data.mypage === 'tabs', `마이페이지가 tabs로 변경됨`);

  console.log('\n🎉 모든 검증 통과');
}

main()
  .catch(err => { console.error('\n💥 테스트 실패:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
