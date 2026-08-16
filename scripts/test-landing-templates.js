// 분양 랜딩페이지 디자인 템플릿(classic/modern/warm) 기능 검증용 임시 테스트.
// - 조직 생성 시 기본 템플릿이 'classic'인지
// - 템플릿 값을 지정해 생성/수정할 수 있는지, 허용되지 않은 값은 거부되는지(400)
// - 공개 조회 API(GET /api/communities/:slug)가 landing_template 필드를 그대로 반환하는지
//   (community-landing.html이 이 값으로 템플릿을 분기하므로 API가 정확해야 함)
// 검증 후 생성한 데이터는 모두 정리한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const HQ_EMAIL = `withplus.template.hq.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';

let createdUserIds = [];
let createdCommunityIds = [];

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
  for (const id of createdCommunityIds) await admin.from('communities').delete().eq('id', id);
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 계정 준비 ===');
  const hq = await createTestUser(HQ_EMAIL, 'super_admin');

  console.log('\n=== 1. landing_template을 지정하지 않고 조직 생성 시 기본값은 classic ===');
  const createDefault = await api('/api/admin/communities', hq.token, {
    method: 'POST',
    body: JSON.stringify({ name: `템플릿테스트-기본-${stamp}`, slug: `template-default-${stamp}` })
  });
  assert(createDefault.ok, `기본 템플릿 조직 생성 성공 (status=${createDefault.status})`);
  createdCommunityIds.push(createDefault.json.data.id);
  assert(createDefault.json.data.landing_template === 'classic', `landing_template 기본값이 classic (실제=${createDefault.json.data.landing_template})`);

  console.log('\n=== 2. landing_template=modern으로 조직 생성 ===');
  const createModern = await api('/api/admin/communities', hq.token, {
    method: 'POST',
    body: JSON.stringify({ name: `템플릿테스트-모던-${stamp}`, slug: `template-modern-${stamp}`, landing_template: 'modern' })
  });
  assert(createModern.ok, `모던 템플릿 조직 생성 성공 (status=${createModern.status})`);
  createdCommunityIds.push(createModern.json.data.id);
  assert(createModern.json.data.landing_template === 'modern', `landing_template이 modern으로 저장됨 (실제=${createModern.json.data.landing_template})`);

  console.log('\n=== 3. 허용되지 않은 템플릿 값으로 생성 시도하면 400 ===');
  const createInvalid = await api('/api/admin/communities', hq.token, {
    method: 'POST',
    body: JSON.stringify({ name: `템플릿테스트-잘못됨-${stamp}`, slug: `template-invalid-${stamp}`, landing_template: 'fancy-3d' })
  });
  assert(createInvalid.status === 400, `허용되지 않은 템플릿 값은 400 (실제=${createInvalid.status})`);

  console.log('\n=== 4. 공개 조회 API가 landing_template을 그대로 반환 (랜딩페이지가 이 값으로 템플릿을 분기함) ===');
  const publicGet = await api('/api/communities/' + encodeURIComponent(createModern.json.data.slug), null);
  assert(publicGet.ok, `공개 조회 성공 (status=${publicGet.status})`);
  assert(publicGet.json.data.landing_template === 'modern', `공개 조회 응답에도 landing_template=modern 포함 (실제=${publicGet.json.data.landing_template})`);

  console.log('\n=== 5. PUT으로 기존 조직의 템플릿을 warm으로 변경 ===');
  const updateWarm = await api('/api/admin/communities/' + createDefault.json.data.id, hq.token, {
    method: 'PUT',
    body: JSON.stringify({ landing_template: 'warm' })
  });
  assert(updateWarm.ok, `템플릿 변경(PUT) 성공 (status=${updateWarm.status})`);
  assert(updateWarm.json.data.landing_template === 'warm', `변경된 템플릿이 warm으로 저장됨 (실제=${updateWarm.json.data.landing_template})`);

  console.log('\n=== 6. PUT에서도 허용되지 않은 템플릿 값은 400으로 거부되고 기존 값이 유지됨 ===');
  const updateInvalid = await api('/api/admin/communities/' + createDefault.json.data.id, hq.token, {
    method: 'PUT',
    body: JSON.stringify({ landing_template: 'not-a-real-template' })
  });
  assert(updateInvalid.status === 400, `허용되지 않은 값으로 변경 시도는 400 (실제=${updateInvalid.status})`);
  const afterInvalid = await api('/api/communities/' + encodeURIComponent(createDefault.json.data.slug), null);
  assert(afterInvalid.json.data.landing_template === 'warm', `거부된 시도 이후에도 기존 값(warm)이 그대로 유지됨 (실제=${afterInvalid.json.data.landing_template})`);

  console.log('\n=== 7. landing_template을 아예 전달하지 않고 PUT하면 기존 값이 바뀌지 않음 (다른 필드만 수정) ===');
  const updateOther = await api('/api/admin/communities/' + createDefault.json.data.id, hq.token, {
    method: 'PUT',
    body: JSON.stringify({ hero_title: '수정된 문구' })
  });
  assert(updateOther.ok, `다른 필드만 수정 성공 (status=${updateOther.status})`);
  assert(updateOther.json.data.landing_template === 'warm', `landing_template을 안 보내면 기존 값(warm) 유지 (실제=${updateOther.json.data.landing_template})`);

  console.log('\n=== 8. 관리자 목록 조회(GET /api/admin/communities)에도 landing_template이 각 조직별로 포함됨 ===');
  const listRes = await api('/api/admin/communities', hq.token);
  const found = listRes.json.data.find(c => c.id === createModern.json.data.id);
  assert(found && found.landing_template === 'modern', `목록에서도 modern 조직의 landing_template이 정확히 조회됨`);

  console.log('\n🎉 모든 검증 통과');
}

main()
  .catch(err => { console.error('\n💥 테스트 실패:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
