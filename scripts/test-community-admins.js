// 분양 조직(커뮤니티)에 여러 담당자를 둘 수 있는 기능 검증용 임시 테스트.
// - 조직 생성 시 admin_email로 지정한 회원이 자동으로 담당자에 등록되는지
// - 담당자 추가/목록/삭제 API가 정상 동작하는지
// - 한 회원이 이미 다른 조직의 담당자면 중복 지정이 거부되는지(409)
// - 담당자로 지정된 회원이 실제로 자기 조직의 관리 화면(getMyManagedCommunity 경로)에 접근 가능한지
// 검증 후 생성한 데이터는 모두 정리한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const SUPER_EMAIL = `withplus.cadmin.super.${stamp}@withplus.test`;
const STAFF1_EMAIL = `withplus.cadmin.staff1.${stamp}@withplus.test`;
const STAFF2_EMAIL = `withplus.cadmin.staff2.${stamp}@withplus.test`;
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
  for (const id of createdCommunityIds) {
    await admin.from('community_admins_with').delete().eq('community_id', id);
    await admin.from('communities').delete().eq('id', id);
  }
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 계정 준비 ===');
  const superAdmin = await createTestUser(SUPER_EMAIL, 'super_admin');
  const staff1 = await createTestUser(STAFF1_EMAIL, null);
  const staff2 = await createTestUser(STAFF2_EMAIL, null);

  console.log('\n=== 1. 조직 생성 시 admin_email로 지정한 회원이 자동 담당자 등록됨 ===');
  const createRes = await api('/api/admin/communities', superAdmin.token, {
    method: 'POST',
    body: JSON.stringify({ name: `담당자테스트교회-${stamp}`, slug: `cadmin-test-${stamp}`, admin_email: STAFF1_EMAIL })
  });
  assert(createRes.ok, `조직 생성 성공 (status=${createRes.status})`);
  const communityId = createRes.json.data.id;
  createdCommunityIds.push(communityId);

  const adminsAfterCreate = await api(`/api/admin/communities/${communityId}/admins`, superAdmin.token);
  assert(adminsAfterCreate.ok, `담당자 목록 조회 성공 (status=${adminsAfterCreate.status})`);
  assert(adminsAfterCreate.json.data.length === 1 && adminsAfterCreate.json.data[0].email === STAFF1_EMAIL, `생성 시 지정한 담당자(${STAFF1_EMAIL})가 자동 등록됨`);

  console.log('\n=== 2. 같은 조직에 두 번째 담당자를 추가하면 담당자가 2명이 됨 (다중 담당자 지원) ===');
  const addStaff2 = await api(`/api/admin/communities/${communityId}/admins`, superAdmin.token, {
    method: 'POST',
    body: JSON.stringify({ email: STAFF2_EMAIL })
  });
  assert(addStaff2.ok, `두 번째 담당자 추가 성공 (status=${addStaff2.status})`);
  const adminsAfterAdd = await api(`/api/admin/communities/${communityId}/admins`, superAdmin.token);
  assert(adminsAfterAdd.json.data.length === 2, `담당자가 2명으로 늘어남 (실제=${adminsAfterAdd.json.data.length})`);

  console.log('\n=== 3. 조직 목록 조회 시 admin_count가 정확히 반영됨 ===');
  const listRes = await api('/api/admin/communities', superAdmin.token);
  const thisCommunity = listRes.json.data.find(c => c.id === communityId);
  assert(thisCommunity.admin_count === 2, `admin_count가 2로 반영됨 (실제=${thisCommunity.admin_count})`);

  console.log('\n=== 4. 이미 다른 조직의 담당자인 회원을 또 다른 조직 담당자로 지정하면 409 ===');
  const secondCommunity = await api('/api/admin/communities', superAdmin.token, {
    method: 'POST',
    body: JSON.stringify({ name: `담당자테스트교회2-${stamp}`, slug: `cadmin-test2-${stamp}` })
  });
  assert(secondCommunity.ok, `두 번째 조직 생성 성공 (status=${secondCommunity.status})`);
  createdCommunityIds.push(secondCommunity.json.data.id);

  const conflictAdd = await api(`/api/admin/communities/${secondCommunity.json.data.id}/admins`, superAdmin.token, {
    method: 'POST',
    body: JSON.stringify({ email: STAFF1_EMAIL })
  });
  assert(conflictAdd.status === 409, `겸직 시도는 409로 거부됨 (실제=${conflictAdd.status})`);

  console.log('\n=== 5. 담당자로 지정된 회원은 자신이 담당하는 조직을 자동으로 찾을 수 있음 ===');
  const myManaged = await api('/api/community-admin/dashboard', staff1.token);
  assert(myManaged.ok, `담당자 본인 조직 조회 성공 (status=${myManaged.status})`);
  assert(myManaged.json.data.community.id === communityId, `담당자1이 실제로 관리하는 조직과 일치함`);

  console.log('\n=== 6. 담당자가 아닌 회원은 관리 조직이 없음(404) ===');
  const notManaged = await createTestUser(`withplus.cadmin.none.${stamp}@withplus.test`, null);
  const noneRes = await api('/api/community-admin/dashboard', notManaged.token);
  assert(noneRes.status === 404, `담당자가 아닌 회원은 404 (실제=${noneRes.status})`);

  console.log('\n=== 7. 담당자 삭제(DELETE) ===');
  const removeStaff2 = await api(`/api/admin/communities/${communityId}/admins/${staff2.id}`, superAdmin.token, { method: 'DELETE' });
  assert(removeStaff2.ok, `담당자 삭제 성공 (status=${removeStaff2.status})`);
  const adminsAfterRemove = await api(`/api/admin/communities/${communityId}/admins`, superAdmin.token);
  assert(adminsAfterRemove.json.data.length === 1, `삭제 후 담당자 1명만 남음 (실제=${adminsAfterRemove.json.data.length})`);

  console.log('\n=== 8. 담당자에서 삭제된 회원은 다른 조직의 담당자로 다시 지정 가능함 ===');
  const reassign = await api(`/api/admin/communities/${secondCommunity.json.data.id}/admins`, superAdmin.token, {
    method: 'POST',
    body: JSON.stringify({ email: STAFF2_EMAIL })
  });
  assert(reassign.ok, `삭제 후 다른 조직 담당자로 재지정 가능 (status=${reassign.status})`);

  console.log('\n=== 9. 관리자가 아니면 담당자 관리 API 접근 불가 ===');
  const forbidden = await api(`/api/admin/communities/${communityId}/admins`, staff1.token, {
    method: 'POST',
    body: JSON.stringify({ email: STAFF2_EMAIL })
  });
  assert(forbidden.status === 403, `일반 회원의 담당자 추가 시도는 403 (실제=${forbidden.status})`);

  console.log('\n🎉 모든 검증 통과');
  createdUserIds.push(notManaged.id);
}

main()
  .catch(err => { console.error('\n💥 테스트 실패:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
