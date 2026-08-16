// 🧩 기능 모듈 카탈로그 API 검증용 임시 테스트.
// - 인증 없이 접근하면 401인지
// - 일반 회원은 403인지
// - 관리자는 200으로 모듈 목록을 받는지, 각 항목에 필요한 필드(key/category/icon/name/desc/status/tabTarget)가 다 있는지
// - key 값에 중복이 없는지
// - status는 'active' 또는 'planned' 둘 중 하나뿐인지, active인데 tabTarget이 없는 항목은 없는지(운영중인데 갈 곳이 없으면 안 됨)
// 검증 후 생성한 계정을 정리한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const ADMIN_EMAIL = `withplus.modcat.admin.${stamp}@withplus.test`;
const MEMBER_EMAIL = `withplus.modcat.member.${stamp}@withplus.test`;
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

async function api(path, token) {
  const res = await fetch(BASE + path, { headers: token ? { Authorization: 'Bearer ' + token } : {} });
  const json = await res.json();
  return { status: res.status, ok: res.ok, json };
}

function assert(cond, msg) {
  if (!cond) throw new Error('❌ 검증 실패: ' + msg);
  console.log('✅ ' + msg);
}

async function cleanup() {
  console.log('\n--- 정리 시작 ---');
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 준비 ===');
  const adminUser = await createTestUser(ADMIN_EMAIL, 'super_admin');
  const member = await createTestUser(MEMBER_EMAIL, 'member');

  console.log('\n=== 1. 인증 없이 접근하면 401 ===');
  const noAuth = await api('/api/admin/modules', null);
  assert(noAuth.status === 401, `인증 없는 요청은 401 (실제=${noAuth.status})`);

  console.log('\n=== 2. 일반 회원은 403 ===');
  const memberRes = await api('/api/admin/modules', member.token);
  assert(memberRes.status === 403, `일반 회원 요청은 403 (실제=${memberRes.status})`);

  console.log('\n=== 3. 관리자는 200으로 모듈 목록을 받음 ===');
  const adminRes = await api('/api/admin/modules', adminUser.token);
  assert(adminRes.ok && adminRes.json.success, `관리자 요청 성공 (status=${adminRes.status})`);
  const modules = adminRes.json.data;
  assert(Array.isArray(modules) && modules.length > 0, `모듈 목록이 배열이고 1개 이상 (실제=${modules?.length})`);

  console.log('\n=== 4. 각 항목에 필수 필드가 다 있는지 ===');
  const requiredFields = ['key', 'category', 'icon', 'name', 'desc', 'status'];
  const missing = modules.filter(m => requiredFields.some(f => !(f in m) || m[f] === '' || m[f] === undefined));
  assert(missing.length === 0, `모든 항목에 필수 필드(${requiredFields.join(', ')})가 존재함 (누락=${missing.length})`);

  console.log('\n=== 5. key 값 중복이 없는지 ===');
  const keys = modules.map(m => m.key);
  const uniqueKeys = new Set(keys);
  assert(uniqueKeys.size === keys.length, `key 값 중복 없음 (전체=${keys.length}, 고유=${uniqueKeys.size})`);

  console.log('\n=== 6. status는 active/planned 둘 중 하나뿐 ===');
  const badStatus = modules.filter(m => m.status !== 'active' && m.status !== 'planned');
  assert(badStatus.length === 0, `모든 항목의 status가 active 또는 planned (이상값=${badStatus.length})`);

  console.log('\n=== 7. status=active인 항목은 tabTarget이 있거나, 없다면 "별도 관리자 설정 화면" 없음을 desc에 명시해야 함 ===');
  // point_redeem/recommendations/search/seo/account_withdrawal처럼 규칙기반으로 자동 동작해 관리 화면 자체가
  // 필요 없는 기능도 있다 - 그런 경우는 tabTarget:null이 실수가 아니라 의도임을 desc에 스스로 밝히도록 강제해서,
  // "화면이 없다"는 것과 "화면을 깜빡했다"는 것을 구분한다.
  const activeWithoutTarget = modules.filter(m => m.status === 'active' && !m.tabTarget && !String(m.desc || '').includes('별도 관리자 설정 화면'));
  assert(activeWithoutTarget.length === 0, `운영중인 모든 항목에 tabTarget이 있거나 "별도 관리자 설정 화면 없음"이 desc에 명시됨 (누락=${activeWithoutTarget.map(m => m.key).join(',') || '없음'})`);

  console.log('\n=== 8. 최소한의 도메인(판매·상품 관리, 회원·커뮤니티, 디자인)이 카탈로그에 포함되어 있는지 ===');
  const categories = new Set(modules.map(m => m.category));
  assert(categories.has('판매·상품 관리') && categories.has('회원·커뮤니티') && categories.has('디자인'), `주요 카테고리 포함 확인 (전체=${[...categories].join(', ')})`);

  console.log('\n🎉 모든 검증 통과');
}

main()
  .catch(err => { console.error('\n💥 테스트 실패:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
