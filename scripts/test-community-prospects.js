// 분양 영업 리스트(전국 종교시설 후보) 기능 검증용 테스트.
// - 스테이징 테이블(community_prospects) bulk-import + 중복(dedup_key) 스킵
// - 목록 조회(GET) 필터(org_type/status/region)
// - 상태/메모 수정(PATCH) 및 converted로 직접 바꾸는 시도는 거부되는지
// - "✅ 공개 전환"(PUT .../promote): communities 행이 실제로 생성되고, 공개 API(GET /api/communities/:slug)로
//   실제 조회되는지, 한글 전용 이름이라도 슬러그가 자동 생성되는지
// - "되돌리기"(PUT .../demote): communities가 inactive로 내려가고 공개 조회에서 사라지는지(주문 이력 보존 위해 삭제는 안 함)
// - 재전환(다시 promote): 같은 communities 행을 재사용하고 새 중복 조직을 만들지 않는지
// 검증 후 생성한 테스트 데이터는 모두 정리(clean up)한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const HQ_EMAIL = `withplus.prospects.hq.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';

let createdUserIds = [];
let createdProspectIds = [];
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
  for (const id of createdProspectIds) await admin.from('community_prospects').delete().eq('id', id);
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 계정 준비 ===');
  const hq = await createTestUser(HQ_EMAIL, 'super_admin');

  console.log('\n=== 1. bulk-import: 신규 2건 등록 + 필수값 누락 거부 ===');
  const testOrgName = `테스트 한글전용성당 ${stamp}`;
  const testOrg2Name = `테스트 교회 ${stamp}`;
  const importRes = await api('/api/admin/prospects/bulk-import', hq.token, {
    method: 'POST',
    body: JSON.stringify({
      items: [
        { name: testOrgName, org_type: 'catholic', address: `서울특별시 테스트구 테스트로 ${stamp}`, region_sido: '서울특별시', region_sigungu: '테스트구', phone: '02-000-0000', source: 'test_source', source_url: 'https://example.com/1' },
        { name: testOrg2Name, org_type: 'church', address: `부산광역시 테스트구 테스트로 ${stamp}`, region_sido: '부산광역시', region_sigungu: '테스트구', source: 'test_source' }
      ]
    })
  });
  assert(importRes.ok && importRes.json.success && importRes.json.inserted === 2, `bulk-import 2건 신규 등록 성공 (inserted=${importRes.json.inserted})`);

  const missingFieldRes = await api('/api/admin/prospects/bulk-import', hq.token, { method: 'POST', body: JSON.stringify({ items: [{ name: '이름만있음' }] }) });
  assert(missingFieldRes.status === 400, 'org_type/source 누락 시 400 거부');

  console.log('\n=== 2. bulk-import 재요청: 동일 항목은 dedup_key로 스킵 ===');
  const reImportRes = await api('/api/admin/prospects/bulk-import', hq.token, {
    method: 'POST',
    body: JSON.stringify({ items: [{ name: testOrgName, org_type: 'catholic', address: `서울특별시 테스트구 테스트로 ${stamp}`, source: 'test_source' }] })
  });
  assert(reImportRes.ok && reImportRes.json.inserted === 0 && reImportRes.json.skipped === 1, `중복 재요청 시 inserted=0, skipped=1 (실제: inserted=${reImportRes.json.inserted}, skipped=${reImportRes.json.skipped})`);

  console.log('\n=== 3. GET 목록/필터 ===');
  const listRes = await api('/api/admin/prospects?org_type=catholic', hq.token);
  assert(listRes.ok && listRes.json.success, 'GET /api/admin/prospects?org_type=catholic 성공');
  const testProspect = listRes.json.data.find(p => p.name === testOrgName);
  assert(!!testProspect, '방금 등록한 테스트 성당이 목록에 존재');
  assert(testProspect.status === 'prospect', '초기 상태는 prospect(잠재)');
  createdProspectIds.push(testProspect.id);
  const testProspect2 = (await api('/api/admin/prospects?org_type=church', hq.token)).json.data.find(p => p.name === testOrg2Name);
  assert(!!testProspect2, '두번째(교회) 테스트 항목도 목록에 존재');
  createdProspectIds.push(testProspect2.id);

  console.log('\n=== 4. PATCH: 상태/메모 수정, converted로 직접 바꾸는 시도는 거부 ===');
  const patchRes = await api(`/api/admin/prospects/${testProspect.id}`, hq.token, { method: 'PATCH', body: JSON.stringify({ status: 'contacted', admin_note: '1차 통화 완료, 담당자 부재중' }) });
  assert(patchRes.ok && patchRes.json.data.status === 'contacted' && patchRes.json.data.admin_note === '1차 통화 완료, 담당자 부재중', 'status=contacted, admin_note 저장 성공');

  const patchConvertedRes = await api(`/api/admin/prospects/${testProspect.id}`, hq.token, { method: 'PATCH', body: JSON.stringify({ status: 'converted' }) });
  assert(patchConvertedRes.status === 400, 'PATCH로 status=converted 직접 지정은 400 거부 (promote API로만 가능해야 함)');

  console.log('\n=== 5. 공개 전환(promote): communities 생성 + 공개 API에서 실제로 조회되는지 ===');
  const promoteRes = await api(`/api/admin/prospects/${testProspect.id}/promote`, hq.token, { method: 'PUT', body: JSON.stringify({}) });
  assert(promoteRes.ok && promoteRes.json.success, `promote 성공 (${promoteRes.json.message || ''})`);
  const promotedCommunity = promoteRes.json.community;
  assert(!!promotedCommunity && !!promotedCommunity.slug, '생성된 communities 행에 slug가 자동 생성됨');
  assert(/^[a-z0-9-]+$/.test(promotedCommunity.slug), `한글 전용 이름이라도 슬러그는 영문/숫자/하이픈만 포함 (slug=${promotedCommunity.slug})`);
  assert(promotedCommunity.org_type === 'catholic', 'org_type이 천주교(catholic)로 정확히 전달됨');
  assert(promotedCommunity.offering_labels && promotedCommunity.offering_labels.dues === '교무금', 'org_type 기본 offering_labels(교무금)가 자동 적용됨');
  createdCommunityIds.push(promotedCommunity.id);

  const publicViewRes = await api(`/api/communities/${promotedCommunity.slug}`, null);
  assert(publicViewRes.ok && publicViewRes.json.success && publicViewRes.json.data.name === testOrgName, '공개 전환 즉시 공개 API(GET /api/communities/:slug)에서 실제로 조회됨');

  const listAfterPromoteRes = await api(`/api/admin/prospects?status=converted`, hq.token);
  const converted = listAfterPromoteRes.json.data.find(p => p.id === testProspect.id);
  assert(!!converted && converted.status === 'converted' && converted.promoted_community_id === promotedCommunity.id, 'community_prospects.status=converted, promoted_community_id 연결 확인');
  assert(converted.promoted_community_slug === promotedCommunity.slug, 'GET 목록 응답에 promoted_community_slug가 함께 내려옴(관리자 화면 "열기" 링크용)');

  console.log('\n=== 6. 되돌리기(demote): communities는 inactive로, 공개 조회에서는 사라짐(삭제는 안 됨) ===');
  const demoteRes = await api(`/api/admin/prospects/${testProspect.id}/demote`, hq.token, { method: 'PUT' });
  assert(demoteRes.ok && demoteRes.json.success, `demote 성공 (${demoteRes.json.message || ''})`);
  assert(demoteRes.json.community.status === 'inactive', 'communities.status가 inactive로 변경됨(완전 삭제 아님)');
  assert(demoteRes.json.data.status === 'prospect', 'community_prospects.status가 prospect로 되돌아감');

  const publicViewAfterDemoteRes = await api(`/api/communities/${promotedCommunity.slug}`, null);
  assert(!publicViewAfterDemoteRes.ok || !publicViewAfterDemoteRes.json.success, '되돌리기 후에는 공개 API에서 더 이상 조회되지 않음(비공개 전환)');

  const { data: communityRowAfterDemote } = await admin.from('communities').select('id').eq('id', promotedCommunity.id).maybeSingle();
  assert(!!communityRowAfterDemote, 'communities 행 자체는 DB에 그대로 남아있음(주문/헌금 이력 보존 목적, 삭제되지 않음)');

  console.log('\n=== 7. 재전환: 다시 promote하면 새 조직을 또 만들지 않고 기존 조직을 재활성화 ===');
  const rePromoteRes = await api(`/api/admin/prospects/${testProspect.id}/promote`, hq.token, { method: 'PUT', body: JSON.stringify({}) });
  assert(rePromoteRes.ok && rePromoteRes.json.success, '재전환(re-promote) 성공');
  assert(rePromoteRes.json.community.id === promotedCommunity.id, `재전환 시 기존과 동일한 communities.id를 재사용함(신규 생성 아님) (기존=${promotedCommunity.id}, 재전환=${rePromoteRes.json.community.id})`);
  assert(rePromoteRes.json.community.status === 'active', '재전환 시 communities.status가 다시 active로 복구됨');

  const { data: communitiesWithSameSlug } = await admin.from('communities').select('id').eq('slug', promotedCommunity.slug);
  assert(communitiesWithSameSlug.length === 1, `같은 슬러그(${promotedCommunity.slug})를 가진 communities 행이 정확히 1개만 존재 (중복 생성 안 됨)`);

  console.log('\n=== 8. slug를 직접 지정해 promote하는 경우 ===');
  const customSlug = `test-org-${stamp}`;
  const promoteWithSlugRes = await api(`/api/admin/prospects/${testProspect2.id}/promote`, hq.token, { method: 'PUT', body: JSON.stringify({ slug: customSlug }) });
  assert(promoteWithSlugRes.ok && promoteWithSlugRes.json.community.slug === customSlug, `관리자가 직접 지정한 slug(${customSlug})가 그대로 사용됨`);
  createdCommunityIds.push(promoteWithSlugRes.json.community.id);

  console.log('\n모든 검증 통과 🎉');
}

main()
  .catch(err => {
    console.error(err.message || err);
    process.exitCode = 1;
  })
  .finally(cleanup);
