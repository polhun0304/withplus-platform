// GIVE+ 1단계(종교 초월 헌금/후원 모듈) 검증용 테스트
// - 종교시설 유형(church/catholic/buddhist) org_type + offering_labels가 올바르게 동작하는지
// - 헌금 생성(POST /api/offerings) -> (토스 실결제는 시뮬레이션 불가하므로 DB에서 직접 paid로 전환) ->
//   내 헌금 내역(GET /api/offerings/my), 조직 관리자 헌금 현황(GET /api/community-admin/offerings)이
//   올바른 수치를 돌려주는지 검증한다.
// 실행 후 생성한 테스트 계정/데이터는 모두 정리(clean up)한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const ORG_ADMIN_EMAIL = `withplus.offering.orgadmin.${stamp}@withplus.test`;
const GIVER_EMAIL = `withplus.offering.giver.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';

let createdUserIds = [];
let createdCommunityId = null;
let createdOfferingIds = [];

async function createTestUser(email) {
  const { data, error } = await admin.auth.admin.createUser({ email, password: PASSWORD, email_confirm: true });
  if (error) throw new Error(`계정 생성 실패(${email}): ${error.message}`);
  createdUserIds.push(data.user.id);
  const { error: profErr } = await admin.from('profiles').upsert({ id: data.user.id, email, role: 'member' });
  if (profErr) throw new Error(`profiles 생성 실패(${email}): ${profErr.message}`);
  const client = createClient(supabaseUrl, anonKey);
  const { data: signIn, error: signInErr } = await client.auth.signInWithPassword({ email, password: PASSWORD });
  if (signInErr) throw new Error(`로그인 실패(${email}): ${signInErr.message}`);
  return { id: data.user.id, token: signIn.session.access_token };
}

async function api(path, token, options = {}) {
  const res = await fetch(BASE + path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {}),
      ...(options.headers || {})
    }
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
  for (const id of createdOfferingIds) {
    await admin.from('offering_payments').delete().eq('offering_id', id);
    await admin.from('offerings').delete().eq('id', id);
  }
  if (createdCommunityId) {
    await admin.from('community_admins_with').delete().eq('community_id', createdCommunityId);
    await admin.from('communities').delete().eq('id', createdCommunityId);
  }
  for (const id of createdUserIds) {
    await admin.from('profiles').delete().eq('id', id);
    await admin.auth.admin.deleteUser(id).catch(() => {});
  }
  console.log('--- 정리 완료 ---');
}

async function run() {
  console.log(`=== GIVE+ 헌금/후원 모듈 테스트 시작 (${new Date().toISOString()}) ===\n`);

  // 1. 종교시설 유형 목록 공개 API
  const orgTypesRes = await api('/api/offering-org-types', null);
  assert(orgTypesRes.ok && orgTypesRes.json.success, '공개 API: 종교시설 유형/기본 항목명 목록 조회 성공');
  assert(orgTypesRes.json.data.org_types.includes('buddhist') && orgTypesRes.json.data.org_types.includes('catholic'), '종교시설 유형에 불교(buddhist)/가톨릭(catholic) 포함 확인');
  assert(orgTypesRes.json.data.default_labels.buddhist.dana === '시주', '불교 기본 항목명에 "시주" 포함 확인');
  assert(orgTypesRes.json.data.default_labels.catholic.dues === '교무금', '가톨릭 기본 항목명에 "교무금" 포함 확인');

  // 2. 테스트 종교시설(불교 사찰) 커뮤니티 생성 - 종교 하드코딩 없이 org_type만으로 사찰 특화 항목명이 적용되는지 검증
  const orgAdmin = await createTestUser(ORG_ADMIN_EMAIL);
  const giver = await createTestUser(GIVER_EMAIL);

  const { data: community, error: cErr } = await admin.from('communities').insert([{
    name: `테스트사찰_${stamp}`,
    slug: `test-temple-${stamp}`,
    status: 'active',
    org_type: 'buddhist',
    offering_labels: { dana: '시주', lantern: '연등접수' },
    admin_user_id: orgAdmin.id
  }]).select().single();
  if (cErr) throw new Error('테스트 커뮤니티 생성 실패: ' + cErr.message);
  createdCommunityId = community.id;
  await admin.from('community_admins_with').insert([{ community_id: community.id, user_id: orgAdmin.id }]);
  assert(community.org_type === 'buddhist' && community.offering_labels.dana === '시주', 'DB: communities.org_type/offering_labels 저장 확인(불교 사찰)');

  // 3. 헌금(시주) 생성 - 서버가 클라이언트가 보낸 label을 신뢰하지 않고 DB의 offering_labels에서 다시 채우는지 검증
  const createRes = await api('/api/offerings', giver.token, {
    method: 'POST',
    body: JSON.stringify({
      community_slug: community.slug,
      items: [{ key: 'dana', amount: 30000, label: '위조시도라벨' }, { key: 'lantern', amount: 10000 }],
      is_anonymous: true,
      memo: '가족 건강 기원'
    })
  });
  assert(createRes.ok && createRes.json.success, 'POST /api/offerings: 헌금(시주) 생성 성공');
  const offering = createRes.json.data;
  createdOfferingIds.push(offering.id);
  assert(offering.total_amount === 40000, `총액 계산 정확성 확인(30000+10000=${offering.total_amount})`);
  assert(offering.items.find(i => i.key === 'dana').label === '시주', '서버가 클라이언트 위조 라벨을 무시하고 DB 라벨("시주")로 재기입 확인');
  assert(offering.status === 'pending', '초기 상태 pending 확인(실결제 전)');
  assert(offering.order_number.startsWith('OFR-'), '주문번호 접두어가 OFR- 로 상품주문(ORD-)과 구분됨을 확인');

  // 4. 잘못된 요청 거부 검증
  const zeroAmountRes = await api('/api/offerings', giver.token, {
    method: 'POST',
    body: JSON.stringify({ community_slug: community.slug, items: [{ key: 'dana', amount: 0 }] })
  });
  assert(zeroAmountRes.status === 400, '0원 헌금 요청 거부 확인');

  const noCommunityRes = await api('/api/offerings', giver.token, {
    method: 'POST',
    body: JSON.stringify({ community_slug: 'no-such-slug-' + stamp, items: [{ key: 'dana', amount: 1000 }] })
  });
  assert(noCommunityRes.status === 404, '존재하지 않는 조직 slug 요청 거부(404) 확인');

  // 5. 실제 토스 결제는 테스트에서 재현 불가하므로, 결제 승인 완료 상태를 DB에서 직접 시뮬레이션
  //    (POST /api/offerings/toss/confirm 자체의 "금액 위변조 방지" 로직은 서버 코드 리뷰로 별도 확인됨 - 기존
  //    /api/payments/toss/confirm과 완전히 동일한 검증 로직을 그대로 재사용했기 때문)
  await admin.from('offerings').update({ status: 'paid', payment_method: 'toss', paid_at: new Date().toISOString() }).eq('id', offering.id);

  // 6. 내 헌금 내역 조회
  const myRes = await api('/api/offerings/my', giver.token);
  assert(myRes.ok && myRes.json.success, 'GET /api/offerings/my: 내 헌금 내역 조회 성공');
  assert(myRes.json.data.length === 1 && myRes.json.data[0].id === offering.id, '내 헌금 내역에 방금 생성한 헌금이 정확히 1건 포함됨을 확인');
  assert(myRes.json.summary.total_all_time === 40000, `내 헌금 내역 합계 정확성 확인(${myRes.json.summary.total_all_time}원)`);
  assert(myRes.json.data[0].communities.org_type === 'buddhist', '내 헌금 내역에 조직 org_type(buddhist)이 함께 내려오는지 확인');

  // 7. 다른 사람의 헌금 내역이 섞이지 않는지 확인(격리)
  const orgAdminMyRes = await api('/api/offerings/my', orgAdmin.token);
  assert(orgAdminMyRes.ok && orgAdminMyRes.json.data.length === 0, '조직 관리자 본인은 헌금한 적 없으므로 본인 내역이 0건임을 확인(사용자간 데이터 격리)');

  // 8. 조직 관리자 헌금 현황 대시보드
  const caRes = await api('/api/community-admin/offerings', orgAdmin.token);
  assert(caRes.ok && caRes.json.success, 'GET /api/community-admin/offerings: 조직 관리자 헌금 현황 조회 성공');
  assert(caRes.json.data.total_all_time === 40000, `조직 헌금 누적액 정확성 확인(${caRes.json.data.total_all_time}원)`);
  assert(caRes.json.data.count === 1, '조직 헌금 누적 건수 정확성 확인(1건)');
  const danaItem = caRes.json.data.by_item.find(i => i.key === 'dana');
  const lanternItem = caRes.json.data.by_item.find(i => i.key === 'lantern');
  assert(danaItem && danaItem.total === 30000, `항목별 집계 정확성 확인(시주 30000원, 실제 ${danaItem && danaItem.total}원)`);
  assert(lanternItem && lanternItem.total === 10000, `항목별 집계 정확성 확인(연등접수 10000원, 실제 ${lanternItem && lanternItem.total}원)`);
  assert(caRes.json.data.recent[0].user_id === null, '무기명(is_anonymous) 헌금은 관리자 화면에서 user_id가 노출되지 않음을 확인');

  // 9. 조직 관리자의 헌금 항목명 커스터마이즈 API
  const putLabelsRes = await api('/api/community-admin/offering-labels', orgAdmin.token, {
    method: 'PUT',
    body: JSON.stringify({ offering_labels: { dana: '시주(보시)', lantern: '연등접수', incense: '불전함' } })
  });
  assert(putLabelsRes.ok && putLabelsRes.json.success, 'PUT /api/community-admin/offering-labels: 항목명 커스터마이즈 저장 성공');
  const { data: afterUpdate } = await admin.from('communities').select('offering_labels').eq('id', community.id).single();
  assert(afterUpdate.offering_labels.incense === '불전함', 'DB에 커스터마이즈된 항목("불전함")이 실제로 반영됨을 확인');

  // 10. 다른 사람(조직 관리자가 아닌 사람)은 조직 관리자 API에 접근할 수 없어야 함
  const forbiddenRes = await api('/api/community-admin/offerings', giver.token);
  assert(forbiddenRes.status === 404, '일반 회원(조직 관리자 아님)은 community-admin/offerings 접근 시 404(담당 조직 없음)로 거부됨을 확인');

  console.log('\n=== 전체 테스트 통과 ===');
}

run()
  .then(() => cleanup())
  .then(() => process.exit(0))
  .catch(async (err) => {
    console.error('\n💥 테스트 실패:', err.message);
    await cleanup();
    process.exit(1);
  });
