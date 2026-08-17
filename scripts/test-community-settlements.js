// 분양조직(커뮤니티) 현금 정산 기능 검증.
// - 관리자가 platform_settings로 언제든 켜고 끌 수 있는지 (기본값 꺼짐, 꺼진 동안은 생성 자체가 막힘)
// - 현금 정산은 사업자등록번호가 등록·검증된 조직만 대상이 되는지 (미등록/미검증 조직은 자동으로 제외)
// - 매출 집계(orders_with.community_id 기준) · 수수료율 스냅샷 · 상태 전환(pending→paid, 취소)이
//   공급자 정산(supplier_settlements)과 동일하게 정확히 동작하는지
// - 조회 권한이 관리자(전체, 조직 필터 가능)와 분양조직 담당자(본인 조직만) 사이에 올바르게 분리되는지
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const PASSWORD = 'WithplusTest2026!';
const SUPER_EMAIL = `withplus.cs.super.${stamp}@withplus.test`;
const STAFF_EMAIL = `withplus.cs.staff.${stamp}@withplus.test`;
const STAFF2_EMAIL = `withplus.cs.staff2.${stamp}@withplus.test`;
const CUST_EMAIL = `withplus.cs.cust.${stamp}@withplus.test`;

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌ 검증 실패:', msg); }
}

let createdUserIds = [];
let createdCommunityIds = [];
let createdOrderIds = [];
let createdProductIds = [];
let createdSettlementIds = [];

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

async function cleanup() {
  console.log('\n--- 정리 시작 ---');
  // 기능을 켰다면 원래 상태(기본 꺼짐)로 되돌려둔다
  await admin.from('platform_settings').upsert({ key: 'community_cash_settlement', value: { enabled: false } }, { onConflict: 'key' });
  for (const id of createdSettlementIds) await admin.from('community_settlements_with').delete().eq('id', id);
  for (const id of createdOrderIds) await admin.from('orders_with').delete().eq('id', id);
  for (const id of createdProductIds) await admin.from('products_with').delete().eq('id', id);
  for (const id of createdCommunityIds) {
    await admin.from('community_members').delete().eq('community_id', id);
    await admin.from('community_admins_with').delete().eq('community_id', id);
    await admin.from('communities').delete().eq('id', id);
  }
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 계정 준비 ===');
  const superAdmin = await createTestUser(SUPER_EMAIL, 'super_admin');
  const staff = await createTestUser(STAFF_EMAIL, null);
  const staff2 = await createTestUser(STAFF2_EMAIL, null);
  const cust = await createTestUser(CUST_EMAIL, null);

  // 시작 전 항상 꺼짐 상태로 초기화 (다른 테스트/수동조작의 잔여 상태 영향 배제)
  await admin.from('platform_settings').upsert({ key: 'community_cash_settlement', value: { enabled: false } }, { onConflict: 'key' });

  console.log('\n=== 0. 조직 2개 생성 (담당자 배정) ===');
  const c1Res = await api('/api/admin/communities', superAdmin.token, {
    method: 'POST',
    body: JSON.stringify({ name: `정산테스트조직-${stamp}`, slug: `cs-test-${stamp}`, admin_email: STAFF_EMAIL })
  });
  assert(c1Res.ok, `조직1 생성 성공 (status=${c1Res.status})`);
  const communityId = c1Res.json.data.id;
  createdCommunityIds.push(communityId);

  const c2Res = await api('/api/admin/communities', superAdmin.token, {
    method: 'POST',
    body: JSON.stringify({ name: `정산테스트조직2-${stamp}`, slug: `cs-test2-${stamp}`, admin_email: STAFF2_EMAIL })
  });
  assert(c2Res.ok, `조직2 생성 성공 (status=${c2Res.status})`);
  const community2Id = c2Res.json.data.id;
  createdCommunityIds.push(community2Id);

  // 구매자를 조직1의 회원으로 가입시켜야 커뮤니티 적립/집계가 발생한다
  const { error: memErr } = await admin.from('community_members').insert({ community_id: communityId, user_id: cust.id, status: 'active' });
  assert(!memErr, `구매자를 조직1 회원으로 가입 처리 성공${memErr ? ' (' + memErr.message + ')' : ''}`);

  console.log('\n=== 1. 기능 on/off 스위치 (기본 꺼짐, 관리자 전용) ===');
  const statusBefore = await api('/api/community-cash-settlement/status', staff.token);
  assert(statusBefore.ok && statusBefore.json.data.enabled === false, `기본 상태는 꺼짐 (실제: ${statusBefore.json.data?.enabled})`);

  const nonAdminToggle = await api('/api/admin/settings/community-cash-settlement', staff.token, {
    method: 'PATCH', body: JSON.stringify({ enabled: true })
  });
  assert(nonAdminToggle.status === 403, `분양조직 담당자는 기능을 켤 수 없음(관리자 전용) (실제: ${nonAdminToggle.status})`);

  console.log('\n=== 2. 꺼진 상태에서는 정산 생성이 막힘 ===');
  const todayStr = new Date().toISOString().slice(0, 10);
  const genWhileOff = await api('/api/admin/community-settlements/generate', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ startDate: todayStr, endDate: todayStr })
  });
  assert(genWhileOff.status === 403, `기능이 꺼져 있으면 정산 생성이 403으로 거부됨 (실제: ${genWhileOff.status})`);

  console.log('\n=== 3. 관리자가 기능을 켬 ===');
  const turnOn = await api('/api/admin/settings/community-cash-settlement', superAdmin.token, {
    method: 'PATCH', body: JSON.stringify({ enabled: true })
  });
  assert(turnOn.ok && turnOn.json.data.enabled === true, `관리자가 기능을 켬 (실제: ${turnOn.json.data?.enabled})`);
  const statusAfterOn = await api('/api/community-cash-settlement/status', cust.token);
  assert(statusAfterOn.json.data.enabled === true, '로그인한 아무 계정이나 켜진 상태를 조회할 수 있음(탭 노출 여부 판단용)');

  console.log('\n=== 4. 사업자등록번호 검증 - 형식 오류는 거부됨 ===');
  const badBiz = await api(`/api/admin/communities/${communityId}`, superAdmin.token, {
    method: 'PUT', body: JSON.stringify({ business_number: '123-45-6789' }) // 9자리(형식 오류)
  });
  assert(badBiz.status === 400, `형식이 잘못된 사업자등록번호는 400으로 거부됨 (실제: ${badBiz.status})`);

  console.log('\n=== 5. 사업자등록번호(체크섬 통과) 등록 - 국세청 키 없는 환경에서는 "미확인" 상태로 저장됨 ===');
  const goodFormatBiz = await api(`/api/admin/communities/${communityId}`, superAdmin.token, {
    method: 'PUT', body: JSON.stringify({ business_number: '100-00-00009' }) // 체크섬은 통과하는 테스트용 번호
  });
  assert(goodFormatBiz.ok, `형식이 올바른 사업자등록번호는 저장됨 (status=${goodFormatBiz.status})`);
  assert(goodFormatBiz.json.data.business_number === '100-00-00009', '사업자등록번호가 저장됨');
  assert(goodFormatBiz.json.data.business_number_verified === false, `NTS_API_KEY가 없는 환경이라 실시간 검증은 못하고 정직하게 미확인 상태로 남음 (실제: ${goodFormatBiz.json.data.business_number_verified})`);

  console.log('\n=== 6. 구매 발생: 조직1을 통한 주문 2건 (수량 2개+3개, 개당 20,000원 = 매출 100,000원) ===');
  const catRes = await fetch(`${BASE}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;
  const PRICE = 20000;
  const { data: prod } = await admin.from('products_with').insert({
    name: `분양정산테스트상품-${stamp}`, slug: `cs-prod-${stamp}`, description: '테스트 상품',
    price: PRICE, stock: 50, category, supplier_id: superAdmin.id, status: 'active'
  }).select().single();
  createdProductIds.push(prod.id);

  for (const qty of [2, 3]) {
    const orderRes = await api('/api/orders', cust.token, {
      method: 'POST',
      body: JSON.stringify({ items: [{ product_id: prod.id, name: prod.name, price: PRICE, quantity: qty }], community_id: communityId })
    });
    if (orderRes.json?.data?.id) createdOrderIds.push(orderRes.json.data.id);
  }
  assert(createdOrderIds.length === 2, `조직1 소속 주문 2건 생성됨 (실제: ${createdOrderIds.length}건)`);

  console.log('\n=== 7. 사업자등록이 "미확인"인 조직은 정산 생성 시 자동으로 제외됨 ===');
  const genExcluded = await api('/api/admin/community-settlements/generate', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ startDate: todayStr, endDate: todayStr })
  });
  assert(genExcluded.ok, `정산 생성 API 자체는 성공 (status=${genExcluded.status})`);
  assert(genExcluded.json.data.created === 0, `미검증 상태라 생성 건수는 0 (실제: ${genExcluded.json.data.created})`);
  const excludedEntry = (genExcluded.json.data.skippedNoBusinessNumber || []).find(s => s.community_id === communityId);
  assert(!!excludedEntry, '사업자등록 미검증으로 제외된 목록에 조직1이 포함됨(사유가 명확히 표시됨)');

  console.log('\n=== 8. (테스트 환경 한계 보완) 국세청 검증을 직접 통과시킨 뒤에는 정상적으로 정산 생성됨 ===');
  await admin.from('communities').update({ business_number_verified: true, business_number_status: '계속사업자' }).eq('id', communityId);
  const genOk = await api('/api/admin/community-settlements/generate', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ startDate: todayStr, endDate: todayStr })
  });
  assert(genOk.ok, `정산 생성 성공 (status=${genOk.status})`);
  const row1 = (genOk.json.data.rows || []).find(r => r.community_id === communityId);
  assert(!!row1, '조직1의 정산 건이 생성됨');
  createdSettlementIds.push(row1.id);
  assert(Number(row1.gross_revenue) === 100000, `매출액이 정확히 집계됨(2개+3개 x 20,000원 = 100,000원) (실제: ${row1.gross_revenue}원)`);
  assert(Number(row1.commission_rate) === 5, `수수료율을 따로 설정 안 했으면 기본값 5%가 적용됨 (실제: ${row1.commission_rate}%)`);
  assert(Number(row1.commission_amount) === 5000, `정산액(지급액)이 정확히 계산됨(100,000원 x 5% = 5,000원) (실제: ${row1.commission_amount}원)`);
  assert(Number(row1.order_count) === 2, `집계된 주문건수가 정확함(2건) (실제: ${row1.order_count}건)`);
  assert(row1.status === 'pending', `신규 생성된 정산 건의 초기 상태는 'pending' (실제: ${row1.status})`);

  console.log('\n=== 9. 조직별 수수료율을 직접 지정하면 재계산 시 반영됨 ===');
  const setRate = await api(`/api/admin/communities/${communityId}`, superAdmin.token, {
    method: 'PUT', body: JSON.stringify({ settlement_commission_rate: 8 })
  });
  assert(setRate.ok && Number(setRate.json.data.settlement_commission_rate) === 8, `조직1 수수료율을 8%로 설정 성공 (실제: ${setRate.json.data?.settlement_commission_rate}%)`);

  const regen = await api('/api/admin/community-settlements/generate', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ startDate: todayStr, endDate: todayStr })
  });
  assert(regen.json.data.updated >= 1, `pending 상태라 재생성 시 갱신(updated)됨 (실제 updated: ${regen.json.data.updated})`);
  const row1b = (regen.json.data.rows || []).find(r => r.community_id === communityId);
  assert(Number(row1b.commission_rate) === 8, `재계산 시 새 수수료율(8%)이 반영됨 (실제: ${row1b.commission_rate}%)`);
  assert(Number(row1b.commission_amount) === 8000, `재계산된 정산액도 함께 갱신됨(100,000원 x 8% = 8,000원) (실제: ${row1b.commission_amount}원)`);

  console.log('\n=== 10. 조회 권한 - 관리자는 전체(조직 필터 가능), 담당자는 본인 조직만 ===');
  const staffView = await api('/api/admin/community-settlements', staff.token);
  assert(staffView.ok, `조직1 담당자는 정산 내역 조회 가능 (실제: ${staffView.status})`);
  assert((staffView.json.data || []).every(r => r.community_id === communityId), '조직1 담당자에게는 본인 조직 정산 건만 보임');
  assert((staffView.json.data || []).some(r => r.id === row1.id), '방금 생성된 조직1 정산 건이 목록에 포함됨');

  const staff2View = await api('/api/admin/community-settlements', staff2.token);
  assert(staff2View.status === 200 && (staff2View.json.data || []).length === 0, `조직2 담당자에게는 조직1의 정산 건이 보이지 않음 (실제 건수: ${staff2View.json.data?.length})`);

  const adminFilteredView = await api(`/api/admin/community-settlements?communityId=${communityId}`, superAdmin.token);
  assert(adminFilteredView.ok && (adminFilteredView.json.data || []).every(r => r.community_id === communityId), `관리자는 조직 필터로 특정 조직 정산만 조회 가능 (실제: ${adminFilteredView.status})`);
  assert((adminFilteredView.json.data || []).some(r => r.community_name), '조직명이 함께 내려옴');

  console.log('\n=== 11. 상태 전환 - 지급완료 처리 후에는 재생성해도 건드리지 않음 ===');
  const nonAdminStatus = await api(`/api/admin/community-settlements/${row1.id}/status`, staff.token, {
    method: 'PATCH', body: JSON.stringify({ status: 'paid' })
  });
  assert(nonAdminStatus.status === 403, `분양조직 담당자는 정산 상태를 직접 바꿀 수 없음(관리자 전용) (실제: ${nonAdminStatus.status})`);

  const markPaid = await api(`/api/admin/community-settlements/${row1.id}/status`, superAdmin.token, {
    method: 'PATCH', body: JSON.stringify({ status: 'paid' })
  });
  assert(markPaid.ok && markPaid.json.data.status === 'paid', `관리자가 정산 건을 지급완료로 처리 성공 (실제: ${markPaid.json.data?.status})`);
  assert(!!markPaid.json.data.paid_at, 'paid_at(지급일시)이 기록됨');

  await api(`/api/admin/communities/${communityId}`, superAdmin.token, {
    method: 'PUT', body: JSON.stringify({ settlement_commission_rate: 50 })
  });
  const regenAfterPaid = await api('/api/admin/community-settlements/generate', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ startDate: todayStr, endDate: todayStr })
  });
  assert(regenAfterPaid.json.data.skippedPaid >= 1, `지급완료된 건은 재생성 시 건드리지 않고 건너뜀 (실제 skippedPaid: ${regenAfterPaid.json.data.skippedPaid})`);
  const { data: afterRegenRow } = await admin.from('community_settlements_with').select('*').eq('id', row1.id).single();
  assert(Number(afterRegenRow.commission_rate) === 8, `지급완료된 정산 건은 이후 수수료율 변경과 무관하게 그대로 보존됨 (실제: ${afterRegenRow.commission_rate}%)`);

  console.log('\n=== 12. 기능을 다시 끄면 새 정산 생성이 막힘(기존 데이터는 유지) ===');
  await api('/api/admin/settings/community-cash-settlement', superAdmin.token, { method: 'PATCH', body: JSON.stringify({ enabled: false }) });
  const genAfterOff = await api('/api/admin/community-settlements/generate', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ startDate: todayStr, endDate: todayStr })
  });
  assert(genAfterOff.status === 403, `다시 끄면 정산 생성이 막힘 (실제: ${genAfterOff.status})`);
  const viewAfterOff = await api('/api/admin/community-settlements', superAdmin.token);
  assert(viewAfterOff.ok && (viewAfterOff.json.data || []).some(r => r.id === row1.id), '기능을 꺼도 이미 생성된 정산 내역 조회는 계속 가능함(과거 기록 보존)');

  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exitCode = fail > 0 ? 1 : 0;
}

main()
  .catch(err => { console.error('\n💥 테스트 실행 중 오류:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
