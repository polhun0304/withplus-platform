// 공급자 정산 시스템 기본 골격 검증: 격차분석에서 지적된 "공급자 정산 시스템 없음" 항목 해결 확인.
// 흐름: (1) provider 계정의 수수료율을 관리자가 설정 → (2) 그 provider 상품으로 고객이 주문 →
// (3) 관리자가 기간을 지정해 정산 생성 → 매출/수수료/정산액이 정확히 계산되는지, provider는 본인 것만
// 보이는지, 지급완료 처리 후에는 재생성해도 건드리지 않는지, 상태 전환이 올바른지 확인한다.
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
  const createdOrderIds = [];
  const createdProductIds = [];
  let providerId, adminId, custId, settlementId;

  try {
    // ============================================
    // 준비: provider(공급자), admin(관리자), member(구매자) 테스트 계정 + 상품
    // ============================================
    const providerEmail = `test-settle-provider-${ts}@withplus-test.local`;
    const adminEmail = `test-settle-admin-${ts}@withplus-test.local`;
    const custEmail = `test-settle-cust-${ts}@withplus-test.local`;

    const { data: provData } = await admin.auth.admin.createUser({ email: providerEmail, password, email_confirm: true });
    providerId = provData.user.id;
    await admin.from('profiles').upsert([{ id: providerId, email: providerEmail, full_name: 'SettleTestProvider', role: 'provider' }]);

    const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
    adminId = adminData.user.id;
    await admin.from('profiles').upsert([{ id: adminId, email: adminEmail, full_name: 'SettleTestAdmin', role: 'admin' }]);

    const { data: custData } = await admin.auth.admin.createUser({ email: custEmail, password, email_confirm: true });
    custId = custData.user.id;
    await admin.from('profiles').upsert([{ id: custId, email: custEmail, full_name: 'SettleTestCustomer', role: 'member' }]);

    const providerToken = await loginAs(providerEmail, password);
    const adminToken = await loginAs(adminEmail, password);
    const custToken = await loginAs(custEmail, password);
    assert(!!providerToken && !!adminToken && !!custToken, '테스트 계정(공급자/관리자/구매자) 로그인 성공');

    const catRes = await fetch(`${API}/api/categories`);
    const catJson = await catRes.json();
    const category = catJson.data[0].db_category || catJson.data[0].slug;

    const PRICE = 20000;
    const { data: prod } = await admin.from('products_with').insert({
      name: `정산테스트상품-${ts}`, slug: `settle-test-${ts}`, description: '테스트 상품입니다',
      price: PRICE, stock: 50, category, supplier_id: providerId, status: 'active'
    }).select().single();
    createdProductIds.push(prod.id);

    // ============================================
    // 1) 기본 수수료율(10%) 확인 - profiles.commission_rate 기본값
    // ============================================
    const providersRes = await fetch(`${API}/api/admin/providers`, { headers: { Authorization: `Bearer ${adminToken}` } });
    const providersJson = await providersRes.json();
    assert(providersRes.status === 200 && providersJson.success, `관리자는 공급자 목록 조회 가능 (실제: ${providersRes.status})`);
    const myProviderRow = (providersJson.data || []).find(p => p.id === providerId);
    assert(!!myProviderRow, '방금 만든 provider 계정이 목록에 포함됨');
    assert(Number(myProviderRow?.commission_rate) === 10, `신규 provider의 기본 수수료율은 10% (실제: ${myProviderRow?.commission_rate}%)`);

    const nonAdminProvidersRes = await fetch(`${API}/api/admin/providers`, { headers: { Authorization: `Bearer ${providerToken}` } });
    assert(nonAdminProvidersRes.status === 403, `공급자 계정은 전체 공급자 목록을 볼 수 없음(관리자 전용) (실제: ${nonAdminProvidersRes.status})`);

    // ============================================
    // 2) 수수료율을 15%로 변경
    // ============================================
    const rateUpdateRes = await fetch(`${API}/api/admin/providers/${providerId}/commission-rate`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ commission_rate: 15 })
    });
    const rateUpdateJson = await rateUpdateRes.json();
    assert(rateUpdateRes.status === 200 && Number(rateUpdateJson.data.commission_rate) === 15, `수수료율을 15%로 변경 성공 (실제: ${rateUpdateJson.data?.commission_rate}%)`);

    const invalidRateRes = await fetch(`${API}/api/admin/providers/${providerId}/commission-rate`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ commission_rate: 150 })
    });
    assert(invalidRateRes.status === 400, `범위를 벗어난 수수료율(150%)은 거부됨 (실제: ${invalidRateRes.status})`);

    const providerSelfRateRes = await fetch(`${API}/api/admin/providers/${providerId}/commission-rate`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ commission_rate: 1 })
    });
    assert(providerSelfRateRes.status === 403, `공급자 본인은 자신의 수수료율을 스스로 바꿀 수 없음(관리자 전용) (실제: ${providerSelfRateRes.status})`);

    // ============================================
    // 3) 주문 2건 생성 (수량 2개 + 3개, 합계 5개 x 20,000원 = 100,000원 매출)
    // ============================================
    for (const qty of [2, 3]) {
      const orderRes = await fetch(`${API}/api/orders`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
        body: JSON.stringify({ items: [{ product_id: prod.id, name: prod.name, price: PRICE, quantity: qty }] })
      });
      const orderJson = await orderRes.json();
      if (orderJson.data) createdOrderIds.push(orderJson.data.id);
    }
    assert(createdOrderIds.length === 2, `테스트 주문 2건 생성됨 (실제: ${createdOrderIds.length}건)`);

    const todayStr = new Date().toISOString().slice(0, 10);

    // ============================================
    // 4) 정산 생성 - 매출 100,000원, 수수료 15% = 15,000원, 정산액 85,000원
    // ============================================
    const genRes = await fetch(`${API}/api/admin/settlements/generate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ startDate: todayStr, endDate: todayStr })
    });
    const genJson = await genRes.json();
    assert(genRes.status === 200 && genJson.success, `정산 생성 API 성공 (실제: ${genRes.status})`);
    const createdRow = (genJson.data.rows || []).find(r => r.supplier_id === providerId);
    assert(!!createdRow, '방금 만든 provider의 정산 건이 생성됨');
    settlementId = createdRow?.id;
    assert(Number(createdRow?.gross_revenue) === 100000, `매출액이 정확히 계산됨(2개+3개 x 20,000원 = 100,000원) (실제: ${createdRow?.gross_revenue}원)`);
    assert(Number(createdRow?.commission_rate) === 15, `정산 건에 생성 시점 수수료율(15%)이 스냅샷으로 저장됨 (실제: ${createdRow?.commission_rate}%)`);
    assert(Number(createdRow?.commission_amount) === 15000, `수수료 금액이 정확히 계산됨(100,000원 x 15% = 15,000원) (실제: ${createdRow?.commission_amount}원)`);
    assert(Number(createdRow?.net_amount) === 85000, `정산액(매출-수수료)이 정확히 계산됨(100,000-15,000=85,000원) (실제: ${createdRow?.net_amount}원)`);
    assert(Number(createdRow?.order_count) === 2, `집계된 주문건수가 정확함(2건) (실제: ${createdRow?.order_count}건)`);
    assert(createdRow?.status === 'pending', `신규 생성된 정산 건의 초기 상태는 'pending'(정산대기) (실제: ${createdRow?.status})`);

    const nonAdminGenRes = await fetch(`${API}/api/admin/settlements/generate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ startDate: todayStr, endDate: todayStr })
    });
    assert(nonAdminGenRes.status === 403, `공급자 계정은 정산을 생성할 수 없음(관리자 전용) (실제: ${nonAdminGenRes.status})`);

    // ============================================
    // 5) 조회 권한 - provider는 본인 것만, admin은 전체
    // ============================================
    const providerViewRes = await fetch(`${API}/api/admin/settlements`, { headers: { Authorization: `Bearer ${providerToken}` } });
    const providerViewJson = await providerViewRes.json();
    assert(providerViewRes.status === 200, `공급자는 본인 정산 내역 조회 가능 (실제: ${providerViewRes.status})`);
    assert((providerViewJson.data || []).every(r => r.supplier_id === providerId), '공급자에게는 본인 정산 건만 보임(다른 공급자 것은 안 보임)');
    assert((providerViewJson.data || []).some(r => r.id === settlementId), '방금 생성된 본인 정산 건이 목록에 포함됨');

    const adminViewRes = await fetch(`${API}/api/admin/settlements?status=pending`, { headers: { Authorization: `Bearer ${adminToken}` } });
    const adminViewJson = await adminViewRes.json();
    assert(adminViewRes.status === 200 && (adminViewJson.data || []).some(r => r.id === settlementId), `관리자는 상태 필터(pending)로 전체 정산 내역 조회 가능 (실제: ${adminViewRes.status})`);

    // ============================================
    // 6) 재계산해도 수수료율이 바뀐 시점 이후라면 최신 수수료율로 갱신되는지(아직 pending이므로)
    // ============================================
    await fetch(`${API}/api/admin/providers/${providerId}/commission-rate`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ commission_rate: 20 })
    });
    const regenRes = await fetch(`${API}/api/admin/settlements/generate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ startDate: todayStr, endDate: todayStr })
    });
    const regenJson = await regenRes.json();
    assert(regenJson.data.updated >= 1, `pending 상태에서는 재생성 시 갱신(updated)됨 (실제 updated: ${regenJson.data.updated})`);
    const updatedRow = (regenJson.data.rows || []).find(r => r.supplier_id === providerId);
    assert(Number(updatedRow?.commission_rate) === 20, `재계산 시 최신 수수료율(20%)이 반영됨 (실제: ${updatedRow?.commission_rate}%)`);
    assert(Number(updatedRow?.commission_amount) === 20000, `재계산된 수수료 금액도 함께 갱신됨(100,000원 x 20% = 20,000원) (실제: ${updatedRow?.commission_amount}원)`);

    // ============================================
    // 7) 상태 전환 - 지급완료(paid) 처리 후에는 재생성해도 건드리지 않음(보호)
    // ============================================
    const nonAdminStatusRes = await fetch(`${API}/api/admin/settlements/${settlementId}/status`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ status: 'paid' })
    });
    assert(nonAdminStatusRes.status === 403, `공급자는 정산 상태를 직접 바꿀 수 없음(관리자 전용) (실제: ${nonAdminStatusRes.status})`);

    const markPaidRes = await fetch(`${API}/api/admin/settlements/${settlementId}/status`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ status: 'paid' })
    });
    const markPaidJson = await markPaidRes.json();
    assert(markPaidRes.status === 200 && markPaidJson.data.status === 'paid', `관리자가 정산 건을 '지급완료'로 처리 성공 (실제: ${markPaidJson.data?.status})`);
    assert(!!markPaidJson.data.paid_at, 'paid_at(지급일시)이 기록됨');

    // 수수료율을 또 바꾸고 재생성 시도 - 이미 paid이므로 절대 건드리면 안 됨
    await fetch(`${API}/api/admin/providers/${providerId}/commission-rate`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ commission_rate: 50 })
    });
    const regenAfterPaidRes = await fetch(`${API}/api/admin/settlements/generate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ startDate: todayStr, endDate: todayStr })
    });
    const regenAfterPaidJson = await regenAfterPaidRes.json();
    assert(regenAfterPaidJson.data.skippedPaid >= 1, `지급완료(paid) 처리된 건은 재생성 시 건드리지 않고 건너뜀 (실제 skippedPaid: ${regenAfterPaidJson.data.skippedPaid})`);

    const { data: afterRegenRow } = await admin.from('supplier_settlements').select('*').eq('id', settlementId).single();
    assert(Number(afterRegenRow.commission_rate) === 20, `지급완료된 정산 건의 수수료율/금액은 이후 수수료율 변경과 무관하게 그대로 보존됨 (실제: ${afterRegenRow.commission_rate}%)`);
    assert(afterRegenRow.status === 'paid', '지급완료된 정산 건의 상태도 그대로 유지됨');

    console.log(`\n결과: ${pass} passed, ${fail} failed`);
    process.exit(fail > 0 ? 1 : 0);
  } finally {
    // ============================================
    // 정리
    // ============================================
    if (settlementId) await admin.from('supplier_settlements').delete().eq('id', settlementId);
    for (const orderId of createdOrderIds) await admin.from('orders_with').delete().eq('id', orderId);
    for (const productId of createdProductIds) await admin.from('products_with').delete().eq('id', productId);
    for (const uid of [providerId, adminId, custId].filter(Boolean)) {
      await admin.from('profiles').delete().eq('id', uid);
      await admin.auth.admin.deleteUser(uid).catch(() => {});
    }
  }
}

main().catch(err => { console.error('테스트 실행 중 오류:', err); process.exit(1); });
