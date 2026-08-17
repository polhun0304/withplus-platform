// 다채널(쇼핑몰/라이브방송/오프라인) 판매 + 재고관리 검증:
// 1) 라이브방송/오프라인 판매가 온라인 주문과 "같은" 재고 풀(adjust_stock_with)을 공유해 초과판매를 막는지
// 2) 판매 취소 시 재고가 정확히 복원되는지
// 3) 쇼핑몰이 직접 등록한 "자체재고" 상품과 공급자(provider) 상품이 공급자 정산/판매리포트에서 올바르게 구분되는지
//    (자체재고 상품의 매출이 실제로는 존재하지 않는 "공급자"에게 수수료가 나가는 것처럼 정산되면 안 됨)
// 4) 관리자가 상품의 소유(공급자↔자체재고)를 나중에 재배정할 수 있는지
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
  let superAdminId, providerId, otherProviderId, buyerId;
  let providerProductId, selfStockedProductId, otherProviderProductId;
  let offlineSaleId, liveSaleId, orderId;

  try {
    // ============================================
    // 준비: super_admin(자체재고 상품 소유자) / provider(공급자 상품 소유자) / 다른 provider / 구매자
    // ============================================
    const superAdminEmail = `test-chsale-super-${ts}@withplus-test.local`;
    const providerEmail = `test-chsale-provider-${ts}@withplus-test.local`;
    const otherProviderEmail = `test-chsale-provider2-${ts}@withplus-test.local`;
    const buyerEmail = `test-chsale-buyer-${ts}@withplus-test.local`;

    const { data: superAdminUser } = await admin.auth.admin.createUser({ email: superAdminEmail, password, email_confirm: true });
    superAdminId = superAdminUser.user.id;
    await admin.from('profiles').upsert([{ id: superAdminId, email: superAdminEmail, full_name: 'ChSaleTestSuperAdmin', role: 'super_admin' }]);

    const { data: providerUser } = await admin.auth.admin.createUser({ email: providerEmail, password, email_confirm: true });
    providerId = providerUser.user.id;
    await admin.from('profiles').upsert([{ id: providerId, email: providerEmail, full_name: 'ChSaleTestProvider', role: 'provider', commission_rate: 10 }]);

    const { data: otherProviderUser } = await admin.auth.admin.createUser({ email: otherProviderEmail, password, email_confirm: true });
    otherProviderId = otherProviderUser.user.id;
    await admin.from('profiles').upsert([{ id: otherProviderId, email: otherProviderEmail, full_name: 'ChSaleTestProvider2', role: 'provider', commission_rate: 15 }]);

    const { data: buyerUser } = await admin.auth.admin.createUser({ email: buyerEmail, password, email_confirm: true });
    buyerId = buyerUser.user.id;
    await admin.from('profiles').upsert([{ id: buyerId, email: buyerEmail, full_name: 'ChSaleTestBuyer', role: 'user' }]);

    const superAdminToken = await loginAs(superAdminEmail, password);
    const providerToken = await loginAs(providerEmail, password);
    const otherProviderToken = await loginAs(otherProviderEmail, password);
    assert(!!superAdminToken && !!providerToken && !!otherProviderToken, '테스트 계정 로그인 성공');

    const { data: providerProduct } = await admin.from('products_with').insert([{
      name: `채널테스트-공급자상품-${ts}`, slug: `chsale-provider-${ts}`, description: '테스트', price: 5000, stock: 20,
      category: 'daily', supplier_id: providerId, status: 'active'
    }]).select().single();
    providerProductId = providerProduct.id;

    const { data: selfProduct } = await admin.from('products_with').insert([{
      name: `채널테스트-자체재고상품-${ts}`, slug: `chsale-self-${ts}`, description: '테스트', price: 8000, stock: 20,
      category: 'daily', supplier_id: superAdminId, status: 'active'
    }]).select().single();
    selfStockedProductId = selfProduct.id;

    const { data: otherProviderProduct } = await admin.from('products_with').insert([{
      name: `채널테스트-타공급자상품-${ts}`, slug: `chsale-other-${ts}`, description: '테스트', price: 3000, stock: 10,
      category: 'daily', supplier_id: otherProviderId, status: 'active'
    }]).select().single();
    otherProviderProductId = otherProviderProduct.id;

    // ============================================
    // 1) 오프라인 판매 등록 — 재고 차감 + 매출 기록이 함께 원자적으로 처리되는지
    // ============================================
    const offlineRes = await fetch(`${API}/api/admin/inventory/channel-sales`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ product_id: providerProductId, channel: 'offline', quantity: 3, unit_price: 5000, channel_ref: '강남 팝업스토어' })
    });
    const offlineJson = await offlineRes.json();
    assert(offlineRes.status === 201 && offlineJson.data.total_amount === 15000 && offlineJson.data.channel === 'offline', `오프라인 판매 등록 성공, 매출 서버 계산 정확(3×5000) (실제: ${offlineRes.status}, total=${offlineJson.data && offlineJson.data.total_amount})`);
    offlineSaleId = offlineJson.data.id;

    const { data: afterOfflineProduct } = await admin.from('products_with').select('stock').eq('id', providerProductId).single();
    assert(afterOfflineProduct.stock === 17, `오프라인 판매 후 재고가 정확히 차감됨(20-3=17) (실제: ${afterOfflineProduct.stock})`);

    const { data: offlineLedger } = await admin.from('stock_adjustments_with').select('*').eq('channel_sale_id', offlineSaleId).maybeSingle();
    assert(!!offlineLedger && offlineLedger.delta === -3 && offlineLedger.scan_source === 'offline_pos', `재고원장에 오프라인 판매 이력이 채널정보(scan_source=offline_pos)와 함께 남음 (실제: delta=${offlineLedger && offlineLedger.delta}, scan_source=${offlineLedger && offlineLedger.scan_source})`);

    // ============================================
    // 2) 라이브방송 판매 등록 — 자체재고(관리자 소유) 상품에도 동일하게 동작
    // ============================================
    const liveRes = await fetch(`${API}/api/admin/inventory/channel-sales`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ product_id: selfStockedProductId, channel: 'live', quantity: 2, unit_price: 8000, channel_ref: '8/17 라이브 3회차' })
    });
    const liveJson = await liveRes.json();
    assert(liveRes.status === 201 && liveJson.data.channel === 'live' && liveJson.data.total_amount === 16000, `라이브방송 판매(자체재고 상품) 등록 성공 (실제: ${liveRes.status}, total=${liveJson.data && liveJson.data.total_amount})`);
    liveSaleId = liveJson.data.id;

    // ============================================
    // 3) 채널 간 초과판매 방지 — 같은 재고 풀을 공유하므로 오프라인에서 이미 판 만큼 라이브에서 또 팔 수 없음
    // ============================================
    const overSellRes = await fetch(`${API}/api/admin/inventory/channel-sales`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ product_id: providerProductId, channel: 'live', quantity: 999, unit_price: 5000 })
    });
    assert(overSellRes.status === 400, `재고보다 많은 채널 판매는 차단됨(초과판매 방지) (실제: ${overSellRes.status})`);

    const listAfterOversellRes = await fetch(`${API}/api/admin/inventory/channel-sales?productId=${providerProductId}`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const listAfterOversellJson = await listAfterOversellRes.json();
    assert(listAfterOversellJson.data.filter(s => s.quantity === 999).length === 0, '초과판매로 실패한 시도는 판매 기록에 남지 않음(부분 실패 방지)');

    // ============================================
    // 4) 본인 상품이 아닌 채널 판매는 거부(공급자 접근 제어)
    // ============================================
    const foreignSaleRes = await fetch(`${API}/api/admin/inventory/channel-sales`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ product_id: otherProviderProductId, channel: 'offline', quantity: 1, unit_price: 3000 })
    });
    assert(foreignSaleRes.status === 403, `다른 공급자의 상품은 채널 판매 등록 불가 (실제: ${foreignSaleRes.status})`);

    // ============================================
    // 5) 채널별 필터 조회
    // ============================================
    const offlineListRes = await fetch(`${API}/api/admin/inventory/channel-sales?channel=offline`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const offlineListJson = await offlineListRes.json();
    assert(offlineListJson.data.some(s => s.id === offlineSaleId) && !offlineListJson.data.some(s => s.id === liveSaleId), 'channel=offline 필터링 시 오프라인 판매만 반환됨');

    // ============================================
    // 6) 매출 요약(오늘) — 라이브/오프라인 합산 확인 (관리자 전용)
    // ============================================
    const summaryRes = await fetch(`${API}/api/admin/inventory/channel-sales/summary`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const summaryJson = await summaryRes.json();
    assert(summaryRes.status === 200 && summaryJson.data.offline.revenue >= 15000 && summaryJson.data.live.revenue >= 16000, `채널별 매출 요약에 오프라인/라이브 매출이 정확히 집계됨 (실제: offline=${summaryJson.data && summaryJson.data.offline.revenue}, live=${summaryJson.data && summaryJson.data.live.revenue})`);

    const summaryAsProviderRes = await fetch(`${API}/api/admin/inventory/channel-sales/summary`, { headers: { Authorization: `Bearer ${providerToken}` } });
    assert(summaryAsProviderRes.status === 403, `공급자는 채널별 매출 요약(전체 통계)을 볼 수 없음 (실제: ${summaryAsProviderRes.status})`);

    // ============================================
    // 7) 판매 취소 — 재고 복원 + 상태 변경, 중복 취소는 거부
    // ============================================
    const cancelRes = await fetch(`${API}/api/admin/inventory/channel-sales/${offlineSaleId}/cancel`, {
      method: 'PATCH', headers: { Authorization: `Bearer ${providerToken}` }
    });
    const cancelJson = await cancelRes.json();
    assert(cancelRes.status === 200 && cancelJson.data.status === 'cancelled', `채널 판매 취소 성공 (실제: ${cancelRes.status}, status=${cancelJson.data && cancelJson.data.status})`);

    const { data: afterCancelProduct } = await admin.from('products_with').select('stock').eq('id', providerProductId).single();
    assert(afterCancelProduct.stock === 20, `판매 취소 후 재고가 원래대로 복원됨(17+3=20) (실제: ${afterCancelProduct.stock})`);

    const doubleCancelRes = await fetch(`${API}/api/admin/inventory/channel-sales/${offlineSaleId}/cancel`, {
      method: 'PATCH', headers: { Authorization: `Bearer ${providerToken}` }
    });
    assert(doubleCancelRes.status === 400, `이미 취소된 판매를 다시 취소하면 거부됨 (실제: ${doubleCancelRes.status})`);

    // ============================================
    // 8) 자체재고 vs 공급자 상품 구분 — 공급자 정산/판매리포트는 role=provider 계정만 대상이어야 함
    // ============================================
    const orderNumber = `TESTORD-${ts}`;
    const { data: order } = await admin.from('orders_with').insert([{
      order_number: orderNumber, user_id: buyerId,
      items: [
        { product_id: providerProductId, name: providerProduct.name, price: 5000, quantity: 2 },
        { product_id: selfStockedProductId, name: selfProduct.name, price: 8000, quantity: 1 }
      ],
      total_price: 18000, final_price: 18000, status: 'paid'
    }]).select().single();
    orderId = order.id;

    const reportRes = await fetch(`${API}/api/admin/supplier-sales-report`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const reportJson = await reportRes.json();
    const providerRow = reportJson.data.rows.find(r => r.supplier_id === providerId);
    const selfStockedRow = reportJson.data.rows.find(r => r.supplier_id === superAdminId);
    assert(!!providerRow && providerRow.revenue >= 10000, `공급자 판매리포트에 실제 공급자(provider) 매출은 정상 집계됨 (실제: ${providerRow && providerRow.revenue})`);
    assert(!selfStockedRow, '공급자 판매리포트에 쇼핑몰 자체재고(관리자 소유) 상품의 매출은 포함되지 않음(존재하지 않는 공급자로 잡히지 않음)');

    const settleGenRes = await fetch(`${API}/api/admin/settlements/generate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ startDate: new Date(Date.now() - 86400000).toISOString().slice(0, 10), endDate: new Date(Date.now() + 86400000).toISOString().slice(0, 10) })
    });
    const settleGenJson = await settleGenRes.json();
    const settledForProvider = (settleGenJson.data.rows || []).some(r => r.supplier_id === providerId);
    const settledForSelfStocked = (settleGenJson.data.rows || []).some(r => r.supplier_id === superAdminId);
    assert(settleGenRes.status === 200 && settledForProvider, `정산 생성 시 실제 공급자에게는 정산 내역이 생성됨 (실제: ${settleGenRes.status}, 생성=${settledForProvider})`);
    assert(!settledForSelfStocked, '정산 생성 시 쇼핑몰 자체재고(관리자) 매출에는 존재하지 않는 "공급자 수수료"가 잘못 정산되지 않음');

    // ============================================
    // 9) 상품 소유 재배정 — 자체재고 ↔ 공급자 전환
    // ============================================
    const reassignRes = await fetch(`${API}/api/products/${selfStockedProductId}/supplier`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ supplier_email: providerEmail })
    });
    const reassignJson = await reassignRes.json();
    assert(reassignRes.status === 200 && reassignJson.data.supplier_id === providerId, `관리자가 자체재고 상품을 공급자에게 재배정 가능 (실제: ${reassignRes.status})`);

    const productsListRes = await fetch(`${API}/api/admin/products`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const productsListJson = await productsListRes.json();
    const reassignedRow = productsListJson.data.find(p => p.id === selfStockedProductId);
    assert(!!reassignedRow && reassignedRow.is_self_stocked === false && reassignedRow.owner_role === 'provider', `상품 목록 조회 시 재배정된 상품이 "공급자 상품"으로 정확히 표시됨 (실제: is_self_stocked=${reassignedRow && reassignedRow.is_self_stocked}, owner_role=${reassignedRow && reassignedRow.owner_role})`);

    const reassignInvalidRes = await fetch(`${API}/api/products/${selfStockedProductId}/supplier`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ supplier_email: 'not-an-existing-account@nowhere.invalid' })
    });
    assert(reassignInvalidRes.status === 400, `존재하지 않는 계정으로는 소유를 재배정할 수 없음 (실제: ${reassignInvalidRes.status})`);

    const reassignAsProviderRes = await fetch(`${API}/api/products/${providerProductId}/supplier`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ supplier_email: providerEmail })
    });
    assert(reassignAsProviderRes.status === 403, `공급자 본인은 상품 소유를 재배정할 수 없음(관리자 전용) (실제: ${reassignAsProviderRes.status})`);

    console.log(`\n결과: ${pass} passed, ${fail} failed`);
    process.exit(fail > 0 ? 1 : 0);
  } catch (err) {
    console.error('💥 테스트 실패:', err.message);
    process.exit(1);
  } finally {
    console.log('\n--- 정리 시작 ---');
    try {
      if (orderId) await admin.from('orders_with').delete().eq('id', orderId);
      if (offlineSaleId) await admin.from('channel_sales_with').delete().eq('id', offlineSaleId);
      if (liveSaleId) await admin.from('channel_sales_with').delete().eq('id', liveSaleId);
      if (providerId) await admin.from('supplier_settlements').delete().eq('supplier_id', providerId);
      if (providerProductId) await admin.from('stock_adjustments_with').delete().eq('product_id', providerProductId);
      if (selfStockedProductId) await admin.from('stock_adjustments_with').delete().eq('product_id', selfStockedProductId);
      if (otherProviderProductId) await admin.from('stock_adjustments_with').delete().eq('product_id', otherProviderProductId);
      if (providerProductId) await admin.from('products_with').delete().eq('id', providerProductId);
      if (selfStockedProductId) await admin.from('products_with').delete().eq('id', selfStockedProductId);
      if (otherProviderProductId) await admin.from('products_with').delete().eq('id', otherProviderProductId);
      if (superAdminId) await admin.auth.admin.deleteUser(superAdminId);
      if (providerId) await admin.auth.admin.deleteUser(providerId);
      if (otherProviderId) await admin.auth.admin.deleteUser(otherProviderId);
      if (buyerId) await admin.auth.admin.deleteUser(buyerId);
    } catch (e) { console.error('정리 중 오류:', e.message); }
    console.log('--- 정리 완료 ---');
  }
}

main();
