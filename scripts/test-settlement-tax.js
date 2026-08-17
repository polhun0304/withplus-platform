// 정산 세무처리(원천징수 3.3% / 세금계산서 발행) 기능 검증.
// - "정산 지급완료" 처리와 직접 연결된 세무 의무를 자동화한 기능: 개인/프리랜서 사업자(공급자·분양조직)에게
//   지급할 때는 3.3%(소득세 3%+지방소득세 0.3%)를 원천징수하고 원천징수영수증을 발급하며,
//   법인/일반과세 사업자에게는 세금계산서 발행이 필요하다는 "발행대기" 상태를 만들어 관리자가 문서번호를
//   입력하면 "발행완료"로 넘어가는 흐름(실제 발행 자체는 홈택스/팝빌 등 외부 연동이 필요해 수동 처리).
// - 공급자 정산(supplier_settlements)과 분양조직 정산(community_settlements_with) 양쪽에 동일하게 적용됨을 검증한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const PASSWORD = 'WithplusTest2026!';
const SUPER_EMAIL = `withplus.tax.super.${stamp}@withplus.test`;
const PROVIDER_EMAIL = `withplus.tax.provider.${stamp}@withplus.test`;
const PROVIDER2_EMAIL = `withplus.tax.provider2.${stamp}@withplus.test`;
const STAFF_EMAIL = `withplus.tax.staff.${stamp}@withplus.test`;
const STAFF2_EMAIL = `withplus.tax.staff2.${stamp}@withplus.test`;
const CUST_EMAIL = `withplus.tax.cust.${stamp}@withplus.test`;

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌ 검증 실패:', msg); }
}

let createdUserIds = [];
let createdCommunityIds = [];
let createdOrderIds = [];
let createdProductIds = [];
let createdSupplierSettlementIds = [];
let createdCommunitySettlementIds = [];
let savedBusinessInfoBefore = null;

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
  for (const id of createdSupplierSettlementIds) await admin.from('supplier_settlements').delete().eq('id', id);
  for (const id of createdCommunitySettlementIds) await admin.from('community_settlements_with').delete().eq('id', id);
  for (const id of createdOrderIds) await admin.from('orders_with').delete().eq('id', id);
  for (const id of createdProductIds) await admin.from('products_with').delete().eq('id', id);
  for (const id of createdCommunityIds) {
    await admin.from('community_members').delete().eq('community_id', id);
    await admin.from('community_admins_with').delete().eq('community_id', id);
    await admin.from('communities').delete().eq('id', id);
  }
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  // 테스트 중 덮어쓴 플랫폼 사업자 정보를 원래 값으로 복원
  if (savedBusinessInfoBefore) {
    await admin.from('platform_settings').upsert({ key: 'platform_business_info', value: savedBusinessInfoBefore }, { onConflict: 'key' });
  }
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 계정 준비 ===');
  const superAdmin = await createTestUser(SUPER_EMAIL, 'super_admin');
  const provider = await createTestUser(PROVIDER_EMAIL, 'provider');
  const provider2 = await createTestUser(PROVIDER2_EMAIL, 'provider');
  const staff = await createTestUser(STAFF_EMAIL, null);
  const staff2 = await createTestUser(STAFF2_EMAIL, null);
  const cust = await createTestUser(CUST_EMAIL, null);

  const { data: existingBizInfo } = await admin.from('platform_settings').select('value').eq('key', 'platform_business_info').maybeSingle();
  savedBusinessInfoBefore = existingBizInfo ? existingBizInfo.value : { company_name: null, ceo_name: null, business_number: null, address: null };

  console.log('\n=== 1. 플랫폼 사업자 정보(원천징수의무자) 등록 - 관리자 전용 ===');
  const nonAdminBizInfo = await api('/api/admin/settings/business-info', staff.token, {
    method: 'PUT', body: JSON.stringify({ company_name: '해킹시도' })
  });
  assert(nonAdminBizInfo.status === 403, `일반 회원은 플랫폼 사업자 정보를 수정할 수 없음(관리자 전용) (실제: ${nonAdminBizInfo.status})`);

  const setBizInfo = await api('/api/admin/settings/business-info', superAdmin.token, {
    method: 'PUT', body: JSON.stringify({ company_name: '주식회사 위드플러스(테스트)', ceo_name: '홍길동', business_number: '100-00-00009', address: '서울시 테스트구' })
  });
  assert(setBizInfo.ok, `플랫폼 사업자 정보 저장 성공 (status=${setBizInfo.status})`);
  const getBizInfo = await api('/api/admin/settings/business-info', superAdmin.token);
  assert(getBizInfo.json.data.company_name === '주식회사 위드플러스(테스트)', '저장한 플랫폼 사업자 정보가 그대로 조회됨');

  console.log('\n=== 2. 공급자 정산 세무처리 방식 설정 - 기본값은 원천징수(withholding) ===');
  const providersList = await api('/api/admin/providers', superAdmin.token);
  const providerEntry = (providersList.json.data || []).find(p => p.id === provider.id);
  assert(providerEntry && providerEntry.settlement_tax_method === 'withholding', `공급자 등록 시 세무처리 방식 기본값은 'withholding' (실제: ${providerEntry?.settlement_tax_method})`);

  const badTaxMethod = await api(`/api/admin/providers/${provider.id}/commission-rate`, superAdmin.token, {
    method: 'PATCH', body: JSON.stringify({ commission_rate: 10, settlement_tax_method: 'invalid_value' })
  });
  assert(badTaxMethod.status === 400, `잘못된 세무처리 방식 값은 400으로 거부됨 (실제: ${badTaxMethod.status})`);

  const setTaxMethod = await api(`/api/admin/providers/${provider.id}/commission-rate`, superAdmin.token, {
    method: 'PATCH', body: JSON.stringify({ commission_rate: 10, settlement_tax_method: 'withholding' })
  });
  assert(setTaxMethod.ok && setTaxMethod.json.data.settlement_tax_method === 'withholding', `공급자 세무처리 방식을 명시적으로 'withholding'으로 저장 성공 (실제: ${setTaxMethod.json.data?.settlement_tax_method})`);

  console.log('\n=== 3. 공급자 매출 발생 (개당 30,000원 x 4개 = 120,000원) ===');
  const catRes = await fetch(`${BASE}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;
  const PRICE = 30000;
  const { data: prod } = await admin.from('products_with').insert({
    name: `세무테스트상품-${stamp}`, slug: `tax-prod-${stamp}`, description: '테스트 상품',
    price: PRICE, stock: 50, category, supplier_id: provider.id, status: 'active'
  }).select().single();
  createdProductIds.push(prod.id);

  const orderRes = await api('/api/orders', cust.token, {
    method: 'POST', body: JSON.stringify({ items: [{ product_id: prod.id, name: prod.name, price: PRICE, quantity: 4 }] })
  });
  if (orderRes.json?.data?.id) createdOrderIds.push(orderRes.json.data.id);
  assert(createdOrderIds.length === 1, `테스트 주문 생성됨 (실제: ${createdOrderIds.length}건)`);

  const todayStr = new Date().toISOString().slice(0, 10);
  const genRes = await api('/api/admin/settlements/generate', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ startDate: todayStr, endDate: todayStr })
  });
  assert(genRes.ok, `공급자 정산 생성 성공 (status=${genRes.status})`);
  const row1 = (genRes.json.data.rows || []).find(r => r.supplier_id === provider.id);
  assert(!!row1, '방금 만든 공급자의 정산 건이 생성됨');
  createdSupplierSettlementIds.push(row1.id);
  assert(Number(row1.commission_amount) === 12000, `수수료(정산 지급액)가 정확히 계산됨(120,000원 x 10% = 12,000원) (실제: ${row1.commission_amount}원)`);

  console.log('\n=== 4. 원천징수 대상 지급완료 처리 시 3.3% 자동 계산 ===');
  const payWithholding = await api(`/api/admin/settlements/${row1.id}/status`, superAdmin.token, {
    method: 'PATCH', body: JSON.stringify({ status: 'paid' })
  });
  assert(payWithholding.ok, `지급완료 처리 성공 (status=${payWithholding.status})`);
  const paid1 = payWithholding.json.data;
  assert(paid1.tax_method === 'withholding', `지급완료 시점의 세무처리 방식이 스냅샷으로 저장됨 (실제: ${paid1.tax_method})`);
  assert(Number(paid1.withholding_tax_rate) === 3.3, `원천징수세율은 3.3% (실제: ${paid1.withholding_tax_rate}%)`);
  const expectedWithholding = Math.round(12000 * 0.033);
  assert(Number(paid1.withholding_tax_amount) === expectedWithholding, `원천징수세액이 정확히 계산됨(12,000원 x 3.3% = ${expectedWithholding}원) (실제: ${paid1.withholding_tax_amount}원)`);
  assert(Number(paid1.net_payment_amount) === 12000 - expectedWithholding, `차인지급액(실지급액)이 정확히 계산됨 (실제: ${paid1.net_payment_amount}원)`);
  assert(paid1.tax_invoice_status === 'not_required', `원천징수 대상 건은 세금계산서 상태가 'not_required' (실제: ${paid1.tax_invoice_status})`);

  console.log('\n=== 5. 원천징수영수증 조회 - 관리자·본인은 가능, 다른 공급자는 불가 ===');
  const receiptAdmin = await api(`/api/admin/settlements/${row1.id}/withholding-receipt`, superAdmin.token);
  assert(receiptAdmin.ok, `관리자는 원천징수영수증 조회 가능 (status=${receiptAdmin.status})`);
  assert(receiptAdmin.json.data.withholder.company_name === '주식회사 위드플러스(테스트)', '영수증에 방금 저장한 플랫폼(원천징수의무자) 정보가 반영됨');
  assert(receiptAdmin.json.data.payee.email === PROVIDER_EMAIL, '영수증에 소득자(공급자) 정보가 포함됨');

  const receiptSelf = await api(`/api/admin/settlements/${row1.id}/withholding-receipt`, provider.token);
  assert(receiptSelf.ok, `공급자 본인도 자신의 원천징수영수증을 조회할 수 있음 (status=${receiptSelf.status})`);

  const receiptOther = await api(`/api/admin/settlements/${row1.id}/withholding-receipt`, provider2.token);
  assert(receiptOther.status === 403, `다른 공급자는 남의 원천징수영수증을 조회할 수 없음 (실제: ${receiptOther.status})`);

  console.log('\n=== 6. 세금계산서 발행 대상으로 전환 - 새 기간 정산 생성 및 지급완료 ===');
  const setInvoiceMethod = await api(`/api/admin/providers/${provider.id}/commission-rate`, superAdmin.token, {
    method: 'PATCH', body: JSON.stringify({ commission_rate: 10, settlement_tax_method: 'tax_invoice' })
  });
  assert(setInvoiceMethod.ok && setInvoiceMethod.json.data.settlement_tax_method === 'tax_invoice', `공급자 세무처리 방식을 '세금계산서 발행'으로 변경 성공 (실제: ${setInvoiceMethod.json.data?.settlement_tax_method})`);

  const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const genRes2 = await api('/api/admin/settlements/generate', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ startDate: yesterday, endDate: yesterday })
  });
  // 어제 날짜엔 매출이 없으므로 직접 두 번째 정산 행을 만들어 지급완료 흐름만 검증한다
  const { data: row2 } = await admin.from('supplier_settlements').insert({
    supplier_id: provider.id, period_start: yesterday, period_end: yesterday,
    order_count: 1, gross_revenue: 50000, commission_rate: 10, commission_amount: 5000, net_amount: 45000,
    status: 'pending', created_by: superAdmin.id
  }).select().single();
  createdSupplierSettlementIds.push(row2.id);

  const payInvoice = await api(`/api/admin/settlements/${row2.id}/status`, superAdmin.token, {
    method: 'PATCH', body: JSON.stringify({ status: 'paid' })
  });
  assert(payInvoice.ok, `세금계산서 대상 건도 지급완료 처리는 정상 동작 (status=${payInvoice.status})`);
  const paid2 = payInvoice.json.data;
  assert(paid2.tax_method === 'tax_invoice', `세무처리 방식이 'tax_invoice'로 스냅샷됨 (실제: ${paid2.tax_method})`);
  assert(Number(paid2.withholding_tax_amount) === 0, `세금계산서 대상은 원천징수를 하지 않음(0원) (실제: ${paid2.withholding_tax_amount}원)`);
  assert(Number(paid2.net_payment_amount) === 5000, `세금계산서 대상은 정산액 전액을 그대로 지급(공제 없음) (실제: ${paid2.net_payment_amount}원)`);
  assert(paid2.tax_invoice_status === 'pending', `세금계산서 상태가 자동으로 '발행대기'가 됨 (실제: ${paid2.tax_invoice_status})`);

  const receiptForInvoiceType = await api(`/api/admin/settlements/${row2.id}/withholding-receipt`, superAdmin.token);
  assert(receiptForInvoiceType.status === 400, `세금계산서 대상 건은 원천징수영수증을 조회할 수 없음(400) (실제: ${receiptForInvoiceType.status})`);

  console.log('\n=== 7. 세금계산서 발행완료 수동 처리 (실제 발행은 외부에서, 문서번호만 입력) ===');
  const nonAdminIssue = await api(`/api/admin/settlements/${row2.id}/tax-invoice`, provider.token, {
    method: 'PATCH', body: JSON.stringify({ tax_invoice_number: 'INV-TEST-001' })
  });
  assert(nonAdminIssue.status === 403, `공급자 본인은 세금계산서 발행완료 처리를 할 수 없음(관리자 전용) (실제: ${nonAdminIssue.status})`);

  const emptyInvoiceNumber = await api(`/api/admin/settlements/${row2.id}/tax-invoice`, superAdmin.token, {
    method: 'PATCH', body: JSON.stringify({ tax_invoice_number: '' })
  });
  assert(emptyInvoiceNumber.status === 400, `문서번호를 비워두면 400으로 거부됨 (실제: ${emptyInvoiceNumber.status})`);

  const issueInvoice = await api(`/api/admin/settlements/${row2.id}/tax-invoice`, superAdmin.token, {
    method: 'PATCH', body: JSON.stringify({ tax_invoice_number: 'INV-TEST-001' })
  });
  assert(issueInvoice.ok && issueInvoice.json.data.tax_invoice_status === 'issued', `세금계산서 발행완료 처리 성공 (실제 상태: ${issueInvoice.json.data?.tax_invoice_status})`);
  assert(issueInvoice.json.data.tax_invoice_number === 'INV-TEST-001', '입력한 문서번호가 저장됨');
  assert(!!issueInvoice.json.data.tax_invoice_issued_at, '발행일시가 기록됨');

  const reissueAttempt = await api(`/api/admin/settlements/${row2.id}/tax-invoice`, superAdmin.token, {
    method: 'PATCH', body: JSON.stringify({ tax_invoice_number: 'INV-TEST-002' })
  });
  assert(reissueAttempt.status === 400, `이미 발행완료된 건을 다시 발행 처리하면 400으로 거부됨 (실제: ${reissueAttempt.status})`);

  console.log("\n=== 8. 세무처리 '해당없음'(none) 방식 - 공제·발행 모두 필요 없음 ===");
  await api(`/api/admin/providers/${provider.id}/commission-rate`, superAdmin.token, {
    method: 'PATCH', body: JSON.stringify({ commission_rate: 10, settlement_tax_method: 'none' })
  });
  const { data: row3 } = await admin.from('supplier_settlements').insert({
    supplier_id: provider.id, period_start: yesterday, period_end: todayStr,
    order_count: 1, gross_revenue: 20000, commission_rate: 10, commission_amount: 2000, net_amount: 18000,
    status: 'pending', created_by: superAdmin.id
  }).select().single();
  createdSupplierSettlementIds.push(row3.id);
  const payNone = await api(`/api/admin/settlements/${row3.id}/status`, superAdmin.token, { method: 'PATCH', body: JSON.stringify({ status: 'paid' }) });
  assert(payNone.ok && payNone.json.data.tax_method === 'none', `'해당없음' 방식으로 지급완료 처리됨 (실제: ${payNone.json.data?.tax_method})`);
  assert(Number(payNone.json.data.withholding_tax_amount) === 0 && Number(payNone.json.data.net_payment_amount) === 2000, `'해당없음'은 공제 없이 전액 지급 처리됨 (실제 실지급액: ${payNone.json.data.net_payment_amount}원)`);
  assert(payNone.json.data.tax_invoice_status === 'not_required', `'해당없음'은 세금계산서도 필요 없음 (실제: ${payNone.json.data.tax_invoice_status})`);

  console.log('\n=== 9. 분양조직 현금 정산에도 동일하게 적용됨 ===');
  await admin.from('platform_settings').upsert({ key: 'community_cash_settlement', value: { enabled: true } }, { onConflict: 'key' });
  const commRes = await api('/api/admin/communities', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ name: `세무테스트조직-${stamp}`, slug: `tax-comm-${stamp}`, admin_email: STAFF_EMAIL, business_number: '100-00-00009' })
  });
  assert(commRes.ok, `테스트 분양조직 생성 성공 (status=${commRes.status})`);
  const communityId = commRes.json.data.id;
  createdCommunityIds.push(communityId);
  // 국세청 API 키가 없는 테스트 환경이므로 직접 검증 완료 상태로 만들어 정산 생성 조건을 충족시킨다 (기존 community-settlements 테스트와 동일한 보완 방식)
  await admin.from('communities').update({ business_number_verified: true, business_number_status: '계속사업자' }).eq('id', communityId);

  const commTaxMethod = await api(`/api/admin/communities/${communityId}`, superAdmin.token, {
    method: 'PUT', body: JSON.stringify({ settlement_tax_method: 'withholding' })
  });
  assert(commTaxMethod.ok && commTaxMethod.json.data.settlement_tax_method === 'withholding', `분양조직 세무처리 방식도 별도로 설정 가능 (실제: ${commTaxMethod.json.data?.settlement_tax_method})`);

  const { data: commRow } = await admin.from('community_settlements_with').insert({
    community_id: communityId, period_start: yesterday, period_end: todayStr,
    order_count: 1, gross_revenue: 60000, commission_rate: 5, commission_amount: 3000,
    status: 'pending', created_by: superAdmin.id
  }).select().single();
  createdCommunitySettlementIds.push(commRow.id);

  const commPay = await api(`/api/admin/community-settlements/${commRow.id}/status`, superAdmin.token, { method: 'PATCH', body: JSON.stringify({ status: 'paid' }) });
  assert(commPay.ok && commPay.json.data.tax_method === 'withholding', `분양조직 정산도 지급완료 시 세무처리 방식이 스냅샷됨 (실제: ${commPay.json.data?.tax_method})`);
  const expectedCommWithholding = Math.round(3000 * 0.033);
  assert(Number(commPay.json.data.withholding_tax_amount) === expectedCommWithholding, `분양조직 정산의 원천징수세액도 동일하게 계산됨 (실제: ${commPay.json.data.withholding_tax_amount}원)`);

  console.log('\n=== 10. 분양조직 원천징수영수증 조회 권한 - 담당자 본인 조직만, 타 조직 담당자는 불가 ===');
  const commReceiptSelf = await api(`/api/admin/community-settlements/${commRow.id}/withholding-receipt`, staff.token);
  assert(commReceiptSelf.ok, `조직 담당자 본인은 자기 조직의 원천징수영수증을 조회할 수 있음 (status=${commReceiptSelf.status})`);
  assert(commReceiptSelf.json.data.payee.name, '영수증에 소득자(조직) 정보가 포함됨');

  const commReceiptOther = await api(`/api/admin/community-settlements/${commRow.id}/withholding-receipt`, staff2.token);
  assert(commReceiptOther.status === 403, `다른 조직 담당자는 남의 조직 원천징수영수증을 조회할 수 없음 (실제: ${commReceiptOther.status})`);

  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exitCode = fail > 0 ? 1 : 0;
}

main()
  .catch(err => { console.error('\n💥 테스트 실행 중 오류:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
