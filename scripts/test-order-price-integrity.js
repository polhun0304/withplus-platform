// 🔒 격차분석에서 발견한 취약점 검증: 주문 생성(POST /api/orders) 시 클라이언트가 보낸 item.price를
// 서버가 그대로 믿지 않고, DB의 실제 판매가(+옵션 가격조정)로 다시 계산하는지 확인한다.
// (수정 전에는 브라우저 요청을 조작해 임의의 가격으로 결제가 성립할 수 있었음)
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
  const custEmail = `test-priceintegrity-${ts}@withplus-test.local`;
  const password = 'TestPass123!';
  const createdOrderIds = [];
  const createdProductIds = [];

  const { data: custData } = await admin.auth.admin.createUser({ email: custEmail, password, email_confirm: true });
  const custId = custData.user.id;
  await admin.from('profiles').upsert([{ id: custId, email: custEmail, full_name: 'PriceIntegrityTestCustomer', role: 'member' }]);
  const custToken = await loginAs(custEmail, password);
  assert(!!custToken, '테스트 고객 로그인 성공');

  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;

  // ============================================
  // 1) 옵션 없는 상품 - 실제 판매가 50,000원인데 클라이언트가 1원으로 조작해서 보내는 경우
  // ============================================
  const REAL_PRICE = 50000;
  const { data: prod } = await admin.from('products_with').insert({
    name: `가격조작테스트상품-${ts}`, slug: `price-tamper-test-${ts}`, description: '테스트 상품입니다',
    price: REAL_PRICE, stock: 20, category, supplier_id: custId, status: 'active'
  }).select().single();
  createdProductIds.push(prod.id);

  const tamperedRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: prod.id, name: prod.name, price: 1, quantity: 1 }] })
  });
  const tamperedJson = await tamperedRes.json();
  assert(tamperedRes.status === 201, `가격 조작된 주문도 일단 접수는 됨 (실제: ${tamperedRes.status})`);
  if (tamperedJson.data) createdOrderIds.push(tamperedJson.data.id);
  assert(tamperedJson.data && Number(tamperedJson.data.total_price) === REAL_PRICE, `클라이언트가 1원으로 조작해도 total_price는 실제 판매가(${REAL_PRICE}원)로 서버가 재계산함 (실제: ${tamperedJson.data?.total_price})`);
  assert(tamperedJson.data && Number(tamperedJson.data.final_price) >= REAL_PRICE, `final_price도 실제 판매가 기준으로 계산됨(배송비 포함, 실제: ${tamperedJson.data?.final_price})`);
  assert(tamperedJson.data && Array.isArray(tamperedJson.data.items) && Number(tamperedJson.data.items[0].price) === REAL_PRICE, `저장된 주문 items[0].price도 조작값(1원)이 아니라 실제 판매가로 정정되어 저장됨 (실제: ${tamperedJson.data?.items?.[0]?.price})`);
  assert(tamperedJson.mileage && tamperedJson.mileage.personal > 0, `마일리지 적립도 조작가(1원)가 아닌 실제 결제금액 기준으로 계산되어 0보다 큼 (실제: ${tamperedJson.mileage?.personal})`);

  // 반대 방향(더 비싸게 조작해서 판매자에게 유리하게 만드는 것)도 막히는지 확인
  const overpriceRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: prod.id, name: prod.name, price: 999999999, quantity: 1 }] })
  });
  const overpriceJson = await overpriceRes.json();
  if (overpriceJson.data) createdOrderIds.push(overpriceJson.data.id);
  assert(overpriceJson.data && Number(overpriceJson.data.total_price) === REAL_PRICE, `반대로 비싸게 조작해도(999,999,999원) 실제 판매가로만 계산됨 (실제: ${overpriceJson.data?.total_price})`);

  // ============================================
  // 2) 옵션(가격조정) 있는 상품 - 옵션가(+1,000원)까지 정확히 서버가 계산하는지, 클라이언트 조작가는 무시되는지
  // ============================================
  const { data: prodWithVariant } = await admin.from('products_with').insert({
    name: `가격조작테스트옵션상품-${ts}`, slug: `price-tamper-variant-test-${ts}`, description: '테스트 상품입니다',
    price: REAL_PRICE, stock: 20, category, supplier_id: custId, status: 'active'
  }).select().single();
  createdProductIds.push(prodWithVariant.id);
  const { data: variant } = await admin.from('product_variants_with').insert({
    product_id: prodWithVariant.id, name: '대형', price_adjustment: 1000, stock: 10, is_active: true
  }).select().single();

  const variantTamperedRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${custToken}` },
    body: JSON.stringify({ items: [{ product_id: prodWithVariant.id, variant_id: variant.id, name: prodWithVariant.name, price: 100, quantity: 2 }] })
  });
  const variantTamperedJson = await variantTamperedRes.json();
  if (variantTamperedJson.data) createdOrderIds.push(variantTamperedJson.data.id);
  const expectedUnitPrice = REAL_PRICE + 1000;
  assert(variantTamperedRes.status === 201 && Number(variantTamperedJson.data.total_price) === expectedUnitPrice * 2, `옵션 가격조정(+1,000원) 포함해 서버가 정확히 재계산함: ${expectedUnitPrice} x 2 = ${expectedUnitPrice * 2}원 (실제: ${variantTamperedJson.data?.total_price})`);
  assert(variantTamperedJson.data.items[0].name.includes('대형'), `저장된 items[0].name에 옵션명이 정확히 포함됨 (실제: ${variantTamperedJson.data?.items?.[0]?.name})`);

  // ============================================
  // 정리
  // ============================================
  if (createdOrderIds.length) await admin.from('orders_with').delete().in('id', createdOrderIds);
  if (createdProductIds.length) {
    await admin.from('product_variants_with').delete().in('product_id', createdProductIds);
    await admin.from('stock_adjustments_with').delete().in('product_id', createdProductIds);
    await admin.from('products_with').delete().in('id', createdProductIds);
  }
  await admin.from('profiles').delete().eq('id', custId);
  await admin.auth.admin.deleteUser(custId).catch(() => {});

  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => { console.error('테스트 실행 중 오류:', err); process.exit(1); });
