// 구매수량별 가격 옵션(products_with.quantity_price_options) 검증
// - 관리자/판매자 저장 시 형식 검증(수량 중복·0원·정수 아님 → 400), 저장/해제
// - 주문 생성(POST /api/orders) 시 서버가 권위적으로 계산:
//   · 수량이 묶음 수량과 정확히 같으면 묶음 총액
//   · 그 외 수량은 1개 가격(할인가 반영) x 수량
//   · 클라이언트가 보낸 price는 무시(조작 불가)
//   · 옵션이 없는 상품은 기존과 동일
// 실행: PORT=3102 node server.js 실행 후 → node scripts/test-quantity-price-options.js
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
const API = process.env.TEST_API || 'http://localhost:3102';

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

async function createTempUser(email, password, role, name) {
  const { data, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
  if (error) throw error;
  const id = data.user.id;
  await admin.from('profiles').upsert([{ id, email, full_name: name, role }]);
  return id;
}

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const sellerEmail = `test-qtp-seller-${ts}@withplus-test.local`;
  const custEmail = `test-qtp-cust-${ts}@withplus-test.local`;
  const createdOrderIds = [];
  const createdProductIds = [];
  const userIds = [];

  try {
    const sellerId = await createTempUser(sellerEmail, password, 'provider', 'QtpTestSeller');
    userIds.push(sellerId);
    const custId = await createTempUser(custEmail, password, 'member', 'QtpTestCustomer');
    userIds.push(custId);
    const sellerToken = await loginAs(sellerEmail, password);
    const custToken = await loginAs(custEmail, password);
    assert(!!sellerToken && !!custToken, '테스트 판매자/고객 로그인 성공');

    const catJson = await (await fetch(`${API}/api/categories`)).json();
    const category = catJson.data[0].db_category || catJson.data[0].slug;

    const authed = (token) => ({ 'Content-Type': 'application/json', Authorization: `Bearer ${token}` });
    const order = async (items) => {
      const res = await fetch(`${API}/api/orders`, { method: 'POST', headers: authed(custToken), body: JSON.stringify({ items }) });
      const json = await res.json();
      if (json.data && json.data.id) createdOrderIds.push(json.data.id);
      return { status: res.status, json };
    };

    // ============================================
    // 0) 등록(POST) 검증 - 잘못된 옵션은 상품을 만들기 전에 400으로 거절
    // ============================================
    const badPayloads = [
      { opts: [{ qty: 2, price: 50000 }, { qty: 2, price: 48000 }], why: '수량 중복' },
      { opts: [{ qty: 2, price: 0 }], why: '판매가 0원' },
      { opts: [{ qty: 1.5, price: 10000 }], why: '수량 정수 아님' },
      { opts: [{ qty: 0, price: 10000 }], why: '수량 0' },
      { opts: 'not-json', why: '형식 오류' }
    ];
    for (const b of badPayloads) {
      const res = await fetch(`${API}/api/products`, {
        method: 'POST', headers: authed(sellerToken),
        body: JSON.stringify({ name: `QTP검증-${ts}`, price: 10000, category, stock: 1, quantity_price_options: b.opts })
      });
      const json = await res.json();
      if (json.data && json.data.id) createdProductIds.push(json.data.id);
      assert(res.status === 400, `등록 시 잘못된 수량별 가격(${b.why}) → 400 거절 (실제: ${res.status} ${json.message || ''})`);
    }

    // ============================================
    // 1) 상품 준비 (정가 30,000 / 할인가 28,900) - 직접 생성 후 PUT으로 옵션 저장
    // ============================================
    const { data: prod, error: prodErr } = await admin.from('products_with').insert({
      name: `수량별가격테스트-${ts}`, slug: `qtp-test-${ts}`, description: '테스트 상품입니다',
      price: 30000, discount_price: 28900, stock: 50, category, supplier_id: sellerId, status: 'active'
    }).select().single();
    if (prodErr) throw prodErr;
    createdProductIds.push(prod.id);

    const badPut = await fetch(`${API}/api/products/${prod.id}`, {
      method: 'PUT', headers: authed(sellerToken),
      body: JSON.stringify({ quantity_price_options: [{ qty: 3, price: 70000 }, { qty: 3, price: 1 }] })
    });
    assert(badPut.status === 400, `수정 시 수량 중복 → 400 거절 (실제: ${badPut.status})`);

    const tiers = [
      { qty: 3, price: 75000, label: '3세트', badge: '' },
      { qty: 2, price: 52920, label: '2세트', badge: '구매많음' }
    ];
    const putRes = await fetch(`${API}/api/products/${prod.id}`, {
      method: 'PUT', headers: authed(sellerToken), body: JSON.stringify({ quantity_price_options: tiers })
    });
    const putJson = await putRes.json();
    assert(putRes.ok, `수량별 가격 옵션 저장 성공 (실제: ${putRes.status} ${putJson.message || ''})`);

    const detail = await (await fetch(`${API}/api/products/${prod.id}`)).json();
    const saved = detail.data && detail.data.quantity_price_options;
    assert(Array.isArray(saved) && saved.length === 2 && saved[0].qty === 2 && saved[1].qty === 3, `상품 상세 API가 quantity_price_options를 수량순으로 정렬해 내려줌 (실제: ${JSON.stringify(saved)})`);
    assert(saved && saved[0].badge === '구매많음' && saved[0].label === '2세트', '표시 이름/뱃지가 저장됨');
    assert(detail.data && 'expiry_date' in detail.data, '상품 상세 API가 expiry_date를 내려줌(유통기한 행 표시용)');

    // ============================================
    // 2) 묶음 수량(2개) 주문 - 클라이언트가 1원으로 조작해도 묶음 총액 52,920원
    // ============================================
    const o2 = await order([{ product_id: prod.id, name: prod.name, price: 1, quantity: 2 }]);
    assert(o2.status === 201, `2개 주문 생성 (실제: ${o2.status} ${o2.json.message || ''})`);
    assert(o2.json.data && Number(o2.json.data.total_price) === 52920, `2개 = 묶음가 52,920원 적용 (실제: ${o2.json.data?.total_price})`);
    const it2 = o2.json.data && o2.json.data.items[0];
    assert(it2 && Number(it2.line_total) === 52920 && Number(it2.price) === 26460, `저장된 항목 line_total=52,920 / 개당 26,460 (실제: ${it2?.line_total} / ${it2?.price})`);
    assert(it2 && it2.quantity_tier && it2.quantity_tier.qty === 2, '저장된 항목에 적용된 묶음 정보(quantity_tier) 기록');
    assert(o2.json.data && Number(o2.json.data.final_price) === Number(o2.json.data.total_price) + Number(o2.json.data.shipping_fee || 0),
      `결제금액 = 상품합계(묶음가) + 배송비(묶음가 합계 기준으로 계산) (실제: ${o2.json.data?.final_price} = ${o2.json.data?.total_price} + ${o2.json.data?.shipping_fee})`);

    // 3개 묶음 - 개당 25,000원
    const o3 = await order([{ product_id: prod.id, name: prod.name, price: 999999, quantity: 3 }]);
    assert(o3.json.data && Number(o3.json.data.total_price) === 75000, `3개 = 묶음가 75,000원 (비싸게 조작해도 무시) (실제: ${o3.json.data?.total_price})`);

    // ============================================
    // 3) 묶음에 없는 수량(4개, 1개) → 1개 가격(할인가 28,900) x 수량
    // ============================================
    const o4 = await order([{ product_id: prod.id, name: prod.name, price: 1, quantity: 4 }]);
    assert(o4.json.data && Number(o4.json.data.total_price) === 28900 * 4, `4개(묶음 없음) = 할인가 28,900 x 4 = 115,600원 (실제: ${o4.json.data?.total_price})`);
    assert(o4.json.data && o4.json.data.items[0].line_total === undefined, '묶음이 적용되지 않은 항목은 line_total 없이 기존 형식 그대로 저장');
    const o1 = await order([{ product_id: prod.id, name: prod.name, price: 1, quantity: 1 }]);
    assert(o1.json.data && Number(o1.json.data.total_price) === 28900, `1개 = 할인가 28,900원 (실제: ${o1.json.data?.total_price})`);

    // ============================================
    // 4) 옵션(variant) 가격조정과 함께 - 묶음 총액 + 조정액 x 수량
    // ============================================
    const { data: variant } = await admin.from('product_variants_with').insert({
      product_id: prod.id, name: '대용량', price_adjustment: 1000, stock: 10, is_active: true
    }).select().single();
    const ov = await order([{ product_id: prod.id, variant_id: variant.id, name: prod.name, price: 1, quantity: 2 }]);
    assert(ov.json.data && Number(ov.json.data.total_price) === 52920 + 2000, `옵션(+1,000원) 2개 = 묶음가 52,920 + 2,000 = 54,920원 (실제: ${ov.json.data?.total_price})`);
    await admin.from('product_variants_with').delete().eq('id', variant.id);

    // ============================================
    // 5) 옵션 없는 일반 상품은 기존과 동일 (정가 50,000, 할인 없음)
    // ============================================
    const { data: plain } = await admin.from('products_with').insert({
      name: `수량별가격없음테스트-${ts}`, slug: `qtp-plain-test-${ts}`, description: '테스트 상품입니다',
      price: 50000, stock: 20, category, supplier_id: sellerId, status: 'active'
    }).select().single();
    createdProductIds.push(plain.id);
    const op = await order([{ product_id: plain.id, name: plain.name, price: 1, quantity: 2 }]);
    assert(op.json.data && Number(op.json.data.total_price) === 100000, `옵션 없는 상품 2개 = 50,000 x 2 = 100,000원 (실제: ${op.json.data?.total_price})`);
    assert(op.json.data && Number(op.json.data.items[0].price) === 50000 && op.json.data.items[0].line_total === undefined, '옵션 없는 상품의 저장 형식 변화 없음(price=단가, line_total 없음)');

    // 혼합 주문: 묶음 상품 2개 + 일반 상품 1개
    const om = await order([
      { product_id: prod.id, name: prod.name, price: 1, quantity: 2 },
      { product_id: plain.id, name: plain.name, price: 1, quantity: 1 }
    ]);
    assert(om.json.data && Number(om.json.data.total_price) === 52920 + 50000, `혼합 주문 합계 = 52,920 + 50,000 = 102,920원 (실제: ${om.json.data?.total_price})`);

    // ============================================
    // 6) 옵션 해제(null) → 다시 1개 가격 x 수량
    // ============================================
    const clearRes = await fetch(`${API}/api/products/${prod.id}`, {
      method: 'PUT', headers: authed(sellerToken), body: JSON.stringify({ quantity_price_options: null })
    });
    assert(clearRes.ok, '수량별 가격 옵션 해제(null) 저장 성공');
    const { data: cleared } = await admin.from('products_with').select('quantity_price_options').eq('id', prod.id).single();
    assert(cleared && cleared.quantity_price_options === null, 'DB 값이 null로 해제됨');
    const oc = await order([{ product_id: prod.id, name: prod.name, price: 1, quantity: 2 }]);
    assert(oc.json.data && Number(oc.json.data.total_price) === 28900 * 2, `해제 후 2개 = 28,900 x 2 = 57,800원 (실제: ${oc.json.data?.total_price})`);

    // 다른 필드만 수정하면 옵션은 그대로 유지(undefined = 변경 안 함)
    await fetch(`${API}/api/products/${prod.id}`, { method: 'PUT', headers: authed(sellerToken), body: JSON.stringify({ quantity_price_options: tiers }) });
    await fetch(`${API}/api/products/${prod.id}`, { method: 'PUT', headers: authed(sellerToken), body: JSON.stringify({ spec: '500ml' }) });
    const { data: kept } = await admin.from('products_with').select('quantity_price_options').eq('id', prod.id).single();
    assert(kept && Array.isArray(kept.quantity_price_options) && kept.quantity_price_options.length === 2, '다른 필드만 수정하면 수량별 가격 옵션은 유지됨');
  } finally {
    // ============================================
    // 정리 - 이 테스트가 만든 행만 삭제
    // ============================================
    if (createdOrderIds.length) await admin.from('orders_with').delete().in('id', createdOrderIds);
    if (createdProductIds.length) {
      await admin.from('product_variants_with').delete().in('product_id', createdProductIds);
      await admin.from('stock_adjustments_with').delete().in('product_id', createdProductIds);
      await admin.from('product_price_history_with').delete().in('product_id', createdProductIds);
      await admin.from('products_with').delete().in('id', createdProductIds);
    }
    for (const uid of userIds) {
      await admin.from('profiles').delete().eq('id', uid);
      await admin.auth.admin.deleteUser(uid).catch(() => {});
    }
  }

  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => { console.error('테스트 실행 중 오류:', err); process.exit(1); });
