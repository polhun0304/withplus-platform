// 상품 옵션(사이즈/색상 등) + 재고관리 고도화 검증용 임시 테스트.
// - 옵션이 있는 상품은 주문 시 옵션 선택 강제 + 재고가 원자적으로 차감되는지
// - 재고 부족 시 주문이 막히는지 (409/400)
// - 옵션이 있는 상품은 상품 자체 stock이 옵션 재고 합계로 동기화되는지
// - 관리자 재고조정(입출고 이력)이 정상 동작하는지
// 검증 후 생성한 데이터는 모두 정리한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const SUPPLIER_EMAIL = `withplus.variant.supplier.${stamp}@withplus.test`;
const BUYER_EMAIL = `withplus.variant.buyer.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';

let createdUserIds = [];
let createdProductIds = [];
let createdOrderIds = [];

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
  for (const id of createdOrderIds) {
    await admin.from('stock_adjustments_with').delete().eq('order_id', id);
    await admin.from('orders_with').delete().eq('id', id);
  }
  for (const id of createdProductIds) {
    await admin.from('stock_adjustments_with').delete().eq('product_id', id);
    await admin.from('product_variants_with').delete().eq('product_id', id);
    await admin.from('products_with').delete().eq('id', id);
  }
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 계정 준비 ===');
  const supplier = await createTestUser(SUPPLIER_EMAIL, 'provider');
  const buyer = await createTestUser(BUYER_EMAIL, null);

  console.log('\n=== 1. 옵션이 있는 상품 생성 및 옵션 등록 ===');
  const createProduct = await api('/api/products', supplier.token, {
    method: 'POST',
    body: JSON.stringify({ name: `옵션테스트상품-${stamp}`, price: 10000, category: 'fashion', stock: 0 })
  });
  assert(createProduct.ok, `상품 생성 성공 (status=${createProduct.status})`);
  const productId = createProduct.json.data.id;
  createdProductIds.push(productId);

  const addVariantS = await api(`/api/admin/products/${productId}/variants`, supplier.token, {
    method: 'POST',
    body: JSON.stringify({ name: '블랙 / S', price_adjustment: 0, stock: 3 })
  });
  assert(addVariantS.ok, `옵션(블랙/S) 등록 성공 (status=${addVariantS.status})`);
  const variantSId = addVariantS.json.data.id;

  const addVariantL = await api(`/api/admin/products/${productId}/variants`, supplier.token, {
    method: 'POST',
    body: JSON.stringify({ name: '블랙 / L', price_adjustment: 1000, stock: 1 })
  });
  assert(addVariantL.ok, `옵션(블랙/L) 등록 성공 (status=${addVariantL.status})`);
  const variantLId = addVariantL.json.data.id;

  console.log('\n=== 2. 상품 stock이 옵션 재고 합계(3+1=4)로 동기화됨 ===');
  const productAfterVariants = await api(`/api/products/${productId}`, null);
  assert(productAfterVariants.json.data.stock === 4, `상품 stock이 옵션 합계로 동기화됨 (실제=${productAfterVariants.json.data.stock})`);
  assert(productAfterVariants.json.data.variants.length === 2, `상품 조회 시 variants 2건 포함됨 (실제=${productAfterVariants.json.data.variants.length})`);

  console.log('\n=== 3. 옵션이 있는 상품을 옵션 없이 주문하면 거부됨 ===');
  const noVariantOrder = await api('/api/orders', buyer.token, {
    method: 'POST',
    body: JSON.stringify({ items: [{ product_id: productId, name: '옵션테스트상품', price: 10000, quantity: 1 }] })
  });
  assert(noVariantOrder.status === 400, `옵션 미선택 주문은 400 (실제=${noVariantOrder.status})`);
  assert(noVariantOrder.json.message.includes('옵션을 선택'), `에러 메시지가 옵션 선택 안내를 포함함 (실제="${noVariantOrder.json.message}")`);

  console.log('\n=== 4. 재고보다 많은 수량 주문 시 거부됨 (L옵션 재고=1, 주문수량=5) ===');
  const overOrder = await api('/api/orders', buyer.token, {
    method: 'POST',
    body: JSON.stringify({ items: [{ product_id: productId, variant_id: variantLId, name: '옵션테스트상품(블랙 / L)', price: 11000, quantity: 5 }] })
  });
  assert(overOrder.status === 400, `재고 초과 주문은 400 (실제=${overOrder.status})`);

  console.log('\n=== 5. 정상 주문 시 해당 옵션 재고가 원자적으로 차감됨 ===');
  const goodOrder = await api('/api/orders', buyer.token, {
    method: 'POST',
    body: JSON.stringify({ items: [{ product_id: productId, variant_id: variantSId, name: '옵션테스트상품(블랙 / S)', price: 10000, quantity: 2 }] })
  });
  assert(goodOrder.ok, `정상 주문 성공 (status=${goodOrder.status})`);
  createdOrderIds.push(goodOrder.json.data.id);

  const variantsAfter = await api(`/api/admin/products/${productId}/variants`, supplier.token);
  const sVariant = variantsAfter.json.data.find(v => v.id === variantSId);
  assert(sVariant.stock === 1, `S옵션 재고가 3->1로 차감됨 (실제=${sVariant.stock})`);

  const productAfterOrder = await api(`/api/products/${productId}`, null);
  assert(productAfterOrder.json.data.stock === 2, `상품 stock도 재동기화됨(1+1=2) (실제=${productAfterOrder.json.data.stock})`);

  console.log('\n=== 6. 재고 조정 이력이 남음 ===');
  const history = await api(`/api/admin/products/${productId}/stock-adjustments`, supplier.token);
  assert(history.ok, `재고 이력 조회 성공 (status=${history.status})`);
  assert(history.json.data.some(h => h.delta === -2), `-2 차감 이력이 기록됨`);

  console.log('\n=== 7. 남은 재고를 넘는 동시 주문 재검증 (S옵션 재고=1, 3개 주문 시도) ===');
  const secondOverOrder = await api('/api/orders', buyer.token, {
    method: 'POST',
    body: JSON.stringify({ items: [{ product_id: productId, variant_id: variantSId, name: '옵션테스트상품(블랙 / S)', price: 10000, quantity: 3 }] })
  });
  assert(secondOverOrder.status === 400, `재고 부족 재주문 거부됨 (실제=${secondOverOrder.status})`);

  console.log('\n=== 8. 옵션이 없는 일반 상품은 관리자 수동 재고조정(+/-)이 가능함 ===');
  const plainProduct = await api('/api/products', supplier.token, {
    method: 'POST',
    body: JSON.stringify({ name: `일반재고상품-${stamp}`, price: 5000, category: 'fashion', stock: 10 })
  });
  assert(plainProduct.ok, `일반 상품 생성 성공 (status=${plainProduct.status})`);
  const plainProductId = plainProduct.json.data.id;
  createdProductIds.push(plainProductId);

  const manualAdjust = await api('/api/admin/stock-adjustments', supplier.token, {
    method: 'POST',
    body: JSON.stringify({ product_id: plainProductId, delta: -3, reason: '테스트 출고' })
  });
  assert(manualAdjust.ok, `수동 재고 조정 성공 (status=${manualAdjust.status})`);
  const plainAfter = await api(`/api/products/${plainProductId}`, null);
  assert(plainAfter.json.data.stock === 7, `수동 조정 후 재고 10->7 (실제=${plainAfter.json.data.stock})`);

  const overManualAdjust = await api('/api/admin/stock-adjustments', supplier.token, {
    method: 'POST',
    body: JSON.stringify({ product_id: plainProductId, delta: -100, reason: '과도한 출고 시도' })
  });
  assert(overManualAdjust.status === 400, `재고보다 많은 수동 출고는 거부됨 (실제=${overManualAdjust.status})`);

  console.log('\n=== 9. 재고 임박(5개 이하) 목록에 노출됨 ===');
  const lowStock = await api('/api/admin/low-stock?threshold=5', supplier.token);
  assert(lowStock.ok, `재고 임박 목록 조회 성공 (status=${lowStock.status})`);
  const foundLowVariant = lowStock.json.data.variants.some(v => v.id === variantLId);
  assert(foundLowVariant, `L옵션(재고1개)이 재고임박 목록에 포함됨`);

  console.log('\n🎉 모든 검증 통과');
}

main()
  .catch(err => { console.error('\n💥 테스트 실패:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
