// 코드 자동채번 기능 검증: 상품 바코드/로케이션 코드/창고 코드/쿠폰 코드가
// 1) 서버가 실제 DB를 확인해 중복 없는 값만 추천하는지, 2) 직접 입력해도 중복이면 저장 시 막히는지 검증한다.
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const PASSWORD = 'WithplusTest2026!';
const SUPER_EMAIL = `withplus.codegen.super.${stamp}@withplus.test`;

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌ 검증 실패:', msg); }
}

let createdUserIds = [];
let createdProductIds = [];
let createdWarehouseCodes = [];
let createdLocationIds = [];
let createdCouponIds = [];

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
  for (const id of createdLocationIds) await admin.from('warehouse_locations_with').delete().eq('id', id);
  for (const code of createdWarehouseCodes) await admin.from('warehouses_with').delete().eq('code', code);
  for (const id of createdProductIds) {
    await admin.from('stock_adjustments_with').delete().eq('product_id', id);
    await admin.from('products_with').delete().eq('id', id);
  }
  for (const id of createdCouponIds) await admin.from('coupons').delete().eq('id', id);
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  const superAdmin = await createTestUser(SUPER_EMAIL, 'super_admin');

  // ---- 1) 상품 바코드 자동채번 ----
  const s1 = await api('/api/admin/products/suggest-barcode', superAdmin.token);
  assert(s1.ok && /^P\d{6}$/.test(s1.json.data.barcode), `상품 바코드 자동채번 형식(P + 6자리): ${s1.json.data && s1.json.data.barcode}`);

  const created = await admin.from('products_with').insert([{
    name: `자동채번테스트상품-${stamp}`, slug: `codegen-test-${stamp}`, description: 'test', price: 1000, category: 'lifestyle',
    stock: 0, barcode: s1.json.data.barcode, status: 'inactive', supplier_id: superAdmin.id
  }]).select().single();
  assert(!created.error, '자동채번된 바코드로 상품 직접 생성(DB) 성공');
  if (created.data) createdProductIds.push(created.data.id);

  const s2 = await api('/api/admin/products/suggest-barcode', superAdmin.token);
  assert(s2.ok && s2.json.data.barcode !== s1.json.data.barcode, `두 번째 제안은 이미 쓰인 첫 번째 값과 겹치지 않음(${s1.json.data.barcode} → ${s2.json.data.barcode})`);

  const dupCheck = await api('/api/admin/products/check-barcode?barcode=' + encodeURIComponent(s1.json.data.barcode), superAdmin.token);
  assert(dupCheck.ok && dupCheck.json.data.available === false, '이미 사용 중인 바코드는 check-barcode에서 available=false로 확인됨');

  const availCheck = await api('/api/admin/products/check-barcode?barcode=ZZZ999999NOTUSED', superAdmin.token);
  assert(availCheck.ok && availCheck.json.data.available === true, '사용된 적 없는 바코드는 available=true로 확인됨');

  // API를 통한 신규 상품 등록 시 같은 바코드를 쓰면 409로 거부되는지 (DB unique 제약 검증)
  const dupCreate = await api('/api/products', superAdmin.token, {
    method: 'POST',
    body: JSON.stringify({ name: '중복바코드테스트', price: 1000, category: 'lifestyle', barcode: s1.json.data.barcode })
  });
  assert(dupCreate.status === 409, `동일 바코드로 상품 등록 시도 시 409 Conflict 반환됨 (status=${dupCreate.status})`);
  if (dupCreate.json && dupCreate.json.data && dupCreate.json.data.id) createdProductIds.push(dupCreate.json.data.id);

  // ---- 2) 로케이션 코드 자동채번 ----
  const zone = `TZ${stamp}`.slice(0, 8);
  const l1 = await api(`/api/admin/inventory/locations/suggest-code?zone=${zone}&floor=1&sub_level=1`, superAdmin.token);
  assert(l1.ok && l1.json.data.code.startsWith(zone.toUpperCase() + '-11-'), `로케이션 코드 자동채번 형식: ${l1.json.data && l1.json.data.code}`);

  const locCreated = await admin.from('warehouse_locations_with').insert([{ code: l1.json.data.code, zone, floor: 1, sub_level: 1 }]).select().single();
  assert(!locCreated.error, '자동채번된 로케이션 코드로 직접 생성(DB) 성공');
  if (locCreated.data) createdLocationIds.push(locCreated.data.id);

  const l2 = await api(`/api/admin/inventory/locations/suggest-code?zone=${zone}&floor=1&sub_level=1`, superAdmin.token);
  assert(l2.ok && l2.json.data.code !== l1.json.data.code, `같은 구역/층/단에서 두 번째 제안은 겹치지 않음(${l1.json.data.code} → ${l2.json.data.code})`);

  const locDupCheck = await api('/api/admin/inventory/locations/check-code?code=' + encodeURIComponent(l1.json.data.code), superAdmin.token);
  assert(locDupCheck.ok && locDupCheck.json.data.available === false, '이미 사용 중인 로케이션 코드는 available=false');

  const locDupCreate = await api('/api/admin/inventory/locations', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ code: l1.json.data.code, zone })
  });
  assert(locDupCreate.status === 409, `동일 로케이션 코드로 등록 시도 시 409 반환됨 (status=${locDupCreate.status})`);

  // ---- 3) 창고 코드 자동채번 ----
  const w1 = await api('/api/admin/inventory/warehouses/suggest-code', superAdmin.token);
  assert(w1.ok && /^WH\d{2,}$/.test(w1.json.data.code), `창고 코드 자동채번 형식(WH + 숫자): ${w1.json.data && w1.json.data.code}`);

  const whCreate = await api('/api/admin/inventory/warehouses', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ code: w1.json.data.code, name: `자동채번테스트창고-${stamp}` })
  });
  assert(whCreate.ok, '자동채번된 창고 코드로 창고 등록 성공');
  if (whCreate.ok) createdWarehouseCodes.push(w1.json.data.code);

  const w2 = await api('/api/admin/inventory/warehouses/suggest-code', superAdmin.token);
  assert(w2.ok && w2.json.data.code !== w1.json.data.code, `두 번째 창고 코드 제안은 겹치지 않음(${w1.json.data.code} → ${w2.json.data.code})`);

  const whDupCreate = await api('/api/admin/inventory/warehouses', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ code: w1.json.data.code, name: '중복창고' })
  });
  assert(whDupCreate.status === 409, `동일 창고 코드로 등록 시도 시 409 반환됨 (status=${whDupCreate.status})`);

  // ---- 4) 쿠폰 코드 자동채번 ----
  const c1 = await api('/api/admin/coupons/suggest-code', superAdmin.token);
  assert(c1.ok && /^[A-Z0-9]{8}$/.test(c1.json.data.code), `쿠폰 코드 자동채번 형식(8자리): ${c1.json.data && c1.json.data.code}`);

  const couponCreate = await api('/api/admin/coupons', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ code: c1.json.data.code, label: '자동채번테스트쿠폰', discount_type: 'fixed', discount_value: 1000 })
  });
  assert(couponCreate.ok, '자동채번된 쿠폰 코드로 쿠폰 발급 성공');
  if (couponCreate.ok) createdCouponIds.push(couponCreate.json.data.id);

  const c2 = await api('/api/admin/coupons/suggest-code', superAdmin.token);
  assert(c2.ok && c2.json.data.code !== c1.json.data.code, `두 번째 쿠폰 코드 제안은 겹치지 않음(충돌 시 서버가 재시도) (${c1.json.data.code} → ${c2.json.data.code})`);

  const couponDupCreate = await api('/api/admin/coupons', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ code: c1.json.data.code, label: '중복쿠폰', discount_type: 'fixed', discount_value: 1000 })
  });
  assert(couponDupCreate.status === 409, `동일 쿠폰 코드로 발급 시도 시 409 반환됨 (status=${couponDupCreate.status})`);

  console.log(`\n=== 결과: ${pass} 통과 / ${fail} 실패 ===`);
  if (fail > 0) process.exitCode = 1;
}

main()
  .catch(err => { console.error('테스트 실행 중 오류:', err); process.exitCode = 1; })
  .finally(() => cleanup());
