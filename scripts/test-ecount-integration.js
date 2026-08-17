// 이카운트(ERP) 연동 작업 검증: 1) 상품DB 신규 필드(유통기한/규격/공급가액/부가세), 2) 창고(warehouses_with) 마스터 CRUD,
// 3) 로케이션의 warehouse_code 연결, 4) 분양조직 도장(stamp_url), 5) 기타이동(창고이동/자가사용/불량처리/재고실사).
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const PASSWORD = 'WithplusTest2026!';
const SUPER_EMAIL = `withplus.ecount.super.${stamp}@withplus.test`;
const PROVIDER_EMAIL = `withplus.ecount.provider.${stamp}@withplus.test`;

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌ 검증 실패:', msg); }
}

let createdUserIds = [];
let createdProductIds = [];
let createdWarehouseCodes = [];
let createdLocationIds = [];
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

async function cleanup() {
  console.log('\n--- 정리 시작 ---');
  for (const id of createdLocationIds) await admin.from('warehouse_locations_with').delete().eq('id', id);
  for (const code of createdWarehouseCodes) await admin.from('warehouses_with').delete().eq('code', code);
  for (const id of createdProductIds) {
    await admin.from('stock_adjustments_with').delete().eq('product_id', id);
    await admin.from('products_with').delete().eq('id', id);
  }
  for (const id of createdCommunityIds) await admin.from('communities').delete().eq('id', id);
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  console.log('=== 테스트 계정 준비 ===');
  const superAdmin = await createTestUser(SUPER_EMAIL, 'super_admin');
  const provider = await createTestUser(PROVIDER_EMAIL, 'provider');

  console.log('\n=== 1) 상품DB 신규 필드(유통기한/규격/공급가액/부가세) ===');
  {
    const { ok, json } = await api('/api/products', provider.token, {
      method: 'POST',
      body: JSON.stringify({
        name: '이카운트연동테스트상품', price: 11000, category: 'health', stock: 5,
        barcode: `TESTBC${stamp}`, expiry_date: '2029-01-01', spec: '100ml'
      })
    });
    assert(ok, `상품 생성 성공(${JSON.stringify(json.message || '')})`);
    if (ok) {
      createdProductIds.push(json.data.id);
      assert(json.data.expiry_date === '2029-01-01', '유통기한 저장 확인');
      assert(json.data.spec === '100ml', '규격 저장 확인');
      // price 11000원(부가세 포함가) -> 공급가액 10000, 부가세 1000 (10% 표준세율 역산)
      assert(Number(json.data.supply_amount) === 10000, `공급가액 자동계산 확인 (기대 10000, 실제 ${json.data.supply_amount})`);
      assert(Number(json.data.vat_amount) === 1000, `부가세 자동계산 확인 (기대 1000, 실제 ${json.data.vat_amount})`);

      const putRes = await api(`/api/products/${json.data.id}`, provider.token, {
        method: 'PUT', body: JSON.stringify({ spec: '200ml', supply_amount: 9000, vat_amount: 900 })
      });
      assert(putRes.ok, '상품 수정(spec/공급가액/부가세 직접입력) 성공');
      if (putRes.ok) {
        assert(putRes.json.data.spec === '200ml', '수정된 규격 반영 확인');
        assert(Number(putRes.json.data.supply_amount) === 9000, '수정된 공급가액(직접입력) 반영 확인');
        assert(Number(putRes.json.data.vat_amount) === 900, '수정된 부가세(직접입력) 반영 확인');
      }
    }
  }

  console.log('\n=== 2) 창고(warehouses_with) 마스터 CRUD ===');
  let testWarehouseCode = `TW${stamp % 100000}`;
  {
    const denied = await api('/api/admin/inventory/warehouses', provider.token, {
      method: 'POST', body: JSON.stringify({ code: testWarehouseCode, name: '테스트창고' })
    });
    assert(denied.status === 403, `일반 provider는 창고 생성 불가(403) - 실제 ${denied.status}`);

    const { ok, json } = await api('/api/admin/inventory/warehouses', superAdmin.token, {
      method: 'POST', body: JSON.stringify({ code: testWarehouseCode, name: '테스트창고', address: '테스트주소 123' })
    });
    assert(ok, `admin은 창고 생성 가능(${JSON.stringify(json.message || '')})`);
    if (ok) createdWarehouseCodes.push(testWarehouseCode);

    const dup = await api('/api/admin/inventory/warehouses', superAdmin.token, {
      method: 'POST', body: JSON.stringify({ code: testWarehouseCode, name: '중복코드창고' })
    });
    assert(dup.status === 409, `중복 코드는 409 반환 - 실제 ${dup.status}`);

    const list = await api('/api/admin/inventory/warehouses', provider.token);
    assert(list.ok && list.json.data.some(w => w.code === testWarehouseCode), '생성된 창고가 목록 조회(provider도 조회 가능)에 포함됨');

    const seeded = ['A1', 'A2', 'B1', 'B2', 'C'];
    assert(seeded.every(c => list.json.data.some(w => w.code === c)), `실제 이카운트 창고 5곳(A1/A2/B1/B2/C) 시드 확인`);

    const putRes = await api(`/api/admin/inventory/warehouses/${testWarehouseCode}`, superAdmin.token, {
      method: 'PUT', body: JSON.stringify({ is_active: false, address: '수정된 주소' })
    });
    assert(putRes.ok && putRes.json.data.is_active === false, '창고 비활성화 수정 확인');
    assert(putRes.json.data.address === '수정된 주소', '창고 주소 수정 확인');
  }

  console.log('\n=== 3) 로케이션의 warehouse_code 연결 ===');
  {
    const { ok, json } = await api('/api/admin/inventory/locations', superAdmin.token, {
      method: 'POST', body: JSON.stringify({ code: `LOCTEST-${stamp}`, zone: 'Z', warehouse_code: testWarehouseCode })
    });
    assert(ok, `warehouse_code를 지정한 로케이션 생성 성공(${JSON.stringify(json.message || '')})`);
    if (ok) {
      createdLocationIds.push(json.data.id);
      assert(json.data.warehouse_code === testWarehouseCode, 'warehouse_code 저장 확인');
    }
  }

  console.log('\n=== 4) 창고 삭제 방지(연결된 로케이션 있을 때) ===');
  {
    const del = await api(`/api/admin/inventory/warehouses/${testWarehouseCode}`, superAdmin.token, { method: 'DELETE' });
    assert(del.status === 409, `연결된 로케이션이 있으면 창고 삭제 거부(409) - 실제 ${del.status}`);
  }

  console.log('\n=== 5) 분양조직 도장(stamp_url) ===');
  {
    const { ok, json } = await api('/api/admin/communities', superAdmin.token, {
      method: 'POST',
      body: JSON.stringify({ name: `이카운트테스트조직${stamp}`, slug: `ecount-test-${stamp}`, stamp_url: 'https://example.com/stamp.png' })
    });
    assert(ok, `커뮤니티 생성(stamp_url 포함) 성공(${JSON.stringify(json.message || '')})`);
    if (ok) {
      createdCommunityIds.push(json.data.id);
      assert(json.data.stamp_url === 'https://example.com/stamp.png', 'stamp_url 저장 확인');

      const putRes = await api(`/api/admin/communities/${json.data.id}`, superAdmin.token, {
        method: 'PUT', body: JSON.stringify({ stamp_url: 'https://example.com/stamp2.png' })
      });
      assert(putRes.ok && putRes.json.data.stamp_url === 'https://example.com/stamp2.png', 'stamp_url 수정 확인');
    }
  }

  console.log('\n=== 6) 기타이동: 자가사용/불량처리 write-off ===');
  {
    const productId = createdProductIds[0];
    const before = await admin.from('products_with').select('stock').eq('id', productId).single();
    const { ok, json } = await api('/api/admin/inventory/write-off', superAdmin.token, {
      method: 'POST', body: JSON.stringify({ product_id: productId, category: 'defect', quantity: 2, note: '테스트 불량' })
    });
    assert(ok, `불량처리 write-off 성공(${JSON.stringify(json.message || '')})`);
    if (ok) assert(Number(json.data.stock) === Number(before.data.stock) - 2, `재고가 2 감소함 (기대 ${Number(before.data.stock) - 2}, 실제 ${json.data.stock})`);

    const badCategory = await api('/api/admin/inventory/write-off', superAdmin.token, {
      method: 'POST', body: JSON.stringify({ product_id: productId, category: 'invalid_cat', quantity: 1 })
    });
    assert(badCategory.status === 400, `잘못된 category는 400 반환 - 실제 ${badCategory.status}`);
  }

  console.log('\n=== 7) 기타이동: 재고실사(stocktake) 차이 자동보정 ===');
  {
    const productId = createdProductIds[0];
    const before = await admin.from('products_with').select('stock').eq('id', productId).single();
    const counted = Number(before.data.stock) + 3;
    const { ok, json } = await api('/api/admin/inventory/stocktake', superAdmin.token, {
      method: 'POST', body: JSON.stringify({ product_id: productId, counted_quantity: counted, note: '테스트 실사' })
    });
    assert(ok, `재고실사 반영 성공(${JSON.stringify(json.message || '')})`);
    if (ok) {
      assert(json.data.delta === 3, `차이(+3) 계산 확인 - 실제 ${json.data.delta}`);
      assert(Number(json.data.stock) === counted, `실사 수량으로 재고 일치 확인 (기대 ${counted}, 실제 ${json.data.stock})`);
    }

    // 같은 수량으로 다시 실사하면 변경 없음(delta 0)
    const noChange = await api('/api/admin/inventory/stocktake', superAdmin.token, {
      method: 'POST', body: JSON.stringify({ product_id: productId, counted_quantity: counted })
    });
    assert(noChange.ok && noChange.json.data.delta === 0, '동일 수량 재실사 시 변경 없음(delta 0) 확인');
  }

  console.log('\n=== 8) 기타이동: 창고 간 재고 이동(transfer) ===');
  {
    const productId = createdProductIds[0];
    const loc2 = await api('/api/admin/inventory/locations', superAdmin.token, {
      method: 'POST', body: JSON.stringify({ code: `LOCTEST2-${stamp}`, zone: 'Z2' })
    });
    assert(loc2.ok, '두번째 테스트 로케이션 생성 성공');
    if (loc2.ok) createdLocationIds.push(loc2.json.data.id);

    const before = await admin.from('products_with').select('stock').eq('id', productId).single();
    const { ok, json } = await api('/api/admin/inventory/transfer', superAdmin.token, {
      method: 'POST',
      body: JSON.stringify({ product_id: productId, from_location_id: createdLocationIds[0], to_location_id: createdLocationIds[1], quantity: 1 })
    });
    assert(ok, `창고 간 이동 성공(${JSON.stringify(json.message || '')})`);
    if (ok) assert(Number(json.data.stock) === Number(before.data.stock), `이동은 총 재고량을 변경하지 않음(순증감 0) - 기대 ${before.data.stock}, 실제 ${json.data.stock}`);

    const sameLocation = await api('/api/admin/inventory/transfer', superAdmin.token, {
      method: 'POST',
      body: JSON.stringify({ product_id: productId, from_location_id: createdLocationIds[0], to_location_id: createdLocationIds[0], quantity: 1 })
    });
    assert(sameLocation.status === 400, `출발/도착 동일 로케이션은 400 반환 - 실제 ${sameLocation.status}`);

    const denied = await api('/api/admin/inventory/transfer', provider.token, {
      method: 'POST',
      body: JSON.stringify({ product_id: productId, from_location_id: createdLocationIds[0], to_location_id: createdLocationIds[1], quantity: 1 })
    });
    assert(denied.status === 403, `provider는 창고이동 권한 없음(403, admin 전용) - 실제 ${denied.status}`);
  }

  console.log(`\n=== 결과: ${pass} 성공 / ${fail} 실패 ===`);
}

main()
  .catch(err => { console.error('테스트 실행 중 오류:', err); fail++; })
  .finally(async () => {
    await cleanup();
    process.exit(fail > 0 ? 1 : 0);
  });
