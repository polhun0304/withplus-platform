// 재고관리(WMS) 1~3단계 검증: 이벤트소싱 재고원장, 바코드/Lot 스캔, 창고 로케이션(Zone-Rack-Bin),
// 2D 디지털트윈 평면도, AGV 작업큐(시뮬레이션 — 실제 하드웨어 연동 아님)까지 전체 흐름을 확인한다.
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
  let superAdminId, providerId, productId, locationId, location2Id, floor2LocId, equipmentId, agvTaskId;

  try {
    // ============================================
    // 준비: super_admin / provider 테스트 계정 + 테스트 상품(옵션 없음, 초기재고 0)
    // ============================================
    const superAdminEmail = `test-wms-super-${ts}@withplus-test.local`;
    const providerEmail = `test-wms-provider-${ts}@withplus-test.local`;

    const { data: superAdminUser } = await admin.auth.admin.createUser({ email: superAdminEmail, password, email_confirm: true });
    superAdminId = superAdminUser.user.id;
    await admin.from('profiles').upsert([{ id: superAdminId, email: superAdminEmail, full_name: 'WmsTestSuperAdmin', role: 'super_admin' }]);

    const { data: providerUser } = await admin.auth.admin.createUser({ email: providerEmail, password, email_confirm: true });
    providerId = providerUser.user.id;
    await admin.from('profiles').upsert([{ id: providerId, email: providerEmail, full_name: 'WmsTestProvider', role: 'provider', commission_rate: 10 }]);

    const superAdminToken = await loginAs(superAdminEmail, password);
    const providerToken = await loginAs(providerEmail, password);
    assert(!!superAdminToken && !!providerToken, '테스트 계정 로그인 성공');

    const { data: product } = await admin.from('products_with').insert([{
      name: `WMS테스트상품-${ts}`, slug: `wms-test-${ts}`, description: '테스트', price: 10000, stock: 0,
      category: 'daily', supplier_id: providerId, status: 'active', barcode: `TESTBC-${ts}`
    }]).select().single();
    productId = product.id;

    // ============================================
    // 1) 재고원장(ledger): 바코드 스캔으로 입고 -> 이력 기록 -> 조회
    // ============================================
    const scanInRes = await fetch(`${API}/api/admin/inventory/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ product_id: productId, delta: 50, lot_number: 'LOT-001', reason: '초기 입고' })
    });
    const scanInJson = await scanInRes.json();
    assert(scanInRes.status === 200 && scanInJson.data.stock === 50, `바코드 스캔 입고 성공 (실제 재고: ${scanInJson.data && scanInJson.data.stock})`);

    const ledgerRes = await fetch(`${API}/api/admin/inventory/ledger?productId=${productId}`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const ledgerJson = await ledgerRes.json();
    const ledgerEntry = ledgerJson.data.find(e => e.lot_number === 'LOT-001');
    assert(!!ledgerEntry && ledgerEntry.delta === 50 && ledgerEntry.scan_source === 'pda_scan', '재고원장에 Lot번호/수량/출처가 정확히 기록됨');

    // ============================================
    // 2) 초과판매 방지: 재고보다 많은 출고 스캔 시 400
    // ============================================
    const overScanRes = await fetch(`${API}/api/admin/inventory/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ product_id: productId, delta: -999, reason: '초과 출고 테스트' })
    });
    assert(overScanRes.status === 400, `재고보다 많은 출고 스캔은 차단됨 (실제: ${overScanRes.status})`);

    // ============================================
    // 3) 바코드/SKU 조회(lookup)
    // ============================================
    const lookupRes = await fetch(`${API}/api/admin/inventory/lookup?code=TESTBC-${ts}`, { headers: { Authorization: `Bearer ${providerToken}` } });
    const lookupJson = await lookupRes.json();
    assert(lookupRes.status === 200 && lookupJson.data.product_id === productId, `바코드로 상품 조회 성공 (실제: ${lookupJson.data && lookupJson.data.name})`);

    const lookupMissRes = await fetch(`${API}/api/admin/inventory/lookup?code=NOTEXIST-${ts}`, { headers: { Authorization: `Bearer ${providerToken}` } });
    assert(lookupMissRes.status === 404, `존재하지 않는 바코드는 404 (실제: ${lookupMissRes.status})`);

    // ============================================
    // 4) 창고 로케이션(Zone-Rack-Bin, 2D 좌표) — 생성은 admin 이상만
    // ============================================
    const locCreateAsProviderRes = await fetch(`${API}/api/admin/inventory/locations`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ code: `A-01-${ts}`, zone: 'A' })
    });
    assert(locCreateAsProviderRes.status === 403, `공급자는 로케이션을 생성할 수 없음 (실제: ${locCreateAsProviderRes.status})`);

    const locRes = await fetch(`${API}/api/admin/inventory/locations`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ code: `A-01-${ts}`, zone: 'A', rack: '01', bin: '01', grid_x: 0, grid_y: 0, is_obstacle: false })
    });
    const locJson = await locRes.json();
    assert(locRes.status === 201, `super_admin은 로케이션 생성 가능 (실제: ${locRes.status})`);
    locationId = locJson.data.id;

    const loc2Res = await fetch(`${API}/api/admin/inventory/locations`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ code: `A-02-${ts}`, zone: 'A', rack: '02', bin: '01', grid_x: 5, grid_y: 0, is_obstacle: false })
    });
    const loc2Json = await loc2Res.json();
    location2Id = loc2Json.data.id;
    assert(loc2Res.status === 201, '두 번째 로케이션(목적지) 생성 성공');

    const dupLocRes = await fetch(`${API}/api/admin/inventory/locations`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ code: `A-01-${ts}`, zone: 'A' })
    });
    assert(dupLocRes.status === 409, `중복 로케이션 코드는 거부됨 (실제: ${dupLocRes.status})`);

    // 상품-로케이션 매핑
    const assignRes = await fetch(`${API}/api/admin/inventory/product-locations`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ product_id: productId, location_id: locationId, is_primary: true })
    });
    assert(assignRes.status === 201, `상품-로케이션 매핑 성공 (실제: ${assignRes.status})`);

    const productLocRes = await fetch(`${API}/api/admin/inventory/product-locations/${productId}`, { headers: { Authorization: `Bearer ${providerToken}` } });
    const productLocJson = await productLocRes.json();
    assert(productLocJson.data.length === 1 && productLocJson.data[0].location_id === locationId, '상품의 로케이션 조회 정상');

    // ============================================
    // 5) 2D 디지털트윈: 평면도 스냅샷
    // ============================================
    const floorplanRes = await fetch(`${API}/api/admin/inventory/floorplan`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const floorplanJson = await floorplanRes.json();
    assert(floorplanRes.status === 200 && floorplanJson.data.locations.some(l => l.id === locationId), '평면도 스냅샷에 로케이션 포함됨');

    // ============================================
    // 5-1) 디지털트윈 고도화: 다층(floor) + 랙 모양(shape)
    // ============================================
    const floor2LocRes = await fetch(`${API}/api/admin/inventory/locations`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ code: `B-01-${ts}`, zone: 'B', grid_x: 0, grid_y: 0, width: 1, height: 2, shape: 'vertical', floor: 2 })
    });
    const floor2LocJson = await floor2LocRes.json();
    assert(floor2LocRes.status === 201 && floor2LocJson.data.floor === 2 && floor2LocJson.data.shape === 'vertical', `2층 세로랙 생성 성공 (실제: ${floor2LocRes.status}, floor=${floor2LocJson.data && floor2LocJson.data.floor})`);
    floor2LocId = floor2LocJson.data.id;

    const badShapeRes = await fetch(`${API}/api/admin/inventory/locations`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ code: `BAD-${ts}`, zone: 'B', shape: 'triangle' })
    });
    assert(badShapeRes.status === 400, `잘못된 shape 값은 거부됨 (실제: ${badShapeRes.status})`);

    const floor1Res = await fetch(`${API}/api/admin/inventory/floorplan?floor=1`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const floor1Json = await floor1Res.json();
    assert(floor1Json.data.locations.every(l => (l.floor || 1) === 1) && !floor1Json.data.locations.some(l => l.id === floor2LocId), '?floor=1 필터링 시 1층 로케이션만 반환됨');

    const floor2Res = await fetch(`${API}/api/admin/inventory/floorplan?floor=2`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const floor2Json = await floor2Res.json();
    assert(floor2Json.data.locations.some(l => l.id === floor2LocId) && !floor2Json.data.locations.some(l => l.id === locationId), '?floor=2 필터링 시 2층 로케이션만 반환됨');
    assert(Array.isArray(floor2Json.data.floors) && floor2Json.data.floors.includes(1) && floor2Json.data.floors.includes(2), '평면도 응답에 존재하는 층 목록(floors)이 포함됨');

    const moveRes = await fetch(`${API}/api/admin/inventory/locations/${floor2LocId}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ grid_x: 3, grid_y: 4, width: 2 })
    });
    const moveJson = await moveRes.json();
    assert(moveRes.status === 200 && moveJson.data.grid_x === 3 && moveJson.data.width === 2, `드래그 이동/크기조절(PUT) 정상 반영 (실제: x=${moveJson.data && moveJson.data.grid_x}, width=${moveJson.data && moveJson.data.width})`);

    // ============================================
    // 6) 장비(PDA/AGV) 등록 — 모두 is_simulated=true (실제 하드웨어 아님)
    // ============================================
    const eqRes = await fetch(`${API}/api/admin/wms/equipment`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ equipment_type: 'agv', name: `테스트AGV-${ts}` })
    });
    const eqJson = await eqRes.json();
    assert(eqRes.status === 201 && eqJson.data.is_simulated === true, `AGV 장비 등록 성공(시뮬레이션 표시 확인) (실제: is_simulated=${eqJson.data && eqJson.data.is_simulated})`);
    equipmentId = eqJson.data.id;

    const eqListRes = await fetch(`${API}/api/admin/wms/equipment`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const eqListJson = await eqListRes.json();
    assert(eqListJson.data.some(e => e.id === equipmentId), '장비 목록 조회 정상');

    // ============================================
    // 7) AGV 작업 생성 — A* 경로 계산 확인 + 상태 진행(queued -> in_progress -> completed)
    // ============================================
    const taskRes = await fetch(`${API}/api/admin/wms/agv-tasks`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ equipment_id: equipmentId, from_location_id: locationId, to_location_id: location2Id, product_id: productId })
    });
    const taskJson = await taskRes.json();
    assert(taskRes.status === 201 && taskJson.data.status === 'queued', `AGV 작업 생성 성공 (실제 상태: ${taskJson.data && taskJson.data.status})`);
    assert(Array.isArray(taskJson.data.path_points) && taskJson.data.path_points.length >= 2, `A* 경로가 계산되어 저장됨 (경로 포인트 수: ${taskJson.data.path_points && taskJson.data.path_points.length})`);
    agvTaskId = taskJson.data.id;

    const advance1Res = await fetch(`${API}/api/admin/wms/agv-tasks/${agvTaskId}/advance`, { method: 'PATCH', headers: { Authorization: `Bearer ${superAdminToken}` } });
    const advance1Json = await advance1Res.json();
    assert(advance1Json.data.status === 'in_progress', `작업 상태 진행 1단계(queued->in_progress) (실제: ${advance1Json.data.status})`);

    const advance2Res = await fetch(`${API}/api/admin/wms/agv-tasks/${agvTaskId}/advance`, { method: 'PATCH', headers: { Authorization: `Bearer ${superAdminToken}` } });
    const advance2Json = await advance2Res.json();
    assert(advance2Json.data.status === 'completed' && !!advance2Json.data.completed_at, `작업 상태 진행 2단계(in_progress->completed) (실제: ${advance2Json.data.status})`);

    const eqAfterRes = await fetch(`${API}/api/admin/wms/equipment`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const eqAfterJson = await eqAfterRes.json();
    const eqAfter = eqAfterJson.data.find(e => e.id === equipmentId);
    assert(eqAfter.status === 'idle' && eqAfter.current_location_id === location2Id, `작업 완료 후 장비 상태/위치가 갱신됨 (실제: status=${eqAfter.status}, location=${eqAfter.current_location_id === location2Id})`);

    // provider는 장비/AGV 관리 권한 없음
    const eqAsProviderRes = await fetch(`${API}/api/admin/wms/equipment`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ equipment_type: 'pda', name: 'x' })
    });
    assert(eqAsProviderRes.status === 403, `공급자는 장비를 등록할 수 없음 (실제: ${eqAsProviderRes.status})`);

    // ============================================
    // 8) 인증 없이 접근 시 401
    // ============================================
    const noAuthRes = await fetch(`${API}/api/admin/inventory/ledger`);
    assert(noAuthRes.status === 401, `인증 없이는 재고원장 조회 불가 (실제: ${noAuthRes.status})`);

    console.log(`\n결과: ${pass} passed, ${fail} failed`);
    process.exit(fail > 0 ? 1 : 0);
  } catch (err) {
    console.error('💥 테스트 실패:', err.message);
    process.exit(1);
  } finally {
    console.log('\n--- 정리 시작 ---');
    try {
      if (agvTaskId) await admin.from('agv_tasks_with').delete().eq('id', agvTaskId);
      if (equipmentId) await admin.from('equipment_with').delete().eq('id', equipmentId);
      if (locationId) await admin.from('product_location_assignments_with').delete().eq('location_id', locationId);
      if (locationId) await admin.from('warehouse_locations_with').delete().eq('id', locationId);
      if (location2Id) await admin.from('warehouse_locations_with').delete().eq('id', location2Id);
      if (floor2LocId) await admin.from('warehouse_locations_with').delete().eq('id', floor2LocId);
      if (productId) await admin.from('stock_adjustments_with').delete().eq('product_id', productId);
      if (productId) await admin.from('products_with').delete().eq('id', productId);
      if (superAdminId) await admin.auth.admin.deleteUser(superAdminId);
      if (providerId) await admin.auth.admin.deleteUser(providerId);
    } catch (e) { console.error('정리 중 오류:', e.message); }
    console.log('--- 정리 완료 ---');
  }
}

main();
