// 📊 재고 현황판(/api/admin/wms/stock-report) 검증 — 읽기 전용 집계 API
// 임시 super_admin / provider 계정만 만들고(끝나면 삭제) 실제 상품·주문 데이터는 건드리지 않는다.
// 실행: PORT=3103 node server.js 를 띄운 뒤 `API=http://localhost:3103 node scripts/test-wms-stock-report.js`
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const admin = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY);
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const API = process.env.API || 'http://localhost:3103';

let pass = 0, fail = 0;
function assert(cond, msg) { if (cond) { pass++; console.log('✅', msg); } else { fail++; console.log('❌', msg); } }

async function loginAs(email, password) {
  const res = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', apikey: anonKey }, body: JSON.stringify({ email, password })
  });
  return (await res.json()).access_token;
}
async function get(path, token) {
  const t = Date.now();
  const res = await fetch(API + path, { headers: { Authorization: `Bearer ${token}` } });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json, ms: Date.now() - t };
}

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const created = [];
  const fixtures = { product: null, orders: [], sales: [] };
  try {
    const mk = async (role) => {
      const email = `test-wmsrep-${role}-${ts}@withplus-test.local`;
      const { data } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
      created.push(data.user.id);
      await admin.from('profiles').upsert([{ id: data.user.id, email, full_name: `WmsReport${role}`, role }]);
      return loginAs(email, password);
    };
    const adminToken = await mk('super_admin');
    const providerToken = await mk('provider');
    assert(adminToken && providerToken, '임시 계정 로그인');

    // 1) 기본(최근 14일)
    let r = await get('/api/admin/wms/stock-report', adminToken);
    assert(r.status === 200 && r.json.success, `기본 조회 200 (${r.ms}ms)`);
    const d = r.json.data;
    console.log(`   기간 ${d.range.from}~${d.range.to} (${d.range.days}일), 상품 ${d.totals.products}개, 총 현수량 ${d.totals.stock}, 기간출고 ${d.totals.period_total}, 권장발주 합 ${d.totals.reorder_qty}, 서버 ${d.elapsed_ms}ms`);
    assert(d.day_columns.length === 14, '날짜 컬럼 14개');
    assert(d.rows.every((x, i, a) => i === 0 || a[i - 1].stock >= x.stock), '현수량 내림차순 정렬');
    assert(d.options.warehouses.length > 0, `위치 선택지 ${d.options.warehouses.length}개`);

    // 2) 긴 기간(출고 데이터가 있는 8~10월)
    r = await get('/api/admin/wms/stock-report?from=2026-08-01&to=2026-10-22&sort=outbound', adminToken);
    const d2 = r.json.data;
    assert(r.status === 200, `8/1~10/22 조회 (${r.ms}ms) — 기간 ${d2.range.days}일, 출고합계 ${d2.totals.period_total} (온라인 ${d2.totals.online}/라이브 ${d2.totals.live}/오프라인 ${d2.totals.offline}), 라이브 회차 ${d2.options.live_sessions.length}개`);
    const top = d2.rows.slice(0, 3).map(x => `${x.name}(${x.code || '-'}) 출고${x.period_total} 일평균${x.avg_daily} 현${x.stock} 위치:${x.location_text || '미배정'} 유통:${x.expiry_date || '-'} 발주${x.reorder_qty}`);
    console.log('   출고 상위:', top.join(' | '));
    const sumDaily = Object.values(d2.totals.daily).reduce((a, b) => a + b, 0);
    assert(sumDaily === d2.totals.period_total, '일자별 합 = 기간 출고합계');
    const liveDays = d2.day_columns.filter(c => c.lives.length).map(c => c.label);
    console.log('   라이브 표기된 날짜:', liveDays.slice(0, 5).join(', ') || '(없음)');

    // 3) 최대 기간 제한
    r = await get('/api/admin/wms/stock-report?from=2025-01-01&to=2026-10-22', adminToken);
    assert(r.json.data.range.days === 92, `기간 상한 92일로 제한 (${r.json.data.range.from}~)`);

    // 4) 검색 (코드/공백무시)
    const sample = d.rows.find(x => x.code) || d.rows[0];
    r = await get('/api/admin/wms/stock-report?q=' + encodeURIComponent(sample.code), adminToken);
    assert(r.json.data.rows.some(x => x.id === sample.id), `코드 "${sample.code}" 검색 → ${r.json.data.rows.length}건`);
    const namePart = sample.name.replace(/\s+/g, '').slice(0, 4);
    r = await get('/api/admin/wms/stock-report?q=' + encodeURIComponent(namePart.split('').join(' ').slice(0, 3)), adminToken);
    assert(r.status === 200, `상품명 일부 검색 → ${r.json.data.rows.length}건`);

    // 5) 필터들
    r = await get('/api/admin/wms/stock-report?expiry_days=30&sort=expiry', adminToken);
    assert(r.json.data.rows.every(x => x.expiry_d !== null && x.expiry_d <= 30), `유통기한 30일 이내 ${r.json.data.rows.length}건`);
    r = await get('/api/admin/wms/stock-report?location=B1', adminToken);
    assert(r.json.data.rows.every(x => x.locations.some(l => l.warehouse_code === 'B1')), `위치 B1 ${r.json.data.rows.length}건`);
    r = await get('/api/admin/wms/stock-report?location=none', adminToken);
    console.log(`   위치 미배정 상품 ${r.json.data.rows.length}건`);
    r = await get('/api/admin/wms/stock-report?category=cosmetics,snack', adminToken);
    assert(r.json.data.rows.every(x => ['cosmetics', 'snack'].includes(x.category)), `구분 cosmetics+snack ${r.json.data.rows.length}건`);
    r = await get('/api/admin/wms/stock-report?low_stock=1', adminToken);
    assert(r.json.data.rows.every(x => x.low_stock), `재고부족만 ${r.json.data.rows.length}건`);
    r = await get('/api/admin/wms/stock-report?from=2026-08-01&to=2026-10-22&channel=live', adminToken);
    assert(r.json.data.totals.online === 0 && r.json.data.totals.offline === 0, `채널=라이브만 출고 ${r.json.data.totals.period_total}`);

    // 6) 상세
    const detailTarget = (d2.rows.find(x => x.period_total > 0) || d2.rows[0]);
    r = await get(`/api/admin/wms/stock-report/${detailTarget.id}?from=2026-08-01&to=2026-10-22`, adminToken);
    assert(r.status === 200 && r.json.data.product.id === detailTarget.id, `상세 조회 (${r.ms}ms) — ${r.json.data.product.name}: 현${r.json.data.product.stock}, 기간출고 ${r.json.data.period_total}, 원장 ${r.json.data.ledger.length}건, Lot ${r.json.data.lots.length}개, 위치 ${r.json.data.locations.map(l => l.text).join(',') || '미배정'}`);
    assert(r.json.data.period_total === detailTarget.period_total, '상세 출고합계 = 목록 출고합계');

    // 7) 공급사 범위 제한
    r = await get('/api/admin/wms/stock-report', providerToken);
    assert(r.status === 200 && r.json.data.rows.length === 0, '공급사(상품 없음)는 0건만 보임');
    r = await get(`/api/admin/wms/stock-report/${detailTarget.id}`, providerToken);
    assert(r.status === 403, '공급사가 남의 상품 상세 조회 시 403');
    r = await get('/api/admin/wms/stock-report', '');
    assert(r.status === 401, '비로그인 401');

    // 8) 집계 정확성 — 임시 상품 1개 + 임시 판매기록(끝나면 전부 삭제). 운영 데이터에는 아직 결제완료 판매가 거의 없어 직접 만들어 검증한다.
    const providerId = created[1];
    const { data: prod } = await admin.from('products_with').insert([{
      name: `재고현황판테스트-${ts}`, slug: `wmsrep-${ts}`, description: '테스트', price: 19900, stock: 12,
      category: 'test', supplier_id: providerId, status: 'active', barcode: `TWR${String(ts).slice(-6)}`,
      expiry_date: new Date(Date.now() + 20 * 86400000).toISOString().slice(0, 10)
    }]).select().single();
    fixtures.product = prod.id;
    const { data: sess } = await admin.from('live_sessions_live').select('id, title').order('created_at', { ascending: false }).limit(1).maybeSingle();
    const now = Date.now();
    const iso = (msAgo) => new Date(now - msAgo).toISOString();
    const orderRows = [
      { order_number: `TWR-${ts}-1`, user_id: providerId, items: [{ product_id: prod.id, variant_id: null, quantity: 3, price: 19900, name: prod.name }], total_price: 59700, final_price: 59700, status: 'paid', created_at: iso(86400000) },
      { order_number: `TWR-${ts}-2`, user_id: providerId, items: [{ product_id: prod.id, variant_id: null, quantity: 2, price: 19900, name: prod.name }], total_price: 39800, final_price: 39800, status: 'delivered', live_session_id: sess ? sess.id : null, created_at: iso(60000) },
      { order_number: `TWR-${ts}-3`, user_id: providerId, items: [{ product_id: prod.id, variant_id: null, quantity: 7, price: 19900, name: prod.name }], total_price: 139300, final_price: 139300, status: 'cancelled', created_at: iso(60000) }
    ];
    const { data: ords, error: oErr } = await admin.from('orders_with').insert(orderRows).select('id');
    if (oErr) throw oErr;
    fixtures.orders = ords.map(o => o.id);
    const { data: chs, error: cErr } = await admin.from('channel_sales_with').insert([
      { product_id: prod.id, channel: 'offline', quantity: 4, unit_price: 19900, total_amount: 79600, status: 'completed', created_by: providerId },
      { product_id: prod.id, channel: 'live', quantity: 5, unit_price: 19900, total_amount: 99500, status: 'cancelled', created_by: providerId }
    ]).select('id');
    if (cErr) throw cErr;
    fixtures.sales = chs.map(c => c.id);

    r = await get('/api/admin/wms/stock-report?from=' + new Date(now - 6 * 86400000 + 9 * 3600000).toISOString().slice(0, 10) + '&target_days=30', providerToken);
    const row = r.json.data.rows.find(x => x.id === prod.id);
    assert(r.json.data.rows.length === 1 && !!row, '공급사는 자기 상품만 보임');
    console.log(`   임시상품: 출고합계 ${row.period_total} (온라인 ${row.channel_split.online}/라이브 ${row.channel_split.live}/오프라인 ${row.channel_split.offline}), 일평균 ${row.avg_daily}, 현수량 ${row.stock}, 소진예상 ${row.depletion_date}(${row.days_left}일), 권장발주 ${row.reorder_qty}, 유통 D-${row.expiry_d}, 일자별 ${JSON.stringify(row.daily)}`);
    const expOnline = sess ? 3 : 5, expLive = sess ? 2 : 0;
    assert(row.period_total === 9 && row.channel_split.online === expOnline && row.channel_split.live === expLive && row.channel_split.offline === 4, `취소 제외, 채널 분리 정확(${expOnline}+${expLive}+4=9)`);
    const elapsed = r.json.data.range.elapsed_days;
    const expAvg = Math.round((9 / elapsed) * 100) / 100;
    assert(row.avg_daily === expAvg, `일평균 = 9/${elapsed}일 = ${expAvg}`);
    assert(row.reorder_qty === Math.max(0, Math.ceil(expAvg * 30 - 12)), `권장발주 = ceil(${expAvg}×30−12) = ${row.reorder_qty}`);
    if (sess) {
      const lr = await get(`/api/admin/wms/stock-report?live_id=${sess.id}&from=${r.json.data.range.from}`, providerToken);
      assert(lr.json.data.rows[0].period_total === 2, `라이브 회차("${sess.title}") 필터 → 2개`);
      assert(lr.json.data.day_columns.some(c => c.lives.length && /\(/.test(c.label)), `라이브 날짜 헤더 표기: ${lr.json.data.day_columns.filter(c => c.lives.length).map(c => c.label).join(', ')}`);
    }
    const dr = await get(`/api/admin/wms/stock-report/${prod.id}?from=${r.json.data.range.from}`, providerToken);
    assert(dr.status === 200 && dr.json.data.period_total === 9, `공급사 본인 상품 상세 OK (일자별 ${dr.json.data.daily.filter(x => x.total).map(x => x.date + ':' + x.total).join(', ')})`);
  } catch (e) {
    fail++; console.error('❌ 예외', e);
  } finally {
    if (fixtures.sales.length) await admin.from('channel_sales_with').delete().in('id', fixtures.sales);
    if (fixtures.orders.length) await admin.from('orders_with').delete().in('id', fixtures.orders);
    if (fixtures.product) await admin.from('products_with').delete().eq('id', fixtures.product);
    for (const id of created) {
      await admin.from('profiles').delete().eq('id', id);
      await admin.auth.admin.deleteUser(id);
    }
    console.log(`\n결과: ${pass} 통과 / ${fail} 실패`);
    process.exit(fail ? 1 : 0);
  }
}
main();
