// 관리자 상품 일괄 처리(POST /api/admin/products/bulk) 검증
// (1) 권한: 비로그인 401 / 일반회원 403 / 공급자는 본인 상품만(남의 상품은 항목별 forbidden)
// (2) 입력 검증: ids 비어있음·500개 초과·잘못된 id·잘못된 action/값 → 400
// (3) 판매상태·카테고리·재고(재고원장 기록)·가격(정률/정액, 할인가 동시 조정, 0원 이하 차단) 일괄 변경
// (4) 품절처리(discontinued)·판매재개 — 품절 상품은 상세 조회는 되고(품절 표시) 주문은 거부
// (4-2) 영구 삭제(purge): 이력 없으면 행 삭제, 리뷰/주문 이력 있으면 inactive+deleted_at 종결(목록 숨김·복구 불가)
// (5) 단건 수정 PUT /api/products/:id 가 리팩터링 후에도 그대로 동작
// 실행: PORT=3101 node server.js 를 띄운 뒤 API=http://localhost:3101 node scripts/test-admin-bulk-products.js
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
const API = process.env.API || 'http://localhost:3101';

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

async function api(token, method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: 'Bearer ' + token } : {}),
    body: body ? JSON.stringify(body) : undefined
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const userIds = [];
  const productIds = [];
  let orderId = null;
  let reviewId = null;

  try {
    const mk = async (tag, role) => {
      const email = `test-bulk-${tag}-${ts}@withplus-test.local`;
      const { data } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
      userIds.push(data.user.id);
      await admin.from('profiles').upsert([{ id: data.user.id, email, full_name: 'BulkTest' + tag, role }]);
      return { id: data.user.id, token: await loginAs(email, password) };
    };
    const adm = await mk('admin', 'admin');
    const provA = await mk('provA', 'provider');
    const provB = await mk('provB', 'provider');
    const member = await mk('member', 'member');
    assert(adm.token && provA.token && provB.token && member.token, '테스트 계정 4개(admin/provider A·B/member) 로그인');

    const { data: cats } = await admin.from('products_with').select('category').eq('status', 'active').limit(2);
    const catA = (cats && cats[0] && cats[0].category) || 'health';

    const create = async (who, name, price, discount, stock) => {
      const r = await api(who.token, 'POST', '/api/products', { name: `[TEST-BULK-${ts}] ${name}`, description: 'bulk test', price, discount_price: discount, category: catA, stock });
      if (r.json && r.json.data) productIds.push(r.json.data.id);
      return r.json && r.json.data;
    };
    const p1 = await create(adm, 'P1', 10000, 8000, 5);
    const p2 = await create(adm, 'P2', 12345, null, 0);
    const p3 = await create(adm, 'P3', 500, null, 3);
    const pa = await create(provA, 'PA', 20000, null, 1);
    const pb = await create(provB, 'PB', 30000, null, 1);
    assert(p1 && p2 && p3 && pa && pb, '테스트 상품 5개 생성');

    // ---------- (1) 권한 ----------
    let r = await api(null, 'POST', '/api/admin/products/bulk', { ids: [p1.id], action: 'status', value: 'active' });
    assert(r.status === 401, `비로그인 401 (실제 ${r.status})`);
    r = await api(member.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id], action: 'status', value: 'active' });
    assert(r.status === 403, `일반회원 403 (실제 ${r.status})`);
    r = await api(provA.token, 'POST', '/api/admin/products/bulk', { ids: [pa.id, pb.id, p1.id], action: 'stock', value: 7 });
    const byId = (res) => Object.fromEntries((res.json.data.results || []).map(x => [x.id, x]));
    let m = byId(r);
    assert(r.status === 200 && m[pa.id].result === 'updated' && m[pb.id].result === 'forbidden' && m[p1.id].result === 'forbidden', `공급자는 본인 상품만 처리(PA updated, PB/P1 forbidden) → ${JSON.stringify(r.json.data.summary)}`);
    const { data: pbRow } = await admin.from('products_with').select('stock').eq('id', pb.id).single();
    assert(Number(pbRow.stock) === 1, `남의 상품(PB) 재고는 그대로 1 (실제 ${pbRow.stock})`);

    // ---------- (2) 입력 검증 ----------
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [], action: 'status', value: 'active' });
    assert(r.status === 400, `빈 ids 400 (${r.json.message})`);
    const many = Array.from({ length: 501 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`);
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: many, action: 'status', value: 'active' });
    assert(r.status === 400, `501개 400 (${r.json.message})`);
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: ['abc'], action: 'status', value: 'active' });
    assert(r.status === 400, `잘못된 id 400 (${r.json.message})`);
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id], action: 'hack' });
    assert(r.status === 400, `알 수 없는 action 400`);
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id], action: 'status', value: 'deleted' });
    assert(r.status === 400, `잘못된 상태값 400`);
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id], action: 'stock', value: -1 });
    assert(r.status === 400, `음수 재고 400`);
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id], action: 'price', mode: 'percent', value: -95 });
    assert(r.status === 400, `정률 -95% 400`);

    // ---------- (3) 일괄 변경 ----------
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id, p2.id, p3.id], action: 'status', value: 'discontinued' });
    assert(r.status === 200 && r.json.data.summary.updated === 3, `판매상태 → 품절 3개 변경 ${JSON.stringify(r.json.data.summary)}`);
    let { data: rows } = await admin.from('products_with').select('id,status').in('id', [p1.id, p2.id, p3.id]);
    assert(rows.every(x => x.status === 'discontinued'), 'DB status=discontinued 확인');
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id, p2.id, p3.id], action: 'status', value: 'active' });
    assert(r.json.data.summary.updated === 3, '다시 판매중으로 3개 복구');
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id], action: 'status', value: 'active' });
    assert(r.json.data.summary.skipped === 1, '이미 같은 상태면 건너뜀');

    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id, p2.id], action: 'category', value: 'bulk-test-cat' });
    ({ data: rows } = await admin.from('products_with').select('id,category').in('id', [p1.id, p2.id]));
    assert(r.json.data.summary.updated === 2 && rows.every(x => x.category === 'bulk-test-cat'), '카테고리 2개 일괄 변경');

    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id, p2.id], action: 'stock', value: 12 });
    ({ data: rows } = await admin.from('products_with').select('id,stock').in('id', [p1.id, p2.id]));
    assert(r.json.data.summary.updated === 2 && rows.every(x => Number(x.stock) === 12), '재고 12개로 일괄 설정');
    const { data: ledger } = await admin.from('stock_adjustments_with').select('product_id, delta, reason').eq('product_id', p2.id);
    assert((ledger || []).some(l => Number(l.delta) === 12 && /관리자/.test(l.reason || '')), `재고원장에 +12 기록 (${(ledger || []).map(l => l.delta + ':' + l.reason).join(', ')})`);

    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id, p2.id], action: 'price', mode: 'percent', value: -10, round: 10 });
    ({ data: rows } = await admin.from('products_with').select('id,price,discount_price,supply_amount,vat_amount').in('id', [p1.id, p2.id]));
    const r1 = rows.find(x => x.id === p1.id), r2 = rows.find(x => x.id === p2.id);
    assert(Number(r1.price) === 9000 && Number(r1.discount_price) === 7200, `정률 -10%: P1 10000/8000 → ${r1.price}/${r1.discount_price}`);
    assert(Number(r2.price) === 11110 && r2.discount_price === null, `정률 -10% 10원 반올림: P2 12345 → ${r2.price}`);
    assert(Number(r2.supply_amount) + Number(r2.vat_amount) === 11110, `공급가액+부가세 재계산 (${r2.supply_amount}+${r2.vat_amount})`);
    const { data: ph } = await admin.from('product_price_history_with').select('price').eq('product_id', p1.id);
    assert((ph || []).some(h => Number(h.price) === 9000), '가격 이력에 9000 기록');

    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id, p3.id], action: 'price', mode: 'amount', value: -1000, round: 1 });
    m = byId(r);
    assert(m[p1.id].result === 'updated' && m[p3.id].result === 'failed', `정액 -1000원: P1 변경, P3(500원) 0원 이하 실패 → ${m[p3.id].message}`);
    const { data: p3Row } = await admin.from('products_with').select('price').eq('id', p3.id).single();
    assert(Number(p3Row.price) === 500, 'P3 가격 그대로 500');

    // ---------- (5) 단건 PUT 회귀 ----------
    r = await api(adm.token, 'PUT', '/api/products/' + p3.id, { name: `[TEST-BULK-${ts}] P3-renamed`, stock: 4 });
    assert(r.status === 200 && r.json.data.name.endsWith('P3-renamed') && Number(r.json.data.stock) === 4, `단건 수정 PUT 정상 (${r.status})`);
    r = await api(provB.token, 'PUT', '/api/products/' + p3.id, { name: 'hack' });
    assert(r.status === 403, `단건 수정 남의 상품 403 (${r.status})`);
    r = await api(adm.token, 'PUT', '/api/products/00000000-0000-4000-8000-000000000000', { name: 'x' });
    assert(r.status === 404, `단건 수정 없는 상품 404 (${r.status})`);

    // ---------- (4) 품절처리 / 판매재개 ----------
    r = await api(adm.token, 'DELETE', '/api/products/' + p1.id);
    let { data: p1Row } = await admin.from('products_with').select('status').eq('id', p1.id).single();
    assert(r.status === 200 && p1Row.status === 'discontinued', `단건 품절처리 → discontinued (${r.status})`);
    const pub = await api(null, 'GET', '/api/products/' + p1.id);
    assert(pub.status === 200 && pub.json.data.status === 'discontinued', `상품 상세 API는 품절 상품을 status=discontinued 로 내려줌(손님 화면 품절 표시용) (${pub.status})`);
    const orderTry = await api(member.token, 'POST', '/api/orders', { items: [{ product_id: p1.id, name: 'p1', quantity: 1, price: 1 }], shipping_address: { name: 't', phone: '010', address: 'x' } });
    assert(orderTry.status === 400 && /판매 중이 아닌/.test(orderTry.json.message || ''), `품절 상품 주문 시도 거부 (${orderTry.status} ${orderTry.json.message || ''})`);
    r = await api(adm.token, 'PUT', '/api/products/' + p1.id, { status: 'active' });
    ({ data: p1Row } = await admin.from('products_with').select('status').eq('id', p1.id).single());
    assert(r.status === 200 && p1Row.status === 'active', '판매재개 → active');
    r = await api(provA.token, 'POST', '/api/admin/products/bulk', { ids: [pa.id], action: 'status', value: 'inactive' });
    const hidden = await api(null, 'GET', '/api/products/' + pa.id);
    assert(r.json.data.summary.updated === 1 && hidden.status === 404, `판매중지(inactive) 상품은 손님 상세 조회 404 (${hidden.status})`);
    const missing = await api(null, 'GET', '/api/products/00000000-0000-4000-8000-000000000000');
    assert(missing.status === 404, `없는 상품 상세 조회 404 (${missing.status})`);

    // ---------- (5) 영구 삭제 ----------
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p3.id], action: 'purge' });
    assert(r.status === 400, `확인 문구 없는 영구 삭제 400 (${r.json.message})`);
    const { data: rev, error: revErr } = await admin.from('product_reviews').insert([{ product_id: p1.id, user_id: member.id, rating: 5, comment: 'bulk test', status: 'hidden' }]).select('id').single();
    reviewId = rev && rev.id;
    assert(!revErr && reviewId, '테스트 리뷰(P1, 숨김) 생성');
    const { data: ord, error: ordErr } = await admin.from('orders_with').insert([{ order_number: `TEST-BULK-${ts}`, user_id: member.id, items: [{ product_id: p2.id, name: 'test', quantity: 1, price: 1 }], total_price: 1, final_price: 1, status: 'cancelled' }]).select('id').single();
    orderId = ord && ord.id;
    assert(!ordErr && orderId, `테스트 주문(P2 포함, 취소상태) 생성 ${ordErr ? ordErr.message : ''}`);

    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p1.id, p2.id, p3.id], action: 'purge', confirm: '영구 삭제' });
    m = byId(r);
    console.log('   영구 삭제 결과:', JSON.stringify(r.json.data.summary), Object.values(m).map(x => x.result + ':' + x.message).join(' | '));
    assert(m[p3.id].result === 'deleted', 'P3(이력 없음) 행 완전 삭제');
    assert(m[p1.id].result === 'archived' && /리뷰/.test(m[p1.id].message), 'P1(리뷰 있음) 삭제됨(숨김) 종결 처리');
    assert(m[p2.id].result === 'archived' && /주문/.test(m[p2.id].message), 'P2(주문 이력) 삭제됨(숨김) 종결 처리');
    const { data: after } = await admin.from('products_with').select('id,status,deleted_at').in('id', [p1.id, p2.id, p3.id]);
    assert(after.length === 2 && after.every(x => x.status === 'inactive' && x.deleted_at), 'DB: P3 행 없음, P1·P2 inactive+deleted_at');
    const { data: ordAfter } = await admin.from('orders_with').select('id, items').eq('id', orderId);
    assert(ordAfter && ordAfter.length === 1 && ordAfter[0].items[0].name === 'test', '주문 기록(상품명 스냅샷) 보존');
    const list = await api(adm.token, 'GET', '/api/admin/products');
    const listIds = new Set((list.json.data || []).map(x => x.id));
    assert(!listIds.has(p1.id) && !listIds.has(p2.id) && listIds.has(pa.id), '관리자 상품 목록에서 영구 삭제 상품 숨김');
    const pubDel = await api(null, 'GET', '/api/products/' + p2.id);
    assert(pubDel.status === 404, `손님 상세 조회 404 (${pubDel.status})`);
    r = await api(adm.token, 'PUT', '/api/products/' + p2.id, { status: 'active' });
    assert(r.status === 404, `영구 삭제 상품 복구(PUT) 불가 404 (${r.status})`);
    r = await api(adm.token, 'DELETE', '/api/products/' + p2.id);
    assert(r.status === 404, `영구 삭제 상품 품절처리 불가 404 (${r.status})`);
    r = await api(adm.token, 'POST', '/api/admin/products/bulk', { ids: [p2.id], action: 'status', value: 'active' });
    assert(r.json.data.summary.failed === 1, '일괄 처리로도 복구 불가');

    r = await api(provA.token, 'POST', '/api/admin/products/bulk', { ids: [pb.id], action: 'purge', confirm: '영구 삭제' });
    m = byId(r);
    const { data: pbAfter } = await admin.from('products_with').select('id, deleted_at').eq('id', pb.id);
    assert(m[pb.id].result === 'forbidden' && pbAfter.length === 1 && !pbAfter[0].deleted_at, '공급자는 남의 상품 영구 삭제 불가');
  } catch (err) {
    fail++;
    console.log('❌ 예외', err);
  } finally {
    if (reviewId) await admin.from('product_reviews').delete().eq('id', reviewId);
    if (orderId) await admin.from('orders_with').delete().eq('id', orderId);
    if (userIds.length) await admin.from('orders_with').delete().in('user_id', userIds); // 혹시 만들어진 테스트 계정 주문 정리
    if (productIds.length) {
      await admin.from('stock_adjustments_with').delete().in('product_id', productIds);
      await admin.from('product_price_history_with').delete().in('product_id', productIds);
      await admin.from('products_with').delete().in('id', productIds);
    }
    for (const uid of userIds) {
      await admin.from('admin_audit_logs_with').delete().eq('admin_id', uid);
      await admin.from('profiles').delete().eq('id', uid);
      await admin.auth.admin.deleteUser(uid).catch(() => {});
    }
    console.log(`\n결과: ${pass} 통과 / ${fail} 실패`);
    process.exit(fail ? 1 : 0);
  }
}
main();
