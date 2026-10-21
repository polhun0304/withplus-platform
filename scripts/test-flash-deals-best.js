// ⚡ 한정수량 초특가 + ⭐ 베스트 상품 자동 순위 검증
// - 관리자 초특가 등록/수정/검증, 공개 목록·상품 상세 flash_deal 표시
// - 주문 가격이 서버에서 초특가로 계산되는지(클라이언트 가격 무시), 잔여 초과 주문 거절, 동시 주문 시 한도 초과 불가
// - 결제완료 표시(paid), 취소 시 수량 반환(멱등), 종료/사용 안 함이면 정상가
// - /api/home/best 페이징 + 관리자 설정(고정·제외·미리보기) — 테스트 전 설정값을 기억했다가 원래대로 되돌린다
// 사용법: 서버 실행 후 API=http://localhost:3104 node scripts/test-flash-deals-best.js
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const admin = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY);
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const API = process.env.API || 'http://localhost:3104';
const SITE_SUFFIX = (process.env.UPLOAD_PLATFORM === 'liveplus') ? '_live' : '';
const BEST_KEY = 'best_products_settings' + SITE_SUFFIX;

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); } else { fail++; console.log('❌', msg); }
}
async function loginAs(email, password) {
  const res = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', apikey: anonKey }, body: JSON.stringify({ email, password })
  });
  return (await res.json()).access_token;
}
async function call(method, path, token, body) {
  const res = await fetch(API + path, {
    method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  let json = null; try { json = await res.json(); } catch (e) { /* 빈 응답 */ }
  return { status: res.status, json };
}

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const userIds = [];
  const createdOrderIds = [];
  const createdProductIds = [];
  const createdDealIds = [];
  const { data: bestBefore } = await admin.from('platform_settings').select('value').eq('key', BEST_KEY).maybeSingle();

  try {
    async function mkUser(tag, role) {
      const email = `test-flash-${tag}-${ts}@withplus-test.local`;
      const { data } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
      const id = data.user.id;
      userIds.push(id);
      await admin.from('profiles').upsert([{ id, email, full_name: `FlashTest${tag}`, role }]);
      return { id, token: await loginAs(email, password) };
    }
    const adm = await mkUser('admin', 'admin');
    const cust = await mkUser('cust', 'member');
    const cust2 = await mkUser('cust2', 'member');
    assert(adm.token && cust.token && cust2.token, '테스트 관리자·고객 로그인 성공');

    const catJson = (await call('GET', '/api/categories')).json;
    const category = catJson.data[0].db_category || catJson.data[0].slug;
    const PRICE = 50000, DEAL = 19900, LIMIT = 5;
    const { data: prod } = await admin.from('products_with').insert({
      name: `초특가테스트상품-${ts}`, slug: `flash-test-${ts}`, description: '테스트 상품입니다', price: PRICE, stock: 100, category, supplier_id: adm.id, status: 'active'
    }).select().single();
    createdProductIds.push(prod.id);

    // ---------- 관리자 등록 검증 ----------
    const now = Date.now();
    const base = { product_id: prod.id, limit_qty: LIMIT, starts_at: new Date(now - 60000).toISOString(), ends_at: new Date(now + 3600000).toISOString() };
    let r = await call('POST', '/api/admin/flash-deals', cust.token, { ...base, deal_price: DEAL });
    assert(r.status === 403, `일반 회원은 초특가 등록 불가 (status ${r.status})`);
    r = await call('POST', '/api/admin/flash-deals', adm.token, { ...base, deal_price: PRICE });
    assert(r.status === 400, `판매가 이상 초특가 가격 거절 (${r.json && r.json.message})`);
    r = await call('POST', '/api/admin/flash-deals', adm.token, { ...base, deal_price: DEAL, ends_at: base.starts_at });
    assert(r.status === 400, '종료 일시 ≤ 시작 일시 거절');
    r = await call('POST', '/api/admin/flash-deals', adm.token, { ...base, deal_price: DEAL, sort_order: -999 });
    assert(r.status === 201 && r.json.data.status === 'active' && r.json.data.remaining === LIMIT, `초특가 등록 성공 (상태 ${r.json && r.json.data && r.json.data.status})`);
    const dealId = r.json && r.json.data && r.json.data.id;
    if (dealId) createdDealIds.push(dealId);

    // 공개 목록 + 상품 상세 + 상품 목록
    r = await call('GET', '/api/flash-deals');
    const pub = (r.json.data || []).find(d => d.id === dealId);
    assert(!!pub && pub.deal_price === DEAL && pub.product && pub.product.id === prod.id && !!r.json.soonest_end, '공개 /api/flash-deals에 진행중 초특가 + 종료 시각 노출');
    r = await call('GET', `/api/products/${prod.id}`);
    assert(r.json.data.flash_deal && r.json.data.flash_deal.deal_price === DEAL && r.json.data.flash_deal.remaining === LIMIT, '상품 상세 응답에 flash_deal(가격·잔여) 포함');
    r = await call('GET', '/api/products');
    const listed = (r.json.data || []).find(p => p.id === prod.id);
    assert(listed && listed.flash_deal && listed.flash_deal.deal_price === DEAL, '상품 목록(장바구니가 쓰는 API)에도 flash_deal 포함');

    // ---------- 주문 가격 = 초특가 (클라이언트 가격 무시) ----------
    r = await call('POST', '/api/orders', cust.token, { items: [{ product_id: prod.id, price: 1, quantity: 2 }] });
    if (r.json && r.json.data) createdOrderIds.push(r.json.data.id);
    const order1 = r.json && r.json.data;
    assert(r.status === 201 && Number(order1.total_price) === DEAL * 2 && order1.items[0].flash_deal_id === dealId, `주문 총액이 서버 초특가로 계산됨: ${DEAL}x2=${DEAL * 2} (실제 ${order1 && order1.total_price})`);
    let { data: dealRow } = await admin.from('flash_deals_with').select('sold_count').eq('id', dealId).single();
    assert(dealRow.sold_count === 2, `주문 생성 시 판매 수량 원자적 증가 (sold_count=${dealRow.sold_count})`);

    // 잔여(3) 초과 주문 거절
    r = await call('POST', '/api/orders', cust.token, { items: [{ product_id: prod.id, quantity: 4 }] });
    assert(r.status === 400 && /잔여 수량\(3개\)/.test(r.json.message || ''), `잔여 초과 주문 거절: "${r.json && r.json.message}"`);

    // ---------- 동시 주문: 잔여 3개를 2개씩 3명이 동시에 → 최대 1건만 성공, 한도 초과 없음 ----------
    const racers = await Promise.all([cust, cust2, cust].map(u => call('POST', '/api/orders', u.token, { items: [{ product_id: prod.id, quantity: 2 }] })));
    racers.forEach(x => { if (x.json && x.json.data) createdOrderIds.push(x.json.data.id); });
    const okCount = racers.filter(x => x.status === 201).length;
    ({ data: dealRow } = await admin.from('flash_deals_with').select('sold_count, limit_qty').eq('id', dealId).single());
    assert(okCount === 1 && dealRow.sold_count === 4 && dealRow.sold_count <= dealRow.limit_qty, `동시 주문 3건 중 ${okCount}건만 성공, sold_count=${dealRow.sold_count} ≤ 한도 ${dealRow.limit_qty}`);
    const raceFail = racers.find(x => x.status !== 201);
    assert(raceFail && [400, 409].includes(raceFail.status), `경합에서 진 주문은 명확한 메시지로 거절 (${raceFail && raceFail.status}: ${raceFail && raceFail.json && raceFail.json.message})`);

    // ---------- 결제완료 표시 + 취소 시 수량 반환(멱등) ----------
    r = await call('PATCH', `/api/admin/orders/${order1.id}/status`, adm.token, { status: 'paid' });
    let { data: claims } = await admin.from('flash_deal_claims_with').select('status').eq('order_id', order1.id);
    assert(r.status === 200 && claims.length === 1 && claims[0].status === 'paid', '결제완료 처리 시 점유 기록이 paid로 표시');
    r = await call('PATCH', `/api/admin/orders/${order1.id}/status`, adm.token, { status: 'cancelled' });
    ({ data: dealRow } = await admin.from('flash_deals_with').select('sold_count').eq('id', dealId).single());
    assert(r.status === 200 && dealRow.sold_count === 2, `취소 시 초특가 수량 반환 (sold_count 4→${dealRow.sold_count})`);
    await call('PATCH', `/api/admin/orders/${order1.id}/status`, adm.token, { status: 'cancelled' });
    ({ data: dealRow } = await admin.from('flash_deals_with').select('sold_count').eq('id', dealId).single());
    assert(dealRow.sold_count === 2, `취소를 한 번 더 해도 이중 반환 없음 (sold_count=${dealRow.sold_count})`);

    // ---------- 한정 수량은 판매 수량 아래로 줄일 수 없음 ----------
    r = await call('PUT', `/api/admin/flash-deals/${dealId}`, adm.token, { limit_qty: 1 });
    assert(r.status === 400, `판매 수량보다 적게 한정 수량 축소 거절 (${r.json && r.json.message})`);
    r = await call('GET', '/api/admin/flash-deals', adm.token);
    const admRow = (r.json.data || []).find(d => d.id === dealId);
    assert(admRow && admRow.sold_count === 2 && admRow.remaining === 3 && admRow.pending_qty === 2, `관리자 목록: 판매 ${admRow && admRow.sold_count} / 잔여 ${admRow && admRow.remaining} / 결제대기 ${admRow && admRow.pending_qty}`);

    // ---------- 사용 안 함 → 정상가 ----------
    r = await call('PUT', `/api/admin/flash-deals/${dealId}`, adm.token, { is_active: false });
    assert(r.status === 200 && r.json.data.status === 'inactive', '사용 안 함으로 전환');
    r = await call('POST', '/api/orders', cust.token, { items: [{ product_id: prod.id, quantity: 1 }] });
    if (r.json && r.json.data) createdOrderIds.push(r.json.data.id);
    assert(r.status === 201 && Number(r.json.data.total_price) === PRICE && !r.json.data.items[0].flash_deal_id, `초특가 꺼지면 정상가로 주문 (${r.json && r.json.data && r.json.data.total_price})`);
    r = await call('DELETE', `/api/admin/flash-deals/${dealId}`, adm.token);
    assert(r.status === 400, '판매 기록 있는 초특가는 삭제 불가(사용 안 함 안내)');

    // 예정 초특가: 공개 목록 include_upcoming에만, 주문 가격엔 미적용
    r = await call('POST', '/api/admin/flash-deals', adm.token, { product_id: prod.id, deal_price: 9900, limit_qty: 3, starts_at: new Date(now + 7200000).toISOString(), ends_at: new Date(now + 10800000).toISOString() });
    const upId = r.json && r.json.data && r.json.data.id;
    if (upId) createdDealIds.push(upId);
    assert(r.status === 201 && r.json.data.status === 'upcoming', '오픈 예정 초특가 등록');
    const pubAll = (await call('GET', '/api/flash-deals?include_upcoming=1')).json.data || [];
    const pubNow = (await call('GET', '/api/flash-deals')).json.data || [];
    assert(pubAll.some(d => d.id === upId) && !pubNow.some(d => d.id === upId), '예정 초특가는 include_upcoming 목록에만 노출');
    r = await call('DELETE', `/api/admin/flash-deals/${upId}`, adm.token);
    assert(r.status === 200, '판매 기록 없는 초특가 삭제');
    if (r.status === 200) createdDealIds.splice(createdDealIds.indexOf(upId), 1);

    // ---------- 페이지 라우트 ----------
    for (const pth of ['/deals', '/best']) {
      const res = await fetch(API + pth);
      const html = await res.text();
      assert(res.status === 200 && html.includes('<!DOCTYPE html>') && !html.trim().startsWith('{'), `${pth} 페이지가 HTML로 열림`);
    }

    // ---------- ⭐ 베스트 상품 ----------
    r = await call('GET', '/api/home/best?limit=8');
    assert(r.status === 200 && Array.isArray(r.json.data) && r.json.data.length <= 8 && typeof r.json.total === 'number' && r.json.data.every((p, i) => p.best_rank === i + 1), `/api/home/best 응답 (${r.json.data.length}개 / 전체 ${r.json.total})`);
    const page2 = await call('GET', '/api/home/best?limit=8&offset=8');
    assert(page2.status === 200 && (page2.json.data[0] ? page2.json.data[0].best_rank === 9 : true), '페이징(offset) 동작');
    r = await call('GET', '/api/admin/best-settings', cust.token);
    assert(r.status === 403, '일반 회원은 베스트 설정 조회 불가');
    r = await call('PUT', '/api/admin/best-settings', adm.token, { period_days: 14, weights: { sales: 50, reviews: 10, rating: 10, cart: 20, wish: 10 }, pinned: [prod.id], excluded: [] });
    assert(r.status === 200 && r.json.data.period_days === 14 && r.json.data.pinned[0] === prod.id, '베스트 설정 저장(사이트별 키)');
    r = await call('GET', '/api/home/best?limit=3');
    assert(r.json.data[0] && r.json.data[0].id === prod.id && r.json.data[0].best_pinned === true, '수동 고정 상품이 1위로 노출 (저장 즉시 캐시 갱신)');
    r = await call('POST', '/api/admin/best-settings/preview?limit=5', adm.token, { period_days: 7, weights: { sales: 100, reviews: 0, rating: 0, cart: 0, wish: 0 }, pinned: [], excluded: [prod.id] });
    assert(r.status === 200 && r.json.data.length <= 5 && !r.json.data.some(x => x.id === prod.id) && r.json.settings.period_days === 7, '미리보기: 저장 전 설정(제외 상품 반영)으로 계산');
    r = await call('PUT', '/api/admin/best-settings', adm.token, { period_days: 9999, weights: { sales: -5 }, pinned: ['not-a-uuid'], excluded: [] });
    assert(r.status === 200 && r.json.data.period_days === 30 && r.json.data.weights.sales === 0 && r.json.data.pinned.length === 0, '잘못된 설정 값은 안전한 기본값으로 정리');
  } finally {
    // ---------- 정리 (내가 만든 데이터만) ----------
    if (bestBefore) await admin.from('platform_settings').update({ value: bestBefore.value }).eq('key', BEST_KEY);
    else await admin.from('platform_settings').delete().eq('key', BEST_KEY);
    if (createdOrderIds.length) {
      await admin.from('flash_deal_claims_with').delete().in('order_id', createdOrderIds);
      await admin.from('email_logs_with').delete().in('order_id', createdOrderIds).then(null, () => {});
      await admin.from('orders_with').delete().in('id', createdOrderIds);
    }
    if (createdDealIds.length) await admin.from('flash_deals_with').delete().in('id', createdDealIds);
    if (createdProductIds.length) {
      await admin.from('flash_deals_with').delete().in('product_id', createdProductIds);
      await admin.from('stock_adjustments_with').delete().in('product_id', createdProductIds);
      await admin.from('product_price_history_with').delete().in('product_id', createdProductIds).then(null, () => {});
      await admin.from('products_with').delete().in('id', createdProductIds);
    }
    if (userIds.length) await admin.from('admin_audit_logs_with').delete().in('admin_id', userIds).then(null, () => {});
    for (const id of userIds) {
      await admin.from('cart_snapshots_with').delete().eq('user_id', id).then(null, () => {});
      // 주문 후처리(메일 기록 등)가 늦게 끝나 참조가 남아 있으면 프로필 삭제가 실패할 수 있어 잠시 뒤 한 번 더 시도
      for (let i = 0; i < 3; i++) {
        const { error } = await admin.from('profiles').delete().eq('id', id);
        if (!error) break;
        await new Promise(r => setTimeout(r, 1500));
      }
      await admin.auth.admin.deleteUser(id).catch(() => {});
    }
  }
  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => { console.error('테스트 실행 중 오류:', err); process.exit(1); });
