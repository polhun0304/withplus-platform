// 채널별 자동 가격 검증 (분양몰 공동체가 = 적립율 연동 / 도매가 = 공통 도매 할인율)
// - 공동체 없는 일반 회원: 기본가
// - 총 적립율이 기본(플랫폼 개인+커뮤니티)보다 높은 공동체: 그만큼 비싸게 / 낮은 공동체: 싸게 (10원 단위 반올림)
// - 최대 가감 폭(±30%) 상한
// - 수량별 묶음가도 같은 비율로 가감
// - 도매 회원: 상품별 도매채널가 > 카테고리 도매 할인율 > 공통 도매 할인율, 도매에는 묶음가 미적용
// - 클라이언트 조작 불가(가격/가입하지 않은 공동체), 설정 끄기·공동체 제외 → 기본가
// - GET /api/me/price-context + public/withplus-pricing.js(화면 계산)가 주문 금액과 1원까지 같은지
// 실행: PORT=3109 node server.js 실행 후 → TEST_API=http://localhost:3109 node scripts/test-channel-pricing.js
// ⚠️ 운영 DB: 이 테스트가 만든 행(회원·공동체·상품·주문·도매채널가·감사로그)만 지우고, 채널 가격 설정은 원래 값으로 되돌린다
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();
const Pricing = require('../public/withplus-pricing.js');

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
const API = process.env.TEST_API || 'http://localhost:3109';

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌', msg); }
}

async function loginAs(email, password) {
  const res = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', apikey: anonKey },
    body: JSON.stringify({ email, password })
  });
  return (await res.json()).access_token;
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
  const userIds = [];
  const communityIds = [];
  const productIds = [];
  const orderIds = [];
  let settingsBefore = null;
  let settingsRowExisted = false;

  const authed = (token) => ({ 'Content-Type': 'application/json', Authorization: `Bearer ${token}` });
  const api = async (path, token, opts = {}) => {
    const res = await fetch(`${API}${path}`, Object.assign({}, opts, { headers: token ? authed(token) : { 'Content-Type': 'application/json' } }));
    const json = await res.json().catch(() => ({}));
    return { status: res.status, ok: res.ok, json };
  };

  try {
    const { data: existingSetting } = await admin.from('platform_settings').select('value').eq('key', 'channel_pricing').maybeSingle();
    settingsRowExisted = !!existingSetting;
    settingsBefore = existingSetting ? existingSetting.value : null;

    // ---------- 계정 ----------
    const adminId = await createTempUser(`test-cp-admin-${ts}@withplus-test.local`, password, 'admin', 'CpTestAdmin'); userIds.push(adminId);
    const memberId = await createTempUser(`test-cp-member-${ts}@withplus-test.local`, password, 'member', 'CpTestMember'); userIds.push(memberId);
    const plainId = await createTempUser(`test-cp-plain-${ts}@withplus-test.local`, password, 'member', 'CpTestPlain'); userIds.push(plainId);
    const wsId = await createTempUser(`test-cp-ws-${ts}@withplus-test.local`, password, 'wholesale', 'CpTestWholesale'); userIds.push(wsId);
    const adminToken = await loginAs(`test-cp-admin-${ts}@withplus-test.local`, password);
    const memberToken = await loginAs(`test-cp-member-${ts}@withplus-test.local`, password);
    const plainToken = await loginAs(`test-cp-plain-${ts}@withplus-test.local`, password);
    const wsToken = await loginAs(`test-cp-ws-${ts}@withplus-test.local`, password);
    assert(adminToken && memberToken && plainToken && wsToken, '테스트 관리자/공동체회원/일반회원/도매회원 로그인 성공');

    // ---------- 설정: 기본값으로 시작 (켜짐, 10원, ±30%, 도매 20%) ----------
    const setRes = await api('/api/admin/settings/channel-pricing', adminToken, { method: 'PATCH', body: JSON.stringify({
      community_enabled: true, rounding_unit: 10, max_adjust_percent: 30, excluded_community_ids: [], wholesale_discount_percent: 20, wholesale_category_rates: {}
    }) });
    assert(setRes.ok, `관리자 채널 가격 설정 저장 (실제: ${setRes.status} ${setRes.json.message || ''})`);
    const badSet = await api('/api/admin/settings/channel-pricing', adminToken, { method: 'PATCH', body: JSON.stringify({ rounding_unit: 7 }) });
    assert(badSet.status === 400, `잘못된 반올림 단위(7원) → 400 (실제: ${badSet.status})`);
    const memberSet = await api('/api/admin/settings/channel-pricing', memberToken, { method: 'PATCH', body: JSON.stringify({ community_enabled: false }) });
    assert(memberSet.status === 403, `일반 회원은 설정 변경 불가 → 403 (실제: ${memberSet.status})`);

    const ratesJson = (await api('/api/settings/mileage-rates')).json.data;
    const baseTotal = Number(ratesJson.personal) + Number(ratesJson.community); // 운영 기본값 1%+2%=3%
    console.log(`   (플랫폼 기본 총 적립율 ${Math.round(baseTotal * 10000) / 100}%)`);

    // ---------- 공동체: 높은 적립(기본+5%p) / 낮은 적립(기본-2%p) / 매우 높은(상한 테스트) ----------
    const mkCommunity = async (tag, personal, community) => {
      const { data, error } = await admin.from('communities').insert({
        name: `가격테스트${tag}-${ts}`, slug: `cp-test-${tag}-${ts}`, status: 'active', personal_point_rate: personal, community_point_rate: community
      }).select().single();
      if (error) throw error;
      communityIds.push(data.id);
      await admin.from('community_members').insert({ community_id: data.id, user_id: memberId, status: 'active' });
      return data;
    };
    const plat = { p: Number(ratesJson.personal), c: Number(ratesJson.community) };
    const high = await mkCommunity('high', Math.round((plat.p + 0.02) * 10000) / 10000, Math.round((plat.c + 0.03) * 10000) / 10000); // +5%p
    const low = await mkCommunity('low', Math.max(0, Math.round((plat.p - 0.01) * 10000) / 10000), Math.max(0, Math.round((plat.c - 0.01) * 10000) / 10000)); // -2%p
    const huge = await mkCommunity('huge', 0.3, 0.2); // 50% - 상한(+30%) 적용
    const lowTotal = Math.max(0, plat.p - 0.01) + Math.max(0, plat.c - 0.01);
    const lowBp = Math.round((lowTotal - baseTotal) * 10000);

    // ---------- 상품 ----------
    const catJson = await (await fetch(`${API}/api/categories`)).json();
    const category = catJson.data[0].db_category || catJson.data[0].slug;
    const mkProduct = async (tag, fields) => {
      const { data, error } = await admin.from('products_with').insert(Object.assign({
        name: `채널가격테스트${tag}-${ts}`, slug: `cp-test-${tag}-${ts}`, description: '테스트 상품입니다', stock: 100, category, status: 'active'
      }, fields)).select().single();
      if (error) throw error;
      productIds.push(data.id);
      return data;
    };
    const p1 = await mkProduct('a', { price: 12345, quantity_price_options: [{ qty: 2, price: 24000, label: '2개', badge: '' }] });
    const p2 = await mkProduct('b', { price: 20000, discount_price: 15000 });
    const p3 = await mkProduct('c', { price: 10000 });

    const order = async (token, items, extra = {}) => {
      const res = await api('/api/orders', token, { method: 'POST', body: JSON.stringify(Object.assign({ items }, extra)) });
      if (res.json.data && res.json.data.id) orderIds.push(res.json.data.id);
      return res;
    };
    const total = (r) => r.json.data ? Number(r.json.data.total_price) : null;

    // ============ 1) 공동체 없는 일반 회원 = 기본가 ============
    const o0 = await order(plainToken, [{ product_id: p1.id, quantity: 1, price: 1 }]);
    assert(o0.status === 201 && total(o0) === 12345, `공동체 없음 → 기본가 12,345원 (실제: ${o0.status} ${total(o0)} ${o0.json.message || ''})`);
    const om0 = await order(memberToken, [{ product_id: p1.id, quantity: 1 }]);
    assert(total(om0) === 12345, `공동체 회원이라도 공동체를 선택하지 않은 주문 → 기본가 12,345원 (실제: ${total(om0)})`);

    // ============ 2) 높은 적립 공동체 = +5% (12,345 x 1.05 = 12,962.25 → 12,960) ============
    const oh = await order(memberToken, [{ product_id: p1.id, quantity: 1, price: 1 }], { community_id: high.id });
    assert(total(oh) === 12960, `높은 적립 공동체(+5%) → 12,960원 (10원 반올림) (실제: ${total(oh)} ${oh.json.message || ''})`);
    const ohItem = oh.json.data && oh.json.data.items[0];
    assert(ohItem && ohItem.price_channel === 'community' && ohItem.price_adjust_bp === 500 && Number(ohItem.base_unit_price) === 12345, `주문 항목에 채널가 기록(community, +500bp, 기본가 12,345) (실제: ${JSON.stringify(ohItem && { c: ohItem.price_channel, bp: ohItem.price_adjust_bp, b: ohItem.base_unit_price })})`);
    // 할인가 상품: 할인가 기준 15,000 x 1.05 = 15,750
    const oh2 = await order(memberToken, [{ product_id: p2.id, quantity: 3 }], { community_id: high.id });
    assert(total(oh2) === 15750 * 3, `할인가 상품도 할인가 기준 가감: 15,750 x 3 = 47,250원 (실제: ${total(oh2)})`);
    // 묶음가 2개 24,000 x 1.05 = 25,200
    const ohT = await order(memberToken, [{ product_id: p1.id, quantity: 2 }], { community_id: high.id });
    assert(total(ohT) === 25200, `묶음가(2개 24,000원)도 +5% → 25,200원 (실제: ${total(ohT)})`);

    // ============ 3) 낮은 적립 공동체 = 싸게 ============
    const expectLow = Pricing.applyBp(12345, Math.max(-3000, lowBp), 10);
    const ol = await order(memberToken, [{ product_id: p1.id, quantity: 1 }], { community_id: low.id });
    assert(lowBp < 0 && total(ol) === expectLow && expectLow < 12345, `낮은 적립 공동체(${lowBp / 100}%) → ${expectLow.toLocaleString()}원 (기본가보다 쌈) (실제: ${total(ol)})`);
    if (lowBp === -200) assert(expectLow === 12100, `-2% 정확한 반올림: 12,345 x 0.98 = 12,098.1 → 12,100원`);

    // ============ 4) 상한 ±30% ============
    const ohuge = await order(memberToken, [{ product_id: p3.id, quantity: 1 }], { community_id: huge.id });
    assert(total(ohuge) === 13000, `총 적립율 50% 공동체도 상한 +30% → 13,000원 (실제: ${total(ohuge)})`);

    // ============ 5) 조작 불가 ============
    const { data: notMine } = await admin.from('communities').insert({ name: `가격테스트미가입-${ts}`, slug: `cp-test-notmine-${ts}`, status: 'active', personal_point_rate: 0, community_point_rate: 0 }).select().single();
    communityIds.push(notMine.id);
    const oTamper = await order(plainToken, [{ product_id: p1.id, quantity: 1 }], { community_id: notMine.id });
    assert(oTamper.status === 400, `가입하지 않은 (싼) 공동체 community_id 로 주문 → 400 거절 (실제: ${oTamper.status})`);
    const oTamper2 = await order(memberToken, [{ product_id: p1.id, quantity: 1, price: 10, line_total: 10 }], { community_id: high.id, price_context: { mode: 'default' } });
    assert(total(oTamper2) === 12960, `클라이언트가 보낸 가격/컨텍스트는 무시 → 12,960원 (실제: ${total(oTamper2)})`);

    // ============ 6) 화면 가격 컨텍스트 = 주문 금액 ============
    const ctxHigh = (await api(`/api/me/price-context?community_id=${high.id}`, memberToken)).json.data;
    assert(ctxHigh.mode === 'community' && ctxHigh.bp === 500 && ctxHigh.label.includes('공동체가'), `price-context(공동체 선택) = community +500bp, 라벨 "${ctxHigh.label}"`);
    const shown = Pricing.adjustProduct(p1, ctxHigh);
    assert(Pricing.effectiveUnitPrice(shown) === 12960 && shown.quantity_price_options[0].price === 25200, `화면 계산(withplus-pricing.js) 단가 12,960 / 묶음 25,200 = 주문 금액과 동일`);
    const shownP2 = Pricing.adjustProduct(p2, ctxHigh);
    assert(Number(shownP2.price) === 21000 && Number(shownP2.discount_price) === 15750, `화면: 정가 21,000 / 할인가 15,750 (할인율 표시 유지)`);
    const ctxNone = (await api(`/api/me/price-context?community_id=`, memberToken)).json.data;
    assert(ctxNone.mode === 'default', `price-context(공동체 선택 안 함) = 기본가 (실제: ${ctxNone.mode})`);
    const ctxNotMine = (await api(`/api/me/price-context?community_id=${notMine.id}`, plainToken)).json.data;
    assert(ctxNotMine.mode === 'default', `price-context(가입 안 한 공동체) = 기본가 (실제: ${ctxNotMine.mode})`);
    const ctxSlug = (await api(`/api/me/price-context?community=${high.slug}`, memberToken)).json.data;
    assert(ctxSlug.mode === 'community' && ctxSlug.community.id === high.id, `price-context(분양몰 슬러그로 들어온 가입 회원) = 그 공동체가`);
    const ctxAnon = (await api(`/api/me/price-context?community=${high.slug}`)).json.data;
    assert(ctxAnon.mode === 'community' && ctxAnon.preview === true && ctxAnon.bp === 500, `비로그인 분양몰 방문자 = 공동체가 미리보기(preview)`);
    const ctxAnonNone = (await api(`/api/me/price-context`)).json.data;
    assert(ctxAnonNone.mode === 'default', '비로그인·슬러그 없음 = 기본가');

    // ============ 7) 도매 ============
    const ow1 = await order(wsToken, [{ product_id: p1.id, quantity: 1, price: 1 }]);
    assert(total(ow1) === 9880, `도매 회원 → 기본가 x (1-20%) = 12,345 x 0.8 = 9,876 → 9,880원 (실제: ${total(ow1)} ${ow1.json.message || ''})`);
    const ow2 = await order(wsToken, [{ product_id: p1.id, quantity: 2 }]);
    assert(total(ow2) === 9880 * 2, `도매에는 묶음가 미적용 → 9,880 x 2 = 19,760원 (실제: ${total(ow2)})`);
    const owc = await order(wsToken, [{ product_id: p2.id, quantity: 1 }]);
    assert(total(owc) === 12000, `도매: 할인가 15,000 기준 20% 할인 → 12,000원 (실제: ${total(owc)})`);
    await admin.from('product_channel_prices_with').insert({ product_id: p3.id, channel: 'wholesale', price: 7000, is_manual_override: true });
    const owo = await order(wsToken, [{ product_id: p3.id, quantity: 2 }]);
    assert(total(owo) === 14000, `상품별 도매채널가(7,000원)가 우선 → 14,000원 (실제: ${total(owo)})`);
    await admin.from('product_channel_prices_with').delete().eq('product_id', p3.id).eq('channel', 'wholesale');
    await api('/api/admin/settings/channel-pricing', adminToken, { method: 'PATCH', body: JSON.stringify({ wholesale_category_rates: { [category]: 15 } }) });
    const owcat = await order(wsToken, [{ product_id: p3.id, quantity: 1 }]);
    assert(total(owcat) === 8500, `카테고리 도매 할인율(15%) → 10,000 x 0.85 = 8,500원 (실제: ${total(owcat)})`);
    const wsCatalog = await api('/api/wholesale/products', wsToken);
    const catP3 = (wsCatalog.json.data || []).find(p => p.id === p3.id);
    assert(catP3 && Number(catP3.wholesale_price) === 8500 && catP3.wholesale_price_source === 'category', `도매 카탈로그 표시가 = 주문 금액 8,500원 (실제: ${catP3 && catP3.wholesale_price})`);
    const ctxWsCat = (await api(`/api/me/price-context?community_id=${high.id}`, wsToken)).json.data;
    assert(ctxWsCat.mode === 'wholesale' && Pricing.unitPrice(p3, ctxWsCat) === 8500, `도매 회원 price-context = 도매가(공동체보다 우선), 화면 계산(카테고리 15%) 8,500원`);
    await api('/api/admin/settings/channel-pricing', adminToken, { method: 'PATCH', body: JSON.stringify({ wholesale_category_rates: {} }) });
    const ctxWs = (await api(`/api/me/price-context`, wsToken)).json.data;
    assert(ctxWs.mode === 'wholesale' && Pricing.unitPrice(p1, ctxWs) === 9880 && Pricing.adjustProduct(p1, ctxWs).quantity_price_options === null, `카테고리 할인율 해제 후 화면 계산 9,880원 = 주문 금액, 도매 화면에는 묶음가 숨김`);

    // ============ 8) 관리자 미리보기 ============
    const prev = await api('/api/admin/channel-pricing/preview', adminToken, { method: 'POST', body: JSON.stringify({ price: 12345, category }) });
    assert(prev.ok && prev.json.data && prev.json.data.default_unit_price === 12345 && prev.json.data.wholesale_unit_price === 9880 && prev.json.data.community_highest,
      `상품 수정 미리보기: 기본가 12,345 / 도매가 9,880 / 최고 적립 공동체 예시 (실제: ${JSON.stringify(prev.json.data && { d: prev.json.data.default_unit_price, w: prev.json.data.wholesale_unit_price })})`);

    // ============ 9) 공동체 제외 / 설정 끄기 → 기본가 ============
    await api('/api/admin/settings/channel-pricing', adminToken, { method: 'PATCH', body: JSON.stringify({ excluded_community_ids: [high.id] }) });
    const oex = await order(memberToken, [{ product_id: p1.id, quantity: 1 }], { community_id: high.id });
    assert(total(oex) === 12345, `"가격 자동조정 제외" 공동체 → 기본가 12,345원 (실제: ${total(oex)})`);
    await api('/api/admin/settings/channel-pricing', adminToken, { method: 'PATCH', body: JSON.stringify({ excluded_community_ids: [], community_enabled: false }) });
    const ooff = await order(memberToken, [{ product_id: p1.id, quantity: 2 }], { community_id: high.id });
    assert(total(ooff) === 24000, `분양몰 자동조정 끄기 → 기본 묶음가 24,000원 (실제: ${total(ooff)})`);
    const ctxOff = (await api(`/api/me/price-context?community_id=${high.id}`, memberToken)).json.data;
    assert(ctxOff.mode === 'default', `끄면 price-context 도 기본가 (실제: ${ctxOff.mode})`);
    // 반올림 단위 100원 → 12,345 x 1.05 = 12,962.25 → 13,000
    await api('/api/admin/settings/channel-pricing', adminToken, { method: 'PATCH', body: JSON.stringify({ community_enabled: true, rounding_unit: 100 }) });
    const o100 = await order(memberToken, [{ product_id: p1.id, quantity: 1 }], { community_id: high.id });
    assert(total(o100) === 13000, `반올림 단위 100원 → 13,000원 (실제: ${total(o100)})`);
  } finally {
    // ---------- 정리 (이 테스트가 만든 행만) ----------
    try {
      if (settingsRowExisted) await admin.from('platform_settings').update({ value: settingsBefore }).eq('key', 'channel_pricing');
      else await admin.from('platform_settings').delete().eq('key', 'channel_pricing');
    } catch (e) { console.error('설정 복원 실패:', e.message); }
    if (orderIds.length) await admin.from('orders_with').delete().in('id', orderIds);
    if (productIds.length) {
      await admin.from('product_channel_prices_with').delete().in('product_id', productIds);
      await admin.from('stock_adjustments_with').delete().in('product_id', productIds);
      await admin.from('product_price_history_with').delete().in('product_id', productIds);
      await admin.from('products_with').delete().in('id', productIds);
    }
    if (communityIds.length) {
      await admin.from('community_members').delete().in('community_id', communityIds);
      await admin.from('communities').delete().in('id', communityIds);
    }
    if (userIds.length) await admin.from('admin_audit_logs_with').delete().in('admin_id', userIds);
    for (const uid of userIds) {
      await admin.from('profiles').delete().eq('id', uid);
      await admin.auth.admin.deleteUser(uid).catch(() => {});
    }
  }
  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  console.log('ℹ️ 테스트 서버는 채널 가격 설정을 최대 30초 캐시하므로, 다른 테스트를 바로 이어서 돌리려면 서버를 재시작하세요.');
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => { console.error('테스트 실행 중 오류:', err); process.exit(1); });
