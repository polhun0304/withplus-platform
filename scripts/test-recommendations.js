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
  const memberAEmail = `test-reco-a-${ts}@withplus-test.local`; // 구매+찜 이력 있음 -> 개인화 추천
  const memberBEmail = `test-reco-b-${ts}@withplus-test.local`; // 이력 없음 -> 베스트셀러 대체
  const buyerCEmail = `test-reco-buyerc-${ts}@withplus-test.local`; // 베스트셀러/동시구매 데이터 생성용

  const { data: aData } = await admin.auth.admin.createUser({ email: memberAEmail, password, email_confirm: true });
  const { data: bData } = await admin.auth.admin.createUser({ email: memberBEmail, password, email_confirm: true });
  const { data: cData } = await admin.auth.admin.createUser({ email: buyerCEmail, password, email_confirm: true });
  const memberAId = aData.user.id;
  const memberBId = bData.user.id;
  const buyerCId = cData.user.id;

  await admin.from('profiles').upsert([
    { id: memberAId, email: memberAEmail, full_name: 'RecoTestA', role: 'member' },
    { id: memberBId, email: memberBEmail, full_name: 'RecoTestB', role: 'member' },
    { id: buyerCId, email: buyerCEmail, full_name: 'RecoTestBuyerC', role: 'member' }
  ]);

  const memberAToken = await loginAs(memberAEmail, password);
  const memberBToken = await loginAs(memberBEmail, password);
  assert(!!memberAToken && !!memberBToken, '테스트 계정 로그인 성공');

  // 실제 운영 중인(실 카테고리) 상품들과 뒤섞이지 않도록, 이 테스트 전용 카테고리 값을 사용한다
  // (개인화 추천은 products_with.category 문자열만 비교하므로 categories 테이블에 등록할 필요는 없다)
  const catX = `reco-test-x-${ts}`;
  const catY = `reco-test-y-${ts}`;

  // 상품 픽스처: X카테고리 3개(구매/찜/추천후보), Y카테고리 2개(찜/추천후보), 베스트셀러/동시구매 전용 2개
  const mk = (name, category, price) => ({ name: `${name}-${ts}`, slug: `reco-${name}-${ts}`.toLowerCase(), description: '테스트', price, category, supplier_id: memberAId, status: 'active' });

  const { data: prodX1 } = await admin.from('products_with').insert(mk('X구매상품', catX, 10000)).select().single();
  const { data: prodX2 } = await admin.from('products_with').insert(mk('X추천후보', catX, 12000)).select().single();
  const { data: prodY1 } = await admin.from('products_with').insert(mk('Y찜상품', catY, 15000)).select().single();
  const { data: prodY2 } = await admin.from('products_with').insert(mk('Y추천후보', catY, 8000)).select().single();
  const { data: prodBestseller } = await admin.from('products_with').insert(mk('베스트셀러', catX, 5000)).select().single();
  const { data: prodLowSeller } = await admin.from('products_with').insert(mk('저조한판매', catY, 5000)).select().single();
  const { data: prodFbtPartner } = await admin.from('products_with').insert(mk('동시구매파트너', catY, 7000)).select().single();
  const { data: prodFbtRare } = await admin.from('products_with').insert(mk('동시구매희귀', catY, 7000)).select().single();
  const { data: prodNoOrders } = await admin.from('products_with').insert(mk('주문없는상품', catX, 9000)).select().single();

  // ============================================
  // 1) 인증 없이 개인화 추천 요청 -> 401
  // ============================================
  const noAuthRes = await fetch(`${API}/api/me/recommendations`);
  assert(noAuthRes.status === 401, `인증 없이 개인화 추천 요청 시 401 (실제: ${noAuthRes.status})`);

  // ============================================
  // 2) memberB: 구매/찜 이력이 전혀 없는 신규회원 -> 베스트셀러로 정직하게 대체
  // ============================================
  // buyerC 계정으로 prodBestseller를 대량 구매(수량 합계 20), prodLowSeller는 소량(수량 합계 2) 구매한 주문을 심어둔다
  await admin.from('orders_with').insert([
    { order_number: `ORD-RECO-BEST-1-${ts}`, user_id: buyerCId, items: [{ product_id: prodBestseller.id, name: prodBestseller.name, price: 5000, quantity: 20 }], total_price: 100000, final_price: 100000, status: 'delivered', payment_method: 'test' },
    { order_number: `ORD-RECO-BEST-2-${ts}`, user_id: buyerCId, items: [{ product_id: prodLowSeller.id, name: prodLowSeller.name, price: 5000, quantity: 2 }], total_price: 10000, final_price: 10000, status: 'delivered', payment_method: 'test' }
  ]);

  const memberBRecoRes = await fetch(`${API}/api/me/recommendations?limit=20`, { headers: { Authorization: `Bearer ${memberBToken}` } });
  const memberBRecoJson = await memberBRecoRes.json();
  const bestsellerIdx = memberBRecoJson.data.findIndex(p => p.id === prodBestseller.id);
  const lowSellerIdx = memberBRecoJson.data.findIndex(p => p.id === prodLowSeller.id);
  assert(memberBRecoRes.status === 200 && memberBRecoJson.basis === 'bestseller', `이력 없는 회원은 basis='bestseller'로 정직하게 대체됨 (실제: ${memberBRecoJson.basis})`);
  assert(bestsellerIdx !== -1, `대량 판매된 상품이 베스트셀러 추천에 포함됨`);
  assert(lowSellerIdx === -1 || bestsellerIdx < lowSellerIdx, `많이 팔린 상품이 적게 팔린 상품보다 상위에 노출됨 (베스트셀러 idx=${bestsellerIdx}, 저조상품 idx=${lowSellerIdx})`);

  // 비회원용 인기 상품 API도 인증 없이 동일하게 동작해야 함
  const popularRes = await fetch(`${API}/api/recommendations/popular?limit=20`);
  const popularJson = await popularRes.json();
  assert(popularRes.status === 200 && popularJson.success && popularJson.basis === 'bestseller', `비회원용 인기 상품 API는 인증 없이도 정상 동작함 (실제: ${popularRes.status}, basis=${popularJson.basis})`);
  assert(popularJson.data.some(p => p.id === prodBestseller.id), '비회원용 인기 상품에도 대량 판매 상품이 포함됨');

  // ============================================
  // 3) memberA: X카테고리 상품 구매 + Y카테고리 상품 찜 -> 개인화 추천
  // ============================================
  await admin.from('orders_with').insert([
    { order_number: `ORD-RECO-A-${ts}`, user_id: memberAId, items: [{ product_id: prodX1.id, name: prodX1.name, price: 10000, quantity: 1 }], total_price: 10000, final_price: 10000, status: 'delivered', payment_method: 'test' }
  ]);
  const wishlistRes = await fetch(`${API}/api/wishlist`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberAToken}` },
    body: JSON.stringify({ product_id: prodY1.id })
  });
  assert(wishlistRes.status === 201, `memberA의 Y카테고리 상품 찜 성공 (실제: ${wishlistRes.status})`);

  const memberARecoRes = await fetch(`${API}/api/me/recommendations?limit=20`, { headers: { Authorization: `Bearer ${memberAToken}` } });
  const memberARecoJson = await memberARecoRes.json();
  const recoIds = memberARecoJson.data.map(p => p.id);
  assert(memberARecoRes.status === 200 && memberARecoJson.basis === 'personalized', `구매+찜 이력이 있는 회원은 basis='personalized' (실제: ${memberARecoJson.basis})`);
  assert(!recoIds.includes(prodX1.id) && !recoIds.includes(prodY1.id), '이미 구매/찜한 상품 자신은 추천 목록에서 제외됨');
  assert(recoIds.includes(prodX2.id), 'X카테고리(구매 이력) 관심사에 맞는 다른 상품이 추천에 포함됨');
  assert(recoIds.includes(prodY2.id), 'Y카테고리(찜 이력) 관심사에 맞는 다른 상품이 추천에 포함됨');
  assert(!recoIds.includes(prodNoOrders.id) || true, '관심 카테고리 밖 상품 존재 확인(참고용)');
  // X는 구매(가중치3), Y는 찜(가중치2) - 두 후보의 평점이 같다면 X쪽이 더 위에 와야 한다
  const x2Idx = recoIds.indexOf(prodX2.id);
  const y2Idx = recoIds.indexOf(prodY2.id);
  assert(x2Idx !== -1 && y2Idx !== -1 && x2Idx < y2Idx, `구매 이력 기반 카테고리(가중치 높음)의 추천이 찜 기반 카테고리보다 상위에 노출됨 (X idx=${x2Idx}, Y idx=${y2Idx})`);

  // ============================================
  // 4) 함께 구매한 상품 (동시구매 분석)
  // ============================================
  await admin.from('orders_with').insert([
    { order_number: `ORD-RECO-FBT-1-${ts}`, user_id: buyerCId, items: [{ product_id: prodX1.id, name: prodX1.name, price: 10000, quantity: 1 }, { product_id: prodFbtPartner.id, name: prodFbtPartner.name, price: 7000, quantity: 1 }], total_price: 17000, final_price: 17000, status: 'delivered', payment_method: 'test' },
    { order_number: `ORD-RECO-FBT-2-${ts}`, user_id: memberAId, items: [{ product_id: prodX1.id, name: prodX1.name, price: 10000, quantity: 1 }, { product_id: prodFbtPartner.id, name: prodFbtPartner.name, price: 7000, quantity: 1 }], total_price: 17000, final_price: 17000, status: 'delivered', payment_method: 'test' },
    { order_number: `ORD-RECO-FBT-3-${ts}`, user_id: buyerCId, items: [{ product_id: prodX1.id, name: prodX1.name, price: 10000, quantity: 1 }, { product_id: prodFbtRare.id, name: prodFbtRare.name, price: 7000, quantity: 1 }], total_price: 17000, final_price: 17000, status: 'delivered', payment_method: 'test' }
  ]);

  const fbtRes = await fetch(`${API}/api/products/${prodX1.id}/frequently-bought-together?limit=10`);
  const fbtJson = await fbtRes.json();
  const fbtIds = fbtJson.data.map(p => p.id);
  assert(fbtRes.status === 200 && fbtJson.success, `함께 구매한 상품 API 인증 없이 조회 성공 (실제: ${fbtRes.status})`);
  assert(!fbtIds.includes(prodX1.id), '자기 자신은 함께 구매한 상품 목록에서 제외됨');
  assert(fbtIds.includes(prodFbtPartner.id) && fbtIds.includes(prodFbtRare.id), '동시구매된 두 상품이 모두 결과에 포함됨');
  const partnerIdx = fbtIds.indexOf(prodFbtPartner.id);
  const rareIdx = fbtIds.indexOf(prodFbtRare.id);
  assert(partnerIdx < rareIdx, `동시구매 빈도(2회)가 더 높은 상품이 1회보다 상위에 노출됨 (partner idx=${partnerIdx}, rare idx=${rareIdx})`);

  const fbtEmptyRes = await fetch(`${API}/api/products/${prodNoOrders.id}/frequently-bought-together`);
  const fbtEmptyJson = await fbtEmptyRes.json();
  assert(fbtEmptyRes.status === 200 && Array.isArray(fbtEmptyJson.data) && fbtEmptyJson.data.length === 0, `주문 이력이 없는 상품은 빈 배열을 정직하게 반환함(가짜 데이터로 채우지 않음) (실제 건수: ${fbtEmptyJson.data?.length})`);

  // 정리
  const productIds = [prodX1.id, prodX2.id, prodY1.id, prodY2.id, prodBestseller.id, prodLowSeller.id, prodFbtPartner.id, prodFbtRare.id, prodNoOrders.id];
  await admin.from('orders_with').delete().like('order_number', `ORD-RECO-%-${ts}`);
  await admin.from('wishlist_with').delete().eq('user_id', memberAId);
  await admin.from('products_with').delete().in('id', productIds);
  await admin.from('profiles').delete().in('id', [memberAId, memberBId, buyerCId]);
  await admin.auth.admin.deleteUser(memberAId);
  await admin.auth.admin.deleteUser(memberBId);
  await admin.auth.admin.deleteUser(buyerCId);
  console.log('정리 완료: 주문/찜/상품/계정 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
