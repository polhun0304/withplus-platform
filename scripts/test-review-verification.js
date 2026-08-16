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
  const custEmail = `test-reviewcust-${ts}@withplus-test.local`;
  const cust2Email = `test-reviewcust2-${ts}@withplus-test.local`;
  const adminEmail = `test-reviewadmin-${ts}@withplus-test.local`;

  const { data: custData } = await admin.auth.admin.createUser({ email: custEmail, password, email_confirm: true });
  const { data: cust2Data } = await admin.auth.admin.createUser({ email: cust2Email, password, email_confirm: true });
  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const custId = custData.user.id;
  const cust2Id = cust2Data.user.id;
  const adminId = adminData.user.id;
  await admin.from('profiles').upsert([
    { id: custId, email: custEmail, full_name: 'ReviewTestCustomer', role: 'member' },
    { id: cust2Id, email: cust2Email, full_name: 'ReviewTestCustomer2', role: 'member' },
    { id: adminId, email: adminEmail, full_name: 'ReviewTestAdmin', role: 'admin' }
  ]);
  const custToken = await loginAs(custEmail, password);
  const cust2Token = await loginAs(cust2Email, password);
  const adminToken = await loginAs(adminEmail, password);
  assert(!!custToken, '테스트 고객 로그인 성공');

  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;
  const { data: prod } = await admin.from('products_with').insert({
    name: `리뷰테스트상품-${ts}`, slug: `review-test-${ts}`, description: '테스트 상품입니다', price: 10000, stock: 20,
    category, supplier_id: adminId, status: 'active'
  }).select().single();

  const { data: prod2 } = await admin.from('products_with').insert({
    name: `리뷰테스트상품2-${ts}`, slug: `review-test2-${ts}`, description: '테스트 상품입니다', price: 10000, stock: 20,
    category, supplier_id: adminId, status: 'active'
  }).select().single();

  const createdReviewIds = [];
  async function postReview(token, body) {
    const res = await fetch(`${API}/api/reviews`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(body)
    });
    const json = await res.json();
    if (json.data && json.data.id) createdReviewIds.push(json.data.id);
    return { res, json };
  }

  // ============================================
  // 1) order_id 없이 리뷰 작성 -> 성공하지만 verified_purchase는 false
  // ============================================
  const { res: unverifiedRes, json: unverifiedJson } = await postReview(custToken, { product_id: prod.id, rating: 5, comment: '좋아요 (주문 연결 안함)' });
  assert(unverifiedRes.status === 201 && unverifiedJson.data.verified_purchase === false, `주문 연결 없이도 리뷰 작성은 성공하지만 verified_purchase=false (실제: ${unverifiedRes.status}, ${unverifiedJson.data?.verified_purchase})`);

  // ============================================
  // 2) 같은 상품에 같은 회원이 두 번째 리뷰 작성 시도 -> 400 (도배 방지)
  // ============================================
  const { res: dupRes, json: dupJson } = await postReview(custToken, { product_id: prod.id, rating: 3, comment: '중복 시도' });
  assert(dupRes.status === 400, `같은 상품에 이미 리뷰가 있으면 재작성 시도 시 400 (실제: ${dupRes.status})`);

  // ============================================
  // 3) 존재하지 않는(또는 타인 소유) order_id로 구매인증 시도 -> 400
  // ============================================
  const { res: fakeOrderRes, json: fakeOrderJson } = await postReview(cust2Token, { product_id: prod2.id, order_id: '00000000-0000-0000-0000-000000000000', rating: 5, comment: '가짜 주문으로 인증 시도' });
  assert(fakeOrderRes.status === 400, `존재하지 않는 order_id로 구매인증 시도 시 400 (실제: ${fakeOrderRes.status})`);

  // ============================================
  // 4) 실제 본인 주문이지만 delivered 상태가 아닌 경우 -> 400
  // ============================================
  const { data: pendingOrder } = await admin.from('orders_with').insert({
    order_number: `TESTORD-${ts}-A`, user_id: cust2Id, items: [{ product_id: prod2.id, name: prod2.name, price: prod2.price, quantity: 1 }],
    total_price: prod2.price, final_price: prod2.price, status: 'paid'
  }).select().single();
  const { res: notDeliveredRes, json: notDeliveredJson } = await postReview(cust2Token, { product_id: prod2.id, order_id: pendingOrder.id, rating: 5, comment: '아직 배송 안됐는데 인증시도' });
  assert(notDeliveredRes.status === 400, `배송완료 상태가 아닌 주문으로 구매인증 시도 시 400 (실제: ${notDeliveredRes.status})`);

  // ============================================
  // 5) 실제 배송완료된 본인 주문 + 해당 상품 포함 -> verified_purchase=true
  // ============================================
  await admin.from('orders_with').update({ status: 'delivered' }).eq('id', pendingOrder.id);
  const { res: verifiedRes, json: verifiedJson } = await postReview(cust2Token, { product_id: prod2.id, order_id: pendingOrder.id, rating: 5, comment: '실제 배송완료 주문으로 구매인증 리뷰' });
  assert(verifiedRes.status === 201 && verifiedJson.data.verified_purchase === true, `배송완료된 본인 주문으로 리뷰 작성 시 verified_purchase=true (실제: ${verifiedRes.status}, ${verifiedJson.data?.verified_purchase})`);

  // ============================================
  // 6) 배송완료 주문이지만 그 주문에 포함되지 않은 다른 상품으로 구매인증 시도 -> 400
  // ============================================
  const { data: prod3 } = await admin.from('products_with').insert({
    name: `리뷰테스트상품3-${ts}`, slug: `review-test3-${ts}`, description: '테스트 상품입니다', price: 10000, stock: 20,
    category, supplier_id: adminId, status: 'active'
  }).select().single();
  const { res: wrongProductRes, json: wrongProductJson } = await postReview(custToken, { product_id: prod3.id, order_id: pendingOrder.id, rating: 5, comment: '이 주문에 없는 상품' });
  assert(wrongProductRes.status === 400, `주문에 포함되지 않은 상품으로 구매인증 시도 시 400 (실제: ${wrongProductRes.status})`);
  await admin.from('products_with').delete().eq('id', prod3.id);

  // ============================================
  // 7) 타인의 주문 id로 구매인증 시도 -> 400 (본인 주문 아님)
  // ============================================
  const custPendingRes = await postReview(custToken, { product_id: prod2.id, order_id: pendingOrder.id, rating: 5, comment: '남의 주문으로 인증 시도' });
  assert(custPendingRes.res.status === 400, `타인의 주문 id로 구매인증 시도 시 400 (실제: ${custPendingRes.res.status})`);

  // ============================================
  // 8) 상품 상세 조회 시 리뷰에 verified_purchase 필드가 정확히 내려오는지 확인
  // ============================================
  const productDetailRes = await fetch(`${API}/api/products/${prod2.id}`);
  const productDetailJson = await productDetailRes.json();
  const foundReview = productDetailJson.data.reviews.find(r => r.id === verifiedJson.data.id);
  assert(!!foundReview && foundReview.verified_purchase === true, '상품 상세 조회 응답에 구매인증 리뷰의 verified_purchase=true가 정확히 포함됨');

  // ============================================
  // 9) 관리자 리뷰 목록 조회 - 권한 체크 + 목록 정상 조회
  // ============================================
  const custAdminListRes = await fetch(`${API}/api/admin/reviews`, { headers: { Authorization: `Bearer ${custToken}` } });
  assert(custAdminListRes.status === 403, `일반회원이 관리자 리뷰 목록 조회 시 403 (실제: ${custAdminListRes.status})`);

  const noAuthListRes = await fetch(`${API}/api/admin/reviews`);
  assert(noAuthListRes.status === 401, `미인증으로 관리자 리뷰 목록 조회 시 401 (실제: ${noAuthListRes.status})`);

  const adminListRes = await fetch(`${API}/api/admin/reviews`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const adminListJson = await adminListRes.json();
  assert(adminListRes.status === 200 && adminListJson.success, `관리자 리뷰 목록 조회 성공 (실제: ${adminListRes.status})`);
  assert(adminListJson.data.some(r => r.id === verifiedJson.data.id), '관리자 목록에 방금 작성한 리뷰가 포함됨');

  // ============================================
  // 10) 관리자가 리뷰를 숨김 처리 -> 상품 상세 화면에서 더 이상 보이지 않는지 확인
  // ============================================
  const hideRes = await fetch(`${API}/api/admin/reviews/${verifiedJson.data.id}/status`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'hidden', hidden_reason: '테스트 사유' })
  });
  const hideJson = await hideRes.json();
  assert(hideRes.status === 200 && hideJson.data.status === 'hidden', `관리자가 리뷰를 숨김 처리 성공 (실제: ${hideRes.status})`);

  const afterHideDetailRes = await fetch(`${API}/api/products/${prod2.id}`);
  const afterHideDetailJson = await afterHideDetailRes.json();
  assert(!afterHideDetailJson.data.reviews.some(r => r.id === verifiedJson.data.id), '숨김 처리된 리뷰는 상품 상세 화면(공개 API)에 더 이상 노출되지 않음');

  // ============================================
  // 11) 상태 필터로 숨김 리뷰만 조회
  // ============================================
  const hiddenOnlyRes = await fetch(`${API}/api/admin/reviews?status=hidden`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const hiddenOnlyJson = await hiddenOnlyRes.json();
  assert(hiddenOnlyJson.data.every(r => r.status === 'hidden'), 'status=hidden 필터 적용 시 숨김 리뷰만 정확히 조회됨');
  assert(hiddenOnlyJson.data.some(r => r.id === verifiedJson.data.id), '숨김 필터 목록에 방금 숨긴 리뷰가 포함됨');

  // ============================================
  // 12) 다시 공개 처리 -> 상품 상세 화면에 다시 노출되는지 확인
  // ============================================
  await fetch(`${API}/api/admin/reviews/${verifiedJson.data.id}/status`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'published' })
  });
  const afterRepublishRes = await fetch(`${API}/api/products/${prod2.id}`);
  const afterRepublishJson = await afterRepublishRes.json();
  assert(afterRepublishJson.data.reviews.some(r => r.id === verifiedJson.data.id), '다시 공개 처리한 리뷰는 상품 상세 화면에 다시 노출됨');

  // ============================================
  // 13) 잘못된 status 값으로 모더레이션 시도 -> 400
  // ============================================
  const invalidStatusRes = await fetch(`${API}/api/admin/reviews/${verifiedJson.data.id}/status`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ status: 'deleted' })
  });
  assert(invalidStatusRes.status === 400, `허용되지 않는 status 값으로 모더레이션 시도 시 400 (실제: ${invalidStatusRes.status})`);

  // ============================================
  // 정리
  // ============================================
  await admin.from('product_reviews').delete().in('id', createdReviewIds);
  await admin.from('orders_with').delete().eq('id', pendingOrder.id);
  await admin.from('products_with').delete().in('id', [prod.id, prod2.id]);
  await admin.from('profiles').delete().in('id', [custId, cust2Id, adminId]);
  await admin.auth.admin.deleteUser(custId);
  await admin.auth.admin.deleteUser(cust2Id);
  await admin.auth.admin.deleteUser(adminId);
  console.log('정리 완료: 리뷰/주문/상품/유저 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
