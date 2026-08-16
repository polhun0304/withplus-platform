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
  const custEmail = `test-restockcust-${ts}@withplus-test.local`;
  const adminEmail = `test-restockadmin-${ts}@withplus-test.local`;
  const password = 'TestPass123!';

  const { data: custData } = await admin.auth.admin.createUser({ email: custEmail, password, email_confirm: true });
  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const custId = custData.user.id;
  const adminId = adminData.user.id;
  const { error: profileErr } = await admin.from('profiles').upsert([
    { id: custId, email: custEmail, full_name: 'RestockTestCustomer', role: 'member' },
    { id: adminId, email: adminEmail, full_name: 'RestockTestAdmin', role: 'admin' }
  ]);
  if (profileErr) { console.error('profile upsert failed', profileErr); process.exit(1); }

  const custToken = await loginAs(custEmail, password);
  const adminToken = await loginAs(adminEmail, password);
  assert(!!custToken && !!adminToken, '테스트 고객/관리자 로그인 성공');

  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;

  const { data: outOfStockProd } = await admin.from('products_with').insert({
    name: `재입고테스트품절상품-${ts}`, slug: `restock-test-oos-${ts}`, description: '테스트', price: 10000, stock: 0,
    category, supplier_id: adminId, status: 'active'
  }).select().single();

  const { data: inStockProd } = await admin.from('products_with').insert({
    name: `재입고테스트재고있음상품-${ts}`, slug: `restock-test-instock-${ts}`, description: '테스트', price: 10000, stock: 5,
    category, supplier_id: adminId, status: 'active'
  }).select().single();

  // ============================================
  // 1) 재고 있는 상품에는 신청 불가 (400)
  // ============================================
  const inStockSubRes = await fetch(`${API}/api/products/${inStockProd.id}/restock-notify`, {
    method: 'POST', headers: { Authorization: `Bearer ${custToken}` }
  });
  assert(inStockSubRes.status === 400, `재고 있는 상품에 재입고 알림 신청 시 400 (실제: ${inStockSubRes.status})`);

  // ============================================
  // 2) 품절 상품에는 신청 가능
  // ============================================
  const subRes = await fetch(`${API}/api/products/${outOfStockProd.id}/restock-notify`, {
    method: 'POST', headers: { Authorization: `Bearer ${custToken}` }
  });
  assert(subRes.status === 201, `품절 상품에 재입고 알림 신청 성공 (실제: ${subRes.status})`);

  // 중복 신청해도 에러 없음 (idempotent)
  const dupSubRes = await fetch(`${API}/api/products/${outOfStockProd.id}/restock-notify`, {
    method: 'POST', headers: { Authorization: `Bearer ${custToken}` }
  });
  assert(dupSubRes.status === 201, `같은 상품 중복 신청해도 에러 없음 (실제: ${dupSubRes.status})`);

  const mySubsRes = await fetch(`${API}/api/me/restock-notifications`, { headers: { Authorization: `Bearer ${custToken}` } });
  const mySubsJson = await mySubsRes.json();
  assert(mySubsJson.data.length === 1, `내 재입고 알림 신청 목록에 1건 조회됨 (실제: ${mySubsJson.data.length})`);

  // ============================================
  // 3) 관리자가 상품 수정(PUT /api/products/:id)으로 재고를 0 -> 양수로 바꾸면 알림 생성 + 신청 자동 해제
  // ============================================
  const restockRes = await fetch(`${API}/api/products/${outOfStockProd.id}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ stock: 10 })
  });
  assert(restockRes.status === 200, `관리자 상품수정으로 재입고 처리 성공 (실제: ${restockRes.status})`);

  // 알림 생성은 best-effort 비동기이므로 약간의 지연을 둔다
  await new Promise(r => setTimeout(r, 500));

  const notifsRes = await fetch(`${API}/api/me/notifications`, { headers: { Authorization: `Bearer ${custToken}` } });
  const notifsJson = await notifsRes.json();
  const restockNotif = notifsJson.data.find(n => n.type === 'restock' && n.message.includes(outOfStockProd.name));
  assert(!!restockNotif, `재입고 알림이 알림함에 생성됨 (실제 알림 수: ${notifsJson.data.length})`);
  assert(restockNotif && restockNotif.is_read === false, `생성된 알림은 안읽음(unread) 상태 (실제: ${restockNotif?.is_read})`);

  const mySubsAfterRes = await fetch(`${API}/api/me/restock-notifications`, { headers: { Authorization: `Bearer ${custToken}` } });
  const mySubsAfterJson = await mySubsAfterRes.json();
  assert(mySubsAfterJson.data.length === 0, `알림 발송 후 신청 목록에서 자동으로 제거됨 (실제: ${mySubsAfterJson.data.length})`);

  // ============================================
  // 4) 알림 읽음 처리
  // ============================================
  const markReadRes = await fetch(`${API}/api/me/notifications/${restockNotif.id}/read`, {
    method: 'PATCH', headers: { Authorization: `Bearer ${custToken}` }
  });
  assert(markReadRes.status === 200, `알림 읽음 처리 성공 (실제: ${markReadRes.status})`);

  const notifsAfterReadRes = await fetch(`${API}/api/me/notifications`, { headers: { Authorization: `Bearer ${custToken}` } });
  const notifsAfterReadJson = await notifsAfterReadRes.json();
  const readNotif = notifsAfterReadJson.data.find(n => n.id === restockNotif.id);
  assert(readNotif && readNotif.is_read === true, `읽음 처리 후 is_read=true로 반영됨 (실제: ${readNotif?.is_read})`);

  // ============================================
  // 5) 신청 취소(구독 해제) - 재입고 전에 취소하면 알림이 생성되지 않아야 함
  // ============================================
  const { data: prod2 } = await admin.from('products_with').insert({
    name: `재입고테스트품절상품2-${ts}`, slug: `restock-test-oos2-${ts}`, description: '테스트', price: 5000, stock: 0,
    category, supplier_id: adminId, status: 'active'
  }).select().single();

  await fetch(`${API}/api/products/${prod2.id}/restock-notify`, { method: 'POST', headers: { Authorization: `Bearer ${custToken}` } });
  const unsubRes = await fetch(`${API}/api/products/${prod2.id}/restock-notify`, { method: 'DELETE', headers: { Authorization: `Bearer ${custToken}` } });
  assert(unsubRes.status === 200, `재입고 알림 신청 취소 성공 (실제: ${unsubRes.status})`);

  await fetch(`${API}/api/products/${prod2.id}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ stock: 8 })
  });
  await new Promise(r => setTimeout(r, 500));
  const notifsAfterUnsubRes = await fetch(`${API}/api/me/notifications`, { headers: { Authorization: `Bearer ${custToken}` } });
  const notifsAfterUnsubJson = await notifsAfterUnsubRes.json();
  const shouldNotExist = notifsAfterUnsubJson.data.find(n => n.type === 'restock' && n.message.includes(prod2.name));
  assert(!shouldNotExist, `신청 취소 후 재입고돼도 알림이 생성되지 않음`);

  // ============================================
  // 6) POST /api/admin/stock-adjustments 경로로도 재입고 알림이 트리거됨
  // ============================================
  const { data: prod3 } = await admin.from('products_with').insert({
    name: `재입고테스트품절상품3-${ts}`, slug: `restock-test-oos3-${ts}`, description: '테스트', price: 7000, stock: 0,
    category, supplier_id: adminId, status: 'active'
  }).select().single();
  await fetch(`${API}/api/products/${prod3.id}/restock-notify`, { method: 'POST', headers: { Authorization: `Bearer ${custToken}` } });

  const adjustRes = await fetch(`${API}/api/admin/stock-adjustments`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ product_id: prod3.id, delta: 15, reason: '재입고 테스트' })
  });
  assert(adjustRes.status === 200, `재고조정(입고) API 성공 (실제: ${adjustRes.status})`);
  await new Promise(r => setTimeout(r, 500));

  const notifsAfterAdjustRes = await fetch(`${API}/api/me/notifications`, { headers: { Authorization: `Bearer ${custToken}` } });
  const notifsAfterAdjustJson = await notifsAfterAdjustRes.json();
  const adjustNotif = notifsAfterAdjustJson.data.find(n => n.type === 'restock' && n.message.includes(prod3.name));
  assert(!!adjustNotif, `stock-adjustments API로 재입고해도 알림 생성됨`);

  // ============================================
  // 7) 인증 없이 신청 시도 -> 401
  // ============================================
  const noAuthRes = await fetch(`${API}/api/products/${prod3.id}/restock-notify`, { method: 'POST' });
  assert(noAuthRes.status === 401, `인증 없이 신청 시도 시 401 (실제: ${noAuthRes.status})`);

  // 정리
  await admin.from('notifications_with').delete().eq('user_id', custId);
  await admin.from('restock_subscriptions_with').delete().eq('user_id', custId);
  await admin.from('products_with').delete().in('id', [outOfStockProd.id, inStockProd.id, prod2.id, prod3.id]);
  await admin.from('profiles').delete().in('id', [custId, adminId]);
  await admin.auth.admin.deleteUser(custId);
  await admin.auth.admin.deleteUser(adminId);
  console.log('정리 완료: 알림/신청/상품/유저 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
