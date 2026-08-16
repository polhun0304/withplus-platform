const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
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
    headers: { 'Content-Type': 'application/json', apikey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY },
    body: JSON.stringify({ email, password })
  });
  const json = await res.json();
  return json.access_token;
}

async function main() {
  const ts = Date.now();

  // 테스트 시작 전, 현재 cart_reminder_settings 상태를 백업해두고 테스트가 끝나면 그대로 복구한다
  const { data: settingsBackupRow } = await admin.from('platform_settings').select('*').eq('key', 'cart_reminder_settings').maybeSingle();

  // ============================================
  // 0) 관리자/구매자 계정 준비
  // ============================================
  const adminEmail = `test-cartrem-admin-${ts}@withplus-test.local`;
  const { data: adminUser } = await admin.auth.admin.createUser({ email: adminEmail, password: 'TestPass123!', email_confirm: true });
  const adminId = adminUser.user.id;
  await admin.from('profiles').upsert([{ id: adminId, email: adminEmail, full_name: 'CartRemTestAdmin', role: 'admin' }]);
  const adminToken = await loginAs(adminEmail, 'TestPass123!');

  const buyerEmail = `test-cartrem-buyer-${ts}@withplus-test.local`;
  const { data: buyerUser } = await admin.auth.admin.createUser({ email: buyerEmail, password: 'TestPass123!', email_confirm: true });
  const buyerId = buyerUser.user.id;
  await admin.from('profiles').upsert([{ id: buyerId, email: buyerEmail, full_name: 'CartRemTestBuyer', role: 'member' }]);
  const buyerToken = await loginAs(buyerEmail, 'TestPass123!');

  // ============================================
  // 1) 인증 없이는 내 장바구니 동기화 API에 접근할 수 없음
  // ============================================
  const noAuthPutRes = await fetch(`${API}/api/me/cart`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ items: [] }) });
  assert(noAuthPutRes.status === 401, '로그인 없이는 장바구니 동기화(PUT /api/me/cart)가 거부됨(401)');
  const noAuthGetRes = await fetch(`${API}/api/me/cart`);
  assert(noAuthGetRes.status === 401, '로그인 없이는 장바구니 조회(GET /api/me/cart)가 거부됨(401)');

  // ============================================
  // 2) 장바구니 서버 동기화 왕복 (localStorage 미러링의 핵심)
  // ============================================
  const putRes = await fetch(`${API}/api/me/cart`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + buyerToken },
    body: JSON.stringify({ items: [{ product_id: '00000000-0000-0000-0000-000000000000', name: '테스트상품', quantity: 2 }] })
  });
  assert(putRes.status === 200, '장바구니 동기화(PUT)가 정상 처리됨');

  const getRes = await fetch(`${API}/api/me/cart`, { headers: { Authorization: 'Bearer ' + buyerToken } });
  const getJson = await getRes.json();
  assert(getRes.ok && getJson.success && Array.isArray(getJson.data.items) && getJson.data.items.length === 1, '동기화한 장바구니를 GET으로 그대로 다시 읽을 수 있음');

  const { data: snapRow } = await admin.from('cart_snapshots_with').select('*').eq('user_id', buyerId).maybeSingle();
  assert(!!snapRow && Array.isArray(snapRow.items) && snapRow.items.length === 1, 'DB(cart_snapshots_with)에 장바구니 스냅샷이 실제로 저장됨');

  // 빈 배열로 PUT하면 스냅샷 행 자체가 정리됨(불필요한 빈 행이 테이블에 남지 않도록)
  const putEmptyRes = await fetch(`${API}/api/me/cart`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + buyerToken },
    body: JSON.stringify({ items: [] })
  });
  assert(putEmptyRes.status === 200, '빈 장바구니 동기화(PUT items:[])도 정상 처리됨');
  const { data: snapAfterEmpty } = await admin.from('cart_snapshots_with').select('*').eq('user_id', buyerId).maybeSingle();
  assert(!snapAfterEmpty, '장바구니를 비우면 서버의 스냅샷 행도 함께 정리됨(리마인더 대상에서 자동 제외)');

  // ============================================
  // 3) 관리자 설정 CRUD - 공개 엔드포인트는 enabled 여부만 노출
  // ============================================
  const patchOffRes = await fetch(`${API}/api/admin/settings/cart-reminder`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + adminToken },
    body: JSON.stringify({ enabled: false, delay_hours: 24, max_reminders: 2, resend_after_hours: 48 })
  });
  assert(patchOffRes.status === 200, '관리자가 리마인더 설정을 저장할 수 있음');

  const publicOffRes = await fetch(`${API}/api/settings/cart-reminder`);
  const publicOffJson = await publicOffRes.json();
  assert(publicOffJson.success && publicOffJson.data.enabled === false && Object.keys(publicOffJson.data).length === 1, '비활성화 상태에서 공개 엔드포인트는 enabled:false만 정직하게 노출함(다른 설정값 유출 없음)');

  const nonAdminPatchRes = await fetch(`${API}/api/admin/settings/cart-reminder`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + buyerToken },
    body: JSON.stringify({ enabled: true })
  });
  assert(nonAdminPatchRes.status === 403, '일반 회원은 리마인더 설정을 변경할 수 없음(403)');

  // ============================================
  // 4) 이탈 장바구니 스캔 + 발송 (run-now로 강제 실행)
  // ============================================
  const { data: supplier } = await admin.from('profiles').select('id').eq('role', 'supplier').limit(1).maybeSingle();
  const supplierId = supplier ? supplier.id : adminId;
  const { data: category } = await admin.from('categories').select('db_category').eq('is_active', true).limit(1).maybeSingle();
  const { data: activeProduct } = await admin.from('products_with').insert({
    name: `장바구니리마인더테스트상품${ts}`, slug: `cart-rem-test-${ts}`, description: '장바구니 리마인더 테스트용 상품입니다.',
    price: 12000, stock: 5, category: category ? category.db_category : 'etc', supplier_id: supplierId, status: 'active'
  }).select().single();
  const { data: deletedProduct } = await admin.from('products_with').insert({
    name: `장바구니리마인더테스트품절상품${ts}`, slug: `cart-rem-test-inactive-${ts}`, description: '판매중지 상품(리마인더에서 제외되어야 함)',
    price: 5000, stock: 0, category: category ? category.db_category : 'etc', supplier_id: supplierId, status: 'inactive'
  }).select().single();

  // 활성 리마인더 설정 (테스트가 오래 기다리지 않도록 1시간 지연으로 설정하고, updated_at을 과거로 조작)
  await fetch(`${API}/api/admin/settings/cart-reminder`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + adminToken },
    body: JSON.stringify({ enabled: true, delay_hours: 1, max_reminders: 2, resend_after_hours: 1 })
  });

  const publicOnRes = await fetch(`${API}/api/settings/cart-reminder`);
  const publicOnJson = await publicOnRes.json();
  assert(publicOnJson.data.enabled === true, '활성화 후 공개 엔드포인트에도 enabled:true로 반영됨');

  // 방치된 것으로 취급되도록 마지막 변경 시각을 2시간 전으로 직접 조작 (실제로는 시간이 지나야 발생하는 상황을 재현)
  const oldTimestamp = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
  await admin.from('cart_snapshots_with').upsert({
    user_id: buyerId,
    items: [
      { product_id: activeProduct.id, name: activeProduct.name, quantity: 1 },
      { product_id: deletedProduct.id, name: deletedProduct.name, quantity: 1 }
    ],
    updated_at: oldTimestamp,
    reminder_sent_at: null,
    reminder_count: 0
  }, { onConflict: 'user_id' });

  const runNowRes = await fetch(`${API}/api/admin/cart-reminder/run-now`, { method: 'POST', headers: { Authorization: 'Bearer ' + adminToken } });
  const runNowJson = await runNowRes.json();
  assert(runNowRes.ok && runNowJson.success, '관리자가 리마인더 스캔을 즉시 실행할 수 있음');
  assert(runNowJson.data.scanned >= 1, '방치된 장바구니가 스캔 대상으로 정확히 잡힘');

  const { data: snapAfterScan } = await admin.from('cart_snapshots_with').select('*').eq('user_id', buyerId).maybeSingle();
  assert(!!snapAfterScan && snapAfterScan.reminder_count === 1 && !!snapAfterScan.reminder_sent_at, '스캔 후 reminder_count/reminder_sent_at이 갱신됨');

  const { data: notifRows } = await admin.from('notifications_with').select('*').eq('user_id', buyerId).eq('type', 'cart_reminder');
  assert((notifRows || []).length >= 1, '장바구니 이탈 인앱 알림(notifications_with)이 실제로 생성됨');
  assert((notifRows[0].message || '').includes('1건'), '판매중지된 상품은 제외하고 유효한 상품(1건)만 알림 문구에 반영됨');

  const nonAdminRunNowRes = await fetch(`${API}/api/admin/cart-reminder/run-now`, { method: 'POST', headers: { Authorization: 'Bearer ' + buyerToken } });
  assert(nonAdminRunNowRes.status === 403, '일반 회원은 리마인더 스캔을 실행할 수 없음(403)');

  // 관리자 설정 조회에 pending_count가 숫자로 함께 내려옴(화면에 대기 건수 표시용)
  const adminSettingsRes = await fetch(`${API}/api/admin/settings/cart-reminder`, { headers: { Authorization: 'Bearer ' + adminToken } });
  const adminSettingsJson = await adminSettingsRes.json();
  assert(typeof adminSettingsJson.pending_count === 'number', '관리자 설정 조회에 대기 중인 이탈 장바구니 개수가 함께 제공됨');

  // ============================================
  // 5) 남은 상품이 전부 판매중지/삭제면 알림 없이 스냅샷만 정리
  // ============================================
  await admin.from('cart_snapshots_with').upsert({
    user_id: buyerId,
    items: [{ product_id: deletedProduct.id, name: deletedProduct.name, quantity: 1 }],
    updated_at: oldTimestamp,
    reminder_sent_at: null,
    reminder_count: 0
  }, { onConflict: 'user_id' });
  const runNowCleanupRes = await fetch(`${API}/api/admin/cart-reminder/run-now`, { method: 'POST', headers: { Authorization: 'Bearer ' + adminToken } });
  const runNowCleanupJson = await runNowCleanupRes.json();
  assert(runNowCleanupJson.data.cleaned >= 1, '남은 상품이 전부 판매중지된 장바구니는 알림 없이 스냅샷만 정리됨');
  const { data: snapAfterCleanup } = await admin.from('cart_snapshots_with').select('*').eq('user_id', buyerId).maybeSingle();
  assert(!snapAfterCleanup, '정리 대상 스냅샷이 실제로 삭제됨');

  // ============================================
  // 6) 주문 생성 시 장바구니 스냅샷이 자동으로 삭제됨(결제 완료 회원에게 리마인더가 나가지 않도록)
  // ============================================
  await admin.from('cart_snapshots_with').upsert({
    user_id: buyerId,
    items: [{ product_id: activeProduct.id, name: activeProduct.name, quantity: 1 }],
    updated_at: new Date().toISOString(),
    reminder_sent_at: null,
    reminder_count: 0
  }, { onConflict: 'user_id' });

  const orderRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + buyerToken },
    body: JSON.stringify({ items: [{ product_id: activeProduct.id, name: activeProduct.name, price: 12000, quantity: 1 }], shipping_address: { name: '테스터', phone: '01000000000', address: '서울시 테스트구' }, payment_method: 'pending' })
  });
  const orderJson = await orderRes.json();
  assert(orderRes.ok && orderJson.success, '주문이 정상 생성됨');
  const order = orderJson.data;

  const { data: snapAfterOrder } = await admin.from('cart_snapshots_with').select('*').eq('user_id', buyerId).maybeSingle();
  assert(!snapAfterOrder, '주문 생성이 완료되면 서버의 장바구니 스냅샷이 자동으로 삭제됨');

  // ============================================
  // 7) 관리자 모듈 카탈로그에 새 모듈이 노출됨
  // ============================================
  const modulesRes = await fetch(`${API}/api/admin/modules`, { headers: { Authorization: 'Bearer ' + adminToken } });
  const modulesJson = await modulesRes.json();
  const moduleKeys = (modulesJson.data || []).map(m => m.key);
  assert(moduleKeys.includes('cart_reminder'), '관리자 "기능 모듈" 카탈로그에 장바구니 이탈 리마인더가 노출됨');

  // ============================================
  // 정리
  // ============================================
  await admin.from('order_payments').delete().eq('order_id', order.id);
  await admin.from('orders_with').delete().eq('id', order.id);
  await admin.from('cart_snapshots_with').delete().in('user_id', [buyerId, adminId]);
  await admin.from('notifications_with').delete().eq('user_id', buyerId).eq('type', 'cart_reminder');
  await admin.from('products_with').delete().in('id', [activeProduct.id, deletedProduct.id]);
  await admin.from('profiles').delete().in('id', [adminId, buyerId]);
  await admin.auth.admin.deleteUser(adminId);
  await admin.auth.admin.deleteUser(buyerId);

  // cart_reminder_settings를 테스트 이전 상태로 정확히 복구 (원래 값이 없었으면 행 자체를 삭제)
  if (settingsBackupRow) {
    await admin.from('platform_settings').update({ value: settingsBackupRow.value, updated_at: settingsBackupRow.updated_at, updated_by: settingsBackupRow.updated_by }).eq('key', 'cart_reminder_settings');
  } else {
    await admin.from('platform_settings').delete().eq('key', 'cart_reminder_settings');
  }
  console.log('정리 완료: 테스트 상품/주문/계정/알림 삭제 및 cart_reminder_settings 원상복구');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
