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
  const providerAEmail = `test-suppreportA-${ts}@withplus-test.local`;
  const providerBEmail = `test-suppreportB-${ts}@withplus-test.local`;
  const adminEmail = `test-suppreportadmin-${ts}@withplus-test.local`;
  const memberEmail = `test-suppreportmember-${ts}@withplus-test.local`;

  const { data: provAData } = await admin.auth.admin.createUser({ email: providerAEmail, password, email_confirm: true });
  const { data: provBData } = await admin.auth.admin.createUser({ email: providerBEmail, password, email_confirm: true });
  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: memberData } = await admin.auth.admin.createUser({ email: memberEmail, password, email_confirm: true });
  const providerAId = provAData.user.id;
  const providerBId = provBData.user.id;
  const adminId = adminData.user.id;
  const memberId = memberData.user.id;

  const { error: profileErr } = await admin.from('profiles').upsert([
    { id: providerAId, email: providerAEmail, full_name: 'SupplierReportTestProviderA', role: 'provider' },
    { id: providerBId, email: providerBEmail, full_name: 'SupplierReportTestProviderB', role: 'provider' },
    { id: adminId, email: adminEmail, full_name: 'SupplierReportTestAdmin', role: 'admin' },
    { id: memberId, email: memberEmail, full_name: 'SupplierReportTestMember', role: 'member' }
  ]);
  if (profileErr) { console.error('profile upsert failed', profileErr); process.exit(1); }

  const providerAToken = await loginAs(providerAEmail, password);
  const providerBToken = await loginAs(providerBEmail, password);
  const adminToken = await loginAs(adminEmail, password);
  const memberToken = await loginAs(memberEmail, password);
  assert(!!providerAToken && !!providerBToken && !!adminToken && !!memberToken, '테스트 계정 4개 로그인 성공');

  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;

  // 상품: A공급자 2개, B공급자 1개
  const { data: prodA1 } = await admin.from('products_with').insert({
    name: `공급사리포트테스트A1-${ts}`, slug: `suppreport-a1-${ts}`, description: '테스트', price: 10000, stock: 100,
    category, supplier_id: providerAId, status: 'active'
  }).select().single();
  const { data: prodA2 } = await admin.from('products_with').insert({
    name: `공급사리포트테스트A2-${ts}`, slug: `suppreport-a2-${ts}`, description: '테스트', price: 5000, stock: 100,
    category, supplier_id: providerAId, status: 'active'
  }).select().single();
  const { data: prodB1 } = await admin.from('products_with').insert({
    name: `공급사리포트테스트B1-${ts}`, slug: `suppreport-b1-${ts}`, description: '테스트', price: 20000, stock: 100,
    category, supplier_id: providerBId, status: 'active'
  }).select().single();

  const now = new Date();
  const recentDate = new Date(now.getTime() - 1 * 24 * 60 * 60 * 1000).toISOString(); // 1일 전
  const oldDate = new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000).toISOString(); // 60일 전

  // 주문1: 최근, A1 2개 + A2 1개 + B1 1개 (정상, delivered)
  const { data: order1 } = await admin.from('orders_with').insert({
    order_number: `ORD-SUPPREPORT-1-${ts}`,
    user_id: memberId,
    items: [
      { product_id: prodA1.id, name: prodA1.name, price: 10000, quantity: 2 },
      { product_id: prodA2.id, name: prodA2.name, price: 5000, quantity: 1 },
      { product_id: prodB1.id, name: prodB1.name, price: 20000, quantity: 1 }
    ],
    total_price: 45000, final_price: 45000, status: 'delivered', payment_method: 'test', created_at: recentDate
  }).select().single();

  // 주문2: 60일 전(오래된), A1 1개 (정상, paid) - 날짜 필터 테스트용
  const { data: order2 } = await admin.from('orders_with').insert({
    order_number: `ORD-SUPPREPORT-2-${ts}`,
    user_id: memberId,
    items: [{ product_id: prodA1.id, name: prodA1.name, price: 10000, quantity: 3 }],
    total_price: 30000, final_price: 30000, status: 'paid', payment_method: 'test', created_at: oldDate
  }).select().single();

  // 주문3: 최근, B1 5개인데 취소됨 (집계에서 제외되어야 함)
  const { data: order3 } = await admin.from('orders_with').insert({
    order_number: `ORD-SUPPREPORT-3-${ts}`,
    user_id: memberId,
    items: [{ product_id: prodB1.id, name: prodB1.name, price: 20000, quantity: 5 }],
    total_price: 100000, final_price: 100000, status: 'cancelled', payment_method: 'test', created_at: recentDate
  }).select().single();

  // 주문4: 최근, 이미 삭제된(존재하지 않는) 상품 라인아이템 포함 - 집계에서 조용히 제외되어야 함
  const fakeProductId = '00000000-0000-0000-0000-000000000000';
  const { data: order4 } = await admin.from('orders_with').insert({
    order_number: `ORD-SUPPREPORT-4-${ts}`,
    user_id: memberId,
    items: [{ product_id: fakeProductId, name: '삭제된상품', price: 9999, quantity: 1 }],
    total_price: 9999, final_price: 9999, status: 'delivered', payment_method: 'test', created_at: recentDate
  }).select().single();

  // ============================================
  // 1) 인증 없이 요청 -> 401
  // ============================================
  const noAuthRes = await fetch(`${API}/api/admin/supplier-sales-report`);
  assert(noAuthRes.status === 401, `인증 없이 요청 시 401 (실제: ${noAuthRes.status})`);

  // ============================================
  // 2) member 권한으로 요청 -> 403
  // ============================================
  const memberRes = await fetch(`${API}/api/admin/supplier-sales-report`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert(memberRes.status === 403, `일반회원 권한으로 요청 시 403 (실제: ${memberRes.status})`);

  // ============================================
  // 3) 관리자 - 전체 기간 조회 (날짜 필터 없음) -> A, B 둘 다 보이고 취소/미상품 라인아이템은 제외됨
  // ============================================
  const adminAllRes = await fetch(`${API}/api/admin/supplier-sales-report`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const adminAllJson = await adminAllRes.json();
  assert(adminAllRes.status === 200 && adminAllJson.success, `관리자 전체기간 조회 성공 (실제: ${adminAllRes.status})`);

  const rowA_all = (adminAllJson.data.rows || []).find(r => r.supplier_id === providerAId);
  const rowB_all = (adminAllJson.data.rows || []).find(r => r.supplier_id === providerBId);
  assert(!!rowA_all, 'A공급자가 전체기간 리포트에 존재함');
  assert(!!rowB_all, 'B공급자가 전체기간 리포트에 존재함');
  // A: 주문1(A1 2개*10000=20000, A2 1개*5000=5000) + 주문2(A1 3개*10000=30000) = 55000원, 수량 6개, 주문 2건
  assert(rowA_all && rowA_all.revenue === 55000, `A공급자 전체기간 매출액 정확히 집계됨 (기대: 55000, 실제: ${rowA_all?.revenue})`);
  assert(rowA_all && rowA_all.quantity === 6, `A공급자 전체기간 판매수량 정확히 집계됨 (기대: 6, 실제: ${rowA_all?.quantity})`);
  assert(rowA_all && rowA_all.order_count === 2, `A공급자 전체기간 주문건수 정확히 집계됨 (기대: 2, 실제: ${rowA_all?.order_count})`);
  // B: 주문1(B1 1개*20000=20000) 만 - 주문3은 취소되어 제외
  assert(rowB_all && rowB_all.revenue === 20000, `B공급자 전체기간 매출액 정확히 집계됨(취소주문 제외) (기대: 20000, 실제: ${rowB_all?.revenue})`);
  assert(rowB_all && rowB_all.order_count === 1, `B공급자 전체기간 주문건수 정확히 집계됨(취소주문 제외) (기대: 1, 실제: ${rowB_all?.order_count})`);

  // ============================================
  // 4) 관리자 - 최근 3일로 날짜 필터 -> 60일 전 주문(order2)이 제외되어 A 매출이 20000+5000=25000원이어야 함
  // ============================================
  const startDate = new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const filteredRes = await fetch(`${API}/api/admin/supplier-sales-report?startDate=${startDate}`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const filteredJson = await filteredRes.json();
  const rowA_filtered = (filteredJson.data.rows || []).find(r => r.supplier_id === providerAId);
  assert(rowA_filtered && rowA_filtered.revenue === 25000, `날짜필터(최근3일) 적용 시 오래된 주문이 제외되어 정확히 집계됨 (기대: 25000, 실제: ${rowA_filtered?.revenue})`);

  // ============================================
  // 5) 공급자(provider) A 계정으로 조회 -> 본인(A) 데이터만 보이고 B는 안 보임
  // ============================================
  const providerARes = await fetch(`${API}/api/admin/supplier-sales-report`, { headers: { Authorization: `Bearer ${providerAToken}` } });
  const providerAJson = await providerARes.json();
  assert(providerARes.status === 200 && providerAJson.success, `공급자A 조회 성공 (실제: ${providerARes.status})`);
  assert(providerAJson.data.rows.length === 1 && providerAJson.data.rows[0].supplier_id === providerAId, '공급자A는 본인 데이터 1건만 조회됨');
  assert(providerAJson.data.rows[0].revenue === 55000, `공급자A 본인 매출액 정확히 집계됨 (기대: 55000, 실제: ${providerAJson.data.rows[0].revenue})`);
  const leakedB = providerAJson.data.rows.find(r => r.supplier_id === providerBId);
  assert(!leakedB, '공급자A 조회 결과에 B공급자 데이터가 섞이지 않음');

  // ============================================
  // 6) 공급자(provider) B 계정으로 조회 -> 본인(B) 데이터만
  // ============================================
  const providerBRes = await fetch(`${API}/api/admin/supplier-sales-report`, { headers: { Authorization: `Bearer ${providerBToken}` } });
  const providerBJson = await providerBRes.json();
  assert(providerBJson.data.rows.length === 1 && providerBJson.data.rows[0].supplier_id === providerBId, '공급자B는 본인 데이터 1건만 조회됨');
  assert(providerBJson.data.rows[0].revenue === 20000, `공급자B 본인 매출액 정확히 집계됨(취소주문 제외) (기대: 20000, 실제: ${providerBJson.data.rows[0].revenue})`);

  // 정리
  await admin.from('orders_with').delete().in('id', [order1.id, order2.id, order3.id, order4.id]);
  await admin.from('products_with').delete().in('id', [prodA1.id, prodA2.id, prodB1.id]);
  await admin.from('profiles').delete().in('id', [providerAId, providerBId, adminId, memberId]);
  await admin.auth.admin.deleteUser(providerAId);
  await admin.auth.admin.deleteUser(providerBId);
  await admin.auth.admin.deleteUser(adminId);
  await admin.auth.admin.deleteUser(memberId);
  console.log('정리 완료: 주문/상품/계정 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
