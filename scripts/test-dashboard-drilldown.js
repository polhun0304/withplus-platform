// 대시보드 통계 카드 드릴다운에 쓰이는 서버 필터(/api/admin/orders?since=, /api/admin/boards?answered=) 검증용 임시 테스트
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const HQ_EMAIL = `withplus.drill.hq.${stamp}@withplus.test`;
const PASSWORD = 'WithplusTest2026!';
let createdUserIds = [];
let createdOrderIds = [];
let createdPostIds = [];
let createdProductIds = [];

async function createTestUser(email, role) {
  const { data, error } = await admin.auth.admin.createUser({ email, password: PASSWORD, email_confirm: true });
  if (error) throw new Error(`계정 생성 실패: ${error.message}`);
  createdUserIds.push(data.user.id);
  const { error: profErr } = await admin.from('profiles').upsert({ id: data.user.id, email, role: role || 'member' });
  if (profErr) throw new Error(`profiles 생성 실패: ${profErr.message}`);
  const client = createClient(supabaseUrl, anonKey);
  const { data: signIn, error: signInErr } = await client.auth.signInWithPassword({ email, password: PASSWORD });
  if (signInErr) throw new Error(`로그인 실패: ${signInErr.message}`);
  return { id: data.user.id, token: signIn.session.access_token };
}

async function api(path, token, options = {}) {
  const res = await fetch(BASE + path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(options.headers || {}) }
  });
  const json = await res.json();
  return { status: res.status, ok: res.ok, json };
}

function assert(cond, msg) {
  if (!cond) throw new Error('❌ 검증 실패: ' + msg);
  console.log('✅ ' + msg);
}

async function cleanup() {
  console.log('\n--- 정리 시작 ---');
  for (const id of createdOrderIds) await admin.from('orders_with').delete().eq('id', id);
  for (const id of createdProductIds) await admin.from('products_with').delete().eq('id', id);
  for (const id of createdPostIds) await admin.from('board_posts').delete().eq('id', id);
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  const hq = await createTestUser(HQ_EMAIL, 'super_admin');

  console.log('\n=== 1. /api/admin/orders?since= : 오래된 주문(직접 insert)은 제외되고 최근 주문만 나오는지 ===');
  const oldOrder = await admin.from('orders_with').insert([{
    order_number: 'DRILL-OLD-' + stamp, user_id: hq.id, items: [{ product_id: 'x', name: 'old', price: 1000, quantity: 1 }],
    total_price: 1000, final_price: 1000, status: 'pending', created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
  }]).select().single();
  assert(!oldOrder.error, `30일 전 테스트 주문 직접 생성 (err=${oldOrder.error && oldOrder.error.message})`);
  createdOrderIds.push(oldOrder.data.id);

  // 주문 API가 실제 상품 존재/재고를 검증하므로(옵션/재고관리 고도화), 테스트용 실제 상품을 만들어둔다
  const productRes = await api('/api/products', hq.token, {
    method: 'POST',
    body: JSON.stringify({ name: `드릴다운테스트상품-${stamp}`, price: 2000, category: 'fashion', stock: 100 })
  });
  assert(productRes.ok, `테스트 상품 생성 성공 (status=${productRes.status})`);
  const testProductId = productRes.json.data.id;
  createdProductIds.push(testProductId);

  const newOrderRes = await api('/api/orders', hq.token, {
    method: 'POST',
    body: JSON.stringify({
      items: [{ product_id: testProductId, name: 'new', price: 2000, quantity: 1 }],
      shipping_address: { name: 'T', phone: '010', address: 'A' },
      payment_method: 'test'
    })
  });
  assert(newOrderRes.ok, '방금 주문(새 주문) 생성 성공');
  createdOrderIds.push(newOrderRes.json.data.id);

  const sinceIso = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const sinceRes = await api('/api/admin/orders?since=' + encodeURIComponent(sinceIso), hq.token);
  assert(sinceRes.ok, `since 필터 조회 성공 (status=${sinceRes.status})`);
  const ids = sinceRes.json.data.map(o => o.id);
  assert(ids.includes(newOrderRes.json.data.id), '최근(7일 이내) 주문은 since 필터 결과에 포함됨');
  assert(!ids.includes(oldOrder.data.id), '30일 전 주문은 since 필터 결과에서 제외됨');

  const allRes = await api('/api/admin/orders', hq.token);
  const allIds = allRes.json.data.map(o => o.id);
  assert(allIds.includes(oldOrder.data.id) && allIds.includes(newOrderRes.json.data.id), 'since 없이 조회하면 둘 다 포함(기존 동작 그대로 유지)');

  console.log('\n=== 2. /api/admin/boards?type=qa&answered=false : 답변 대기 Q&A만 필터링되는지 ===');
  const answeredPost = await admin.from('board_posts').insert([{ board_type: 'qa', title: 'Q-answered-' + stamp, content: 'c', author_id: hq.id, author_name: 'HQ', status: 'published', is_answered: true }]).select().single();
  const pendingPost = await admin.from('board_posts').insert([{ board_type: 'qa', title: 'Q-pending-' + stamp, content: 'c', author_id: hq.id, author_name: 'HQ', status: 'published', is_answered: false }]).select().single();
  assert(!answeredPost.error && !pendingPost.error, `테스트 Q&A 게시글 2건 생성 (errs=${answeredPost.error && answeredPost.error.message},${pendingPost.error && pendingPost.error.message})`);
  createdPostIds.push(answeredPost.data.id, pendingPost.data.id);

  const pendingRes = await api('/api/admin/boards?type=qa&answered=false', hq.token);
  assert(pendingRes.ok, `answered=false 조회 성공 (status=${pendingRes.status})`);
  const pendingIds = pendingRes.json.data.map(p => p.id);
  assert(pendingIds.includes(pendingPost.data.id), '답변대기 게시글은 결과에 포함됨');
  assert(!pendingIds.includes(answeredPost.data.id), '답변완료 게시글은 결과에서 제외됨');

  console.log('\n🎉 모든 검증 통과');
}

main()
  .catch(err => { console.error('\n💥 테스트 실패:', err.message); process.exitCode = 1; })
  .finally(async () => { await cleanup(); });
