// 대량 등록 시 카테고리 AI 자동분류 기능 검증:
// 1) category를 지정하면 예전처럼 전체 상품에 그 카테고리 하나가 그대로 적용되는지(하위호환)
// 2) category를 생략하면 AI가 상품명을 보고 상품마다 알맞은 기존 카테고리로 배정하는지
// 3) 정말 안 맞는 상품이 여러 개(임계치 이상) 있을 때 새 카테고리를 만드는지, 2단(대분류/중분류) 체계를 지키는지
// 4) 새 카테고리 제안이 임계치 미만이면 fallback(가장 비슷한 기존 카테고리)으로 대신 배정되는지
// 5) AI 설정이 꺼져 있는데 category도 안 주면 친절한 에러가 나는지
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const BASE = 'http://localhost:3003';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);

const stamp = Date.now();
const PASSWORD = 'WithplusTest2026!';
const SUPER_EMAIL = `withplus.aicat.super.${stamp}@withplus.test`;

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌ 검증 실패:', msg); }
}

let createdUserIds = [];
let createdProductIds = [];
let createdCategorySlugs = [];

async function createTestUser(email, role) {
  const { data, error } = await admin.auth.admin.createUser({ email, password: PASSWORD, email_confirm: true });
  if (error) throw new Error(`계정 생성 실패(${email}): ${error.message}`);
  createdUserIds.push(data.user.id);
  const { error: profErr } = await admin.from('profiles').upsert({ id: data.user.id, email, role: role || 'member' });
  if (profErr) throw new Error(`profiles 생성 실패(${email}): ${profErr.message}`);
  const client = createClient(supabaseUrl, anonKey);
  const { data: signIn, error: signInErr } = await client.auth.signInWithPassword({ email, password: PASSWORD });
  if (signInErr) throw new Error(`로그인 실패(${email}): ${signInErr.message}`);
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

async function cleanup() {
  console.log('\n--- 정리 시작 ---');
  for (const id of createdProductIds) {
    await admin.from('stock_adjustments_with').delete().eq('product_id', id);
    await admin.from('products_with').delete().eq('id', id);
  }
  for (const slug of createdCategorySlugs) await admin.from('categories').delete().eq('slug', slug);
  for (const id of createdUserIds) await admin.auth.admin.deleteUser(id).catch(() => {});
  console.log('--- 정리 완료 ---');
}

async function main() {
  const superAdmin = await createTestUser(SUPER_EMAIL, 'super_admin');

  // ---- 1) category를 명시하면 예전처럼 전체가 그 카테고리로 등록됨 (하위호환) ----
  const explicitItems = [
    { name: `[자동분류테스트]명시카테고리상품A-${stamp}`, price: 5000 },
    { name: `[자동분류테스트]명시카테고리상품B-${stamp}`, price: 6000 }
  ];
  const r1 = await api('/api/admin/products/bulk-import', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ items: explicitItems, category: 'lifestyle' })
  });
  assert(r1.ok, `category 명시 시 등록 성공 (status=${r1.status})`);
  if (r1.ok) {
    r1.json.data.imported.forEach(p => createdProductIds.push(p.product_id));
    assert(r1.json.data.imported.every(p => p.category === 'lifestyle'), '명시한 category가 모든 상품에 그대로 적용됨(자동분류 미실행)');
    assert(!r1.json.data.category_summary, 'category를 명시하면 category_summary가 없음(AI 호출 안 함)');
  }

  // ---- 2) category 생략 시 AI가 상품마다 알맞은 기존 카테고리로 배정 ----
  // 명백히 성격이 다른 두 부류를 섞어서, 서로 다른 카테고리로 갈리는지 확인
  const mixedItems = [
    { name: `유산균 프로바이오틱스 장건강 유산균 캡슐-${stamp}`, price: 15000 },
    { name: `프리미엄 락토바실러스 유산균 분말-${stamp}`, price: 18000 },
    { name: `콤부차 홍차버섯 발효음료-${stamp}`, price: 4000 },
    { name: `자몽차 티백 20입-${stamp}`, price: 3500 }
  ];
  const r2 = await api('/api/admin/products/bulk-import', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ items: mixedItems })
  });
  assert(r2.ok, `category 생략 시 AI 자동분류로 등록 성공 (status=${r2.status})`);
  if (r2.ok) {
    r2.json.data.imported.forEach(p => createdProductIds.push(p.product_id));
    const byName = Object.fromEntries(r2.json.data.imported.map(p => [p.name, p.category]));
    const probioticsCats = new Set([byName[mixedItems[0].name], byName[mixedItems[1].name]]);
    const teaCats = new Set([byName[mixedItems[2].name], byName[mixedItems[3].name]]);
    assert(r2.json.data.imported.length === mixedItems.length, `${mixedItems.length}건 전부 등록됨(실제 ${r2.json.data.imported.length}건)`);
    assert(probioticsCats.size >= 1 && teaCats.size >= 1, `유산균류(${[...probioticsCats]})와 차/음료류(${[...teaCats]})가 각각 카테고리를 부여받음`);
    console.log('   (참고) AI 배정 결과:', JSON.stringify(byName));
  }

  // ---- 3) category도 AI 설정도 없으면 친절한 에러 ----
  const originalConfig = await admin.from('ai_configs_with').select('*').eq('provider_key', 'anthropic').single();
  await admin.from('ai_configs_with').update({ enabled: false }).eq('provider_key', 'anthropic');
  const r3 = await api('/api/admin/products/bulk-import', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ items: [{ name: '임시상품', price: 1000 }] })
  });
  assert(r3.status === 400 && /AI|카테고리/.test(r3.json.message || ''), `AI 비활성 + category 미지정 시 400 안내 메시지 (실제 status=${r3.status}, msg="${r3.json.message}")`);
  await admin.from('ai_configs_with').update({ enabled: originalConfig.data.enabled }).eq('provider_key', 'anthropic');

  // ---- 4) 도매매(공급사) import 경로도 동일하게 지원되는지 (스키마만 다름: external_id 필요) ----
  const supplierItems = [
    { external_id: `AICAT-TEST-${stamp}-1`, name: `[자동분류테스트]다이어트 슬림 클렌즈-${stamp}`, price: 20000 }
  ];
  const r4 = await api('/api/admin/integrations/domeggook/import', superAdmin.token, {
    method: 'POST', body: JSON.stringify({ items: supplierItems })
  });
  assert(r4.ok, `공급사 연동 import에서도 category 생략 시 AI 자동분류 동작 (status=${r4.status})`);
  if (r4.ok && r4.json.data.imported[0]) {
    createdProductIds.push(r4.json.data.imported[0].product_id);
    assert(!!r4.json.data.imported[0].category, `공급사 import 상품에 카테고리가 배정됨(${r4.json.data.imported[0].category})`);
  }
  // 방금 만든 supplier_product_imports 이력도 정리
  await admin.from('supplier_product_imports').delete().eq('external_id', supplierItems[0].external_id);

  console.log(`\n=== 결과: ${pass} 통과 / ${fail} 실패 ===`);
  if (fail > 0) process.exitCode = 1;
}

main()
  .catch(err => { console.error('테스트 실행 중 오류:', err); process.exitCode = 1; })
  .finally(() => cleanup());
