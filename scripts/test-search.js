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

async function main() {
  const ts = Date.now();
  const { data: adminUser } = await admin.auth.admin.createUser({ email: `test-searchadmin-${ts}@withplus-test.local`, password: 'TestPass123!', email_confirm: true });
  const adminId = adminUser.user.id;
  await admin.from('profiles').upsert([{ id: adminId, email: `test-searchadmin-${ts}@withplus-test.local`, full_name: 'SearchTestAdmin', role: 'admin' }]);

  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;

  // 오타허용(trigram) 검색은 문자열 전체를 기준으로 유사도를 계산하므로, 상품명에 타임스탬프를 그대로
  // 붙이면(예: -1786565817991) 숫자가 대부분을 차지해 실제 유사도가 크게 희석되어 버린다(실제 서비스
  // 상품명에는 이런 접미사가 붙지 않으므로 이건 순전히 테스트 데이터 유일성 확보 방식의 문제).
  // products_with.name에는 유일성 제약이 없고 slug에만 있으므로, name은 순수하게 유지하고
  // slug 쪽에만 타임스탬프를 붙여 유일성을 확보한다.
  const productNames = [
    '우르사갈매나무열매추출물세럼',
    '콜라겐펩타이드파우더',
    '프로바이오틱스유산균'
  ];
  const createdIds = [];
  for (const name of productNames) {
    const { data } = await admin.from('products_with').insert({
      name, slug: name.toLowerCase() + '-' + ts + '-' + Math.random().toString(36).slice(2, 7), description: '검색 테스트용 설명입니다', price: 15000, stock: 10,
      category, supplier_id: adminId, status: 'active'
    }).select().single();
    createdIds.push(data.id);
  }
  // 비활성 상품(품절/판매중지 아님, status='inactive')도 하나 만들어 검색 결과에서 제외되는지 확인
  const inactiveName = `검색테스트비활성상품-${ts}`;
  const { data: inactiveProd } = await admin.from('products_with').insert({
    name: inactiveName, slug: inactiveName.toLowerCase(), description: '비활성 상품', price: 5000, stock: 5,
    category, supplier_id: adminId, status: 'inactive'
  }).select().single();
  createdIds.push(inactiveProd.id);

  // ============================================
  // 1) 정확한 이름 부분일치 검색
  // ============================================
  const exactRes = await fetch(`${API}/api/products?search=${encodeURIComponent('콜라겐펩타이드')}`);
  const exactJson = await exactRes.json();
  assert(exactJson.success && exactJson.data.some(p => p.id === createdIds[1]), `정확한 부분 문자열로 검색 시 해당 상품이 결과에 포함됨 (실제 건수: ${exactJson.data.length})`);

  // ============================================
  // 2) 오타가 섞인 검색어 - trigram 유사도로 여전히 찾아짐
  // ============================================
  const typoQuery = `콜라갠펩타이드`; // '겐' -> '갠' 오타
  const typoRes = await fetch(`${API}/api/products?search=${encodeURIComponent(typoQuery)}`);
  const typoJson = await typoRes.json();
  assert(typoJson.success && typoJson.data.some(p => p.id === createdIds[1]), `오타가 섞인 검색어(콜라갠펩타이드)로도 유사한 상품(콜라겐펩타이드파우더)을 찾음 (실제 건수: ${typoJson.data.length})`);

  // ============================================
  // 3) 완전히 무관한 검색어는 결과 없음 (가짜로 아무거나 채우지 않음)
  // ============================================
  const noMatchRes = await fetch(`${API}/api/products?search=${encodeURIComponent('완전히무관한검색어XYZ123')}`);
  const noMatchJson = await noMatchRes.json();
  assert(noMatchJson.success && noMatchJson.data.length === 0, `전혀 무관한 검색어는 빈 결과를 정직하게 반환 (실제 건수: ${noMatchJson.data.length})`);

  // ============================================
  // 4) 비활성(inactive) 상품은 검색 결과에 나오지 않음
  // ============================================
  const inactiveSearchRes = await fetch(`${API}/api/products?search=${encodeURIComponent('검색테스트비활성상품')}`);
  const inactiveSearchJson = await inactiveSearchRes.json();
  assert(inactiveSearchJson.data.every(p => p.id !== inactiveProd.id), '판매중(active)이 아닌 상품은 검색 결과에서 제외됨');

  // ============================================
  // 5) 검색어 없이 요청하면 기존처럼 전체 목록이 반환됨 (회귀 없음 확인)
  // ============================================
  const noSearchRes = await fetch(`${API}/api/products`);
  const noSearchJson = await noSearchRes.json();
  assert(noSearchJson.success && noSearchJson.data.length > 0, `검색어 없이 요청 시 기존처럼 전체 상품 목록이 반환됨 (실제 건수: ${noSearchJson.data.length})`);

  // ============================================
  // 6) 자동완성 - 짧은 검색어에도 상위 후보를 내려줌
  // ============================================
  const acRes = await fetch(`${API}/api/search/autocomplete?q=${encodeURIComponent('우르사')}`);
  const acJson = await acRes.json();
  assert(acJson.success && acJson.data.some(s => s.id === createdIds[0]), `자동완성이 '우르사' 검색어로 상품을 정확히 추천함 (실제: ${JSON.stringify(acJson.data.map(s => s.name))})`);
  assert(acJson.data.length <= 8, '자동완성 결과는 최대 8개로 제한됨');

  // ============================================
  // 7) 자동완성 - 빈 검색어는 빈 배열 반환
  // ============================================
  const acEmptyRes = await fetch(`${API}/api/search/autocomplete?q=`);
  const acEmptyJson = await acEmptyRes.json();
  assert(acEmptyJson.success && acEmptyJson.data.length === 0, '빈 검색어로 자동완성 요청 시 빈 배열 반환');

  // ============================================
  // 8) 검색을 하면 search_logs_with에 기록이 남는지 확인 (인기 검색어 집계 기반)
  // ============================================
  const uniqueQuery = `유니크검색어-${ts}`;
  await fetch(`${API}/api/products?search=${encodeURIComponent(uniqueQuery)}`);
  await new Promise(r => setTimeout(r, 500));
  const { data: logRows } = await admin.from('search_logs_with').select('*').eq('query', uniqueQuery);
  assert(!!logRows && logRows.length === 1, `검색 시 search_logs_with에 기록이 정확히 남음 (실제: ${logRows ? logRows.length : 0}건)`);

  // ============================================
  // 9) 인기 검색어 API가 방금 남긴 기록을 반영하는지 확인
  // ============================================
  const popularRes = await fetch(`${API}/api/search/popular`);
  const popularJson = await popularRes.json();
  assert(popularJson.success && popularJson.data.some(p => p.query === uniqueQuery.toLowerCase()), '인기 검색어 목록에 방금 검색한 검색어가 포함됨');
  assert(popularJson.data.length <= 10, '인기 검색어는 최대 10개로 제한됨');

  // ============================================
  // 정리
  // ============================================
  await admin.from('search_logs_with').delete().in('query', [uniqueQuery]);
  await admin.from('products_with').delete().in('id', createdIds);
  await admin.from('profiles').delete().eq('id', adminId);
  await admin.auth.admin.deleteUser(adminId);
  console.log('정리 완료: 검색로그/상품/계정 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
