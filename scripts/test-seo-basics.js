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

  // ============================================
  // 1) robots.txt
  // ============================================
  const robotsRes = await fetch(`${API}/robots.txt`);
  const robotsText = await robotsRes.text();
  assert(robotsRes.status === 200, 'robots.txt가 200으로 응답함');
  assert(robotsText.includes('Sitemap:') && robotsText.includes('/sitemap.xml'), 'robots.txt에 사이트맵 위치가 명시됨');
  assert(robotsText.includes('Disallow: /admin'), 'robots.txt가 관리자 페이지는 색인 차단함');
  assert(robotsText.includes('Allow: /'), 'robots.txt가 기본적으로 전체 허용함');

  // ============================================
  // 2) sitemap.xml - 실제 DB 데이터 기준으로 생성되는지 확인
  // ============================================
  const sitemapRes = await fetch(`${API}/sitemap.xml`);
  const sitemapText = await sitemapRes.text();
  assert(sitemapRes.status === 200, 'sitemap.xml이 200으로 응답함');
  assert(sitemapRes.headers.get('content-type').includes('xml'), 'sitemap.xml의 Content-Type이 xml임');
  assert(sitemapText.startsWith('<?xml'), '유효한 XML 선언으로 시작함');
  assert(sitemapText.includes('<urlset'), 'urlset 루트 요소를 포함함');
  assert((sitemapText.match(/<url>/g) || []).length > 10, `정적페이지+카테고리+상품이 합쳐져 충분한 수의 <url> 항목이 있음 (실제: ${(sitemapText.match(/<url>/g) || []).length}개)`);

  // 테스트 상품을 하나 만들어서 sitemap에 정확히 반영되는지 확인
  const { data: adminUser } = await admin.auth.admin.createUser({ email: `test-seoadmin-${ts}@withplus-test.local`, password: 'TestPass123!', email_confirm: true });
  const adminId = adminUser.user.id;
  await admin.from('profiles').upsert([{ id: adminId, email: `test-seoadmin-${ts}@withplus-test.local`, full_name: 'SeoTestAdmin', role: 'admin' }]);
  const catRes = await fetch(`${API}/api/categories`);
  const catJson = await catRes.json();
  const category = catJson.data[0].db_category || catJson.data[0].slug;

  const seoProductName = `SEO테스트상품${ts}`;
  const { data: product } = await admin.from('products_with').insert({
    name: seoProductName, slug: `seo-test-${ts}`, description: 'SEO 테스트용 실제 설명입니다. 이 상품은 검증 직후 삭제됩니다.',
    price: 12345, stock: 5, category, supplier_id: adminId, status: 'active',
    images_urls: ['/images/products/seo-test.png']
  }).select().single();

  const sitemapRes2 = await fetch(`${API}/sitemap.xml`);
  const sitemapText2 = await sitemapRes2.text();
  assert(sitemapText2.includes(`/product/${product.id}`), '방금 만든 판매중 상품이 sitemap.xml에 정확히 포함됨');

  await admin.from('products_with').update({ status: 'inactive' }).eq('id', product.id);
  const sitemapRes3 = await fetch(`${API}/sitemap.xml`);
  const sitemapText3 = await sitemapRes3.text();
  assert(!sitemapText3.includes(`/product/${product.id}`), '비활성(inactive) 상품은 sitemap.xml에서 정직하게 제외됨');
  await admin.from('products_with').update({ status: 'active' }).eq('id', product.id);

  // ============================================
  // 3) 상품 상세 페이지 - 서버측 Open Graph + JSON-LD 주입
  // ============================================
  const prodPageRes = await fetch(`${API}/product/${product.id}`);
  const prodPageHtml = await prodPageRes.text();
  assert(prodPageRes.status === 200, '상품 상세 페이지가 200으로 응답함');
  assert(prodPageHtml.includes(`<title>${seoProductName} - WITH+</title>`), '상품명이 실제로 <title> 태그에 반영됨');
  assert(prodPageHtml.includes('og:title" content="' + seoProductName), 'og:title에 실제 상품명이 들어감');
  assert(prodPageHtml.includes('og:description'), 'og:description이 포함됨');
  assert(prodPageHtml.includes('product:price:amount" content="12345"'), 'og 가격 메타태그에 실제 가격이 정확히 반영됨');
  assert(prodPageHtml.includes('og:image" content="http://'), 'og:image가 절대 URL로 변환되어 포함됨(상대경로 그대로 노출되지 않음)');
  assert(prodPageHtml.includes('application/ld+json'), 'JSON-LD 구조화데이터 스크립트가 포함됨');
  const ldMatch = prodPageHtml.match(/<script type="application\/ld\+json">([^<]+)<\/script>/);
  assert(!!ldMatch, 'JSON-LD 스크립트 내용을 추출할 수 있음');
  if (ldMatch) {
    const ld = JSON.parse(ldMatch[1]);
    assert(ld['@type'] === 'Product' && ld.name === seoProductName, 'JSON-LD가 유효한 Product 스키마이며 실제 상품명을 담고 있음');
    assert(ld.offers && ld.offers.price === '12345' && ld.offers.priceCurrency === 'KRW', 'JSON-LD offers에 실제 가격/통화가 정확히 반영됨');
    assert(!ld.aggregateRating, '리뷰가 없는 상품은 가짜 평점을 만들지 않고 aggregateRating을 정직하게 생략함');
  }

  // 리뷰를 하나 추가한 뒤 aggregateRating이 정확히 반영되는지 확인
  await admin.from('product_reviews').insert({ product_id: product.id, user_id: adminId, rating: 5, comment: 'SEO 테스트 리뷰', status: 'published' });
  const prodPageRes2 = await fetch(`${API}/product/${product.id}`);
  const prodPageHtml2 = await prodPageRes2.text();
  const ldMatch2 = prodPageHtml2.match(/<script type="application\/ld\+json">([^<]+)<\/script>/);
  const ld2 = JSON.parse(ldMatch2[1]);
  assert(ld2.aggregateRating && ld2.aggregateRating.ratingValue === '5.0' && ld2.aggregateRating.reviewCount === '1', `리뷰가 생기면 JSON-LD에 실제 평균 평점이 정확히 반영됨 (실제: ${JSON.stringify(ld2.aggregateRating)})`);

  // 존재하지 않는 상품/비활성 상품은 가짜 메타태그 없이 기본 템플릿 그대로 응답
  const notFoundRes = await fetch(`${API}/product/00000000-0000-0000-0000-000000000000`);
  const notFoundHtml = await notFoundRes.text();
  assert(notFoundRes.status === 200 && notFoundHtml.includes('<title>상품 상세 - WITH+</title>'), '존재하지 않는 상품 id는 가짜 메타태그 없이 기본 템플릿 그대로 응답함');

  // ============================================
  // 4) 카테고리 페이지 - 서버측 Open Graph 주입
  // ============================================
  const { data: testCategory } = await admin.from('categories').insert({
    slug: `seo-cat-${ts}`, label: `SEO테스트카테고리${ts}`, emoji: '🧪', db_category: `seo-cat-${ts}`, is_active: true, display_order: 999
  }).select().single();

  const catPageRes = await fetch(`${API}/category/${testCategory.slug}`);
  const catPageHtml = await catPageRes.text();
  assert(catPageHtml.includes(`<title>${testCategory.label} - WITH+</title>`), '카테고리명이 실제로 <title> 태그에 반영됨');
  assert(catPageHtml.includes('og:title" content="' + testCategory.label), 'og:title에 실제 카테고리명이 들어감');

  await admin.from('categories').update({ is_active: false }).eq('id', testCategory.id);
  const catPageRes2 = await fetch(`${API}/category/${testCategory.slug}`);
  const catPageHtml2 = await catPageRes2.text();
  assert(catPageHtml2.includes('<title>카테고리 - WITH+</title>'), '비노출(is_active=false) 카테고리는 가짜 메타태그 없이 기본 템플릿 그대로 응답함');

  const catNotFoundRes = await fetch(`${API}/category/존재하지않는카테고리-${ts}`);
  const catNotFoundHtml = await catNotFoundRes.text();
  assert(catNotFoundRes.status === 200 && catNotFoundHtml.includes('<title>카테고리 - WITH+</title>'), '존재하지 않는 카테고리 슬러그도 가짜 메타태그 없이 기본 템플릿 그대로 응답함');

  // ============================================
  // 5) 홈 화면 - 정적 OG 태그/구조화데이터 확인 (회귀 없음 겸 실제 반영 확인)
  // ============================================
  const homeRes = await fetch(`${API}/`);
  const homeHtml = await homeRes.text();
  assert(homeHtml.includes('property="og:title"'), '홈 화면에 og:title이 포함됨');
  assert(homeHtml.includes('name="description"'), '홈 화면에 meta description이 포함됨');
  assert(homeHtml.includes('"@type": "Organization"') || homeHtml.includes('"@type":"Organization"'), '홈 화면에 Organization JSON-LD가 포함됨');
  assert(homeHtml.includes('"@type": "WebSite"') || homeHtml.includes('"@type":"WebSite"'), '홈 화면에 WebSite(SearchAction) JSON-LD가 포함됨');

  // ============================================
  // 정리
  // ============================================
  await admin.from('product_reviews').delete().eq('product_id', product.id);
  await admin.from('products_with').delete().eq('id', product.id);
  await admin.from('categories').delete().eq('id', testCategory.id);
  await admin.from('profiles').delete().eq('id', adminId);
  await admin.auth.admin.deleteUser(adminId);
  console.log('정리 완료: 테스트 상품/카테고리/계정 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
