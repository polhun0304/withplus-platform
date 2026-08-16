// 마케팅자동화 탭(세그먼트 캠페인/캠페인 이력/자동 쿠폰 규칙) 전용 브라우저 시각/콘솔에러 확인 스크립트
const { chromium } = require('playwright');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
const API = 'http://localhost:3003';

(async () => {
  const ts = Date.now();
  const password = 'TestPass123!';
  const email = `test-mkt-browser-${ts}@withplus-test.local`;
  let userId;
  const consoleErrors = [];
  const failedRequests = [];

  try {
    const { data: user } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
    userId = user.user.id;
    await admin.from('profiles').upsert([{ id: userId, email, full_name: 'MarketingBrowserTest', role: 'super_admin' }]);

    const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
    const page = await browser.newPage();
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', err => consoleErrors.push('pageerror: ' + err.message));
    page.on('requestfailed', req => failedRequests.push(`${req.method()} ${req.url()} :: ${req.failure()?.errorText}`));
    page.on('response', res => { if (res.status() >= 400) failedRequests.push(`${res.status()} ${res.url()}`); });
    page.on('dialog', async d => { failedRequests.push(`DIALOG(${d.type()}): ${d.message()}`); await d.dismiss().catch(() => {}); });

    const projectRef = supabaseUrl.match(/https:\/\/([a-z0-9]+)\.supabase\.co/)[1];
    const authRes = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', apikey: anonKey },
      body: JSON.stringify({ email, password })
    });
    const authJson = await authRes.json();

    await page.goto(`${API}/admin`, { waitUntil: 'domcontentloaded' });
    await page.evaluate(({ key, session }) => {
      localStorage.setItem(key, JSON.stringify({
        access_token: session.access_token, refresh_token: session.refresh_token,
        expires_at: Math.floor(Date.now() / 1000) + 3600, token_type: 'bearer',
        user: session.user
      }));
    }, { key: `sb-${projectRef}-auth-token`, session: authJson });

    await page.reload({ waitUntil: 'networkidle' });
    await page.waitForTimeout(1500);

    console.log('마케팅자동화 탭 버튼 존재:', await page.locator('[data-tab="marketing"]').count() > 0);
    await page.locator('[data-tab="marketing"]').click();
    await page.waitForSelector('#tab-marketing.active, #tab-marketing[style*="display: block"]', { timeout: 8000 }).catch(() => {});
    // dataset.loaded는 비동기 로딩 함수들을 기다리지 않고 클릭 즉시(동기적으로) 세팅되는 "중복 로딩 방지" 플래그일
    // 뿐이라 완료 신호로 쓸 수 없다 - 실제 데이터(등급 옵션/캠페인 이력 텍스트)가 채워질 때까지 기다린다.
    await page.waitForFunction(
      () => (document.getElementById('mkt-filter-grades')?.options.length || 0) > 0
        && !(document.getElementById('mkt-campaign-history-area')?.innerText || '').includes('불러오는 중')
        && !(document.getElementById('mkt-rules-area')?.innerText || '').includes('불러오는 중'),
      { timeout: 8000 }
    ).catch(() => {});

    console.log('세그먼트 캠페인 카드 표시:', await page.locator('#mkt-campaign-name').isVisible());
    console.log('등급 필터 옵션 개수(로딩됨):', await page.locator('#mkt-filter-grades option').count());
    console.log('자동 쿠폰 규칙 - 등급 셀렉트 옵션 개수(로딩됨):', await page.locator('#mkt-rule-grade option').count());
    console.log('캠페인 이력 영역 로딩 완료(불러오는 중 문구 사라짐):', !(await page.locator('#mkt-campaign-history-area').innerText()).includes('불러오는 중'));
    console.log('자동 쿠폰 규칙 목록 영역 로딩 완료:', !(await page.locator('#mkt-rules-area').innerText()).includes('불러오는 중'));

    // 세그먼트 미리보기 버튼 클릭 - 결과 영역에 내용이 채워지는지
    await page.locator('#mkt-preview-btn').click();
    await page.waitForFunction(
      () => (document.getElementById('mkt-preview-result')?.textContent || '').includes('대상 회원'),
      { timeout: 8000 }
    ).catch(() => {});
    console.log('세그먼트 미리보기 결과 표시:', (await page.locator('#mkt-preview-result').innerText()).includes('대상 회원'));

    // 규칙 종류를 구매마일스톤으로 바꾸면 등급 필드는 숨고 마일스톤 필드가 보이는지
    await page.locator('#mkt-rule-type').selectOption('purchase_milestone');
    await page.waitForTimeout(300);
    console.log('마일스톤 선택 시 등급 필드 숨김:', !(await page.locator('#mkt-rule-grade-field').isVisible()));
    console.log('마일스톤 선택 시 마일스톤 필드 표시:', await page.locator('#mkt-rule-milestone-field').isVisible());

    await page.screenshot({ path: '/tmp/marketing_tab_screenshot.png', fullPage: true });

    console.log('\n콘솔 에러 수:', consoleErrors.length);
    consoleErrors.forEach(e => console.log(' - console:', e));
    console.log('실패한 네트워크 요청 수:', failedRequests.length);
    failedRequests.forEach(e => console.log(' - request:', e));

    await browser.close();
    process.exit(0);
  } catch (err) {
    console.error('실패:', err.message);
    process.exit(1);
  } finally {
    if (userId) await admin.auth.admin.deleteUser(userId);
  }
})();
