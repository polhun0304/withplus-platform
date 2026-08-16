// admin.html의 새 "창고관리(WMS)" 탭이 실제 브라우저에서 콘솔 에러 없이 렌더링되고
// 서브탭(재고원장/스캔/로케이션/디지털트윈/AGV)이 정상 전환되는지 눈으로 보듯 확인한다.
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
  const email = `test-wms-browser-${ts}@withplus-test.local`;
  let userId;
  const consoleErrors = [];

  try {
    const { data: user } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
    userId = user.user.id;
    await admin.from('profiles').upsert([{ id: userId, email, full_name: 'WmsBrowserTest', role: 'super_admin' }]);

    const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
    const page = await browser.newPage();
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    page.on('pageerror', err => consoleErrors.push('pageerror: ' + err.message));

    // 로그인 페이지에서 실제 로그인 흐름을 타는 대신, localStorage에 세션을 직접 주입해 admin.html로 바로 진입
    await page.goto(`${API}/login`, { waitUntil: 'domcontentloaded' });
    const { data: signInData } = await admin.auth.signInWithPassword ? {} : {};
    const authRes = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', apikey: anonKey },
      body: JSON.stringify({ email, password })
    });
    const authJson = await authRes.json();

    await page.evaluate((session) => {
      const key = Object.keys(localStorage).find(k => k.includes('supabase.auth.token')) || 'sb-' + location.hostname + '-auth-token';
    }, null);

    // supabase-js v2는 localStorage 키를 `sb-<project-ref>-auth-token` 형태로 사용한다
    const projectRef = supabaseUrl.match(/https:\/\/([a-z0-9]+)\.supabase\.co/)[1];
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

    const wmsTabVisible = await page.locator('[data-tab="wms"]').count();
    console.log('WMS 탭 버튼 존재:', wmsTabVisible > 0);

    if (wmsTabVisible > 0) {
      await page.locator('[data-tab="wms"]').click();
      await page.waitForTimeout(1000);
      const ledgerVisible = await page.locator('#wms-tab-ledger.active').count();
      console.log('재고원장 서브탭 기본 활성:', ledgerVisible > 0);

      for (const sub of ['scan', 'locations', 'twin', 'agv']) {
        const btn = page.locator(`[data-wms-tab="${sub}"]`);
        if (await btn.count() > 0) {
          await btn.click();
          await page.waitForTimeout(800);
          const panelVisible = await page.locator(`#wms-tab-${sub}.active`).count();
          console.log(`서브탭 [${sub}] 전환 성공:`, panelVisible > 0);
        }
      }

      // 스캔 터미널 실제 입력 테스트
      await page.locator('[data-wms-tab="scan"]').click();
      await page.waitForTimeout(500);
      const scanInputCount = await page.locator('#wms-scan-barcode-input').count();
      console.log('스캔 입력창 존재:', scanInputCount > 0);
    }

    console.log('\n콘솔 에러 수:', consoleErrors.length);
    if (consoleErrors.length > 0) consoleErrors.forEach(e => console.log(' -', e));

    await page.screenshot({ path: '/tmp/wms_screenshot.png', fullPage: true });
    await browser.close();
    process.exit(consoleErrors.length > 0 ? 1 : 0);
  } catch (err) {
    console.error('💥 실패:', err.message);
    process.exit(1);
  } finally {
    if (userId) await admin.auth.admin.deleteUser(userId);
  }
})();
