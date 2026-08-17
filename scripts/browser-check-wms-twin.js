// 디지털트윈 고도화(다층/드래그편집/프리셋 툴박스) 전용 브라우저 시각 확인 스크립트
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
  const email = `test-wms-twin-${ts}@withplus-test.local`;
  let userId;
  const consoleErrors = [];
  const failedRequests = [];

  try {
    const { data: user } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
    userId = user.user.id;
    await admin.from('profiles').upsert([{ id: userId, email, full_name: 'WmsTwinBrowserTest', role: 'super_admin' }]);

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

    await page.locator('[data-tab="wms"]').click();
    await page.waitForTimeout(500);
    await page.locator('[data-wms-tab="twin"]').click();
    await page.waitForSelector('#wms-twin-floor-tabs .wms-floor-tab-btn', { timeout: 8000 }).catch(() => {});

    console.log('층 탭 렌더링:', await page.locator('#wms-twin-floor-tabs .wms-floor-tab-btn').count() > 0);
    console.log('편집모드 토글 버튼 존재:', await page.locator('#wms-twin-edit-toggle').count() > 0);

    // 편집 모드 켜기 → 툴박스 표시 확인
    await page.locator('#wms-twin-edit-toggle').click();
    await page.waitForTimeout(500);
    const toolboxVisible = await page.locator('#wms-twin-toolbox').isVisible();
    console.log('편집모드 진입 시 툴박스 표시:', toolboxVisible);

    // 사각랙 프리셋 클릭 → 새 랙 생성 + 캔버스에 그려지는지, 컨트롤패널 열리는지
    await page.locator('.wms-shape-btn[data-shape="rect"]').click();
    await page.waitForSelector('#wms-twin-control-panel[style*="display: block"]', { timeout: 8000 }).catch(() => {});
    const controlPanelVisible = await page.locator('#wms-twin-control-panel').isVisible();
    console.log('랙 추가 후 속성 컨트롤 패널 표시:', controlPanelVisible);
    const widthCmInputVal = await page.locator('#wms-twin-ctl-width-cm').inputValue().catch(() => null);
    console.log('컨트롤 패널 가로(cm) 입력값:', widthCmInputVal);

    // + 층 추가 → 새 층 탭이 늘어나는지
    const floorTabCountBefore = await page.locator('#wms-twin-floor-tabs .wms-floor-tab-btn').count();
    await page.locator('#wms-twin-add-floor-btn').click();
    await page.waitForFunction(
      (before) => document.querySelectorAll('#wms-twin-floor-tabs .wms-floor-tab-btn').length > before,
      floorTabCountBefore,
      { timeout: 8000 }
    ).catch(() => {});
    const floorTabCountAfter = await page.locator('#wms-twin-floor-tabs .wms-floor-tab-btn').count();
    console.log(`층 추가 전/후 탭 개수: ${floorTabCountBefore} -> ${floorTabCountAfter}`);

    // + 단 추가 → 같은 층 안에 새 단(복층/중층) 탭이 늘어나는지
    console.log('단(sub_level) 탭 렌더링:', await page.locator('#wms-twin-sublevel-tabs .wms-sublevel-tab-btn').count() > 0);
    const subLevelTabCountBefore = await page.locator('#wms-twin-sublevel-tabs .wms-sublevel-tab-btn').count();
    await page.locator('#wms-twin-add-sublevel-btn').click();
    await page.waitForFunction(
      (before) => document.querySelectorAll('#wms-twin-sublevel-tabs .wms-sublevel-tab-btn').length > before,
      subLevelTabCountBefore,
      { timeout: 8000 }
    ).catch(() => {});
    const subLevelTabCountAfter = await page.locator('#wms-twin-sublevel-tabs .wms-sublevel-tab-btn').count();
    console.log(`단 추가 전/후 탭 개수: ${subLevelTabCountBefore} -> ${subLevelTabCountAfter}`);

    await page.screenshot({ path: '/tmp/wms_twin_screenshot.png', fullPage: true });

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
