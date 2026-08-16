// Final accessibility (WCAG 2.0/2.1 AA) verification after color-contrast fixes.
// Checks the pages most likely to be affected by the --primary-color / --primary-dark / --success change.
const { chromium } = require('playwright');
const fs = require('fs');

const BASE = 'http://localhost:3003';
const PAGES = [
  { name: 'index', url: '/' },
  { name: 'category-all', url: '/category/all' },
  { name: 'join', url: '/join' },
  { name: 'mypage', url: '/mypage' },
  { name: '404', url: '/nonexistent-page-xyz' },
  { name: 'offline', url: '/offline.html' },
];

(async () => {
  const axeSource = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
  const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
  const page = await browser.newPage();

  let totalSerious = 0;
  let totalCritical = 0;
  let totalContrast = 0;

  for (const p of PAGES) {
    await page.goto(BASE + p.url, { waitUntil: 'domcontentloaded' });
    await page.addScriptTag({ content: axeSource });
    const results = await page.evaluate(async () => {
      return await axe.run(document, { runOnly: ['wcag2a', 'wcag2aa'] });
    });
    const serious = results.violations.filter(v => v.impact === 'serious');
    const critical = results.violations.filter(v => v.impact === 'critical');
    const contrast = results.violations.filter(v => v.id === 'color-contrast');
    totalSerious += serious.length;
    totalCritical += critical.length;
    totalContrast += contrast.length;
    console.log(`\n=== ${p.name} (${p.url}) ===`);
    console.log(`  전체 위반: ${results.violations.length}건 (critical=${critical.length}, serious=${serious.length}, contrast=${contrast.length})`);
    if (contrast.length > 0) {
      contrast.forEach(v => {
        console.log(`  [color-contrast] ${v.nodes.length}개 노드:`);
        v.nodes.slice(0, 3).forEach(n => console.log(`    - ${n.target.join(' ')}`));
      });
    }
  }

  console.log(`\n\n=== 최종 요약 ===`);
  console.log(`critical=${totalCritical}, serious=${totalSerious}, color-contrast=${totalContrast}`);
  await browser.close();
  process.exit(totalCritical > 0 ? 1 : 0);
})().catch(e => { console.error('FATAL:', e); process.exit(1); });
