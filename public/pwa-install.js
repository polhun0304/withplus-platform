/* 설치형 앱(PWA) 표준 v1 — 서비스워커 등록 + "앱으로 설치" 안내 (PWA_APP_STANDARD.md, PwaClient 바닐라 이식)
 *  - Android·PC 크롬/엣지/삼성인터넷: 브라우저 설치 창(beforeinstallprompt)
 *  - iPhone/iPad 사파리: '공유 → 홈 화면에 추가' 안내
 *  - 카카오톡·네이버·인스타그램 등 앱 안 브라우저: 설치가 안 되므로 '다른 브라우저로 열기' 안내 + 주소 복사
 *  - 이미 설치해서 앱으로 연 경우·관리/인증 화면·최근 닫음(14일)에는 띄우지 않는다
 * 브랜드 값은 아래 PWA 한 곳만 바꾸면 된다. */
(function () {
  'use strict';
  if (window.__pwaInstallV1) return;
  window.__pwaInstallV1 = true;

  var PWA = {
    name: 'WITH+',
    icon: '/pwa/icon/192',
    color: '#D32F5B',
    dismissDays: 14,
    dismissKey: 'wp_pwa_install_dismissed_at', // 기존 배너와 같은 키 — 이미 닫은 분께 다시 띄우지 않음
    hideOn: ['/admin', '/seller', '/login', '/join', '/reset-password', '/verify-phone', '/auth', '/payment-result', '/live-host-control']
  };

  if ('serviceWorker' in navigator && location.protocol !== 'file:') {
    var reg = function () { navigator.serviceWorker.register('/sw.js').catch(function () {}); };
    if (document.readyState === 'complete') reg(); else window.addEventListener('load', reg);
  }

  var standalone = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || window.navigator.standalone === true;
  if (standalone) return;

  var path = (location.pathname || '/').replace(/\.html$/, '');
  for (var i = 0; i < PWA.hideOn.length; i++) {
    var h = PWA.hideOn[i];
    if (path === h || path.indexOf(h + '/') === 0) return;
  }

  try {
    var at = Number(localStorage.getItem(PWA.dismissKey) || 0);
    if (at && Date.now() - at < PWA.dismissDays * 864e5) return;
  } catch (e) { /* 저장소 불가 시 무시 */ }

  var ua = navigator.userAgent || '';
  var inApp = /KAKAOTALK|NAVER\(inapp|Instagram|FBAN|FBAV|Line\/|DaumApps|everytimeApp/i.test(ua);
  var ios = /iphone|ipad|ipod/i.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
  var mode = null;
  var deferred = null;
  var bar = null;
  var sheet = null;

  function el(tag, css, text) {
    var n = document.createElement(tag);
    if (css) n.style.cssText = css;
    if (text != null) n.textContent = text;
    return n;
  }

  function close() {
    if (bar) { bar.remove(); bar = null; }
    if (sheet) { sheet.remove(); sheet = null; }
  }

  function dismiss() {
    close();
    mode = null;
    try { localStorage.setItem(PWA.dismissKey, String(Date.now())); } catch (e) { /* 무시 */ }
  }

  function steps(items) {
    var ol = el('ol', 'margin:0;padding-left:18px;font-size:14px;line-height:1.8;color:#334155;');
    items.forEach(function (t) { ol.appendChild(el('li', null, t)); });
    return ol;
  }

  function showHelp() {
    if (sheet) return;
    sheet = el('div', 'position:fixed;inset:0;z-index:10000;background:rgba(2,6,23,.5);display:flex;align-items:flex-end;justify-content:center;');
    sheet.addEventListener('click', dismiss);
    var box = el('div', 'background:#fff;color:#0f172a;width:100%;max-width:460px;border-top-left-radius:18px;border-top-right-radius:18px;padding:20px 20px calc(28px + env(safe-area-inset-bottom));box-sizing:border-box;');
    box.addEventListener('click', function (e) { e.stopPropagation(); });
    var title = el('div', 'font-size:16px;font-weight:800;margin-bottom:12px;');
    box.appendChild(title);
    if (mode === 'inapp') {
      title.textContent = '다른 브라우저로 열기';
      box.appendChild(steps([
        '오른쪽 위(또는 아래) ⋯ 메뉴를 누르세요.',
        '‘다른 브라우저로 열기’(아이폰은 ‘Safari로 열기’)를 고르세요.',
        '열린 화면에서 다시 ‘앱으로 쓰기’를 누르면 설치돼요.'
      ]));
      var copyBtn = el('button', 'margin-top:14px;width:100%;font-size:14px;font-weight:700;color:#0f172a;background:#f1f5f9;border:0;border-radius:12px;padding:11px;cursor:pointer;', '이 주소 복사하기');
      copyBtn.type = 'button';
      copyBtn.addEventListener('click', function () {
        var done = function () { copyBtn.textContent = '주소를 복사했어요 — 브라우저에 붙여 넣으세요'; };
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(location.href).then(done, function () {});
        } catch (e) { /* 무시 */ }
      });
      box.appendChild(copyBtn);
    } else if (mode === 'ios') {
      title.textContent = '홈 화면에 추가하기 (iPhone·iPad)';
      box.appendChild(steps([
        '사파리 아래쪽 공유 버튼(□↑)을 누르세요.',
        '메뉴에서 ‘홈 화면에 추가’를 고르세요.',
        '오른쪽 위 ‘추가’를 누르면 끝!'
      ]));
    } else {
      title.textContent = '앱으로 설치하기';
      box.appendChild(el('p', 'margin:0;font-size:14px;line-height:1.7;color:#334155;', '브라우저 메뉴(⋮)에서 ‘앱 설치’ 또는 ‘홈 화면에 추가’를 누르세요.'));
    }
    var ok = el('button', 'margin-top:14px;width:100%;font-size:15px;font-weight:700;color:#fff;background:' + PWA.color + ';border:0;border-radius:12px;padding:12px;cursor:pointer;', '확인');
    ok.type = 'button';
    ok.addEventListener('click', dismiss);
    box.appendChild(ok);
    sheet.appendChild(box);
    document.body.appendChild(sheet);
  }

  function act() {
    if (mode !== 'native' || !deferred) { showHelp(); return; }
    var d = deferred;
    deferred = null;
    Promise.resolve(d.prompt()).then(function () { return d.userChoice; }).catch(function () {}).then(function () { mode = null; close(); });
  }

  function render() {
    if (!mode || !document.body) return;
    if (bar) bar.remove();
    bar = el('div', 'position:fixed;left:16px;right:16px;bottom:calc(16px + env(safe-area-inset-bottom));z-index:9999;max-width:420px;margin:0 auto;display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:14px;background:#fff;color:#0f172a;box-shadow:0 10px 30px rgba(2,6,23,.18);border:1px solid #e2e8f0;box-sizing:border-box;font-family:inherit;');
    bar.id = 'pwa-install-banner';
    bar.setAttribute('role', 'dialog');
    bar.setAttribute('aria-label', '앱 설치 안내');
    var img = el('img', 'width:40px;height:40px;border-radius:10px;flex-shrink:0;');
    img.src = PWA.icon; img.alt = '';
    var txt = el('div', 'flex:1;min-width:0;');
    txt.appendChild(el('div', 'font-size:14px;font-weight:700;', PWA.name + ' 앱으로 쓰기'));
    txt.appendChild(el('div', 'font-size:12px;color:#475569;', mode === 'inapp' ? '이 화면에서는 설치가 안 돼요. 다른 브라우저로 열어 주세요.' : '홈 화면에 추가하면 앱처럼 바로 열려요.'));
    var go = el('button', 'flex-shrink:0;font-size:13px;font-weight:700;color:#fff;background:' + PWA.color + ';border:0;border-radius:10px;padding:9px 14px;cursor:pointer;', mode === 'native' ? '설치' : '방법 보기');
    go.type = 'button';
    go.addEventListener('click', act);
    var x = el('button', 'flex-shrink:0;font-size:18px;line-height:1;color:#94a3b8;background:transparent;border:0;padding:4px 6px;cursor:pointer;', '×');
    x.type = 'button';
    x.setAttribute('aria-label', '닫기');
    x.addEventListener('click', dismiss);
    bar.appendChild(img); bar.appendChild(txt); bar.appendChild(go); bar.appendChild(x);
    document.body.appendChild(bar);
  }

  function whenReady(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn); else fn();
  }

  if (inApp) mode = 'inapp';
  else if (ios && /safari/i.test(ua) && !/crios|fxios|edgios/i.test(ua)) mode = 'ios';
  if (mode) whenReady(render);

  window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault();
    deferred = e;
    mode = 'native';
    whenReady(render);
  });
  window.addEventListener('appinstalled', function () { deferred = null; mode = null; close(); });
})();
