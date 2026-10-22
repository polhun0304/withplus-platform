/* 설치형 앱(PWA) 표준 v1 — 서비스워커 등록 + "앱으로 설치" 안내 (PWA_APP_STANDARD.md, PwaClient 바닐라 이식)
 *  - Android·PC 크롬/엣지/삼성인터넷: 브라우저 설치 창(beforeinstallprompt)
 *  - iPhone/iPad 사파리: '공유 → 홈 화면에 추가' 그림 안내
 *  - 카카오톡·네이버·인스타그램 등 앱 안 브라우저: 설치가 안 되므로 '다른 브라우저로 열기' 안내 + 주소 복사
 *  - 이미 설치해서 앱으로 연 경우·관리/인증 화면·최근 닫음(14일)에는 자동 배너를 띄우지 않는다
 * 📱 앱 버전: 메뉴·마이페이지의 "앱 설치" 버튼([data-wp-app-install] 또는 WithPlusPWA.open())은
 *  자동 배너를 닫았던 분도 언제든 설치 창을 열 수 있다. 앱으로 실행 중이면 버튼을 숨긴다(html.wp-standalone).
 * 브랜드 값은 아래 PWA 한 곳만 바꾸면 된다. */
(function () {
  'use strict';
  if (window.__pwaInstallV1) return;
  window.__pwaInstallV1 = true;

  var PWA = {
    name: 'WITH+',
    icon: '/images/icons/icon-192.png',
    color: '#D32F5B',
    dismissDays: 14,
    dismissKey: 'wp_pwa_install_dismissed_at', // 기존 배너와 같은 키 — 이미 닫은 분께 다시 띄우지 않음
    hideOn: ['/admin', '/seller', '/login', '/join', '/reset-password', '/verify-phone', '/auth', '/payment-result', '/live-host-control', '/offline']
  };

  if ('serviceWorker' in navigator && location.protocol !== 'file:') {
    var reg = function () { navigator.serviceWorker.register('/sw.js').catch(function () {}); };
    if (document.readyState === 'complete') reg(); else window.addEventListener('load', reg);
  }

  var standalone = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches)
    || window.navigator.standalone === true
    || /^android-app:\/\//.test(document.referrer || ''); // Play 스토어 앱(TWA)으로 열린 경우
  var ua = navigator.userAgent || '';
  var inApp = /KAKAOTALK|NAVER\(inapp|Instagram|FBAN|FBAV|Line\/|DaumApps|everytimeApp|BAND\//i.test(ua);
  var ios = /iphone|ipad|ipod/i.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
  var iosSafari = ios && /safari/i.test(ua) && !/crios|fxios|edgios/i.test(ua);
  var iosOther = ios && !iosSafari;
  var installed = false;

  // 앱으로 실행 중이면 "앱 설치" 버튼을 모두 숨긴다
  var STYLE = 'html.wp-standalone [data-wp-app-install],html.wp-standalone [data-wp-app-install-card]{display:none !important;}';
  try {
    var st = document.createElement('style');
    st.textContent = STYLE;
    (document.head || document.documentElement).appendChild(st);
    if (standalone) document.documentElement.classList.add('wp-standalone');
  } catch (e) { /* 무시 */ }

  var path = (location.pathname || '/').replace(/\.html$/, '');
  var autoAllowed = !standalone;
  for (var i = 0; i < PWA.hideOn.length && autoAllowed; i++) {
    var h = PWA.hideOn[i];
    if (path === h || path.indexOf(h + '/') === 0) autoAllowed = false;
  }
  try {
    var at = Number(localStorage.getItem(PWA.dismissKey) || 0);
    if (at && Date.now() - at < PWA.dismissDays * 864e5) autoAllowed = false;
  } catch (e) { /* 저장소 불가 시 무시 */ }

  var mode = null; // 'native' | 'ios' | 'inapp' | null
  var deferred = null;
  var bar = null;
  var sheet = null;

  function el(tag, css, text) {
    var n = document.createElement(tag);
    if (css) n.style.cssText = css;
    if (text != null) n.textContent = text;
    return n;
  }
  function svg(markup, size) {
    var s = el('span', 'display:inline-flex;align-items:center;justify-content:center;width:' + size + 'px;height:' + size + 'px;flex-shrink:0;');
    s.innerHTML = markup;
    return s;
  }
  var ICON_SHARE = '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#007AFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12"/><path d="M8 7l4-4 4 4"/><path d="M6 11H5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-8a1 1 0 0 0-1-1h-1"/></svg>';
  var ICON_ADD = '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#0f172a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="4"/><path d="M12 8v8M8 12h8"/></svg>';
  var ICON_DOTS = '<svg viewBox="0 0 24 24" width="22" height="22" fill="#0f172a" aria-hidden="true"><circle cx="5" cy="12" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="19" cy="12" r="2"/></svg>';
  var ICON_GLOBE = '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#0f172a" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>';
  var ICON_OK = '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#16a34a" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12l5 5 9-10"/></svg>';

  function closeBar() { if (bar) { bar.remove(); bar = null; } }
  function closeSheet() { if (sheet) { sheet.remove(); sheet = null; document.removeEventListener('keydown', onKey); } }
  function onKey(e) { if (e.key === 'Escape') closeSheet(); }

  function dismiss() {
    closeBar();
    closeSheet();
    try { localStorage.setItem(PWA.dismissKey, String(Date.now())); } catch (e) { /* 무시 */ }
  }

  // 그림 단계 안내: [{icon, text}]
  function illustratedSteps(items) {
    var ol = el('ol', 'list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:10px;');
    items.forEach(function (it, idx) {
      var li = el('li', 'display:flex;align-items:center;gap:12px;padding:10px 12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;');
      li.appendChild(el('span', 'flex-shrink:0;width:22px;height:22px;border-radius:50%;background:' + PWA.color + ';color:#fff;font-size:12px;font-weight:800;display:flex;align-items:center;justify-content:center;', String(idx + 1)));
      if (it.icon) {
        var ic = svg(it.icon, 36);
        ic.style.background = '#fff';
        ic.style.border = '1px solid #e2e8f0';
        ic.style.borderRadius = '10px';
        li.appendChild(ic);
      }
      var t = el('span', 'flex:1;min-width:0;font-size:14px;line-height:1.5;color:#334155;word-break:keep-all;');
      t.innerHTML = it.text; // 고정 문구만 사용(사용자 입력 없음)
      li.appendChild(t);
      ol.appendChild(li);
    });
    return ol;
  }

  function primaryBtn(label, onClick) {
    var b = el('button', 'margin-top:14px;width:100%;font-size:15px;font-weight:700;color:#fff;background:' + PWA.color + ';border:0;border-radius:12px;padding:13px;cursor:pointer;', label);
    b.type = 'button';
    b.addEventListener('click', onClick);
    return b;
  }

  function showSheet(fromBanner) {
    closeSheet();
    sheet = el('div', 'position:fixed;inset:0;z-index:10000;background:rgba(2,6,23,.5);display:flex;align-items:flex-end;justify-content:center;');
    sheet.setAttribute('role', 'dialog');
    sheet.setAttribute('aria-modal', 'true');
    sheet.setAttribute('aria-label', PWA.name + ' 앱 설치');
    sheet.addEventListener('click', function () { if (fromBanner) dismiss(); else closeSheet(); });
    var box = el('div', 'position:relative;background:#fff;color:#0f172a;width:100%;max-width:460px;max-height:90vh;overflow-y:auto;border-top-left-radius:18px;border-top-right-radius:18px;padding:20px 20px calc(24px + env(safe-area-inset-bottom));box-sizing:border-box;font-family:inherit;');
    box.addEventListener('click', function (e) { e.stopPropagation(); });

    var x = el('button', 'position:absolute;top:10px;right:10px;width:36px;height:36px;font-size:22px;line-height:1;color:#94a3b8;background:transparent;border:0;cursor:pointer;', '×');
    x.type = 'button';
    x.setAttribute('aria-label', '닫기');
    x.addEventListener('click', function () { if (fromBanner) dismiss(); else closeSheet(); });
    box.appendChild(x);

    var head = el('div', 'display:flex;align-items:center;gap:12px;margin:0 36px 14px 0;');
    var img = el('img', 'width:48px;height:48px;border-radius:12px;flex-shrink:0;box-shadow:0 2px 8px rgba(2,6,23,.12);');
    img.src = PWA.icon; img.alt = '';
    var ht = el('div', 'min-width:0;');
    var title = el('div', 'font-size:17px;font-weight:800;');
    var sub = el('div', 'font-size:12.5px;color:#64748b;margin-top:2px;');
    ht.appendChild(title); ht.appendChild(sub);
    head.appendChild(img); head.appendChild(ht);
    box.appendChild(head);

    if (standalone || installed) {
      title.textContent = '이미 앱으로 쓰고 계세요';
      sub.textContent = '홈 화면의 ' + PWA.name + ' 아이콘으로 바로 열 수 있어요.';
      box.appendChild(primaryBtn('확인', closeSheet));
    } else if (inApp) {
      title.textContent = '다른 브라우저로 열어 주세요';
      sub.textContent = '카카오톡·네이버·인스타그램 안에서는 앱 설치가 안 돼요.';
      box.appendChild(illustratedSteps([
        { icon: ICON_DOTS, text: '화면 오른쪽 위(또는 아래)의 <b>⋯ 메뉴</b>를 누르세요.' },
        { icon: ICON_GLOBE, text: '<b>‘다른 브라우저로 열기’</b>를 고르세요.<br><span style="color:#64748b;font-size:12.5px;">아이폰은 ‘Safari로 열기’</span>' },
        { icon: ICON_ADD, text: '열린 화면에서 메뉴의 <b>📱 앱 설치</b>를 다시 누르면 끝!' }
      ]));
      var copyBtn = el('button', 'margin-top:12px;width:100%;font-size:14px;font-weight:700;color:#0f172a;background:#f1f5f9;border:0;border-radius:12px;padding:12px;cursor:pointer;', '이 주소 복사하기');
      copyBtn.type = 'button';
      copyBtn.addEventListener('click', function () {
        var done = function () { copyBtn.textContent = '주소를 복사했어요 — 브라우저에 붙여 넣으세요'; };
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(location.href).then(done, function () {});
        } catch (e) { /* 무시 */ }
      });
      box.appendChild(copyBtn);
      box.appendChild(primaryBtn('확인', fromBanner ? dismiss : closeSheet));
    } else if (iosSafari) {
      title.textContent = '홈 화면에 추가하기';
      sub.textContent = 'iPhone·iPad 사파리에서 3단계면 앱처럼 쓸 수 있어요.';
      box.appendChild(illustratedSteps([
        { icon: ICON_SHARE, text: '화면 아래(아이패드는 위)의 <b>공유 버튼</b>을 누르세요.' },
        { icon: ICON_ADD, text: '메뉴를 올려 <b>‘홈 화면에 추가’</b>를 고르세요.' },
        { icon: ICON_OK, text: '오른쪽 위 <b>‘추가’</b>를 누르면 홈 화면에 ' + PWA.name + ' 아이콘이 생겨요.' }
      ]));
      box.appendChild(primaryBtn('확인', fromBanner ? dismiss : closeSheet));
    } else if (iosOther) {
      title.textContent = '사파리에서 열어 주세요';
      sub.textContent = '아이폰은 사파리(Safari)에서만 홈 화면에 추가할 수 있어요.';
      box.appendChild(illustratedSteps([
        { icon: ICON_GLOBE, text: '이 주소를 <b>Safari</b>로 여세요.' },
        { icon: ICON_SHARE, text: '<b>공유 버튼</b> → <b>‘홈 화면에 추가’</b>를 누르세요.' }
      ]));
      box.appendChild(primaryBtn('확인', fromBanner ? dismiss : closeSheet));
    } else if (deferred) {
      title.textContent = PWA.name + ' 앱 설치';
      sub.textContent = '설치하면 홈 화면 아이콘으로 바로 열리고, 주문·배송 알림을 받을 수 있어요.';
      box.appendChild(illustratedSteps([
        { icon: ICON_ADD, text: '아래 <b>‘지금 설치하기’</b>를 누르세요.' },
        { icon: ICON_OK, text: '브라우저 창에서 <b>‘설치’</b>를 누르면 끝!' }
      ]));
      box.appendChild(primaryBtn('지금 설치하기', function () { closeSheet(); nativePrompt(); }));
    } else {
      title.textContent = PWA.name + ' 앱 설치';
      sub.textContent = '크롬·삼성 인터넷·엣지에서 설치할 수 있어요.';
      box.appendChild(illustratedSteps([
        { icon: ICON_DOTS, text: '브라우저 메뉴(<b>⋮</b> 또는 <b>≡</b>)를 누르세요.' },
        { icon: ICON_ADD, text: '<b>‘앱 설치’</b> 또는 <b>‘홈 화면에 추가’</b>를 고르세요.<br><span style="color:#64748b;font-size:12.5px;">PC 크롬·엣지는 주소창 오른쪽의 설치 아이콘(⊕)을 눌러도 돼요.</span>' }
      ]));
      box.appendChild(primaryBtn('확인', fromBanner ? dismiss : closeSheet));
    }

    sheet.appendChild(box);
    document.body.appendChild(sheet);
    document.addEventListener('keydown', onKey);
    try { x.focus(); } catch (e) { /* 무시 */ }
  }

  function nativePrompt() {
    if (!deferred) { showSheet(false); return; }
    var d = deferred;
    deferred = null;
    Promise.resolve(d.prompt()).then(function () { return d.userChoice; }).catch(function () {}).then(function () { closeBar(); });
  }

  function act() {
    if (mode === 'native' && deferred) { nativePrompt(); return; }
    showSheet(true);
  }

  function render() {
    if (!autoAllowed || !mode || !document.body) return;
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

  // 메뉴·마이페이지 등 어디서든 "앱 설치" 창 열기
  function open() {
    closeBar();
    if (!standalone && !installed && !inApp && !ios && deferred) {
      // 크롬·삼성 인터넷: 안내 창 없이 곧바로 브라우저 설치 창
      nativePrompt();
      return;
    }
    whenReady(function () { showSheet(false); });
  }
  window.WithPlusPWA = {
    open: open,
    isStandalone: function () { return standalone; },
    canPromptNative: function () { return !!deferred; },
    platform: inApp ? 'inapp' : (iosSafari ? 'ios' : (iosOther ? 'ios-other' : 'browser'))
  };
  document.addEventListener('click', function (e) {
    var t = e.target && e.target.closest ? e.target.closest('[data-wp-app-install]') : null;
    if (!t) return;
    e.preventDefault();
    open();
  });

  if (standalone) return;

  if (inApp) mode = 'inapp';
  else if (iosSafari) mode = 'ios';
  if (mode) whenReady(render);

  window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault();
    deferred = e;
    mode = 'native';
    whenReady(render);
  });
  window.addEventListener('appinstalled', function () {
    deferred = null; mode = null; installed = true; closeBar(); closeSheet();
  });
  // 마이페이지 등에서 /…#app-install 로 들어오면 설치 창을 바로 연다
  if (location.hash === '#app-install') whenReady(function () { setTimeout(open, 300); });
})();
