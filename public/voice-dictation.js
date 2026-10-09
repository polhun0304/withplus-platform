/*
 * 음성 입력(말로 쓰기) — 모든 페이지 공통. 각 페이지에 <script src="/voice-dictation.js?v=1" defer></script> 한 줄.
 * 글을 쓰는 칸(여러 줄 칸·한 줄 글자 칸)을 누르면 칸 오른쪽에 🎤 버튼이 뜨고, 누르고 말하면 커서 위치에 글자로 들어간다.
 * - 브라우저 내장 음성 인식(Web Speech API, 한국어) — 서버로 따로 보내는 것 없음, 키 불필요
 * - 비밀번호·이메일·전화·숫자·주소(URL)·코드 칸, 읽기 전용 칸, data-no-mic 이 붙은 칸에는 뜨지 않는다
 * - 지원하지 않는 브라우저(파이어폭스 등)에서는 아무것도 하지 않는다
 * - 기본 setter + input 이벤트로 넣어 페이지 스크립트의 입력 감지도 그대로 동작
 * 필요: Permissions-Policy 에서 microphone=(self) (microphone=() 이면 막힌다)
 * (EKOS AEO src/components/VoiceDictation.tsx 와 같은 동작의 바닐라 JS 판)
 */
(function () {
  'use strict';
  if (window.__voiceDictation) return;
  window.__voiceDictation = true;
  var Ctor = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!Ctor) return;

  var SKIP_NAME = /pass|email|phone|tel|mobile|zip|postal|url|domain|slug|code|amount|price|fee|rate|qty|quantity|number|no$|_no|otp|token|key|card|account|birth|date/i;

  function eligible(el) {
    if (!el) return false;
    if (el instanceof HTMLTextAreaElement) return !el.readOnly && !el.disabled && !el.closest('[data-no-mic]');
    if (!(el instanceof HTMLInputElement)) return false;
    if (['text', 'search', ''].indexOf(el.type) < 0 || el.readOnly || el.disabled || el.closest('[data-no-mic]')) return false;
    if (el.dataset.mic === 'on') return true;
    var im = el.inputMode;
    if (im && im !== 'text' && im !== 'search') return false;
    var ac = el.autocomplete || '';
    if (/email|tel|password|one-time-code|postal|cc-|url|bday/.test(ac)) return false;
    return !SKIP_NAME.test((el.name || '') + ' ' + (el.id || ''));
  }

  function insertText(el, text) {
    var start = el.selectionStart == null ? el.value.length : el.selectionStart;
    var end = el.selectionEnd == null ? el.value.length : el.selectionEnd;
    var before = el.value.slice(0, start);
    var sep = before && !/\s$/.test(before) ? ' ' : '';
    var next = before + sep + text + el.value.slice(end);
    if (el.maxLength > 0) next = next.slice(0, el.maxLength);
    var proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    var desc = Object.getOwnPropertyDescriptor(proto, 'value');
    if (desc && desc.set) desc.set.call(el, next); else el.value = next;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    var pos = Math.min(next.length, (before + sep + text).length);
    try { el.setSelectionRange(pos, pos); } catch (e) { /* 일부 칸은 커서 지정 불가 */ }
  }

  var ERR = {
    'not-allowed': '마이크 사용이 막혀 있습니다. 주소창 왼쪽 자물쇠 → 마이크 ‘허용’ 후 다시 눌러 주세요.',
    'service-not-allowed': '이 브라우저에서는 음성 인식을 쓸 수 없습니다. 크롬·엣지·사파리를 쓰거나 휴대폰 키보드의 🎤 를 이용해 주세요.',
    'audio-capture': '마이크를 찾지 못했습니다. 마이크 연결을 확인해 주세요.',
    'network': '음성 인식 서버에 연결하지 못했습니다(일부 브라우저는 지원하지 않음). 크롬·엣지에서 다시 시도해 주세요.',
    'no-speech': '말소리가 들리지 않았습니다. 다시 눌러 말씀해 주세요.'
  };

  var target = null, rec = null, msgTimer = null;
  var MIC_SVG = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="2" width="6" height="12" rx="3"/><path d="M5 10a7 7 0 0 0 14 0M12 17v5M8 22h8"/></svg>';

  var btn = document.createElement('button');
  btn.type = 'button';
  btn.innerHTML = MIC_SVG;
  btn.style.cssText = 'position:fixed;z-index:2147483000;display:none;width:32px;height:32px;padding:0;margin:0;border-radius:9999px;' +
    'align-items:center;justify-content:center;cursor:pointer;box-shadow:0 1px 3px rgba(0,0,0,.2);transition:background .15s,color .15s;';
  var status = document.createElement('div');
  status.setAttribute('role', 'status');
  status.style.cssText = 'position:fixed;bottom:16px;left:50%;transform:translateX(-50%);z-index:2147483001;display:none;max-width:92vw;' +
    'border-radius:12px;background:#0f172a;color:#fff;padding:8px 16px;font-size:14px;line-height:1.4;box-shadow:0 10px 15px rgba(0,0,0,.25);';
  var styleTag = document.createElement('style');
  styleTag.textContent = '@keyframes vdPulse{50%{opacity:.6}}';

  function paintButton() {
    var on = !!rec;
    btn.setAttribute('aria-label', on ? '음성 입력 멈추기' : '말로 입력하기');
    btn.title = on ? '멈추기' : '말로 입력하기(한국어)';
    btn.style.background = on ? '#e11d48' : '#fff';
    btn.style.color = on ? '#fff' : '#475569';
    btn.style.border = '1px solid ' + (on ? '#be123c' : '#cbd5e1');
    btn.style.animation = on ? 'vdPulse 2s cubic-bezier(.4,0,.6,1) infinite' : 'none';
  }

  function showStatus(html) {
    if (html == null) { status.style.display = 'none'; status.textContent = ''; return; }
    status.innerHTML = html;
    status.style.display = 'block';
  }
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function showMsg(m) {
    clearTimeout(msgTimer);
    showStatus(esc(m));
    msgTimer = setTimeout(function () { if (!rec) showStatus(null); }, 6000);
  }
  function showListening(interim) {
    clearTimeout(msgTimer);
    showStatus('🎤 듣는 중… ' + (interim ? '<span style="opacity:.7">' + esc(interim) + '</span>' : '말씀하세요 (다시 누르면 멈춤)'));
  }

  function place() {
    var el = target;
    if (!el || !el.isConnected) { btn.style.display = 'none'; return; }
    var r = el.getBoundingClientRect();
    if (r.width < 80 || r.bottom < 0 || r.top > window.innerHeight) { btn.style.display = 'none'; return; }
    var multi = el instanceof HTMLTextAreaElement;
    btn.style.top = (r.top + (multi ? 6 : Math.max(0, (r.height - 32) / 2))) + 'px';
    btn.style.left = (r.right - 38) + 'px';
    btn.style.display = 'flex';
  }

  function toggle() {
    if (rec) { rec.stop(); return; }
    var el = target;
    if (!el) return;
    var r = new Ctor();
    var lang = document.documentElement.lang || '';
    r.lang = lang.indexOf('en') === 0 ? 'en-US' : 'ko-KR';
    r.continuous = true;
    r.interimResults = true;
    r.onresult = function (e) {
      var live = '';
      for (var i = e.resultIndex; i < e.results.length; i++) {
        var res = e.results[i];
        var t = res[0].transcript.trim();
        if (!t) continue;
        if (res.isFinal) insertText(el, t); else live += t;
      }
      showListening(live);
    };
    r.onerror = function (e) {
      if (e.error !== 'aborted') { rec = null; paintButton(); showMsg(ERR[e.error] || ('음성 입력 오류(' + e.error + '). 다시 눌러 주세요.')); }
    };
    r.onend = function () {
      var hadMsg = status.style.display !== 'none' && rec === null;
      rec = null; paintButton();
      if (!hadMsg) showStatus(null);
      try { el.focus(); } catch (x) { /* noop */ }
    };
    try {
      r.start();
      rec = r;
      paintButton();
      showListening('');
    } catch (x) {
      showMsg('음성 입력을 시작하지 못했습니다. 다시 눌러 주세요.');
    }
  }

  function init() {
    document.head.appendChild(styleTag);
    document.body.appendChild(btn);
    document.body.appendChild(status);
    paintButton();
    btn.addEventListener('mousedown', function (e) { e.preventDefault(); });
    btn.addEventListener('click', toggle);
    document.addEventListener('focusin', function (e) {
      if (e.target === btn) return;
      if (eligible(e.target)) { target = e.target; place(); }
    });
    document.addEventListener('focusout', function () {
      // 버튼을 누르는 순간 포커스가 빠지는 것은 mousedown 에서 막는다. 듣는 중이면 유지.
      setTimeout(function () {
        if (rec) return;
        var a = document.activeElement;
        if (a === btn) return;
        if (!eligible(a)) { target = null; btn.style.display = 'none'; }
      }, 150);
    });
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
    window.addEventListener('pagehide', function () { if (rec) rec.abort(); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
