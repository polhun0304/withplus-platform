// ⚡ 한정수량 초특가 — 홈 섹션 · /deals 페이지 · 상품 상세 공용 스크립트 (withplus-common.js 다음에 불러온다)
// 가격·잔여 수량은 모두 서버(/api/flash-deals) 실제 값만 보여준다. 결제 가격은 주문 생성 시 서버가 다시 계산한다.
(function (global) {
  'use strict';
  const W = global.WithPlus;
  let serverOffset = 0; // 서버 시각 - 내 기기 시각 (기기 시계가 틀려도 카운트다운이 맞도록)
  const now = () => Date.now() + serverOffset;

  function esc(s) { return W ? W.escapeHtml(s) : String(s == null ? '' : s); }
  function won(n) { return Number(n || 0).toLocaleString('ko-KR') + '원'; }
  function pad(n) { return String(n).padStart(2, '0'); }

  // 남은 시간 → { d, h, m, s }
  function splitMs(ms) {
    const t = Math.max(0, Math.floor(ms / 1000));
    return { d: Math.floor(t / 86400), h: Math.floor((t % 86400) / 3600), m: Math.floor((t % 3600) / 60), s: t % 60 };
  }
  // "06 : 23 : 45" (하루 이상 남으면 "2일 06 : 23 : 45")
  function timerHtml(ms, suffix) {
    const x = splitMs(ms);
    return `${x.d > 0 ? `<b>${x.d}일</b> ` : ''}<b>${pad(x.h)}</b><i> : </i><b>${pad(x.m)}</b><i> : </i><b>${pad(x.s)}</b>${suffix ? `<span class="fd-left"> ${suffix}</span>` : ''}`;
  }

  async function fetchDeals(opts) {
    const qs = new URLSearchParams();
    if (opts && opts.includeUpcoming) qs.set('include_upcoming', '1');
    if (opts && opts.limit) qs.set('limit', String(opts.limit));
    const res = await fetch('/api/flash-deals?' + qs.toString(), { cache: 'no-store' });
    const json = await res.json();
    if (!res.ok || !json.success) throw new Error(json.message || '초특가를 불러오지 못했습니다');
    if (json.server_time) serverOffset = new Date(json.server_time).getTime() - Date.now();
    return json;
  }

  function renderCard(d, opts) {
    const p = d.product || {};
    const img = Array.isArray(p.images_urls) && p.images_urls[0] ? p.images_urls[0] : null;
    const listPrice = Number(p.price) || 0;
    const regular = (p.discount_price && Number(p.discount_price) < listPrice) ? Number(p.discount_price) : listPrice; // 평소 판매가
    const rate = listPrice > 0 ? Math.round((1 - d.deal_price / listPrice) * 100) : 0;
    const soldPct = d.limit_qty > 0 ? Math.min(100, Math.round(d.sold_count / d.limit_qty * 100)) : 0;
    let stateHtml = '';
    if (d.status === 'soldout') stateHtml = '<span class="fd-state">SOLD OUT</span>';
    else if (d.status === 'upcoming') {
      const st = new Date(d.starts_at);
      stateHtml = `<span class="fd-state upcoming">${st.getMonth() + 1}/${st.getDate()} ${pad(st.getHours())}:${pad(st.getMinutes())}<br>오픈 예정</span>`;
    }
    const timer = opts && opts.cardTimer
      ? (d.status === 'upcoming'
        ? `<div class="fd-card-timer">오픈까지 <b data-fd-end="${esc(d.starts_at)}" data-fd-compact="1"></b></div>`
        : (d.status === 'active' ? `<div class="fd-card-timer">종료까지 <b data-fd-end="${esc(d.ends_at)}" data-fd-compact="1"></b></div>` : ''))
      : '';
    return `
      <a class="fd-card" href="/product/${encodeURIComponent(d.product_id)}" data-deal-id="${esc(d.id)}">
        <div class="fd-img">
          ${img ? `<img src="${W ? W.safeUrlAttr(img) : img}" alt="${esc(p.name)}" loading="lazy">` : '🎁'}
          ${rate > 0 ? `<span class="fd-badge">${rate}%</span>` : ''}
          ${stateHtml}
        </div>
        <div class="fd-name">${esc(p.name)}</div>
        <div class="fd-was">${listPrice > regular ? won(listPrice) : (regular > d.deal_price ? won(regular) : '')}</div>
        <div class="fd-price">
          ${listPrice > regular ? `<span class="fd-reg">${won(regular)}</span><span class="fd-arrow">→</span>` : ''}
          <span class="fd-deal">${won(d.deal_price)}</span>
        </div>
        <div class="fd-bar">
          <span class="fd-track"><span class="fd-fill" style="width:${soldPct}%"></span></span>
          <span class="fd-remain">${d.status === 'soldout' ? '소진' : `잔여 ${Number(d.remaining).toLocaleString('ko-KR')}개`}</span>
        </div>
        ${timer}
      </a>`;
  }

  // 1초마다 [data-fd-end] 요소들의 남은 시간을 갱신. 끝나면 onExpire 콜백(목록 새로고침)
  const expireHandlers = [];
  let ticking = false;
  function tick() {
    const t = now();
    let expired = false;
    document.querySelectorAll('[data-fd-end]').forEach(el => {
      const end = new Date(el.getAttribute('data-fd-end')).getTime();
      const left = end - t;
      if (left <= 0 && !el.dataset.fdDone) { el.dataset.fdDone = '1'; expired = true; }
      el.innerHTML = el.getAttribute('data-fd-compact')
        ? (() => { const x = splitMs(left); return (x.d > 0 ? x.d + '일 ' : '') + pad(x.h) + ':' + pad(x.m) + ':' + pad(x.s); })()
        : timerHtml(left, el.getAttribute('data-fd-suffix') || '');
    });
    if (expired) expireHandlers.forEach(fn => { try { fn(); } catch (e) { /* 무시 */ } });
  }
  function startTicker(onExpire) {
    if (onExpire) expireHandlers.push(onExpire);
    tick();
    if (ticking) return;
    ticking = true;
    setInterval(tick, 1000);
  }

  // 홈: 진행중 초특가가 있을 때만 섹션을 보여준다(없으면 숨김 — 가짜 상품을 채우지 않음)
  async function mountHomeSection(sectionId) {
    const section = document.getElementById(sectionId || 'flash-section');
    if (!section) return;
    const row = section.querySelector('.fd-row');
    const timerEl = section.querySelector('.fd-timer');
    async function load() {
      try {
        const json = await fetchDeals({ limit: 20 });
        const list = (json.data || []).filter(d => d.status === 'active' || d.status === 'soldout');
        if (!list.some(d => d.status === 'active')) { section.hidden = true; return; }
        row.innerHTML = list.map(d => renderCard(d)).join('');
        if (timerEl && json.soonest_end) {
          timerEl.setAttribute('data-fd-end', json.soonest_end);
          timerEl.setAttribute('data-fd-suffix', '남음');
          timerEl.removeAttribute('data-fd-done');
          delete timerEl.dataset.fdDone;
        }
        section.hidden = false;
        tick();
      } catch (e) {
        section.hidden = true;
      }
    }
    await load();
    startTicker(() => setTimeout(load, 1200));
  }

  // 상품 상세: 진행중 초특가 박스(카운트다운 + 잔여 수량)
  function detailBoxHtml(fd) {
    if (!fd) return '';
    const soldPct = fd.limit_qty > 0 ? Math.min(100, Math.round(fd.sold_count / fd.limit_qty * 100)) : 0;
    return `
      <div class="fd-detail" id="fd-detail">
        <div class="fd-detail-top">
          <span class="fd-detail-tag">⚡ 한정수량 초특가</span>
          <span class="fd-timer" data-fd-end="${esc(fd.ends_at)}" data-fd-suffix="남음"></span>
        </div>
        <div class="fd-detail-remain">
          <span class="fd-track"><span class="fd-fill" style="width:${soldPct}%"></span></span>
          <span class="fd-remain">잔여 ${Number(fd.remaining).toLocaleString('ko-KR')}개 / ${Number(fd.limit_qty).toLocaleString('ko-KR')}개</span>
        </div>
      </div>`;
  }

  global.WPFlash = { fetchDeals, renderCard, startTicker, tick, mountHomeSection, detailBoxHtml, timerHtml };
})(window);
