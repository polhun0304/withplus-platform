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


  // ===== /deals 한 줄 목록(상품 하나씩) — 사진 · 카테고리/홍보 문구 · 이름 · 설명 · 할인율/가격 · 총수량/남은수량 · 자세히 보기/장바구니 =====
  const DOW = ['일', '월', '화', '수', '목', '금', '토'];
  function openLabel(iso) {
    const st = new Date(iso);
    return `${st.getMonth() + 1}/${st.getDate()}(${DOW[st.getDay()]}) ${pad(st.getHours())}:${pad(st.getMinutes())}`;
  }
  const CART_SVG = '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="9" cy="20" r="1.4"/><circle cx="18" cy="20" r="1.4"/><path d="M2.5 3.5h2.6l2.4 11.2a1.6 1.6 0 0 0 1.6 1.3h8.6a1.6 1.6 0 0 0 1.6-1.2l1.7-7.3H6"/></svg>';
  function renderRow(d) {
    const p = d.product || {};
    const img = Array.isArray(p.images_urls) && p.images_urls[0] ? p.images_urls[0] : null;
    const listPrice = Number(p.price) || 0;
    const rate = listPrice > 0 ? Math.round((1 - d.deal_price / listPrice) * 100) : 0;
    const limit = Number(d.limit_qty) || 0;
    const remain = Math.max(0, Number(d.remaining) || 0);
    const remainPct = limit > 0 ? Math.round(remain / limit * 100) : 0;
    // 초특가 수량이 남아도 상품 재고가 없으면 품절로(상품 상세와 같은 판정 — 장바구니에 못 담게)
    const noStock = d.status !== 'upcoming' && (W && W.isProductSoldOut ? W.isProductSoldOut(p) : (p.stock != null && Number(p.stock) <= 0));
    const sold = d.status === 'soldout' || noStock, soon = d.status === 'upcoming';
    const href = '/product/' + encodeURIComponent(d.product_id);
    const desc = d.subtitle || p.description || '';
    const n = (x) => Number(x).toLocaleString('ko-KR');
    // 품절 줄은 링크 대신 품절 안내 팝업(비슷한 특가 추천)을 연다
    const linkAttr = sold ? `href="${href}" data-fd-soldout="1"` : `href="${href}"`;
    return `
      <article class="fdr${sold ? ' is-soldout' : ''}${soon ? ' is-upcoming' : ''}" data-deal-id="${esc(d.id)}" data-pid="${esc(d.product_id)}">
        <a class="fdr-img" ${linkAttr} aria-label="${esc(p.name)}">
          ${img ? `<img src="${W ? W.safeUrlAttr(img) : img}" alt="" loading="lazy">` : '<span class="fdr-noimg">🎁</span>'}
          <span class="fdr-ribbon">한정수량</span>
          ${sold ? '<span class="fdr-sold"><span><b>SOLD OUT</b><small>품절되었습니다</small></span></span>' : ''}
          ${soon ? `<span class="fdr-soon">${esc(openLabel(d.starts_at))}<br>오픈 예정</span>` : ''}
        </a>
        <div class="fdr-info">
          <div class="fdr-tags">${p.category_label ? `<span class="fdr-cat">${esc(p.category_label)}</span>` : ''}${d.headline ? `<span class="fdr-headline">${esc(d.headline)}</span>` : ''}</div>
          <a class="fdr-name" ${linkAttr}>${esc(p.name)}</a>
          ${desc ? `<p class="fdr-desc">${esc(desc)}</p>` : ''}
          <div class="fdr-price">${rate > 0 ? `<b class="fdr-rate">${rate}%</b>` : ''}<b class="fdr-deal">${won(d.deal_price)}</b>${listPrice > d.deal_price ? `<s>${won(listPrice)}</s>` : ''}</div>
        </div>
        <div class="fdr-side">
          ${d.status === 'active' ? `<span hidden data-fd-end="${esc(d.ends_at)}" data-fd-compact="1"></span>` : ''}${soon ? `<span hidden data-fd-end="${esc(d.starts_at)}" data-fd-compact="1"></span>` : ''}
          <dl class="fdr-qty"><dt>총수량</dt><dd>${n(limit)}개</dd><dt>남은수량</dt><dd><b>${n(remain)}개</b></dd></dl>
          <div class="fdr-bar" role="img" aria-label="남은 수량 ${remainPct}%"><span class="fdr-fill" style="width:${sold ? 100 : remainPct}%"></span></div>
          <div class="fdr-pct">${sold ? '완판' : `${remainPct}% 남음`}</div>
          <div class="fdr-btns">
            ${sold ? '<span class="fdr-detail is-off">품절되었습니다</span>'
              : soon ? `<span class="fdr-detail is-off">${esc(openLabel(d.starts_at))} 오픈</span>`
              : `<a class="fdr-detail" href="${href}"><span class="fdr-long">상품 </span>자세히 보기 ›</a>`}
            <button type="button" class="fdr-cart" data-fd-cart="${esc(d.product_id)}" data-opt="${p.has_options ? '1' : ''}" aria-label="장바구니 담기"${sold || soon ? ' disabled' : ''}>${CART_SVG}</button>
          </div>
        </div>
      </article>`;
  }

  // /deals 목록의 장바구니 버튼 · 품절 줄 클릭(이벤트 위임 — 목록을 다시 그려도 한 번만 연결)
  function bindRowActions(container, getDeal) {
    container.addEventListener('click', (e) => {
      const cartBtn = e.target.closest('[data-fd-cart]');
      if (cartBtn) {
        e.preventDefault();
        if (cartBtn.disabled) return;
        const pid = cartBtn.getAttribute('data-fd-cart');
        // 사이즈/색상 옵션이 있는 상품은 옵션을 골라야 하므로 상세로 보낸다
        if (cartBtn.getAttribute('data-opt') === '1') { location.href = '/product/' + encodeURIComponent(pid); return; }
        if (W && W.addToCart) W.addToCart(pid, 1);
        cartBtn.classList.add('is-done');
        cartBtn.setAttribute('aria-label', '장바구니에 담겼습니다');
        setTimeout(() => { cartBtn.classList.remove('is-done'); cartBtn.setAttribute('aria-label', '장바구니 담기'); }, 1600);
        return;
      }
      const soldLink = e.target.closest('[data-fd-soldout]');
      if (soldLink && global.WPSoldout && global.WPSoldout.showPopup) {
        e.preventDefault();
        const row = soldLink.closest('.fdr');
        const d = getDeal(row && row.getAttribute('data-deal-id'));
        global.WPSoldout.showPopup({ id: row.getAttribute('data-pid'), category: d && d.product ? d.product.category : '' });
      }
    });
  }

  // 다음 금요일 00:00(한국 시간) — "매주 금요일 새로운 특가" 카운트다운 기준
  function nextFridayKst(fromMs) {
    const KST = 9 * 3600 * 1000;
    const k = new Date((fromMs || now()) + KST);
    const add = ((5 - k.getUTCDay() + 7) % 7) || 7;
    return new Date(Date.UTC(k.getUTCFullYear(), k.getUTCMonth(), k.getUTCDate() + add) - KST);
  }

  // 홈: 한정수량 초특가 배너(항상 보임 → 누르면 /deals). 진행중 초특가 상품 사진·문구를 실제 데이터로 채운다
  async function mountHomeBanner(bannerId) {
    const el = document.getElementById(bannerId || 'flash-banner');
    if (!el) return;
    const sub = el.querySelector('.ffb-sub');
    const imgBox = el.querySelector('.ffb-img');
    try {
      const json = await fetchDeals({ includeUpcoming: true, limit: 20 });
      const list = json.data || [];
      const active = list.filter(d => d.status === 'active');
      const upcoming = list.filter(d => d.status === 'upcoming');
      const pics = (active.length ? active : list)
        .map(d => d.product && Array.isArray(d.product.images_urls) ? d.product.images_urls[0] : null)
        .filter(Boolean).slice(0, 2);
      if (pics.length && imgBox) {
        imgBox.innerHTML = pics.map((u, i) => `<img src="${W ? W.safeUrlAttr(u) : u}" alt="" loading="lazy" class="ffb-pic ffb-pic-${i}">`).join('');
      }
      if (sub) {
        if (active.length) sub.textContent = '지금만 만나보는 특가 상품!';
        else if (upcoming.length) sub.textContent = openLabel(upcoming[0].starts_at) + ' 오픈 예정';
        else sub.textContent = '매주 금요일 특가 오픈!';
      }
      el.setAttribute('aria-label', '한정수량 초특가 — ' + (sub ? sub.textContent : '') + ' (초특가 페이지로 이동)');
    } catch (e) { /* 실패해도 기본 문구 그대로 — 누르면 /deals 로 이동 */ }
  }

  global.WPFlash = { fetchDeals, renderCard, renderRow, bindRowActions, startTicker, tick, mountHomeSection, mountHomeBanner, nextFridayKst, detailBoxHtml, timerHtml, now };
})(window);
