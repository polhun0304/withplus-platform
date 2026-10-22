/* 🔴 품절 상품 안내 팝업 + 비슷한 특가상품 추천 (상품 상세 전용)
 *  - 품절 상품: 어두운 배경 위 가운데 흰 상자 → "본 상품은 품절되었습니다! / 더 많은 할인 상품을 살펴보세요!"
 *    + 빨간 "특가상품 찾아보기 >>" 버튼 → 같은 상자가 그대로 넓어지며 같은·비슷한 카테고리 특가상품 목록을 보여준다.
 *    닫으면 상세 화면은 그대로 볼 수 있고, 구매 버튼은 "품절"로 잠긴다(다시 보기 버튼 제공).
 *  - 삭제(영구 삭제)·존재하지 않는 상품: "존재하지 않거나 삭제된 상품입니다" + 같은 추천 목록을 화면에 바로 보여준다.
 *  - 추천 데이터: GET /api/products/:id/soldout-recommendations (판매중·재고 있음·할인율 큰 순)
 * product.html 의 메인 스크립트와 분리해 둔 독립 모듈(window.WPSoldout). */
(function (global) {
  'use strict';
  if (global.WPSoldout) return;

  var RED = '#E53935';
  var styleDone = false;
  function ensureStyle() {
    if (styleDone) return;
    styleDone = true;
    var st = document.createElement('style');
    st.id = 'wp-soldout-style';
    st.textContent = [
      '.wso-backdrop{position:fixed;inset:0;z-index:9500;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px;box-sizing:border-box;}',
      '.wso-box{position:relative;background:#fff;width:100%;max-width:380px;border-radius:6px;padding:40px 24px 26px;box-sizing:border-box;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,.3);max-height:calc(100vh - 32px);display:flex;flex-direction:column;transition:max-width .25s ease;}',
      '.wso-box.is-wide{max-width:880px;padding:22px 18px 18px;text-align:left;}',
      '.wso-x{position:absolute;top:8px;right:10px;width:36px;height:36px;border:0;background:transparent;font-size:28px;line-height:1;color:#222;cursor:pointer;}',
      '.wso-msg{margin:0 0 22px;font-size:19px;font-weight:800;line-height:1.55;color:#111;word-break:keep-all;}',
      '.wso-btn{display:block;width:100%;border:0;border-radius:4px;background:' + RED + ';color:#fff;font-size:17px;font-weight:800;padding:15px 12px;cursor:pointer;font-family:inherit;}',
      '.wso-btn:hover{filter:brightness(.95);}',
      '.wso-head{display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin:0 40px 12px 2px;flex-wrap:wrap;}',
      '.wso-head h3{margin:0;font-size:18px;font-weight:800;color:#111;}',
      '.wso-head p{margin:0;font-size:13px;color:#777;}',
      '.wso-scroll{overflow-y:auto;-webkit-overflow-scrolling:touch;margin:0 -4px;padding:0 4px;min-height:0;flex:1;}',
      '.wso-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px 12px;}',
      '.wso-card{display:block;text-decoration:none;color:#222;min-width:0;}',
      '.wso-img{position:relative;width:100%;aspect-ratio:1/1;border-radius:8px;background:#f5f5f5 center/cover no-repeat;display:flex;align-items:center;justify-content:center;font-size:34px;color:#ccc;overflow:hidden;}',
      '.wso-tag{position:absolute;left:6px;top:6px;background:' + RED + ';color:#fff;font-size:11px;font-weight:800;padding:3px 6px;border-radius:3px;}',
      '.wso-name{margin:7px 0 3px;font-size:13px;line-height:1.4;height:2.8em;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;word-break:break-all;}',
      '.wso-price{display:flex;align-items:baseline;gap:5px;flex-wrap:wrap;}',
      '.wso-rate{color:' + RED + ';font-weight:800;font-size:15px;}',
      '.wso-now{font-weight:800;font-size:15px;color:#111;}',
      '.wso-was{font-size:12px;color:#aaa;text-decoration:line-through;}',
      '.wso-more{display:block;margin-top:14px;text-align:center;font-size:14px;font-weight:700;color:' + RED + ';text-decoration:none;padding:10px;border:1px solid #f3c4c3;border-radius:6px;}',
      '.wso-empty,.wso-loading{padding:30px 10px;text-align:center;color:#888;font-size:14px;}',
      '.wso-inline{margin:18px 0 6px;padding:12px 14px;border:1px solid #f3c4c3;background:#FFF5F5;border-radius:8px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;}',
      '.wso-inline span{font-size:14px;font-weight:700;color:#C62828;}',
      '.wso-inline button{border:0;background:' + RED + ';color:#fff;font-weight:800;font-size:13.5px;border-radius:4px;padding:9px 12px;cursor:pointer;font-family:inherit;}',
      '.btn.wso-locked,.btn.wso-locked:disabled{background:#9e9e9e !important;color:#fff !important;border-color:#9e9e9e !important;cursor:not-allowed;opacity:1;}',
      '.wso-deleted{max-width:1100px;margin:0 auto;padding:36px 16px 40px;box-sizing:border-box;}',
      '.wso-deleted .wso-del-msg{text-align:center;margin-bottom:26px;}',
      '.wso-deleted .wso-del-msg .emoji{font-size:44px;}',
      '.wso-deleted .wso-del-msg h3{margin:10px 0 6px;font-size:20px;font-weight:800;color:#111;}',
      '.wso-deleted .wso-del-msg p{margin:0 0 14px;color:#777;font-size:14px;}',
      '.wso-deleted .wso-del-msg a{display:inline-block;padding:10px 22px;border:1px solid #ddd;border-radius:999px;color:#333;text-decoration:none;font-size:14px;}',
      '.wso-deleted .wso-head{margin-right:0;}',
      'body.wso-lock{overflow:hidden;}',
      '@media (max-width:768px){.wso-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:12px 10px;}.wso-box.is-wide{padding:18px 12px 14px;max-height:calc(100vh - 24px);}.wso-msg{font-size:17px;}}',
      '@media (min-width:769px) and (max-width:1024px){.wso-grid{grid-template-columns:repeat(3,minmax(0,1fr));}}'
    ].join('\n');
    document.head.appendChild(st);
  }

  function esc(s) { return global.WithPlus ? global.WithPlus.escapeHtml(String(s == null ? '' : s)) : String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function price(n) { return global.WithPlus ? global.WithPlus.formatPrice(n) : Number(n || 0).toLocaleString('ko-KR') + '원'; }
  function urlAttr(u) { return global.WithPlus && global.WithPlus.safeUrlAttr ? global.WithPlus.safeUrlAttr(u) : ''; }

  var recoCache = {};
  function fetchReco(productId, category) {
    var key = productId + '|' + (category || '');
    if (recoCache[key]) return recoCache[key];
    var url = '/api/products/' + encodeURIComponent(productId || 'none') + '/soldout-recommendations?limit=12' + (category ? '&category=' + encodeURIComponent(category) : '');
    recoCache[key] = fetch(url).then(function (r) { return r.json(); }).then(function (j) {
      if (!j || !j.success) throw new Error((j && j.message) || '추천 상품을 불러오지 못했어요');
      return j;
    });
    recoCache[key].catch(function () { delete recoCache[key]; });
    return recoCache[key];
  }

  function cardHtml(p) {
    var img = Array.isArray(p.images_urls) && p.images_urls[0] ? p.images_urls[0] : '';
    var emoji = (global.WithPlus && global.WithPlus.CATEGORY_EMOJI && (global.WithPlus.CATEGORY_EMOJI[p.category] || global.WithPlus.CATEGORY_EMOJI['default'])) || '🛍️';
    var hasSale = Number(p.discount_rate) > 0;
    var now = hasSale ? p.discount_price : p.price;
    return '<a class="wso-card" href="/product/' + encodeURIComponent(p.id) + '">' +
      '<div class="wso-img"' + (img ? ' style="background-image:url(\'' + urlAttr(img) + '\')"' : '') + '>' + (img ? '' : emoji) +
      (hasSale ? '<span class="wso-tag">특가</span>' : '') + '</div>' +
      '<div class="wso-name">' + esc(p.name) + '</div>' +
      '<div class="wso-price">' + (hasSale ? '<span class="wso-rate">' + Number(p.discount_rate) + '%</span>' : '') +
      '<span class="wso-now">' + price(now) + '</span>' + (hasSale ? '<span class="wso-was">' + price(p.price) + '</span>' : '') + '</div></a>';
  }

  function headTitle(base) {
    return base && base.category_label ? '🔥 ' + esc(base.category_label) + ' 특가상품' : '🔥 지금 할인 중인 특가상품';
  }

  function renderRecoInto(container, productId, category, opts) {
    opts = opts || {};
    container.innerHTML = '<div class="wso-loading">비슷한 특가상품을 찾고 있어요…</div>';
    return fetchReco(productId, category).then(function (j) {
      var list = j.data || [];
      var base = j.base || {};
      var moreHref = base.category_slug ? '/category/' + encodeURIComponent(base.category_slug) : '/';
      container.innerHTML =
        '<div class="wso-head"><h3>' + (opts.title || headTitle(base)) + '</h3><p>판매 중인 상품을 할인율 높은 순으로 골랐어요</p></div>' +
        (list.length ? '<div class="wso-scroll"><div class="wso-grid">' + list.map(cardHtml).join('') + '</div>' +
          '<a class="wso-more" href="' + moreHref + '">' + (base.category_label ? esc(base.category_label) + ' 상품 더 보기 ›' : '전체 상품 보러 가기 ›') + '</a></div>'
          : '<div class="wso-empty">지금 추천할 수 있는 특가상품이 없어요. <a href="/" style="color:' + RED + ';">홈으로 가기</a></div>');
    }).catch(function (err) {
      container.innerHTML = '<div class="wso-empty">' + esc(err.message || '추천 상품을 불러오지 못했어요') + '</div>';
    });
  }

  var modal = null;
  function closeModal() {
    if (!modal) return;
    modal.remove();
    modal = null;
    document.body.classList.remove('wso-lock');
    document.removeEventListener('keydown', onKey);
  }
  function onKey(e) { if (e.key === 'Escape') closeModal(); }

  function openModal(p, expandNow) {
    ensureStyle();
    closeModal();
    modal = document.createElement('div');
    modal.className = 'wso-backdrop';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-label', '품절 상품 안내');
    modal.addEventListener('click', function (e) { if (e.target === modal) closeModal(); });
    var box = document.createElement('div');
    box.className = 'wso-box';
    box.innerHTML =
      '<button type="button" class="wso-x" aria-label="닫기">×</button>' +
      '<div class="wso-body">' +
      '<p class="wso-msg">본 상품은 품절되었습니다!<br>더 많은 할인 상품을 살펴보세요!</p>' +
      '<button type="button" class="wso-btn">특가상품 찾아보기 &gt;&gt;</button>' +
      '</div>';
    modal.appendChild(box);
    document.body.appendChild(modal);
    document.body.classList.add('wso-lock');
    document.addEventListener('keydown', onKey);
    box.querySelector('.wso-x').addEventListener('click', closeModal);
    var body = box.querySelector('.wso-body');
    function expand() {
      box.classList.add('is-wide');
      body.style.cssText = 'display:flex;flex-direction:column;min-height:0;flex:1;';
      renderRecoInto(body, p.id, p.category);
    }
    box.querySelector('.wso-btn').addEventListener('click', expand);
    // 버튼을 누르기 전에 미리 불러와 두면 펼칠 때 바로 보인다
    fetchReco(p.id, p.category).catch(function () {});
    if (expandNow) expand();
    try { box.querySelector('.wso-btn').focus({ preventScroll: true }); } catch (e) { /* 무시 */ }
  }

  // 구매 버튼 잠금: "품절" 표시 + 옵션·수량·정기배송 조작 막기
  function lockPurchase(p) {
    ensureStyle();
    ['detail-cart-btn', 'detail-buy-btn'].forEach(function (id) {
      var b = document.getElementById(id);
      if (!b) return;
      b.disabled = true;
      b.textContent = '품절';
      b.classList.add('wso-locked');
      b.setAttribute('aria-disabled', 'true');
    });
    ['variant-select', 'qty-minus', 'qty-plus', 'subscribe-toggle-btn'].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.disabled = true;
    });
    var sub = document.getElementById('subscribe-box');
    if (sub) sub.style.display = 'none';
    var stockEl = document.getElementById('stock-info-text');
    if (stockEl) stockEl.textContent = '❌ 현재 품절된 상품입니다';
    var actions = document.querySelector('.detail-actions');
    if (actions && !document.getElementById('wso-inline')) {
      var bar = document.createElement('div');
      bar.className = 'wso-inline';
      bar.id = 'wso-inline';
      bar.innerHTML = '<span>품절된 상품이에요</span><button type="button">비슷한 특가상품 보기 &gt;&gt;</button>';
      bar.querySelector('button').addEventListener('click', function () { openModal(p, true); });
      actions.parentNode.insertBefore(bar, actions.nextSibling);
    }
  }

  global.WPSoldout = {
    // 품절 상품: 구매 잠금 + 안내 팝업
    show: function (p) {
      if (!p) return;
      lockPurchase(p);
      openModal(p, false);
    },
    // 삭제·없는 상품: 상세 영역을 안내 + 추천 목록으로 바꾼다
    showDeleted: function (wrap, productId) {
      ensureStyle();
      if (!wrap) return;
      wrap.innerHTML =
        '<div class="wso-deleted">' +
        '<div class="wso-del-msg"><div class="emoji">😕</div><h3>존재하지 않거나 삭제된 상품입니다</h3>' +
        '<p>대신 지금 할인 중인 상품을 둘러보세요.</p><a href="/">홈으로 돌아가기</a></div>' +
        '<div id="wso-del-reco"></div></div>';
      var cur = document.getElementById('breadcrumb-current');
      if (cur) cur.textContent = '삭제된 상품';
      document.title = '존재하지 않는 상품 - WITH+';
      renderRecoInto(document.getElementById('wso-del-reco'), productId, '', { title: '🔥 이런 특가상품은 어떠세요?' });
    },
    isSoldOut: function (p) {
      return global.WithPlus && global.WithPlus.isProductSoldOut ? global.WithPlus.isProductSoldOut(p) : !!(p && p.is_sold_out);
    }
  };
})(window);
