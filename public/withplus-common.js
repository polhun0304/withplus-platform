/**
 * WITH+ 공통 JS (홈페이지 / 카테고리 / 상품상세 / 로그인 / 장바구니 / 마이페이지 공용)
 * 이 파일을 쓰는 페이지는 <head>에 아래 두 줄이 먼저 있어야 합니다:
 *   <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js"></script>
 *   <script src="/withplus-common.js"></script>
 */
(function (global) {
  // 같은 서버에서 서빙되면 상대 경로, file://로 직접 열었을 때는 절대 경로
  const API_BASE = (location.protocol === 'file:') ? 'http://localhost:3003' : '';

  // 카테고리는 관리자가 언제든 추가/수정/삭제할 수 있도록 DB(categories 테이블)에서 관리됩니다.
  // 아래 상수는 API 호출이 실패했을 때만 쓰이는 최소 폴백(fallback)입니다.
  const FALLBACK_CATEGORY_MAP = { all: { label: '전체 상품', emoji: '🛍️', dbCategories: null } };
  const FALLBACK_CATEGORY_EMOJI = { default: '🎁' };

  let cachedCategoryMap = Object.assign({}, FALLBACK_CATEGORY_MAP);
  let cachedCategoryEmoji = Object.assign({}, FALLBACK_CATEGORY_EMOJI);
  let cachedCategoriesRaw = [];

  // 분양 조직(커뮤니티) 랜딩페이지(/c/:슬러그)를 거쳐 들어온 방문자는 그 사실을 localStorage에
  // 저장해두는데(withplus_preferred_community_slug), 지금까지는 저장만 하고 실제로 다시 읽어서
  // 카테고리/상품 목록에 반영하는 코드가 없었다. 아래 함수로 그 값을 읽어 API 호출에 일관되게 반영한다.
  function getPreferredCommunitySlug() {
    try { return localStorage.getItem('withplus_preferred_community_slug') || null; } catch (e) { return null; }
  }

  // 커뮤니티 랜딩(/c/:슬러그)을 한 번 거치면 이 브라우저는 그 커뮤니티를 "선호"로 계속 기억하는데,
  // 지금까지는 이걸 빠져나와 전체 쇼핑몰로 돌아갈 방법이 사이트 어디에도 없었다. 그 커뮤니티가
  // "선택 카테고리만" 노출로 설정되어 있는데 실제로 고른 카테고리가 하나도 없으면(관리자가 아직
  // 카테고리를 선택하지 않은 상태), 방문자는 이유도 모른 채 카테고리 없이 "전체 상품" 한 칸만
  // 계속 보게 되고 빠져나올 수도 없었다 — 이번에 신고된 "카테고리가 전체상품 1개로만 보인다"
  // 증상이 정확히 이 경로다. 아래 배너로 언제든 눈에 보이게 안내하고, 클릭 한 번으로 빠져나가게 한다.
  function clearPreferredCommunity() {
    try {
      localStorage.removeItem('withplus_preferred_community_slug');
      localStorage.removeItem('withplus_preferred_community_name');
    } catch (e) {}
  }

  function renderCommunityBanner() {
    const slug = getPreferredCommunitySlug();
    const existing = document.getElementById('wp-community-banner');
    if (!slug) {
      if (existing) existing.remove();
      return;
    }
    if (existing) return; // 이미 떠 있으면 다시 그리지 않음
    if (document.getElementById('wp-community-bar')) return; // 홈의 공동체 바가 같은 역할(매장 표시 + 전체 쇼핑몰 보기)을 대신한다
    let name = '';
    try { name = localStorage.getItem('withplus_preferred_community_name') || ''; } catch (e) {}
    const bar = document.createElement('div');
    bar.id = 'wp-community-banner';
    bar.style.cssText = 'background:#FFF3E0;color:#7A4A00;font-size:13px;text-align:center;padding:8px 12px;position:relative;z-index:200;';
    bar.innerHTML = `🏠 ${name ? escapeHtml(name) + ' 매장을 보는 중입니다' : '특정 매장을 보는 중입니다'} · <a href="#" id="wp-community-banner-reset" style="color:#E65100;font-weight:700;text-decoration:underline;">전체 쇼핑몰 보기</a>`;
    document.body.insertBefore(bar, document.body.firstChild);
    const link = document.getElementById('wp-community-banner-reset');
    if (link) {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        clearPreferredCommunity();
        location.href = '/';
      });
    }
  }

  // /api/products 등 커뮤니티별로 결과가 달라질 수 있는 API 경로에 현재 선호 커뮤니티를 쿼리파라미터로 붙여준다
  function withCommunityParam(path, communitySlug) {
    const slug = communitySlug !== undefined ? communitySlug : getPreferredCommunitySlug();
    if (!slug) return path;
    const sep = path.indexOf('?') === -1 ? '?' : '&';
    return path + sep + 'community=' + encodeURIComponent(slug);
  }

  async function refreshCategoryMap(communitySlug) {
    try {
      const res = await fetch(API_BASE + withCommunityParam('/api/categories', communitySlug));
      const json = await res.json();
      if (res.ok && json.success && Array.isArray(json.data)) {
        cachedCategoriesRaw = json.data;
        const map = { all: { label: '전체 상품', emoji: '🛍️', dbCategories: null } };
        const emojiMap = { default: '🎁' };
        const byParent = {}; // 대분류 id -> 중분류(카테고리) 목록 (2단 카테고리 계층 - parent_id가 없으면 대분류)
        json.data.forEach(c => {
          if (c.parent_id) {
            if (!byParent[c.parent_id]) byParent[c.parent_id] = [];
            byParent[c.parent_id].push(c);
          }
        });
        json.data.forEach(c => {
          const children = byParent[c.id] || [];
          // 대분류를 선택해 들어오면 자기 자신 + 모든 하위(중분류) 상품까지 함께 보여준다(카테고리 페이지 필터 로직은 변경 없이 그대로 재사용됨)
          const dbCategories = [c.db_category, ...children.map(ch => ch.db_category)];
          map[c.slug] = {
            label: c.label, emoji: c.emoji, dbCategories, id: c.id,
            parentId: c.parent_id || null,
            children: children.map(ch => ({ slug: ch.slug, label: ch.label, emoji: ch.emoji }))
          };
          emojiMap[c.db_category] = c.emoji;
        });
        cachedCategoryMap = map;
        cachedCategoryEmoji = emojiMap;
      }
    } catch (err) { /* 실패 시 기존 캐시(또는 폴백) 유지 */ }
    return cachedCategoryMap;
  }

  function getCategoryMapCached() { return cachedCategoryMap; }
  function getCategoryEmoji(category) { return cachedCategoryEmoji[category] || cachedCategoryEmoji.default; }
  function getCategoriesRawCached() { return cachedCategoriesRaw; }

  // 상단 카테고리 메뉴(nav)/홈 화면 카테고리 그리드를 실제 카테고리 데이터로 렌더링한다.
  // #nav-menu, #category-grid 요소가 있는 페이지에서만 동작하고, 없으면 조용히 무시한다.
  // (지금까지는 이 두 영역이 8개 카테고리로 고정된 정적 HTML이라 관리자가 카테고리를
  //  추가/삭제/노출설정을 바꿔도 실제 메뉴에는 반영되지 않는 문제가 있었다.)
  // 카테고리는 대분류/중분류 2단 계층을 지원한다 - 대분류에 중분류가 있으면 마우스오버 시 펼쳐지는 드롭다운으로 보여준다.
  let navDropdownStyleInjected = false;
  function ensureNavDropdownStyle() {
    if (navDropdownStyleInjected) return;
    navDropdownStyleInjected = true;
    const style = document.createElement('style');
    style.textContent = `
      .wp-nav-item { position: relative; display: inline-block; }
      .wp-nav-dropdown { display: none; position: absolute; top: 100%; left: 0; background: #fff; border: 1px solid #eee; border-radius: 8px; box-shadow: 0 4px 14px rgba(0,0,0,0.08); min-width: 140px; padding: 6px 0; z-index: 50; }
      .wp-nav-item:hover .wp-nav-dropdown { display: block; }
      .wp-nav-dropdown a { display: block; padding: 8px 14px; white-space: nowrap; font-weight: 400; }
      .wp-nav-dropdown a:hover { background: #FAFAFA; }
    `;
    document.head.appendChild(style);
  }
  function renderCategoryNav() {
    const cats = cachedCategoriesRaw.filter(c => !c.parent_id); // 상단 메뉴/홈 그리드에는 대분류만 노출 (중분류는 대분류 진입 후 하위 필터로 노출)
    const currentPath = location.pathname.replace(/\/$/, '');
    const navEl = document.getElementById('nav-menu');
    if (navEl) {
      if (cats.length === 0) {
        navEl.innerHTML = '<a href="/">🛍️ 전체 상품</a>';
      } else {
        ensureNavDropdownStyle();
        navEl.innerHTML = cats.map(c => {
          const href = '/category/' + c.slug;
          const active = currentPath === href ? ' class="active"' : '';
          const info = cachedCategoryMap[c.slug];
          const children = info ? info.children : [];
          if (children.length === 0) {
            return `<a href="${href}"${active}>${c.emoji} ${escapeHtml(c.label)}</a>`;
          }
          return `<span class="wp-nav-item">
              <a href="${href}"${active}>${c.emoji} ${escapeHtml(c.label)}</a>
              <span class="wp-nav-dropdown">${children.map(ch => `<a href="/category/${ch.slug}">${ch.emoji} ${escapeHtml(ch.label)}</a>`).join('')}</span>
            </span>`;
        }).join('');
      }
    }
    const gridEl = document.getElementById('category-grid');
    if (gridEl) {
      if (cats.length === 0) {
        gridEl.innerHTML = '<a href="/" class="category-item"><div class="category-icon">🛍️</div><div class="category-name">전체 상품</div></a>';
      } else {
        // 홈 카테고리 아이콘 메뉴 — WITH+ 기본틀처럼 원형 배경 위 라인 아이콘으로 보여준다
        gridEl.innerHTML = cats.map(c => `
          <a href="/category/${c.slug}" class="category-item">
              <div class="category-icon">${getCategoryLineIcon(c)}</div>
              <div class="category-name">${escapeHtml(c.label)}</div>
          </a>`).join('');
      }
    }
  }

  // refreshCategoryMap + renderCategoryNav를 함께 호출하는 편의 함수 (nav-menu/category-grid가 있는 페이지에서 사용)
  async function initCategoryNav(communitySlug) {
    await refreshCategoryMap(communitySlug);
    renderCategoryNav();
  }

  // 하위 호환용: 과거 코드가 참조하던 이름 그대로도 접근 가능하게 getter로 노출 (항상 최신 캐시를 반환)
  const CATEGORY_MAP = new Proxy({}, { get: (_, prop) => cachedCategoryMap[prop] });
  const CATEGORY_EMOJI = new Proxy({}, { get: (_, prop) => cachedCategoryEmoji[prop] || cachedCategoryEmoji.default });

  function formatPrice(price) {
    return Number(price).toLocaleString('ko-KR') + '원';
  }

  function getShippingBadgeLabel(stock) {
    const n = Number(stock);
    if (!Number.isFinite(n) || n <= 0) return '';
    if (n <= 5) return `⏰ 재고 ${n}개 남음 - 서둘러 주문해주세요`;
    return '🚚 오늘 주문하면 빠르게 배송해드립니다';
  }

  // ============================================
  // 마일리지 적립율 (관리자가 언제든 동적으로 변경 가능 - 하드코딩 금지)
  // ============================================
  let cachedMileageRates = { personal: 0.01, community: 0.02, personalPercent: 1, communityPercent: 2 };
  let mileageRatesLoaded = false;

  async function refreshMileageRates() {
    try {
      const res = await fetch(API_BASE + '/api/settings/mileage-rates');
      const json = await res.json();
      if (res.ok && json.success && json.data) {
        cachedMileageRates = json.data;
        mileageRatesLoaded = true;
      }
    } catch (err) { /* 실패 시 기존 캐시(또는 기본값) 유지 */ }
    return cachedMileageRates;
  }

  function getMileageRatesCached() {
    return cachedMileageRates;
  }

  // ============================================
  // 디자인 부품 갤러리 - 화면 구성요소(상품목록/장바구니/로그인/마이페이지)별로
  // 관리자가 선택해둔 디자인 템플릿 값을 각 페이지가 렌더링 전에 참조한다.
  // ============================================
  let cachedPageTemplates = { product_list: 'grid', cart: 'classic', login: 'classic', mypage: 'classic' };
  let pageTemplatesLoaded = false;
  async function refreshPageTemplates() {
    try {
      const res = await fetch(API_BASE + '/api/settings/page-templates');
      const json = await res.json();
      if (res.ok && json.success && json.data && json.data.selected) {
        cachedPageTemplates = json.data.selected;
        pageTemplatesLoaded = true;
      }
    } catch (err) { /* 실패 시 기존 캐시(또는 기본값) 유지 */ }
    return cachedPageTemplates;
  }
  function getPageTemplatesCached() {
    return cachedPageTemplates;
  }

  function formatPercent(num) {
    const n = Number(num || 0);
    return (Math.round(n * 100) / 100).toString();
  }

  async function fetchJSON(path, options) {
    const res = await fetch(API_BASE + path, options);
    const json = await res.json();
    return { ok: res.ok, status: res.status, json };
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = String(str == null ? '' : str);
    return div.innerHTML;
  }

  // 이미지 URL을 style="background-image:url('...')" 같은 홑따옴표 인라인 속성 안에 안전하게 넣기 위한 헬퍼.
  // escapeHtml은 텍스트 노드 직렬화 기준이라 홑따옴표(')를 이스케이프하지 않으므로(HTML 텍스트 콘텐츠에서는
  // 따옴표가 특별한 의미가 없음) 그대로 쓰면 url('${...}') 같은 속성에서 홑따옴표로 속성을 깨고 나가는
  // 저장형 XSS가 가능하다. encodeURI로 URL을 인코딩하되(URL 구조는 보존하면서 위험 문자는 인코딩),
  // encodeURI만으로는 인코딩되지 않는 홑따옴표를 추가로 %27로 치환해 속성 탈출을 막는다.
  function safeUrlAttr(url) {
    const str = String(url == null ? '' : url);
    try {
      return encodeURI(str).replace(/'/g, '%27');
    } catch (e) {
      return '';
    }
  }

  function timeAgo(dateStr) {
    const diffMs = Date.now() - new Date(dateStr).getTime();
    const min = Math.floor(diffMs / 60000);
    if (min < 1) return '방금 전';
    if (min < 60) return min + '분 전';
    const hr = Math.floor(min / 60);
    if (hr < 24) return hr + '시간 전';
    return Math.floor(hr / 24) + '일 전';
  }

  // ============================================
  // Supabase 클라이언트 (인증용) - /api/config에서 URL/ANON_KEY를 받아와 초기화
  // ============================================
  let clientPromise = null;
  function getClient() {
    if (clientPromise) return clientPromise;
    clientPromise = (async () => {
      const { json } = await fetchJSON('/api/config');
      if (!global.supabase || !global.supabase.createClient) {
        throw new Error('Supabase JS SDK가 로드되지 않았습니다. <head>에 CDN 스크립트를 추가하세요.');
      }
      return global.supabase.createClient(json.supabaseUrl, json.supabaseAnonKey);
    })();
    return clientPromise;
  }

  async function getSession() {
    try {
      const client = await getClient();
      const { data } = await client.auth.getSession();
      return data.session || null;
    } catch (e) {
      return null;
    }
  }

  async function getAccessToken() {
    const session = await getSession();
    return session ? session.access_token : null;
  }

  async function signOut() {
    const client = await getClient();
    await client.auth.signOut();
  }

  // ============================================
  // 장바구니 (localStorage 기반)
  // ============================================
  const CART_KEY = 'withplus_cart';

  function getCart() {
    try {
      return JSON.parse(localStorage.getItem(CART_KEY) || '[]');
    } catch (e) {
      return [];
    }
  }

  function saveCart(cart) {
    try { localStorage.setItem(CART_KEY, JSON.stringify(cart)); } catch (e) { /* ignore */ }
    scheduleCartSync(cart);
  }

  // 장바구니 이탈 리마인더 기능을 위해, 로그인된 사용자에 한해 장바구니를 서버에도 동기화한다(cart_snapshots_with).
  // 비로그인 사용자는 보낼 이메일 주소가 없으므로 동기화를 생략한다(로컬 장바구니 자체는 그대로 정상 동작).
  // 매 클릭마다 요청을 보내지 않도록 1.5초 debounce - 실패해도 조용히 무시(로컬 장바구니 동작을 막지 않음)
  let cartSyncTimer = null;
  function scheduleCartSync(cart) {
    if (cartSyncTimer) clearTimeout(cartSyncTimer);
    cartSyncTimer = setTimeout(async () => {
      try {
        const token = await getAccessToken();
        if (!token) return;
        await fetch('/api/me/cart', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
          body: JSON.stringify({ items: cart })
        });
      } catch (e) { /* 장바구니 서버 동기화 실패는 조용히 무시 */ }
    }, 1500);
  }

  // 옵션(사이즈/색상 등)이 있는 상품은 상품ID만으로는 장바구니 항목을 특정할 수 없으므로,
  // variantId까지 함께 비교해 서로 다른 옵션은 별개의 장바구니 줄로 취급한다. (옵션 없는 상품은 variantId가 null)
  function addToCart(productId, qty, variantId) {
    qty = qty || 1;
    variantId = variantId || null;
    const cart = getCart();
    const existing = cart.find(i => i.product_id === productId && (i.variant_id || null) === variantId);
    if (existing) {
      existing.quantity += qty;
    } else {
      cart.push({ product_id: productId, variant_id: variantId, quantity: qty });
    }
    saveCart(cart);
    refreshCartBadge();
    return cart;
  }

  function setCartQty(productId, qty, variantId) {
    variantId = variantId || null;
    let cart = getCart();
    if (qty <= 0) {
      cart = cart.filter(i => !(i.product_id === productId && (i.variant_id || null) === variantId));
    } else {
      const existing = cart.find(i => i.product_id === productId && (i.variant_id || null) === variantId);
      if (existing) existing.quantity = qty;
    }
    saveCart(cart);
    refreshCartBadge();
    return cart;
  }

  function removeFromCart(productId, variantId) {
    return setCartQty(productId, 0, variantId);
  }

  function clearCart() {
    saveCart([]);
    refreshCartBadge();
  }

  function getCartCount() {
    return getCart().reduce((sum, i) => sum + i.quantity, 0);
  }

  function refreshCartBadge() {
    const count = getCartCount();
    document.querySelectorAll('.cart-badge').forEach(el => {
      el.textContent = count;
      el.dataset.count = String(count); // .wp-icon-badge[data-count="0"]는 숨김 처리
    });
  }

  // ============================================
  // 헤더 공통 초기화 (계정 링크 / 장바구니 배지)
  // 각 페이지 헤더에 id="account-link" (👤 아이콘)가 있으면 로그인 상태 반영
  // ============================================
  async function initHeader() {
    refreshCartBadge();
    const session = await getSession();
    if (session && session.user) applyPendingReferralIfAny();
    const accountLink = document.getElementById('account-link');
    if (!accountLink) return;
    if (session && session.user) {
      accountLink.setAttribute('href', '/mypage');
      accountLink.setAttribute('title', session.user.email + ' (마이페이지)');
    } else {
      accountLink.setAttribute('href', '/login');
      accountLink.setAttribute('title', '로그인');
    }
  }

  // ============================================
  // 🎁 추천인(리퍼럴) 프로그램 — 추천 링크(?ref=코드)로 들어오면 로컬에 잠시 저장해두었다가,
  // 로그인 세션이 확인되는 시점(가입 직후든, 나중에 이메일 인증 후 로그인이든)에 한 번만 서버에 등록을 시도한다.
  // ============================================
  function capturePendingReferralCode() {
    try {
      const ref = new URLSearchParams(location.search).get('ref');
      if (ref && ref.trim()) localStorage.setItem('withplus_pending_referral', ref.trim().toUpperCase());
    } catch (e) { /* ignore */ }
  }
  capturePendingReferralCode();

  async function applyPendingReferralIfAny() {
    let pending;
    try { pending = localStorage.getItem('withplus_pending_referral'); } catch (e) { return; }
    if (!pending) return;
    try {
      const token = await getAccessToken();
      if (!token) return;
      await fetch(API_BASE + '/api/me/apply-referral', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
        body: JSON.stringify({ code: pending })
      });
    } catch (e) { /* 추천코드 등록 실패는 조용히 무시 - 회원가입/로그인 자체를 막지 않음 */
    } finally {
      try { localStorage.removeItem('withplus_pending_referral'); } catch (e) { /* ignore */ }
    }
  }

  // 상품 카드 HTML (홈페이지/카테고리 페이지 공용)
  // ============================================
  // ⭐ 별점/상품평 표시 (쿠팡식) — 0.5 단위까지 채워지는 별 5개 + "N 개 상품평" + "👍 N명 이상 만족했어요"
  // ============================================
  let ratingStyleInjected = false;
  function ensureRatingStyle() {
    if (ratingStyleInjected) return;
    ratingStyleInjected = true;
    const style = document.createElement('style');
    style.textContent = `
      .wp-stars { position: relative; display: inline-block; line-height: 1; letter-spacing: 1px; color: #DADADA; white-space: nowrap; vertical-align: middle; }
      .wp-stars-fill { position: absolute; top: 0; left: 0; overflow: hidden; color: #FF8A00; white-space: nowrap; }
      .wp-rating-summary { display: flex; align-items: center; flex-wrap: wrap; gap: 6px 10px; font-size: 15px; }
      .wp-rating-count { color: #346AFF; text-decoration: none; }
      .wp-rating-count:hover { text-decoration: underline; }
      .wp-rating-satisfied { color: #333; }
      .wp-rating-satisfied b { color: #E8590C; font-weight: 700; }
      .wp-review-head { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
      .wp-review-avatar { width: 44px; height: 44px; border-radius: 50%; background: linear-gradient(135deg, #CBD3E1, #AEB8CA); flex-shrink: 0; }
      .wp-review-author { font-weight: 700; font-size: 15px; color: #222; }
      .wp-review-sub { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #888; margin-top: 2px; }
      .product-rating-line { display: flex; align-items: center; gap: 4px; font-size: 12px; color: #888; margin: 4px 0 2px; }
    `;
    document.head.appendChild(style);
  }

  function renderStars(rating, size) {
    ensureRatingStyle();
    const r = Math.max(0, Math.min(5, Number(rating) || 0));
    const pct = Math.round(r * 2) / 2 / 5 * 100; // 0.5 단위로 반올림
    const fs = size ? `font-size:${size}px;` : '';
    return `<span class="wp-stars" style="${fs}" role="img" aria-label="별점 5점 만점에 ${r.toFixed(1)}점">★★★★★<span class="wp-stars-fill" style="width:${pct}%">★★★★★</span></span>`;
  }

  // 만족 인원 표기 — 10명 미만은 정확히, 그 이상은 자릿수 단위로 내림해 "N명 이상"으로 보여준다 (예: 127 → 100명 이상)
  function formatSatisfied(count) {
    const n = Number(count) || 0;
    if (n <= 0) return '';
    if (n < 10) return `<b>${n}명</b>이 만족했어요`;
    const unit = n < 100 ? 10 : n < 1000 ? 100 : 1000;
    return `<b>${(Math.floor(n / unit) * unit).toLocaleString('ko-KR')}명 이상</b> 만족했어요`;
  }

  function renderRatingSummary(rating, reviewCount, satisfiedCount, reviewsHref) {
    const count = Number(reviewCount) || 0;
    const satisfied = formatSatisfied(satisfiedCount);
    return `<div class="wp-rating-summary">
        ${renderStars(rating, 17)}
        <a class="wp-rating-count" href="${reviewsHref || '#reviews'}">${count.toLocaleString('ko-KR')} 개 상품평</a>
        ${satisfied ? `<span class="wp-rating-satisfied">👍 ${satisfied}</span>` : ''}
      </div>`;
  }

  // 리뷰 한 건 (작성자 가린 이름 + 별점 + 날짜 + 본문)
  function renderReviewItem(r) {
    const date = new Date(r.created_at);
    const dateText = isNaN(date) ? '' : `${date.getFullYear()}.${String(date.getMonth() + 1).padStart(2, '0')}.${String(date.getDate()).padStart(2, '0')}`;
    return `
      <div class="review-item">
        <div class="wp-review-head">
          <span class="wp-review-avatar" aria-hidden="true"></span>
          <div>
            <div class="wp-review-author">${escapeHtml(r.author_name || '구매자')}</div>
            <div class="wp-review-sub">${renderStars(r.rating, 16)}<span>${dateText}</span>${r.verified_purchase ? '<span style="color:#D32F5B; font-weight:600;">✅ 구매인증</span>' : ''}</div>
          </div>
        </div>
        <div class="review-comment">${escapeHtml(r.comment || '')}</div>
      </div>`;
  }

  function renderProductCard(product) {
    const emoji = CATEGORY_EMOJI[product.category] || CATEGORY_EMOJI.default;
    const hasDiscount = product.discount_price && Number(product.discount_price) < Number(product.price);
    const currentPrice = hasDiscount ? product.discount_price : product.price;
    const discountRate = hasDiscount
      ? Math.round((1 - Number(product.discount_price) / Number(product.price)) * 100)
      : 0;
    const rating = Number(product.rating || 0).toFixed(1);
    const reviewCount = product.review_count || 0;
    const outOfStock = Number(product.stock) <= 0;
    const imageUrl = Array.isArray(product.images_urls) && product.images_urls.length > 0 ? product.images_urls[0] : null;
    const rates = cachedMileageRates;

    return `
    <div class="product-card" data-product-id="${product.id}" style="cursor:pointer;">
        <div class="product-image" ${imageUrl ? `style="background-image:url('${safeUrlAttr(imageUrl)}');background-size:cover;background-position:center;"` : ''}>
            <div class="mileage-badge">
                <span class="individual">적립 ${formatPercent(rates.personalPercent)}%</span>
                <span class="bonus">+${formatPercent(rates.communityPercent)}%</span>
            </div>
            <div class="product-actions">
                <button class="action-btn wishlist-btn" type="button">❤️</button>
                <button class="action-btn" type="button">🛒</button>
            </div>
            ${imageUrl ? '' : emoji}
        </div>
        <div class="product-info">
            <h3 class="product-name">${escapeHtml(product.name)}</h3>
            <div class="product-price">
                <span class="current-price">${formatPrice(currentPrice)}</span>
                ${hasDiscount ? `<span class="original-price">${formatPrice(product.price)}</span>
                <span class="discount-rate">${discountRate}%</span>` : ''}
            </div>
            <div class="product-rating-line">${renderStars(rating, 14)} <span class="product-review-count">(${Number(reviewCount).toLocaleString('ko-KR')})</span></div>
            <div class="product-meta">
                ${outOfStock ? '품절' : '재고 ' + product.stock + '개'} | 배송비 무료
            </div>
            <button class="add-to-cart-btn" type="button" ${outOfStock ? 'disabled' : ''}>${outOfStock ? '품절된 상품입니다' : '장바구니 담기'}</button>
        </div>
    </div>`;
  }

  // 카드 클릭(상세 이동) + 장바구니 + 찜하기 : 이벤트 위임(동적으로 추가된 카드에도 동작)
  function attachProductCardInteractions() {
    if (global.__withplusInteractionsAttached) return;
    global.__withplusInteractionsAttached = true;

    // 상세 페이지 이동 (버튼/액션 영역 클릭은 제외)
    document.addEventListener('click', function (e) {
      const card = e.target.closest('.product-card[data-product-id]');
      if (!card) return;
      if (e.target.closest('.product-actions') || e.target.closest('.add-to-cart-btn')) return;
      const id = card.getAttribute('data-product-id');
      if (id) location.href = '/product/' + id;
    });

    // 장바구니 담기 (실제 localStorage 장바구니에 저장)
    document.addEventListener('click', function (e) {
      const btn = e.target.closest('.add-to-cart-btn');
      if (!btn || btn.disabled) return;
      e.preventDefault();
      e.stopPropagation();
      const card = btn.closest('[data-product-id]');
      const productId = card ? card.getAttribute('data-product-id') : null;
      if (productId) addToCart(productId, 1);
      const original = btn.textContent;
      btn.textContent = '✓ 장바구니에 담겼습니다';
      btn.style.background = '#4CAF50';
      setTimeout(() => {
        btn.textContent = original;
        btn.style.background = 'var(--primary-color)';
      }, 2000);
    });

    // 찜하기 토글 (실제 서버에 저장/삭제되는 위시리스트)
    document.addEventListener('click', async function (e) {
      const btn = e.target.closest('.wishlist-btn, .product-actions .action-btn:first-child');
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();

      const session = await getSession();
      if (!session) {
        if (confirm('찜하기는 로그인 후 이용할 수 있습니다. 로그인 화면으로 이동할까요?')) {
          location.href = '/login';
        }
        return;
      }

      const card = btn.closest('[data-product-id]');
      const productId = card ? card.getAttribute('data-product-id') : null;
      if (!productId || btn.disabled) return;

      const isWishlisted = btn.textContent.trim() === '🖤';
      btn.disabled = true;
      try {
        const token = await getAccessToken();
        if (isWishlisted) {
          await fetch(API_BASE + '/api/wishlist/' + productId, {
            method: 'DELETE',
            headers: { 'Authorization': 'Bearer ' + token }
          });
          btn.textContent = '❤️';
        } else {
          await fetch(API_BASE + '/api/wishlist', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
            body: JSON.stringify({ product_id: productId })
          });
          btn.textContent = '🖤';
        }
      } catch (err) {
        // 실패 시 상태 변경 없이 그대로 둠 (사용자가 다시 시도할 수 있도록)
      } finally {
        btn.disabled = false;
      }
    });
  }

  // 현재 화면에 렌더링된 상품 카드 중, 로그인한 회원이 실제로 찜한 상품의 하트를 채워서 표시
  async function syncWishlistHearts() {
    try {
      const session = await getSession();
      if (!session) return;

      const token = await getAccessToken();
      const res = await fetch(API_BASE + '/api/wishlist', { headers: { 'Authorization': 'Bearer ' + token } });
      const json = await res.json();
      if (!res.ok || !json.success) return;

      const wishlistedIds = new Set(json.data.map(p => p.id));
      document.querySelectorAll('.product-card[data-product-id]').forEach(card => {
        const id = card.getAttribute('data-product-id');
        const btn = card.querySelector('.wishlist-btn, .product-actions .action-btn:first-child');
        if (btn && wishlistedIds.has(id)) btn.textContent = '🖤';
      });
    } catch (err) { /* 실패 시 조용히 무시 (기본 빈 하트 상태 유지) */ }
  }

  // 최근 본 상품 기록 (localStorage)
  const RECENT_KEY = 'withplus_recently_viewed';
  function recordRecentlyViewed(productId) {
    try {
      let list = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]');
      list = list.filter(id => id !== productId);
      list.unshift(productId);
      list = list.slice(0, 10);
      localStorage.setItem(RECENT_KEY, JSON.stringify(list));
    } catch (e) { /* localStorage 미지원 환경 무시 */ }
  }
  function getRecentlyViewed() {
    try {
      return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]');
    } catch (e) {
      return [];
    }
  }

  const VALID_INTERACTION_EVENTS = ['view', 'view_end', 'cart_add', 'cart_remove'];
  async function recordInteraction(eventType, productId, extra, opts) {
    try {
      if (!productId || !VALID_INTERACTION_EVENTS.includes(eventType)) return;
      const body = Object.assign({ product_id: productId, event_type: eventType }, extra || {});
      const keepalive = !!(opts && opts.keepalive);
      const session = await getSession().catch(() => null);
      const token = session && session.access_token;
      if (keepalive && !token && typeof navigator !== 'undefined' && navigator.sendBeacon) {
        const blob = new Blob([JSON.stringify(body)], { type: 'application/json' });
        const sent = navigator.sendBeacon(API_BASE + '/api/interactions', blob);
        if (sent) return;
      }
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers.Authorization = 'Bearer ' + token;
      await fetch(API_BASE + '/api/interactions', { method: 'POST', headers, body: JSON.stringify(body), keepalive });
    } catch (e) { /* 트래킹 실패가 사용자 경험을 막아서는 안 됨 - 조용히 무시 */ }
  }

  // ============================================
  // 검색창 공통 초기화 - 헤더의 .search-box(input+button)가 있는 모든 페이지에서 호출.
  // 엔터/돋보기 클릭 시 /search?q=검색어로 이동하고, 입력하는 동안 오타허용 자동완성 드롭다운을 보여준다.
  // 예전에는 검색 버튼을 눌러도 "검색 기능은 준비 중입니다" 알림만 뜨고 실제로 동작하지 않았다.
  // ============================================
  function initSearchBox() {
    document.querySelectorAll('.search-box').forEach(box => {
      const input = box.querySelector('input');
      const btn = box.querySelector('button');
      if (!input || input.dataset.wpSearchInit) return;
      input.dataset.wpSearchInit = '1';

      function doSearch() {
        const q = input.value.trim();
        if (!q) return;
        location.href = '/search?q=' + encodeURIComponent(q);
      }
      if (btn) btn.addEventListener('click', (e) => { e.preventDefault(); doSearch(); });
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doSearch(); } });

      box.style.position = 'relative';
      const dropdown = document.createElement('div');
      dropdown.className = 'wp-autocomplete-dropdown';
      dropdown.style.cssText = 'position:absolute; top:calc(100% + 6px); left:0; right:0; min-width:260px; background:#fff; border:1px solid #E0E0E0; border-radius:10px; box-shadow:0 8px 24px rgba(0,0,0,0.12); z-index:200; max-height:320px; overflow-y:auto; display:none;';
      box.appendChild(dropdown);

      let debounceTimer;
      input.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        const q = input.value.trim();
        if (q.length < 1) { dropdown.style.display = 'none'; return; }
        debounceTimer = setTimeout(async () => {
          try {
            const { json } = await fetchJSON('/api/search/autocomplete?q=' + encodeURIComponent(q));
            const items = (json && json.data) || [];
            if (items.length === 0) { dropdown.style.display = 'none'; return; }
            dropdown.innerHTML = items.map(it => `
              <div class="wp-autocomplete-item" data-id="${it.id}" style="padding:10px 14px; cursor:pointer; font-size:0.88em; display:flex; justify-content:space-between; align-items:center; gap:10px; border-bottom:1px solid #F5F5F5; text-align:left; color:#333;">
                <span>${escapeHtml(it.name)}</span>
                ${it.price ? `<span style="color:#999; white-space:nowrap;">${formatPrice(it.price)}원</span>` : ''}
              </div>`).join('');
            dropdown.style.display = 'block';
            dropdown.querySelectorAll('.wp-autocomplete-item').forEach(el => {
              el.addEventListener('click', () => { location.href = '/product/' + el.dataset.id; });
            });
          } catch (e) { dropdown.style.display = 'none'; }
        }, 250);
      });

      document.addEventListener('click', (e) => {
        if (!box.contains(e.target)) dropdown.style.display = 'none';
      });
    });
  }

  // ===== PWA (Progressive Web App) =====
  const PWA_INSTALL_DISMISS_KEY = 'wp_pwa_install_dismissed_at';
  const PWA_INSTALL_DISMISS_DAYS = 14;
  let _pwaDeferredPrompt = null;

  function injectPwaHeadTags() {
    if (!document.querySelector('link[rel="manifest"]')) {
      const link = document.createElement('link');
      link.rel = 'manifest';
      link.href = '/manifest.json';
      document.head.appendChild(link);
    }
    if (!document.querySelector('meta[name="theme-color"]')) {
      const meta = document.createElement('meta');
      meta.name = 'theme-color';
      meta.content = '#D32F5B';
      document.head.appendChild(meta);
    }
    if (!document.querySelector('link[rel="apple-touch-icon"]')) {
      const appleLink = document.createElement('link');
      appleLink.rel = 'apple-touch-icon';
      appleLink.href = '/images/icons/apple-touch-icon.png';
      document.head.appendChild(appleLink);
    }
  }

  function registerServiceWorker() {
    if (location.protocol === 'file:') return;
    if (!('serviceWorker' in navigator)) return;
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js').catch(err => {
        console.warn('[WithPlus] 서비스워커 등록 실패:', err);
      });
    });
  }

  function shouldShowInstallBanner() {
    try {
      const dismissedAt = localStorage.getItem(PWA_INSTALL_DISMISS_KEY);
      if (!dismissedAt) return true;
      const elapsedDays = (Date.now() - Number(dismissedAt)) / (1000 * 60 * 60 * 24);
      return elapsedDays >= PWA_INSTALL_DISMISS_DAYS;
    } catch (e) {
      return true;
    }
  }

  function renderInstallBanner() {
    if (document.getElementById('wp-pwa-install-banner')) return;
    const banner = document.createElement('div');
    banner.id = 'wp-pwa-install-banner';
    banner.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:9999;background:#222;color:#fff;padding:14px 20px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;box-shadow:0 -2px 8px rgba(0,0,0,0.2);font-size:0.92em;';
    banner.innerHTML = `
      <span>📱 WITH+를 홈 화면에 추가하고 더 빠르게 이용해보세요.</span>
      <span style="display:flex; gap:8px; flex-shrink:0;">
        <button type="button" id="wp-pwa-install-btn" style="background:#D32F5B; color:#fff; border:none; border-radius:20px; padding:8px 18px; font-weight:600; cursor:pointer;">설치</button>
        <button type="button" id="wp-pwa-dismiss-btn" style="background:transparent; color:#ccc; border:1px solid #555; border-radius:20px; padding:8px 14px; cursor:pointer;">닫기</button>
      </span>`;
    document.body.appendChild(banner);

    document.getElementById('wp-pwa-install-btn').addEventListener('click', async () => {
      if (!_pwaDeferredPrompt) { banner.remove(); return; }
      _pwaDeferredPrompt.prompt();
      await _pwaDeferredPrompt.userChoice;
      _pwaDeferredPrompt = null;
      banner.remove();
    });
    document.getElementById('wp-pwa-dismiss-btn').addEventListener('click', () => {
      try { localStorage.setItem(PWA_INSTALL_DISMISS_KEY, String(Date.now())); } catch (e) {}
      banner.remove();
    });
  }

  function registerPwa() {
    injectPwaHeadTags();
    registerServiceWorker();

    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      _pwaDeferredPrompt = e;
      if (shouldShowInstallBanner()) renderInstallBanner();
    });

    window.addEventListener('appinstalled', () => {
      _pwaDeferredPrompt = null;
      const banner = document.getElementById('wp-pwa-install-banner');
      if (banner) banner.remove();
    });
  }

  // ============================================
  // GMWOS ↔ WITH+ 단일 로그인(SSO) 수신
  // GMWOS(같은 Supabase 프로젝트)에서 로그인한 세션을 URL 해시(#wp_sso=1&at=..&rt=..)로
  // 넘겨받아 이 도메인(onrender)에도 동일 세션을 심는다. 토큰은 심기 전에 URL/히스토리에서 즉시 제거.
  // 해시는 서버로 전송되지 않으므로 서버 로그에 남지 않는다(Supabase OAuth 리다이렉트와 동일 패턴).
  // ============================================
  async function consumeSsoHandoff() {
    let hash = '';
    try { hash = location.hash || ''; } catch (e) { return; }
    if (hash.indexOf('wp_sso=1') === -1) return;
    const p = new URLSearchParams(hash.replace(/^#/, ''));
    const at = p.get('at');
    const rt = p.get('rt');
    // 토큰을 URL/히스토리에서 먼저 제거 (심기 전에)
    try { history.replaceState(null, '', location.pathname + location.search); }
    catch (e) { try { location.hash = ''; } catch (e2) {} }
    if (!at || !rt) return;
    try {
      const client = await getClient();
      const { error } = await client.auth.setSession({ access_token: at, refresh_token: rt });
      if (!error) {
        // 세션이 반영된 상태로 전체 페이지 재초기화(헤더 로그인표시·장바구니 동기화 등)
        location.replace(location.pathname + location.search);
      }
    } catch (e) { /* 실패해도 일반 로그인 흐름으로 계속 진행 */ }
  }

  // ============================================
  // 개수 선택 컨트롤: 상품이 계속 이어지는 섹션(베스트 상품, 추천 상품 등) 옆에
  // "8개/16개/24개/전체" 버튼을 붙여 사용자가 원하는 만큼만 보이도록 한다.
  // controlsEl: 버튼을 그릴 컨테이너, gridEl: 카드가 렌더링될 그리드,
  // fullItems: 이미 로드해 둔 전체 상품 배열(추가 API 호출 없이 클라이언트에서 자름).
  // options.counts: 버튼에 노출할 개수 목록(기본 [8, 16, 24]), options.renderItem: 카드 렌더 함수,
  // options.storageKey: 선택한 개수를 기억해둘 localStorage 키(생략 시 매번 첫 옵션으로 시작).
  // ============================================
  function mountCountControl(controlsEl, gridEl, fullItems, options) {
    if (!controlsEl || !gridEl) return;
    options = options || {};
    const counts = options.counts || [8, 16, 24];
    const renderItem = options.renderItem || renderProductCard;
    const storageKey = options.storageKey || null;
    const items = fullItems || [];

    // 전체 개수가 가장 작은 옵션보다도 적으면 굳이 컨트롤을 보여줄 필요가 없다
    const availableCounts = counts.filter(c => c < items.length);

    function render(count) {
      const shown = (count == null) ? items : items.slice(0, count);
      gridEl.innerHTML = shown.map(renderItem).join('');
      syncWishlistHearts();
      attachProductCardInteractions();
    }

    if (availableCounts.length === 0) {
      controlsEl.innerHTML = '';
      render(null);
      return;
    }

    function readSaved() {
      if (!storageKey) return null;
      try { return localStorage.getItem(storageKey); } catch (e) { return null; }
    }
    function save(value) {
      if (!storageKey) return;
      try { localStorage.setItem(storageKey, value); } catch (e) { /* 무시 */ }
    }

    const saved = readSaved();
    let initial = availableCounts[0];
    if (saved === 'all') {
      initial = null;
    } else {
      const savedNum = parseInt(saved, 10);
      if (availableCounts.includes(savedNum)) initial = savedNum;
    }

    controlsEl.innerHTML = availableCounts.map(c =>
      `<button type="button" class="count-btn" data-count="${c}">${c}개</button>`
    ).join('') + `<button type="button" class="count-btn" data-count="all">전체</button>`;

    function setActive(count) {
      controlsEl.querySelectorAll('.count-btn').forEach(btn => {
        const isAllBtn = btn.dataset.count === 'all';
        btn.classList.toggle('active', isAllBtn ? count == null : parseInt(btn.dataset.count, 10) === count);
      });
    }

    controlsEl.querySelectorAll('.count-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const isAllBtn = btn.dataset.count === 'all';
        const count = isAllBtn ? null : parseInt(btn.dataset.count, 10);
        render(count);
        setActive(count);
        save(isAllBtn ? 'all' : String(count));
      });
    });

    setActive(initial);
    render(initial);
  }

  // 종교 중립 문구 헬퍼 (GIVE+ 1단계) - community.org_type에 따라 랜딩페이지 하단 문구를 다르게 보여준다.
  // 예전에는 "하나님의 사랑을 전하는 사역"이 모든 조직(성당/사찰 포함)에 하드코딩되어 있었는데,
  // 개신교 외 종교시설(성당/사찰) 연결이 실제로 예정되어 있어 org_type별로 분기하도록 고쳤다.
  const ORG_TYPE_NAMES = { church: '교회', catholic: '성당', buddhist: '사찰', other: '기관/단체' };
  const POWERED_BY_TAGLINES = {
    church: '하나님의 사랑을 전하는 사역에 동참합니다',
    catholic: '하느님의 사랑을 전하는 사목에 동참합니다',
    buddhist: '자비의 마음을 나누는 원력에 동참합니다',
    other: '공동체의 나눔에 함께합니다'
  };
  function getOrgTypeName(orgType) {
    return ORG_TYPE_NAMES[orgType] || ORG_TYPE_NAMES.other;
  }
  function getPoweredByTagline(orgType) {
    return POWERED_BY_TAGLINES[orgType] || POWERED_BY_TAGLINES.other;
  }

  // 분양 랜딩페이지의 "헌금/후원하러 가기" 버튼 문구 - org_type에 맞는 실제 용어로 자동 전환한다
  // (교회는 "헌금", 사찰은 "시주"가 실제로 쓰이는 표현이라 통일하면 부자연스러움).
  const OFFERING_CTA_LABELS = {
    church: '🙏 온라인 헌금하기',
    catholic: '🙏 온라인 헌금하기',
    buddhist: '🙏 온라인 시주하기',
    other: '🙏 온라인 후원하기'
  };
  function getOfferingCtaLabel(orgType) {
    return OFFERING_CTA_LABELS[orgType] || OFFERING_CTA_LABELS.other;
  }

  // ============================================
  // 📱 WITH+ 앱 셸 (기본틀 메뉴) — 브랜드 로고 / ☰ 전체메뉴(드로어) / 🔔 알림 배지 / 하단 탭바
  // WITH+ 기본틀 디자인(모바일 앱형)의 메뉴 구성을 모든 쇼핑 화면에 공통으로 붙인다.
  //  - 하단 탭바: 홈 · 카테고리 · LIVE · 찜 · 마이페이지 (태블릿/모바일 폭에서만 노출, 데스크톱은 상단 메뉴 사용)
  //  - ☰ 버튼: 헤더 로고 왼쪽에 자동으로 붙고, 누르면 카테고리/게시판/고객센터 전체메뉴 드로어가 열린다
  //  - 관리자/로그인·가입 같은 단독 화면은 SHELL_EXCLUDED_PATHS로 제외한다
  // ============================================
  const BRAND_LOGO_SRC = '/images/brand/withplus-logo.webp';
  const SHELL_EXCLUDED_PATHS = /^\/(admin|login|join|reset-password|verify-phone|payment-result|welcome|offline|404)(\.html)?(\/|$)/;

  const SHELL_ICONS = {
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    close: '<path d="M6 6l12 12M18 6L6 18"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
    bell: '<path d="M6 9a6 6 0 1 1 12 0c0 6 2.5 7.5 2.5 7.5h-17S6 15 6 9z"/><path d="M10.3 20a1.9 1.9 0 0 0 3.4 0"/>',
    cart: '<path d="M3 4h2.2l2.3 11h10.8l2.2-8H6.6"/><circle cx="9.5" cy="19.5" r="1.4"/><circle cx="17" cy="19.5" r="1.4"/>',
    home: '<path d="M3.5 10.5L12 3.5l8.5 7V20a1 1 0 0 1-1 1H15v-6h-6v6H4.5a1 1 0 0 1-1-1z"/>',
    grid: '<rect x="4" y="4" width="6.5" height="6.5" rx="1.6"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.6"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.6"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.6"/>',
    live: '<circle cx="12" cy="12" r="9"/><path d="M10 8.8v6.4l5.2-3.2z"/>',
    heart: '<path d="M12 20s-7.5-4.6-7.5-10.2A4.3 4.3 0 0 1 12 7.2a4.3 4.3 0 0 1 7.5 2.6C19.5 15.4 12 20 12 20z"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4.5 20.5c1.2-3.6 4-5.3 7.5-5.3s6.3 1.7 7.5 5.3"/>',
    pin: '<path d="M12 21s-6.5-6.2-6.5-11.3a6.5 6.5 0 0 1 13 0C18.5 14.8 12 21 12 21z"/><circle cx="12" cy="9.7" r="2.4"/>',
    chevronDown: '<path d="M6 9l6 6 6-6"/>',
    chevronRight: '<path d="M9 6l6 6-6 6"/>'
  };
  function shellIcon(name, size) {
    const s = size || 24;
    return `<svg viewBox="0 0 24 24" width="${s}" height="${s}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${SHELL_ICONS[name] || ''}</svg>`;
  }

  // 홈 화면 카테고리 아이콘 메뉴용 라인 아이콘 — 카테고리는 관리자가 DB에서 관리하므로
  // 슬러그/이름에 들어있는 키워드로 아이콘을 고르고, 맞는 게 없으면 카테고리 이모지를 그대로 쓴다.
  const CATEGORY_LINE_ICONS = [
    { keys: ['diet', '다이어트', '슬림'], svg: '<path d="M8 3c-.5 3 .5 5 1.5 6.5M16 3c.5 3-.5 5-1.5 6.5"/><path d="M9.5 9.5C8 12 7.5 14.5 8.5 17.5c.6 1.8 2 3 3.5 3s2.9-1.2 3.5-3c1-3 .5-5.5-1-8"/><path d="M5 12h3M16 12h3M5 12l1.3-1.3M5 12l1.3 1.3M19 12l-1.3-1.3M19 12l-1.3 1.3"/>' },
    { keys: ['beauty', 'cosmetic', '화장품', '뷰티'], svg: '<rect x="5" y="9" width="6" height="12" rx="1.5"/><path d="M6.5 9V6.5h3V9M8 6.5V4h3"/><rect x="13" y="7" width="6" height="14" rx="1.5"/><path d="M14.5 7V4.5h3V7M13 12h6"/>' },
    { keys: ['health', 'functional', 'vitamin', 'probiotic', '건강', '기능', '비타민', '유산균', '영양'], svg: '<rect x="3.2" y="9" width="11" height="6" rx="3" transform="rotate(-35 8.7 12)"/><path d="M6.2 15.4l4.9-3.4"/><circle cx="16.5" cy="15.5" r="4.3"/><path d="M13.5 18.5l6-6"/>' },
    { keys: ['food', 'tea', '식품', '음료', '차', '간식'], svg: '<path d="M3.5 12h17a8.5 8.5 0 0 1-17 0z"/><circle cx="9" cy="8.5" r="2.3"/><circle cx="14" cy="7.5" r="2.6"/><path d="M11.5 4.5c.5-1 1.5-1.5 2.5-1.3"/>' },
    { keys: ['lifestyle', 'living', 'household', '생활', '리빙'], svg: '<path d="M9 3h4v3H9z"/><path d="M13 4.5h3l1.5 2"/><path d="M8 9a3 3 0 0 1 3-3h0a3 3 0 0 1 3 3v10a2 2 0 0 1-2 2h-2a2 2 0 0 1-2-2z"/><path d="M15.5 17c0-3 3.5-3.5 4-6 1 2.5.5 6-2 7.5"/>' },
    { keys: ['fashion', 'cloth', 'apparel', '패션', '의류'], svg: '<path d="M8.5 3.5L4 6l1.8 4.2 2.2-.9V20.5h8V9.3l2.2.9L20 6l-4.5-2.5a3.5 3.5 0 0 1-7 0z"/>' },
    { keys: ['special', 'event', 'promotion', 'exhibition', '기획', '이벤트', '특가'], svg: '<path d="M3.5 12.5l8-8h7.5a1.5 1.5 0 0 1 1.5 1.5v7.5l-8 8a1.5 1.5 0 0 1-2.1 0L3.5 14.6a1.5 1.5 0 0 1 0-2.1z"/><circle cx="16" cy="8" r="1.4"/><path d="M9.5 15.5l4-4M10 11.8h.01M13.2 15h.01"/>' }
  ];
  function getCategoryLineIcon(cat) {
    const hay = ((cat.slug || '') + ' ' + (cat.label || '')).toLowerCase();
    const hit = CATEGORY_LINE_ICONS.find(i => i.keys.some(k => hay.indexOf(k) !== -1));
    return hit
      ? `<svg viewBox="0 0 24 24" width="30" height="30" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${hit.svg}</svg>`
      : `<span class="wp-cat-emoji">${escapeHtml(cat.emoji || '🎁')}</span>`;
  }

  function isShellPage() {
    if (document.body && document.body.hasAttribute('data-wp-no-shell')) return false;
    return !SHELL_EXCLUDED_PATHS.test(location.pathname);
  }

  let shellStyleInjected = false;
  function ensureShellStyle() {
    if (shellStyleInjected) return;
    shellStyleInjected = true;
    const style = document.createElement('style');
    style.id = 'wp-shell-style';
    style.textContent = `
      .wp-logo-img { height: 40px; width: auto; display: block; }
      a.logo:has(.wp-logo-img), .top-logo a:has(.wp-logo-img) { display: inline-flex; flex-direction: column; align-items: center; line-height: 1.1; text-decoration: none; }
      /* 로고 마크 아래 슬로건 — 브랜드 이미지와 같은 배색(앞 검정 · 뒤 핑크) */
      .logo .wp-logo-tagline, .top-logo .wp-logo-tagline { display: block; margin: 3px 0 0; font-size: 11.5px; font-weight: 800; color: #333; letter-spacing: -0.03em; white-space: nowrap; line-height: 1.2; }
      .logo .wp-logo-tagline b, .top-logo .wp-logo-tagline b { color: #E8125C; font-weight: 800; }
      .top-logo .wp-logo-tagline { font-size: 13px; margin-top: 4px; }
      .wp-icon-btn { position: relative; display: inline-flex; align-items: center; justify-content: center; width: 42px; height: 42px; border: none; background: none; color: #222; cursor: pointer; border-radius: 50%; text-decoration: none; flex-shrink: 0; }
      .wp-icon-btn:hover { background: #FFF0F4; color: #E8125C; }
      .wp-icon-badge { position: absolute; top: 2px; right: 0; min-width: 18px; height: 18px; padding: 0 5px; border-radius: 9px; background: #E8125C; color: #fff; font-size: 11px; font-weight: 700; line-height: 18px; text-align: center; border: 2px solid #fff; box-sizing: content-box; }
      .wp-icon-badge[data-count="0"] { display: none; }
      .wp-menu-btn { margin-right: 4px; }

      .wp-drawer-backdrop { position: fixed; inset: 0; background: rgba(20,10,15,0.45); z-index: 1000; opacity: 0; pointer-events: none; transition: opacity .2s; }
      .wp-drawer-backdrop.open { opacity: 1; pointer-events: auto; }
      .wp-drawer { position: fixed; top: 0; left: 0; bottom: 0; width: min(340px, 88vw); background: #fff; z-index: 1001; transform: translateX(-100%); transition: transform .25s ease; display: flex; flex-direction: column; box-shadow: 4px 0 24px rgba(0,0,0,0.12); }
      .wp-drawer.open { transform: translateX(0); }
      .wp-drawer-head { display: flex; align-items: center; justify-content: space-between; padding: 14px 12px 14px 18px; border-bottom: 1px solid #F3E3E8; }
      .wp-drawer-head img { height: 34px; }
      .wp-drawer-user { margin: 14px 16px 6px; padding: 14px 16px; border-radius: 14px; background: linear-gradient(135deg, #FFF0F4, #FFE3EC); font-size: 14px; color: #333; display: flex; align-items: center; justify-content: space-between; gap: 10px; }
      .wp-drawer-user a { color: #E8125C; font-weight: 700; text-decoration: none; white-space: nowrap; }
      .wp-drawer-body { overflow-y: auto; padding: 6px 0 24px; flex: 1; }
      .wp-drawer-section { padding: 12px 18px 4px; font-size: 12px; font-weight: 700; color: #E8125C; letter-spacing: .02em; }
      .wp-drawer-cats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; padding: 6px 12px 8px; }
      .wp-drawer-cats a { display: flex; flex-direction: column; align-items: center; gap: 4px; padding: 10px 4px; border-radius: 12px; text-decoration: none; color: #333; font-size: 13px; }
      .wp-drawer-cats a:hover { background: #FFF0F4; }
      .wp-drawer-cats .wp-cat-ico { width: 46px; height: 46px; border-radius: 50%; background: #FFF0F4; color: #E8125C; display: flex; align-items: center; justify-content: center; }
      .wp-drawer-cats .wp-cat-ico svg { width: 24px; height: 24px; }
      .wp-cat-emoji { font-size: 22px; line-height: 1; }
      .wp-drawer-link { display: flex; align-items: center; justify-content: space-between; padding: 12px 18px; color: #222; text-decoration: none; font-size: 15px; }
      .wp-drawer-link:hover { background: #FFF7F9; color: #E8125C; }
      .wp-drawer-link svg { color: #C9AAB4; }
      body.wp-drawer-lock { overflow: hidden; }

      .wp-tabbar { display: none; }
      @media (max-width: 1024px) {
        body.wp-has-tabbar { padding-bottom: calc(64px + env(safe-area-inset-bottom)); }
        .wp-tabbar { display: grid; grid-template-columns: repeat(5, 1fr); position: fixed; left: 0; right: 0; bottom: 0; z-index: 900; background: rgba(255,255,255,0.97); backdrop-filter: blur(8px); border-top: 1px solid #F1E4E8; padding: 6px 4px calc(6px + env(safe-area-inset-bottom)); box-shadow: 0 -2px 12px rgba(0,0,0,0.04); }
        .wp-tabbar a, .wp-tabbar button { display: flex; flex-direction: column; align-items: center; gap: 2px; padding: 4px 0; font-size: 11px; color: #777; text-decoration: none; background: none; border: none; cursor: pointer; font-family: inherit; }
        .wp-tabbar .active { color: #E8125C; font-weight: 700; }
        .wp-tabbar .active svg { fill: currentColor; fill-opacity: .12; }
      }
    `;
    document.head.appendChild(style);
  }

  // 정적 HTML에 아직 텍스트 로고("WITH+")가 남아있는 화면이 있으면 브랜드 마크 이미지로 바꿔준다
  function applyBrandLogo() {
    document.querySelectorAll('a.logo, .top-logo a').forEach(el => {
      if (el.querySelector('img')) return;
      const sub = el.querySelector('span');
      const subText = sub ? sub.textContent.trim() : '';
      el.innerHTML = `<img src="${BRAND_LOGO_SRC}" alt="WITH+" class="wp-logo-img">` +
        (subText && subText !== '함께할수록 더해지는 가치'
          ? `<span>${escapeHtml(subText)}</span>`
          : '<span class="wp-logo-tagline">함께할수록 <b>더해지는 가치</b></span>');
      el.setAttribute('aria-label', 'WITH+ 홈');
    });
  }

  function buildDrawer() {
    if (document.getElementById('wp-drawer')) return;
    const backdrop = document.createElement('div');
    backdrop.className = 'wp-drawer-backdrop';
    backdrop.id = 'wp-drawer-backdrop';
    const drawer = document.createElement('aside');
    drawer.className = 'wp-drawer';
    drawer.id = 'wp-drawer';
    drawer.setAttribute('aria-label', '전체 메뉴');
    drawer.setAttribute('aria-hidden', 'true');
    const link = (href, label) => `<a class="wp-drawer-link" href="${href}"><span>${label}</span>${shellIcon('chevronRight', 18)}</a>`;
    drawer.innerHTML = `
      <div class="wp-drawer-head">
        <a href="/" class="logo" aria-label="WITH+ 홈"><img src="${BRAND_LOGO_SRC}" alt="WITH+" class="wp-logo-img" style="height:34px;"><span class="wp-logo-tagline">함께할수록 <b>더해지는 가치</b></span></a>
        <button type="button" class="wp-icon-btn" id="wp-drawer-close" aria-label="메뉴 닫기">${shellIcon('close')}</button>
      </div>
      <div class="wp-drawer-user" id="wp-drawer-user"><span>로그인하고 적립 혜택을 받아보세요</span><a href="/login">로그인</a></div>
      <div class="wp-drawer-body">
        <div class="wp-drawer-section" id="wp-drawer-cats-title">카테고리</div>
        <div class="wp-drawer-cats" id="wp-drawer-cats"></div>
        <div class="wp-drawer-section">쇼핑</div>
        ${link('/search', '상품 검색')}
        ${link('/cart', '장바구니')}
        ${link('/mypage#wish', '찜한 상품')}
        ${link('/live', 'LIVE 라이브 쇼핑')}
        <div class="wp-drawer-section">커뮤니티</div>
        ${link('/communities', '공동체(커뮤니티) 혜택 안내')}
        ${link('/notice', '공지사항')}
        ${link('/board/review', '사용후기')}
        ${link('/board/qa', 'Q&amp;A')}
        ${link('/board/free', '자유게시판')}
        <div class="wp-drawer-section">고객지원</div>
        ${link('/support', '고객센터')}
        ${link('/faq', '자주 묻는 질문')}
        ${link('/manual.html', '사용설명서')}
      </div>`;
    document.body.appendChild(backdrop);
    document.body.appendChild(drawer);
    backdrop.addEventListener('click', closeDrawer);
    drawer.querySelector('#wp-drawer-close').addEventListener('click', closeDrawer);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
  }

  async function fillDrawer() {
    const catsEl = document.getElementById('wp-drawer-cats');
    if (catsEl && !catsEl.dataset.loaded) {
      if (cachedCategoriesRaw.length === 0) await refreshCategoryMap();
      const cats = cachedCategoriesRaw.filter(c => !c.parent_id);
      catsEl.innerHTML = (cats.length ? cats : [{ slug: '', label: '전체 상품', emoji: '🛍️' }]).map(c => `
        <a href="${c.slug ? '/category/' + encodeURIComponent(c.slug) : '/'}">
          <span class="wp-cat-ico">${getCategoryLineIcon(c)}</span>
          <span>${escapeHtml(c.label)}</span>
        </a>`).join('');
      catsEl.dataset.loaded = '1';
    }
    const userEl = document.getElementById('wp-drawer-user');
    if (userEl) {
      const session = await getSession();
      if (session && session.user) {
        userEl.innerHTML = `<span>${escapeHtml(session.user.email || '회원')}님 반가워요</span><a href="/mypage">마이페이지</a>`;
      }
    }
  }

  function openDrawer(focusCategories) {
    buildDrawer();
    document.getElementById('wp-drawer-backdrop').classList.add('open');
    const drawer = document.getElementById('wp-drawer');
    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
    document.body.classList.add('wp-drawer-lock');
    fillDrawer().then(() => {
      if (focusCategories) {
        const t = document.getElementById('wp-drawer-cats-title');
        if (t) t.scrollIntoView({ block: 'start' });
      }
    });
  }

  function closeDrawer() {
    const drawer = document.getElementById('wp-drawer');
    if (!drawer) return;
    drawer.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    document.getElementById('wp-drawer-backdrop').classList.remove('open');
    document.body.classList.remove('wp-drawer-lock');
  }

  // 헤더 로고 왼쪽에 ☰ 버튼을 붙인다 (홈처럼 이미 #wp-menu-btn을 가진 화면은 그대로 사용)
  function mountMenuButton() {
    let btn = document.getElementById('wp-menu-btn');
    if (!btn) {
      const logo = document.querySelector('header a.logo');
      if (!logo) return;
      btn = document.createElement('button');
      btn.type = 'button';
      btn.id = 'wp-menu-btn';
      btn.className = 'wp-icon-btn wp-menu-btn';
      btn.setAttribute('aria-label', '전체 메뉴 열기');
      btn.innerHTML = shellIcon('menu', 26);
      const wrap = document.createElement('span');
      wrap.style.cssText = 'display:inline-flex;align-items:center;gap:4px;';
      logo.parentNode.insertBefore(wrap, logo);
      wrap.appendChild(btn);
      wrap.appendChild(logo);
    }
    btn.addEventListener('click', () => openDrawer(false));
  }

  function getActiveTab() {
    const p = location.pathname.replace(/\/$/, '') || '/';
    if (p === '/' || p === '/index.html') return 'home';
    if (p.startsWith('/category') || p.startsWith('/search')) return 'category';
    if (p.startsWith('/live')) return 'live';
    if (p.startsWith('/mypage') && location.hash === '#wish') return 'wish';
    if (p.startsWith('/mypage') || p.startsWith('/my-info')) return 'my';
    return '';
  }

  function mountTabBar() {
    if (document.getElementById('wp-tabbar')) return;
    const active = getActiveTab();
    const nav = document.createElement('nav');
    nav.className = 'wp-tabbar';
    nav.id = 'wp-tabbar';
    nav.setAttribute('aria-label', '하단 메뉴');
    const cls = (key) => active === key ? ' class="active" aria-current="page"' : '';
    nav.innerHTML = `
      <a href="/"${cls('home')}>${shellIcon('home')}<span>홈</span></a>
      <button type="button" id="wp-tab-category"${cls('category')}>${shellIcon('grid')}<span>카테고리</span></button>
      <a href="/live"${cls('live')}>${shellIcon('live')}<span>LIVE</span></a>
      <a href="/mypage#wish"${cls('wish')}>${shellIcon('heart')}<span>찜</span></a>
      <a href="/mypage"${cls('my')}>${shellIcon('user')}<span>마이페이지</span></a>`;
    document.body.appendChild(nav);
    document.body.classList.add('wp-has-tabbar');
    nav.querySelector('#wp-tab-category').addEventListener('click', () => openDrawer(true));
    // 같은 /mypage 안에서 찜 ↔ 마이페이지를 오갈 때(해시만 바뀜) 활성 탭 표시를 갱신
    window.addEventListener('hashchange', () => {
      const now = getActiveTab();
      nav.querySelectorAll('a, button').forEach(el => el.classList.remove('active'));
      const map = { home: 0, category: 1, live: 2, wish: 3, my: 4 };
      if (now in map) nav.children[map[now]].classList.add('active');
    });
  }

  // 🔔 알림 배지 — 헤더에 .wp-noti-badge가 있는 화면에서만 읽지 않은 알림 수를 채운다
  async function refreshNotificationBadge() {
    const badges = document.querySelectorAll('.wp-noti-badge');
    if (badges.length === 0) return;
    let count = 0;
    try {
      const token = await getAccessToken();
      if (token) {
        const res = await fetch(API_BASE + '/api/me/notifications', { headers: { Authorization: 'Bearer ' + token } });
        const json = await res.json();
        if (res.ok && json.success) count = Number(json.unread_count) || 0;
      }
    } catch (e) { /* 실패 시 배지 숨김 */ }
    badges.forEach(b => { b.textContent = count > 99 ? '99+' : String(count); b.dataset.count = String(count); });
  }

  function mountAppShell() {
    ensureShellStyle();
    applyBrandLogo();
    if (!isShellPage()) return;
    buildDrawer();
    mountMenuButton();
    mountTabBar();
    refreshNotificationBadge();
  }

  global.WithPlus = {
    API_BASE,
    CATEGORY_MAP,
    CATEGORY_EMOJI,
    getOrgTypeName,
    getPoweredByTagline,
    getOfferingCtaLabel,
    refreshCategoryMap,
    getCategoryMapCached,
    getCategoryEmoji,
    getCategoriesRawCached,
    getPreferredCommunitySlug,
    withCommunityParam,
    renderCategoryNav,
    initCategoryNav,
    formatPrice,
    getShippingBadgeLabel,
    fetchJSON,
    refreshMileageRates,
    getMileageRatesCached,
    refreshPageTemplates,
    getPageTemplatesCached,
    formatPercent,
    renderProductCard,
    escapeHtml,
    safeUrlAttr,
    timeAgo,
    attachProductCardInteractions,
    syncWishlistHearts,
    mountCountControl,
    recordRecentlyViewed,
    getRecentlyViewed,
    recordInteraction,
    getClient,
    getSession,
    getAccessToken,
    signOut,
    getCart,
    addToCart,
    setCartQty,
    removeFromCart,
    clearCart,
    getCartCount,
    refreshCartBadge,
    initHeader,
    initSearchBox,
    applyPendingReferralIfAny,
    clearPreferredCommunity,
    renderCommunityBanner,
    registerPwa,
    shellIcon,
    getCategoryLineIcon,
    renderStars,
    renderRatingSummary,
    renderReviewItem,
    formatSatisfied,
    openDrawer,
    closeDrawer,
    refreshNotificationBadge
  };

  // 어느 페이지든 이 스크립트만 불러오면 자동으로 배너 여부를 판단하도록 한다
  // (index/category/search 처럼 initCategoryNav를 쓰는 페이지뿐 아니라 상품상세·마이페이지 등에서도
  //  "특정 매장 보는 중" 상태를 알아채고 빠져나갈 수 있어야 하기 때문에, 카테고리 렌더링과는 별도로 항상 실행한다)
  // ============================================
  // WITH+ → GMWOS(의료복지 플랫폼) 역방향 SSO 링크 주입
  // 어느 쪽에서 가입/로그인하든 다른 쪽도 재로그인 없이 이용(세션 핸드오프).
  // 헤더(.header-top-right)에 "의료복지 플랫폼" 링크를 넣고, 클릭 시 현재 세션을
  // GMWOS /sso 로 URL 해시로 전달한다.
  // ============================================
  const GMWOS_BASE = 'https://global-medical-welfare-os.vercel.app';
  function injectGmwosLink() {
    try {
      const bar = document.querySelector('.header-top-right');
      if (!bar || document.getElementById('wp-gmwos-link')) return;
      const a = document.createElement('a');
      a.id = 'wp-gmwos-link';
      a.href = GMWOS_BASE + '/health';
      a.textContent = '🏥 의료복지 플랫폼';
      a.style.cssText = 'font-weight:700;color:#0F766E;';
      a.addEventListener('click', async (e) => {
        e.preventDefault();
        const win = window.open('', '_blank'); // 제스처 내 새 탭 선점(팝업차단 회피)
        let url = GMWOS_BASE + '/health';
        try {
          const session = await getSession();
          if (session && session.access_token && session.refresh_token) {
            url = GMWOS_BASE + '/sso#wp_sso=1&at=' + encodeURIComponent(session.access_token) +
                  '&rt=' + encodeURIComponent(session.refresh_token) + '&next=' + encodeURIComponent('/health');
          }
        } catch (err) { /* 세션 없으면 일반 진입 */ }
        if (win) win.location.href = url; else window.location.href = url;
      });
      bar.insertBefore(a, bar.firstChild);
    } catch (e) { /* 헤더 없으면 조용히 무시 */ }
  }

  // GMWOS에서 넘어온 SSO 세션이 있으면 먼저 이식(성공 시 재로딩되어 로그인 상태로 시작)
  consumeSsoHandoff();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectGmwosLink);
  } else {
    injectGmwosLink();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renderCommunityBanner);
  } else {
    renderCommunityBanner();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountAppShell);
  } else {
    mountAppShell();
  }

  registerPwa();
})(window);
