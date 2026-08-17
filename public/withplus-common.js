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
        gridEl.innerHTML = cats.map(c => `
          <a href="/category/${c.slug}" class="category-item">
              <div class="category-icon">${c.emoji}</div>
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
    document.querySelectorAll('.cart-badge').forEach(el => {
      el.textContent = getCartCount();
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
        <div class="product-image" ${imageUrl ? `style="background-image:url('${imageUrl}');background-size:cover;background-position:center;"` : ''}>
            <div class="mileage-badge">
                <span class="individual">💰 ${formatPercent(rates.personalPercent)}%</span>
                <span class="bonus">+커뮤니티 ${formatPercent(rates.communityPercent)}%</span>
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
            <div class="product-meta">
                ⭐ ${rating} (${reviewCount}개 리뷰) | ${outOfStock ? '품절' : '재고 ' + product.stock + '개'} | 배송비 무료
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

  global.WithPlus = {
    API_BASE,
    CATEGORY_MAP,
    CATEGORY_EMOJI,
    refreshCategoryMap,
    getCategoryMapCached,
    getCategoryEmoji,
    getCategoriesRawCached,
    getPreferredCommunitySlug,
    withCommunityParam,
    renderCategoryNav,
    initCategoryNav,
    formatPrice,
    fetchJSON,
    refreshMileageRates,
    getMileageRatesCached,
    refreshPageTemplates,
    getPageTemplatesCached,
    formatPercent,
    renderProductCard,
    escapeHtml,
    timeAgo,
    attachProductCardInteractions,
    syncWishlistHearts,
    recordRecentlyViewed,
    getRecentlyViewed,
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
    registerPwa
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

  registerPwa();
})(window);
