/**
 * WITH+ 채널별 자동 가격 (분양몰 = 적립율 차이만큼 가감 / 도매 = 기본가에서 공통 도매 할인율 차감)
 *
 * 이 파일 하나를 서버(server.js - require)와 브라우저(<script src="/withplus-pricing.js">)가 함께 쓴다.
 * 그래서 "화면에 보이는 가격"과 "실제로 결제되는 가격"의 계산식·반올림이 글자 그대로 같다.
 * (브라우저 쪽 계산은 표시용일 뿐이고, 결제 금액은 항상 서버가 이 함수로 다시 계산한다)
 *
 * 가격 컨텍스트(ctx) 형식 - 서버 resolvePriceContext() 가 만들어 GET /api/me/price-context 로 내려준다
 *   { mode: 'default' }
 *   { mode: 'community', bp: 200, rounding_unit: 10, community: { id, name, slug }, label: '선훈교회 공동체가' }
 *       bp = 기본가 대비 가감률(0.01% 단위 정수, 200 = +2%) - 정수로 계산해 부동소수점 오차로 서버/화면이 1원이라도 어긋나지 않게 한다
 *   { mode: 'wholesale', rounding_unit: 10, wholesale_bp: 2000, category_bp: { food: 1500 }, product_bp: { <product_id>: 2500 }, overrides: { <product_id>: 8000 }, label: '도매가' }
 *       wholesale_bp = 공통 도매 할인율(2000 = 20%), category_bp = 카테고리별 할인율, product_bp = 상품별 도매 할인율,
 *       overrides = 상품별 도매채널가(고정 금액, 최우선)
 *       우선순위: overrides > product_bp > category_bp > wholesale_bp
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.WithPlusPricing = api;
})(typeof self !== 'undefined' ? self : this, function () {
  const DEFAULT_ROUNDING_UNIT = 10;

  function num(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  }

  // 할인가가 있으면 할인가, 없으면 판매가 (서버 effectivePriceOf 와 동일 규칙)
  function effectiveUnitPrice(p) {
    const price = num(p && p.price);
    const dp = p && p.discount_price !== null && p.discount_price !== undefined && p.discount_price !== '' ? Number(p.discount_price) : null;
    return (dp !== null && Number.isFinite(dp) && dp > 0 && dp < price) ? dp : price;
  }

  // amount * (1 + bp/10000) 를 unit 단위로 반올림 - 정수 연산(amount*(10000+bp))으로 계산
  function applyBp(amount, bp, unit) {
    const a = num(amount);
    const b = Math.round(num(bp));
    if (!b || a <= 0) return a;
    const u = num(unit) > 0 ? num(unit) : DEFAULT_ROUNDING_UNIT;
    const scaled = Math.round(a * (10000 + b)); // 0.0001원 단위 정수
    return Math.max(0, Math.round(scaled / (10000 * u)) * u);
  }

  // 공동체 가감률(bp): (공동체 총 적립율 - 기본 총 적립율), 상한 ±capPercent%
  // rates 는 소수(0.03 = 3%) - 서버 getEffectiveMileageRates / getMileageRates 와 같은 단위
  function communityBp(baseTotalRate, communityTotalRate, capPercent) {
    let bp = Math.round((num(communityTotalRate) - num(baseTotalRate)) * 10000);
    const cap = Math.round(Math.abs(num(capPercent)) * 100);
    if (cap > 0) bp = Math.max(-cap, Math.min(cap, bp));
    else bp = 0; // 상한 0% = 사실상 조정 안 함
    return bp;
  }

  function wholesaleBpFor(product, ctx) {
    const pid = product && product.id;
    if (ctx.product_bp && pid !== undefined && pid !== null && ctx.product_bp[pid] !== undefined && ctx.product_bp[pid] !== null) return num(ctx.product_bp[pid]);
    const cat = product && product.category;
    if (ctx.category_bp && cat !== undefined && cat !== null && ctx.category_bp[cat] !== undefined) return num(ctx.category_bp[cat]);
    return num(ctx.wholesale_bp);
  }

  function hasOverride(product, ctx) {
    return !!(ctx && ctx.overrides && product && ctx.overrides[product.id] !== undefined && ctx.overrides[product.id] !== null);
  }

  // 이 상품 1개 단가 (옵션 가격조정 제외) - 서버 주문 생성과 화면 표시 모두 이 값을 쓴다
  // TODO(타임딜): 진행 중인 타임딜 가격(getFlashDealPrice)이 있으면 그 고정가를 그대로 쓰고 채널 가감을 하지 않는다 -
  //   타임딜 브랜치가 합쳐지면 호출부(서버 computeChannelUnitPrice)에서 타임딜 가격을 먼저 확인하고 이 함수는 건너뛴다.
  function unitPrice(product, ctx) {
    const base = effectiveUnitPrice(product);
    if (!ctx || !ctx.mode || ctx.mode === 'default') return base;
    if (ctx.mode === 'wholesale') {
      if (hasOverride(product, ctx)) return num(ctx.overrides[product.id]);
      return applyBp(base, -wholesaleBpFor(product, ctx), ctx.rounding_unit);
    }
    if (ctx.mode === 'community') return applyBp(base, ctx.bp, ctx.rounding_unit);
    return base;
  }

  // 수량별 묶음 총액 - 공동체가는 묶음 총액도 같은 비율로 가감, 도매는 묶음가 미적용(null)
  function tierTotal(tierPrice, ctx) {
    if (!ctx || !ctx.mode || ctx.mode === 'default') return num(tierPrice);
    if (ctx.mode === 'wholesale') return null;
    if (ctx.mode === 'community') return applyBp(tierPrice, ctx.bp, ctx.rounding_unit);
    return num(tierPrice);
  }

  // 화면 표시용: 상품 객체의 price / discount_price / quantity_price_options 를 컨텍스트 가격으로 바꾼 사본
  // (원래 값은 base_price / base_discount_price 로 보존, 이미 적용된 객체는 다시 적용하지 않는다)
  function adjustProduct(product, ctx) {
    if (!product || typeof product !== 'object' || product.price === undefined) return product;
    if (product._price_ctx_applied) return product;
    if (!ctx || !ctx.mode || ctx.mode === 'default') return product;
    const out = Object.assign({}, product, {
      base_price: product.price,
      base_discount_price: product.discount_price,
      _price_ctx_applied: ctx.mode,
      price_label: ctx.label || ''
    });
    if (ctx.mode === 'community') {
      if (!ctx.bp) { out.price_label = ''; return out; }
      out.price = applyBp(product.price, ctx.bp, ctx.rounding_unit);
      if (product.discount_price !== null && product.discount_price !== undefined && product.discount_price !== '') {
        out.discount_price = applyBp(product.discount_price, ctx.bp, ctx.rounding_unit);
      }
      if (Array.isArray(product.quantity_price_options)) {
        out.quantity_price_options = product.quantity_price_options.map(o => Object.assign({}, o, { price: applyBp(o.price, ctx.bp, ctx.rounding_unit) }));
      }
      return out;
    }
    if (ctx.mode === 'wholesale') {
      // 도매가는 "할인가" 자리에 넣어 정가(기본가) 대비 할인율이 함께 보이게 한다. 도매에는 묶음가 미적용.
      const ws = unitPrice(product, ctx);
      const listPrice = num(product.price);
      out.quantity_price_options = null;
      if (ws < listPrice) { out.price = listPrice; out.discount_price = ws; }
      else { out.price = ws; out.discount_price = null; }
      return out;
    }
    return product;
  }

  // 도매가가 어디서 정해졌는지: product(상품별 도매채널가) / product_rate(상품별 할인율) / category / default
  function wholesaleSource(product, ctx) {
    if (hasOverride(product, ctx)) return 'product';
    const pid = product && product.id;
    if (ctx && ctx.product_bp && pid !== undefined && pid !== null && ctx.product_bp[pid] !== undefined && ctx.product_bp[pid] !== null) return 'product_rate';
    const cat = product && product.category;
    if (ctx && ctx.category_bp && cat !== undefined && cat !== null && ctx.category_bp[cat] !== undefined) return 'category';
    return 'default';
  }

  return { DEFAULT_ROUNDING_UNIT, effectiveUnitPrice, applyBp, communityBp, unitPrice, tierTotal, adjustProduct, wholesaleBpFor, wholesaleSource };
});
