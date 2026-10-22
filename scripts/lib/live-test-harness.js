// 📺 WITH+ 라이브 테스트 공용 하네스 — 테스트가 만든 행을 추적했다가 끝나면 그것만 지운다.
// - LIVE+에서 옮겨온 라이브 테스트들은 원래 정리(cleanup)가 없어 운영 DB에 테스트 행이 남았다(channels_live 등).
//   WITH+ 쪽은 이 하네스로 "이 실행이 만든 것만" 정확히 지운다(시간 범위·이름 패턴으로 지우지 않음).
// - 추적 대상: admin.auth.admin.createUser 로 만든 회원, admin.from(t).insert(...).select() 로 만든 행(id),
//   테스트가 API로 만든 채널·세션·주문·쿠폰(fetch 응답의 data.id).
// - 실행 전 상태를 저장해 두었다가 되돌리는 것: WITH+ 전용 OmniCast 플랫폼 설정(omnicast_platform_configs_with),
//   WITH+ 라이브 설정 키(platform_settings: live_*_with).
// - 라이브 데이터는 WITH+ 전용(*_with) 테이블만 다룬다. LIVE+의 *_live 테이블은 절대 건드리지 않는다.
'use strict';

const LIVE_SETTING_KEYS_WITH = ['live_cashback_rate_with', 'live_share_coupon_settings_with', 'channel_tier_thresholds_with', 'live_reminder_settings_with', 'live_gift_catalog_with'];

function install(admin, { liveSuffix = '_with' } = {}) {
  if (liveSuffix !== '_with') throw new Error('이 하네스는 WITH+(_with) 라이브 테이블 전용입니다');
  const T = base => base + liveSuffix;
  const tracked = { users: new Set(), products: new Set(), channels: new Set(), sessions: new Set(), orders: new Set(), coupons: new Set(), creators: new Set(), rows: [] };
  let snapshot = null;

  // 1) 회원 생성 추적
  const authAdmin = admin.auth.admin;
  const origCreateUser = authAdmin.createUser.bind(authAdmin);
  authAdmin.createUser = async (...args) => {
    const r = await origCreateUser(...args);
    if (r && r.data && r.data.user) tracked.users.add(r.data.user.id);
    return r;
  };

  // 2) 서비스키로 직접 insert 한 행 추적 (.select() 로 id를 돌려받는 경우)
  const origFrom = admin.from.bind(admin);
  admin.from = (table) => {
    const qb = origFrom(table);
    const origInsert = qb.insert.bind(qb);
    qb.insert = (...args) => {
      const b = origInsert(...args);
      const origThen = b.then.bind(b);
      b.then = (onF, onR) => origThen(res => {
        try {
          const rows = res && res.data ? (Array.isArray(res.data) ? res.data : [res.data]) : [];
          rows.forEach(row => {
            if (!row || !row.id) return;
            if (table === 'products_with') tracked.products.add(row.id);
            else if (table === 'coupons') tracked.coupons.add(row.id);
            else if (table === T('channels')) tracked.channels.add(row.id);
            else if (table === T('live_sessions')) tracked.sessions.add(row.id);
            else if (table === 'orders_with') tracked.orders.add(row.id);
            else tracked.rows.push({ table, id: row.id });
          });
        } catch (e) { /* 추적 실패는 테스트 결과에 영향 주지 않음 */ }
        return res;
      }).then(onF, onR);
      return b;
    };
    return qb;
  };

  // 3) API로 만든 채널·세션·주문·쿠폰 추적 (응답 data.id)
  const origFetch = global.fetch;
  global.fetch = async (url, opts = {}) => {
    const res = await origFetch(url, opts);
    try {
      const method = String((opts && opts.method) || 'GET').toUpperCase();
      const u = String(url);
      if (method === 'POST' && res.ok) {
        const json = await res.clone().json().catch(() => null);
        const d = json && json.data;
        const id = d && d.id;
        if (id) {
          if (/\/api\/admin\/live\/channels(\?|$)/.test(u)) tracked.channels.add(id);
          else if (/\/api\/admin\/live\/channels\/[^/]+\/sessions(\?|$)/.test(u)) tracked.sessions.add(id);
          else if (/\/api\/orders(\?|$)/.test(u)) tracked.orders.add(id);
          else if (/\/api\/admin\/coupons(\?|$)/.test(u) || /\/coupon-drops(\?|$)/.test(u)) tracked.coupons.add(id);
          else if (/\/api\/admin\/creators(\?|$)/.test(u)) tracked.creators.add(id);
        }
      }
    } catch (e) { /* 추적 실패는 무시 */ }
    return res;
  };

  async function takeSnapshot() {
    const [{ data: omni }, { data: settings }] = await Promise.all([
      origFrom(T('omnicast_platform_configs')).select('*'),
      origFrom('platform_settings').select('*').in('key', LIVE_SETTING_KEYS_WITH)
    ]);
    snapshot = { omni: omni || [], settings: settings || [] };
  }

  async function del(table, col, ids) {
    const list = [...ids].filter(Boolean);
    for (let i = 0; i < list.length; i += 100) {
      const { error } = await origFrom(table).delete().in(col, list.slice(i, i + 100));
      if (error && !/does not exist|schema cache/i.test(error.message)) console.error(`  정리 경고 ${table}.${col}:`, error.message);
    }
  }
  async function ids(table, col, values, pick = 'id') {
    const list = [...values].filter(Boolean);
    if (!list.length) return [];
    const { data } = await origFrom(table).select(pick).in(col, list);
    return (data || []).map(r => r[pick]);
  }

  async function cleanup() {
    const users = [...tracked.users];
    // 사용자가 만든 채널(관리자 API 외 경로)·주문도 함께 찾는다
    (await ids(T('channels'), 'owner_user_id', users)).forEach(id => tracked.channels.add(id));
    (await ids('orders_with', 'user_id', users)).forEach(id => tracked.orders.add(id));
    (await ids(T('live_sessions'), 'channel_id', tracked.channels)).forEach(id => tracked.sessions.add(id));
    (await ids('coupons', 'live_session_id', tracked.sessions)).forEach(id => tracked.coupons.add(id));
    (await ids('coupons', 'created_by', users)).forEach(id => tracked.coupons.add(id));
    // 테스트 회원에게만 발급된 쿠폰(경매 낙찰·바이럴 공유쿠폰·퀴즈 보상 등 target_user_ids 지정)
    if (users.length) {
      const { data: targeted } = await origFrom('coupons').select('id').overlaps('target_user_ids', users);
      (targeted || []).forEach(r => tracked.coupons.add(r.id));
    }
    (await ids(T('live_creators'), 'created_by', users)).forEach(id => tracked.creators.add(id));
    const sessions = [...tracked.sessions];
    const orders = [...tracked.orders];

    // FK 순서대로 (CASCADE가 없는 것부터)
    const invIds = await ids(T('live_session_inventory'), 'live_session_id', sessions);
    await del(T('live_session_inventory_log'), 'inventory_id', invIds);
    await del(T('live_session_inventory_log'), 'actor_user_id', users);
    await del(T('live_session_reservations'), 'live_session_id', sessions);
    await del(T('live_session_reservations'), 'order_id', orders);
    await del(T('live_session_reservations'), 'user_id', users);
    const quizIds = await ids(T('live_quizzes'), 'live_session_id', sessions);
    await del(T('live_quiz_winners'), 'quiz_id', quizIds);
    await del(T('live_quiz_winners'), 'user_id', users);
    await del(T('live_quizzes'), 'live_session_id', sessions);
    await del(T('live_flash_sales'), 'live_session_id', sessions);
    await del(T('live_share_redemptions'), 'order_id', orders);
    await del(T('live_creator_settlements'), 'creator_id', tracked.creators);
    await del(T('live_creator_referral_codes'), 'creator_id', tracked.creators);
    await del('coupon_redemptions', 'order_id', orders);
    await del('coupon_redemptions', 'coupon_id', tracked.coupons);
    await del('orders_with', 'id', orders);
    await del(T('live_creators'), 'id', tracked.creators);
    await del('coupons', 'id', tracked.coupons);
    await del(T('omnicast_pending_facebook_selections'), 'channel_id', tracked.channels);
    await del(T('channels'), 'id', tracked.channels); // 세션·채팅·멤버·상품연결·원장 등은 CASCADE
    // 직접 insert 해 추적한 기타 행
    for (const r of tracked.rows) await origFrom(r.table).delete().eq('id', r.id).then(null, () => {});
    // 상품 (재고 원장·가격 이력 등 딸린 행 먼저)
    const products = [...tracked.products];
    for (const t of ['stock_adjustments_with', 'product_price_history_with', 'product_channel_prices_with', 'product_channel_stock_with', 'product_variants_with', 'activity_events_with', 'agv_tasks_with', 'product_interactions_with']) await del(t, 'product_id', products);
    await del('products_with', 'id', products);
    // 회원
    for (const t of ['mileage_adjustments_with', 'notifications_with', 'activity_events_with']) await del(t, 'user_id', users);
    await del('admin_audit_logs_with', 'admin_id', users);
    await del('cost_access_audit_log_with', 'profile_id', users);
    for (const uid of users) {
      await origFrom('profiles').delete().eq('id', uid).then(null, () => {});
      // Supabase Auth가 가끔 Gateway Timeout을 돌려주므로 몇 번 다시 시도한다
      for (let attempt = 0; attempt < 4; attempt++) {
        const r = await authAdmin.deleteUser(uid).catch(err => ({ error: err }));
        if (!r || !r.error || /not.?found/i.test(String(r.error.message || ''))) break;
        if (attempt === 3) console.error(`  정리 경고: 테스트 회원 ${uid} 삭제 실패 - ${r.error.message}`);
        await new Promise(res => setTimeout(res, 1500 * (attempt + 1)));
      }
    }
    // 설정 되돌리기
    if (snapshot) {
      for (const row of snapshot.omni) await origFrom(T('omnicast_platform_configs')).update(row).eq('provider_key', row.provider_key);
      const keep = new Set(snapshot.settings.map(s => s.key));
      for (const s of snapshot.settings) await origFrom('platform_settings').update({ value: s.value }).eq('key', s.key);
      const toDrop = LIVE_SETTING_KEYS_WITH.filter(k => !keep.has(k));
      if (toDrop.length) await origFrom('platform_settings').delete().in('key', toDrop);
    }
    global.fetch = origFetch;
    console.log(`🧹 정리 완료: 회원 ${users.length}, 채널 ${tracked.channels.size}, 세션 ${sessions.length}, 주문 ${orders.length}, 쿠폰 ${tracked.coupons.size}, 상품 ${products.length}`);
  }

  return { tracked, takeSnapshot, cleanup };
}

// 테스트 main()을 감싸 실행 → 성공/실패와 무관하게 정리 → 종료코드 유지
async function runWithCleanup(admin, main) {
  const H = install(admin);
  await H.takeSnapshot();
  let code = 1;
  const origExit = process.exit;
  try {
    // 테스트 본문이 process.exit(...)를 부르면 정리 후에 종료하도록 가로챈다
    code = await new Promise((resolve, reject) => {
      process.exit = (c) => resolve(typeof c === 'number' ? c : 0);
      Promise.resolve().then(main).then(() => resolve(0), reject);
    });
  } catch (err) {
    console.error('테스트 실행 중 오류:', err);
    code = 1;
  } finally {
    process.exit = origExit;
    try { await H.cleanup(); } catch (e) { console.error('정리 중 오류:', e.message); }
  }
  process.exit(code);
}

module.exports = { install, runWithCleanup };
