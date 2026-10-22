// WITH+ 라이브 참여·매출 기능 통합 테스트 (LIVE+에서 이식한 기능을 WITH+ 전용 *_with 테이블로 검증)
// - 라이브 채널가(product_channel_prices_with channel='live') · 라이브 타임세일가가 주문 가격 규칙(서버 재계산)에 반영되는지
// - 세션 한정재고(직접 주문 강제 + 예약→주문 확정) · 주문의 WITH+ 라이브 출처 컬럼(live_channel_id_with/live_session_id_with)
// - 선착순 쿠폰함(다운로드·선착순 소진·미다운로드 사용 거부) · 실시간 퀴즈(정답자 선착순 쿠폰, 본인 전용) · 경매(입찰·소프트클로즈·낙찰 쿠폰)
// - 가상 선물(마일리지 차감) · 바이럴 공유쿠폰(공유자·구매자 양쪽) · 라이브 구매 캐시백
// - 다른 사이트(LIVE+) 라이브 쿠폰·세션은 WITH+에서 쓸 수 없음
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-engagement-with.js
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
const API = process.env.API || process.env.TEST_API || 'http://localhost:3140';

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌', msg); }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function loginAs(email, password) {
  const res = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', apikey: anonKey },
    body: JSON.stringify({ email, password })
  });
  return (await res.json()).access_token;
}

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const mkUser = async (tag, role) => {
    const email = `test-lew-${tag}-${ts}@withplus-test.local`;
    const { data, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
    if (error) throw error;
    await admin.from('profiles').upsert([{ id: data.user.id, email, full_name: `라이브테스트${tag}`, role, member_type: 'general' }]);
    return { id: data.user.id, token: await loginAs(email, password) };
  };
  const adminU = await mkUser('admin', 'admin');
  const A = await mkUser('a', 'member');
  const B = await mkUser('b', 'member');
  const C = await mkUser('c', 'member');
  assert(adminU.token && A.token && B.token && C.token, '테스트 관리자/회원 3명 로그인');

  const api = async (path, token, method = 'GET', body) => {
    const res = await fetch(`${API}${path}`, { method, headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: `Bearer ${token}` } : {}), body: body !== undefined ? JSON.stringify(body) : undefined });
    const json = await res.json().catch(() => ({}));
    return { status: res.status, ok: res.ok, json };
  };

  // ---------- 상품 2개 (공유 products_with) ----------
  const { data: p1, error: p1Err } = await admin.from('products_with').insert([{ name: `라이브참여테스트A ${ts}`, slug: `lew-a-${ts}`, description: '테스트', price: 20000, stock: 100, status: 'active', category: '테스트' }]).select().single();
  if (p1Err) throw p1Err;
  const { data: p2 } = await admin.from('products_with').insert([{ name: `라이브참여테스트B ${ts}`, slug: `lew-b-${ts}`, description: '테스트', price: 10000, stock: 100, status: 'active', category: '테스트' }]).select().single();

  // ---------- 채널·세션 ----------
  const slug = `lew-${ts}`;
  const ch = await api('/api/admin/live/channels', adminU.token, 'POST', { slug, name: '참여테스트 채널', channel_type: 'brand' });
  assert(ch.status === 201, `채널 생성 (실제: ${ch.status})`);
  const channelId = ch.json.data.id;
  await api(`/api/admin/live/channels/${channelId}`, adminU.token, 'PATCH', { status: 'active' });
  await api(`/api/admin/live/channels/${channelId}/products`, adminU.token, 'POST', { product_id: p1.id, is_featured: true });
  await api(`/api/admin/live/channels/${channelId}/products`, adminU.token, 'POST', { product_id: p2.id });
  const ses = await api(`/api/admin/live/channels/${channelId}/sessions`, adminU.token, 'POST', { title: '참여테스트 방송' });
  assert(ses.status === 201, `세션 생성 (실제: ${ses.status})`);
  const sessionId = ses.json.data.id;
  const inv = await api(`/api/admin/live/channels/${channelId}/sessions/${sessionId}/inventory`, adminU.token, 'POST', { product_id: p1.id, allocated_qty: 10, safety_stock: 0 });
  assert(inv.ok, `세션 한정재고 10개 배정 (실제: ${inv.status} ${inv.json.message || ''})`);
  const goLive = await api(`/api/admin/live/channels/${channelId}/sessions/${sessionId}`, adminU.token, 'PATCH', { status: 'live' });
  assert(goLive.ok && goLive.json.data?.status === 'live', `방송 시작 (실제: ${goLive.status})`);

  // ---------- 1) 라이브 채널가 ----------
  await admin.from('product_channel_prices_with').insert([{ product_id: p1.id, channel: 'live', price: 18000, is_manual_override: true }]);
  const prods = await api(`/api/live/channels/${slug}/products`);
  const lp1 = (prods.json.data || []).find(p => p.id === p1.id);
  assert(lp1 && Number(lp1.live_price) === 18000 && lp1.cost_price === undefined, `채널 상품 목록 라이브가 18,000원·원가 비노출 (실제: ${lp1 && lp1.live_price})`);
  const o1 = await api('/api/orders', A.token, 'POST', { items: [{ product_id: p1.id, quantity: 1 }], channel_id: channelId, live_session_id: sessionId, live_attribution: { source_platform: 'test' } });
  const it1 = o1.json.data?.items?.[0];
  assert(o1.status === 201 && Number(it1?.price) === 18000 && it1?.price_channel === 'live', `라이브 주문 단가 = 라이브 채널가 18,000원 (실제: ${o1.status} ${it1?.price} ${it1?.price_channel} ${o1.json.message || ''})`);
  assert(o1.json.data?.live_channel_id_with === channelId && o1.json.data?.live_session_id_with === sessionId && o1.json.data?.channel_id === null,
    `주문에 WITH+ 라이브 출처 컬럼 기록, LIVE+ 컬럼(channel_id)은 비움 (실제: ${o1.json.data?.live_channel_id_with}, ${o1.json.data?.channel_id})`);
  const o1plain = await api('/api/orders', A.token, 'POST', { items: [{ product_id: p1.id, quantity: 1 }] });
  assert(o1plain.status === 201 && Number(o1plain.json.data?.items?.[0]?.price) === 20000, `일반 주문은 라이브가 미적용 20,000원 (실제: ${o1plain.json.data?.items?.[0]?.price})`);
  const { data: invRow1 } = await admin.from('live_session_inventory_with').select('sold_qty, reserved_qty').eq('live_session_id', sessionId).eq('product_id', p1.id).single();
  assert(invRow1.sold_qty === 1 && invRow1.reserved_qty === 0, `예약 없이 직접 주문해도 세션 한정재고 1개 확정 (실제: sold=${invRow1.sold_qty}, reserved=${invRow1.reserved_qty})`);

  // ---------- 2) 라이브 타임세일 ----------
  const fs1 = await api(`/api/admin/live/channels/${channelId}/sessions/${sessionId}/flash-sales`, adminU.token, 'POST', { product_id: p1.id, discount_price: 15000, duration_minutes: 5 });
  assert(fs1.status === 201, `타임세일 시작 15,000원 (실제: ${fs1.status} ${fs1.json.message || ''})`);
  const fsList = await api(`/api/live/channels/${slug}/sessions/${sessionId}/flash-sales`);
  assert((fsList.json.data || []).some(f => f.product_id === p1.id && Number(f.discount_price) === 15000), '시청 화면 타임세일 목록 노출');
  const o2 = await api('/api/orders', B.token, 'POST', { items: [{ product_id: p1.id, quantity: 1 }], channel_id: channelId, live_session_id: sessionId });
  const it2 = o2.json.data?.items?.[0];
  assert(o2.status === 201 && Number(it2?.price) === 15000 && it2?.price_channel === 'live_flash_sale', `타임세일 중 주문 15,000원 (실제: ${it2?.price} ${it2?.price_channel})`);
  await api(`/api/admin/live/channels/${channelId}/sessions/${sessionId}/flash-sales/${fs1.json.data.id}/cancel`, adminU.token, 'PATCH');
  const o3 = await api('/api/orders', B.token, 'POST', { items: [{ product_id: p1.id, quantity: 1 }], channel_id: channelId, live_session_id: sessionId });
  assert(o3.status === 201 && Number(o3.json.data?.items?.[0]?.price) === 18000, `타임세일 취소 뒤엔 다시 라이브가 18,000원 (실제: ${o3.json.data?.items?.[0]?.price})`);

  // ---------- 3) 세션 한정재고 초과 판매 차단 ----------
  const over = await api('/api/orders', C.token, 'POST', { items: [{ product_id: p1.id, quantity: 8 }], channel_id: channelId, live_session_id: sessionId });
  assert(over.status === 409, `남은 세션 한정재고(7개)를 넘는 주문 8개는 409 (실제: ${over.status} ${over.json.message || ''})`);

  // ---------- 4) 선착순 쿠폰함 ----------
  const drop = await api(`/api/admin/live/channels/${channelId}/sessions/${sessionId}/coupon-drops`, adminU.token, 'POST', { label: '선착순 10%', discount_type: 'percent', discount_value: 10, claim_limit: 1, valid_minutes: 30 });
  assert(drop.status === 201 && drop.json.data?.claim_limit === 1, `선착순 쿠폰 1장 발급 (실제: ${drop.status} ${drop.json.message || ''})`);
  const dropId = drop.json.data.id, dropCode = drop.json.data.code;
  const dropsPublic = await api(`/api/live/channels/${slug}/sessions/${sessionId}/coupon-drops`);
  assert((dropsPublic.json.data || []).some(d => d.id === dropId), '시청 화면 쿠폰함에 노출');
  const claimA = await api(`/api/live/coupon-drops/${dropId}/claim`, A.token, 'POST');
  const claimB = await api(`/api/live/coupon-drops/${dropId}/claim`, B.token, 'POST');
  assert(claimA.status === 201 && claimB.status === 409, `A 다운로드 성공, B는 선착순 소진 409 (실제: ${claimA.status}/${claimB.status})`);
  const useA = await api('/api/orders', A.token, 'POST', { items: [{ product_id: p2.id, quantity: 1 }], channel_id: channelId, live_session_id: sessionId, coupon_code: dropCode });
  assert(useA.status === 201 && Number(useA.json.data?.discount_amount) === 1000, `다운로드한 A는 방송 중 쿠폰 사용 (10% = 1,000원) (실제: ${useA.status} ${useA.json.data?.discount_amount} ${useA.json.message || ''})`);
  const useB = await api('/api/orders', B.token, 'POST', { items: [{ product_id: p2.id, quantity: 1 }], coupon_code: dropCode });
  assert(useB.status === 400, `다운로드 안 한 B는 사용 불가 400 (실제: ${useB.status} ${useB.json.message || ''})`);

  // ---------- 5) 실시간 퀴즈 ----------
  const quiz = await api(`/api/admin/live/channels/${channelId}/sessions/${sessionId}/quizzes`, adminU.token, 'POST', { question: '위드플러스 색은?', correct_answer: '핑크', winner_limit: 1, reward_discount_type: 'fixed', reward_discount_value: 2000 });
  assert(quiz.status === 201, `퀴즈 시작 (실제: ${quiz.status})`);
  const active = await api(`/api/live/channels/${slug}/sessions/${sessionId}/quiz/active`);
  assert(active.json.data && active.json.data.correct_answer === undefined, '공개 퀴즈 조회에 정답 비노출');
  const wrong = await api(`/api/live/channels/${slug}/sessions/${sessionId}/chat`, C.token, 'POST', { message: '파랑' });
  assert(wrong.status === 201 && !wrong.json.data?.quiz_result, '오답은 일반 채팅으로 처리');
  // 동시 정답 2명(정원 1명) - 원자적 RPC(award_quiz_win_with)로 1명만 당첨
  const [ansA, ansB] = await Promise.all([
    api(`/api/live/channels/${slug}/sessions/${sessionId}/chat`, A.token, 'POST', { message: ' 핑 크 ' }),
    api(`/api/live/channels/${slug}/sessions/${sessionId}/chat`, B.token, 'POST', { message: '핑크' })
  ]);
  const winners = [ansA, ansB].filter(r => r.json.data?.quiz_result?.correct);
  assert(winners.length === 1, `정원 1명 퀴즈에 동시 정답 2명 → 당첨 1명 (실제: ${winners.length})`);
  const winnerCode = winners[0]?.json.data.quiz_result.coupon_code;
  const { data: quizCoupon } = await admin.from('coupons').select('target_user_ids, live_session_id, source').eq('code', winnerCode).maybeSingle();
  const winnerUser = ansA.json.data?.quiz_result?.correct ? A : B;
  assert(quizCoupon && quizCoupon.live_session_id === sessionId && Array.isArray(quizCoupon.target_user_ids) && quizCoupon.target_user_ids[0] === winnerUser.id && quizCoupon.source === 'live_quiz_reward',
    `퀴즈 쿠폰은 이 세션 전용 + 정답자 본인 전용 (실제: ${JSON.stringify(quizCoupon)})`);
  const { count: winnerRows } = await admin.from('live_quiz_winners_with').select('id', { count: 'exact', head: true }).eq('quiz_id', quiz.json.data.id);
  assert(winnerRows === 1, `WITH+ 퀴즈 당첨 테이블에 1행 (실제: ${winnerRows})`);

  // ---------- 6) 실시간 경매 ----------
  const auc = await api(`/api/admin/live/channels/${channelId}/sessions/${sessionId}/auctions`, adminU.token, 'POST', { product_id: p2.id, title: '테스트 경매', starting_price: 1000, bid_increment: 500, duration_seconds: 6, soft_close_seconds: 0 });
  assert(auc.status === 201, `경매 시작 (실제: ${auc.status})`);
  const aucId = auc.json.data.id;
  const bidA = await api(`/api/live/channels/${slug}/sessions/${sessionId}/auction/${aucId}/bid`, A.token, 'POST', { amount: 1500 });
  const bidLow = await api(`/api/live/channels/${slug}/sessions/${sessionId}/auction/${aucId}/bid`, B.token, 'POST', { amount: 1600 });
  const bidB = await api(`/api/live/channels/${slug}/sessions/${sessionId}/auction/${aucId}/bid`, B.token, 'POST', { amount: 2500 });
  assert(bidA.ok && bidLow.status === 400 && bidB.ok, `입찰 1,500 성공 → 1,600 최소단위 미달 거부 → 2,500 성공 (실제: ${bidA.status}/${bidLow.status}/${bidB.status})`);
  await sleep(7000);
  const aucEnd = await api(`/api/live/channels/${slug}/sessions/${sessionId}/auction/active`);
  const myRes = await api(`/api/live/channels/${slug}/sessions/${sessionId}/auction/${aucId}/my-result`, B.token);
  const { data: aucRow } = await admin.from('live_auctions_with').select('status, winner_id, winner_coupon_code').eq('id', aucId).single();
  assert(aucRow.status === 'ended' && aucRow.winner_id === B.id && !!aucRow.winner_coupon_code, `마감 후 낙찰 확정 + 낙찰 쿠폰 발급 (실제: ${JSON.stringify(aucRow)}, active=${aucEnd.status})`);
  const otherRes = await api(`/api/live/channels/${slug}/sessions/${sessionId}/auction/${aucId}/my-result`, A.token);
  assert(myRes.ok && myRes.json.data?.is_winner === true && myRes.json.data?.coupon_code === aucRow.winner_coupon_code && otherRes.json.data?.is_winner === false && !otherRes.json.data?.coupon_code,
    `낙찰자 본인만 쿠폰 코드 확인, 다른 입찰자는 못 봄 (실제: ${myRes.status} ${JSON.stringify(myRes.json.data)})`);
  const { data: aucCoupon } = await admin.from('coupons').select('discount_value, target_user_ids').eq('code', aucRow.winner_coupon_code).maybeSingle();
  assert(aucCoupon && Number(aucCoupon.discount_value) === 7500 && aucCoupon.target_user_ids?.[0] === B.id, `낙찰 쿠폰 = 정가 10,000 - 낙찰가 2,500 = 7,500원 (실제: ${aucCoupon && aucCoupon.discount_value})`);

  // ---------- 7) 가상 선물 ----------
  await admin.from('mileage_adjustments_with').insert([{ user_id: C.id, amount: 1000, reason: 'test_grant', reference: `lew-${ts}` }]).select();
  await sleep(2100); // 채팅 도배 방지(2초) 이후
  const gift = await api(`/api/live/channels/${slug}/sessions/${sessionId}/gifts`, C.token, 'POST', { giftKey: 'heart' });
  assert(gift.ok, `마일리지로 하트 선물 (실제: ${gift.status} ${gift.json.error || ''})`);
  const { data: giftAdj } = await admin.from('mileage_adjustments_with').select('amount, reason').eq('user_id', C.id).eq('reason', 'live_gift_sent');
  assert((giftAdj || []).length === 1 && giftAdj[0].amount === -100, `선물 비용 100 마일리지 차감 기록 (실제: ${JSON.stringify(giftAdj)})`);
  const { count: giftRows } = await admin.from('live_gifts_with').select('id', { count: 'exact', head: true }).eq('session_id', sessionId);
  assert(giftRows === 1, `WITH+ 선물 테이블에 1행 (실제: ${giftRows})`);

  // ---------- 8) 바이럴 공유쿠폰 + 9) 라이브 캐시백 ----------
  const sc = await api('/api/admin/settings/live-share-coupon', adminU.token, 'PATCH', { discount_percent: 10, valid_days: 7 });
  const cb = await api('/api/admin/settings/live-cashback-rate', adminU.token, 'PATCH', { rate: 0.05 });
  assert(sc.ok && cb.ok, `공유쿠폰 10%·캐시백 5% 설정 (실제: ${sc.status}/${cb.status})`);
  const { data: keyRows } = await admin.from('platform_settings').select('key').in('key', ['live_share_coupon_settings_with', 'live_cashback_rate_with']);
  assert((keyRows || []).length === 2, `설정은 WITH+ 전용 키(*_with)에 저장 (실제: ${(keyRows || []).map(k => k.key).join(',')})`);
  const link = await api(`/api/live/channels/${slug}/sessions/${sessionId}/share-coupon-link`, A.token);
  const shareCode = link.json.data?.share_code;
  assert(link.ok && /^SH/.test(shareCode || ''), `A의 공유 코드 발급 (실제: ${shareCode})`);
  const resv = await api(`/api/live/channels/${slug}/sessions/${sessionId}/reservations`, C.token, 'POST', { product_id: p1.id, quantity: 1, stage: 'checkout' });
  assert(resv.status === 201, `C 세션 재고 예약 (실제: ${resv.status} ${resv.json.message || ''})`);
  const o4 = await api('/api/orders', C.token, 'POST', { items: [{ product_id: p1.id, quantity: 1 }], channel_id: channelId, live_session_id: sessionId, reservation_ids: [resv.json.data.id], live_attribution: { share_code: shareCode } });
  assert(o4.status === 201, `C가 A의 공유 링크로 예약 결제 주문 (실제: ${o4.status} ${o4.json.message || ''})`);
  const { data: redemption } = await admin.from('live_share_redemptions_with').select('status, sharer_coupon_code, referred_coupon_code').eq('session_id', sessionId).eq('referred_user_id', C.id).maybeSingle();
  assert(redemption && redemption.status === 'rewarded' && redemption.sharer_coupon_code && redemption.referred_coupon_code, `공유자·구매자 양쪽 쿠폰 지급 (실제: ${JSON.stringify(redemption)})`);
  const { data: resvRow } = await admin.from('live_session_reservations_with').select('status, order_id').eq('id', resv.json.data.id).single();
  assert(resvRow.status === 'confirmed' && resvRow.order_id === o4.json.data.id, `예약이 주문으로 확정 (실제: ${resvRow.status})`);
  const { data: cashback } = await admin.from('mileage_adjustments_with').select('amount').eq('user_id', C.id).eq('reason', 'live_purchase_cashback');
  assert((cashback || []).length === 1 && cashback[0].amount === Math.floor(Number(o4.json.data.final_price) * 0.05), `라이브 구매 캐시백 5% 적립 (실제: ${JSON.stringify(cashback)})`);
  const selfShare = await api('/api/orders', A.token, 'POST', { items: [{ product_id: p2.id, quantity: 1 }], channel_id: channelId, live_session_id: sessionId, live_attribution: { share_code: shareCode } });
  const { count: selfRedeem } = await admin.from('live_share_redemptions_with').select('id', { count: 'exact', head: true }).eq('session_id', sessionId).eq('referred_user_id', A.id);
  assert(selfShare.status === 201 && selfRedeem === 0, `자기 공유코드로 구매해도 보상 없음 (실제: ${selfRedeem})`);

  // ---------- 10) 다른 사이트(LIVE+) 라이브 데이터는 WITH+에서 못 씀 ----------
  const { data: foreignCoupon } = await admin.from('coupons').insert([{ code: `LEWFOREIGN${ts}`, label: '타사이트 라이브쿠폰(테스트)', discount_type: 'fixed', discount_value: 1000, per_user_limit: 1, is_active: true, live_session_id: '00000000-0000-4000-8000-000000000001', created_by: adminU.id }]).select().single();
  const useForeign = await api('/api/orders', A.token, 'POST', { items: [{ product_id: p2.id, quantity: 1 }], coupon_code: foreignCoupon.code });
  assert(useForeign.status === 400, `이 사이트 세션이 아닌 라이브 쿠폰은 사용 불가 400 (실제: ${useForeign.status})`);
  const claimForeign = await api(`/api/live/coupon-drops/${foreignCoupon.id}/claim`, A.token, 'POST');
  assert(claimForeign.status === 404, `다른 사이트 쿠폰은 쿠폰함 다운로드 불가 404 (실제: ${claimForeign.status})`);
  const badSess = await api('/api/orders', A.token, 'POST', { items: [{ product_id: p2.id, quantity: 1 }], channel_id: channelId, live_session_id: '00000000-0000-4000-8000-000000000002' });
  assert(badSess.status === 400, `이 사이트에 없는 세션 ID로 주문 시 400 (실제: ${badSess.status})`);

  // 방송 종료 → 라이브 쿠폰 무효
  await api(`/api/admin/live/channels/${channelId}/sessions/${sessionId}`, adminU.token, 'PATCH', { status: 'ended' });
  const afterEnd = await api('/api/coupons/validate', A.token, 'POST', { code: dropCode, order_amount: 10000 });
  assert(afterEnd.status === 400 && /라이브 방송 중/.test(afterEnd.json.message || ''), `방송 종료 후 라이브 쿠폰은 무효 (실제: ${afterEnd.status} ${JSON.stringify(afterEnd.json).slice(0, 120)})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리 - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
