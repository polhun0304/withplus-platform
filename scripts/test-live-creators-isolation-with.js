// WITH+ 라이브 크리에이터 제휴 커미션 + 사이트 데이터 분리(WITH+ ↔ LIVE+) 테스트
// - 크리에이터 등록·추천코드 발급(대표자 부트스트랩) → 추천코드 유입 라이브 주문에 WITH+ 크리에이터 귀속(live_creator_id_with)
// - 셀프 리퍼럴 미귀속 · 기간별 커미션 정산 생성 · 채널 등급/랭킹 API
// - 분리 검증: WITH+에서 만든 채널/세션/주문은 LIVE+ *_live 테이블·컬럼에 없고, LIVE+ 채널은 WITH+ API에 보이지 않는다
//   (LIVE+ 테이블은 읽기만 한다 - 절대 쓰지 않는다)
// 실행: PORT=3140 node server.js 실행 후 → API=http://localhost:3140 node scripts/test-live-creators-isolation-with.js
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
  const mkUser = async (tag, role, extra = {}) => {
    const email = `test-lci-${tag}-${ts}@withplus-test.local`;
    const { data, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
    if (error) throw error;
    await admin.from('profiles').upsert([Object.assign({ id: data.user.id, email, full_name: `크리에이터테스트${tag}`, role, member_type: 'general' }, extra)]);
    return { id: data.user.id, token: await loginAs(email, password) };
  };
  // 크리에이터 관리 API는 대표자(super_admin + is_owner) 전용 - 2단계 인증 수단이 아직 없는 대표자는 부트스트랩으로 통과
  const owner = await mkUser('owner', 'super_admin', { is_owner: true });
  const plainAdmin = await mkUser('admin', 'admin');
  const creatorUser = await mkUser('creator', 'member');
  const buyer = await mkUser('buyer', 'member');
  assert(owner.token && plainAdmin.token && creatorUser.token && buyer.token, '테스트 대표자/관리자/크리에이터/구매자 로그인');

  const api = async (path, token, method = 'GET', body) => {
    const res = await fetch(`${API}${path}`, { method, headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: `Bearer ${token}` } : {}), body: body !== undefined ? JSON.stringify(body) : undefined });
    const json = await res.json().catch(() => ({}));
    return { status: res.status, ok: res.ok, json };
  };

  const { data: product, error: pErr } = await admin.from('products_with').insert([{ name: `크리에이터테스트상품 ${ts}`, slug: `lci-p-${ts}`, description: '테스트', price: 30000, stock: 50, status: 'active', category: '테스트' }]).select().single();
  if (pErr) throw pErr;

  const slug = `lci-${ts}`;
  const ch = await api('/api/admin/live/channels', owner.token, 'POST', { slug, name: '크리에이터 테스트 채널', channel_type: 'creator' });
  assert(ch.status === 201, `채널 생성 (실제: ${ch.status})`);
  const channelId = ch.json.data.id;
  await api(`/api/admin/live/channels/${channelId}`, owner.token, 'PATCH', { status: 'active' });
  await api(`/api/admin/live/channels/${channelId}/products`, owner.token, 'POST', { product_id: product.id });
  const ses = await api(`/api/admin/live/channels/${channelId}/sessions`, owner.token, 'POST', { title: '크리에이터 방송' });
  const sessionId = ses.json.data.id;
  await api(`/api/admin/live/channels/${channelId}/sessions/${sessionId}`, owner.token, 'PATCH', { status: 'live' });

  // ---------- 크리에이터 ----------
  const denied = await api('/api/admin/creators', plainAdmin.token);
  assert(denied.status === 403, `대표자가 아닌 관리자는 크리에이터(수수료율·계좌) 조회 불가 403 (실제: ${denied.status})`);
  const cr = await api('/api/admin/creators', owner.token, 'POST', { display_name: '테스트 크리에이터', commission_rate: 10, user_id: creatorUser.id, bank_name: '테스트은행', bank_account: '000-000', account_holder: '테스트' });
  assert(cr.status === 201 && Number(cr.json.data?.commission_rate) === 10, `크리에이터 등록 (실제: ${cr.status} ${cr.json.message || ''})`);
  const creatorId = cr.json.data.id;
  const { data: crRow } = await admin.from('live_creators_with').select('id').eq('id', creatorId).maybeSingle();
  const { data: crLive } = await admin.from('creators_with').select('id').eq('id', creatorId).maybeSingle();
  assert(crRow && !crLive, 'WITH+ 크리에이터는 live_creators_with에만 저장(LIVE+ creators_with에는 없음)');
  const code = `LCI${String(ts).slice(-6)}`;
  const rc = await api(`/api/admin/creators/${creatorId}/referral-codes`, owner.token, 'POST', { code });
  assert(rc.status === 201 && rc.json.data?.code === code, `추천코드 발급 (실제: ${rc.status})`);

  const o1 = await api('/api/orders', buyer.token, 'POST', { items: [{ product_id: product.id, quantity: 1 }], channel_id: channelId, live_session_id: sessionId, live_attribution: { referrer_code: code, source_platform: 'instagram', campaign: 'lci' } });
  assert(o1.status === 201 && o1.json.data?.live_creator_id_with === creatorId && o1.json.data?.creator_id === null && o1.json.data?.attribution_referrer_code === code,
    `추천코드 유입 주문에 WITH+ 크리에이터 귀속 (실제: ${o1.status} ${o1.json.data?.live_creator_id_with})`);
  const self = await api('/api/orders', creatorUser.token, 'POST', { items: [{ product_id: product.id, quantity: 1 }], channel_id: channelId, live_attribution: { referrer_code: code } });
  assert(self.status === 201 && self.json.data?.live_creator_id_with === null, `셀프 리퍼럴은 커미션 미귀속 (실제: ${self.json.data?.live_creator_id_with})`);

  const today = new Date(Date.now() + 9 * 3600 * 1000).toISOString().slice(0, 10);
  const yesterday = new Date(Date.now() + 9 * 3600 * 1000 - 86400000).toISOString().slice(0, 10);
  const gen = await api('/api/admin/creator-settlements/generate', owner.token, 'POST', { startDate: yesterday, endDate: today });
  const myRow = (gen.json.data?.rows || []).find(r => r.creator_id === creatorId);
  const expectedGross = Number(o1.json.data.final_price);
  assert(gen.ok && myRow && Number(myRow.gross_revenue) === expectedGross && Number(myRow.commission_amount) === Math.round(expectedGross * 0.1),
    `기간 정산: 매출 ${expectedGross}원 × 10% 커미션 (실제: ${gen.status} ${myRow && myRow.gross_revenue}/${myRow && myRow.commission_amount})`);
  const list = await api('/api/admin/creator-settlements', owner.token);
  assert(list.ok && (list.json.data || []).some(r => r.creator_id === creatorId && r.creator_name === '테스트 크리에이터'), '정산 목록에 크리에이터명 포함');

  // ---------- 채널 등급/랭킹 ----------
  const rank = await api(`/api/live/channels/${slug}/rank`);
  assert(rank.ok && typeof rank.json.data?.tier === 'string', `채널 등급 공개 API (실제: ${rank.status} ${rank.json.data?.tier})`);
  const rankings = await api('/api/admin/live/channel-rankings', owner.token);
  assert(rankings.ok && Array.isArray(rankings.json.data?.rankings), `관리자 채널 랭킹 API (실제: ${rankings.status})`);

  // ---------- 사이트 분리 ----------
  const { data: inLiveCh } = await admin.from('channels_live').select('id').eq('id', channelId).maybeSingle();
  const { data: inLiveSes } = await admin.from('live_sessions_live').select('id').eq('id', sessionId).maybeSingle();
  const { data: inWithCh } = await admin.from('channels_with').select('id').eq('id', channelId).maybeSingle();
  assert(inWithCh && !inLiveCh && !inLiveSes, 'WITH+에서 만든 채널·세션은 channels_with/live_sessions_with에만 있고 LIVE+ *_live에는 없음');
  const { data: liveOnlyChannel } = await admin.from('channels_live').select('id, slug').eq('status', 'active').limit(1).maybeSingle();
  if (liveOnlyChannel) {
    const seen = await api(`/api/live/channels/${encodeURIComponent(liveOnlyChannel.slug)}`);
    const { data: sameSlugWith } = await admin.from('channels_with').select('id').eq('slug', liveOnlyChannel.slug).maybeSingle();
    assert(seen.status === 404 || (sameSlugWith && seen.json.data?.id === sameSlugWith.id), `LIVE+ 채널(${liveOnlyChannel.slug})은 WITH+ API에서 보이지 않음 (실제: ${seen.status})`);
    const listAll = await api('/api/live/channels');
    assert(!(listAll.json.data || []).some(c => c.id === liveOnlyChannel.id), 'WITH+ 채널 목록에 LIVE+ 채널 ID 없음');
    const foreignOrder = await api('/api/orders', buyer.token, 'POST', { items: [{ product_id: product.id, quantity: 1 }], channel_id: liveOnlyChannel.id });
    assert(foreignOrder.status === 400, `LIVE+ 채널 ID로 WITH+ 라이브 주문 불가 400 (실제: ${foreignOrder.status})`);
  } else {
    console.log('ℹ️ 활성 LIVE+ 채널이 없어 교차 조회 검증은 건너뜀');
  }
  const { data: omniWith } = await admin.from('omnicast_platform_configs_with').select('provider_key, redirect_uri').eq('provider_key', 'youtube').maybeSingle();
  const platforms = await api('/api/admin/live/omnicast/platforms', owner.token);
  const ytCfg = (platforms.json.data || []).find(p => p.provider_key === 'youtube');
  assert(omniWith && ytCfg && ytCfg.redirect_uri === omniWith.redirect_uri && !/live-plus/.test(ytCfg.redirect_uri || ''),
    `OmniCast 플랫폼 설정은 WITH+ 전용 테이블(redirect ${ytCfg && ytCfg.redirect_uri})`);

  console.log(`\n결과: ${pass}개 통과, ${fail}개 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

// 이 실행이 만든 행만 정리 - scripts/lib/live-test-harness.js
require('./lib/live-test-harness').runWithCleanup(admin, main);
