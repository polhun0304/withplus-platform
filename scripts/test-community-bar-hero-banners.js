// 홈 공동체 바(내 공동체 이름 + 공동체 적립금·나의 적립금)와 홈 메인 이미지 배너(관리자 등록 → 공개 노출 필터)를 검증하는 임시 테스트.
// 실행: PORT=3107 node server.js 를 띄운 뒤 BASE=http://localhost:3107 node scripts/test-community-bar-hero-banners.js
// 만든 계정·조직·주문·배너 설정·업로드 사진은 끝나면 모두 정리하고, 원래 배너 설정 값은 그대로 되돌린다.
const { createClient } = require('@supabase/supabase-js');
const zlib = require('zlib');
require('dotenv').config();

const BASE = process.env.BASE || 'http://localhost:3107';
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY);
const KEEP = process.argv.includes('--keep'); // 화면 확인용: 정리를 미루고 계정 정보를 출력한 뒤 Enter를 기다린다

const stamp = Date.now();
const PASSWORD = 'WithplusTest2026!';
const BANNER_KEY = 'home_hero_banners' + (process.env.UPLOAD_PLATFORM === 'liveplus' ? '_live' : '');
const created = { users: [], communities: [], orders: [], storage: [] };
let originalBannerRow = null;

function assert(cond, msg) {
  if (!cond) throw new Error('❌ 검증 실패: ' + msg);
  console.log('✅ ' + msg);
}
async function api(path, token, options = {}) {
  const res = await fetch(BASE + path, { ...options, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(options.headers || {}) } });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, ok: res.ok, json };
}
async function createTestUser(email, role) {
  const { data, error } = await admin.auth.admin.createUser({ email, password: PASSWORD, email_confirm: true });
  if (error) throw new Error(`계정 생성 실패(${email}): ${error.message}`);
  created.users.push(data.user.id);
  const { error: pErr } = await admin.from('profiles').upsert({ id: data.user.id, email, role: role || 'member' });
  if (pErr) throw new Error('profiles 생성 실패: ' + pErr.message);
  const client = createClient(supabaseUrl, anonKey);
  const { data: s, error: sErr } = await client.auth.signInWithPassword({ email, password: PASSWORD });
  if (sErr) throw new Error('로그인 실패: ' + sErr.message);
  return { id: data.user.id, email, token: s.session.access_token };
}
// 단색 PNG(가로×세로) — 업로드/화면 확인용 테스트 사진
function makePng(w, h, [r, g, b]) {
  const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
  const crc = (buf) => { let c = 0xFFFFFFFF; for (const x of buf) c = crcTable[(c ^ x) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
  const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type), data]); const c = Buffer.alloc(4); c.writeUInt32BE(crc(td)); return Buffer.concat([len, td, c]); };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2;
  const row = Buffer.alloc(1 + w * 3); for (let x = 0; x < w; x++) { row[1 + x * 3] = r; row[2 + x * 3] = g; row[3 + x * 3] = b; }
  const raw = Buffer.concat(Array.from({ length: h }, () => row));
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}
async function upload(token, buf) {
  const res = await fetch(BASE + '/api/admin/uploads/product-image', { method: 'POST', headers: { 'Content-Type': 'image/png', 'X-Product-Key': 'home-banner', Authorization: 'Bearer ' + token }, body: buf });
  const json = await res.json();
  if (!res.ok) throw new Error('업로드 실패: ' + JSON.stringify(json));
  created.storage.push(json.data.path);
  return json.data.url;
}
function ymd(offsetDays) { return new Date(Date.now() + 9 * 3600e3 + offsetDays * 86400e3).toISOString().slice(0, 10); }

async function cleanup() {
  console.log('\n--- 정리 시작 ---');
  if (originalBannerRow) await admin.from('platform_settings').upsert(originalBannerRow, { onConflict: 'key' });
  else await admin.from('platform_settings').delete().eq('key', BANNER_KEY);
  for (const id of created.orders) await admin.from('orders_with').delete().eq('id', id);
  for (const id of created.communities) {
    await admin.from('community_members').delete().eq('community_id', id);
    await admin.from('communities').delete().eq('id', id);
  }
  if (created.storage.length) await admin.storage.from('product-images').remove(created.storage);
  for (const id of created.users) {
    await admin.from('profiles').delete().eq('id', id);
    await admin.auth.admin.deleteUser(id).catch(() => {});
  }
  console.log('--- 정리 완료 ---');
}

async function main() {
  const { data: orig } = await admin.from('platform_settings').select('*').eq('key', BANNER_KEY).maybeSingle();
  originalBannerRow = orig || null;

  const hq = await createTestUser(`withplus.wcb.hq.${stamp}@withplus.test`, 'super_admin');
  const member = await createTestUser(`withplus.wcb.member.${stamp}@withplus.test`, null);
  const loner = await createTestUser(`withplus.wcb.loner.${stamp}@withplus.test`, null);

  // ---------- 1) 공동체 바 ----------
  const anon = await api('/api/me/community-summary');
  assert(anon.status === 401, `비로그인 요약 요청은 401 (status=${anon.status})`);
  const none = await api('/api/me/community-summary', loner.token);
  assert(none.ok && none.json.data.primary === null && none.json.data.communities.length === 0, '공동체 없는 회원 → primary 없음(기존 "전체 쇼핑몰" 유지)');

  const mk = async (name, slug) => {
    const r = await api('/api/admin/communities', hq.token, { method: 'POST', body: JSON.stringify({ name, slug }) });
    assert(r.ok, `테스트 조직 생성: ${name} (status=${r.status})`);
    created.communities.push(r.json.data.id);
    return r.json.data;
  };
  const older = await mk(`인천테스트교회-${stamp}`, `wcb-older-${stamp}`);
  const newer = await mk(`부천테스트교회-${stamp}`, `wcb-newer-${stamp}`);
  assert((await api(`/api/communities/${older.slug}/join`, member.token, { method: 'POST' })).ok, '회원이 첫 조직 가입');
  await admin.from('community_members').update({ joined_at: new Date(Date.now() - 86400e3).toISOString() }).eq('community_id', older.id).eq('user_id', member.id);
  assert((await api(`/api/communities/${newer.slug}/join`, member.token, { method: 'POST' })).ok, '회원이 두 번째 조직 가입');

  // 실제 잔액 계산 경로 확인용 주문(취소 주문은 합계에서 빠져야 한다)
  const baseOrder = { user_id: member.id, total_price: 10000, final_price: 10000, items: [], status: 'delivered' };
  const rows = [
    { ...baseOrder, community_id: older.id, personal_earned_points: 300, community_earned_points: 1200 },
    { ...baseOrder, community_id: older.id, personal_earned_points: 100, community_earned_points: 560 },
    { ...baseOrder, community_id: older.id, personal_earned_points: 999, community_earned_points: 9999, status: 'cancelled' }
  ];
  for (const [i, row] of rows.entries()) {
    const { data, error } = await admin.from('orders_with').insert({ ...row, order_number: `TEST-WCB-${stamp}-${i}` }).select('id').single();
    if (error) throw new Error('테스트 주문 생성 실패: ' + error.message);
    created.orders.push(data.id);
  }

  const s1 = await api('/api/me/community-summary', member.token);
  assert(s1.ok, '공동체 요약 조회 성공');
  const d1 = s1.json.data;
  assert(d1.primary && d1.primary.slug === newer.slug, `기본 대표 공동체 = 가장 최근 가입한 곳 (${d1.primary && d1.primary.name})`);
  assert(d1.communities.length === 2, '내 공동체 2곳 모두 목록에 포함');
  assert(d1.primary.community_points === 0, '주문 없는 공동체의 적립금 0');
  // 나의 적립금 = 장바구니·회원 혜택 바와 같은 잔액 API 값
  const bal = await api('/api/me/mileage-balance', member.token);
  assert(d1.my_points === bal.json.data.balance, `나의 적립금 = /api/me/mileage-balance (${d1.my_points}P)`);
  assert(d1.my_points === 300 + 1200 + 100 + 560, '나의 적립금에 취소 주문 제외 (기존 잔액 계산식 그대로)');

  const s2 = await api(`/api/me/community-summary?prefer=${older.slug}`, member.token);
  assert(s2.json.data.primary.slug === older.slug, '지금 보는 매장(prefer)이 내 공동체면 그곳이 대표');
  assert(s2.json.data.primary.community_points === 1760, `공동체 적립금 = 취소 제외 합계 1,760P (실제 ${s2.json.data.primary.community_points})`);
  const landing = await api(`/api/communities/${older.slug}`);
  assert(landing.json.data.total_points_earned === s2.json.data.primary.community_points, '공동체 적립금이 조직 랜딩 페이지 값과 같다');
  const s3 = await api('/api/me/community-summary?prefer=not-my-community', member.token);
  assert(s3.json.data.primary.slug === newer.slug, '가입하지 않은 매장을 prefer로 보내면 무시하고 내 공동체를 대표로');

  // ---------- 2) 메인 이미지 배너 ----------
  const noAuth = await api('/api/admin/home/hero-banners', member.token);
  assert(noAuth.status === 403, `일반 회원은 배너 관리 API 접근 불가 (status=${noAuth.status})`);
  const pc = await upload(hq.token, makePng(1200, 400, [92, 58, 40]));
  const mobile = await upload(hq.token, makePng(750, 500, [40, 92, 58]));
  assert(/^https:\/\//.test(pc) && pc.includes('/home-banner/'), 'PC 배너 사진 업로드(Storage) 성공');

  const bad = await api('/api/admin/home/hero-banners', hq.token, { method: 'PUT', body: JSON.stringify({ banners: [{ pc_image: 'javascript:alert(1)', active: true }] }) });
  assert(bad.status === 400, '잘못된 사진 주소는 저장 거부');
  const badLink = await api('/api/admin/home/hero-banners', hq.token, { method: 'PUT', body: JSON.stringify({ banners: [{ pc_image: pc, link_url: 'javascript:alert(1)', active: true }] }) });
  assert(badLink.status === 400, 'javascript: 링크 저장 거부');

  const put = await api('/api/admin/home/hero-banners', hq.token, { method: 'PUT', body: JSON.stringify({ banners: [
    { pc_image: pc, mobile_image: mobile, link_url: '/category/food', alt: '테스트 배너 B', sort_order: 2, active: true, start_date: ymd(-1), end_date: ymd(3) },
    { pc_image: pc, alt: '테스트 배너 A', sort_order: 1, active: true },
    { pc_image: pc, alt: '꺼진 배너', sort_order: 3, active: false },
    { pc_image: pc, alt: '예약 배너', sort_order: 4, active: true, start_date: ymd(2) },
    { pc_image: pc, alt: '끝난 배너', sort_order: 5, active: true, end_date: ymd(-1) }
  ] }) });
  assert(put.ok && put.json.data.length === 5, '관리자 배너 5개 저장');
  const pub = await api('/api/home/hero-banners');
  const alts = pub.json.data.map(b => b.alt);
  assert(JSON.stringify(alts) === JSON.stringify(['테스트 배너 A', '테스트 배너 B']), `공개 API는 켜짐+기간 안 배너만 순서대로 (${alts.join(', ')})`);
  assert(pub.json.data[1].mobile_image === mobile && pub.json.data[1].link_url === '/category/food', '모바일 사진·링크 포함');

  if (KEEP) {
    console.log(`\n[화면 확인용] 회원: ${member.email} / 관리자: ${hq.email} (비밀번호는 스크립트 상수)`);
    console.log('MEMBER_TOKEN=' + member.token);
    console.log('ADMIN_TOKEN=' + hq.token);
    console.log('Enter를 누르면 정리합니다…');
    await new Promise(r => process.stdin.once('data', r));
  }
}

main().then(() => console.log('\n🎉 모든 검증 통과')).catch(e => { console.error(e.message || e); process.exitCode = 1; }).finally(cleanup);
