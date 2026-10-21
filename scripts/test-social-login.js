// 카카오·네이버 로그인(서버 직접 처리) 검증
//   node scripts/test-social-login.js
// - 이 스크립트가 테스트 전용 모드(SOCIAL_LOGIN_TEST_MODE=1, NODE_ENV≠production, 127.0.0.1 요청만)로
//   서버를 포트 3106에 직접 띄운다. 테스트 모드에서는 카카오/네이버 서버 대신 인가코드에 담긴 가짜 프로필로
//   토큰·회원정보 응답을 흉내내고, 나머지(state 검증·회원 연결/생성·세션 발급)는 운영과 똑같이 실행된다.
// - 실제 DB(Supabase)에 테스트 회원을 만들고 끝나면 전부 지운다(테스트가 만든 회원만 - 이메일 접두사로 구분).
// - 이미 떠 있는 테스트 모드 서버를 쓰려면 SOCIAL_TEST_BASE=http://127.0.0.1:포트 로 지정.
const { spawn } = require('child_process');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true });

const PORT = 3106;
const BASE = process.env.SOCIAL_TEST_BASE || `http://127.0.0.1:${PORT}`;
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const admin = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
const anon = createClient(supabaseUrl, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } });

let pass = 0, fail = 0;
function assert(cond, msg, extra) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌', msg, extra !== undefined ? JSON.stringify(extra).slice(0, 300) : ''); }
}
const RUN = crypto.randomBytes(4).toString('hex');
const createdUserIds = new Set();

function b64url(obj) { return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url'); }
function decodeState(state) {
  const [, payload] = state.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}
function forgeState(data) { // 서버와 같은 비밀키로 서명(만료 테스트용)
  const payload = b64url(data);
  const sig = crypto.createHmac('sha256', process.env.JWT_SECRET).update('v1.' + payload).digest('base64url');
  return `v1.${payload}.${sig}`;
}
async function get(pathname, headers) {
  return fetch(BASE + pathname, { redirect: 'manual', headers: headers || {} });
}
function cookieFrom(res, name) {
  const all = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [res.headers.get('set-cookie') || ''];
  for (const c of all) { const m = c.match(new RegExp('^' + name + '=([^;]*)')); if (m) return m[1]; }
  return null;
}
function socialErrorOf(location) {
  try { return new URL(location, BASE).searchParams.get('social_error'); } catch (e) { return null; }
}

// 로그인 시작 → state·쿠키 확보 → 가짜 프로필 인가코드로 콜백 호출 → 결과 해석
async function runFlow(provider, profileBody, next) {
  const start = await get(`/api/auth/${provider}/login?` + new URLSearchParams({ next: next || '/', from: 'login' }));
  const loc = new URL(start.headers.get('location'));
  const state = loc.searchParams.get('state');
  const nonce = cookieFrom(start, `wp_oauth_${provider}`);
  const code = 'stub.' + b64url(profileBody);
  const cb = await get(`/api/auth/${provider}/callback?` + new URLSearchParams({ code, state }), { Cookie: `wp_oauth_${provider}=${nonce}` });
  const location = cb.headers.get('location') || '';
  const out = { status: cb.status, location, error: socialErrorOf(location) };
  const hashIdx = location.indexOf('#');
  if (hashIdx >= 0) {
    const h = new URLSearchParams(location.slice(hashIdx + 1));
    out.at = h.get('at'); out.rt = h.get('rt');
    const q = new URL(location.slice(0, hashIdx), BASE).searchParams;
    out.next = q.get('next'); out.isNew = q.get('social_new') === '1'; out.done = q.get('social_done');
    if (out.at) {
      const { data } = await anon.auth.getUser(out.at);
      out.user = data && data.user;
      if (out.user) createdUserIds.add(out.user.id);
    }
  }
  return out;
}

async function waitForServer() {
  for (let i = 0; i < 90; i++) {
    try { const r = await fetch(BASE + '/api/health'); if (r.ok) return true; } catch (e) { /* not yet */ }
    await new Promise(r => setTimeout(r, 1000));
  }
  return false;
}

async function main() {
  let child = null;
  if (!process.env.SOCIAL_TEST_BASE) {
    child = spawn(process.execPath, ['server.js'], {
      cwd: path.join(__dirname, '..'),
      env: { ...process.env, PORT: String(PORT), SOCIAL_LOGIN_TEST_MODE: '1', NODE_ENV: 'development' },
      stdio: ['ignore', 'ignore', 'pipe']
    });
    child.stderr.on('data', () => {});
  }
  try {
    if (!(await waitForServer())) throw new Error('테스트 서버가 뜨지 않았습니다');

    // ===== 1. 준비 상태 =====
    const st = await (await fetch(BASE + '/api/auth/social-status')).json();
    assert(st.data.kakao === true && st.data.kakao_via === 'server' && st.data.naver === true, '테스트 모드: 카카오(서버 방식)·네이버 준비됨', st.data);

    // ===== 2. 로그인 시작 URL =====
    const k = await get('/api/auth/kakao/login?next=' + encodeURIComponent('/product/123?opt=1') + '&from=join');
    const kLoc = new URL(k.headers.get('location'));
    assert(k.status === 302 && kLoc.origin + kLoc.pathname === 'https://kauth.kakao.com/oauth/authorize', '카카오: 인가 URL로 302');
    assert(kLoc.searchParams.get('client_id') === 'test-kakao-client-id', '카카오: client_id = REST API 키');
    assert(kLoc.searchParams.get('redirect_uri') === `${BASE}/api/auth/kakao/callback`, '카카오: redirect_uri = 이 사이트/api/auth/kakao/callback', kLoc.searchParams.get('redirect_uri'));
    assert(kLoc.searchParams.get('response_type') === 'code', '카카오: response_type=code');
    const kState = kLoc.searchParams.get('state');
    const kData = decodeState(kState);
    assert(kState.startsWith('v1.') && kData.p === 'kakao' && kData.r === '/product/123?opt=1' && kData.f === 'join', 'state: 서명 형식·제공자·복귀경로·출발화면 포함', kData);
    assert(cookieFrom(k, 'wp_oauth_kakao') === kData.n, 'state nonce = HttpOnly 쿠키 nonce');
    assert(/HttpOnly/i.test((k.headers.getSetCookie ? k.headers.getSetCookie() : []).join(';')) && /SameSite=Lax/i.test((k.headers.getSetCookie ? k.headers.getSetCookie() : []).join(';')), 'nonce 쿠키: HttpOnly; SameSite=Lax');

    const n = await get('/api/auth/naver/login?next=/mypage');
    const nLoc = new URL(n.headers.get('location'));
    assert(nLoc.origin + nLoc.pathname === 'https://nid.naver.com/oauth2.0/authorize' && nLoc.searchParams.get('client_id') === 'test-naver-client-id' && nLoc.searchParams.get('redirect_uri') === `${BASE}/api/auth/naver/callback`, '네이버: 인가 URL·client_id·redirect_uri');

    for (const bad of ['//evil.example.com/x', 'https://evil.example.com', '/\\evil.example.com', '/login?next=/x', 'javascript:alert(1)']) {
      const r = await get('/api/auth/kakao/login?next=' + encodeURIComponent(bad));
      const d = decodeState(new URL(r.headers.get('location')).searchParams.get('state'));
      assert(d.r === '/', `복귀경로 차단: ${bad} → /`, d.r);
    }

    const fwd = await get('/api/auth/kakao/login', { 'X-Forwarded-For': '1.2.3.4' });
    const fwdLoc = fwd.headers.get('location') || '';
    assert(!fwdLoc.includes('test-kakao-client-id'), '프록시 경유 요청에는 테스트 키가 절대 쓰이지 않음', fwdLoc.slice(0, 120));

    // ===== 3. 콜백 거부 =====
    const goodCookie = { Cookie: `wp_oauth_kakao=${kData.n}` };
    let r = await get('/api/auth/kakao/callback?code=stub.x&state=' + encodeURIComponent(kState.slice(0, -2) + 'AA'), goodCookie);
    assert(/^\/login\?/.test(r.headers.get('location')) && /만료되었거나 올바르지/.test(socialErrorOf(r.headers.get('location'))), '변조된 state 거부');
    const expired = forgeState({ p: 'kakao', n: 'abc', t: Date.now() - 11 * 60 * 1000, r: '/', f: 'login' });
    r = await get('/api/auth/kakao/callback?code=stub.x&state=' + encodeURIComponent(expired), { Cookie: 'wp_oauth_kakao=abc' });
    assert(/만료되었거나 올바르지/.test(socialErrorOf(r.headers.get('location')) || ''), '만료된 state(11분) 거부');
    const naverState = forgeState({ p: 'naver', n: 'abc', t: Date.now(), r: '/', f: 'login' });
    r = await get('/api/auth/kakao/callback?code=stub.x&state=' + encodeURIComponent(naverState), { Cookie: 'wp_oauth_kakao=abc' });
    assert(/만료되었거나 올바르지/.test(socialErrorOf(r.headers.get('location')) || ''), '다른 제공자용 state 거부');
    r = await get('/api/auth/kakao/callback?code=stub.x&state=' + encodeURIComponent(kState));
    assert(/같은 브라우저/.test(socialErrorOf(r.headers.get('location')) || ''), 'nonce 쿠키 없는 콜백 거부(로그인 CSRF 방지)');
    r = await get('/api/auth/kakao/callback?code=stub.x&state=' + encodeURIComponent(kState), { Cookie: 'wp_oauth_kakao=wrong' });
    assert(/같은 브라우저/.test(socialErrorOf(r.headers.get('location')) || ''), 'nonce 불일치 거부');
    r = await get('/api/auth/kakao/callback?error=access_denied&state=' + encodeURIComponent(kState), goodCookie);
    const cancelLoc = r.headers.get('location') || '';
    assert(/^\/join\?/.test(cancelLoc) && /취소/.test(socialErrorOf(cancelLoc)) && new URL(cancelLoc, BASE).searchParams.get('next') === '/product/123?opt=1', '사용자 취소 → 출발화면(가입)으로 안내·복귀경로 유지', cancelLoc);
    r = await get('/api/auth/kakao/callback?code=bad-code&state=' + encodeURIComponent(kState), goodCookie);
    assert(/인증 서버 응답에 실패/.test(socialErrorOf(r.headers.get('location')) || ''), '토큰 교환 실패 안내');

    // ===== 4. 신규 가입(이메일 미제공) → 세션 =====
    const kid1 = String(9000000000 + Math.floor(Math.random() * 99999999));
    const f1 = await runFlow('kakao', { id: Number(kid1), properties: { nickname: `테스트${RUN}` }, kakao_account: { profile: { nickname: `테스트${RUN}` } } }, '/product/77');
    assert(f1.status === 302 && f1.done === 'kakao' && !!f1.at && !!f1.rt, '카카오 신규: 세션(access/refresh) 발급 후 /login 으로 전달', f1.error || f1.location.slice(0, 80));
    assert(f1.location.startsWith('/login?') && f1.location.includes('#wp_sso=1'), '세션은 URL 해시(#wp_sso)로만 전달(서버로 전송 안 됨)');
    assert(f1.next === '/product/77', '복귀경로 유지(/product/77)', f1.next);
    assert(f1.isNew === true, '신규 가입 표시(social_new=1)');
    assert(f1.user && f1.user.email === `kakao_${kid1}@social.withplus.local`, '이메일 없으면 카카오 회원번호 기반 계정 생성', f1.user && f1.user.email);
    const uid1 = f1.user && f1.user.id;
    const { data: prof1 } = await admin.from('profiles').select('id, full_name, role').eq('id', uid1).maybeSingle();
    assert(prof1 && prof1.full_name === `테스트${RUN}` && prof1.role === 'member', 'profiles 행 생성(닉네임·member)', prof1);
    const { data: ident1 } = await admin.from('social_identities_with').select('user_id, linked_by').eq('provider', 'kakao').eq('provider_user_id', kid1).maybeSingle();
    assert(ident1 && ident1.user_id === uid1 && ident1.linked_by === 'created', '소셜 연결 대장 기록', ident1);
    const me = await fetch(BASE + '/api/me', { headers: { Authorization: 'Bearer ' + f1.at } });
    assert(me.ok, '발급된 세션으로 우리 API 인증 통과', me.status);

    // 재로그인 → 같은 회원
    const f1b = await runFlow('kakao', { id: Number(kid1), kakao_account: { profile: { nickname: 'x' } } }, '/');
    assert(f1b.user && f1b.user.id === uid1 && !f1b.isNew, '같은 카카오 회원번호 재로그인 → 같은 계정');

    // ===== 5. 인증된 이메일 → 기존 회원 연결 / 미인증 → 연결 안 함 =====
    const existingEmail = `wp-social-test-${RUN}@example.com`;
    const { data: ex } = await admin.auth.admin.createUser({ email: existingEmail, password: crypto.randomBytes(12).toString('hex') + 'A1!', email_confirm: true });
    createdUserIds.add(ex.user.id);
    await admin.from('profiles').upsert([{ id: ex.user.id, email: existingEmail, full_name: '기존회원테스트', role: 'member', member_type: 'general' }], { onConflict: 'id' });
    const kid2 = String(Number(kid1) + 1);
    const f2 = await runFlow('kakao', { id: Number(kid2), kakao_account: { email: existingEmail.toUpperCase(), is_email_valid: true, is_email_verified: true, profile: { nickname: 'k2' } } });
    assert(f2.user && f2.user.id === ex.user.id && !f2.isNew, '카카오 인증 이메일 → 같은 이메일 기존 회원에 연결', f2.error);
    const { data: ident2 } = await admin.from('social_identities_with').select('linked_by').eq('provider', 'kakao').eq('provider_user_id', kid2).maybeSingle();
    assert(ident2 && ident2.linked_by === 'email_match', '연결 방식 email_match 기록');
    const kid3 = String(Number(kid1) + 2);
    const f3 = await runFlow('kakao', { id: Number(kid3), kakao_account: { email: existingEmail, is_email_valid: true, is_email_verified: false } });
    assert(f3.user && f3.user.id !== ex.user.id && f3.user.email === `kakao_${kid3}@social.withplus.local`, '미인증 이메일은 기존 회원에 연결하지 않고 별도 계정', f3.user && f3.user.email);

    // ===== 6. 네이버 신규(이메일 제공) =====
    const naverEmail = `wp-social-test-${RUN}-n@example.com`;
    const nid = 'NV' + RUN;
    const f4 = await runFlow('naver', { resultcode: '00', message: 'success', response: { id: nid, email: naverEmail, name: '네이버테스트' } }, '/cart');
    assert(f4.user && f4.user.email === naverEmail && f4.isNew && f4.next === '/cart', '네이버 신규: 이메일 계정 생성·세션·복귀경로', f4.error);
    const f4b = await runFlow('naver', { response: { id: nid, email: naverEmail } });
    assert(f4b.user && f4.user && f4b.user.id === f4.user.id, '네이버 재로그인 → 같은 계정');

    // ===== 7. 탈퇴·정지 계정 거부 =====
    await admin.from('profiles').update({ is_active: false }).eq('id', f4.user.id);
    const f5 = await runFlow('naver', { response: { id: nid, email: naverEmail } });
    assert(!f5.at && /탈퇴한 계정/.test(f5.error || ''), '탈퇴(is_active=false) 계정 로그인 거부', f5.error);
    await admin.auth.admin.updateUserById(uid1, { ban_duration: '24h' });
    const f6 = await runFlow('kakao', { id: Number(kid1) });
    assert(!f6.at && /이용이 제한된/.test(f6.error || ''), '이용정지(ban) 계정 로그인 거부', f6.error);
  } finally {
    // 테스트가 만든 회원만 정리(profiles·social_identities_with는 FK cascade로 함께 삭제)
    let cleaned = 0;
    for (const id of createdUserIds) {
      const { data } = await admin.auth.admin.getUserById(id);
      const email = data && data.user && data.user.email || '';
      if (!/^kakao_9\d+@social\.withplus\.local$|^wp-social-test-/.test(email)) { console.log('⚠️ 정리 건너뜀(테스트 회원 아님):', id); continue; }
      let error = null;
      for (let i = 0; i < 3; i++) {
        ({ error } = await admin.auth.admin.deleteUser(id));
        if (!error) break;
        await new Promise(r => setTimeout(r, 1500));
      }
      if (!error) cleaned++; else console.log('⚠️ 테스트 회원 삭제 실패:', id, error.message);
    }
    console.log(`🧹 테스트 회원 ${cleaned}명 정리`);
    if (child) child.kill();
  }
  console.log(`\n결과: ${pass} 통과 / ${fail} 실패`);
  process.exit(fail ? 1 : 0);
}

main().catch(err => { console.error('테스트 실행 오류:', err); process.exit(1); });
