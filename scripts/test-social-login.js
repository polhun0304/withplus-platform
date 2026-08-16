// 소셜 로그인(구글/카카오/네이버) 중 서버 코드로 구현한 부분(네이버 OAuth 흐름 + 관리자 설정 API)을 검증한다.
// 구글/카카오는 Supabase Auth가 기본 제공하는 OAuth Provider라 서버 코드가 없고(프론트엔드의
// signInWithOAuth 호출 + Supabase 대시보드 설정만으로 동작), 실제 제공자 연동 여부는 Supabase 대시보드에서
// 확인해야 하므로 이 테스트의 범위가 아니다. 네이버도 실제 발급받은 Client ID/Secret이 있어야만 완주할 수
// 있는 "인가코드 → 토큰 교환 → 프로필 조회" 부분(실제 네이버 계정 필요)은 이 자동 테스트로 확인할 수 없고,
// 그 앞뒤(관리자 설정 CRUD, state 서명/검증, 미설정 시 안전한 처리, 잘못된 state/코드 처리)만 검증한다.
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
const API = 'http://localhost:3003';

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌', msg); }
}

async function loginAs(email, password) {
  const res = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: anonKey },
    body: JSON.stringify({ email, password })
  });
  const json = await res.json();
  return json.access_token;
}

// server.js의 signNaverState/verifyNaverState와 동일한 알고리즘(JWT_SECRET으로 HMAC-SHA256 서명)을
// 테스트에서도 재현해, 임의의 만료/위조 state를 만들어 서버가 정확히 거부하는지 확인한다.
function makeState({ nonce = crypto.randomBytes(16).toString('hex'), tsOffsetMs = 0, badSig = false } = {}) {
  const ts = (Date.now() + tsOffsetMs).toString();
  const payload = `${nonce}.${ts}`;
  const sig = badSig
    ? crypto.randomBytes(32).toString('hex')
    : crypto.createHmac('sha256', process.env.JWT_SECRET || 'withplus-fallback-secret').update(payload).digest('hex');
  return `${payload}.${sig}`;
}

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  let superAdminId, providerId;
  // 테스트 시작 전 oauth_configs.naver 백업 (테스트가 실제 저장된 값을 건드릴 수 있으므로 끝나면 복구)
  const { data: backup } = await admin.from('oauth_configs').select('*').eq('provider_key', 'naver').maybeSingle();

  try {
    // ============================================
    // 0) 계정 준비
    // ============================================
    const superAdminEmail = `test-social-admin-${ts}@withplus-test.local`;
    const { data: saUser } = await admin.auth.admin.createUser({ email: superAdminEmail, password, email_confirm: true });
    superAdminId = saUser.user.id;
    await admin.from('profiles').upsert([{ id: superAdminId, email: superAdminEmail, full_name: '소셜테스트관리자', role: 'super_admin' }]);
    const superAdminToken = await loginAs(superAdminEmail, password);

    const providerEmail = `test-social-provider-${ts}@withplus-test.local`;
    const { data: pUser } = await admin.auth.admin.createUser({ email: providerEmail, password, email_confirm: true });
    providerId = pUser.user.id;
    await admin.from('profiles').upsert([{ id: providerId, email: providerEmail, full_name: '소셜테스트공급자', role: 'provider' }]);
    const providerToken = await loginAs(providerEmail, password);

    // ============================================
    // 1) 관리자 설정 API - 권한 분리
    // ============================================
    const noAuthGet = await fetch(`${API}/api/admin/oauth-config/naver`);
    assert(noAuthGet.status === 401, `인증 없이 조회 시 401 (실제: ${noAuthGet.status})`);

    const providerGet = await fetch(`${API}/api/admin/oauth-config/naver`, { headers: { Authorization: `Bearer ${providerToken}` } });
    assert(providerGet.status === 403, `공급자는 네이버 로그인 설정을 조회할 수 없음 (실제: ${providerGet.status})`);

    const providerPut = await fetch(`${API}/api/admin/oauth-config/naver`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${providerToken}` },
      body: JSON.stringify({ client_id: 'hacked' })
    });
    assert(providerPut.status === 403, `공급자는 네이버 로그인 설정을 저장할 수 없음 (실제: ${providerPut.status})`);

    // ============================================
    // 2) 관리자 설정 API - 저장/조회 (시크릿은 절대 응답에 노출되지 않음)
    // ============================================
    const testClientId = `test-client-id-${ts}`;
    const testSecret = `test-secret-${ts}`;
    const saveRes = await fetch(`${API}/api/admin/oauth-config/naver`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ client_id: testClientId, client_secret: testSecret, enabled: true })
    });
    const saveJson = await saveRes.json();
    assert(saveRes.status === 200 && saveJson.data.client_id === testClientId, `super_admin이 네이버 로그인 설정 저장 성공 (실제: ${saveRes.status})`);
    assert(saveJson.data.has_client_secret === true && saveJson.data.client_secret === undefined, '저장 응답에 시크릿 원문이 포함되지 않음(has_client_secret만 존재)');

    const getRes = await fetch(`${API}/api/admin/oauth-config/naver`, { headers: { Authorization: `Bearer ${superAdminToken}` } });
    const getJson = await getRes.json();
    assert(getRes.status === 200 && getJson.data.client_id === testClientId && getJson.data.enabled === true, '저장한 설정이 조회 시 정확히 반영됨');
    assert(getJson.data.client_secret === undefined, '조회 응답에도 시크릿 원문이 절대 포함되지 않음');
    assert(typeof getJson.data.callback_url === 'string' && getJson.data.callback_url.endsWith('/api/auth/naver/callback'), `콜백 URL이 올바르게 계산됨 (실제: ${getJson.data.callback_url})`);

    // 시크릿을 빈 값으로 보내면 기존 값을 유지해야 한다(실수로 빈 문자열 저장해 로그인이 깨지는 것을 방지)
    const saveNoSecretRes = await fetch(`${API}/api/admin/oauth-config/naver`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ client_id: testClientId, client_secret: '', enabled: true })
    });
    const saveNoSecretJson = await saveNoSecretRes.json();
    assert(saveNoSecretRes.status === 200 && saveNoSecretJson.data.has_client_secret === true, '시크릿을 빈 값으로 보내면 기존 저장값이 유지됨');

    // ============================================
    // 3) 네이버 로그인 시작 (/api/auth/naver/login) - 설정된 상태에서는 네이버 인가 URL로 리다이렉트
    // ============================================
    const loginStartRes = await fetch(`${API}/api/auth/naver/login`, { redirect: 'manual' });
    const loginLocation = loginStartRes.headers.get('location') || '';
    assert(loginStartRes.status === 302 && loginLocation.startsWith('https://nid.naver.com/oauth2.0/authorize'), `설정된 상태에서 /api/auth/naver/login이 네이버 인가 URL로 리다이렉트 (실제: ${loginStartRes.status}, ${loginLocation.slice(0, 60)})`);
    const loginUrl = new URL(loginLocation);
    assert(loginUrl.searchParams.get('client_id') === testClientId, '인가 URL에 설정된 client_id가 그대로 포함됨');
    assert(!!loginUrl.searchParams.get('state'), '인가 URL에 CSRF 방지용 state 파라미터가 포함됨');
    assert(loginUrl.searchParams.get('redirect_uri') === getJson.data.callback_url, '인가 URL의 redirect_uri가 콜백 주소와 일치함');

    // 비활성화 상태에서는 네이버로 보내지 않고 로그인 화면으로 안내 메시지와 함께 되돌아온다
    await fetch(`${API}/api/admin/oauth-config/naver`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ enabled: false })
    });
    const loginDisabledRes = await fetch(`${API}/api/auth/naver/login`, { redirect: 'manual' });
    const disabledLocation = loginDisabledRes.headers.get('location') || '';
    assert(loginDisabledRes.status === 302 && disabledLocation.startsWith('/login?social_error='), `비활성화 상태에서는 /login으로 안내 메시지와 함께 리다이렉트 (실제: ${loginDisabledRes.status}, ${disabledLocation.slice(0, 50)})`);

    // 다시 활성화(이후 콜백 테스트에서 "설정은 되어 있음" 상태가 필요)
    await fetch(`${API}/api/admin/oauth-config/naver`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${superAdminToken}` },
      body: JSON.stringify({ enabled: true })
    });

    // ============================================
    // 4) 네이버 로그인 콜백 (/api/auth/naver/callback) - state 서명/만료 검증
    // 실제 네이버 계정으로 발급된 진짜 인가코드가 없어 토큰교환 이후(성공 로그인)까지는 이 자동
    // 테스트로 확인할 수 없다 - 그 앞단의 방어 로직(위조/만료 state, 코드 누락, 취소)만 검증한다.
    // ============================================
    const noCodeRes = await fetch(`${API}/api/auth/naver/callback?state=${encodeURIComponent(makeState())}`, { redirect: 'manual' });
    assert(noCodeRes.status === 302 && (noCodeRes.headers.get('location') || '').startsWith('/login?social_error='), `인가코드 없이 콜백 호출 시 안내 메시지와 함께 로그인 화면으로 리다이렉트 (실제: ${noCodeRes.status})`);

    const tamperedSigRes = await fetch(`${API}/api/auth/naver/callback?code=fake&state=${encodeURIComponent(makeState({ badSig: true }))}`, { redirect: 'manual' });
    assert(tamperedSigRes.status === 302 && (tamperedSigRes.headers.get('location') || '').startsWith('/login?social_error='), `서명이 위조된 state는 거부됨 (실제: ${tamperedSigRes.status})`);

    const expiredStateRes = await fetch(`${API}/api/auth/naver/callback?code=fake&state=${encodeURIComponent(makeState({ tsOffsetMs: -11 * 60 * 1000 }))}`, { redirect: 'manual' });
    assert(expiredStateRes.status === 302 && (expiredStateRes.headers.get('location') || '').startsWith('/login?social_error='), `11분 전에 발급된(만료된) state는 거부됨 (실제: ${expiredStateRes.status})`);

    const noStateRes = await fetch(`${API}/api/auth/naver/callback?code=fake`, { redirect: 'manual' });
    assert(noStateRes.status === 302 && (noStateRes.headers.get('location') || '').startsWith('/login?social_error='), `state 파라미터 자체가 없으면 거부됨 (실제: ${noStateRes.status})`);

    const canceledRes = await fetch(`${API}/api/auth/naver/callback?error=access_denied&state=${encodeURIComponent(makeState())}`, { redirect: 'manual' });
    assert(canceledRes.status === 302 && (canceledRes.headers.get('location') || '').startsWith('/login?social_error='), `사용자가 네이버 동의화면에서 취소하면(error 파라미터) 안내와 함께 되돌아옴 (실제: ${canceledRes.status})`);

    // 유효한 state + 가짜 코드 → 네이버 토큰교환 서버 호출까지는 가지만(실제 네트워크 호출), 가짜 코드라
    // 네이버 서버가 실패 응답을 주고, 그 실패도 안전하게(500 대신) 로그인 화면 리다이렉트로 처리되는지 확인
    const validStateFakeCodeRes = await fetch(`${API}/api/auth/naver/callback?code=definitely-not-a-real-naver-auth-code&state=${encodeURIComponent(makeState())}`, { redirect: 'manual' });
    assert(validStateFakeCodeRes.status === 302 && (validStateFakeCodeRes.headers.get('location') || '').startsWith('/login?social_error='), `유효한 state에 가짜 인가코드를 보내도(네이버가 거부) 서버가 500이 아닌 안내 리다이렉트로 안전하게 처리함 (실제: ${validStateFakeCodeRes.status})`);

  } finally {
    console.log('\n--- 정리 시작 ---');
    try {
      if (backup) {
        await admin.from('oauth_configs').update({ client_id: backup.client_id, client_secret: backup.client_secret, enabled: backup.enabled }).eq('provider_key', 'naver');
      } else {
        await admin.from('oauth_configs').update({ client_id: null, client_secret: null, enabled: false }).eq('provider_key', 'naver');
      }
      if (superAdminId) await admin.auth.admin.deleteUser(superAdminId);
      if (providerId) await admin.auth.admin.deleteUser(providerId);
    } catch (e) { console.error('정리 중 오류:', e.message); }
    console.log('--- 정리 완료 ---');
  }

  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => { console.error('💥 테스트 실패:', err.message); process.exit(1); });
