// 관리자 2단계 인증(2FA) 검증: 격차분석에서 지적된 "관리자 계정에 2FA 없음" 항목 해결 확인.
// Supabase Auth의 내장 MFA(TOTP)를 그대로 사용하고, 서버(requireRole)는 "TOTP를 등록해둔 admin/
// super_admin 계정은 세션이 aal2(2단계 인증 완료)여야만 통과"하도록 강제한다. 아직 등록 안 한 계정은
// 기존처럼 aal1로도 통과되어(하위호환) 갑자기 잠기지 않는다.
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const admin = createClient(supabaseUrl, serviceKey);
const API = 'http://localhost:3003';

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌', msg); }
}

function base32Decode(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of base32.replace(/=+$/, '').toUpperCase()) {
    const val = alphabet.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substr(i, 8), 2));
  return Buffer.from(bytes);
}
function generateTOTP(secretBase32, timeStepSeconds = 30, digits = 6) {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / timeStepSeconds);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 | (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff)) % (10 ** digits);
  return String(code).padStart(digits, '0');
}

async function main() {
  const ts = Date.now();
  const email = `test-adminmfa-${ts}@withplus-test.local`;
  const password = 'TestPass123!';

  const { data: userData } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
  const userId = userData.user.id;
  await admin.from('profiles').upsert([{ id: userId, email, full_name: 'AdminMfaTest', role: 'admin' }]);

  const client = createClient(supabaseUrl, anonKey);

  // ============================================
  // 1) MFA 미등록 상태 - 기존처럼 aal1 토큰으로도 관리자 API 정상 접근(하위호환, 갑자기 잠기지 않음)
  // ============================================
  const { data: signIn1 } = await client.auth.signInWithPassword({ email, password });
  const tokenBeforeMfa = signIn1.session.access_token;
  const beforeMfaRes = await fetch(`${API}/api/admin/dashboard`, { headers: { Authorization: `Bearer ${tokenBeforeMfa}` } });
  assert(beforeMfaRes.status === 200, `MFA 미등록 관리자는 aal1 토큰으로도 정상 접근 가능(하위호환) (실제: ${beforeMfaRes.status})`);

  // ============================================
  // 2) TOTP 등록 시작(enroll) - 아직 코드 인증(verify) 전이므로 factor는 unverified 상태
  // ============================================
  const enrollRes = await client.auth.mfa.enroll({ factorType: 'totp' });
  assert(!enrollRes.error, `TOTP 등록(enroll) 성공 (실제 에러: ${enrollRes.error?.message})`);
  const factorId = enrollRes.data.id;
  const secret = enrollRes.data.totp.secret;
  assert(!!enrollRes.data.totp.qr_code, 'enroll 응답에 QR코드(data URI)가 포함됨');

  // unverified 상태에서는 아직 강제되지 않아야 함(등록 완료 전까지는 기존과 동일하게 통과)
  const unverifiedRes = await fetch(`${API}/api/admin/dashboard`, { headers: { Authorization: `Bearer ${tokenBeforeMfa}` } });
  assert(unverifiedRes.status === 200, `등록만 하고 아직 코드 인증을 완료하지 않은 상태에서는 여전히 aal1로 접근 가능 (실제: ${unverifiedRes.status})`);

  // ============================================
  // 3) 코드 인증으로 등록 완료(verify) - 이 과정 자체가 challengeAndVerify라 세션이 즉시 aal2로 승격됨
  // ============================================
  const code1 = generateTOTP(secret);
  const verifyRes = await client.auth.mfa.challengeAndVerify({ factorId, code: code1 });
  assert(!verifyRes.error, `TOTP 코드 인증(verify) 성공 (실제 에러: ${verifyRes.error?.message})`);
  const aal2Token = verifyRes.data.access_token;

  const withAal2Res = await fetch(`${API}/api/admin/dashboard`, { headers: { Authorization: `Bearer ${aal2Token}` } });
  assert(withAal2Res.status === 200, `등록 완료 직후(aal2 세션)로는 정상 접근됨 (실제: ${withAal2Res.status})`);

  // ============================================
  // 4) 등록 완료 후 - 비밀번호만으로 새로 로그인한(아직 2단계 인증 코드를 입력하지 않은, aal1) 세션은 차단되어야 함
  // ============================================
  const client2 = createClient(supabaseUrl, anonKey);
  const { data: signIn2 } = await client2.auth.signInWithPassword({ email, password });
  const freshAal1Token = signIn2.session.access_token;
  const payload = JSON.parse(Buffer.from(freshAal1Token.split('.')[1], 'base64').toString());
  assert(payload.aal === 'aal1', `TOTP 등록 완료 후 비밀번호만으로 재로그인하면 세션은 aal1로 시작함 (실제: ${payload.aal})`);

  const blockedRes = await fetch(`${API}/api/admin/dashboard`, { headers: { Authorization: `Bearer ${freshAal1Token}` } });
  const blockedJson = await blockedRes.json();
  assert(blockedRes.status === 403, `2단계 인증을 등록한 관리자는 aal1 세션으로 관리자 API 접근 시 403으로 차단됨 (실제: ${blockedRes.status})`);
  assert(blockedJson.mfaRequired === true, 'mfaRequired 플래그가 true로 내려와 클라이언트가 2단계 인증 필요 상태임을 구분할 수 있음');

  // ============================================
  // 5) 그 세션에서 코드 인증을 완료하면(aal2로 승격) 다시 정상 접근됨
  // ============================================
  const { data: factorsData2 } = await client2.auth.mfa.listFactors();
  const verifiedFactor = factorsData2.totp.find(f => f.status === 'verified');
  assert(!!verifiedFactor, 'listFactors로 조회 시 방금 등록한 TOTP factor가 verified 상태로 확인됨');
  const code2 = generateTOTP(secret);
  const verify2Res = await client2.auth.mfa.challengeAndVerify({ factorId: verifiedFactor.id, code: code2 });
  assert(!verify2Res.error, `재로그인 세션에서 2단계 인증 코드 입력 성공 (실제 에러: ${verify2Res.error?.message})`);
  const upgradedToken = verify2Res.data.access_token;
  const afterUpgradeRes = await fetch(`${API}/api/admin/dashboard`, { headers: { Authorization: `Bearer ${upgradedToken}` } });
  assert(afterUpgradeRes.status === 200, `2단계 인증 완료(aal2) 후에는 정상적으로 관리자 API에 접근됨 (실제: ${afterUpgradeRes.status})`);

  // ============================================
  // 6) 2단계 인증 해제(unenroll) 후에는 다시 aal1만으로도 접근 가능 (원상복구 겸 기능 확인)
  // ============================================
  const unenrollRes = await client2.auth.mfa.unenroll({ factorId: verifiedFactor.id });
  assert(!unenrollRes.error, `2단계 인증 해제 성공 (실제 에러: ${unenrollRes.error?.message})`);
  const { data: signIn3 } = await client2.auth.signInWithPassword({ email, password });
  const afterUnenrollRes = await fetch(`${API}/api/admin/dashboard`, { headers: { Authorization: `Bearer ${signIn3.session.access_token}` } });
  assert(afterUnenrollRes.status === 200, `2단계 인증 해제 후에는 다시 비밀번호만으로도 정상 접근 가능 (실제: ${afterUnenrollRes.status})`);

  // ============================================
  // 정리
  // ============================================
  await admin.from('profiles').delete().eq('id', userId);
  await admin.auth.admin.deleteUser(userId).catch(() => {});

  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => { console.error('테스트 실행 중 오류:', err); process.exit(1); });
