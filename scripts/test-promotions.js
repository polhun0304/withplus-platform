const { createClient } = require('@supabase/supabase-js');
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

function todayStr() { return new Date().toISOString().slice(0, 10); }
function yesterdayStr() { return new Date(Date.now() - 86400000).toISOString().slice(0, 10); }

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const adminEmail = `test-promo-admin-${ts}@withplus-test.local`;
  const memberSerialEmail = `test-promo-serial-${ts}@withplus-test.local`;
  const memberAttendanceEmail = `test-promo-att-${ts}@withplus-test.local`;
  const memberStreakEmail = `test-promo-streak-${ts}@withplus-test.local`;
  const memberDisabledEmail = `test-promo-disabled-${ts}@withplus-test.local`;

  const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const { data: serialData } = await admin.auth.admin.createUser({ email: memberSerialEmail, password, email_confirm: true });
  const { data: attData } = await admin.auth.admin.createUser({ email: memberAttendanceEmail, password, email_confirm: true });
  const { data: streakData } = await admin.auth.admin.createUser({ email: memberStreakEmail, password, email_confirm: true });
  const { data: disabledData } = await admin.auth.admin.createUser({ email: memberDisabledEmail, password, email_confirm: true });
  const adminId = adminData.user.id;
  const serialUserId = serialData.user.id;
  const attUserId = attData.user.id;
  const streakUserId = streakData.user.id;
  const disabledUserId = disabledData.user.id;

  await admin.from('profiles').upsert([
    { id: adminId, email: adminEmail, full_name: 'PromoTestAdmin', role: 'admin' },
    { id: serialUserId, email: memberSerialEmail, full_name: 'PromoTestSerial', role: 'member' },
    { id: attUserId, email: memberAttendanceEmail, full_name: 'PromoTestAtt', role: 'member' },
    { id: streakUserId, email: memberStreakEmail, full_name: 'PromoTestStreak', role: 'member' },
    { id: disabledUserId, email: memberDisabledEmail, full_name: 'PromoTestDisabled', role: 'member' }
  ]);

  const adminToken = await loginAs(adminEmail, password);
  const serialToken = await loginAs(memberSerialEmail, password);
  const attToken = await loginAs(memberAttendanceEmail, password);
  const streakToken = await loginAs(memberStreakEmail, password);
  const disabledToken = await loginAs(memberDisabledEmail, password);
  assert(adminToken && serialToken && attToken && streakToken && disabledToken, '테스트 계정 5개 로그인 성공');

  // ============================================
  // 🎫 시리얼 쿠폰
  // ============================================
  const batchName = `테스트캠페인-${ts}`;

  const noAuthGenRes = await fetch(`${API}/api/admin/serial-coupons/generate`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ batch_name: batchName, reward_mileage: 500, count: 3 })
  });
  assert(noAuthGenRes.status === 401, `인증 없이 시리얼 코드 생성 시도 시 401 (실제: ${noAuthGenRes.status})`);

  const memberGenRes = await fetch(`${API}/api/admin/serial-coupons/generate`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${serialToken}` },
    body: JSON.stringify({ batch_name: batchName, reward_mileage: 500, count: 3 })
  });
  assert(memberGenRes.status === 403, `일반회원 권한으로 시리얼 코드 생성 시도 시 403 (실제: ${memberGenRes.status})`);

  const genRes = await fetch(`${API}/api/admin/serial-coupons/generate`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ batch_name: batchName, reward_mileage: 500, count: 3 })
  });
  const genJson = await genRes.json();
  assert(genRes.status === 201 && genJson.data.length === 3, `관리자 권한으로 시리얼 코드 3개 생성 성공 (실제 생성 개수: ${genJson.data?.length})`);
  const generatedCodes = genJson.data.map(c => c.code);

  const batchesRes = await fetch(`${API}/api/admin/serial-coupons/batches`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const batchesJson = await batchesRes.json();
  const myBatch = batchesJson.data.find(b => b.batch_name === batchName);
  assert(!!myBatch && myBatch.total === 3 && myBatch.redeemed === 0, `배치 목록 조회 시 방금 생성한 배치가 total=3, redeemed=0으로 보임 (실제: total=${myBatch?.total}, redeemed=${myBatch?.redeemed})`);

  const codesRes = await fetch(`${API}/api/admin/serial-coupons?batch_name=${encodeURIComponent(batchName)}`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const codesJson = await codesRes.json();
  assert(codesJson.data.length === 3, `배치 코드 목록 조회 시 정확히 3개 코드 반환 (실제: ${codesJson.data.length})`);

  const notFoundRedeemRes = await fetch(`${API}/api/serial-coupons/redeem`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${serialToken}` },
    body: JSON.stringify({ code: 'WITH-NONE-XXXX' })
  });
  assert(notFoundRedeemRes.status === 404, `존재하지 않는 코드 등록 시도 시 404 (실제: ${notFoundRedeemRes.status})`);

  const redeemRes = await fetch(`${API}/api/serial-coupons/redeem`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${serialToken}` },
    body: JSON.stringify({ code: generatedCodes[0] })
  });
  const redeemJson = await redeemRes.json();
  assert(redeemRes.status === 200 && redeemJson.data.reward_mileage === 500 && redeemJson.data.new_balance === 500, `회원이 코드 1개 등록 성공 + 마일리지 500 지급 확인 (실제 잔액: ${redeemJson.data?.new_balance})`);

  const redeemAgainRes = await fetch(`${API}/api/serial-coupons/redeem`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${serialToken}` },
    body: JSON.stringify({ code: generatedCodes[0] })
  });
  assert(redeemAgainRes.status === 409, `같은 코드를 다시 등록 시도하면 409 (실제: ${redeemAgainRes.status})`);

  const { data: expiredCoupon } = await admin.from('serial_coupons_with').insert([{
    batch_name: `만료테스트-${ts}`, code: `WITH-EXPR-${ts}`.slice(0, 20), reward_mileage: 100,
    expires_at: new Date(Date.now() - 86400000).toISOString(), created_by: adminId
  }]).select().single();
  const expiredRedeemRes = await fetch(`${API}/api/serial-coupons/redeem`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${serialToken}` },
    body: JSON.stringify({ code: expiredCoupon.code })
  });
  assert(expiredRedeemRes.status === 400, `유효기간이 지난 코드 등록 시도 시 400 (실제: ${expiredRedeemRes.status})`);

  const unusedCodeId = codesJson.data.find(c => c.code === generatedCodes[1]).id;
  const deleteUnusedRes = await fetch(`${API}/api/admin/serial-coupons/${unusedCodeId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${adminToken}` } });
  assert(deleteUnusedRes.status === 200, `관리자가 미사용 코드 삭제 성공 (실제: ${deleteUnusedRes.status})`);

  const redeemedCodeId = codesJson.data.find(c => c.code === generatedCodes[0]).id;
  const deleteRedeemedRes = await fetch(`${API}/api/admin/serial-coupons/${redeemedCodeId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${adminToken}` } });
  assert(deleteRedeemedRes.status === 400, `관리자가 이미 사용된 코드 삭제 시도 시 400 차단 (실제: ${deleteRedeemedRes.status})`);

  // ============================================
  // 📅 출석체크 이벤트
  // ============================================
  const publicSettingsRes = await fetch(`${API}/api/settings/attendance-event`);
  const publicSettingsJson = await publicSettingsRes.json();
  assert(publicSettingsRes.status === 200 && publicSettingsJson.success, `공개 출석체크 설정 조회(인증불필요) 성공 (실제: ${publicSettingsRes.status})`);

  const memberPatchRes = await fetch(`${API}/api/admin/settings/attendance-event`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${attToken}` },
    body: JSON.stringify({ is_active: true, daily_reward: 20, streak_bonus_days: 3, streak_bonus_reward: 100 })
  });
  assert(memberPatchRes.status === 403, `일반회원 권한으로 출석체크 설정 변경 시도 시 403 (실제: ${memberPatchRes.status})`);

  const adminPatchRes = await fetch(`${API}/api/admin/settings/attendance-event`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ is_active: true, daily_reward: 20, streak_bonus_days: 3, streak_bonus_reward: 100 })
  });
  assert(adminPatchRes.status === 200, `관리자 권한으로 출석체크 설정 변경 성공 (일 20 / 3일마다 +100) (실제: ${adminPatchRes.status})`);

  const statusBeforeRes = await fetch(`${API}/api/attendance/status`, { headers: { Authorization: `Bearer ${attToken}` } });
  const statusBeforeJson = await statusBeforeRes.json();
  assert(statusBeforeJson.data.checked_in_today === false && statusBeforeJson.data.current_streak === 0, `출석 전 상태 조회 시 checked_in_today=false, current_streak=0 (실제: ${statusBeforeJson.data.checked_in_today}, ${statusBeforeJson.data.current_streak})`);

  const firstCheckinRes = await fetch(`${API}/api/attendance/checkin`, { method: 'POST', headers: { Authorization: `Bearer ${attToken}` } });
  const firstCheckinJson = await firstCheckinRes.json();
  assert(firstCheckinRes.status === 200 && firstCheckinJson.data.streak_count === 1 && firstCheckinJson.data.reward_mileage === 20 && firstCheckinJson.data.bonus_mileage === 0, `첫 출석체크 성공 (streak=1, 보상 20, 보너스 0) (실제: streak=${firstCheckinJson.data?.streak_count}, reward=${firstCheckinJson.data?.reward_mileage}, bonus=${firstCheckinJson.data?.bonus_mileage})`);

  const secondCheckinRes = await fetch(`${API}/api/attendance/checkin`, { method: 'POST', headers: { Authorization: `Bearer ${attToken}` } });
  assert(secondCheckinRes.status === 400, `같은 날 다시 출석체크 시도 시 400 (실제: ${secondCheckinRes.status})`);

  // 어제 이미 연속 2일째 출석한 것으로 미리 심어두고, 오늘 출석 시 3일 연속(보너스 기준일의 배수)이 되는지 검증
  await admin.from('attendance_checkins_with').insert([{
    user_id: streakUserId, checkin_date: yesterdayStr(), streak_count: 2, reward_mileage: 20, bonus_mileage: 0
  }]);
  const streakStatusRes = await fetch(`${API}/api/attendance/status`, { headers: { Authorization: `Bearer ${streakToken}` } });
  const streakStatusJson = await streakStatusRes.json();
  assert(streakStatusJson.data.current_streak === 2 && streakStatusJson.data.checked_in_today === false, `어제까지 연속 2일 출석한 회원의 사전 상태 확인 (실제 streak: ${streakStatusJson.data.current_streak})`);

  const streakCheckinRes = await fetch(`${API}/api/attendance/checkin`, { method: 'POST', headers: { Authorization: `Bearer ${streakToken}` } });
  const streakCheckinJson = await streakCheckinRes.json();
  assert(
    streakCheckinRes.status === 200 && streakCheckinJson.data.streak_count === 3 && streakCheckinJson.data.bonus_mileage === 100 && streakCheckinJson.data.total_awarded === 120,
    `연속 3일째 출석 시 보너스 100 포함 총 120 마일리지 지급 확인 (실제: streak=${streakCheckinJson.data?.streak_count}, bonus=${streakCheckinJson.data?.bonus_mileage}, total=${streakCheckinJson.data?.total_awarded})`
  );

  const streakBalanceRes = await fetch(`${API}/api/me/mileage-balance`, { headers: { Authorization: `Bearer ${streakToken}` } });
  const streakBalanceJson = await streakBalanceRes.json();
  assert(streakBalanceJson.data.balance === 120, `연속출석 보너스 회원의 마일리지 잔액이 정확히 120으로 반영됨 (실제: ${streakBalanceJson.data.balance})`);

  const disableRes = await fetch(`${API}/api/admin/settings/attendance-event`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ is_active: false, daily_reward: 20, streak_bonus_days: 3, streak_bonus_reward: 100 })
  });
  assert(disableRes.status === 200, `관리자가 출석체크 이벤트를 비활성화 (실제: ${disableRes.status})`);

  const disabledCheckinRes = await fetch(`${API}/api/attendance/checkin`, { method: 'POST', headers: { Authorization: `Bearer ${disabledToken}` } });
  assert(disabledCheckinRes.status === 400, `이벤트 비활성화 상태에서는 출석체크 시도 시 400 차단 (실제: ${disabledCheckinRes.status})`);

  const reenableRes = await fetch(`${API}/api/admin/settings/attendance-event`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ is_active: true, daily_reward: 20, streak_bonus_days: 3, streak_bonus_reward: 100 })
  });
  assert(reenableRes.status === 200, `다시 활성화 성공 (실제: ${reenableRes.status})`);

  const disabledCheckinRetryRes = await fetch(`${API}/api/attendance/checkin`, { method: 'POST', headers: { Authorization: `Bearer ${disabledToken}` } });
  const disabledCheckinRetryJson = await disabledCheckinRetryRes.json();
  assert(disabledCheckinRetryRes.status === 200 && disabledCheckinRetryJson.data.streak_count === 1, `다시 활성화된 뒤에는 정상적으로 출석체크가 처리됨 (실제: ${disabledCheckinRetryRes.status}, streak=${disabledCheckinRetryJson.data?.streak_count})`);

  // 정리
  await admin.from('serial_coupons_with').delete().eq('batch_name', batchName);
  await admin.from('serial_coupons_with').delete().eq('batch_name', `만료테스트-${ts}`);
  await admin.from('attendance_checkins_with').delete().in('user_id', [attUserId, streakUserId, disabledUserId]);
  await admin.from('mileage_adjustments_with').delete().in('user_id', [serialUserId, attUserId, streakUserId, disabledUserId]);
  await admin.from('profiles').delete().in('id', [adminId, serialUserId, attUserId, streakUserId, disabledUserId]);
  await admin.auth.admin.deleteUser(adminId);
  await admin.auth.admin.deleteUser(serialUserId);
  await admin.auth.admin.deleteUser(attUserId);
  await admin.auth.admin.deleteUser(streakUserId);
  await admin.auth.admin.deleteUser(disabledUserId);
  console.log('정리 완료: 시리얼쿠폰/출석기록/마일리지원장/계정 삭제');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
