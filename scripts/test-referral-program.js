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

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';

  // 테스트 시작 전, 현재 referral_settings 상태를 백업해두고 테스트가 끝나면 그대로 복구한다
  const { data: settingsBackupRow } = await admin.from('platform_settings').select('*').eq('key', 'referral_settings').maybeSingle();

  // ============================================
  // 0) 계정 준비
  // - 관리자 계정만 profiles를 미리 upsert해둔다(기존 관행). referrer/referred/solo 계정은
  //   "실제 회원가입"을 재현하기 위해 일부러 profiles를 만들지 않고 auth 유저만 생성한다 -
  //   이 상태에서 인증된 API를 처음 호출했을 때 서버(authenticate 미들웨어의 ensureProfileExists)가
  //   profiles 행을 자동으로 만들어주는지가 이번 세그먼트에서 고친 핵심 버그의 검증 포인트다.
  // ============================================
  const adminEmail = `test-refadmin-${ts}@withplus-test.local`;
  const { data: adminUser } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
  const adminId = adminUser.user.id;
  await admin.from('profiles').upsert([{ id: adminId, email: adminEmail, full_name: 'RefTestAdmin', role: 'admin' }]);
  const adminToken = await loginAs(adminEmail, password);

  const referrerEmail = `test-refreferrer-${ts}@withplus-test.local`;
  const { data: referrerUser } = await admin.auth.admin.createUser({ email: referrerEmail, password, email_confirm: true });
  const referrerId = referrerUser.user.id;
  const referrerToken = await loginAs(referrerEmail, password);

  const referredEmail = `test-refreferred-${ts}@withplus-test.local`;
  const { data: referredUser } = await admin.auth.admin.createUser({ email: referredEmail, password, email_confirm: true });
  const referredId = referredUser.user.id;
  const referredToken = await loginAs(referredEmail, password);

  const soloEmail = `test-refsolo-${ts}@withplus-test.local`;
  const { data: soloUser } = await admin.auth.admin.createUser({ email: soloEmail, password, email_confirm: true });
  const soloId = soloUser.user.id;
  const soloToken = await loginAs(soloEmail, password);

  const allTestUserIds = [adminId, referrerId, referredId, soloId];

  // ============================================
  // 1) 프로필 자동 생성 (이번에 고친 핵심 버그) - 인증 필요 없는 회원가입 직후, profiles 행이 없는 상태에서
  //    인증된 API를 처음 호출하면 서버가 자동으로 profiles를 만들어주는지 확인
  // ============================================
  const { data: beforeProfile } = await admin.from('profiles').select('id').eq('id', referrerId).maybeSingle();
  assert(!beforeProfile, '가입 직후에는 profiles 행이 아직 없음(실제 회원가입 흐름 재현)');

  const noAuthReferralRes = await fetch(`${API}/api/me/referral`, { headers: { Authorization: 'Bearer ' + referrerToken } });
  assert(noAuthReferralRes.status === 200, '인증된 첫 API 요청이 정상 처리됨');

  const { data: afterProfile } = await admin.from('profiles').select('id, role, member_type').eq('id', referrerId).maybeSingle();
  assert(!!afterProfile && afterProfile.role === 'member' && afterProfile.member_type === 'general', '인증 미들웨어가 profiles 행을 자동 생성함(회원가입 시 트리거가 없는 문제의 근본 수정 검증)');

  // 나머지 테스트 계정들도 각각 한 번씩 인증 요청을 보내 profiles를 생성해둔다
  await fetch(`${API}/api/me/referral`, { headers: { Authorization: 'Bearer ' + referredToken } });
  await fetch(`${API}/api/me/referral`, { headers: { Authorization: 'Bearer ' + soloToken } });

  // ============================================
  // 2) 공개 설정 엔드포인트는 enabled 여부만 노출 (초기값: 비활성화)
  // ============================================
  const publicOffRes = await fetch(`${API}/api/settings/referral-program`);
  const publicOffJson = await publicOffRes.json();
  assert(publicOffJson.success, '공개 추천인 프로그램 상태 조회 성공');

  // ============================================
  // 3) 관리자 설정 CRUD
  // ============================================
  const nonAdminPatchRes = await fetch(`${API}/api/admin/settings/referral-program`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + referrerToken },
    body: JSON.stringify({ enabled: true, referrer_reward: 3000, referred_reward: 3000 })
  });
  assert(nonAdminPatchRes.status === 403, '일반 회원은 추천인 프로그램 설정을 변경할 수 없음(403)');

  const enablePatchRes = await fetch(`${API}/api/admin/settings/referral-program`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + adminToken },
    body: JSON.stringify({ enabled: true, referrer_reward: 3000, referred_reward: 2000 })
  });
  const enablePatchJson = await enablePatchRes.json();
  assert(enablePatchRes.ok && enablePatchJson.success && enablePatchJson.data.enabled === true, '관리자가 추천인 프로그램을 활성화하고 보상 금액을 저장할 수 있음');

  const publicOnRes = await fetch(`${API}/api/settings/referral-program`);
  const publicOnJson = await publicOnRes.json();
  assert(publicOnJson.data.enabled === true && Object.keys(publicOnJson.data).length === 1, '활성화 후에도 공개 엔드포인트는 enabled만 노출하고 보상 금액은 유출하지 않음');

  const adminGetRes = await fetch(`${API}/api/admin/settings/referral-program`, { headers: { Authorization: 'Bearer ' + adminToken } });
  const adminGetJson = await adminGetRes.json();
  assert(adminGetJson.data.referrer_reward === 3000 && adminGetJson.data.referred_reward === 2000, '관리자 조회에는 실제 보상 금액이 정확히 내려옴');
  assert(adminGetJson.stats && typeof adminGetJson.stats.total_referrals === 'number', '관리자 조회에 누적 통계가 함께 제공됨');

  // ============================================
  // 4) 추천코드 조회 + 등록 유효성 검증
  // ============================================
  const referrerCodeRes = await fetch(`${API}/api/me/referral`, { headers: { Authorization: 'Bearer ' + referrerToken } });
  const referrerCodeJson = await referrerCodeRes.json();
  const referrerCode = referrerCodeJson.data.referral_code;
  assert(!!referrerCode && referrerCode.length === 8, '추천인의 추천코드가 8자리로 발급됨');
  assert(referrerCodeJson.data.referral_link.includes(referrerCode), '추천 링크에 추천코드가 포함되어 있음');

  const invalidCodeRes = await fetch(`${API}/api/me/apply-referral`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + referredToken },
    body: JSON.stringify({ code: 'ZZZZZZZZ' })
  });
  assert(invalidCodeRes.status === 404, '존재하지 않는 추천코드는 404로 거부됨');

  const selfReferralRes = await fetch(`${API}/api/me/apply-referral`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + referrerToken },
    body: JSON.stringify({ code: referrerCode })
  });
  assert(selfReferralRes.status === 400, '본인의 추천코드는 등록할 수 없음(400)');

  const applyRes = await fetch(`${API}/api/me/apply-referral`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + referredToken },
    body: JSON.stringify({ code: referrerCode })
  });
  assert(applyRes.status === 200, '유효한 추천코드 등록 성공');

  const { data: referralRow } = await admin.from('referrals_with').select('*').eq('referred_id', referredId).maybeSingle();
  assert(!!referralRow && referralRow.status === 'pending' && referralRow.referrer_id === referrerId, 'referrals_with에 pending 상태로 관계가 정확히 기록됨');

  const dupApplyRes = await fetch(`${API}/api/me/apply-referral`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + referredToken },
    body: JSON.stringify({ code: referrerCode })
  });
  assert(dupApplyRes.status === 409, '이미 추천인이 등록된 회원은 중복 등록할 수 없음(409)');

  // ============================================
  // 5) 첫 주문 완료 시 양쪽에 마일리지 지급
  // ============================================
  const { data: category } = await admin.from('categories').select('db_category').eq('is_active', true).limit(1).maybeSingle();
  const { data: product } = await admin.from('products_with').insert({
    name: `추천인테스트상품${ts}`, slug: `referral-test-${ts}`, description: '추천인 프로그램 테스트용 상품입니다.',
    price: 20000, stock: 10, category: category ? category.db_category : 'etc', supplier_id: adminId, status: 'active'
  }).select().single();

  const referrerBalanceBeforeRes = await fetch(`${API}/api/me/mileage-balance`, { headers: { Authorization: 'Bearer ' + referrerToken } });
  const referrerBalanceBefore = (await referrerBalanceBeforeRes.json()).data.balance;

  const firstOrderRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + referredToken },
    body: JSON.stringify({
      items: [{ product_id: product.id, name: product.name, price: product.price, quantity: 1 }],
      shipping_address: { name: '테스터', phone: '01000000000', address: '서울시 테스트구' },
      payment_method: 'pending'
    })
  });
  const firstOrderJson = await firstOrderRes.json();
  assert(firstOrderRes.ok && firstOrderJson.success, '피추천인의 첫 주문이 정상 생성됨');
  const firstOrder = firstOrderJson.data;

  const { data: referralRowAfterOrder } = await admin.from('referrals_with').select('*').eq('referred_id', referredId).maybeSingle();
  assert(!!referralRowAfterOrder && referralRowAfterOrder.status === 'rewarded' && !!referralRowAfterOrder.rewarded_at, '첫 주문 완료 후 추천 관계 상태가 rewarded로 전환됨');

  const { data: referrerAdjustments } = await admin.from('mileage_adjustments_with').select('*').eq('user_id', referrerId).eq('reason', 'referral_referrer');
  assert((referrerAdjustments || []).length === 1 && Number(referrerAdjustments[0].amount) === 3000, '추천인에게 설정된 금액(3000) 그대로 마일리지가 지급됨');

  const { data: referredAdjustments } = await admin.from('mileage_adjustments_with').select('*').eq('user_id', referredId).eq('reason', 'referral_referred');
  assert((referredAdjustments || []).length === 1 && Number(referredAdjustments[0].amount) === 2000, '신규 회원에게 설정된 금액(2000) 그대로 마일리지가 지급됨');

  const referrerBalanceAfterRes = await fetch(`${API}/api/me/mileage-balance`, { headers: { Authorization: 'Bearer ' + referrerToken } });
  const referrerBalanceAfter = (await referrerBalanceAfterRes.json()).data.balance;
  assert(referrerBalanceAfter === referrerBalanceBefore + 3000, '추천인의 마일리지 잔액에 정확히 반영됨');

  const referrerStatsRes = await fetch(`${API}/api/me/referral`, { headers: { Authorization: 'Bearer ' + referrerToken } });
  const referrerStatsJson = await referrerStatsRes.json();
  assert(referrerStatsJson.data.rewarded_referrals === 1 && referrerStatsJson.data.total_earned_mileage === 3000, '추천인 본인 화면에서도 보상 완료 건수/누적 적립액이 정확히 조회됨');

  // ============================================
  // 6) 두 번째 주문에서는 중복 지급되지 않음
  // ============================================
  const secondOrderRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + referredToken },
    body: JSON.stringify({
      items: [{ product_id: product.id, name: product.name, price: product.price, quantity: 1 }],
      shipping_address: { name: '테스터', phone: '01000000000', address: '서울시 테스트구' },
      payment_method: 'pending'
    })
  });
  const secondOrderJson = await secondOrderRes.json();
  assert(secondOrderRes.ok && secondOrderJson.success, '피추천인의 두 번째 주문도 정상 생성됨');

  const { data: referrerAdjustmentsAfter2nd } = await admin.from('mileage_adjustments_with').select('*').eq('user_id', referrerId).eq('reason', 'referral_referrer');
  assert((referrerAdjustmentsAfter2nd || []).length === 1, '재구매(두 번째 주문)에서는 추천 보상이 중복 지급되지 않음');

  // ============================================
  // 7) 비활성화 상태에서는 이미 등록된 pending 관계가 있어도 보상하지 않음
  // ============================================
  const applySoloRes = await fetch(`${API}/api/me/apply-referral`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + soloToken },
    body: JSON.stringify({ code: referrerCode })
  });
  assert(applySoloRes.status === 200, '두 번째 피추천인(solo)도 추천코드 등록 성공');

  await fetch(`${API}/api/admin/settings/referral-program`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + adminToken },
    body: JSON.stringify({ enabled: false, referrer_reward: 3000, referred_reward: 2000 })
  });

  const { data: product2 } = await admin.from('products_with').insert({
    name: `추천인테스트상품2-${ts}`, slug: `referral-test2-${ts}`, description: '추천인 프로그램 비활성화 테스트용 상품입니다.',
    price: 10000, stock: 10, category: category ? category.db_category : 'etc', supplier_id: adminId, status: 'active'
  }).select().single();

  const soloOrderRes = await fetch(`${API}/api/orders`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + soloToken },
    body: JSON.stringify({
      items: [{ product_id: product2.id, name: product2.name, price: product2.price, quantity: 1 }],
      shipping_address: { name: '테스터', phone: '01000000000', address: '서울시 테스트구' },
      payment_method: 'pending'
    })
  });
  const soloOrderJson = await soloOrderRes.json();
  assert(soloOrderRes.ok && soloOrderJson.success, '비활성화 상태에서도 주문 생성 자체는 정상 처리됨');

  const { data: soloReferralRow } = await admin.from('referrals_with').select('*').eq('referred_id', soloId).maybeSingle();
  assert(!!soloReferralRow && soloReferralRow.status === 'pending', '프로그램이 비활성화된 동안에는 첫 주문을 완료해도 pending 상태 그대로 유지되고 보상되지 않음(설정 확인 후 정직하게 지급)');

  const { data: referrerAdjustmentsFinal } = await admin.from('mileage_adjustments_with').select('*').eq('user_id', referrerId).eq('reason', 'referral_referrer');
  assert((referrerAdjustmentsFinal || []).length === 1, '비활성화 상태에서는 추가 마일리지가 지급되지 않음(여전히 1건)');

  // ============================================
  // 8) 관리자 모듈 카탈로그에 노출됨
  // ============================================
  const modulesRes = await fetch(`${API}/api/admin/modules`, { headers: { Authorization: 'Bearer ' + adminToken } });
  const modulesJson = await modulesRes.json();
  const moduleKeys = (modulesJson.data || []).map(m => m.key);
  assert(moduleKeys.includes('referral_program'), '관리자 "기능 모듈" 카탈로그에 추천인 프로그램이 노출됨');

  // ============================================
  // 9) 인증 없이는 내 추천 정보/등록 API에 접근할 수 없음
  // ============================================
  const noAuthMeRes = await fetch(`${API}/api/me/referral`);
  assert(noAuthMeRes.status === 401, '로그인 없이는 내 추천 정보 조회가 거부됨(401)');
  const noAuthApplyRes = await fetch(`${API}/api/me/apply-referral`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: 'ABCDEFGH' }) });
  assert(noAuthApplyRes.status === 401, '로그인 없이는 추천코드 등록이 거부됨(401)');

  // ============================================
  // 정리
  // ============================================
  const { data: allOrders } = await admin.from('orders_with').select('id').in('user_id', [referredId, soloId]);
  const orderIds = (allOrders || []).map(o => o.id);
  await admin.from('order_payments').delete().in('order_id', orderIds);
  await admin.from('orders_with').delete().in('id', orderIds);
  await admin.from('products_with').delete().in('id', [product.id, product2.id]);
  await admin.from('referrals_with').delete().in('referred_id', [referredId, soloId]);
  await admin.from('referral_profiles_with').delete().in('user_id', allTestUserIds);
  await admin.from('mileage_adjustments_with').delete().in('user_id', allTestUserIds);
  await admin.from('profiles').delete().in('id', allTestUserIds);
  for (const id of allTestUserIds) await admin.auth.admin.deleteUser(id);

  if (settingsBackupRow) {
    await admin.from('platform_settings').update({ value: settingsBackupRow.value, updated_at: settingsBackupRow.updated_at, updated_by: settingsBackupRow.updated_by }).eq('key', 'referral_settings');
  } else {
    await admin.from('platform_settings').delete().eq('key', 'referral_settings');
  }
  console.log('정리 완료: 테스트 상품/주문/추천관계/마일리지조정/계정 삭제 및 referral_settings 원상복구');

  console.log(`\n총 ${pass + fail}건 중 ${pass}건 성공, ${fail}건 실패`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
