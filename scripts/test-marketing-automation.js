// 마케팅자동화(세그먼트 캠페인 + 등급유지/구매마일스톤 자동 쿠폰)를 검증한다.
// - 세그먼트 매칭(누적구매액 정확 매칭으로 테스트 계정만 골라내기), 캠페인 발송 시 target_user_ids로
//   대상 회원만 쿠폰을 쓸 수 있게 제한되는지(evaluateCouponEligibility), 캠페인 이력, 자동 쿠폰 규칙
//   CRUD + 권한분리, run-now 실행 시 실제로 발급되고 같은 규칙을 다시 돌려도 같은 회원에게 중복
//   발급되지 않는지(coupon_automation_issuances_with 유니크 제약 기반 멱등성)를 확인한다.
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
  const createdUserIds = [];
  const createdCouponIds = [];
  const createdCampaignIds = [];
  const createdRuleIds = [];

  try {
    // ============================================
    // 0) 계정/데이터 준비
    // ============================================
    const adminEmail = `test-mkt-admin-${ts}@withplus-test.local`;
    const { data: adminUser } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
    createdUserIds.push(adminUser.user.id);
    await admin.from('profiles').upsert([{ id: adminUser.user.id, email: adminEmail, full_name: '마케팅테스트관리자', role: 'admin' }]);
    const adminToken = await loginAs(adminEmail, password);

    const memberEmail = `test-mkt-member-${ts}@withplus-test.local`;
    const { data: memberUser } = await admin.auth.admin.createUser({ email: memberEmail, password, email_confirm: true });
    createdUserIds.push(memberUser.user.id);
    await admin.from('profiles').upsert([{ id: memberUser.user.id, email: memberEmail, full_name: '일반회원(권한테스트용)', role: 'member' }]);
    const memberToken = await loginAs(memberEmail, password);

    // 세그먼트를 다른 실사용자와 절대 겹치지 않도록, 이번 실행 시각(ts) 기반의 매우 특이한 누적구매액으로
    // "고액구매 회원(userHigh)"을 만든다 - minTotalSpent=maxTotalSpent를 이 값으로 걸면 이 회원 1명만 매칭된다.
    const uniqueSpent = 1000000 + (ts % 900000);
    const userHighEmail = `test-mkt-high-${ts}@withplus-test.local`;
    const { data: userHigh } = await admin.auth.admin.createUser({ email: userHighEmail, password, email_confirm: true });
    createdUserIds.push(userHigh.user.id);
    await admin.from('profiles').upsert([{ id: userHigh.user.id, email: userHighEmail, full_name: '고액구매테스트', role: 'member' }]);
    const { data: highOrder } = await admin.from('orders_with').insert([
      { order_number: `ORD-MKT-HIGH-${ts}`, user_id: userHigh.user.id, items: [{ product_id: 'test', name: '테스트상품', price: uniqueSpent, quantity: 1 }], total_price: uniqueSpent, final_price: uniqueSpent, status: 'delivered', payment_method: 'test' }
    ]).select();
    assert(highOrder && highOrder.length === 1, '고액구매 테스트 회원의 주문(누적구매액 특정값) 생성 성공');

    // 캠페인 대상에서 제외되어야 하는(타겟팅 안 된) 제3의 회원 - 쿠폰 코드를 알아도 못 써야 함
    const outsiderEmail = `test-mkt-outsider-${ts}@withplus-test.local`;
    const { data: outsider } = await admin.auth.admin.createUser({ email: outsiderEmail, password, email_confirm: true });
    createdUserIds.push(outsider.user.id);
    await admin.from('profiles').upsert([{ id: outsider.user.id, email: outsiderEmail, full_name: '타겟외회원', role: 'member' }]);
    const outsiderToken = await loginAs(outsiderEmail, password);

    // 구매마일스톤(정확히 3번째 구매) 테스트용 - 소액 주문 3건
    const userMilestoneEmail = `test-mkt-milestone-${ts}@withplus-test.local`;
    const { data: userMilestone } = await admin.auth.admin.createUser({ email: userMilestoneEmail, password, email_confirm: true });
    createdUserIds.push(userMilestone.user.id);
    await admin.from('profiles').upsert([{ id: userMilestone.user.id, email: userMilestoneEmail, full_name: '마일스톤테스트', role: 'member' }]);
    await admin.from('orders_with').insert([1, 2, 3].map(n => ({
      order_number: `ORD-MKT-MILE-${n}-${ts}`, user_id: userMilestone.user.id,
      items: [{ product_id: 'test', name: '테스트상품', price: 10000, quantity: 1 }],
      total_price: 10000, final_price: 10000, status: 'delivered', payment_method: 'test'
    })));

    // 등급유지 자동 쿠폰 테스트용 - 등급 기준 중 가장 높은 등급의 문턱값보다 확실히 높은 금액으로 1건 구매
    const gradesRes = await fetch(`${API}/api/settings/member-grades`);
    const gradesJson = await gradesRes.json();
    const grades = gradesJson.data.slice().sort((a, b) => a.min_spent - b.min_spent);
    const topGrade = grades[grades.length - 1];
    const userGradeEmail = `test-mkt-grade-${ts}@withplus-test.local`;
    const { data: userGrade } = await admin.auth.admin.createUser({ email: userGradeEmail, password, email_confirm: true });
    createdUserIds.push(userGrade.user.id);
    await admin.from('profiles').upsert([{ id: userGrade.user.id, email: userGradeEmail, full_name: '등급테스트', role: 'member' }]);
    await admin.from('orders_with').insert([
      { order_number: `ORD-MKT-GRADE-${ts}`, user_id: userGrade.user.id, items: [{ product_id: 'test', name: '테스트상품', price: topGrade.min_spent + 500000, quantity: 1 }], total_price: topGrade.min_spent + 500000, final_price: topGrade.min_spent + 500000, status: 'delivered', payment_method: 'test' }
    ]);

    // ============================================
    // 1) 세그먼트 미리보기 - 권한분리 + 정확한 매칭
    // ============================================
    const previewNoAuth = await fetch(`${API}/api/admin/marketing/segment-preview`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
    assert(previewNoAuth.status === 401, `인증 없이 세그먼트 미리보기 시도 시 401 (실제: ${previewNoAuth.status})`);

    const previewMemberRes = await fetch(`${API}/api/admin/marketing/segment-preview`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` }, body: JSON.stringify({})
    });
    assert(previewMemberRes.status === 403, `일반 회원은 세그먼트 미리보기 접근 불가 (실제: ${previewMemberRes.status})`);

    const previewRes = await fetch(`${API}/api/admin/marketing/segment-preview`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ minTotalSpent: uniqueSpent, maxTotalSpent: uniqueSpent })
    });
    const previewJson = await previewRes.json();
    assert(previewRes.status === 200 && previewJson.success, `관리자는 세그먼트 미리보기 조회 성공 (실제: ${previewRes.status})`);
    assert(previewJson.data.matchedCount === 1, `누적구매액 정확 매칭으로 테스트 회원 1명만 매칭됨 (실제: ${previewJson.data.matchedCount}명)`);
    assert(previewJson.data.sample[0]?.email === userHighEmail, '미리보기 샘플에 고액구매 테스트 회원이 정확히 포함됨');

    // ============================================
    // 2) 캠페인 발송 - 유효성 검사 + target_user_ids 발급
    // ============================================
    const noNameRes = await fetch(`${API}/api/admin/marketing/campaigns`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ segment_filter: {}, coupon: { label: 'x', discount_type: 'fixed', discount_value: 1000 } })
    });
    assert(noNameRes.status === 400, `캠페인 이름 없이 발송 시도 시 400 (실제: ${noNameRes.status})`);

    const badCouponRes = await fetch(`${API}/api/admin/marketing/campaigns`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ name: '테스트캠페인', segment_filter: { minTotalSpent: uniqueSpent, maxTotalSpent: uniqueSpent }, coupon: { label: 'x' } })
    });
    assert(badCouponRes.status === 400, `쿠폰 정보(discount_type/discount_value 누락) 불완전하면 400 (실제: ${badCouponRes.status})`);

    const noMatchRes = await fetch(`${API}/api/admin/marketing/campaigns`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ name: '테스트캠페인-매칭없음', segment_filter: { minTotalSpent: 999999999999 }, coupon: { label: 'x', discount_type: 'fixed', discount_value: 1000 } })
    });
    assert(noMatchRes.status === 400, `조건에 맞는 회원이 없으면 400 (실제: ${noMatchRes.status})`);

    const memberCampaignRes = await fetch(`${API}/api/admin/marketing/campaigns`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
      body: JSON.stringify({ name: '권한테스트', segment_filter: {}, coupon: { label: 'x', discount_type: 'fixed', discount_value: 1000 } })
    });
    assert(memberCampaignRes.status === 403, `일반 회원은 캠페인 발송 불가 (실제: ${memberCampaignRes.status})`);

    const campaignRes = await fetch(`${API}/api/admin/marketing/campaigns`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({
        name: `테스트캠페인-${ts}`,
        segment_filter: { minTotalSpent: uniqueSpent, maxTotalSpent: uniqueSpent },
        coupon: { label: '테스트캠페인쿠폰', discount_type: 'fixed', discount_value: 5000, min_order_amount: 0, valid_days: 30 }
      })
    });
    const campaignJson = await campaignRes.json();
    assert(campaignRes.status === 201 && campaignJson.success, `유효한 조건으로 캠페인 발송 성공 (실제: ${campaignRes.status})`);
    assert(campaignJson.data.matchedCount === 1, `캠페인 대상 회원이 정확히 1명으로 집계됨 (실제: ${campaignJson.data.matchedCount})`);
    const campaignCoupon = campaignJson.data.coupon;
    createdCouponIds.push(campaignCoupon.id);
    createdCampaignIds.push(campaignJson.data.campaign.id);
    assert(Array.isArray(campaignCoupon.target_user_ids) && campaignCoupon.target_user_ids.length === 1 && campaignCoupon.target_user_ids[0] === userHigh.user.id, '발급된 쿠폰의 target_user_ids가 대상 회원 1명으로 정확히 제한됨');

    const { data: notifRows } = await admin.from('notifications_with').select('*').eq('user_id', userHigh.user.id).eq('type', 'marketing_coupon');
    assert(notifRows && notifRows.length >= 1, '캠페인 발송 시 대상 회원에게 알림이 생성됨');

    // ============================================
    // 3) 타겟 쿠폰 사용 제한 - 대상 회원만 사용 가능, 제3자는 코드를 알아도 사용 불가
    // ============================================
    const highValidateRes = await fetch(`${API}/api/coupons/validate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${await loginAs(userHighEmail, password)}` },
      body: JSON.stringify({ code: campaignCoupon.code, order_amount: 10000 })
    });
    const highValidateJson = await highValidateRes.json();
    assert(highValidateRes.status === 200 && highValidateJson.success && highValidateJson.data.discountAmount === 5000, `대상 회원은 캠페인 쿠폰을 정상 사용 가능 (실제: ${highValidateRes.status})`);

    const outsiderValidateRes = await fetch(`${API}/api/coupons/validate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${outsiderToken}` },
      body: JSON.stringify({ code: campaignCoupon.code, order_amount: 10000 })
    });
    const outsiderValidateJson = await outsiderValidateRes.json();
    assert(outsiderValidateRes.status === 400 && outsiderValidateJson.message === '본인에게 발급된 쿠폰이 아닙니다', `타겟팅 안 된 회원은 코드를 알아도 사용 불가 (실제: ${outsiderValidateRes.status}, ${outsiderValidateJson.message})`);

    // ============================================
    // 4) 캠페인 이력 조회 - 권한분리 + 방금 발송한 캠페인 포함 확인
    // ============================================
    const historyMemberRes = await fetch(`${API}/api/admin/marketing/campaigns`, { headers: { Authorization: `Bearer ${memberToken}` } });
    assert(historyMemberRes.status === 403, `일반 회원은 캠페인 이력 조회 불가 (실제: ${historyMemberRes.status})`);

    const historyRes = await fetch(`${API}/api/admin/marketing/campaigns`, { headers: { Authorization: `Bearer ${adminToken}` } });
    const historyJson = await historyRes.json();
    assert(historyRes.status === 200 && historyJson.data.some(c => c.id === campaignJson.data.campaign.id), '캠페인 이력에 방금 발송한 캠페인이 포함됨');

    // ============================================
    // 5) 자동 쿠폰 규칙 CRUD - 유효성 검사 + 권한분리
    // ============================================
    const badRuleTypeRes = await fetch(`${API}/api/admin/marketing/automation-rules`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ rule_type: 'invalid', rule_config: {}, coupon_template: { label: 'x', discount_type: 'fixed', discount_value: 1000 } })
    });
    assert(badRuleTypeRes.status === 400, `잘못된 rule_type이면 400 (실제: ${badRuleTypeRes.status})`);

    const missingGradeKeyRes = await fetch(`${API}/api/admin/marketing/automation-rules`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ rule_type: 'grade', rule_config: {}, coupon_template: { label: 'x', discount_type: 'fixed', discount_value: 1000 } })
    });
    assert(missingGradeKeyRes.status === 400, `등급유지 규칙에 grade_key가 없으면 400 (실제: ${missingGradeKeyRes.status})`);

    const missingMilestoneRes = await fetch(`${API}/api/admin/marketing/automation-rules`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ rule_type: 'purchase_milestone', rule_config: {}, coupon_template: { label: 'x', discount_type: 'fixed', discount_value: 1000 } })
    });
    assert(missingMilestoneRes.status === 400, `구매마일스톤 규칙에 order_count가 없으면 400 (실제: ${missingMilestoneRes.status})`);

    const memberRuleRes = await fetch(`${API}/api/admin/marketing/automation-rules`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
      body: JSON.stringify({ rule_type: 'grade', rule_config: { grade_key: topGrade.key }, coupon_template: { label: 'x', discount_type: 'fixed', discount_value: 1000 } })
    });
    assert(memberRuleRes.status === 403, `일반 회원은 자동 쿠폰 규칙 생성 불가 (실제: ${memberRuleRes.status})`);

    // ---- 구매마일스톤(정확히 3번째 구매) 규칙 ----
    const milestoneRuleRes = await fetch(`${API}/api/admin/marketing/automation-rules`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ rule_type: 'purchase_milestone', rule_config: { order_count: 3 }, coupon_template: { label: `마일스톤테스트-${ts}`, discount_type: 'fixed', discount_value: 2000, valid_days: 30 }, enabled: true })
    });
    const milestoneRuleJson = await milestoneRuleRes.json();
    assert(milestoneRuleRes.status === 201, `구매마일스톤 규칙 생성 성공 (실제: ${milestoneRuleRes.status})`);
    const milestoneRuleId = milestoneRuleJson.data.id;
    createdRuleIds.push(milestoneRuleId);

    const runNow1Res = await fetch(`${API}/api/admin/marketing/automation-rules/${milestoneRuleId}/run-now`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
    assert(runNow1Res.status === 200, `구매마일스톤 규칙 1차 실행 성공 (실제: ${runNow1Res.status})`);
    const { data: issuance1 } = await admin.from('coupon_automation_issuances_with').select('*').eq('rule_id', milestoneRuleId).eq('user_id', userMilestone.user.id);
    assert(issuance1 && issuance1.length === 1, `3번째 구매를 정확히 채운 테스트 회원에게 1차 실행으로 발급됨 (실제: ${issuance1?.length}건)`);

    const runNow2Res = await fetch(`${API}/api/admin/marketing/automation-rules/${milestoneRuleId}/run-now`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
    assert(runNow2Res.status === 200, `구매마일스톤 규칙 2차(재실행) 성공 (실제: ${runNow2Res.status})`);
    const { data: issuance2 } = await admin.from('coupon_automation_issuances_with').select('*').eq('rule_id', milestoneRuleId).eq('user_id', userMilestone.user.id);
    assert(issuance2 && issuance2.length === 1, `재실행해도 같은 회원에게 중복 발급되지 않음 - 멱등성 확인 (실제: ${issuance2?.length}건)`);
    if (issuance1 && issuance1[0]) createdCouponIds.push(issuance1[0].coupon_id);

    // ---- 등급유지(최고 등급) 규칙 ----
    const gradeRuleRes = await fetch(`${API}/api/admin/marketing/automation-rules`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ rule_type: 'grade', rule_config: { grade_key: topGrade.key }, coupon_template: { label: `등급테스트-${ts}`, discount_type: 'percent', discount_value: 5, valid_days: 30 }, enabled: true })
    });
    const gradeRuleJson = await gradeRuleRes.json();
    assert(gradeRuleRes.status === 201, `등급유지 규칙 생성 성공 (실제: ${gradeRuleRes.status})`);
    const gradeRuleId = gradeRuleJson.data.id;
    createdRuleIds.push(gradeRuleId);

    const gradeRunNow1Res = await fetch(`${API}/api/admin/marketing/automation-rules/${gradeRuleId}/run-now`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
    assert(gradeRunNow1Res.status === 200, `등급유지 규칙 1차 실행 성공 (실제: ${gradeRunNow1Res.status})`);
    const { data: gradeIssuance1 } = await admin.from('coupon_automation_issuances_with').select('*').eq('rule_id', gradeRuleId).eq('user_id', userGrade.user.id);
    assert(gradeIssuance1 && gradeIssuance1.length === 1, `최고 등급 테스트 회원에게 1차 실행으로 발급됨 (실제: ${gradeIssuance1?.length}건)`);

    const gradeRunNow2Res = await fetch(`${API}/api/admin/marketing/automation-rules/${gradeRuleId}/run-now`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
    assert(gradeRunNow2Res.status === 200, `등급유지 규칙 2차(재실행) 성공 (실제: ${gradeRunNow2Res.status})`);
    const { data: gradeIssuance2 } = await admin.from('coupon_automation_issuances_with').select('*').eq('rule_id', gradeRuleId).eq('user_id', userGrade.user.id);
    assert(gradeIssuance2 && gradeIssuance2.length === 1, `같은 달에 재실행해도 중복 발급되지 않음 - 멱등성 확인 (실제: ${gradeIssuance2?.length}건)`);
    if (gradeIssuance1 && gradeIssuance1[0]) createdCouponIds.push(gradeIssuance1[0].coupon_id);

    const runNowNotFoundRes = await fetch(`${API}/api/admin/marketing/automation-rules/00000000-0000-0000-0000-000000000000/run-now`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
    assert(runNowNotFoundRes.status === 404, `존재하지 않는 규칙 실행 시도 시 404 (실제: ${runNowNotFoundRes.status})`);

    // ---- 목록 조회 / 활성화 토글 / 수정 유효성 / 삭제 ----
    const listMemberRes = await fetch(`${API}/api/admin/marketing/automation-rules`, { headers: { Authorization: `Bearer ${memberToken}` } });
    assert(listMemberRes.status === 403, `일반 회원은 자동 쿠폰 규칙 목록 조회 불가 (실제: ${listMemberRes.status})`);

    const listRes = await fetch(`${API}/api/admin/marketing/automation-rules`, { headers: { Authorization: `Bearer ${adminToken}` } });
    const listJson = await listRes.json();
    assert(listRes.status === 200 && listJson.data.some(r => r.id === milestoneRuleId) && listJson.data.some(r => r.id === gradeRuleId), '목록 조회에 방금 생성한 규칙 2건이 모두 포함됨');

    const toggleRes = await fetch(`${API}/api/admin/marketing/automation-rules/${milestoneRuleId}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` }, body: JSON.stringify({ enabled: false })
    });
    const toggleJson = await toggleRes.json();
    assert(toggleRes.status === 200 && toggleJson.data.enabled === false, `규칙 비활성화 토글 성공 (실제: ${toggleRes.status})`);

    const badUpdateRes = await fetch(`${API}/api/admin/marketing/automation-rules/${milestoneRuleId}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` }, body: JSON.stringify({ coupon_template: { label: 'x' } })
    });
    assert(badUpdateRes.status === 400, `수정 시에도 쿠폰 내용 유효성 검사가 적용됨 (실제: ${badUpdateRes.status})`);

    const deleteMemberRes = await fetch(`${API}/api/admin/marketing/automation-rules/${gradeRuleId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${memberToken}` } });
    assert(deleteMemberRes.status === 403, `일반 회원은 자동 쿠폰 규칙 삭제 불가 (실제: ${deleteMemberRes.status})`);

    const deleteRes = await fetch(`${API}/api/admin/marketing/automation-rules/${gradeRuleId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${adminToken}` } });
    assert(deleteRes.status === 200, `규칙 삭제 성공 (실제: ${deleteRes.status})`);
    createdRuleIds.splice(createdRuleIds.indexOf(gradeRuleId), 1);
    const listAfterDeleteRes = await fetch(`${API}/api/admin/marketing/automation-rules`, { headers: { Authorization: `Bearer ${adminToken}` } });
    const listAfterDeleteJson = await listAfterDeleteRes.json();
    assert(!listAfterDeleteJson.data.some(r => r.id === gradeRuleId), '삭제 후 목록에서 사라짐');

  } finally {
    console.log('\n--- 정리 시작 ---');
    try {
      for (const ruleId of createdRuleIds) {
        await admin.from('coupon_automation_issuances_with').delete().eq('rule_id', ruleId);
        await admin.from('coupon_automation_rules_with').delete().eq('id', ruleId);
      }
      for (const campaignId of createdCampaignIds) {
        await admin.from('marketing_campaigns_with').delete().eq('id', campaignId);
      }
      for (const couponId of createdCouponIds) {
        if (couponId) {
          await admin.from('coupon_redemptions').delete().eq('coupon_id', couponId);
          await admin.from('coupons').delete().eq('id', couponId);
        }
      }
      await admin.from('notifications_with').delete().in('user_id', createdUserIds);
      await admin.from('orders_with').delete().in('user_id', createdUserIds);
      for (const uid of createdUserIds) {
        await admin.from('profiles').delete().eq('id', uid);
        await admin.auth.admin.deleteUser(uid);
      }
    } catch (e) { console.error('정리 중 오류:', e.message); }
    console.log('--- 정리 완료 ---');
  }

  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => { console.error('💥 테스트 실패:', err.message); process.exit(1); });
