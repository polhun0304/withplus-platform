// 관리자 감사로그(Admin Audit Log) 검증: 격차분석에서 지적된 "관리자 감사로그 없음" 항목 해결 확인.
// 흐름: (1) 관리자가 상태변경(POST/PUT/PATCH/DELETE) 요청을 보내면 자동으로 기록되는지 →
// (2) 조회(GET) 요청은 기록되지 않는지 → (3) super_admin만 로그를 열람할 수 있는지(admin은 403) →
// (4) 비밀번호/시크릿 등 민감한 필드는 저장 전에 마스킹되는지 → (5) 필터(admin/method/path)가 정확히 동작하는지 확인한다.
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
  let superAdminId, adminId, memberId, providerId;
  let originalEmailConfig = null;

  try {
    // ============================================
    // 준비: super_admin / admin / member / (감사대상 액션용) provider 테스트 계정
    // ============================================
    const superAdminEmail = `test-audit-super-${ts}@withplus-test.local`;
    const adminEmail = `test-audit-admin-${ts}@withplus-test.local`;
    const memberEmail = `test-audit-member-${ts}@withplus-test.local`;
    const providerEmail = `test-audit-provider-${ts}@withplus-test.local`;

    const { data: superData } = await admin.auth.admin.createUser({ email: superAdminEmail, password, email_confirm: true });
    superAdminId = superData.user.id;
    await admin.from('profiles').upsert([{ id: superAdminId, email: superAdminEmail, full_name: 'AuditTestSuperAdmin', role: 'super_admin' }]);

    const { data: adminData } = await admin.auth.admin.createUser({ email: adminEmail, password, email_confirm: true });
    adminId = adminData.user.id;
    await admin.from('profiles').upsert([{ id: adminId, email: adminEmail, full_name: 'AuditTestAdmin', role: 'admin' }]);

    const { data: memberData } = await admin.auth.admin.createUser({ email: memberEmail, password, email_confirm: true });
    memberId = memberData.user.id;
    await admin.from('profiles').upsert([{ id: memberId, email: memberEmail, full_name: 'AuditTestMember', role: 'member' }]);

    const { data: provData } = await admin.auth.admin.createUser({ email: providerEmail, password, email_confirm: true });
    providerId = provData.user.id;
    await admin.from('profiles').upsert([{ id: providerId, email: providerEmail, full_name: 'AuditTestProvider', role: 'provider', commission_rate: 10 }]);

    const superToken = await loginAs(superAdminEmail, password);
    const adminToken = await loginAs(adminEmail, password);
    const memberToken = await loginAs(memberEmail, password);
    assert(!!superToken && !!adminToken && !!memberToken, '테스트 계정(super_admin/admin/member) 로그인 성공');

    // ============================================
    // 1) 권한: super_admin만 감사로그 열람 가능
    // ============================================
    const memberViewRes = await fetch(`${API}/api/admin/audit-logs`, { headers: { Authorization: `Bearer ${memberToken}` } });
    assert(memberViewRes.status === 403, `일반 회원은 감사로그 조회 불가(403) (실제: ${memberViewRes.status})`);

    const adminViewRes = await fetch(`${API}/api/admin/audit-logs`, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert(adminViewRes.status === 403, `일반 admin은 감사로그 조회 불가(403, super_admin 전용) (실제: ${adminViewRes.status})`);

    const noAuthRes = await fetch(`${API}/api/admin/audit-logs`);
    assert(noAuthRes.status === 401, `로그인 없이는 감사로그 조회가 거부됨(401) (실제: ${noAuthRes.status})`);

    const superViewRes = await fetch(`${API}/api/admin/audit-logs`, { headers: { Authorization: `Bearer ${superToken}` } });
    const superViewJson = await superViewRes.json();
    assert(superViewRes.status === 200 && superViewJson.success, `super_admin은 감사로그 조회 가능 (실제: ${superViewRes.status})`);
    assert(superViewJson.pagination && typeof superViewJson.pagination.total === 'number', '페이지네이션 정보(total/page/pageSize)가 함께 내려옴');

    const adminsListRes = await fetch(`${API}/api/admin/audit-logs/admins`, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert(adminsListRes.status === 403, `일반 admin은 관리자 목록(필터용) 조회도 불가(403) (실제: ${adminsListRes.status})`);

    // ============================================
    // 2) 상태변경(PATCH) 요청은 기록되고, 조회(GET) 요청은 기록되지 않음
    // ============================================
    const beforeCountRes = await fetch(`${API}/api/admin/audit-logs?adminId=${adminId}&pageSize=1`, { headers: { Authorization: `Bearer ${superToken}` } });
    const beforeCountJson = await beforeCountRes.json();
    const beforeTotal = beforeCountJson.pagination.total;

    // GET 요청(조회성) - 감사로그에 남으면 안 됨
    await fetch(`${API}/api/admin/providers`, { headers: { Authorization: `Bearer ${adminToken}` } });

    const afterGetCountRes = await fetch(`${API}/api/admin/audit-logs?adminId=${adminId}&pageSize=1`, { headers: { Authorization: `Bearer ${superToken}` } });
    const afterGetCountJson = await afterGetCountRes.json();
    assert(afterGetCountJson.pagination.total === beforeTotal, `조회(GET) 요청은 감사로그에 기록되지 않음 (기록 전: ${beforeTotal}, GET 후: ${afterGetCountJson.pagination.total})`);

    // PATCH 요청(상태변경) - 감사로그에 남아야 함
    const patchRes = await fetch(`${API}/api/admin/providers/${providerId}/commission-rate`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ commission_rate: 15 })
    });
    assert(patchRes.status === 200, `감사대상 PATCH 요청 자체는 정상 처리됨 (실제: ${patchRes.status})`);

    // finish 이벤트 기반 비동기 기록이므로 잠시 대기
    await new Promise(r => setTimeout(r, 800));

    const afterPatchRes = await fetch(`${API}/api/admin/audit-logs?adminId=${adminId}&method=PATCH&pathContains=commission-rate`, { headers: { Authorization: `Bearer ${superToken}` } });
    const afterPatchJson = await afterPatchRes.json();
    assert(afterPatchJson.data.length >= 1, `PATCH 요청이 감사로그에 정확히 기록됨 (실제 건수: ${afterPatchJson.data.length})`);
    const loggedRow = afterPatchJson.data[0];
    assert(loggedRow.method === 'PATCH' && loggedRow.path.includes('commission-rate'), `기록된 로그의 method/path가 정확함 (실제: ${loggedRow.method} ${loggedRow.path})`);
    assert(loggedRow.status_code === 200, `기록된 로그의 상태코드가 실제 응답과 일치함 (실제: ${loggedRow.status_code})`);
    assert(loggedRow.admin_email === adminEmail, `기록된 로그의 관리자 이메일이 정확함 (실제: ${loggedRow.admin_email})`);
    assert(loggedRow.body_snapshot && loggedRow.body_snapshot.commission_rate === 15, `기록된 로그에 요청 본문(수수료율 15)이 그대로 저장됨`);

    // ============================================
    // 3) 민감한 필드(비밀번호류)는 저장 전에 마스킹됨
    // ============================================
    const { data: emailConfigRows } = await admin.from('email_configs_with').select('*').eq('provider_key', 'smtp').limit(1);
    originalEmailConfig = (emailConfigRows && emailConfigRows[0]) || null;

    const smtpPatchRes = await fetch(`${API}/api/admin/email-config`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ smtp_pass: 'super-secret-value-should-not-be-stored-in-plaintext' })
    });
    assert(smtpPatchRes.status === 200, `이메일(SMTP) 설정 변경 요청 자체는 정상 처리됨 (실제: ${smtpPatchRes.status})`);

    await new Promise(r => setTimeout(r, 800));

    const smtpLogRes = await fetch(`${API}/api/admin/audit-logs?adminId=${adminId}&pathContains=email-config`, { headers: { Authorization: `Bearer ${superToken}` } });
    const smtpLogJson = await smtpLogRes.json();
    const smtpLogRow = smtpLogJson.data[0];
    assert(!!smtpLogRow, '이메일 설정 변경도 감사로그에 기록됨');
    assert(smtpLogRow.body_snapshot.smtp_pass === '[REDACTED]', `smtp_pass 같은 민감한 필드는 원문 대신 [REDACTED]로 마스킹되어 저장됨 (실제 저장값: ${smtpLogRow.body_snapshot.smtp_pass})`);
    assert(JSON.stringify(smtpLogRow).indexOf('super-secret-value-should-not-be-stored-in-plaintext') === -1, '마스킹 대상 필드의 실제 비밀값은 로그 어디에도 평문으로 남지 않음');

    console.log(`\n결과: ${pass} passed, ${fail} failed`);
    process.exit(fail > 0 ? 1 : 0);
  } finally {
    // ============================================
    // 정리: 테스트로 생성된 감사로그/계정 삭제, SMTP 설정 원상복구
    // ============================================
    if (originalEmailConfig) {
      await admin.from('email_configs_with').update({
        smtp_host: originalEmailConfig.smtp_host,
        smtp_port: originalEmailConfig.smtp_port,
        smtp_secure: originalEmailConfig.smtp_secure,
        smtp_user: originalEmailConfig.smtp_user,
        smtp_pass: originalEmailConfig.smtp_pass,
        from_name: originalEmailConfig.from_name,
        from_email: originalEmailConfig.from_email,
        enabled: originalEmailConfig.enabled,
        updated_at: originalEmailConfig.updated_at
      }).eq('provider_key', 'smtp');
    }
    await admin.from('admin_audit_logs_with').delete().in('admin_id', [adminId, superAdminId].filter(Boolean));
    for (const uid of [superAdminId, adminId, memberId, providerId].filter(Boolean)) {
      await admin.from('profiles').delete().eq('id', uid);
      await admin.auth.admin.deleteUser(uid).catch(() => {});
    }
    console.log('정리 완료: 테스트 계정/감사로그 삭제, SMTP 설정 원상복구');
  }
}

main().catch(err => { console.error('테스트 실행 중 오류:', err); process.exit(1); });
