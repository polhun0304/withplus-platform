// 운영 화면(분양 조직·분양조직 정산·크리에이터)은 관리자(admin)도 사용, 돈 이체·송금키·원가는 대표자 전용 유지 (형님 결정 2026-10-22)
// 실행: PORT=3170 node server.js 를 띄운 뒤 API=http://localhost:3170 node scripts/test-ops-admin-access.js
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const admin = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY);
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const API = process.env.API || 'http://localhost:3170';
let pass = 0, fail = 0;
const assert = (c, m) => { if (c) { pass++; console.log('✅', m); } else { fail++; console.log('❌', m); } };

async function makeUser(role) {
  const email = `withplus.ops.${role}.${Date.now()}@withplus.test`;
  const password = 'Test!' + Math.random().toString(36).slice(2) + 'A1';
  const { data, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
  if (error) throw error;
  await admin.from('profiles').upsert({ id: data.user.id, email, role, full_name: `테스트 ${role}` }, { onConflict: 'id' });
  const r = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, { method: 'POST', headers: { 'Content-Type': 'application/json', apikey: anonKey }, body: JSON.stringify({ email, password }) });
  return { id: data.user.id, token: (await r.json()).access_token };
}

(async () => {
  const made = [];
  try {
    const adm = await makeUser('admin'); made.push(adm.id);
    const mem = await makeUser('member'); made.push(mem.id);
    const get = async (t, p) => (await fetch(API + p, { headers: { Authorization: `Bearer ${t}` } })).status;
    for (const p of ['/api/admin/communities', '/api/admin/community-settlements', '/api/admin/creators', '/api/admin/creator-settlements', '/api/admin/providers']) {
      assert(await get(adm.token, p) === 200, `관리자 ${p} → 200`);
      assert(await get(mem.token, p) === 403 || p === '/api/admin/community-settlements', `일반회원 ${p} 거부`);
    }
    // 일반회원은 분양조직 정산에서 자기 조직만(담당 조직 없으면 404)
    assert([403, 404].includes(await get(mem.token, '/api/admin/community-settlements')), '일반회원 분양조직 정산 → 403/404');
    // 대표자 전용 유지: 송금 API 키 설정·원가·마진율 정책
    for (const p of ['/api/admin/payout-providers', '/api/admin/pricing-policies']) {
      assert(await get(adm.token, p) === 403, `관리자 ${p} → 403 (대표자 전용 유지)`);
    }
  } catch (e) {
    fail++; console.log('❌ 예외:', e.message);
  } finally {
    for (const id of made) { await admin.from('profiles').delete().eq('id', id); await admin.auth.admin.deleteUser(id); }
    console.log(`결과: ${pass} 통과 / ${fail} 실패 (테스트 계정 ${made.length}개 삭제)`);
    process.exit(fail ? 1 : 0);
  }
})();
