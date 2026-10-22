// 공급자별 수수료율 — 관리자(admin)도 조회·수정 가능, 일반회원은 거부되는지 검증 (형님 결정 2026-10-22)
// 실행: PORT=3160 node server.js 를 띄운 뒤 API=http://localhost:3160 node scripts/test-commission-admin-access.js
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const admin = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY);
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const API = process.env.API || 'http://localhost:3160';
let pass = 0, fail = 0;
const assert = (c, m) => { if (c) { pass++; console.log('✅', m); } else { fail++; console.log('❌', m); } };

async function makeUser(role) {
  const email = `withplus.commission.${role}.${Date.now()}@withplus.test`;
  const password = 'Test!' + Math.random().toString(36).slice(2) + 'A1';
  const { data, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
  if (error) throw error;
  await admin.from('profiles').upsert({ id: data.user.id, email, role, full_name: `테스트 ${role}` }, { onConflict: 'id' });
  const r = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, { method: 'POST', headers: { 'Content-Type': 'application/json', apikey: anonKey }, body: JSON.stringify({ email, password }) });
  const j = await r.json();
  return { id: data.user.id, token: j.access_token };
}

(async () => {
  const made = [];
  try {
    const adm = await makeUser('admin'); made.push(adm.id);
    const prov = await makeUser('provider'); made.push(prov.id);
    const mem = await makeUser('member'); made.push(mem.id);
    const h = (t) => ({ Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' });

    let r = await fetch(`${API}/api/admin/providers`, { headers: h(adm.token) });
    let j = await r.json();
    assert(r.status === 200 && j.success, `관리자 수수료율 목록 조회 200 (받은 값 ${r.status})`);
    assert((j.data || []).some(p => p.id === prov.id), '목록에 테스트 공급자 포함');

    r = await fetch(`${API}/api/admin/providers/${prov.id}/commission-rate`, { method: 'PATCH', headers: h(adm.token), body: JSON.stringify({ commission_rate: 12.5 }) });
    j = await r.json();
    assert(r.status === 200 && j.success, `관리자 수수료율 저장 200 (받은 값 ${r.status} ${j.message || ''})`);
    const { data: saved } = await admin.from('profiles').select('commission_rate').eq('id', prov.id).single();
    assert(Number(saved.commission_rate) === 12.5, `DB에 12.5% 저장됨 (값 ${saved.commission_rate})`);

    r = await fetch(`${API}/api/admin/providers/${prov.id}/commission-rate`, { method: 'PATCH', headers: h(adm.token), body: JSON.stringify({ commission_rate: 150 }) });
    assert(r.status === 400, `범위 밖(150%) 거부 400 (받은 값 ${r.status})`);

    r = await fetch(`${API}/api/admin/providers`, { headers: h(mem.token) });
    assert(r.status === 403, `일반회원 조회 거부 403 (받은 값 ${r.status})`);
    r = await fetch(`${API}/api/admin/providers/${prov.id}/commission-rate`, { method: 'PATCH', headers: h(mem.token), body: JSON.stringify({ commission_rate: 1 }) });
    assert(r.status === 403, `일반회원 저장 거부 403 (받은 값 ${r.status})`);
    r = await fetch(`${API}/api/admin/providers`);
    assert(r.status === 401, `비로그인 거부 401 (받은 값 ${r.status})`);
  } catch (e) {
    fail++; console.log('❌ 예외:', e.message);
  } finally {
    for (const id of made) { await admin.from('profiles').delete().eq('id', id); await admin.auth.admin.deleteUser(id); }
    console.log(`결과: ${pass} 통과 / ${fail} 실패 (테스트 계정 ${made.length}개 삭제)`);
    process.exit(fail ? 1 : 0);
  }
})();
