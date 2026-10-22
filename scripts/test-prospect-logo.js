// 분양 영업 리스트 로고 관리 검증 (POST/PUT/DELETE /api/admin/prospects/:id/logo + 공개 전환 시 로고 이관)
// (1) 권한: 비로그인 401 / 일반회원 403 (업로드·주소·삭제 모두)
// (2) 입력 검증: 빈 본문·이미지 아닌 파일·GIF·2MB 초과·http/javascript 주소·잘못된 ID·없는 ID
// (3) 업로드 → 저장소 파일 생성(공개 URL 200) / 교체 → 이전 파일 삭제 / 주소 입력 → 업로드 파일 삭제 / 삭제 → 비움
// (4) "+ 후보 직접 추가"(bulk-import)에 logo_url 포함 + 응답 ids
// (5) 공개 전환 시 로고가 communities.logo_url로 이관, 전환 후 교체·삭제는 조직 로고에 반영
//     단, 조직에서 따로 넣은 로고(영업리스트 로고와 다른 주소)는 덮어쓰지 않음
// 실행: PORT=3180 node server.js 를 띄운 뒤 API=http://localhost:3180 node scripts/test-prospect-logo.js
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const admin = createClient(supabaseUrl, serviceKey);
const API = process.env.API || 'http://localhost:3180';
const BUCKET = 'product-images';

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
  return (await res.json()).access_token;
}

async function api(token, method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: 'Bearer ' + token } : {}),
    body: body ? JSON.stringify(body) : undefined
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}

async function upload(token, id, buf, contentType) {
  const res = await fetch(`${API}/api/admin/prospects/${id}/logo`, {
    method: 'POST',
    headers: Object.assign({ 'Content-Type': contentType || 'image/png' }, token ? { Authorization: 'Bearer ' + token } : {}),
    body: buf
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}

// 1x1 PNG (픽셀 색만 바꿔 서로 다른 파일로 사용)
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');
const JPG_HEAD = Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), Buffer.alloc(60)]);
const GIF = Buffer.concat([Buffer.from('GIF89a', 'ascii'), Buffer.alloc(40)]);

async function fileExists(path) {
  const dir = path.split('/').slice(0, -1).join('/');
  const name = path.split('/').pop();
  const { data } = await admin.storage.from(BUCKET).list(dir, { limit: 100 });
  return (data || []).some(f => f.name === name);
}

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const userIds = [];
  const prospectIds = [];
  const communityIds = [];

  try {
    const mk = async (tag, role) => {
      const email = `test-plogo-${tag}-${ts}@withplus-test.local`;
      const { data } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
      userIds.push(data.user.id);
      await admin.from('profiles').upsert([{ id: data.user.id, email, full_name: 'PLogoTest' + tag, role }]);
      return { id: data.user.id, token: await loginAs(email, password) };
    };
    const adm = await mk('admin', 'admin');
    const member = await mk('member', 'member');
    assert(adm.token && member.token, '테스트 계정(admin/member) 로그인');

    // ---------- (4) 후보 직접 추가 + logo_url ----------
    let r = await api(adm.token, 'POST', '/api/admin/prospects/bulk-import', { items: [{ name: `[TEST-PLOGO-${ts}] 잘못된로고`, org_type: 'church', source: 'admin_manual', logo_url: 'http://example.com/a.png' }] });
    assert(r.status === 400, `http:// 로고 주소로 추가 → 400 (${r.json.message})`);
    const extLogo = `https://example.com/test-plogo-${ts}.png`;
    r = await api(adm.token, 'POST', '/api/admin/prospects/bulk-import', { items: [{ name: `[TEST-PLOGO-${ts}] 테스트교회A`, org_type: 'church', address: `테스트시 ${ts}`, source: 'admin_manual', logo_url: extLogo }] });
    assert(r.status === 201 && r.json.inserted === 1 && Array.isArray(r.json.ids) && r.json.ids.length === 1, `로고 주소 포함 후보 추가 201 + ids 반환`);
    const pA = r.json.ids && r.json.ids[0];
    if (pA) prospectIds.push(pA);
    let { data: rowA } = await admin.from('community_prospects').select('logo_url, logo_storage_path').eq('id', pA).single();
    assert(rowA.logo_url === extLogo && !rowA.logo_storage_path, '추가 시 logo_url 저장(외부 주소라 storage_path 없음)');

    r = await api(adm.token, 'POST', '/api/admin/prospects/bulk-import', { items: [{ name: `[TEST-PLOGO-${ts}] 테스트성당B`, org_type: 'catholic', address: `테스트시 ${ts}-b`, source: 'admin_manual' }] });
    const pB = r.json.ids && r.json.ids[0];
    if (pB) prospectIds.push(pB);
    assert(!!pB, '로고 없는 후보 B 추가');

    // ---------- (1) 권한 ----------
    r = await upload(null, pB, PNG);
    assert(r.status === 401, `비로그인 업로드 401 (실제 ${r.status})`);
    r = await upload(member.token, pB, PNG);
    assert(r.status === 403, `일반회원 업로드 403 (실제 ${r.status})`);
    r = await api(member.token, 'PUT', `/api/admin/prospects/${pA}/logo`, { logo_url: 'https://example.com/x.png' });
    assert(r.status === 403, `일반회원 주소 입력 403 (실제 ${r.status})`);
    r = await api(member.token, 'DELETE', `/api/admin/prospects/${pA}/logo`);
    assert(r.status === 403, `일반회원 삭제 403 (실제 ${r.status})`);
    r = await api(null, 'DELETE', `/api/admin/prospects/${pA}/logo`);
    assert(r.status === 401, `비로그인 삭제 401 (실제 ${r.status})`);
    ({ data: rowA } = await admin.from('community_prospects').select('logo_url').eq('id', pA).single());
    assert(rowA.logo_url === extLogo, '권한 없는 요청 후에도 로고 그대로');

    // ---------- (2) 입력 검증 ----------
    r = await upload(adm.token, pB, Buffer.from('hello, not an image at all'), 'application/octet-stream');
    assert(r.status === 400, `이미지 아닌 파일 400 (${r.json.message})`);
    r = await upload(adm.token, pB, GIF, 'image/gif');
    assert(r.status === 400, `GIF 400 (${r.json.message})`);
    r = await upload(adm.token, pB, Buffer.concat([PNG, Buffer.alloc(2 * 1024 * 1024)]), 'image/png');
    assert(r.status === 413, `2MB 초과 413 (${r.json.message})`);
    r = await upload(adm.token, 'not-a-uuid', PNG);
    assert(r.status === 400, `잘못된 ID 400`);
    r = await upload(adm.token, '00000000-0000-4000-8000-000000000000', PNG);
    assert(r.status === 404, `없는 후보 404`);
    r = await api(adm.token, 'PUT', `/api/admin/prospects/${pB}/logo`, { logo_url: 'javascript:alert(1)' });
    assert(r.status === 400, `javascript: 주소 400`);
    r = await api(adm.token, 'PUT', `/api/admin/prospects/${pB}/logo`, { logo_url: '' });
    assert(r.status === 400, `빈 주소 400`);
    r = await api(adm.token, 'DELETE', `/api/admin/prospects/${pB}/logo`);
    assert(r.status === 400, `로고 없는데 삭제 → 400`);

    // ---------- (3) 업로드·교체·주소·삭제 ----------
    r = await upload(adm.token, pB, PNG, 'image/png');
    assert(r.status === 201 && r.json.data.logo_url && r.json.data.logo_storage_path, `PNG 업로드 201 (${r.json.message})`);
    const path1 = r.json.data.logo_storage_path;
    const url1 = r.json.data.logo_url;
    assert(path1 && path1.startsWith(`withplus/prospect-logos/${pB}/`) && path1.endsWith('.png'), `사이트별 경로에 저장: ${path1}`);
    assert(await fileExists(path1), '저장소에 파일 존재');
    const pub = await fetch(url1);
    assert(pub.status === 200, `공개 URL 열림 (${pub.status})`);

    r = await upload(adm.token, pB, JPG_HEAD, 'image/jpeg');
    assert(r.status === 201 && r.json.data.logo_storage_path !== path1 && r.json.data.logo_storage_path.endsWith('.jpg'), `JPG로 교체 201 (${r.json.message})`);
    const path2 = r.json.data.logo_storage_path;
    assert(!(await fileExists(path1)), '교체 후 이전 파일 삭제됨');
    assert(await fileExists(path2), '새 파일 존재');

    r = await api(adm.token, 'PUT', `/api/admin/prospects/${pB}/logo`, { logo_url: 'https://example.com/b-logo.png' });
    assert(r.status === 200 && r.json.data.logo_url === 'https://example.com/b-logo.png' && r.json.data.logo_storage_path === null, '주소 입력으로 교체 → storage_path 비움');
    assert(!(await fileExists(path2)), '주소로 교체 시 업로드 파일 삭제됨');

    r = await upload(adm.token, pB, PNG, 'image/png');
    const path3 = r.json.data && r.json.data.logo_storage_path;
    r = await api(adm.token, 'DELETE', `/api/admin/prospects/${pB}/logo`);
    assert(r.status === 200 && r.json.data.logo_url === null && r.json.data.logo_storage_path === null, `로고 삭제 200 (${r.json.message})`);
    assert(path3 && !(await fileExists(path3)), '삭제 시 저장소 파일도 삭제됨');

    r = await api(adm.token, 'GET', '/api/admin/prospects?org_type=church');
    const listed = (r.json.data || []).find(p => p.id === pA);
    assert(listed && listed.logo_url === extLogo, '목록 API에 logo_url 포함');

    // ---------- (5) 공개 전환·동기화 ----------
    r = await upload(adm.token, pA, PNG, 'image/png');
    const aUrl1 = r.json.data && r.json.data.logo_url;
    assert(r.status === 201 && r.json.community_sync === null, '전환 전 업로드는 조직 동기화 없음');
    r = await api(adm.token, 'PUT', `/api/admin/prospects/${pA}/promote`, { slug: `test-plogo-${ts}` });
    const commId = r.json.community && r.json.community.id;
    if (commId) communityIds.push(commId);
    assert(r.status === 200 && r.json.community && r.json.community.logo_url === aUrl1, `공개 전환 시 로고 이관 (${r.json.message})`);

    r = await upload(adm.token, pA, JPG_HEAD, 'image/jpeg');
    const aUrl2 = r.json.data && r.json.data.logo_url;
    let { data: comm } = await admin.from('communities').select('logo_url').eq('id', commId).single();
    assert(r.json.community_sync === 'synced' && comm.logo_url === aUrl2, `전환 후 교체 → 조직 로고도 교체 (${r.json.message})`);

    r = await api(adm.token, 'DELETE', `/api/admin/prospects/${pA}/logo`);
    ({ data: comm } = await admin.from('communities').select('logo_url').eq('id', commId).single());
    assert(r.json.community_sync === 'synced' && comm.logo_url === null, '전환 후 삭제 → 조직 로고도 비움');

    r = await api(adm.token, 'PUT', `/api/admin/prospects/${pA}/logo`, { logo_url: 'https://example.com/a2.png' });
    ({ data: comm } = await admin.from('communities').select('logo_url').eq('id', commId).single());
    assert(r.json.community_sync === 'synced' && comm.logo_url === 'https://example.com/a2.png', '조직 로고가 비어 있으면 새 로고로 채움');

    // 조직 관리 화면에서 직접 넣은 로고(관리자 API)는 보호
    r = await api(adm.token, 'PUT', `/api/admin/communities/${commId}`, { logo_url: 'https://example.com/own-community-logo.png' });
    assert(r.status === 200, `조직 관리에서 자체 로고 지정 (${r.status})`);
    r = await upload(adm.token, pA, PNG, 'image/png');
    ({ data: comm } = await admin.from('communities').select('logo_url').eq('id', commId).single());
    assert(r.status === 201 && r.json.community_sync === 'kept_community_logo' && comm.logo_url === 'https://example.com/own-community-logo.png', `조직 자체 로고는 덮어쓰지 않음 (${r.json.message})`);
    r = await api(adm.token, 'DELETE', `/api/admin/prospects/${pA}/logo`);
    ({ data: comm } = await admin.from('communities').select('logo_url').eq('id', commId).single());
    assert(r.json.community_sync === 'kept_community_logo' && comm.logo_url === 'https://example.com/own-community-logo.png', '영업리스트 로고 삭제해도 조직 자체 로고 유지');

    // 되돌리기 → 로고 등록 → 재전환: 조직 로고가 있으면 유지, 비어 있으면 채움
    r = await api(adm.token, 'PUT', `/api/admin/prospects/${pA}/demote`);
    assert(r.status === 200, '공개 되돌리기');
    await admin.from('communities').update({ logo_url: null }).eq('id', commId);
    r = await api(adm.token, 'PUT', `/api/admin/prospects/${pA}/logo`, { logo_url: 'https://example.com/a3.png' });
    r = await api(adm.token, 'PUT', `/api/admin/prospects/${pA}/promote`, {});
    assert(r.status === 200 && r.json.community && r.json.community.id === commId && r.json.community.logo_url === 'https://example.com/a3.png', '재전환 시 비어 있던 조직 로고를 영업리스트 로고로 채움');
  } catch (err) {
    fail++;
    console.log('❌ 예외:', err.message);
  } finally {
    // 테스트가 만든 저장소 파일·후보·조직·계정만 정리
    for (const pid of prospectIds) {
      const dir = `withplus/prospect-logos/${pid}`;
      const { data: files } = await admin.storage.from(BUCKET).list(dir, { limit: 100 });
      if (files && files.length) await admin.storage.from(BUCKET).remove(files.map(f => `${dir}/${f.name}`));
    }
    if (prospectIds.length) await admin.from('community_prospects').delete().in('id', prospectIds);
    if (communityIds.length) await admin.from('communities').delete().in('id', communityIds);
    for (const uid of userIds) {
      await admin.from('admin_audit_logs_with').delete().eq('admin_id', uid);
      await admin.from('profiles').delete().eq('id', uid);
      await admin.auth.admin.deleteUser(uid).catch(() => {});
    }
    console.log(`\n결과: ${pass} 통과 / ${fail} 실패`);
    process.exit(fail ? 1 : 0);
  }
}
main();
