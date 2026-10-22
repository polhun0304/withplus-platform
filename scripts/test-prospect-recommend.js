// 분양 영업 리스트 "구분"(비종교 조직 유형) + 🔎 분양 후보 추천(내부 점수·카카오 로컬 외부 찾기) + 분양 조직 로고·직인 업로드 검증
// (1) 조직 유형 10종: 새 유형(company·association·school·apartment·club·nonprofit) 허용, 엉뚱한 값 400, DB CHECK도 거절
//     라벨: /api/offering-org-types labels, admin.html "전체"/"구분", withplus-common.js ORG_TYPE_OPTIONS
// (2) 내부 추천: 점수 순서·근거 문구(연락처/컨택중/같은 시군구 운영 조직/회원 수/규모 힌트/로고), 보류·공개전환 제외
// (3) 외부 찾기: 테스트 전용 가짜 카카오 응답(PROSPECT_KAKAO_TEST_MODE=1, 127.0.0.1만) - 실제 카카오는 호출하지 않음
//     키 없음 안내(412)·입력 검증·쪽 넘김(15+5)·캐시·이미 있는 후보 표시·선택 추가(source=kakao_local)·중복 건너뜀
// (4) 권한: 일반회원 403 / 비로그인 401
// (5) 분양 조직 로고·직인: https 주소 검사, 파일 업로드·교체·주소 교체·삭제 시 저장소 정리
// 실행: node scripts/test-prospect-recommend.js  (이 스크립트가 테스트 모드 서버를 PORT=3190 으로 직접 띄운다)
//       이미 띄운 테스트 모드 서버를 쓰려면 API=http://127.0.0.1:3190 지정
const { createClient } = require('@supabase/supabase-js');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const admin = createClient(supabaseUrl, process.env.SUPABASE_SERVICE_ROLE_KEY);
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const PORT = 3190;
const API = process.env.API || `http://127.0.0.1:${PORT}`;
const BUCKET = 'product-images';

let pass = 0, fail = 0;
function assert(cond, msg, extra) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌', msg, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ''); }
}
async function loginAs(email, password) {
  const res = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, { method: 'POST', headers: { 'Content-Type': 'application/json', apikey: anonKey }, body: JSON.stringify({ email, password }) });
  return (await res.json()).access_token;
}
async function api(token, method, p, body, headers) {
  const res = await fetch(API + p, { method, headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: 'Bearer ' + token } : {}, headers || {}), body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}
async function upload(token, id, kind, buf, ct) {
  const res = await fetch(`${API}/api/admin/communities/${id}/logo?kind=${kind}`, { method: 'POST', headers: Object.assign({ 'Content-Type': ct || 'image/png' }, token ? { Authorization: 'Bearer ' + token } : {}), body: buf });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}
async function fileExists(p) {
  const dir = p.split('/').slice(0, -1).join('/');
  const { data } = await admin.storage.from(BUCKET).list(dir, { limit: 100 });
  return (data || []).some(f => f.name === p.split('/').pop());
}
async function waitForServer() {
  for (let i = 0; i < 90; i++) {
    try { const r = await fetch(API + '/api/health'); if (r.ok) return true; } catch (e) { /* 아직 */ }
    await new Promise(r => setTimeout(r, 1000));
  }
  return false;
}
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');
const JPG_HEAD = Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), Buffer.alloc(60)]);
const GIF = Buffer.concat([Buffer.from('GIF89a', 'ascii'), Buffer.alloc(40)]);

async function main() {
  const ts = Date.now();
  const password = 'TestPass123!';
  const userIds = [], communityIds = [];
  const TAG = `[TEST-PREC-${ts}]`;
  const KW = `TESTKAKAO${ts}`;
  const SIGUNGU = `테스트${ts}시`;
  let child = null;
  if (!process.env.API) {
    child = spawn(process.execPath, ['server.js'], { cwd: path.join(__dirname, '..'), env: { ...process.env, PORT: String(PORT), PROSPECT_KAKAO_TEST_MODE: '1', NODE_ENV: 'development' }, stdio: ['ignore', 'ignore', 'pipe'] });
    child.stderr.on('data', () => {});
  }
  try {
    if (!(await waitForServer())) throw new Error('테스트 서버가 뜨지 않았습니다');
    const mk = async (tag, role) => {
      const email = `test-prec-${tag}-${ts}@withplus-test.local`;
      const { data } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
      userIds.push(data.user.id);
      await admin.from('profiles').upsert([{ id: data.user.id, email, full_name: 'PrecTest' + tag, role }]);
      return { id: data.user.id, token: await loginAs(email, password) };
    };
    const adm = await mk('admin', 'admin');
    const member = await mk('member', 'member');
    assert(adm.token && member.token, '테스트 계정(admin/member) 로그인');

    // ========== (1) 조직 유형 ==========
    let r = await api(null, 'GET', '/api/offering-org-types');
    const ot = r.json.data || {};
    assert(['company', 'association', 'school', 'apartment', 'club', 'nonprofit', 'church', 'catholic', 'buddhist', 'other'].every(t => (ot.org_types || []).includes(t)), '유형 목록 10종 공개');
    assert(ot.labels && ot.labels.company === '일반회사' && ot.labels.association === '협회·단체' && ot.labels.nonprofit === '비영리·복지기관' && ot.labels.church === '개신교(교회)', '유형 라벨(일반회사·협회·단체·비영리·복지기관·개신교(교회))');
    assert(ot.default_labels && ot.default_labels.company && ot.default_labels.company.general === '후원금', '비종교 유형 기본 항목명은 "후원금"');

    const addOne = async (item) => api(adm.token, 'POST', '/api/admin/prospects/bulk-import', { items: [Object.assign({ source: 'admin_manual' }, item)] });
    for (const t of ['company', 'association', 'school', 'apartment', 'club', 'nonprofit']) {
      r = await addOne({ name: `${TAG} 유형확인 ${t}`, org_type: t, address: `서울특별시 유형구 ${t}로 ${ts}` });
      assert(r.status === 201 && r.json.inserted === 1, `새 유형 ${t} 후보 추가 201`);
    }
    r = await addOne({ name: `${TAG} 잘못된유형`, org_type: 'religion' });
    assert(r.status === 400, `엉뚱한 유형(religion) 400 (${r.json.message})`);
    r = await addOne({ name: `${TAG} 잘못된유형2`, org_type: 'COMPANY' });
    assert(r.status === 400, '대문자 COMPANY 400');
    const dbBad = await admin.from('community_prospects').insert([{ name: `${TAG} DB거절`, org_type: 'foo', source: 'test', dedup_key: `test-prec-bad-${ts}` }]).select('id');
    assert(!!dbBad.error && dbBad.error.code === '23514', `DB CHECK가 foo 거절 (${dbBad.error && dbBad.error.code})`);
    if (dbBad.data && dbBad.data.length) await admin.from('community_prospects').delete().in('id', dbBad.data.map(x => x.id));
    r = await api(adm.token, 'GET', '/api/admin/prospects?org_type=company');
    assert(r.status === 200 && (r.json.data || []).some(p => p.name === `${TAG} 유형확인 company`), '구분 필터 org_type=company 조회');
    r = await api(adm.token, 'GET', '/api/admin/prospects?org_type=bogus');
    assert(r.status === 400, '구분 필터 엉뚱한 값 400');

    r = await api(adm.token, 'POST', '/api/admin/communities', { name: `${TAG} 회사조직`, slug: `test-prec-co-${ts}`, org_type: 'company', address: `제주특별자치도 ${SIGUNGU} 테스트로 1` });
    const coId = r.json.data && r.json.data.id;
    if (coId) communityIds.push(coId);
    assert(r.status === 201 && r.json.data.org_type === 'company' && r.json.data.offering_labels.general === '후원금', `분양 조직 등록 org_type=company (${r.json.message})`);
    r = await api(adm.token, 'PUT', `/api/admin/communities/${coId}`, { org_type: 'nonprofit' });
    assert(r.status === 200 && r.json.data.org_type === 'nonprofit' && r.json.data.offering_labels.regular === '정기후원', '조직 유형 nonprofit 변경 + 기본 항목명');
    r = await api(adm.token, 'PUT', `/api/admin/communities/${coId}`, { org_type: 'xyz' });
    assert(r.status === 400, '조직 유형 엉뚱한 값 400');
    await api(adm.token, 'PUT', `/api/admin/communities/${coId}`, { org_type: 'company' });

    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'admin.html'), 'utf8');
    assert(!html.includes('전체 종교') && html.includes('<option value="">전체</option>') && html.includes('<th>구분</th>'), 'admin.html: "전체 종교"→"전체", 열 제목 "종교"→"구분"');
    assert(!html.includes('전국 교회·성당·사찰 등 수집 후보') && html.includes('일반회사·협회·단체'), 'admin.html: 설명 문구 일반화');
    const common = fs.readFileSync(path.join(__dirname, '..', 'public', 'withplus-common.js'), 'utf8');
    assert(common.includes("value: 'apartment', label: '아파트·주민모임'") && common.includes('getOfferingWord'), 'withplus-common.js: 유형 목록·후원 용어 헬퍼');
    r = await fetch(API + '/admin.html');
    assert(r.status === 200, 'admin.html 응답 200');

    // ========== (2) 내부 추천 ==========
    // 같은 시군구(제주 SIGUNGU)에 운영 중 조직 2곳(위 회사조직 + 아래에서 공개 전환하는 학원) + 회원 2명
    await admin.from('community_members').insert([{ community_id: coId, user_id: adm.id, role: 'member', status: 'active' }, { community_id: coId, user_id: member.id, role: 'member', status: 'active' }]);
    const base = { region_sido: '제주특별자치도', region_sigungu: SIGUNGU };
    r = await api(adm.token, 'POST', '/api/admin/prospects/bulk-import', { items: [
      { ...base, name: `${TAG} 제주중앙교회`, org_type: 'church', address: `제주특별자치도 ${SIGUNGU} 1`, phone: '064-111-2222', source: 'admin_manual', logo_url: 'https://example.com/prec-logo.png' },
      { ...base, name: `${TAG} 제주상사`, org_type: 'company', address: `제주특별자치도 ${SIGUNGU} 2`, phone: '064-333-4444', source: 'admin_manual' },
      { ...base, name: `${TAG} 제주모임`, org_type: 'other', address: `제주특별자치도 ${SIGUNGU} 3`, source: 'admin_manual' },
      { ...base, name: `${TAG} 제주보류`, org_type: 'club', address: `제주특별자치도 ${SIGUNGU} 4`, phone: '064-555-6666', source: 'admin_manual' },
      { ...base, name: `${TAG} 제주학원`, org_type: 'school', address: `제주특별자치도 ${SIGUNGU} 5`, phone: '064-777-8888', source: 'admin_manual' }
    ] });
    const [pChurch, pCo, pOther, pDecl, pSchool] = r.json.ids || [];
    assert(r.status === 201 && (r.json.ids || []).length === 5, '추천용 후보 5곳 추가');
    await api(adm.token, 'PATCH', `/api/admin/prospects/${pChurch}`, { status: 'contacted' });
    await api(adm.token, 'PATCH', `/api/admin/prospects/${pDecl}`, { status: 'declined' });
    r = await api(adm.token, 'PUT', `/api/admin/prospects/${pSchool}/promote`, { slug: `test-prec-school-${ts}` });
    if (r.json.community) communityIds.push(r.json.community.id);
    assert(r.status === 200 && r.json.community && r.json.community.org_type === 'school', `학교·학원 후보 공개 전환 → 조직 유형 school (${r.json.message})`);

    r = await api(adm.token, 'GET', `/api/admin/prospects/recommend?region_sigungu=${encodeURIComponent(SIGUNGU)}&limit=10`);
    const rec = r.json.data || [];
    assert(r.status === 200 && rec.length === 3, `추천 대상 3곳(보류·공개전환 제외) (실제 ${rec.length})`, rec.map(x => x.name));
    assert(rec[0] && rec[0].id === pChurch && rec[1] && rec[1].id === pCo && rec[2] && rec[2].id === pOther, '점수 순서: 컨택중+연락처+규모+로고 > 연락처 > 연락처 없음', rec.map(x => [x.name, x.score]));
    const rs0 = (rec[0] && rec[0].reasons) || [];
    assert(rs0.includes('연락처 있음') && rs0.includes('연락함(컨택중)') && rs0.includes('같은 시군구에 운영 중 조직 2곳') && rs0.includes('회원 2명 지역') && rs0.includes("규모 힌트(이름에 '중앙')") && rs0.includes('로고 등록됨'), '1위 근거 문구', rs0);
    const rs1 = (rec[1] && rec[1].reasons) || [];
    assert(rs1.includes('미컨택') && rs1.some(x => /운영 중 같은 유형\(일반회사\) \d+곳/.test(x)), '2위 근거: 미컨택·운영 중 같은 유형(일반회사)', rs1);
    assert(((rec[2] && rec[2].reasons) || []).includes('연락처 없음'), '3위 근거: 연락처 없음');
    assert(rec[0] && rec[0].score > rec[1].score && rec[1].score > rec[2].score, `점수 ${rec.map(x => x.score).join(' > ')}`);
    assert(r.json.summary && r.json.summary.candidates === 3 && typeof r.json.scoring === 'string', '요약·점수 기준 문구 포함');
    r = await api(adm.token, 'GET', '/api/admin/prospects/recommend?org_type=bogus');
    assert(r.status === 400, '추천 org_type 검증 400');

    // ========== (3) 외부 찾기(가짜 카카오) ==========
    r = await api(adm.token, 'GET', '/api/admin/prospects/kakao-status');
    assert(r.status === 200 && r.json.data.configured === true && r.json.data.key_source === 'test' && (r.json.data.presets.company || []).includes('회사') && (r.json.data.presets.apartment || []).includes('아파트 관리사무소'), '카카오 상태: 테스트 키·업종 프리셋');
    r = await api(adm.token, 'GET', '/api/admin/prospects/kakao-status', null, { 'x-test-kakao-key': 'none' });
    assert(r.status === 200 && r.json.data.configured === false && (r.json.data.guide || []).some(g => g.includes('REST API 키')), '키 없을 때 상태: 미설정 + 설정 안내');
    const searchBody = { org_type: 'company', sido: '서울특별시', sigungu: '테스트구', keywords: [KW] };
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-search', searchBody, { 'x-test-kakao-key': 'none' });
    assert(r.status === 412 && r.json.code === 'KAKAO_KEY_MISSING' && (r.json.guide || []).length >= 3, `키 없으면 검색 대신 안내(412) (${r.json.message})`);
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-search', { org_type: 'company', keywords: [KW] });
    assert(r.status === 400, '지역·주소 없이 검색 400');
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-search', { org_type: 'company', sido: '서울특별시', keywords: [] });
    assert(r.status === 400, '키워드 없이 검색 400');
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-search', { org_type: 'company', sido: '서울특별시', keywords: ['a', 'b', 'c', 'd', 'e', 'f'] });
    assert(r.status === 400, '키워드 6개 400');
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-search', { org_type: 'bogus', sido: '서울특별시', keywords: [KW] });
    assert(r.status === 400, '검색 org_type 검증 400');

    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-search', searchBody);
    let items = r.json.data || [];
    const calls1 = r.json._stub_calls;
    assert(r.status === 200 && items.length === 20 && r.json.cached === false, `검색 결과 20곳(15+5 쪽 넘김) (실제 ${items.length})`, [r.status, r.json.message]);
    assert(r.json.searched && r.json.searched[0].query === `서울특별시 테스트구 ${KW}`, '검색어 = 지역 + 키워드', r.json.searched);
    assert(items.every(it => !it.existing) && r.json.new_count === 20, '처음엔 모두 새 후보');
    assert(items[0].address.startsWith('서울특별시 테스트구') && items[0].region_sido === '서울특별시' && items[0].region_sigungu === '테스트구', '주소 정식 시도명으로 정규화 + 시도·시군구 분리', items[0]);
    assert(items.every(it => /^https:\/\/place\.map\.kakao\.com\/\d+$/.test(it.place_url)), '카카오맵 장소 주소(place_url)');

    // 다른 유형(교회)으로 같은 장소를 미리 넣어 두면 "이미 있음"으로 표시(이름+주소)
    const pre = items[2];
    r = await addOne({ name: pre.name, org_type: 'church', address: pre.address, region_sido: pre.region_sido, region_sigungu: pre.region_sigungu });
    assert(r.status === 201 && r.json.inserted === 1, '같은 장소를 다른 유형으로 미리 추가');
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-search', searchBody);
    items = r.json.data || [];
    assert(r.json.cached === true && r.json._stub_calls === calls1, `같은 검색은 캐시 사용(카카오 재호출 없음) (${calls1}→${r.json._stub_calls})`);
    const preHit = items.find(it => it.kakao_id === pre.kakao_id);
    assert(preHit && preHit.existing && preHit.existing.org_type === 'church' && r.json.new_count === 19, '이미 있는 후보 표시(유형이 달라도 이름+주소로 감지)');

    r = await api(member.token, 'POST', '/api/admin/prospects/kakao-import', { org_type: 'company', kakao_ids: [items[0].kakao_id] });
    assert(r.status === 403, `일반회원 외부 업체 추가 403 (${r.status})`);
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-import', { org_type: 'company', kakao_ids: ['999999999'] });
    assert(r.status === 400, '검색하지 않은 업체 ID 추가 400');
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-import', { org_type: 'bogus', kakao_ids: [items[0].kakao_id] });
    assert(r.status === 400, '추가 org_type 검증 400');
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-import', { org_type: 'company', kakao_ids: [items[0].kakao_id, items[1].kakao_id, pre.kakao_id] });
    assert(r.status === 201 && r.json.inserted === 2 && r.json.skipped_existing === 1, `선택 3곳 추가 → 2곳 추가·1곳 건너뜀 (${r.json.message})`);
    const { data: kr } = await admin.from('community_prospects').select('*').in('id', r.json.ids || []);
    const k0 = (kr || []).find(x => x.name === items[0].name);
    assert(k0 && k0.source === 'kakao_local' && k0.source_url === items[0].place_url && k0.org_type === 'company' && k0.region_sido === '서울특별시' && k0.region_sigungu === '테스트구' && k0.status === 'prospect' && !k0.promoted_community_id, 'DB: source=kakao_local · source_url=place_url · 구분·지역 저장(비공개 후보)', k0);
    assert(k0 && k0.dedup_key === `company_${items[0].name.replace(/\s+/g, '')}_${items[0].address.replace(/\s+/g, '').slice(0, 30)}`, '기존 중복 키 규칙(computeDedupKeyForProspect) 그대로');
    assert(k0 && (k0.phone || '') === (items[0].phone || ''), '전화번호 저장');
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-search', searchBody);
    items = r.json.data || [];
    assert(items.filter(it => it.existing).length === 3 && r.json.new_count === 17, '추가 후 재검색: 3곳 "이미 있음"');
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-import', { org_type: 'company', kakao_ids: [items[0].kakao_id] });
    assert(r.status === 201 && r.json.inserted === 0 && r.json.skipped_existing === 1, '같은 업체 다시 추가 → 건너뜀(중복 없음)');

    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-search', { org_type: 'apartment', address: `테스트 기준주소 ${ts}`, radius: 3000, keywords: ['아파트 관리사무소'] });
    assert(r.status === 200 && r.json.center && r.json.center.x && (r.json.data || []).length === 20, '기준 주소 + 반경 검색');
    r = await api(adm.token, 'POST', '/api/admin/prospects/kakao-search', { org_type: 'apartment', address: '__none__', keywords: ['아파트'] });
    assert(r.status === 400, `찾을 수 없는 주소 400 (${r.json.message})`);

    // ========== (4) 권한 ==========
    for (const [m, p, b] of [['GET', '/api/admin/prospects/recommend'], ['GET', '/api/admin/prospects/kakao-status'], ['POST', '/api/admin/prospects/kakao-search', searchBody], ['PUT', `/api/admin/communities/${coId}/logo`, { kind: 'logo', url: 'https://example.com/x.png' }], ['DELETE', `/api/admin/communities/${coId}/logo?kind=logo`]]) {
      r = await api(member.token, m, p, b);
      assert(r.status === 403, `일반회원 ${m} ${p.split('?')[0]} → 403 (${r.status})`);
    }
    r = await api(null, 'GET', '/api/admin/prospects/recommend');
    assert(r.status === 401, '비로그인 추천 401');
    r = await upload(member.token, coId, 'logo', PNG);
    assert(r.status === 403, '일반회원 조직 로고 업로드 403');

    // ========== (5) 분양 조직 로고·직인 ==========
    r = await api(adm.token, 'POST', '/api/admin/communities', { name: `${TAG} 로고검사`, slug: `test-prec-bad-${ts}`, logo_url: 'http://example.com/a.png' });
    assert(r.status === 400, `등록 시 http:// 로고 주소 400 (${r.json.message})`);
    if (r.json.data && r.json.data.id) communityIds.push(r.json.data.id);
    r = await api(adm.token, 'PUT', `/api/admin/communities/${coId}`, { stamp_url: 'javascript:alert(1)' });
    assert(r.status === 400, '수정 시 javascript: 직인 주소 400');
    r = await upload(adm.token, coId, 'bad', PNG);
    assert(r.status === 400, 'kind 검증 400');
    r = await upload(adm.token, coId, 'logo', GIF, 'image/gif');
    assert(r.status === 400, 'GIF 400');
    r = await upload(adm.token, coId, 'logo', Buffer.concat([PNG, Buffer.alloc(2 * 1024 * 1024)]));
    assert(r.status === 413, '2MB 초과 413');
    r = await upload(adm.token, '00000000-0000-4000-8000-000000000000', 'logo', PNG);
    assert(r.status === 404, '없는 조직 404');

    r = await upload(adm.token, coId, 'logo', PNG);
    const lp1 = r.json.data && r.json.data.logo_storage_path;
    assert(r.status === 201 && lp1 && lp1.startsWith(`withplus/community-logos/${coId}/logo-`) && lp1.endsWith('.png') && r.json.data.logo_url.includes(lp1), `로고 파일 업로드 201 (${lp1})`);
    assert(await fileExists(lp1), '저장소에 로고 파일 존재');
    assert((await fetch(r.json.data.logo_url)).status === 200, '로고 공개 주소 열림');
    r = await upload(adm.token, coId, 'logo', JPG_HEAD, 'image/jpeg');
    const lp2 = r.json.data && r.json.data.logo_storage_path;
    assert(r.status === 201 && lp2 !== lp1 && lp2.endsWith('.jpg') && !(await fileExists(lp1)) && (await fileExists(lp2)), '파일로 교체 → 이전 파일 삭제');
    r = await api(adm.token, 'PUT', `/api/admin/communities/${coId}/logo`, { kind: 'logo', url: 'https://example.com/prec-ext-logo.png' });
    assert(r.status === 200 && r.json.data.logo_url === 'https://example.com/prec-ext-logo.png' && r.json.data.logo_storage_path === null && !(await fileExists(lp2)), '주소로 교체 → 업로드 파일 삭제·storage_path 비움');
    r = await api(adm.token, 'DELETE', `/api/admin/communities/${coId}/logo?kind=logo`);
    assert(r.status === 200 && r.json.data.logo_url === null, '외부 주소 로고 삭제(원본은 외부라 저장소 작업 없음)');
    r = await api(adm.token, 'DELETE', `/api/admin/communities/${coId}/logo?kind=logo`);
    assert(r.status === 400, '로고 없는데 삭제 400');

    r = await upload(adm.token, coId, 'stamp', PNG);
    const sp1 = r.json.data && r.json.data.stamp_storage_path;
    assert(r.status === 201 && sp1 && sp1.startsWith(`withplus/community-logos/${coId}/stamp-`) && r.json.data.logo_url === null, '직인 파일 업로드(로고와 별개)');
    // 조직 수정 폼에서 같은 주소 그대로 저장 → 파일 유지
    r = await api(adm.token, 'PUT', `/api/admin/communities/${coId}`, { stamp_url: r.json.data.stamp_url, name: `${TAG} 회사조직` });
    assert(r.status === 200 && r.json.data.stamp_storage_path === sp1 && (await fileExists(sp1)), '수정 폼에서 직인 주소 그대로 저장 → 파일 유지');
    r = await api(adm.token, 'PUT', `/api/admin/communities/${coId}`, { stamp_url: '' });
    assert(r.status === 200 && r.json.data.stamp_url === null && r.json.data.stamp_storage_path === null && !(await fileExists(sp1)), '수정 폼에서 직인 비우기 → 업로드 파일도 삭제');
    r = await upload(adm.token, coId, 'logo', PNG);
    const lp3 = r.json.data && r.json.data.logo_storage_path;
    r = await api(adm.token, 'PUT', `/api/admin/communities/${coId}`, { logo_url: 'https://example.com/prec-form-logo.png' });
    assert(r.status === 200 && r.json.data.logo_url === 'https://example.com/prec-form-logo.png' && r.json.data.logo_storage_path === null && lp3 && !(await fileExists(lp3)), '수정 폼에서 주소로 바꾸면 이전 업로드 파일 삭제');
    // 예전 데이터(http 주소)는 그대로 다시 저장 가능, 새로 바꿀 때만 https 강제
    await admin.from('communities').update({ logo_url: 'http://legacy.example.com/logo.png' }).eq('id', coId);
    r = await api(adm.token, 'PUT', `/api/admin/communities/${coId}`, { logo_url: 'http://legacy.example.com/logo.png' });
    assert(r.status === 200, '예전 http 로고 주소는 바꾸지 않으면 저장 허용');
    r = await api(adm.token, 'PUT', `/api/admin/communities/${coId}`, { logo_url: 'http://other.example.com/logo.png' });
    assert(r.status === 400, '새 http 로고 주소 400');
    r = await upload(adm.token, coId, 'logo', PNG);
    const lp4 = r.json.data && r.json.data.logo_storage_path;
    r = await api(adm.token, 'DELETE', `/api/admin/communities/${coId}/logo?kind=logo`);
    assert(r.status === 200 && r.json.data.logo_storage_path === null && lp4 && !(await fileExists(lp4)), '업로드 로고 삭제 → 저장소 파일 삭제');
  } catch (err) {
    fail++;
    console.log('❌ 예외:', err.stack || err.message);
  } finally {
    // 이 테스트가 만든 것만 정리: 저장소 파일 → 후보 → 조직(회원 연결 포함) → 감사로그 → 계정
    for (const cid of communityIds) {
      const dir = `withplus/community-logos/${cid}`;
      const { data: files } = await admin.storage.from(BUCKET).list(dir, { limit: 100 });
      if (files && files.length) await admin.storage.from(BUCKET).remove(files.map(f => `${dir}/${f.name}`));
    }
    const { data: ps } = await admin.from('community_prospects').select('id').or(`name.like."${TAG}*",name.like."*${KW}*",name.like."*${ts}*"`);
    if (ps && ps.length) await admin.from('community_prospects').delete().in('id', ps.map(p => p.id));
    if (communityIds.length) {
      await admin.from('community_members').delete().in('community_id', communityIds);
      await admin.from('community_prospects').delete().in('promoted_community_id', communityIds);
      await admin.from('communities').delete().in('id', communityIds);
    }
    for (const uid of userIds) {
      await admin.from('community_members').delete().eq('user_id', uid);
      await admin.from('admin_audit_logs_with').delete().eq('admin_id', uid);
      await admin.from('profiles').delete().eq('id', uid);
      await admin.auth.admin.deleteUser(uid).catch(() => {});
      // 프로필 삭제가 DB 문장 시간 초과로 실패하는 경우가 있어 한 번 더 확인·재시도
      const { data: still } = await admin.from('profiles').select('id').eq('id', uid).maybeSingle();
      if (still) { await new Promise(r => setTimeout(r, 1500)); await admin.from('profiles').delete().eq('id', uid); await admin.auth.admin.deleteUser(uid).catch(() => {}); }
    }
    // 남은 것 확인
    const left = await Promise.all([
      admin.from('community_prospects').select('id', { count: 'exact', head: true }).or(`name.like."${TAG}*",name.like."*${KW}*"`),
      admin.from('communities').select('id', { count: 'exact', head: true }).like('name', `${TAG}*`),
      admin.from('profiles').select('id', { count: 'exact', head: true }).like('email', `test-prec-%-${ts}@withplus-test.local`)
    ]);
    const leftCount = left.reduce((s, x) => s + (x.count || 0), 0);
    if (leftCount === 0) { pass++; console.log('✅ 정리 완료(테스트 후보·조직·계정 0건 남음)'); } else { fail++; console.log('❌ 정리 후 남은 테스트 데이터', left.map(x => x.count)); }
    if (child) child.kill();
    console.log(`\n결과: ${pass} 통과 / ${fail} 실패`);
    process.exit(fail ? 1 : 0);
  }
}
main();
