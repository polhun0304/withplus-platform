// 품질·거버넌스 관리자 API(qg/qg-router.js) 단위 시험 — DB·계정 없이 가짜 Supabase 클라이언트로 라우팅·입력 검사·토큰 전달을 확인한다.
// 실행: node scripts/test-qg-router.js   (운영 DB 에 아무것도 쓰지 않는다)
const express = require('express');
const http = require('http');
const createQgRouter = require('../qg/qg-router');

let pass = 0, fail = 0;
function assert(cond, msg) { if (cond) { pass++; console.log('✅', msg); } else { fail++; console.log('❌', msg); } }

const calls = [];
function fakeCreateClient(url, key, opts) {
  const auth = opts && opts.global && opts.global.headers && opts.global.headers.Authorization;
  const chain = (table) => {
    const q = { table, filters: [], auth };
    const api = {
      select() { return api; }, order() { return api; }, limit() { return api; }, in(c, v) { q.filters.push(['in', c, v]); return api; },
      eq(c, v) { q.filters.push(['eq', c, v]); return api; },
      then(resolve) { calls.push({ kind: 'from', ...q }); resolve({ data: table === 'wpl_qg_runs' ? [{ id: 'r1' }] : [], error: null }); },
    };
    return api;
  };
  return {
    from: chain,
    rpc: async (name, args) => {
      calls.push({ kind: 'rpc', name, args, auth });
      if (name === 'wpl_qg_run_engine') return { data: '00000000-0000-4000-8000-000000000099', error: null };
      if (name === 'wpl_qg_issue_transition' && args.p_to === 'verified') return { data: null, error: { message: '이 상태로는 바꿀 수 없습니다.' } };
      if (name === 'wpl_qg_review_request') return { data: { review_id: 'rv', reviewers: [{ code: 'legal' }, { code: 'privacy' }] }, error: null };
      return { data: { ok: true }, error: null };
    },
  };
}

const app = express();
app.use('/api/admin/qg', createQgRouter({ createClient: fakeCreateClient, supabaseUrl: 'http://x', supabaseAnonKey: 'anon', siteLabel: 'WITH+' }));

function req(method, path, body, token = 'tok-admin') {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port: server.address().port, method, path,
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) } }, (res) => {
      let s = ''; res.on('data', (c) => { s += c; }); res.on('end', () => { let j = null; try { j = JSON.parse(s); } catch (e) {} resolve({ status: res.statusCode, json: j, headers: res.headers, raw: s }); });
    });
    if (data) r.write(data); r.end();
  });
}

const server = app.listen(0, async () => {
  try {
    let r = await req('GET', '/api/admin/qg/dashboard', null, null);
    assert(r.status === 401, '토큰 없으면 401');
    r = await req('GET', '/api/admin/qg/dashboard');
    assert(r.status === 200 && r.json.data.site === 'WITH+', '대시보드 200 + 사이트 표시');
    assert(calls.some((c) => c.kind === 'rpc' && c.name === 'wpl_qg_dashboard' && c.auth === 'Bearer tok-admin'), 'RPC 를 요청한 관리자 토큰으로 부름(서비스 키 아님)');
    r = await req('POST', '/api/admin/qg/engines/integrity/run');
    assert(r.status === 200 && r.json.data.run_id, '엔진 지금 실행');
    r = await req('POST', '/api/admin/qg/engines/drop_table/run');
    assert(r.status === 400, '모르는 엔진 거부');
    r = await req('POST', '/api/admin/qg/engines/all/run');
    assert(r.status === 200 && r.json.data.length === 10, '엔진 10종 모두 실행');
    r = await req('POST', '/api/admin/qg/issues/not-a-uuid/transition', { to: 'fixed' });
    assert(r.status === 400 && /골라/.test(r.json.message), 'UUID 아닌 이슈 id 거부(손입력 방지)');
    const iid = '11111111-1111-4111-8111-111111111111';
    r = await req('POST', `/api/admin/qg/issues/${iid}/transition`, { to: 'accepted_risk', note: '짧음' });
    assert(r.status === 400 && /10자/.test(r.json.message), '위험 수용은 사유 10자 이상');
    r = await req('POST', `/api/admin/qg/issues/${iid}/transition`, { to: 'accepted_risk', note: '시험 데이터라 위험을 받아들입니다' });
    assert(r.status === 200, '사유가 있으면 위험 수용 요청 전달');
    r = await req('POST', `/api/admin/qg/issues/${iid}/transition`, { to: 'deleted' });
    assert(r.status === 400, '없는 상태 거부');
    r = await req('POST', `/api/admin/qg/issues/${iid}/transition`, { to: 'verified' });
    assert(r.status === 400 && r.json.message === '이 상태로는 바꿀 수 없습니다.', 'DB 오류 문구를 사람 말 그대로 전달');
    r = await req('POST', '/api/admin/qg/releases', { git_sha: 'not-sha' });
    assert(r.status === 400, '커밋 SHA 형식 검사');
    r = await req('POST', '/api/admin/qg/releases', { git_sha: 'abcdef1234567' });
    assert(r.status === 200 && calls.some((c) => c.name === 'wpl_qg_release_create' && c.args.p_kind === 'code_deploy'), '코드 배포 출시 후보 만들기');
    r = await req('POST', `/api/admin/qg/releases/${iid}/decide`, { decision: 'rejected', note: '' });
    assert(r.status === 400, '출시 거절은 사유 필수');
    r = await req('POST', '/api/admin/qg/reviews', { target: iid });
    assert(r.status === 200 && calls.filter((c) => c.name === 'wpl_qg_review_submit').length === 2 && calls.some((c) => c.name === 'wpl_qg_review_finalize'), '검토 요청 → 검토자별 판정 → 합의');
    r = await req('POST', '/api/admin/qg/regulations/BAD%20CODE/reviewed', { note: '확인했습니다' });
    assert(r.status === 400 || r.status === 404, '법령 코드 형식 검사');
    r = await req('GET', '/api/admin/qg/evidence/export');
    assert(r.status === 200 && /attachment; filename="qg-evidence-wpl-\d{4}-\d{2}-\d{2}\.json"/.test(r.headers['content-disposition'] || ''), '증거 내려받기(한국 날짜 파일 이름)');
    // 서버 코드 출시 관문 종류(v1.2): 대상 목록·후보 만들기·관찰 요약
    r = await req('GET', '/api/admin/qg/releases/targets?kind=supplier_approve');
    assert(r.status === 200 && calls.some((c) => c.name === 'wpl_qg_release_target_list' && c.args.p_kind === 'supplier_approve' && c.auth === 'Bearer tok-admin'), '출시 대상 목록(관리자 토큰으로 DB 확인)');
    r = await req('GET', '/api/admin/qg/releases/targets?kind=DROP');
    assert(r.status === 400, '출시 종류 형식 검사');
    r = await req('GET', '/api/admin/qg/releases/targets?kind=code_deploy');
    assert(r.status === 400, '코드 배포는 대상 목록 없음(커밋 SHA 입력)');
    r = await req('POST', '/api/admin/qg/releases', { kind: 'live_go_live', target: '' });
    assert(r.status === 400 && /목록/.test(r.json.message), '대상 없는 후보 거부');
    r = await req('POST', '/api/admin/qg/releases', { kind: 'supplier_approve', target: iid });
    assert(r.status === 200 && calls.some((c) => c.name === 'wpl_qg_release_create' && c.args.p_kind === 'supplier_approve' && c.args.p_target === iid && c.args.p_git_sha === null), '입점 승인 출시 후보 만들기');
    r = await req('GET', '/api/admin/qg/releases/observations');
    assert(r.status === 200 && Array.isArray(r.json.data.summary) && calls.some((c) => c.kind === 'from' && c.table === 'wpl_qg_release_observations'), '서버 코드 출시 관찰 요약');
    r = await req('GET', '/api/admin/qg/releases/kinds');
    assert(r.status === 200 && calls.some((c) => c.kind === 'from' && c.table === 'wpl_qg_gate_policies'), '출시 종류(관문 정책) 목록');
    r = await req('GET', '/api/admin/qg/nothing');
    assert(r.status === 404, '없는 기능 404');
  } catch (e) { fail++; console.log('❌ 예외', e.message); }
  server.close();
  console.log(`\n결과: 통과 ${pass} · 실패 ${fail}`);
  process.exit(fail ? 1 : 0);
});
