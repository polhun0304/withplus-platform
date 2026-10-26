// 서버 코드 출시 관문(qg/release-gate.js) + server.js 공개·승인 라우트 연결 시험 — DB·계정 없이(운영 DB 에 아무것도 쓰지 않는다).
//  A. 헬퍼 단위 시험: 강제 꺼짐 = 절대 막지 않음(RPC 없음·실패·연결 없음 포함), 켜짐 + 승인 없음 = 사람 말 거부, 완료 기록은 절대 던지지 않음.
//  B. 라우트 동등성 시험: server.js 를 가짜 Supabase 로 띄워 '관문을 뺀 원래 server.js'(QG 줄만 지운 사본)와
//     같은 요청을 보내고 응답(상태·본문)과 업무 DB 쓰기(표·내용)가 완전히 같은지 비교한다 — 강제 스위치 꺼짐·RPC 없음·승인 후보 있음.
//     켜짐 + 승인 없음이면 409 + 사람 말 메시지, 업무 DB 쓰기 0.
// 실행: node scripts/test-qg-release-gate.js
const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const APP_ID = '2b1f6c3e-6a1d-4c55-9f1e-0a0b0c0d0e01';
const APPLICANT = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const ADMIN = 'a0000000-0000-4000-8000-0000000000ad';
const CHANNEL = '3d6f0a2b-1c4e-4f5a-8b9c-0d1e2f3a4b5c';
const SESSION = '9f8e7d6c-5b4a-4321-8fed-cba987654321';

// ───────────────────────── B. 자식 프로세스: server.js 를 가짜 의존성으로 띄우고 시나리오 실행 ─────────────────────────
if (process.argv[2] === '--child') {
  const serverFile = process.argv[3];
  const mode = process.argv[4];   // off | missing | on | approved
  const Module = require('module');
  const writes = []; const rpcs = [];
  const scrub = (v) => JSON.parse(JSON.stringify(v === undefined ? null : v, (k, x) => (/(_at|^at|^timestamp)$/.test(k) && typeof x === 'string' ? '<ts>' : x)));
  const tableRow = (table, filters) => {
    const id = (filters.find((f) => f[0] === 'eq' && f[1] === 'id') || [])[2];
    if (table === 'profiles') return { id, is_active: true, role: id === ADMIN ? 'admin' : 'member' };
    if (table === 'supplier_applications_with' || table === 'wholesale_applications_with') return { id: APP_ID, applicant_id: APPLICANT, company_name: '시험 상사', status: 'pending' };
    if (/^live_sessions_/.test(table)) return { id: SESSION, channel_id: CHANNEL, title: '시험 방송', status: 'scheduled' };
    return null;
  };
  function builder(table) {
    const st = { table, op: 'select', payload: null, filters: [], single: false };
    const api = new Proxy({}, {
      get(_, prop) {
        if (prop === 'then') {
          return (resolve, reject) => {
            let data = null;
            if (st.op === 'select') {
              const row = tableRow(table, st.filters);
              data = st.single ? row : (row ? [row] : []);
            } else {
              writes.push({ table, op: st.op, payload: scrub(st.payload), filters: st.filters.map((f) => f.slice(0, 3)) });
              const base = tableRow(table, st.filters) || {};
              const p = Array.isArray(st.payload) ? st.payload[0] : st.payload;
              data = st.single ? { ...base, ...(p || {}) } : [{ ...base, ...(p || {}) }];
            }
            Promise.resolve({ data, error: null, count: 0 }).then(resolve, reject);
          };
        }
        return (...a) => {
          if (['insert', 'update', 'upsert', 'delete'].includes(prop)) { st.op = prop; st.payload = a[0]; }
          else if (prop === 'single' || prop === 'maybeSingle') st.single = true;
          else if (['eq', 'neq', 'in', 'is', 'gt', 'lt', 'gte', 'lte', 'like', 'ilike'].includes(prop)) st.filters.push([prop, a[0], a[1]]);
          return api;
        };
      },
    });
    return api;
  }
  const fakeClient = {
    from: (t) => builder(t),
    rpc: async (name, args) => {
      rpcs.push({ name, args });
      if (name === 'wpl_qg_release_gate_check_server') {
        if (mode === 'missing') return { data: null, error: { message: 'Could not find the function public.wpl_qg_release_gate_check_server' } };
        if (mode === 'on') return { data: { ok: true, allowed: false, enforced: true, would_block: true, reason: 'no_approved', release_id: null, observation_id: 11,
          message: '품질·거버넌스 출시 관문을 통과·승인한 기록이 없어 판매자 입점 승인을 진행할 수 없습니다. (시험 문구)' }, error: null };
        if (mode === 'approved') return { data: { ok: true, allowed: true, enforced: true, would_block: false, reason: 'approved', release_id: 'r1', rel_no: 7, observation_id: 12 }, error: null };
        return { data: { ok: true, allowed: true, enforced: false, would_block: true, reason: 'no_approved', release_id: null, observation_id: 10, message: null }, error: null };
      }
      if (name === 'wpl_qg_release_mark_server') {
        if (mode === 'missing') throw new Error('network down');   // 완료 기록 실패도 응답을 바꾸지 않아야 함
        return { data: { ok: true, linked: mode === 'approved', release_id: mode === 'approved' ? 'r1' : null, reason: mode === 'approved' ? 'linked' : 'no_approved' }, error: null };
      }
      return { data: null, error: null };
    },
    auth: {
      getUser: async (tok) => ({ data: { user: tok === 'tok-admin' ? { id: ADMIN, email: 'admin@test.local', user_metadata: {}, factors: [] } : null }, error: tok === 'tok-admin' ? null : { message: 'bad' } }),
      admin: new Proxy({}, { get: () => async () => ({ data: {}, error: null }) }),
    },
    storage: new Proxy({}, { get: () => () => new Proxy({}, { get: () => async () => ({ data: null, error: null }) }) }),
    channel: () => new Proxy({}, { get: () => () => ({}) }),
  };
  const fakes = {
    '@supabase/supabase-js': { createClient: () => fakeClient },
    'node-cron': { schedule: () => ({ stop() {} }) },
    nodemailer: { createTransport: () => ({ sendMail: async () => ({}), verify: async () => true }) },
    'web-push': { setVapidDetails() {}, sendNotification: async () => ({}), generateVAPIDKeys: () => ({ publicKey: 'x', privateKey: 'y' }) },
  };
  const origLoad = Module._load;
  Module._load = function (req, parent, isMain) { if (Object.prototype.hasOwnProperty.call(fakes, req)) return fakes[req]; return origLoad.apply(this, arguments); };
  const origWarn = console.warn; const origErr = console.error; const origLog = console.log;
  console.warn = () => {}; console.error = () => {}; console.log = () => {};
  const http = require('http');
  let server = null;
  const origListen = http.Server.prototype.listen;
  http.Server.prototype.listen = function (...a) { server = this; return origListen.call(this, 0, '127.0.0.1', typeof a[a.length - 1] === 'function' ? a[a.length - 1] : undefined); };
  process.env.PORT = '0';
  process.env.NEXT_PUBLIC_SUPABASE_URL = 'http://fake.local'; process.env.SUPABASE_SERVICE_ROLE_KEY = 'service-fake'; process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'anon-fake';
  process.env.JWT_SECRET = 'test-secret-only-for-unit-test';
  require(path.resolve(serverFile));

  const send = (method, url, body) => new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port: server.address().port, method, path: url,
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok-admin', ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) } }, (res) => {
      let s = ''; res.on('data', (c) => { s += c; }); res.on('end', () => { let j = null; try { j = JSON.parse(s); } catch (_) {} resolve({ status: res.statusCode, body: scrub(j) }); });
    });
    if (data) r.write(data); r.end();
  });
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  (async () => {
    for (let i = 0; i < 100 && !(server && server.listening); i++) await wait(20);
    const out = {};
    const cases = [
      ['supplier', 'PUT', `/api/admin/supplier-applications/${APP_ID}/approve`, null],
      ['wholesale', 'PUT', `/api/admin/wholesale-applications/${APP_ID}/approve`, null],
      ['live_on', 'PATCH', `/api/admin/live/channels/${CHANNEL}/sessions/${SESSION}`, { status: 'live' }],
      ['live_end', 'PATCH', `/api/admin/live/channels/${CHANNEL}/sessions/${SESSION}`, { status: 'ended' }],
      ['live_bad', 'PATCH', `/api/admin/live/channels/${CHANNEL}/sessions/${SESSION}`, { status: 'paused' }],
    ];
    for (const [name, method, url, body] of cases) {
      writes.length = 0; rpcs.length = 0;
      const res = await send(method, url, body);
      await wait(150);   // 응답 뒤 기록(관리자 감사로그 등)까지
      out[name] = { res, writes: writes.filter((w) => w.table !== 'admin_audit_logs_with').slice(), auditWrites: writes.filter((w) => w.table === 'admin_audit_logs_with').length,
        qgRpcs: rpcs.filter((x) => /^wpl_qg_/.test(x.name)).map((x) => ({ name: x.name, kind: x.args.p_kind, ref: x.args.p_ref, key: x.args.p_server_key })) };
    }
    console.warn = origWarn; console.error = origErr; console.log = origLog;
    process.stdout.write('@@RESULT@@' + JSON.stringify(out));
    process.exit(0);
  })().catch((e) => { process.stdout.write('@@RESULT@@' + JSON.stringify({ crash: e.message })); process.exit(1); });
  return;
}

// ───────────────────────── 부모: A 단위 시험 + B 비교 ─────────────────────────
let pass = 0, fail = 0;
function assert(cond, msg, extra) { if (cond) { pass++; console.log('✅', msg); } else { fail++; console.log('❌', msg, extra !== undefined ? JSON.stringify(extra).slice(0, 600) : ''); } }

const { createQgReleaseGate, QgReleaseBlockedError } = require('../qg/release-gate');

async function partA() {
  const silence = console.warn; console.warn = () => {};
  const mk = (impl) => { const calls = []; return { calls, db: { rpc: async (n, a) => { calls.push({ n, a }); return impl(n, a); } } }; };
  // 꺼짐: 승인 후보 없어도 통과 + 관찰 기록
  let f = mk(() => ({ data: { ok: true, allowed: true, enforced: false, would_block: true, reason: 'no_approved', observation_id: 5 }, error: null }));
  let g = createQgReleaseGate({ db: f.db });
  let r = await g.qgReleaseGate({ kind: 'supplier_approve', ref: '  ABCDEF00-0000-4000-8000-000000000001 ' });
  assert(r.allowed && !r.enforced && r.wouldBlock && r.observed && r.observationId === 5, '꺼짐: 승인 없음이어도 통과 + 켰다면 막힘 관찰');
  assert(f.calls[0].n === 'wpl_qg_release_gate_check_server' && f.calls[0].a.p_ref === 'abcdef00-0000-4000-8000-000000000001' && f.calls[0].a.p_server_key === null,
    '서버 확인 RPC 이름·ref 정규화(소문자·공백 제거)·service_role 이라 서버 증명키 없음');
  // 꺼짐 + DB 함수 없음 / 호출 예외 / 연결 없음 → 모두 통과(던지지 않음)
  g = createQgReleaseGate({ db: mk(() => ({ data: null, error: { message: 'function does not exist' } })).db });
  r = await g.qgReleaseGate({ kind: 'k1', ref: 'x' });
  assert(r.allowed && !r.observed && r.reason === 'error', 'DB 함수 없음: 경고만 남기고 통과');
  g = createQgReleaseGate({ db: { rpc: async () => { throw new Error('ECONNRESET'); } } });
  r = await g.qgReleaseGate({ kind: 'k1', ref: 'x' });
  assert(r.allowed && r.error === 'ECONNRESET', '호출 예외: 통과');
  g = createQgReleaseGate({ db: null });
  r = await g.qgReleaseGate({ kind: 'k1', ref: 'x' });
  assert(r.allowed && r.error === 'no_server_client', '연결 없음: 통과');
  // failClosed 를 준 경우만 호출 실패에서 막음
  let threw = null;
  try { await createQgReleaseGate({ db: null, failClosed: true }).qgReleaseGate({ kind: 'k1', ref: 'x' }); } catch (e) { threw = e; }
  assert(threw instanceof QgReleaseBlockedError && /확인하지 못해/.test(threw.message), 'failClosed: 확인 실패면 사람 말로 막음');
  // 켜짐 + 승인 없음 → 사람 말 거부
  const msg = '품질·거버넌스 출시 관문을 통과·승인한 기록이 없어 라이브 방송 공개 시작을 진행할 수 없습니다.';
  g = createQgReleaseGate({ db: mk(() => ({ data: { ok: true, allowed: false, enforced: true, would_block: true, reason: 'no_approved', message: msg }, error: null })).db });
  threw = null;
  try { await g.qgReleaseGate({ kind: 'live_go_live', ref: 'x' }); } catch (e) { threw = e; }
  assert(threw instanceof QgReleaseBlockedError && threw.message === msg && threw.result.enforced, '켜짐 + 승인 없음: QgReleaseBlockedError(사람 말 그대로)');
  r = await g.qgReleaseGate({ kind: 'live_go_live', ref: 'x' }, { throwOnBlock: false });
  assert(!r.allowed && r.message === msg, 'throwOnBlock:false 면 결과만 돌려줌');
  // Express 응답 도우미
  const resMock = () => { const o = { code: 200, body: null, status(c) { o.code = c; return o; }, json(b) { o.body = b; return o; } }; return o; };
  let res = resMock();
  assert(await g.qgReleaseBlocked(res, { kind: 'live_go_live', ref: 'x' }) === true && res.code === 409 && res.body.message === msg, '켜짐: 라우트 응답 409 + 사람 말');
  res = resMock();
  assert(await createQgReleaseGate({ db: f.db }).qgReleaseBlocked(res, { kind: 'supplier_approve', ref: 'x' }) === false && res.body === null, '꺼짐: 라우트 응답 손대지 않음');
  // 완료 기록: 성공·실패·예외 어느 경우도 던지지 않음
  f = mk(() => ({ data: { ok: true, linked: true, release_id: 'r9', rel_no: 9, reason: 'linked' }, error: null }));
  r = await createQgReleaseGate({ db: f.db }).qgReleaseMarkReleased({ kind: 'supplier_approve', ref: 'A', note: '승인' });
  assert(r.ok && r.linked && r.relNo === 9 && f.calls[0].n === 'wpl_qg_release_mark_server' && f.calls[0].a.p_note === '승인' && f.calls[0].a.p_ref === 'a', '완료 기록: 승인 후보 연결');
  r = await createQgReleaseGate({ db: { rpc: async () => { throw new Error('boom'); } } }).qgReleaseMarkReleased({ kind: 'k', ref: 'x' });
  assert(!r.ok && r.reason === 'error', '완료 기록 예외: 던지지 않음');
  r = await createQgReleaseGate({ db: mk(() => ({ data: null, error: { message: 'nope' } })).db }).qgReleaseMarkReleased({ kind: 'k', ref: 'x' });
  assert(!r.ok, '완료 기록 DB 오류: 던지지 않음');
  // withQgReleaseGate: 반환값 그대로, 실패면 완료 기록 안 함
  f = mk((n) => (n === 'wpl_qg_release_gate_check_server' ? { data: { allowed: true }, error: null } : { data: { ok: true }, error: null }));
  g = createQgReleaseGate({ db: f.db });
  const out = await g.withQgReleaseGate({ kind: 'k', ref: 'x' }, async () => ({ failed: 1 }), { isSuccess: (x) => x.failed === 0 });
  assert(out.failed === 1 && !f.calls.some((c) => c.n === 'wpl_qg_release_mark_server'), 'withQgReleaseGate: 원래 결과 그대로 · 일부 실패면 완료 기록 안 함');
  threw = null;
  try { await g.withQgReleaseGate({ kind: 'k', ref: 'x' }, async () => { throw new Error('원래 오류'); }); } catch (e) { threw = e; }
  assert(threw && threw.message === '원래 오류', 'withQgReleaseGate: 원래 예외 그대로 전달');
  console.warn = silence;
}

function runChild(serverFile, mode) {
  const r = spawnSync(process.execPath, [__filename, '--child', serverFile, mode], { cwd: ROOT, encoding: 'utf8', timeout: 120000, maxBuffer: 64 * 1024 * 1024 });
  const s = String(r.stdout || '');
  const i = s.lastIndexOf('@@RESULT@@');
  if (i < 0) return { crash: (r.stderr || s).slice(-800) };
  return JSON.parse(s.slice(i + '@@RESULT@@'.length));
}

async function partB() {
  const cur = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
  // '관문을 뺀 원래 server.js' = QG 출시 관문 줄만 지운 사본(머리 주석 4줄 + 생성 1줄 + 라우트마다 ①·② 줄)
  const lines = cur.split('\n'); const kept = []; let skip = false; let removed = 0;
  for (const ln of lines) {
    if (ln.startsWith('// 품질·거버넌스(QG) 서버 코드 출시 관문(QG 키트 v1.2')) skip = true;
    if (skip) { removed++; if (ln.startsWith('const qgRelease = ')) skip = false; continue; }
    if (/qgRelease\.|const qgTarget = |\[QG\] 출시 관문/.test(ln)) { removed++; continue; }
    kept.push(ln);
  }
  // 지운 줄 뒤에 남는 빈 줄 하나(①의 뒤)는 동작과 무관
  assert(removed >= 5 + 3 * 3 + 3 && !/qgRelease|release-gate/.test(kept.join('\n')), `관문 줄만 지운 원래 server.js 사본 만들기(지운 줄 ${removed})`);
  const baseFile = path.join(ROOT, `.qg-baseline-server-${process.pid}.tmp.js`);
  fs.writeFileSync(baseFile, kept.join('\n'));
  let base, off, missing, on, approved;
  try {
    base = runChild(baseFile, 'off');
    off = runChild(path.join(ROOT, 'server.js'), 'off');
    missing = runChild(path.join(ROOT, 'server.js'), 'missing');
    approved = runChild(path.join(ROOT, 'server.js'), 'approved');
    on = runChild(path.join(ROOT, 'server.js'), 'on');
  } finally { fs.rmSync(baseFile, { force: true }); }
  if (base.crash || off.crash) { assert(false, '서버 띄우기', base.crash || off.crash); return; }
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  for (const name of ['supplier', 'wholesale', 'live_on', 'live_end', 'live_bad']) {
    assert(base[name].res.status === (name === 'live_bad' ? 400 : 200), `원래 server.js ${name}: 기대 상태(${base[name].res.status})`);
    for (const [label, run] of [['강제 꺼짐', off], ['관문 RPC 없음·완료 기록 실패', missing], ['승인 후보 있음(켜짐)', approved]]) {
      assert(same(run[name].res, base[name].res), `${name} · ${label}: 응답(상태·본문) 원래와 같음`, { base: base[name].res, now: run[name].res });
      assert(same(run[name].writes, base[name].writes) && run[name].auditWrites === base[name].auditWrites, `${name} · ${label}: 업무 DB 쓰기(표·내용·순서) 원래와 같음`,
        { base: base[name].writes, now: run[name].writes });
    }
  }
  // 관문 호출 위치: 승인 2종 = 확인 → 완료 기록, 라이브 = 방송 중으로 바꿀 때만
  const kinds = (run, name) => run[name].qgRpcs.map((x) => `${x.name.replace('wpl_qg_release_', '')}:${x.kind}`).join(',');
  assert(kinds(off, 'supplier') === 'gate_check_server:supplier_approve,mark_server:supplier_approve' && off.supplier.qgRpcs[0].ref === APP_ID, '입점 승인: 확인 → 성공 뒤 완료 기록(ref = 신청 id)');
  assert(kinds(off, 'wholesale') === 'gate_check_server:wholesale_approve,mark_server:wholesale_approve', '도매 승인: 확인 → 성공 뒤 완료 기록');
  assert(kinds(off, 'live_on') === 'gate_check_server:live_go_live,mark_server:live_go_live' && off.live_on.qgRpcs[0].ref === SESSION, '라이브 공개 시작: 확인 → 성공 뒤 완료 기록(ref = 세션 id)');
  assert(off.live_end.qgRpcs.length === 0 && off.live_bad.qgRpcs.length === 0, '라이브 종료·잘못된 상태: 관문 호출 없음');
  assert(off.supplier.qgRpcs.every((x) => x.key === null), '서비스 키 클라이언트라 서버 증명키를 보내지 않음');
  // 켜짐 + 승인 없음: 409 사람 말, 업무 쓰기 0, 완료 기록 안 함
  for (const name of ['supplier', 'wholesale', 'live_on']) {
    assert(on[name].res.status === 409 && /출시 관문/.test(on[name].res.body.message) && !/qg_enforce/.test(on[name].res.body.message), `${name} · 켜짐 + 승인 없음: 409 + 사람 말 거부`, on[name].res);
    assert(on[name].writes.length === 0, `${name} · 켜짐 + 승인 없음: 권한·신청·세션 변경 없음`, on[name].writes);
    assert(!on[name].qgRpcs.some((x) => x.name === 'wpl_qg_release_mark_server'), `${name} · 켜짐 + 승인 없음: 완료 기록 안 함`);
  }
  assert(same(on.live_end.res, base.live_end.res) && same(on.live_end.writes, base.live_end.writes), '켜짐이어도 방송 종료는 그대로');
}

(async () => {
  try { await partA(); await partB(); } catch (e) { fail++; console.log('❌ 예외', e && e.stack); }
  console.log(`\n결과: 통과 ${pass} · 실패 ${fail}`);
  process.exit(fail ? 1 : 0);
})();
