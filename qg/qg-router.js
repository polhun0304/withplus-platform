// =====================================================================
// 품질·거버넌스(QG) 관리자 API — WITH+ · LIVE+ 공용(같은 운영 DB 의 wpl_qg_* 를 쓴다). QG 키트 §9.3 Express 변형.
//  · 서버가 server.js 에서 authenticate + requireRole(['admin','super_admin']) 뒤에 붙인다(권한 확인이 먼저).
//  · DB 호출은 서비스 키가 아니라 "요청한 관리자의 토큰"으로 만든 클라이언트로 한다 → auth.uid() 가 채워져
//    QG RPC 안의 관리자 확인(wpl_qga_is_admin)·RLS 가 한 번 더 막는다(서비스 키로 부르면 관리자 RPC 가 거부됨).
//  · 되돌리기 어려운 동작(위험 수용·오탐·출시 결정)은 사유를 받는다. 화면 문구는 한국어.
// =====================================================================
const express = require('express');

const P = 'wpl';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ENGINES = ['review', 'testing', 'adversarial', 'compliance', 'evidence', 'release', 'security', 'integrity', 'ai_model', 'evolution'];
const ISSUE_TO = ['acknowledged', 'fixed', 'verified', 'accepted_risk', 'false_positive', 'open'];
const PROPOSAL_TO = ['accepted', 'declined', 'in_progress', 'shipped', 'verified', 'proposed'];
const t = (n) => `${P}_qg_${n}`;

function clip(v, max) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return s ? s.slice(0, max) : null;
}

module.exports = function createQgRouter({ createClient, supabaseUrl, supabaseAnonKey, siteLabel }) {
  const router = express.Router();
  router.use(express.json({ limit: '200kb' }));

  // 요청한 관리자의 토큰으로 DB 클라이언트(세션 저장 없음)
  router.use((req, res, next) => {
    const token = (req.headers.authorization || '').split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized', message: '관리자 로그인이 필요합니다' });
    req.qgdb = createClient(supabaseUrl, supabaseAnonKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      global: { headers: { Authorization: `Bearer ${token}` } },
    });
    next();
  });

  const ok = (res, data) => res.json({ success: true, data, timestamp: new Date().toISOString() });
  const fail = (res, err, status = 400) => {
    const msg = (err && (err.message || err.details)) || '처리하지 못했습니다';
    return res.status(status).json({ error: 'QG', message: String(msg).slice(0, 500), timestamp: new Date().toISOString() });
  };
  const rpc = async (req, name, args) => {
    const { data, error } = await req.qgdb.rpc(t(name), args || {});
    if (error) throw Object.assign(new Error(error.message), { status: 400 });
    return data;
  };
  const sel = async (q) => { const { data, error } = await q; if (error) throw new Error(error.message); return data || []; };
  const needUuid = (v, what) => { if (!UUID_RE.test(String(v || ''))) throw Object.assign(new Error(`${what}를 목록에서 골라 주세요.`), { status: 400 }); return v; };
  const route = (fn) => async (req, res) => {
    try { await fn(req, res); } catch (e) { fail(res, e, e.status || 500); }
  };

  // 센터: 대시보드 + 어댑터 정보
  router.get('/dashboard', route(async (req, res) => {
    const [dash, info] = await Promise.all([rpc(req, 'dashboard'), rpc(req, 'adapter_info')]);
    ok(res, { dashboard: dash, adapter: info, site: siteLabel });
  }));

  // 엔진 지금 실행(엔진 하나 또는 전체)
  router.post('/engines/:code/run', route(async (req, res) => {
    const code = String(req.params.code);
    if (code === 'all') {
      const out = [];
      for (const e of ENGINES) {
        try { out.push({ engine: e, run_id: await rpc(req, 'run_engine', { p_engine: e, p_tenant: null }) }); }
        catch (err) { out.push({ engine: e, error: err.message }); }
      }
      return ok(res, out);
    }
    if (!ENGINES.includes(code)) throw Object.assign(new Error('알 수 없는 엔진입니다.'), { status: 400 });
    ok(res, { run_id: await rpc(req, 'run_engine', { p_engine: code, p_tenant: null }) });
  }));

  // 이슈함
  router.get('/issues', route(async (req, res) => {
    const status = String(req.query.status || 'active');
    let q = req.qgdb.from(t('issues')).select('id,engine_code,check_code,tenant_id,severity,title,status,first_seen,last_seen,last_pass_at,occurrences,last_run_id,last_detail,due_at,note,status_changed_at')
      .order('last_seen', { ascending: false }).limit(300);
    if (status === 'active') q = q.in('status', ['open', 'acknowledged']);
    else if (status !== 'all') q = q.eq('status', status);
    if (req.query.engine && ENGINES.includes(String(req.query.engine))) q = q.eq('engine_code', String(req.query.engine));
    ok(res, await sel(q));
  }));
  router.post('/issues/:id/transition', route(async (req, res) => {
    const id = needUuid(req.params.id, '이슈');
    const to = String((req.body || {}).to || '');
    if (!ISSUE_TO.includes(to)) throw Object.assign(new Error('바꿀 상태를 골라 주세요.'), { status: 400 });
    const note = clip((req.body || {}).note, 2000);
    if ((to === 'accepted_risk' || to === 'false_positive') && (!note || note.length < 10)) {
      throw Object.assign(new Error('위험 수용·오탐 처리는 사유를 10자 이상 적어 주세요.'), { status: 400 });
    }
    ok(res, await rpc(req, 'issue_transition', { p_issue: id, p_to: to, p_note: note }));
  }));
  // 확인 대기(고침 + 다음 실행 통과) 모두 해결 확인
  router.post('/issues/verify-fixed', route(async (req, res) => {
    const rows = await sel(req.qgdb.from(t('issues')).select('id,last_pass_at,last_seen').eq('status', 'fixed').limit(500));
    const ids = rows.filter((r) => r.last_pass_at && r.last_pass_at >= r.last_seen).map((r) => r.id);
    if (!ids.length) return ok(res, { changed: 0 });
    ok(res, await rpc(req, 'issue_bulk_transition', { p_ids: ids, p_to: 'verified', p_note: clip((req.body || {}).note, 500) || '다음 실행에서 통과해 해결 확인' }));
  }));

  // 실행 기록
  router.get('/runs', route(async (req, res) => {
    let q = req.qgdb.from(t('runs')).select('id,engine_code,tenant_id,trigger,schedule,started_at,finished_at,duration_ms,checks_run,totals,status,actor_label,evidence_id')
      .order('finished_at', { ascending: false }).limit(100);
    if (req.query.engine && ENGINES.includes(String(req.query.engine))) q = q.eq('engine_code', String(req.query.engine));
    ok(res, await sel(q));
  }));
  router.get('/runs/:id', route(async (req, res) => {
    const id = needUuid(req.params.id, '실행');
    const [run] = await sel(req.qgdb.from(t('runs')).select('*').eq('id', id).limit(1));
    if (!run) throw Object.assign(new Error('실행 기록이 없습니다.'), { status: 404 });
    const findings = await sel(req.qgdb.from(t('findings')).select('id,check_code,tenant_id,status,severity,title,detail,issue_id').eq('run_id', id).order('status').limit(1000));
    ok(res, { run, findings });
  }));

  // 검사 항목(관리자만 읽음)
  router.get('/checks', route(async (req, res) => {
    ok(res, await sel(req.qgdb.from(t('checks')).select('code,engine_code,name,description,risk,scope,schedule,active,expect,remediation,sort').order('engine_code').order('sort').limit(500)));
  }));

  // 증거 원장
  router.get('/evidence', route(async (req, res) => {
    ok(res, await sel(req.qgdb.from(t('evidence')).select('id,seq,kind,ref,title,tenant_id,run_id,payload_sha256,hash,hash_v,created_at').order('seq', { ascending: false }).limit(100)));
  }));
  router.get('/evidence/verify', route(async (req, res) => { ok(res, await rpc(req, 'verify_evidence_chain')); }));
  router.get('/evidence/export', route(async (req, res) => {
    const rows = await sel(req.qgdb.from(t('evidence')).select('*').order('seq', { ascending: true }).limit(5000));
    const verify = await rpc(req, 'verify_evidence_chain');
    const day = new Date(Date.now() + 9 * 3600 * 1000).toISOString().slice(0, 10);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="qg-evidence-${P}-${day}.json"`);
    res.send(JSON.stringify({ prefix: P, exported_at: new Date().toISOString(), verify,
      hash_formula: { v1: 'sha256(prev_hash || kind || ref || payload_sha256 || created_at)', v2: 'sha256(prev_hash || kind || ref || title || tenant_id || run_id || created_by || payload_sha256 || created_at)' },
      rows }, null, 2));
  }));

  // 다중 검토(규칙 검토자 — AI 키 없이 동작): 대상 고르기 → 요청 → 검토자별 독립 판정 → 합의 → 사람이 확정
  router.get('/review/candidates', route(async (req, res) => { ok(res, await rpc(req, 'review_candidates', { p_kind: 'copy', p_limit: 100 })); }));
  router.get('/reviews', route(async (req, res) => {
    ok(res, await sel(req.qgdb.from(t('reviews')).select('id,target_kind,target_id,target_label,status,outcome,outcome_detail,final_decision,final_note,created_at,confirmed_at').order('created_at', { ascending: false }).limit(50)));
  }));
  router.post('/reviews', route(async (req, res) => {
    const b = req.body || {};
    const target = needUuid(b.target, '검토할 상품');
    const reqData = await rpc(req, 'review_request', { p_kind: 'copy', p_target: target, p_text: null, p_title: clip(b.title, 300), p_tenant: null, p_use_ai: false });
    for (const r of (reqData.reviewers || [])) {
      await rpc(req, 'review_submit', { p_review: reqData.review_id, p_reviewer: r.code, p_ai: null });
    }
    ok(res, await rpc(req, 'review_finalize', { p_review: reqData.review_id }));
  }));
  router.post('/reviews/:id/confirm', route(async (req, res) => {
    const id = needUuid(req.params.id, '검토');
    const d = String((req.body || {}).decision || '');
    if (!['approved', 'rejected'].includes(d)) throw Object.assign(new Error('통과 또는 반려를 골라 주세요.'), { status: 400 });
    ok(res, await rpc(req, 'review_confirm', { p_review: id, p_decision: d, p_note: clip((req.body || {}).note, 2000) }));
  }));

  // 법령·정책
  router.get('/regulations', route(async (req, res) => {
    ok(res, await sel(req.qgdb.from(t('regulations')).select('code,name,law_name,article,kind,summary,source_url,effective_date,last_reviewed_at,review_cycle_days,links,note,active,sort').order('sort').limit(200)));
  }));
  router.post('/regulations/:code/reviewed', route(async (req, res) => {
    const code = String(req.params.code);
    if (!/^[a-z][a-z0-9_]{1,59}$/.test(code)) throw Object.assign(new Error('법령을 목록에서 골라 주세요.'), { status: 400 });
    const note = clip((req.body || {}).note, 2000);
    if (!note || note.length < 5) throw Object.assign(new Error('검토 메모를 5자 이상 적어 주세요.'), { status: 400 });
    ok(res, await rpc(req, 'regulation_mark_reviewed', { p_code: code, p_note: note }));
  }));

  // 출시 관문(코드 배포 후보: Render 배포 커밋)
  router.get('/releases', route(async (req, res) => {
    ok(res, await sel(req.qgdb.from(t('releases')).select('id,rel_no,kind,target_ref,target_label,title,git_sha,status,verdict,evaluated_at,approved_at,decided_at,decision_note,deploy_state,deploy_sha,released_at,created_at').order('created_at', { ascending: false }).limit(50)));
  }));
  router.post('/releases', route(async (req, res) => {
    const b = req.body || {};
    const sha = String(b.git_sha || '').trim();
    if (!/^[0-9a-f]{7,40}$/.test(sha)) throw Object.assign(new Error('커밋 SHA(7~40자리 16진수)를 넣어 주세요.'), { status: 400 });
    ok(res, await rpc(req, 'release_create', { p_kind: 'code_deploy', p_target: sha, p_title: clip(b.title, 200) || `${siteLabel} 코드 배포 ${sha.slice(0, 7)}`, p_git_sha: sha, p_note: clip(b.note, 2000) }));
  }));
  router.post('/releases/:id/evaluate', route(async (req, res) => {
    ok(res, await rpc(req, 'release_evaluate', { p_release: needUuid(req.params.id, '출시 후보'), p_run_engines: !!(req.body || {}).run_engines }));
  }));
  router.post('/releases/:id/decide', route(async (req, res) => {
    const d = String((req.body || {}).decision || '');
    if (!['approved', 'rejected'].includes(d)) throw Object.assign(new Error('승인 또는 거절을 골라 주세요.'), { status: 400 });
    const note = clip((req.body || {}).note, 1000);
    if (d === 'rejected' && (!note || note.length < 5)) throw Object.assign(new Error('거절 사유를 5자 이상 적어 주세요.'), { status: 400 });
    ok(res, await rpc(req, 'release_decide', { p_release: needUuid(req.params.id, '출시 후보'), p_decision: d, p_note: note }));
  }));

  // 개선 제안(진화)
  router.get('/proposals', route(async (req, res) => {
    ok(res, await sel(req.qgdb.from(t('proposals')).select('id,prop_no,source,title,problem,scope,acceptance,verification,signal_count,last_signal_at,priority_score,status,decline_reason,tenant_id,created_at').order('priority_score', { ascending: false, nullsFirst: false }).limit(100)));
  }));
  router.post('/proposals/:id/transition', route(async (req, res) => {
    const to = String((req.body || {}).to || '');
    if (!PROPOSAL_TO.includes(to)) throw Object.assign(new Error('바꿀 상태를 골라 주세요.'), { status: 400 });
    const note = clip((req.body || {}).note, 2000);
    if (to === 'declined' && (!note || note.length < 5)) throw Object.assign(new Error('거절 사유를 5자 이상 적어 주세요.'), { status: 400 });
    ok(res, await rpc(req, 'proposal_transition', { p_id: needUuid(req.params.id, '제안'), p_to: to, p_note: note, p_release: null }));
  }));

  // 설정(읽기): 강제 스위치·자동 실행 — 스위치를 켜는 것은 형님 결정이라 화면에서 바꾸지 않는다
  router.get('/settings', route(async (req, res) => {
    const rows = await sel(req.qgdb.from(t('settings')).select('key,value,label,description,updated_at').order('key').limit(200));
    ok(res, rows.filter((r) => r.key !== 'qg_server_attest_key_hash').concat(rows.filter((r) => r.key === 'qg_server_attest_key_hash')
      .map((r) => ({ ...r, value: /^[0-9a-f]{64}$/.test(String(r.value)) ? '(설정됨 — 해시만 저장)' : '(설정 안 됨)' }))));
  }));

  router.use((req, res) => res.status(404).json({ error: 'Not Found', message: '없는 품질·거버넌스 기능입니다' }));
  return router;
};
