// =====================================================================
// 서버 코드용 출시 관문(QG 키트 v1.2 §7.2 · lib/qg/release-gate.ts 의 Express(CommonJS) 이식) — WITH+ · LIVE+ 공용.
//  공개·승인을 DB 함수가 아니라 Express 라우트(service_role 로 update)에서 하므로, 그 라우트에 두 단계로 넣는다:
//    ① 바꾸기 전  qgReleaseGate({ kind, ref, tenantId?, label? })      — 강제 스위치 꺼짐(기본)이면 항상 통과하고 '관찰 기록'만 남긴다.
//                                                                        켜짐 + 승인된 출시 후보 없음이면 QgReleaseBlockedError(사람 말 메시지).
//    ② 성공 뒤에만 qgReleaseMarkReleased({ kind, ref, tenantId? })     — 승인 후보가 있으면 '출시 완료'로 연결(없으면 관찰만). 절대 던지지 않는다.
//  강제 스위치 false(기본)에서 원래 동작과 결과가 같다는 약속:
//   - qgReleaseGate 는 꺼짐에서 절대 던지지 않는다. DB 함수가 없거나 호출이 실패해도 경고만 남기고 통과(failClosed 를 준 경우만 막음).
//   - qgReleaseMarkReleased 는 어떤 경우에도 던지지 않는다(이미 바뀐 뒤라서).
//  연결: server.js 의 service_role 클라이언트(supabase)를 db 로 넘긴다 → DB 함수 안에서 service_role 로 확인된다(서버 증명키 불필요).
//        service_role 이 아닌 클라이언트를 쓰면 서버 증명키(QG_SERVER_ATTEST_KEY)를 함께 보낸다. 비밀값은 로그에 남기지 않는다.
//  kind 는 관문 정책(wpl_qg_gate_policies)에, ref 는 어댑터 wpl_qga_release_target(kind, ref) 가 확인하는 값(보통 행 id)과 같아야 한다.
// =====================================================================
const P = 'wpl';
const rpcName = (n) => `${P}_qg_${n}`;

class QgReleaseBlockedError extends Error {
  constructor(result) {
    super((result && result.message) || '품질·거버넌스 출시 관문을 통과·승인한 기록이 없어 진행할 수 없습니다.');
    this.name = 'QgReleaseBlockedError';
    this.result = result;
  }
}

function warn(what, e) {
  console.warn(`[QG 출시 관문] ${what}: ${e instanceof Error ? e.message : String(e)}`.slice(0, 500));
}

function args(t, key) {
  return {
    p_kind: String(t.kind),
    p_ref: String(t.ref == null ? '' : t.ref).trim().toLowerCase(),   // 행 id(uuid) — 어댑터가 정규화한 값과 같게(소문자)
    p_server_key: key,
    p_tenant: t.tenantId || null,
    p_label: t.label ? String(t.label).slice(0, 200) : null,
  };
}

/**
 * @param {{ db: { rpc: Function } | null, serverKey?: string|null, failClosed?: boolean }} cfg
 */
function createQgReleaseGate(cfg = {}) {
  const getDb = typeof cfg.db === 'function' ? cfg.db : () => cfg.db;
  const serverKey = cfg.serverKey !== undefined ? cfg.serverKey : null;

  /** ① 바꾸기 전 확인. 꺼짐이면 항상 통과(관찰만), 켜짐 + 승인 없음이면 QgReleaseBlockedError. */
  async function qgReleaseGate(target, opts = {}) {
    const failClosed = opts.failClosed !== undefined ? !!opts.failClosed : !!cfg.failClosed;
    const failed = (msg) => {
      const r = { allowed: !failClosed, enforced: false, wouldBlock: false, reason: 'error', releaseId: null, relNo: null, observationId: null,
        message: failClosed ? '출시 관문을 확인하지 못해 진행하지 않았습니다. 잠시 뒤 다시 해 주세요.' : null, observed: false, error: msg };
      if (failClosed && opts.throwOnBlock !== false) throw new QgReleaseBlockedError(r);
      return r;
    };
    const db = getDb();
    if (!db || typeof db.rpc !== 'function') { warn('서버 연결 없음', '확인 없이 통과'); return failed('no_server_client'); }
    let data, error;
    try { ({ data, error } = await db.rpc(rpcName('release_gate_check_server'), args(target, serverKey))); }
    catch (e) { warn('확인 호출 실패', e); return failed(e instanceof Error ? e.message : String(e)); }
    if (error || !data || typeof data !== 'object') { warn('확인 실패', (error && error.message) || '빈 응답'); return failed((error && error.message) || 'empty'); }
    const r = {
      allowed: data.allowed !== false, enforced: data.enforced === true, wouldBlock: data.would_block === true, reason: String(data.reason || ''),
      releaseId: data.release_id || null, relNo: typeof data.rel_no === 'number' ? data.rel_no : null,
      observationId: typeof data.observation_id === 'number' ? data.observation_id : null, message: data.message || null, observed: true,
    };
    if (!r.allowed && opts.throwOnBlock !== false) throw new QgReleaseBlockedError(r);
    return r;
  }

  /** ② 실제로 성공한 뒤에만. 승인 후보가 있으면 출시 완료로 연결(없으면 관찰만). 절대 던지지 않는다. */
  async function qgReleaseMarkReleased(target) {
    const none = (reason, err) => ({ ok: false, linked: false, releaseId: null, relNo: null, reason, observationId: null, error: err });
    try {
      const db = getDb();
      if (!db || typeof db.rpc !== 'function') return none('no_server_client');
      const { data, error } = await db.rpc(rpcName('release_mark_server'), { ...args(target, serverKey), p_note: target.note ? String(target.note).slice(0, 500) : null });
      if (error || !data || typeof data !== 'object') { warn('출시 완료 기록 실패', (error && error.message) || '빈 응답'); return none('error', error && error.message); }
      return { ok: true, linked: data.linked === true, releaseId: data.release_id || null, relNo: typeof data.rel_no === 'number' ? data.rel_no : null,
        reason: String(data.reason || ''), observationId: typeof data.observation_id === 'number' ? data.observation_id : null };
    } catch (e) {
      warn('출시 완료 기록 실패', e);
      return none('error', e instanceof Error ? e.message : String(e));
    }
  }

  /** ①·② 한 번에: 확인 → run() → (성공이면) 출시 완료 기록. run 의 반환값·예외는 그대로 전달. */
  async function withQgReleaseGate(target, run, opts = {}) {
    await qgReleaseGate(target, opts);
    const result = await run();
    let ok = true;
    try { ok = opts.isSuccess ? !!opts.isSuccess(result) : true; } catch (_) { ok = false; }
    if (ok) await qgReleaseMarkReleased(target);
    return result;
  }

  /**
   * Express 라우트용: 확인해서 막혔으면 409 + 사람 말 메시지로 응답하고 true(라우트는 바로 return), 아니면 false.
   * 강제 스위치 꺼짐(기본)에서는 항상 false — 원래 라우트 흐름 그대로.
   */
  async function qgReleaseBlocked(res, target) {
    try {
      await qgReleaseGate(target);
      return false;
    } catch (e) {
      if (e instanceof QgReleaseBlockedError) {
        res.status(409).json({ error: 'Release Blocked', message: e.message, qg: { kind: target.kind, reason: e.result && e.result.reason }, timestamp: new Date().toISOString() });
        return true;
      }
      throw e;
    }
  }

  return { qgReleaseGate, qgReleaseMarkReleased, withQgReleaseGate, qgReleaseBlocked, QgReleaseBlockedError };
}

// 사이트 = QG 테넌트(공유 DB 에 사이트 2개): WITH+ / LIVE+
const QG_SITE_TENANT = { withplus: 'a17e0000-0000-4000-8000-000000000001', liveplus: 'a17e0000-0000-4000-8000-000000000002' };

module.exports = { createQgReleaseGate, QgReleaseBlockedError, QG_SITE_TENANT };
