-- QG 키트 1.1.0 · 접두어 wpl · seed — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
-- =====================================================================
-- QG 키트 11 — 시드: 엔진 10행 · evidence 엔진 검사 항목 · anon 허용 목록 실측 절차
--  · 엔진 화면 주소는 관리자 경로(/admin) 아래 /qg/… (설치 스크립트가 채움)
--  · anon 허용 목록은 여기서 넣지 않는다 — 플랫폼마다 다르므로 설치 직후 실측해 사람이 사유와 함께 넣는다(QG_KIT.md §4.3,
--    `node scripts/qg-verify.mjs --allowlist-draft` 가 초안 SQL 을 만들어 줌). 사유 없이(TODO) 넣으면 표 제약이 거부한다.
--  두 번 적용해도 같은 결과(on conflict).
-- =====================================================================

insert into public.wpl_qg_engines(code, name, purpose, route, icon, sort) values
 ('review',      '다중 AI 독립 검토',        '법무·개인정보·보안·UX·사업·소비자 관점의 검토자가 서로의 판정을 보지 않고 독립적으로 판정하고, 정족수·거부권 규칙으로 합의합니다. AI 키가 없으면 규칙 검토자(금칙어·숫자 검증·필수 조항·개인정보·비밀값 패턴)로 동작합니다.', '/admin/qg/review', '🧑‍⚖️', 10),
 ('testing',     '위험도별 테스트',          '기능마다 영향×가능성으로 위험 등급을 매기고 등급별로 필요한 테스트 깊이를 정합니다. 고위험인데 테스트가 없거나 오래된 기능을 찾아 보여 줍니다.', '/admin/qg/testing', '🧪', 20),
 ('adversarial', '공격·장애 시뮬레이션',     '교차 테넌트·익명 호출·금액 조작·자기 승인·폭주·외부 API 장애 같은 시나리오를 되돌리기(rollback) 전용으로 실행하고 기대 결과(거부·0행·대체 동작)와 비교합니다.', '/admin/qg/adversarial', '🥷', 30),
 ('compliance',  '법령·정책 변경 분석',      '법령·고시·정책 레지스트리와 변경 기록을 관리하고, 바뀐 내용이 어느 규칙·정책·템플릿·테넌트에 걸리는지 영향 분석과 할 일을 만듭니다.', '/admin/qg/compliance', '⚖️', 40),
 ('evidence',    '테스트 증거 보존',         '모든 실행·검토·출시 결정을 추가 전용 증거 원장에 SHA-256 해시체인으로 남기고, 체인이 끊기지 않았는지 검증하며 증거 묶음을 내려받습니다.', '/admin/qg/evidence', '🧾', 50),
 ('release',     '출시 승인·차단',           '코드 배포·정책 변경·플랫폼 고유 출시 후보를 관문 정책(필수 엔진 통과·치명 이슈 0·검토 정족수)으로 판정하고, 다른 관리자가 승인해야 출시합니다.', '/admin/qg/releases', '🚦', 60),
 ('security',    '보안 위협 탐지·대응',      '허용 목록 밖 익명 실행 함수·RLS 꺼진 표·정책 없는 표·search_path 없는 함수·내부 함수 실행 권한·서버 증명키·감사 체인을 매시 점검하고 조치 안내를 붙입니다.', '/admin/qg/security', '🛡️', 70),
 ('integrity',   '데이터 정합성 검증',       '추가 전용 표 변조 가드·감사 체인·고아 행·교차 테넌트 참조 같은 일반 정합성과, 플랫폼별 업무 정합성(결제·정산·예약…)을 매일 확인합니다.', '/admin/qg/integrity', '🧮', 80),
 ('ai_model',    'AI 모델 평가·승인·추적',   '작업별 평가 세트로 모델을 평가하고 모델×작업 승인 상태(후보→승인→퇴역)를 관리하며, 실패율·비용·지연 추세에서 이상을 찾습니다.', '/admin/qg/ai-models', '🤖', 90),
 ('evolution',   '개선사항 분석·개발 제안',  '반복 이슈·실패 테스트·플랫폼 업무 신호를 모아 우선순위가 매겨진 개선 제안을 만들고, 개발 지시서(마크다운)로 내보냅니다.', '/admin/qg/evolution', '🌱', 100)
on conflict (code) do update set name = excluded.name, purpose = excluded.purpose, route = excluded.route, icon = excluded.icon, sort = excluded.sort;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('evidence.chain_intact', 'evidence', '증거 원장 해시체인 무결성',
  '증거 원장의 모든 기록을 처음부터 다시 계산해 순번이 빠지지 않았는지, 이전 해시가 이어지는지, 내용 지문(SHA-256)과 해시가 기록 당시와 같은지 확인합니다.',
  'wpl_qg_probe_evidence_chain', 'critical', 'platform', 'daily', '{}'::jsonb,
  '끊긴 곳 0건',
  '끊긴 순번의 기록과 그 앞뒤를 확인하세요. 추가 전용 가드가 있어 앱 경로로는 바꿀 수 없으므로, 끊김은 DB 관리자 권한으로 직접 손댄 흔적입니다. 즉시 DB 접근 기록을 확인하고 책임자에게 보고하세요.', 10),
 ('evidence.audit_chain', 'evidence', '플랫폼 감사 로그 해시체인 무결성',
  '플랫폼 감사 기록의 해시체인을 다시 계산해 끊긴 곳이 없는지 확인합니다(어댑터 wpl_qga_audit_chain_check). 감사 체인이 없는 플랫폼은 건너뜁니다.',
  'wpl_qg_probe_audit_chain', 'critical', 'platform', 'daily', '{"tail":0}'::jsonb,
  '끊긴 곳 0건(없는 플랫폼은 건너뜀)',
  '플랫폼의 감사 체인 검증 화면·RPC 로 끊긴 위치를 확인하고, 그 시각 전후의 DB 접근 기록을 살펴 책임자에게 보고하세요. 감사 기록은 되돌리지 말고 사건 기록으로 남깁니다.', 20),
 ('evidence.run_has_evidence', 'evidence', '실행마다 증거 연결',
  '최근 30일 실행 기록마다 실행 보고서 증거가 붙어 있고, 결과들이 같은 증거를 가리키는지 확인합니다.',
  'wpl_qg_probe_run_evidence_link', 'high', 'platform', 'daily', '{"days":30}'::jsonb,
  '증거 없는 실행 0건 · 어긋난 결과 0건',
  '실행기(wpl_qg_record_run_internal)를 거치지 않고 실행·결과를 넣은 경로가 있는지 확인하세요. 실행·결과는 실행기와 외부 결과 올리기(wpl_qg_ingest)로만 기록해야 합니다.', 30)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
  schedule = excluded.schedule, params = excluded.params, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort;

-- ───────── anon 허용 목록: 설치 직후 실측(이 블록은 안내만 남기고 넣지 않는다) ─────────
do $$
declare v_n int; v_list text;
begin
  select count(*), string_agg(p.oid::regprocedure::text, ', ' order by 1)
    into v_n, v_list
    from pg_proc p
   where p.pronamespace = 'public'::regnamespace and p.prosecdef and has_function_privilege('anon', p.oid, 'execute')
     and p.oid::regprocedure::text not in (select signature from public.wpl_qg_anon_allowlist where active);
  if v_n > 0 then
    raise notice 'QG: 익명(anon)이 실행할 수 있는 SECURITY DEFINER 함수 %개가 허용 목록에 없습니다. 정당한 공개 함수만 사유·보호 장치와 함께 wpl_qg_anon_allowlist 에 넣고, 나머지는 실행 권한을 회수하세요: %', v_n, left(v_list, 3000);
  end if;
end $$;
