-- QG 키트 1.1.0 · 접두어 wpl · review — C:/Users/polhu/dev/QG_KIT 에서 렌더링(직접 고치지 말고 키트를 고친 뒤 다시 설치)
-- =====================================================================
-- QG 키트 30 — 다중 AI 독립 검토 엔진(review) (원본: F-MATRIX 2920)
--  · wpl_qg_reviewers         카탈로그: 관점별 검토자(법무·개인정보·보안·UX·사업·소비자), 지시문, 규칙 검사 목록, 거부권
--  · wpl_qg_reviews           검토 요청(대상 종류·대상 id·스냅샷·SHA-256) — 상태는 RPC 로만(가드 트리거)
--  · wpl_qg_review_verdicts   추가 전용: 검토자별 독립 판정(approve/concern/reject)·근거·AI/규칙
--  · wpl_qg_banned_phrases    카탈로그: 금칙어(정규식·block/warn·사유·대안·업종) — 어댑터 wpl_qga_banned_phrases() 결과와 합쳐 쓴다
--  · wpl_qg_required_clauses  카탈로그: 대상 종류별 필수 조항(이름이 본문에 있어야 함)
--  독립성: 서버 액션이 검토자마다 따로 AI 를 부르고(다른 판정을 입력에 넣지 않음) 순서는 DB 가 무작위로 정한다.
--  규칙 바닥선: AI 판정도 DB 가 같은 검토자의 규칙 판정을 함께 계산해 더 엄한 쪽을 남긴다.
--  대상 종류: document(붙여 넣은 글)·release(출시 후보)는 QG 가 해석, 그 밖(copy·ad_material·contract_template·notice)은 어댑터
--  wpl_qga_review_target(kind, ref) 가 {tenant_id,label,text,context,industry,target_id} 로 해석(모르면 붙여 넣기만 가능).
-- =====================================================================

insert into public.wpl_qg_settings(key, value, label, description) values
 ('qg_review_quorum', '3', '품질·거버넌스: 다중 검토 통과에 필요한 승인 수',
  '검토자 중 이 수 이상이 ''승인''하고 아무도 ''거부''하지 않아야 통과입니다. 거부권 검토자가 거부하면 승인 수와 관계없이 차단됩니다.'),
 ('qg_review_max_chars', '30000', '품질·거버넌스: 다중 검토 문서 최대 글자 수', '검토를 요청할 수 있는 문서의 최대 글자 수입니다.'),
 ('qg_review_sentence_max', '180', '품질·거버넌스: UX 검토 — 한 문장 최대 글자 수', 'UX 관점 규칙 검토자가 이보다 긴 문장을 ''읽기 어려움''으로 지적합니다.'),
 ('qg_review_override_note_min_len', '10', '품질·거버넌스: 차단·사람 판단 검토를 통과시킬 때 사유 최소 글자 수',
  '합의 결과가 ''차단''이나 ''사람 판단 필요''인 검토를 사람이 ''통과''로 확정할 때 적어야 하는 사유의 최소 글자 수입니다. 차단을 통과시키는 것은 관리자만, 요청자 본인은 불가입니다.'),
 ('qg_review_stale_days', '3', '품질·거버넌스: 검토 확정 대기 알림(일)', '검토를 요청하고 이 일수가 지나도록 사람이 확정하지 않으면 품질 이슈(주의)로 알립니다.')
on conflict (key) do nothing;

-- ───────── 1) 표 ─────────
create table if not exists public.wpl_qg_banned_phrases (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{1,59}$'),
  pattern text not null check (char_length(pattern) between 1 and 300),
  severity text not null default 'warn' check (severity in ('block','warn')),
  reason text not null check (char_length(reason) between 2 and 300),
  suggestion text,
  industry text,
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_required_clauses (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{1,59}$'),
  target_kind text not null check (target_kind ~ '^[a-z][a-z0-9_]{1,39}$'),
  name text not null check (char_length(name) between 1 and 120),
  law_ref text,
  required boolean not null default true,
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_reviewers (
  code text primary key check (code ~ '^[a-z][a-z0-9_]{1,39}$'),
  name text not null check (char_length(name) between 1 and 60),
  perspective text not null check (char_length(perspective) between 1 and 200),
  instructions text not null check (char_length(instructions) between 10 and 4000),
  rule_checks text[] not null default '{}'
    check (rule_checks <@ array['banned_phrases','unverified_number','required_clauses','pii','secrets','readability','markup']::text[]),
  veto boolean not null default false,
  applies_to text[] not null default array['document','copy','ad_material','contract_template','notice','release']::text[]
    check (cardinality(applies_to) >= 1),
  active boolean not null default true,
  sort int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wpl_qg_reviews (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid,
  target_kind text not null check (target_kind ~ '^[a-z][a-z0-9_]{1,39}$'),
  target_id text check (target_id is null or char_length(target_id) between 1 and 200),
  target_label text not null check (char_length(target_label) between 1 and 300),
  snapshot_text text not null,
  context_text text,
  snapshot_sha256 text not null check (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
  industry_code text,
  use_ai boolean not null default false,
  reviewers text[] not null check (cardinality(reviewers) >= 1),
  status text not null default 'reviewing' check (status in ('reviewing','decided','confirmed')),
  outcome text check (outcome is null or outcome in ('passed','blocked','needs_human')),
  outcome_detail jsonb,
  decided_at timestamptz,
  final_decision text check (final_decision is null or final_decision in ('approved','rejected')),
  final_note text,
  confirmed_by uuid,
  confirmed_at timestamptz,
  evidence_id uuid references public.wpl_qg_evidence(id),
  decision_evidence_id uuid references public.wpl_qg_evidence(id),
  requested_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists wpl_qg_reviews_tenant_idx on public.wpl_qg_reviews(tenant_id, created_at desc);
create index if not exists wpl_qg_reviews_status_idx on public.wpl_qg_reviews(status, created_at desc);
create index if not exists wpl_qg_reviews_target_idx on public.wpl_qg_reviews(target_kind, target_id);

create table if not exists public.wpl_qg_review_verdicts (
  id uuid primary key default gen_random_uuid(),
  review_id uuid not null references public.wpl_qg_reviews(id),
  tenant_id uuid,
  reviewer_code text not null references public.wpl_qg_reviewers(code) on update cascade,
  verdict text not null check (verdict in ('approve','concern','reject')),
  ai_verdict text check (ai_verdict is null or ai_verdict in ('approve','concern','reject')),
  rules_verdict text not null check (rules_verdict in ('approve','concern','reject')),
  reasons jsonb not null default '[]'::jsonb check (jsonb_typeof(reasons) = 'array'),
  summary text,
  mode text not null check (mode in ('ai','rules')),
  model text,
  ai_run_id uuid,
  position int not null default 1,
  created_by uuid,
  created_at timestamptz not null default now(),
  unique (review_id, reviewer_code)
);
create index if not exists wpl_qg_review_verdicts_review_idx on public.wpl_qg_review_verdicts(review_id);

do $$ declare t text; begin
  foreach t in array array['wpl_qg_banned_phrases','wpl_qg_required_clauses','wpl_qg_reviewers'] loop
    execute format('drop trigger if exists %I on public.%I', t || '_touch', t);
    execute format('create trigger %I before update on public.%I for each row execute function public.wpl_qg_touch()', t || '_touch', t);
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists %I on public.%I', t || '_read', t);
    -- v1.1: 검토자 표도 관리자만(지시문=프롬프트가 들어 있음). 구성원 검토 요청은 DEFINER RPC 가 처리한다.
    execute format('create policy %I on public.%I for select to authenticated using (public.wpl_qga_is_admin())', t || '_read', t);
    execute format('drop policy if exists %I on public.%I', t || '_admin_ins', t);
    execute format('create policy %I on public.%I for insert to authenticated with check (public.wpl_qga_is_admin())', t || '_admin_ins', t);
    execute format('drop policy if exists %I on public.%I', t || '_admin_upd', t);
    execute format('create policy %I on public.%I for update to authenticated using (public.wpl_qga_is_admin()) with check (public.wpl_qga_is_admin())', t || '_admin_upd', t);
    execute format('drop policy if exists %I on public.%I', t || '_no_delete', t);
    execute format('create policy %I on public.%I as restrictive for delete to authenticated, anon using (false)', t || '_no_delete', t);
    execute format('revoke all on public.%I from anon', t);
    execute format('revoke delete, truncate on public.%I from authenticated', t);
    execute format('grant select, insert, update on public.%I to authenticated', t);
  end loop;
end $$;

drop trigger if exists wpl_qg_review_verdicts_no_mutation on public.wpl_qg_review_verdicts;
create trigger wpl_qg_review_verdicts_no_mutation before update or delete on public.wpl_qg_review_verdicts for each row execute function public.wpl_qg_forbid_mutation();
drop trigger if exists wpl_qg_review_verdicts_no_truncate on public.wpl_qg_review_verdicts;
create trigger wpl_qg_review_verdicts_no_truncate before truncate on public.wpl_qg_review_verdicts for each statement execute function public.wpl_qg_forbid_mutation();

create or replace function public.wpl_qg_review_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'DELETE' then raise exception '검토 기록은 지울 수 없습니다.'; end if;
  if coalesce(current_setting('wpl.qg_write', true), '') <> 'on' then
    raise exception '검토 상태는 다중 검토 화면의 절차(판정·합의·확정)로만 바꿀 수 있습니다.';
  end if;
  if new.snapshot_text is distinct from old.snapshot_text or new.snapshot_sha256 is distinct from old.snapshot_sha256
     or new.context_text is distinct from old.context_text or new.target_kind is distinct from old.target_kind
     or new.target_id is distinct from old.target_id or new.tenant_id is distinct from old.tenant_id
     or new.reviewers is distinct from old.reviewers or new.requested_by is distinct from old.requested_by
     or new.created_at is distinct from old.created_at then
    raise exception '검토 대상·스냅샷·검토자 목록은 바꿀 수 없습니다(새 검토를 요청해 주세요).';
  end if;
  new.updated_at := now();
  return new;
end $$;
revoke all on function public.wpl_qg_review_guard() from public, anon, authenticated;
drop trigger if exists wpl_qg_reviews_guard on public.wpl_qg_reviews;
create trigger wpl_qg_reviews_guard before update or delete on public.wpl_qg_reviews for each row execute function public.wpl_qg_review_guard();
drop trigger if exists wpl_qg_reviews_no_truncate on public.wpl_qg_reviews;
create trigger wpl_qg_reviews_no_truncate before truncate on public.wpl_qg_reviews for each statement execute function public.wpl_qg_forbid_mutation();

do $$ declare t text; begin
  foreach t in array array['wpl_qg_reviews','wpl_qg_review_verdicts'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists %I on public.%I', t || '_read', t);
    execute format('create policy %I on public.%I for select to authenticated using (public.wpl_qga_is_admin() or (tenant_id is not null and public.wpl_qga_can_read_tenant(tenant_id)))', t || '_read', t);
    execute format('drop policy if exists %I on public.%I', t || '_no_delete', t);
    execute format('create policy %I on public.%I as restrictive for delete to authenticated, anon using (false)', t || '_no_delete', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
  end loop;
end $$;

-- ───────── 2) 규칙 검사(허용 목록) ─────────
-- 결과: [{check, level: reject|concern, code, message}] — 개인정보·비밀값은 원문을 남기지 않고 건수만 남긴다.
create or replace function public.wpl_qg_review_check_internal(p_check text, p_text text, p_context text, p_kind text, p_target text, p_industry text)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare
  t text := coalesce(p_text, ''); v jsonb := '[]'::jsonb; n text; v_norm text; v_cnt int; v_max int; r record; v_n int := 0;
begin
  if p_check = 'banned_phrases' then
    select coalesce(jsonb_agg(jsonb_build_object('check', 'banned_phrases', 'level', case when b.severity = 'block' then 'reject' else 'concern' end,
             'code', 'banned_' || b.severity, 'message', b.reason || coalesce(' — 대안: ' || nullif(b.suggestion, ''), ''))
             order by b.severity, b.reason), '[]'::jsonb)
      into v
      from (select q.pattern, q.severity, q.reason, q.suggestion, q.industry from public.wpl_qg_banned_phrases q where q.active
            union all
            select a.pattern, case when a.severity in ('block','reject') then 'block' else 'warn' end, a.reason, a.suggestion, a.industry
              from public.wpl_qga_banned_phrases() a) b
     where (b.industry is null or b.industry = p_industry)
       and public.wpl_qg_regex_hit_internal(t, b.pattern);

  elsif p_check = 'unverified_number' then
    if coalesce(btrim(p_context), '') = '' then return '[]'::jsonb; end if;
    for n in select distinct m[1] from regexp_matches(t, '([0-9][0-9,.]*[0-9]|[0-9])', 'g') m loop
      if position(replace(n, ',', '') in replace(p_context, ',', '')) = 0 then
        v_n := v_n + 1;
        exit when v_n > 20;
        v := v || jsonb_build_array(jsonb_build_object('check', 'unverified_number', 'level', 'concern', 'code', 'unverified_number',
               'message', '원문·자료에 없는 숫자(' || left(n, 30) || ')입니다. 근거 없는 수치는 쓸 수 없습니다.'));
      end if;
    end loop;

  elsif p_check = 'required_clauses' then
    v_norm := regexp_replace(t, '\s', '', 'g');
    for r in select c.name, c.law_ref, c.required from public.wpl_qg_required_clauses c where c.active and c.target_kind = p_kind order by c.sort, c.code loop
      if position(regexp_replace(r.name, '\s', '', 'g') in v_norm) = 0 then
        v := v || jsonb_build_array(jsonb_build_object('check', 'required_clauses', 'level', case when r.required then 'reject' else 'concern' end, 'code', 'missing_clause',
               'message', '필수 항목 ''' || r.name || '''이(가) 본문에 없습니다' || coalesce('(' || r.law_ref || ')', '') || '.'));
      end if;
    end loop;

  elsif p_check = 'pii' then
    select count(*) into v_cnt from regexp_matches(t, '(^|[^0-9])[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[- ]?[1-8][0-9]{6}([^0-9]|$)', 'g');
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'pii', 'level', 'reject', 'code', 'pii_rrn',
      'message', '주민등록번호로 보이는 값 ' || v_cnt || '건 — 법상 받거나 남기면 안 되는 정보입니다. 지우고 다시 요청하세요.')); end if;
    select count(*) into v_cnt from regexp_matches(t, '(^|[^0-9])[3-6][0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{3,4}([^0-9]|$)', 'g');
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'pii', 'level', 'reject', 'code', 'pii_card',
      'message', '카드번호로 보이는 값 ' || v_cnt || '건 — 결제 정보는 문서에 넣지 마세요.')); end if;
    select count(*) into v_cnt from regexp_matches(t, '(계좌|입금|account)[^0-9]{0,12}[0-9]{2,6}-[0-9]{2,6}-[0-9]{2,8}', 'gi');
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'pii', 'level', 'concern', 'code', 'pii_account',
      'message', '계좌번호로 보이는 값 ' || v_cnt || '건 — 공개 문서라면 지우세요.')); end if;
    select count(*) into v_cnt from regexp_matches(t, '(^|[^0-9])01[016789][- ]?[0-9]{3,4}[- ]?[0-9]{4}([^0-9]|$)', 'g');
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'pii', 'level', 'concern', 'code', 'pii_phone',
      'message', '휴대폰 번호 ' || v_cnt || '건 — 대표 번호가 아니면 지우세요.')); end if;
    select count(*) into v_cnt from regexp_matches(t, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', 'g');
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'pii', 'level', 'concern', 'code', 'pii_email',
      'message', '이메일 주소 ' || v_cnt || '건 — 대표 주소가 아니면 지우세요.')); end if;

  elsif p_check = 'secrets' then
    if t ~ '(sk-[A-Za-z0-9_-]{16,}|sk_live_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.)' then
      v := v || jsonb_build_array(jsonb_build_object('check', 'secrets', 'level', 'reject', 'code', 'secret_key',
             'message', 'API 키·비밀키·토큰으로 보이는 값이 있습니다. 즉시 지우고, 이미 공유했다면 키를 바꾸세요.'));
    end if;
    if t ~* '(password|passwd|비밀번호|비번)\s*[:=]\s*\S{4,}' then
      v := v || jsonb_build_array(jsonb_build_object('check', 'secrets', 'level', 'reject', 'code', 'secret_password',
             'message', '비밀번호로 보이는 값이 있습니다. 문서에 비밀번호를 적지 마세요.'));
    end if;

  elsif p_check = 'markup' then
    if t ~* '(<\s*script|javascript\s*:|<\s*iframe|\son(error|load|click|mouseover)\s*=)' then
      v := v || jsonb_build_array(jsonb_build_object('check', 'markup', 'level', 'reject', 'code', 'script_markup',
             'message', '스크립트·이벤트 속성 같은 실행 코드가 들어 있습니다.'));
    end if;

  elsif p_check = 'readability' then
    if char_length(btrim(t)) = 0 then
      return jsonb_build_array(jsonb_build_object('check', 'readability', 'level', 'reject', 'code', 'empty', 'message', '내용이 비어 있습니다.'));
    end if;
    v_max := greatest(40, coalesce((public.wpl_qg_setting_internal('qg_review_sentence_max', '180'::jsonb) #>> '{}')::int, 180));
    select count(*) into v_cnt from regexp_split_to_table(t, '[.!?。]\s+|\n+') x where char_length(btrim(x)) > v_max;
    if v_cnt > 0 then v := v || jsonb_build_array(jsonb_build_object('check', 'readability', 'level', 'concern', 'code', 'long_sentence',
      'message', v_max || '자보다 긴 문장 ' || v_cnt || '개 — 나눠 쓰면 읽기 쉽습니다.')); end if;
    if t ~ '[ㄱ-ㅎㅏ-ㅣ]{3,}' then v := v || jsonb_build_array(jsonb_build_object('check', 'readability', 'level', 'concern', 'code', 'jamo',
      'message', '자음·모음만 이어진 부분(오타·축약)이 있습니다.')); end if;
  end if;
  return coalesce(v, '[]'::jsonb);
end $$;

-- 정규식 맞춤(잘못된 패턴은 맞지 않음으로 — 카탈로그 오타가 검토를 멈추지 않게)
create or replace function public.wpl_qg_regex_hit_internal(p_text text, p_pattern text) returns boolean
language plpgsql immutable set search_path = public as $$
begin
  return coalesce(p_text, '') ~* p_pattern;
exception when others then return false;
end $$;
revoke all on function public.wpl_qg_regex_hit_internal(text, text) from public, anon, authenticated;
revoke all on function public.wpl_qg_review_check_internal(text, text, text, text, text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_review_worst_internal(a text, b text) returns text
language sql immutable set search_path = public as $$
  select case when 'reject' in (a, b) then 'reject' when 'concern' in (a, b) then 'concern' else 'approve' end
$$;
revoke all on function public.wpl_qg_review_worst_internal(text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_review_rules_internal(p_review public.wpl_qg_reviews, p_reviewer public.wpl_qg_reviewers)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_hits jsonb := '[]'::jsonb; c text; v_rej int; v_con int; v_verdict text;
begin
  foreach c in array coalesce(p_reviewer.rule_checks, '{}'::text[]) loop
    v_hits := v_hits || public.wpl_qg_review_check_internal(c, p_review.snapshot_text, p_review.context_text, p_review.target_kind, p_review.target_id, p_review.industry_code);
  end loop;
  select count(*) filter (where e->>'level' = 'reject'), count(*) filter (where e->>'level' = 'concern') into v_rej, v_con from jsonb_array_elements(v_hits) e;
  v_verdict := case when v_rej > 0 then 'reject' when v_con > 0 then 'concern' else 'approve' end;
  return jsonb_build_object('verdict', v_verdict, 'reasons', v_hits,
    'summary', case when v_rej + v_con = 0 then '규칙 검사(' || coalesce(nullif(array_to_string(p_reviewer.rule_checks, '·'), ''), '-') || ')에서 문제를 찾지 못했습니다.'
                    else '규칙 검사 결과: 거부 사유 ' || v_rej || '건 · 주의 ' || v_con || '건' end);
end $$;
revoke all on function public.wpl_qg_review_rules_internal(public.wpl_qg_reviews, public.wpl_qg_reviewers) from public, anon, authenticated;

-- ───────── 3) 대상 해석 ─────────
create or replace function public.wpl_qg_review_target_internal(p_kind text, p_target text, p_text text, p_title text)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb;
begin
  if p_kind is null or p_kind !~ '^[a-z][a-z0-9_]{1,39}$' then raise exception '검토 대상 종류를 골라 주세요.'; end if;
  if nullif(btrim(coalesce(p_target, '')), '') is null then
    if char_length(btrim(coalesce(p_text, ''))) = 0 then raise exception '검토할 대상을 고르거나 글을 붙여 넣어 주세요.'; end if;
    return jsonb_build_object('tenant_id', null, 'label', coalesce(nullif(left(btrim(p_title), 300), ''), '붙여 넣은 문서'), 'text', p_text, 'context', null, 'industry', null, 'target_id', null);
  end if;
  if p_kind = 'document' then raise exception '붙여 넣은 문서는 대상 id 없이 요청합니다.'; end if;
  if p_kind = 'release' then
    if to_regclass('public.wpl_qg_releases') is null then raise exception '출시 후보 기능이 아직 없습니다. 출시 내용을 붙여 넣어 요청해 주세요.'; end if;
    execute 'select to_jsonb(x) from public.wpl_qg_releases x where x.id::text = $1' into v using p_target;
    if v is null then raise exception '출시 후보를 찾을 수 없습니다.'; end if;
    return jsonb_build_object('tenant_id', v->>'tenant_id', 'label', '출시 후보 #' || coalesce(v->>'rel_no', '?') || ': ' || coalesce(v->>'title', p_target),
      'text', coalesce(nullif(btrim(coalesce(p_text, '')), ''), jsonb_pretty(v - 'verdict')), 'context', null, 'industry', null, 'target_id', p_target);
  end if;
  v := public.wpl_qga_review_target(p_kind, p_target);
  if v is null or jsonb_typeof(v) <> 'object' then
    raise exception '이 플랫폼에서는 ''%'' 대상을 목록에서 고를 수 없습니다. 내용을 붙여 넣어 요청해 주세요.', p_kind;
  end if;
  return jsonb_build_object('tenant_id', v->>'tenant_id', 'label', coalesce(v->>'label', p_kind || ' ' || p_target), 'text', coalesce(v->>'text', ''),
    'context', v->>'context', 'industry', v->>'industry', 'target_id', coalesce(v->>'target_id', p_target));
end $$;
revoke all on function public.wpl_qg_review_target_internal(text, text, text, text) from public, anon, authenticated;

create or replace function public.wpl_qg_review_can_internal(p public.wpl_qg_reviews) returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and (public.wpl_qga_is_admin() or (p.tenant_id is not null and public.wpl_qga_can_read_tenant(p.tenant_id)))
$$;
revoke all on function public.wpl_qg_review_can_internal(public.wpl_qg_reviews) from public, anon, authenticated;

-- 관리자: 화면에서 고를 검토 대상 목록(UUID 손입력 없이) — [{kind, ref, label, tenant_id?, kind_label?}]
--  QG 출시 후보(release) + 선택 어댑터 함수 wpl_qga_review_candidates(p_kind text, p_limit int)
--  returns table(kind text, ref text, label text, tenant_id uuid, kind_label text) 가 있으면 그 결과(계약 v1 필수 함수 아님).
create or replace function public.wpl_qg_review_candidates(p_kind text default null, p_limit int default 200)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v jsonb := '[]'::jsonb; v_lim int := least(500, greatest(1, coalesce(p_limit, 200))); v_more jsonb;
begin
  if auth.uid() is null or not public.wpl_qga_is_admin() then raise exception '검토 대상 목록은 관리자만 볼 수 있습니다.'; end if;
  if (p_kind is null or p_kind = 'release') and to_regclass('public.wpl_qg_releases') is not null then
    execute 'select coalesce(jsonb_agg(jsonb_build_object(''kind'', ''release'', ''ref'', x.id::text, ''label'', ''#'' || x.rel_no || '' '' || x.title, ''tenant_id'', x.tenant_id)
               order by x.created_at desc), ''[]''::jsonb)
               from (select * from public.wpl_qg_releases where status in (''candidate'',''checking'',''passed'',''blocked'',''approved'') order by created_at desc limit $1) x'
      into v using v_lim;
  end if;
  if to_regprocedure('public.wpl_qga_review_candidates(text,integer)') is not null then
    begin
      execute 'select coalesce(jsonb_agg(jsonb_build_object(''kind'', c.kind, ''ref'', c.ref, ''label'', c.label, ''tenant_id'', c.tenant_id, ''kind_label'', c.kind_label)), ''[]''::jsonb)
                 from public.wpl_qga_review_candidates($1, $2) c where c.kind ~ ''^[a-z][a-z0-9_]{1,39}$'' and c.ref is not null'
        into v_more using p_kind, v_lim;
      v := v || coalesce(v_more, '[]'::jsonb);
    exception when others then
      v := v || jsonb_build_array(jsonb_build_object('kind', '_error', 'ref', '-', 'label', left(sqlerrm, 200)));
    end;
  end if;
  return v;
end $$;
revoke all on function public.wpl_qg_review_candidates(text, int) from public, anon, authenticated;
grant execute on function public.wpl_qg_review_candidates(text, int) to authenticated;

-- ───────── 4) RPC: 요청 → 판정 → 합의 → 사람 확정 ─────────
-- 요청: 관리자는 모든 종류, 테넌트 구성원(can_read_tenant)은 자기 테넌트의 document·copy·ad_material 만.
create or replace function public.wpl_qg_review_request(p_kind text, p_target text default null, p_text text default null, p_title text default null,
  p_tenant uuid default null, p_use_ai boolean default false)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_hq boolean := auth.uid() is not null and public.wpl_qga_is_admin(); t jsonb; v_tenant uuid; v_txt text; v_max int; v_codes text[]; v_id uuid;
begin
  if auth.uid() is null then raise exception '로그인이 필요합니다.'; end if;
  if not v_hq then
    if p_tenant is null or not public.wpl_qga_can_read_tenant(p_tenant) then raise exception '다중 검토를 요청할 권한이 없습니다.'; end if;
    if p_kind not in ('document','copy','ad_material') then raise exception '테넌트에서는 붙여 넣은 문서·문구·광고 자료만 검토를 요청할 수 있습니다.'; end if;
  end if;
  if p_tenant is not null and not public.wpl_qga_tenant_exists(p_tenant) then raise exception '테넌트를 찾을 수 없습니다.'; end if;
  t := public.wpl_qg_review_target_internal(p_kind, p_target, p_text, p_title);
  v_tenant := coalesce(nullif(t->>'tenant_id', '')::uuid, p_tenant);
  if not v_hq and v_tenant is distinct from p_tenant then raise exception '다른 테넌트의 자료는 검토를 요청할 수 없습니다.'; end if;
  v_txt := t->>'text';
  v_max := greatest(1000, coalesce((public.wpl_qg_setting_internal('qg_review_max_chars', '30000'::jsonb) #>> '{}')::int, 30000));
  if char_length(btrim(coalesce(v_txt, ''))) = 0 then raise exception '검토할 내용이 비어 있습니다.'; end if;
  if char_length(v_txt) > v_max then raise exception '문서가 너무 깁니다(최대 %자). 나눠서 요청해 주세요.', to_char(v_max, 'FM999,999,999'); end if;
  select array_agg(r.code order by random()) into v_codes from public.wpl_qg_reviewers r where r.active and p_kind = any(r.applies_to);
  if coalesce(cardinality(v_codes), 0) = 0 then raise exception '이 대상 종류를 검토할 검토자가 없습니다(카탈로그에서 검토자를 켜 주세요).'; end if;

  insert into public.wpl_qg_reviews(tenant_id, target_kind, target_id, target_label, snapshot_text, context_text, snapshot_sha256, industry_code, use_ai, reviewers, requested_by)
  values (v_tenant, p_kind, t->>'target_id', t->>'label', v_txt, nullif(t->>'context', ''), encode(sha256(convert_to(v_txt, 'UTF8')), 'hex'),
          nullif(t->>'industry', ''), coalesce(p_use_ai, false), v_codes, auth.uid())
  returning id into v_id;
  perform public.wpl_qga_audit(v_tenant, 'user', 'qg.review.request', 'wpl_qg_reviews', v_id::text,
    jsonb_build_object('kind', p_kind, 'target', t->>'target_id', 'reviewers', to_jsonb(v_codes), 'use_ai', coalesce(p_use_ai, false)));
  return jsonb_build_object('review_id', v_id, 'kind', p_kind, 'label', t->>'label', 'tenant_id', v_tenant, 'text', v_txt, 'context', t->>'context',
    'reviewers', (select jsonb_agg(jsonb_build_object('code', r.code, 'name', r.name, 'perspective', r.perspective,
                                    'instructions', case when v_hq then r.instructions end, 'veto', r.veto) order by x.ord)
                    from unnest(v_codes) with ordinality x(code, ord) join public.wpl_qg_reviewers r on r.code = x.code));
end $$;
revoke all on function public.wpl_qg_review_request(text, text, text, text, uuid, boolean) from public, anon, authenticated;
grant execute on function public.wpl_qg_review_request(text, text, text, text, uuid, boolean) to authenticated;

-- 판정 1건 기록. p_ai 가 null 이면 규칙 판정. AI 판정은 {verdict, reasons:[{message}], summary, run_id} —
-- run_id 는 이 검토를 대상으로 같은 사람이 방금 남긴 성공한 AI 실행(작업 qg_review)이어야 하고, 규칙 판정보다 느슨해질 수 없다.
create or replace function public.wpl_qg_review_submit(p_review uuid, p_reviewer text, p_ai jsonb default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  rv public.wpl_qg_reviews; rr public.wpl_qg_reviewers; v_rules jsonb; v_ai text; v_final text; v_mode text := 'rules'; v_run uuid; v_model text;
  v_reasons jsonb := '[]'::jsonb; x jsonb; v_pos int; v_summary text; v_done int;
begin
  select * into rv from public.wpl_qg_reviews where id = p_review for update;
  if rv.id is null then raise exception '검토를 찾을 수 없습니다.'; end if;
  if not public.wpl_qg_review_can_internal(rv) then raise exception '이 검토를 다룰 권한이 없습니다.'; end if;
  if rv.status <> 'reviewing' then raise exception '이미 합의가 끝난 검토입니다.'; end if;
  if not (p_reviewer = any(rv.reviewers)) then raise exception '이 검토에 배정되지 않은 검토자입니다.'; end if;
  if exists (select 1 from public.wpl_qg_review_verdicts where review_id = rv.id and reviewer_code = p_reviewer) then raise exception '이 검토자는 이미 판정했습니다.'; end if;
  select * into rr from public.wpl_qg_reviewers where code = p_reviewer;

  v_rules := public.wpl_qg_review_rules_internal(rv, rr);
  v_final := v_rules->>'verdict';
  v_summary := v_rules->>'summary';
  if p_ai is not null and jsonb_typeof(p_ai) = 'object' then
    v_ai := p_ai->>'verdict';
    if v_ai is null or v_ai not in ('approve','concern','reject') then raise exception 'AI 판정 형식이 올바르지 않습니다.'; end if;
    begin v_run := (p_ai->>'run_id')::uuid; exception when others then v_run := null; end;
    select g.model_code into v_model from public.wpl_qga_ai_runs(now() - interval '1 hour') g
     where g.id = v_run and g.task_code = 'qg_review' and g.ref_id = rv.id::text and g.status = 'ok' and g.created_by = auth.uid();
    if v_run is null or v_model is null then
      raise exception 'AI 판정의 실행 기록을 확인할 수 없습니다(규칙 판정으로 다시 요청해 주세요).';
    end if;
    v_mode := 'ai';
    for x in select e from jsonb_array_elements(case when jsonb_typeof(p_ai->'reasons') = 'array' then p_ai->'reasons' else '[]'::jsonb end) e limit 10 loop
      v_reasons := v_reasons || jsonb_build_array(jsonb_build_object('check', 'ai', 'level', case when v_ai = 'approve' then 'note' else v_ai end,
        'code', 'ai', 'message', left(coalesce(case when jsonb_typeof(x) = 'string' then x #>> '{}' else x->>'message' end, ''), 500)));
    end loop;
    v_final := public.wpl_qg_review_worst_internal(v_ai, v_rules->>'verdict');
    v_summary := left(coalesce(nullif(btrim(p_ai->>'summary'), ''), 'AI 판정'), 500)
      || case when v_final <> v_ai then ' · 규칙 바닥선으로 ''' || case v_final when 'reject' then '거부' else '주의' end || '''(으)로 올림' else '' end;
  end if;
  v_reasons := v_reasons || coalesce(v_rules->'reasons', '[]'::jsonb);
  select count(*) + 1 into v_pos from public.wpl_qg_review_verdicts where review_id = rv.id;

  insert into public.wpl_qg_review_verdicts(review_id, tenant_id, reviewer_code, verdict, ai_verdict, rules_verdict, reasons, summary, mode, model, ai_run_id, position, created_by)
  values (rv.id, rv.tenant_id, p_reviewer, v_final, v_ai, v_rules->>'verdict', v_reasons, v_summary, v_mode, coalesce(v_model, case when v_mode = 'rules' then 'rules' end), v_run, v_pos, auth.uid());
  select count(*) into v_done from public.wpl_qg_review_verdicts where review_id = rv.id;
  return jsonb_build_object('ok', true, 'reviewer', p_reviewer, 'verdict', v_final, 'ai_verdict', v_ai, 'rules_verdict', v_rules->>'verdict', 'mode', v_mode,
    'done', v_done, 'total', cardinality(rv.reviewers));
end $$;
revoke all on function public.wpl_qg_review_submit(uuid, text, jsonb) from public, anon, authenticated;
grant execute on function public.wpl_qg_review_submit(uuid, text, jsonb) to authenticated;

-- 합의: 거부권 검토자 거부 → blocked · 승인 ≥ 정족수이고 거부 0 → passed · 그 밖 → needs_human
create or replace function public.wpl_qg_review_finalize(p_review uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  rv public.wpl_qg_reviews; v_quorum int; v_app int; v_con int; v_rej int; v_veto text[]; v_missing text[]; v_outcome text; v_detail jsonb; v_ev uuid;
begin
  select * into rv from public.wpl_qg_reviews where id = p_review for update;
  if rv.id is null then raise exception '검토를 찾을 수 없습니다.'; end if;
  if not public.wpl_qg_review_can_internal(rv) then raise exception '이 검토를 다룰 권한이 없습니다.'; end if;
  if rv.status <> 'reviewing' then raise exception '이미 합의가 끝난 검토입니다.'; end if;
  if not exists (select 1 from public.wpl_qg_review_verdicts where review_id = rv.id) then raise exception '아직 판정이 하나도 없습니다.'; end if;
  v_quorum := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_review_quorum', '3'::jsonb) #>> '{}')::int, 3));
  select count(*) filter (where v.verdict = 'approve'), count(*) filter (where v.verdict = 'concern'), count(*) filter (where v.verdict = 'reject'),
         coalesce(array_agg(v.reviewer_code) filter (where v.verdict = 'reject' and r.veto), '{}')
    into v_app, v_con, v_rej, v_veto
    from public.wpl_qg_review_verdicts v join public.wpl_qg_reviewers r on r.code = v.reviewer_code where v.review_id = rv.id;
  select coalesce(array_agg(c), '{}') into v_missing from unnest(rv.reviewers) c
   where not exists (select 1 from public.wpl_qg_review_verdicts v where v.review_id = rv.id and v.reviewer_code = c);
  v_outcome := case when cardinality(v_veto) > 0 then 'blocked' when v_rej = 0 and v_app >= v_quorum then 'passed' else 'needs_human' end;
  v_detail := jsonb_build_object('quorum', v_quorum, 'approve', v_app, 'concern', v_con, 'reject', v_rej, 'veto_rejects', to_jsonb(v_veto),
    'missing', to_jsonb(v_missing), 'total', cardinality(rv.reviewers),
    'reason', case v_outcome when 'blocked' then '거부권 검토자(' || array_to_string(v_veto, ', ') || ')가 거부했습니다.'
                             when 'passed' then '승인 ' || v_app || '명(정족수 ' || v_quorum || ') · 거부 0명.'
                             else case when v_rej > 0 then '거부 ' || v_rej || '명이 있어 사람이 판단해야 합니다.'
                                       else '승인 ' || v_app || '명으로 정족수(' || v_quorum || ')에 못 미칩니다.' end end);
  v_ev := public.wpl_qg_evidence_append('review', 'review:' || rv.id::text,
    jsonb_build_object('review_id', rv.id, 'kind', rv.target_kind, 'target_id', rv.target_id, 'label', rv.target_label, 'tenant_id', rv.tenant_id,
      'snapshot_sha256', rv.snapshot_sha256, 'reviewers', to_jsonb(rv.reviewers), 'outcome', v_outcome, 'detail', v_detail,
      'verdicts', (select jsonb_agg(jsonb_build_object('reviewer', v.reviewer_code, 'verdict', v.verdict, 'ai_verdict', v.ai_verdict, 'rules_verdict', v.rules_verdict,
                     'mode', v.mode, 'model', v.model, 'ai_run_id', v.ai_run_id, 'position', v.position, 'summary', v.summary, 'reasons', v.reasons) order by v.position)
                     from public.wpl_qg_review_verdicts v where v.review_id = rv.id),
      'finalized_by', auth.uid(), 'finalized_by_label', public.wpl_qg_actor_label_internal()),
    '다중 검토 합의: ' || left(rv.target_label, 200), rv.tenant_id, null);
  perform set_config('wpl.qg_write', 'on', true);
  update public.wpl_qg_reviews set status = 'decided', outcome = v_outcome, outcome_detail = v_detail, decided_at = now(), evidence_id = v_ev where id = rv.id;
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(rv.tenant_id, 'user', 'qg.review.finalize', 'wpl_qg_reviews', rv.id::text, jsonb_build_object('outcome', v_outcome, 'detail', v_detail, 'evidence_id', v_ev));
  return jsonb_build_object('ok', true, 'outcome', v_outcome, 'detail', v_detail, 'evidence_id', v_ev);
end $$;
revoke all on function public.wpl_qg_review_finalize(uuid) from public, anon, authenticated;
grant execute on function public.wpl_qg_review_finalize(uuid) to authenticated;

-- 사람 최종 확정. '차단'을 통과시키는 것은 관리자만·요청자 본인 불가·사유 필수. '사람 판단 필요'를 통과시킬 때도 사유 필수.
create or replace function public.wpl_qg_review_confirm(p_review uuid, p_decision text, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare rv public.wpl_qg_reviews; v_note text := nullif(btrim(coalesce(p_note, '')), ''); v_min int; v_ev uuid;
begin
  select * into rv from public.wpl_qg_reviews where id = p_review for update;
  if rv.id is null then raise exception '검토를 찾을 수 없습니다.'; end if;
  if not public.wpl_qg_review_can_internal(rv) then raise exception '이 검토를 다룰 권한이 없습니다.'; end if;
  if rv.status = 'reviewing' then raise exception '먼저 검토자 판정을 모아 합의를 내야 합니다.'; end if;
  if rv.status = 'confirmed' then raise exception '이미 확정된 검토입니다.'; end if;
  if p_decision is null or p_decision not in ('approved','rejected') then raise exception '통과 또는 반려를 골라 주세요.'; end if;
  if v_note is not null and char_length(v_note) > 2000 then raise exception '메모는 2,000자 이하로 적어 주세요.'; end if;
  v_min := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_review_override_note_min_len', '10'::jsonb) #>> '{}')::int, 10));
  if p_decision = 'approved' and rv.outcome <> 'passed' then
    if char_length(coalesce(v_note, '')) < v_min then
      raise exception '합의 결과가 ''%''인 검토를 통과시키려면 사유를 %자 이상 적어 주세요.', case rv.outcome when 'blocked' then '차단' else '사람 판단 필요' end, v_min;
    end if;
    if rv.outcome = 'blocked' then
      if not public.wpl_qga_is_admin() then raise exception '차단된 검토는 관리자만 통과시킬 수 있습니다.'; end if;
      if not public.wpl_qg_self_approval_ok_internal(rv.requested_by) then
        raise exception '자기가 요청한 검토의 차단은 스스로 풀 수 없습니다. 다른 관리자에게 맡겨 주세요.';
      end if;
    end if;
  end if;
  v_ev := public.wpl_qg_evidence_append('review_decision', 'review:' || rv.id::text,
    jsonb_build_object('review_id', rv.id, 'snapshot_sha256', rv.snapshot_sha256, 'outcome', rv.outcome, 'decision', p_decision, 'note', v_note,
      'override', p_decision = 'approved' and rv.outcome <> 'passed', 'requested_by', rv.requested_by, 'decided_by', auth.uid(),
      'decided_by_label', public.wpl_qg_actor_label_internal(), 'consensus_evidence_id', rv.evidence_id),
    '다중 검토 확정(' || case p_decision when 'approved' then '통과' else '반려' end || '): ' || left(rv.target_label, 200), rv.tenant_id, null);
  perform set_config('wpl.qg_write', 'on', true);
  update public.wpl_qg_reviews set status = 'confirmed', final_decision = p_decision, final_note = v_note, confirmed_by = auth.uid(), confirmed_at = now(),
         decision_evidence_id = v_ev where id = rv.id;
  perform set_config('wpl.qg_write', '', true);
  perform public.wpl_qga_audit(rv.tenant_id, 'user', 'qg.review.confirm', 'wpl_qg_reviews', rv.id::text,
    jsonb_build_object('decision', p_decision, 'outcome', rv.outcome, 'note', v_note, 'evidence_id', v_ev));
  return jsonb_build_object('ok', true, 'decision', p_decision, 'evidence_id', v_ev);
end $$;
revoke all on function public.wpl_qg_review_confirm(uuid, text, text) from public, anon, authenticated;
grant execute on function public.wpl_qg_review_confirm(uuid, text, text) to authenticated;

-- 출시 관문이 읽는 검토 결과(대상 종류 'qg_release' → 출시 후보 id): 사람 확정 approved = passed, rejected = blocked, 그 밖 = pending
create or replace function public.wpl_qg_review_outcome_internal(p_target_kind text, p_target_ref text)
returns jsonb language sql stable security definer set search_path = public as $$
  select coalesce((select jsonb_build_object('result', case when x.final_decision = 'approved' then 'passed' when x.final_decision = 'rejected' then 'blocked' else 'pending' end,
                                             'review_id', x.id, 'outcome', x.outcome, 'status', x.status, 'at', x.created_at)
                     from public.wpl_qg_reviews x
                    where x.target_kind = case when p_target_kind = 'qg_release' then 'release' else p_target_kind end and x.target_id = p_target_ref
                    order by x.created_at desc limit 1),
                  jsonb_build_object('result', 'none'))
$$;
revoke all on function public.wpl_qg_review_outcome_internal(text, text) from public, anon, authenticated;

-- ───────── 5) probe ─────────
create or replace function public.wpl_qg_probe_review_stale(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_days int := greatest(1, coalesce((p_check.params->>'days')::int, (public.wpl_qg_setting_internal('qg_review_stale_days', '3'::jsonb) #>> '{}')::int, 3));
        v_n int; v_list jsonb;
begin
  select count(*), coalesce(jsonb_agg(jsonb_build_object('id', x.id, 'label', x.target_label, 'status', x.status, 'outcome', x.outcome, 'created_at', x.created_at)) filter (where x.rn <= 20), '[]'::jsonb)
    into v_n, v_list
    from (select r.*, row_number() over (order by r.created_at) rn from public.wpl_qg_reviews r
           where r.status in ('reviewing','decided') and r.created_at < now() - make_interval(days => v_days)
             and (p_tenant is null or r.tenant_id = p_tenant)) x;
  if v_n = 0 then return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('days', v_days, 'message', '오래 걸리는 검토가 없습니다.')); end if;
  return jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', 'review_stale', 'title', v_days || '일 넘게 확정되지 않은 다중 검토 ' || v_n || '건',
    'detail', jsonb_build_object('days', v_days, 'count', v_n, 'reviews', v_list));
end $$;
revoke all on function public.wpl_qg_probe_review_stale(public.wpl_qg_checks, uuid) from public, anon, authenticated;

create or replace function public.wpl_qg_probe_review_catalog(p_check public.wpl_qg_checks, p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare v_quorum int := greatest(1, coalesce((public.wpl_qg_setting_internal('qg_review_quorum', '3'::jsonb) #>> '{}')::int, 3)); v_out jsonb := '[]'::jsonb; k text; v_n int; v_veto int;
        v_kinds text[];
begin
  select coalesce(array_agg(distinct k2 order by k2), array['document']) into v_kinds from public.wpl_qg_reviewers r, unnest(r.applies_to) k2 where r.active;
  foreach k in array v_kinds loop
    select count(*), count(*) filter (where veto) into v_n, v_veto from public.wpl_qg_reviewers where active and k = any(applies_to);
    if v_n < v_quorum then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'fail', 'severity', 'high', 'fingerprint', 'quorum_unreachable:' || k,
        'title', '다중 검토 정족수를 채울 수 없음(' || k || ')', 'detail', jsonb_build_object('kind', k, 'reviewers', v_n, 'quorum', v_quorum)));
    end if;
    if v_veto = 0 then
      v_out := v_out || jsonb_build_array(jsonb_build_object('status', 'warn', 'severity', 'medium', 'fingerprint', 'no_veto:' || k,
        'title', '거부권 검토자가 없음(' || k || ')', 'detail', jsonb_build_object('kind', k, 'reviewers', v_n)));
    end if;
  end loop;
  if jsonb_array_length(v_out) = 0 then
    return jsonb_build_object('status', 'pass', 'detail', jsonb_build_object('quorum', v_quorum, 'kinds', to_jsonb(v_kinds), 'message', '모든 대상 종류에서 정족수를 채울 수 있고 거부권 검토자가 있습니다.'));
  end if;
  return v_out;
end $$;
revoke all on function public.wpl_qg_probe_review_catalog(public.wpl_qg_checks, uuid) from public, anon, authenticated;

-- ───────── 6) 시드 ─────────
insert into public.wpl_qg_reviewers(code, name, perspective, instructions, rule_checks, veto, sort) values
 ('legal', '법무 검토자', '표시광고법·전자상거래법·개인정보보호법·업종 법령 위반 위험',
  '너는 한국 법무 검토자다. 문서가 표시광고법(과장·단정·보장·검증 안 된 수치), 전자상거래법(청약철회·사업자 정보·중개자 고지), 개인정보보호법, 이 플랫폼 업종 법령에 어긋나는지 본다. 위반이 분명하면 reject, 애매하면 concern, 문제가 없으면 approve. 법률 자문이 아니라 위험 신호를 짚는 것이다.',
  array['banned_phrases','required_clauses'], true, 10),
 ('privacy', '개인정보 검토자', '개인정보보호법 — 주민등록번호·카드번호·계좌·연락처 노출',
  '너는 개인정보 보호 검토자다. 문서에 주민등록번호·카드번호·계좌번호·개인 연락처·이메일 같은 개인정보가 노출되는지, 수집·이용 목적 없이 개인정보를 요구하는지 본다. 주민등록번호·카드번호가 있으면 반드시 reject. 개인 연락처는 concern.',
  array['pii'], true, 20),
 ('security', '보안 검토자', 'API 키·비밀번호·토큰·실행 코드 노출',
  '너는 보안 검토자다. 문서에 API 키·비밀키·비밀번호·토큰·스크립트 같은 실행 코드가 들어 있는지, 권한 우회·내부 주소 노출이 있는지 본다. 비밀값이나 실행 코드가 있으면 reject.',
  array['secrets','markup'], false, 30),
 ('ux', 'UX 검토자', '처음 보는 사람이 3분 안에 이해하는지(문장 길이·용어·오타)',
  '너는 UX 라이터다. 처음 보는 사람이 바로 이해할 수 있는지(문장이 너무 길지 않은지, 전문 용어·영어 약어를 풀어 썼는지, 오타가 없는지, 다음에 무엇을 하면 되는지) 본다. 읽기 어려우면 concern, 내용이 비었으면 reject.',
  array['readability'], false, 40),
 ('business', '사업 검토자', '근거 없는 수치·실적 주장·과장 약속으로 인한 사업 위험',
  '너는 사업 검토자다. 원문·자료에 없는 숫자(매출·수익·고객 수·만족도), 근거 없는 실적·인증·수상 주장, 지킬 수 없는 약속이 있는지 본다. 근거 없는 수치나 과장이 있으면 concern, 수익 보장처럼 사업을 위태롭게 하면 reject.',
  array['unverified_number','banned_phrases'], false, 50),
 ('consumer', '소비자 보호 검토자', '소비자가 오해하거나 압박받는 표현(긴박감·단정·환불 제한)',
  '너는 소비자 보호 검토자다. 소비자를 오해하게 하거나 압박하는 표현(오늘만·마감 임박·무조건·부작용 없음·환불 불가), 중요한 조건(가격·환불·위약금)을 숨기는지 본다. 금칙어에 해당하면 reject, 오해 소지가 있으면 concern.',
  array['banned_phrases'], false, 60)
on conflict (code) do update set name = excluded.name, perspective = excluded.perspective, instructions = excluded.instructions,
  rule_checks = excluded.rule_checks, veto = excluded.veto, sort = excluded.sort;

-- 금칙어(표시광고법·유사수신 공통 — 업종별은 설치 뒤 더한다)
insert into public.wpl_qg_banned_phrases(code, pattern, severity, reason, suggestion, sort) values
 ('guarantee_profit', '(수익|매출|원금|이자)[^.\n]{0,12}보장', 'block', '수익·원금 보장 표현(표시광고법·유사수신행위법 위험)', '예상치는 근거와 함께 범위로, 보장 표현은 빼세요', 10),
 ('guarantee_100', '100\s*%\s*(보장|환불|성공|효과)', 'block', '100% 보장·성공 단정(표시광고법)', '조건과 예외를 함께 적으세요', 20),
 ('no_side_effect', '부작용\s*(이|은)?\s*(전혀\s*)?없', 'block', '부작용 없음 단정(표시광고법·업종 광고 규제)', '개인차가 있음을 알리세요', 30),
 ('superlative', '(업계|국내|세계)?\s*(최고|최상|1\s*위|넘버\s*원|No\.?\s*1)', 'warn', '최상급·순위 표현은 객관적 근거가 있어야 합니다(표시광고법)', '근거(출처·기간)를 함께 적거나 빼세요', 40),
 ('first_only', '(최초|유일|독보적)', 'warn', '최초·유일 표현은 근거가 있어야 합니다(표시광고법)', '근거를 함께 적거나 빼세요', 50),
 ('absolute', '(무조건|절대|반드시\s*(성공|효과))', 'warn', '단정 표현(표시광고법)', '조건을 함께 적으세요', 60),
 ('urgency', '(오늘\s*만|마감\s*임박|단\s*하루|지금\s*안\s*하면)', 'warn', '소비자를 압박하는 긴박감 표현', '기간을 사실대로 적으세요', 70),
 ('no_refund', '(환불\s*(불가|안\s*됨)|청약\s*철회\s*불가)', 'block', '청약철회 제한 표시(전자상거래법 — 법정 예외 외 불가)', '청약철회 기간·예외를 정확히 적으세요', 80)
on conflict (code) do nothing;

insert into public.wpl_qg_checks(code, engine_code, name, description, probe, risk, scope, schedule, params, expect, remediation, sort) values
 ('review.stale_pending', 'review', '오래 확정되지 않은 다중 검토',
  '검토를 요청하고 정해진 일수(qg_review_stale_days)가 지나도록 사람이 통과·반려를 확정하지 않은 검토를 찾습니다.',
  'wpl_qg_probe_review_stale', 'medium', 'platform', 'daily', '{}'::jsonb,
  '확정 대기 0건',
  '품질·거버넌스 → 다중 AI 독립 검토에서 해당 검토를 열어 검토자 판정과 합의 결과를 보고 통과 또는 반려로 확정하세요.', 10),
 ('review.catalog_quorum', 'review', '검토자 카탈로그 합의 가능성',
  '대상 종류마다 켜진 검토자 수가 정족수(qg_review_quorum) 이상인지, 거부권 검토자가 1명 이상인지 확인합니다.',
  'wpl_qg_probe_review_catalog', 'high', 'platform', 'daily', '{}'::jsonb,
  '모든 종류에서 정족수 충족 · 거부권 검토자 있음',
  '검토자 카탈로그(wpl_qg_reviewers)에서 검토자를 켜거나 적용 대상을 넓히고, 정족수 설정을 확인하세요.', 20)
on conflict (code) do update set name = excluded.name, description = excluded.description, probe = excluded.probe, risk = excluded.risk, scope = excluded.scope,
  schedule = excluded.schedule, params = excluded.params, expect = excluded.expect, remediation = excluded.remediation, sort = excluded.sort;
