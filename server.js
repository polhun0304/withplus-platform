const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
// bcryptjs/otplib/qrcode: WITH+에서 포팅한 대표자 2FA 스텝업(requireOwnerStepUp) 인프라가 사용한다
// (분양조직 정산 자동이체 방법 B/C 실행 라우트를 보호하기 위해 필요 - package.json에도 추가함).
const bcrypt = require('bcryptjs');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
// 참고: 인증은 전부 Supabase Auth(supabase.auth.getUser)로 처리하므로
// jsonwebtoken을 이용한 자체 JWT 발급/검증 로직은 사용하지 않습니다.

// OAuth state 서명(HMAC) 폴백 시크릿: JWT_SECRET 환경변수가 없을 때만 사용된다.
// 예전에는 'withplus-fallback-secret'이라는 고정 문자열을 그대로 썼는데, 이 값이 소스코드에 공개돼 있어
// JWT_SECRET을 설정하지 않은 배포본에서는 누구나 이 문자열로 state를 위조할 수 있는 문제가 있었다.
// 대신 프로세스가 시작될 때마다 새로 생성되는 임의의 32바이트 값을 폴백으로 사용한다(재시작 시 값이
// 바뀌어 그 이전에 발급된 state는 무효화되지만, JWT_SECRET을 제대로 설정해두면 이 값 자체가 쓰이지
// 않으므로 정상적으로 운영 중인 환경에는 영향이 없다).
const RUNTIME_FALLBACK_SECRET = crypto.randomBytes(32).toString('hex');

// OmniCast(YouTube/Facebook OAuth access_token·refresh_token, 커스텀 RTMP stream_key) 저장용 암호화 키.
// OMNICAST_ENCRYPTION_KEY 환경변수(32바이트를 hex로 인코딩한 64자 문자열)를 우선 사용하고, 없으면
// JWT_SECRET 폴백(RUNTIME_FALLBACK_SECRET)과 동일한 패턴으로 프로세스가 시작될 때마다 새로 생성되는
// 임의의 32바이트 값으로 폴백한다.
// 트레이드오프 주의: 폴백을 쓰는 경우 서버가 재시작되면 키가 바뀌어, 그 이전에 이 키로 암호화 저장해둔
// access_token/refresh_token/stream_key를 더 이상 복호화할 수 없게 된다(YouTube/Facebook 재연결,
// 커스텀 RTMP 스트림키 재입력이 필요해짐) - 운영 환경에서는 반드시 OMNICAST_ENCRYPTION_KEY를 고정값으로 설정해야 한다.
let omnicastEncryptionKey;
if (process.env.OMNICAST_ENCRYPTION_KEY) {
  const keyBuf = Buffer.from(process.env.OMNICAST_ENCRYPTION_KEY, 'hex');
  if (keyBuf.length === 32) {
    omnicastEncryptionKey = keyBuf;
  } else {
    console.warn('⚠️  OMNICAST_ENCRYPTION_KEY는 32바이트(hex 64자)여야 합니다. 형식이 올바르지 않아 런타임 임의 키로 폴백합니다.');
    omnicastEncryptionKey = crypto.randomBytes(32);
  }
} else {
  console.warn('⚠️  OMNICAST_ENCRYPTION_KEY 환경변수가 설정되지 않아 OmniCast 토큰/스트림키를 런타임 임의 키로 암호화합니다. 서버가 재시작되면 기존에 암호화 저장된 값을 복호화할 수 없게 되니(YouTube/Facebook 재연결, RTMP 키 재입력 필요), 운영 환경에서는 반드시 OMNICAST_ENCRYPTION_KEY를 고정값으로 설정하세요.');
  omnicastEncryptionKey = crypto.randomBytes(32);
}

// AES-256-GCM으로 OmniCast 시크릿(OAuth access_token/refresh_token, RTMP stream_key)을 암호화한다.
// 반환값 형식: "enc:v1:<iv-hex>:<authTag-hex>:<ciphertext-hex>" - 접두사(enc:v1:)로 기존에 평문으로
// 저장돼 있던(이번 수정 이전의, 마이그레이션 전) 값과 구분한다. null/빈 문자열은 그대로 null로 저장한다.
function encryptSecret(text) {
  if (text === null || text === undefined || text === '') return null;
  const iv = crypto.randomBytes(12); // GCM 권장 IV 길이(12바이트)
  const cipher = crypto.createCipheriv('aes-256-gcm', omnicastEncryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `enc:v1:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

// encryptSecret으로 암호화된 값을 복호화한다. "enc:v1:" 접두사가 없으면(이번 수정 이전에 평문으로 저장된
// 기존 값 - 별도 마이그레이션 전까지는 평문으로 남아있다) 그대로 돌려준다(하위호환). 복호화 자체가
// 실패하면(암호화 키가 그 사이 바뀐 경우 등) null을 돌려주고 에러만 로그로 남긴다.
function decryptSecret(stored) {
  if (stored === null || stored === undefined || stored === '') return stored;
  if (typeof stored !== 'string' || !stored.startsWith('enc:v1:')) return stored; // 평문(마이그레이션 전) 하위호환
  try {
    const [, , ivHex, authTagHex, dataHex] = stored.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', omnicastEncryptionKey, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) {
    console.error('OmniCast 시크릿 복호화 실패 (암호화 키가 바뀌었을 수 있음):', err.message);
    return null;
  }
}

const { createClient } = require('@supabase/supabase-js');

const cron = require('node-cron');

// ============================================
// Supabase 초기화
// ============================================
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

// 관리자 권한 클라이언트 (SERVICE_ROLE_KEY)
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// 공개 클라이언트 (ANON_KEY) - RLS 정책이 적용됨
const supabasePublic = createClient(supabaseUrl, supabaseAnonKey);

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// 미들웨어
// ============================================
// 홈페이지의 인라인 스크립트/스타일 허용을 위해 CSP 비활성화
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================
// Rate Limiting - 격차분석에서 짚었던 "API 남용 방어 전무" 항목 해결.
// 로그인 자체는 클라이언트가 Supabase Auth를 직접 호출하므로(이 서버를 거치지 않음) 여기서 막을 수 없지만,
// 이 서버가 직접 처리하는 API 전반(특히 쿠폰 코드처럼 무작위 대입 공격이 가능한 것들)은 방어가 전혀 없었다.
// 프록시(ALB/nginx) 뒤에 놓일 가능성을 고려해 X-Forwarded-For 첫 번째 IP를 신뢰한다(현재는 EC2에 직접
// 노출되어 있지만, 도메인 연결 시 CloudFront/ALB를 앞에 두는 것이 일반적인 구성이라 미리 대응해둔다).
app.set('trust proxy', 1);

// 전체 API 공통 - 넉넉하지만 스크래핑/전수조사성 남용은 막는 기본 방어선
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too Many Requests', message: '요청이 너무 많습니다. 잠시 후 다시 시도해주세요.', timestamp: new Date().toISOString() }
});
app.use('/api/', apiLimiter);

// 쿠폰 코드(시리얼 쿠폰/일반 쿠폰) 검증·등록 - 코드를 무작위로 대입해보는 공격이 가능한 엔드포인트라 훨씬 엄격하게 제한
const couponLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too Many Requests', message: '쿠폰 코드 시도 횟수가 너무 많습니다. 15분 후 다시 시도해주세요.', timestamp: new Date().toISOString() }
});
app.use('/api/serial-coupons/redeem', couponLimiter);
app.use('/api/coupons/validate', couponLimiter);

// 팬 활동 점수 API - view/share처럼 서버가 실제 발생 여부를 검증할 수 없는 가벼운 활동은, 클라이언트가
// 짧은 시간에 반복 호출해 점수를 긁어가는 남용을 막기 위해 별도로 더 엄격하게 제한한다.
const fanActivityLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too Many Requests', message: '활동 기록 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.', timestamp: new Date().toISOString() }
});

// LIVE+ 세션 채팅 도배 방지 - 기존에는 "마지막 메시지 시각을 조회한 뒤 삽입" 방식이라, 같은 사용자가 보낸
// 두 요청이 동시에 병렬로 도착하면 둘 다 "마지막 메시지가 오래전"이라고 잘못 판단해 도배 방지 체크를
// 우회할 수 있었다(TOCTOU 레이스). express-rate-limit을 이 라우트 전용으로 추가해 사용자 단위로 짧은
// 시간창(2초)에 1회만 허용되도록 별도의 방어선을 하나 더 둔다 - 이 미들웨어가 요청 자체를 라우트 핸들러
// 진입 전에 걸러내므로, 기존 DB 조회 기반 체크와 별개로 병렬요청 레이스를 실질적으로 차단한다.
const liveChatLimiter = rateLimit({
  windowMs: 2 * 1000,
  max: 1,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.user && req.user.id) || req.ip,
  message: { error: 'Too Many Requests', message: '메시지를 너무 빠르게 보내고 있어요. 잠시 후 다시 시도해주세요', timestamp: new Date().toISOString() }
});

// 정적 파일 서빙 (홈페이지: public/index.html)

app.use(express.static(path.join(__dirname, 'public')));

// 인증 미들웨어
// 회원가입(join.html)은 client.auth.signUp()만 호출하는 순수 Supabase Auth 방식이라, auth.users에는
// 계정이 생기지만 이 코드베이스 어디에도 profiles 행을 만들어주는 곳이 없었다(테스트 스크립트만
// admin.auth.admin.createUser 직후 별도로 profiles를 upsert해왔기 때문에 지금까지 드러나지 않았던
// 실제 버그). profiles가 없으면 주문/리뷰/마일리지 등 거의 모든 기능이 조회 실패로 조용히 깨지므로,
// 인증 미들웨어에서 매 요청마다 정직하게 확인해 없으면 만들어준다. 이미 확인된 사용자는 메모리에
// 캐시해 매 요청마다 DB를 다시 조회하지 않도록 한다(서버 재시작 전까지 유효 - shippingPolicyCache 등
// 기존의 인메모리 캐시 패턴과 동일).
// knownProfileUserIds는 "존재 + 탈퇴하지 않음(활성)"이 확인된 사용자만 캐시한다. 탈퇴 처리(회원탈퇴 API)
// 시점에 이 캐시에서 즉시 제거되므로, 캐시에 없는 사용자는 항상 DB에서 다시 확인한다.
const knownProfileUserIds = new Set();
async function ensureProfileExists(user) {
  if (knownProfileUserIds.has(user.id)) return { active: true };
  try {
    const { data: existing } = await supabase.from('profiles').select('id, is_active').eq('id', user.id).maybeSingle();
    if (existing) {
      // is_active가 명시적으로 false면 탈퇴한 계정 - is_active 컬럼 자체를 아직 안 쓰는 기존 회원은
      // null/undefined이므로 활성으로 취급한다(회원탈퇴 API가 탈퇴 시에만 명시적으로 false를 넣음).
      if (existing.is_active === false) return { active: false };
      knownProfileUserIds.add(user.id);
      return { active: true };
    }
    const meta = user.user_metadata || {};
    const { error: insertErr } = await supabase.from('profiles').upsert([{
      id: user.id,
      email: user.email,
      full_name: meta.full_name || meta.name || null, // 소셜 로그인(구글/카카오) 제공자별로 메타데이터 키가 다를 수 있어 둘 다 확인
      role: 'member',
      member_type: 'general'
    }], { onConflict: 'id', ignoreDuplicates: true });
    if (insertErr) throw insertErr;
    knownProfileUserIds.add(user.id);
    return { active: true };
  } catch (err) {
    console.error('Error ensuring profile exists for user', user.id, ':', err.message);
    // 조회 자체가 실패한 경우(일시적 DB 오류 등)까지 차단하면 서비스 전체가 막히므로, 기존 동작과 동일하게 통과시킨다.
    return { active: true };
  }
}

// JWT의 페이로드(가운데 부분)만 디코딩해 AAL(Authenticator Assurance Level) 클레임을 읽어온다.
// 서명 검증은 이미 supabase.auth.getUser(token)이 Supabase 서버에 물어봐서 대신해주므로, 여기서는
// 이미 신뢰할 수 있다고 확인된 토큰의 클레임만 꺼내 쓴다(추가 서명 검증이 필요 없음).
function decodeJwtAal(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8'));
    return payload.aal || 'aal1';
  } catch (e) {
    return 'aal1';
  }
}

// amr(Authentication Methods Reference) 클레임 - "언제 어떤 방법으로 인증했는지"의 이력 배열
// ({method, timestamp} 형태)이다. 대표자 스텝업을 "내 계정 2FA"(Supabase Auth MFA)로 병합할 때
// "방금 TOTP로 aal2를 통과했는지"의 신선도를 검사하는 용도로만 쓴다(/api/admin/owner/stepup/via-account-mfa
// 참고). decodeJwtAal과 마찬가지로 서명 검증은 이미 끝난 토큰의 클레임만 꺼내 쓰는 것이라 안전하다.
function decodeJwtAmr(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8'));
    return Array.isArray(payload.amr) ? payload.amr : [];
  } catch (e) {
    return [];
  }
}

const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication token required',
        timestamp: new Date().toISOString()
      });
    }

    // Supabase에서 토큰 검증
    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid or expired token',
        timestamp: new Date().toISOString()
      });
    }

    req.user = user;
    req.authAal = decodeJwtAal(token);
    const profileStatus = await ensureProfileExists(user);
    if (!profileStatus.active) {
      return res.status(403).json({
        error: 'Forbidden',
        message: '탈퇴 처리된 계정입니다',
        timestamp: new Date().toISOString()
      });
    }
    next();
  } catch (err) {
    res.status(401).json({
      error: 'Unauthorized',
      message: err.message,
      timestamp: new Date().toISOString()
    });
  }
};

// authenticate와 달리 토큰이 없거나 유효하지 않아도 요청을 막지 않고 그냥 req.user 없이 통과시킨다.
// 비로그인 방문자의 행동(클릭/체류시간 등)도 기록하고 싶은 엔드포인트(예: /api/interactions)에서 사용 -
// 로그인 상태면 개인화 신호로 이어붙이고, 비로그인이면 익명으로만 기록한다.
const optionalAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return next();
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (!error && user) req.user = user;
  } catch (err) { /* 토큰 검증 실패해도 비로그인으로 취급하고 계속 진행 */ }
  next();
};

// ============================================
// 사용자 행동 이벤트 기록 (개인화 추천 알고리즘의 입력 신호)
// ============================================
// 상품상세 진입(view)/이탈(view_end + 체류시간)/장바구니 담기(cart_add)/삭제(cart_remove)를 기록한다.
// 로그인 여부와 무관하게 호출되므로 optionalAuth를 사용하고, 비로그인 방문자는 user_id 없이(익명으로) 저장한다.
// 프론트엔드의 트래킹 호출(특히 sendBeacon으로 보내는 view_end)이 실패해도 사용자 경험에 영향이 없어야 하므로
// 유효성 검증만 엄격히 하고 DB 오류는 관대하게(로그만 남기고 200) 처리한다.
const VALID_INTERACTION_EVENTS = ['view', 'view_end', 'cart_add', 'cart_remove'];
app.post('/api/interactions', optionalAuth, async (req, res) => {
  try {
    const { product_id, event_type, dwell_ms, session_id, category } = req.body || {};
    if (!product_id || typeof product_id !== 'string') {
      return res.status(400).json({ error: 'Bad Request', message: 'product_id가 필요합니다', timestamp: new Date().toISOString() });
    }
    if (!VALID_INTERACTION_EVENTS.includes(event_type)) {
      return res.status(400).json({ error: 'Bad Request', message: `event_type은 ${VALID_INTERACTION_EVENTS.join('/')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
    }
    let dwellMs = null;
    if (dwell_ms !== undefined && dwell_ms !== null) {
      const n = Number(dwell_ms);
      if (Number.isFinite(n) && n >= 0) dwellMs = Math.round(n);
    }

    const { error } = await supabase.from('product_interactions_with').insert([{
      user_id: req.user ? req.user.id : null,
      product_id,
      category: category ? String(category).slice(0, 100) : null,
      event_type,
      dwell_ms: dwellMs,
      session_id: session_id ? String(session_id).slice(0, 200) : null
    }]);
    if (error) {
      // product_id가 삭제된 상품이거나 FK 위반 등 - 트래킹 실패가 사용자 경험을 막아서는 안 되므로 로그만 남긴다.
      console.error('행동 이벤트 기록 실패:', error.message);
      return res.status(204).end();
    }
    res.status(204).end();
  } catch (err) {
    console.error('Error recording interaction:', err);
    // 트래킹 엔드포인트는 실패해도 프론트를 막지 않는다.
    res.status(204).end();
  }
});

// ============================================
// 헬스 체크 엔드포인트
// ============================================
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'WITH+ Community E-commerce Platform',
    port: PORT,
    database: 'Supabase (GMWOS 통합)',
  });
});

// ============================================
// 클라이언트 설정 엔드포인트 (ANON_KEY는 공개 정보이므로 노출 안전)
// 프론트엔드(login.html 등)가 Supabase Auth를 직접 사용할 수 있도록 제공
// ============================================
app.get('/api/config', (req, res) => {
  res.json({
    supabaseUrl,
    supabaseAnonKey
  });
});

// ============================================
// API 정보 엔드포인트
// (루트 '/'는 이제 홈페이지 index.html이 서빙됨)
// ============================================
app.get('/api', (req, res) => {
  res.json({
    message: 'WITH+ Community E-commerce Platform API',
    version: '1.0.0',
    mode: '통합 모드 (GMWOS Supabase)',
    endpoints: {
      health: '/api/health',
      products: '/api/products',
      orders: '/api/orders',
      reviews: '/api/reviews'
    }
  });
});

// ============================================
// 역할(Role) 기반 접근 제어
// profiles.role 은 GMWOS 와 공유하는 컬럼이므로 읽기만 하고 절대 쓰지 않음.
// WITH+ 에서 의미있는 역할: provider(공급자) / admin / super_admin
// ============================================
const requireRole = (allowedRoles) => async (req, res, next) => {
  try {
    const { data: profile, error } = await supabase
      .from('profiles')
      .select('role')
      .eq('id', req.user.id)
      .single();

    if (error || !profile) {
      return res.status(403).json({
        error: 'Forbidden',
        message: '프로필 정보를 확인할 수 없습니다',
        timestamp: new Date().toISOString()
      });
    }

    if (!allowedRoles.includes(profile.role)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: '이 작업을 수행할 권한이 없습니다',
        timestamp: new Date().toISOString()
      });
    }

    // 🔒 관리자 2단계 인증(2FA) - 격차분석에서 지적된 "관리자 계정에 2FA 없음" 항목 해결.
    // 계정을 탈취당하면 전체 회원/주문/결제설정까지 조작 가능한 admin/super_admin에 한해 강제한다.
    // 아직 2FA를 등록하지 않은 관리자까지 당장 차단하면 형님 계정을 포함해 기존 관리자들이 전부
    // 잠길 수 있으므로, "TOTP를 등록해둔 계정만" 2단계 인증(세션이 aal2)을 요구한다 - 즉 등록하는
    // 순간부터 그 계정은 반드시 2단계 인증을 통과해야 로그인이 완성되는 방식(선택적 활성화, 활성화 후 강제).
    if (isAdminRole(profile.role)) {
      const hasVerifiedTotp = Array.isArray(req.user.factors) && req.user.factors.some(f => f.factor_type === 'totp' && f.status === 'verified');
      if (hasVerifiedTotp && req.authAal !== 'aal2') {
        return res.status(403).json({
          error: 'Forbidden',
          message: '2단계 인증이 필요합니다. 로그인 시 인증 앱의 코드를 입력해주세요.',
          mfaRequired: true,
          timestamp: new Date().toISOString()
        });
      }
    }

    req.userRole = profile.role;

    // 🕵️ 관리자 감사로그: admin/super_admin의 상태변경 요청만 기록(조회성 GET은 제외)
    if (isAdminRole(profile.role) && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      res.on('finish', () => { logAdminAction(req, res, profile.role); });
    }

    next();
  } catch (err) {
    res.status(403).json({
      error: 'Forbidden',
      message: err.message,
      timestamp: new Date().toISOString()
    });
  }
};

const isAdminRole = (role) => role === 'admin' || role === 'super_admin';

// ============================================
// 🕵️ 관리자 감사로그 (Admin Audit Log)
// admin/super_admin이 상태를 변경하는 요청(POST/PUT/PATCH/DELETE)을 보낼 때마다
// requireRole 통과 직후 등록되어, 응답이 실제로 나간 다음(res.on('finish')) 비동기로 기록한다.
// 요청 처리 자체를 막지 않기 위해 실패해도 조용히 콘솔에만 남기고 넘어간다(fire-and-forget).
// ============================================
const AUDIT_SENSITIVE_KEY_PATTERN = /pass|token|secret|api[-_]?key|credential/i;
function redactSensitiveFields(value, depth = 0) {
  if (depth > 4 || value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(v => redactSensitiveFields(v, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = AUDIT_SENSITIVE_KEY_PATTERN.test(k) ? '[REDACTED]' : redactSensitiveFields(v, depth + 1);
    }
    return out;
  }
  return value;
}

async function logAdminAction(req, res, role) {
  try {
    let bodySnapshot = redactSensitiveFields(req.body);
    let serialized = JSON.stringify(bodySnapshot);
    if (serialized && serialized.length > 4000) {
      bodySnapshot = { _truncated: true, preview: serialized.slice(0, 4000) };
    }
    await supabase.from('admin_audit_logs_with').insert([{
      admin_id: req.user.id,
      admin_email: req.user.email || null,
      role,
      method: req.method,
      path: req.originalUrl || req.path,
      status_code: res.statusCode,
      body_snapshot: bodySnapshot,
      ip_address: (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString().split(',')[0].trim() || null
    }]);
  } catch (err) {
    console.error('감사로그 기록 실패:', err.message);
  }
}

// ============================================
// 🔐 대표자 2FA 스텝업 인프라 (WITH+에서 포팅) - 분양조직 정산 자동이체(오픈뱅킹/정산대행) 방법 B/C 실행을
// 보호하기 위해 이식했다. LIVE+는 원래 원가(cost_price) 개념/화면이 없어 이 인프라가 없었으므로, 아래는
// WITH+ server.js의 "원가(cost_price) 접근 제어 인프라" + "대표자 2단계 인증(2FA)" 섹션을 거의 그대로
// 옮긴 것이다(로직/DB 테이블은 두 저장소가 공유하는 동일 Supabase 프로젝트를 그대로 사용).
// ============================================
function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString().split(',')[0].trim() || null;
}

// 원가 열람/수정 시도는 성공/실패를 가리지 않고 전부 감사로그에 남긴다 (실패해도 원래 요청을 막지 않는다)
async function logCostAudit({ profileId, action, productId, detail, ip }) {
  try {
    await supabase.from('cost_access_audit_log_with').insert([{
      profile_id: profileId || null,
      action,
      product_id: productId || null,
      detail: detail || null,
      ip: ip || null
    }]);
  } catch (err) {
    console.error('원가 접근 감사로그 기록 실패:', err.message);
  }
}

// 🔒 대표자 TOTP 시크릿 암호화 키 - JWT_SECRET과 동일한 폴백 철학: 미설정 시 소스에 공개된 고정값 대신
// 프로세스 시작 시 1회 생성한 런타임 전용 랜덤 키를 쓴다(재시작하면 이전에 등록된 TOTP는 전부 무효화되지만,
// 아무도 예측할 수 없는 값이 하드코딩된 고정값보다 안전하다). 운영 환경에서는 반드시 .env에 설정해야 한다.
if (!process.env.OWNER_SECURITY_KEY) {
  console.error('[SECURITY WARNING] OWNER_SECURITY_KEY 환경변수가 설정되지 않았습니다. 프로세스 시작 시 생성한 런타임 전용 임시 키를 대신 사용합니다(대표자 TOTP 암호화용). 재시작 시 기존 등록된 TOTP는 모두 무효화됩니다. 반드시 .env에 OWNER_SECURITY_KEY를 설정해주세요.');
}
const OWNER_SECURITY_RUNTIME_FALLBACK_KEY = crypto.randomBytes(32).toString('hex');
function getOwnerSecurityKey() {
  const raw = process.env.OWNER_SECURITY_KEY || OWNER_SECURITY_RUNTIME_FALLBACK_KEY;
  return crypto.createHash('sha256').update(raw).digest(); // 임의 길이 문자열을 AES-256용 32바이트 키로 정규화
}
function encryptOwnerSecret(plainText) {
  const key = getOwnerSecurityKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [iv.toString('base64'), authTag.toString('base64'), encrypted.toString('base64')].join('.');
}
function decryptOwnerSecret(payload) {
  const key = getOwnerSecurityKey();
  const parts = String(payload || '').split('.');
  if (parts.length !== 3) throw new Error('잘못된 암호화 데이터 형식입니다');
  const [ivB64, tagB64, dataB64] = parts;
  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(tagB64, 'base64');
  const data = Buffer.from(dataB64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

// 원가 열람용 스텝업 토큰 - 15분 짧은 수명. 이 코드베이스는 인증을 전부 Supabase Auth로 처리하고
// jsonwebtoken 같은 별도 JWT 라이브러리를 쓰지 않으므로(파일 상단 주석 참고), 새 의존성을 추가하는 대신
// 이미 쓰고 있는 HMAC-SHA256 서명 패턴(OAuth state 파라미터와 동일한 방식)으로 JWT 호환 구조
// (header.payload.signature, base64url)를 직접 서명/검증한다.
const COST_STEPUP_TTL_SECONDS = 15 * 60;
function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(input) {
  let s = String(input).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}
function signCostStepUpToken(profileId) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = { sub: profileId, type: 'cost_stepup', iat: nowSec, exp: nowSec + COST_STEPUP_TTL_SECONDS };
  const headerPart = base64url(JSON.stringify(header));
  const payloadPart = base64url(JSON.stringify(payload));
  const signature = crypto.createHmac('sha256', process.env.JWT_SECRET || RUNTIME_FALLBACK_SECRET)
    .update(`${headerPart}.${payloadPart}`).digest();
  return `${headerPart}.${payloadPart}.${base64url(signature)}`;
}
function verifyCostStepUpToken(token) {
  try {
    if (!token || typeof token !== 'string') return { valid: false, reason: 'missing' };
    const parts = token.split('.');
    if (parts.length !== 3) return { valid: false, reason: 'malformed' };
    const [headerPart, payloadPart, signaturePart] = parts;
    const expectedSig = base64url(crypto.createHmac('sha256', process.env.JWT_SECRET || RUNTIME_FALLBACK_SECRET)
      .update(`${headerPart}.${payloadPart}`).digest());
    const sigBuf = Buffer.from(signaturePart);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return { valid: false, reason: 'bad_signature' };
    }
    const payload = JSON.parse(base64urlDecode(payloadPart).toString('utf8'));
    if (payload.type !== 'cost_stepup') return { valid: false, reason: 'wrong_type' };
    if (!payload.exp || Math.floor(Date.now() / 1000) > payload.exp) return { valid: false, reason: 'expired' };
    return { valid: true, payload };
  } catch (err) {
    return { valid: false, reason: 'parse_error' };
  }
}

// 🔒 원가/마진율 접근 게이트. authenticate 뒤에 붙여서 쓴다. (a) role === 'super_admin' (b) profiles.is_owner
// === true (c) X-Cost-StepUp-Token 헤더가 유효(서명+15분 이내+본인+type:'cost_stepup') 셋을 모두 만족해야
// 통과하고, 하나라도 실패하면 무조건 403 + 감사로그(action:'step_up_denied')를 남기고 거부한다.
const requireOwnerStepUp = async (req, res, next) => {
  const ip = getClientIp(req);
  const deny = async (reason, detail) => {
    await logCostAudit({
      profileId: req.user ? req.user.id : null,
      action: 'step_up_denied',
      productId: (req.params && (req.params.id || req.params.productId)) || null,
      detail: { reason, ...(detail || {}) },
      ip
    });
    return res.status(403).json({
      error: 'Forbidden',
      message: '원가 정보는 대표자 계정이 2단계 인증을 완료해야 조회/수정할 수 있습니다',
      timestamp: new Date().toISOString()
    });
  };
  try {
    if (!req.user) return deny('not_authenticated');
    const { data: profile, error } = await supabase
      .from('profiles')
      .select('id, role, is_owner')
      .eq('id', req.user.id)
      .single();
    if (error || !profile) return deny('profile_not_found');
    if (profile.role !== 'super_admin' || !profile.is_owner) {
      return deny('not_owner', { role: profile.role, is_owner: !!profile.is_owner });
    }
    const token = req.headers['x-cost-stepup-token'];
    if (!token) return deny('missing_token');
    const verified = verifyCostStepUpToken(token);
    if (!verified.valid) return deny('invalid_token', { token_reason: verified.reason });
    if (verified.payload.sub !== profile.id) return deny('token_subject_mismatch');
    req.ownerProfile = profile;
    next();
  } catch (err) {
    console.error('requireOwnerStepUp 오류:', err.message);
    return deny('internal_error');
  }
};

// 대표자가 "내 계정 2단계 인증"(Supabase Auth MFA TOTP) 또는 owner_security_with의 SMS/이메일 중
// 최소 하나라도 등록해두었는지 확인한다. requireOwnerStepUpOrBootstrap(아래)이 "대표자가 아직 아무
// 인증수단도 등록하지 않은 부트스트랩 상태에서는 스텝업 없이 통과시킬지"를 판단하는 데만 쓰인다.
async function hasAnyOwnerStepUpFactor(profileId, user) {
  const accountTotpVerified = Array.isArray(user?.factors) && user.factors.some(f => f.factor_type === 'totp' && f.status === 'verified');
  if (accountTotpVerified) return true;
  const { data: security } = await supabase.from('owner_security_with').select('phone, otp_email').eq('profile_id', profileId).maybeSingle();
  return !!(security && (security.phone || security.otp_email));
}

// requireOwnerStepUp과 같은 3가지 조건(로그인 + 대표자 본인 + 유효한 스텝업 토큰)을 검사하는 로직을
// 미들웨어가 아니라 "필요할 때 직접 호출할 수 있는 순수 함수"로도 재사용할 수 있게 뽑아둔 버전이다.
// GET /api/admin/community-settlements처럼 "같은 엔드포인트를 관리자와 분양조직 담당자가 공유하고,
// 관리자로 호출할 때만" 이 검사를 추가로 걸어야 하는 경우 미들웨어 체인에 넣을 수 없어서 필요하다.
// allowBootstrap:true면 대표자가 2FA 수단을 하나도 등록하지 않은 상태에서는 토큰 없이 통과시킨다 -
// 그렇지 않으면 대표자 본인도 "🔐 대표자 보안설정"에서 수단을 등록하기 전까지 분양 조직/정산/수수료율
// 화면을 영원히 볼 수 없는 닭과 달걀 문제가 생기기 때문이다. (원가/마진율을 지키는 requireOwnerStepUp
// 자체에는 이 예외가 없다 - 그 데이터가 더 민감하다고 보고 부트스트랩 여부와 무관하게 항상 강제한다.)
async function checkOwnerStepUp(req, { allowBootstrap = false } = {}) {
  if (!req.user) return { ok: false, status: 403, message: '로그인이 필요합니다', reason: 'not_authenticated' };
  const { data: profile, error } = await supabase.from('profiles').select('id, role, is_owner').eq('id', req.user.id).single();
  if (error || !profile) return { ok: false, status: 403, message: '프로필 정보를 확인할 수 없습니다', reason: 'profile_not_found' };
  if (profile.role !== 'super_admin' || !profile.is_owner) {
    return { ok: false, status: 403, message: '대표자 계정만 조회/수정할 수 있습니다', reason: 'not_owner' };
  }
  const token = req.headers['x-cost-stepup-token'];
  if (!token) {
    if (allowBootstrap && !(await hasAnyOwnerStepUpFactor(profile.id, req.user))) {
      return { ok: true, profile };
    }
    return { ok: false, status: 403, message: '대표자 계정이 2단계 인증을 완료해야 조회/수정할 수 있습니다', reason: 'missing_token' };
  }
  const verified = verifyCostStepUpToken(token);
  if (!verified.valid) return { ok: false, status: 403, message: '2단계 인증이 만료되었거나 유효하지 않습니다. 다시 인증해주세요.', reason: 'invalid_token' };
  if (verified.payload.sub !== profile.id) return { ok: false, status: 403, message: '2단계 인증 토큰이 이 계정의 것이 아닙니다', reason: 'token_subject_mismatch' };
  return { ok: true, profile };
}

// 🔒 분양 조직 관리 / 분양조직 정산 / 공급자별 수수료율 조회처럼 "은행계좌·수수료율 등 민감정보를 보여주는
// 화면"의 진입 게이트. requireOwnerStepUp과 동일하지만 부트스트랩 예외(위 checkOwnerStepUp 주석 참고)가 있다.
const requireOwnerStepUpOrBootstrap = async (req, res, next) => {
  try {
    const result = await checkOwnerStepUp(req, { allowBootstrap: true });
    if (!result.ok) {
      await logCostAudit({ profileId: req.user ? req.user.id : null, action: 'step_up_denied', detail: { reason: result.reason }, ip: getClientIp(req) });
      return res.status(result.status).json({ error: 'Forbidden', message: result.message, timestamp: new Date().toISOString() });
    }
    req.ownerProfile = result.profile;
    next();
  } catch (err) {
    console.error('requireOwnerStepUpOrBootstrap 오류:', err.message);
    res.status(403).json({ error: 'Forbidden', message: '2단계 인증 확인 중 오류가 발생했습니다', timestamp: new Date().toISOString() });
  }
};

// ============================================
// 대표자 2단계 인증(2FA) - 원가 열람용 스텝업 토큰 발급
// ------------------------------------------------------------
// Supabase Auth 로그인 자체의 관리자 2FA(TOTP, aal2 - requireRole 안에 이미 구현됨)와는 완전히 별개다.
// 여기 구현하는 2FA는 "로그인은 이미 끝난 대표자 계정"이 원가/마진율처럼 극히 민감한 화면에 들어갈 때
// 한 번 더 통과해야 하는 추가 관문이며, 통과하면 15분짜리 스텝업 토큰만 내어준다(세션 자체를 바꾸지 않음).
// ============================================

function verifyTotpCode(code, secret) {
  try {
    return authenticator.check(String(code || '').trim(), secret);
  } catch (err) {
    return false;
  }
}

// 📱 대표자 원가열람용 SMS 인증코드 발송 - 프로바이더별로 분기 가능한 얇은 wrapper.
// 정직하게 밝히자면: 현재는 알리고(aligo) 하나만 골격을 만들어두었고 실제 API 호출은 구현되어 있지 않다.
// (알리고의 정확한 요청 스펙 - 엔드포인트/파라미터명/발신번호 사전등록 여부 등을 확신할 수 없어 임의로
// 구현하면 "됐다고 나오지만 실제로는 안 가는" 상태가 될 위험이 크기 때문. 그런 거짓 성공보다는 명확한 에러가 낫다)
// SMS_PROVIDER 환경변수가 없거나 지원하지 않는 값이면 즉시 에러를 던지고, 호출부(request-otp)는 이를
// 501 Not Implemented로 정직하게 응답한다 - 절대 발송된 것처럼 거짓 성공 응답을 만들지 않는다.
async function sendSms(phone, code) {
  const provider = process.env.SMS_PROVIDER;
  if (!provider) {
    throw new Error('SMS_PROVIDER 환경변수가 설정되지 않았습니다');
  }
  if (provider === 'aligo') {
    const apiKey = process.env.ALIGO_API_KEY;
    const userId = process.env.ALIGO_USER_ID;
    const sender = process.env.ALIGO_SENDER;
    if (!apiKey || !userId || !sender) {
      throw new Error('ALIGO_API_KEY / ALIGO_USER_ID / ALIGO_SENDER 환경변수가 설정되지 않았습니다');
    }
    // TODO: 알리고 SMS API(https://smartsms.aligo.in/send/) 실제 연동. 정확한 요청 스펙을 확인 후
    // axios/fetch로 POST 요청을 구현해야 한다. 지금은 뼈대만 있고 실제 발송은 되지 않는다.
    throw new Error('aligo SMS 연동이 아직 구현되지 않았습니다 (뼈대만 준비됨, sendSms() 함수의 TODO 참고)');
  }
  throw new Error(`지원하지 않는 SMS_PROVIDER입니다: ${provider}`);
}

// TOTP 등록 시작 - 시크릿 생성 → 암호화 저장 → QR코드/백업코드 발급(백업코드 평문은 이 응답에서 딱 한 번만 보여준다)
// 대표자 2FA 등록 상태 조회 - 시크릿 자체는 절대 내려주지 않고 "등록 여부/연락처 등록 여부"만 알려준다.
// (원가 화면에서 "설정 안 됨 → 최초 설정 유도" vs "설정됨 → 코드 입력 모달"을 프론트가 분기하기 위해 필요)
app.get('/api/admin/owner/2fa/status', authenticate, async (req, res) => {
  try {
    const { data: profile, error } = await supabase.from('profiles').select('id, is_owner').eq('id', req.user.id).single();
    if (error || !profile || !profile.is_owner) {
      return res.status(403).json({ error: 'Forbidden', message: '대표자 계정만 조회할 수 있습니다', timestamp: new Date().toISOString() });
    }
    const { data: security } = await supabase.from('owner_security_with').select('totp_enabled, phone, otp_email, preferred_method, backup_codes_hashed, backup_codes_used_count').eq('profile_id', profile.id).maybeSingle();
    res.json({
      success: true,
      data: {
        totp_enabled: !!(security && security.totp_enabled),
        has_phone: !!(security && security.phone),
        has_otp_email: !!(security && security.otp_email),
        preferred_method: (security && security.preferred_method) || null,
        backup_codes_remaining: security && Array.isArray(security.backup_codes_hashed) ? security.backup_codes_hashed.length : 0,
        backup_codes_used_count: (security && security.backup_codes_used_count) || 0
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('대표자 2FA 상태 조회 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/owner/2fa/setup/totp', authenticate, async (req, res) => {
  const ip = getClientIp(req);
  try {
    const { data: profile, error } = await supabase.from('profiles').select('id, is_owner, email').eq('id', req.user.id).single();
    if (error || !profile || !profile.is_owner) {
      await logCostAudit({ profileId: req.user.id, action: 'totp_setup_denied', ip });
      return res.status(403).json({ error: 'Forbidden', message: '대표자 계정만 설정할 수 있습니다', timestamp: new Date().toISOString() });
    }

    const secret = authenticator.generateSecret();
    const otpauthUrl = authenticator.keyuri(profile.email || req.user.email || profile.id, 'WITH+ 대표자', secret);
    const qrDataUrl = await QRCode.toDataURL(otpauthUrl);

    const backupCodesPlain = Array.from({ length: 10 }, () => crypto.randomBytes(5).toString('hex').toUpperCase());
    const backupCodesHashed = await Promise.all(backupCodesPlain.map(c => bcrypt.hash(c, 10)));

    const { error: upsertErr } = await supabase.from('owner_security_with').upsert([{
      profile_id: profile.id,
      totp_secret_encrypted: encryptOwnerSecret(secret),
      totp_enabled: false,
      backup_codes_hashed: backupCodesHashed,
      backup_codes_used_count: 0,
      updated_at: new Date().toISOString()
    }], { onConflict: 'profile_id' });
    if (upsertErr) throw upsertErr;

    await logCostAudit({ profileId: profile.id, action: 'totp_setup_initiated', ip });

    res.json({
      success: true,
      data: { qr_code_data_url: qrDataUrl, otpauth_url: otpauthUrl, backup_codes: backupCodesPlain },
      message: '백업 코드는 이 응답에서 한 번만 표시됩니다. 반드시 안전한 곳에 저장한 뒤, 인증 앱에 QR코드를 등록하고 확인 코드를 입력해 활성화를 완료해주세요.',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('TOTP 설정 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
});

// TOTP 등록 확정 - 최초 6자리 코드가 실제로 맞아야(=인증 앱에 정상 등록됐음을 증명해야) 활성화된다
app.post('/api/admin/owner/2fa/confirm-totp', authenticate, async (req, res) => {
  const ip = getClientIp(req);
  try {
    const { data: profile, error } = await supabase.from('profiles').select('id, is_owner').eq('id', req.user.id).single();
    if (error || !profile || !profile.is_owner) {
      return res.status(403).json({ error: 'Forbidden', message: '대표자 계정만 설정할 수 있습니다', timestamp: new Date().toISOString() });
    }
    const { code } = req.body || {};
    const { data: security, error: secErr } = await supabase.from('owner_security_with').select('totp_secret_encrypted').eq('profile_id', profile.id).maybeSingle();
    if (secErr || !security || !security.totp_secret_encrypted) {
      return res.status(400).json({ error: 'Bad Request', message: '먼저 TOTP 설정을 시작해주세요', timestamp: new Date().toISOString() });
    }
    let secret;
    try {
      secret = decryptOwnerSecret(security.totp_secret_encrypted);
    } catch (e) {
      return res.status(500).json({ error: 'Internal Server Error', message: '저장된 TOTP 시크릿을 복호화할 수 없습니다', timestamp: new Date().toISOString() });
    }
    const valid = code && verifyTotpCode(code, secret);
    if (!valid) {
      await logCostAudit({ profileId: profile.id, action: 'totp_confirm_failed', ip });
      return res.status(400).json({ error: 'Bad Request', message: '인증코드가 올바르지 않습니다', timestamp: new Date().toISOString() });
    }
    await supabase.from('owner_security_with').update({ totp_enabled: true, updated_at: new Date().toISOString() }).eq('profile_id', profile.id);
    await logCostAudit({ profileId: profile.id, action: 'totp_enabled', ip });
    res.json({ success: true, message: 'TOTP 2단계 인증이 활성화되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('TOTP 확인 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 대표자 연락처(SMS/이메일 인증용) 및 선호 인증방식 등록
app.post('/api/admin/owner/2fa/setup/contact', authenticate, async (req, res) => {
  try {
    const { data: profile, error } = await supabase.from('profiles').select('id, is_owner').eq('id', req.user.id).single();
    if (error || !profile || !profile.is_owner) {
      return res.status(403).json({ error: 'Forbidden', message: '대표자 계정만 설정할 수 있습니다', timestamp: new Date().toISOString() });
    }
    const { phone, otp_email, preferred_method } = req.body || {};
    if (preferred_method && !['totp', 'sms', 'email'].includes(preferred_method)) {
      return res.status(400).json({ error: 'Bad Request', message: 'preferred_method는 totp/sms/email 중 하나여야 합니다', timestamp: new Date().toISOString() });
    }
    const patch = { profile_id: profile.id, updated_at: new Date().toISOString() };
    if (phone !== undefined) patch.phone = phone ? String(phone).trim() : null;
    if (otp_email !== undefined) patch.otp_email = otp_email ? String(otp_email).trim() : null;
    if (preferred_method !== undefined) patch.preferred_method = preferred_method || null;
    const { error: upsertErr } = await supabase.from('owner_security_with').upsert([patch], { onConflict: 'profile_id' });
    if (upsertErr) throw upsertErr;
    res.json({ success: true, message: '연락처 정보가 저장되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('대표자 연락처 설정 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
});

// SMS/이메일 1회용 인증코드 발송 요청
app.post('/api/admin/owner/2fa/request-otp', authenticate, async (req, res) => {
  const ip = getClientIp(req);
  try {
    const { data: profile, error } = await supabase.from('profiles').select('id, is_owner, email').eq('id', req.user.id).single();
    if (error || !profile || !profile.is_owner) {
      return res.status(403).json({ error: 'Forbidden', message: '대표자 계정만 사용할 수 있습니다', timestamp: new Date().toISOString() });
    }
    const { method } = req.body || {};
    if (!['sms', 'email'].includes(method)) {
      return res.status(400).json({ error: 'Bad Request', message: 'method는 sms 또는 email이어야 합니다', timestamp: new Date().toISOString() });
    }
    const { data: security } = await supabase.from('owner_security_with').select('phone, otp_email').eq('profile_id', profile.id).maybeSingle();

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const codeHash = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    if (method === 'email') {
      const to = (security && security.otp_email) || profile.email || req.user.email;
      const html = `<p>대표자 원가 열람 인증코드: <b>${code}</b></p><p>5분간 유효합니다. 본인이 요청하지 않았다면 즉시 비밀번호를 변경해주세요.</p>`;
      const result = await sendEmail({ to, subject: '[WITH+] 대표자 원가 열람 인증코드', html, template: 'owner_cost_otp' });
      if (!result.sent) {
        await logCostAudit({ profileId: profile.id, action: 'otp_request_failed', detail: { method, reason: result.reason }, ip });
        return res.status(501).json({ error: 'Not Implemented', message: '이메일 발송 설정이 안 되어 있습니다 (관리자 설정에서 SMTP 정보를 먼저 등록해주세요)', timestamp: new Date().toISOString() });
      }
    } else {
      const phone = security && security.phone;
      if (!phone) {
        return res.status(400).json({ error: 'Bad Request', message: '먼저 대표자 연락처(휴대폰 번호)를 등록해주세요', timestamp: new Date().toISOString() });
      }
      try {
        await sendSms(phone, code);
      } catch (smsErr) {
        await logCostAudit({ profileId: profile.id, action: 'otp_request_failed', detail: { method, reason: smsErr.message }, ip });
        return res.status(501).json({ error: 'Not Implemented', message: 'SMS 발송이 아직 설정/구현되지 않았습니다: ' + smsErr.message, timestamp: new Date().toISOString() });
      }
    }

    await supabase.from('owner_otp_codes_with').insert([{ profile_id: profile.id, method, code_hash: codeHash, expires_at: expiresAt }]);
    await logCostAudit({ profileId: profile.id, action: 'otp_requested', detail: { method }, ip });

    res.json({ success: true, message: `${method === 'email' ? '이메일' : 'SMS'}로 인증코드를 발송했습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('OTP 요청 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
});

// method(totp/sms/email) 또는 backupCode 중 하나로 대표자 본인임을 증명하는 공용 검증 로직.
// verify-2fa / verify-otp 두 엔드포인트가 이 함수를 공유한다(요구사항: "동일 응답 형식으로 통합해도 됨").
async function verifyOwnerFactor({ profileId, method, code, backupCode }) {
  const { data: security } = await supabase.from('owner_security_with').select('*').eq('profile_id', profileId).maybeSingle();

  if (backupCode) {
    if (!security || !Array.isArray(security.backup_codes_hashed) || security.backup_codes_hashed.length === 0) {
      return { ok: false, reason: 'no_backup_codes' };
    }
    const trimmed = String(backupCode).trim();
    for (let i = 0; i < security.backup_codes_hashed.length; i++) {
      // eslint-disable-next-line no-await-in-loop
      const matched = await bcrypt.compare(trimmed, security.backup_codes_hashed[i]);
      if (matched) {
        const remaining = security.backup_codes_hashed.slice(0, i).concat(security.backup_codes_hashed.slice(i + 1));
        await supabase.from('owner_security_with').update({
          backup_codes_hashed: remaining,
          backup_codes_used_count: (security.backup_codes_used_count || 0) + 1,
          updated_at: new Date().toISOString()
        }).eq('profile_id', profileId);
        return { ok: true, via: 'backup_code' };
      }
    }
    return { ok: false, reason: 'backup_code_mismatch' };
  }

  if (method === 'totp') {
    if (!security || !security.totp_enabled || !security.totp_secret_encrypted) {
      return { ok: false, reason: 'totp_not_enabled' };
    }
    if (!code) return { ok: false, reason: 'code_required' };
    let secret;
    try {
      secret = decryptOwnerSecret(security.totp_secret_encrypted);
    } catch (e) {
      return { ok: false, reason: 'decrypt_failed' };
    }
    return verifyTotpCode(code, secret) ? { ok: true, via: 'totp' } : { ok: false, reason: 'totp_mismatch' };
  }

  if (method === 'sms' || method === 'email') {
    if (!code) return { ok: false, reason: 'code_required' };
    const { data: otpRow } = await supabase
      .from('owner_otp_codes_with')
      .select('*')
      .eq('profile_id', profileId)
      .eq('method', method)
      .is('consumed_at', null)
      .gte('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (!otpRow) return { ok: false, reason: 'no_pending_code' };
    if (otpRow.attempt_count >= 5) return { ok: false, reason: 'too_many_attempts' };
    const match = await bcrypt.compare(String(code).trim(), otpRow.code_hash);
    if (!match) {
      await supabase.from('owner_otp_codes_with').update({ attempt_count: otpRow.attempt_count + 1 }).eq('id', otpRow.id);
      return { ok: false, reason: 'code_mismatch' };
    }
    await supabase.from('owner_otp_codes_with').update({ consumed_at: new Date().toISOString() }).eq('id', otpRow.id);
    return { ok: true, via: method };
  }

  return { ok: false, reason: 'unknown_method' };
}

async function handleOwnerStepUpVerify(req, res) {
  const ip = getClientIp(req);
  try {
    const { data: profile, error } = await supabase.from('profiles').select('id, role, is_owner, email').eq('id', req.user.id).single();
    if (error || !profile) {
      return res.status(403).json({ error: 'Forbidden', message: '프로필을 확인할 수 없습니다', timestamp: new Date().toISOString() });
    }
    if (!profile.is_owner) {
      await logCostAudit({ profileId: profile.id, action: 'step_up_verify_failed', detail: { reason: 'not_owner' }, ip });
      return res.status(403).json({ error: 'Forbidden', message: '대표자 계정만 사용할 수 있습니다', timestamp: new Date().toISOString() });
    }
    const { method, code, backupCode } = req.body || {};
    if (!['totp', 'sms', 'email'].includes(method)) {
      return res.status(400).json({ error: 'Bad Request', message: 'method는 totp/sms/email 중 하나여야 합니다', timestamp: new Date().toISOString() });
    }
    const result = await verifyOwnerFactor({ profileId: profile.id, method, code, backupCode });
    if (!result.ok) {
      await logCostAudit({ profileId: profile.id, action: 'step_up_verify_failed', detail: { method, reason: result.reason }, ip });
      return res.status(400).json({ error: 'Bad Request', message: '인증에 실패했습니다', reason: result.reason, timestamp: new Date().toISOString() });
    }
    const token = signCostStepUpToken(profile.id);
    await logCostAudit({ profileId: profile.id, action: 'step_up_granted', detail: { method, via: result.via }, ip });
    res.json({ success: true, data: { token, expires_in: COST_STEPUP_TTL_SECONDS }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('대표자 2FA 검증 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
}
// verify-2fa(TOTP/백업코드 중심)와 verify-otp(SMS/이메일 코드 검증)는 내부 로직이 동일하므로 같은 핸들러를 공유한다.
app.post('/api/admin/owner/verify-2fa', authenticate, handleOwnerStepUpVerify);
app.post('/api/admin/owner/2fa/verify-otp', authenticate, handleOwnerStepUpVerify);

// 🔐 병합된 2FA 경로 (대표자 요청사항) - "내 계정 2단계 인증"(설정 탭, Supabase Auth MFA/TOTP)을 이미
// 등록해두었다면, 대표자 전용 owner_security_with TOTP를 따로 또 등록하지 않아도(인증 앱에 코드를 두 번
// 등록하는 번거로움 없이) 그 계정 MFA만으로 대표자 스텝업 토큰을 받을 수 있게 한다. 방법:
//   1) 호출자가 방금 client.auth.mfa.challengeAndVerify()로 aal2 세션을 새로 받았다는 것을,
//      그 세션의 access_token(Authorization 헤더로 전달됨)의 aal/amr 클레임으로 직접 확인한다
//      (jsonwebtoken 같은 별도 JWT 라이브러리를 쓰지 않는다는 파일 상단 방침과 동일하게 Buffer로 페이로드만
//      디코딩 - authenticate가 이미 서명을 Supabase 서버에 검증받았으므로 추가 서명 검증은 필요 없다).
//   2) amr 배열에서 method가 'totp' 또는 'mfa/totp'인 가장 최근 항목의 timestamp가 180초 이내여야 한다
//      (오래된 aal2 세션을 재사용해 방금 인증한 것처럼 위장하는 것을 막기 위함).
//   3) 이 계정이 실제 대표자(role==='super_admin' && is_owner===true)여야 한다.
// 세 조건을 모두 만족하면 handleOwnerStepUpVerify와 동일하게 signCostStepUpToken()으로 같은 종류의
// 스텝업 토큰을 발급한다 - 발급 로직 자체를 중복 구현하지 않고 그대로 재사용한다.
// SMS/이메일/백업코드 스텝업은 이 병합과 무관하게 기존 verify-2fa/verify-otp(→ verifyOwnerFactor,
// owner_security_with 기반) 경로를 그대로 사용한다 - Supabase Auth MFA가 TOTP만 지원하기 때문이다.
app.post('/api/admin/owner/stepup/via-account-mfa', authenticate, async (req, res) => {
  const ip = getClientIp(req);
  try {
    const { data: profile, error } = await supabase.from('profiles').select('id, role, is_owner').eq('id', req.user.id).single();
    if (error || !profile || profile.role !== 'super_admin' || !profile.is_owner) {
      await logCostAudit({ profileId: req.user.id, action: 'step_up_verify_failed', detail: { reason: 'not_owner', method: 'account_mfa' }, ip });
      return res.status(403).json({ error: 'Forbidden', message: '대표자 계정만 사용할 수 있습니다', timestamp: new Date().toISOString() });
    }

    if (req.authAal !== 'aal2') {
      await logCostAudit({ profileId: profile.id, action: 'step_up_verify_failed', detail: { reason: 'not_aal2', method: 'account_mfa' }, ip });
      return res.status(400).json({
        error: 'Bad Request',
        message: '계정 2단계 인증(aal2) 세션이 아닙니다. 설정 탭에서 "내 계정 2단계 인증"의 인증 앱 코드를 다시 확인해주세요.',
        reason: 'not_aal2',
        timestamp: new Date().toISOString()
      });
    }

    const token = req.headers.authorization.split(' ')[1];
    const amr = decodeJwtAmr(token);
    const nowSec = Math.floor(Date.now() / 1000);
    const recentTotpEntry = amr
      .filter(e => e && (e.method === 'totp' || e.method === 'mfa/totp') && typeof e.timestamp === 'number')
      .sort((a, b) => b.timestamp - a.timestamp)[0];
    if (!recentTotpEntry || (nowSec - recentTotpEntry.timestamp) > 180) {
      await logCostAudit({ profileId: profile.id, action: 'step_up_verify_failed', detail: { reason: 'stale_or_missing_totp_amr', method: 'account_mfa' }, ip });
      return res.status(400).json({
        error: 'Bad Request',
        message: '방금 완료한 인증 앱(TOTP) 인증이 필요합니다. 설정 탭에서 2단계 인증 코드를 다시 입력한 뒤 재시도해주세요.',
        reason: 'fresh_totp_required',
        timestamp: new Date().toISOString()
      });
    }

    const stepupToken = signCostStepUpToken(profile.id);
    await logCostAudit({ profileId: profile.id, action: 'step_up_granted', detail: { method: 'totp', via: 'account_mfa' }, ip });
    res.json({ success: true, data: { token: stepupToken, expires_in: COST_STEPUP_TTL_SECONDS }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('계정 MFA 기반 대표자 스텝업 발급 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 👑 대표자(is_owner) 지정 - 관리자 화면에서 완결되는 "최초 부트스트랩 + 이후 추가/해제" 흐름
// ------------------------------------------------------------
// is_owner를 처음 true로 지정하는 절차가 지금까지 관리자 화면에 전혀 없어서(원가/마진율/자동이체를
// "대표자만" 볼 수 있게 만들어놔도 정작 그 대표자를 지정할 방법이 없었다), Supabase에 직접 SQL을 날려야
// 했다. 이를 관리자 화면 안에서 끝낼 수 있게 하되, "super_admin이면 아무나 버튼 하나로 자기 자신을 대표자로
// 지정"할 수 있게 만들면 원가 보호 모델 자체가 무의미해지므로(직원 계정이 super_admin 권한만 있으면 스스로
// 대표자가 되어 원가를 볼 수 있게 됨), 최초 지정과 그 이후 지정을 다르게 보호한다:
//   - 최초 지정(부트스트랩): 대표자가 0명일 때만, 서버 관리자(Render 환경변수 접근 권한자 = 실제 대표자
//     본인)만 아는 OWNER_SETUP_CODE를 입력해야 한다. "관리자 화면 접근 권한"이 아니라 "서버 인프라 접근
//     권한"을 가진 사람만 통제할 수 있는 유일한 통로다. 요청을 보낸 본인 계정에만 적용된다(다른 사람을
//     대신 지정할 수 없다).
//   - 이후 추가/해제: 이미 대표자가 있는 상태에서는 반드시 "현재 대표자"가 자기 2FA로 스텝업 인증을 통과한
//     상태에서만(requireOwnerStepUp, 원가 조회와 동일한 미들웨어) 가능하다.
// ============================================

// 🔒 대표자 부트스트랩 설정코드 - 위의 다른 시크릿들(JWT_SECRET/OWNER_SECURITY_KEY 등)과 달리 런타임 임의값
// 폴백을 절대 두지 않는다. 폴백을 두면 "서버를 재시작할 수 있는 사람"이 곧 "대표자를 자칭할 수 있는 사람"이
// 되어버려서 부트스트랩을 보호하는 의미가 없어지기 때문이다. 미설정이면 부트스트랩 자체를 항상 거부한다.
if (!process.env.OWNER_SETUP_CODE) {
  console.error('[SECURITY WARNING] OWNER_SETUP_CODE 환경변수가 설정되지 않았습니다. 대표자가 아직 한 명도 지정되지 않은 상태라면, 이 값을 설정하기 전까지는 관리자 화면에서 대표자 최초 지정(부트스트랩)을 진행할 수 없습니다. Render 환경변수에 OWNER_SETUP_CODE를 설정해주세요(임의 폴백 없음 - 반드시 명시적으로 설정해야 합니다).');
}

// 상수 시간 문자열 비교 - verifyCostStepUpToken의 서명 비교(crypto.timingSafeEqual)와 동일한 패턴.
// 길이가 다르면 그 자체로 이미 불일치이므로 그대로 false를 반환한다(기존 서명 비교 코드와 동일한 수준의 보호).
function timingSafeEqualString(a, b) {
  const aBuf = Buffer.from(String(a === undefined || a === null ? '' : a), 'utf8');
  const bBuf = Buffer.from(String(b === undefined || b === null ? '' : b), 'utf8');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function maskOwnerEmail(email) {
  if (!email || typeof email !== 'string' || !email.includes('@')) return null;
  const [local, domain] = email.split('@');
  const visible = local.slice(0, Math.min(2, local.length));
  return `${visible}${'*'.repeat(Math.max(1, local.length - visible.length))}@${domain}`;
}

// 지금 대표자가 존재하는지 + (있다면) 마스킹된 이메일만 알려준다. super_admin이면 항상 접근 가능해야
// 부트스트랩 화면 자체에 처음 진입할 수 있으므로(닭과 달걀 문제) requireOwnerStepUp이 아니라
// requireRole(['super_admin'])만 건다.
app.get('/api/admin/owner/bootstrap-status', authenticate, requireRole(['super_admin']), async (req, res) => {
  try {
    const { data: owners, error } = await supabase
      .from('profiles')
      .select('email, owner_granted_at')
      .eq('is_owner', true)
      .order('owner_granted_at', { ascending: true });
    if (error) throw error;
    const exists = Array.isArray(owners) && owners.length > 0;
    res.json({
      success: true,
      data: {
        owner_exists: exists,
        owner_count: exists ? owners.length : 0,
        first_owner_email_masked: exists ? maskOwnerEmail(owners[0].email) : null,
        setup_code_configured: !!process.env.OWNER_SETUP_CODE
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('대표자 부트스트랩 상태 조회 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 대표자 목록 - "지금 누가 대표자인지"는 원가처럼 숫자가 새는 정보가 아니므로 admin/super_admin이면
// 스텝업 없이 볼 수 있게 한다.
app.get('/api/admin/owner/list', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: owners, error } = await supabase
      .from('profiles')
      .select('id, email, full_name, owner_granted_at')
      .eq('is_owner', true)
      .order('owner_granted_at', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: owners || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('대표자 목록 조회 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 최초 대표자 부트스트랩 - 대표자가 단 한 명도 없을 때만 통과한다. requireOwnerStepUp을 걸지 않는다(아직
// 대표자가 없으니 애초에 스텝업 토큰을 발급받을 방법이 없다 - handleOwnerStepUpVerify도 profile.is_owner를
// 요구한다). 대신 requireRole(['super_admin'])로 "관리자 화면에 super_admin으로 로그인은 되어 있는 사람"까지만
// 걸러내고, 그 위에 OWNER_SETUP_CODE 검증을 추가로 요구한다.
app.post('/api/admin/owner/bootstrap-claim', authenticate, requireRole(['super_admin']), async (req, res) => {
  const ip = getClientIp(req);
  try {
    const { setup_code } = req.body || {};
    // logAdminAction이 res.on('finish') 시점에 req.body를 그대로 감사로그에 스냅샷하므로(admin_audit_logs_with),
    // 여기서 값을 사용한 직후 즉시 지워서 설정코드 원문이 평문으로 로그에 남지 않게 한다(성공/실패 무관).
    const submittedCode = setup_code;
    if (req.body) req.body.setup_code = '[REDACTED]';

    if (!process.env.OWNER_SETUP_CODE) {
      await logCostAudit({ profileId: req.user.id, action: 'owner_bootstrap_denied', detail: { reason: 'setup_code_not_configured' }, ip });
      return res.status(503).json({
        error: 'Service Unavailable',
        message: '서버에 OWNER_SETUP_CODE가 설정되어 있지 않아 대표자 지정을 진행할 수 없습니다. Render 환경변수 설정이 먼저 필요합니다.',
        timestamp: new Date().toISOString()
      });
    }
    if (!submittedCode || !timingSafeEqualString(submittedCode, process.env.OWNER_SETUP_CODE)) {
      await logCostAudit({ profileId: req.user.id, action: 'owner_bootstrap_denied', detail: { reason: 'code_mismatch' }, ip });
      return res.status(403).json({ error: 'Forbidden', message: '설정코드가 올바르지 않습니다', timestamp: new Date().toISOString() });
    }
    // 레이스 컨디션 방지: 코드 검증을 통과한 뒤 "현재 대표자가 0명"인지 서버에서 다시 한번 확인한다
    // (동시에 여러 super_admin이 부트스트랩을 시도할 가능성을 막는다).
    const { count, error: countErr } = await supabase
      .from('profiles')
      .select('id', { count: 'exact', head: true })
      .eq('is_owner', true);
    if (countErr) throw countErr;
    if (count && count > 0) {
      await logCostAudit({ profileId: req.user.id, action: 'owner_bootstrap_denied', detail: { reason: 'owner_already_exists' }, ip });
      return res.status(409).json({
        error: 'Conflict',
        message: '이미 대표자가 지정되어 있어 부트스트랩을 사용할 수 없습니다. 대표자 추가는 "대표자 관리" 화면에서 기존 대표자의 2단계 인증을 통해 진행해주세요.',
        timestamp: new Date().toISOString()
      });
    }
    // 반드시 요청을 보낸 본인 계정(req.user.id)에만 적용한다 - 다른 사람 계정을 지정하는 게 아니라
    // "그 코드를 아는 사람이 로그인해서 직접 클레임한다"는 안전한 구조를 유지하기 위함이다.
    const { error: updateErr } = await supabase
      .from('profiles')
      .update({ is_owner: true, owner_granted_at: new Date().toISOString() })
      .eq('id', req.user.id);
    if (updateErr) throw updateErr;
    await logCostAudit({ profileId: req.user.id, action: 'owner_bootstrap_claimed', detail: {}, ip });
    res.json({ success: true, message: '대표자로 지정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('대표자 부트스트랩 클레임 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 대표자 추가(공동대표 등) - 반드시 기존 대표자의 2FA 스텝업을 통과해야 한다.
app.post('/api/admin/owner/grant', authenticate, requireOwnerStepUp, async (req, res) => {
  const ip = getClientIp(req);
  try {
    const { email } = req.body || {};
    if (!email || typeof email !== 'string' || !email.trim()) {
      return res.status(400).json({ error: 'Bad Request', message: '이메일을 입력해주세요', timestamp: new Date().toISOString() });
    }
    const { data: target, error: findErr } = await supabase
      .from('profiles')
      .select('id, email, role, is_owner')
      .eq('email', email.trim())
      .maybeSingle();
    if (findErr) throw findErr;
    if (!target) {
      return res.status(404).json({ error: 'Not Found', message: '해당 이메일로 가입된 회원을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    if (target.is_owner) {
      return res.status(400).json({ error: 'Bad Request', message: '이미 대표자로 지정된 계정입니다', timestamp: new Date().toISOString() });
    }
    // requireOwnerStepUp 자체가 "role === super_admin && is_owner === true"만 owner 기능을 쓸 수 있게 하므로,
    // super_admin이 아닌 계정을 대표자로 지정하면 스텝업 토큰을 발급받아도 실제로는 어떤 owner 라우트도 통과할
    // 수 없는 "이름뿐인 대표자"가 되어버린다. super_admin 승격은 이 관리자 화면에서 다루지 않는 영역이므로
    // (/api/admin/members/:id/role 의 ALLOWED_ROLES에 super_admin이 없는 것과 동일한 이유 - "최고관리자 변경은
    // DB에서 직접"), 대표자 지정도 "이미 super_admin인 계정"만 대상으로 한다.
    if (target.role !== 'super_admin') {
      return res.status(400).json({
        error: 'Bad Request',
        message: '대표자로 지정하려면 해당 계정이 먼저 super_admin 권한을 가지고 있어야 합니다. super_admin 승격은 관리자 화면에서 지원하지 않으며 DB에서 직접 처리해야 합니다.',
        timestamp: new Date().toISOString()
      });
    }
    const { error: updateErr } = await supabase
      .from('profiles')
      .update({ is_owner: true, owner_granted_at: new Date().toISOString() })
      .eq('id', target.id);
    if (updateErr) throw updateErr;
    await logCostAudit({ profileId: req.user.id, action: 'owner_granted', detail: { target_id: target.id, target_email: target.email }, ip });
    res.json({ success: true, message: `${target.email} 계정이 대표자로 지정되었습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('대표자 추가 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 대표자 해제 - 반드시 기존 대표자의 2FA 스텝업을 통과해야 하고, 마지막 남은 대표자는 해제할 수 없다
// (0명이 되면 OWNER_SETUP_CODE 부트스트랩은 "최초 1회"만 허용되는 절차라 이 경로로는 다시 복구할 수 없어
// 시스템이 잠긴다).
app.post('/api/admin/owner/revoke', authenticate, requireOwnerStepUp, async (req, res) => {
  const ip = getClientIp(req);
  try {
    const { userId } = req.body || {};
    if (!userId) {
      return res.status(400).json({ error: 'Bad Request', message: 'userId를 입력해주세요', timestamp: new Date().toISOString() });
    }
    const { data: target, error: findErr } = await supabase
      .from('profiles')
      .select('id, email, is_owner')
      .eq('id', userId)
      .maybeSingle();
    if (findErr) throw findErr;
    if (!target || !target.is_owner) {
      return res.status(404).json({ error: 'Not Found', message: '대표자로 지정된 해당 계정을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    const { count, error: countErr } = await supabase
      .from('profiles')
      .select('id', { count: 'exact', head: true })
      .eq('is_owner', true);
    if (countErr) throw countErr;
    if ((count || 0) <= 1) {
      return res.status(400).json({
        error: 'Bad Request',
        message: '마지막 남은 대표자는 해제할 수 없습니다. 먼저 다른 계정을 대표자로 추가한 뒤 해제해주세요.',
        timestamp: new Date().toISOString()
      });
    }
    const { error: updateErr } = await supabase
      .from('profiles')
      .update({ is_owner: false, owner_granted_at: null })
      .eq('id', target.id);
    if (updateErr) throw updateErr;
    await logCostAudit({ profileId: req.user.id, action: 'owner_revoked', detail: { target_id: target.id, target_email: target.email }, ip });
    res.json({ success: true, message: `${target.email} 계정의 대표자 지정이 해제되었습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('대표자 해제 오류:', err);
    res.status(500).json({ error: 'Internal Server Error', message: err.message, timestamp: new Date().toISOString() });
  }
});


// 현재 로그인한 사용자의 프로필/권한 정보 (관리자 페이지 접근 가능 여부 확인용)
app.get('/api/me', authenticate, async (req, res) => {
  try {
    const { data: profile, error } = await supabase
      .from('profiles')
      .select('id, email, full_name, role, is_owner')
      .eq('id', req.user.id)
      .single();

    if (error || !profile) {
      return res.json({
        success: true,
        data: { id: req.user.id, email: req.user.email, role: 'member' },
        timestamp: new Date().toISOString()
      });
    }

    res.json({ success: true, data: profile, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 회원 배송지 관리 (마이페이지 배송지록 + 장바구니 자동 불러오기용)
// 여러 개 저장 가능, 그중 하나를 기본 배송지(is_default)로 지정
// ============================================
function validateAddressInput(body) {
  const { receiver_name, receiver_phone, address } = body;
  if (!receiver_name || !String(receiver_name).trim()) return '받는 분 성함을 입력해주세요';
  if (!receiver_phone || !String(receiver_phone).trim()) return '연락처를 입력해주세요';
  if (!address || !String(address).trim()) return '주소를 입력해주세요';
  return null;
}

app.get('/api/me/addresses', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('shipping_addresses_with')
      .select('*')
      .eq('user_id', req.user.id)
      .order('is_default', { ascending: false })
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching addresses:', err);
    res.status(500).json({ error: 'Failed to fetch addresses', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/me/addresses', authenticate, async (req, res) => {
  try {
    const validationError = validateAddressInput(req.body);
    if (validationError) {
      return res.status(400).json({ error: 'Bad Request', message: validationError, timestamp: new Date().toISOString() });
    }
    const { label, receiver_name, receiver_phone, postal_code, address, address_detail, is_default } = req.body;

    const { count } = await supabase
      .from('shipping_addresses_with')
      .select('id', { count: 'exact', head: true })
      .eq('user_id', req.user.id);
    const makeDefault = !!is_default || (count || 0) === 0; // 첫 배송지는 자동으로 기본 배송지

    if (makeDefault) {
      await supabase.from('shipping_addresses_with').update({ is_default: false }).eq('user_id', req.user.id);
    }

    const { data, error } = await supabase
      .from('shipping_addresses_with')
      .insert([{
        user_id: req.user.id,
        label: (label && String(label).trim()) || '배송지',
        receiver_name: String(receiver_name).trim(),
        receiver_phone: String(receiver_phone).trim(),
        postal_code: postal_code || null,
        address: String(address).trim(),
        address_detail: address_detail ? String(address_detail).trim() : null,
        is_default: makeDefault
      }])
      .select()
      .single();
    if (error) throw error;
    res.status(201).json({ success: true, data, message: '배송지가 등록되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating address:', err);
    res.status(500).json({ error: 'Failed to create address', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/me/addresses/:id', authenticate, async (req, res) => {
  try {
    const { data: existing } = await supabase
      .from('shipping_addresses_with')
      .select('id, user_id')
      .eq('id', req.params.id)
      .maybeSingle();
    if (!existing || existing.user_id !== req.user.id) {
      return res.status(404).json({ error: 'Not Found', message: '배송지를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }

    const { label, receiver_name, receiver_phone, postal_code, address, address_detail, is_default } = req.body;
    const updates = { updated_at: new Date().toISOString() };
    if (label !== undefined) updates.label = (label && String(label).trim()) || '배송지';
    if (receiver_name !== undefined) {
      if (!String(receiver_name).trim()) return res.status(400).json({ error: 'Bad Request', message: '받는 분 성함을 입력해주세요', timestamp: new Date().toISOString() });
      updates.receiver_name = String(receiver_name).trim();
    }
    if (receiver_phone !== undefined) {
      if (!String(receiver_phone).trim()) return res.status(400).json({ error: 'Bad Request', message: '연락처를 입력해주세요', timestamp: new Date().toISOString() });
      updates.receiver_phone = String(receiver_phone).trim();
    }
    if (postal_code !== undefined) updates.postal_code = postal_code || null;
    if (address !== undefined) {
      if (!String(address).trim()) return res.status(400).json({ error: 'Bad Request', message: '주소를 입력해주세요', timestamp: new Date().toISOString() });
      updates.address = String(address).trim();
    }
    if (address_detail !== undefined) updates.address_detail = address_detail ? String(address_detail).trim() : null;

    if (is_default === true) {
      await supabase.from('shipping_addresses_with').update({ is_default: false }).eq('user_id', req.user.id);
      updates.is_default = true;
    }

    const { data, error } = await supabase
      .from('shipping_addresses_with')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json({ success: true, data, message: '배송지가 수정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating address:', err);
    res.status(500).json({ error: 'Failed to update address', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.delete('/api/me/addresses/:id', authenticate, async (req, res) => {
  try {
    const { data: existing } = await supabase
      .from('shipping_addresses_with')
      .select('id, user_id, is_default')
      .eq('id', req.params.id)
      .maybeSingle();
    if (!existing || existing.user_id !== req.user.id) {
      return res.status(404).json({ error: 'Not Found', message: '배송지를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }

    const { error } = await supabase.from('shipping_addresses_with').delete().eq('id', req.params.id);
    if (error) throw error;

    // 기본 배송지를 삭제한 경우, 남은 배송지 중 가장 최근 것을 새 기본 배송지로 자동 승격
    if (existing.is_default) {
      const { data: rest } = await supabase
        .from('shipping_addresses_with')
        .select('id')
        .eq('user_id', req.user.id)
        .order('created_at', { ascending: false })
        .limit(1);
      if (rest && rest.length > 0) {
        await supabase.from('shipping_addresses_with').update({ is_default: true }).eq('id', rest[0].id);
      }
    }

    res.json({ success: true, message: '배송지가 삭제되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting address:', err);
    res.status(500).json({ error: 'Failed to delete address', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/me/addresses/:id/default', authenticate, async (req, res) => {
  try {
    const { data: existing } = await supabase
      .from('shipping_addresses_with')
      .select('id, user_id')
      .eq('id', req.params.id)
      .maybeSingle();
    if (!existing || existing.user_id !== req.user.id) {
      return res.status(404).json({ error: 'Not Found', message: '배송지를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }

    await supabase.from('shipping_addresses_with').update({ is_default: false }).eq('user_id', req.user.id);
    const { data, error } = await supabase
      .from('shipping_addresses_with')
      .update({ is_default: true })
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json({ success: true, data, message: '기본 배송지로 설정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error setting default address:', err);
    res.status(500).json({ error: 'Failed to set default address', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 회원탈퇴 - 개인정보보호법상 회원은 언제든 자신의 개인정보 삭제(탈퇴)를 요청할 수 있어야 한다.
// 다만 전자상거래법(전자상거래 등에서의 소비자보호에 관한 법률)상 거래기록(주문내역)은 5년간 보관
// 의무가 있으므로, 주문(orders_with)/쿠폰사용(coupon_redemptions)/마일리지(mileage_adjustments_with)
// 기록은 삭제하지 않고 user_id 연결은 유지하되, 그 외 불필요한 개인정보(이름/연락처/주소/카드정보/
// 배송지/장바구니/찜/재입고알림/알림함/게시글·댓글 작성자명)는 즉시 삭제·익명화한다.
// 탈퇴 후에는 (1) Supabase Auth 계정을 밴 처리해 재로그인을 막고, (2) 이미 발급된(아직 만료 전인)
// 액세스 토큰도 이 서버 프로세스 안에서는 즉시 거부되도록 authenticate 미들웨어의 캐시에서 제거한다.
// ============================================
app.post('/api/me/withdraw', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const { data: profile } = await supabase.from('profiles').select('id, is_active').eq('id', userId).maybeSingle();
    if (profile && profile.is_active === false) {
      return res.status(400).json({ error: 'Bad Request', message: '이미 탈퇴 처리된 계정입니다', timestamp: new Date().toISOString() });
    }

    const { reason } = req.body || {};

    // 1) 프로필 익명화 - 완전 삭제 대신 비식별화(다른 테이블의 user_id 참조 무결성을 지키면서
    //    실제 개인정보만 제거). 이메일은 관리자 화면 등에서 문자열로 다뤄지는 곳이 많아 null 대신
    //    고유한 자리표시자로 대체해 이후 어떤 화면에서도 실제 이메일이 노출되지 않게 한다.
    const placeholderEmail = `withdrawn-${userId}@withplus.local`;
    const { error: profileErr } = await supabase.from('profiles').update({
      full_name: '탈퇴한 회원',
      email: placeholderEmail,
      phone: null,
      birth_date: null,
      address: null,
      // card_token은 WITH+ 코드베이스 어디에서도 쓰지 않는 GMWOS 공유 컬럼이고 NOT NULL 제약이 걸려있어
      // (기본값이 자동 채번되는 방식으로 보임) 건드리지 않는다 - null로 지우면 제약 위반으로 탈퇴 자체가 실패한다.
      is_active: false
    }).eq('id', userId);
    if (profileErr) throw profileErr;

    // 2) 더 이상 필요 없는 개인정보성 데이터 삭제 (거래기록이 아닌 것들)
    await Promise.all([
      supabase.from('shipping_addresses_with').delete().eq('user_id', userId),
      supabase.from('cart_snapshots_with').delete().eq('user_id', userId),
      supabase.from('wishlist_with').delete().eq('user_id', userId),
      supabase.from('restock_subscriptions_with').delete().eq('user_id', userId),
      supabase.from('notifications_with').delete().eq('user_id', userId)
    ].map(p => Promise.resolve(p).catch(err => { console.error('회원탈퇴 부가데이터 정리 중 일부 실패(계속 진행):', err.message); return null; })));

    // 게시판에 남긴 글/댓글 자체는 커뮤니티 기록으로 유지하되(작성자 삭제 시 다른 회원의 답글 맥락이 깨지는 것을 방지),
    // 화면에 노출되는 작성자명 스냅샷만 익명화한다.
    await Promise.all([
      supabase.from('board_posts').update({ author_name: '탈퇴한 회원' }).eq('author_id', userId),
      supabase.from('board_comments').update({ author_name: '탈퇴한 회원' }).eq('author_id', userId)
    ].map(p => Promise.resolve(p).catch(err => { console.error('회원탈퇴 게시글 익명화 중 일부 실패(계속 진행):', err.message); return null; })));

    // 3) 탈퇴 사유 기록 (선택 입력, 운영 참고용 - 별도 테이블 없이 email_logs 성격의 감사 로그가 없으므로
    //    가장 단순하게 콘솔에 남긴다. 향후 관리자 감사로그 기능이 생기면 그쪽으로 옮길 수 있다.)
    if (reason) {
      console.log(`[회원탈퇴] user_id=${userId} 사유: ${String(reason).slice(0, 500)}`);
    }

    // 4) Supabase Auth 계정 밴 처리 - 재로그인 자체를 막는다 (탈퇴는 되돌릴 수 없는 것으로 취급)
    try {
      await supabase.auth.admin.updateUserById(userId, { ban_duration: '876000h' }); // 약 100년 = 사실상 영구
    } catch (banErr) {
      console.error('회원탈퇴 - Auth 계정 밴 처리 실패(프로필 비식별화는 완료됨):', banErr.message);
    }

    // 5) 이 서버 프로세스의 프로필 캐시에서 제거 - 이미 발급된 액세스 토큰이 만료 전이라도
    //    다음 요청부터는 authenticate 미들웨어가 DB를 다시 확인해 탈퇴 계정을 즉시 차단하게 한다.
    knownProfileUserIds.delete(userId);

    res.json({ success: true, message: '회원탈퇴가 완료되었습니다. 그동안 이용해주셔서 감사합니다.', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error processing account withdrawal:', err);
    res.status(500).json({ error: 'Failed to process withdrawal', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 상품 slug 생성 헬퍼
// products_with.slug 는 NOT NULL + UNIQUE 라서 상품 등록 시 반드시 채워줘야 함
// ============================================
function slugify(name) {
  const base = String(name || '')
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, '-') // 한글 포함 유니코드 문자/숫자 외 전부 하이픈으로
    .replace(/^-+|-+$/g, '')
    .slice(0, 60) || 'product';
  const suffix = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  return `${base}-${suffix}`;
}

// ============================================
// 플랫폼 설정 (마일리지 적립율 등, 관리자가 언제든 동적으로 변경 가능)
// ============================================
const DEFAULT_MILEAGE_RATES = { personal: 0.01, community: 0.02 };
let mileageRatesCache = null;
let mileageRatesCacheAt = 0;
const MILEAGE_RATES_CACHE_TTL_MS = 30 * 1000; // 30초 캐시 (관리자 변경이 최대 30초 내 전체 반영)

async function getMileageRates() {
  const now = Date.now();
  if (mileageRatesCache && (now - mileageRatesCacheAt) < MILEAGE_RATES_CACHE_TTL_MS) {
    return mileageRatesCache;
  }
  try {
    const { data, error } = await supabase
      .from('platform_settings')
      .select('value')
      .eq('key', 'mileage_rates')
      .single();
    if (error || !data) return mileageRatesCache || DEFAULT_MILEAGE_RATES;
    const value = data.value || {};
    const rates = {
      personal: typeof value.personal === 'number' ? value.personal : DEFAULT_MILEAGE_RATES.personal,
      community: typeof value.community === 'number' ? value.community : DEFAULT_MILEAGE_RATES.community
    };
    mileageRatesCache = rates;
    mileageRatesCacheAt = now;
    return rates;
  } catch (err) {
    console.error('Error fetching mileage rates:', err);
    return mileageRatesCache || DEFAULT_MILEAGE_RATES;
  }
}

// 특정 주문에 실제로 적용할 적립율을 계산한다.
// - 분양 조직(community)이 personal_point_rate / community_point_rate 를 직접 지정해두었으면 그 값을 우선 사용
// - 지정해두지 않았으면(null) 플랫폼 기본값(getMileageRates)을 그대로 사용
// - community_id가 없는 주문(조직 미소속 개인 구매)은 항상 플랫폼 기본 개인 적립율만 적용하고, 커뮤니티 적립율은 0
async function getEffectiveMileageRates(communityId) {
  const platformRates = await getMileageRates();
  if (!communityId) {
    return { personal: platformRates.personal, community: 0 };
  }
  const { data: community, error } = await supabase
    .from('communities')
    .select('personal_point_rate, community_point_rate')
    .eq('id', communityId)
    .maybeSingle();
  if (error || !community) {
    return { personal: platformRates.personal, community: platformRates.community };
  }
  const personal = (community.personal_point_rate !== null && community.personal_point_rate !== undefined)
    ? Number(community.personal_point_rate)
    : platformRates.personal;
  const communityRate = (community.community_point_rate !== null && community.community_point_rate !== undefined)
    ? Number(community.community_point_rate)
    : platformRates.community;
  return { personal, community: communityRate };
}

// ============================================
// 🔴 라이브 전용 구매 캐시백(적립금) - 네이버쇼핑라이브 "라이브적립금"과 동일한 컨셉.
// ============================================
// 일반 마일리지 적립(getMileageRates/getEffectiveMileageRates, 주문에 이미 박제된 personal_earned_points)은
// 절대 건드리지 않고, 완전히 별개의 보너스 레이어로 mileage_adjustments_with 원장에 추가 적립만 얹는다
// (시리얼쿠폰/출석체크 보너스와 동일한 패턴) - 그래서 이 기능이 꺼져있거나 실패해도 기존 마일리지 계산/주문
// 로직에는 아무 영향이 없다. "실제로 라이브 중 예약을 거쳐 산 것"만 인정한다(reservation_ids가 있는 주문만 -
// 단순히 채널에서 유입된 주문 전체가 아니라, 방송 중 상품을 담아 산 경우로 좁혀야 "라이브 전용"이라는 이름에 맞다).
let liveCashbackRateCache = null;
let liveCashbackRateCacheAt = 0;
const LIVE_CASHBACK_RATE_CACHE_TTL_MS = 30 * 1000;

async function getLiveCashbackRate() {
  const now = Date.now();
  if (liveCashbackRateCache !== null && (now - liveCashbackRateCacheAt) < LIVE_CASHBACK_RATE_CACHE_TTL_MS) {
    return liveCashbackRateCache;
  }
  try {
    const { data, error } = await supabase.from('platform_settings').select('value').eq('key', 'live_cashback_rate').maybeSingle();
    const rate = (!error && data && typeof data.value?.rate === 'number') ? data.value.rate : 0;
    liveCashbackRateCache = rate;
    liveCashbackRateCacheAt = now;
    return rate;
  } catch (err) {
    console.error('Error fetching live cashback rate:', err);
    return liveCashbackRateCache || 0;
  }
}

async function awardLiveCashbackBonus(userId, orderId, finalPrice) {
  const rate = await getLiveCashbackRate();
  if (!rate || rate <= 0) return;
  const bonus = Math.floor(Number(finalPrice) * rate);
  if (bonus <= 0) return;
  await creditMileageAdjustment(userId, bonus, 'live_purchase_cashback', orderId);
}

// ============================================
// 🎁 바이럴 공유쿠폰(소문내면 할인) - 카카오톡딜 "소문내면 할인"과 동일한 컨셉.
// ============================================
// 시청자가 자신만의 공유링크(share_code)를 만들어 친구에게 보내고, 그 친구가 그 링크로 들어와 같은
// 세션에서 실제로 구매를 완료하면 공유한 사람과 구매한 사람 양쪽 모두에게 할인쿠폰이 지급된다.
// - 셀프 공유(자기 링크로 자기가 구매) 방지, 한 세션당 한 사람(피추천인)은 딱 한 번만 보상 대상이 된다
//   (live_share_redemptions_live(session_id, referred_user_id) 유니크 제약으로 이중 방어).
// - 마일리지가 아니라 실제 할인쿠폰(coupons 테이블, 마케팅 캠페인과 동일한 issueCouponForBatch 재사용)을
//   지급하며, target_user_ids로 해당 회원 본인만 쓸 수 있게 제한한다. 라이브 전용 구매 캐시백과 달리
//   "다음 구매에 쓰라고 주는 것"이라 특정 세션에 묶지 않는다(방송이 끝나도 유효기간 내엔 사용 가능).
let liveShareCouponSettingsCache = null;
let liveShareCouponSettingsCacheAt = 0;
const LIVE_SHARE_COUPON_SETTINGS_CACHE_TTL_MS = 30 * 1000;
const DEFAULT_LIVE_SHARE_COUPON_SETTINGS = { discount_percent: 0, valid_days: 14 };

function normalizeLiveShareCouponSettings(value) {
  const v = value && typeof value === 'object' ? value : {};
  const pct = Number(v.discount_percent);
  const days = Number(v.valid_days);
  return {
    discount_percent: Number.isFinite(pct) ? Math.min(50, Math.max(0, pct)) : 0,
    valid_days: Number.isFinite(days) && days > 0 ? Math.floor(days) : 14
  };
}

async function getLiveShareCouponSettings() {
  const now = Date.now();
  if (liveShareCouponSettingsCache && (now - liveShareCouponSettingsCacheAt) < LIVE_SHARE_COUPON_SETTINGS_CACHE_TTL_MS) {
    return liveShareCouponSettingsCache;
  }
  try {
    const { data, error } = await supabase.from('platform_settings').select('value').eq('key', 'live_share_coupon_settings').maybeSingle();
    const settings = normalizeLiveShareCouponSettings(error || !data ? null : data.value);
    liveShareCouponSettingsCache = settings;
    liveShareCouponSettingsCacheAt = now;
    return settings;
  } catch (err) {
    console.error('Error fetching live share coupon settings:', err);
    return liveShareCouponSettingsCache || DEFAULT_LIVE_SHARE_COUPON_SETTINGS;
  }
}

function generateShareCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = 'SH';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// 이 세션에서 이 사용자의 공유코드를 가져오거나(이미 만든 적 있으면 그대로 재사용) 새로 만든다.
async function getOrCreateShareLink(sessionId, channelId, userId) {
  const { data: existing } = await supabase.from('live_share_links_live').select('share_code').eq('session_id', sessionId).eq('sharer_user_id', userId).maybeSingle();
  if (existing) return existing.share_code;
  for (let attempt = 0; attempt < 8; attempt++) {
    const code = generateShareCode();
    const { data: inserted, error } = await supabase.from('live_share_links_live')
      .insert([{ session_id: sessionId, channel_id: channelId, sharer_user_id: userId, share_code: code }])
      .select('share_code').maybeSingle();
    if (!error && inserted) return inserted.share_code;
    // 코드 중복 충돌이거나 동시요청으로 이미 만들어졌을 수 있음 - 다시 조회해서 있으면 그걸 반환
    const { data: raceCheck } = await supabase.from('live_share_links_live').select('share_code').eq('session_id', sessionId).eq('sharer_user_id', userId).maybeSingle();
    if (raceCheck) return raceCheck.share_code;
  }
  throw new Error('공유 링크 생성에 실패했습니다');
}

// 주문 완료 시 호출 - liveAttribution.share_code가 유효한 공유링크를 가리키고, 자기 자신의 링크가 아니며,
// 이 세션에서 아직 보상을 받은 적 없는 구매자라면 공유한 사람과 구매한 사람 양쪽에 할인쿠폰을 지급한다.
// 실패해도(중복/자기공유/설정꺼짐/코드무효 등) 조용히 무시하고 절대 주문 자체를 막지 않는다.
async function awardShareViralCouponIfEligible(buyerId, sessionId, orderId, shareCode) {
  if (!shareCode) return;
  const settings = await getLiveShareCouponSettings();
  if (!settings.discount_percent || settings.discount_percent <= 0) return;

  const { data: link } = await supabase.from('live_share_links_live').select('*').eq('share_code', String(shareCode).trim().toUpperCase()).maybeSingle();
  if (!link || link.session_id !== sessionId) return;
  if (link.sharer_user_id === buyerId) return; // 셀프 공유 방지

  const { data: already } = await supabase.from('live_share_redemptions_live').select('id').eq('session_id', sessionId).eq('referred_user_id', buyerId).maybeSingle();
  if (already) return; // 이 세션에서는 이미 보상 대상이 된 적 있음(다른 공유코드로든 이 코드로든)

  const { data: redemption, error: insertErr } = await supabase.from('live_share_redemptions_live').insert([{
    share_link_id: link.id, session_id: sessionId, sharer_user_id: link.sharer_user_id, referred_user_id: buyerId,
    status: 'pending', order_id: orderId
  }]).select().maybeSingle();
  if (insertErr || !redemption) return; // 유니크 제약 충돌(동시 주문 등) - 조용히 무시

  try {
    const template = {
      label: `친구 공유 할인 쿠폰 (${settings.discount_percent}%)`,
      discount_type: 'percent', discount_value: settings.discount_percent, valid_days: settings.valid_days, per_user_limit: 1
    };
    const sharerCoupon = await issueCouponForBatch([link.sharer_user_id], template, 'live_share_viral_sharer', {
      codePrefix: 'SHARE', notifyTitle: '🎁 공유 할인쿠폰 도착!',
      notifyMessage: `공유한 링크로 친구가 구매를 완료해 ${settings.discount_percent}% 할인쿠폰을 받았어요!`
    });
    const referredCoupon = await issueCouponForBatch([buyerId], template, 'live_share_viral_referred', {
      codePrefix: 'SHARE', notifyTitle: '🎁 공유 할인쿠폰 도착!',
      notifyMessage: `공유받은 링크로 구매하셔서 ${settings.discount_percent}% 할인쿠폰을 받았어요! 다음 구매 때 사용해보세요.`
    });
    await supabase.from('live_share_redemptions_live').update({
      status: 'rewarded', rewarded_at: new Date().toISOString(),
      sharer_coupon_code: sharerCoupon ? sharerCoupon.code : null,
      referred_coupon_code: referredCoupon ? referredCoupon.code : null
    }).eq('id', redemption.id);
  } catch (err) {
    console.error('바이럴 공유쿠폰 발급 오류:', err.message);
    // 실패해도 redemption 행은 'pending'으로 남는다(주문 자체는 이미 정상 완료됨 - 필요 시 수동 조치 가능)
  }
}

// 공개: 현재 공유쿠폰 할인율 조회 (누구나, 로그인 불필요 - 라이브 화면에 "공유하고 둘 다 N% 할인" 버튼 노출 여부 판단용)
app.get('/api/settings/live-share-coupon', async (req, res) => {
  try {
    const settings = await getLiveShareCouponSettings();
    res.json({ success: true, data: settings, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch live share coupon settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.patch('/api/admin/settings/live-share-coupon', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const pctNum = Number(req.body.discount_percent);
    const daysNum = req.body.valid_days !== undefined ? Number(req.body.valid_days) : 14;
    if (!Number.isFinite(pctNum) || pctNum < 0 || pctNum > 50) {
      return res.status(400).json({ error: 'Bad Request', message: '할인율은 0% ~ 50% 사이여야 합니다', timestamp: new Date().toISOString() });
    }
    if (!Number.isFinite(daysNum) || daysNum < 1 || daysNum > 365) {
      return res.status(400).json({ error: 'Bad Request', message: '유효기간은 1일 ~ 365일 사이여야 합니다', timestamp: new Date().toISOString() });
    }
    const settings = { discount_percent: pctNum, valid_days: Math.floor(daysNum) };
    const { error } = await supabase.from('platform_settings').upsert({
      key: 'live_share_coupon_settings', value: settings, updated_at: new Date().toISOString(), updated_by: req.user.id
    }, { onConflict: 'key' });
    if (error) throw error;
    liveShareCouponSettingsCache = settings;
    liveShareCouponSettingsCacheAt = Date.now();
    res.json({ success: true, data: settings, message: '공유쿠폰 설정이 변경되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating live share coupon settings:', err);
    res.status(500).json({ error: 'Failed to update live share coupon settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공개: 현재 라이브 캐시백율 조회 (누구나, 로그인 불필요 - 라이브 화면에 "구매 시 N% 추가 적립" 배지로 노출하기 위함)
app.get('/api/settings/live-cashback-rate', async (req, res) => {
  try {
    const rate = await getLiveCashbackRate();
    res.json({ success: true, data: { rate }, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch live cashback rate', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.patch('/api/admin/settings/live-cashback-rate', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const rateNum = Number(req.body.rate);
    if (!Number.isFinite(rateNum) || rateNum < 0 || rateNum > 0.5) {
      return res.status(400).json({ error: 'Bad Request', message: '적립율은 0% ~ 50% 사이여야 합니다', timestamp: new Date().toISOString() });
    }
    const { error } = await supabase.from('platform_settings').upsert({
      key: 'live_cashback_rate', value: { rate: rateNum }, updated_at: new Date().toISOString(), updated_by: req.user.id
    }, { onConflict: 'key' });
    if (error) throw error;
    liveCashbackRateCache = rateNum;
    liveCashbackRateCacheAt = Date.now();
    res.json({ success: true, data: { rate: rateNum }, message: '라이브 캐시백율이 변경되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating live cashback rate:', err);
    res.status(500).json({ error: 'Failed to update live cashback rate', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공개: 현재 마일리지 적립율 조회 (누구나, 로그인 불필요 - 상품 카드/상세페이지에 표시하기 위함)
app.get('/api/settings/mileage-rates', async (req, res) => {
  try {
    const rates = await getMileageRates();
    res.json({
      success: true,
      data: {
        personal: rates.personal,
        community: rates.community,
        personalPercent: Math.round(rates.personal * 10000) / 100,
        communityPercent: Math.round(rates.community * 10000) / 100
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch mileage rates', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 마일리지 적립율 변경
app.patch('/api/admin/settings/mileage-rates', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { personal, community } = req.body;
    const personalNum = Number(personal);
    const communityNum = Number(community);

    if (!Number.isFinite(personalNum) || !Number.isFinite(communityNum)) {
      return res.status(400).json({ error: 'Bad Request', message: 'personal, community는 숫자여야 합니다', timestamp: new Date().toISOString() });
    }
    if (personalNum < 0 || personalNum > 0.5 || communityNum < 0 || communityNum > 0.5) {
      return res.status(400).json({ error: 'Bad Request', message: '적립율은 0% ~ 50% 사이여야 합니다', timestamp: new Date().toISOString() });
    }

    const { data, error } = await supabase
      .from('platform_settings')
      .upsert({
        key: 'mileage_rates',
        value: { personal: personalNum, community: communityNum },
        updated_at: new Date().toISOString(),
        updated_by: req.user.id
      }, { onConflict: 'key' })
      .select()
      .single();
    if (error) throw error;

    mileageRatesCache = { personal: personalNum, community: communityNum };
    mileageRatesCacheAt = Date.now();

    res.json({
      success: true,
      data: { personal: personalNum, community: communityNum },
      message: '마일리지 적립율이 변경되었습니다',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error updating mileage rates:', err);
    res.status(500).json({ error: 'Failed to update mileage rates', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 배송비 정책 (관리자가 언제든 변경 가능 - platform_settings(key='shipping_policy'))
// 다른 쇼핑몰들의 일반적인 방식(기본 배송비 + 조건부 무료배송 + 제주/도서산간 추가배송비)을 참고해 구성했다.
// 도서산간 추가배송비 구간(surcharge_zones)은 "우편번호 범위 + 추가금액"으로 정의하며, 기본값은
// 제주(우편번호 63000~63644, 전국 공통으로 신뢰할 수 있는 범위)만 들어있다. 울릉도/백령도 등 그 외
// 도서산간 지역은 택배사 계약(실비)마다 금액이 다르고 우편번호가 연속 범위가 아니라 정확한 전국 목록을
// 함부로 하드코딩하지 않았다 - 관리자가 "⚙️ 설정 > 배송비 정책"에서 우편번호 범위를 직접 추가/조정할 수 있다.
// ============================================
const DEFAULT_SHIPPING_POLICY = {
  base_fee: 3000,
  free_shipping_threshold: 30000,
  surcharge_zones: [
    { label: '제주', postal_start: '63000', postal_end: '63644', fee: 3000 }
  ]
};
let shippingPolicyCache = null;
let shippingPolicyCacheAt = 0;
const SHIPPING_POLICY_CACHE_TTL_MS = 30 * 1000; // 30초 캐시 (관리자 변경이 최대 30초 내 전체 반영)

function normalizeShippingPolicy(value) {
  const v = value || {};
  const base_fee = Number.isFinite(Number(v.base_fee)) ? Math.max(0, Math.floor(Number(v.base_fee))) : DEFAULT_SHIPPING_POLICY.base_fee;
  const free_shipping_threshold = Number.isFinite(Number(v.free_shipping_threshold)) ? Math.max(0, Math.floor(Number(v.free_shipping_threshold))) : DEFAULT_SHIPPING_POLICY.free_shipping_threshold;
  const zonesSrc = Array.isArray(v.surcharge_zones) ? v.surcharge_zones : DEFAULT_SHIPPING_POLICY.surcharge_zones;
  const surcharge_zones = zonesSrc
    .filter(z => z && z.postal_start !== undefined && z.postal_end !== undefined)
    .map(z => ({
      label: String(z.label || '추가배송비 지역').trim().slice(0, 30),
      postal_start: String(z.postal_start).replace(/[^0-9]/g, '').padStart(5, '0').slice(0, 5),
      postal_end: String(z.postal_end).replace(/[^0-9]/g, '').padStart(5, '0').slice(0, 5),
      fee: Number.isFinite(Number(z.fee)) ? Math.max(0, Math.floor(Number(z.fee))) : 0
    }));
  return { base_fee, free_shipping_threshold, surcharge_zones };
}

async function getShippingPolicy() {
  const now = Date.now();
  if (shippingPolicyCache && (now - shippingPolicyCacheAt) < SHIPPING_POLICY_CACHE_TTL_MS) {
    return shippingPolicyCache;
  }
  try {
    const { data, error } = await supabase.from('platform_settings').select('value').eq('key', 'shipping_policy').single();
    const policy = normalizeShippingPolicy(error || !data ? null : data.value);
    shippingPolicyCache = policy;
    shippingPolicyCacheAt = now;
    return policy;
  } catch (err) {
    console.error('Error fetching shipping policy:', err);
    return shippingPolicyCache || DEFAULT_SHIPPING_POLICY;
  }
}

// 상품 합계금액 + 배송지 우편번호를 받아 실제 배송비를 계산한다 (서버가 최종 권한을 가짐 - 클라이언트가 보낸 배송비 값은 신뢰하지 않음)
// 도서산간 추가배송비는 무료배송 조건 충족 여부와 무관하게 항상 별도로 부과된다(대부분의 쇼핑몰과 동일한 관행).
function calcShippingFee(policy, subtotal, postalCode) {
  const base = subtotal >= policy.free_shipping_threshold ? 0 : policy.base_fee;
  let surcharge = 0, surchargeLabel = null;
  const postal = postalCode ? String(postalCode).replace(/[^0-9]/g, '').padStart(5, '0').slice(0, 5) : null;
  if (postal) {
    const zone = policy.surcharge_zones.find(z => postal >= z.postal_start && postal <= z.postal_end);
    if (zone) { surcharge = zone.fee; surchargeLabel = zone.label; }
  }
  return { fee: base + surcharge, base_fee: base, surcharge_fee: surcharge, surcharge_label: surchargeLabel };
}

// 공개: 현재 배송비 정책 조회 (누구나, 로그인 불필요 - 장바구니 화면에 실시간 배송비 표시하기 위함)
app.get('/api/settings/shipping-policy', async (req, res) => {
  try {
    const policy = await getShippingPolicy();
    res.json({ success: true, data: policy, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch shipping policy', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 배송비 정책 변경
app.patch('/api/admin/settings/shipping-policy', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const policy = normalizeShippingPolicy(req.body);
    if (policy.surcharge_zones.some(z => z.postal_start > z.postal_end)) {
      return res.status(400).json({ error: 'Bad Request', message: '우편번호 시작값은 끝값보다 작거나 같아야 합니다', timestamp: new Date().toISOString() });
    }
    const { error } = await supabase.from('platform_settings').upsert({
      key: 'shipping_policy',
      value: policy,
      updated_at: new Date().toISOString(),
      updated_by: req.user.id
    }, { onConflict: 'key' });
    if (error) throw error;

    shippingPolicyCache = policy;
    shippingPolicyCacheAt = Date.now();

    res.json({ success: true, data: policy, message: '배송비 정책이 저장되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating shipping policy:', err);
    res.status(500).json({ error: 'Failed to update shipping policy', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 택배사 목록 + 운송장 조회 URL 자동 생성
// 이전에는 관리자가 택배사명을 자유 텍스트로 입력해 오타가 나거나(예: "CJ대한통운" vs "cj대한통운") 조회 링크를
// 전혀 제공하지 못했다. 이제 표준 택배사 목록에서 고르면(목록에 없으면 "기타"로 직접 입력 가능) 서버가
// 운송장번호와 조합해 조회 링크를 자동 생성해 회원(마이페이지)과 관리자 화면에 모두 보여준다.
// ============================================
const COURIERS = [
  { name: 'CJ대한통운', trackingUrl: n => `https://trace.cjlogistics.com/next/tracking.html?wblNo=${n}` },
  { name: '우체국택배', trackingUrl: n => `https://service.epost.go.kr/trace.RetrieveDomRigiTraceList.comm?sid1=${n}` },
  { name: '한진택배', trackingUrl: n => `https://www.hanjin.com/kor/CMS/DeliveryMgr/WaybillResult.do?mCode=MN038&wblnumText2=${n}` },
  { name: '롯데택배', trackingUrl: n => `https://www.lotteglogis.com/open/tracking?InvNo=${n}` },
  { name: '로젠택배', trackingUrl: n => `https://www.ilogen.com/web/personal/trace/${n}` },
  { name: '대신택배', trackingUrl: n => `https://www.ds3211.co.kr/freight/internalFreightSearch.ht?billno=${n}` },
  { name: '경동택배', trackingUrl: n => `https://kdexp.com/newDeliverySearch.kd?barcode=${n}` },
  { name: 'GS Postbox 택배', trackingUrl: n => `https://www.cvsnet.co.kr/invoice/tracking.do?invoice_no=${n}` },
  { name: 'CU 편의점택배', trackingUrl: n => `https://www.cupost.co.kr/postbox/delivery/localResult.cupost?invoice_no=${n}` },
  { name: '일양로지스', trackingUrl: n => `https://www.ilyanglogis.com/functionality/popup_result.asp?hawb_no=${n}` },
  { name: '기타', trackingUrl: null }
];
function buildTrackingUrl(courierName, trackingNumber) {
  if (!courierName || !trackingNumber) return null;
  const courier = COURIERS.find(c => c.name === courierName);
  if (!courier || !courier.trackingUrl) return null;
  return courier.trackingUrl(encodeURIComponent(String(trackingNumber).trim()));
}

// 공개: 택배사 목록 (관리자 화면 드롭다운용)
app.get('/api/couriers', (req, res) => {
  res.json({ success: true, data: COURIERS.map(c => c.name), timestamp: new Date().toISOString() });
});

// ============================================
// 디자인 부품 갤러리 (카페24 "모듈리스트"를 참고해, 화면 구성요소별로 여러 디자인 템플릿 중 하나를
// 관리자가 골라 끼울 수 있게 하는 기능). 플랫폼 전체에 적용되는 단일 설정이며(조직별 랜딩페이지
// 템플릿과는 별개), platform_settings(key='page_design_templates')에 저장되어 언제든 변경 가능하다.
// ============================================
const PAGE_TEMPLATE_COMPONENTS = {
  product_list: {
    label: '상품목록',
    options: [
      { value: 'grid', label: '그리드형', desc: '카드형 상품을 격자로 배치 (기본)' },
      { value: 'list', label: '리스트형', desc: '가로로 긴 줄 형태로 상품 정보를 더 자세히 표시' }
    ]
  },
  cart: {
    label: '장바구니',
    options: [
      { value: 'classic', label: '기본형', desc: '여유있는 카드형 장바구니 아이템 (기본)' },
      { value: 'compact', label: '컴팩트형', desc: '한 줄에 더 많은 정보를 담는 밀도 높은 표 형태' }
    ]
  },
  login: {
    label: '로그인',
    options: [
      { value: 'classic', label: '기본형', desc: '중앙 정렬된 카드형 로그인 화면 (기본)' },
      { value: 'split', label: '스플릿형', desc: '좌측 브랜드 패널 + 우측 로그인 폼으로 나뉜 화면' }
    ]
  },
  mypage: {
    label: '마이페이지',
    options: [
      { value: 'classic', label: '기본형', desc: '모든 섹션을 위에서 아래로 순서대로 표시 (기본)' },
      { value: 'tabs', label: '탭형', desc: '배송지·찜한상품·주문내역을 탭으로 전환해서 표시' }
    ]
  }
};
const DEFAULT_PAGE_TEMPLATES = { product_list: 'grid', cart: 'classic', login: 'classic', mypage: 'classic' };
let pageTemplatesCache = null;
let pageTemplatesCacheAt = 0;
const PAGE_TEMPLATES_CACHE_TTL_MS = 30 * 1000;

async function getPageTemplates() {
  const now = Date.now();
  if (pageTemplatesCache && (now - pageTemplatesCacheAt) < PAGE_TEMPLATES_CACHE_TTL_MS) {
    return pageTemplatesCache;
  }
  try {
    const { data, error } = await supabase
      .from('platform_settings')
      .select('value')
      .eq('key', 'page_design_templates')
      .single();
    if (error || !data) return pageTemplatesCache || DEFAULT_PAGE_TEMPLATES;
    const value = data.value || {};
    const templates = {};
    Object.keys(PAGE_TEMPLATE_COMPONENTS).forEach(key => {
      const allowed = PAGE_TEMPLATE_COMPONENTS[key].options.map(o => o.value);
      templates[key] = allowed.includes(value[key]) ? value[key] : DEFAULT_PAGE_TEMPLATES[key];
    });
    pageTemplatesCache = templates;
    pageTemplatesCacheAt = now;
    return templates;
  } catch (err) {
    return pageTemplatesCache || DEFAULT_PAGE_TEMPLATES;
  }
}

// 공개: 현재 선택된 디자인 템플릿 + 고를 수 있는 옵션 목록 조회 (누구나, 로그인 불필요 - 각 화면이 렌더링 전에 참조)
app.get('/api/settings/page-templates', async (req, res) => {
  try {
    const templates = await getPageTemplates();
    res.json({
      success: true,
      data: { selected: templates, components: PAGE_TEMPLATE_COMPONENTS },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch page templates', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 화면 구성요소별 디자인 템플릿 변경
app.patch('/api/admin/settings/page-templates', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const updates = req.body || {};
    const current = await getPageTemplates();
    const next = { ...current };
    for (const key of Object.keys(updates)) {
      if (!PAGE_TEMPLATE_COMPONENTS[key]) {
        return res.status(400).json({ error: 'Bad Request', message: `알 수 없는 화면 구성요소입니다: ${key}`, timestamp: new Date().toISOString() });
      }
      const allowed = PAGE_TEMPLATE_COMPONENTS[key].options.map(o => o.value);
      if (!allowed.includes(updates[key])) {
        return res.status(400).json({ error: 'Bad Request', message: `'${key}'에는 허용되지 않는 템플릿 값입니다: ${updates[key]}`, timestamp: new Date().toISOString() });
      }
      next[key] = updates[key];
    }

    const { error } = await supabase
      .from('platform_settings')
      .upsert({
        key: 'page_design_templates',
        value: next,
        updated_at: new Date().toISOString(),
        updated_by: req.user.id
      }, { onConflict: 'key' });
    if (error) throw error;

    pageTemplatesCache = next;
    pageTemplatesCacheAt = Date.now();

    res.json({ success: true, data: next, message: '디자인 템플릿이 변경되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating page templates:', err);
    res.status(500).json({ error: 'Failed to update page templates', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 회원 등급/혜택 시스템
// - 누적 구매액(취소/환불 제외) 기준으로 등급이 자동 산정된다 (관리자가 등급을 수동 부여하지 않음 - 실제 구매실적 그대로 반영)
// - 등급별 혜택은 지금 실제로 계산에 반영되는 것만 제공한다: 개인 마일리지 추가 적립율(%p)
// - 등급 기준/혜택은 platform_settings(key='member_grades')에 저장되어 관리자가 언제든 조정 가능
// ============================================
const DEFAULT_MEMBER_GRADES = [
  { key: 'general', label: '일반', min_spent: 0, bonus_personal_rate: 0 },
  { key: 'silver', label: '실버', min_spent: 300000, bonus_personal_rate: 0.005 },
  { key: 'gold', label: '골드', min_spent: 1000000, bonus_personal_rate: 0.01 },
  { key: 'vip', label: 'VIP', min_spent: 3000000, bonus_personal_rate: 0.02 }
];
let memberGradesCache = null;
let memberGradesCacheAt = 0;

async function getMemberGrades() {
  const now = Date.now();
  if (memberGradesCache && (now - memberGradesCacheAt) < MILEAGE_RATES_CACHE_TTL_MS) {
    return memberGradesCache;
  }
  try {
    const { data, error } = await supabase.from('platform_settings').select('value').eq('key', 'member_grades').single();
    if (error || !data || !Array.isArray(data.value) || data.value.length === 0) {
      return memberGradesCache || DEFAULT_MEMBER_GRADES;
    }
    const grades = data.value
      .filter(g => g && g.key && g.label)
      .map(g => ({
        key: String(g.key),
        label: String(g.label),
        min_spent: Number(g.min_spent) || 0,
        bonus_personal_rate: Number(g.bonus_personal_rate) || 0
      }))
      .sort((a, b) => a.min_spent - b.min_spent);
    memberGradesCache = grades.length > 0 ? grades : DEFAULT_MEMBER_GRADES;
    memberGradesCacheAt = now;
    return memberGradesCache;
  } catch (err) {
    console.error('Error fetching member grades:', err);
    return memberGradesCache || DEFAULT_MEMBER_GRADES;
  }
}

// 누적 구매액(취소/환불 제외) 기준으로 지금 등급 + 다음 등급을 판정한다
function resolveMemberGrade(totalSpent, grades) {
  let current = grades[0];
  for (const g of grades) {
    if (Number(totalSpent) >= Number(g.min_spent)) current = g;
  }
  const next = grades.find(g => Number(g.min_spent) > Number(current.min_spent)) || null;
  return { current, next };
}

async function getUserCumulativeSpent(userId) {
  const { data, error } = await supabase
    .from('orders_with')
    .select('final_price, status')
    .eq('user_id', userId)
    .not('status', 'in', '(cancelled,refunded)');
  if (error || !data) return 0;
  return data.reduce((sum, o) => sum + Number(o.final_price || 0), 0);
}

// 💰 마일리지 수동 적립 원장 (mileage_adjustments_with) - 시리얼쿠폰/출석체크처럼 "주문과 무관하게" 지급되는 마일리지용.
// 기존 마일리지 잔액은 orders_with의 적립/사용 필드만으로 계산되고 있었는데, 그 구조에는 주문 없이 지급되는
// 보상을 넣을 곳이 없었다. 그래서 이 원장 테이블을 새로 두고, getUserMileageBalance가 여기 쌓인 금액도
// 함께 더하도록 확장했다(원장에 아무 것도 없으면 지금까지와 완전히 동일하게 동작 - 기존 동작 100% 유지).
async function creditMileageAdjustment(userId, amount, reason, reference) {
  const { error } = await supabase.from('mileage_adjustments_with').insert([{
    user_id: userId,
    amount: Math.round(Number(amount)),
    reason,
    reference: reference || null
  }]);
  if (error) throw error;
}

async function getMileageAdjustmentTotal(userId) {
  const { data, error } = await supabase.from('mileage_adjustments_with').select('amount').eq('user_id', userId);
  if (error || !data) return 0;
  return data.reduce((sum, r) => sum + Number(r.amount || 0), 0);
}

// 사용 가능한 마일리지 잔액 = (취소/환불되지 않은 주문에서 적립된 개인+커뮤니티 마일리지 합) - (같은 주문들에서 이미 사용한 마일리지 합) + (시리얼쿠폰/출석체크 등 주문과 무관하게 지급된 수동 적립분)
// 취소/환불된 주문은 적립분도, 사용분도 함께 제외되므로(= 둘 다 무효화) 별도의 "마일리지 복구" 로직 없이도 자연스럽게 잔액이 원상복구된다.
async function getUserMileageBalance(userId) {
  const { data, error } = await supabase
    .from('orders_with')
    .select('personal_earned_points, community_earned_points, used_mileage, status')
    .eq('user_id', userId)
    .not('status', 'in', '(cancelled,refunded)');
  if (error || !data) return 0;
  const earned = data.reduce((sum, o) => sum + Number(o.personal_earned_points || 0) + Number(o.community_earned_points || 0), 0);
  const used = data.reduce((sum, o) => sum + Number(o.used_mileage || 0), 0);
  const adjustments = await getMileageAdjustmentTotal(userId);
  return Math.max(0, earned - used + adjustments);
}

// 내 마일리지 사용 가능 잔액 조회 (장바구니에서 결제 시 사용할 마일리지 입력 전 참고용)
app.get('/api/me/mileage-balance', authenticate, async (req, res) => {
  try {
    const balance = await getUserMileageBalance(req.user.id);
    res.json({ success: true, data: { balance }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching mileage balance:', err);
    res.status(500).json({ error: 'Failed to fetch mileage balance', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공개: 등급 기준/혜택 조회 (마이페이지·등급 안내에 필요, 로그인 불필요)
app.get('/api/settings/member-grades', async (req, res) => {
  try {
    const grades = await getMemberGrades();
    res.json({ success: true, data: grades, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch member grades', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 등급 기준/혜택 전체 교체
app.patch('/api/admin/settings/member-grades', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { grades } = req.body;
    if (!Array.isArray(grades) || grades.length === 0) {
      return res.status(400).json({ error: 'Bad Request', message: '등급을 하나 이상 입력해주세요', timestamp: new Date().toISOString() });
    }
    const cleaned = [];
    for (const g of grades) {
      const label = g && g.label ? String(g.label).trim() : '';
      const key = g && g.key ? String(g.key).trim() : '';
      const minSpent = Number(g && g.min_spent);
      const bonusRate = Number(g && g.bonus_personal_rate);
      if (!key || !label) {
        return res.status(400).json({ error: 'Bad Request', message: '모든 등급에 이름을 입력해주세요', timestamp: new Date().toISOString() });
      }
      if (!Number.isFinite(minSpent) || minSpent < 0) {
        return res.status(400).json({ error: 'Bad Request', message: `${label} 등급의 기준 금액이 올바르지 않습니다`, timestamp: new Date().toISOString() });
      }
      if (!Number.isFinite(bonusRate) || bonusRate < 0 || bonusRate > 0.1) {
        return res.status(400).json({ error: 'Bad Request', message: `${label} 등급의 추가 적립율은 0~10% 사이여야 합니다`, timestamp: new Date().toISOString() });
      }
      cleaned.push({ key, label, min_spent: minSpent, bonus_personal_rate: bonusRate });
    }
    cleaned.sort((a, b) => a.min_spent - b.min_spent);
    if (cleaned[0].min_spent !== 0) {
      return res.status(400).json({ error: 'Bad Request', message: '가장 낮은 등급의 기준 금액은 0원이어야 합니다 (모든 회원이 속할 기본 등급)', timestamp: new Date().toISOString() });
    }

    const { error } = await supabase
      .from('platform_settings')
      .upsert({ key: 'member_grades', value: cleaned, updated_at: new Date().toISOString(), updated_by: req.user.id }, { onConflict: 'key' });
    if (error) throw error;

    memberGradesCache = cleaned;
    memberGradesCacheAt = Date.now();

    res.json({ success: true, data: cleaned, message: '회원 등급 설정이 저장되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating member grades:', err);
    res.status(500).json({ error: 'Failed to update member grades', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 내 등급 조회 (마이페이지) - 누적 구매액, 현재 등급, 다음 등급까지 남은 금액
app.get('/api/me/grade', authenticate, async (req, res) => {
  try {
    const [grades, totalSpent] = await Promise.all([
      getMemberGrades(),
      getUserCumulativeSpent(req.user.id)
    ]);
    const { current, next } = resolveMemberGrade(totalSpent, grades);
    res.json({
      success: true,
      data: {
        totalSpent,
        current,
        next,
        amountToNext: next ? Math.max(0, Number(next.min_spent) - totalSpent) : null
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching my grade:', err);
    res.status(500).json({ error: 'Failed to fetch grade', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🎟️ 시리얼 쿠폰 - 관리자가 고유 코드를 대량 생성해 배포하고, 회원이 코드를 입력하면
// 1회성으로 마일리지가 지급된다 (카페24 관리자 화면 실사 때 확인했던 "시리얼 쿠폰" 기능을 참고해 구현).
// 기존 coupons 테이블(장바구니에서 쓰는 할인쿠폰, 여러 명이 같은 코드를 공유·사용 가능)과는 성격이 완전히
// 달라서 별도의 테이블/API로 분리했다 - 시리얼 코드는 1개당 딱 1명만, 딱 1번만 사용할 수 있다.
// ============================================
function generateSerialCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 혼동되기 쉬운 0/O, 1/I는 제외
  const seg = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return `WITH-${seg()}-${seg()}`;
}

// 관리자: 시리얼 쿠폰 배치 생성 (한 번에 여러 개의 고유 코드를 만든다)
// count가 클 수 있으므로(최대 5천만) 발급을 백그라운드 작업으로 처리한다.
// 예전에는 한 번의 HTTP 요청 안에서 전부 생성했는데, 그러면 (1) 대량 요청 시 응답이 몇 분~몇 시간씩 걸려
// 관리자 브라우저/프록시 타임아웃에 걸리고, (2) 전체 요청 개수만큼의 코드를 중복확인용 메모리(Set)에
// 계속 쌓아두는 구조라 수천만 개 규모에서는 서버 메모리를 다 써버릴 위험이 있었다.
// 지금은 작업(job) 행을 먼저 만들어 즉시 202로 응답하고, 실제 생성은 청크(5000개)씩 나눠 백그라운드에서
// 진행하며 매 청크마다 진행 상황을 job 행에 기록한다 - 청크 단위 메모리만 쓰므로 총 개수와 무관하게 가볍다.
// 코드 중복은 청크 내부에서는 Set으로, 청크 간/기존 배치와는 DB의 code UNIQUE 제약으로 막는다
// (혹시 우연히 겹치면 insert 자체가 23505 에러로 실패하는데, 그 경우 그 청크 전체를 새 코드로 재시도한다).
const SERIAL_COUPON_BATCH_CHUNK = 5000;
const SERIAL_COUPON_CHUNK_MAX_RETRIES = 5;

async function processSerialCouponJob(jobId, { batchName, rewardMileage, countNum, expiresAt, createdBy }) {
  let generatedCount = 0;
  const sampleCodes = [];
  try {
    await supabase.from('serial_coupon_jobs_with').update({ status: 'processing', updated_at: new Date().toISOString() }).eq('id', jobId);

    while (generatedCount < countNum) {
      const chunkTarget = Math.min(SERIAL_COUPON_BATCH_CHUNK, countNum - generatedCount);
      let chunkInserted = null;
      for (let attempt = 1; attempt <= SERIAL_COUPON_CHUNK_MAX_RETRIES && !chunkInserted; attempt++) {
        const seen = new Set();
        const rows = [];
        while (rows.length < chunkTarget) {
          const code = generateSerialCode();
          if (seen.has(code)) continue; // 이 청크 안에서의 1차 중복 방지
          seen.add(code);
          rows.push({ batch_name: batchName, code, reward_mileage: rewardMileage, expires_at: expiresAt, created_by: createdBy });
        }
        const { data: chunkData, error } = await supabase.from('serial_coupons_with').insert(rows).select('id, code');
        if (!error) {
          chunkInserted = chunkData;
        } else if (error.code === '23505') {
          // 다른 배치와 코드가 우연히 겹친 경우(극히 드묾) - 이 청크는 전부 새 코드로 다시 시도
          continue;
        } else {
          throw error;
        }
      }
      if (!chunkInserted) {
        throw new Error(`코드 중복 충돌로 청크 생성을 ${SERIAL_COUPON_CHUNK_MAX_RETRIES}번 재시도했지만 실패했습니다`);
      }
      generatedCount += chunkInserted.length;
      for (const r of chunkInserted) { if (sampleCodes.length < 20) sampleCodes.push(r.code); }
      await supabase.from('serial_coupon_jobs_with').update({
        generated_count: generatedCount, sample_codes: sampleCodes, updated_at: new Date().toISOString()
      }).eq('id', jobId);
    }

    await supabase.from('serial_coupon_jobs_with').update({
      status: 'completed', generated_count: generatedCount, sample_codes: sampleCodes, updated_at: new Date().toISOString()
    }).eq('id', jobId);
  } catch (err) {
    console.error('시리얼쿠폰 배치 생성 작업 실패:', err);
    try {
      await supabase.from('serial_coupon_jobs_with').update({
        status: 'failed', error_message: String(err.message || err), updated_at: new Date().toISOString()
      }).eq('id', jobId);
    } catch (_) { /* 실패 기록 자체가 실패해도 더 할 수 있는 게 없음 */ }
  }
}

app.post('/api/admin/serial-coupons/generate', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { batch_name, reward_mileage, count, expires_at } = req.body;
    const rewardNum = Number(reward_mileage);
    const countNum = Number(count);
    if (!batch_name || !String(batch_name).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: 'batch_name이 필요합니다', timestamp: new Date().toISOString() });
    }
    if (!Number.isFinite(rewardNum) || rewardNum <= 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'reward_mileage는 0보다 큰 숫자여야 합니다', timestamp: new Date().toISOString() });
    }
    if (!Number.isInteger(countNum) || countNum < 1 || countNum > 50000000) {
      return res.status(400).json({ error: 'Bad Request', message: 'count는 1~50,000,000 사이여야 합니다', timestamp: new Date().toISOString() });
    }

    const trimmedBatchName = String(batch_name).trim();
    const roundedReward = Math.round(rewardNum);
    const { data: job, error: jobErr } = await supabase.from('serial_coupon_jobs_with').insert([{
      batch_name: trimmedBatchName,
      reward_mileage: roundedReward,
      requested_count: countNum,
      expires_at: expires_at || null,
      created_by: req.user.id,
      status: 'pending'
    }]).select().single();
    if (jobErr) throw jobErr;

    // 응답은 바로 돌려주고, 실제 생성은 백그라운드에서 진행 - 관리자는 job_id로 진행 상황을 조회한다
    processSerialCouponJob(job.id, {
      batchName: trimmedBatchName, rewardMileage: roundedReward, countNum,
      expiresAt: expires_at || null, createdBy: req.user.id
    }).catch(err => console.error('시리얼쿠폰 배치 생성 작업 처리 중 예외:', err));

    res.status(202).json({
      success: true,
      data: job,
      message: `${countNum}개 발급 작업을 시작했습니다. 진행 상황은 job_id로 조회하세요.`,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error starting serial coupon generation job:', err);
    res.status(500).json({ error: 'Failed to start serial coupon generation job', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 시리얼쿠폰 대량발급 작업 진행 상황 조회 (폴링용)
app.get('/api/admin/serial-coupons/jobs/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('serial_coupon_jobs_with').select('*').eq('id', req.params.id).maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '작업을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching serial coupon job:', err);
    res.status(500).json({ error: 'Failed to fetch serial coupon job', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 최근 시리얼쿠폰 대량발급 작업 목록 (페이지 새로고침 후에도 진행 중/최근 작업을 볼 수 있도록)
app.get('/api/admin/serial-coupons/jobs', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('serial_coupon_jobs_with').select('*').order('created_at', { ascending: false }).limit(20);
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching serial coupon jobs:', err);
    res.status(500).json({ error: 'Failed to fetch serial coupon jobs', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 시리얼 쿠폰 배치 목록(배치별 발급/사용 현황 집계)
app.get('/api/admin/serial-coupons/batches', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('serial_coupons_with')
      .select('batch_name, reward_mileage, is_redeemed, expires_at, created_at')
      .order('created_at', { ascending: false });
    if (error) throw error;

    const byBatch = {};
    (data || []).forEach(row => {
      if (!byBatch[row.batch_name]) {
        byBatch[row.batch_name] = { batch_name: row.batch_name, reward_mileage: row.reward_mileage, expires_at: row.expires_at, total: 0, redeemed: 0, created_at: row.created_at };
      }
      byBatch[row.batch_name].total += 1;
      if (row.is_redeemed) byBatch[row.batch_name].redeemed += 1;
      if (row.created_at > byBatch[row.batch_name].created_at) byBatch[row.batch_name].created_at = row.created_at;
    });
    const batches = Object.values(byBatch).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json({ success: true, data: batches, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching serial coupon batches:', err);
    res.status(500).json({ error: 'Failed to fetch serial coupon batches', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 특정 배치의 코드 목록 (복사해서 이벤트 참가자에게 전달하기 위함)
app.get('/api/admin/serial-coupons', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { batch_name } = req.query;
    if (!batch_name) {
      return res.status(400).json({ error: 'Bad Request', message: 'batch_name이 필요합니다', timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase
      .from('serial_coupons_with')
      .select('id, code, is_redeemed, redeemed_at, expires_at, created_at')
      .eq('batch_name', batch_name)
      .order('created_at', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching serial coupons:', err);
    res.status(500).json({ error: 'Failed to fetch serial coupons', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 미사용 시리얼 코드 삭제 (이미 사용된 코드는 회원의 지급 이력 보존을 위해 삭제할 수 없게 막는다)
app.delete('/api/admin/serial-coupons/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: existing, error: findErr } = await supabase.from('serial_coupons_with').select('is_redeemed').eq('id', req.params.id).maybeSingle();
    if (findErr) throw findErr;
    if (!existing) return res.status(404).json({ error: 'Not Found', message: '존재하지 않는 코드입니다', timestamp: new Date().toISOString() });
    if (existing.is_redeemed) {
      return res.status(400).json({ error: 'Bad Request', message: '이미 사용된 코드는 삭제할 수 없습니다', timestamp: new Date().toISOString() });
    }
    const { error } = await supabase.from('serial_coupons_with').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: '삭제되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting serial coupon:', err);
    res.status(500).json({ error: 'Failed to delete serial coupon', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 회원: 시리얼 코드 등록 -> 검증 통과 시 즉시 마일리지 지급 (1코드 1인 1회)
app.post('/api/serial-coupons/redeem', authenticate, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code || !String(code).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: '시리얼 코드를 입력해주세요', timestamp: new Date().toISOString() });
    }
    const normalized = String(code).trim().toUpperCase();

    const { data: coupon, error: findErr } = await supabase.from('serial_coupons_with').select('*').eq('code', normalized).maybeSingle();
    if (findErr) throw findErr;
    if (!coupon) {
      return res.status(404).json({ error: 'Not Found', message: '존재하지 않는 시리얼 코드입니다', timestamp: new Date().toISOString() });
    }
    if (coupon.is_redeemed) {
      return res.status(409).json({ error: 'Conflict', message: '이미 사용된 코드입니다', timestamp: new Date().toISOString() });
    }
    if (coupon.expires_at && new Date(coupon.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Bad Request', message: '유효기간이 지난 코드입니다', timestamp: new Date().toISOString() });
    }

    // 동시에 같은 코드를 등록하는 경합 상황 방어: is_redeemed=false 조건이 걸린 채로 업데이트해서
    // 먼저 도착한 요청만 실제로 성공하게 하고, 늦게 도착한 요청은 0건 매칭되어 아래에서 409로 처리된다.
    const { data: updated, error: updateErr } = await supabase
      .from('serial_coupons_with')
      .update({ is_redeemed: true, redeemed_by: req.user.id, redeemed_at: new Date().toISOString() })
      .eq('id', coupon.id)
      .eq('is_redeemed', false)
      .select()
      .maybeSingle();
    if (updateErr) throw updateErr;
    if (!updated) {
      return res.status(409).json({ error: 'Conflict', message: '이미 사용된 코드입니다', timestamp: new Date().toISOString() });
    }

    await creditMileageAdjustment(req.user.id, updated.reward_mileage, 'serial_coupon', updated.code);
    const newBalance = await getUserMileageBalance(req.user.id);

    res.json({
      success: true,
      data: { reward_mileage: updated.reward_mileage, new_balance: newBalance },
      message: `시리얼 코드가 등록되어 ${Number(updated.reward_mileage).toLocaleString('ko-KR')} 마일리지가 지급되었습니다`,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error redeeming serial coupon:', err);
    res.status(500).json({ error: 'Failed to redeem serial coupon', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 📅 출석체크 이벤트 - 하루 1회 출석 시 마일리지 지급, N일 연속 출석 시 추가 보너스 지급
// - 설정은 platform_settings(key='attendance_event')에 저장되어 관리자가 언제든 조정 가능
//   (마일리지 적립율·회원등급과 동일한 캐시 패턴 - 최대 30초 내 전체 반영)
// - "오늘"/"연속 출석" 판정은 서버 시각(UTC) 기준 날짜로 한다. 실제 배포 서버가 UTC로 동작하고 있어
//   한국시간 자정과 서버 날짜 경계가 다를 수 있다는 점은 정직하게 밝혀둔다(예: 한국시간 오전 9시가
//   서버 기준 날짜가 바뀌는 시점).
// ============================================
const DEFAULT_ATTENDANCE_SETTINGS = { is_active: true, daily_reward: 10, streak_bonus_days: 7, streak_bonus_reward: 50 };
let attendanceSettingsCache = null;
let attendanceSettingsCacheAt = 0;

async function getAttendanceSettings() {
  const now = Date.now();
  if (attendanceSettingsCache && (now - attendanceSettingsCacheAt) < MILEAGE_RATES_CACHE_TTL_MS) {
    return attendanceSettingsCache;
  }
  try {
    const { data, error } = await supabase.from('platform_settings').select('value').eq('key', 'attendance_event').single();
    if (error || !data || !data.value) return attendanceSettingsCache || DEFAULT_ATTENDANCE_SETTINGS;
    const v = data.value;
    const settings = {
      is_active: typeof v.is_active === 'boolean' ? v.is_active : DEFAULT_ATTENDANCE_SETTINGS.is_active,
      daily_reward: Number.isFinite(Number(v.daily_reward)) ? Number(v.daily_reward) : DEFAULT_ATTENDANCE_SETTINGS.daily_reward,
      streak_bonus_days: (Number.isInteger(Number(v.streak_bonus_days)) && Number(v.streak_bonus_days) > 0) ? Number(v.streak_bonus_days) : DEFAULT_ATTENDANCE_SETTINGS.streak_bonus_days,
      streak_bonus_reward: Number.isFinite(Number(v.streak_bonus_reward)) ? Number(v.streak_bonus_reward) : DEFAULT_ATTENDANCE_SETTINGS.streak_bonus_reward
    };
    attendanceSettingsCache = settings;
    attendanceSettingsCacheAt = now;
    return settings;
  } catch (err) {
    console.error('Error fetching attendance settings:', err);
    return attendanceSettingsCache || DEFAULT_ATTENDANCE_SETTINGS;
  }
}

function todayDateString() {
  return new Date().toISOString().slice(0, 10);
}
function yesterdayDateString() {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - 1);
  return d.toISOString().slice(0, 10);
}

// 공개: 출석체크 이벤트 설정 조회 (로그인 불필요 - 비회원에게도 안내문구를 보여주기 위함)
app.get('/api/settings/attendance-event', async (req, res) => {
  try {
    const settings = await getAttendanceSettings();
    res.json({ success: true, data: settings, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch attendance settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 출석체크 이벤트 설정 변경
app.patch('/api/admin/settings/attendance-event', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { is_active, daily_reward, streak_bonus_days, streak_bonus_reward } = req.body;
    const dailyNum = Number(daily_reward);
    const streakDaysNum = Number(streak_bonus_days);
    const streakRewardNum = Number(streak_bonus_reward);
    if (!Number.isFinite(dailyNum) || dailyNum < 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'daily_reward는 0 이상의 숫자여야 합니다', timestamp: new Date().toISOString() });
    }
    if (!Number.isInteger(streakDaysNum) || streakDaysNum < 1) {
      return res.status(400).json({ error: 'Bad Request', message: 'streak_bonus_days는 1 이상의 정수여야 합니다', timestamp: new Date().toISOString() });
    }
    if (!Number.isFinite(streakRewardNum) || streakRewardNum < 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'streak_bonus_reward는 0 이상의 숫자여야 합니다', timestamp: new Date().toISOString() });
    }
    const settings = {
      is_active: !!is_active,
      daily_reward: Math.round(dailyNum),
      streak_bonus_days: Math.round(streakDaysNum),
      streak_bonus_reward: Math.round(streakRewardNum)
    };
    const { error } = await supabase
      .from('platform_settings')
      .upsert({ key: 'attendance_event', value: settings, updated_at: new Date().toISOString(), updated_by: req.user.id }, { onConflict: 'key' });
    if (error) throw error;

    attendanceSettingsCache = settings;
    attendanceSettingsCacheAt = Date.now();

    res.json({ success: true, data: settings, message: '출석체크 이벤트 설정이 저장되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating attendance settings:', err);
    res.status(500).json({ error: 'Failed to update attendance settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 회원: 내 출석체크 현황 (이번 달 출석일 목록, 연속 출석일수, 오늘 출석 여부, 이벤트 설정을 한 번에)
app.get('/api/attendance/status', authenticate, async (req, res) => {
  try {
    const settings = await getAttendanceSettings();
    const today = todayDateString();
    const monthPrefix = today.slice(0, 7); // YYYY-MM

    const { data: checkins, error } = await supabase
      .from('attendance_checkins_with')
      .select('checkin_date, streak_count')
      .eq('user_id', req.user.id)
      .order('checkin_date', { ascending: false })
      .limit(370); // 최근 1년치 - 연속 출석일수 판정에 충분
    if (error) throw error;

    const checkedInToday = (checkins || []).some(c => c.checkin_date === today);
    const currentStreak = (checkins && checkins.length > 0 && (checkedInToday || checkins[0].checkin_date === yesterdayDateString()))
      ? checkins[0].streak_count
      : 0; // 어제도 오늘도 출석하지 않았다면 연속 기록은 끊긴 것
    const thisMonthDates = (checkins || []).filter(c => c.checkin_date.startsWith(monthPrefix)).map(c => c.checkin_date);

    res.json({
      success: true,
      data: { ...settings, checked_in_today: checkedInToday, current_streak: currentStreak, this_month_dates: thisMonthDates },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching attendance status:', err);
    res.status(500).json({ error: 'Failed to fetch attendance status', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 회원: 오늘 출석체크 (하루 1회만 가능, 연속 출석일수가 streak_bonus_days의 배수가 될 때마다 보너스 지급)
app.post('/api/attendance/checkin', authenticate, async (req, res) => {
  try {
    const settings = await getAttendanceSettings();
    if (!settings.is_active) {
      return res.status(400).json({ error: 'Bad Request', message: '현재 출석체크 이벤트가 진행 중이 아닙니다', timestamp: new Date().toISOString() });
    }
    const today = todayDateString();

    const { data: existing, error: existErr } = await supabase
      .from('attendance_checkins_with')
      .select('id')
      .eq('user_id', req.user.id)
      .eq('checkin_date', today)
      .maybeSingle();
    if (existErr) throw existErr;
    if (existing) {
      return res.status(400).json({ error: 'Bad Request', message: '오늘은 이미 출석체크를 완료했습니다', timestamp: new Date().toISOString() });
    }

    const { data: prevRow } = await supabase
      .from('attendance_checkins_with')
      .select('streak_count')
      .eq('user_id', req.user.id)
      .eq('checkin_date', yesterdayDateString())
      .maybeSingle();
    const streakCount = prevRow ? prevRow.streak_count + 1 : 1;
    const bonusMileage = (streakCount % settings.streak_bonus_days === 0) ? settings.streak_bonus_reward : 0;
    const rewardMileage = settings.daily_reward;

    const { error: insertErr } = await supabase.from('attendance_checkins_with').insert([{
      user_id: req.user.id,
      checkin_date: today,
      streak_count: streakCount,
      reward_mileage: rewardMileage,
      bonus_mileage: bonusMileage
    }]);
    if (insertErr) {
      if (insertErr.code === '23505') { // unique(user_id, checkin_date) 위반 = 동시요청으로 이미 출석 처리됨
        return res.status(400).json({ error: 'Bad Request', message: '오늘은 이미 출석체크를 완료했습니다', timestamp: new Date().toISOString() });
      }
      throw insertErr;
    }

    const totalAwarded = rewardMileage + bonusMileage;
    if (totalAwarded > 0) {
      await creditMileageAdjustment(req.user.id, totalAwarded, 'attendance', today);
    }
    const newBalance = await getUserMileageBalance(req.user.id);

    res.json({
      success: true,
      data: { streak_count: streakCount, reward_mileage: rewardMileage, bonus_mileage: bonusMileage, total_awarded: totalAwarded, new_balance: newBalance },
      message: bonusMileage > 0
        ? `출석체크 완료! ${rewardMileage}마일리지 + ${streakCount}일 연속 보너스 ${bonusMileage}마일리지가 지급되었습니다`
        : `출석체크 완료! ${rewardMileage}마일리지가 지급되었습니다`,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error processing attendance checkin:', err);
    res.status(500).json({ error: 'Failed to process attendance checkin', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🎁 추천인(리퍼럴) 프로그램
// - 회원마다 고유 추천코드를 가지고, 그 코드로 가입한 신규 회원이 첫 주문을 만들면
//   추천인·피추천인 양쪽에게 마일리지를 지급한다(시리얼쿠폰/출석체크와 동일하게 mileage_adjustments_with 재사용).
// - 가입 즉시가 아니라 "첫 주문 생성 시점"에 보상하는 이유: 실제 구매 의사가 없는 허위/중복 가입으로
//   마일리지만 챙기는 어뷰징을 막기 위함(다른 쇼핑몰들의 일반적인 리퍼럴 프로그램 관행과 동일).
// - 참고: 이 Supabase 프로젝트에는 이미 접두사 없는 referrals/referral_codes 등 GMWOS 소유로 보이는
//   테이블이 존재하지만, 코드베이스의 "_with 접미사 = WITH+ 전용 테이블" 규칙에 따라 완전히 별도의
//   referral_profiles_with/referrals_with 테이블을 새로 만들어 충돌 없이 분리했다(과거 notifications
//   테이블 충돌 사례와 동일한 원칙).
// ============================================
const DEFAULT_REFERRAL_SETTINGS = {
  enabled: false,
  referrer_reward: 3000,  // 추천인(코드를 공유한 사람)에게 지급되는 마일리지
  referred_reward: 3000   // 피추천인(코드로 가입한 신규 회원)에게 지급되는 마일리지
};
let referralSettingsCache = null;
let referralSettingsCacheAt = 0;
const REFERRAL_SETTINGS_CACHE_TTL_MS = 30 * 1000;

function normalizeReferralSettings(value) {
  const v = value || {};
  return {
    enabled: !!v.enabled,
    referrer_reward: Number.isFinite(Number(v.referrer_reward)) ? Math.max(0, Math.floor(Number(v.referrer_reward))) : DEFAULT_REFERRAL_SETTINGS.referrer_reward,
    referred_reward: Number.isFinite(Number(v.referred_reward)) ? Math.max(0, Math.floor(Number(v.referred_reward))) : DEFAULT_REFERRAL_SETTINGS.referred_reward
  };
}

async function getReferralSettings() {
  const now = Date.now();
  if (referralSettingsCache && (now - referralSettingsCacheAt) < REFERRAL_SETTINGS_CACHE_TTL_MS) {
    return referralSettingsCache;
  }
  try {
    const { data, error } = await supabase.from('platform_settings').select('value').eq('key', 'referral_settings').single();
    const settings = normalizeReferralSettings(error || !data ? null : data.value);
    referralSettingsCache = settings;
    referralSettingsCacheAt = now;
    return settings;
  } catch (err) {
    console.error('Error fetching referral settings:', err);
    return referralSettingsCache || DEFAULT_REFERRAL_SETTINGS;
  }
}

// 헷갈리는 문자(0/O/1/I) 제외한 8자리 추천코드 생성 (시리얼쿠폰과 동일한 문자셋 관행)
function generateReferralCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// 이 회원의 추천코드를 조회하고, 없으면 새로 발급한다(최초 조회 시점에 지연 생성 - 가입 시점에 미리 만들어두지 않음)
async function getOrCreateReferralCode(userId) {
  const { data: existing } = await supabase.from('referral_profiles_with').select('referral_code').eq('user_id', userId).maybeSingle();
  if (existing) return existing.referral_code;

  for (let attempt = 0; attempt < 5; attempt++) {
    const code = generateReferralCode();
    const { data: inserted, error } = await supabase.from('referral_profiles_with').insert([{ user_id: userId, referral_code: code }]).select('referral_code').maybeSingle();
    if (!error && inserted) return inserted.referral_code;
    // unique 충돌(극히 낮은 확률)이면 다시 시도, 그 외 동시요청으로 이미 생성됐을 수 있으니 재조회
    const { data: raceCheck } = await supabase.from('referral_profiles_with').select('referral_code').eq('user_id', userId).maybeSingle();
    if (raceCheck) return raceCheck.referral_code;
  }
  throw new Error('추천코드 생성에 실패했습니다');
}

// 신규 가입 회원이 추천코드를 입력했을 때, 서버에서 유효성을 다시 검증하고 관계만 기록한다(보상은 아직 지급하지 않음 - 첫 주문 시 지급).
app.post('/api/me/apply-referral', authenticate, async (req, res) => {
  try {
    const code = String(req.body?.code || '').trim().toUpperCase();
    if (!code) {
      return res.status(400).json({ error: 'Bad Request', message: '추천코드를 입력해주세요', timestamp: new Date().toISOString() });
    }

    const { data: referrerProfile } = await supabase.from('referral_profiles_with').select('user_id').eq('referral_code', code).maybeSingle();
    if (!referrerProfile) {
      return res.status(404).json({ error: 'Not Found', message: '존재하지 않는 추천코드입니다', timestamp: new Date().toISOString() });
    }
    if (referrerProfile.user_id === req.user.id) {
      return res.status(400).json({ error: 'Bad Request', message: '본인의 추천코드는 사용할 수 없습니다', timestamp: new Date().toISOString() });
    }

    const { data: existingReferral } = await supabase.from('referrals_with').select('id').eq('referred_id', req.user.id).maybeSingle();
    if (existingReferral) {
      return res.status(409).json({ error: 'Conflict', message: '이미 추천인이 등록되어 있습니다(1회만 등록 가능)', timestamp: new Date().toISOString() });
    }

    const { error: insertErr } = await supabase.from('referrals_with').insert([{
      referrer_id: referrerProfile.user_id,
      referred_id: req.user.id,
      referral_code_used: code,
      status: 'pending'
    }]);
    if (insertErr) throw insertErr;

    res.json({ success: true, message: '추천인이 등록되었습니다. 첫 주문을 완료하면 서로 마일리지가 지급됩니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error applying referral code:', err);
    res.status(500).json({ error: 'Failed to apply referral code', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 신규 가입 회원의 첫 주문이 생성됐을 때 호출되어, 대기 중인(pending) 추천 관계가 있으면 양쪽에 마일리지를 지급한다.
// 이미 rewarded 상태면 아무 것도 하지 않고, 프로그램이 비활성화 상태여도 이미 등록된 pending 관계는 정직하게 보상하지 않고 넘어간다(설정 확인 후 지급).
async function rewardReferralIfEligible(referredUserId, orderId) {
  try {
    const { data: referral } = await supabase.from('referrals_with').select('*').eq('referred_id', referredUserId).eq('status', 'pending').maybeSingle();
    if (!referral) return;

    const settings = await getReferralSettings();
    if (!settings.enabled) return;

    // 이 주문이 피추천인의 "첫 주문"인지 확인 (재구매/추가주문에는 중복 지급하지 않기 위함 - referrals_with.status가 이미 이를 보장하지만 이중 방어)
    const { count } = await supabase.from('orders_with').select('id', { count: 'exact', head: true }).eq('user_id', referredUserId);
    if ((count || 0) > 1) return; // 방금 생성된 주문을 포함해 2건 이상이면 이미 첫 주문이 아님

    if (settings.referrer_reward > 0) {
      await creditMileageAdjustment(referral.referrer_id, settings.referrer_reward, 'referral_referrer', String(orderId));
    }
    if (settings.referred_reward > 0) {
      await creditMileageAdjustment(referredUserId, settings.referred_reward, 'referral_referred', String(orderId));
    }
    await supabase.from('referrals_with').update({ status: 'rewarded', rewarded_at: new Date().toISOString() }).eq('id', referral.id);
  } catch (err) {
    console.error('Error rewarding referral:', err);
  }
}

// 내 추천코드/추천 링크/실적 조회
app.get('/api/me/referral', authenticate, async (req, res) => {
  try {
    const code = await getOrCreateReferralCode(req.user.id);
    const { data: myReferrals } = await supabase
      .from('referrals_with')
      .select('status, created_at, rewarded_at, referred_id')
      .eq('referrer_id', req.user.id)
      .order('created_at', { ascending: false });

    const referredIds = (myReferrals || []).map(r => r.referred_id);
    let nameMap = {};
    if (referredIds.length > 0) {
      const { data: profiles } = await supabase.from('profiles').select('id, full_name, email').in('id', referredIds);
      (profiles || []).forEach(p => { nameMap[p.id] = p.full_name || (p.email ? p.email.replace(/(.{2}).+(@.+)/, '$1***$2') : '회원'); });
    }
    const rewardedCount = (myReferrals || []).filter(r => r.status === 'rewarded').length;
    const settings = await getReferralSettings();

    res.json({
      success: true,
      data: {
        referral_code: code,
        referral_link: `${req.protocol}://${req.get('host')}/join?ref=${code}`,
        total_referrals: (myReferrals || []).length,
        rewarded_referrals: rewardedCount,
        total_earned_mileage: rewardedCount * settings.referrer_reward,
        referred_reward: settings.referred_reward,
        referrals: (myReferrals || []).map(r => ({
          name: nameMap[r.referred_id] || '회원',
          status: r.status,
          created_at: r.created_at,
          rewarded_at: r.rewarded_at
        }))
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching referral info:', err);
    res.status(500).json({ error: 'Failed to fetch referral info', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공개: 추천인 프로그램 활성화 여부만 (가입 화면에서 추천코드 입력란을 보여줄지 판단하는 용도)
app.get('/api/settings/referral-program', async (req, res) => {
  try {
    const settings = await getReferralSettings();
    res.json({ success: true, data: { enabled: settings.enabled }, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch referral settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 추천인 프로그램 설정 + 누적 통계 조회
app.get('/api/admin/settings/referral-program', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const settings = await getReferralSettings();
    const { count: totalCount } = await supabase.from('referrals_with').select('id', { count: 'exact', head: true });
    const { count: rewardedCount } = await supabase.from('referrals_with').select('id', { count: 'exact', head: true }).eq('status', 'rewarded');
    res.json({
      success: true,
      data: settings,
      stats: { total_referrals: totalCount || 0, rewarded_referrals: rewardedCount || 0, pending_referrals: (totalCount || 0) - (rewardedCount || 0) },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching referral admin settings:', err);
    res.status(500).json({ error: 'Failed to fetch referral settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 추천인 프로그램 설정 저장
app.patch('/api/admin/settings/referral-program', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const settings = normalizeReferralSettings(req.body);
    const { error } = await supabase.from('platform_settings').upsert({
      key: 'referral_settings',
      value: settings,
      updated_at: new Date().toISOString(),
      updated_by: req.user.id
    }, { onConflict: 'key' });
    if (error) throw error;

    referralSettingsCache = settings;
    referralSettingsCacheAt = Date.now();

    res.json({ success: true, data: settings, message: '저장되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating referral settings:', err);
    res.status(500).json({ error: 'Failed to update referral settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🧩 기능 모듈 카탈로그 ("카페24 모듈리스트"를 참고한 모듈형 기능 카탈로그)
// - 지금은 각 기능이 독립된 설정 키/화면을 가진 채로 관리자 화면 여기저기에 흩어져 있는데,
//   이 카탈로그는 그것들을 한눈에 모아 보여주는 안내판(런처) 역할을 한다.
// - status: 'active'(지금 실제로 쓸 수 있음) | 'planned'(로드맵엔 있지만 아직 미구현/보류 중)
// - tabTarget: 관리자 화면에서 해당 기능을 관리하는 탭의 data-tab 값 (없으면 아직 이동할 화면이 없다는 뜻)
// - 각 항목을 독립 단위(키/카테고리/설명)로 정의해둔 이유: 나중에 정말 플러그인 구조로 확장하게 되더라도
//   이 목록을 설치형 모듈 메타데이터의 기초로 그대로 재사용할 수 있게 하기 위함.
// ============================================
const MODULE_REGISTRY = [
  { key: 'products', category: '판매·상품 관리', icon: '📦', name: '상품 관리', desc: '상품 등록, 옵션/재고 관리를 합니다.', status: 'active', tabTarget: 'products' },
  { key: 'categories', category: '판매·상품 관리', icon: '🏷️', name: '카테고리 관리', desc: '상품을 분류하는 카테고리를 자유롭게 추가/수정하고, 드래그로 순서를 바꿀 수 있습니다.', status: 'active', tabTarget: 'categories' },
  { key: 'ai_category_recommender', category: '판매·상품 관리', icon: '🤖', name: 'AI 카테고리 추천', desc: '원하는 방향을 입력하면 Anthropic API로 어울리는 카테고리 후보를 만들어줍니다. (Anthropic API 키 등록 필요)', status: 'active', tabTarget: 'settings' },
  { key: 'suppliers', category: '판매·상품 관리', icon: '🏭', name: '공급자 관리', desc: '상품을 공급하는 업체 정보를 관리합니다.', status: 'active', tabTarget: 'suppliers' },
  { key: 'coupons', category: '판매·상품 관리', icon: '🎟️', name: '쿠폰/할인 관리', desc: '할인 쿠폰을 발급하고 사용 조건을 설정합니다.', status: 'active', tabTarget: 'coupons' },
  { key: 'returns', category: '판매·상품 관리', icon: '↩️', name: '반품/교환 관리', desc: '회원의 반품·교환 신청을 접수하고 처리합니다.', status: 'active', tabTarget: 'returns' },
  { key: 'members', category: '회원·커뮤니티', icon: '👥', name: '회원 관리', desc: '가입 회원 목록과 등급, 활동 내역을 확인합니다.', status: 'active', tabTarget: 'members' },
  { key: 'communities', category: '회원·커뮤니티', icon: '🏢', name: '분양 조직 관리', desc: '분양받은 조직별로 담당 관리자, 상품 노출 범위를 설정합니다.', status: 'active', tabTarget: 'communities' },
  { key: 'boards', category: '회원·커뮤니티', icon: '📝', name: '게시판 관리', desc: '공지사항 등 커뮤니티 게시글을 관리합니다.', status: 'active', tabTarget: 'boards' },
  { key: 'mileage', category: '적립·혜택', icon: '💰', name: '마일리지 적립율', desc: '구매 시 적립되는 기본 적립율(개인/커뮤니티 참여)을 설정합니다.', status: 'active', tabTarget: 'settings' },
  { key: 'grades', category: '적립·혜택', icon: '🏅', name: '회원 등급/혜택', desc: '누적 구매액 기준 회원 등급과 등급별 추가 적립율을 설정합니다.', status: 'active', tabTarget: 'settings' },
  { key: 'serial_coupons', category: '적립·혜택', icon: '🎫', name: '시리얼 쿠폰', desc: '고유 시리얼 코드를 대량 발급해 배포하고, 회원이 코드를 등록하면 마일리지가 지급됩니다.', status: 'active', tabTarget: 'promotions' },
  { key: 'attendance', category: '적립·혜택', icon: '📅', name: '출석체크 이벤트', desc: '하루 1회 출석 시 마일리지를 지급하고, N일 연속 출석하면 추가 보너스를 지급합니다.', status: 'active', tabTarget: 'promotions' },
  { key: 'design_gallery', category: '디자인', icon: '🎨', name: '디자인 부품 갤러리', desc: '상품목록·장바구니·로그인·마이페이지 화면마다 디자인 템플릿을 골라 적용합니다.', status: 'active', tabTarget: 'settings' },
  { key: 'landing_templates', category: '디자인', icon: '🖼️', name: '랜딩페이지 템플릿', desc: '분양 조직별로 전용 랜딩페이지 디자인 템플릿을 선택합니다.', status: 'active', tabTarget: 'communities' },
  { key: 'payment_gateway', category: '판매·상품 관리', icon: '💳', name: '결제(PG) 연동', desc: '토스페이먼츠로 실제 카드 결제를 받습니다. (실제 승인에는 판매자의 토스페이먼츠 키가 필요 - 테스트 키는 가입 없이도 발급 가능)', status: 'active', tabTarget: 'settings' },
  { key: 'kakaopay', category: '판매·상품 관리', icon: '🟡', name: '카카오페이 간편결제', desc: '카카오페이로 결제를 받습니다. (실제 승인에는 판매자의 CID/SECRET_KEY가 필요 - 테스트 CID는 가입 없이도 발급 가능)', status: 'active', tabTarget: 'settings' },
  { key: 'naverpay', category: '판매·상품 관리', icon: '🟢', name: '네이버페이 간편결제', desc: '네이버페이로 결제를 받습니다. (실제 승인에는 판매자의 Client-Id/Secret/파트너ID가 필요 - 네이버페이 가맹 심사 통과 후 발급됨)', status: 'active', tabTarget: 'settings' },
  { key: 'cart_reminder', category: '판매·상품 관리', icon: '🛒', name: '장바구니 이탈 리마인더', desc: '장바구니에 담아두고 결제하지 않은 회원에게 일정 시간 후 이메일/인앱 알림을 보냅니다. (node-cron으로 30분마다 자동 스캔 - SMTP 미설정 시 인앱 알림만 발송됩니다)', status: 'active', tabTarget: 'settings' },
  { key: 'referral_program', category: '적립·혜택', icon: '🎁', name: '추천인(리퍼럴) 프로그램', desc: '회원마다 고유 추천코드를 발급하고, 그 코드로 가입한 신규 회원이 첫 주문을 하면 추천인·피추천인 양쪽에 마일리지를 지급합니다.', status: 'active', tabTarget: 'settings' },
  { key: 'social_login', category: '회원·커뮤니티', icon: '📱', name: '소셜 로그인', desc: '구글/카카오/네이버 계정으로 간편 로그인하는 기능입니다. 구글·카카오는 Supabase 대시보드에서, 네이버는 이 화면(설정 탭)에서 클라이언트ID/시크릿을 등록해야 실제로 동작합니다.', status: 'active', tabTarget: 'settings' },
  { key: 'phone_verify', category: '앞으로 추가될 모듈', icon: '🔒', name: '휴대폰 본인인증', desc: '가입/비밀번호 찾기 시 휴대폰 인증(PASS/NICE)입니다. 화면은 준비되어 있으나 본인인증 서비스사(PASS/NICE 등)와의 실제 제휴·계약이 필요해 보류 중입니다.', status: 'planned', tabTarget: null },
  { key: 'product_import', category: '판매·상품 관리', icon: '📥', name: '외부 상품 가져오기', desc: '도매매(도매꾹) 오픈API로 실시간 검색 후 우리 플랫폼 상품으로 가져옵니다. (요청 형식 최종 검증에는 실제 API 키가 필요)', status: 'active', tabTarget: 'import' },
  { key: 'point_redeem', category: '적립·혜택', icon: '💸', name: '마일리지 사용(차감)', desc: '장바구니에서 보유 마일리지를 결제에 사용할 수 있습니다(직접입력/전액사용, 취소 시 자동 원복). 별도 관리자 설정 화면은 없습니다.', status: 'active', tabTarget: null },
  { key: 'subscriptions', category: '판매·상품 관리', icon: '🔄', name: '정기배송(구독)', desc: '회원이 상품을 주기적으로 배송받도록 신청하고, 관리자가 배송 일정(발송 처리)을 관리합니다. 자동결제·자동주문생성은 범위 밖입니다(신청/일정 관리만).', status: 'active', tabTarget: 'subscriptions' },
  { key: 'recommendations', category: '판매·상품 관리', icon: '🎯', name: '개인화 추천(쇼핑 큐레이션)', desc: '구매(5)·장바구니 담음(3)·찜(2)·리뷰작성(2)·클릭/체류시간(0.5~1.5) 5개 신호에 브랜드 선호·가격대 선호·전체 회원 구매 패턴 기반 협업 필터링(다른 회원들이 함께 구매한 상품)까지 더해 홈 화면을 "관심 상품/맞춤 추천/함께 구매한 상품/자주 구매/한정특가" 섹션으로 개인화합니다. 섹션 순서 자체도 회원마다 신호가 강한 순으로 재배열됩니다. 이번 세션에서 방금 본 상품은 서버 이력 반영을 기다리지 않고 즉시 신호에 포함됩니다(실시간 개인화). 신호가 없는 신규 회원·비회원에게는 정직하게 인기 상품으로 대체합니다. 규칙 기반 추천이며 별도 관리자 설정 화면은 없습니다.', status: 'active', tabTarget: null },
  { key: 'repurchase_reminder', category: '판매·상품 관리', icon: '🔁', name: '재구매 알림 · 재주문', desc: '같은 상품을 2번 이상 구매한 회원의 평균 구매 간격으로 예상 재구매일을 계산해, 임박한 회원에게 이메일/인앱으로 "다시 필요하지 않으신가요?" 알림을 보냅니다. 매일 새벽 4시 자동 실행(node-cron), 같은 상품은 14일 안에는 재알림하지 않습니다. 마이페이지 주문내역에는 지난 주문을 그대로 장바구니에 담는 "재주문" 버튼이 있습니다. 찜한 상품의 가격이 내려가면 인앱 알림도 자동 발송되고, 찜해본 적 있는 카테고리에 신상품이 등록되면 그 회원들에게도 인앱 알림이 갑니다.', status: 'active', tabTarget: 'settings' },
  { key: 'reviews', category: '판매·상품 관리', icon: '⭐', name: '리뷰 관리', desc: '실제 구매자만 작성 가능한 구매인증(verified purchase) 리뷰를 모더레이션(숨김/노출)합니다. 상품 상세페이지에는 구매인증 리뷰 중 평점 4점 이상 비율을 "구매자 OO% 만족"으로 요약해 노출합니다(리뷰 3건 미만이면 정직하게 숨깁니다).', status: 'active', tabTarget: 'reviews' },
  { key: 'trust_badges', category: '판매·상품 관리', icon: '🚚', name: '재고·배송 신뢰 배지 · 최저가 이력', desc: '재고가 있고 출고 마감(오후 3시) 전이면 "오늘 출고" 배지를 상품 카드/상세페이지에 노출합니다(재고를 실시간으로 정확히 아는 재고원장 인프라를 그대로 활용). 상품 가격이 바뀔 때마다 이력을 기록해, 상세페이지에서 "최근 90일 최저가"인지 비교해 보여줍니다. 둘 다 규칙 기반으로 자동 동작하며 별도 관리자 설정 화면은 없습니다.', status: 'active', tabTarget: null },
  { key: 'search', category: '판매·상품 관리', icon: '🔍', name: '상품 검색 개선', desc: '전문검색, 오타 허용, 자동완성을 지원합니다. 로그인 회원에게는 상품명 완전일치로 순위가 동점 처리되는 구간 안에서만 선호 카테고리 상품을 우선 노출하는 개인화가 적용됩니다(진짜 연관도가 다른 결과는 순서를 바꾸지 않습니다). 규칙 기반으로 자동 동작하며 별도 관리자 설정 화면은 없습니다.', status: 'active', tabTarget: null },
  { key: 'seo', category: '디자인', icon: '📈', name: 'SEO 기초', desc: 'sitemap.xml/robots.txt 자동 생성과 상품·카테고리 페이지 Open Graph/구조화데이터(JSON-LD)를 자동으로 붙여줍니다. 별도 관리자 설정 화면은 없습니다.', status: 'active', tabTarget: null },
  { key: 'email_notifications', category: '회원·커뮤니티', icon: '📧', name: '주문/배송 이메일 알림', desc: 'SMTP 계정을 등록하면 주문 접수·상태 변경 시 회원에게 자동으로 이메일을 발송합니다.', status: 'active', tabTarget: 'settings' },
  { key: 'admin_mfa', category: '회원·커뮤니티', icon: '🔐', name: '관리자 2단계 인증(2FA)', desc: '관리자 본인 계정에 TOTP 기반 2단계 인증을 설정합니다(Supabase Auth MFA 기능 사용).', status: 'active', tabTarget: 'settings' },
  { key: 'account_withdrawal', category: '회원·커뮤니티', icon: '🚪', name: '회원 탈퇴', desc: '회원이 마이페이지에서 직접 탈퇴 신청을 할 수 있습니다. 별도 관리자 설정 화면은 없습니다.', status: 'active', tabTarget: null },
  { key: 'audit_log', category: '회원·커뮤니티', icon: '🕵️', name: '관리자 감사로그', desc: '관리자/최고관리자의 주요 API 호출(등록·수정·삭제 등 57개 엔드포인트)을 자동으로 기록합니다(최고관리자 전용, 민감정보는 마스킹). ', status: 'active', tabTarget: 'audit-log' },
  { key: 'wms', category: '재고·물류', icon: '🏭', name: '창고관리(WMS)', desc: '이벤트소싱 재고원장, 바코드/Lot 추적, 창고 로케이션(Zone-Rack-Bin), 2D 디지털트윈 평면도(다층 + 층별 최대 5단 복층 지원)와 AGV 이동 시뮬레이션까지 지원합니다.', status: 'active', tabTarget: 'wms' },
  { key: 'marketing_automation', category: '적립·혜택', icon: '📢', name: '마케팅자동화', desc: '등급/누적구매액/주문건수/미구매기간/가입일 조건으로 회원을 골라 타겟 쿠폰을 즉시 발급하는 세그먼트 캠페인과, 등급유지·구매마일스톤 조건을 매일 자동 스캔해 발급하는 자동 쿠폰 규칙을 지원합니다.', status: 'active', tabTarget: 'marketing' },
  { key: 'supplier_settlements', category: '판매·상품 관리', icon: '💰', name: '공급자 정산 관리', desc: '기간별로 공급자(판매자)의 매출·수수료·정산금액을 자동 집계하고, 정산 처리(지급완료 표시)까지 관리합니다.', status: 'active', tabTarget: 'settlements' },
  { key: 'live_channels', category: '라이브커머스(LIVE+)', icon: '🎬', name: '라이브 채널 관리', desc: '실시간 라이브 방송 채널을 개설하고, 채널별 등급(티어)·노출 상품·방송 세션을 관리합니다.', status: 'active', tabTarget: 'live-channels' },
  { key: 'live_sessions', category: '라이브커머스(LIVE+)', icon: '📡', name: '라이브 세션·방송 진행', desc: '방송 세션을 시작/종료하고, 세션별 상품 노출과 실시간 채팅(페이지네이션 지원), 호스트용 방송 진행 화면을 관리합니다.', status: 'active', tabTarget: 'live-channels' },
  { key: 'live_inventory_reservation', category: '라이브커머스(LIVE+)', icon: '📦', name: '라이브 세션 재고예약', desc: '방송 중 시청자가 상품을 담으면 세션 재고에서 실시간으로 예약(홀드)되어, 여러 시청자에게 동시에 초과판매되는 것을 방지합니다.', status: 'active', tabTarget: 'live-channels' },
  { key: 'live_watch_payment', category: '라이브커머스(LIVE+)', icon: '💳', name: '시청페이지 실시간 PG결제', desc: '고객용 라이브 시청 페이지에서 방송을 보면서 바로 PG 결제로 구매할 수 있습니다. 별도 관리자 설정 화면은 없습니다.', status: 'active', tabTarget: null },
  { key: 'live_licenses', category: '라이브커머스(LIVE+)', icon: '🪪', name: '채널 자격·라이선스 관리', desc: '채널별 방송 자격(라이선스) 상태와 변경 이력을 관리하고, 시청 접근 딥링크를 추적합니다.', status: 'active', tabTarget: 'live-channels' },
  { key: 'omnicast', category: '라이브커머스(LIVE+)', icon: '🛰️', name: 'OmniCast 동시송출', desc: '유튜브/카카오/네이버 등 여러 외부 플랫폼에 하나의 라이브 방송을 동시에 송출합니다(플랫폼별 연동키/OAuth 연결 필요).', status: 'active', tabTarget: 'live-channels' },
  { key: 'fan_official_channel', category: '라이브커머스(LIVE+)', icon: '⭐', name: 'FAN 공식채널', desc: '브랜드/인플루언서 공식 채널 구조를 지원하고, 시청자의 팬 활동(참여) 점수를 적립·관리합니다.', status: 'active', tabTarget: 'live-channels' }
];

app.get('/api/admin/modules', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    res.json({ success: true, data: MODULE_REGISTRY, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching module catalog:', err);
    res.status(500).json({ error: 'Failed to fetch module catalog', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 📥 외부 도매/사입 사이트 실시간 API 연동 - 1차로 도매매(도매꾹) 오픈API 지원
// - 조사 결과: 도매매(도매꾹)는 openapi.domeggook.com에 API키 인증(계정당 최대 5개), HTTPS,
//   분당 180회/일 15,000회 요청 제한이 걸린 실제 문서화된 오픈API를 운영 중임을 공식 가이드 페이지에서 확인했다.
//   다만 파라미터 상세 문서(참조 페이지)는 도매매 계정으로 로그인해야 열람 가능해, 정확한 요청 파라미터명까지는
//   이 세션에서 100% 확정하지 못했다 — 아래 요청 형식은 공개적으로 확인된 사실(키 인증 방식, 분당/일일 제한)과
//   일반적으로 알려진 요청 규격을 바탕으로 최선을 다해 구현했고, 실제 판매회원 API 키로 처음 테스트할 때
//   형식이 다르면 그 자리에서 바로잡아야 한다는 점을 관리자 화면에도 정직하게 안내한다.
// - 오너클랜/젠트레이드/도매토피아는 API 존재만 일부 확인되고 공식 파라미터 문서를 찾지 못해 이번에는 미포함.
// ============================================
const DOMEGGOOK_BASE = 'https://domeggook.com/ssl/api/';

async function callDomeggookApi(apiKey, mode, extraParams = {}) {
  const params = new URLSearchParams({ ver: '4.1', mode, aid: apiKey, om: 'json', market: 'dome', ...extraParams });
  const url = `${DOMEGGOOK_BASE}?${params.toString()}`;
  const resp = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(15000) });
  const text = await resp.text();
  let json = null;
  try { json = JSON.parse(text); } catch (e) { /* JSON이 아니면 raw 텍스트를 그대로 보존해서 반환 */ }
  return { httpStatus: resp.status, json, raw: text.slice(0, 4000) };
}

// 도매매 응답의 상품 배열이 어떤 키에 들어있을지 몇 가지 흔한 형태를 방어적으로 시도(정확한 스키마 미확정 상태이므로)
function extractDomeggookItems(json) {
  if (!json || typeof json !== 'object') return [];
  const candidates = [json.domeggook?.item, json.domeggook?.items, json.item, json.items, json.list, json.data];
  for (const c of candidates) {
    if (Array.isArray(c)) return c;
  }
  return [];
}
function normalizeDomeggookItem(raw) {
  const pick = (...keys) => { for (const k of keys) { if (raw && raw[k] !== undefined && raw[k] !== null && raw[k] !== '') return raw[k]; } return null; };
  return {
    external_id: String(pick('no', 'itemNo', 'item_no', 'id') ?? ''),
    name: pick('title', 'name', 'itemName', 'item_name') || '',
    price: Number(pick('price', 'unitPrice', 'unit_price') ?? 0) || 0,
    image_url: pick('img', 'image', 'thumbnail', 'thumbUrl', 'thumb_url') || '',
    stock: Number(pick('qty', 'stock', 'stockQty') ?? 0) || 0
  };
}

// 저장된 연동 설정 조회(내부용) - API 키를 매번 반환하지 않고, 있는지 여부만 확인할 때도 이 함수를 씀
async function getSupplierIntegration(supplierKey) {
  const { data, error } = await supabase.from('supplier_integrations').select('*').eq('supplier_key', supplierKey).maybeSingle();
  if (error) throw error;
  return data;
}

// 목록: 등록된 외부 공급사 연동 현황 (API 키 원문은 절대 응답에 포함하지 않음 - has_key로만 알림)
app.get('/api/admin/integrations', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('supplier_integrations').select('*').order('supplier_name');
    if (error) throw error;
    const safe = (data || []).map(row => ({
      supplier_key: row.supplier_key,
      supplier_name: row.supplier_name,
      has_key: !!row.api_key,
      enabled: row.enabled,
      last_tested_at: row.last_tested_at,
      last_test_status: row.last_test_status,
      last_test_message: row.last_test_message
    }));
    res.json({ success: true, data: safe, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching supplier integrations:', err);
    res.status(500).json({ error: 'Failed to fetch supplier integrations', message: err.message, timestamp: new Date().toISOString() });
  }
});

// API 키 저장/해제
app.patch('/api/admin/integrations/:supplierKey', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { supplierKey } = req.params;
    const existing = await getSupplierIntegration(supplierKey);
    if (!existing) return res.status(404).json({ error: 'Not Found', message: '지원하지 않는 공급사입니다', timestamp: new Date().toISOString() });

    const update = { updated_at: new Date().toISOString() };
    if (typeof req.body.api_key === 'string') update.api_key = req.body.api_key.trim() || null;
    if (typeof req.body.enabled === 'boolean') update.enabled = req.body.enabled;

    const { data, error } = await supabase.from('supplier_integrations').update(update).eq('supplier_key', supplierKey).select().single();
    if (error) throw error;
    res.json({ success: true, data: { supplier_key: data.supplier_key, has_key: !!data.api_key, enabled: data.enabled }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating supplier integration:', err);
    res.status(500).json({ error: 'Failed to update supplier integration', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 연결 테스트: 저장된 키로 실제 도매매 서버에 가벼운 요청(상품 1건 조회)을 실시간으로 보내본다
app.post('/api/admin/integrations/:supplierKey/test', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { supplierKey } = req.params;
    if (supplierKey !== 'domeggook') {
      return res.status(400).json({ error: 'Bad Request', message: '아직 지원하지 않는 공급사입니다', timestamp: new Date().toISOString() });
    }
    const existing = await getSupplierIntegration(supplierKey);
    if (!existing || !existing.api_key) {
      return res.status(400).json({ error: 'Bad Request', message: 'API 키가 등록되어 있지 않습니다. 먼저 API 키를 저장해주세요.', timestamp: new Date().toISOString() });
    }

    let status, message;
    try {
      const { httpStatus, json, raw } = await callDomeggookApi(existing.api_key, 'getItemLst', { sz: 1, pg: 1 });
      if (json && json.errors) {
        // 도매매 서버가 실제로 구조화된 에러(JSON errors 객체)를 내려줬다는 것 자체가 요청이 서버에 정상 도달했다는 뜻.
        // 다만 API 키 자체가 거절된 것이므로 실패로 표시하고, 서버가 알려준 실제 사유를 그대로 보여준다.
        status = 'failed';
        message = `도매매 서버에 요청은 정상 도달했지만 거절되었습니다 - ${json.errors.dmessage || json.errors.message || JSON.stringify(json.errors)} (code=${json.errors.code || json.errors.dcode || '?'})`;
      } else if (httpStatus === 200 && json) {
        status = 'success';
        message = `도매매 서버로부터 정상 응답을 받았습니다(HTTP ${httpStatus}, 에러 없음).`;
      } else {
        status = 'failed';
        message = `도매매 서버 응답이 예상과 다릅니다(HTTP ${httpStatus}). 응답 원문: ${raw.slice(0, 300)}`;
      }
    } catch (callErr) {
      status = 'failed';
      message = '도매매 서버 호출에 실패했습니다: ' + callErr.message;
    }

    await supabase.from('supplier_integrations').update({
      last_tested_at: new Date().toISOString(), last_test_status: status, last_test_message: message
    }).eq('supplier_key', supplierKey);

    res.json({ success: true, data: { status, message }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error testing supplier integration:', err);
    res.status(500).json({ error: 'Failed to test supplier integration', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 상품 검색(도매매 카탈로그를 실시간으로 검색) - 응답 스키마가 100% 확정되지 않았으므로 정규화 결과와 원문을 함께 반환
app.get('/api/admin/integrations/:supplierKey/search', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { supplierKey } = req.params;
    if (supplierKey !== 'domeggook') {
      return res.status(400).json({ error: 'Bad Request', message: '아직 지원하지 않는 공급사입니다', timestamp: new Date().toISOString() });
    }
    const existing = await getSupplierIntegration(supplierKey);
    if (!existing || !existing.api_key) {
      return res.status(400).json({ error: 'Bad Request', message: 'API 키가 등록되어 있지 않습니다. 먼저 API 키를 저장해주세요.', timestamp: new Date().toISOString() });
    }
    const keyword = (req.query.keyword || '').toString().trim();
    if (!keyword) return res.status(400).json({ error: 'Bad Request', message: '검색어(keyword)를 입력해주세요', timestamp: new Date().toISOString() });
    const page = Math.max(1, parseInt(req.query.page) || 1);

    const { httpStatus, json, raw } = await callDomeggookApi(existing.api_key, 'getItemLst', { kw: keyword, pg: page, sz: 20 });
    const items = extractDomeggookItems(json).map(normalizeDomeggookItem).filter(i => i.external_id && i.name);

    let warning = null;
    if (json && json.errors) {
      warning = `도매매 서버가 요청을 거절했습니다 - ${json.errors.dmessage || json.errors.message || JSON.stringify(json.errors)}. "연동 설정" 카드에서 API 키를 확인해주세요.`;
    } else if (items.length === 0) {
      warning = '정상 응답을 받았더라도 정규화된 상품이 0건이면, 응답 스키마가 예상과 달라 자동 인식이 안 됐을 수 있습니다. rawPreview를 확인해주세요.';
    }

    res.json({
      success: true,
      data: { items, httpStatus, rawPreview: raw.slice(0, 1500), warning },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error searching supplier catalog:', err);
    res.status(500).json({ error: 'Failed to search supplier catalog', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 선택한 상품들을 실제로 우리 플랫폼 상품(products_with)으로 가져오기 - 이미 가져온 external_id는 건너뜀(중복 방지)
// ============================================
// 🤖 대량 등록 시 카테고리 AI 자동분류
// - 예전에는 대량 등록(도매매/엑셀 가져오기) 시 상품 전체에 카테고리 하나를 똑같이 적용해서,
//   실제로는 성격이 다른 상품들이 한 카테고리에 뒤섞이는 문제가 있었다(이카운트 829개 가져올 때 실제로 겪은 문제).
// - 이제는 상품명을 하나씩 AI가 보고, 기존 카테고리 중 가장 알맞은 곳에 배정하거나(우선),
//   정말 기존 카테고리 어디에도 안 맞을 때만 새 카테고리를 제안한다.
// - 새 카테고리는 무한정 늘어나지 않도록: 이번 가져오기 1건당 최대 개수 제한 + 최소 상품 개수(너무 적으면 새로 만들지 않고
//   가장 비슷한 기존 카테고리로 대신 배정) 두 가지 안전장치를 둔다. 새 카테고리는 기존에 이미 만들어둔
//   2단(대분류/중분류) 체계를 그대로 활용해 적절한 대분류 아래 중분류로 만드는 것을 기본으로 한다.
// ============================================
const CATEGORY_AUTOCLASSIFY_CHUNK_SIZE = 40; // 한 번의 AI 호출에 담는 상품 수(프롬프트/응답 크기 관리용)
const CATEGORY_AUTOCLASSIFY_MAX_NEW_PER_BATCH = 5; // 이번 가져오기 1건에서 새로 만들 수 있는 카테고리 최대 개수
const CATEGORY_AUTOCLASSIFY_MIN_ITEMS_FOR_NEW = 3; // 이 개수 미만으로 몰린 새 카테고리 제안은 만들지 않고 fallback으로 대체

async function classifyProductsForCategories(names, existingCategories, config) {
  const topLevel = existingCategories.filter(c => !c.parent_id);
  const catSummary = topLevel.map(c => {
    const children = existingCategories.filter(ch => ch.parent_id === c.id);
    return `- ${c.slug} (${c.label})${children.length ? ' > 하위: ' + children.map(ch => `${ch.slug}(${ch.label})`).join(', ') : ''}`;
  }).join('\n');

  const results = [];
  for (let i = 0; i < names.length; i += CATEGORY_AUTOCLASSIFY_CHUNK_SIZE) {
    const chunk = names.slice(i, i + CATEGORY_AUTOCLASSIFY_CHUNK_SIZE);
    const prompt = `당신은 이커머스 쇼핑몰의 상품 카테고리 분류 담당자입니다.
아래 기존 카테고리 목록을 참고해, 상품명 목록 각각을 가장 알맞은 카테고리에 배정하세요.

기존 카테고리(대분류 및 그 아래 중분류):
${catSummary}

규칙:
1. 기존 카테고리 중 자연스럽게 맞는 것이 있으면 그 slug를 category_slug에 넣으세요. 이 경우가 기본입니다.
2. 기존 카테고리 어디에도 정말 안 맞는 상품들만 new_category를 제안하세요(남용 금지 — 애매하면 가장 가까운 기존 카테고리를 쓰세요).
3. new_category를 제안할 때는 fallback_slug(새 카테고리가 이번에 실제로 만들어지지 않을 경우 대신 사용할, 가장 비슷한 기존 카테고리의 slug)를 반드시 함께 주세요.
4. 새 카테고리는 기본적으로 가장 어울리는 기존 대분류 밑에 중분류로 만드세요(parent_slug에 그 대분류의 slug를 넣으세요). 정말 이질적이어서 대분류 자체가 필요하면 parent_slug를 null로 하세요.
5. 같은 성격의 상품이 여러 개 있어 같은 새 카테고리를 제안할 때는, 그 상품들 모두 new_category.slug를 동일한 값으로 통일하세요.

상품 목록(0번부터 순서대로):
${chunk.map((n, idx) => `${idx}. ${n}`).join('\n')}

반드시 아래 JSON 배열 형식으로만 응답하세요(코드블록/설명 문구 금지, 상품 개수·순서를 정확히 지키세요):
[{"index":0,"category_slug":"기존카테고리slug 또는 null","new_category":null,"fallback_slug":"가장비슷한기존카테고리slug"}]
new_category를 제안할 때는 예: {"index":1,"category_slug":null,"new_category":{"label":"홍삼","emoji":"🌿","slug":"ginseng","parent_slug":"functional"},"fallback_slug":"functional"}`;

    let aiResp;
    try {
      aiResp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': config.api_key, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 4096, messages: [{ role: 'user', content: prompt }] }),
        signal: AbortSignal.timeout(45000)
      });
    } catch (callErr) {
      throw new Error('AI 서버 호출에 실패했습니다: ' + callErr.message);
    }
    const aiJson = await aiResp.json().catch(() => null);
    if (!aiResp.ok || !aiJson) {
      throw new Error(aiJson?.error?.message || `AI 응답을 받아오지 못했습니다(HTTP ${aiResp.status})`);
    }
    const rawText = (aiJson.content || []).map(b => b.text || '').join('').trim();
    let parsed;
    try {
      const jsonMatch = rawText.match(/\[[\s\S]*\]/);
      parsed = JSON.parse(jsonMatch ? jsonMatch[0] : rawText);
    } catch (parseErr) {
      throw new Error('AI 응답을 해석하지 못했습니다(카테고리 자동분류). 다시 시도해주세요');
    }
    if (!Array.isArray(parsed)) throw new Error('AI 응답 형식이 올바르지 않습니다(카테고리 자동분류)');
    parsed.forEach(p => {
      if (p && Number.isInteger(p.index) && chunk[p.index] !== undefined) {
        results[i + p.index] = p;
      }
    });
  }
  return results; // results[k]는 names[k]에 대응 (AI가 건너뛴 항목은 undefined일 수 있음)
}

// AI 분류 결과(상품별 category_slug/new_category/fallback_slug)를 받아, 실제로 db_category 문자열을 확정한다.
// - 새 카테고리는 이번 배치에서 충분히 많이(>= MIN) 제안된 것 중 상위 MAX개만 실제로 생성한다(무한 증식 방지).
// - 채택되지 않은 새 카테고리 제안이나 매칭 실패 항목은 fallback_slug(그마저 없으면 첫 번째 기존 카테고리)로 대체한다.
async function resolveAutoClassifiedCategories(classifications, existingCategories) {
  const bySlug = new Map(existingCategories.map(c => [c.slug, c]));
  const defaultDbCategory = (existingCategories[0] && existingCategories[0].db_category) || 'lifestyle';

  // 1) 새 카테고리 제안 집계 (slug 기준)
  const proposals = new Map(); // slug -> { label, emoji, parent_slug, count }
  classifications.forEach(c => {
    if (c && c.new_category && c.new_category.slug) {
      const cleanSlug = String(c.new_category.slug).trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
      if (!cleanSlug || bySlug.has(cleanSlug)) return; // 이미 존재하는 slug와 겹치면 새로 만들지 않음(그 카테고리를 쓴 것으로 간주하지 않고 fallback 처리)
      const existing = proposals.get(cleanSlug);
      if (existing) { existing.count++; }
      else {
        proposals.set(cleanSlug, {
          label: String(c.new_category.label || cleanSlug).trim(),
          emoji: (c.new_category.emoji && String(c.new_category.emoji).trim()) || '🛍️',
          parent_slug: c.new_category.parent_slug ? String(c.new_category.parent_slug).trim() : null,
          count: 1
        });
      }
    }
  });

  // 2) 개수 많은 순으로 정렬해, 최소 개수 이상이면서 상한 개수 이내인 것만 실제로 생성 승인
  const approved = Array.from(proposals.entries())
    .filter(([, v]) => v.count >= CATEGORY_AUTOCLASSIFY_MIN_ITEMS_FOR_NEW)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, CATEGORY_AUTOCLASSIFY_MAX_NEW_PER_BATCH)
    .map(([slug, v]) => ({ slug, ...v }));

  const created = [];
  const rejected = Array.from(proposals.entries())
    .filter(([slug]) => !approved.some(a => a.slug === slug))
    .map(([slug, v]) => ({ slug, label: v.label, count: v.count }));

  for (const cat of approved) {
    let parentId = null;
    if (cat.parent_slug) {
      const parent = bySlug.get(cat.parent_slug);
      if (parent && !parent.parent_id) parentId = parent.id; // 2단(대분류/중분류) 제약을 지켜, 이미 중분류인 것은 상위로 쓰지 않음
    }
    const { data: newCat, error } = await supabase.from('categories').insert([{
      slug: cat.slug, label: cat.label, emoji: cat.emoji, db_category: cat.slug, parent_id: parentId,
      display_order: 999, is_active: true
    }]).select().single();
    if (error) {
      // 동시성 등으로 방금 다른 요청이 같은 slug를 먼저 만들었을 수 있음 - 실패해도 배치 전체를 막지 않고 기존 카테고리로 취급
      rejected.push({ slug: cat.slug, label: cat.label, count: cat.count, reason: error.message });
      continue;
    }
    created.push(newCat);
    bySlug.set(newCat.slug, newCat);
  }

  // 3) 상품별 최종 db_category 확정
  const finalCategories = classifications.map(c => {
    if (!c) return { db_category: defaultDbCategory, used: 'default_fallback' };
    if (c.new_category && c.new_category.slug) {
      const cleanSlug = String(c.new_category.slug).trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
      const approvedCat = bySlug.get(cleanSlug);
      if (approvedCat && created.some(cr => cr.slug === cleanSlug)) {
        return { db_category: approvedCat.db_category, used: 'new_category', category_label: approvedCat.label };
      }
    }
    if (c.category_slug && bySlug.has(c.category_slug)) {
      const cat = bySlug.get(c.category_slug);
      return { db_category: cat.db_category, used: 'existing', category_label: cat.label };
    }
    if (c.fallback_slug && bySlug.has(c.fallback_slug)) {
      const cat = bySlug.get(c.fallback_slug);
      return { db_category: cat.db_category, used: 'fallback', category_label: cat.label };
    }
    return { db_category: defaultDbCategory, used: 'default_fallback' };
  });

  return { finalCategories, created, rejected };
}

app.post('/api/admin/integrations/:supplierKey/import', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { supplierKey } = req.params;
    const { items, category } = req.body;
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Bad Request', message: '가져올 상품(items)이 없습니다', timestamp: new Date().toISOString() });
    }

    // category를 명시적으로 지정하지 않으면 AI가 상품명을 보고 하나씩 알맞은 카테고리로 자동분류한다(없으면 적당한 선에서 새로 만듦).
    // category를 지정하면 예전처럼 전체 상품에 그 카테고리 하나를 그대로 적용한다(관리자가 명시적으로 원할 때를 위한 기존 동작 유지).
    let perItemCategory = null;
    let categorySummary = null;
    if (!category) {
      const aiConfig = await getAiConfig('anthropic');
      if (!aiConfig || !aiConfig.enabled || !aiConfig.api_key) {
        return res.status(400).json({ error: 'Bad Request', message: '카테고리를 지정하지 않으셨습니다. AI 자동분류를 쓰려면 "⚙️ 설정"에서 Anthropic API 키를 등록·활성화하시거나, 등록할 카테고리를 직접 선택해주세요', timestamp: new Date().toISOString() });
      }
      const { data: existingCategories, error: catErr } = await supabase.from('categories').select('id, slug, label, db_category, parent_id').eq('is_active', true);
      if (catErr) throw catErr;
      let classifications;
      try {
        classifications = await classifyProductsForCategories(items.map(it => String(it.name || '')), existingCategories, aiConfig);
      } catch (aiErr) {
        return res.status(502).json({ error: 'AI Request Failed', message: aiErr.message, timestamp: new Date().toISOString() });
      }
      const resolved = await resolveAutoClassifiedCategories(classifications, existingCategories);
      perItemCategory = resolved.finalCategories.map(f => f.db_category);
      categorySummary = {
        new_categories_created: resolved.created.map(c => ({ slug: c.slug, label: c.label, parent_id: c.parent_id })),
        new_categories_rejected: resolved.rejected // 개수 부족 등으로 새로 만들지 않고 fallback으로 대체된 제안들(참고용)
      };
    }

    const results = { imported: [], skipped_duplicate: [], failed: [] };
    for (let idx = 0; idx < items.length; idx++) {
      const raw = items[idx];
      const externalId = String(raw.external_id || '').trim();
      const name = String(raw.name || '').trim();
      const price = Number(raw.price);
      const itemCategory = category || perItemCategory[idx];
      if (!externalId || !name || !Number.isFinite(price) || price <= 0) {
        results.failed.push({ external_id: externalId, reason: '필수 정보(상품명/가격)가 올바르지 않습니다' });
        continue;
      }
      const { data: dup } = await supabase.from('supplier_product_imports').select('id').eq('supplier_key', supplierKey).eq('external_id', externalId).maybeSingle();
      if (dup) {
        results.skipped_duplicate.push({ external_id: externalId, name });
        continue;
      }
      const { data: created, error: insertErr } = await supabase.from('products_with').insert([{
        name,
        slug: slugify(name) + '-' + Date.now().toString(36),
        description: `외부 공급사(${supplierKey === 'domeggook' ? '도매매' : supplierKey})에서 가져온 상품입니다.`,
        price,
        category: itemCategory,
        stock: Number.isFinite(Number(raw.stock)) ? Number(raw.stock) : 0,
        images_urls: raw.image_url ? [raw.image_url] : [],
        supplier_id: req.user.id,
        status: 'active'
      }]).select().single();
      if (insertErr) {
        results.failed.push({ external_id: externalId, reason: insertErr.message });
        continue;
      }
      await supabase.from('supplier_product_imports').insert([{ supplier_key: supplierKey, external_id: externalId, product_id: created.id }]);
      // 신규 행이라 동시성 문제가 없으므로 초기재고는 그대로 두고, 재고원장에는 "신규 등록" 이벤트만 추적용으로 남긴다
      if (Number(created.stock) > 0) {
        await supabase.from('stock_adjustments_with').insert([{ product_id: created.id, variant_id: null, delta: Number(created.stock), reason: '외부 공급사 일괄 등록', created_by: req.user.id, scan_source: 'admin_manual' }]);
      }
      results.imported.push({ external_id: externalId, name, product_id: created.id, category: itemCategory });
    }
    if (categorySummary) results.category_summary = categorySummary;

    res.json({ success: true, data: results, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error importing supplier products:', err);
    res.status(500).json({ error: 'Failed to import supplier products', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 📄 엑셀/CSV 상품 일괄 등록
// - 카페24 관리자 대시보드를 실제로 열어본 결과, "상품목록 > 엑셀다운로드"로 기존에 운영 중인 쇼핑몰의
//   실제 상품 데이터를 그대로 뽑아낼 수 있다는 것을 확인했다. 도매매 API 키가 아직 없어도(사업자 인증 전)
//   형님이 이미 갖고 있는 실제 상품 데이터(카페24든 직접 만든 엑셀이든)를 바로 우리 플랫폼에 옮겨올 수 있도록
//   범용 엑셀/CSV 업로드 등록 기능을 추가한다. 파일 파싱은 관리자 화면(브라우저)에서 SheetJS로 하고,
//   서버는 이미 파싱되어 넘어온 행(items) 배열만 검증 후 저장한다.
// - 같은 이름의 상품이 이미 등록되어 있으면(같은 판매자 기준) 중복 등록을 막기 위해 건너뛴다.
// ============================================
app.post('/api/admin/products/bulk-import', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { items, category } = req.body;
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Bad Request', message: '등록할 상품(items)이 없습니다', timestamp: new Date().toISOString() });
    }
    if (items.length > 500) {
      return res.status(400).json({ error: 'Bad Request', message: '한 번에 최대 500건까지 등록할 수 있습니다. 파일을 나눠서 올려주세요', timestamp: new Date().toISOString() });
    }

    // category를 명시적으로 지정하지 않으면 AI가 상품명을 보고 하나씩 알맞은 카테고리로 자동분류한다(없으면 적당한 선에서 새로 만듦).
    // category를 지정하면 예전처럼 전체 상품에 그 카테고리 하나를 그대로 적용한다(관리자가 명시적으로 원할 때를 위한 기존 동작 유지).
    let perItemCategory = null;
    let categorySummary = null;
    if (!category) {
      const aiConfig = await getAiConfig('anthropic');
      if (!aiConfig || !aiConfig.enabled || !aiConfig.api_key) {
        return res.status(400).json({ error: 'Bad Request', message: '카테고리를 지정하지 않으셨습니다. AI 자동분류를 쓰려면 "⚙️ 설정"에서 Anthropic API 키를 등록·활성화하시거나, 등록할 카테고리를 직접 선택해주세요', timestamp: new Date().toISOString() });
      }
      const { data: existingCategories, error: catErr } = await supabase.from('categories').select('id, slug, label, db_category, parent_id').eq('is_active', true);
      if (catErr) throw catErr;
      let classifications;
      try {
        classifications = await classifyProductsForCategories(items.map(it => String(it.name || '')), existingCategories, aiConfig);
      } catch (aiErr) {
        return res.status(502).json({ error: 'AI Request Failed', message: aiErr.message, timestamp: new Date().toISOString() });
      }
      const resolved = await resolveAutoClassifiedCategories(classifications, existingCategories);
      perItemCategory = resolved.finalCategories.map(f => f.db_category);
      categorySummary = {
        new_categories_created: resolved.created.map(c => ({ slug: c.slug, label: c.label, parent_id: c.parent_id })),
        new_categories_rejected: resolved.rejected
      };
    }

    // 이 판매자가 이미 등록해둔 상품명 목록(중복 등록 방지용) - 대소문자/공백 무시하고 비교
    const { data: existingProducts } = await supabase.from('products_with').select('name').eq('supplier_id', req.user.id);
    const existingNames = new Set((existingProducts || []).map(p => String(p.name || '').trim().toLowerCase()));

    const results = { imported: [], skipped_duplicate: [], failed: [] };
    for (let idx = 0; idx < items.length; idx++) {
      const raw = items[idx];
      const name = String(raw.name || '').trim();
      const price = Number(raw.price);
      const itemCategory = category || perItemCategory[idx];
      if (!name || !Number.isFinite(price) || price <= 0) {
        results.failed.push({ name: name || '(이름없음)', reason: '필수 정보(상품명/가격)가 올바르지 않습니다' });
        continue;
      }
      const nameKey = name.toLowerCase();
      if (existingNames.has(nameKey)) {
        results.skipped_duplicate.push({ name });
        continue;
      }
      const discountPrice = Number(raw.discount_price);
      const stock = Number(raw.stock);

      const { data: created, error: insertErr } = await supabase.from('products_with').insert([{
        name,
        slug: slugify(name),
        description: (raw.description && String(raw.description).trim()) || '엑셀/CSV 일괄 등록으로 추가된 상품입니다.',
        price,
        discount_price: Number.isFinite(discountPrice) && discountPrice > 0 && discountPrice < price ? discountPrice : null,
        category: itemCategory,
        stock: Number.isFinite(stock) && stock >= 0 ? stock : 0,
        images_urls: raw.image_url ? [String(raw.image_url).trim()] : [],
        supplier_id: req.user.id,
        status: 'active'
      }]).select().single();

      if (insertErr) {
        results.failed.push({ name, reason: insertErr.message });
        continue;
      }
      existingNames.add(nameKey); // 같은 파일 안에서의 중복도 함께 방지
      // 신규 행이라 동시성 문제가 없으므로 초기재고는 그대로 두고, 재고원장에는 "신규 등록" 이벤트만 추적용으로 남긴다
      if (Number(created.stock) > 0) {
        await supabase.from('stock_adjustments_with').insert([{ product_id: created.id, variant_id: null, delta: Number(created.stock), reason: '엑셀/CSV 일괄 등록', created_by: req.user.id, scan_source: 'admin_manual' }]);
      }
      results.imported.push({ name, product_id: created.id, category: itemCategory });
    }
    if (categorySummary) results.category_summary = categorySummary;

    res.json({ success: true, data: results, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error bulk-importing products from file:', err);
    res.status(500).json({ error: 'Failed to bulk-import products', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 💳 결제(PG) 연동 - 토스페이먼츠 (카페24 관리자의 "카페24페이먼츠(PG)" 메뉴를 확인해본 결과 정리)
// - 카페24페이먼츠는 카페24가 호스팅하는 쇼핑몰 전용 결제 기능(토스페이먼츠·나이스정보통신을 파트너PG로 사용)이라
//   카페24 밖에 있는 우리 플랫폼(별도 Node.js 서버)에서 그 API를 직접 가져다 쓸 수는 없다는 것을 확인했다.
// - 다만 카페24페이먼츠가 쓰는 파트너PG인 토스페이먼츠는 그 자체로 어떤 웹사이트에도 붙일 수 있는
//   독립적인 결제 API/SDK를 공식 제공하고(docs.tosspayments.com), 회원가입 없이도 테스트 키로 바로 연동
//   테스트가 가능하다 - 그래서 카페24페이먼츠가 아니라 토스페이먼츠를 직접 붙이는 방식으로 구현했다.
// - 요청 URL/파라미터명(위젯 SDK, requestPayment, /v1/payments/confirm, Basic Auth 방식)은
//   토스페이먼츠 공식 문서와 공식 블로그에서 실제로 확인된 내용을 그대로 반영했다.
// - 다만 테스트/실서비스 키 자체는 형님(또는 판매자 계정)이 발급받아 아래 관리자 화면에 입력해야 한다
//   (임의로 만든 키를 넣어두지 않음 - 정직하게, 실제 키가 있어야만 동작).
// ============================================
async function getPgConfig(providerKey) {
  const { data, error } = await supabase.from('pg_configs').select('*').eq('provider_key', providerKey).maybeSingle();
  if (error) throw error;
  return data;
}

// 공개: 결제 위젯 초기화에 필요한 정보만(클라이언트 키는 원래 프론트엔드에 노출되는 값이라 비밀이 아님 - secret_key는 여기 포함 안 함)
app.get('/api/payments/toss/config', async (req, res) => {
  try {
    const config = await getPgConfig('toss');
    if (!config || !config.enabled || !config.client_key) {
      return res.json({ success: true, data: { enabled: false }, timestamp: new Date().toISOString() });
    }
    res.json({ success: true, data: { enabled: true, clientKey: config.client_key, mode: config.mode }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching toss config:', err);
    res.status(500).json({ error: 'Failed to fetch payment config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 연동 현황 조회 (secret_key 원문은 절대 응답에 포함하지 않음)
app.get('/api/admin/payment-gateway', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const config = await getPgConfig('toss');
    if (!config) return res.status(404).json({ error: 'Not Found', message: '결제 연동 정보를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({
      success: true,
      data: {
        provider_key: config.provider_key,
        provider_name: config.provider_name,
        client_key: config.client_key || null, // 클라이언트 키는 원래 공개되는 값이므로 그대로 보여줌
        has_secret_key: !!config.secret_key,
        mode: config.mode,
        enabled: config.enabled,
        last_tested_at: config.last_tested_at,
        last_test_status: config.last_test_status,
        last_test_message: config.last_test_message
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching payment gateway config:', err);
    res.status(500).json({ error: 'Failed to fetch payment gateway config', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.patch('/api/admin/payment-gateway', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const update = { updated_at: new Date().toISOString() };
    if (typeof req.body.client_key === 'string') update.client_key = req.body.client_key.trim() || null;
    if (typeof req.body.secret_key === 'string') update.secret_key = req.body.secret_key.trim() || null;
    if (req.body.mode === 'test' || req.body.mode === 'live') update.mode = req.body.mode;
    if (typeof req.body.enabled === 'boolean') update.enabled = req.body.enabled;

    const { data, error } = await supabase.from('pg_configs').update(update).eq('provider_key', 'toss').select().single();
    if (error) throw error;
    res.json({ success: true, data: { client_key: data.client_key, has_secret_key: !!data.secret_key, mode: data.mode, enabled: data.enabled }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating payment gateway config:', err);
    res.status(500).json({ error: 'Failed to update payment gateway config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 연결 테스트: 일부러 존재하지 않는 결제건으로 승인 API를 호출해본다 - 시크릿 키가 틀리면 401(인증 실패)이,
// 시크릿 키가 맞으면 "존재하지 않는 결제"류의 400이 돌아온다(토스 서버에 실제로 도달해 인증까지 통과했다는 뜻)
app.post('/api/admin/payment-gateway/test', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const config = await getPgConfig('toss');
    if (!config || !config.secret_key) {
      return res.status(400).json({ error: 'Bad Request', message: '시크릿 키가 등록되어 있지 않습니다. 먼저 키를 저장해주세요.', timestamp: new Date().toISOString() });
    }
    let status, message;
    try {
      const authHeader = 'Basic ' + Buffer.from(config.secret_key + ':').toString('base64');
      const resp = await fetch('https://api.tosspayments.com/v1/payments/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: authHeader },
        body: JSON.stringify({ paymentKey: 'test-connection-check', orderId: 'test-connection-check', amount: 1 }),
        signal: AbortSignal.timeout(15000)
      });
      const json = await resp.json().catch(() => null);
      if (resp.status === 401) {
        status = 'failed';
        message = '시크릿 키 인증에 실패했습니다(HTTP 401). 키가 올바른지 확인해주세요. ' + (json?.message || '');
      } else if (resp.status >= 200 && resp.status < 500) {
        // 400 등으로 거절되더라도, 토스 서버에 실제로 도달해서 "인증은 통과하고 결제건을 못 찾았다"는 정상적인 응답이면 연동 자체는 성공
        status = 'success';
        message = `토스페이먼츠 서버에 정상적으로 인증되었습니다(HTTP ${resp.status}). 응답: ${json?.message || JSON.stringify(json)}`;
      } else {
        status = 'failed';
        message = `토스페이먼츠 서버 응답이 예상과 다릅니다(HTTP ${resp.status})`;
      }
    } catch (callErr) {
      status = 'failed';
      message = '토스페이먼츠 서버 호출에 실패했습니다: ' + callErr.message;
    }
    await supabase.from('pg_configs').update({ last_tested_at: new Date().toISOString(), last_test_status: status, last_test_message: message }).eq('provider_key', 'toss');
    res.json({ success: true, data: { status, message }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error testing payment gateway:', err);
    res.status(500).json({ error: 'Failed to test payment gateway', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 결제 승인: 토스 결제창에서 돌아온 뒤 프론트엔드가 이 API를 호출해 실제로 결제를 확정한다.
// 클라이언트가 보낸 금액을 그대로 믿지 않고, 반드시 우리 DB에 저장된 주문 금액과 대조해서 위변조를 막는다.
app.post('/api/payments/toss/confirm', authenticate, async (req, res) => {
  try {
    const { paymentKey, orderId, amount } = req.body;
    if (!paymentKey || !orderId || !Number.isFinite(Number(amount))) {
      return res.status(400).json({ error: 'Bad Request', message: 'paymentKey, orderId, amount가 모두 필요합니다', timestamp: new Date().toISOString() });
    }

    const { data: order, error: orderErr } = await supabase.from('orders_with').select('*').eq('order_number', orderId).eq('user_id', req.user.id).maybeSingle();
    if (orderErr) throw orderErr;
    if (!order) return res.status(404).json({ error: 'Not Found', message: '주문을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (order.status !== 'pending') {
      return res.status(400).json({ error: 'Bad Request', message: `이미 처리된 주문입니다 (현재 상태: ${order.status})`, timestamp: new Date().toISOString() });
    }
    if (Math.round(Number(order.final_price)) !== Math.round(Number(amount))) {
      return res.status(400).json({ error: 'Bad Request', message: '결제 금액이 주문 금액과 일치하지 않습니다', timestamp: new Date().toISOString() });
    }

    const config = await getPgConfig('toss');
    if (!config || !config.enabled || !config.secret_key) {
      return res.status(400).json({ error: 'Bad Request', message: '결제 연동이 활성화되어 있지 않습니다', timestamp: new Date().toISOString() });
    }

    const authHeader = 'Basic ' + Buffer.from(config.secret_key + ':').toString('base64');
    const tossResp = await fetch('https://api.tosspayments.com/v1/payments/confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: authHeader },
      body: JSON.stringify({ paymentKey, orderId, amount: Number(amount) }),
      signal: AbortSignal.timeout(20000)
    });
    const tossJson = await tossResp.json().catch(() => null);

    if (tossResp.ok) {
      await supabase.from('order_payments').insert([{ order_id: order.id, provider_key: 'toss', payment_key: paymentKey, amount: Number(amount), status: 'approved', raw_response: tossJson }]);
      await supabase.from('orders_with').update({ status: 'paid', payment_method: 'toss' }).eq('id', order.id);
      return res.json({ success: true, data: { order_number: order.order_number, status: 'paid' }, timestamp: new Date().toISOString() });
    } else {
      await supabase.from('order_payments').insert([{ order_id: order.id, provider_key: 'toss', payment_key: paymentKey, amount: Number(amount), status: 'failed', raw_response: tossJson }]);
      return res.status(400).json({ error: 'Payment Failed', message: tossJson?.message || '결제 승인에 실패했습니다', timestamp: new Date().toISOString() });
    }
  } catch (err) {
    console.error('Error confirming toss payment:', err);
    res.status(500).json({ error: 'Failed to confirm payment', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 💳 결제(PG) 연동 - 카카오페이 / 네이버페이 간편결제 (토스페이먼츠와 동일한 pg_configs 패턴 재사용)
// - "2순위부터 차례로 진행해줘" 5번(카카오페이/네이버페이 간편결제 추가) 작업.
// - 카카오페이: developers.kakaopay.com 문서 기준 신규(2024~) 온라인결제 API(open-api.kakaopay.com,
//   Authorization: "SECRET_KEY {키}")를 사용했다. 공개 테스트 CID(TC0ONETIME)와 개발용 시크릿 키는
//   카카오 계정으로 개발자센터에 "애플리케이션"을 등록하면 사업자등록 없이 형님이 직접 바로 발급받을 수 있다.
// - 네이버페이: 공식 "결제형 독립몰 연동 개발가이드" 기준으로 작성했다. 다만 네이버페이는 토스/카카오와 달리
//   가맹 심사(사업자 확인 등)가 완료되어야 Client-Id/Client-Secret/파트너ID를 발급해준다고 안내되어 있어
//   (심사 전에는 자가발급 테스트 키 자체가 없음), 이번 라운드에서는 코드는 문서에 나온 요청/응답 필드명
//   그대로 준비해뒀지만 실제 키로 끝까지 호출 성공을 확인하지는 못했다 - 형님이 가맹 심사를 통과해 실제
//   발급받은 개발가이드와 API 경로(reserve/apply)가 다르면 바로 맞춰 고치겠다(정직하게 밝혀둠).
// - 두 PG 모두 결제창을 서버가 먼저 열어주는(ready/reserve) 방식이라, 토스처럼 브라우저에 시크릿 키가
//   노출될 일이 없다(요청은 항상 우리 서버 → 카카오/네이버 서버로만 나간다).
// ============================================
const SIMPLE_PAY_PROVIDERS = {
  kakaopay: { name: '카카오페이' },
  naverpay: { name: '네이버페이' }
};

// 공개: 결제 버튼을 보여줄지 여부만 노출 (시크릿 키는 절대 포함 안 함)
app.get('/api/payments/:provider/config', async (req, res) => {
  try {
    const provider = req.params.provider;
    if (!SIMPLE_PAY_PROVIDERS[provider]) return res.status(404).json({ error: 'Not Found', message: '지원하지 않는 결제수단입니다', timestamp: new Date().toISOString() });
    const config = await getPgConfig(provider);
    if (!config || !config.enabled || !config.client_key || !config.secret_key) {
      return res.json({ success: true, data: { enabled: false }, timestamp: new Date().toISOString() });
    }
    res.json({ success: true, data: { enabled: true, mode: config.mode }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error(`Error fetching ${req.params.provider} config:`, err);
    res.status(500).json({ error: 'Failed to fetch payment config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 카카오페이/네이버페이 연동 현황 조회 (secret_key 원문은 절대 응답에 포함하지 않음) - 토스와 동일 패턴
app.get('/api/admin/payment-gateway/:provider', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const provider = req.params.provider;
    if (!SIMPLE_PAY_PROVIDERS[provider]) return res.status(404).json({ error: 'Not Found', message: '지원하지 않는 결제수단입니다', timestamp: new Date().toISOString() });
    const config = await getPgConfig(provider);
    if (!config) return res.status(404).json({ error: 'Not Found', message: '결제 연동 정보를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({
      success: true,
      data: {
        provider_key: config.provider_key,
        provider_name: config.provider_name,
        client_key: config.client_key || null, // 카카오페이는 CID, 네이버페이는 Client-Id (둘 다 비밀값이 아님)
        has_secret_key: !!config.secret_key, // 카카오페이는 SECRET_KEY, 네이버페이는 Client-Secret
        extra_config: config.extra_config || {}, // 네이버페이 파트너 ID 등 공급자별 추가 값
        mode: config.mode,
        enabled: config.enabled,
        last_tested_at: config.last_tested_at,
        last_test_status: config.last_test_status,
        last_test_message: config.last_test_message
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching payment gateway config:', err);
    res.status(500).json({ error: 'Failed to fetch payment gateway config', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.patch('/api/admin/payment-gateway/:provider', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const provider = req.params.provider;
    if (!SIMPLE_PAY_PROVIDERS[provider]) return res.status(404).json({ error: 'Not Found', message: '지원하지 않는 결제수단입니다', timestamp: new Date().toISOString() });
    const current = await getPgConfig(provider);
    if (!current) return res.status(404).json({ error: 'Not Found', message: '결제 연동 정보를 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const update = { updated_at: new Date().toISOString() };
    if (typeof req.body.client_key === 'string') update.client_key = req.body.client_key.trim() || null;
    if (typeof req.body.secret_key === 'string') update.secret_key = req.body.secret_key.trim() || null;
    if (req.body.mode === 'test' || req.body.mode === 'live') update.mode = req.body.mode;
    if (typeof req.body.enabled === 'boolean') update.enabled = req.body.enabled;
    if (req.body.extra_config && typeof req.body.extra_config === 'object') {
      update.extra_config = { ...(current.extra_config || {}), ...req.body.extra_config };
    }

    const { data, error } = await supabase.from('pg_configs').update(update).eq('provider_key', provider).select().single();
    if (error) throw error;
    res.json({ success: true, data: { client_key: data.client_key, has_secret_key: !!data.secret_key, extra_config: data.extra_config, mode: data.mode, enabled: data.enabled }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating payment gateway config:', err);
    res.status(500).json({ error: 'Failed to update payment gateway config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 연결 테스트: 실제로 카카오페이/네이버페이 서버에 결제 준비 요청을 보내 키가 유효한지 확인한다
// (일부러 실패할 값을 보내는 토스와 달리, 카카오/네이버의 "준비" API는 정상 키면 그 자체로 성공 응답이 온다 -
//  실제로 결제되는 건 아니고 사용자가 완료하지 않으면 자동 만료되는 미완료 세션이 하나 생길 뿐이다)
app.post('/api/admin/payment-gateway/:provider/test', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const provider = req.params.provider;
    if (!SIMPLE_PAY_PROVIDERS[provider]) return res.status(404).json({ error: 'Not Found', message: '지원하지 않는 결제수단입니다', timestamp: new Date().toISOString() });
    const config = await getPgConfig(provider);
    if (!config || !config.secret_key || !config.client_key) {
      return res.status(400).json({ error: 'Bad Request', message: '키가 모두 등록되어 있지 않습니다. 먼저 키를 저장해주세요.', timestamp: new Date().toISOString() });
    }
    let status, message;
    const baseUrl = getBaseUrl(req);
    try {
      if (provider === 'kakaopay') {
        const resp = await fetch('https://open-api.kakaopay.com/online/v1/payment/ready', {
          method: 'POST',
          headers: { Authorization: 'SECRET_KEY ' + config.secret_key, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            cid: config.client_key, partner_order_id: 'connection-check', partner_user_id: 'connection-check',
            item_name: '연동 테스트', quantity: 1, total_amount: 100, tax_free_amount: 0,
            approval_url: `${baseUrl}/api/payments/kakaopay/approve`, cancel_url: `${baseUrl}/`, fail_url: `${baseUrl}/`
          }),
          signal: AbortSignal.timeout(15000)
        });
        const json = await resp.json().catch(() => null);
        if (resp.status === 401) { status = 'failed'; message = `SECRET_KEY 인증에 실패했습니다(HTTP 401). ${json?.error_message || json?.msg || ''}`; }
        else if (resp.status === 200 && json?.tid) { status = 'success'; message = `카카오페이 서버에 정상적으로 인증되어 결제 준비까지 성공했습니다(tid: ${json.tid}, 사용자가 완료하지 않으면 자동 만료됩니다)`; }
        else { status = 'failed'; message = `카카오페이 서버 응답이 예상과 다릅니다(HTTP ${resp.status}). CID가 올바른지 확인해주세요. ${json?.error_message || json?.msg || JSON.stringify(json)}`; }
      } else if (provider === 'naverpay') {
        const partnerId = (config.extra_config && config.extra_config.partner_id) || '';
        if (!partnerId) { status = 'failed'; message = '네이버페이 파트너 ID(extra_config.partner_id)가 등록되어 있지 않습니다.'; }
        else {
          const domain = config.mode === 'live' ? 'apis.naver.com' : 'dev.apis.naver.com';
          const resp = await fetch(`https://${domain}/${partnerId}/naverpay/payments/v2.2/reserve`, {
            method: 'POST',
            headers: { 'X-Naver-Client-Id': config.client_key, 'X-Naver-Client-Secret': config.secret_key, 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ merchantPayKey: 'connection-check', productName: '연동 테스트', totalPayAmount: '100', taxScopeAmount: '100', taxExScopeAmount: '0', productCount: '1', returnUrl: `${baseUrl}/` }).toString(),
            signal: AbortSignal.timeout(15000)
          });
          const json = await resp.json().catch(() => null);
          if (resp.status === 401 || resp.status === 403) { status = 'failed'; message = `Client-Id/Client-Secret 인증에 실패했습니다(HTTP ${resp.status}).`; }
          else if (resp.ok) { status = 'success'; message = `네이버페이 서버에 정상적으로 인증되어 결제 예약까지 성공했습니다.`; }
          else { status = 'failed'; message = `네이버페이 서버 응답이 예상과 다릅니다(HTTP ${resp.status}). 파트너 ID가 올바른지 확인해주세요. ${JSON.stringify(json)}`; }
        }
      }
    } catch (callErr) {
      status = 'failed';
      message = `${SIMPLE_PAY_PROVIDERS[provider].name} 서버 호출에 실패했습니다: ${callErr.message}`;
    }
    await supabase.from('pg_configs').update({ last_tested_at: new Date().toISOString(), last_test_status: status, last_test_message: message }).eq('provider_key', provider);
    res.json({ success: true, data: { status, message }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error testing payment gateway:', err);
    res.status(500).json({ error: 'Failed to test payment gateway', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 카카오페이 결제 준비: 주문 접수 직후 프론트엔드가 이 API를 호출해 카카오페이 결제창 URL을 받는다
app.post('/api/orders/:id/kakaopay/ready', authenticate, async (req, res) => {
  try {
    const { data: order, error: orderErr } = await supabase.from('orders_with').select('*').eq('id', req.params.id).eq('user_id', req.user.id).maybeSingle();
    if (orderErr) throw orderErr;
    if (!order) return res.status(404).json({ error: 'Not Found', message: '주문을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (order.status !== 'pending') return res.status(400).json({ error: 'Bad Request', message: `이미 처리된 주문입니다 (현재 상태: ${order.status})`, timestamp: new Date().toISOString() });

    const config = await getPgConfig('kakaopay');
    if (!config || !config.enabled || !config.secret_key || !config.client_key) {
      return res.status(400).json({ error: 'Bad Request', message: '카카오페이 연동이 활성화되어 있지 않습니다', timestamp: new Date().toISOString() });
    }

    const baseUrl = getBaseUrl(req);
    const amount = Math.round(Number(order.final_price));
    const resp = await fetch('https://open-api.kakaopay.com/online/v1/payment/ready', {
      method: 'POST',
      headers: { Authorization: 'SECRET_KEY ' + config.secret_key, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        cid: config.client_key, partner_order_id: order.order_number, partner_user_id: order.user_id,
        item_name: `WITH+ 주문 (${order.order_number})`.slice(0, 100), quantity: 1, total_amount: amount, tax_free_amount: 0,
        approval_url: `${baseUrl}/api/payments/kakaopay/approve?order_id=${order.id}`,
        cancel_url: `${baseUrl}/payment-result.html?provider=kakaopay&status=cancel&order=${encodeURIComponent(order.order_number)}`,
        fail_url: `${baseUrl}/payment-result.html?provider=kakaopay&status=fail&order=${encodeURIComponent(order.order_number)}`
      }),
      signal: AbortSignal.timeout(15000)
    });
    const json = await resp.json().catch(() => null);
    if (!resp.ok || !json?.tid) {
      return res.status(400).json({ error: 'Payment Ready Failed', message: json?.error_message || json?.msg || '카카오페이 결제 준비에 실패했습니다', timestamp: new Date().toISOString() });
    }
    await supabase.from('order_payments').insert([{ order_id: order.id, provider_key: 'kakaopay', payment_key: json.tid, amount, status: 'requested', raw_response: json }]);
    res.json({ success: true, data: { redirect_url: json.next_redirect_pc_url, redirect_url_mobile: json.next_redirect_mobile_url }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error preparing kakaopay payment:', err);
    res.status(500).json({ error: 'Failed to prepare kakaopay payment', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 카카오페이 결제 승인 콜백: 사용자가 카카오페이 결제창에서 결제를 완료하면 브라우저가 이 URL로 리다이렉트된다
app.get('/api/payments/kakaopay/approve', async (req, res) => {
  const redirectFail = (orderNumber, reason) => res.redirect(`/payment-result.html?provider=kakaopay&status=fail${orderNumber ? `&order=${encodeURIComponent(orderNumber)}` : ''}${reason ? `&reason=${encodeURIComponent(reason)}` : ''}`);
  try {
    const { order_id, pg_token } = req.query;
    if (!order_id || !pg_token) return redirectFail(null, 'missing_params');

    const { data: order, error: orderErr } = await supabase.from('orders_with').select('*').eq('id', order_id).maybeSingle();
    if (orderErr) throw orderErr;
    if (!order) return redirectFail(null, 'order_not_found');

    const { data: payment, error: paymentErr } = await supabase.from('order_payments').select('*').eq('order_id', order.id).eq('provider_key', 'kakaopay').eq('status', 'requested').order('created_at', { ascending: false }).limit(1).maybeSingle();
    if (paymentErr) throw paymentErr;
    if (!payment) return redirectFail(order.order_number, 'no_ready_session');

    const config = await getPgConfig('kakaopay');
    if (!config || !config.secret_key || !config.client_key) return redirectFail(order.order_number, 'config_missing');

    const resp = await fetch('https://open-api.kakaopay.com/online/v1/payment/approve', {
      method: 'POST',
      headers: { Authorization: 'SECRET_KEY ' + config.secret_key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ cid: config.client_key, tid: payment.payment_key, partner_order_id: order.order_number, partner_user_id: order.user_id, pg_token }),
      signal: AbortSignal.timeout(15000)
    });
    const json = await resp.json().catch(() => null);

    if (resp.ok) {
      await supabase.from('order_payments').update({ status: 'approved', raw_response: json }).eq('id', payment.id);
      await supabase.from('orders_with').update({ status: 'paid', payment_method: 'kakaopay' }).eq('id', order.id);
      return res.redirect(`/payment-result.html?provider=kakaopay&status=success&order=${encodeURIComponent(order.order_number)}`);
    } else {
      await supabase.from('order_payments').update({ status: 'failed', raw_response: json }).eq('id', payment.id);
      return redirectFail(order.order_number, 'approve_rejected');
    }
  } catch (err) {
    console.error('Error approving kakaopay payment:', err);
    return redirectFail(null, 'server_error');
  }
});

// 네이버페이 결제 예약: 주문 접수 직후 프론트엔드가 이 API를 호출해 네이버페이 결제창 URL을 받는다
app.post('/api/orders/:id/naverpay/reserve', authenticate, async (req, res) => {
  try {
    const { data: order, error: orderErr } = await supabase.from('orders_with').select('*').eq('id', req.params.id).eq('user_id', req.user.id).maybeSingle();
    if (orderErr) throw orderErr;
    if (!order) return res.status(404).json({ error: 'Not Found', message: '주문을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (order.status !== 'pending') return res.status(400).json({ error: 'Bad Request', message: `이미 처리된 주문입니다 (현재 상태: ${order.status})`, timestamp: new Date().toISOString() });

    const config = await getPgConfig('naverpay');
    const partnerId = config && config.extra_config && config.extra_config.partner_id;
    if (!config || !config.enabled || !config.secret_key || !config.client_key || !partnerId) {
      return res.status(400).json({ error: 'Bad Request', message: '네이버페이 연동이 활성화되어 있지 않습니다', timestamp: new Date().toISOString() });
    }

    const baseUrl = getBaseUrl(req);
    const amount = Math.round(Number(order.final_price));
    const domain = config.mode === 'live' ? 'apis.naver.com' : 'dev.apis.naver.com';
    const resp = await fetch(`https://${domain}/${partnerId}/naverpay/payments/v2.2/reserve`, {
      method: 'POST',
      headers: { 'X-Naver-Client-Id': config.client_key, 'X-Naver-Client-Secret': config.secret_key, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        merchantPayKey: order.order_number, productName: `WITH+ 주문 (${order.order_number})`.slice(0, 100),
        totalPayAmount: String(amount), taxScopeAmount: String(amount), taxExScopeAmount: '0', productCount: '1',
        returnUrl: `${baseUrl}/api/payments/naverpay/approve?order_id=${order.id}`
      }).toString(),
      signal: AbortSignal.timeout(15000)
    });
    const json = await resp.json().catch(() => null);
    const reserveId = json?.body?.reserveId || json?.reserveId;
    if (!resp.ok || !reserveId) {
      return res.status(400).json({ error: 'Payment Reserve Failed', message: json?.message || '네이버페이 결제 예약에 실패했습니다', timestamp: new Date().toISOString() });
    }
    await supabase.from('order_payments').insert([{ order_id: order.id, provider_key: 'naverpay', payment_key: reserveId, amount, status: 'requested', raw_response: json }]);
    // 네이버페이는 결제창을 팝업/리다이렉트로 열 때 reserveId를 그대로 사용한다
    res.json({ success: true, data: { reserve_id: reserveId, mode: config.mode }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error reserving naverpay payment:', err);
    res.status(500).json({ error: 'Failed to reserve naverpay payment', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 네이버페이 결제 승인 콜백: 사용자가 네이버페이 결제창에서 결제를 완료하면 브라우저가 이 URL로 리다이렉트된다
app.get('/api/payments/naverpay/approve', async (req, res) => {
  const redirectFail = (orderNumber, reason) => res.redirect(`/payment-result.html?provider=naverpay&status=fail${orderNumber ? `&order=${encodeURIComponent(orderNumber)}` : ''}${reason ? `&reason=${encodeURIComponent(reason)}` : ''}`);
  try {
    const { order_id, paymentId, resultCode } = req.query;
    if (!order_id) return redirectFail(null, 'missing_params');

    const { data: order, error: orderErr } = await supabase.from('orders_with').select('*').eq('id', order_id).maybeSingle();
    if (orderErr) throw orderErr;
    if (!order) return redirectFail(null, 'order_not_found');

    if (resultCode && resultCode !== 'Success') return redirectFail(order.order_number, 'user_cancelled');
    if (!paymentId) return redirectFail(order.order_number, 'missing_payment_id');

    const { data: payment, error: paymentErr } = await supabase.from('order_payments').select('*').eq('order_id', order.id).eq('provider_key', 'naverpay').eq('status', 'requested').order('created_at', { ascending: false }).limit(1).maybeSingle();
    if (paymentErr) throw paymentErr;
    if (!payment) return redirectFail(order.order_number, 'no_reserve_session');

    const config = await getPgConfig('naverpay');
    const partnerId = config && config.extra_config && config.extra_config.partner_id;
    if (!config || !config.secret_key || !config.client_key || !partnerId) return redirectFail(order.order_number, 'config_missing');

    const domain = config.mode === 'live' ? 'apis.naver.com' : 'dev.apis.naver.com';
    const resp = await fetch(`https://${domain}/${partnerId}/naverpay/payments/v2.2/apply/payment`, {
      method: 'POST',
      headers: { 'X-Naver-Client-Id': config.client_key, 'X-Naver-Client-Secret': config.secret_key, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ paymentId }).toString(),
      signal: AbortSignal.timeout(15000)
    });
    const json = await resp.json().catch(() => null);

    if (resp.ok && json?.code === 'Success') {
      await supabase.from('order_payments').update({ status: 'approved', raw_response: json }).eq('id', payment.id);
      await supabase.from('orders_with').update({ status: 'paid', payment_method: 'naverpay' }).eq('id', order.id);
      return res.redirect(`/payment-result.html?provider=naverpay&status=success&order=${encodeURIComponent(order.order_number)}`);
    } else {
      await supabase.from('order_payments').update({ status: 'failed', raw_response: json }).eq('id', payment.id);
      return redirectFail(order.order_number, 'approve_rejected');
    }
  } catch (err) {
    console.error('Error approving naverpay payment:', err);
    return redirectFail(null, 'server_error');
  }
});

// ============================================
// 🔑 소셜 로그인(OAuth) - 구글/카카오/네이버
// - 구글/카카오는 Supabase Auth가 기본 제공하는 OAuth Provider라 서버 코드가 필요 없다. 관리자가
//   Supabase 대시보드(Authentication > Providers)에서 각 서비스의 클라이언트ID/시크릿을 등록해두면
//   프론트엔드의 supabase.auth.signInWithOAuth({ provider: 'google' | 'kakao' }) 호출만으로 전체
//   흐름(동의화면 → 콜백 → 세션발급)이 Supabase 쪽에서 자동으로 처리된다.
// - 네이버는 Supabase가 기본 제공하지 않는 제공자라, 토스페이먼츠/카카오페이와 동일한 패턴(관리자가
//   아래 관리자 화면에서 클라이언트ID/시크릿을 직접 등록)으로 서버가 OAuth 인가코드 흐름을 직접
//   처리한다. 네이버 프로필 조회까지 마친 뒤에는 우리가 직접 비밀번호나 세션 토큰을 만들지 않고,
//   Supabase의 매직링크 발급(admin.generateLink)을 재사용해 그 링크로 그대로 리다이렉트한다 -
//   Supabase가 링크를 검증하고 세션을 만들어 프론트엔드로 돌려준다.
// ============================================
async function getOauthConfig(providerKey) {
  const { data, error } = await supabase.from('oauth_configs').select('*').eq('provider_key', providerKey).maybeSingle();
  if (error) throw error;
  return data;
}

// state 파라미터: 별도의 서버 세션/쿠키 저장소 없이 JWT_SECRET으로 서명한 값을 그대로 왕복시켜
// CSRF를 방지한다(발급 후 10분 이내에만 유효 - 위조 방지는 HMAC 서명, 재생공격 방지는 만료시간).
function signNaverState() {
  const nonce = crypto.randomBytes(16).toString('hex');
  const ts = Date.now().toString();
  const payload = `${nonce}.${ts}`;
  const sig = crypto.createHmac('sha256', process.env.JWT_SECRET || RUNTIME_FALLBACK_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}
function verifyNaverState(state) {
  if (!state || typeof state !== 'string') return false;
  const parts = state.split('.');
  if (parts.length !== 3) return false;
  const [nonce, ts, sig] = parts;
  const payload = `${nonce}.${ts}`;
  const expected = crypto.createHmac('sha256', process.env.JWT_SECRET || RUNTIME_FALLBACK_SECRET).update(payload).digest('hex');
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  const age = Date.now() - Number(ts);
  if (!Number.isFinite(age) || age < 0 || age > 10 * 60 * 1000) return false; // 10분 초과 시 만료
  return true;
}

// 관리자: 네이버 로그인 연동 상태 조회 (시크릿 원문은 절대 응답에 포함하지 않음)
app.get('/api/admin/oauth-config/naver', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const config = await getOauthConfig('naver');
    if (!config) return res.status(404).json({ error: 'Not Found', message: '네이버 로그인 연동 정보를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({
      success: true,
      data: {
        provider_key: config.provider_key,
        provider_name: config.provider_name,
        client_id: config.client_id || null,
        has_client_secret: !!config.client_secret,
        enabled: config.enabled,
        callback_url: `${getBaseUrl(req)}/api/auth/naver/callback`,
        last_tested_at: config.last_tested_at,
        last_test_status: config.last_test_status,
        last_test_message: config.last_test_message
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching naver oauth config:', err);
    res.status(500).json({ error: 'Failed to fetch oauth config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 네이버 로그인 클라이언트ID/시크릿 저장 (시크릿은 입력값이 있을 때만 갱신 - 빈 값이면 기존 값 유지)
app.put('/api/admin/oauth-config/naver', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { client_id, client_secret, enabled } = req.body;
    const updates = { updated_at: new Date().toISOString() };
    if (client_id !== undefined) updates.client_id = client_id ? String(client_id).trim() : null;
    if (client_secret !== undefined && client_secret !== '') updates.client_secret = String(client_secret).trim();
    if (enabled !== undefined) updates.enabled = !!enabled;
    const { data, error } = await supabase.from('oauth_configs').update(updates).eq('provider_key', 'naver').select().maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '네이버 로그인 연동 정보를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({
      success: true,
      data: { provider_key: data.provider_key, client_id: data.client_id, has_client_secret: !!data.client_secret, enabled: data.enabled },
      message: '저장되었습니다',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error saving naver oauth config:', err);
    res.status(500).json({ error: 'Failed to save oauth config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 네이버 로그인 시작: 로그인 화면의 "네이버로 로그인" 버튼이 location.href로 이 URL에 직접 진입한다
app.get('/api/auth/naver/login', async (req, res) => {
  try {
    const config = await getOauthConfig('naver');
    if (!config || !config.enabled || !config.client_id || !config.client_secret) {
      return res.redirect('/login?social_error=' + encodeURIComponent('네이버 로그인이 아직 설정되지 않았습니다. 이메일로 로그인해주세요.'));
    }
    const state = signNaverState();
    const redirectUri = `${getBaseUrl(req)}/api/auth/naver/callback`;
    const authorizeUrl = 'https://nid.naver.com/oauth2.0/authorize?' + new URLSearchParams({
      response_type: 'code',
      client_id: config.client_id,
      redirect_uri: redirectUri,
      state
    }).toString();
    res.redirect(authorizeUrl);
  } catch (err) {
    console.error('Error starting naver oauth:', err);
    res.redirect('/login?social_error=' + encodeURIComponent('네이버 로그인을 시작하지 못했습니다. 잠시 후 다시 시도해주세요.'));
  }
});

// 네이버 로그인 콜백: 인가코드 → 토큰 교환 → 프로필 조회 → 이메일로 기존회원 매칭(없으면 신규가입,
// 비밀번호 없는 소셜 전용 계정) → Supabase 매직링크 발급받아 그 링크로 그대로 리다이렉트
app.get('/api/auth/naver/callback', async (req, res) => {
  const { code, state, error: naverError } = req.query;
  const failRedirect = (msg) => res.redirect('/login?social_error=' + encodeURIComponent(msg));
  try {
    if (naverError) return failRedirect('네이버 로그인이 취소되었거나 거부되었습니다.');
    if (!verifyNaverState(state)) return failRedirect('로그인 요청이 만료되었거나 올바르지 않습니다. 다시 시도해주세요.');
    if (!code) return failRedirect('네이버 로그인 인가코드를 받지 못했습니다.');

    const config = await getOauthConfig('naver');
    if (!config || !config.enabled || !config.client_id || !config.client_secret) {
      return failRedirect('네이버 로그인이 아직 설정되지 않았습니다.');
    }

    const redirectUri = `${getBaseUrl(req)}/api/auth/naver/callback`;
    const tokenResp = await fetch('https://nid.naver.com/oauth2.0/token?' + new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: config.client_id,
      client_secret: config.client_secret,
      code: String(code),
      state: String(state),
      redirect_uri: redirectUri
    }).toString(), { method: 'GET', signal: AbortSignal.timeout(15000) });
    const tokenJson = await tokenResp.json().catch(() => null);
    if (!tokenResp.ok || !tokenJson?.access_token) {
      console.error('Naver token exchange failed:', tokenJson);
      return failRedirect('네이버 인증 서버 응답에 실패했습니다. 잠시 후 다시 시도해주세요.');
    }

    const profileResp = await fetch('https://openapi.naver.com/v1/nid/me', {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` },
      signal: AbortSignal.timeout(15000)
    });
    const profileJson = await profileResp.json().catch(() => null);
    const naverProfile = profileJson?.response;
    if (!profileResp.ok || !naverProfile?.id) {
      console.error('Naver profile fetch failed:', profileJson);
      return failRedirect('네이버 프로필 정보를 가져오지 못했습니다.');
    }
    const email = naverProfile.email;
    if (!email) {
      return failRedirect('네이버 계정에 이메일 제공 동의가 필요합니다. 네이버 개인정보 설정에서 이메일 제공에 동의한 뒤 다시 시도해주세요.');
    }

    // 이미 가입된 이메일이면 그 계정 그대로 로그인, 처음이면 신규가입(비밀번호 없이 - 소셜 전용 계정)
    const { data: existingProfile } = await supabase.from('profiles').select('id').eq('email', email).maybeSingle();
    let userId = existingProfile?.id;
    if (!userId) {
      const { data: created, error: createErr } = await supabase.auth.admin.createUser({
        email,
        email_confirm: true,
        user_metadata: { full_name: naverProfile.name || null, oauth_provider: 'naver', naver_id: naverProfile.id }
      });
      if (createErr) {
        console.error('Error creating user from naver profile:', createErr);
        return failRedirect('회원 생성 중 오류가 발생했습니다: ' + createErr.message);
      }
      userId = created.user.id;
      // authenticate 미들웨어의 ensureProfileExists가 첫 API 호출 시에도 만들어주지만, 로그인 직후
      // 화면에서 바로 프로필 정보를 쓰는 경우를 대비해 여기서 선제적으로 만들어둔다.
      await supabase.from('profiles').upsert([{ id: userId, email, full_name: naverProfile.name || null, role: 'member', member_type: 'general' }], { onConflict: 'id', ignoreDuplicates: true });
    }

    const redirectTo = `${getBaseUrl(req)}/`;
    const { data: linkData, error: linkErr } = await supabase.auth.admin.generateLink({ type: 'magiclink', email, options: { redirectTo } });
    if (linkErr || !linkData?.properties?.action_link) {
      console.error('Error generating magic link for naver login:', linkErr);
      return failRedirect('로그인 세션 발급에 실패했습니다. 잠시 후 다시 시도해주세요.');
    }
    return res.redirect(linkData.properties.action_link);
  } catch (err) {
    console.error('Error in naver oauth callback:', err);
    return failRedirect('네이버 로그인 처리 중 오류가 발생했습니다.');
  }
});

// ============================================
// 📧 이메일 알림 (주문접수/상태변경) - 토스페이먼츠/AI연동과 동일한 패턴으로 관리자가 SMTP 계정정보를
// 직접 등록해야 실제로 발송된다(임의의 발신 계정을 코드에 넣어두지 않음 - 정직하게 미설정 시 발송 생략).
// nodemailer는 어떤 SMTP 제공자(네이버메일/Gmail 앱비밀번호/AWS SES/SendGrid 등)와도 동작하는
// 범용 라이브러리라 특정 벤더에 종속되지 않는다.
// ============================================
const nodemailer = require('nodemailer');

async function getEmailConfig() {
  const { data, error } = await supabase.from('email_configs_with').select('*').eq('provider_key', 'smtp').maybeSingle();
  if (error) throw error;
  return data;
}

function buildTransporter(config) {
  return nodemailer.createTransport({
    host: config.smtp_host,
    port: Number(config.smtp_port) || 587,
    secure: !!config.smtp_secure,
    auth: { user: config.smtp_user, pass: config.smtp_pass },
    // 발송 실패/무응답 SMTP 서버 때문에 주문 생성 같은 핵심 흐름이 오래 멈춰있지 않도록 타임아웃을 짧게 둔다
    connectionTimeout: 8000,
    greetingTimeout: 8000,
    socketTimeout: 8000
  });
}

// 실제 발송 + 결과를 email_logs_with에 정직하게 기록(성공/실패/미설정으로 건너뜀 모두 남긴다).
// 이 함수는 절대 예외를 던지지 않는다 - 이메일 발송 실패가 주문 생성 같은 핵심 흐름을 절대 막으면 안 되기 때문.
async function sendEmail({ to, subject, html, template, orderId }) {
  if (!to) {
    await supabase.from('email_logs_with').insert([{ to_email: '(없음)', template, subject, related_order_id: orderId || null, status: 'skipped', error_message: '수신자 이메일 주소가 없음' }]);
    return { sent: false, reason: 'no_recipient' };
  }
  let config;
  try {
    config = await getEmailConfig();
  } catch (err) {
    console.error('Error fetching email config:', err);
    config = null;
  }
  if (!config || !config.enabled || !config.smtp_host || !config.smtp_user || !config.smtp_pass) {
    await supabase.from('email_logs_with').insert([{ to_email: to, template, subject, related_order_id: orderId || null, status: 'skipped', error_message: 'SMTP 미설정 또는 비활성화 상태' }]);
    return { sent: false, reason: 'not_configured' };
  }
  try {
    const transporter = buildTransporter(config);
    await transporter.sendMail({
      from: `"${config.from_name || 'WITH+'}" <${config.from_email || config.smtp_user}>`,
      to, subject, html
    });
    await supabase.from('email_logs_with').insert([{ to_email: to, template, subject, related_order_id: orderId || null, status: 'sent' }]);
    return { sent: true };
  } catch (err) {
    console.error('Error sending email:', err.message);
    await supabase.from('email_logs_with').insert([{ to_email: to, template, subject, related_order_id: orderId || null, status: 'failed', error_message: err.message }]);
    return { sent: false, reason: 'send_error', error: err.message };
  }
}

const ORDER_STATUS_LABEL_KO = { pending: '주문 접수', paid: '결제 완료', processing: '상품 준비 중', shipped: '배송 중', delivered: '배송 완료', cancelled: '취소됨', refunded: '환불됨' };

function orderEmailLayout(title, bodyHtml) {
  return `<div style="font-family:'Apple SD Gothic Neo','Malgun Gothic',sans-serif; max-width:520px; margin:0 auto; padding:24px; border:1px solid #eee; border-radius:12px;">
    <h2 style="color:#E91E63; margin-top:0;">WITH+</h2>
    <h3>${title}</h3>
    ${bodyHtml}
    <p style="margin-top:24px; font-size:0.82em; color:#999;">본 메일은 WITH+ 주문 알림 발송 전용 주소로 발송되었습니다.</p>
  </div>`;
}

async function sendOrderConfirmationEmail(order, userEmail) {
  const itemsHtml = (Array.isArray(order.items) ? order.items : []).map(it => `<li>${it.name} x${it.quantity}</li>`).join('');
  const html = orderEmailLayout('주문이 접수되었습니다', `
    <p>주문번호: <b>${order.order_number}</b></p>
    <ul>${itemsHtml}</ul>
    <p>결제 예정 금액: <b>${Number(order.final_price).toLocaleString('ko-KR')}원</b>${Number(order.shipping_fee) > 0 ? ` (배송비 ${Number(order.shipping_fee).toLocaleString('ko-KR')}원 포함)` : ''}</p>`);
  return sendEmail({ to: userEmail, subject: `[WITH+] 주문이 접수되었습니다 (${order.order_number})`, html, template: 'order_confirmation', orderId: order.id });
}

async function sendOrderStatusEmail(order, userEmail, newStatus) {
  const label = ORDER_STATUS_LABEL_KO[newStatus] || newStatus;
  let extra = '';
  if (newStatus === 'shipped' && order.tracking_number) {
    extra = `<p>택배사: ${order.courier_name || '-'} / 운송장번호: ${order.tracking_number}</p>${order.tracking_url ? `<p><a href="${order.tracking_url}">배송조회 바로가기</a></p>` : ''}`;
  }
  const html = orderEmailLayout(`주문 상태가 변경되었습니다: ${label}`, `<p>주문번호: <b>${order.order_number}</b></p>${extra}`);
  return sendEmail({ to: userEmail, subject: `[WITH+] 주문 상태 변경: ${label} (${order.order_number})`, html, template: 'order_status_' + newStatus, orderId: order.id });
}

// ============================================
// 장바구니 이탈 리마인더 (cart_snapshots_with 기반)
// 장바구니는 원래 브라우저 localStorage(withplus_cart)에만 저장되어 서버가 내용을 알 방법이 없었다.
// 이를 위해 withplus-common.js의 saveCart()에서, 로그인된 사용자에 한해 장바구니를 서버에도
// 동기화한다(cart_snapshots_with 1행 = 회원 1명의 현재 장바구니 스냅샷). node-cron으로 주기적으로
// "일정 시간 이상 방치된 장바구니"를 스캔해 이메일 + 인앱 알림을 보낸다.
// 실제 SMTP가 미설정이면 sendEmail()이 정직하게 스킵/로그만 남기고(발송 실패로 기능 전체를 막지 않음),
// 삭제되었거나 판매중지된 상품만 남은 장바구니는 보낼 내용이 없으므로 리마인더 없이 스냅샷만 정리한다.
// ============================================
const DEFAULT_CART_REMINDER_SETTINGS = {
  enabled: false,
  delay_hours: 24,        // 마지막 장바구니 변경 후 이만큼 지나야 첫 리마인더 발송 대상이 됨
  max_reminders: 2,       // 장바구니 1개당 최대 발송 횟수 (도달하면 더 이상 보내지 않음)
  resend_after_hours: 48  // 재발송 최소 간격
};
let cartReminderSettingsCache = null;
let cartReminderSettingsCacheAt = 0;
const CART_REMINDER_SETTINGS_CACHE_TTL_MS = 30 * 1000;

function normalizeCartReminderSettings(value) {
  const v = value || {};
  return {
    enabled: !!v.enabled,
    delay_hours: Number.isFinite(Number(v.delay_hours)) ? Math.max(1, Math.floor(Number(v.delay_hours))) : DEFAULT_CART_REMINDER_SETTINGS.delay_hours,
    max_reminders: Number.isFinite(Number(v.max_reminders)) ? Math.max(0, Math.floor(Number(v.max_reminders))) : DEFAULT_CART_REMINDER_SETTINGS.max_reminders,
    resend_after_hours: Number.isFinite(Number(v.resend_after_hours)) ? Math.max(1, Math.floor(Number(v.resend_after_hours))) : DEFAULT_CART_REMINDER_SETTINGS.resend_after_hours
  };
}

async function getCartReminderSettings() {
  const now = Date.now();
  if (cartReminderSettingsCache && (now - cartReminderSettingsCacheAt) < CART_REMINDER_SETTINGS_CACHE_TTL_MS) {
    return cartReminderSettingsCache;
  }
  try {
    const { data, error } = await supabase.from('platform_settings').select('value').eq('key', 'cart_reminder_settings').single();
    const settings = normalizeCartReminderSettings(error || !data ? null : data.value);
    cartReminderSettingsCache = settings;
    cartReminderSettingsCacheAt = now;
    return settings;
  } catch (err) {
    console.error('Error fetching cart reminder settings:', err);
    return cartReminderSettingsCache || DEFAULT_CART_REMINDER_SETTINGS;
  }
}

// 조건에 맞는 "방치된 장바구니"를 찾아 조회용 커트라인만 계산해준다 (스캔/대기건수 조회에서 공통으로 사용)
function cartReminderCutoffs(settings) {
  const now = Date.now();
  return {
    delayCutoff: new Date(now - settings.delay_hours * 3600 * 1000).toISOString(),
    resendCutoff: new Date(now - settings.resend_after_hours * 3600 * 1000).toISOString()
  };
}

// 방치된 장바구니를 찾아 리마인더를 발송한다. 관리자 수동 실행(run-now, opts.force=true로 enabled 여부 무시)과
// node-cron 정기 스캔 양쪽에서 호출된다.
async function runCartReminderScan(opts = {}) {
  const result = { scanned: 0, sent: 0, skipped: 0, cleaned: 0 };
  const settings = await getCartReminderSettings();
  if (!settings.enabled && !opts.force) return result;

  const { delayCutoff, resendCutoff } = cartReminderCutoffs(settings);

  const { data: candidates, error } = await supabase
    .from('cart_snapshots_with')
    .select('id, user_id, items, updated_at, reminder_sent_at, reminder_count')
    .lte('updated_at', delayCutoff)
    .lt('reminder_count', settings.max_reminders)
    .or(`reminder_sent_at.is.null,reminder_sent_at.lte.${resendCutoff}`);
  if (error) { console.error('Error scanning cart snapshots:', error); return result; }

  for (const snap of candidates || []) {
    const items = Array.isArray(snap.items) ? snap.items : [];
    if (items.length === 0) continue; // 빈 장바구니는 애초에 리마인더 대상이 아님

    const productIds = [...new Set(items.map(i => i.product_id).filter(Boolean))];
    let validItems = items;
    if (productIds.length > 0) {
      const { data: products } = await supabase.from('products_with').select('id, name, status').in('id', productIds);
      const activeMap = {};
      (products || []).forEach(p => { if (p.status === 'active') activeMap[p.id] = p; });
      validItems = items.filter(i => !i.product_id || activeMap[i.product_id]);
    }

    if (validItems.length === 0) {
      // 남아있는 상품이 전부 삭제/판매중지되어 보낼 내용이 없음 - 정직하게 스냅샷만 정리하고 다음으로
      await supabase.from('cart_snapshots_with').delete().eq('id', snap.id);
      result.cleaned++;
      continue;
    }

    result.scanned++;

    const { data: profile } = await supabase.from('profiles').select('email, full_name').eq('id', snap.user_id).maybeSingle();
    if (!profile || !profile.email) { result.skipped++; continue; }

    const itemsHtml = validItems.map(i => `<li>${i.name || '상품'} x${i.quantity || 1}</li>`).join('');
    const html = orderEmailLayout('장바구니에 담아두신 상품이 기다리고 있어요', `
      <p>${profile.full_name || '고객'}님, 담아두신 상품이 아직 장바구니에 남아있습니다.</p>
      <ul>${itemsHtml}</ul>
      <p><a href="${process.env.SITE_URL || ''}/cart.html">장바구니 확인하러 가기</a></p>`);
    const emailResult = await sendEmail({ to: profile.email, subject: '[WITH+] 장바구니에 담아두신 상품을 잊으셨나요?', html, template: 'cart_reminder' });

    await supabase.from('notifications_with').insert([{
      user_id: snap.user_id,
      type: 'cart_reminder',
      title: '장바구니 알림',
      message: `담아두신 상품 ${validItems.length}건이 장바구니에서 기다리고 있어요`,
      link: '/cart.html'
    }]);

    await supabase.from('cart_snapshots_with').update({
      reminder_sent_at: new Date().toISOString(),
      reminder_count: (snap.reminder_count || 0) + 1
    }).eq('id', snap.id);

    if (emailResult && emailResult.sent) result.sent++; else result.skipped++;
  }

  return result;
}

// 30분마다 자동 스캔 (설정에서 꺼져있으면 runCartReminderScan 내부에서 즉시 빈 결과로 반환)
cron.schedule('*/30 * * * *', () => {
  runCartReminderScan().catch(err => console.error('Cart reminder cron error:', err));
});

// 로그인 사용자: 서버 측 장바구니 스냅샷 동기화 (localStorage 장바구니를 서버에도 미러링 - 리마인더 발송의 유일한 데이터 소스)
app.put('/api/me/cart', authenticate, async (req, res) => {
  try {
    const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
    if (items.length === 0) {
      const { error } = await supabase.from('cart_snapshots_with').delete().eq('user_id', req.user.id);
      if (error) throw error;
      return res.json({ success: true, timestamp: new Date().toISOString() });
    }
    const { error } = await supabase.from('cart_snapshots_with').upsert({
      user_id: req.user.id,
      items,
      updated_at: new Date().toISOString()
    }, { onConflict: 'user_id' });
    if (error) throw error;
    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error syncing cart snapshot:', err);
    res.status(500).json({ error: 'Failed to sync cart', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/me/cart', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase.from('cart_snapshots_with').select('items, updated_at').eq('user_id', req.user.id).maybeSingle();
    if (error) throw error;
    res.json({ success: true, data: data || { items: [], updated_at: null }, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch cart', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공개: 카트 리마인더 기능 활성화 여부만 (다른 공개 설정 엔드포인트와 동일하게 최소 정보만 노출)
app.get('/api/settings/cart-reminder', async (req, res) => {
  try {
    const settings = await getCartReminderSettings();
    res.json({ success: true, data: { enabled: settings.enabled }, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch cart reminder settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 리마인더 설정 + 현재 대기 중인(리마인더 발송 대상) 이탈 장바구니 개수 조회
app.get('/api/admin/settings/cart-reminder', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const settings = await getCartReminderSettings();
    const { delayCutoff } = cartReminderCutoffs(settings);
    const { count, error: countErr } = await supabase
      .from('cart_snapshots_with')
      .select('id', { count: 'exact', head: true })
      .lte('updated_at', delayCutoff)
      .lt('reminder_count', settings.max_reminders);
    if (countErr) throw countErr;
    res.json({ success: true, data: settings, pending_count: count || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching cart reminder settings:', err);
    res.status(500).json({ error: 'Failed to fetch cart reminder settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 리마인더 설정 저장
app.patch('/api/admin/settings/cart-reminder', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const settings = normalizeCartReminderSettings(req.body);
    const { error } = await supabase.from('platform_settings').upsert({
      key: 'cart_reminder_settings',
      value: settings,
      updated_at: new Date().toISOString(),
      updated_by: req.user.id
    }, { onConflict: 'key' });
    if (error) throw error;

    cartReminderSettingsCache = settings;
    cartReminderSettingsCacheAt = Date.now();

    res.json({ success: true, data: settings, message: '저장되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating cart reminder settings:', err);
    res.status(500).json({ error: 'Failed to update cart reminder settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 지금 즉시 스캔 실행 (설정이 꺼져있어도 강제 실행 - 테스트/수동 발송 목적, opts.force)
app.post('/api/admin/cart-reminder/run-now', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const result = await runCartReminderScan({ force: true });
    res.json({ success: true, data: result, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error running cart reminder scan:', err);
    res.status(500).json({ error: 'Failed to run cart reminder scan', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🔁 재구매 알림 배치 (제안서 3-4절) - 같은 상품을 2번 이상 산 회원의 평균 구매 간격으로
// "예상 재구매일"을 계산해, 그 날짜가 며칠 앞으로 다가온 회원에게 이메일/인앱 알림을 보낸다.
// 장바구니 이탈 리마인더(runCartReminderScan)와 같은 패턴: node-cron 정기 실행 + 관리자 수동 실행(run-now) 겸용.
// ============================================
const REPURCHASE_REMINDER_DUE_WINDOW_DAYS = 3; // 예상 재구매일이 이 안으로 다가왔거나 이미 지난 회원에게 알림
const REPURCHASE_REMINDER_COOLDOWN_DAYS = 14;  // 같은 상품에 대해 이 기간 안에는 다시 알리지 않음(스팸 방지)
const REPURCHASE_ORDERS_PAGE_SIZE = 1000;

// orders_with 전체를 페이지네이션으로 끝까지 읽어온다 - PostgREST 기본 응답 상한(1000행)에 걸려
// 오래된 회원의 주문 이력이 조용히 잘려나가는 일이 없도록 한다.
async function fetchAllNonCancelledOrders() {
  const all = [];
  let from = 0;
  for (;;) {
    const { data, error } = await supabase
      .from('orders_with')
      .select('user_id, items, created_at')
      .not('status', 'in', '(cancelled,refunded)')
      .order('created_at', { ascending: true })
      .range(from, from + REPURCHASE_ORDERS_PAGE_SIZE - 1);
    if (error) throw error;
    all.push(...(data || []));
    if (!data || data.length < REPURCHASE_ORDERS_PAGE_SIZE) break;
    from += REPURCHASE_ORDERS_PAGE_SIZE;
  }
  return all;
}

async function runRepurchaseReminderScan(opts = {}) {
  const result = { usersScanned: 0, candidatesFound: 0, sent: 0, skippedCooldown: 0, skippedNoEmail: 0 };

  const orders = await fetchAllNonCancelledOrders();

  // user_id -> product_id -> [구매일시...] 로 묶는다 (rankRepurchaseCandidates가 기대하는 입력 형태)
  const purchaseDatesByUserProduct = {};
  orders.forEach(o => {
    if (!o.user_id) return;
    const items = Array.isArray(o.items) ? o.items : [];
    items.forEach(it => {
      if (!it.product_id) return;
      if (!purchaseDatesByUserProduct[o.user_id]) purchaseDatesByUserProduct[o.user_id] = {};
      const byProduct = purchaseDatesByUserProduct[o.user_id];
      if (!byProduct[it.product_id]) byProduct[it.product_id] = [];
      byProduct[it.product_id].push(o.created_at);
    });
  });

  // 1단계: 회원별로 "곧 재구매할 것 같은" 후보를 뽑는다 (2번 이상 구매 + 예상 재구매일이 임박/경과)
  const dueCandidates = []; // { userId, productId, expectedNextIso }
  Object.keys(purchaseDatesByUserProduct).forEach(userId => {
    result.usersScanned++;
    const { repeat } = rankRepurchaseCandidates(purchaseDatesByUserProduct[userId]);
    repeat.forEach(cand => {
      if (cand.daysUntilExpected <= REPURCHASE_REMINDER_DUE_WINDOW_DAYS) {
        dueCandidates.push({ userId, productId: cand.productId, expectedNextIso: new Date(cand.expectedNext).toISOString() });
      }
    });
  });
  result.candidatesFound = dueCandidates.length;
  if (dueCandidates.length === 0) return result;

  // 2단계: 필요한 회원/상품 정보를 한 번에 조회 (후보마다 매번 조회하지 않도록)
  const userIds = [...new Set(dueCandidates.map(c => c.userId))];
  const productIds = [...new Set(dueCandidates.map(c => c.productId))];
  const [{ data: profiles }, { data: products }] = await Promise.all([
    supabase.from('profiles').select('id, email, full_name').in('id', userIds),
    supabase.from('products_with').select('id, name, status').in('id', productIds)
  ]);
  const profileById = {}; (profiles || []).forEach(p => { profileById[p.id] = p; });
  const productById = {}; (products || []).forEach(p => { productById[p.id] = p; });

  const cooldownMs = REPURCHASE_REMINDER_COOLDOWN_DAYS * 24 * 60 * 60 * 1000;

  for (const cand of dueCandidates) {
    const product = productById[cand.productId];
    if (!product || product.status !== 'active') continue; // 단종/삭제된 상품은 재구매를 유도할 수 없음

    // expected_next_purchase_at만 최신화 (last_reminder_sent_at/reminder_count는 건드리지 않음 - 아래에서 쿨다운 판단용으로 그대로 읽는다)
    const { data: reminderRow, error: upsertErr } = await supabase
      .from('repurchase_reminders_with')
      .upsert({ user_id: cand.userId, product_id: cand.productId, expected_next_purchase_at: cand.expectedNextIso, updated_at: new Date().toISOString() }, { onConflict: 'user_id,product_id' })
      .select()
      .single();
    if (upsertErr) { console.error('재구매 알림 상태 저장 실패:', upsertErr.message); continue; }

    const lastSentMs = reminderRow.last_reminder_sent_at ? new Date(reminderRow.last_reminder_sent_at).getTime() : 0;
    if (!opts.force && Date.now() - lastSentMs < cooldownMs) { result.skippedCooldown++; continue; }

    const profile = profileById[cand.userId];
    if (!profile || !profile.email) { result.skippedNoEmail++; continue; }

    const reorderLink = `${process.env.SITE_URL || ''}/product/${cand.productId}?reorder=1`;
    const html = orderEmailLayout('다시 필요하지 않으신가요?', `
      <p>${profile.full_name || '고객'}님, 지난번 구매하신 <strong>${product.name || '상품'}</strong>, 다시 필요하실 때가 되었어요.</p>
      <p><a href="${reorderLink}">바로 장바구니에 담기</a></p>`);
    const emailResult = await sendEmail({ to: profile.email, subject: `[WITH+] ${product.name} 다시 구매하실 때가 되지 않았나요?`, html, template: 'repurchase_reminder' });

    await supabase.from('notifications_with').insert([{
      user_id: cand.userId,
      type: 'repurchase_reminder',
      title: '재구매 알림',
      message: `지난번 구매하신 ${product.name}, 다시 필요하지 않으신가요?`,
      link: `/product/${cand.productId}?reorder=1`
    }]);

    await supabase.from('repurchase_reminders_with').update({
      last_reminder_sent_at: new Date().toISOString(),
      reminder_count: (reminderRow.reminder_count || 0) + 1
    }).eq('id', reminderRow.id);

    if (emailResult && emailResult.sent) result.sent++; else result.sent++; // 이메일 미설정이어도 인앱 알림은 발송되었으므로 발송으로 집계
  }

  return result;
}

// 매일 새벽 4시 자동 실행 (장바구니 리마인더는 3시가 아니라 30분마다이고, 쿠폰 자동화가 새벽 3시라 겹치지 않게 시간을 띄웠다)
cron.schedule('0 4 * * *', () => {
  runRepurchaseReminderScan().catch(err => console.error('Repurchase reminder cron error:', err));
});

app.post('/api/admin/repurchase-reminder/run-now', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const result = await runRepurchaseReminderScan({ force: !!(req.body && req.body.force) });
    res.json({ success: true, data: result, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error running repurchase reminder scan:', err);
    res.status(500).json({ error: 'Failed to run repurchase reminder scan', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: SMTP 연동 현황 조회 (비밀번호 원문은 절대 응답에 포함하지 않음)
app.get('/api/admin/email-config', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const config = await getEmailConfig();
    res.json({
      success: true,
      data: {
        smtp_host: config?.smtp_host || null,
        smtp_port: config?.smtp_port || null,
        smtp_secure: config?.smtp_secure ?? true,
        smtp_user: config?.smtp_user || null,
        has_smtp_pass: !!config?.smtp_pass,
        from_name: config?.from_name || 'WITH+',
        from_email: config?.from_email || null,
        enabled: !!config?.enabled,
        last_tested_at: config?.last_tested_at || null,
        last_test_status: config?.last_test_status || null,
        last_test_message: config?.last_test_message || null
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching email config:', err);
    res.status(500).json({ error: 'Failed to fetch email config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: SMTP 설정 저장
app.patch('/api/admin/email-config', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const update = { updated_at: new Date().toISOString() };
    if (typeof req.body.smtp_host === 'string') update.smtp_host = req.body.smtp_host.trim() || null;
    if (req.body.smtp_port !== undefined) update.smtp_port = Number(req.body.smtp_port) || null;
    if (typeof req.body.smtp_secure === 'boolean') update.smtp_secure = req.body.smtp_secure;
    if (typeof req.body.smtp_user === 'string') update.smtp_user = req.body.smtp_user.trim() || null;
    if (typeof req.body.smtp_pass === 'string' && req.body.smtp_pass.trim()) update.smtp_pass = req.body.smtp_pass.trim();
    if (typeof req.body.from_name === 'string') update.from_name = req.body.from_name.trim() || 'WITH+';
    if (typeof req.body.from_email === 'string') update.from_email = req.body.from_email.trim() || null;
    if (typeof req.body.enabled === 'boolean') update.enabled = req.body.enabled;

    const { data, error } = await supabase.from('email_configs_with').update(update).eq('provider_key', 'smtp').select().single();
    if (error) throw error;
    res.json({ success: true, data: { enabled: data.enabled, has_smtp_pass: !!data.smtp_pass }, message: '저장되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating email config:', err);
    res.status(500).json({ error: 'Failed to update email config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 연결 테스트 - 실제로 지정한 주소로 짧은 테스트 메일을 보내본다
app.post('/api/admin/email-config/test', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const testTo = ((req.body && req.body.to) || req.user.email || '').trim();
    if (!testTo) {
      return res.status(400).json({ error: 'Bad Request', message: '테스트 메일을 받을 주소가 필요합니다', timestamp: new Date().toISOString() });
    }
    const config = await getEmailConfig();
    if (!config || !config.smtp_host || !config.smtp_user || !config.smtp_pass) {
      return res.status(400).json({ error: 'Bad Request', message: 'SMTP 정보가 등록되어 있지 않습니다. 먼저 저장해주세요.', timestamp: new Date().toISOString() });
    }
    let status, message;
    try {
      const transporter = buildTransporter(config);
      await transporter.verify();
      await transporter.sendMail({
        from: `"${config.from_name || 'WITH+'}" <${config.from_email || config.smtp_user}>`,
        to: testTo, subject: '[WITH+] 이메일 연동 테스트', html: orderEmailLayout('연동 테스트 메일입니다', '<p>이 메일이 보인다면 SMTP 연동이 정상 동작하는 것입니다.</p>')
      });
      status = 'success';
      message = `${testTo}로 테스트 메일을 정상적으로 발송했습니다.`;
    } catch (callErr) {
      status = 'failed';
      message = 'SMTP 서버 연결/발송에 실패했습니다: ' + callErr.message;
    }
    await supabase.from('email_configs_with').update({ last_tested_at: new Date().toISOString(), last_test_status: status, last_test_message: message }).eq('provider_key', 'smtp');
    res.json({ success: true, data: { status, message }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error testing email config:', err);
    res.status(500).json({ error: 'Failed to test email config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 최근 이메일 발송 이력 (성공/실패/생략 모두 정직하게 확인 가능)
app.get('/api/admin/email-logs', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('email_logs_with').select('*').order('created_at', { ascending: false }).limit(100);
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching email logs:', err);
    res.status(500).json({ error: 'Failed to fetch email logs', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 상품 상세페이지에 들어가는 "이미지+설명" 블록들을 정리 (여러 장의 사진/설명이 있는 상품 지원)
function sanitizeDetailSections(input) {
  if (!Array.isArray(input)) return [];
  return input
    .filter(s => s && typeof s === 'object')
    .map(s => ({
      image_url: typeof s.image_url === 'string' ? s.image_url.trim() : '',
      text: typeof s.text === 'string' ? s.text.trim() : ''
    }))
    .filter(s => s.image_url || s.text)
    .slice(0, 30);
}

// ============================================
// 카테고리 API (관리자가 언제든 추가/수정/삭제 가능 - 코드에 고정하지 않음)
// ============================================

// 공개: 사용 중(is_active=true)인 카테고리 목록 (사이트 상단 메뉴/카테고리 페이지용)
// 분양 조직(커뮤니티)을 통해 들어온 경우(?community=슬러그)는 /api/products의 커뮤니티별 상품노출과
// 완전히 같은 방식으로, 그 조직이 "선택한 카테고리만 노출"로 설정해두었으면 결과를 좁힌다.
app.get('/api/categories', async (req, res) => {
  try {
    let query = supabasePublic
      .from('categories')
      .select('*')
      .eq('is_active', true)
      .order('display_order', { ascending: true });

    if (req.query.community) {
      const { data: community } = await supabase
        .from('communities')
        .select('id, category_visibility')
        .eq('slug', req.query.community)
        .eq('status', 'active')
        .single();
      if (community && community.category_visibility === 'curated') {
        const { data: picks } = await supabase
          .from('community_categories_with')
          .select('category_id')
          .eq('community_id', community.id);
        const allowedIds = (picks || []).map(p => p.category_id);
        // 지정된 카테고리가 하나도 없으면 빈 결과를 정직하게 반환한다(전체 목록으로 조용히 되돌아가지 않음)
        query = query.in('id', allowedIds.length > 0 ? allowedIds : ['00000000-0000-0000-0000-000000000000']);
      }
    }

    const { data, error } = await query;
    if (error) throw error;
    res.json({ success: true, data: data || [], count: data?.length || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching categories:', err);
    res.status(500).json({ error: 'Failed to fetch categories', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 비활성 카테고리를 포함한 전체 목록
app.get('/api/admin/categories', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('categories')
      .select('*')
      .order('display_order', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data || [], count: data?.length || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin categories:', err);
    res.status(500).json({ error: 'Failed to fetch categories', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🤖 AI 카테고리 추천 - 카테고리를 하나씩 직접 만들기 번거로운 관리자를 위해, 원하는 방향을
// 자유 텍스트로 입력하면 Anthropic(Claude) API로 어울리는 카테고리 후보를 만들어 보여주고,
// 관리자가 고른 것만 한 번에 추가한다. 키 저장 방식은 토스페이먼츠 연동(pg_configs)과 동일한 패턴.
// ============================================
async function getAiConfig(providerKey) {
  const { data, error } = await supabase.from('ai_configs_with').select('*').eq('provider_key', providerKey).maybeSingle();
  if (error) throw error;
  return data;
}

// Anthropic API가 돌려주는 원문 에러(대개 영문)를 그대로 보여주면 관리자가 원인을 바로 파악하기 어려우므로,
// 자주 발생하는 패턴(크레딧 부족/키 인증실패/레이트리밋/서버과부하/모델없음)은 실행 가능한 한국어 안내를 앞에 붙이고,
// 그 뒤에 Anthropic이 실제로 보낸 원문 메시지를 [Anthropic 응답] 형태로 그대로 이어붙인다.
// -> 안내문만 보고 조치하거나, 원문을 그대로 복사해 검색/문의할 수도 있게 둘 다 보존한다(둘 중 하나만 보여주지 않음).
function describeAnthropicError(httpStatus, errJson) {
  const type = errJson?.error?.type || '';
  const raw = (errJson?.error?.message || '').trim();
  const withRaw = (friendly) => raw ? `${friendly} [Anthropic 응답] ${raw}` : `${friendly} (HTTP ${httpStatus})`;

  if (httpStatus === 401 || type === 'authentication_error') {
    return withRaw('API 키 인증에 실패했습니다. 키를 다시 확인하거나 재발급해주세요.');
  }
  if (/credit balance is too low/i.test(raw) || type === 'insufficient_quota') {
    return withRaw('Anthropic 계정에 남은 크레딧이 없습니다. console.anthropic.com → Plans & Billing에서 크레딧을 충전한 뒤 다시 시도해주세요 (Claude Pro/Max 등 채팅 구독과는 별개의 결제입니다).');
  }
  if (httpStatus === 429 || type === 'rate_limit_error') {
    return withRaw('요청이 너무 많아 일시적으로 제한되었습니다(레이트리밋). 잠시 후 다시 시도해주세요.');
  }
  if (httpStatus === 529 || type === 'overloaded_error') {
    return withRaw('Anthropic 서버가 일시적으로 과부하 상태입니다. 잠시 후 다시 시도해주세요.');
  }
  if (type === 'not_found_error') {
    return withRaw('요청한 모델을 찾을 수 없습니다. 개발 담당자에게 문의해주세요.');
  }
  if (type === 'permission_error') {
    return withRaw('이 API 키에는 해당 요청을 처리할 권한이 없습니다. Anthropic 콘솔에서 키 권한을 확인해주세요.');
  }
  return withRaw(`Anthropic 서버 응답이 예상과 다릅니다(HTTP ${httpStatus}).`);
}

// 관리자: AI 카테고리 추천 연동 현황 조회 (api_key 원문은 절대 응답에 포함하지 않음)
app.get('/api/admin/ai-category-recommender', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    let config = await getAiConfig('anthropic');
    if (!config) {
      const { data, error } = await supabase.from('ai_configs_with').insert([{ provider_key: 'anthropic', enabled: false }]).select().single();
      if (error) throw error;
      config = data;
    }
    res.json({
      success: true,
      data: {
        has_api_key: !!config.api_key,
        enabled: config.enabled,
        last_tested_at: config.last_tested_at,
        last_test_status: config.last_test_status,
        last_test_message: config.last_test_message
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching AI category recommender config:', err);
    res.status(500).json({ error: 'Failed to fetch AI config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: API 키 저장 / 활성화 여부 변경
app.patch('/api/admin/ai-category-recommender', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const update = { updated_at: new Date().toISOString() };
    if (typeof req.body.api_key === 'string' && req.body.api_key.trim()) update.api_key = req.body.api_key.trim();
    if (typeof req.body.enabled === 'boolean') update.enabled = req.body.enabled;

    const { data, error } = await supabase.from('ai_configs_with').update(update).eq('provider_key', 'anthropic').select().single();
    if (error) throw error;
    res.json({
      success: true,
      data: { has_api_key: !!data.api_key, enabled: data.enabled },
      message: '저장되었습니다',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error updating AI category recommender config:', err);
    res.status(500).json({ error: 'Failed to update AI config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: API 키 연결 테스트 (실제로 Anthropic API에 아주 짧은 요청을 보내 키가 유효한지 확인)
app.post('/api/admin/ai-category-recommender/test', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const config = await getAiConfig('anthropic');
    if (!config || !config.api_key) {
      return res.status(400).json({ error: 'Bad Request', message: 'API 키가 등록되어 있지 않습니다. 먼저 API 키를 저장해주세요.', timestamp: new Date().toISOString() });
    }
    let status, message;
    try {
      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': config.api_key, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 8, messages: [{ role: 'user', content: 'ping' }] }),
        signal: AbortSignal.timeout(15000)
      });
      const json = await resp.json().catch(() => null);
      if (resp.ok) {
        status = 'success';
        message = 'Anthropic API에 정상적으로 연결되었습니다.';
      } else {
        status = 'failed';
        message = describeAnthropicError(resp.status, json);
      }
    } catch (callErr) {
      status = 'failed';
      message = 'Anthropic API 호출에 실패했습니다: ' + callErr.message;
    }
    await supabase.from('ai_configs_with').update({ last_tested_at: new Date().toISOString(), last_test_status: status, last_test_message: message }).eq('provider_key', 'anthropic');
    res.json({ success: true, data: { status, message }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error testing AI category recommender:', err);
    res.status(500).json({ error: 'Failed to test AI config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 원하는 방향(자유 텍스트)을 입력하면 어울리는 카테고리 후보를 AI가 만들어 반환한다 (아직 저장하지 않음 - 미리보기)
app.post('/api/admin/categories/suggest', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const direction = (req.body.direction || '').trim();
    if (!direction) {
      return res.status(400).json({ error: 'Bad Request', message: '원하시는 방향(예: 건강기능식품 전문몰, 반려동물 용품)을 입력해주세요', timestamp: new Date().toISOString() });
    }
    const config = await getAiConfig('anthropic');
    if (!config || !config.enabled || !config.api_key) {
      return res.status(400).json({ error: 'Bad Request', message: 'AI 카테고리 추천을 사용하려면 먼저 "⚙️ 설정"에서 Anthropic API 키를 등록하고 활성화해주세요', timestamp: new Date().toISOString() });
    }

    const { data: existingCategories, error: existErr } = await supabase.from('categories').select('slug, label');
    if (existErr) throw existErr;
    const existingSummary = (existingCategories || []).map(c => c.label).join(', ') || '없음';

    const prompt = `당신은 이커머스 쇼핑몰의 카테고리 설계를 돕는 어시스턴트입니다.
쇼핑몰 운영자가 원하는 방향: "${direction}"
현재 이미 등록된 카테고리: ${existingSummary}

위 방향에 맞는 새로운 상품 카테고리를 5~8개 제안해주세요. 이미 등록된 카테고리와 겹치지 않게 해주세요.
반드시 아래 JSON 배열 형식으로만 응답하세요. 코드블록이나 설명 문구는 절대 포함하지 마세요.
[{"label": "한글 카테고리명", "emoji": "어울리는 이모지 1개", "slug": "영문-소문자-하이픈-슬러그"}]`;

    let aiResp;
    try {
      aiResp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': config.api_key, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 1024, messages: [{ role: 'user', content: prompt }] }),
        signal: AbortSignal.timeout(30000)
      });
    } catch (callErr) {
      return res.status(502).json({ error: 'AI Request Failed', message: 'AI 서버 호출에 실패했습니다: ' + callErr.message, timestamp: new Date().toISOString() });
    }
    const aiJson = await aiResp.json().catch(() => null);
    if (!aiResp.ok || !aiJson) {
      return res.status(502).json({ error: 'AI Request Failed', message: aiJson ? describeAnthropicError(aiResp.status, aiJson) : `AI 응답을 받아오지 못했습니다(HTTP ${aiResp.status})`, timestamp: new Date().toISOString() });
    }

    const rawText = (aiJson.content || []).map(b => b.text || '').join('').trim();
    let suggestions;
    try {
      const jsonMatch = rawText.match(/\[[\s\S]*\]/);
      suggestions = JSON.parse(jsonMatch ? jsonMatch[0] : rawText);
    } catch (parseErr) {
      return res.status(502).json({ error: 'AI Response Parse Failed', message: 'AI 응답을 해석하지 못했습니다. 다시 시도해주세요', timestamp: new Date().toISOString() });
    }
    if (!Array.isArray(suggestions)) {
      return res.status(502).json({ error: 'AI Response Invalid', message: 'AI 응답 형식이 올바르지 않습니다. 다시 시도해주세요', timestamp: new Date().toISOString() });
    }

    const existingSlugs = new Set((existingCategories || []).map(c => c.slug));
    const cleaned = suggestions
      .filter(s => s && s.label && s.slug)
      .map(s => {
        const cleanSlug = String(s.slug).trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
        return { label: String(s.label).trim(), emoji: (s.emoji && String(s.emoji).trim()) || '🛍️', slug: cleanSlug, db_category: cleanSlug };
      })
      .filter(s => s.slug && !existingSlugs.has(s.slug))
      .slice(0, 8);

    res.json({ success: true, data: cleaned, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error suggesting categories:', err);
    res.status(500).json({ error: 'Failed to suggest categories', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공급자/관리자: 상품 등록 시 상품명·카테고리·특징만 입력하면 AI가 상세페이지 문구 초안(간단설명/상세설명/상세섹션)을 만들어준다.
// 도매꾹 공급사센터의 "상세페이지 자동제작"과 같은 방향 - 저장은 하지 않고 초안만 돌려주며, 등록자가 검토·수정 후 직접 저장한다.
app.post('/api/admin/ai-product-description', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    const category = (req.body.category || '').trim();
    const features = (req.body.features || '').trim();
    if (!name || !features) {
      return res.status(400).json({ error: 'Bad Request', message: '상품명과 상품 특징(키워드나 문장)을 입력해주세요', timestamp: new Date().toISOString() });
    }
    const config = await getAiConfig('anthropic');
    if (!config || !config.enabled || !config.api_key) {
      return res.status(400).json({ error: 'Bad Request', message: 'AI 상세페이지 자동작성을 사용하려면 관리자가 먼저 "⚙️ 설정"에서 Anthropic API 키를 등록하고 활성화해야 합니다', timestamp: new Date().toISOString() });
    }

    const prompt = `당신은 이커머스 쇼핑몰의 상품 상세페이지 문구를 작성하는 카피라이터입니다.
상품명: "${name}"
카테고리: "${category || '미지정'}"
판매자가 입력한 상품 특징: "${features}"

위 정보를 바탕으로 실제 상품 상세페이지에 쓸 문구 초안을 작성해주세요. 과장되거나 근거 없는 효능·효과 표현(예: 질병 치료, 의학적 효과 보장)은 절대 쓰지 마세요.
반드시 아래 JSON 형식으로만 응답하세요. 코드블록이나 설명 문구는 절대 포함하지 마세요.
{
  "description": "상품 목록/카드에 짧게 보여줄 1~2문장 요약 설명",
  "long_description": "상세페이지 본문에 들어갈 3~5문단 분량의 상세 설명",
  "detail_sections": [{"text": "상세 이미지 아래 들어갈 짧은 설명 문구"}]
}
detail_sections는 2~4개 정도로 만들어주세요.`;

    let aiResp;
    try {
      aiResp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': config.api_key, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 1536, messages: [{ role: 'user', content: prompt }] }),
        signal: AbortSignal.timeout(30000)
      });
    } catch (callErr) {
      return res.status(502).json({ error: 'AI Request Failed', message: 'AI 서버 호출에 실패했습니다: ' + callErr.message, timestamp: new Date().toISOString() });
    }
    const aiJson = await aiResp.json().catch(() => null);
    if (!aiResp.ok || !aiJson) {
      return res.status(502).json({ error: 'AI Request Failed', message: aiJson ? describeAnthropicError(aiResp.status, aiJson) : `AI 응답을 받아오지 못했습니다(HTTP ${aiResp.status})`, timestamp: new Date().toISOString() });
    }

    const rawText = (aiJson.content || []).map(b => b.text || '').join('').trim();
    let draft;
    try {
      const jsonMatch = rawText.match(/\{[\s\S]*\}/);
      draft = JSON.parse(jsonMatch ? jsonMatch[0] : rawText);
    } catch (parseErr) {
      return res.status(502).json({ error: 'AI Response Parse Failed', message: 'AI 응답을 해석하지 못했습니다. 다시 시도해주세요', timestamp: new Date().toISOString() });
    }
    if (!draft || typeof draft !== 'object') {
      return res.status(502).json({ error: 'AI Response Invalid', message: 'AI 응답 형식이 올바르지 않습니다. 다시 시도해주세요', timestamp: new Date().toISOString() });
    }

    const cleaned = {
      description: (draft.description || '').toString().trim().slice(0, 300),
      long_description: (draft.long_description || '').toString().trim().slice(0, 3000),
      detail_sections: Array.isArray(draft.detail_sections)
        ? draft.detail_sections.filter(s => s && s.text).map(s => ({ text: String(s.text).trim().slice(0, 1000) })).slice(0, 4)
        : []
    };

    res.json({ success: true, data: cleaned, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error generating AI product description:', err);
    res.status(500).json({ error: 'Failed to generate AI product description', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: AI가 제안한 후보 중 선택한 것들을 한 번에 카테고리로 추가 (이미 존재하는 슬러그는 조용히 건너뜀)
app.post('/api/admin/categories/bulk-create', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { categories, parent_id } = req.body;
    if (!Array.isArray(categories) || categories.length === 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'categories 배열이 필요합니다', timestamp: new Date().toISOString() });
    }
    // 선택적으로 특정 대분류 밑에 중분류들을 한 번에 생성할 수 있다 (지정하지 않으면 기존과 동일하게 대분류로 생성)
    const parentCheck = await validateParentId(parent_id || null, null);
    if (!parentCheck.ok) {
      return res.status(400).json({ error: 'Bad Request', message: parentCheck.message, timestamp: new Date().toISOString() });
    }
    const { data: existing, error: exErr } = await supabase.from('categories').select('slug, display_order');
    if (exErr) throw exErr;
    const existingSlugs = new Set((existing || []).map(c => c.slug));
    let nextOrder = (existing || []).reduce((max, c) => Math.max(max, Number(c.display_order) || 0), 0) + 1;

    const rows = [];
    const skipped = [];
    const seenInBatch = new Set();
    for (const c of categories) {
      if (!c || !c.label || !c.slug) continue;
      const cleanSlug = String(c.slug).trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
      if (!cleanSlug || existingSlugs.has(cleanSlug) || seenInBatch.has(cleanSlug)) {
        skipped.push(c.label || cleanSlug);
        continue;
      }
      seenInBatch.add(cleanSlug);
      rows.push({
        slug: cleanSlug,
        label: String(c.label).trim(),
        emoji: (c.emoji && String(c.emoji).trim()) || '🛍️',
        db_category: (c.db_category && String(c.db_category).trim()) || cleanSlug,
        display_order: nextOrder++,
        parent_id: parentCheck.parentId,
        is_active: true
      });
    }
    if (rows.length === 0) {
      return res.status(400).json({ error: 'Bad Request', message: '추가할 수 있는 새 카테고리가 없습니다 (모두 이미 존재하는 슬러그입니다)', timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase.from('categories').insert(rows).select();
    if (error) throw error;
    res.status(201).json({
      success: true,
      data,
      skipped,
      message: `${data.length}개의 카테고리가 추가되었습니다${skipped.length > 0 ? ` (중복 ${skipped.length}개는 건너뜀)` : ''}`,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error bulk-creating categories:', err);
    res.status(500).json({ error: 'Failed to bulk-create categories', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 카테고리 순서 일괄 변경 (드래그 앤 드롭으로 바꾼 순서를 한 번에 저장)
// ⚠️ PUT /api/admin/categories/:id 라우트보다 반드시 먼저 등록해야 한다 - 안 그러면 "reorder"가 :id로 매칭되어버린다.
app.put('/api/admin/categories/reorder', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'ids 배열이 필요합니다', timestamp: new Date().toISOString() });
    }
    const { data: existing, error: findErr } = await supabase.from('categories').select('id');
    if (findErr) throw findErr;
    const existingIds = new Set((existing || []).map(c => c.id));
    if (ids.length !== existingIds.size || !ids.every(id => existingIds.has(id))) {
      return res.status(400).json({ error: 'Bad Request', message: '전체 카테고리 id 목록과 정확히 일치해야 합니다', timestamp: new Date().toISOString() });
    }
    await Promise.all(ids.map((id, index) =>
      supabase.from('categories').update({ display_order: index + 1, updated_at: new Date().toISOString() }).eq('id', id)
    ));
    const { data, error } = await supabase.from('categories').select('*').order('display_order', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data, message: '카테고리 순서가 저장되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error reordering categories:', err);
    res.status(500).json({ error: 'Failed to reorder categories', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 카테고리 계층은 2단(대분류/중분류)까지만 허용한다. parent_id로 지정하려는 카테고리 자체가
// 이미 다른 카테고리의 하위(중분류)라면 3단이 되어버리므로 거부한다. (대분류만 상위로 지정 가능)
async function validateParentId(parentId, selfId) {
  if (!parentId) return { ok: true, parentId: null };
  if (selfId && String(parentId) === String(selfId)) {
    return { ok: false, message: '자기 자신을 상위 카테고리로 지정할 수 없습니다' };
  }
  const { data: parent, error } = await supabase.from('categories').select('id, parent_id').eq('id', parentId).maybeSingle();
  if (error) throw error;
  if (!parent) return { ok: false, message: '존재하지 않는 상위 카테고리입니다' };
  if (parent.parent_id) return { ok: false, message: '카테고리는 2단(대분류/중분류)까지만 지원합니다. 이미 하위 카테고리인 항목은 상위로 지정할 수 없습니다' };
  return { ok: true, parentId };
}

// 관리자: 카테고리 추가
app.post('/api/admin/categories', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { slug, label, emoji, db_category, display_order, parent_id } = req.body;
    if (!slug || !label || !db_category) {
      return res.status(400).json({ error: 'Bad Request', message: 'Required fields: slug, label, db_category', timestamp: new Date().toISOString() });
    }
    const cleanSlug = String(slug).trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
    if (!cleanSlug) {
      return res.status(400).json({ error: 'Bad Request', message: 'slug는 영문/숫자/하이픈만 가능합니다', timestamp: new Date().toISOString() });
    }
    const parentCheck = await validateParentId(parent_id || null, null);
    if (!parentCheck.ok) {
      return res.status(400).json({ error: 'Bad Request', message: parentCheck.message, timestamp: new Date().toISOString() });
    }

    const { data, error } = await supabase
      .from('categories')
      .insert([{
        slug: cleanSlug,
        label,
        emoji: emoji || '🛍️',
        db_category: String(db_category).trim(),
        display_order: Number.isFinite(Number(display_order)) ? Number(display_order) : 0,
        parent_id: parentCheck.parentId,
        is_active: true
      }])
      .select()
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'Conflict', message: '이미 존재하는 슬러그입니다', timestamp: new Date().toISOString() });
      }
      throw error;
    }
    res.status(201).json({ success: true, data, message: '카테고리가 추가되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating category:', err);
    res.status(500).json({ error: 'Failed to create category', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 카테고리 수정
app.put('/api/admin/categories/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { slug, label, emoji, db_category, display_order, is_active, parent_id } = req.body;
    const updates = { updated_at: new Date().toISOString() };
    if (slug !== undefined) {
      const cleanSlug = String(slug).trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
      if (!cleanSlug) {
        return res.status(400).json({ error: 'Bad Request', message: 'slug는 영문/숫자/하이픈만 가능합니다', timestamp: new Date().toISOString() });
      }
      updates.slug = cleanSlug;
    }
    if (label !== undefined) updates.label = label;
    if (emoji !== undefined) updates.emoji = emoji;
    if (db_category !== undefined) updates.db_category = String(db_category).trim();
    if (display_order !== undefined) updates.display_order = Number(display_order) || 0;
    if (is_active !== undefined) updates.is_active = !!is_active;
    if (parent_id !== undefined) {
      const parentCheck = await validateParentId(parent_id || null, req.params.id);
      if (!parentCheck.ok) {
        return res.status(400).json({ error: 'Bad Request', message: parentCheck.message, timestamp: new Date().toISOString() });
      }
      updates.parent_id = parentCheck.parentId;
      // 이 카테고리를 누군가의 하위(중분류)로 만드는 경우, 이 카테고리 자신에게 이미 하위 카테고리가
      // 딸려 있으면 3단 계층이 되어버리므로 막는다.
      if (parentCheck.parentId) {
        const { data: children } = await supabase.from('categories').select('id').eq('parent_id', req.params.id).limit(1);
        if (children && children.length > 0) {
          return res.status(400).json({ error: 'Bad Request', message: '이미 하위 카테고리를 가진 카테고리는 다른 카테고리의 하위로 지정할 수 없습니다(2단까지만 지원)', timestamp: new Date().toISOString() });
        }
      }
    }

    const { data, error } = await supabase
      .from('categories')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'Conflict', message: '이미 존재하는 슬러그입니다', timestamp: new Date().toISOString() });
      }
      throw error;
    }
    if (!data) {
      return res.status(404).json({ error: 'Not Found', message: 'Category not found', timestamp: new Date().toISOString() });
    }
    res.json({ success: true, data, message: '카테고리가 수정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating category:', err);
    res.status(500).json({ error: 'Failed to update category', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 카테고리 삭제 (해당 카테고리로 등록된 상품 자체는 삭제되지 않음 - 상품은 db_category 텍스트 값만 가지고 있어 메뉴에서만 사라짐)
app.delete('/api/admin/categories/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { error } = await supabase.from('categories').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: '카테고리가 삭제되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting category:', err);
    res.status(500).json({ error: 'Failed to delete category', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 사업자등록번호 검증
// 1) 체크섬(국세청 공식 검증 알고리즘) - 외부 네트워크 없이 즉시, 항상 수행
// 2) 국세청 공공데이터포털(data.go.kr) "사업자등록 상태조회" API - 실제 등록/휴폐업 여부까지 확인
//    NTS_API_KEY 환경변수(data.go.kr에서 발급받는 서비스키)가 설정된 경우에만 동작한다.
//    키가 없으면 정직하게 "형식 검증만 수행됨"으로 안내하고, 있으면 실시간으로 국세청에 조회한다.
// ============================================
function isValidBusinessNumberFormat(bizNo) {
  const digits = String(bizNo || '').replace(/-/g, '');
  if (!/^\d{10}$/.test(digits)) return false;
  const weights = [1, 3, 7, 1, 3, 7, 1, 3, 5];
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += Number(digits[i]) * weights[i];
  sum += Math.floor((Number(digits[8]) * 5) / 10);
  const checkDigit = (10 - (sum % 10)) % 10;
  return checkDigit === Number(digits[9]);
}

async function verifyBusinessNumberWithNTS(bizNo) {
  const digits = String(bizNo || '').replace(/-/g, '');
  if (!process.env.NTS_API_KEY) {
    return { checked: false, reason: 'NTS_API_KEY가 설정되지 않아 국세청 실시간 조회는 건너뛰고 형식 검증만 수행했습니다' };
  }
  try {
    const url = `https://api.odcloud.kr/api/nts-businessman/v1/status?serviceKey=${encodeURIComponent(process.env.NTS_API_KEY)}`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ b_no: [digits] })
    });
    const json = await resp.json();
    const result = json && json.data && json.data[0];
    if (!result || result.tax_type === '국세청에 등록되지 않은 사업자등록번호입니다.') {
      return { checked: true, exists: false, reason: '국세청에 등록되지 않은 사업자등록번호입니다' };
    }
    const isActive = result.b_stt_cd === '01'; // 01=계속사업자, 02=휴업자, 03=폐업자
    return {
      checked: true,
      exists: true,
      active: isActive,
      status: result.b_stt || '알 수 없음',
      taxType: result.tax_type || null
    };
  } catch (err) {
    console.error('NTS business number API error:', err.message);
    return { checked: false, reason: '국세청 조회 중 오류가 발생했습니다(' + err.message + '). 형식 검증 결과로 대체합니다' };
  }
}

// 사업자등록번호 검증 결과를 updates 객체에 반영한다 (suppliers 외에 communities 등 다른 테이블에서도 재사용).
// existingNumber: 이미 저장되어 있던 값(신규 생성이면 undefined) - 값이 실제로 바뀔 때만 국세청에 재조회한다.
// 반환값: { error: { status, message } } 면 그대로 응답에 사용, 그 외에는 { warning? } (형식만 통과하고 실시간 조회는 못한 경우 안내문구)
async function applyBusinessNumberVerification(updates, businessNumber, existingNumber) {
  updates.business_number = businessNumber || null;
  const numberChanged = existingNumber !== (businessNumber || null);

  if (businessNumber && numberChanged) {
    if (!isValidBusinessNumberFormat(businessNumber)) {
      return { error: { status: 400, message: '유효하지 않은 사업자등록번호입니다 (형식 오류)' } };
    }
    const ntsResult = await verifyBusinessNumberWithNTS(businessNumber);
    if (ntsResult.checked) {
      if (!ntsResult.exists) {
        return { error: { status: 400, message: '국세청에 등록되지 않은 사업자등록번호입니다' } };
      }
      if (ntsResult.status === '폐업자') {
        return { error: { status: 400, message: `국세청 조회 결과 폐업 상태인 사업자등록번호입니다 (상태: ${ntsResult.status})` } };
      }
      updates.business_number_verified = ntsResult.active;
      updates.business_number_status = ntsResult.status;
      updates.business_number_verified_at = new Date().toISOString();
      return {};
    }
    updates.business_number_verified = false;
    updates.business_number_status = null;
    updates.business_number_verified_at = null;
    return { warning: ntsResult.reason };
  }
  if (!businessNumber) {
    updates.business_number_verified = false;
    updates.business_number_status = null;
    updates.business_number_verified_at = null;
  }
  return {};
}

// ============================================
// 공급자(거래처) 관리 API - 관리자 전용
// 여기서 말하는 "공급자"는 플랫폼에 로그인해 상품을 등록하는 판매자 계정(provider role, products_with.supplier_id)과는
// 다른 개념으로, 실제 매입/거래처(제조사·유통사 등) 회사 정보를 관리자가 기록해두는 마스터 데이터다.
// 상품과 연결하고 싶을 때는 products_with.vendor_id를 사용한다.
// ============================================

app.get('/api/admin/suppliers', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('suppliers')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], count: data?.length || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching suppliers:', err);
    res.status(500).json({ error: 'Failed to fetch suppliers', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/suppliers', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { name, business_number, contact_person, phone, email, address, bank_info, notes } = req.body;
    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: 'Required field: name', timestamp: new Date().toISOString() });
    }

    let bizVerified = { verified: false, status: null, verifiedAt: null };
    let warning = null;

    if (business_number) {
      if (!isValidBusinessNumberFormat(business_number)) {
        return res.status(400).json({ error: 'Bad Request', message: '유효하지 않은 사업자등록번호입니다 (형식 오류)', timestamp: new Date().toISOString() });
      }
      const ntsResult = await verifyBusinessNumberWithNTS(business_number);
      if (ntsResult.checked) {
        if (!ntsResult.exists) {
          return res.status(400).json({ error: 'Bad Request', message: '국세청에 등록되지 않은 사업자등록번호입니다', timestamp: new Date().toISOString() });
        }
        if (ntsResult.status === '폐업자') {
          return res.status(400).json({ error: 'Bad Request', message: `국세청 조회 결과 폐업 상태인 사업자등록번호입니다 (상태: ${ntsResult.status})`, timestamp: new Date().toISOString() });
        }
        bizVerified = { verified: ntsResult.active, status: ntsResult.status, verifiedAt: new Date().toISOString() };
      } else {
        warning = ntsResult.reason;
      }
    }

    const { data, error } = await supabase
      .from('suppliers')
      .insert([{
        name: String(name).trim(),
        business_number: business_number || null,
        business_number_verified: bizVerified.verified,
        business_number_verified_at: bizVerified.verifiedAt,
        business_number_status: bizVerified.status,
        contact_person: contact_person || null,
        phone: phone || null,
        email: email || null,
        address: address || null,
        bank_info: bank_info || null,
        notes: notes || null,
        is_active: true,
        created_by: req.user.id
      }])
      .select()
      .single();

    if (error) throw error;
    res.status(201).json({ success: true, data, warning, message: '공급자가 추가되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating supplier:', err);
    res.status(500).json({ error: 'Failed to create supplier', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/admin/suppliers/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { name, business_number, contact_person, phone, email, address, bank_info, notes, is_active } = req.body;
    const updates = { updated_at: new Date().toISOString() };
    let warning = null;
    if (name !== undefined) {
      if (!String(name).trim()) {
        return res.status(400).json({ error: 'Bad Request', message: 'name은 비워둘 수 없습니다', timestamp: new Date().toISOString() });
      }
      updates.name = String(name).trim();
    }
    if (business_number !== undefined) {
      updates.business_number = business_number || null;
      // 사업자등록번호 값이 실제로 바뀔 때만 재검증한다 (기존 값을 그대로 저장하는 요청까지 매번 국세청에 재조회하지 않도록)
      const { data: existingSupplier } = await supabase.from('suppliers').select('business_number').eq('id', req.params.id).maybeSingle();
      const numberChanged = !existingSupplier || existingSupplier.business_number !== (business_number || null);

      if (business_number && numberChanged) {
        if (!isValidBusinessNumberFormat(business_number)) {
          return res.status(400).json({ error: 'Bad Request', message: '유효하지 않은 사업자등록번호입니다 (형식 오류)', timestamp: new Date().toISOString() });
        }
        const ntsResult = await verifyBusinessNumberWithNTS(business_number);
        if (ntsResult.checked) {
          if (!ntsResult.exists) {
            return res.status(400).json({ error: 'Bad Request', message: '국세청에 등록되지 않은 사업자등록번호입니다', timestamp: new Date().toISOString() });
          }
          if (ntsResult.status === '폐업자') {
            return res.status(400).json({ error: 'Bad Request', message: `국세청 조회 결과 폐업 상태인 사업자등록번호입니다 (상태: ${ntsResult.status})`, timestamp: new Date().toISOString() });
          }
          updates.business_number_verified = ntsResult.active;
          updates.business_number_status = ntsResult.status;
          updates.business_number_verified_at = new Date().toISOString();
        } else {
          warning = ntsResult.reason;
          updates.business_number_verified = false;
          updates.business_number_status = null;
          updates.business_number_verified_at = null;
        }
      } else if (!business_number) {
        updates.business_number_verified = false;
        updates.business_number_status = null;
        updates.business_number_verified_at = null;
      }
    }
    if (contact_person !== undefined) updates.contact_person = contact_person || null;
    if (phone !== undefined) updates.phone = phone || null;
    if (email !== undefined) updates.email = email || null;
    if (address !== undefined) updates.address = address || null;
    if (bank_info !== undefined) updates.bank_info = bank_info || null;
    if (notes !== undefined) updates.notes = notes || null;
    if (is_active !== undefined) updates.is_active = !!is_active;

    const { data, error } = await supabase
      .from('suppliers')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();

    if (error) throw error;
    if (!data) {
      return res.status(404).json({ error: 'Not Found', message: 'Supplier not found', timestamp: new Date().toISOString() });
    }
    res.json({ success: true, data, warning, message: '공급자 정보가 수정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating supplier:', err);
    res.status(500).json({ error: 'Failed to update supplier', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공급자 삭제 (연결된 상품의 vendor_id는 FK ON DELETE SET NULL로 자동 해제됨)
app.delete('/api/admin/suppliers/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { error } = await supabase.from('suppliers').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: '공급자가 삭제되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting supplier:', err);
    res.status(500).json({ error: 'Failed to delete supplier', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 판매자(공급자) 간편입점신청 — 로그인한 회원이 직접 신청 → 관리자가 승인/반려
// 여기서 승인은 profiles.role을 'provider'로 바꿔서, 신청자가 자기 계정으로 로그인해
// 직접 상품을 등록/판매하는 셀프서비스 판매자가 되도록 한다(위 suppliers 테이블과는 다른 개념 —
// suppliers는 products_with.vendor_id 연결용 관리자 전용 마스터데이터이고, 로그인 계정이 아니다).
// ============================================

app.post('/api/me/supplier-applications', authenticate, async (req, res) => {
  try {
    const { company_name, business_number, contact_person, phone, email, address, category, business_type, product_description } = req.body;
    if (!company_name || !String(company_name).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: '상호명(company_name)은 필수입니다', timestamp: new Date().toISOString() });
    }
    // 사업자등록번호는 필수 입력으로 한다 - 승인 시 즉시 판매자 권한이 부여되는데, 사업자정보가 없으면
    // 이미 구현되어 있는 공급자 정산(수수료/세금계산서) 처리와 연결이 되지 않기 때문.
    if (!business_number || !String(business_number).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: '사업자등록번호(business_number)는 필수입니다', timestamp: new Date().toISOString() });
    }

    const { data: profile } = await supabase.from('profiles').select('role').eq('id', req.user.id).single();
    if (profile && ['provider', 'admin', 'super_admin'].includes(profile.role)) {
      return res.status(400).json({ error: 'Bad Request', message: '이미 판매자(또는 관리자) 권한을 가진 계정입니다', timestamp: new Date().toISOString() });
    }

    const { data: existingPending } = await supabase.from('supplier_applications_with').select('id').eq('applicant_id', req.user.id).eq('status', 'pending').maybeSingle();
    if (existingPending) {
      return res.status(409).json({ error: 'Conflict', message: '이미 심사 대기 중인 입점 신청이 있습니다', timestamp: new Date().toISOString() });
    }

    let bizVerified = false, bizStatus = null;
    if (business_number) {
      if (!isValidBusinessNumberFormat(business_number)) {
        return res.status(400).json({ error: 'Bad Request', message: '유효하지 않은 사업자등록번호입니다 (형식 오류)', timestamp: new Date().toISOString() });
      }
      const ntsResult = await verifyBusinessNumberWithNTS(business_number);
      if (ntsResult.checked) {
        if (!ntsResult.exists) {
          return res.status(400).json({ error: 'Bad Request', message: '국세청에 등록되지 않은 사업자등록번호입니다', timestamp: new Date().toISOString() });
        }
        if (ntsResult.status === '폐업자') {
          return res.status(400).json({ error: 'Bad Request', message: `국세청 조회 결과 폐업 상태인 사업자등록번호입니다 (상태: ${ntsResult.status})`, timestamp: new Date().toISOString() });
        }
        bizVerified = ntsResult.active;
        bizStatus = ntsResult.status;
      }
    }

    const { data, error } = await supabase.from('supplier_applications_with').insert([{
      applicant_id: req.user.id,
      company_name: String(company_name).trim(),
      business_number: business_number || null,
      business_number_verified: bizVerified,
      business_number_status: bizStatus,
      contact_person: contact_person || null,
      phone: phone || null,
      email: email || null,
      address: address || null,
      category: category || null,
      business_type: business_type || null,
      product_description: product_description || null,
      status: 'pending'
    }]).select().single();
    if (error) throw error;
    res.status(201).json({ success: true, data, message: '입점 신청이 접수되었습니다. 검토 후 결과를 알려드립니다.', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating supplier application:', err);
    res.status(500).json({ error: 'Failed to create supplier application', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 내 신청 이력(가장 최근 것 기준 상태 확인용 — 마이페이지에서 사용)
app.get('/api/me/supplier-applications', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase.from('supplier_applications_with').select('*').eq('applicant_id', req.user.id).order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching my supplier applications:', err);
    res.status(500).json({ error: 'Failed to fetch supplier applications', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/supplier-applications', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    let query = supabase.from('supplier_applications_with').select('*, profiles!supplier_applications_with_applicant_id_fkey(email, full_name)').order('created_at', { ascending: false });
    if (req.query.status) query = query.eq('status', req.query.status);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching supplier applications:', err);
    res.status(500).json({ error: 'Failed to fetch supplier applications', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/admin/supplier-applications/:id/approve', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: appRow, error: findErr } = await supabase.from('supplier_applications_with').select('*').eq('id', req.params.id).maybeSingle();
    if (findErr) throw findErr;
    if (!appRow) return res.status(404).json({ error: 'Not Found', message: '신청을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (appRow.status !== 'pending') return res.status(400).json({ error: 'Bad Request', message: '이미 처리된 신청입니다', timestamp: new Date().toISOString() });

    const { data: applicantProfile } = await supabase.from('profiles').select('role').eq('id', appRow.applicant_id).maybeSingle();
    if (!applicantProfile) return res.status(404).json({ error: 'Not Found', message: '신청자 계정을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (!['member'].includes(applicantProfile.role)) {
      return res.status(400).json({ error: 'Bad Request', message: `신청자 계정의 현재 권한(${applicantProfile.role})은 이 화면에서 승인 처리할 수 없습니다`, timestamp: new Date().toISOString() });
    }

    const { error: roleErr } = await supabase.from('profiles').update({ role: 'provider' }).eq('id', appRow.applicant_id);
    if (roleErr) throw roleErr;

    const { data, error } = await supabase.from('supplier_applications_with').update({
      status: 'approved', reviewed_by: req.user.id, reviewed_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }).eq('id', req.params.id).select().single();
    if (error) throw error;

    await supabase.from('notifications_with').insert([{
      user_id: appRow.applicant_id,
      type: 'supplier_application_approved',
      title: '입점 신청이 승인되었습니다',
      message: `"${appRow.company_name}" 판매자 입점 신청이 승인되었습니다. 이제 로그인 후 상품을 등록하실 수 있습니다.`,
      link: '/mypage.html'
    }]);

    try {
      await supabase.from('admin_actions').insert([{
        actor_id: req.user.id, action: 'supplier_application_approve', target_type: 'supplier_application', target_id: req.params.id,
        meta: { applicant_id: appRow.applicant_id, company_name: appRow.company_name }
      }]);
    } catch (_) { /* 감사로그 기록 실패는 승인 처리 자체를 막지 않음 */ }

    res.json({ success: true, data, message: '입점 신청을 승인했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error approving supplier application:', err);
    res.status(500).json({ error: 'Failed to approve supplier application', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/admin/supplier-applications/:id/reject', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { reason } = req.body;
    const { data: appRow, error: findErr } = await supabase.from('supplier_applications_with').select('*').eq('id', req.params.id).maybeSingle();
    if (findErr) throw findErr;
    if (!appRow) return res.status(404).json({ error: 'Not Found', message: '신청을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (appRow.status !== 'pending') return res.status(400).json({ error: 'Bad Request', message: '이미 처리된 신청입니다', timestamp: new Date().toISOString() });

    const { data, error } = await supabase.from('supplier_applications_with').update({
      status: 'rejected', reviewed_by: req.user.id, reviewed_at: new Date().toISOString(), rejection_reason: reason || null, updated_at: new Date().toISOString()
    }).eq('id', req.params.id).select().single();
    if (error) throw error;

    await supabase.from('notifications_with').insert([{
      user_id: appRow.applicant_id,
      type: 'supplier_application_rejected',
      title: '입점 신청이 반려되었습니다',
      message: reason ? `"${appRow.company_name}" 입점 신청이 반려되었습니다. 사유: ${reason}` : `"${appRow.company_name}" 입점 신청이 반려되었습니다.`,
      link: '/mypage.html'
    }]);

    try {
      await supabase.from('admin_actions').insert([{
        actor_id: req.user.id, action: 'supplier_application_reject', target_type: 'supplier_application', target_id: req.params.id,
        meta: { applicant_id: appRow.applicant_id, company_name: appRow.company_name, reason: reason || null }
      }]);
    } catch (_) { /* 감사로그 기록 실패는 반려 처리 자체를 막지 않음 */ }

    res.json({ success: true, data, message: '입점 신청을 반려했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error rejecting supplier application:', err);
    res.status(500).json({ error: 'Failed to reject supplier application', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 상품 원가(cost_price) 비노출 화이트리스트 - WITH+에서 포팅. products_with를 select('*')로 조회하면
// cost_price(원가)까지 그대로 API 응답에 실려나가므로, 원가 노출이 필요 없는 일반 조회/목록/추천/찜 등
// 모든 라우트는 이 컬럼 목록으로 select해야 한다. cost_price는 절대 포함하지 않는다.
// (원가 자체가 필요한 관리 화면은 LIVE+에 아직 없다 - 만들게 되면 반드시 requireOwnerStepUp으로 보호할 것)
const PRODUCT_SAFE_COLUMNS = 'id, created_at, name, slug, description, long_description, price, discount_price, category, stock, images_urls, supplier_id, rating, review_count, status, detail_sections, vendor_id, subscription_available, barcode, expiry_date, spec, supply_amount, vat_amount, brand';

// ============================================
// 상품 API
// ============================================

// 모든 상품 조회 (인증 필요 없음 - ANON_KEY 사용)
// ?category=xxx 쿼리로 카테고리 필터링 가능
app.get('/api/products', optionalAuth, async (req, res) => {
  try {
    const searchQuery = (req.query.search || '').trim();

    // 검색어가 있으면 오타허용(trigram 유사도)+부분일치 검색 함수(search_products_with)로 결과를 가져오고,
    // 없으면 지금까지처럼 일반 목록 조회를 그대로 사용한다 (기존 동작 100% 유지).
    let data, error;
    if (searchQuery) {
      ({ data, error } = await supabasePublic.rpc('search_products_with', { search_query: searchQuery, limit_count: 100 }));
    } else {
      let query = supabasePublic
        .from('products_with')
        .select(PRODUCT_SAFE_COLUMNS)
        .eq('status', 'active');

      if (req.query.category) {
        query = query.eq('category', req.query.category);
      }

      // 분양 조직(커뮤니티)을 통해 들어온 경우(?community=슬러그) - 그 조직이 "선택한 상품만 노출"로
      // 설정해두었으면 그 조직에서 지정한 상품으로만 결과를 좁힌다. "전체 노출"이거나 커뮤니티를
      // 특정하지 않은 일반 홈/카테고리 접근이면 지금까지처럼 전체 카탈로그를 그대로 보여준다.
      if (req.query.community) {
        const { data: community } = await supabase
          .from('communities')
          .select('id, product_visibility')
          .eq('slug', req.query.community)
          .eq('status', 'active')
          .single();
        if (community && community.product_visibility === 'curated') {
          const { data: picks } = await supabase
            .from('community_products')
            .select('product_id')
            .eq('community_id', community.id);
          const allowedIds = (picks || []).map(p => p.product_id);
          // 지정된 상품이 하나도 없으면 빈 결과를 정직하게 반환한다(전체 카탈로그로 조용히 되돌아가지 않음)
          query = query.in('id', allowedIds.length > 0 ? allowedIds : ['00000000-0000-0000-0000-000000000000']);
        }
      }

      ({ data, error } = await query);
    }

    if (error) throw error;

    // 검색 개인화 (제안서 5절) - 진짜 연관도가 다른 상품의 순서는 건드리지 않고, SQL에서 이미 동점으로
    // 처리되는 그룹(상품명에 검색어가 그대로 포함되어 relevance가 1로 동일한 상품들, search_products_with 참고)
    // 안에서만 로그인 회원의 선호 카테고리 상품을 앞으로 당긴다. 트라이그램 유사도로만 매칭된(부분 유사) 상품은
    // 서로 연관도가 다르므로 재정렬 대상에서 제외한다 - "동점일 때만" 개인화한다는 원칙을 지킨다.
    if (searchQuery && req.user && Array.isArray(data) && data.length > 1) {
      try {
        const q = searchQuery.toLowerCase();
        const tier1 = []; // 상품명에 검색어가 그대로 포함 - SQL에서 relevance 1로 동점 처리됨
        const tier2 = []; // 트라이그램 유사도로만 걸린 부분 매칭 - 진짜 연관도 순서라 그대로 둠
        data.forEach(p => { (String(p.name || '').toLowerCase().includes(q) ? tier1 : tier2).push(p); });
        if (tier1.length > 1) {
          const signals = await getPersonalizedSignals(req.user.id);
          const catWeight = signals.categoryWeight || {};
          tier1.forEach((p, i) => { p.__origIdx = i; });
          tier1.sort((a, b) => (catWeight[b.category] || 0) - (catWeight[a.category] || 0) || a.__origIdx - b.__origIdx);
          tier1.forEach(p => { delete p.__origIdx; });
        }
        data = [...tier1, ...tier2];
      } catch (personalizeErr) {
        // 개인화 재정렬이 실패해도 검색 자체는 원래(비개인화) 순서로 정상 응답한다 - 정직한 대체
      }
    }

    // 검색 기록은 인기 검색어 집계용으로 남긴다 - 실패해도 검색 결과 응답 자체를 막지 않는다(정직하게 최선을 다해 기록만 시도).
    // supabase-js의 쿼리빌더 반환값에 .catch를 직접 체이닝하면 이 라이브러리 버전에서 문제가 생길 수 있어(과거에 실제로 발견된 버그),
    // await + try/catch로 안전하게 처리한다.
    if (searchQuery) {
      try {
        await supabase.from('search_logs_with').insert([{ query: searchQuery, result_count: data?.length || 0, user_id: null }]);
      } catch (logErr) { /* 검색 로그 기록 실패는 검색 자체를 막지 않는다 */ }
    }

    res.json({
      success: true,
      data: data || [],
      count: data?.length || 0,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching products:', err);
    res.status(500).json({
      error: 'Failed to fetch products',
      message: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// 검색창 자동완성 - 상품명 기준 오타허용 유사도로 상위 몇 개만 가볍게 추천
app.get('/api/search/autocomplete', async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (!q || q.length < 1) {
      return res.json({ success: true, data: [], timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabasePublic.rpc('search_products_with', { search_query: q, limit_count: 8 });
    if (error) throw error;
    const suggestions = (data || []).map(p => ({ id: p.id, name: p.name, image_url: (p.images_urls && p.images_urls[0]) || null, price: p.price }));
    res.json({ success: true, data: suggestions, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching autocomplete suggestions:', err);
    res.status(500).json({ error: 'Failed to fetch autocomplete suggestions', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 인기 검색어 - 최근 30일 검색 기록을 검색어(대소문자 무시) 기준으로 집계해 상위 10개를 보여준다.
// 검색 기록이 아직 없으면(신규 오픈 초기) 빈 배열을 정직하게 반환한다(가짜 인기 검색어를 채우지 않음).
app.get('/api/search/popular', async (req, res) => {
  try {
    const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const { data, error } = await supabase
      .from('search_logs_with')
      .select('query')
      .gte('created_at', since)
      .not('query', 'is', null);
    if (error) throw error;

    const counts = {};
    (data || []).forEach(row => {
      const normalized = row.query.trim().toLowerCase();
      if (!normalized) return;
      counts[normalized] = (counts[normalized] || 0) + 1;
    });
    const popular = Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([query, count]) => ({ query, count }));

    res.json({ success: true, data: popular, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching popular search terms:', err);
    res.status(500).json({ error: 'Failed to fetch popular search terms', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 여러 상품의 옵션(변형) 목록을 한 번에 조회 (장바구니처럼 여러 상품의 옵션명/재고를 한꺼번에 확인할 때 사용, 로그인 불필요, 판매중 옵션만)
app.get('/api/product-variants', async (req, res) => {
  try {
    const ids = String(req.query.product_ids || '').split(',').map(s => s.trim()).filter(Boolean);
    if (ids.length === 0) {
      return res.json({ success: true, data: [], timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabasePublic
      .from('product_variants_with')
      .select('id, product_id, name, option_values, price_adjustment, stock, is_active')
      .in('product_id', ids)
      .eq('is_active', true);
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching product variants:', err);
    res.status(500).json({ error: 'Failed to fetch product variants', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 상품 상세 조회 (인증 필요 없음 - ANON_KEY 사용)
app.get('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabasePublic
      .from('products_with')
      .select(`
        ${PRODUCT_SAFE_COLUMNS},
        reviews:product_reviews(id, rating, title, comment, user_id, created_at, verified_purchase, status)
      `)
      .eq('id', id)
      .single();

    if (error) throw error;
    if (!data) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Product not found',
        timestamp: new Date().toISOString()
      });
    }

    // 옵션(사이즈/색상 등)이 등록된 상품이면 함께 내려준다 (판매중인 옵션만)
    const { data: variants } = await supabasePublic
      .from('product_variants_with')
      .select('id, name, option_values, price_adjustment, stock, is_active')
      .eq('product_id', id)
      .eq('is_active', true)
      .order('created_at', { ascending: true });

    // 관리자가 숨김 처리한(status='hidden') 리뷰는 일반 방문자 화면에 절대 노출되지 않도록 여기서 걸러낸다
    // (nested select에서는 임베드된 리소스를 직접 필터링할 수 없어 응답 직전에 한 번 더 걸러낸다)
    const visibleReviews = (data.reviews || []).filter(r => r.status === 'published').map(r => {
      const { status, ...rest } = r;
      return rest;
    });

    // 리뷰 신뢰도 강화 노출 (제안서 6절 "리뷰 신뢰도 강화 노출") - 실제 구매인증(verified_purchase) 리뷰만으로
    // "평점 4점 이상 비율"을 계산한다. 표본이 너무 적으면(3건 미만) 퍼센트가 왜곡되기 쉬우므로 정직하게
    // null로 남겨 화면에서 아예 배지를 숨긴다(브랜드 데이터가 부족한 상품은 브랜드 신호를 안 쓰는 것과 같은 원칙).
    const REVIEW_SATISFACTION_MIN_COUNT = 3;
    const verifiedReviews = visibleReviews.filter(r => r.verified_purchase);
    const reviewSatisfaction = {
      verified_count: verifiedReviews.length,
      percent: verifiedReviews.length >= REVIEW_SATISFACTION_MIN_COUNT
        ? Math.round((verifiedReviews.filter(r => Number(r.rating) >= 4).length / verifiedReviews.length) * 100)
        : null
    };

    res.json({
      success: true,
      data: { ...data, reviews: visibleReviews, variants: variants || [], review_satisfaction: reviewSatisfaction },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching product:', err);
    res.status(500).json({
      error: 'Failed to fetch product',
      message: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// 상품 생성 (공급자 전용)
// 공급가액/부가세 - 입력값이 없으면 판매가(price)를 부가세 포함가로 보고 표준 10% 세율로 자동 역산한다
// (유통기한/규격/공급가액/부가세 항목이 상품DB에 없던 것을 보완하면서 함께 추가한 헬퍼)
function computeVatSplit(price, suppliedSupplyAmount, suppliedVatAmount) {
  if (suppliedSupplyAmount !== undefined || suppliedVatAmount !== undefined) {
    const supply = suppliedSupplyAmount !== undefined && suppliedSupplyAmount !== null && suppliedSupplyAmount !== ''
      ? Number(suppliedSupplyAmount) : null;
    const vat = suppliedVatAmount !== undefined && suppliedVatAmount !== null && suppliedVatAmount !== ''
      ? Number(suppliedVatAmount) : null;
    return { supply_amount: supply, vat_amount: vat };
  }
  const p = Number(price) || 0;
  const supply = Math.round(p / 1.1);
  return { supply_amount: supply, vat_amount: p - supply };
}

// 상품 바코드/상품코드 자동채번 — 'P' + 6자리 순번(이카운트 등 외부 코드 접두사 A/B/C와 겹치지 않게 구분). 항상 미사용 값만 반환한다.
app.get('/api/admin/products/suggest-barcode', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products_with')
      .select('barcode')
      .like('barcode', 'P______')
      .order('barcode', { ascending: false })
      .limit(1);
    if (error) throw error;
    let nextNum = 1;
    if (data && data[0] && data[0].barcode) {
      const m = String(data[0].barcode).match(/^P(\d{6})$/);
      if (m) nextNum = parseInt(m[1], 10) + 1;
    }
    let candidate = 'P' + String(nextNum).padStart(6, '0');
    // 동시성 등으로 이미 존재할 가능성에 대비해, 비어있는 값을 찾을 때까지 순번을 올려가며 확인한다 (최대 50회 시도)
    for (let attempt = 0; attempt < 50; attempt++) {
      const { data: exists } = await supabase.from('products_with').select('id').eq('barcode', candidate).maybeSingle();
      if (!exists) break;
      nextNum++;
      candidate = 'P' + String(nextNum).padStart(6, '0');
    }
    res.json({ success: true, data: { barcode: candidate }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error suggesting barcode:', err);
    res.status(500).json({ error: 'Failed to suggest barcode', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 상품 바코드/상품코드 중복 확인 — 등록/수정 화면에서 입력 즉시 확인용 (exclude_id: 수정 중인 상품 자신은 제외)
app.get('/api/admin/products/check-barcode', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const barcode = String(req.query.barcode || '').trim();
    const excludeId = req.query.exclude_id ? String(req.query.exclude_id) : null;
    if (!barcode) {
      return res.status(400).json({ error: 'Bad Request', message: '확인할 바코드를 입력해주세요', timestamp: new Date().toISOString() });
    }
    let query = supabase.from('products_with').select('id, name').eq('barcode', barcode);
    if (excludeId) query = query.neq('id', excludeId);
    const { data, error } = await query.maybeSingle();
    if (error) throw error;
    res.json({ success: true, data: { available: !data, existing: data || null }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error checking barcode:', err);
    res.status(500).json({ error: 'Failed to check barcode', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/products', authenticate, async (req, res) => {
  try {
    const { name, description, long_description, price, discount_price, category, stock, images_urls, detail_sections, vendor_id, brand, subscription_available, barcode, expiry_date, spec, supply_amount, vat_amount } = req.body;

    if (!name || !price || !category) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Required fields: name, price, category',
        timestamp: new Date().toISOString()
      });
    }

    const vatSplit = computeVatSplit(price, supply_amount, vat_amount);
    const initialStock = stock ? parseInt(stock, 10) : 0;
    const { data, error } = await supabase
      .from('products_with')
      .insert([{
        name,
        slug: slugify(name),
        description: description || '',
        long_description: long_description || '',
        price: parseFloat(price),
        discount_price: discount_price ? parseFloat(discount_price) : null,
        category,
        stock: 0,
        barcode: barcode ? String(barcode).trim() : null,
        expiry_date: expiry_date || null,
        spec: spec ? String(spec).trim() : null,
        supply_amount: vatSplit.supply_amount,
        vat_amount: vatSplit.vat_amount,
        images_urls: images_urls || [],
        detail_sections: sanitizeDetailSections(detail_sections),
        supplier_id: req.user.id,
        vendor_id: vendor_id || null,
        brand: brand ? String(brand).trim() : null,
        subscription_available: !!subscription_available,
        status: 'active'
      }])
      .select()
      .single();

    if (error) {
      if (error.code === '23503') {
        return res.status(400).json({ error: 'Bad Request', message: '존재하지 않는 공급자입니다', timestamp: new Date().toISOString() });
      }
      if (error.code === '23505') {
        return res.status(409).json({ error: 'Conflict', message: '이미 사용 중인 바코드/상품코드입니다. 다른 코드를 입력하거나 자동생성을 이용해주세요', timestamp: new Date().toISOString() });
      }
      throw error;
    }

    // 초기 재고는 0으로 만든 뒤 재고원장(ledger)에 "신규 상품 등록" 이벤트로 기록하며 반영한다 (모든 증감이 이력에 남도록)
    if (Number.isFinite(initialStock) && initialStock > 0) {
      try {
        await supabase.rpc('adjust_stock_with', {
          p_product_id: data.id, p_variant_id: null, p_delta: initialStock, p_reason: '신규 상품 등록', p_order_id: null, p_created_by: req.user.id, p_scan_source: 'admin_manual'
        });
        data.stock = initialStock;
      } catch (stockErr) { console.error('Error recording initial stock:', stockErr); }
    }

    recordPriceHistory(data.id, data.price, data.discount_price).catch(() => {});

    if (data.status === 'active') {
      triggerCategoryInterestNotifications(data.id, data.name, data.category).catch(() => {});
    }

    res.status(201).json({
      success: true,
      data: data,
      message: 'Product created successfully',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error creating product:', err);
    res.status(500).json({
      error: 'Failed to create product',
      message: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// 상품 수정 (공급자 본인 상품 또는 관리자)
app.put('/api/products/:id', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, long_description, price, discount_price, category, stock, images_urls, detail_sections, status, vendor_id, brand, subscription_available, barcode, expiry_date, spec, supply_amount, vat_amount } = req.body;

    const { data: existing, error: findErr } = await supabase
      .from('products_with')
      .select('id, supplier_id, stock, price, discount_price')
      .eq('id', id)
      .single();

    if (findErr || !existing) {
      return res.status(404).json({ error: 'Not Found', message: 'Product not found', timestamp: new Date().toISOString() });
    }

    if (!isAdminRole(req.userRole) && existing.supplier_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden', message: '본인 상품만 수정할 수 있습니다', timestamp: new Date().toISOString() });
    }

    const updates = {};
    if (name !== undefined) updates.name = name;
    if (description !== undefined) updates.description = description;
    if (long_description !== undefined) updates.long_description = long_description;
    if (price !== undefined) updates.price = parseFloat(price);
    if (discount_price !== undefined) updates.discount_price = discount_price === null || discount_price === '' ? null : parseFloat(discount_price);
    if (category !== undefined) updates.category = category;
    if (images_urls !== undefined) updates.images_urls = images_urls;
    if (detail_sections !== undefined) updates.detail_sections = sanitizeDetailSections(detail_sections);
    if (status !== undefined) updates.status = status;
    if (vendor_id !== undefined) updates.vendor_id = vendor_id || null;
    if (brand !== undefined) updates.brand = brand ? String(brand).trim() : null;
    if (subscription_available !== undefined) updates.subscription_available = !!subscription_available;
    if (barcode !== undefined) updates.barcode = barcode ? String(barcode).trim() : null;
    if (expiry_date !== undefined) updates.expiry_date = expiry_date || null;
    if (spec !== undefined) updates.spec = spec ? String(spec).trim() : null;
    if (supply_amount !== undefined || vat_amount !== undefined) {
      const vatSplit = computeVatSplit(price !== undefined ? price : undefined, supply_amount, vat_amount);
      if (vatSplit.supply_amount !== null) updates.supply_amount = vatSplit.supply_amount;
      if (vatSplit.vat_amount !== null) updates.vat_amount = vatSplit.vat_amount;
    }

    // 옵션(사이즈/색상 등)이 등록된 상품은 재고가 "옵션별 재고의 합"으로 자동 관리되므로,
    // 여기로 직접 들어온 재고값은 무시한다 (옵션 재고는 /api/admin/product-variants/:id 로 조정).
    // 옵션이 없는 상품은 재고원장(adjust_stock_with)을 통해 차액만큼만 원자적으로 반영하고 이력을 남긴다 (직접 덮어쓰지 않음).
    let stockChanged = false;
    if (stock !== undefined) {
      const { data: activeVariants } = await supabase.from('product_variants_with').select('id').eq('product_id', id).eq('is_active', true).limit(1);
      if (!activeVariants || activeVariants.length === 0) {
        const targetStock = parseInt(stock, 10);
        if (Number.isFinite(targetStock) && targetStock >= 0) {
          const delta = targetStock - Number(existing.stock || 0);
          if (delta !== 0) {
            try {
              await supabase.rpc('adjust_stock_with', {
                p_product_id: id, p_variant_id: null, p_delta: delta, p_reason: '관리자 상품정보 수정 중 재고 변경', p_order_id: null, p_created_by: req.user.id, p_scan_source: 'admin_manual'
              });
              stockChanged = true;
            } catch (stockErr) {
              if (stockErr.message && stockErr.message.includes('INSUFFICIENT_STOCK')) {
                return res.status(400).json({ error: 'Bad Request', message: '재고보다 많이 차감할 수 없습니다', timestamp: new Date().toISOString() });
              }
              throw stockErr;
            }
          }
        }
      }
    }

    // stock만 변경되고 다른 필드는 그대로인 경우 updates가 비어있을 수 있으므로(빈 객체로 update 호출하면 오류) 그럴 땐 업데이트를 건너뛰고 최신 행만 다시 읽어온다
    let data;
    if (Object.keys(updates).length > 0) {
      const { data: updated, error } = await supabase
        .from('products_with')
        .update(updates)
        .eq('id', id)
        .select(PRODUCT_SAFE_COLUMNS)
        .single();
      if (error) {
        if (error.code === '23503') {
          return res.status(400).json({ error: 'Bad Request', message: '존재하지 않는 공급자입니다', timestamp: new Date().toISOString() });
        }
        if (error.code === '23505') {
          return res.status(409).json({ error: 'Conflict', message: '이미 사용 중인 바코드/상품코드입니다. 다른 코드를 입력하거나 자동생성을 이용해주세요', timestamp: new Date().toISOString() });
        }
        throw error;
      }
      data = updated;
    } else {
      const { data: current, error } = await supabase.from('products_with').select(PRODUCT_SAFE_COLUMNS).eq('id', id).single();
      if (error) throw error;
      data = current;
    }

    // 재고가 0 이하 -> 양수로 바뀌었으면(= 재입고) 이 상품에 재입고 알림을 신청해둔 회원들에게 알린다
    if (stockChanged && Number(existing.stock) <= 0 && Number(data.stock) > 0) {
      triggerRestockNotifications(id).catch(() => {});
    }

    // 실제 판매가(할인가 우선)가 이전보다 내려갔으면 이 상품을 찜해둔 회원들에게 가격 인하를 알린다
    const oldEffectivePrice = effectivePriceOf(existing);
    const newEffectivePrice = effectivePriceOf(data);
    if (newEffectivePrice < oldEffectivePrice) {
      triggerPriceDropNotifications(id, data.name, oldEffectivePrice, newEffectivePrice).catch(() => {});
    }

    // 가격(price) 또는 할인가(discount_price)가 실제로 바뀌었으면 가격 이력에 스냅샷을 남긴다 (최저가 이력용)
    const priceFieldsChanged = Number(data.price) !== Number(existing.price) || Number(data.discount_price || 0) !== Number(existing.discount_price || 0);
    if (priceFieldsChanged) {
      recordPriceHistory(id, data.price, data.discount_price).catch(() => {});
    }

    res.json({ success: true, data, message: 'Product updated successfully', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating product:', err);
    res.status(500).json({ error: 'Failed to update product', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 상품 삭제 (실제로는 소프트 삭제 - status를 discontinued로 변경, 주문 이력 보존)
app.delete('/api/products/:id', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const { data: existing, error: findErr } = await supabase
      .from('products_with')
      .select('id, supplier_id')
      .eq('id', id)
      .single();

    if (findErr || !existing) {
      return res.status(404).json({ error: 'Not Found', message: 'Product not found', timestamp: new Date().toISOString() });
    }

    if (!isAdminRole(req.userRole) && existing.supplier_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden', message: '본인 상품만 삭제할 수 있습니다', timestamp: new Date().toISOString() });
    }

    const { error } = await supabase
      .from('products_with')
      .update({ status: 'discontinued' })
      .eq('id', id);

    if (error) throw error;

    res.json({ success: true, message: 'Product discontinued successfully', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting product:', err);
    res.status(500).json({ error: 'Failed to delete product', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 상품 소유 계정(supplier_id) 재배정 — 관리자 전용.
// 쇼핑몰이 상품을 직접 등록해 자체재고로 운영하다가 나중에 특정 공급자에게 위탁하거나, 반대로
// 공급자 상품을 쇼핑몰이 직접 사입/자체재고로 전환하고 싶을 때 사용한다(둘 다 같은 products_with 테이블을
// 쓰고 supplier_id만 다르므로, 상품을 새로 만들지 않고도 소유를 옮길 수 있다).
app.patch('/api/products/:id/supplier', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { supplier_id, supplier_email } = req.body;
    if (!supplier_id && !supplier_email) {
      return res.status(400).json({ error: 'Bad Request', message: 'supplier_id 또는 supplier_email 중 하나는 필수입니다', timestamp: new Date().toISOString() });
    }
    const lookupQuery = supabase.from('profiles').select('id, role, full_name, email');
    const { data: targetProfile, error: profErr } = supplier_id
      ? await lookupQuery.eq('id', supplier_id).maybeSingle()
      : await lookupQuery.eq('email', String(supplier_email).trim().toLowerCase()).maybeSingle();
    if (profErr) throw profErr;
    if (!targetProfile) {
      return res.status(400).json({ error: 'Bad Request', message: '존재하지 않는 계정입니다', timestamp: new Date().toISOString() });
    }
    if (!['provider', 'admin', 'super_admin'].includes(targetProfile.role)) {
      return res.status(400).json({ error: 'Bad Request', message: '상품 소유 계정은 공급자(provider) 또는 관리자 계정이어야 합니다', timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase.from('products_with').update({ supplier_id: targetProfile.id }).eq('id', req.params.id).select(PRODUCT_SAFE_COLUMNS).maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '상품을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({
      success: true, data,
      message: `상품 소유가 "${targetProfile.full_name || targetProfile.email}" 계정(${targetProfile.role === 'provider' ? '공급자' : '관리자/자체재고'})으로 변경되었습니다`,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error reassigning product supplier:', err);
    res.status(500).json({ error: 'Failed to reassign product supplier', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자/공급자용 상품 목록 (상태 무관 전체 조회 - 관리자는 전체, 공급자는 본인 상품만)
app.get('/api/admin/products', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    let query = supabase.from('products_with').select(PRODUCT_SAFE_COLUMNS).order('created_at', { ascending: false });

    if (!isAdminRole(req.userRole)) {
      query = query.eq('supplier_id', req.user.id);
    }

    const { data, error } = await query;
    if (error) throw error;

    // 관리자 화면에서 "자체재고(쇼핑몰 직접 등록)" 상품과 "공급자 위탁" 상품을 한눈에 구분할 수 있도록
    // 소유 계정의 role/이름을 함께 내려준다(공급자 정산 로직과 동일한 기준: role='provider'만 "공급자").
    const supplierIds = [...new Set((data || []).map(p => p.supplier_id).filter(Boolean))];
    const { data: ownerProfiles } = supplierIds.length
      ? await supabase.from('profiles').select('id, role, full_name, email').in('id', supplierIds)
      : { data: [] };
    const ownerMap = {};
    (ownerProfiles || []).forEach(p => { ownerMap[p.id] = p; });
    const enriched = (data || []).map(p => {
      const owner = ownerMap[p.supplier_id];
      return {
        ...p,
        owner_role: owner ? owner.role : null,
        owner_name: owner ? (owner.full_name || owner.email) : null,
        is_self_stocked: !owner || owner.role !== 'provider' // 소유 계정이 provider가 아니면(관리자 등) 쇼핑몰 자체재고로 간주
      };
    });

    res.json({ success: true, data: enriched, count: enriched.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin products:', err);
    res.status(500).json({ error: 'Failed to fetch products', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 상품 옵션(사이즈/색상 등) + 재고관리 고도화
// - 상품에 옵션(변형)을 등록하면, 옵션별로 재고/가격조정을 따로 관리할 수 있다
// - 옵션이 있는 상품은 products_with.stock이 "판매 가능한 옵션들의 재고 합"으로 자동 동기화된다(목록/카드에서 보이는 재고)
// - 재고 증감은 adjust_stock_with() DB 함수로 원자적으로 처리해 동시 주문 시 재고가 음수로 내려가지 않도록 한다
// - 모든 증감은 stock_adjustments_with에 이력으로 남는다 (주문 차감/관리자 수동 조정 등)
// ============================================

async function assertProductAccess(productId, req) {
  const { data: product, error } = await supabase
    .from('products_with')
    .select('id, name, supplier_id, stock')
    .eq('id', productId)
    .maybeSingle();
  if (error || !product) return { error: { status: 404, message: '상품을 찾을 수 없습니다' } };
  if (!isAdminRole(req.userRole) && product.supplier_id !== req.user.id) {
    return { error: { status: 403, message: '본인 상품만 관리할 수 있습니다' } };
  }
  return { product };
}

async function syncProductStockFromVariants(productId) {
  const { data: variants } = await supabase
    .from('product_variants_with')
    .select('stock')
    .eq('product_id', productId)
    .eq('is_active', true);
  if (!variants) return;
  const total = variants.reduce((sum, v) => sum + Number(v.stock || 0), 0);
  await supabase.from('products_with').update({ stock: total }).eq('id', productId);
}

// 옵션 목록 조회 (관리자/공급자용 - 비활성 옵션 포함)
app.get('/api/admin/products/:productId/variants', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const access = await assertProductAccess(req.params.productId, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase
      .from('product_variants_with')
      .select('*')
      .eq('product_id', req.params.productId)
      .order('created_at', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching variants:', err);
    res.status(500).json({ error: 'Failed to fetch variants', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 옵션 등록
app.post('/api/admin/products/:productId/variants', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const access = await assertProductAccess(req.params.productId, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }
    const { name, option_values, price_adjustment, stock, sku, barcode } = req.body;
    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: '옵션명을 입력해주세요 (예: 블랙 / L)', timestamp: new Date().toISOString() });
    }
    const initialStock = parseInt(stock, 10);
    if (!Number.isFinite(initialStock) || initialStock < 0) {
      return res.status(400).json({ error: 'Bad Request', message: '옵션 재고는 0 이상의 숫자여야 합니다', timestamp: new Date().toISOString() });
    }

    const { data, error } = await supabase
      .from('product_variants_with')
      .insert([{
        product_id: req.params.productId,
        name: String(name).trim(),
        option_values: (option_values && typeof option_values === 'object') ? option_values : {},
        price_adjustment: price_adjustment ? Number(price_adjustment) : 0,
        stock: initialStock,
        sku: sku ? String(sku).trim() : null,
        barcode: barcode ? String(barcode).trim() : null,
        is_active: true
      }])
      .select()
      .single();
    if (error) throw error;

    if (initialStock > 0) {
      await supabase.from('stock_adjustments_with').insert([{
        product_id: req.params.productId, variant_id: data.id, delta: initialStock, reason: '옵션 신규 등록', created_by: req.user.id
      }]);
    }
    await syncProductStockFromVariants(req.params.productId);

    res.status(201).json({ success: true, data, message: '옵션이 등록되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating variant:', err);
    res.status(500).json({ error: 'Failed to create variant', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 옵션 수정 (이름/가격조정/활성여부/재고 - 재고를 바꾸면 차액만큼 adjust_stock_with로 이력이 남는다)
app.put('/api/admin/product-variants/:variantId', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { data: variant, error: findErr } = await supabase
      .from('product_variants_with')
      .select('*')
      .eq('id', req.params.variantId)
      .maybeSingle();
    if (findErr || !variant) {
      return res.status(404).json({ error: 'Not Found', message: '옵션을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    const access = await assertProductAccess(variant.product_id, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }

    const { name, option_values, price_adjustment, is_active, stock, sku, barcode } = req.body;
    const updates = { updated_at: new Date().toISOString() };
    if (name !== undefined) {
      if (!String(name).trim()) return res.status(400).json({ error: 'Bad Request', message: '옵션명을 입력해주세요', timestamp: new Date().toISOString() });
      updates.name = String(name).trim();
    }
    if (option_values !== undefined) updates.option_values = (option_values && typeof option_values === 'object') ? option_values : {};
    if (price_adjustment !== undefined) updates.price_adjustment = Number(price_adjustment) || 0;
    if (is_active !== undefined) updates.is_active = !!is_active;
    if (sku !== undefined) updates.sku = sku ? String(sku).trim() : null;
    if (barcode !== undefined) updates.barcode = barcode ? String(barcode).trim() : null;

    if (Object.keys(updates).length > 1) {
      const { error: updateErr } = await supabase.from('product_variants_with').update(updates).eq('id', req.params.variantId);
      if (updateErr) throw updateErr;
    }

    // 재고는 "몇 개로 맞출지"를 입력받아 현재값과의 차이만큼 원자적으로 반영한다 (직접 stock 컬럼을 덮어쓰지 않음)
    if (stock !== undefined) {
      const targetStock = parseInt(stock, 10);
      if (!Number.isFinite(targetStock) || targetStock < 0) {
        return res.status(400).json({ error: 'Bad Request', message: '재고는 0 이상의 숫자여야 합니다', timestamp: new Date().toISOString() });
      }
      const delta = targetStock - Number(variant.stock || 0);
      if (delta !== 0) {
        const { error: rpcErr } = await supabase.rpc('adjust_stock_with', {
          p_product_id: variant.product_id, p_variant_id: variant.id, p_delta: delta, p_reason: '관리자 재고 수정', p_order_id: null, p_created_by: req.user.id, p_scan_source: 'admin_manual'
        });
        if (rpcErr) throw rpcErr;
      }
    }

    await syncProductStockFromVariants(variant.product_id);

    const { data: updated } = await supabase.from('product_variants_with').select('*').eq('id', req.params.variantId).single();
    res.json({ success: true, data: updated, message: '옵션이 수정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating variant:', err);
    res.status(500).json({ error: 'Failed to update variant', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 옵션 삭제
app.delete('/api/admin/product-variants/:variantId', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { data: variant, error: findErr } = await supabase
      .from('product_variants_with')
      .select('id, product_id')
      .eq('id', req.params.variantId)
      .maybeSingle();
    if (findErr || !variant) {
      return res.status(404).json({ error: 'Not Found', message: '옵션을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    const access = await assertProductAccess(variant.product_id, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }

    const { error } = await supabase.from('product_variants_with').delete().eq('id', req.params.variantId);
    if (error) throw error;
    await syncProductStockFromVariants(variant.product_id);

    res.json({ success: true, message: '옵션이 삭제되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting variant:', err);
    res.status(500).json({ error: 'Failed to delete variant', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 재고 입출고 이력 조회 (특정 상품 기준)
app.get('/api/admin/products/:productId/stock-adjustments', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const access = await assertProductAccess(req.params.productId, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase
      .from('stock_adjustments_with')
      .select('*')
      .eq('product_id', req.params.productId)
      .order('created_at', { ascending: false })
      .limit(200);
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching stock adjustments:', err);
    res.status(500).json({ error: 'Failed to fetch stock adjustments', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 옵션이 없는 상품의 재고를 관리자가 직접 가감(+/-)할 때 사용 (입고/파손/실사 보정 등) - 이력이 남는다
app.post('/api/admin/stock-adjustments', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { product_id, delta, reason } = req.body;
    if (!product_id || delta === undefined || delta === null) {
      return res.status(400).json({ error: 'Bad Request', message: 'product_id와 delta는 필수입니다', timestamp: new Date().toISOString() });
    }
    const deltaNum = parseInt(delta, 10);
    if (!Number.isFinite(deltaNum) || deltaNum === 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'delta는 0이 아닌 정수여야 합니다', timestamp: new Date().toISOString() });
    }
    const access = await assertProductAccess(product_id, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }

    const { data: newStock, error } = await supabase.rpc('adjust_stock_with', {
      p_product_id: product_id, p_variant_id: null, p_delta: deltaNum, p_reason: (reason && String(reason).trim()) || '관리자 수동 조정', p_order_id: null, p_created_by: req.user.id, p_scan_source: 'admin_manual'
    });
    if (error) {
      if (error.message && error.message.includes('INSUFFICIENT_STOCK')) {
        return res.status(400).json({ error: 'Bad Request', message: '재고보다 많이 차감할 수 없습니다', timestamp: new Date().toISOString() });
      }
      throw error;
    }

    // 재고가 0 이하 -> 양수로 바뀌었으면(= 재입고) 알림 신청자들에게 알린다 (delta를 알고 있으므로 별도 조회 없이 조정 전 재고를 역산)
    const stockBeforeAdjustment = Number(newStock) - deltaNum;
    if (stockBeforeAdjustment <= 0 && Number(newStock) > 0) {
      triggerRestockNotifications(product_id).catch(() => {});
    }

    res.json({ success: true, data: { stock: newStock }, message: '재고가 조정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error adjusting stock:', err);
    res.status(500).json({ error: 'Failed to adjust stock', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 재고 임박 상품 목록 (기본 5개 이하, ?threshold=로 조정 가능) - 옵션이 있는 상품은 옵션별로도 함께 확인
app.get('/api/admin/low-stock', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const threshold = Number.isFinite(Number(req.query.threshold)) ? Number(req.query.threshold) : 5;

    let productQuery = supabase.from('products_with').select('id, name, stock, supplier_id').eq('status', 'active').lte('stock', threshold);
    if (!isAdminRole(req.userRole)) productQuery = productQuery.eq('supplier_id', req.user.id);
    const { data: lowProducts, error: pErr } = await productQuery;
    if (pErr) throw pErr;

    let variantQuery = supabase
      .from('product_variants_with')
      .select('id, name, stock, product_id, products_with!inner(id, name, supplier_id, status)')
      .eq('is_active', true)
      .lte('stock', threshold)
      .eq('products_with.status', 'active');
    if (!isAdminRole(req.userRole)) variantQuery = variantQuery.eq('products_with.supplier_id', req.user.id);
    const { data: lowVariants, error: vErr } = await variantQuery;
    if (vErr) throw vErr;

    res.json({
      success: true,
      data: {
        products: lowProducts || [],
        variants: (lowVariants || []).map(v => ({ id: v.id, name: v.name, stock: v.stock, product_id: v.product_id, product_name: v.products_with ? v.products_with.name : null }))
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching low stock:', err);
    res.status(500).json({ error: 'Failed to fetch low stock', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 창고관리(WMS) API — 재고원장/바코드스캔/로케이션/디지털트윈/AGV(시뮬레이션)
// ------------------------------------------------------------------
// 기반: stock_adjustments_with(불변 재고 원장) + adjust_stock_with() 원자적 RPC는
// 이미 상품/옵션 관리 섹션에서 구축되어 있음(초과판매 방지 포함). 여기서는 그 위에
// 1) lot/serial/로케이션 단위 조회, 2) 바코드 스캔 터미널, 3) 창고 로케이션(2D 좌표) 관리,
// 4) 2D 디지털트윈 뷰어용 데이터, 5) AGV 작업큐(주의: 실제 로봇 하드웨어 연동이 아니라
// 관리자 화면에서 확인 가능한 "시뮬레이션"입니다 — equipment_with.is_simulated=true)를 추가한다.
// ============================================

// 재고 원장(전체) 조회 — 상품별이 아니라 사이트 전체 이력을 필터링하며 볼 수 있음
app.get('/api/admin/inventory/ledger', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize, 10) || 30));
    const from = (page - 1) * pageSize;
    const to = from + pageSize - 1;

    let query = supabase
      .from('stock_adjustments_with')
      .select('*, products_with(name, supplier_id)', { count: 'exact' })
      .order('created_at', { ascending: false });

    if (!isAdminRole(req.userRole)) {
      // 공급사는 본인 상품 이력만 볼 수 있다
      const { data: myProducts } = await supabase.from('products_with').select('id').eq('supplier_id', req.user.id);
      const ids = (myProducts || []).map(p => p.id);
      if (ids.length === 0) {
        return res.json({ success: true, data: [], pagination: { page, pageSize, total: 0, totalPages: 0 }, timestamp: new Date().toISOString() });
      }
      query = query.in('product_id', ids);
    }
    if (req.query.productId) query = query.eq('product_id', req.query.productId);
    if (req.query.lotNumber) query = query.eq('lot_number', req.query.lotNumber);
    if (req.query.serialNumber) query = query.eq('serial_number', req.query.serialNumber);
    if (req.query.locationId) query = query.eq('location_id', req.query.locationId);
    if (req.query.scanSource) query = query.eq('scan_source', req.query.scanSource);
    if (req.query.dateFrom) query = query.gte('created_at', req.query.dateFrom);
    if (req.query.dateTo) query = query.lte('created_at', req.query.dateTo);

    const { data, error, count } = await query.range(from, to);
    if (error) throw error;

    res.json({
      success: true,
      data: (data || []).map(row => ({ ...row, product_name: row.products_with ? row.products_with.name : null, products_with: undefined })),
      pagination: { page, pageSize, total: count || 0, totalPages: Math.ceil((count || 0) / pageSize) },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching inventory ledger:', err);
    res.status(500).json({ error: 'Failed to fetch inventory ledger', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 바코드/SKU로 상품(또는 옵션) 조회 — 스캔 터미널에서 입력 즉시 무엇을 스캔했는지 확인할 때 사용
app.get('/api/admin/inventory/lookup', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const code = (req.query.code || '').trim();
    if (!code) return res.status(400).json({ error: 'Bad Request', message: 'code 파라미터가 필요합니다', timestamp: new Date().toISOString() });

    const { data: variant } = await supabase
      .from('product_variants_with')
      .select('id, name, stock, sku, barcode, product_id, products_with(id, name, supplier_id, stock)')
      .or(`barcode.eq.${code},sku.eq.${code}`)
      .maybeSingle();
    if (variant) {
      if (!isAdminRole(req.userRole) && variant.products_with && variant.products_with.supplier_id !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden', message: '본인 상품만 조회할 수 있습니다', timestamp: new Date().toISOString() });
      }
      return res.json({
        success: true,
        data: { type: 'variant', id: variant.id, name: `${variant.products_with ? variant.products_with.name : ''} - ${variant.name}`, stock: variant.stock, product_id: variant.product_id, variant_id: variant.id },
        timestamp: new Date().toISOString()
      });
    }

    const { data: product } = await supabase
      .from('products_with')
      .select('id, name, stock, barcode, supplier_id')
      .or(`barcode.eq.${code},id.eq.${/^[0-9a-f-]{36}$/i.test(code) ? code : '00000000-0000-0000-0000-000000000000'}`)
      .maybeSingle();
    if (product) {
      if (!isAdminRole(req.userRole) && product.supplier_id !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden', message: '본인 상품만 조회할 수 있습니다', timestamp: new Date().toISOString() });
      }
      return res.json({
        success: true,
        data: { type: 'product', id: product.id, name: product.name, stock: product.stock, product_id: product.id, variant_id: null },
        timestamp: new Date().toISOString()
      });
    }

    res.status(404).json({ error: 'Not Found', message: `바코드/SKU "${code}"에 해당하는 상품을 찾을 수 없습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error looking up barcode:', err);
    res.status(500).json({ error: 'Failed to lookup barcode', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 바코드 스캔 터미널 — 키보드 웨지 방식 스캐너로 연속 입출고 처리 (Lot/시리얼/로케이션 단위 기록)
app.post('/api/admin/inventory/scan', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { product_id, variant_id, delta, lot_number, serial_number, location_id, reason } = req.body;
    if (!product_id || delta === undefined || delta === null) {
      return res.status(400).json({ error: 'Bad Request', message: 'product_id와 delta는 필수입니다', timestamp: new Date().toISOString() });
    }
    const deltaNum = parseInt(delta, 10);
    if (!Number.isFinite(deltaNum) || deltaNum === 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'delta는 0이 아닌 정수여야 합니다', timestamp: new Date().toISOString() });
    }
    const access = await assertProductAccess(product_id, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }

    const { data: newStock, error } = await supabase.rpc('adjust_stock_with', {
      p_product_id: product_id,
      p_variant_id: variant_id || null,
      p_delta: deltaNum,
      p_reason: (reason && String(reason).trim()) || (deltaNum > 0 ? 'PDA 스캔 입고' : 'PDA 스캔 출고'),
      p_order_id: null,
      p_created_by: req.user.id,
      p_lot_number: lot_number ? String(lot_number).trim() : null,
      p_serial_number: serial_number ? String(serial_number).trim() : null,
      p_location_id: location_id || null,
      p_scan_source: 'pda_scan'
    });
    if (error) {
      if (error.message && error.message.includes('INSUFFICIENT_STOCK')) {
        return res.status(400).json({ error: 'Bad Request', message: '재고보다 많이 출고할 수 없습니다', timestamp: new Date().toISOString() });
      }
      throw error;
    }
    if (variant_id) await syncProductStockFromVariants(product_id);

    res.json({ success: true, data: { stock: newStock }, message: '스캔 처리 완료', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error processing scan:', err);
    res.status(500).json({ error: 'Failed to process scan', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ---- 기타이동(창고이동/자가사용/불량처리/재고조정) ----
// 실제 운영 중인 여러 물리 창고(A1/A2/B1/B2/C 등, warehouses_with) 사이의 재고 이동과,
// 판매 외 사유로 재고가 줄어드는 상황(자가사용/불량)을 이력에 명확히 남기기 위한 카테고리형 처리.
// 모두 stock_adjustments_with 원장(adjust_stock_with RPC)을 그대로 사용하므로 기존 재고 집계/판매 로직과 완전히 호환된다.
const WMS_WRITE_OFF_REASONS = { self_use: '자가사용', defect: '불량처리' };

// 창고(로케이션) 간 재고 이동 — 순증감 0이 되도록 출발지에 -수량, 도착지에 +수량 두 건의 이력을 남긴다.
app.post('/api/admin/inventory/transfer', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { product_id, variant_id, from_location_id, to_location_id, quantity, note, lot_number } = req.body;
    if (!product_id || !from_location_id || !to_location_id || quantity === undefined || quantity === null) {
      return res.status(400).json({ error: 'Bad Request', message: 'product_id, from_location_id, to_location_id, quantity는 필수입니다', timestamp: new Date().toISOString() });
    }
    if (String(from_location_id) === String(to_location_id)) {
      return res.status(400).json({ error: 'Bad Request', message: '출발 로케이션과 도착 로케이션이 같습니다', timestamp: new Date().toISOString() });
    }
    const qtyNum = parseInt(quantity, 10);
    if (!Number.isFinite(qtyNum) || qtyNum <= 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'quantity는 1 이상의 정수여야 합니다', timestamp: new Date().toISOString() });
    }
    const access = await assertProductAccess(product_id, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }
    const noteSuffix = note ? ` (${String(note).trim()})` : '';

    const lotNumberTrimmed = lot_number ? String(lot_number).trim() : null;
    const { error: outErr } = await supabase.rpc('adjust_stock_with', {
      p_product_id: product_id, p_variant_id: variant_id || null, p_delta: -qtyNum,
      p_reason: `창고이동 - 출고${noteSuffix}`, p_order_id: null, p_created_by: req.user.id,
      p_location_id: from_location_id, p_scan_source: 'admin_manual', p_lot_number: lotNumberTrimmed
    });
    if (outErr) {
      if (outErr.message && outErr.message.includes('INSUFFICIENT_STOCK')) {
        return res.status(400).json({ error: 'Bad Request', message: '출발 로케이션의 재고보다 많이 이동할 수 없습니다', timestamp: new Date().toISOString() });
      }
      throw outErr;
    }
    const { data: newStock, error: inErr } = await supabase.rpc('adjust_stock_with', {
      p_product_id: product_id, p_variant_id: variant_id || null, p_delta: qtyNum,
      p_reason: `창고이동 - 입고${noteSuffix}`, p_order_id: null, p_created_by: req.user.id,
      p_location_id: to_location_id, p_scan_source: 'admin_manual', p_lot_number: lotNumberTrimmed
    });
    if (inErr) throw inErr; // 입고 실패 시 총 재고량은 이미 -qtyNum 만큼 줄어든 상태이므로 이력을 보고 수동 보정 필요 (극히 드문 DB 오류 상황)

    if (variant_id) await syncProductStockFromVariants(product_id);
    res.json({ success: true, data: { stock: newStock }, message: '창고 간 재고 이동이 완료되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error transferring stock:', err);
    res.status(500).json({ error: 'Failed to transfer stock', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 판매 외 사유(자가사용/불량처리)로 인한 재고 차감 — 사유를 카테고리로 강제해 이력을 명확히 남긴다.
app.post('/api/admin/inventory/write-off', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { product_id, variant_id, quantity, category, location_id, note, lot_number } = req.body;
    if (!product_id || quantity === undefined || quantity === null || !category) {
      return res.status(400).json({ error: 'Bad Request', message: 'product_id, quantity, category는 필수입니다', timestamp: new Date().toISOString() });
    }
    if (!WMS_WRITE_OFF_REASONS[category]) {
      return res.status(400).json({ error: 'Bad Request', message: `category는 ${Object.keys(WMS_WRITE_OFF_REASONS).join('/')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
    }
    const qtyNum = parseInt(quantity, 10);
    if (!Number.isFinite(qtyNum) || qtyNum <= 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'quantity는 1 이상의 정수여야 합니다', timestamp: new Date().toISOString() });
    }
    const access = await assertProductAccess(product_id, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }
    const reasonLabel = WMS_WRITE_OFF_REASONS[category] + (note ? ` (${String(note).trim()})` : '');

    const { data: newStock, error } = await supabase.rpc('adjust_stock_with', {
      p_product_id: product_id, p_variant_id: variant_id || null, p_delta: -qtyNum,
      p_reason: reasonLabel, p_order_id: null, p_created_by: req.user.id,
      p_location_id: location_id || null, p_scan_source: 'admin_manual', p_lot_number: lot_number ? String(lot_number).trim() : null
    });
    if (error) {
      if (error.message && error.message.includes('INSUFFICIENT_STOCK')) {
        return res.status(400).json({ error: 'Bad Request', message: '재고보다 많이 처리할 수 없습니다', timestamp: new Date().toISOString() });
      }
      throw error;
    }
    if (variant_id) await syncProductStockFromVariants(product_id);
    res.json({ success: true, data: { stock: newStock }, message: `${WMS_WRITE_OFF_REASONS[category]} 처리가 완료되었습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error processing write-off:', err);
    res.status(500).json({ error: 'Failed to process write-off', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 재고실사(현물 카운트) 차이 자동 보정 — 관리자가 실사로 센 실제 수량을 입력하면 현재 시스템 재고와의 차이만큼 자동으로 +/- 이력을 남긴다.
app.post('/api/admin/inventory/stocktake', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { product_id, variant_id, counted_quantity, location_id, note } = req.body;
    if (!product_id || counted_quantity === undefined || counted_quantity === null) {
      return res.status(400).json({ error: 'Bad Request', message: 'product_id와 counted_quantity는 필수입니다', timestamp: new Date().toISOString() });
    }
    const countedNum = parseInt(counted_quantity, 10);
    if (!Number.isFinite(countedNum) || countedNum < 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'counted_quantity는 0 이상의 정수여야 합니다', timestamp: new Date().toISOString() });
    }
    const access = await assertProductAccess(product_id, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }

    let currentStock;
    if (location_id) {
      // location_id가 있으면 "이 랙(로케이션)에 실제로 몇 개 있는지"를 실사한 것이므로,
      // 상품 전체재고(여러 랙에 나뉘어 있을 수 있음)와 비교하면 안 되고 그 로케이션에 쌓인
      // 원장 이력만 합산해서 비교해야 한다. (예: 전체재고 50개 중 이 랙엔 5개뿐인데 실사로 5개를
      // 세서 넘기면, 전체재고 기준으로는 delta=-45가 되어 다른 랙 재고까지 엉뚱하게 지워버리는
      // 사고가 난다 - 랙 상세 관리 패널에서 실사 기능을 쓸 때 실제로 발생 가능한 문제였다.)
      let locQuery = supabase.from('stock_adjustments_with').select('delta').eq('product_id', product_id).eq('location_id', location_id);
      locQuery = variant_id ? locQuery.eq('variant_id', variant_id) : locQuery.is('variant_id', null);
      const { data: locRows, error: locErr } = await locQuery;
      if (locErr) throw locErr;
      currentStock = (locRows || []).reduce((sum, r) => sum + Number(r.delta || 0), 0);
    } else if (variant_id) {
      const { data: variant, error: vErr } = await supabase.from('product_variants_with').select('stock').eq('id', variant_id).maybeSingle();
      if (vErr) throw vErr;
      if (!variant) return res.status(404).json({ error: 'Not Found', message: '옵션을 찾을 수 없습니다', timestamp: new Date().toISOString() });
      currentStock = variant.stock;
    } else {
      const { data: product, error: pErr } = await supabase.from('products_with').select('stock').eq('id', product_id).maybeSingle();
      if (pErr) throw pErr;
      if (!product) return res.status(404).json({ error: 'Not Found', message: '상품을 찾을 수 없습니다', timestamp: new Date().toISOString() });
      currentStock = product.stock;
    }

    const delta = countedNum - Number(currentStock || 0);
    if (delta === 0) {
      return res.json({ success: true, data: { stock: currentStock, delta: 0 }, message: '실사 수량이 시스템 재고와 일치합니다 (변경 없음)', timestamp: new Date().toISOString() });
    }
    const reasonLabel = `재고실사 차이 보정(${delta > 0 ? '+' : ''}${delta})` + (note ? ` - ${String(note).trim()}` : '');

    const { data: newStock, error } = await supabase.rpc('adjust_stock_with', {
      p_product_id: product_id, p_variant_id: variant_id || null, p_delta: delta,
      p_reason: reasonLabel, p_order_id: null, p_created_by: req.user.id,
      p_location_id: location_id || null, p_scan_source: 'admin_manual'
    });
    if (error) {
      if (error.message && error.message.includes('INSUFFICIENT_STOCK')) {
        return res.status(400).json({ error: 'Bad Request', message: '재고 보정 처리 중 오류가 발생했습니다', timestamp: new Date().toISOString() });
      }
      throw error;
    }
    if (variant_id) await syncProductStockFromVariants(product_id);
    res.json({ success: true, data: { stock: newStock, delta }, message: `재고실사 차이(${delta > 0 ? '+' : ''}${delta})가 보정되었습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error processing stocktake:', err);
    res.status(500).json({ error: 'Failed to process stocktake', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ---- 다채널 판매(쇼핑몰/라이브방송/오프라인) ----
// 쇼핑몰(온라인) 매출은 기존 주문(orders_with) 플로우를 그대로 사용한다.
// 라이브방송/오프라인 매장은 회원가입 없는 손님도 많고 결제도 그 자리에서 즉시 끝나는 경우가 대부분이라
// 장바구니/배송/마일리지가 딸린 무거운 주문 플로우 대신, 여기서 가볍게 "판매 기록"만 남기고
// 재고 차감은 온라인 주문과 완전히 동일한 adjust_stock_with()로 처리해 재고 풀을 하나로 공유한다.
// → 온라인에서 막 팔린 상품을 모르고 오프라인/라이브에서 또 파는 초과판매를 원천적으로 방지한다.
const WMS_CHANNEL_LABEL = { offline: '오프라인 매장', live: '라이브방송' };
const WMS_CHANNEL_SCAN_SOURCE = { offline: 'offline_pos', live: 'live_commerce' };

app.post('/api/admin/inventory/channel-sales', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { product_id, variant_id, channel, quantity, unit_price, channel_ref, memo } = req.body;
    if (!product_id || !WMS_CHANNEL_LABEL[channel]) {
      return res.status(400).json({ error: 'Bad Request', message: `product_id와 channel(${Object.keys(WMS_CHANNEL_LABEL).join('/')})은 필수입니다`, timestamp: new Date().toISOString() });
    }
    const qty = parseInt(quantity, 10);
    if (!Number.isFinite(qty) || qty <= 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'quantity는 1 이상의 정수여야 합니다', timestamp: new Date().toISOString() });
    }
    const unitPriceNum = Number.isFinite(Number(unit_price)) && Number(unit_price) >= 0 ? Number(unit_price) : 0;
    const totalAmount = qty * unitPriceNum; // 매출 금액은 서버가 직접 계산(클라이언트 값을 신뢰하지 않음)

    const access = await assertProductAccess(product_id, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }

    const { data: sale, error: saleErr } = await supabase
      .from('channel_sales_with')
      .insert([{
        product_id, variant_id: variant_id || null, channel,
        quantity: qty, unit_price: unitPriceNum, total_amount: totalAmount,
        channel_ref: channel_ref ? String(channel_ref).trim() : null,
        memo: memo ? String(memo).trim() : null,
        created_by: req.user.id
      }])
      .select()
      .single();
    if (saleErr) throw saleErr;

    let chStockQuery = supabase.from('product_channel_stock_with').select('id').eq('product_id', product_id).eq('channel', channel);
    chStockQuery = variant_id ? chStockQuery.eq('variant_id', variant_id) : chStockQuery.is('variant_id', null);
    const { data: chRow } = await chStockQuery.maybeSingle();
    let chReserved = false;
    if (chRow) {
      const { data: reserved } = await supabase.rpc('reserve_channel_stock', { p_product_id: product_id, p_variant_id: variant_id || null, p_channel: channel, p_qty: qty });
      if (!reserved) {
        await supabase.from('channel_sales_with').delete().eq('id', sale.id);
        return res.status(400).json({ error: 'Bad Request', message: `이 상품은 ${WMS_CHANNEL_LABEL[channel]} 채널에 배정된 재고가 소진되었습니다`, timestamp: new Date().toISOString() });
      }
      chReserved = true;
    }

    const { error: stockErr } = await supabase.rpc('adjust_stock_with', {
      p_product_id: product_id, p_variant_id: variant_id || null, p_delta: -qty,
      p_reason: `${WMS_CHANNEL_LABEL[channel]} 판매`, p_order_id: null, p_created_by: req.user.id,
      p_scan_source: WMS_CHANNEL_SCAN_SOURCE[channel], p_channel_sale_id: sale.id
    });
    if (stockErr) {
      // 재고 부족 등으로 차감이 실패하면 방금 만든 판매 기록도 되돌려 남기지 않는다(부분 실패 방지)
      if (chReserved) await supabase.rpc('release_channel_stock', { p_product_id: product_id, p_variant_id: variant_id || null, p_channel: channel, p_qty: qty }).catch(() => {});
      await supabase.from('channel_sales_with').delete().eq('id', sale.id);
      if (stockErr.message && stockErr.message.includes('INSUFFICIENT_STOCK')) {
        return res.status(400).json({ error: 'Bad Request', message: '재고보다 많이 판매할 수 없습니다', timestamp: new Date().toISOString() });
      }
      throw stockErr;
    }
    if (variant_id) await syncProductStockFromVariants(product_id);

    res.status(201).json({ success: true, data: sale, message: `${WMS_CHANNEL_LABEL[channel]} 판매가 등록되고 재고가 차감되었습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating channel sale:', err);
    res.status(500).json({ error: 'Failed to create channel sale', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/inventory/channel-sales', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize, 10) || 30));
    const from = (page - 1) * pageSize;
    const to = from + pageSize - 1;

    let query = supabase
      .from('channel_sales_with')
      .select('*, products_with(name, supplier_id), product_variants_with(name)', { count: 'exact' })
      .order('created_at', { ascending: false });

    if (!isAdminRole(req.userRole)) {
      const { data: myProducts } = await supabase.from('products_with').select('id').eq('supplier_id', req.user.id);
      const ids = (myProducts || []).map(p => p.id);
      if (ids.length === 0) {
        return res.json({ success: true, data: [], pagination: { page, pageSize, total: 0, totalPages: 0 }, timestamp: new Date().toISOString() });
      }
      query = query.in('product_id', ids);
    }
    if (req.query.channel) query = query.eq('channel', req.query.channel);
    if (req.query.status) query = query.eq('status', req.query.status);
    if (req.query.productId) query = query.eq('product_id', req.query.productId);
    if (req.query.dateFrom) query = query.gte('created_at', req.query.dateFrom);
    if (req.query.dateTo) query = query.lte('created_at', req.query.dateTo);

    const { data, error, count } = await query.range(from, to);
    if (error) throw error;

    res.json({
      success: true,
      data: (data || []).map(row => ({
        ...row,
        product_name: row.products_with ? row.products_with.name : null,
        variant_name: row.product_variants_with ? row.product_variants_with.name : null,
        products_with: undefined, product_variants_with: undefined
      })),
      pagination: { page, pageSize, total: count || 0, totalPages: Math.ceil((count || 0) / pageSize) },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching channel sales:', err);
    res.status(500).json({ error: 'Failed to fetch channel sales', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 채널별(오늘/기간) 매출 요약 — 쇼핑몰(orders_with) + 라이브방송/오프라인(channel_sales_with)을 한 화면에서 비교
app.get('/api/admin/inventory/channel-sales/summary', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const dateFrom = req.query.dateFrom || new Date(new Date().setHours(0, 0, 0, 0)).toISOString();
    const dateTo = req.query.dateTo || new Date().toISOString();

    const { data: onlineOrders, error: onlineErr } = await supabase
      .from('orders_with')
      .select('final_price, status')
      .gte('created_at', dateFrom)
      .lte('created_at', dateTo);
    if (onlineErr) throw onlineErr;
    const onlineValid = (onlineOrders || []).filter(o => o.status !== 'cancelled' && o.status !== 'refunded');
    const onlineRevenue = onlineValid.reduce((s, o) => s + Number(o.final_price || 0), 0);

    const { data: channelSales, error: chErr } = await supabase
      .from('channel_sales_with')
      .select('channel, total_amount, status')
      .gte('created_at', dateFrom)
      .lte('created_at', dateTo);
    if (chErr) throw chErr;
    const validChannelSales = (channelSales || []).filter(s => s.status !== 'cancelled');
    const sumBy = (ch) => validChannelSales.filter(s => s.channel === ch).reduce((s, r) => s + Number(r.total_amount || 0), 0);
    const countBy = (ch) => validChannelSales.filter(s => s.channel === ch).length;

    const offlineRevenue = sumBy('offline');
    const liveRevenue = sumBy('live');

    res.json({
      success: true,
      data: {
        dateFrom, dateTo,
        online: { revenue: onlineRevenue, count: onlineValid.length },
        offline: { revenue: offlineRevenue, count: countBy('offline') },
        live: { revenue: liveRevenue, count: countBy('live') },
        total: onlineRevenue + offlineRevenue + liveRevenue
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching channel sales summary:', err);
    res.status(500).json({ error: 'Failed to fetch channel sales summary', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.patch('/api/admin/inventory/channel-sales/:id/cancel', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { data: sale, error: findErr } = await supabase.from('channel_sales_with').select('*').eq('id', req.params.id).maybeSingle();
    if (findErr) throw findErr;
    if (!sale) return res.status(404).json({ error: 'Not Found', message: '판매 기록을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (sale.status === 'cancelled') {
      return res.status(400).json({ error: 'Bad Request', message: '이미 취소된 판매입니다', timestamp: new Date().toISOString() });
    }
    const access = await assertProductAccess(sale.product_id, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }

    await supabase.rpc('release_channel_stock', { p_product_id: sale.product_id, p_variant_id: sale.variant_id, p_channel: sale.channel, p_qty: sale.quantity }).catch(() => {});

    const { error: stockErr } = await supabase.rpc('adjust_stock_with', {
      p_product_id: sale.product_id, p_variant_id: sale.variant_id, p_delta: sale.quantity,
      p_reason: `${WMS_CHANNEL_LABEL[sale.channel] || sale.channel} 판매 취소(재고 복원)`, p_order_id: null, p_created_by: req.user.id,
      p_scan_source: 'channel_sale_cancel', p_channel_sale_id: sale.id
    });
    if (stockErr) throw stockErr;
    if (sale.variant_id) await syncProductStockFromVariants(sale.product_id);

    const { data, error } = await supabase
      .from('channel_sales_with')
      .update({ status: 'cancelled', cancelled_at: new Date().toISOString(), cancelled_by: req.user.id })
      .eq('id', sale.id)
      .select()
      .single();
    if (error) throw error;

    res.json({ success: true, data, message: '판매가 취소되고 재고가 복원되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error cancelling channel sale:', err);
    res.status(500).json({ error: 'Failed to cancel channel sale', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ---- 창고(Warehouse) 마스터 ----
// warehouses_with: 실제 물리적으로 분리된 건물/동 단위의 창고 목록(예: A1/A2/B1/B2/C 등).
// warehouse_locations_with(Zone-Rack-Bin 로케이션)는 선택적으로 warehouse_code FK를 통해 이 마스터에 연결된다.
app.get('/api/admin/inventory/warehouses', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('warehouses_with').select('*').order('code', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching warehouses:', err);
    res.status(500).json({ error: 'Failed to fetch warehouses', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 창고 코드 자동채번 — 'WH' + 2자리 순번(기존 A1/B1/C 같은 수기 코드와 겹치지 않는 새 접두사 사용)
app.get('/api/admin/inventory/warehouses/suggest-code', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('warehouses_with').select('code').like('code', 'WH%').order('code', { ascending: false });
    if (error) throw error;
    let maxSeq = 0;
    (data || []).forEach(row => {
      const m = String(row.code || '').match(/^WH(\d{2,})$/);
      if (m) maxSeq = Math.max(maxSeq, parseInt(m[1], 10));
    });
    let seq = maxSeq + 1;
    let candidate = 'WH' + String(seq).padStart(2, '0');
    for (let attempt = 0; attempt < 50; attempt++) {
      const { data: exists } = await supabase.from('warehouses_with').select('code').eq('code', candidate).maybeSingle();
      if (!exists) break;
      seq++;
      candidate = 'WH' + String(seq).padStart(2, '0');
    }
    res.json({ success: true, data: { code: candidate }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error suggesting warehouse code:', err);
    res.status(500).json({ error: 'Failed to suggest warehouse code', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 창고 코드 중복 확인
app.get('/api/admin/inventory/warehouses/check-code', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const code = String(req.query.code || '').trim();
    if (!code) return res.status(400).json({ error: 'Bad Request', message: '확인할 코드를 입력해주세요', timestamp: new Date().toISOString() });
    const { data, error } = await supabase.from('warehouses_with').select('code, name').eq('code', code).maybeSingle();
    if (error) throw error;
    res.json({ success: true, data: { available: !data, existing: data || null }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error checking warehouse code:', err);
    res.status(500).json({ error: 'Failed to check warehouse code', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/inventory/warehouses', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { code, name, address, is_active } = req.body;
    if (!code || !String(code).trim() || !name || !String(name).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: 'code와 name은 필수입니다', timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase
      .from('warehouses_with')
      .insert([{
        code: String(code).trim(),
        name: String(name).trim(),
        address: address ? String(address).trim() : null,
        is_active: is_active === undefined ? true : !!is_active
      }])
      .select()
      .single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Conflict', message: '이미 존재하는 창고 코드입니다', timestamp: new Date().toISOString() });
      throw error;
    }
    res.status(201).json({ success: true, data, message: '창고가 등록되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating warehouse:', err);
    res.status(500).json({ error: 'Failed to create warehouse', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/admin/inventory/warehouses/:code', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { name, address, is_active } = req.body;
    const updates = { updated_at: new Date().toISOString() };
    if (name !== undefined) updates.name = String(name).trim();
    if (address !== undefined) updates.address = address ? String(address).trim() : null;
    if (is_active !== undefined) updates.is_active = !!is_active;
    const { data, error } = await supabase.from('warehouses_with').update(updates).eq('code', req.params.code).select().maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '창고를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({ success: true, data, message: '창고 정보가 수정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating warehouse:', err);
    res.status(500).json({ error: 'Failed to update warehouse', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.delete('/api/admin/inventory/warehouses/:code', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: existing, error: existErr } = await supabase.from('warehouses_with').select('code').eq('code', req.params.code).maybeSingle();
    if (existErr) throw existErr;
    if (!existing) return res.status(404).json({ error: 'Not Found', message: '창고를 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const { data: linked, error: linkErr } = await supabase.from('warehouse_locations_with').select('id').eq('warehouse_code', req.params.code).limit(1);
    if (linkErr) throw linkErr;
    if (linked && linked.length > 0) {
      return res.status(409).json({ error: 'Conflict', message: '이 창고에 연결된 로케이션이 있어 삭제할 수 없습니다. 먼저 로케이션 연결을 해제하세요.', timestamp: new Date().toISOString() });
    }
    const { error } = await supabase.from('warehouses_with').delete().eq('code', req.params.code);
    if (error) throw error;
    res.json({ success: true, message: '창고가 삭제되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting warehouse:', err);
    res.status(500).json({ error: 'Failed to delete warehouse', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ---- 창고 로케이션(Zone-Rack-Bin, 2D 좌표) ----
// CM_PER_CELL: 2D 디지털트윈 평면도의 1칸(grid cell)이 실제로 몇 cm에 해당하는지의 환산 기준.
// 관리자는 랙의 실제 가로/세로/높이를 cm 단위로 직접 입력하고, 평면도에 그려지는 칸 크기(width/height)는 이 값으로 자동 환산된다.
const WMS_CM_PER_CELL = 100; // 1칸 = 100cm(1m)
app.get('/api/admin/inventory/locations', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('warehouse_locations_with').select('*').order('code', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching locations:', err);
    res.status(500).json({ error: 'Failed to fetch locations', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 로케이션 코드 자동채번 — 구역(zone)+층+단을 넣으면 그 안에서 아직 안 쓰인 다음 번호를 제안한다 (예: zone=A, floor=1, sub_level=1 → "A-11-01")
app.get('/api/admin/inventory/locations/suggest-code', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const zone = String(req.query.zone || '').trim().toUpperCase();
    if (!zone) {
      return res.status(400).json({ error: 'Bad Request', message: '구역(zone)을 먼저 입력해주세요', timestamp: new Date().toISOString() });
    }
    const floor = Number.isFinite(Number(req.query.floor)) && Number(req.query.floor) > 0 ? Math.floor(Number(req.query.floor)) : 1;
    const subLevel = Number.isFinite(Number(req.query.sub_level)) && Number(req.query.sub_level) >= 1 && Number(req.query.sub_level) <= 5 ? Math.floor(Number(req.query.sub_level)) : 1;
    const prefix = `${zone}-${floor}${subLevel}-`;
    const { data: existingCodes, error } = await supabase.from('warehouse_locations_with').select('code').like('code', prefix + '%');
    if (error) throw error;
    let maxSeq = 0;
    (existingCodes || []).forEach(row => {
      const m = String(row.code || '').match(new RegExp('^' + prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(\\d+)$'));
      if (m) maxSeq = Math.max(maxSeq, parseInt(m[1], 10));
    });
    let seq = maxSeq + 1;
    let candidate = prefix + String(seq).padStart(2, '0');
    for (let attempt = 0; attempt < 50; attempt++) {
      const { data: exists } = await supabase.from('warehouse_locations_with').select('id').eq('code', candidate).maybeSingle();
      if (!exists) break;
      seq++;
      candidate = prefix + String(seq).padStart(2, '0');
    }
    res.json({ success: true, data: { code: candidate }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error suggesting location code:', err);
    res.status(500).json({ error: 'Failed to suggest location code', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 로케이션 코드 중복 확인
app.get('/api/admin/inventory/locations/check-code', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const code = String(req.query.code || '').trim();
    const excludeId = req.query.exclude_id ? String(req.query.exclude_id) : null;
    if (!code) return res.status(400).json({ error: 'Bad Request', message: '확인할 코드를 입력해주세요', timestamp: new Date().toISOString() });
    let query = supabase.from('warehouse_locations_with').select('id, label').eq('code', code);
    if (excludeId) query = query.neq('id', excludeId);
    const { data, error } = await query.maybeSingle();
    if (error) throw error;
    res.json({ success: true, data: { available: !data, existing: data || null }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error checking location code:', err);
    res.status(500).json({ error: 'Failed to check location code', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/inventory/locations', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { code, zone, rack, bin, label, grid_x, grid_y, width, height, is_obstacle, floor, shape, sub_level, width_cm, depth_cm, height_cm, warehouse_code } = req.body;
    if (!code || !String(code).trim() || !zone || !String(zone).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: 'code와 zone은 필수입니다', timestamp: new Date().toISOString() });
    }
    const VALID_SHAPES = ['rect', 'vertical', 'square', 'conveyor'];
    if (shape !== undefined && !VALID_SHAPES.includes(shape)) {
      return res.status(400).json({ error: 'Bad Request', message: `shape는 ${VALID_SHAPES.join('/')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
    }
    // 실측 치수(cm)가 오면 그것을 기준으로 삼고, 없으면 과거 방식(width/height 칸 수)을 cm로 환산해 채운다.
    const widthCmVal = Number.isFinite(Number(width_cm)) && Number(width_cm) > 0 ? Number(width_cm)
      : (Number.isFinite(Number(width)) && Number(width) > 0 ? Number(width) * WMS_CM_PER_CELL : 100);
    const depthCmVal = Number.isFinite(Number(depth_cm)) && Number(depth_cm) > 0 ? Number(depth_cm)
      : (Number.isFinite(Number(height)) && Number(height) > 0 ? Number(height) * WMS_CM_PER_CELL : 100);
    const heightCmVal = Number.isFinite(Number(height_cm)) && Number(height_cm) > 0 ? Number(height_cm) : 200;
    const { data, error } = await supabase
      .from('warehouse_locations_with')
      .insert([{
        code: String(code).trim(), zone: String(zone).trim(), rack: rack ? String(rack).trim() : null, bin: bin ? String(bin).trim() : null,
        label: label ? String(label).trim() : null,
        grid_x: Number.isFinite(Number(grid_x)) ? Number(grid_x) : 0,
        grid_y: Number.isFinite(Number(grid_y)) ? Number(grid_y) : 0,
        width: widthCmVal / WMS_CM_PER_CELL,
        height: depthCmVal / WMS_CM_PER_CELL,
        width_cm: widthCmVal,
        depth_cm: depthCmVal,
        height_cm: heightCmVal,
        is_obstacle: !!is_obstacle,
        floor: Number.isFinite(Number(floor)) && Number(floor) > 0 ? Number(floor) : 1,
        // sub_level: 한 층(floor) 안에서 다시 나뉘는 단/중층(복층랙) 번호. 1(기본)~5까지 지원, 범위 밖이면 1로 처리.
        sub_level: Number.isFinite(Number(sub_level)) && Number(sub_level) >= 1 && Number(sub_level) <= 5 ? Math.floor(Number(sub_level)) : 1,
        shape: shape || 'rect',
        warehouse_code: warehouse_code ? String(warehouse_code).trim() : null
      }])
      .select()
      .single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Conflict', message: '이미 존재하는 로케이션 코드입니다', timestamp: new Date().toISOString() });
      throw error;
    }
    res.status(201).json({ success: true, data, message: '로케이션이 등록되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating location:', err);
    res.status(500).json({ error: 'Failed to create location', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/admin/inventory/locations/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { code, zone, rack, bin, label, grid_x, grid_y, width, height, is_obstacle, is_active, floor, shape, sub_level, width_cm, depth_cm, height_cm, warehouse_code } = req.body;
    const VALID_SHAPES = ['rect', 'vertical', 'square', 'conveyor'];
    if (shape !== undefined && !VALID_SHAPES.includes(shape)) {
      return res.status(400).json({ error: 'Bad Request', message: `shape는 ${VALID_SHAPES.join('/')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
    }
    const updates = { updated_at: new Date().toISOString() };
    if (code !== undefined) updates.code = String(code).trim();
    if (zone !== undefined) updates.zone = String(zone).trim();
    if (rack !== undefined) updates.rack = rack ? String(rack).trim() : null;
    if (bin !== undefined) updates.bin = bin ? String(bin).trim() : null;
    if (label !== undefined) updates.label = label ? String(label).trim() : null;
    if (grid_x !== undefined) updates.grid_x = Number(grid_x) || 0;
    if (grid_y !== undefined) updates.grid_y = Number(grid_y) || 0;
    // 실측 치수(cm)가 오면 그 값을 기준으로 width/height(칸 수)까지 함께 갱신하고,
    // 없고 과거 방식(width/height 칸 수)만 오면 그 값을 그대로 반영하면서 width_cm/depth_cm도 맞춰 갱신한다.
    if (width_cm !== undefined && Number.isFinite(Number(width_cm)) && Number(width_cm) > 0) {
      updates.width_cm = Number(width_cm);
      updates.width = Number(width_cm) / WMS_CM_PER_CELL;
    } else if (width !== undefined) {
      updates.width = Number(width) || 1;
      updates.width_cm = updates.width * WMS_CM_PER_CELL;
    }
    if (depth_cm !== undefined && Number.isFinite(Number(depth_cm)) && Number(depth_cm) > 0) {
      updates.depth_cm = Number(depth_cm);
      updates.height = Number(depth_cm) / WMS_CM_PER_CELL;
    } else if (height !== undefined) {
      updates.height = Number(height) || 1;
      updates.depth_cm = updates.height * WMS_CM_PER_CELL;
    }
    if (height_cm !== undefined && Number.isFinite(Number(height_cm)) && Number(height_cm) > 0) {
      updates.height_cm = Number(height_cm);
    }
    if (is_obstacle !== undefined) updates.is_obstacle = !!is_obstacle;
    if (is_active !== undefined) updates.is_active = !!is_active;
    if (floor !== undefined) updates.floor = Number.isFinite(Number(floor)) && Number(floor) > 0 ? Number(floor) : 1;
    // sub_level: 한 층 안의 단/중층(복층랙) 번호. 1~5 범위 밖이면 1로 처리.
    if (sub_level !== undefined) updates.sub_level = Number.isFinite(Number(sub_level)) && Number(sub_level) >= 1 && Number(sub_level) <= 5 ? Math.floor(Number(sub_level)) : 1;
    if (shape !== undefined) updates.shape = shape;
    if (warehouse_code !== undefined) updates.warehouse_code = warehouse_code ? String(warehouse_code).trim() : null;

    const { data, error } = await supabase.from('warehouse_locations_with').update(updates).eq('id', req.params.id).select().maybeSingle();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Conflict', message: '이미 존재하는 로케이션 코드입니다', timestamp: new Date().toISOString() });
      throw error;
    }
    if (!data) return res.status(404).json({ error: 'Not Found', message: '로케이션을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({ success: true, data, message: '로케이션이 수정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating location:', err);
    res.status(500).json({ error: 'Failed to update location', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.delete('/api/admin/inventory/locations/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { error } = await supabase.from('warehouse_locations_with').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: '로케이션이 삭제되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting location:', err);
    res.status(500).json({ error: 'Failed to delete location', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ---- 2D 디지털트윈: 특정 로케이션(랙)의 현재 재고 내역 ----
// 랙을 클릭했을 때 "여기에 지금 무엇이 몇 개 있는지"를 바로 보여주기 위한 조회 전용 엔드포인트.
// stock_adjustments_with는 이력만 쌓이는 불변 원장이므로, product_id+variant_id+lot_number 조합별로
// delta를 합산해 "현재 이 랙에 남아있는 수량"을 계산한다(다른 곳의 현재고 계산과 동일한 원리).
// 합계가 0 이하인 조합(이미 전부 빠져나간 것)은 응답에서 제외한다.
// 상품 정보는 원가(cost_price)가 절대 섞여 나가지 않도록 PRODUCT_SAFE_COLUMNS만 사용한다.
app.get('/api/admin/inventory/locations/:id/contents', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { data: location, error: locErr } = await supabase
      .from('warehouse_locations_with')
      .select('id, code, zone, rack, bin, label, floor, sub_level, shape, is_obstacle, warehouse_code')
      .eq('id', req.params.id)
      .maybeSingle();
    if (locErr) throw locErr;
    if (!location) {
      return res.status(404).json({ error: 'Not Found', message: '로케이션을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }

    const { data: rows, error: rowsErr } = await supabase
      .from('stock_adjustments_with')
      .select('product_id, variant_id, lot_number, delta')
      .eq('location_id', req.params.id);
    if (rowsErr) throw rowsErr;

    // product_id + variant_id + lot_number 조합별로 delta 합산 (SQL GROUP BY 대신 Node에서 집계)
    const groups = new Map();
    (rows || []).forEach(r => {
      const key = `${r.product_id}|${r.variant_id || ''}|${r.lot_number || ''}`;
      const g = groups.get(key) || { product_id: r.product_id, variant_id: r.variant_id || null, lot_number: r.lot_number || null, quantity: 0 };
      g.quantity += Number(r.delta) || 0;
      groups.set(key, g);
    });
    let items = Array.from(groups.values()).filter(g => g.quantity > 0);

    if (!items.length) {
      return res.json({ success: true, data: { location, items: [] }, timestamp: new Date().toISOString() });
    }

    const productIds = Array.from(new Set(items.map(i => i.product_id)));
    const variantIds = Array.from(new Set(items.filter(i => i.variant_id).map(i => i.variant_id)));

    const { data: products, error: pErr } = await supabase
      .from('products_with')
      .select(PRODUCT_SAFE_COLUMNS)
      .in('id', productIds);
    if (pErr) throw pErr;
    const productMap = new Map((products || []).map(p => [p.id, p]));

    // provider 역할은 자기 상품만 볼 수 있음 (본인 소유가 아닌 상품이 이 랙에 섞여 있으면 그 항목은 응답에서 제외)
    if (!isAdminRole(req.userRole)) {
      items = items.filter(i => {
        const p = productMap.get(i.product_id);
        return p && p.supplier_id === req.user.id;
      });
    }

    let variantMap = new Map();
    if (variantIds.length) {
      const { data: variants, error: vErr } = await supabase
        .from('product_variants_with')
        .select('id, name, sku, barcode')
        .in('id', variantIds);
      if (vErr) throw vErr;
      variantMap = new Map((variants || []).map(v => [v.id, v]));
    }

    const data = items
      .map(i => {
        const p = productMap.get(i.product_id);
        if (!p) return null; // 삭제된 상품 등 - 안전하게 건너뜀
        const v = i.variant_id ? variantMap.get(i.variant_id) : null;
        return {
          product_id: i.product_id,
          product_name: p.name,
          product_image: (p.images_urls && p.images_urls[0]) || null,
          barcode: (v && v.barcode) || p.barcode || null,
          variant_id: i.variant_id,
          variant_name: v ? v.name : null,
          lot_number: i.lot_number,
          quantity: i.quantity
        };
      })
      .filter(Boolean)
      .sort((a, b) => (a.product_name || '').localeCompare(b.product_name || ''));

    res.json({ success: true, data: { location, items: data }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching location contents:', err);
    res.status(500).json({ error: 'Failed to fetch location contents', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 상품(옵션)-로케이션 매핑
app.post('/api/admin/inventory/product-locations', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { product_id, variant_id, location_id, is_primary } = req.body;
    if (!product_id || !location_id) {
      return res.status(400).json({ error: 'Bad Request', message: 'product_id와 location_id는 필수입니다', timestamp: new Date().toISOString() });
    }
    const access = await assertProductAccess(product_id, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase
      .from('product_location_assignments_with')
      .upsert([{ product_id, variant_id: variant_id || null, location_id, is_primary: !!is_primary }], { onConflict: 'product_id,variant_id,location_id' })
      .select()
      .single();
    if (error) throw error;
    res.status(201).json({ success: true, data, message: '로케이션이 배정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error assigning product location:', err);
    res.status(500).json({ error: 'Failed to assign product location', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/inventory/product-locations/:productId', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const access = await assertProductAccess(req.params.productId, req);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.status === 404 ? 'Not Found' : 'Forbidden', message: access.error.message, timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase
      .from('product_location_assignments_with')
      .select('*, warehouse_locations_with(code, zone, rack, bin, label, grid_x, grid_y)')
      .eq('product_id', req.params.productId);
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching product locations:', err);
    res.status(500).json({ error: 'Failed to fetch product locations', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ---- 2D 디지털트윈: 평면도(로케이션 좌표+장애물) 전체 스냅샷 ----
// 건물은 여러 층(floor)으로 이루어지고, 한 층은 다시 여러 단/중층(sub_level, 복층랙 등)으로 나뉠 수 있다.
// floor만 지정하고 subLevel을 지정하지 않으면 그 층의 1단(기본값)만 보여준다(다른 단 로케이션과 좌표가 겹쳐 보이는 것을 방지).
app.get('/api/admin/inventory/floorplan', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    let query = supabase.from('warehouse_locations_with').select('*').eq('is_active', true).order('code');
    const floorParam = req.query.floor;
    const subLevelParam = req.query.subLevel;
    const hasFloor = floorParam !== undefined && floorParam !== '' && Number.isFinite(Number(floorParam));
    const hasSubLevel = subLevelParam !== undefined && subLevelParam !== '' && Number.isFinite(Number(subLevelParam));
    if (hasFloor) query = query.eq('floor', Number(floorParam));
    if (hasSubLevel) query = query.eq('sub_level', Number(subLevelParam));
    else if (hasFloor) query = query.eq('sub_level', 1);
    const { data: locations, error } = await query;
    if (error) throw error;

    const { data: allFloorsRaw } = await supabase.from('warehouse_locations_with').select('floor, sub_level').eq('is_active', true);
    const floorMap = new Map();
    (allFloorsRaw || []).forEach(r => {
      const f = r.floor;
      if (!floorMap.has(f)) floorMap.set(f, new Set());
      floorMap.get(f).add(r.sub_level || 1);
    });
    let floors = Array.from(floorMap.entries())
      .map(([floor, subSet]) => ({ floor, subLevels: Array.from(subSet).sort((a, b) => a - b) }))
      .sort((a, b) => a.floor - b.floor);
    if (!floors.length) floors = [{ floor: 1, subLevels: [1] }];

    // 목록(텍스트) 보기에서 매 로케이션마다 /contents를 따로 호출하지 않도록, 이 층/단의 로케이션들에 대해
    // 품목 종류 수(item_count)와 총 수량(total_quantity)을 미리 집계해 locations 응답에 얹어준다.
    // (stock_adjustments_with는 이력 원장이므로 product_id+variant_id+lot_number 단위로 delta를 합산해야 "현재 수량"이 나온다 - /contents와 동일한 방식)
    const locationIds = (locations || []).map(l => l.id);
    let locationsWithSummary = locations || [];
    if (locationIds.length) {
      const { data: stockRows } = await supabase
        .from('stock_adjustments_with')
        .select('location_id, product_id, variant_id, lot_number, delta')
        .in('location_id', locationIds);
      let supplierByProduct = new Map();
      if (!isAdminRole(req.userRole) && (stockRows || []).length) {
        const productIdsForScope = Array.from(new Set(stockRows.map(r => r.product_id)));
        const { data: productsForScope } = await supabase.from('products_with').select('id, supplier_id').in('id', productIdsForScope);
        supplierByProduct = new Map((productsForScope || []).map(p => [p.id, p.supplier_id]));
      }
      const groupsByLocation = new Map();
      (stockRows || []).forEach(r => {
        if (!r.location_id) return;
        if (!isAdminRole(req.userRole) && supplierByProduct.get(r.product_id) !== req.user.id) return; // provider는 본인 상품만 집계에 포함
        const locGroups = groupsByLocation.get(r.location_id) || new Map();
        const key = `${r.product_id}|${r.variant_id || ''}|${r.lot_number || ''}`;
        locGroups.set(key, (locGroups.get(key) || 0) + (Number(r.delta) || 0));
        groupsByLocation.set(r.location_id, locGroups);
      });
      locationsWithSummary = (locations || []).map(l => {
        const locGroups = groupsByLocation.get(l.id);
        let itemCount = 0, totalQuantity = 0;
        if (locGroups) {
          locGroups.forEach(qty => { if (qty > 0) { itemCount++; totalQuantity += qty; } });
        }
        return { ...l, item_count: itemCount, total_quantity: totalQuantity };
      });
    }

    const { data: equipment } = await supabase.from('equipment_with').select('*, warehouse_locations_with(code, grid_x, grid_y, floor, sub_level)');
    res.json({
      success: true,
      data: { locations: locationsWithSummary, equipment: equipment || [], floors },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching floorplan:', err);
    res.status(500).json({ error: 'Failed to fetch floorplan', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ---- 2D 디지털트윈: "랙에 있는 물건찾기" - 상품명/바코드로 검색해 어느 랙에 배정되어 있는지 조회 ----
// 여러 상품이 매칭될 수 있고, 한 상품이 여러 로케이션에 배정될 수도 있으므로 (상품, 로케이션) 쌍을 모두 반환한다.
// 프론트엔드는 이 결과의 floor/sub_level/grid_x/grid_y로 디지털트윈 화면의 층을 전환하고 해당 랙으로 확대/이동한다.
app.get('/api/admin/inventory/find-product-location', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    if (!q) {
      return res.json({ success: true, data: [], message: '검색어를 입력해주세요', timestamp: new Date().toISOString() });
    }
    const [{ data: byName, error: nameErr }, { data: byBarcode, error: barcodeErr }] = await Promise.all([
      supabase.from('products_with').select('id, name, barcode, supplier_id').ilike('name', `%${q}%`).limit(20),
      supabase.from('products_with').select('id, name, barcode, supplier_id').ilike('barcode', `%${q}%`).limit(20)
    ]);
    if (nameErr) throw nameErr;
    if (barcodeErr) throw barcodeErr;
    const productMap = new Map();
    (byName || []).forEach(p => productMap.set(p.id, p));
    (byBarcode || []).forEach(p => productMap.set(p.id, p));
    let products = Array.from(productMap.values());
    if (!isAdminRole(req.userRole)) products = products.filter(p => p.supplier_id === req.user.id);
    if (!products.length) {
      return res.json({ success: true, data: [], message: `"${q}"와(과) 일치하는 상품을 찾을 수 없습니다`, timestamp: new Date().toISOString() });
    }
    const productIds = products.map(p => p.id);
    const { data: assignments, error: assignErr } = await supabase
      .from('product_location_assignments_with')
      .select('product_id, variant_id, location_id, is_primary, warehouse_locations_with(code, floor, sub_level, grid_x, grid_y, zone)')
      .in('product_id', productIds);
    if (assignErr) throw assignErr;
    const productById = new Map(products.map(p => [p.id, p]));
    const results = (assignments || [])
      .filter(a => a.warehouse_locations_with && productById.has(a.product_id))
      .map(a => {
        const p = productById.get(a.product_id);
        const loc = a.warehouse_locations_with;
        return {
          product_id: a.product_id,
          product_name: p.name,
          barcode: p.barcode,
          variant_id: a.variant_id,
          is_primary: a.is_primary,
          location_id: a.location_id,
          location_code: loc.code,
          floor: loc.floor || 1,
          sub_level: loc.sub_level || 1,
          grid_x: loc.grid_x,
          grid_y: loc.grid_y,
          zone: loc.zone
        };
      });
    if (!results.length) {
      return res.json({ success: true, data: [], message: `"${q}" 상품은 찾았지만 창고 로케이션에 배정되어 있지 않습니다`, timestamp: new Date().toISOString() });
    }
    res.json({ success: true, data: results, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error finding product location:', err);
    res.status(500).json({ error: 'Failed to find product location', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ---- 장비(PDA/AGV) — is_simulated=true: 실제 하드웨어와 연동되지 않는 데모/시뮬레이션 데이터입니다 ----
app.get('/api/admin/wms/equipment', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('equipment_with').select('*, warehouse_locations_with(code, grid_x, grid_y)').order('name');
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching equipment:', err);
    res.status(500).json({ error: 'Failed to fetch equipment', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/wms/equipment', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { equipment_type, name, current_location_id } = req.body;
    if (!equipment_type || !['pda', 'agv'].includes(equipment_type) || !name || !String(name).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: 'equipment_type(pda/agv)과 name은 필수입니다', timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase
      .from('equipment_with')
      .insert([{ equipment_type, name: String(name).trim(), current_location_id: current_location_id || null, is_simulated: true }])
      .select()
      .single();
    if (error) throw error;
    res.status(201).json({ success: true, data, message: '장비가 등록되었습니다 (시뮬레이션)', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating equipment:', err);
    res.status(500).json({ error: 'Failed to create equipment', message: err.message, timestamp: new Date().toISOString() });
  }
});

// A* 최단경로 탐색 — 그리드 기반, is_obstacle 로케이션은 통과 불가로 처리 (디지털트윈 시각화 + AGV 작업 경로용)
function computeAStarPath(locations, fromLoc, toLoc) {
  const GRID_SIZE = 1;
  const obstacles = new Set(
    locations.filter(l => l.is_obstacle).map(l => `${Math.round(l.grid_x)},${Math.round(l.grid_y)}`)
  );
  const start = { x: Math.round(fromLoc.grid_x), y: Math.round(fromLoc.grid_y) };
  const goal = { x: Math.round(toLoc.grid_x), y: Math.round(toLoc.grid_y) };
  const key = (p) => `${p.x},${p.y}`;
  const heuristic = (a, b) => Math.abs(a.x - b.x) + Math.abs(a.y - b.y);

  const openSet = [start];
  const cameFrom = {};
  const gScore = { [key(start)]: 0 };
  const fScore = { [key(start)]: heuristic(start, goal) };
  let iterations = 0;

  while (openSet.length > 0 && iterations < 2000) {
    iterations++;
    openSet.sort((a, b) => (fScore[key(a)] ?? Infinity) - (fScore[key(b)] ?? Infinity));
    const current = openSet.shift();
    if (current.x === goal.x && current.y === goal.y) {
      const path = [current];
      let k = key(current);
      while (cameFrom[k]) {
        path.unshift(cameFrom[k]);
        k = key(cameFrom[k]);
      }
      return path;
    }
    const neighbors = [
      { x: current.x + GRID_SIZE, y: current.y }, { x: current.x - GRID_SIZE, y: current.y },
      { x: current.x, y: current.y + GRID_SIZE }, { x: current.x, y: current.y - GRID_SIZE }
    ];
    for (const n of neighbors) {
      if (obstacles.has(key(n))) continue;
      const tentativeG = (gScore[key(current)] ?? Infinity) + 1;
      if (tentativeG < (gScore[key(n)] ?? Infinity)) {
        cameFrom[key(n)] = current;
        gScore[key(n)] = tentativeG;
        fScore[key(n)] = tentativeG + heuristic(n, goal);
        if (!openSet.some(o => o.x === n.x && o.y === n.y)) openSet.push(n);
      }
    }
  }
  // 경로를 찾지 못하면(장애물로 완전히 막힘) 직선 이동으로 폴백 표시
  return [start, goal];
}

// AGV 작업 생성 — 실제 로봇에 명령을 보내는 것이 아니라, 관리자 화면에서 진행 상황을 시뮬레이션으로 보여주기 위한 작업 큐입니다.
app.post('/api/admin/wms/agv-tasks', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { equipment_id, task_type, from_location_id, to_location_id, product_id } = req.body;
    if (!from_location_id || !to_location_id) {
      return res.status(400).json({ error: 'Bad Request', message: 'from_location_id와 to_location_id는 필수입니다', timestamp: new Date().toISOString() });
    }
    const { data: locations, error: locErr } = await supabase.from('warehouse_locations_with').select('*');
    if (locErr) throw locErr;
    const fromLoc = locations.find(l => l.id === from_location_id);
    const toLoc = locations.find(l => l.id === to_location_id);
    if (!fromLoc || !toLoc) return res.status(404).json({ error: 'Not Found', message: '출발지 또는 도착지 로케이션을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const path = computeAStarPath(locations, fromLoc, toLoc);

    const { data, error } = await supabase
      .from('agv_tasks_with')
      .insert([{
        equipment_id: equipment_id || null,
        task_type: task_type || 'pick_drop',
        from_location_id, to_location_id,
        product_id: product_id || null,
        status: 'queued',
        path_points: path,
        created_by: req.user.id
      }])
      .select()
      .single();
    if (error) throw error;
    res.status(201).json({ success: true, data, message: 'AGV 작업이 큐에 등록되었습니다 (시뮬레이션)', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating AGV task:', err);
    res.status(500).json({ error: 'Failed to create AGV task', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/wms/agv-tasks', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    let query = supabase.from('agv_tasks_with').select('*, equipment_with(name, battery_pct, status)').order('created_at', { ascending: false }).limit(50);
    if (req.query.status) query = query.eq('status', req.query.status);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching AGV tasks:', err);
    res.status(500).json({ error: 'Failed to fetch AGV tasks', message: err.message, timestamp: new Date().toISOString() });
  }
});

// AGV 작업 상태 진행 (시뮬레이션 — 관리자가 "다음 단계로" 버튼을 눌러 진행시킴: queued→in_progress→completed)
app.patch('/api/admin/wms/agv-tasks/:id/advance', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: task, error: findErr } = await supabase.from('agv_tasks_with').select('*').eq('id', req.params.id).maybeSingle();
    if (findErr || !task) return res.status(404).json({ error: 'Not Found', message: '작업을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const nextStatus = task.status === 'queued' ? 'in_progress' : (task.status === 'in_progress' ? 'completed' : task.status);
    const updates = { status: nextStatus };
    if (nextStatus === 'completed') updates.completed_at = new Date().toISOString();

    const { data, error } = await supabase.from('agv_tasks_with').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;

    if (task.equipment_id) {
      const eqUpdates = { status: nextStatus === 'completed' ? 'idle' : 'active', updated_at: new Date().toISOString() };
      if (nextStatus === 'completed' && task.to_location_id) eqUpdates.current_location_id = task.to_location_id;
      await supabase.from('equipment_with').update(eqUpdates).eq('id', task.equipment_id);
    }

    res.json({ success: true, data, message: '작업 상태가 갱신되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error advancing AGV task:', err);
    res.status(500).json({ error: 'Failed to advance AGV task', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 쿠폰/할인 API (관리자가 언제든 발급/수정 가능)
// ============================================

// 쿠폰 코드는 목록으로 노출하지 않음(누구나 긁어갈 수 있으므로) - 검증 결과만 반환
// (이미 가져온 coupon row 하나에 대해 이 사용자/이 주문금액 기준으로 사용 가능한지 판정하는 공통 로직.
//  validateCouponForUser(코드로 조회)와 findBestCouponForUser(활성 쿠폰 전체 중 최적 1건 탐색) 양쪽에서 재사용한다)
async function evaluateCouponEligibility(coupon, userId, orderAmount) {
  if (!coupon.is_active) return { valid: false, reason: '더 이상 사용할 수 없는 쿠폰입니다' };

  // 라이브 전용 한정 쿠폰 - 그 세션이 지금 실제로 방송 중(live)일 때만 유효, 방송이 끝나면 자동 만료된다.
  if (coupon.live_session_id) {
    const { data: session } = await supabase.from('live_sessions_live').select('status').eq('id', coupon.live_session_id).maybeSingle();
    if (!session || session.status !== 'live') {
      return { valid: false, reason: '이 쿠폰은 라이브 방송 중에만 사용할 수 있습니다' };
    }
  }

  // 마케팅자동화(세그먼트 캠페인/등급유지/구매마일스톤)로 특정 회원에게만 발급된 쿠폰인 경우,
  // target_user_ids에 포함되지 않은 회원은 코드를 알아도 사용할 수 없다(target_user_ids가 없거나
  // 빈 배열이면 기존 쿠폰처럼 조건만 맞으면 누구나 사용 가능 - 완전히 하위호환).
  if (Array.isArray(coupon.target_user_ids) && coupon.target_user_ids.length > 0 && !coupon.target_user_ids.includes(userId)) {
    return { valid: false, reason: '본인에게 발급된 쿠폰이 아닙니다' };
  }

  const now = new Date();
  if (coupon.valid_from && new Date(coupon.valid_from) > now) return { valid: false, reason: '아직 사용 기간이 시작되지 않은 쿠폰입니다' };
  if (coupon.valid_until && new Date(coupon.valid_until) < now) return { valid: false, reason: '유효기간이 지난 쿠폰입니다' };

  if (Number(orderAmount) < Number(coupon.min_order_amount || 0)) {
    return { valid: false, reason: `최소 주문 금액 ${Number(coupon.min_order_amount).toLocaleString('ko-KR')}원 이상부터 사용 가능합니다` };
  }

  if (coupon.usage_limit !== null && coupon.used_count >= coupon.usage_limit) {
    return { valid: false, reason: '쿠폰 사용 가능 횟수를 모두 소진했습니다' };
  }

  const { count: userUsedCount, error: countErr } = await supabase
    .from('coupon_redemptions')
    .select('id', { count: 'exact', head: true })
    .eq('coupon_id', coupon.id)
    .eq('user_id', userId);
  if (countErr) throw countErr;
  if ((userUsedCount || 0) >= coupon.per_user_limit) {
    return { valid: false, reason: '이미 이 쿠폰을 사용하셨습니다 (1인당 사용 횟수 초과)' };
  }

  let discountAmount = coupon.discount_type === 'percent'
    ? Math.floor(Number(orderAmount) * (Number(coupon.discount_value) / 100))
    : Math.floor(Number(coupon.discount_value));
  if (coupon.max_discount_amount !== null && discountAmount > Number(coupon.max_discount_amount)) {
    discountAmount = Number(coupon.max_discount_amount);
  }
  discountAmount = Math.min(discountAmount, Number(orderAmount));

  return { valid: true, coupon, discountAmount };
}

async function validateCouponForUser(code, userId, orderAmount) {
  if (!code) return { valid: false, reason: '쿠폰 코드를 입력해주세요' };

  const { data: coupon, error } = await supabase
    .from('coupons')
    .select('*')
    .eq('code', String(code).trim().toUpperCase())
    .single();

  if (error || !coupon) return { valid: false, reason: '존재하지 않는 쿠폰 코드입니다' };
  return evaluateCouponEligibility(coupon, userId, orderAmount);
}

// 이 사용자가 지금 이 주문 금액으로 실제 사용 가능한 쿠폰 중 할인액이 가장 큰 1건을 찾는다.
// (코드를 모르는 사용자도 자동으로 혜택을 받을 수 있게 하기 위함 - 단, 코드 자체를 목록으로 응답하지 않고
//  "지금 이 사람에게 적용 가능한 것"만 서버가 판단해서 딱 1건만 돌려주므로 전체 쿠폰 목록 유출과는 다르다)
async function findBestCouponForUser(userId, orderAmount) {
  const { data: activeCoupons, error } = await supabase
    .from('coupons')
    .select('*')
    .eq('is_active', true);
  if (error || !activeCoupons || activeCoupons.length === 0) return null;

  let best = null;
  for (const coupon of activeCoupons) {
    const result = await evaluateCouponEligibility(coupon, userId, orderAmount);
    if (result.valid && (!best || result.discountAmount > best.discountAmount)) {
      best = result;
    }
  }
  return best;
}

// 회원: 쿠폰 코드 검증 (실제 적용 전 미리보기)
app.post('/api/coupons/validate', authenticate, async (req, res) => {
  try {
    const { code, order_amount } = req.body;
    if (order_amount === undefined || isNaN(Number(order_amount))) {
      return res.status(400).json({ error: 'Bad Request', message: 'order_amount가 필요합니다', timestamp: new Date().toISOString() });
    }
    const result = await validateCouponForUser(code, req.user.id, Number(order_amount));
    if (!result.valid) {
      return res.status(400).json({ success: false, message: result.reason, timestamp: new Date().toISOString() });
    }
    res.json({
      success: true,
      data: {
        code: result.coupon.code,
        label: result.coupon.label,
        discountAmount: result.discountAmount,
        finalAmount: Number(order_amount) - result.discountAmount
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error validating coupon:', err);
    res.status(500).json({ error: 'Failed to validate coupon', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 회원: 지금 이 주문 금액으로 사용 가능한 쿠폰이 있는지 자동으로 찾아준다 (장바구니에서 코드를 몰라도 자동 적용 안내에 사용)
// 전체 쿠폰 목록을 노출하는 것이 아니라, 이 사용자에게 지금 적용 가능한 것 중 가장 할인액이 큰 1건만 돌려준다
app.get('/api/coupons/best-available', authenticate, async (req, res) => {
  try {
    const orderAmount = Number(req.query.amount);
    if (!Number.isFinite(orderAmount) || orderAmount <= 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'amount가 필요합니다', timestamp: new Date().toISOString() });
    }
    const best = await findBestCouponForUser(req.user.id, orderAmount);
    if (!best) {
      return res.json({ success: true, data: null, timestamp: new Date().toISOString() });
    }
    res.json({
      success: true,
      data: {
        code: best.coupon.code,
        label: best.coupon.label,
        discountAmount: best.discountAmount,
        finalAmount: orderAmount - best.discountAmount
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error finding best available coupon:', err);
    res.status(500).json({ error: 'Failed to find best coupon', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 이 사용자가 지금 이 주문 금액으로 실제 사용 가능한 쿠폰을 전부 찾는다 (findBestCouponForUser와 달리 1건이 아니라 목록 전체).
// 마감이 임박한 쿠폰(COUPON_EXPIRING_SOON_DAYS일 이내)이 있으면 할인액과 무관하게 맨 앞으로 올려서,
// 구매자가 "할인액은 작아도 곧 사라지는 쿠폰"을 놓치지 않고 직접 선택해 쓸 수 있게 한다.
const COUPON_EXPIRING_SOON_DAYS = 3;
async function findAllAvailableCouponsForUser(userId, orderAmount) {
  const { data: activeCoupons, error } = await supabase
    .from('coupons')
    .select('*')
    .eq('is_active', true);
  if (error || !activeCoupons || activeCoupons.length === 0) return [];

  const now = Date.now();
  const results = [];
  for (const coupon of activeCoupons) {
    const result = await evaluateCouponEligibility(coupon, userId, orderAmount);
    if (!result.valid) continue;
    let daysLeft = null;
    if (coupon.valid_until) {
      daysLeft = Math.ceil((new Date(coupon.valid_until).getTime() - now) / (1000 * 60 * 60 * 24));
    }
    results.push({
      code: coupon.code,
      label: coupon.label,
      discount_type: coupon.discount_type,
      discount_value: coupon.discount_value,
      discountAmount: result.discountAmount,
      finalAmount: Number(orderAmount) - result.discountAmount,
      valid_until: coupon.valid_until,
      days_left: daysLeft,
      is_expiring_soon: daysLeft !== null && daysLeft <= COUPON_EXPIRING_SOON_DAYS
    });
  }

  results.sort((a, b) => {
    if (a.is_expiring_soon !== b.is_expiring_soon) return a.is_expiring_soon ? -1 : 1;
    if (a.is_expiring_soon) return a.days_left - b.days_left; // 임박한 것끼리는 더 급한(days_left가 작은) 순
    return b.discountAmount - a.discountAmount; // 나머지는 할인액 큰 순
  });
  return results;
}

// 회원: 지금 이 주문 금액으로 사용 가능한 쿠폰 전체 목록 (마감 임박 쿠폰을 놓치지 않도록 눈에 띄게 보여주기 위함).
// best는 할인액이 가장 큰 1건(기존 자동적용 기준과 동일, 하위호환) - 프론트는 이걸 기본 자동적용하고, all 목록은 "다른 쿠폰 보기"에서 사용자가 직접 선택할 수 있게 노출한다.
app.get('/api/coupons/available', authenticate, async (req, res) => {
  try {
    const orderAmount = Number(req.query.amount);
    if (!Number.isFinite(orderAmount) || orderAmount <= 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'amount가 필요합니다', timestamp: new Date().toISOString() });
    }
    const all = await findAllAvailableCouponsForUser(req.user.id, orderAmount);
    let best = null;
    for (const c of all) {
      if (!best || c.discountAmount > best.discountAmount) best = c;
    }
    res.json({ success: true, data: { best, all, count: all.length }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error finding available coupons:', err);
    res.status(500).json({ error: 'Failed to find available coupons', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 쿠폰 목록
app.get('/api/admin/coupons', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('coupons').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], count: data?.length || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching coupons:', err);
    res.status(500).json({ error: 'Failed to fetch coupons', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 쿠폰 생성
// 쿠폰 코드 자동채번 — 알아보기 쉬운 8자리 랜덤 코드(혼동되는 0/O, 1/I 제외)를 생성하되, 서버에서 실제 중복 여부를 확인해 미사용 값만 돌려준다
app.get('/api/admin/coupons/suggest-code', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    function randomCode() {
      let code = '';
      for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
      return code;
    }
    let candidate = randomCode();
    for (let attempt = 0; attempt < 50; attempt++) {
      const { data: exists } = await supabase.from('coupons').select('id').eq('code', candidate).maybeSingle();
      if (!exists) break;
      candidate = randomCode();
    }
    res.json({ success: true, data: { code: candidate }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error suggesting coupon code:', err);
    res.status(500).json({ error: 'Failed to suggest coupon code', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/coupons', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { code, label, discount_type, discount_value, max_discount_amount, min_order_amount, usage_limit, per_user_limit, valid_from, valid_until, live_session_id } = req.body;
    if (!code || !label || !discount_type || !discount_value) {
      return res.status(400).json({ error: 'Bad Request', message: 'Required fields: code, label, discount_type, discount_value', timestamp: new Date().toISOString() });
    }
    if (!['percent', 'fixed'].includes(discount_type)) {
      return res.status(400).json({ error: 'Bad Request', message: "discount_type은 'percent' 또는 'fixed'여야 합니다", timestamp: new Date().toISOString() });
    }
    if (live_session_id) {
      const { data: sessionCheck } = await supabase.from('live_sessions_live').select('id').eq('id', live_session_id).maybeSingle();
      if (!sessionCheck) return res.status(400).json({ error: 'Bad Request', message: '존재하지 않는 라이브 세션입니다', timestamp: new Date().toISOString() });
    }

    const { data, error } = await supabase
      .from('coupons')
      .insert([{
        code: String(code).trim().toUpperCase(),
        label,
        discount_type,
        discount_value: Number(discount_value),
        max_discount_amount: max_discount_amount ? Number(max_discount_amount) : null,
        min_order_amount: min_order_amount ? Number(min_order_amount) : 0,
        usage_limit: usage_limit ? Number(usage_limit) : null,
        per_user_limit: per_user_limit ? Number(per_user_limit) : 1,
        valid_from: valid_from || new Date().toISOString(),
        valid_until: valid_until || null,
        live_session_id: live_session_id || null,
        is_active: true,
        created_by: req.user.id
      }])
      .select()
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'Conflict', message: '이미 존재하는 쿠폰 코드입니다', timestamp: new Date().toISOString() });
      }
      throw error;
    }
    res.status(201).json({ success: true, data, message: '쿠폰이 생성되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating coupon:', err);
    res.status(500).json({ error: 'Failed to create coupon', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 쿠폰 수정
app.put('/api/admin/coupons/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { label, discount_type, discount_value, max_discount_amount, min_order_amount, usage_limit, per_user_limit, valid_from, valid_until, is_active } = req.body;
    const updates = { updated_at: new Date().toISOString() };
    if (label !== undefined) updates.label = label;
    if (discount_type !== undefined) {
      if (!['percent', 'fixed'].includes(discount_type)) {
        return res.status(400).json({ error: 'Bad Request', message: "discount_type은 'percent' 또는 'fixed'여야 합니다", timestamp: new Date().toISOString() });
      }
      updates.discount_type = discount_type;
    }
    if (discount_value !== undefined) updates.discount_value = Number(discount_value);
    if (max_discount_amount !== undefined) updates.max_discount_amount = max_discount_amount === null || max_discount_amount === '' ? null : Number(max_discount_amount);
    if (min_order_amount !== undefined) updates.min_order_amount = Number(min_order_amount) || 0;
    if (usage_limit !== undefined) updates.usage_limit = usage_limit === null || usage_limit === '' ? null : Number(usage_limit);
    if (per_user_limit !== undefined) updates.per_user_limit = Number(per_user_limit) || 1;
    if (valid_from !== undefined) updates.valid_from = valid_from;
    if (valid_until !== undefined) updates.valid_until = valid_until || null;
    if (is_active !== undefined) updates.is_active = !!is_active;

    const { data, error } = await supabase.from('coupons').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: 'Coupon not found', timestamp: new Date().toISOString() });
    res.json({ success: true, data, message: '쿠폰이 수정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating coupon:', err);
    res.status(500).json({ error: 'Failed to update coupon', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 쿠폰 삭제
app.delete('/api/admin/coupons/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { error } = await supabase.from('coupons').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: '쿠폰이 삭제되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting coupon:', err);
    res.status(500).json({ error: 'Failed to delete coupon', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 📢 마케팅자동화 - 세그먼트 캠페인 + 등급유지/구매마일스톤 자동 쿠폰
// - 기존 coupons 테이블에 target_user_ids(특정 회원에게만 발급)를 추가해 그대로 재사용한다(위의
//   evaluateCouponEligibility에서 이미 검증 로직을 추가해뒀다) - 새로운 "쿠폰함" 시스템을 따로 만들지
//   않고, 회원이 체크아웃에서 코드를 입력(또는 findBestCouponForUser로 자동 적용)하는 기존 흐름을 그대로 탄다.
// - 등급은 profiles에 저장되는 값이 아니라 누적 구매액으로 매번 계산되는 값(resolveMemberGrade)이라
//   "등급이 바뀌는 순간"을 이벤트로 잡을 수 없다. 그래서 "지금 이 등급을 유지하고 있는 회원 중 이번
//   달에 아직 못 받은 사람"을 매일 스캔하는 방식으로 구현했다(이벤트 기반보다 놓치는 경우가 없고,
//   coupon_automation_issuances_with의 유니크 제약(rule_id, user_id, period_key)이 중복 발급을
//   DB 레벨에서 원천 차단한다).
// ============================================

// 회원 세그먼트(등급/누적구매액/주문건수/미구매기간/가입일)를 조건에 맞춰 찾아준다.
// 세그먼트 캠페인 미리보기/발송과 자동 쿠폰 규칙(등급유지/구매마일스톤) 스캔이 모두 이 함수를 재사용한다.
async function computeSegmentMatches(filter = {}) {
  const grades = await getMemberGrades();
  const { data: profiles, error: profErr } = await supabase
    .from('profiles')
    .select('id, email, full_name, is_active, created_at')
    .or('is_active.is.null,is_active.eq.true'); // is_active를 아직 안 쓰는 기존 회원(null)은 활성으로 취급 - 기존 관행과 동일
  if (profErr) throw profErr;

  const userIds = (profiles || []).map(p => p.id);
  const ordersByUser = {};
  if (userIds.length > 0) {
    const { data: orders, error: ordErr } = await supabase
      .from('orders_with')
      .select('user_id, final_price, status, created_at')
      .in('user_id', userIds)
      .not('status', 'in', '(cancelled,refunded)'); // 취소/환불은 등급과 마찬가지로 실적에서 제외 (getUserCumulativeSpent와 동일한 기준)
    if (ordErr) throw ordErr;
    (orders || []).forEach(o => {
      if (!ordersByUser[o.user_id]) ordersByUser[o.user_id] = { orderCount: 0, totalSpent: 0, lastOrderAt: null };
      const s = ordersByUser[o.user_id];
      s.orderCount += 1;
      s.totalSpent += Number(o.final_price || 0);
      if (!s.lastOrderAt || new Date(o.created_at) > new Date(s.lastOrderAt)) s.lastOrderAt = o.created_at;
    });
  }

  const nowMs = Date.now();
  const matched = [];
  for (const p of profiles || []) {
    const stats = ordersByUser[p.id] || { orderCount: 0, totalSpent: 0, lastOrderAt: null };
    const { current } = resolveMemberGrade(stats.totalSpent, grades);

    if (Array.isArray(filter.grades) && filter.grades.length > 0 && !filter.grades.includes(current.key)) continue;
    if (filter.minTotalSpent != null && filter.minTotalSpent !== '' && stats.totalSpent < Number(filter.minTotalSpent)) continue;
    if (filter.maxTotalSpent != null && filter.maxTotalSpent !== '' && stats.totalSpent > Number(filter.maxTotalSpent)) continue;
    if (filter.minOrderCount != null && filter.minOrderCount !== '' && stats.orderCount < Number(filter.minOrderCount)) continue;
    if (filter.maxOrderCount != null && filter.maxOrderCount !== '' && stats.orderCount > Number(filter.maxOrderCount)) continue;
    if (filter.noPurchaseSinceDays != null && filter.noPurchaseSinceDays !== '') {
      // "N일 이상 미구매(재구매 유도)"는 구매 이력이 있는데 오래 뜸한 회원이 대상이다 - 한 번도
      // 구매한 적 없는 회원은 "미구매 회원"이라는 별개의 세그먼트이므로 여기서는 제외한다.
      const cutoff = nowMs - Number(filter.noPurchaseSinceDays) * 24 * 60 * 60 * 1000;
      if (!stats.lastOrderAt || new Date(stats.lastOrderAt).getTime() > cutoff) continue;
    }
    if (filter.joinedAfter && new Date(p.created_at) < new Date(filter.joinedAfter)) continue;
    if (filter.joinedBefore && new Date(p.created_at) > new Date(filter.joinedBefore)) continue;

    matched.push({
      id: p.id, email: p.email, full_name: p.full_name, grade: current.key,
      totalSpent: stats.totalSpent, orderCount: stats.orderCount, lastOrderAt: stats.lastOrderAt, createdAt: p.created_at
    });
  }
  return matched;
}

function generateAutoCouponCode(prefix) {
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
}

const COUPON_TEMPLATE_FIELDS_REQUIRED = ['label', 'discount_type', 'discount_value'];
function validateCouponTemplate(t) {
  if (!t || typeof t !== 'object') return '쿠폰 내용(coupon_template)이 필요합니다';
  for (const f of COUPON_TEMPLATE_FIELDS_REQUIRED) if (!t[f]) return `쿠폰 내용에 ${f}가 필요합니다`;
  if (!['percent', 'fixed'].includes(t.discount_type)) return "discount_type은 'percent' 또는 'fixed'여야 합니다";
  if (!(Number(t.discount_value) > 0)) return 'discount_value는 0보다 커야 합니다';
  return null;
}

// 대상 회원 목록에게 쿠폰 1건을 발급(target_user_ids로 그 사람들만 사용 가능하게 제한)하고 알림까지 보낸다.
async function issueCouponForBatch(userIds, template, source, { codePrefix = 'AUTO', notifyTitle, notifyMessage } = {}) {
  if (!userIds || userIds.length === 0) return null;
  const validDays = Number(template.valid_days) > 0 ? Number(template.valid_days) : 30;
  const { data: coupon, error } = await supabase.from('coupons').insert([{
    code: generateAutoCouponCode(codePrefix),
    label: template.label || '자동 발급 쿠폰',
    discount_type: template.discount_type === 'percent' ? 'percent' : 'fixed',
    discount_value: Number(template.discount_value) || 0,
    max_discount_amount: template.max_discount_amount ? Number(template.max_discount_amount) : null,
    min_order_amount: Number(template.min_order_amount) || 0,
    per_user_limit: Number(template.per_user_limit) > 0 ? Number(template.per_user_limit) : 1,
    valid_from: new Date().toISOString(),
    valid_until: new Date(Date.now() + validDays * 24 * 60 * 60 * 1000).toISOString(),
    is_active: true,
    target_user_ids: userIds,
    source
  }]).select().single();
  if (error) throw error;

  const notifRows = userIds.map(uid => ({
    user_id: uid,
    type: 'marketing_coupon',
    title: notifyTitle || `${coupon.label} 지급 안내`,
    message: notifyMessage || `쿠폰(${coupon.code})이 발급되었습니다. 마이페이지에서 확인해보세요.`,
    link: '/mypage.html'
  }));
  const { error: notifErr } = await supabase.from('notifications_with').insert(notifRows);
  if (notifErr) console.error('Error sending marketing coupon notifications:', notifErr); // 알림 실패는 쿠폰 발급 자체를 막지 않음

  return coupon;
}

// 관리자: 세그먼트 미리보기 (실제 쿠폰을 발급하지 않고, 조건에 맞는 회원 수/샘플만 확인)
app.post('/api/admin/marketing/segment-preview', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const matches = await computeSegmentMatches(req.body || {});
    res.json({
      success: true,
      data: {
        matchedCount: matches.length,
        sample: matches.slice(0, 20).map(m => ({ email: m.email, full_name: m.full_name, grade: m.grade, totalSpent: m.totalSpent, orderCount: m.orderCount }))
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error previewing segment:', err);
    res.status(500).json({ error: 'Failed to preview segment', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 세그먼트 캠페인 발송 (조건에 맞는 회원 전체에게 타겟 쿠폰 1건 발급 + 알림 발송)
app.post('/api/admin/marketing/campaigns', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { name, segment_filter, coupon } = req.body;
    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: '캠페인 이름이 필요합니다', timestamp: new Date().toISOString() });
    }
    const templateErr = validateCouponTemplate(coupon);
    if (templateErr) return res.status(400).json({ error: 'Bad Request', message: templateErr, timestamp: new Date().toISOString() });

    const matches = await computeSegmentMatches(segment_filter || {});
    if (matches.length === 0) {
      return res.status(400).json({ error: 'Bad Request', message: '조건에 맞는 회원이 없습니다. 조건을 조정해주세요.', timestamp: new Date().toISOString() });
    }

    const issuedCoupon = await issueCouponForBatch(matches.map(m => m.id), coupon, 'segment_campaign', {
      codePrefix: 'CAMP',
      notifyTitle: `[${name}] 쿠폰이 도착했어요`,
      notifyMessage: `"${name}" 캠페인으로 쿠폰(${coupon.label})이 발급되었습니다. 마이페이지에서 확인해보세요.`
    });

    const { data: campaign, error: campErr } = await supabase.from('marketing_campaigns_with').insert([{
      name: String(name).trim(),
      segment_filter: segment_filter || {},
      matched_user_count: matches.length,
      coupon_id: issuedCoupon.id,
      created_by: req.user.id
    }]).select().single();
    if (campErr) throw campErr;

    await supabase.from('coupons').update({ campaign_id: campaign.id }).eq('id', issuedCoupon.id);

    res.status(201).json({
      success: true,
      data: { campaign, coupon: issuedCoupon, matchedCount: matches.length },
      message: `${matches.length}명에게 쿠폰이 발급되었습니다`,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error creating marketing campaign:', err);
    res.status(500).json({ error: 'Failed to create campaign', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 캠페인 이력 (발급 쿠폰의 사용 현황 포함)
app.get('/api/admin/marketing/campaigns', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    // coupons 테이블과는 두 개의 FK 관계가 있어(campaigns.coupon_id -> coupons.id, coupons.campaign_id ->
    // campaigns.id) PostgREST가 임베딩을 자동으로 고르지 못한다. 캠페인이 실제로 발급한 쿠폰 1건을 가리키는
    // coupon_id 관계(marketing_campaigns_with_coupon_id_fkey)를 명시해 모호함을 해소한다.
    const { data: campaigns, error } = await supabase
      .from('marketing_campaigns_with')
      .select('*, coupons!marketing_campaigns_with_coupon_id_fkey(code, label, used_count, is_active, valid_until)')
      .order('created_at', { ascending: false })
      .limit(100);
    if (error) throw error;
    res.json({ success: true, data: campaigns || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching marketing campaigns:', err);
    res.status(500).json({ error: 'Failed to fetch campaigns', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 자동 쿠폰 규칙 CRUD (등급유지 grade / 구매마일스톤 purchase_milestone)
app.get('/api/admin/marketing/automation-rules', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('coupon_automation_rules_with').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching automation rules:', err);
    res.status(500).json({ error: 'Failed to fetch automation rules', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/marketing/automation-rules', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { rule_type, rule_config, coupon_template, enabled } = req.body;
    if (!['grade', 'purchase_milestone'].includes(rule_type)) {
      return res.status(400).json({ error: 'Bad Request', message: "rule_type은 'grade' 또는 'purchase_milestone'이어야 합니다", timestamp: new Date().toISOString() });
    }
    if (rule_type === 'grade' && !rule_config?.grade_key) {
      return res.status(400).json({ error: 'Bad Request', message: 'grade 규칙은 rule_config.grade_key가 필요합니다', timestamp: new Date().toISOString() });
    }
    if (rule_type === 'purchase_milestone' && !(Number(rule_config?.order_count) > 0)) {
      return res.status(400).json({ error: 'Bad Request', message: 'purchase_milestone 규칙은 rule_config.order_count(양의 정수)가 필요합니다', timestamp: new Date().toISOString() });
    }
    const templateErr = validateCouponTemplate(coupon_template);
    if (templateErr) return res.status(400).json({ error: 'Bad Request', message: templateErr, timestamp: new Date().toISOString() });

    const { data, error } = await supabase.from('coupon_automation_rules_with').insert([{
      rule_type, rule_config: rule_config || {}, coupon_template, enabled: enabled === undefined ? true : !!enabled, created_by: req.user.id
    }]).select().single();
    if (error) throw error;
    res.status(201).json({ success: true, data, message: '자동 쿠폰 규칙이 생성되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating automation rule:', err);
    res.status(500).json({ error: 'Failed to create automation rule', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/admin/marketing/automation-rules/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { rule_config, coupon_template, enabled } = req.body;
    const updates = { updated_at: new Date().toISOString() };
    if (rule_config !== undefined) updates.rule_config = rule_config;
    if (coupon_template !== undefined) {
      const templateErr = validateCouponTemplate(coupon_template);
      if (templateErr) return res.status(400).json({ error: 'Bad Request', message: templateErr, timestamp: new Date().toISOString() });
      updates.coupon_template = coupon_template;
    }
    if (enabled !== undefined) updates.enabled = !!enabled;
    const { data, error } = await supabase.from('coupon_automation_rules_with').update(updates).eq('id', req.params.id).select().maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '규칙을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({ success: true, data, message: '규칙이 수정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating automation rule:', err);
    res.status(500).json({ error: 'Failed to update automation rule', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.delete('/api/admin/marketing/automation-rules/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { error } = await supabase.from('coupon_automation_rules_with').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: '규칙이 삭제되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting automation rule:', err);
    res.status(500).json({ error: 'Failed to delete automation rule', message: err.message, timestamp: new Date().toISOString() });
  }
});

function currentGradePeriodKey() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

// 이번 달에 아직 이 규칙으로 쿠폰을 못 받은, "지금 이 등급을 유지 중인" 회원들을 찾아 한 번에 발급한다.
// 매일 스캔하지만 이미 이번 달에 받은 회원은 유니크 제약(rule_id, user_id, period_key)으로 걸러지므로
// 하루에 몇 번을 돌려도(수동 재실행 포함) 같은 회원에게 중복 발급되지 않는다.
async function runGradeCouponScan() {
  const result = { rulesProcessed: 0, couponsIssued: 0, usersNotified: 0 };
  const { data: rules, error } = await supabase.from('coupon_automation_rules_with').select('*').eq('rule_type', 'grade').eq('enabled', true);
  if (error) { console.error('Error fetching grade coupon rules:', error); return result; }
  const periodKey = currentGradePeriodKey();

  for (const rule of rules || []) {
    result.rulesProcessed++;
    try {
      const targetGrade = rule.rule_config?.grade_key;
      if (!targetGrade) continue;

      const { data: already } = await supabase.from('coupon_automation_issuances_with').select('user_id').eq('rule_id', rule.id).eq('period_key', periodKey);
      const alreadyIds = new Set((already || []).map(r => r.user_id));

      const matches = await computeSegmentMatches({ grades: [targetGrade] });
      const newUsers = matches.filter(m => !alreadyIds.has(m.id));
      if (newUsers.length === 0) continue;

      const coupon = await issueCouponForBatch(newUsers.map(u => u.id), rule.coupon_template, 'auto_grade', {
        codePrefix: 'GRADE',
        notifyTitle: `${rule.coupon_template.label || '등급 혜택'} 쿠폰 지급`,
        notifyMessage: `등급 유지 혜택으로 쿠폰이 발급되었습니다. 마이페이지에서 확인해보세요.`
      });
      const issuanceRows = newUsers.map(u => ({ rule_id: rule.id, user_id: u.id, period_key: periodKey, coupon_id: coupon.id }));
      const { error: insErr } = await supabase.from('coupon_automation_issuances_with').insert(issuanceRows);
      if (insErr) { console.error('Error logging grade coupon issuance:', insErr); continue; }

      result.couponsIssued++;
      result.usersNotified += newUsers.length;
    } catch (ruleErr) {
      console.error(`Error processing grade coupon rule ${rule.id}:`, ruleErr);
    }
  }
  return result;
}

// N번째 구매를 정확히 달성한(그 이상은 대상 아님 - 1회성 마일스톤) 회원 중 아직 못 받은 사람을 찾아 발급한다.
async function runPurchaseMilestoneScan() {
  const result = { rulesProcessed: 0, couponsIssued: 0, usersNotified: 0 };
  const { data: rules, error } = await supabase.from('coupon_automation_rules_with').select('*').eq('rule_type', 'purchase_milestone').eq('enabled', true);
  if (error) { console.error('Error fetching milestone coupon rules:', error); return result; }

  for (const rule of rules || []) {
    result.rulesProcessed++;
    try {
      const milestone = Number(rule.rule_config?.order_count);
      if (!Number.isFinite(milestone) || milestone <= 0) continue;
      const periodKey = String(milestone); // 마일스톤은 평생 1번만 - "몇 번째 구매"가 곧 기간 키

      const matches = await computeSegmentMatches({ minOrderCount: milestone, maxOrderCount: milestone });
      if (matches.length === 0) continue;

      const { data: already } = await supabase.from('coupon_automation_issuances_with').select('user_id').eq('rule_id', rule.id).eq('period_key', periodKey);
      const alreadyIds = new Set((already || []).map(r => r.user_id));
      const newUsers = matches.filter(m => !alreadyIds.has(m.id));
      if (newUsers.length === 0) continue;

      const coupon = await issueCouponForBatch(newUsers.map(u => u.id), rule.coupon_template, 'auto_milestone', {
        codePrefix: 'MILE',
        notifyTitle: `${milestone}번째 구매 축하 쿠폰`,
        notifyMessage: `${milestone}번째 구매를 축하하는 쿠폰이 발급되었습니다. 마이페이지에서 확인해보세요.`
      });
      const issuanceRows = newUsers.map(u => ({ rule_id: rule.id, user_id: u.id, period_key: periodKey, coupon_id: coupon.id }));
      const { error: insErr } = await supabase.from('coupon_automation_issuances_with').insert(issuanceRows);
      if (insErr) { console.error('Error logging milestone coupon issuance:', insErr); continue; }

      result.couponsIssued++;
      result.usersNotified += newUsers.length;
    } catch (ruleErr) {
      console.error(`Error processing milestone coupon rule ${rule.id}:`, ruleErr);
    }
  }
  return result;
}

// 매일 새벽 3시 자동 스캔 (규칙이 없거나 모두 비활성화면 각 함수 내부에서 즉시 빈 결과로 반환)
cron.schedule('0 3 * * *', () => {
  runGradeCouponScan().catch(err => console.error('Grade coupon cron error:', err));
  runPurchaseMilestoneScan().catch(err => console.error('Milestone coupon cron error:', err));
});

// 관리자: 지금 즉시 1회 실행 (다음 새벽까지 기다리지 않고 바로 확인하고 싶을 때). 이 규칙과 같은 종류
// (등급유지 또는 구매마일스톤)의 활성화된 규칙 전체를 한 번에 스캔한다 - 어차피 이미 발급받은 회원은
// 유니크 제약으로 걸러지므로 다른 규칙까지 함께 스캔돼도 결과에는 영향이 없고, 매일 새벽 자동 스캔과
// 완전히 동일한 로직을 재사용해 두 경로의 동작이 어긋나지 않는다.
app.post('/api/admin/marketing/automation-rules/:id/run-now', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: rule, error } = await supabase.from('coupon_automation_rules_with').select('*').eq('id', req.params.id).maybeSingle();
    if (error) throw error;
    if (!rule) return res.status(404).json({ error: 'Not Found', message: '규칙을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    let result;
    if (rule.rule_type === 'grade') {
      result = await runGradeCouponScan();
    } else {
      result = await runPurchaseMilestoneScan();
    }
    res.json({ success: true, data: result, message: '실행되었습니다 (같은 종류의 활성화된 규칙 전체를 함께 스캔했습니다)', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error running automation rule now:', err);
    res.status(500).json({ error: 'Failed to run automation rule', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 주문 API
// ============================================

// 사용자의 주문 조회
app.get('/api/orders', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('orders_with')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json({
      success: true,
      data: data || [],
      count: data?.length || 0,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching orders:', err);
    res.status(500).json({
      error: 'Failed to fetch orders',
      message: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// 주문 생성
app.post('/api/orders', authenticate, async (req, res) => {
  try {
    const { items, community_id, shipping_address, payment_method, coupon_code, use_mileage, channel_id, live_session_id, live_attribution, reservation_ids } = req.body;
    // live_attribution: 딥링크/QR을 통해 유입된 경우의 출처 정보(유입플랫폼/캠페인/추천인/쿠폰) - 전부 선택값.
    // 기존 coupon_code(WITH+ 쿠폰)와는 별개이며, LIVE+ 채널 출처 주문에서만 의미를 가진다.
    const liveAttribution = live_attribution || {};

    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Items array is required and must not be empty',
        timestamp: new Date().toISOString()
      });
    }

    // 커뮤니티 적립을 받으려면 실제로 그 커뮤니티에 가입되어 있어야 한다 - 클라이언트가 임의의 community_id를
    // 직접 API에 보내는 것을 막기 위해 서버에서도 다시 한번 검증한다 (화면에는 가입한 커뮤니티만 표시되지만,
    // API를 직접 호출할 가능성까지 고려한 방어)
    if (community_id) {
      const { data: membership } = await supabase
        .from('community_members')
        .select('id')
        .eq('community_id', community_id)
        .eq('user_id', req.user.id)
        .eq('status', 'active')
        .maybeSingle();
      if (!membership) {
        return res.status(400).json({
          error: 'Bad Request',
          message: '가입되지 않은 커뮤니티입니다. 먼저 해당 커뮤니티에 가입해주세요.',
          timestamp: new Date().toISOString()
        });
      }
    }

    // LIVE+ 채널 출처 - 커뮤니티와 달리 가입 여부와 무관하게(비가입 시청자도 구매 가능) 채널이
    // 실제로 존재하고 활성 상태인지만 확인한다. 가입 여부에 따른 팬 활동점수 적립 여부는 주문 성공 후
    // recordChannelOrderAttribution/awardFanActivity에서 별도로 처리된다.
    // isLiveChannelOrder: 이 주문이 LIVE+ 채널(라이브쇼핑) 출처인지 - 참이면 아래에서 상품 단가를
    // products_with.price가 아니라 채널별 가격정책(channel='live')이 계산한 최종 판매가로 재계산한다.
    let isLiveChannelOrder = false;
    if (channel_id) {
      const { data: channelExists } = await supabase.from('channels_live').select('id').eq('id', channel_id).eq('status', 'active').maybeSingle();
      if (!channelExists) {
        return res.status(400).json({ error: 'Bad Request', message: '유효하지 않은 채널입니다', timestamp: new Date().toISOString() });
      }
      isLiveChannelOrder = true;
    }

    // 🎁 크리에이터 제휴 커미션(격차분석 2-8) - live_attribution.referrer_code는 원래도 딥링크 유입 출처를
    // 그대로 기록만 해두던 필드였는데, 이 코드가 실제로 활성 상태인 크리에이터 추천코드와 일치하면 주문에
    // creator_id를 함께 기록해 이후 기간별 정산(creator_settlements_with) 생성 시 집계 대상이 되게 한다.
    // 코드가 없거나 등록되지 않은/비활성 코드면 그냥 무시하고 기존처럼 텍스트 기록만 남는다 - 주문 자체를
    // 막지 않는다(잘못된 추천코드라고 해서 구매를 거부할 이유는 없음).
    let creatorId = null;
    if (liveAttribution.referrer_code) {
      const { data: refCode } = await supabase.from('creator_referral_codes_with')
        .select('creator_id, status, creators_with(status, user_id)')
        .eq('code', liveAttribution.referrer_code).eq('status', 'active').maybeSingle();
      if (refCode && refCode.creators_with && refCode.creators_with.status === 'active') {
        // 셀프 리퍼럴 방지: 크리에이터 본인 계정으로 자신의 추천코드를 통해 구매하면 커미션 귀속을
        // 하지 않는다(자기 자신에게 커미션을 지급하는 부정매출 패턴 차단). 주문 자체는 정상 진행되고,
        // 단지 이 주문이 정산 대상 매출로 집계되지 않을 뿐이다.
        if (refCode.creators_with.user_id && refCode.creators_with.user_id === req.user.id) {
          console.warn(`[creator-referral] self-referral blocked: user ${req.user.id} used own referral code`);
        } else {
          creatorId = refCode.creator_id;
        }
      }
    }

    // 재고 검증 - 상품별로 옵션(사이즈/색상 등)이 있으면 반드시 옵션을 선택해야 하고, 그 옵션의 재고를 확인한다.
    // (여기서는 "충분히 있어 보이는지" 사전 확인만 하고, 실제 차감은 주문 생성 성공 뒤 원자적으로 처리한다 - 동시 주문 대비)
    // product_id가 UUID 형식이 아니면(예: 잘못된 클라이언트 요청) DB 조회 자체가 500 에러로 죽으므로,
    // UUID 형식이 아닌 값은 애초에 "존재하지 않는 상품"으로 취급해 조용히 400으로 처리한다.
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const requestedProductIds = [...new Set(items.map(i => i.product_id).filter(Boolean))];
    const productIds = requestedProductIds.filter(id => UUID_RE.test(id));
    const productMap = {};
    const variantsByProduct = {};
    let liveChannelPriceByProductId = {};
    const flashSalePriceByProductId = {};
    if (productIds.length > 0) {
      const { data: orderProducts, error: prodErr } = await supabase
        .from('products_with')
        .select('id, name, price, stock, status, category, cost_price')
        .in('id', productIds);
      if (prodErr) throw prodErr;
      (orderProducts || []).forEach(p => { productMap[p.id] = p; });

      // 🔒 LIVE+ 채널 출처 주문은 단가를 products_with.price가 아니라 채널가격정책(channel='live')으로
      // 다시 계산한다 - cost_price/category는 서버 내부 계산에만 쓰이고 응답/저장 어디에도 그대로 노출되지 않는다
      // (verifiedItems에는 계산된 단가(price)만 들어간다).
      if (isLiveChannelOrder) {
        liveChannelPriceByProductId = await resolveLiveChannelPrices((orderProducts || []).map(p => ({
          id: p.id, cost_price: p.cost_price, category: p.category, fallbackPrice: p.price
        })));
      }

      // 🔒 타임세일(플래시세일) 가격은 결제 시점에 서버가 다시 검증한다 - 클라이언트가 "할인이 아직
      // 유효하다"고 보내온 정보는 신뢰하지 않고, live_session_id + product_id 조합으로 현재 시각 기준
      // cancelled_at IS NULL AND ends_at > now() 인 행만 유효한 것으로 취급한다. 이렇게 하면 타이머가
      // 만료된 뒤 또는 관리자가 취소한 뒤에 들어온 주문에는 할인가가 절대 적용되지 않는다.
      if (live_session_id && productIds.length > 0) {
        const { data: activeFlashSales } = await supabase
          .from('live_flash_sales_live')
          .select('product_id, discount_price, ends_at, cancelled_at')
          .eq('live_session_id', live_session_id)
          .in('product_id', productIds)
          .is('cancelled_at', null)
          .gt('ends_at', new Date().toISOString());
        (activeFlashSales || []).forEach(fs => {
          flashSalePriceByProductId[fs.product_id] = Number(fs.discount_price) || 0;
        });
      }

      const { data: allVariants, error: varErr } = await supabase
        .from('product_variants_with')
        .select('id, product_id, name, price_adjustment, stock, is_active')
        .in('product_id', productIds)
        .eq('is_active', true);
      if (varErr) throw varErr;
      (allVariants || []).forEach(v => {
        if (!variantsByProduct[v.product_id]) variantsByProduct[v.product_id] = [];
        variantsByProduct[v.product_id].push(v);
      });
    }

    // 🔒 보안: 상품 가격은 절대 클라이언트(브라우저)가 보낸 값을 신뢰하지 않는다. 여기서 검증하면서
    // 동시에 DB의 실제 판매가(옵션이 있으면 옵션 가격조정 포함)로 다시 계산한 "검증된 주문항목"을
    // 새로 만들어, 이후 총액 계산·주문 저장에는 이 값만 사용한다. (이전에는 item.price를 그대로 믿어서
    // 브라우저 요청을 조작하면 임의의 가격으로 결제가 성립하는 취약점이 있었다 - 형님이 요청하신 격차분석에서 발견)
    const verifiedItems = [];
    for (const item of items) {
      if (!item.product_id) continue;
      const product = productMap[item.product_id];
      if (!product || product.status !== 'active') {
        return res.status(400).json({ error: 'Bad Request', message: `판매 중이 아닌 상품이 포함되어 있습니다: ${item.name || item.product_id}`, timestamp: new Date().toISOString() });
      }
      const variants = variantsByProduct[item.product_id] || [];
      const qty = Number(item.quantity) || 1;
      // LIVE+ 채널 주문이면 채널가격정책이 계산한 라이브 채널가를 기준 단가로 쓴다(없으면 기존처럼 product.price로 폴백 -
      // resolveLiveChannelPrices 자체도 폴백을 product.price로 두었으므로 이 두 경로는 결과가 항상 일치한다).
      // 타임세일(플래시세일)이 현재 활성 상태면 그 어떤 가격보다 우선한다 - 위에서 이미 서버가
      // ends_at/cancelled_at을 재검증했으므로 여기서는 맵에 값이 있으면 곧 유효한 할인이다.
      let unitPrice = Object.prototype.hasOwnProperty.call(flashSalePriceByProductId, item.product_id)
        ? flashSalePriceByProductId[item.product_id]
        : (isLiveChannelOrder && Object.prototype.hasOwnProperty.call(liveChannelPriceByProductId, item.product_id))
          ? Number(liveChannelPriceByProductId[item.product_id]) || 0
          : (Number(product.price) || 0);
      let variantLabel = '';

      if (variants.length > 0) {
        if (!item.variant_id) {
          return res.status(400).json({ error: 'Bad Request', message: `옵션을 선택해주세요: ${product.name}`, timestamp: new Date().toISOString() });
        }
        const variant = variants.find(v => v.id === item.variant_id);
        if (!variant) {
          return res.status(400).json({ error: 'Bad Request', message: `선택한 옵션을 찾을 수 없습니다: ${product.name}`, timestamp: new Date().toISOString() });
        }
        if (Number(variant.stock) < qty) {
          return res.status(400).json({ error: 'Bad Request', message: `재고가 부족합니다: ${product.name} (${variant.name})`, timestamp: new Date().toISOString() });
        }
        unitPrice += Number(variant.price_adjustment) || 0;
        variantLabel = ` (${variant.name})`;
      } else if (Number(product.stock) < qty) {
        return res.status(400).json({ error: 'Bad Request', message: `재고가 부족합니다: ${product.name}`, timestamp: new Date().toISOString() });
      }

      verifiedItems.push({
        product_id: item.product_id,
        variant_id: item.variant_id || null,
        name: product.name + variantLabel,
        price: unitPrice,
        quantity: qty
      });
    }

    // 총액 계산 - verifiedItems(서버가 재검증한 가격)만 사용
    let totalPrice = 0;
    for (const item of verifiedItems) {
      totalPrice += item.price * item.quantity;
    }

    // 쿠폰 적용 (있는 경우) - 주문 생성 시점에 서버에서 다시 한번 검증(레이스 컨디션/중복사용 방지)
    let discountAmount = 0;
    let appliedCoupon = null;
    if (coupon_code) {
      const couponResult = await validateCouponForUser(coupon_code, req.user.id, totalPrice);
      if (!couponResult.valid) {
        return res.status(400).json({ error: 'Bad Request', message: couponResult.reason, timestamp: new Date().toISOString() });
      }
      discountAmount = couponResult.discountAmount;
      appliedCoupon = couponResult.coupon;
    }
    const amountAfterCoupon = totalPrice - discountAmount;

    // 마일리지 사용 (있는 경우) - 클라이언트가 보낸 값을 그대로 믿지 않고, 실제 보유 잔액과 주문 금액 범위 내에서만 사용을 허용한다
    // (배송비에는 마일리지를 사용할 수 없다 - 다른 쇼핑몰들의 일반적인 관행과 동일하게 상품 금액까지만 적용)
    let usedMileage = 0;
    if (use_mileage !== undefined && use_mileage !== null && Number(use_mileage) > 0) {
      usedMileage = Math.floor(Number(use_mileage));
      if (!Number.isFinite(usedMileage) || usedMileage < 0) {
        return res.status(400).json({ error: 'Bad Request', message: '사용할 마일리지 값이 올바르지 않습니다', timestamp: new Date().toISOString() });
      }
      const availableMileage = await getUserMileageBalance(req.user.id);
      if (usedMileage > availableMileage) {
        return res.status(400).json({ error: 'Bad Request', message: `보유 마일리지(${availableMileage.toLocaleString('ko-KR')}원)보다 많이 사용할 수 없습니다`, timestamp: new Date().toISOString() });
      }
      if (usedMileage > amountAfterCoupon) {
        usedMileage = amountAfterCoupon; // 결제 금액을 초과해 사용할 수 없으므로 자동으로 결제 금액만큼만 사용 처리
      }
    }
    const productPaymentAmount = amountAfterCoupon - usedMileage; // 마일리지 적립 기준 금액 (배송비 제외 - 배송비에는 적립도 되지 않음)

    // 배송비 계산 - 클라이언트가 보낸 값은 절대 신뢰하지 않고, 서버가 상품 합계금액과 배송지 우편번호로 직접 계산한다
    const shippingPolicy = await getShippingPolicy();
    const shippingPostal = shipping_address && shipping_address.postal_code ? shipping_address.postal_code : null;
    const shippingCalc = calcShippingFee(shippingPolicy, totalPrice, shippingPostal);
    const finalPrice = productPaymentAmount + shippingCalc.fee;

    // WITH+ 마일리지 적립 계산: 할인+마일리지 사용까지 반영한 실제 상품 결제 금액 기준(마일리지로 낸 금액과 배송비에는 적립되지 않도록),
    // 개인 적립율(항상) + 커뮤니티 참여 시 추가 적립율
    // (분양 조직이 자체 적립율을 지정해두었으면 그 값 우선, 아니면 플랫폼 기본값 - getEffectiveMileageRates 참고)
    // + 회원 등급 혜택: 이 주문 이전까지의 누적 구매액으로 등급을 산정해 개인 적립율에 등급 보너스(%p)를 더해준다
    const mileageRates = await getEffectiveMileageRates(community_id || null);
    const [memberGrades, totalSpentSoFar] = await Promise.all([getMemberGrades(), getUserCumulativeSpent(req.user.id)]);
    const { current: memberGrade } = resolveMemberGrade(totalSpentSoFar, memberGrades);
    const personalRateWithGrade = mileageRates.personal + Number(memberGrade.bonus_personal_rate || 0);
    const personalEarnedPoints = Math.floor(productPaymentAmount * personalRateWithGrade);
    const communityEarnedPoints = community_id ? Math.floor(productPaymentAmount * mileageRates.community) : 0;

    // 주문번호 생성
    const orderNumber = `ORD-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    // 레이스 컨디션 완화: 위에서 사용 가능 마일리지를 검증한 시점과 실제 주문 INSERT 사이에, 동시에
    // 도착한 다른 주문이 먼저 같은 마일리지를 써버릴 수 있는 창이 있다. 완전히 막을 수는 없지만(진짜
    // 원자적 처리는 DB 레벨 잠금/트랜잭션이 필요하다), INSERT 직전에 한 번 더 재확인해 그 창을 최대한 좁힌다.
    // TODO: 완전한 동시성 방어를 위해서는 DB 레벨 처리(예: 마일리지 차감 전용 advisory lock 또는 원자적
    // 차감 RPC)가 필요하다.
    if (usedMileage > 0) {
      const balanceRightBeforeInsert = await getUserMileageBalance(req.user.id);
      if (usedMileage > balanceRightBeforeInsert) {
        return res.status(409).json({
          error: 'Conflict',
          message: `보유 마일리지(${balanceRightBeforeInsert.toLocaleString('ko-KR')}원)보다 많이 사용할 수 없습니다. 다시 시도해주세요.`,
          timestamp: new Date().toISOString()
        });
      }
    }

    const { data, error } = await supabase
      .from('orders_with')
      .insert([{
        order_number: orderNumber,
        user_id: req.user.id,
        community_id: community_id || null,
        channel_id: channel_id || null,
        live_session_id: live_session_id || null,
        creator_id: creatorId,
        attribution_source_platform: liveAttribution.source_platform || null,
        attribution_campaign: liveAttribution.campaign || null,
        attribution_referrer_code: liveAttribution.referrer_code || null,
        attribution_coupon_code: liveAttribution.coupon_code || null,
        items: verifiedItems,
        total_price: totalPrice,
        final_price: finalPrice,
        coupon_code: appliedCoupon ? appliedCoupon.code : null,
        discount_amount: discountAmount,
        used_mileage: usedMileage,
        personal_earned_points: personalEarnedPoints,
        community_earned_points: communityEarnedPoints,
        member_grade: memberGrade.key,
        shipping_address: shipping_address ? JSON.stringify(shipping_address) : null,
        shipping_fee: shippingCalc.fee,
        shipping_surcharge_label: shippingCalc.surcharge_label,
        payment_method: payment_method || 'pending',
        status: 'pending'
      }])
      .select()
      .single();

    if (error) throw error;

    // LIVE+ 세션 한정재고 강제 - live_session_id가 함께 전달된 주문인데 그 상품에 유효한 reservation_id가
    // 없으면(예: 예약 없이 바로 이 API를 직접 호출) 기존에는 세션 재고 풀을 건너뛰고 실재고(products_with.stock)만
    // 체크했기 때문에, 방송에서 "OO개 한정"이라고 안내한 세션별 한정수량을 초과 판매할 수 있었다.
    // 여기서는 reservation_ids로 커버되지 않는 수량에 대해 세션 재고 풀에서도 직접 원자적으로 "예약"을 시도해,
    // 세션 재고가 부족하면(0개 남음 포함) 주문 자체를 거부한다. 실제 sold_qty 확정(reserved→sold)은 아래에서
    // 실재고 차감까지 전부 성공한 뒤에 한다 - 그래야 실재고 차감이 실패했을 때 이 예약만 깔끔하게 release하면 되고,
    // sold_qty를 되돌리는 보정 로직(해당 RPC가 없음)이 따로 필요 없다.
    const sessionInventoryReserves = []; // { inventoryId, qty }
    if (live_session_id) {
      // reservation_ids로 이미 선점된 수량은 상품별로 합산해 커버리지로 인정한다 (본인 소유의, 이 세션의,
      // 아직 유효한(cart/checkout, 미만료) 예약만 - confirmLiveSessionReservations와 동일한 검증 기준)
      const coveredQtyByProduct = {};
      if (Array.isArray(reservation_ids) && reservation_ids.length > 0) {
        const { data: coveringReservations } = await supabase.from('live_session_reservations_live')
          .select('product_id, quantity, status, expires_at, user_id, live_session_id')
          .in('id', reservation_ids);
        for (const r of (coveringReservations || [])) {
          if (r.user_id !== req.user.id) continue;
          if (r.live_session_id !== live_session_id) continue;
          if (!['cart', 'checkout'].includes(r.status)) continue;
          if (r.expires_at && new Date(r.expires_at) < new Date()) continue;
          coveredQtyByProduct[r.product_id] = (coveredQtyByProduct[r.product_id] || 0) + (Number(r.quantity) || 0);
        }
      }

      // 이 주문에서 상품별 요청 수량 합산 (같은 상품이 옵션만 다르게 여러 항목으로 나뉠 수 있으나,
      // 세션 재고 풀은 옵션 구분 없이 상품 단위로만 운영된다)
      const requestedQtyByProduct = {};
      for (const item of verifiedItems) {
        if (!item.product_id) continue;
        requestedQtyByProduct[item.product_id] = (requestedQtyByProduct[item.product_id] || 0) + item.quantity;
      }

      let sessionReserveError = null;
      for (const [productId, requestedQty] of Object.entries(requestedQtyByProduct)) {
        const uncoveredQty = requestedQty - (coveredQtyByProduct[productId] || 0);
        if (uncoveredQty <= 0) continue;

        const { data: inv } = await supabase.from('live_session_inventory_live')
          .select('id').eq('live_session_id', live_session_id).eq('product_id', productId).maybeSingle();
        if (!inv) continue; // 이 상품은 세션 한정재고 풀 대상이 아님 - 실재고만으로 정상 판매

        const { data: reservedInv } = await supabase.rpc('reserve_live_session_inventory', { p_inventory_id: inv.id, p_qty: uncoveredQty });
        if (!reservedInv || !reservedInv.id) {
          const productName = verifiedItems.find(i => i.product_id === productId)?.name || productId;
          sessionReserveError = `이 방송에 배정된 한정 재고가 부족합니다: ${productName}`;
          break;
        }
        sessionInventoryReserves.push({ inventoryId: inv.id, qty: uncoveredQty });
      }

      if (sessionReserveError) {
        // 보상: 이미 예약한 세션 재고 되돌리기 + 방금 만든 주문 삭제 (아직 실재고는 건드리지 않았으므로 이것만으로 충분)
        for (const r of sessionInventoryReserves) {
          try { await supabase.rpc('release_live_session_inventory', { p_inventory_id: r.inventoryId, p_qty: r.qty }); } catch (e) { /* 최선 노력 */ }
        }
        await supabase.from('orders_with').delete().eq('id', data.id);
        return res.status(409).json({ error: 'Conflict', message: sessionReserveError, timestamp: new Date().toISOString() });
      }
    }

    // 재고 원자적 차감 - 사전 검증을 통과했더라도 그 사이 다른 주문이 먼저 재고를 가져갔을 수 있으므로
    // DB 함수(adjust_stock_with)로 다시 한번 원자적으로 확인하며 차감한다. 도중에 하나라도 부족하면
    // 이미 차감된 항목들은 원복(보상)하고 방금 만든 주문도 삭제해 재고 불일치가 남지 않도록 한다.
    // 채널별 재고 분리 할당(옵트인) - product_channel_stock_with에 이 상품/옵션의 'live' 채널 행이 있으면
    // 그 배정 한도 안에서만 팔리고(물리 재고가 남아있어도 그 채널에서는 품절 처리), 행이 없으면 기존과
    // 완전히 동일하게(공유 풀) 동작한다. WITH+와 LIVE+가 같은 Supabase 프로젝트를 공유하므로 별도 마이그레이션
    // 없이 WITH+ 쪽에서 만든 테이블/RPC를 그대로 쓸 수 있다. 미팅 요청사항 격차분석 보고서 5번 항목.
    const decrementedItems = [];

    let stockError = null;
    for (const item of verifiedItems) {
      if (!item.product_id) continue;
      const qty = Number(item.quantity) || 1;

      let chStockQuery = supabase.from('product_channel_stock_with').select('id').eq('product_id', item.product_id).eq('channel', 'live');
      chStockQuery = item.variant_id ? chStockQuery.eq('variant_id', item.variant_id) : chStockQuery.is('variant_id', null);
      const { data: chRow } = await chStockQuery.maybeSingle();
      let channelReserved = false;
      if (chRow) {
        const { data: reserved } = await supabase.rpc('reserve_channel_stock', { p_product_id: item.product_id, p_variant_id: item.variant_id || null, p_channel: 'live', p_qty: qty });
        if (!reserved) {
          stockError = { item, err: { message: '채널(라이브) 배정 재고 소진' } };
          break;
        }
        channelReserved = true;
      }

      const { error: rpcErr } = await supabase.rpc('adjust_stock_with', {
        p_product_id: item.product_id,
        p_variant_id: item.variant_id || null,
        p_delta: -qty,
        p_reason: `주문 차감 - 주문번호 ${orderNumber}`,
        p_order_id: data.id,
        p_created_by: req.user.id,
        p_scan_source: 'order'
      });
      if (rpcErr) {
        if (channelReserved) {
          await supabase.rpc('release_channel_stock', { p_product_id: item.product_id, p_variant_id: item.variant_id || null, p_channel: 'live', p_qty: qty }).catch(() => {});
        }
        stockError = { item, err: rpcErr };
        break;
      }
      decrementedItems.push({ product_id: item.product_id, variant_id: item.variant_id || null, qty, channelReserved });
    }

    if (stockError) {
      // 보상: 이미 차감된 항목들 원복 (물리 재고 + 채널 배정분 모두)
      for (const d of decrementedItems) {
        try {
          await supabase.rpc('adjust_stock_with', {
            p_product_id: d.product_id, p_variant_id: d.variant_id, p_delta: d.qty, p_reason: '재고 부족으로 인한 주문 실패 - 자동 원복', p_order_id: data.id, p_created_by: req.user.id
          });
          if (d.channelReserved) {
            await supabase.rpc('release_channel_stock', { p_product_id: d.product_id, p_variant_id: d.variant_id, p_channel: 'live', p_qty: d.qty });
          }
        } catch (compensateErr) { /* 재고 원복은 최선을 다해 시도하되, 실패해도 요청 처리를 막지 않는다 */ }
      }
      // 보상: 앞서 예약해둔 세션 한정재고도 함께 되돌린다 (아직 sold로 확정 전이므로 release로 충분)
      for (const r of sessionInventoryReserves) {
        try { await supabase.rpc('release_live_session_inventory', { p_inventory_id: r.inventoryId, p_qty: r.qty }); } catch (e) { /* 최선 노력 */ }
      }
      await supabase.from('orders_with').delete().eq('id', data.id);
      return res.status(409).json({
        error: 'Conflict',
        message: `재고가 방금 소진되었습니다: ${stockError.item.name || stockError.item.product_id}. 다시 시도해주세요.`,
        timestamp: new Date().toISOString()
      });
    }

    // 실재고 차감까지 전부 성공했으므로, 앞서 예약해둔 세션 한정재고를 이제 sold로 확정한다 (reserved→sold).
    // 실패해도 주문 자체는 이미 정상 처리되었으므로 막지 않되(이미 실결제/실재고가 확정된 뒤이므로 되돌릴 수 없음),
    // 로그로 남겨 세션 재고 카운터 불일치를 관리자가 수동으로 대사할 수 있게 한다.
    for (const r of sessionInventoryReserves) {
      try {
        await supabase.rpc('confirm_live_session_inventory', { p_inventory_id: r.inventoryId, p_qty: r.qty });
        await supabase.from('live_session_inventory_log_live').insert([{
          inventory_id: r.inventoryId, change_type: 'confirm', delta_reserved: 0, delta_sold: r.qty,
          actor_user_id: req.user.id, note: `예약 없이 직접 주문 - 세션 한정재고 직접 확정 (주문번호 ${orderNumber})`
        }]);
      } catch (confirmErr) {
        console.error('LIVE+ 세션 한정재고 확정 중 오류 (실재고/주문 자체는 정상 처리됨):', confirmErr.message);
      }
    }

    // 옵션이 있는 상품은 products_with.stock(목록에 표시되는 재고)을 옵션 재고 합계로 다시 맞춰준다
    const affectedProductIds = [...new Set(decrementedItems.filter(d => d.variant_id).map(d => d.product_id))];
    for (const pid of affectedProductIds) {
      await syncProductStockFromVariants(pid);
    }

    // 쿠폰 사용 기록 (주문 생성이 성공한 뒤에만 사용 처리 - 실패 시 쿠폰이 소모되지 않도록)
    // used_count 증가를 예전에는 read-then-write(조회해둔 값 + 1을 그대로 저장)로 처리했는데, 동시에 여러
    // 주문이 마지막 남은 한 자리를 두고 경합하면 usage_limit을 넘겨서 통과시킬 수 있는 레이스 컨디션이
    // 있었다. 시리얼쿠폰/출석체크와 동일하게 조건부 UPDATE(.lt('used_count', usage_limit))로 원자적으로
    // 처리하고, 실제로 갱신된 행이 없으면(=그 사이 다른 요청이 한도를 이미 채움) 앞서 차감해둔 재고를
    // 보상 원복한 뒤(재고 부족 실패 시와 동일한 순서/방식) 주문 생성 자체를 실패시킨다.
    if (appliedCoupon) {
      let couponUpdateQuery = supabase
        .from('coupons')
        .update({ used_count: appliedCoupon.used_count + 1 })
        .eq('id', appliedCoupon.id);
      if (appliedCoupon.usage_limit !== null && appliedCoupon.usage_limit !== undefined) {
        couponUpdateQuery = couponUpdateQuery.lt('used_count', appliedCoupon.usage_limit);
      }
      const { data: couponUpdated, error: couponUpdateErr } = await couponUpdateQuery.select().maybeSingle();
      if (couponUpdateErr) throw couponUpdateErr;
      if (!couponUpdated) {
        // 보상: 이미 차감된 재고 원복 + 방금 만든 주문 삭제 (재고 부족으로 인한 실패 처리와 동일한 순서)
        for (const d of decrementedItems) {
          try {
            await supabase.rpc('adjust_stock_with', {
              p_product_id: d.product_id, p_variant_id: d.variant_id, p_delta: d.qty, p_reason: '쿠폰 사용 한도 초과로 인한 주문 실패 - 자동 원복', p_order_id: data.id, p_created_by: req.user.id
            });
            await supabase.rpc('release_channel_stock', { p_product_id: d.product_id, p_variant_id: d.variant_id, p_channel: 'live', p_qty: d.qty });
          } catch (compensateErr) { /* 재고 원복은 최선을 다해 시도하되, 실패해도 요청 처리를 막지 않는다 */ }
        }
        await supabase.from('orders_with').delete().eq('id', data.id);
        return res.status(409).json({
          error: 'Conflict',
          message: '쿠폰 사용 가능 횟수를 모두 소진했습니다. 다시 시도해주세요.',
          timestamp: new Date().toISOString()
        });
      }
      await supabase.from('coupon_redemptions').insert([{
        coupon_id: appliedCoupon.id,
        user_id: req.user.id,
        order_id: data.id,
        discount_amount: discountAmount
      }]);
    }

    // 주문 접수 이메일 발송 - SMTP 미설정이면 조용히 생략(정직하게 email_logs_with에 기록)되고,
    // 발송 실패가 나더라도 절대 주문 생성 자체를 실패시키지 않는다(sendEmail은 예외를 던지지 않음).
    // 응답 전에 기다리되(타임아웃 최대 8초로 제한해둠), 실패해도 주문 자체는 이미 완료된 상태이므로 안전하다.
    await sendOrderConfirmationEmail(data, req.user.email).catch(() => {});

    // 주문이 성공적으로 생성되었으므로 더 이상 "이탈된 장바구니"가 아니다 - 리마인더 대상에서 제외되도록 스냅샷 정리
    // (클라이언트도 별도로 clearCart()를 호출하지만, 서버에서도 확실히 정리해 리마인더가 결제 완료 회원에게 나가는 것을 막는다)
    await supabase.from('cart_snapshots_with').delete().eq('user_id', req.user.id).then(null, () => {});

    // 추천인 프로그램: 이 주문이 회원의 첫 주문이고 대기 중인 추천 관계가 있으면 추천인·피추천인 양쪽에 마일리지 지급 (실패해도 주문 자체는 막지 않음)
    await rewardReferralIfEligible(req.user.id, data.id);

    // LIVE+ 채널 출처 주문이면 정산 원장 기록 + 팬 활동점수 적립 (실패해도 주문 자체는 막지 않음)
    if (channel_id) {
      await recordChannelOrderAttribution(data.id, orderNumber, finalPrice, channel_id, req.user.id, liveAttribution).catch(() => {});
    }

    // 세션별 재고예약(장바구니/결제진행 단계)을 이 주문으로 확정 - 예약은 이미 결제 전에 재고를 선점해뒀으므로
    // 여기서는 reserved_qty를 sold_qty로 옮기는 정산일 뿐, 재고 부족으로 실패할 일이 없다. 그래도 실패 시
    // 주문 자체는 막지 않는다(이미 정상적으로 성사된 결제를 되돌릴 수는 없음 - 대신 로그로 남겨 수동 대사 가능하게 함).
    if (Array.isArray(reservation_ids) && reservation_ids.length > 0) {
      await confirmLiveSessionReservations(reservation_ids, req.user.id, data.id).catch(err => {
        console.error('LIVE+ 재고예약 확정 중 오류 (주문 자체는 정상 처리됨):', err.message);
      });
      // 🔴 라이브 전용 구매 캐시백 - "방송 중 실제로 예약을 거쳐 산 주문"에만 얹어주는 추가 적립금.
      // 관리자가 캐시백율을 설정해두지 않았으면(기본 0%) 아무 일도 일어나지 않는다.
      if (channel_id) {
        await awardLiveCashbackBonus(req.user.id, data.id, finalPrice).catch(err => {
          console.error('라이브 구매 캐시백 지급 오류 (주문 자체는 정상 처리됨):', err.message);
        });
      }
      // 🎁 바이럴 공유쿠폰 - 다른 시청자의 공유링크를 통해 들어와 실제로 이 세션에서 구매를 완료한 경우
      // 공유한 사람/구매한 사람 양쪽에 할인쿠폰 지급(자기공유·중복지급은 함수 내부에서 방어).
      if (live_session_id && liveAttribution.share_code) {
        await awardShareViralCouponIfEligible(req.user.id, live_session_id, data.id, liveAttribution.share_code).catch(err => {
          console.error('바이럴 공유쿠폰 지급 오류 (주문 자체는 정상 처리됨):', err.message);
        });
      }
    }

    res.status(201).json({
      success: true,
      data: data,
      discount: { couponCode: appliedCoupon ? appliedCoupon.code : null, discountAmount },
      mileage: {
        personal: personalEarnedPoints,
        community: communityEarnedPoints,
        total: personalEarnedPoints + communityEarnedPoints
      },
      memberGrade: { key: memberGrade.key, label: memberGrade.label, bonusPersonalRate: memberGrade.bonus_personal_rate },
      message: 'Order created successfully',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error creating order:', err);
    res.status(500).json({
      error: 'Failed to create order',
      message: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// 미결제 pending 주문 자동취소 (LIVE+ 전용) - WITH+에는 24시간 기준의 동일한 패턴(cancelStalePendingOrders)이
// 있지만, LIVE+는 라이브 방송 중 한정 재고를 실재고에서 즉시 차감해두는 특성상 결제 대기시간을 짧게 잡아야
// 한다(방송이 끝나면 다른 시청자에게 재고를 풀어줘야 하므로). orders_with 테이블은 WITH+와 LIVE+가 공유하므로,
// 여기서는 채널/라이브세션 출처가 있는 주문(channel_id 또는 live_session_id가 있는 주문)만 대상으로 하여
// WITH+ 일반몰 주문의 기존 24시간 정책과 충돌하지 않도록 한다.
// (orders_with에는 취소 시각 컬럼(cancelled_at)이 없어 status만 갱신한다 - WITH+ cancelStalePendingOrders와 동일)
async function cancelStaleLiveSessionPendingOrders() {
  const cutoff = new Date(Date.now() - 30 * 60 * 1000).toISOString();
  const { data: staleOrders, error } = await supabase
    .from('orders_with')
    .select('id, order_number, items, user_id, created_at, channel_id, live_session_id')
    .eq('status', 'pending')
    .lt('created_at', cutoff)
    .or('channel_id.not.is.null,live_session_id.not.is.null');
  if (error) {
    console.error('Error fetching stale LIVE+ pending orders:', error);
    return { cancelled: 0 };
  }

  let cancelledCount = 0;
  for (const order of staleOrders || []) {
    try {
      const items = Array.isArray(order.items) ? order.items : [];
      const affectedProductIds = new Set();
      for (const item of items) {
        if (!item.product_id) continue;
        const qty = Number(item.quantity) || 1;
        try {
          await supabase.rpc('adjust_stock_with', {
            p_product_id: item.product_id,
            p_variant_id: item.variant_id || null,
            p_delta: qty,
            p_reason: `LIVE+ 30분 미결제 주문 자동 취소에 따른 재고 복구 (주문번호 ${order.order_number})`,
            p_order_id: order.id,
            p_created_by: null,
            p_scan_source: 'auto_cancel_pending_live'
          });
          await supabase.rpc('release_channel_stock', { p_product_id: item.product_id, p_variant_id: item.variant_id || null, p_channel: 'live', p_qty: qty });
          if (item.variant_id) affectedProductIds.add(item.product_id);
        } catch (stockErr) {
          console.error(`Error restoring stock for stale LIVE+ order ${order.order_number}:`, stockErr);
        }
      }
      for (const pid of affectedProductIds) {
        await syncProductStockFromVariants(pid).catch(() => {});
      }

      const { error: updateErr } = await supabase
        .from('orders_with')
        .update({ status: 'cancelled' })
        .eq('id', order.id)
        .eq('status', 'pending'); // 그 사이 결제가 완료됐을 수 있으므로 여전히 pending일 때만 취소 (레이스 컨디션 방지)
      if (updateErr) {
        console.error(`Error cancelling stale LIVE+ order ${order.order_number}:`, updateErr);
        continue;
      }
      cancelledCount++;
    } catch (orderErr) {
      console.error(`Error processing stale LIVE+ pending order ${order.order_number}:`, orderErr);
    }
  }
  return { cancelled: cancelledCount };
}

// 10분마다 스캔 (30분 컷오프이므로 24시간 기준보다 촘촘하게 확인해야 재고 회수가 지연되지 않는다)
cron.schedule('*/10 * * * *', () => {
  cancelStaleLiveSessionPendingOrders().catch(err => console.error('LIVE+ stale pending order cancel cron error:', err));
});

// 관리자용 전체 주문 조회 (상태 필터 가능, 주문자 이메일 포함)

app.get('/api/admin/orders', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    let query = supabase.from('orders_with').select('*').order('created_at', { ascending: false });

    if (req.query.status) {
      query = query.eq('status', req.query.status);
    }
    // 대시보드의 "이번 주 신규 주문" 등 통계 카드에서 그대로 드릴다운할 수 있도록, 특정 시점 이후 주문만 조회하는 필터
    if (req.query.since) {
      const sinceDate = new Date(req.query.since);
      if (!isNaN(sinceDate.getTime())) {
        query = query.gte('created_at', sinceDate.toISOString());
      }
    }

    const { data: orders, error } = await query;
    if (error) throw error;

    // profiles 는 orders_with 와 FK로 연결돼 있지 않아 PostgREST 중첩조회가 안 되므로
    // 주문에 등장하는 user_id들만 모아서 별도로 조회 후 서버에서 합쳐줌
    const userIds = [...new Set((orders || []).map(o => o.user_id))];
    let profileMap = {};
    if (userIds.length > 0) {
      const { data: profiles } = await supabase
        .from('profiles')
        .select('id, email, full_name')
        .in('id', userIds);
      (profiles || []).forEach(p => { profileMap[p.id] = p; });
    }

    const result = (orders || []).map(o => ({
      ...o,
      buyer_email: profileMap[o.user_id]?.email || null,
      buyer_name: profileMap[o.user_id]?.full_name || null
    }));

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin orders:', err);
    res.status(500).json({ error: 'Failed to fetch orders', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자용 주문 상태 변경 (배송중/완료/취소 처리 등)
app.patch('/api/admin/orders/:id/status', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status, shipping_status, tracking_number, courier_name } = req.body;

    // DB의 orders_with_status_check 제약조건과 반드시 일치해야 함
    const validStatuses = ['pending', 'paid', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'];
    if (status !== undefined && !validStatuses.includes(status)) {
      return res.status(400).json({
        error: 'Bad Request',
        message: `status must be one of: ${validStatuses.join(', ')}`,
        timestamp: new Date().toISOString()
      });
    }

    const updates = {};
    if (status !== undefined) updates.status = status;
    if (shipping_status !== undefined) updates.shipping_status = shipping_status;
    if (tracking_number !== undefined) updates.tracking_number = tracking_number;
    if (courier_name !== undefined) updates.courier_name = courier_name;

    // 택배사명 또는 운송장번호 중 하나라도 바뀌면, 조회 링크도 최신 값 기준으로 다시 계산한다
    // (한쪽만 바뀐 경우를 위해 바뀌지 않은 나머지 값은 기존 저장값을 조회해서 함께 사용)
    if (tracking_number !== undefined || courier_name !== undefined) {
      const { data: existingOrder } = await supabase.from('orders_with').select('tracking_number, courier_name').eq('id', id).maybeSingle();
      const finalCourier = courier_name !== undefined ? courier_name : (existingOrder ? existingOrder.courier_name : null);
      const finalTracking = tracking_number !== undefined ? tracking_number : (existingOrder ? existingOrder.tracking_number : null);
      updates.tracking_url = buildTrackingUrl(finalCourier, finalTracking);
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'Bad Request', message: '변경할 값이 없습니다', timestamp: new Date().toISOString() });
    }

    // 관리자가 상태를 cancelled/refunded로 직접 바꾸는 경우 재고를 복구해야 한다(반품요청 승인 경로의
    // adjust_stock_with 재고복구 로직과 동일). 이미 cancelled/refunded였던 주문을 다시 같은 상태로 저장해도
    // 재고가 중복 복구되지 않도록, 업데이트 전 상태를 미리 조회해둔다.
    let orderBeforeStatusChange = null;
    if (status === 'cancelled' || status === 'refunded') {
      const { data: existingOrderForStock } = await supabase
        .from('orders_with')
        .select('id, items, status')
        .eq('id', id)
        .maybeSingle();
      orderBeforeStatusChange = existingOrderForStock || null;
    }

    const { data, error } = await supabase
      .from('orders_with')
      .update(updates)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    if (!data) {
      return res.status(404).json({ error: 'Not Found', message: 'Order not found', timestamp: new Date().toISOString() });
    }

    // 재고 복구: cancelled/refunded로 "새로" 전환되는 경우에만 수행한다(변경 전 상태가 이미 cancelled/refunded면
    // 건너뛰어 중복 복구를 막는다 - 반품요청 승인 처리의 completed 전이 로직과 동일한 원칙).
    let stockRestored = null;
    if (
      (status === 'cancelled' || status === 'refunded') &&
      orderBeforeStatusChange &&
      orderBeforeStatusChange.status !== 'cancelled' &&
      orderBeforeStatusChange.status !== 'refunded'
    ) {
      const items = Array.isArray(orderBeforeStatusChange.items) ? orderBeforeStatusChange.items : [];
      for (const item of items) {
        if (!item.product_id) continue;
        const qty = Number(item.quantity) || 1;
        try {
          await supabase.rpc('adjust_stock_with', {
            p_product_id: item.product_id,
            p_variant_id: item.variant_id || null,
            p_delta: qty,
            p_reason: `관리자 주문상태 변경(${status})에 따른 재고 복구 (주문 ${id})`,
            p_order_id: id,
            p_created_by: req.user.id,
            p_scan_source: 'order_restore'
          });
          await supabase.rpc('release_channel_stock', { p_product_id: item.product_id, p_variant_id: item.variant_id || null, p_channel: 'live', p_qty: qty });
        } catch (restoreErr) { /* 재고 복구는 최선을 다해 시도하되, 하나가 실패해도 전체 처리를 막지 않는다 */ }
        if (item.variant_id) await syncProductStockFromVariants(item.product_id);
      }
      stockRestored = items.length;
    }

    // 주문 상태(status)가 실제로 바뀐 경우에만 알림 이메일을 보낸다 (운송장 정보만 저장한 경우는 발송하지 않음 - shipped로 바뀔 때 함께 안내됨)
    if (status !== undefined) {
      const { data: profile } = await supabase.from('profiles').select('email').eq('id', data.user_id).maybeSingle();
      await sendOrderStatusEmail(data, profile?.email, status).catch(() => {});
    }

    res.json({ success: true, data, stockRestored, message: 'Order status updated successfully', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating order status:', err);
    res.status(500).json({ error: 'Failed to update order status', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공급자(판매자)용 "내 상품이 포함된 주문" 확인 - 읽기 전용
// orders_with.items 는 여러 판매자의 상품이 한 주문에 섞여 담길 수 있는 장바구니형 구조이므로,
// 다른 공급자의 매출/구매자 정보가 노출되지 않도록 응답에는 본인 상품에 해당하는 라인아이템만 골라서 내려준다.
// 주문 상태 변경은 관리자만 가능하며(주문 전체가 여러 공급자에 걸칠 수 있어 한 공급자가 임의로 바꿀 수 없음),
// 이 엔드포인트는 조회 전용이다.
app.get('/api/provider/orders', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    // 관리자가 이 엔드포인트를 호출하면(테스트 등) 전체 주문에서 필터링할 상품 후보가 없으므로
    // 요청자 본인 명의로 등록된 상품만 기준으로 삼는다 (관리자용 전체 조회는 /api/admin/orders 사용)
    const { data: myProducts, error: pErr } = await supabase
      .from('products_with')
      .select('id, name')
      .eq('supplier_id', req.user.id);
    if (pErr) throw pErr;

    const myProductIds = new Set((myProducts || []).map(p => String(p.id)));
    const myProductNames = {};
    (myProducts || []).forEach(p => { myProductNames[String(p.id)] = p.name; });

    if (myProductIds.size === 0) {
      return res.json({ success: true, data: [], count: 0, message: '등록된 상품이 없어 확인할 주문이 없습니다', timestamp: new Date().toISOString() });
    }

    // 최근 주문부터 조회 (과도한 전체 스캔을 피하기 위해 최근 500건으로 제한)
    const { data: orders, error } = await supabase
      .from('orders_with')
      .select('id, order_number, user_id, community_id, items, status, shipping_status, tracking_number, courier_name, created_at')
      .order('created_at', { ascending: false })
      .limit(500);
    if (error) throw error;

    const matched = (orders || [])
      .map(o => {
        const myItems = (o.items || []).filter(it => myProductIds.has(String(it.product_id)));
        if (myItems.length === 0) return null;
        const mySubtotal = myItems.reduce((sum, it) => sum + Number(it.price || 0) * Number(it.quantity || 1), 0);
        return {
          id: o.id,
          order_number: o.order_number,
          created_at: o.created_at,
          status: o.status,
          shipping_status: o.shipping_status,
          tracking_number: o.tracking_number,
          courier_name: o.courier_name,
          community_id: o.community_id,
          user_id: o.user_id,
          my_items: myItems,
          my_subtotal: mySubtotal
        };
      })
      .filter(Boolean);

    // 주문자/커뮤니티 이름은 orders_with 와 FK 조인이 안 되므로 별도 조회 후 서버에서 합쳐준다
    const userIds = [...new Set(matched.map(o => o.user_id).filter(Boolean))];
    const communityIds = [...new Set(matched.map(o => o.community_id).filter(Boolean))];
    const [{ data: profiles }, { data: communities }] = await Promise.all([
      userIds.length ? supabase.from('profiles').select('id, email, full_name').in('id', userIds) : Promise.resolve({ data: [] }),
      communityIds.length ? supabase.from('communities').select('id, name, slug').in('id', communityIds) : Promise.resolve({ data: [] })
    ]);

    const result = matched.map(o => {
      const { user_id, ...rest } = o;
      const profile = (profiles || []).find(p => p.id === user_id);
      const community = (communities || []).find(c => c.id === o.community_id);
      return {
        ...rest,
        buyer_name: profile?.full_name || null,
        buyer_email: profile?.email || null,
        community_name: community?.name || null,
        community_slug: community?.slug || null
      };
    });

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching provider orders:', err);
    res.status(500).json({ error: 'Failed to fetch provider orders', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 리뷰 API
// ============================================

// 최근 리뷰 조회 (홈페이지 실시간 활동 섹션용, 인증 불필요)
app.get('/api/reviews/recent', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 5, 20);
    const { data, error } = await supabasePublic
      .from('product_reviews')
      .select('id, rating, comment, created_at, verified_purchase, products_with(name)')
      .eq('status', 'published')
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) throw error;

    const reviews = (data || []).map(r => ({
      id: r.id,
      rating: r.rating,
      comment: r.comment,
      created_at: r.created_at,
      verified_purchase: r.verified_purchase,
      product_name: r.products_with ? r.products_with.name : '상품'
    }));

    res.json({ success: true, data: reviews, count: reviews.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching recent reviews:', err);
    res.status(500).json({ error: 'Failed to fetch recent reviews', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 리뷰 생성 - order_id를 함께 보내면 "구매인증" 배지를 받으려면 서버가 실제로
// (1) 그 주문이 본인 것인지 (2) 배송완료 상태인지 (3) 그 주문에 이 상품이 실제로 포함되어 있는지를
// 검증한다. order_id 없이도 리뷰 작성 자체는 가능하지만(카페24 등 일반 쇼핑몰 관행과 동일), 이 경우
// verified_purchase는 항상 false로 남아 화면에 "구매인증" 배지가 붙지 않는다 - 절대 가짜로 인증배지를
// 붙이지 않는다. 같은 상품에는 회원 1명당 리뷰 1개만 허용해 도배를 막는다.
app.post('/api/reviews', authenticate, async (req, res) => {
  try {
    const { product_id, order_id, rating, title, comment } = req.body;

    if (!product_id || !rating || !comment) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Required fields: product_id, rating, comment',
        timestamp: new Date().toISOString()
      });
    }

    // rating이 숫자가 아닌 값이면 Number()가 NaN이 되고, NaN과의 대소비교는 항상 false라
    // `rating < 1 || rating > 5` 검증을 그대로 통과해버리는 문제가 있었다. 정수 여부부터 명시적으로 검증한다.
    const ratingNum = Number(rating);
    if (!Number.isInteger(ratingNum) || ratingNum < 1 || ratingNum > 5) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Rating must be an integer between 1 and 5',
        timestamp: new Date().toISOString()
      });
    }

    // 같은 회원이 같은 상품에 이미 리뷰를 남겼는지 확인 (도배 방지 - 상품당 회원 1리뷰)
    const { data: existingReview } = await supabase
      .from('product_reviews')
      .select('id')
      .eq('product_id', product_id)
      .eq('user_id', req.user.id)
      .maybeSingle();
    if (existingReview) {
      return res.status(400).json({
        error: 'Bad Request',
        message: '이미 이 상품에 리뷰를 작성하셨습니다. 기존 리뷰를 수정해주세요.',
        timestamp: new Date().toISOString()
      });
    }

    let verifiedPurchase = false;
    if (order_id) {
      const { data: order } = await supabase
        .from('orders_with')
        .select('id, user_id, status, items')
        .eq('id', order_id)
        .maybeSingle();
      if (!order || order.user_id !== req.user.id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: '본인의 주문이 아니거나 존재하지 않는 주문입니다.',
          timestamp: new Date().toISOString()
        });
      }
      if (order.status !== 'delivered') {
        return res.status(400).json({
          error: 'Bad Request',
          message: '배송완료된 주문만 구매인증 리뷰로 등록할 수 있습니다.',
          timestamp: new Date().toISOString()
        });
      }
      const itemsInOrder = Array.isArray(order.items) ? order.items : [];
      const productInOrder = itemsInOrder.some(i => i.product_id === product_id);
      if (!productInOrder) {
        return res.status(400).json({
          error: 'Bad Request',
          message: '해당 주문에 포함되지 않은 상품입니다.',
          timestamp: new Date().toISOString()
        });
      }
      verifiedPurchase = true;
    }

    const { data, error } = await supabase
      .from('product_reviews')
      .insert([{
        product_id,
        order_id: order_id || null,
        user_id: req.user.id,
        rating: ratingNum,
        title: title || null,
        comment,
        status: 'published',
        verified_purchase: verifiedPurchase
      }])
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      data: data,
      message: 'Review created successfully',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error creating review:', err);
    res.status(500).json({
      error: 'Failed to create review',
      message: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// 관리자: 전체 리뷰 목록 조회 (모더레이션용, 상태 필터 가능)
app.get('/api/admin/reviews', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    // product_reviews.user_id는 profiles에 대한 FK가 없어(PostgREST가 자동 조인할 관계를 못 찾음)
    // 작성자 정보는 여기서 직접 한 번에 조회해 매칭한다.
    let query = supabase
      .from('product_reviews')
      .select('*, products_with(name)')
      .order('created_at', { ascending: false });
    if (req.query.status) {
      query = query.eq('status', req.query.status);
    }
    const { data, error } = await query;
    if (error) throw error;

    const reviews = data || [];
    const userIds = [...new Set(reviews.map(r => r.user_id).filter(Boolean))];
    let profileMap = {};
    if (userIds.length > 0) {
      const { data: profiles } = await supabase.from('profiles').select('id, email, full_name').in('id', userIds);
      (profiles || []).forEach(p => { profileMap[p.id] = p; });
    }
    const enriched = reviews.map(r => ({ ...r, profiles: profileMap[r.user_id] || null }));

    res.json({ success: true, data: enriched, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin reviews:', err);
    res.status(500).json({ error: 'Failed to fetch reviews', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 리뷰 숨김/공개 처리 (도배·조작·부적절한 리뷰 대응)
app.patch('/api/admin/reviews/:id/status', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status, hidden_reason } = req.body;
    if (status !== 'published' && status !== 'hidden') {
      return res.status(400).json({
        error: 'Bad Request',
        message: "status는 'published' 또는 'hidden'이어야 합니다",
        timestamp: new Date().toISOString()
      });
    }
    const { data, error } = await supabase
      .from('product_reviews')
      .update({
        status,
        hidden_reason: status === 'hidden' ? (hidden_reason || null) : null,
        moderated_by: req.user.id,
        moderated_at: new Date().toISOString()
      })
      .eq('id', id)
      .select()
      .single();
    if (error) throw error;
    if (!data) {
      return res.status(404).json({ error: 'Not Found', message: '리뷰를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    res.json({ success: true, data, message: '리뷰 상태가 변경되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error moderating review:', err);
    res.status(500).json({ error: 'Failed to moderate review', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 커뮤니티 API (인증 불필요, 공개 목록)
// ============================================
app.get('/api/communities', async (req, res) => {
  try {
    const [{ data: communities, error: cErr }, { data: members, error: mErr }] = await Promise.all([
      supabase.from('communities').select('id, name, slug, description, image_url, logo_url, total_points_earned').eq('status', 'active').order('created_at', { ascending: false }),
      supabase.from('community_members').select('community_id').eq('status', 'active')
    ]);
    if (cErr) throw cErr;
    if (mErr) throw mErr;

    const memberCounts = {};
    (members || []).forEach(m => {
      memberCounts[m.community_id] = (memberCounts[m.community_id] || 0) + 1;
    });

    const result = (communities || []).map(c => ({
      ...c,
      member_count: memberCounts[c.id] || 0
    }));

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching communities:', err);
    res.status(500).json({ error: 'Failed to fetch communities', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 커뮤니티(조직) 단건 조회 - 분양형 랜딩페이지(/c/:slug)용, 인증 불필요
// "공동체 총 적립금"은 communities.total_points_earned(정적 컬럼, 실시간 반영 안 됨) 대신
// 실제 주문 데이터(orders_with.community_earned_points)를 합산해 정직한 실시간 값으로 계산한다.
app.get('/api/communities/:slug', async (req, res) => {
  try {
    const { data: community, error } = await supabase
      .from('communities')
      .select('*')
      .eq('slug', req.params.slug)
      .eq('status', 'active')
      .single();
    if (error || !community) {
      return res.status(404).json({ error: 'Not Found', message: '커뮤니티를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }

    const [{ count: memberCount }, { data: orders }] = await Promise.all([
      supabase.from('community_members').select('id', { count: 'exact', head: true }).eq('community_id', community.id).eq('status', 'active'),
      supabase.from('orders_with').select('community_earned_points, status').eq('community_id', community.id)
    ]);

    const totalPointsEarned = (orders || [])
      .filter(o => !['cancelled', 'refunded'].includes(o.status))
      .reduce((sum, o) => sum + Number(o.community_earned_points || 0), 0);

    // 랜딩페이지 하단에 표시할 사업자정보 - communities.business_info_mode에 따라 "이 조직 자체 정보" 또는
    // "WITH+ 플랫폼 정보" 중 실제로 보여줄 값을 서버가 미리 계산해 내려준다(프론트는 모드 분기를 몰라도 됨).
    let resolvedBusinessInfo;
    if (community.business_info_mode === 'own') {
      resolvedBusinessInfo = {
        company_name: community.business_name || community.name || '',
        ceo_name: community.ceo_name || '',
        business_number: community.business_number || '',
        mail_order_registration_number: community.mail_order_registration_number || '',
        address: community.address || '',
        phone: community.phone || '',
        email: community.contact_email || '',
        privacy_officer_name: community.privacy_officer_name || '',
        privacy_officer_position: community.privacy_officer_position || '',
        privacy_officer_contact: community.privacy_officer_contact || ''
      };
    } else {
      const platformInfo = await getPlatformBusinessInfo();
      resolvedBusinessInfo = {
        company_name: platformInfo.company_name || '',
        ceo_name: platformInfo.ceo_name || '',
        business_number: platformInfo.business_number || '',
        mail_order_registration_number: platformInfo.mail_order_registration_number || '',
        address: platformInfo.address || '',
        phone: platformInfo.phone || '',
        email: platformInfo.email || '',
        privacy_officer_name: platformInfo.privacy_officer_name || '',
        privacy_officer_position: platformInfo.privacy_officer_position || '',
        privacy_officer_contact: platformInfo.privacy_officer_contact || ''
      };
    }

    res.json({
      success: true,
      data: { ...community, member_count: memberCount || 0, total_points_earned: totalPointsEarned, resolved_business_info: resolvedBusinessInfo },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching community detail:', err);
    res.status(500).json({ error: 'Failed to fetch community', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 커뮤니티 가입 (분양 조직 랜딩페이지를 통한 회원가입 시 자동 연결, 또는 언제든 직접 가입 가능)
app.post('/api/communities/:slug/join', authenticate, async (req, res) => {
  try {
    const { data: community, error: cErr } = await supabase
      .from('communities')
      .select('id, status')
      .eq('slug', req.params.slug)
      .single();
    if (cErr || !community || community.status !== 'active') {
      return res.status(404).json({ error: 'Not Found', message: '커뮤니티를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }

    const { data: existing } = await supabase
      .from('community_members')
      .select('id, status')
      .eq('community_id', community.id)
      .eq('user_id', req.user.id)
      .maybeSingle();

    if (existing) {
      if (existing.status !== 'active') {
        await supabase.from('community_members').update({ status: 'active' }).eq('id', existing.id);
      }
      return res.json({ success: true, message: '이미 가입된 커뮤니티입니다', timestamp: new Date().toISOString() });
    }

    const { error } = await supabase.from('community_members').insert([{
      community_id: community.id,
      user_id: req.user.id,
      role: 'member',
      status: 'active'
    }]);
    if (error) throw error;

    res.status(201).json({ success: true, message: '커뮤니티에 가입되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error joining community:', err);
    res.status(500).json({ error: 'Failed to join community', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 로그인한 회원이 특정 커뮤니티에 기여한 적립금 - 인증 필요
app.get('/api/communities/:slug/my-contribution', authenticate, async (req, res) => {
  try {
    const { data: community, error: cErr } = await supabase
      .from('communities')
      .select('id')
      .eq('slug', req.params.slug)
      .single();
    if (cErr || !community) {
      return res.status(404).json({ error: 'Not Found', message: '커뮤니티를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }

    const { data: orders, error } = await supabase
      .from('orders_with')
      .select('community_earned_points, status')
      .eq('community_id', community.id)
      .eq('user_id', req.user.id);
    if (error) throw error;

    const myContribution = (orders || [])
      .filter(o => !['cancelled', 'refunded'].includes(o.status))
      .reduce((sum, o) => sum + Number(o.community_earned_points || 0), 0);

    res.json({ success: true, data: { myContribution }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching my community contribution:', err);
    res.status(500).json({ error: 'Failed to fetch contribution', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 로그인한 회원이 실제로 가입되어 있는 커뮤니티 목록 (장바구니 커뮤니티 선택 등에서 사용)
// 전체 커뮤니티 목록(/api/communities)과 달리, 이 회원이 community_members에 active로 연결된 조직만 반환한다
app.get('/api/my/communities', authenticate, async (req, res) => {
  try {
    const { data: memberships, error } = await supabase
      .from('community_members')
      .select('community_id')
      .eq('user_id', req.user.id)
      .eq('status', 'active');
    if (error) throw error;

    const communityIds = [...new Set((memberships || []).map(m => m.community_id))];
    if (communityIds.length === 0) {
      return res.json({ success: true, data: [], count: 0, timestamp: new Date().toISOString() });
    }

    const { data: communities, error: cErr } = await supabase
      .from('communities')
      .select('id, name, slug, logo_url, status')
      .in('id', communityIds)
      .eq('status', 'active');
    if (cErr) throw cErr;

    res.json({ success: true, data: communities || [], count: (communities || []).length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching my communities:', err);
    res.status(500).json({ error: 'Failed to fetch my communities', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 커뮤니티(분양 조직) 관리 API - 관리자 전용
// ============================================
// 조직별 사업자등록번호·수수료율·은행계좌가 그대로 포함되어 나가므로 requireOwnerStepUpOrBootstrap로
// 대표자 전용 조회로 제한한다("🏢 분양 조직 관리" 탭과 "💵 분양조직 정산" 탭의 조직별 수수료율 섹션이 공유).
app.get('/api/admin/communities', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUpOrBootstrap, async (req, res) => {
  try {
    const { data, error } = await supabase.from('communities').select('*').order('created_at', { ascending: false });
    if (error) throw error;

    // admin_user_id는 raw UUID라 관리자 화면에 표시하려면 이메일이 필요 - profiles와 FK 조인이 안 되므로 별도 조회 후 합쳐준다
    const adminIds = [...new Set((data || []).map(c => c.admin_user_id).filter(Boolean))];
    let adminEmailMap = {};
    if (adminIds.length > 0) {
      const { data: admins } = await supabase.from('profiles').select('id, email').in('id', adminIds);
      (admins || []).forEach(a => { adminEmailMap[a.id] = a.email; });
    }

    // 조직별 실제 담당자(다중) 수 - 목록 화면에 "담당자 N명"으로 표시하기 위함
    const { data: adminMappings } = await supabase.from('community_admins_with').select('community_id');
    const adminCountMap = {};
    (adminMappings || []).forEach(m => { adminCountMap[m.community_id] = (adminCountMap[m.community_id] || 0) + 1; });

    const result = (data || []).map(c => ({
      ...c,
      admin_email: c.admin_user_id ? (adminEmailMap[c.admin_user_id] || null) : null,
      admin_count: adminCountMap[c.id] || 0
    }));

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin communities:', err);
    res.status(500).json({ error: 'Failed to fetch communities', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 이메일로 가입된 회원의 user_id를 찾는다 (분양 조직 관리자 지정용) - 존재하지 않으면 null
async function resolveUserIdByEmail(email) {
  if (!email || !String(email).trim()) return null;
  const { data } = await supabase.from('profiles').select('id').ilike('email', String(email).trim()).maybeSingle();
  return data ? data.id : null;
}

// 분양 조직별 커스텀 적립율 입력값 검증
// - undefined: 이 필드를 변경하지 않음 (updates에 아예 넣지 않음)
// - null 또는 빈 문자열: 커스텀 적립율 해제 -> 플랫폼 기본값을 따르도록 null 저장
// - 그 외: 0~0.5(0%~50%) 범위의 숫자여야 함
function parsePointRateInput(value) {
  if (value === undefined) return { present: false };
  if (value === null || value === '') return { present: true, value: null };
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > 0.5) return { present: true, invalid: true };
  return { present: true, value: n };
}

// 분양 랜딩페이지 디자인 템플릿 - DB CHECK 제약과 동일한 허용값 목록 (여기서 먼저 걸러야 깔끔한 400 메시지를 줄 수 있음)
const LANDING_TEMPLATES = ['classic', 'modern', 'warm'];
// 이 조직 랜딩페이지에 표시할 사업자정보를 "WITH+ 플랫폼 정보"로 할지 "이 조직 자체 정보"로 할지 - communities.business_info_mode CHECK 제약과 동일
const BUSINESS_INFO_MODES = ['platform', 'own'];

app.post('/api/admin/communities', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { name, slug, description, image_url, logo_url, stamp_url, primary_color, hero_title, hero_subtitle, intro_text, address, phone, website_url, contact_email, admin_email, personal_point_rate, community_point_rate, landing_template, business_number, business_info_mode, business_name, ceo_name, mail_order_registration_number, privacy_officer_name, privacy_officer_position, privacy_officer_contact } = req.body;
    if (!name || !slug) {
      return res.status(400).json({ error: 'Bad Request', message: 'Required fields: name, slug', timestamp: new Date().toISOString() });
    }
    const cleanSlug = String(slug).trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
    if (!cleanSlug) {
      return res.status(400).json({ error: 'Bad Request', message: 'slug는 영문/숫자/하이픈만 가능합니다', timestamp: new Date().toISOString() });
    }
    if (landing_template !== undefined && !LANDING_TEMPLATES.includes(landing_template)) {
      return res.status(400).json({ error: 'Bad Request', message: `landing_template은 ${LANDING_TEMPLATES.join(', ')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
    }
    if (business_info_mode !== undefined && !BUSINESS_INFO_MODES.includes(business_info_mode)) {
      return res.status(400).json({ error: 'Bad Request', message: `business_info_mode는 ${BUSINESS_INFO_MODES.join(', ')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
    }

    // 이 조직을 담당할 관리자를 이메일로 지정 (WITH+에 이미 가입된 회원이어야 함) - 이 사람만 /api/community-admin/* 로 이 조직 데이터를 볼 수 있다
    let adminUserId = null;
    if (admin_email) {
      adminUserId = await resolveUserIdByEmail(admin_email);
      if (!adminUserId) {
        return res.status(400).json({ error: 'Bad Request', message: `해당 이메일(${admin_email})로 가입된 회원을 찾을 수 없습니다. 먼저 일반 회원으로 가입한 뒤 조직 관리자로 지정해주세요.`, timestamp: new Date().toISOString() });
      }
    }

    // 이 조직 전용 적립율 (비워두면 플랫폼 기본값을 따름 - getEffectiveMileageRates 참고)
    const personalRate = parsePointRateInput(personal_point_rate);
    const communityRate = parsePointRateInput(community_point_rate);
    if (personalRate.invalid || communityRate.invalid) {
      return res.status(400).json({ error: 'Bad Request', message: '적립율은 0% ~ 50% 사이여야 합니다', timestamp: new Date().toISOString() });
    }

    // 사업자등록번호(있으면 국세청 상태조회로 검증) - 분양조직 현금 정산을 받으려면 사실상 필수지만,
    // 등록 자체를 막지는 않는다 (나중에 정산 기능을 켤 때/정산 생성 시점에 없으면 자동으로 걸러진다)
    const bizUpdates = {};
    const bizResult = await applyBusinessNumberVerification(bizUpdates, business_number, undefined);
    if (bizResult.error) {
      return res.status(bizResult.error.status).json({ error: 'Bad Request', message: bizResult.error.message, timestamp: new Date().toISOString() });
    }

    const { data, error } = await supabase
      .from('communities')
      .insert([{
        name: String(name).trim(),
        slug: cleanSlug,
        description: description || '',
        image_url: image_url || null,
        business_number: bizUpdates.business_number,
        business_number_verified: bizUpdates.business_number_verified || false,
        business_number_verified_at: bizUpdates.business_number_verified_at || null,
        business_number_status: bizUpdates.business_number_status || null,
        logo_url: logo_url || null,
        stamp_url: stamp_url || null,
        primary_color: primary_color || null,
        hero_title: hero_title || null,
        hero_subtitle: hero_subtitle || null,
        intro_text: intro_text || null,
        address: address || null,
        phone: phone || null,
        website_url: website_url || null,
        contact_email: contact_email || null,
        admin_user_id: adminUserId,
        personal_point_rate: personalRate.present ? personalRate.value : null,
        community_point_rate: communityRate.present ? communityRate.value : null,
        landing_template: landing_template || 'classic',
        business_info_mode: business_info_mode || 'platform',
        business_name: business_name || null,
        ceo_name: ceo_name || null,
        mail_order_registration_number: mail_order_registration_number || null,
        privacy_officer_name: privacy_officer_name || null,
        privacy_officer_position: privacy_officer_position || null,
        privacy_officer_contact: privacy_officer_contact || null,
        status: 'active'
      }])
      .select()
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'Conflict', message: '이미 존재하는 슬러그입니다', timestamp: new Date().toISOString() });
      }
      throw error;
    }

    // 생성 시 지정한 담당자를 다중 담당자 테이블에도 첫 담당자로 등록한다 (이미 다른 조직 담당이면 조용히 건너뜀 - 생성 자체는 막지 않음)
    let adminAssignWarning = null;
    if (adminUserId) {
      const { error: adminInsertErr } = await supabase.from('community_admins_with').insert([{ community_id: data.id, user_id: adminUserId }]);
      if (adminInsertErr && adminInsertErr.code === '23505') {
        adminAssignWarning = '지정한 담당자가 이미 다른 분양 조직의 담당자로 등록되어 있어, 이 조직의 담당자로는 추가되지 않았습니다. "담당자 관리"에서 다시 추가해주세요.';
      }
    }

    const combinedWarning = [bizResult.warning, adminAssignWarning].filter(Boolean).join(' / ') || null;
    res.status(201).json({ success: true, data, warning: combinedWarning, message: '분양 조직(커뮤니티)이 추가되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating community:', err);
    res.status(500).json({ error: 'Failed to create community', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/admin/communities/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { name, slug, description, image_url, logo_url, stamp_url, primary_color, hero_title, hero_subtitle, intro_text, address, phone, website_url, contact_email, status, admin_email, personal_point_rate, community_point_rate, landing_template, settlement_commission_rate, business_number, settlement_tax_method, bank_name, bank_account, account_holder, bank_account_verified, business_info_mode, business_name, ceo_name, mail_order_registration_number, privacy_officer_name, privacy_officer_position, privacy_officer_contact } = req.body;
    const updates = { updated_at: new Date().toISOString() };
    let bizWarning = null;
    // business_number/bank_account 변경 여부 판정에 기존 값이 필요하므로, 둘 중 하나라도 바뀌면 한 번만 조회해서 같이 재사용한다
    const needsExistingLookup = business_number !== undefined || bank_account !== undefined;
    let existingCommunityRow = null;
    if (needsExistingLookup) {
      const { data: existingCommunity } = await supabase.from('communities').select('business_number, bank_account').eq('id', req.params.id).maybeSingle();
      existingCommunityRow = existingCommunity || null;
    }
    if (business_number !== undefined) {
      const bizResult = await applyBusinessNumberVerification(updates, business_number, existingCommunityRow ? existingCommunityRow.business_number : undefined);
      if (bizResult.error) {
        return res.status(bizResult.error.status).json({ error: 'Bad Request', message: bizResult.error.message, timestamp: new Date().toISOString() });
      }
      bizWarning = bizResult.warning || null;
    }
    // 정산금을 실제로 보낼 계좌 정보 - 계좌번호가 (기존 값 대비) 바뀌면 검증 여부를 자동으로 초기화한다(오래된/틀린 계좌를 그대로 신뢰하지 않도록).
    // 실명조회 API 연동 전까지는 관리자가 인터넷뱅킹 등에서 직접 확인한 뒤 bank_account_verified 체크박스로만 검증한다.
    if (bank_name !== undefined) updates.bank_name = bank_name || null;
    if (account_holder !== undefined) updates.account_holder = account_holder || null;
    if (bank_account !== undefined) {
      const bankAccountChanged = !existingCommunityRow || existingCommunityRow.bank_account !== (bank_account || null);
      updates.bank_account = bank_account || null;
      if (bankAccountChanged) {
        updates.bank_account_verified = false;
        updates.bank_account_updated_at = new Date().toISOString();
      }
    }
    if (bank_account_verified !== undefined && updates.bank_account_verified === undefined) {
      updates.bank_account_verified = !!bank_account_verified;
    }
    if (name !== undefined) updates.name = String(name).trim();
    if (slug !== undefined) {
      const cleanSlug = String(slug).trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
      if (!cleanSlug) {
        return res.status(400).json({ error: 'Bad Request', message: 'slug는 영문/숫자/하이픈만 가능합니다', timestamp: new Date().toISOString() });
      }
      updates.slug = cleanSlug;
    }
    if (landing_template !== undefined) {
      if (!LANDING_TEMPLATES.includes(landing_template)) {
        return res.status(400).json({ error: 'Bad Request', message: `landing_template은 ${LANDING_TEMPLATES.join(', ')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
      }
      updates.landing_template = landing_template;
    }
    if (description !== undefined) updates.description = description;
    if (image_url !== undefined) updates.image_url = image_url || null;
    if (logo_url !== undefined) updates.logo_url = logo_url || null;
    if (stamp_url !== undefined) updates.stamp_url = stamp_url || null;
    if (primary_color !== undefined) updates.primary_color = primary_color || null;
    if (hero_title !== undefined) updates.hero_title = hero_title || null;
    if (hero_subtitle !== undefined) updates.hero_subtitle = hero_subtitle || null;
    if (intro_text !== undefined) updates.intro_text = intro_text || null;
    if (address !== undefined) updates.address = address || null;
    if (phone !== undefined) updates.phone = phone || null;
    if (website_url !== undefined) updates.website_url = website_url || null;
    if (contact_email !== undefined) updates.contact_email = contact_email || null;
    if (status !== undefined) updates.status = status;
    // 대표 담당자 표시값 변경/해제 - 빈 문자열이면 해제(null), 값이 있으면 해당 이메일 회원으로 교체
    // (실제 조직 데이터 접근 권한은 이 값이 아니라 담당자 목록(community_admins_with)으로 판정된다 - "담당자 관리"에서 추가/제거)
    let putAdminAssignWarning = null;
    if (admin_email !== undefined) {
      if (!admin_email) {
        updates.admin_user_id = null;
      } else {
        const adminUserId = await resolveUserIdByEmail(admin_email);
        if (!adminUserId) {
          return res.status(400).json({ error: 'Bad Request', message: `해당 이메일(${admin_email})로 가입된 회원을 찾을 수 없습니다`, timestamp: new Date().toISOString() });
        }
        updates.admin_user_id = adminUserId;
        const { error: adminInsertErr } = await supabase.from('community_admins_with').insert([{ community_id: req.params.id, user_id: adminUserId }]);
        if (adminInsertErr && adminInsertErr.code === '23505') {
          // 이미 이 조직 담당자거나, 다른 조직 담당자인 경우 - 어느 쪽이든 조용히 건너뛰되 후자는 안내
          const { data: alreadyThisOrg } = await supabase.from('community_admins_with').select('id').eq('community_id', req.params.id).eq('user_id', adminUserId).maybeSingle();
          if (!alreadyThisOrg) {
            putAdminAssignWarning = '지정한 담당자가 이미 다른 분양 조직의 담당자로 등록되어 있어, 이 조직의 담당자로는 추가되지 않았습니다. "담당자 관리"에서 다시 추가해주세요.';
          }
        }
      }
    }
    // 이 조직 전용 적립율 변경/해제 (본부 관리자는 어느 조직이든 조정 가능)
    {
      const personalRate = parsePointRateInput(personal_point_rate);
      const communityRate = parsePointRateInput(community_point_rate);
      if (personalRate.invalid || communityRate.invalid) {
        return res.status(400).json({ error: 'Bad Request', message: '적립율은 0% ~ 50% 사이여야 합니다', timestamp: new Date().toISOString() });
      }
      if (personalRate.present) updates.personal_point_rate = personalRate.value;
      if (communityRate.present) updates.community_point_rate = communityRate.value;
    }
    // 이 조직의 현금 정산 수수료율(%) 변경/해제 - 분양조직 현금 정산 기능이 켜져 있을 때만 의미가 있지만,
    // 꺼져 있어도 미리 설정해둘 수 있도록 값 자체는 언제든 받아준다
    if (settlement_commission_rate !== undefined) {
      if (settlement_commission_rate === null || settlement_commission_rate === '') {
        updates.settlement_commission_rate = null;
      } else {
        const rate = Number(settlement_commission_rate);
        if (!Number.isFinite(rate) || rate < 0 || rate > 100) {
          return res.status(400).json({ error: 'Bad Request', message: '현금 정산 수수료율은 0~100 사이의 숫자여야 합니다', timestamp: new Date().toISOString() });
        }
        updates.settlement_commission_rate = rate;
      }
    }
    // 이 조직의 정산 지급 시 세무처리 방식(원천징수 3.3% / 세금계산서 발행 / 해당없음)
    if (settlement_tax_method !== undefined) {
      if (!SETTLEMENT_TAX_METHODS.includes(settlement_tax_method)) {
        return res.status(400).json({ error: 'Bad Request', message: `settlement_tax_method는 ${SETTLEMENT_TAX_METHODS.join(', ')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
      }
      updates.settlement_tax_method = settlement_tax_method;
    }
    // 랜딩페이지 하단 사업자정보를 "WITH+ 플랫폼 정보"로 보여줄지 "이 조직 자체 정보"로 보여줄지 선택
    if (business_info_mode !== undefined) {
      if (!BUSINESS_INFO_MODES.includes(business_info_mode)) {
        return res.status(400).json({ error: 'Bad Request', message: `business_info_mode는 ${BUSINESS_INFO_MODES.join(', ')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
      }
      updates.business_info_mode = business_info_mode;
    }
    // 이 조직 자체 사업자정보(business_info_mode가 'own'일 때 표시됨) - business_number/address/phone/contact_email은
    // 원천징수 등 기존 용도와 겸용이라 위에서 이미 처리되므로 여기서는 신규 필드만 다룬다
    if (business_name !== undefined) updates.business_name = business_name || null;
    if (ceo_name !== undefined) updates.ceo_name = ceo_name || null;
    if (mail_order_registration_number !== undefined) updates.mail_order_registration_number = mail_order_registration_number || null;
    if (privacy_officer_name !== undefined) updates.privacy_officer_name = privacy_officer_name || null;
    if (privacy_officer_position !== undefined) updates.privacy_officer_position = privacy_officer_position || null;
    if (privacy_officer_contact !== undefined) updates.privacy_officer_contact = privacy_officer_contact || null;

    const { data, error } = await supabase
      .from('communities')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'Conflict', message: '이미 존재하는 슬러그입니다', timestamp: new Date().toISOString() });
      }
      throw error;
    }
    if (!data) {
      return res.status(404).json({ error: 'Not Found', message: 'Community not found', timestamp: new Date().toISOString() });
    }
    const combinedPutWarning = [bizWarning, putAdminAssignWarning].filter(Boolean).join(' / ') || null;
    res.json({ success: true, data, warning: combinedPutWarning, message: '커뮤니티 정보가 수정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating community:', err);
    res.status(500).json({ error: 'Failed to update community', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 분양 조직(커뮤니티) 다중 담당자 관리 (본부 관리자 전용)
// 한 조직에 여러 명의 담당 직원을 둘 수 있다. 단, 한 사람은 동시에 한 조직만 담당할 수 있다
// (community_admins_with.user_id UNIQUE 제약으로 DB에서 강제됨 - 겸직으로 인한 데이터 혼선 방지)
// ============================================

app.get('/api/admin/communities/:id/admins', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: rows, error } = await supabase
      .from('community_admins_with')
      .select('id, user_id, created_at')
      .eq('community_id', req.params.id)
      .order('created_at', { ascending: true });
    if (error) throw error;

    const userIds = (rows || []).map(r => r.user_id);
    let profileMap = {};
    if (userIds.length > 0) {
      const { data: profiles } = await supabase.from('profiles').select('id, email, full_name').in('id', userIds);
      (profiles || []).forEach(p => { profileMap[p.id] = p; });
    }
    const result = (rows || []).map(r => ({
      id: r.id,
      user_id: r.user_id,
      email: profileMap[r.user_id]?.email || null,
      full_name: profileMap[r.user_id]?.full_name || null,
      added_at: r.created_at
    }));
    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching community admins:', err);
    res.status(500).json({ error: 'Failed to fetch community admins', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/communities/:id/admins', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !String(email).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: '이메일을 입력해주세요', timestamp: new Date().toISOString() });
    }
    const { data: community } = await supabase.from('communities').select('id, name').eq('id', req.params.id).maybeSingle();
    if (!community) {
      return res.status(404).json({ error: 'Not Found', message: '분양 조직을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    const userId = await resolveUserIdByEmail(String(email).trim());
    if (!userId) {
      return res.status(400).json({ error: 'Bad Request', message: `해당 이메일(${email})로 가입된 회원을 찾을 수 없습니다. WITH+에 먼저 일반 회원으로 가입되어 있어야 합니다.`, timestamp: new Date().toISOString() });
    }

    const { data, error } = await supabase
      .from('community_admins_with')
      .insert([{ community_id: req.params.id, user_id: userId }])
      .select()
      .single();
    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'Conflict', message: '이미 다른 분양 조직의 담당자로 지정되어 있는 회원입니다. 먼저 기존 담당에서 해제해주세요.', timestamp: new Date().toISOString() });
      }
      throw error;
    }
    res.status(201).json({ success: true, data, message: `${community.name}의 담당자로 추가되었습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error adding community admin:', err);
    res.status(500).json({ error: 'Failed to add community admin', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.delete('/api/admin/communities/:id/admins/:userId', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { error } = await supabase
      .from('community_admins_with')
      .delete()
      .eq('community_id', req.params.id)
      .eq('user_id', req.params.userId);
    if (error) throw error;
    res.json({ success: true, message: '담당자에서 해제되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error removing community admin:', err);
    res.status(500).json({ error: 'Failed to remove community admin', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 분양 조직별 상품 노출 범위 ("전체 노출" 또는 "선택한 상품만 노출")
// - 기본값은 all(전체 노출) - 지금까지와 동일하게 모든 조직에 전체 카탈로그가 그대로 보인다.
// - curated로 바꾸면 community_products에 등록해둔 상품만 그 조직 방문자에게 보인다.
// ============================================
app.get('/api/admin/communities/:id/products', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: community, error: cErr } = await supabase
      .from('communities')
      .select('id, product_visibility')
      .eq('id', req.params.id)
      .maybeSingle();
    if (cErr) throw cErr;
    if (!community) {
      return res.status(404).json({ error: 'Not Found', message: '분양 조직을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    const { data: picks, error: pErr } = await supabase
      .from('community_products')
      .select('product_id')
      .eq('community_id', req.params.id);
    if (pErr) throw pErr;
    res.json({
      success: true,
      data: { product_visibility: community.product_visibility, product_ids: (picks || []).map(p => p.product_id) },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching community product visibility:', err);
    res.status(500).json({ error: 'Failed to fetch community products', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/admin/communities/:id/products', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { product_visibility, product_ids } = req.body;
    if (!['all', 'curated'].includes(product_visibility)) {
      return res.status(400).json({ error: 'Bad Request', message: "product_visibility는 'all' 또는 'curated'여야 합니다", timestamp: new Date().toISOString() });
    }
    const ids = Array.isArray(product_ids) ? [...new Set(product_ids)] : [];

    const { data: community, error: cErr } = await supabase
      .from('communities')
      .select('id, name')
      .eq('id', req.params.id)
      .maybeSingle();
    if (cErr) throw cErr;
    if (!community) {
      return res.status(404).json({ error: 'Not Found', message: '분양 조직을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }

    if (ids.length > 0) {
      const { data: validProducts, error: vErr } = await supabase.from('products_with').select('id').in('id', ids);
      if (vErr) throw vErr;
      const validIds = new Set((validProducts || []).map(p => p.id));
      const invalid = ids.filter(id => !validIds.has(id));
      if (invalid.length > 0) {
        return res.status(400).json({ error: 'Bad Request', message: `존재하지 않는 상품 id가 포함되어 있습니다: ${invalid.join(', ')}`, timestamp: new Date().toISOString() });
      }
    }

    const { error: upErr } = await supabase.from('communities').update({ product_visibility }).eq('id', req.params.id);
    if (upErr) throw upErr;

    // 선택 목록은 통째로 교체한다(기존 것 전부 삭제 후 새로 넣기) - 부분 추가/삭제보다 "지금 화면에서 고른 것 = 저장 결과"가 명확함
    const { error: delErr } = await supabase.from('community_products').delete().eq('community_id', req.params.id);
    if (delErr) throw delErr;
    if (ids.length > 0) {
      const { error: insErr } = await supabase.from('community_products').insert(ids.map(product_id => ({ community_id: req.params.id, product_id })));
      if (insErr) throw insErr;
    }

    res.json({
      success: true,
      data: { product_visibility, product_ids: ids },
      message: `${community.name}의 상품 노출 설정이 저장되었습니다`,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error updating community product visibility:', err);
    res.status(500).json({ error: 'Failed to update community products', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 분양 조직별 카테고리 노출 범위 ("전체 노출" 또는 "선택한 카테고리만 노출")
// - 위의 상품 노출 범위 기능과 완전히 같은 설계(all/curated + 매핑 테이블 통째로 교체).
// - 기본값은 all(전체 노출) - 지금까지와 동일하게 모든 조직에 전체 카테고리 메뉴가 그대로 보인다.
// ============================================
app.get('/api/admin/communities/:id/categories', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: community, error: cErr } = await supabase
      .from('communities')
      .select('id, category_visibility')
      .eq('id', req.params.id)
      .maybeSingle();
    if (cErr) throw cErr;
    if (!community) {
      return res.status(404).json({ error: 'Not Found', message: '분양 조직을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    const { data: picks, error: pErr } = await supabase
      .from('community_categories_with')
      .select('category_id')
      .eq('community_id', req.params.id);
    if (pErr) throw pErr;
    res.json({
      success: true,
      data: { category_visibility: community.category_visibility, category_ids: (picks || []).map(p => p.category_id) },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching community category visibility:', err);
    res.status(500).json({ error: 'Failed to fetch community categories', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/admin/communities/:id/categories', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { category_visibility, category_ids } = req.body;
    if (!['all', 'curated'].includes(category_visibility)) {
      return res.status(400).json({ error: 'Bad Request', message: "category_visibility는 'all' 또는 'curated'여야 합니다", timestamp: new Date().toISOString() });
    }
    const ids = Array.isArray(category_ids) ? [...new Set(category_ids)] : [];

    const { data: community, error: cErr } = await supabase
      .from('communities')
      .select('id, name')
      .eq('id', req.params.id)
      .maybeSingle();
    if (cErr) throw cErr;
    if (!community) {
      return res.status(404).json({ error: 'Not Found', message: '분양 조직을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }

    if (ids.length > 0) {
      const { data: validCategories, error: vErr } = await supabase.from('categories').select('id').in('id', ids);
      if (vErr) throw vErr;
      const validIds = new Set((validCategories || []).map(c => c.id));
      const invalid = ids.filter(id => !validIds.has(id));
      if (invalid.length > 0) {
        return res.status(400).json({ error: 'Bad Request', message: `존재하지 않는 카테고리 id가 포함되어 있습니다: ${invalid.join(', ')}`, timestamp: new Date().toISOString() });
      }
    }

    const { error: upErr } = await supabase.from('communities').update({ category_visibility }).eq('id', req.params.id);
    if (upErr) throw upErr;

    // 선택 목록은 통째로 교체한다(기존 것 전부 삭제 후 새로 넣기) - 부분 추가/삭제보다 "지금 화면에서 고른 것 = 저장 결과"가 명확함
    const { error: delErr } = await supabase.from('community_categories_with').delete().eq('community_id', req.params.id);
    if (delErr) throw delErr;
    if (ids.length > 0) {
      const { error: insErr } = await supabase.from('community_categories_with').insert(ids.map(category_id => ({ community_id: req.params.id, category_id })));
      if (insErr) throw insErr;
    }

    res.json({
      success: true,
      data: { category_visibility, category_ids: ids },
      message: `${community.name}의 카테고리 노출 설정이 저장되었습니다`,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error updating community category visibility:', err);
    res.status(500).json({ error: 'Failed to update community categories', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 분양 조직(커뮤니티) 담당 관리자용 API
// 이 사람은 본부(admin/super_admin)가 아니라 개별 분양 조직(예: 인천선한목자교회)의 담당자로,
// communities.admin_user_id 가 본인과 일치하는 "자기 조직" 데이터만 조회할 수 있다.
// 다른 조직의 회원·주문은 절대 노출되지 않는다(쿼리 자체가 자기 조직 id로만 필터링됨).
// 본부 관리자(admin/super_admin)는 이 API 대신 기존 /api/admin/* (전체 조회)를 사용한다.
// ============================================

// 담당자 지정은 community_admins_with 매핑 테이블 기준 (한 조직에 여러 담당자를 둘 수 있다 - 다중 담당자 지원)
// communities.admin_user_id 컬럼은 "대표 담당자" 표시용으로만 남아있고, 실제 접근 권한 판정에는 쓰이지 않는다
async function getMyManagedCommunity(userId) {
  const { data: mapping, error: mapErr } = await supabase
    .from('community_admins_with')
    .select('community_id')
    .eq('user_id', userId)
    .maybeSingle();
  if (mapErr) throw mapErr;
  if (!mapping) return null;
  const { data, error } = await supabase.from('communities').select('*').eq('id', mapping.community_id).maybeSingle();
  if (error) throw error;
  return data;
}

app.get('/api/community-admin/dashboard', authenticate, async (req, res) => {
  try {
    const community = await getMyManagedCommunity(req.user.id);
    if (!community) {
      return res.status(404).json({ error: 'Not Found', message: '담당하고 있는 분양 조직이 없습니다', timestamp: new Date().toISOString() });
    }

    const [{ count: memberCount }, { data: orders }] = await Promise.all([
      supabase.from('community_members').select('id', { count: 'exact', head: true }).eq('community_id', community.id).eq('status', 'active'),
      supabase.from('orders_with').select('final_price, community_earned_points, status').eq('community_id', community.id)
    ]);

    const validOrders = (orders || []).filter(o => !['cancelled', 'refunded'].includes(o.status));
    const totalSales = validOrders.reduce((sum, o) => sum + Number(o.final_price || 0), 0);
    const totalPointsEarned = validOrders.reduce((sum, o) => sum + Number(o.community_earned_points || 0), 0);

    res.json({
      success: true,
      data: {
        community,
        member_count: memberCount || 0,
        order_count: validOrders.length,
        total_sales: totalSales,
        total_points_earned: totalPointsEarned
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching community-admin dashboard:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/community-admin/members', authenticate, async (req, res) => {
  try {
    const community = await getMyManagedCommunity(req.user.id);
    if (!community) {
      return res.status(404).json({ error: 'Not Found', message: '담당하고 있는 분양 조직이 없습니다', timestamp: new Date().toISOString() });
    }

    const { data: members, error } = await supabase
      .from('community_members')
      .select('user_id, role, status, joined_at')
      .eq('community_id', community.id)
      .order('joined_at', { ascending: false });
    if (error) throw error;

    const userIds = (members || []).map(m => m.user_id);
    let profileMap = {};
    if (userIds.length > 0) {
      // GMWOS와 공유하는 profiles 테이블이므로 이름/이메일 외 민감정보(주민번호 등)는 절대 포함하지 않는다
      const { data: profiles } = await supabase.from('profiles').select('id, email, full_name').in('id', userIds);
      (profiles || []).forEach(p => { profileMap[p.id] = p; });
    }

    // 회원별 이 조직에 대한 기여 적립금도 함께 내려준다 (실시간 계산, 취소/환불 제외)
    const { data: orders } = await supabase
      .from('orders_with')
      .select('user_id, community_earned_points, status')
      .eq('community_id', community.id);
    const contributionMap = {};
    (orders || []).filter(o => !['cancelled', 'refunded'].includes(o.status)).forEach(o => {
      contributionMap[o.user_id] = (contributionMap[o.user_id] || 0) + Number(o.community_earned_points || 0);
    });

    const result = (members || []).map(m => ({
      user_id: m.user_id,
      email: profileMap[m.user_id]?.email || null,
      full_name: profileMap[m.user_id]?.full_name || null,
      role: m.role,
      status: m.status,
      joined_at: m.joined_at,
      contribution_points: contributionMap[m.user_id] || 0
    }));

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching community-admin members:', err);
    res.status(500).json({ error: 'Failed to fetch members', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/community-admin/orders', authenticate, async (req, res) => {
  try {
    const community = await getMyManagedCommunity(req.user.id);
    if (!community) {
      return res.status(404).json({ error: 'Not Found', message: '담당하고 있는 분양 조직이 없습니다', timestamp: new Date().toISOString() });
    }

    const { data: orders, error } = await supabase
      .from('orders_with')
      .select('id, order_number, user_id, items, final_price, community_earned_points, status, shipping_status, tracking_number, courier_name, created_at')
      .eq('community_id', community.id)
      .order('created_at', { ascending: false });
    if (error) throw error;

    const userIds = [...new Set((orders || []).map(o => o.user_id))];
    let profileMap = {};
    if (userIds.length > 0) {
      const { data: profiles } = await supabase.from('profiles').select('id, email, full_name').in('id', userIds);
      (profiles || []).forEach(p => { profileMap[p.id] = p; });
    }

    const result = (orders || []).map(o => ({
      ...o,
      buyer_email: profileMap[o.user_id]?.email || null,
      buyer_name: profileMap[o.user_id]?.full_name || null
    }));

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching community-admin orders:', err);
    res.status(500).json({ error: 'Failed to fetch orders', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 분양 조직 담당 관리자: 자기 조직의 개인/커뮤니티 적립율을 직접 동적으로 조정
// 커스텀 값을 지정하지 않았으면(null) 플랫폼 기본값을 그대로 따른다 - 무엇이 기본값이고 무엇이 커스텀인지
// is_custom_* 플래그로 정직하게 구분해 내려준다.
app.get('/api/community-admin/point-rates', authenticate, async (req, res) => {
  try {
    const community = await getMyManagedCommunity(req.user.id);
    if (!community) {
      return res.status(404).json({ error: 'Not Found', message: '담당하고 있는 분양 조직이 없습니다', timestamp: new Date().toISOString() });
    }
    const platformRates = await getMileageRates();
    const hasCustomPersonal = community.personal_point_rate !== null && community.personal_point_rate !== undefined;
    const hasCustomCommunity = community.community_point_rate !== null && community.community_point_rate !== undefined;
    res.json({
      success: true,
      data: {
        personal: hasCustomPersonal ? Number(community.personal_point_rate) : platformRates.personal,
        community: hasCustomCommunity ? Number(community.community_point_rate) : platformRates.community,
        is_custom_personal: hasCustomPersonal,
        is_custom_community: hasCustomCommunity,
        platform_default: platformRates
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching community-admin point rates:', err);
    res.status(500).json({ error: 'Failed to fetch point rates', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/community-admin/point-rates', authenticate, async (req, res) => {
  try {
    const community = await getMyManagedCommunity(req.user.id);
    if (!community) {
      return res.status(404).json({ error: 'Not Found', message: '담당하고 있는 분양 조직이 없습니다', timestamp: new Date().toISOString() });
    }

    const personalRate = parsePointRateInput(req.body.personal);
    const communityRate = parsePointRateInput(req.body.community);
    if (personalRate.invalid || communityRate.invalid) {
      return res.status(400).json({ error: 'Bad Request', message: '적립율은 0% ~ 50% 사이여야 합니다', timestamp: new Date().toISOString() });
    }

    const updates = { updated_at: new Date().toISOString() };
    if (personalRate.present) updates.personal_point_rate = personalRate.value;
    if (communityRate.present) updates.community_point_rate = communityRate.value;

    const { data, error } = await supabase
      .from('communities')
      .update(updates)
      .eq('id', community.id)
      .select()
      .single();
    if (error) throw error;

    const platformRates = await getMileageRates();
    const hasCustomPersonal = data.personal_point_rate !== null && data.personal_point_rate !== undefined;
    const hasCustomCommunity = data.community_point_rate !== null && data.community_point_rate !== undefined;
    res.json({
      success: true,
      data: {
        personal: hasCustomPersonal ? Number(data.personal_point_rate) : platformRates.personal,
        community: hasCustomCommunity ? Number(data.community_point_rate) : platformRates.community,
        is_custom_personal: hasCustomPersonal,
        is_custom_community: hasCustomCommunity,
        platform_default: platformRates
      },
      message: '적립율이 변경되었습니다',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error updating community-admin point rates:', err);
    res.status(500).json({ error: 'Failed to update point rates', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 분양 조직 담당 관리자: 자기 조직의 "자체 사업자정보"(랜딩페이지 하단 표시용)를 직접 입력/조회
// business_info_mode 자체는 본부 관리자만 바꿀 수 있다(담당자는 플랫폼 정보 표시 <-> 자체 정보 표시를 스스로 전환할 수 없음) -
// GET은 현재 모드를 그대로 알려줘서 프론트가 "아직 활성화 안됨" 안내를 보여줄 수 있게 하고, PUT은 모드가 'own'이 아니면 거절한다.
app.get('/api/community-admin/business-info', authenticate, async (req, res) => {
  try {
    const community = await getMyManagedCommunity(req.user.id);
    if (!community) {
      return res.status(403).json({ error: 'Forbidden', message: '담당하고 있는 분양 조직이 없습니다', timestamp: new Date().toISOString() });
    }
    res.json({
      success: true,
      data: {
        business_info_mode: community.business_info_mode || 'platform',
        business_name: community.business_name || '',
        ceo_name: community.ceo_name || '',
        business_number: community.business_number || '',
        mail_order_registration_number: community.mail_order_registration_number || '',
        address: community.address || '',
        phone: community.phone || '',
        contact_email: community.contact_email || '',
        privacy_officer_name: community.privacy_officer_name || '',
        privacy_officer_position: community.privacy_officer_position || '',
        privacy_officer_contact: community.privacy_officer_contact || ''
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching community-admin business info:', err);
    res.status(500).json({ error: 'Failed to fetch business info', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/community-admin/business-info', authenticate, async (req, res) => {
  try {
    const community = await getMyManagedCommunity(req.user.id);
    if (!community) {
      return res.status(403).json({ error: 'Forbidden', message: '담당하고 있는 분양 조직이 없습니다', timestamp: new Date().toISOString() });
    }
    if (community.business_info_mode !== 'own') {
      return res.status(400).json({ error: 'Bad Request', message: '플랫폼 관리자가 자체 사업자정보 표시를 아직 활성화하지 않았습니다', timestamp: new Date().toISOString() });
    }

    const { business_name, ceo_name, business_number, mail_order_registration_number, address, phone, contact_email, privacy_officer_name, privacy_officer_position, privacy_officer_contact } = req.body || {};
    const updates = { updated_at: new Date().toISOString() };
    if (business_name !== undefined) updates.business_name = business_name || null;
    if (ceo_name !== undefined) updates.ceo_name = ceo_name || null;
    if (business_number !== undefined) updates.business_number = business_number || null;
    if (mail_order_registration_number !== undefined) updates.mail_order_registration_number = mail_order_registration_number || null;
    if (address !== undefined) updates.address = address || null;
    if (phone !== undefined) updates.phone = phone || null;
    if (contact_email !== undefined) updates.contact_email = contact_email || null;
    if (privacy_officer_name !== undefined) updates.privacy_officer_name = privacy_officer_name || null;
    if (privacy_officer_position !== undefined) updates.privacy_officer_position = privacy_officer_position || null;
    if (privacy_officer_contact !== undefined) updates.privacy_officer_contact = privacy_officer_contact || null;

    const { data, error } = await supabase
      .from('communities')
      .update(updates)
      .eq('id', community.id)
      .select()
      .single();
    if (error) throw error;

    res.json({
      success: true,
      data: {
        business_info_mode: data.business_info_mode || 'platform',
        business_name: data.business_name || '',
        ceo_name: data.ceo_name || '',
        business_number: data.business_number || '',
        mail_order_registration_number: data.mail_order_registration_number || '',
        address: data.address || '',
        phone: data.phone || '',
        contact_email: data.contact_email || '',
        privacy_officer_name: data.privacy_officer_name || '',
        privacy_officer_position: data.privacy_officer_position || '',
        privacy_officer_contact: data.privacy_officer_contact || ''
      },
      message: '사업자 정보가 저장되었습니다',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error updating community-admin business info:', err);
    res.status(500).json({ error: 'Failed to save business info', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 플랫폼 통계 API (홈페이지 실시간 활동 섹션용, 인증 불필요)
// ============================================
app.get('/api/stats/summary', async (req, res) => {
  try {
    const [{ count: productCount }, { count: reviewCount }, { count: orderCount }, { data: mileageRows }] = await Promise.all([
      supabase.from('products_with').select('*', { count: 'exact', head: true }).eq('status', 'active'),
      supabase.from('product_reviews').select('*', { count: 'exact', head: true }).eq('status', 'published'),
      supabase.from('orders_with').select('*', { count: 'exact', head: true }),
      supabase.from('orders_with').select('personal_earned_points, community_earned_points')
    ]);

    const totalMileage = (mileageRows || []).reduce(
      (sum, o) => sum + Number(o.personal_earned_points || 0) + Number(o.community_earned_points || 0),
      0
    );

    res.json({
      success: true,
      data: {
        totalProducts: productCount || 0,
        totalReviews: reviewCount || 0,
        totalOrders: orderCount || 0,
        totalMileagePaid: totalMileage
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching stats summary:', err);
    res.status(500).json({ error: 'Failed to fetch stats', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 게시판 API (공지사항 / 사용후기 / Q&A / 자유게시판)
// 읽기는 ANON_KEY(RLS: published만 공개), 쓰기는 전부 서버(service role)를 거쳐
// 인증 + 권한 체크 후 처리 -- products_with/orders_with 와 동일한 설계 원칙
// ============================================
const BOARD_TYPES = ['notice', 'review', 'qa', 'free'];

// 게시글 목록 (공개, 페이지네이션 없이 최신순 최대 100건)
app.get('/api/boards', async (req, res) => {
  try {
    const { type, search } = req.query;
    if (type && !BOARD_TYPES.includes(type)) {
      return res.status(400).json({ error: 'Bad Request', message: `type must be one of: ${BOARD_TYPES.join(', ')}`, timestamp: new Date().toISOString() });
    }

    let query = supabasePublic
      .from('board_posts')
      .select('id, board_type, title, author_name, is_pinned, view_count, is_answered, created_at')
      .order('is_pinned', { ascending: false })
      .order('created_at', { ascending: false })
      .limit(100);

    if (type) query = query.eq('board_type', type);
    if (search) query = query.ilike('title', `%${search}%`);

    const { data, error } = await query;
    if (error) throw error;

    res.json({ success: true, data: data || [], count: data?.length || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching boards:', err);
    res.status(500).json({ error: 'Failed to fetch boards', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 게시글 상세 (공개, 조회수 +1) + 댓글 목록
app.get('/api/boards/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { data: post, error } = await supabasePublic
      .from('board_posts')
      .select('*')
      .eq('id', id)
      .single();

    if (error || !post) {
      return res.status(404).json({ error: 'Not Found', message: 'Post not found', timestamp: new Date().toISOString() });
    }

    // 조회수 증가는 service role로 (anon 키엔 update 권한 없음)
    supabase.from('board_posts').update({ view_count: (post.view_count || 0) + 1 }).eq('id', id).then(() => {}).catch(() => {});

    const { data: comments } = await supabasePublic
      .from('board_comments')
      .select('*')
      .eq('post_id', id)
      .order('created_at', { ascending: true });

    res.json({ success: true, data: { ...post, comments: comments || [] }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching board post:', err);
    res.status(500).json({ error: 'Failed to fetch post', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 게시글 작성 (로그인 필요, 공지사항은 관리자만)
app.post('/api/boards', authenticate, async (req, res) => {
  try {
    const { board_type, title, content } = req.body;
    if (!board_type || !BOARD_TYPES.includes(board_type)) {
      return res.status(400).json({ error: 'Bad Request', message: `board_type must be one of: ${BOARD_TYPES.join(', ')}`, timestamp: new Date().toISOString() });
    }
    if (!title || !content) {
      return res.status(400).json({ error: 'Bad Request', message: 'Required fields: title, content', timestamp: new Date().toISOString() });
    }

    if (board_type === 'notice') {
      const { data: profile } = await supabase.from('profiles').select('role').eq('id', req.user.id).single();
      if (!profile || !isAdminRole(profile.role)) {
        return res.status(403).json({ error: 'Forbidden', message: '공지사항은 관리자만 작성할 수 있습니다', timestamp: new Date().toISOString() });
      }
    }

    const { data: profile } = await supabase.from('profiles').select('email, full_name').eq('id', req.user.id).single();
    const authorName = profile?.full_name || profile?.email || req.user.email || '회원';

    const { data, error } = await supabase
      .from('board_posts')
      .insert([{ board_type, title, content, author_id: req.user.id, author_name: authorName, status: 'published' }])
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({ success: true, data, message: 'Post created successfully', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating board post:', err);
    res.status(500).json({ error: 'Failed to create post', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 게시글 수정 (작성자 본인 또는 관리자)
app.put('/api/boards/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content } = req.body;

    const { data: existing, error: findErr } = await supabase.from('board_posts').select('id, author_id').eq('id', id).single();
    if (findErr || !existing) {
      return res.status(404).json({ error: 'Not Found', message: 'Post not found', timestamp: new Date().toISOString() });
    }

    const { data: profile } = await supabase.from('profiles').select('role').eq('id', req.user.id).single();
    const isOwnerOrAdmin = existing.author_id === req.user.id || isAdminRole(profile?.role);
    if (!isOwnerOrAdmin) {
      return res.status(403).json({ error: 'Forbidden', message: '본인 게시글만 수정할 수 있습니다', timestamp: new Date().toISOString() });
    }

    const updates = { updated_at: new Date().toISOString() };
    if (title !== undefined) updates.title = title;
    if (content !== undefined) updates.content = content;

    const { data, error } = await supabase.from('board_posts').update(updates).eq('id', id).select().single();
    if (error) throw error;

    res.json({ success: true, data, message: 'Post updated successfully', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating board post:', err);
    res.status(500).json({ error: 'Failed to update post', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 게시글 삭제 (작성자 본인 또는 관리자)
app.delete('/api/boards/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: existing, error: findErr } = await supabase.from('board_posts').select('id, author_id').eq('id', id).single();
    if (findErr || !existing) {
      return res.status(404).json({ error: 'Not Found', message: 'Post not found', timestamp: new Date().toISOString() });
    }

    const { data: profile } = await supabase.from('profiles').select('role').eq('id', req.user.id).single();
    const isOwnerOrAdmin = existing.author_id === req.user.id || isAdminRole(profile?.role);
    if (!isOwnerOrAdmin) {
      return res.status(403).json({ error: 'Forbidden', message: '본인 게시글만 삭제할 수 있습니다', timestamp: new Date().toISOString() });
    }

    const { error } = await supabase.from('board_posts').delete().eq('id', id);
    if (error) throw error;

    res.json({ success: true, message: 'Post deleted successfully', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting board post:', err);
    res.status(500).json({ error: 'Failed to delete post', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 댓글 작성 (로그인 필요, Q&A 답변 등. 관리자가 작성하면 is_admin_reply=true로 자동 표시)
app.post('/api/boards/:id/comments', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;
    if (!content) {
      return res.status(400).json({ error: 'Bad Request', message: 'Required field: content', timestamp: new Date().toISOString() });
    }

    const { data: post } = await supabase.from('board_posts').select('id, board_type').eq('id', id).single();
    if (!post) {
      return res.status(404).json({ error: 'Not Found', message: 'Post not found', timestamp: new Date().toISOString() });
    }

    const { data: profile } = await supabase.from('profiles').select('role, email, full_name').eq('id', req.user.id).single();
    const isAdminReply = isAdminRole(profile?.role);
    const authorName = profile?.full_name || profile?.email || req.user.email || '회원';

    const { data, error } = await supabase
      .from('board_comments')
      .insert([{ post_id: id, author_id: req.user.id, author_name: authorName, content, is_admin_reply: isAdminReply }])
      .select()
      .single();
    if (error) throw error;

    if (isAdminReply && post.board_type === 'qa') {
      await supabase.from('board_posts').update({ is_answered: true }).eq('id', id);
    }

    res.status(201).json({ success: true, data, message: 'Comment created successfully', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating comment:', err);
    res.status(500).json({ error: 'Failed to create comment', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 댓글 삭제 (작성자 본인 또는 관리자)
app.delete('/api/boards/:postId/comments/:commentId', authenticate, async (req, res) => {
  try {
    const { commentId } = req.params;
    const { data: existing } = await supabase.from('board_comments').select('id, author_id').eq('id', commentId).single();
    if (!existing) {
      return res.status(404).json({ error: 'Not Found', message: 'Comment not found', timestamp: new Date().toISOString() });
    }

    const { data: profile } = await supabase.from('profiles').select('role').eq('id', req.user.id).single();
    const isOwnerOrAdmin = existing.author_id === req.user.id || isAdminRole(profile?.role);
    if (!isOwnerOrAdmin) {
      return res.status(403).json({ error: 'Forbidden', message: '본인 댓글만 삭제할 수 있습니다', timestamp: new Date().toISOString() });
    }

    const { error } = await supabase.from('board_comments').delete().eq('id', commentId);
    if (error) throw error;

    res.json({ success: true, message: 'Comment deleted successfully', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting comment:', err);
    res.status(500).json({ error: 'Failed to delete comment', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자용 게시글 목록 (hidden 포함 전체, 상태/타입 필터)
app.get('/api/admin/boards', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    let query = supabase.from('board_posts').select('*').order('created_at', { ascending: false });
    if (req.query.type) query = query.eq('board_type', req.query.type);
    if (req.query.status) query = query.eq('status', req.query.status);
    if (req.query.answered !== undefined) query = query.eq('is_answered', req.query.answered === 'true');

    const { data, error } = await query;
    if (error) throw error;

    res.json({ success: true, data: data || [], count: data?.length || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin boards:', err);
    res.status(500).json({ error: 'Failed to fetch boards', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자용 게시글 상태 변경 (숨김 처리/고정)
app.patch('/api/admin/boards/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status, is_pinned } = req.body;

    const updates = {};
    if (status !== undefined) {
      if (!['published', 'hidden'].includes(status)) {
        return res.status(400).json({ error: 'Bad Request', message: 'status must be published or hidden', timestamp: new Date().toISOString() });
      }
      updates.status = status;
    }
    if (is_pinned !== undefined) updates.is_pinned = !!is_pinned;

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'status 또는 is_pinned 중 최소 하나는 필요합니다', timestamp: new Date().toISOString() });
    }

    const { data, error } = await supabase.from('board_posts').update(updates).eq('id', id).select().single();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: 'Post not found', timestamp: new Date().toISOString() });

    res.json({ success: true, data, message: 'Post updated successfully', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating admin board post:', err);
    res.status(500).json({ error: 'Failed to update post', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 회원 관리 API (관리자 전용, 읽기 전용)
// profiles 는 GMWOS 와 공유하는 테이블이므로 WITH+ 운영에 필요한 안전한 필드만 선택하고
// 절대 쓰기(수정)는 하지 않음. 민감 정보(주민번호/복지등급/국적 등)는 조회 대상에서 제외.
// ============================================
app.get('/api/admin/members', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { search } = req.query;
    let query = supabase
      .from('profiles')
      .select('id, email, full_name, phone, role, is_active, created_at')
      .order('created_at', { ascending: false })
      .limit(300);

    if (search) query = query.or(`email.ilike.%${search}%,full_name.ilike.%${search}%`);

    const { data: members, error } = await query;
    if (error) throw error;

    const memberIds = (members || []).map(m => m.id);
    let orderStatsByUser = {};
    if (memberIds.length > 0) {
      const { data: orders } = await supabase
        .from('orders_with')
        .select('user_id, final_price, personal_earned_points, community_earned_points')
        .in('user_id', memberIds);
      (orders || []).forEach(o => {
        if (!orderStatsByUser[o.user_id]) orderStatsByUser[o.user_id] = { orderCount: 0, totalSpent: 0, totalMileage: 0 };
        orderStatsByUser[o.user_id].orderCount += 1;
        orderStatsByUser[o.user_id].totalSpent += Number(o.final_price || 0);
        orderStatsByUser[o.user_id].totalMileage += Number(o.personal_earned_points || 0) + Number(o.community_earned_points || 0);
      });
    }

    const result = (members || []).map(m => ({
      ...m,
      orderCount: orderStatsByUser[m.id]?.orderCount || 0,
      totalSpent: orderStatsByUser[m.id]?.totalSpent || 0,
      totalMileage: orderStatsByUser[m.id]?.totalMileage || 0
    }));

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin members:', err);
    res.status(500).json({ error: 'Failed to fetch members', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 회원 상세 (본인 주문 내역 포함, 관리자 전용, 읽기 전용)
app.get('/api/admin/members/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { data: member, error } = await supabase
      .from('profiles')
      .select('id, email, full_name, phone, role, is_active, created_at')
      .eq('id', id)
      .single();
    if (error || !member) {
      return res.status(404).json({ error: 'Not Found', message: 'Member not found', timestamp: new Date().toISOString() });
    }

    const { data: orders } = await supabase
      .from('orders_with')
      .select('id, order_number, status, final_price, personal_earned_points, community_earned_points, created_at')
      .eq('user_id', id)
      .order('created_at', { ascending: false });

    res.json({ success: true, data: { ...member, orders: orders || [] }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching member detail:', err);
    res.status(500).json({ error: 'Failed to fetch member', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 회원 role 변경 (최고관리자 전용) - 플랫폼 관리자(admin)를 지정/해제하는 용도
// WITH+에서 의미있는 역할만 대상으로 한다: member / provider / admin
// - super_admin 계정끼리는 서로 건드릴 수 없음(실수로 잠기는 것 방지, 최고관리자 변경은 DB에서 직접)
// - GMWOS 쪽에서 쓰는 role(super_admin 외 finance_manager 등)은 WITH+ 관리자 페이지에서 다루지 않음
app.patch('/api/admin/members/:id/role', authenticate, requireRole(['super_admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;
    const ALLOWED_ROLES = ['member', 'provider', 'admin'];

    if (!ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({ error: 'Bad Request', message: `role은 ${ALLOWED_ROLES.join('/')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
    }
    if (id === req.user.id) {
      return res.status(400).json({ error: 'Bad Request', message: '본인 계정의 권한은 이 화면에서 변경할 수 없습니다', timestamp: new Date().toISOString() });
    }

    const { data: target, error: findErr } = await supabase
      .from('profiles')
      .select('id, email, role')
      .eq('id', id)
      .single();
    if (findErr || !target) {
      return res.status(404).json({ error: 'Not Found', message: 'Member not found', timestamp: new Date().toISOString() });
    }
    if (target.role === 'super_admin') {
      return res.status(403).json({ error: 'Forbidden', message: '최고관리자 계정의 권한은 이 화면에서 변경할 수 없습니다', timestamp: new Date().toISOString() });
    }
    if (!['member', 'provider', 'admin'].includes(target.role)) {
      return res.status(403).json({ error: 'Forbidden', message: '해당 계정의 권한은 WITH+ 관리자 페이지에서 변경할 수 없습니다', timestamp: new Date().toISOString() });
    }

    const { data, error } = await supabase
      .from('profiles')
      .update({ role })
      .eq('id', id)
      .select('id, email, full_name, phone, role, is_active, created_at')
      .single();
    if (error) throw error;

    // 공유 profiles 테이블의 민감한 컬럼(role)을 변경하는 작업이므로, GMWOS 쪽에서도 추적할 수 있도록 감사 로그를 남긴다.
    // (WITH+가 GMWOS의 권한 판단 로직을 직접 알 수 없어 role 값 자체를 신뢰성 있게 검증할 수는 없지만,
    //  누가/언제/무엇을 바꿨는지는 남겨두어 문제 발생 시 추적 가능하게 한다)
    try {
      await supabase.from('admin_actions').insert([{
        actor_id: req.user.id,
        action: 'withplus_member_role_change',
        target_type: 'profile',
        target_id: id,
        meta: { from_role: target.role, to_role: role, target_email: target.email }
      }]);
    } catch (logErr) {
      console.error('admin_actions 로그 기록 실패 (권한 변경 자체는 정상 처리됨):', logErr.message);
    }

    res.json({ success: true, data, message: `${target.email}님의 권한이 ${role}(으)로 변경되었습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating member role:', err);
    res.status(500).json({ error: 'Failed to update member role', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 관리자 대시보드 통계 API (관리자 전용)
// ============================================
app.get('/api/admin/dashboard', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const [
      { data: allOrders },
      { count: memberCount },
      { count: productCount },
      { count: pendingQaCount },
      { data: recentOrdersRaw }
    ] = await Promise.all([
      supabase.from('orders_with').select('status, final_price, personal_earned_points, community_earned_points, items, created_at'),
      supabase.from('profiles').select('*', { count: 'exact', head: true }),
      supabase.from('products_with').select('*', { count: 'exact', head: true }).eq('status', 'active'),
      supabase.from('board_posts').select('*', { count: 'exact', head: true }).eq('board_type', 'qa').eq('is_answered', false),
      supabase.from('orders_with').select('id, order_number, final_price, status, created_at').order('created_at', { ascending: false }).limit(5)
    ]);

    const orders = allOrders || [];
    const totalSales = orders.filter(o => o.status !== 'cancelled' && o.status !== 'refunded').reduce((s, o) => s + Number(o.final_price || 0), 0);
    const totalMileagePaid = orders.reduce((s, o) => s + Number(o.personal_earned_points || 0) + Number(o.community_earned_points || 0), 0);
    const statusBreakdown = {};
    orders.forEach(o => { statusBreakdown[o.status] = (statusBreakdown[o.status] || 0) + 1; });

    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const ordersThisWeek = orders.filter(o => o.created_at >= oneWeekAgo).length;

    // 카테고리별 판매량 (주문 items의 product_id로는 카테고리를 알 수 없으므로 이름 기준 집계로 단순화)
    const categorySales = {};
    orders.forEach(o => {
      (Array.isArray(o.items) ? o.items : []).forEach(item => {
        const key = item.name || '기타';
        categorySales[key] = (categorySales[key] || 0) + (Number(item.quantity) || 0);
      });
    });
    const topSellingItems = Object.entries(categorySales)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, qty]) => ({ name, qty }));

    res.json({
      success: true,
      data: {
        totalSales,
        totalOrders: orders.length,
        totalMembers: memberCount || 0,
        totalProducts: productCount || 0,
        totalMileagePaid,
        ordersThisWeek,
        pendingQaCount: pendingQaCount || 0,
        statusBreakdown,
        topSellingItems,
        recentOrders: recentOrdersRaw || []
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching admin dashboard:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 공급사별 판매 리포트 (관리자: 전체 공급사 / 판매자(provider): 본인 데이터만)
// 여기서 "공급사"는 플랫폼에 로그인해 상품을 등록하는 판매자 계정(provider role,
// products_with.supplier_id)을 뜻한다 — 위의 /api/admin/suppliers(거래처 마스터데이터)와는 다른 개념.
// 주문에 실제 상품 라인아이템 테이블이 없어(orders_with.items가 JSON 배열) 서버에서 직접 집계한다.
// ============================================
// products_with.supplier_id는 "누가 이 상품을 등록했는가"를 가리킬 뿐, 그 계정이 실제 공급자(provider role)인지
// 아니면 관리자가 쇼핑몰 자체 재고로 직접 등록한 것인지는 구분해주지 않는다. 공급자 정산/판매리포트는
// 반드시 role='provider'인 계정만 대상으로 삼아야 한다 — 그렇지 않으면 쇼핑몰이 직접 파는 자체재고 상품의 매출까지
// "공급자 매출"로 잡혀서 존재하지도 않는 제3자에게 수수료를 떼어주는 것처럼 정산이 생성되는 문제가 생긴다.
async function getProviderIdSet() {
  const { data, error } = await supabase.from('profiles').select('id').eq('role', 'provider');
  if (error) throw error;
  return new Set((data || []).map(p => p.id));
}

app.get('/api/admin/supplier-sales-report', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;

    let ordersQuery = supabase
      .from('orders_with')
      .select('id, items, status, final_price, created_at')
      .not('status', 'in', '(cancelled,refunded)');
    if (startDate) ordersQuery = ordersQuery.gte('created_at', startDate);
    if (endDate) {
      // endDate는 날짜만 넘어올 수 있으므로(예: 2026-08-12) 그 날 끝까지 포함되도록 다음날 자정 미만으로 처리
      const endExclusive = /^\d{4}-\d{2}-\d{2}$/.test(endDate)
        ? new Date(new Date(endDate + 'T00:00:00Z').getTime() + 24 * 60 * 60 * 1000).toISOString()
        : endDate;
      ordersQuery = ordersQuery.lt('created_at', endExclusive);
    }

    const [{ data: orders, error: ordersErr }, { data: allProducts, error: prodErr }, providerIds] = await Promise.all([
      ordersQuery,
      supabase.from('products_with').select('id, supplier_id, name'),
      getProviderIdSet()
    ]);
    if (ordersErr) throw ordersErr;
    if (prodErr) throw prodErr;

    // role='provider'인 계정 소유 상품만 "공급자 상품"으로 집계한다. 관리자가 직접 등록한 자체재고 상품은
    // 여기서 제외되어(=쇼핑몰 자체 매출이라 별도 통계는 관리자 통계 탭에서 확인), 공급자 리포트를 왜곡하지 않는다.
    const productSupplierMap = {};
    (allProducts || []).forEach(p => { if (p.supplier_id && providerIds.has(p.supplier_id)) productSupplierMap[String(p.id)] = p.supplier_id; });

    const onlyOwnSupplierId = isAdminRole(req.userRole) ? null : req.user.id;

    // supplierId -> { revenue, quantity, orderIds: Set }
    const agg = {};
    (orders || []).forEach(o => {
      const items = Array.isArray(o.items) ? o.items : [];
      items.forEach(item => {
        const supplierId = productSupplierMap[String(item.product_id)];
        if (!supplierId) return; // 삭제된 상품 등 공급자를 알 수 없는 라인아이템은 집계에서 제외
        if (onlyOwnSupplierId && supplierId !== onlyOwnSupplierId) return;
        if (!agg[supplierId]) agg[supplierId] = { revenue: 0, quantity: 0, orderIds: new Set() };
        agg[supplierId].revenue += Number(item.price || 0) * Number(item.quantity || 1);
        agg[supplierId].quantity += Number(item.quantity || 1);
        agg[supplierId].orderIds.add(o.id);
      });
    });

    const supplierIds = Object.keys(agg);
    const { data: supplierProfiles } = supplierIds.length
      ? await supabase.from('profiles').select('id, full_name, email').in('id', supplierIds)
      : { data: [] };

    const rows = supplierIds.map(supplierId => {
      const profile = (supplierProfiles || []).find(p => p.id === supplierId);
      return {
        supplier_id: supplierId,
        supplier_name: profile?.full_name || null,
        supplier_email: profile?.email || null,
        revenue: agg[supplierId].revenue,
        quantity: agg[supplierId].quantity,
        order_count: agg[supplierId].orderIds.size
      };
    }).sort((a, b) => b.revenue - a.revenue);

    const totalRevenue = rows.reduce((s, r) => s + r.revenue, 0);
    const totalQuantity = rows.reduce((s, r) => s + r.quantity, 0);

    res.json({
      success: true,
      data: {
        rows,
        totalRevenue,
        totalQuantity,
        startDate: startDate || null,
        endDate: endDate || null
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching supplier sales report:', err);
    res.status(500).json({ error: 'Failed to fetch supplier sales report', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 공급자(판매자, provider role) 정산 시스템 기본 골격
// - "공급자"는 위 suppliers 마스터 데이터(매입처)와는 다른 개념으로, 플랫폼에 상품을 등록해 파는
//   provider role 계정(products_with.supplier_id = profiles.id)을 말한다. 위 supplier-sales-report가
//   보여주는 매출을 바탕으로, 관리자가 수수료율을 적용해 기간별 정산 내역을 생성/관리한다.
// ============================================

// 특정 기간의 공급자별(provider) 매출 집계 - settlements 생성 시 재사용
async function computeProviderRevenueForPeriod(startDate, endDate) {
  let ordersQuery = supabase
    .from('orders_with')
    .select('id, items, status, created_at')
    .not('status', 'in', '(cancelled,refunded)');
  if (startDate) ordersQuery = ordersQuery.gte('created_at', startDate);
  if (endDate) {
    const endExclusive = /^\d{4}-\d{2}-\d{2}$/.test(endDate)
      ? new Date(new Date(endDate + 'T00:00:00Z').getTime() + 24 * 60 * 60 * 1000).toISOString()
      : endDate;
    ordersQuery = ordersQuery.lt('created_at', endExclusive);
  }

  const [{ data: orders, error: ordersErr }, { data: allProducts, error: prodErr }, providerIds] = await Promise.all([
    ordersQuery,
    supabase.from('products_with').select('id, supplier_id'),
    getProviderIdSet()
  ]);
  if (ordersErr) throw ordersErr;
  if (prodErr) throw prodErr;

  // role='provider'인 계정 소유 상품만 정산 대상. 관리자가 직접 등록한 자체재고 상품은 제외(자체 매출이라 정산/수수료 대상이 아님).
  const productSupplierMap = {};
  (allProducts || []).forEach(p => { if (p.supplier_id && providerIds.has(p.supplier_id)) productSupplierMap[String(p.id)] = p.supplier_id; });

  const agg = {}; // supplierId -> { revenue, orderIds: Set }
  (orders || []).forEach(o => {
    const items = Array.isArray(o.items) ? o.items : [];
    const touchedSuppliers = new Set();
    items.forEach(item => {
      const supplierId = productSupplierMap[String(item.product_id)];
      if (!supplierId) return; // 삭제된 상품 등 공급자를 알 수 없는 라인아이템은 집계에서 제외
      if (!agg[supplierId]) agg[supplierId] = { revenue: 0, orderIds: new Set() };
      agg[supplierId].revenue += Number(item.price || 0) * Number(item.quantity || 1);
      touchedSuppliers.add(supplierId);
    });
    touchedSuppliers.forEach(supplierId => agg[supplierId].orderIds.add(o.id));
  });

  return agg;
}

// ============================================
// 🧾 정산 세무처리(원천징수 3.3% / 세금계산서 발행) - 공급자·분양조직 정산 공용
// - "정산 지급완료" 처리와 직접 연결된 세무 의무: 개인/프리랜서 사업자에게 사업소득을 지급할 때는
//   소득세 3% + 지방소득세 0.3% = 3.3%를 원천징수하고 원천징수영수증을 발급해야 하고,
//   법인/일반과세 사업자에게 지급할 때는 세금계산서를 발행(수취)해야 한다.
// - 실제 세금계산서 "자동 발행"은 홈택스/팝빌 등 외부 연동(공동인증서+API 계약)이 필요해 이 환경에는 연결돼
//   있지 않으므로, 상태를 "발행대기"로 만들어두고 관리자가 외부에서 발행한 뒤 문서번호를 수동으로 입력하면
//   "발행완료"로 전환하는 방식으로 동작한다 (사업자번호 검증에서 NTS_API_KEY가 없을 때 형식검증까지만
//   자동 수행하고 나머지는 관리자 확인에 맡기는 것과 동일한 패턴).
// ============================================

const SETTLEMENT_TAX_METHODS = ['withholding', 'tax_invoice', 'none'];
const WITHHOLDING_TAX_RATE = 3.3; // 사업소득 원천징수: 소득세 3% + 지방소득세 0.3%

function computeSettlementTaxFields(commissionAmount, taxMethod) {
  const method = SETTLEMENT_TAX_METHODS.includes(taxMethod) ? taxMethod : 'withholding';
  const amount = Number(commissionAmount || 0);
  if (method === 'withholding') {
    const withholdingTaxAmount = Math.round(amount * WITHHOLDING_TAX_RATE / 100);
    return {
      tax_method: method,
      withholding_tax_rate: WITHHOLDING_TAX_RATE,
      withholding_tax_amount: withholdingTaxAmount,
      net_payment_amount: amount - withholdingTaxAmount,
      tax_invoice_status: 'not_required'
    };
  }
  if (method === 'tax_invoice') {
    return { tax_method: method, withholding_tax_rate: 0, withholding_tax_amount: 0, net_payment_amount: amount, tax_invoice_status: 'pending' };
  }
  // 'none' - 해당없음(세무처리 대상이 아닌 특수 케이스)
  return { tax_method: method, withholding_tax_rate: 0, withholding_tax_amount: 0, net_payment_amount: amount, tax_invoice_status: 'not_required' };
}

// 원천징수영수증 + 공개 페이지(하단 사업자정보 푸터, 이용약관/개인정보처리방침의 사업자정보 표)에 표시할
// "원천징수의무자"/"사업자정보" 겸용 플랫폼(WITH+ 본사) 정보 - platform_settings(key='platform_business_info')에서 관리자가 직접 입력·관리
// 오래된 행(신규 필드 도입 이전에 저장된 값)에도 항상 모든 키가 존재하도록 여기서 빈 문자열로 채워 내려준다(undefined 방지)
const PLATFORM_BUSINESS_INFO_DEFAULTS = {
  company_name: '',
  ceo_name: '',
  business_number: '',
  address: '',
  mail_order_registration_number: '',
  phone: '',
  email: '',
  privacy_officer_name: '',
  privacy_officer_position: '',
  privacy_officer_contact: ''
};
async function getPlatformBusinessInfo() {
  const { data } = await supabase.from('platform_settings').select('value').eq('key', 'platform_business_info').maybeSingle();
  const stored = (data && data.value) ? data.value : {};
  const info = { ...PLATFORM_BUSINESS_INFO_DEFAULTS };
  Object.keys(PLATFORM_BUSINESS_INFO_DEFAULTS).forEach(k => {
    if (stored[k] !== undefined && stored[k] !== null) info[k] = stored[k];
  });
  return info;
}

// 플랫폼(WITH+ 본사) 사업자 정보 조회 - 원천징수영수증의 "원천징수의무자" 란 + 관리자 설정 화면 표시용
app.get('/api/admin/settings/business-info', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const info = await getPlatformBusinessInfo();
    res.json({ success: true, data: info, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching platform business info:', err);
    res.status(500).json({ error: 'Failed to fetch business info', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/admin/settings/business-info', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { company_name, ceo_name, business_number, address, mail_order_registration_number, phone, email, privacy_officer_name, privacy_officer_position, privacy_officer_contact } = req.body || {};
    const value = {
      company_name: company_name ? String(company_name).trim() : null,
      ceo_name: ceo_name ? String(ceo_name).trim() : null,
      business_number: business_number ? String(business_number).trim() : null,
      address: address ? String(address).trim() : null,
      mail_order_registration_number: mail_order_registration_number ? String(mail_order_registration_number).trim() : null,
      phone: phone ? String(phone).trim() : null,
      email: email ? String(email).trim() : null,
      privacy_officer_name: privacy_officer_name ? String(privacy_officer_name).trim() : null,
      privacy_officer_position: privacy_officer_position ? String(privacy_officer_position).trim() : null,
      privacy_officer_contact: privacy_officer_contact ? String(privacy_officer_contact).trim() : null
    };
    const { error } = await supabase.from('platform_settings').upsert({ key: 'platform_business_info', value }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true, data: value, message: '사업자 정보가 저장되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error saving platform business info:', err);
    res.status(500).json({ error: 'Failed to save business info', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 플랫폼(WITH+ 본사) 사업자 정보 - 공개 조회(인증 불필요). index/about/terms/privacy 등 공개 페이지 하단에
// 법적으로 표시해야 하는 상호/대표자/사업자등록번호/통신판매업신고번호/주소/연락처/개인정보보호책임자를
// 관리자가 입력한 값 그대로 내려준다(민감정보가 아니라 별도 필터링 없이 getPlatformBusinessInfo()를 그대로 재사용).
app.get('/api/public/business-info', async (req, res) => {
  try {
    const info = await getPlatformBusinessInfo();
    res.json({ success: true, data: info, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching public business info:', err);
    res.status(500).json({ error: 'Failed to fetch business info', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공급자(provider) 목록 + 현재 수수료율 조회 (정산 화면용)
// 공급자별 수수료율이 응답에 그대로 노출되므로(마진율과 같은 급의 민감정보) requireOwnerStepUpOrBootstrap로
// 대표자 전용 조회로 제한한다 - "🏢 분양 조직 관리"/"💵 분양조직 정산"의 GET과 동일한 판단.
app.get('/api/admin/providers', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUpOrBootstrap, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select('id, full_name, email, commission_rate, settlement_tax_method, is_active, created_at')
      .eq('role', 'provider')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], count: data?.length || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching providers:', err);
    res.status(500).json({ error: 'Failed to fetch providers', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공급자별 수수료율 설정 - requireOwnerStepUp 필수 (수수료율도 마진율과 같은 급의 민감정보)
app.patch('/api/admin/providers/:id/commission-rate', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUp, async (req, res) => {
  try {
    const { id } = req.params;
    const rate = Number(req.body?.commission_rate);
    if (!Number.isFinite(rate) || rate < 0 || rate > 100) {
      return res.status(400).json({ error: 'Bad Request', message: 'commission_rate는 0~100 사이의 숫자여야 합니다', timestamp: new Date().toISOString() });
    }
    const { data: target, error: targetErr } = await supabase.from('profiles').select('id, role').eq('id', id).maybeSingle();
    if (targetErr) throw targetErr;
    if (!target || target.role !== 'provider') {
      return res.status(404).json({ error: 'Not Found', message: '공급자(provider) 계정을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    const updates = { commission_rate: rate };
    // 정산 지급 시 세무처리 방식(원천징수 3.3% / 세금계산서 발행 / 해당없음) - 지급완료 처리 시점에 이 값을 스냅샷으로 사용한다
    if (req.body?.settlement_tax_method !== undefined) {
      if (!SETTLEMENT_TAX_METHODS.includes(req.body.settlement_tax_method)) {
        return res.status(400).json({ error: 'Bad Request', message: `settlement_tax_method는 ${SETTLEMENT_TAX_METHODS.join(', ')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
      }
      updates.settlement_tax_method = req.body.settlement_tax_method;
    }
    const { data, error } = await supabase.from('profiles').update(updates).eq('id', id).select('id, full_name, commission_rate, settlement_tax_method').single();
    if (error) throw error;
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating commission rate:', err);
    res.status(500).json({ error: 'Failed to update commission rate', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 기간을 지정해 공급자별 정산 내역 생성(또는 재계산). 이미 'paid' 상태인 건은 건드리지 않는다.
app.post('/api/admin/settlements/generate', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { startDate, endDate } = req.body || {};
    if (!startDate || !endDate) {
      return res.status(400).json({ error: 'Bad Request', message: 'startDate, endDate는 필수입니다 (예: 2026-08-01)', timestamp: new Date().toISOString() });
    }

    const agg = await computeProviderRevenueForPeriod(startDate, endDate);
    const supplierIds = Object.keys(agg);

    if (supplierIds.length === 0) {
      return res.json({ success: true, data: { created: 0, updated: 0, skippedPaid: 0, rows: [] }, timestamp: new Date().toISOString() });
    }

    const { data: providers, error: provErr } = await supabase
      .from('profiles').select('id, commission_rate').in('id', supplierIds);
    if (provErr) throw provErr;
    const rateMap = {};
    (providers || []).forEach(p => { rateMap[p.id] = Number(p.commission_rate) || 0; });

    const { data: existingRows, error: existErr } = await supabase
      .from('supplier_settlements')
      .select('id, supplier_id, status')
      .eq('period_start', startDate)
      .eq('period_end', endDate)
      .in('supplier_id', supplierIds);
    if (existErr) throw existErr;
    const existingBySupplier = {};
    (existingRows || []).forEach(r => { existingBySupplier[r.supplier_id] = r; });

    let created = 0, updated = 0, skippedPaid = 0;
    const resultRows = [];

    for (const supplierId of supplierIds) {
      const grossRevenue = agg[supplierId].revenue;
      const orderCount = agg[supplierId].orderIds.size;
      const commissionRate = rateMap[supplierId] != null ? rateMap[supplierId] : 10;
      const commissionAmount = Math.round(grossRevenue * commissionRate / 100);
      const netAmount = grossRevenue - commissionAmount;

      const existing = existingBySupplier[supplierId];
      if (existing && existing.status === 'paid') {
        skippedPaid++;
        continue;
      }

      if (existing) {
        const { data, error } = await supabase.from('supplier_settlements').update({
          order_count: orderCount, gross_revenue: grossRevenue, commission_rate: commissionRate,
          commission_amount: commissionAmount, net_amount: netAmount
        }).eq('id', existing.id).select().single();
        if (error) throw error;
        updated++;
        resultRows.push(data);
      } else {
        const { data, error } = await supabase.from('supplier_settlements').insert([{
          supplier_id: supplierId, period_start: startDate, period_end: endDate,
          order_count: orderCount, gross_revenue: grossRevenue, commission_rate: commissionRate,
          commission_amount: commissionAmount, net_amount: netAmount,
          status: 'pending', created_by: req.user.id
        }]).select().single();
        if (error) throw error;
        created++;
        resultRows.push(data);
      }
    }

    res.json({ success: true, data: { created, updated, skippedPaid, rows: resultRows }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error generating settlements:', err);
    res.status(500).json({ error: 'Failed to generate settlements', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 정산 내역 조회 (관리자는 전체, provider는 본인 것만)
app.get('/api/admin/settlements', authenticate, requireRole(['provider', 'admin', 'super_admin']), async (req, res) => {
  try {
    const { status, supplierId } = req.query;
    let query = supabase.from('supplier_settlements').select('*').order('period_start', { ascending: false });

    if (!isAdminRole(req.userRole)) {
      query = query.eq('supplier_id', req.user.id);
    } else if (supplierId) {
      query = query.eq('supplier_id', supplierId);
    }
    if (status) query = query.eq('status', status);

    const { data: rows, error } = await query;
    if (error) throw error;

    const supplierIds = [...new Set((rows || []).map(r => r.supplier_id))];
    const { data: supplierProfiles } = supplierIds.length
      ? await supabase.from('profiles').select('id, full_name, email').in('id', supplierIds)
      : { data: [] };
    const profileMap = {};
    (supplierProfiles || []).forEach(p => { profileMap[p.id] = p; });

    const result = (rows || []).map(r => ({
      ...r,
      supplier_name: profileMap[r.supplier_id]?.full_name || null,
      supplier_email: profileMap[r.supplier_id]?.email || null
    }));

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching settlements:', err);
    res.status(500).json({ error: 'Failed to fetch settlements', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 정산 상태 변경 (지급 완료 / 취소) - 관리자 전용
app.patch('/api/admin/settlements/:id/status', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body || {};
    if (!['pending', 'paid', 'cancelled'].includes(status)) {
      return res.status(400).json({ error: 'Bad Request', message: "status는 'pending', 'paid', 'cancelled' 중 하나여야 합니다", timestamp: new Date().toISOString() });
    }
    const update = { status };
    if (status === 'paid') {
      update.paid_at = new Date().toISOString();
      // 지급완료 시점에 공급자의 세무처리 방식을 스냅샷으로 반영: 원천징수 3.3% 자동계산 또는 세금계산서 발행대기 표시
      const { data: existing } = await supabase.from('supplier_settlements').select('supplier_id, commission_amount').eq('id', id).maybeSingle();
      if (existing) {
        const { data: supplierProfile } = await supabase.from('profiles').select('settlement_tax_method').eq('id', existing.supplier_id).maybeSingle();
        Object.assign(update, computeSettlementTaxFields(existing.commission_amount, supplierProfile?.settlement_tax_method));
      }
    } else {
      update.paid_at = null;
    }

    const { data, error } = await supabase.from('supplier_settlements').update(update).eq('id', id).select().single();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '정산 내역을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating settlement status:', err);
    res.status(500).json({ error: 'Failed to update settlement status', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 💵 분양조직(커뮤니티) 현금 정산 - 공급자 정산(supplier_settlements)과 동일한 구조를 분양조직에도 적용
// - "정산관리도 공급자별/분양조직관리자별/관리자별로 분리되어 언제든 확인 가능한가"라는 질문에서 시작.
//   기존에는 분양조직에는 매출/적립금을 보여주는 실시간 대시보드만 있고, 공급자처럼 기간별로
//   "정산 생성 → 지급대기 → 지급완료" 흐름을 갖는 실제 현금 정산 기능은 없었다. 이번에 새로 추가하되,
//   당장 필요 없을 수도 있어 관리자가 platform_settings(key='community_cash_settlement')로 언제든
//   켜고 끌 수 있게 했다 (기본값은 꺼짐 - 켜기 전까지는 기존처럼 마일리지 대시보드만 동작).
// ============================================

async function isCommunityCashSettlementEnabled() {
  const { data, error } = await supabase.from('platform_settings').select('value').eq('key', 'community_cash_settlement').maybeSingle();
  if (error || !data) return false;
  return !!(data.value && data.value.enabled);
}

// 기능 on/off 상태 조회 - 로그인한 사용자면 누구나(관리자 화면/분양조직 담당자 화면 모두 이 값으로 탭 노출 여부를 결정)
app.get('/api/community-cash-settlement/status', authenticate, async (req, res) => {
  try {
    const enabled = await isCommunityCashSettlementEnabled();
    res.json({ success: true, data: { enabled }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching community cash settlement status:', err);
    res.status(500).json({ error: 'Failed to fetch status', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 기능 on/off 전환 - 관리자 전용
app.patch('/api/admin/settings/community-cash-settlement', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const enabled = !!req.body?.enabled;
    const { error } = await supabase.from('platform_settings').upsert({ key: 'community_cash_settlement', value: { enabled } }, { onConflict: 'key' });
    if (error) throw error;
    res.json({ success: true, data: { enabled }, message: enabled ? '분양조직 현금 정산 기능을 켰습니다' : '분양조직 현금 정산 기능을 껐습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error toggling community cash settlement:', err);
    res.status(500).json({ error: 'Failed to toggle setting', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 특정 기간의 분양조직별 매출 집계 (orders_with.community_id 기준, 취소/환불 제외) - settlements 생성 시 재사용
async function computeCommunityRevenueForPeriod(startDate, endDate) {
  let ordersQuery = supabase
    .from('orders_with')
    .select('id, community_id, final_price, status, created_at')
    .not('community_id', 'is', null)
    .not('status', 'in', '(cancelled,refunded)');
  if (startDate) ordersQuery = ordersQuery.gte('created_at', startDate);
  if (endDate) {
    const endExclusive = /^\d{4}-\d{2}-\d{2}$/.test(endDate)
      ? new Date(new Date(endDate + 'T00:00:00Z').getTime() + 24 * 60 * 60 * 1000).toISOString()
      : endDate;
    ordersQuery = ordersQuery.lt('created_at', endExclusive);
  }
  const { data: orders, error } = await ordersQuery;
  if (error) throw error;

  const agg = {}; // communityId -> { revenue, orderCount }
  (orders || []).forEach(o => {
    if (!o.community_id) return;
    if (!agg[o.community_id]) agg[o.community_id] = { revenue: 0, orderCount: 0 };
    agg[o.community_id].revenue += Number(o.final_price || 0);
    agg[o.community_id].orderCount += 1;
  });
  return agg;
}

// 기간을 지정해 분양조직별 정산 내역 생성(또는 재계산). 이미 'paid' 상태인 건은 건드리지 않는다. 관리자 전용.
app.post('/api/admin/community-settlements/generate', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    if (!(await isCommunityCashSettlementEnabled())) {
      return res.status(403).json({ error: 'Forbidden', message: '분양조직 현금 정산 기능이 꺼져 있습니다. 먼저 "분양조직 정산" 화면에서 기능을 켜주세요.', timestamp: new Date().toISOString() });
    }
    const { startDate, endDate } = req.body || {};
    if (!startDate || !endDate) {
      return res.status(400).json({ error: 'Bad Request', message: 'startDate, endDate는 필수입니다 (예: 2026-08-01)', timestamp: new Date().toISOString() });
    }

    const agg = await computeCommunityRevenueForPeriod(startDate, endDate);
    const communityIds = Object.keys(agg);
    if (communityIds.length === 0) {
      return res.json({ success: true, data: { created: 0, updated: 0, skippedPaid: 0, skippedNoBusinessNumber: [], rows: [] }, timestamp: new Date().toISOString() });
    }

    const { data: communities, error: commErr } = await supabase
      .from('communities').select('id, name, settlement_commission_rate, business_number, business_number_verified, bank_name, bank_account, account_holder').in('id', communityIds);
    if (commErr) throw commErr;
    const rateMap = {};
    const bizVerifiedMap = {};
    const nameMap = {};
    const bankMap = {};
    (communities || []).forEach(c => {
      rateMap[c.id] = c.settlement_commission_rate != null ? Number(c.settlement_commission_rate) : 5; // 기본 5%
      bizVerifiedMap[c.id] = !!(c.business_number && c.business_number_verified);
      nameMap[c.id] = c.name;
      bankMap[c.id] = { bank_name: c.bank_name || null, bank_account: c.bank_account || null, account_holder: c.account_holder || null };
    });

    const { data: existingRows, error: existErr } = await supabase
      .from('community_settlements_with')
      .select('id, community_id, status')
      .eq('period_start', startDate)
      .eq('period_end', endDate)
      .in('community_id', communityIds);
    if (existErr) throw existErr;
    const existingByCommunity = {};
    (existingRows || []).forEach(r => { existingByCommunity[r.community_id] = r; });

    let created = 0, updated = 0, skippedPaid = 0;
    const skippedNoBusinessNumber = [];
    // 계좌 미등록 조직 - 사업자번호와 달리 정산 생성 자체를 막지는 않는다(매출 집계는 계좌 유무와 무관하게 필요한 기록이므로).
    // 다만 이 조직들은 계좌 정보가 없어 "지급완료 처리" 시점에 서버가 거부하므로, 관리자가 놓치지 않도록 여기서 별도로 안내한다.
    const skippedNoBankAccount = [];
    const resultRows = [];

    for (const communityId of communityIds) {
      // 사업자등록번호가 없거나 국세청 검증을 통과하지 못한 조직은 현금 정산 대상에서 제외한다
      // (개별 사업자가 아니면 본사가 현금으로 지급할 법적 근거가 없음) - "분양 조직 관리"에서 등록/검증 먼저 해야 한다
      if (!bizVerifiedMap[communityId]) {
        skippedNoBusinessNumber.push({ community_id: communityId, community_name: nameMap[communityId] || '(이름 없음)' });
        continue;
      }

      const bank = bankMap[communityId] || {};
      if (!bank.bank_account) {
        skippedNoBankAccount.push({ community_id: communityId, community_name: nameMap[communityId] || '(이름 없음)' });
      }

      const grossRevenue = agg[communityId].revenue;
      const orderCount = agg[communityId].orderCount;
      const commissionRate = rateMap[communityId] != null ? rateMap[communityId] : 5;
      const commissionAmount = Math.round(grossRevenue * commissionRate / 100);

      const existing = existingByCommunity[communityId];
      if (existing && existing.status === 'paid') {
        skippedPaid++;
        continue;
      }

      // 계좌 정보는 정산 건 생성/재계산 시점의 조직 정보를 스냅샷으로 같이 저장한다 - 이후 조직이 계좌를 바꿔도
      // 이미 생성된 과거 정산 기록의 송금 대상 계좌는 그대로 유지된다(재계산을 다시 돌리면 최신 계좌로 갱신됨).
      if (existing) {
        const { data, error } = await supabase.from('community_settlements_with').update({
          order_count: orderCount, gross_revenue: grossRevenue, commission_rate: commissionRate,
          commission_amount: commissionAmount, updated_at: new Date().toISOString(),
          bank_name: bank.bank_name, bank_account: bank.bank_account, account_holder: bank.account_holder
        }).eq('id', existing.id).select().single();
        if (error) throw error;
        updated++;
        resultRows.push(data);
      } else {
        const { data, error } = await supabase.from('community_settlements_with').insert([{
          community_id: communityId, period_start: startDate, period_end: endDate,
          order_count: orderCount, gross_revenue: grossRevenue, commission_rate: commissionRate,
          commission_amount: commissionAmount, status: 'pending', created_by: req.user.id,
          bank_name: bank.bank_name, bank_account: bank.bank_account, account_holder: bank.account_holder
        }]).select().single();
        if (error) throw error;
        created++;
        resultRows.push(data);
      }
    }

    res.json({ success: true, data: { created, updated, skippedPaid, skippedNoBusinessNumber, skippedNoBankAccount, rows: resultRows }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error generating community settlements:', err);
    res.status(500).json({ error: 'Failed to generate community settlements', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 정산 내역 조회 - 관리자는 전체(조직 필터 가능), 분양조직 담당자는 본인이 담당하는 조직 것만
app.get('/api/admin/community-settlements', authenticate, async (req, res) => {
  try {
    const { status, communityId } = req.query;
    let query = supabase.from('community_settlements_with').select('*').order('period_start', { ascending: false });

    // 이 엔드포인트는 requireRole을 쓰지 않고(관리자·분양조직 담당자 모두 호출 가능해야 하므로) authenticate만
    // 거치기 때문에 req.userRole이 채워지지 않는다(requireRole 미들웨어에서만 설정됨) - 직접 프로필을 조회한다.
    const { data: callerProfile } = await supabase.from('profiles').select('role').eq('id', req.user.id).maybeSingle();
    if (callerProfile && isAdminRole(callerProfile.role)) {
      // 관리자 화면("💵 분양조직 정산" 탭)에서 조회하는 경로는 전체 조직의 매출·수수료·은행계좌가 그대로
      // 노출되므로 대표자 전용으로 제한한다. requireRole 미들웨어로 걸 수 없는 이유는 바로 아래 else 분기
      // (분양조직 담당자 본인 조회, 이 검사와 무관)와 같은 엔드포인트를 공유하기 때문 - checkOwnerStepUp을
      // 관리자 분기 안에서만 직접 호출한다(requireOwnerStepUpOrBootstrap과 동일한 로직, 부트스트랩 예외 포함).
      const stepUpResult = await checkOwnerStepUp(req, { allowBootstrap: true });
      if (!stepUpResult.ok) {
        await logCostAudit({ profileId: req.user.id, action: 'step_up_denied', detail: { reason: stepUpResult.reason }, ip: getClientIp(req) });
        return res.status(stepUpResult.status).json({ error: 'Forbidden', message: stepUpResult.message, timestamp: new Date().toISOString() });
      }
      if (communityId) query = query.eq('community_id', communityId);
    } else {
      const myCommunity = await getMyManagedCommunity(req.user.id);
      if (!myCommunity) {
        return res.status(404).json({ error: 'Not Found', message: '담당하고 있는 분양 조직이 없습니다', timestamp: new Date().toISOString() });
      }
      query = query.eq('community_id', myCommunity.id);
    }
    if (status) query = query.eq('status', status);

    const { data: rows, error } = await query;
    if (error) throw error;

    const communityIds = [...new Set((rows || []).map(r => r.community_id))];
    const { data: communityRows } = communityIds.length
      ? await supabase.from('communities').select('id, name').in('id', communityIds)
      : { data: [] };
    const nameMap = {};
    (communityRows || []).forEach(c => { nameMap[c.id] = c.name; });

    const result = (rows || []).map(r => ({ ...r, community_name: nameMap[r.community_id] || null }));

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching community settlements:', err);
    res.status(500).json({ error: 'Failed to fetch community settlements', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 정산 상태 변경 (지급 완료 / 취소) - 관리자 전용
app.patch('/api/admin/community-settlements/:id/status', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status, payout_memo } = req.body || {};
    if (!['pending', 'paid', 'cancelled'].includes(status)) {
      return res.status(400).json({ error: 'Bad Request', message: "status는 'pending', 'paid', 'cancelled' 중 하나여야 합니다", timestamp: new Date().toISOString() });
    }
    const update = { status };
    // 관리자가 실제 송금(인터넷뱅킹 등)을 처리하면서 남기는 메모 (예: "국민은행 앱, 거래번호 12345") - 지급완료 처리가 아니어도 언제든 갱신 가능
    if (payout_memo !== undefined) update.payout_memo = payout_memo || null;
    if (status === 'paid') {
      update.paid_at = new Date().toISOString();
      const { data: existing } = await supabase.from('community_settlements_with').select('community_id, commission_amount, bank_account').eq('id', id).maybeSingle();
      if (!existing) {
        return res.status(404).json({ error: 'Not Found', message: '정산 내역을 찾을 수 없습니다', timestamp: new Date().toISOString() });
      }
      // 실제로 돈을 보낼 계좌 정보가 이 정산 건에 스냅샷되어 있지 않으면 지급완료 처리를 막는다 - 정산 생성 시점에 조직에 계좌가
      // 없었거나, 이후에야 계좌가 등록된 경우다. "분양 조직 관리"에서 계좌를 등록한 뒤 정산을 다시 생성(재계산)하면 반영된다.
      if (!existing.bank_account) {
        return res.status(400).json({ error: 'Bad Request', message: '이 정산 건에는 송금할 계좌 정보가 없습니다. 분양 조직 관리에서 계좌를 등록한 뒤, 해당 기간 정산을 다시 생성(재계산)하면 계좌 정보가 반영됩니다.', timestamp: new Date().toISOString() });
      }
      // 지급완료 시점에 분양조직의 세무처리 방식을 스냅샷으로 반영: 원천징수 3.3% 자동계산 또는 세금계산서 발행대기 표시
      const { data: community } = await supabase.from('communities').select('settlement_tax_method').eq('id', existing.community_id).maybeSingle();
      Object.assign(update, computeSettlementTaxFields(existing.commission_amount, community?.settlement_tax_method));
    } else {
      update.paid_at = null;
    }

    const { data, error } = await supabase.from('community_settlements_with').update(update).eq('id', id).select().single();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '정산 내역을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating community settlement status:', err);
    res.status(500).json({ error: 'Failed to update community settlement status', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 송금대상 CSV 다운로드 - "지급완료 처리" 전에 관리자가 은행 인터넷뱅킹의 "대량이체" 화면에 참고해서 직접 입력하거나
// 엑셀로 열어 확인하는 용도다. 은행마다 대량이체 양식이 달라 자동 업로드는 지원하지 않으며, 실제 송금은 관리자가 수행한다.
app.get('/api/admin/community-settlements/payout-csv', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { status, communityId, ids } = req.query;
    let query = supabase.from('community_settlements_with').select('*').order('period_start', { ascending: false });
    if (ids) {
      const idList = String(ids).split(',').map(s => s.trim()).filter(Boolean);
      if (idList.length === 0) {
        return res.status(400).json({ error: 'Bad Request', message: 'ids가 비어 있습니다', timestamp: new Date().toISOString() });
      }
      query = query.in('id', idList);
    } else {
      query = query.eq('status', status || 'pending');
      if (communityId) query = query.eq('community_id', communityId);
    }
    const { data: rows, error } = await query;
    if (error) throw error;

    const communityIds = [...new Set((rows || []).map(r => r.community_id))];
    const { data: communityRows } = communityIds.length
      ? await supabase.from('communities').select('id, name').in('id', communityIds)
      : { data: [] };
    const nameMap = {};
    (communityRows || []).forEach(c => { nameMap[c.id] = c.name; });
    const statusLabelMap = { pending: '정산대기', paid: '지급완료', cancelled: '취소' };

    const csvEscape = (v) => {
      const s = (v === null || v === undefined) ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const header = ['조직명', '은행명', '계좌번호', '예금주', '지급액', '정산시작일', '정산종료일', '상태'];
    const lines = [header.join(',')];
    (rows || []).forEach(r => {
      const amount = (r.net_payment_amount !== null && r.net_payment_amount !== undefined) ? r.net_payment_amount : r.commission_amount;
      lines.push([
        csvEscape(nameMap[r.community_id] || ''),
        csvEscape(r.bank_name || ''),
        csvEscape(r.bank_account || ''),
        csvEscape(r.account_holder || ''),
        csvEscape(amount),
        csvEscape(r.period_start),
        csvEscape(r.period_end),
        csvEscape(statusLabelMap[r.status] || r.status)
      ].join(','));
    });
    // 엑셀에서 한글이 깨지지 않도록 UTF-8 BOM을 CSV 맨 앞에 붙인다
    const csv = '\uFEFF' + lines.join('\r\n');

    const filename = `community-settlements-payout-${new Date().toISOString().slice(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (err) {
    console.error('Error generating community settlements payout CSV:', err);
    res.status(500).json({ error: 'Failed to generate payout CSV', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🎁 크리에이터 제휴 커미션(어필리에이트 라이브) - 매출견인기능 격차분석 2-8
// - 위 "분양조직 현금 정산"과 완전히 동일한 구조(추천코드/링크로 유입된 주문 귀속 -> 기간별 정산 생성 ->
//   지급대기 -> 지급완료)를 그대로 본떴다. 다만 이 항목은 보고서가 명시했듯 실제 크리에이터 섭외·계약·
//   세무처리 등 "코드 밖의" 운영 준비가 함께 필요한 항목이라, 여기서는 그 운영이 시작될 수 있도록
//   코드 레벨의 뼈대(추천코드 발급, 주문 귀속, 정산 계산/지급기록)까지만 완성해둔다 - 실제 대량 송금
//   자동화(위 오픈뱅킹/정산대행 연동)까지 확장할지는 운영 준비가 끝난 뒤 별도로 결정할 일이다.
// ============================================

// 크리에이터 목록 (수수료율 등 마진율급 민감정보 포함 - 대표자 스텝업 필요, provider 목록과 동일한 기준)
app.get('/api/admin/creators', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUpOrBootstrap, async (req, res) => {
  try {
    const { data, error } = await supabase.from('creators_with').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], count: data?.length || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching creators:', err);
    res.status(500).json({ error: 'Failed to fetch creators', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 크리에이터 등록 - 플랫폼 회원일 필요는 없다(user_id는 선택값). 실제 계약이 확정된 뒤 등록하는 것을 전제로 한다.
app.post('/api/admin/creators', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUpOrBootstrap, async (req, res) => {
  try {
    const { display_name, commission_rate, user_id, bank_name, bank_account, account_holder } = req.body || {};
    if (!display_name || !String(display_name).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: 'display_name은 필수입니다', timestamp: new Date().toISOString() });
    }
    let rate = 10;
    if (commission_rate !== undefined && commission_rate !== null && commission_rate !== '') {
      rate = Number(commission_rate);
      if (!Number.isFinite(rate) || rate < 0 || rate > 100) {
        return res.status(400).json({ error: 'Bad Request', message: 'commission_rate는 0~100 사이의 숫자여야 합니다', timestamp: new Date().toISOString() });
      }
    }
    const { data, error } = await supabase.from('creators_with').insert([{
      display_name: String(display_name).trim(), commission_rate: rate, user_id: user_id || null,
      bank_name: bank_name || null, bank_account: bank_account || null, account_holder: account_holder || null,
      created_by: req.user.id
    }]).select().single();
    if (error) throw error;
    res.status(201).json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating creator:', err);
    res.status(500).json({ error: 'Failed to create creator', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 크리에이터 정보 수정(수수료율/상태/세무처리방식/계좌) - provider 수수료율 변경과 동일하게 requireOwnerStepUp(부트스트랩 예외 없음) 필수
app.patch('/api/admin/creators/:id', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUp, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: existing } = await supabase.from('creators_with').select('id').eq('id', id).maybeSingle();
    if (!existing) return res.status(404).json({ error: 'Not Found', message: '크리에이터를 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const updates = {};
    if (req.body.display_name !== undefined) {
      if (!String(req.body.display_name).trim()) return res.status(400).json({ error: 'Bad Request', message: 'display_name은 비울 수 없습니다', timestamp: new Date().toISOString() });
      updates.display_name = String(req.body.display_name).trim();
    }
    if (req.body.commission_rate !== undefined) {
      const rate = Number(req.body.commission_rate);
      if (!Number.isFinite(rate) || rate < 0 || rate > 100) {
        return res.status(400).json({ error: 'Bad Request', message: 'commission_rate는 0~100 사이의 숫자여야 합니다', timestamp: new Date().toISOString() });
      }
      updates.commission_rate = rate;
    }
    if (req.body.status !== undefined) {
      if (!['active', 'inactive'].includes(req.body.status)) {
        return res.status(400).json({ error: 'Bad Request', message: "status는 'active' 또는 'inactive'여야 합니다", timestamp: new Date().toISOString() });
      }
      updates.status = req.body.status;
    }
    if (req.body.settlement_tax_method !== undefined) {
      if (!SETTLEMENT_TAX_METHODS.includes(req.body.settlement_tax_method)) {
        return res.status(400).json({ error: 'Bad Request', message: `settlement_tax_method는 ${SETTLEMENT_TAX_METHODS.join(', ')} 중 하나여야 합니다`, timestamp: new Date().toISOString() });
      }
      updates.settlement_tax_method = req.body.settlement_tax_method;
    }
    ['bank_name', 'bank_account', 'account_holder'].forEach(k => {
      if (req.body[k] !== undefined) updates[k] = req.body[k] || null;
    });

    const { data, error } = await supabase.from('creators_with').update(updates).eq('id', id).select().single();
    if (error) throw error;
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating creator:', err);
    res.status(500).json({ error: 'Failed to update creator', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 크리에이터 추천코드 발급 - 코드를 직접 지정하지 않으면 자동 생성(퀴즈 쿠폰 코드 생성과 동일한 비혼동 문자셋)
async function generateUniqueCreatorReferralCode() {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  for (let attempt = 0; attempt < 50; attempt++) {
    let suffix = '';
    for (let i = 0; i < 6; i++) suffix += charset[Math.floor(Math.random() * charset.length)];
    const code = `CR${suffix}`;
    const { data: existing } = await supabase.from('creator_referral_codes_with').select('id').eq('code', code).maybeSingle();
    if (!existing) return code;
  }
  return `CR${Date.now().toString(36).toUpperCase()}`;
}

app.post('/api/admin/creators/:id/referral-codes', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUpOrBootstrap, async (req, res) => {
  try {
    const { data: creator } = await supabase.from('creators_with').select('id').eq('id', req.params.id).maybeSingle();
    if (!creator) return res.status(404).json({ error: 'Not Found', message: '크리에이터를 찾을 수 없습니다', timestamp: new Date().toISOString() });

    let code = req.body?.code ? String(req.body.code).trim().toUpperCase() : null;
    if (code) {
      const { data: existing } = await supabase.from('creator_referral_codes_with').select('id').eq('code', code).maybeSingle();
      if (existing) return res.status(409).json({ error: 'Conflict', message: '이미 사용 중인 코드입니다', timestamp: new Date().toISOString() });
    } else {
      code = await generateUniqueCreatorReferralCode();
    }

    const { data, error } = await supabase.from('creator_referral_codes_with').insert([{
      creator_id: req.params.id, code, created_by: req.user.id
    }]).select().single();
    if (error) throw error;
    res.status(201).json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating creator referral code:', err);
    res.status(500).json({ error: 'Failed to create referral code', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/creators/:id/referral-codes', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUpOrBootstrap, async (req, res) => {
  try {
    const { data, error } = await supabase.from('creator_referral_codes_with')
      .select('*').eq('creator_id', req.params.id).order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], count: data?.length || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching creator referral codes:', err);
    res.status(500).json({ error: 'Failed to fetch referral codes', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 코드 활성/비활성 전환 - 삭제하지 않고 비활성화만 지원한다(이미 이 코드로 유입된 과거 주문 기록은 그대로 보존).
app.patch('/api/admin/creators/referral-codes/:codeId', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUpOrBootstrap, async (req, res) => {
  try {
    if (!['active', 'inactive'].includes(req.body?.status)) {
      return res.status(400).json({ error: 'Bad Request', message: "status는 'active' 또는 'inactive'여야 합니다", timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase.from('creator_referral_codes_with')
      .update({ status: req.body.status }).eq('id', req.params.codeId).select().single();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '추천코드를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating creator referral code:', err);
    res.status(500).json({ error: 'Failed to update referral code', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🏆 크리에이터(채널) 등급/랭킹 시스템 (경쟁사 기능 격차 백로그 3번) - 그립/아마존 "TOP 판매자" 배지와 동일한 컨셉.
// ============================================
// orders_with.channel_id 매출 집계를 기준으로 "전체 기간 누적 매출"로 등급(브론즈~플래티넘)을 매기고,
// "최근 30일 매출" TOP 3 채널에는 별도로 "이달의 TOP 판매자" 배지를 추가로 부여한다. 완전히 읽기 시점
// 집계(이 프로젝트의 "스케줄러 없이 읽는 시점에 처리" 원칙)이며, 짧은 캐시(5분)로 페이지뷰마다 전체
// 주문을 다시 스캔하지 않게 방어한다.
const DEFAULT_CHANNEL_TIER_THRESHOLDS = { silver: 3000000, gold: 10000000, platinum: 50000000 };
const CHANNEL_TIER_LABELS = { bronze: '브론즈', silver: '실버', gold: '골드', platinum: '플래티넘' };
const CHANNEL_TIER_EMOJIS = { bronze: '🥉', silver: '🥈', gold: '🥇', platinum: '💎' };
let channelRankingCache = null;
let channelRankingCacheAt = 0;
const CHANNEL_RANKING_CACHE_TTL_MS = 5 * 60 * 1000;

async function getChannelTierThresholds() {
  try {
    const { data } = await supabase.from('platform_settings').select('value').eq('key', 'channel_tier_thresholds').maybeSingle();
    const v = data && data.value && typeof data.value === 'object' ? data.value : {};
    return {
      silver: Number.isFinite(Number(v.silver)) ? Number(v.silver) : DEFAULT_CHANNEL_TIER_THRESHOLDS.silver,
      gold: Number.isFinite(Number(v.gold)) ? Number(v.gold) : DEFAULT_CHANNEL_TIER_THRESHOLDS.gold,
      platinum: Number.isFinite(Number(v.platinum)) ? Number(v.platinum) : DEFAULT_CHANNEL_TIER_THRESHOLDS.platinum
    };
  } catch (err) {
    console.error('Error fetching channel tier thresholds:', err);
    return DEFAULT_CHANNEL_TIER_THRESHOLDS;
  }
}

function tierForRevenue(revenue, thresholds) {
  if (revenue >= thresholds.platinum) return 'platinum';
  if (revenue >= thresholds.gold) return 'gold';
  if (revenue >= thresholds.silver) return 'silver';
  return 'bronze';
}

// 전체 채널의 (전체기간 누적매출, 최근30일 매출)을 한 번에 집계한다.
async function computeChannelRankings() {
  const now = Date.now();
  if (channelRankingCache && (now - channelRankingCacheAt) < CHANNEL_RANKING_CACHE_TTL_MS) {
    return channelRankingCache;
  }
  const thresholds = await getChannelTierThresholds();
  const { data: orders, error } = await supabase
    .from('orders_with')
    .select('channel_id, final_price, status, created_at')
    .not('channel_id', 'is', null)
    .not('status', 'in', '(cancelled,refunded)');
  if (error) throw error;

  const thirtyDaysAgoMs = now - 30 * 24 * 60 * 60 * 1000;
  const agg = {}; // channelId -> { allTimeRevenue, last30Revenue }
  (orders || []).forEach(o => {
    if (!o.channel_id) return;
    if (!agg[o.channel_id]) agg[o.channel_id] = { allTimeRevenue: 0, last30Revenue: 0 };
    const price = Number(o.final_price || 0);
    agg[o.channel_id].allTimeRevenue += price;
    if (new Date(o.created_at).getTime() >= thirtyDaysAgoMs) agg[o.channel_id].last30Revenue += price;
  });

  const rows = Object.keys(agg).map(channelId => ({
    channel_id: channelId,
    all_time_revenue: agg[channelId].allTimeRevenue,
    last_30d_revenue: agg[channelId].last30Revenue,
    tier: tierForRevenue(agg[channelId].allTimeRevenue, thresholds)
  }));
  rows.sort((a, b) => b.last_30d_revenue - a.last_30d_revenue);
  rows.forEach((r, i) => { r.top3_rank = (i < 3 && r.last_30d_revenue > 0) ? i + 1 : null; });

  const result = { thresholds, rows, computed_at: new Date().toISOString() };
  channelRankingCache = result;
  channelRankingCacheAt = now;
  return result;
}

async function getChannelRankInfo(channelId) {
  const { rows } = await computeChannelRankings();
  const row = rows.find(r => r.channel_id === channelId);
  if (!row) {
    return { tier: 'bronze', tier_label: CHANNEL_TIER_LABELS.bronze, tier_emoji: CHANNEL_TIER_EMOJIS.bronze, top3_rank: null, all_time_revenue: 0, last_30d_revenue: 0 };
  }
  return {
    tier: row.tier, tier_label: CHANNEL_TIER_LABELS[row.tier], tier_emoji: CHANNEL_TIER_EMOJIS[row.tier],
    top3_rank: row.top3_rank, all_time_revenue: row.all_time_revenue, last_30d_revenue: row.last_30d_revenue
  };
}

// 공개: 이 채널의 등급/랭킹 정보 (시청 화면에 배지로 노출하기 위함, 로그인 불필요)
app.get('/api/live/channels/:slug/rank', async (req, res) => {
  try {
    const { data: channel } = await supabase.from('channels_live').select('id').eq('slug', req.params.slug).maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const rank = await getChannelRankInfo(channel.id);
    res.json({ success: true, data: rank, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching channel rank:', err);
    res.status(500).json({ error: 'Failed to fetch channel rank', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 전체 채널 등급/랭킹 목록 + 등급 기준 조회
app.get('/api/admin/live/channel-rankings', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { thresholds, rows, computed_at } = await computeChannelRankings();
    const channelIds = rows.map(r => r.channel_id);
    const nameMap = {};
    if (channelIds.length > 0) {
      const { data: channels } = await supabase.from('channels_live').select('id, name, slug').in('id', channelIds);
      (channels || []).forEach(c => { nameMap[c.id] = c; });
    }
    const enriched = rows.map(r => ({
      ...r,
      name: nameMap[r.channel_id] ? nameMap[r.channel_id].name : '(알 수 없음)',
      slug: nameMap[r.channel_id] ? nameMap[r.channel_id].slug : null,
      tier_label: CHANNEL_TIER_LABELS[r.tier], tier_emoji: CHANNEL_TIER_EMOJIS[r.tier]
    })).sort((a, b) => b.all_time_revenue - a.all_time_revenue);
    res.json({ success: true, data: { thresholds, rankings: enriched, computed_at }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching channel rankings:', err);
    res.status(500).json({ error: 'Failed to fetch channel rankings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 등급 기준 금액 저장
app.patch('/api/admin/settings/channel-tier-thresholds', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const s = Number(req.body?.silver), g = Number(req.body?.gold), p = Number(req.body?.platinum);
    if (![s, g, p].every(n => Number.isFinite(n) && n >= 0)) {
      return res.status(400).json({ error: 'Bad Request', message: '모든 기준 금액은 0 이상 숫자여야 합니다', timestamp: new Date().toISOString() });
    }
    if (!(s < g && g < p)) {
      return res.status(400).json({ error: 'Bad Request', message: '실버 < 골드 < 플래티넘 순서로 커져야 합니다', timestamp: new Date().toISOString() });
    }
    const value = { silver: s, gold: g, platinum: p };
    const { error } = await supabase.from('platform_settings').upsert({
      key: 'channel_tier_thresholds', value, updated_at: new Date().toISOString(), updated_by: req.user.id
    }, { onConflict: 'key' });
    if (error) throw error;
    channelRankingCache = null; // 기준이 바뀌었으니 캐시 무효화
    res.json({ success: true, data: value, message: '저장되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating channel tier thresholds:', err);
    res.status(500).json({ error: 'Failed to update channel tier thresholds', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 특정 기간의 크리에이터별 매출 집계 (orders_with.creator_id 기준, 취소/환불 제외) - 위 분양조직 집계와 완전히 동일한 패턴
async function computeCreatorRevenueForPeriod(startDate, endDate) {
  let ordersQuery = supabase
    .from('orders_with')
    .select('id, creator_id, final_price, status, created_at')
    .not('creator_id', 'is', null)
    .not('status', 'in', '(cancelled,refunded)');
  if (startDate) ordersQuery = ordersQuery.gte('created_at', startDate);
  if (endDate) {
    const endExclusive = /^\d{4}-\d{2}-\d{2}$/.test(endDate)
      ? new Date(new Date(endDate + 'T00:00:00Z').getTime() + 24 * 60 * 60 * 1000).toISOString()
      : endDate;
    ordersQuery = ordersQuery.lt('created_at', endExclusive);
  }
  const { data: orders, error } = await ordersQuery;
  if (error) throw error;

  const agg = {}; // creatorId -> { revenue, orderCount }
  (orders || []).forEach(o => {
    if (!o.creator_id) return;
    if (!agg[o.creator_id]) agg[o.creator_id] = { revenue: 0, orderCount: 0 };
    agg[o.creator_id].revenue += Number(o.final_price || 0);
    agg[o.creator_id].orderCount += 1;
  });
  return agg;
}

// 기간을 지정해 크리에이터별 정산 내역 생성(또는 재계산). 이미 'paid' 상태인 건은 건드리지 않는다. 관리자 전용.
app.post('/api/admin/creator-settlements/generate', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUpOrBootstrap, async (req, res) => {
  try {
    const { startDate, endDate } = req.body || {};
    if (!startDate || !endDate) {
      return res.status(400).json({ error: 'Bad Request', message: 'startDate, endDate는 필수입니다 (예: 2026-08-01)', timestamp: new Date().toISOString() });
    }

    const agg = await computeCreatorRevenueForPeriod(startDate, endDate);
    const creatorIds = Object.keys(agg);
    if (creatorIds.length === 0) {
      return res.json({ success: true, data: { created: 0, updated: 0, skippedPaid: 0, skippedNoBankAccount: [], rows: [] }, timestamp: new Date().toISOString() });
    }

    const { data: creators, error: creatorErr } = await supabase
      .from('creators_with').select('id, display_name, commission_rate, bank_name, bank_account, account_holder').in('id', creatorIds);
    if (creatorErr) throw creatorErr;
    const rateMap = {}, nameMap = {}, bankMap = {};
    (creators || []).forEach(c => {
      rateMap[c.id] = c.commission_rate != null ? Number(c.commission_rate) : 10;
      nameMap[c.id] = c.display_name;
      bankMap[c.id] = { bank_name: c.bank_name || null, bank_account: c.bank_account || null, account_holder: c.account_holder || null };
    });

    const { data: existingRows, error: existErr } = await supabase
      .from('creator_settlements_with').select('id, creator_id, status')
      .eq('period_start', startDate).eq('period_end', endDate).in('creator_id', creatorIds);
    if (existErr) throw existErr;
    const existingByCreator = {};
    (existingRows || []).forEach(r => { existingByCreator[r.creator_id] = r; });

    let created = 0, updated = 0, skippedPaid = 0;
    const skippedNoBankAccount = [];
    const resultRows = [];

    for (const creatorId of creatorIds) {
      const bank = bankMap[creatorId] || {};
      if (!bank.bank_account) skippedNoBankAccount.push({ creator_id: creatorId, creator_name: nameMap[creatorId] || '(이름 없음)' });

      const grossRevenue = agg[creatorId].revenue;
      const orderCount = agg[creatorId].orderCount;
      const commissionRate = rateMap[creatorId] != null ? rateMap[creatorId] : 10;
      const commissionAmount = Math.round(grossRevenue * commissionRate / 100);

      const existing = existingByCreator[creatorId];
      if (existing && existing.status === 'paid') { skippedPaid++; continue; }

      if (existing) {
        const { data, error } = await supabase.from('creator_settlements_with').update({
          order_count: orderCount, gross_revenue: grossRevenue, commission_rate: commissionRate,
          commission_amount: commissionAmount, updated_at: new Date().toISOString(),
          bank_name: bank.bank_name, bank_account: bank.bank_account, account_holder: bank.account_holder
        }).eq('id', existing.id).select().single();
        if (error) throw error;
        updated++; resultRows.push(data);
      } else {
        const { data, error } = await supabase.from('creator_settlements_with').insert([{
          creator_id: creatorId, period_start: startDate, period_end: endDate,
          order_count: orderCount, gross_revenue: grossRevenue, commission_rate: commissionRate,
          commission_amount: commissionAmount, status: 'pending', created_by: req.user.id,
          bank_name: bank.bank_name, bank_account: bank.bank_account, account_holder: bank.account_holder
        }]).select().single();
        if (error) throw error;
        created++; resultRows.push(data);
      }
    }

    res.json({ success: true, data: { created, updated, skippedPaid, skippedNoBankAccount, rows: resultRows }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error generating creator settlements:', err);
    res.status(500).json({ error: 'Failed to generate creator settlements', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/creator-settlements', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUpOrBootstrap, async (req, res) => {
  try {
    const { status, creatorId } = req.query;
    let query = supabase.from('creator_settlements_with').select('*').order('period_start', { ascending: false });
    if (creatorId) query = query.eq('creator_id', creatorId);
    if (status) query = query.eq('status', status);

    const { data: rows, error } = await query;
    if (error) throw error;

    const creatorIds = [...new Set((rows || []).map(r => r.creator_id))];
    const { data: creatorRows } = creatorIds.length
      ? await supabase.from('creators_with').select('id, display_name').in('id', creatorIds)
      : { data: [] };
    const nameMap = {};
    (creatorRows || []).forEach(c => { nameMap[c.id] = c.display_name; });

    const result = (rows || []).map(r => ({ ...r, creator_name: nameMap[r.creator_id] || null }));
    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching creator settlements:', err);
    res.status(500).json({ error: 'Failed to fetch creator settlements', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 정산 상태 변경(지급완료/취소) - 지급완료 시점에 계좌정보 스냅샷 필수 + 세무처리 스냅샷(공급자/분양조직과 동일한 규칙)
app.patch('/api/admin/creator-settlements/:id/status', authenticate, requireRole(['admin', 'super_admin']), requireOwnerStepUpOrBootstrap, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, payout_memo } = req.body || {};
    if (!['pending', 'paid', 'cancelled'].includes(status)) {
      return res.status(400).json({ error: 'Bad Request', message: "status는 'pending', 'paid', 'cancelled' 중 하나여야 합니다", timestamp: new Date().toISOString() });
    }
    const update = { status };
    if (payout_memo !== undefined) update.payout_memo = payout_memo || null;
    if (status === 'paid') {
      update.paid_at = new Date().toISOString();
      const { data: existing } = await supabase.from('creator_settlements_with').select('creator_id, commission_amount, bank_account').eq('id', id).maybeSingle();
      if (!existing) return res.status(404).json({ error: 'Not Found', message: '정산 내역을 찾을 수 없습니다', timestamp: new Date().toISOString() });
      if (!existing.bank_account) {
        return res.status(400).json({ error: 'Bad Request', message: '이 정산 건에는 송금할 계좌 정보가 없습니다. 크리에이터 관리에서 계좌를 등록한 뒤, 해당 기간 정산을 다시 생성(재계산)하면 계좌 정보가 반영됩니다.', timestamp: new Date().toISOString() });
      }
      const { data: creator } = await supabase.from('creators_with').select('settlement_tax_method').eq('id', existing.creator_id).maybeSingle();
      Object.assign(update, computeSettlementTaxFields(existing.commission_amount, creator?.settlement_tax_method));
    } else {
      update.paid_at = null;
    }

    const { data, error } = await supabase.from('creator_settlements_with').update(update).eq('id', id).select().single();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '정산 내역을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating creator settlement status:', err);
    res.status(500).json({ error: 'Failed to update creator settlement status', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🏦 분양조직 정산 자동송금 연동 (방법 B: 오픈뱅킹 / 방법 C: 정산대행 서비스)
// ------------------------------------------------------------
// 정산 지급에는 세 가지 방법이 있다:
//   A) 수동 CSV(위 payout-csv) - 관리자가 은행 인터넷뱅킹 "대량이체" 화면에 직접 입력. 이미 구현됨.
//   B) 오픈뱅킹(금융결제원) API로 자동 입금이체
//   C) 정산대행 서비스(세틀뱅크 등) API로 자동 송금
// 방법 B/C는 실제 은행 계좌를 움직이므로 반드시:
//   - 기본값은 테스트모드(is_test_mode=true)이며, 테스트모드에서는 외부 API를 절대 호출하지 않고
//     시뮬레이션 응답만 만들어 로그에 남긴다.
//   - 설정 저장/실행 라우트는 반드시 requireOwnerStepUp(대표자 2FA 스텝업)으로 보호한다.
//   - API 키/시크릿은 encryptOwnerSecret()/decryptOwnerSecret()로만 암호화 저장한다(새 암호화 로직 금지).
//   - 실행 시도는 성공/실패 관계없이 전부 community_payout_transfer_log에 기록한다.
// 정직성 안내: 오픈뱅킹/정산대행사 모두 아직 실제 계약·심사(오픈뱅킹은 이용기관 등록 심사, 정산대행은
// 가맹계약)가 없는 상태라 실제 키로 검증하지 못했다. 아래 요청/응답 형식은 공개된 문서(금융결제원 오픈뱅킹
// 개발가이드 - https://developers.kftc.or.kr)와 정산대행업계에서 흔히 쓰이는 "API Key 헤더 + POST 이체요청 +
// 거래ID 응답" 패턴을 최선을 다해 반영했을 뿐, 실제 계약 후 해당 업체의 최종 API 문서로 필드명을 다시
// 검증해야 한다(도매매 오픈API를 이런 식으로 정직하게 처리한 전례를 그대로 따른다 - 위 DOMEGGOOK_BASE 주석 참고).
// ============================================

const PAYOUT_PROVIDER_KEYS = ['openbanking', 'settlement_agency'];

// 한국 주요 은행명 -> 오픈뱅킹 표준 은행코드(3자리). 오픈뱅킹 입금이체 API는 계좌를 "은행코드+계좌번호"로
// 식별하므로, communities.bank_name에 자유 텍스트로 저장된 은행명을 코드로 변환해야 한다. 여기 없는
// 은행명은 이체를 시도하기 전에 명확한 오류로 막는다(추측해서 잘못된 코드로 보내는 것보다 안전).
const OPENBANKING_BANK_CODE_MAP = {
  '한국은행': '001', 'KDB산업은행': '002', '산업은행': '002', 'IBK기업은행': '003', '기업은행': '003',
  'KB국민은행': '004', '국민은행': '004', '수협은행': '007', 'NH농협은행': '011', '농협은행': '011',
  '농협': '011', '우리은행': '020', 'SC제일은행': '023', '제일은행': '023', '한국씨티은행': '027',
  '씨티은행': '027', '대구은행': '031', 'DGB대구은행': '031', '부산은행': '032', 'BNK부산은행': '032',
  '광주은행': '034', '제주은행': '035', '전북은행': '037', '경남은행': '039', 'BNK경남은행': '039',
  '새마을금고': '045', '신협': '048', '신협중앙회': '048', '우체국': '071', '우체국예금보험': '071',
  'KEB하나은행': '081', '하나은행': '081', '신한은행': '088', '케이뱅크': '089', '카카오뱅크': '090',
  '토스뱅크': '092'
};

// ---- 공용: provider 설정 조회 + JSON 시크릿 암/복호화(기존 encryptOwnerSecret/decryptOwnerSecret 재사용) ----
async function getPayoutProvider(provider) {
  const { data, error } = await supabase.from('community_payout_providers').select('*').eq('provider', provider).maybeSingle();
  if (error) throw error;
  return data;
}
// encrypted_secret 컬럼에는 { client_id, client_secret, ... } 같은 JSON 객체를 문자열로 직렬화한 뒤
// encryptOwnerSecret()로 통째로 암호화해서 저장한다 - 컬럼을 여러 개 늘리지 않고 provider마다 다른
// 시크릿 필드 구성(오픈뱅킹은 client_id/secret/refresh_token, 정산대행은 API Key 하나)을 유연하게 담기 위함.
function decryptPayoutSecretJSON(providerRow) {
  if (!providerRow || !providerRow.encrypted_secret) return {};
  try {
    return JSON.parse(decryptOwnerSecret(providerRow.encrypted_secret));
  } catch (err) {
    console.error(`payout provider(${providerRow.provider}) 시크릿 복호화 실패:`, err.message);
    throw new Error('저장된 인증정보를 복호화하지 못했습니다. 송금 방법 설정 화면에서 키를 다시 저장해주세요.');
  }
}
function encryptPayoutSecretJSON(obj) {
  return encryptOwnerSecret(JSON.stringify(obj || {}));
}

// 이체 시도 전용 상세 로그 - admin_audit_logs_with(요청 전체를 잡는 범용 감사로그)와 별개로,
// 이체 성공/실패/테스트시뮬레이션 여부와 요청·응답 스냅샷을 전용 테이블에 남긴다. 로그 기록 자체가
// 실패해도(네트워크 등) 원래 응답 흐름을 막지 않는다.
async function logPayoutTransfer({ settlementId, provider, status, amount, requestSnapshot, responseSnapshot, errorMessage, executedBy }) {
  try {
    await supabase.from('community_payout_transfer_log').insert([{
      settlement_id: settlementId || null,
      provider,
      status,
      amount: (amount === undefined || amount === null) ? null : amount,
      request_snapshot: requestSnapshot ? redactSensitiveFields(requestSnapshot) : null,
      response_snapshot: responseSnapshot ? redactSensitiveFields(responseSnapshot) : null,
      error_message: errorMessage || null,
      executed_by: executedBy || null
    }]);
  } catch (err) {
    console.error('이체 시도 로그 기록 실패:', err.message);
  }
}

// ---- 방법 B: 오픈뱅킹(금융결제원) ----
// config: { institution_use_code, fintech_use_num(플랫폼 출금계좌), api_env: 'testbed'|'production' }
// secret: { client_id, client_secret, refresh_token, access_token, access_token_expires_at }
// ⚠️ 중요한 전제: 오픈뱅킹으로 특정 계좌에 입금이체를 하려면, 그 계좌가 우리 오픈뱅킹 "이용기관"에
// 사전 등록되어 fintech_use_num(핀테크이용번호)을 이미 발급받은 상태여야 한다(오픈뱅킹의 구조적 제약 -
// 계좌번호만으로는 이체 불가, 반드시 출금동의 등록 절차를 먼저 거쳐야 함). 이 기능은 지금 그 등록 절차
// (계좌 실명 확인 + 1원 인증 등)를 구현하지 않았고, community_settlements_with에도 상대 계좌의
// fintech_use_num을 저장할 컬럼이 없다 - 즉 아래 이체 함수는 "조직 계좌가 이미 등록되어 있다"는 것을
// 전제로만 동작하며, 실제 도입 시에는 계좌 등록(출금동의) 플로우를 별도로 먼저 구현해야 한다.
const OPENBANKING_API_BASE = {
  testbed: 'https://testapi.openbanking.or.kr',
  production: 'https://openapi.kftc.or.kr'
};

async function refreshOpenBankingAccessToken(providerRow, secret) {
  const apiBase = OPENBANKING_API_BASE[providerRow.config?.api_env] || OPENBANKING_API_BASE.testbed;
  if (!secret.client_id || !secret.client_secret) {
    throw new Error('오픈뱅킹 Client ID/Secret이 설정되지 않았습니다');
  }
  // 캐시된 access_token이 아직 유효하면(만료 60초 이상 남음) 재사용
  if (secret.access_token && secret.access_token_expires_at && Date.now() < new Date(secret.access_token_expires_at).getTime() - 60000) {
    return secret.access_token;
  }
  if (!secret.refresh_token) {
    // 오픈뱅킹은 최초 access_token/refresh_token 발급에 사용자(대표자) 브라우저 리다이렉트 동의가 필요한
    // OAuth2 Authorization Code 플로우를 거쳐야 한다 - 이 서버는 헤드리스라 그 최초 동의 플로우를 자체적으로
    // 수행할 수 없다. 금융결제원 개발자센터에서 별도로 OAuth 동의를 완료해 발급받은 refresh_token을
    // "송금 방법 설정" 화면에 직접 입력해줘야 이후 자동 갱신이 가능하다.
    throw new Error('오픈뱅킹 refresh_token이 설정되지 않았습니다. 금융결제원 오픈뱅킹 개발자센터에서 최초 OAuth 동의를 완료한 뒤 발급받은 refresh_token을 저장해주세요.');
  }
  // 공개 문서 기준 토큰 갱신: POST {base}/oauth/2.0/token (application/x-www-form-urlencoded)
  const resp = await fetch(`${apiBase}/oauth/2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: secret.client_id,
      client_secret: secret.client_secret,
      refresh_token: secret.refresh_token,
      scope: 'transfer'
    }).toString(),
    signal: AbortSignal.timeout(15000)
  });
  const json = await resp.json().catch(() => null);
  if (!resp.ok || !json?.access_token) {
    throw new Error(`오픈뱅킹 토큰 갱신 실패: ${json?.rsp_message || json?.error_description || resp.status}`);
  }
  const expiresInSec = Number(json.expires_in) || 3600;
  const updatedSecret = {
    ...secret,
    access_token: json.access_token,
    access_token_expires_at: new Date(Date.now() + expiresInSec * 1000).toISOString(),
    refresh_token: json.refresh_token || secret.refresh_token // 오픈뱅킹은 갱신 시 refresh_token도 함께 재발급될 수 있음
  };
  // 갱신된 토큰을 다음 호출을 위해 다시 암호화해서 저장(재요청마다 매번 갱신하지 않도록)
  try {
    await supabase.from('community_payout_providers').update({ encrypted_secret: encryptPayoutSecretJSON(updatedSecret) }).eq('provider', 'openbanking');
  } catch (err) {
    console.error('오픈뱅킹 access_token 캐시 저장 실패(다음 요청에서 재갱신됨):', err.message);
  }
  return json.access_token;
}

// 오픈뱅킹 입금이체 실행. 필드명은 금융결제원 공개 개발가이드(입금이체 API)를 기준으로 최선을 다해
// 구성했으나, 실제 계약/테스트베드 접근 전까지는 100% 확정할 수 없다 - 특히 bank_tran_id(이체거래고유번호)
// 채번 규칙(이용기관코드 10자리 + 구분코드 1자리 + 일련번호 등)은 기관마다 안내받는 방식이 달라, 여기서는
// 통상적으로 알려진 "타임스탬프 기반 유니크 문자열"로 대체했다 - 실제 연동 시 금융결제원이 안내하는
// 정확한 채번 규칙으로 교체해야 한다.
async function executeOpenBankingTransfer(providerRow, secret, { bankName, bankAccount, accountHolder, amount, printContent }) {
  const apiBase = OPENBANKING_API_BASE[providerRow.config?.api_env] || OPENBANKING_API_BASE.testbed;
  const withdrawFintechNum = providerRow.config?.fintech_use_num;
  const institutionUseCode = providerRow.config?.institution_use_code;
  if (!withdrawFintechNum || !institutionUseCode) {
    throw new Error('오픈뱅킹 설정에 출금계좌 핀테크이용번호(fintech_use_num) 또는 이용기관코드가 없습니다');
  }
  const bankCode = OPENBANKING_BANK_CODE_MAP[String(bankName || '').trim()];
  if (!bankCode) {
    throw new Error(`오픈뱅킹으로 이체할 수 없는 은행명입니다: "${bankName}" (지원 은행코드 매핑에 없음 - 서버 코드의 OPENBANKING_BANK_CODE_MAP에 추가해야 합니다)`);
  }
  const accessToken = await refreshOpenBankingAccessToken(providerRow, secret);
  const bankTranId = `${institutionUseCode}U${Date.now()}`.slice(0, 20); // 이용기관코드+구분코드(U)+타임스탬프, 20자 이내
  const nowKst = new Date();
  const body = {
    bank_tran_id: bankTranId,
    cntr_account_type: 'N',
    cntr_account_num: withdrawFintechNum,
    dps_print_content: (printContent || '분양조직정산').slice(0, 20),
    fintech_use_num: withdrawFintechNum,
    tran_amt: String(Math.round(Number(amount) || 0)),
    tran_dtime: nowKst.toISOString().replace(/[-:TZ.]/g, '').slice(0, 14),
    req_client_name: '플랫폼', // 실제 도입 시 platform_business_info의 상호명으로 대체 필요
    req_client_bank_code: bankCode,
    req_client_account_num: bankAccount,
    req_client_num: institutionUseCode,
    transfer_purpose: 'TR',
    recv_client_name: accountHolder,
    recv_client_bank_code: bankCode,
    recv_client_account_num: bankAccount,
    recv_client_fintech_use_num: '' // 수취계좌의 fintech_use_num은 별도 등록 절차가 필요(위 주석 참고) - 현재 빈 값
  };
  const resp = await fetch(`${apiBase}/v2.0/transfer/deposit/${withdrawFintechNum}`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20000)
  });
  const json = await resp.json().catch(() => null);
  const ok = resp.ok && (json?.rsp_code === 'A0000' || json?.res_cd === '00000');
  return { ok, httpStatus: resp.status, request: body, response: json, transactionId: json?.bank_tran_id || json?.api_tran_id || null, message: json?.rsp_message || json?.res_msg || (ok ? '성공' : '오픈뱅킹 이체 실패') };
}

// ---- 방법 C: 정산대행 서비스 (범용 어댑터) ----
// config: { base_url, transfer_path(기본 '/transfer'), merchant_id, auth_header(기본 'Authorization'),
//           auth_scheme(기본 'Bearer') }
// secret: { api_key }
// 특정 업체(세틀뱅크 등) 전용 필드명을 하드코딩하지 않고, "REST API에 API Key 인증 헤더를 붙여 수취인
// 계좌/금액을 POST하면 거래ID를 반환한다"는 정산대행업계의 흔한 패턴을 그대로 따르는 범용 어댑터로
// 구현했다. 실제 계약한 업체의 API 문서를 받으면 아래 요청/응답 필드명(bankCode/bankName,
// accountNumber, amount, transactionId 등)을 그 업체 스펙에 맞게 조정해야 한다 - 지금은 어떤 업체와도
// 계약 전이라 검증할 방법이 없었다.
async function executeSettlementAgencyTransfer(providerRow, secret, { bankName, bankAccount, accountHolder, amount, settlementId }) {
  const config = providerRow.config || {};
  if (!config.base_url) throw new Error('정산대행 서비스 base_url이 설정되지 않았습니다');
  if (!secret.api_key) throw new Error('정산대행 서비스 API Key가 설정되지 않았습니다');
  const authHeader = config.auth_header || 'Authorization';
  const authScheme = config.auth_scheme !== undefined ? config.auth_scheme : 'Bearer';
  const headerValue = authScheme ? `${authScheme} ${secret.api_key}` : secret.api_key;
  const url = `${String(config.base_url).replace(/\/$/, '')}${config.transfer_path || '/transfer'}`;
  const body = {
    merchantId: config.merchant_id || undefined,
    bankName,
    accountNumber: bankAccount,
    accountHolder,
    amount: Math.round(Number(amount) || 0),
    note: `분양조직정산 ${settlementId || ''}`.trim()
  };
  const resp = await fetch(url, {
    method: 'POST',
    headers: { [authHeader]: headerValue, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20000)
  });
  const json = await resp.json().catch(() => null);
  // 성공 판정 기준도 업체마다 다를 수 있어(success:true, code:'0000' 등) 흔한 두 가지 형태를 방어적으로 확인
  const ok = resp.ok && (json?.success === true || json?.status === 'success' || json?.code === '0000' || json?.resultCode === '0000');
  const transactionId = json?.transactionId || json?.txId || json?.tranId || json?.id || null;
  return { ok, httpStatus: resp.status, request: { ...body, headerName: authHeader }, response: json, transactionId, message: json?.message || (ok ? '성공' : '정산대행 이체 실패') };
}

// ---- 공급자 설정 CRUD (대표자 2FA 스텝업 필수) ----
app.get('/api/admin/payout-providers', authenticate, requireOwnerStepUp, async (req, res) => {
  try {
    const { data, error } = await supabase.from('community_payout_providers').select('*').order('provider');
    if (error) throw error;
    const safe = (data || []).map(row => ({
      provider: row.provider,
      display_name: row.display_name,
      is_enabled: row.is_enabled,
      is_test_mode: row.is_test_mode,
      config: row.config || {},
      hasSecret: !!row.encrypted_secret,
      updated_at: row.updated_at
    }));
    res.json({ success: true, data: safe, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching payout providers:', err);
    res.status(500).json({ error: 'Failed to fetch payout providers', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.put('/api/admin/payout-providers/:provider', authenticate, requireOwnerStepUp, async (req, res) => {
  try {
    const { provider } = req.params;
    if (!PAYOUT_PROVIDER_KEYS.includes(provider)) {
      return res.status(400).json({ error: 'Bad Request', message: `지원하지 않는 provider입니다 (${PAYOUT_PROVIDER_KEYS.join(', ')} 중 하나)`, timestamp: new Date().toISOString() });
    }
    const { is_enabled, is_test_mode, config, secret, display_name } = req.body || {};
    const update = { provider, updated_by: req.user.id, updated_at: new Date().toISOString() };
    if (display_name !== undefined) update.display_name = display_name || null;
    if (is_enabled !== undefined) update.is_enabled = !!is_enabled;
    // is_test_mode를 아예 안 보내면 기존 값을 그대로 두고, 명시적으로 보낼 때만 바뀐다 - 신규 provider row는
    // 마이그레이션에서 이미 true(테스트모드)로 미리 만들어 두었으므로 "실수로 누락되어 실모드가 되는" 경우는 없다.
    if (is_test_mode !== undefined) update.is_test_mode = !!is_test_mode;
    if (config !== undefined && typeof config === 'object') update.config = config;
    // secret은 값이 있을 때만 새로 암호화해서 갱신(빈 값/미전달이면 기존 값 유지) - naver oauth_config PUT과 동일한 원칙
    if (secret && typeof secret === 'object' && Object.keys(secret).length > 0) {
      const existing = await getPayoutProvider(provider);
      const merged = { ...(existing ? decryptPayoutSecretJSON(existing) : {}), ...secret };
      update.encrypted_secret = encryptPayoutSecretJSON(merged);
    }
    const { data, error } = await supabase.from('community_payout_providers').upsert(update, { onConflict: 'provider' }).select().single();
    if (error) throw error;
    res.json({
      success: true,
      data: { provider: data.provider, display_name: data.display_name, is_enabled: data.is_enabled, is_test_mode: data.is_test_mode, config: data.config, hasSecret: !!data.encrypted_secret },
      message: '저장되었습니다',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error saving payout provider:', err);
    res.status(500).json({ error: 'Failed to save payout provider', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ---- 실행 공용 로직 ----
async function runPayoutTransfer({ settlement, provider, executedBy }) {
  const providerRow = await getPayoutProvider(provider);
  if (!providerRow || !providerRow.is_enabled) {
    const err = new Error(`${provider} 방식은 아직 활성화되어 있지 않습니다. 대표자 보안설정 > 송금 방법 설정에서 먼저 활성화해주세요.`);
    err.statusCode = 400;
    throw err;
  }
  const amount = (settlement.net_payment_amount !== null && settlement.net_payment_amount !== undefined) ? settlement.net_payment_amount : settlement.commission_amount;
  if (!settlement.bank_account) {
    const err = new Error('이 정산 건에는 송금할 계좌 정보가 없습니다');
    err.statusCode = 400;
    throw err;
  }

  if (providerRow.is_test_mode) {
    // 🧪 테스트모드: 외부 API를 절대 호출하지 않는다. 시뮬레이션 성공 응답만 만들어 로그에 남기고,
    // 정산 상태는 바꾸지 않는다(테스트모드는 실제로 지급된 게 아니므로).
    const simulated = {
      simulated: true, provider, amount,
      bankName: settlement.bank_name, bankAccount: settlement.bank_account, accountHolder: settlement.account_holder,
      note: '테스트모드 - 실제 외부 API를 호출하지 않았습니다'
    };
    await logPayoutTransfer({
      settlementId: settlement.id, provider, status: 'test_simulated', amount,
      requestSnapshot: simulated, responseSnapshot: { simulated: true, transactionId: `TEST-${Date.now()}` },
      executedBy
    });
    return { testMode: true, simulated: true, message: '테스트 모드로 시뮬레이션되었습니다. 실제로 송금되지 않았으며 정산 상태도 변경되지 않았습니다.' };
  }

  // 🔴 실모드: 실제로 외부 API를 호출한다.
  const secret = decryptPayoutSecretJSON(providerRow);
  const transferInput = {
    bankName: settlement.bank_name, bankAccount: settlement.bank_account, accountHolder: settlement.account_holder,
    amount, printContent: '분양조직정산', settlementId: settlement.id
  };
  let result;
  try {
    result = provider === 'openbanking'
      ? await executeOpenBankingTransfer(providerRow, secret, transferInput)
      : await executeSettlementAgencyTransfer(providerRow, secret, transferInput);
  } catch (err) {
    await logPayoutTransfer({ settlementId: settlement.id, provider, status: 'failed', amount, requestSnapshot: transferInput, errorMessage: err.message, executedBy });
    const wrapped = new Error(err.message);
    wrapped.statusCode = 502;
    throw wrapped;
  }

  if (!result.ok) {
    await logPayoutTransfer({ settlementId: settlement.id, provider, status: 'failed', amount, requestSnapshot: result.request, responseSnapshot: result.response, errorMessage: result.message, executedBy });
    const err = new Error(result.message || '이체에 실패했습니다');
    err.statusCode = 502;
    throw err;
  }

  await logPayoutTransfer({ settlementId: settlement.id, provider, status: 'success', amount, requestSnapshot: result.request, responseSnapshot: result.response, executedBy });

  // 성공했을 때만 정산 상태를 지급완료로 갱신(세무처리 필드도 함께 스냅샷)
  const { data: community } = await supabase.from('communities').select('settlement_tax_method').eq('id', settlement.community_id).maybeSingle();
  const taxFields = computeSettlementTaxFields(settlement.commission_amount, community?.settlement_tax_method);
  const { data: updated, error: updateErr } = await supabase.from('community_settlements_with').update({
    status: 'paid', payout_method: provider, paid_at: new Date().toISOString(),
    payout_memo: `${provider === 'openbanking' ? '오픈뱅킹' : '정산대행'} 자동이체 (거래ID: ${result.transactionId || '-'})`,
    ...taxFields
  }).eq('id', settlement.id).select().single();
  if (updateErr) throw updateErr;

  return { testMode: false, transactionId: result.transactionId, settlement: updated, message: '이체가 완료되어 지급완료로 처리되었습니다' };
}

app.post('/api/admin/community-settlements/:id/execute-transfer', authenticate, requireOwnerStepUp, async (req, res) => {
  try {
    const { id } = req.params;
    const { provider } = req.body || {};
    if (!['openbanking', 'settlement_agency'].includes(provider)) {
      return res.status(400).json({ error: 'Bad Request', message: "provider는 'openbanking' 또는 'settlement_agency'여야 합니다", timestamp: new Date().toISOString() });
    }
    const { data: settlement, error } = await supabase.from('community_settlements_with').select('*').eq('id', id).maybeSingle();
    if (error) throw error;
    if (!settlement) return res.status(404).json({ error: 'Not Found', message: '정산 내역을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (settlement.status !== 'pending') {
      return res.status(400).json({ error: 'Bad Request', message: '정산대기 상태인 건만 자동이체를 실행할 수 있습니다', timestamp: new Date().toISOString() });
    }
    const result = await runPayoutTransfer({ settlement, provider, executedBy: req.user.id });
    res.json({ success: true, data: result, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error executing payout transfer:', err);
    res.status(err.statusCode || 500).json({ error: 'Failed to execute transfer', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ---- 실행: 배치(선택 기능) ----
app.post('/api/admin/community-settlements/execute-transfer-batch', authenticate, requireOwnerStepUp, async (req, res) => {
  try {
    const { ids, provider } = req.body || {};
    if (!['openbanking', 'settlement_agency'].includes(provider)) {
      return res.status(400).json({ error: 'Bad Request', message: "provider는 'openbanking' 또는 'settlement_agency'여야 합니다", timestamp: new Date().toISOString() });
    }
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'ids 배열이 비어 있습니다', timestamp: new Date().toISOString() });
    }
    const { data: settlements, error } = await supabase.from('community_settlements_with').select('*').in('id', ids);
    if (error) throw error;
    const results = [];
    for (const settlement of (settlements || [])) {
      if (settlement.status !== 'pending') {
        results.push({ id: settlement.id, ok: false, message: '정산대기 상태가 아니어서 건너뜀' });
        continue;
      }
      try {
        const r = await runPayoutTransfer({ settlement, provider, executedBy: req.user.id });
        results.push({ id: settlement.id, ok: true, ...r });
      } catch (err) {
        results.push({ id: settlement.id, ok: false, message: err.message });
      }
    }
    res.json({ success: true, data: { results, total: results.length, succeeded: results.filter(r => r.ok).length }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error executing batch payout transfer:', err);
    res.status(500).json({ error: 'Failed to execute batch transfer', message: err.message, timestamp: new Date().toISOString() });
  }
});


// 원천징수영수증 데이터 조회 (지급완료 + 원천징수 대상 건만) - 관리자 전용
// 본인(공급자) 또는 관리자만 조회 가능 - authenticate만 걸고 내부에서 판정한다(정산 내역 목록 조회와 동일한 패턴).
// 원천징수영수증은 지급받은 당사자가 본인 세무신고에 써야 하는 문서라 관리자뿐 아니라 본인도 볼 수 있어야 한다.
app.get('/api/admin/settlements/:id/withholding-receipt', authenticate, async (req, res) => {
  try {
    const { data: row, error } = await supabase.from('supplier_settlements').select('*').eq('id', req.params.id).maybeSingle();
    if (error) throw error;
    if (!row) return res.status(404).json({ error: 'Not Found', message: '정산 내역을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const { data: callerProfile } = await supabase.from('profiles').select('role').eq('id', req.user.id).maybeSingle();
    const isSelf = row.supplier_id === req.user.id;
    if (!isSelf && !(callerProfile && isAdminRole(callerProfile.role))) {
      return res.status(403).json({ error: 'Forbidden', message: '본인의 정산 건만 조회할 수 있습니다', timestamp: new Date().toISOString() });
    }
    if (row.status !== 'paid' || row.tax_method !== 'withholding') {
      return res.status(400).json({ error: 'Bad Request', message: '지급완료된 원천징수 대상 정산 건만 영수증을 조회할 수 있습니다', timestamp: new Date().toISOString() });
    }
    // profiles(공급자 계정)에는 사업자등록번호 컬럼이 없다(별도 suppliers 마스터데이터 테이블 소관) - 영수증에는 이름/이메일만 표시
    const { data: supplier } = await supabase.from('profiles').select('full_name, email').eq('id', row.supplier_id).maybeSingle();
    const withholder = await getPlatformBusinessInfo();
    res.json({ success: true, data: { settlement: row, payee: supplier || {}, withholder }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching withholding receipt:', err);
    res.status(500).json({ error: 'Failed to fetch withholding receipt', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/community-settlements/:id/withholding-receipt', authenticate, async (req, res) => {
  try {
    const { data: row, error } = await supabase.from('community_settlements_with').select('*').eq('id', req.params.id).maybeSingle();
    if (error) throw error;
    if (!row) return res.status(404).json({ error: 'Not Found', message: '정산 내역을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const { data: callerProfile } = await supabase.from('profiles').select('role').eq('id', req.user.id).maybeSingle();
    let allowed = !!(callerProfile && isAdminRole(callerProfile.role));
    if (!allowed) {
      const myCommunity = await getMyManagedCommunity(req.user.id);
      allowed = !!(myCommunity && myCommunity.id === row.community_id);
    }
    if (!allowed) {
      return res.status(403).json({ error: 'Forbidden', message: '본인이 담당하는 조직의 정산 건만 조회할 수 있습니다', timestamp: new Date().toISOString() });
    }
    if (row.status !== 'paid' || row.tax_method !== 'withholding') {
      return res.status(400).json({ error: 'Bad Request', message: '지급완료된 원천징수 대상 정산 건만 영수증을 조회할 수 있습니다', timestamp: new Date().toISOString() });
    }
    const { data: community } = await supabase.from('communities').select('name, business_number').eq('id', row.community_id).maybeSingle();
    const withholder = await getPlatformBusinessInfo();
    res.json({ success: true, data: { settlement: row, payee: community || {}, withholder }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching community withholding receipt:', err);
    res.status(500).json({ error: 'Failed to fetch withholding receipt', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 세금계산서 발행완료 수동 처리 - 실제 발행은 홈택스/팝빌 등 외부에서 하고, 발행 후 문서번호를 여기에 입력해 상태를 전환한다
app.patch('/api/admin/settlements/:id/tax-invoice', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const invoiceNumber = String(req.body?.tax_invoice_number || '').trim();
    if (!invoiceNumber) return res.status(400).json({ error: 'Bad Request', message: 'tax_invoice_number는 필수입니다', timestamp: new Date().toISOString() });
    const { data: existing } = await supabase.from('supplier_settlements').select('tax_invoice_status').eq('id', req.params.id).maybeSingle();
    if (!existing) return res.status(404).json({ error: 'Not Found', message: '정산 내역을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (existing.tax_invoice_status !== 'pending') {
      return res.status(400).json({ error: 'Bad Request', message: '세금계산서 발행대기 상태인 건만 처리할 수 있습니다', timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase.from('supplier_settlements').update({
      tax_invoice_status: 'issued', tax_invoice_number: invoiceNumber, tax_invoice_issued_at: new Date().toISOString()
    }).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ success: true, data, message: '세금계산서 발행완료로 처리되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error marking tax invoice issued:', err);
    res.status(500).json({ error: 'Failed to update tax invoice status', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.patch('/api/admin/community-settlements/:id/tax-invoice', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const invoiceNumber = String(req.body?.tax_invoice_number || '').trim();
    if (!invoiceNumber) return res.status(400).json({ error: 'Bad Request', message: 'tax_invoice_number는 필수입니다', timestamp: new Date().toISOString() });
    const { data: existing } = await supabase.from('community_settlements_with').select('tax_invoice_status').eq('id', req.params.id).maybeSingle();
    if (!existing) return res.status(404).json({ error: 'Not Found', message: '정산 내역을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (existing.tax_invoice_status !== 'pending') {
      return res.status(400).json({ error: 'Bad Request', message: '세금계산서 발행대기 상태인 건만 처리할 수 있습니다', timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase.from('community_settlements_with').update({
      tax_invoice_status: 'issued', tax_invoice_number: invoiceNumber, tax_invoice_issued_at: new Date().toISOString()
    }).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ success: true, data, message: '세금계산서 발행완료로 처리되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error marking community tax invoice issued:', err);
    res.status(500).json({ error: 'Failed to update tax invoice status', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🕵️ 관리자 감사로그 조회 (super_admin 전용 - 로그 자체는 최고 권한만 열람 가능해야 의미가 있음)
// ============================================
app.get('/api/admin/audit-logs', authenticate, requireRole(['super_admin']), async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize, 10) || 30));
    const from = (page - 1) * pageSize;
    const to = from + pageSize - 1;

    let query = supabase.from('admin_audit_logs_with').select('*', { count: 'exact' }).order('created_at', { ascending: false });

    if (req.query.adminId) query = query.eq('admin_id', req.query.adminId);
    if (req.query.method) query = query.eq('method', req.query.method.toUpperCase());
    if (req.query.pathContains) query = query.ilike('path', `%${req.query.pathContains}%`);
    if (req.query.dateFrom) query = query.gte('created_at', req.query.dateFrom);
    if (req.query.dateTo) query = query.lte('created_at', req.query.dateTo);

    const { data, error, count } = await query.range(from, to);
    if (error) throw error;

    res.json({
      success: true,
      data: data || [],
      pagination: { page, pageSize, total: count || 0, totalPages: Math.ceil((count || 0) / pageSize) },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching audit logs:', err);
    res.status(500).json({ error: 'Failed to fetch audit logs', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자 목록(super_admin 전용) - 감사로그 화면에서 "관리자별 필터" 드롭다운을 채우는 용도
app.get('/api/admin/audit-logs/admins', authenticate, requireRole(['super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('profiles').select('id, full_name, email').in('role', ['admin', 'super_admin']).order('email');
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admins', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 찜하기(위시리스트) API
// ============================================
app.get('/api/wishlist', authenticate, async (req, res) => {
  try {
    const { data: rows, error } = await supabase
      .from('wishlist_with')
      .select('id, product_id, created_at')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    if (error) throw error;

    const productIds = (rows || []).map(r => r.product_id);
    let products = [];
    if (productIds.length > 0) {
      const { data: productRows, error: pErr } = await supabase
        .from('products_with')
        .select(PRODUCT_SAFE_COLUMNS)
        .in('id', productIds);
      if (pErr) throw pErr;
      products = productRows || [];
    }
    const byId = {};
    products.forEach(p => { byId[p.id] = p; });

    const result = (rows || [])
      .map(r => byId[r.product_id] ? { ...byId[r.product_id], wishlisted_at: r.created_at } : null)
      .filter(Boolean);

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching wishlist:', err);
    res.status(500).json({ error: 'Failed to fetch wishlist', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/wishlist', authenticate, async (req, res) => {
  try {
    const { product_id } = req.body;
    if (!product_id) {
      return res.status(400).json({ error: 'Bad Request', message: 'product_id는 필수입니다', timestamp: new Date().toISOString() });
    }

    const { data, error } = await supabase
      .from('wishlist_with')
      .upsert({ user_id: req.user.id, product_id }, { onConflict: 'user_id,product_id', ignoreDuplicates: true })
      .select()
      .maybeSingle();
    if (error) throw error;

    res.status(201).json({ success: true, data, message: '찜 목록에 추가했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error adding to wishlist:', err);
    res.status(500).json({ error: 'Failed to add to wishlist', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.delete('/api/wishlist/:productId', authenticate, async (req, res) => {
  try {
    const { error } = await supabase
      .from('wishlist_with')
      .delete()
      .eq('user_id', req.user.id)
      .eq('product_id', req.params.productId);
    if (error) throw error;

    res.json({ success: true, message: '찜 목록에서 제거했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error removing from wishlist:', err);
    res.status(500).json({ error: 'Failed to remove from wishlist', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 관심 카테고리 신상품 알림 (제안서 5절 "개인화 푸시/알림톡 캠페인 자동화") - 기존 마케팅 자동화 규칙 엔진
// (등급/구매마일스톤 기반 쿠폰 자동발급)과는 별개로, 재입고/가격추적과 같은 "이벤트 발생 시 알림" 패턴을 그대로 재사용한다.
// 신상품이 등록되는 순간, 같은 카테고리의 다른 상품을 찜해본 적 있는 회원들에게 인앱 알림을 보낸다.
// (구매 이력까지 함께 스캔하면 신호는 더 넓어지지만 상품 등록마다 전체 주문을 훑어야 해 비용이 커지므로,
// 우선은 찜 신호만으로 시작한다 - 필요하면 나중에 구매 이력 기반으로 확장 가능하도록 함수를 분리해두었다.)
async function triggerCategoryInterestNotifications(newProductId, newProductName, category) {
  try {
    if (!category) return;
    const { data: categoryProducts } = await supabase
      .from('products_with')
      .select('id')
      .eq('category', category)
      .eq('status', 'active')
      .neq('id', newProductId);
    const categoryProductIds = (categoryProducts || []).map(p => p.id);
    if (categoryProductIds.length === 0) return; // 같은 카테고리에 다른 상품이 없으면 찜할 기회 자체가 없었으므로 대상도 없다

    const { data: wishlisters } = await supabase.from('wishlist_with').select('user_id').in('product_id', categoryProductIds);
    const userIds = [...new Set((wishlisters || []).map(w => w.user_id))];
    if (userIds.length === 0) return;

    const notifRows = userIds.map(uid => ({
      user_id: uid,
      type: 'category_interest',
      title: '관심 카테고리 신상품 입고',
      message: `관심 있으셨던 카테고리에 새 상품 "${newProductName}"이(가) 들어왔어요!`,
      link: `/product/${newProductId}`
    }));
    await supabase.from('notifications_with').insert(notifRows);
  } catch (err) {
    console.error('Error triggering category interest notifications:', err);
  }
}

// 가격 추적(가격 하락) 알림 (제안서 5절 "가격 하락/재입고 알림") - 재입고 알림과 완전히 같은 인프라(알림 인프라 재사용)를 쓰되,
// 별도 "가격 추적 신청" 버튼/테이블 없이 이미 있는 찜(위시리스트) 목록을 그대로 추적 대상으로 재사용한다(제안서가 권장한 방식).
// 상품 가격이 실제로 "내려갈 때"(관리자가 PUT /api/products/:id로 가격을 수정하는 시점)만 트리거되므로,
// 같은 가격으로 다시 저장해도 "내려갔다"는 조건 자체가 성립하지 않아 중복 알림이 생기지 않는다.
// 가격 비교/최저가 이력 (제안서 6절 "가격 비교/최저가 이력") - 가격이 실제로 바뀔 때마다 스냅샷을 남겨서,
// 나중에 "최근 N일 최저가 대비 지금 얼마나 저렴한지"를 정직하게 보여줄 수 있게 한다.
async function recordPriceHistory(productId, price, discountPrice) {
  try {
    await supabase.from('product_price_history_with').insert({ product_id: productId, price, discount_price: discountPrice === undefined ? null : discountPrice });
  } catch (err) {
    console.error('Error recording price history:', err);
  }
}

function effectivePriceOf(p) {
  const price = Number(p && p.price) || 0;
  const dp = p && p.discount_price !== null && p.discount_price !== undefined ? Number(p.discount_price) : null;
  return (dp !== null && Number.isFinite(dp) && dp < price) ? dp : price;
}
async function triggerPriceDropNotifications(productId, productName, oldEffectivePrice, newEffectivePrice) {
  try {
    const { data: wishlisters, error } = await supabase.from('wishlist_with').select('user_id').eq('product_id', productId);
    if (error || !wishlisters || wishlisters.length === 0) return;
    const notifRows = wishlisters.map(w => ({
      user_id: w.user_id,
      type: 'price_drop',
      title: '찜한 상품 가격 인하',
      message: `찜하신 "${productName}"의 가격이 ${Math.round(oldEffectivePrice).toLocaleString('ko-KR')}원에서 ${Math.round(newEffectivePrice).toLocaleString('ko-KR')}원으로 내렸습니다!`,
      link: `/product/${productId}`
    }));
    await supabase.from('notifications_with').insert(notifRows);
  } catch (err) {
    console.error('Error triggering price drop notifications:', err);
  }
}

// 재입고 알림 신청 + 인앱 알림
// - 실제 이메일/SMS/푸시 발송 인프라가 없으므로, 정직하게 "사이트 안에서 확인하는 알림"으로 구현한다.
//   품절 상품에 신청해두면, 관리자가 재고를 채워 넣는 순간(재고가 0 이하 -> 양수로 바뀌는 순간) 알림이 생성되고,
//   신청은 1회성으로 자동 해제된다(다시 품절되면 재신청 필요 - 재입고를 계속 알림받고 싶다면 매번 다시 신청).
// ============================================

// 재고가 0 이하 -> 양수로 바뀔 때 호출되어, 해당 상품에 재입고 알림을 신청해둔 회원들에게 알림을 생성하고
// 신청을 정리한다(1회성 알림이므로 알림을 보낸 신청 건은 삭제). 실패해도 재고 처리 자체를 막지 않는다(best-effort).
async function triggerRestockNotifications(productId) {
  try {
    const { data: subs, error: subsErr } = await supabase
      .from('restock_subscriptions_with')
      .select('id, user_id')
      .eq('product_id', productId);
    if (subsErr || !subs || subs.length === 0) return;

    const { data: product } = await supabase.from('products_with').select('id, name').eq('id', productId).maybeSingle();
    const productName = product ? product.name : '상품';

    const notifRows = subs.map(s => ({
      user_id: s.user_id,
      type: 'restock',
      title: '재입고 알림',
      message: `신청하신 "${productName}"이(가) 재입고되었습니다!`,
      link: `/product/${productId}`
    }));
    await supabase.from('notifications_with').insert(notifRows);
    await supabase.from('restock_subscriptions_with').delete().eq('product_id', productId);
  } catch (err) {
    console.error('Error triggering restock notifications:', err);
  }
}

// 재입고 알림 신청 (품절 상품에만 신청 가능 - 재고가 있으면 바로 구매하면 되므로)
app.post('/api/products/:id/restock-notify', authenticate, async (req, res) => {
  try {
    const { data: product, error: productErr } = await supabase
      .from('products_with')
      .select('id, name, stock')
      .eq('id', req.params.id)
      .maybeSingle();
    if (productErr) throw productErr;
    if (!product) return res.status(404).json({ error: 'Not Found', message: '상품을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (Number(product.stock) > 0) {
      return res.status(400).json({ error: 'Bad Request', message: '현재 재고가 있는 상품입니다. 바로 구매해주세요!', timestamp: new Date().toISOString() });
    }

    const { data, error } = await supabase
      .from('restock_subscriptions_with')
      .upsert({ product_id: req.params.id, user_id: req.user.id }, { onConflict: 'product_id,user_id', ignoreDuplicates: true })
      .select()
      .maybeSingle();
    if (error) throw error;

    res.status(201).json({ success: true, data, message: '재입고되면 알림을 보내드릴게요', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error subscribing restock notification:', err);
    res.status(500).json({ error: 'Failed to subscribe restock notification', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 재입고 알림 신청 취소
app.delete('/api/products/:id/restock-notify', authenticate, async (req, res) => {
  try {
    const { error } = await supabase
      .from('restock_subscriptions_with')
      .delete()
      .eq('user_id', req.user.id)
      .eq('product_id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: '재입고 알림 신청을 취소했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error unsubscribing restock notification:', err);
    res.status(500).json({ error: 'Failed to unsubscribe restock notification', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 내가 신청해둔 재입고 알림 목록 (마이페이지에서 확인/취소용)
app.get('/api/me/restock-notifications', authenticate, async (req, res) => {
  try {
    const { data: subs, error } = await supabase
      .from('restock_subscriptions_with')
      .select('id, product_id, created_at')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    if (error) throw error;

    const productIds = (subs || []).map(s => s.product_id);
    let products = [];
    if (productIds.length > 0) {
      const { data: productRows } = await supabase.from('products_with').select('id, name, stock, images_urls').in('id', productIds);
      products = productRows || [];
    }
    const byId = {}; products.forEach(p => { byId[p.id] = p; });
    const result = (subs || []).map(s => ({ subscription_id: s.id, subscribed_at: s.created_at, product: byId[s.product_id] || null })).filter(r => r.product);

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching restock notifications:', err);
    res.status(500).json({ error: 'Failed to fetch restock notifications', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 내 알림함 (재입고 알림 등 - 앞으로 다른 유형의 알림도 이 테이블/API를 함께 사용할 수 있도록 범용으로 설계)
app.get('/api/me/notifications', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('notifications_with')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(50);
    if (error) throw error;
    res.json({ success: true, data: data || [], unread_count: (data || []).filter(n => !n.is_read).length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching notifications:', err);
    res.status(500).json({ error: 'Failed to fetch notifications', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.patch('/api/me/notifications/:id/read', authenticate, async (req, res) => {
  try {
    const { error } = await supabase
      .from('notifications_with')
      .update({ is_read: true })
      .eq('id', req.params.id)
      .eq('user_id', req.user.id);
    if (error) throw error;
    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error marking notification read:', err);
    res.status(500).json({ error: 'Failed to update notification', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/me/notifications/read-all', authenticate, async (req, res) => {
  try {
    const { error } = await supabase
      .from('notifications_with')
      .update({ is_read: true })
      .eq('user_id', req.user.id)
      .eq('is_read', false);
    if (error) throw error;
    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error marking all notifications read:', err);
    res.status(500).json({ error: 'Failed to update notifications', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🔄 정기배송(구독) — 신청/일정 관리만 (자동결제/자동주문생성은 범위 밖)
// - 카페24 관리자에 있던 "정기배송(결제)" 기능을 확인하고, 형님과 논의한 결과 이번 라운드는
//   "일단 신청/일정 관리 기능만" 구현하기로 범위를 정했다. 즉, 회원이 상품+수량+배송주기+배송지를
//   등록해두면 "다음 배송 예정일"이 자동으로 계산/관리되고, 관리자가 그 일정을 보고 발송을 처리하면
//   다음 예정일로 넘어가는 것까지만 한다. 실제 결제(카드 자동청구)나 주문(orders) 자동 생성은
//   하지 않는다 — 정직하게 범위 밖으로 남겨둔다(주석으로 명시).
// ============================================
const SUBSCRIPTION_CYCLE_DAYS = [7, 14, 30, 60];
const SUBSCRIPTION_STATUSES = ['active', 'paused', 'cancelled'];

function addDaysToDateString(dateStr, days) {
  const d = new Date(dateStr + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + Number(days));
  return d.toISOString().slice(0, 10);
}

// 정기배송 신청 (구독 가능 상품으로 표시된 상품만)
app.post('/api/subscriptions', authenticate, async (req, res) => {
  try {
    const { product_id, quantity, cycle_days, shipping_address_id, recipient_name, recipient_phone, postal_code, address, address_detail, memo } = req.body;

    if (!product_id) {
      return res.status(400).json({ error: 'Bad Request', message: '상품을 선택해주세요', timestamp: new Date().toISOString() });
    }
    if (!SUBSCRIPTION_CYCLE_DAYS.includes(Number(cycle_days))) {
      return res.status(400).json({ error: 'Bad Request', message: '배송 주기가 올바르지 않습니다', timestamp: new Date().toISOString() });
    }
    const qty = parseInt(quantity, 10);
    if (!Number.isFinite(qty) || qty < 1 || qty > 99) {
      return res.status(400).json({ error: 'Bad Request', message: '수량은 1~99개 사이여야 합니다', timestamp: new Date().toISOString() });
    }

    const { data: product, error: productErr } = await supabase
      .from('products_with')
      .select('id, name, status, subscription_available')
      .eq('id', product_id)
      .maybeSingle();
    if (productErr) throw productErr;
    if (!product || product.status !== 'active') {
      return res.status(404).json({ error: 'Not Found', message: '상품을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    if (!product.subscription_available) {
      return res.status(400).json({ error: 'Bad Request', message: '정기배송을 지원하지 않는 상품입니다', timestamp: new Date().toISOString() });
    }

    // 배송지: 저장된 배송지를 지정하면 그 정보를 그대로 스냅샷으로 복사해서 저장한다
    // (나중에 배송지를 수정/삭제해도 이미 등록된 구독의 배송정보는 바뀌지 않도록 하기 위함).
    let addressFields;
    if (shipping_address_id) {
      const { data: savedAddr } = await supabase
        .from('shipping_addresses_with')
        .select('*')
        .eq('id', shipping_address_id)
        .eq('user_id', req.user.id)
        .maybeSingle();
      if (!savedAddr) {
        return res.status(400).json({ error: 'Bad Request', message: '선택하신 배송지를 찾을 수 없습니다', timestamp: new Date().toISOString() });
      }
      addressFields = {
        shipping_address_id: savedAddr.id,
        recipient_name: savedAddr.receiver_name,
        recipient_phone: savedAddr.receiver_phone,
        postal_code: savedAddr.postal_code || null,
        address: savedAddr.address,
        address_detail: savedAddr.address_detail || null
      };
    } else {
      if (!recipient_name || !String(recipient_name).trim() || !recipient_phone || !String(recipient_phone).trim() || !address || !String(address).trim()) {
        return res.status(400).json({ error: 'Bad Request', message: '받는 분 성함/연락처/주소를 입력해주세요', timestamp: new Date().toISOString() });
      }
      addressFields = {
        shipping_address_id: null,
        recipient_name: String(recipient_name).trim(),
        recipient_phone: String(recipient_phone).trim(),
        postal_code: postal_code ? String(postal_code).trim() : null,
        address: String(address).trim(),
        address_detail: address_detail ? String(address_detail).trim() : null
      };
    }

    const { data, error } = await supabase
      .from('product_subscriptions_with')
      .insert([{
        user_id: req.user.id,
        product_id,
        quantity: qty,
        cycle_days: Number(cycle_days),
        ...addressFields,
        status: 'active',
        next_delivery_date: addDaysToDateString(todayDateString(), Number(cycle_days)),
        memo: memo ? String(memo).trim() : null
      }])
      .select()
      .single();
    if (error) throw error;

    res.status(201).json({ success: true, data, message: `정기배송 신청이 완료되었습니다. 다음 배송 예정일: ${data.next_delivery_date}`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating subscription:', err);
    res.status(500).json({ error: 'Failed to create subscription', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 내 정기배송 목록
app.get('/api/me/subscriptions', authenticate, async (req, res) => {
  try {
    const { data: subs, error } = await supabase
      .from('product_subscriptions_with')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    if (error) throw error;

    const productIds = [...new Set((subs || []).map(s => s.product_id))];
    let products = [];
    if (productIds.length > 0) {
      const { data: productRows } = await supabase.from('products_with').select('id, name, images_urls, price, discount_price').in('id', productIds);
      products = productRows || [];
    }
    const byId = {}; products.forEach(p => { byId[p.id] = p; });
    const result = (subs || []).map(s => ({ ...s, product: byId[s.product_id] || null }));

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching subscriptions:', err);
    res.status(500).json({ error: 'Failed to fetch subscriptions', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 내 정기배송 수정 (수량/주기/상태(일시중지·재개)/배송지) - 취소된 구독은 수정 불가
app.patch('/api/me/subscriptions/:id', authenticate, async (req, res) => {
  try {
    const { data: existing, error: findErr } = await supabase
      .from('product_subscriptions_with')
      .select('id, user_id, status, cycle_days')
      .eq('id', req.params.id)
      .maybeSingle();
    if (findErr) throw findErr;
    if (!existing || existing.user_id !== req.user.id) {
      return res.status(404).json({ error: 'Not Found', message: '정기배송 신청을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    if (existing.status === 'cancelled') {
      return res.status(400).json({ error: 'Bad Request', message: '취소된 정기배송은 수정할 수 없습니다', timestamp: new Date().toISOString() });
    }

    const { quantity, cycle_days, status, shipping_address_id, recipient_name, recipient_phone, postal_code, address, address_detail } = req.body;
    const updates = { updated_at: new Date().toISOString() };

    if (quantity !== undefined) {
      const qty = parseInt(quantity, 10);
      if (!Number.isFinite(qty) || qty < 1 || qty > 99) {
        return res.status(400).json({ error: 'Bad Request', message: '수량은 1~99개 사이여야 합니다', timestamp: new Date().toISOString() });
      }
      updates.quantity = qty;
    }
    if (cycle_days !== undefined) {
      if (!SUBSCRIPTION_CYCLE_DAYS.includes(Number(cycle_days))) {
        return res.status(400).json({ error: 'Bad Request', message: '배송 주기가 올바르지 않습니다', timestamp: new Date().toISOString() });
      }
      updates.cycle_days = Number(cycle_days);
    }
    if (status !== undefined) {
      if (!['active', 'paused'].includes(status)) {
        return res.status(400).json({ error: 'Bad Request', message: '상태값이 올바르지 않습니다 (취소는 별도 API를 사용해주세요)', timestamp: new Date().toISOString() });
      }
      updates.status = status;
    }
    if (shipping_address_id !== undefined && shipping_address_id) {
      const { data: savedAddr } = await supabase
        .from('shipping_addresses_with')
        .select('*')
        .eq('id', shipping_address_id)
        .eq('user_id', req.user.id)
        .maybeSingle();
      if (!savedAddr) {
        return res.status(400).json({ error: 'Bad Request', message: '선택하신 배송지를 찾을 수 없습니다', timestamp: new Date().toISOString() });
      }
      updates.shipping_address_id = savedAddr.id;
      updates.recipient_name = savedAddr.receiver_name;
      updates.recipient_phone = savedAddr.receiver_phone;
      updates.postal_code = savedAddr.postal_code || null;
      updates.address = savedAddr.address;
      updates.address_detail = savedAddr.address_detail || null;
    } else if (recipient_name !== undefined || recipient_phone !== undefined || address !== undefined) {
      if (!recipient_name || !String(recipient_name).trim() || !recipient_phone || !String(recipient_phone).trim() || !address || !String(address).trim()) {
        return res.status(400).json({ error: 'Bad Request', message: '받는 분 성함/연락처/주소를 입력해주세요', timestamp: new Date().toISOString() });
      }
      updates.shipping_address_id = null;
      updates.recipient_name = String(recipient_name).trim();
      updates.recipient_phone = String(recipient_phone).trim();
      updates.postal_code = postal_code ? String(postal_code).trim() : null;
      updates.address = String(address).trim();
      updates.address_detail = address_detail ? String(address_detail).trim() : null;
    }

    const { data, error } = await supabase
      .from('product_subscriptions_with')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json({ success: true, data, message: '정기배송 신청이 수정되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating subscription:', err);
    res.status(500).json({ error: 'Failed to update subscription', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 내 정기배송 취소
app.delete('/api/me/subscriptions/:id', authenticate, async (req, res) => {
  try {
    const { data: existing, error: findErr } = await supabase
      .from('product_subscriptions_with')
      .select('id, user_id, status')
      .eq('id', req.params.id)
      .maybeSingle();
    if (findErr) throw findErr;
    if (!existing || existing.user_id !== req.user.id) {
      return res.status(404).json({ error: 'Not Found', message: '정기배송 신청을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    if (existing.status === 'cancelled') {
      return res.status(400).json({ error: 'Bad Request', message: '이미 취소된 정기배송입니다', timestamp: new Date().toISOString() });
    }

    const { error } = await supabase
      .from('product_subscriptions_with')
      .update({ status: 'cancelled', cancelled_at: new Date().toISOString() })
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: '정기배송이 취소되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error cancelling subscription:', err);
    res.status(500).json({ error: 'Failed to cancel subscription', message: err.message, timestamp: new Date().toISOString() });
  }
});

// [관리자] 전체 정기배송 목록 - 상태/발송기한 도래 여부로 필터링 가능
app.get('/api/admin/subscriptions', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    let query = supabase.from('product_subscriptions_with').select('*').order('next_delivery_date', { ascending: true });
    if (req.query.status && SUBSCRIPTION_STATUSES.includes(req.query.status)) {
      query = query.eq('status', req.query.status);
    }
    if (req.query.due === 'true') {
      query = query.eq('status', 'active').lte('next_delivery_date', todayDateString());
    }
    const { data: subs, error } = await query;
    if (error) throw error;

    const productIds = [...new Set((subs || []).map(s => s.product_id))];
    const userIds = [...new Set((subs || []).map(s => s.user_id))];
    const [{ data: products }, { data: profiles }] = await Promise.all([
      productIds.length > 0 ? supabase.from('products_with').select('id, name').in('id', productIds) : Promise.resolve({ data: [] }),
      userIds.length > 0 ? supabase.from('profiles').select('id, email').in('id', userIds) : Promise.resolve({ data: [] })
    ]);
    const productById = {}; (products || []).forEach(p => { productById[p.id] = p; });
    const profileById = {}; (profiles || []).forEach(p => { profileById[p.id] = p; });

    const result = (subs || []).map(s => ({
      ...s,
      product: productById[s.product_id] || null,
      member_email: (profileById[s.user_id] || {}).email || null
    }));

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin subscriptions:', err);
    res.status(500).json({ error: 'Failed to fetch subscriptions', message: err.message, timestamp: new Date().toISOString() });
  }
});

// [관리자] 정기배송 발송 처리 — 이번 회차를 "처리완료"로 기록하고 다음 배송 예정일로 넘긴다.
// 정직하게 밝히자면: 실제 주문(orders) 생성이나 결제 청구는 하지 않는다(이번 라운드 범위 밖 - 신청/일정 관리만).
app.post('/api/admin/subscriptions/:id/process', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: sub, error: findErr } = await supabase
      .from('product_subscriptions_with')
      .select('*')
      .eq('id', req.params.id)
      .maybeSingle();
    if (findErr) throw findErr;
    if (!sub) return res.status(404).json({ error: 'Not Found', message: '정기배송 신청을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (sub.status !== 'active') {
      return res.status(400).json({ error: 'Bad Request', message: '일시중지/취소된 정기배송은 발송 처리할 수 없습니다', timestamp: new Date().toISOString() });
    }

    const scheduledDate = sub.next_delivery_date;
    const nextDate = addDaysToDateString(scheduledDate, sub.cycle_days);

    const { error: logErr } = await supabase.from('subscription_delivery_logs_with').insert([{
      subscription_id: sub.id,
      scheduled_date: scheduledDate,
      processed_by: req.user.id,
      quantity: sub.quantity,
      note: req.body && req.body.note ? String(req.body.note).trim() : null
    }]);
    if (logErr) throw logErr;

    const { data, error } = await supabase
      .from('product_subscriptions_with')
      .update({ next_delivery_date: nextDate, last_delivered_at: new Date().toISOString(), updated_at: new Date().toISOString() })
      .eq('id', sub.id)
      .select()
      .single();
    if (error) throw error;

    res.json({ success: true, data, message: `발송 처리되었습니다. 다음 배송 예정일: ${nextDate}`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error processing subscription:', err);
    res.status(500).json({ error: 'Failed to process subscription', message: err.message, timestamp: new Date().toISOString() });
  }
});

// [관리자] 특정 정기배송의 발송 이력
app.get('/api/admin/subscriptions/:id/logs', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('subscription_delivery_logs_with')
      .select('*')
      .eq('subscription_id', req.params.id)
      .order('processed_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching subscription logs:', err);
    res.status(500).json({ error: 'Failed to fetch subscription logs', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🎯 개인화 추천 (쇼핑 큐레이션)
// - 지금까지 홈 화면의 "추천 상품" 섹션은 사실 개인화가 전혀 안 되어 있었다(그냥 최신 등록순 - 방문자가
//   누구든 항상 똑같은 목록). 정직하게 밝히고, 이번에 실제로 구매 이력·찜 목록 기반의 개인화 추천으로
//   교체한다. 별도 AI/외부 API 없이, 회원이 관심을 보인 카테고리에 가중치를 줘서 순위를 매기는
//   규칙 기반 추천이다 — 신규 회원(구매/찜 이력이 전혀 없음)에게는 정직하게 "인기 상품"으로 대체한다.
// - 상품 상세페이지에는 "함께 구매한 상품"(동시구매 분석)을 추가한다. 별도 라인아이템 테이블이 없어
//   (공급사별 판매 리포트와 동일하게) orders_with.items JSON을 직접 분석해서 계산한다.
// ============================================

// 판매량 기준 베스트셀러 상품 (개인화 신호가 없는 회원/비회원에게 정직한 대체 추천으로 사용)
async function getBestsellingProducts(limit, excludeIds) {
  const { data: orders } = await supabase
    .from('orders_with')
    .select('items')
    .not('status', 'in', '(cancelled,refunded)')
    .order('created_at', { ascending: false })
    .limit(1000);

  const salesCount = {};
  (orders || []).forEach(o => {
    (Array.isArray(o.items) ? o.items : []).forEach(item => {
      if (!item.product_id) return;
      salesCount[item.product_id] = (salesCount[item.product_id] || 0) + Number(item.quantity || 1);
    });
  });

  const soldIds = Object.keys(salesCount)
    .filter(id => !excludeIds || !excludeIds.has(id))
    .sort((a, b) => salesCount[b] - salesCount[a])
    .slice(0, limit);

  if (soldIds.length === 0) return { data: [], basis: 'newest' };

  const { data: products } = await supabase.from('products_with').select(PRODUCT_SAFE_COLUMNS).in('id', soldIds).eq('status', 'active');
  const byId = {}; (products || []).forEach(p => { byId[p.id] = p; });
  const ordered = soldIds.map(id => byId[id]).filter(Boolean);
  return { data: ordered, basis: 'bestseller' };
}

// 개인화 추천 1단계: 구매(5) + 장바구니담음-미구매(3) + 찜(2) + 리뷰작성(2) + 클릭-30초이상체류(1.5)
// + 클릭(0.5) - 장바구니삭제-미구매(-1) 다섯(+2) 개 신호를 카테고리 단위로 합산해 관심 카테고리를 산출하고,
// 그 카테고리의 (아직 사지 않은) 상품을 추천한다. 신호가 전혀 없으면 정직하게 베스트셀러로 대체한다.
// (설계 근거: WITH+_개인화추천_알고리즘_고도화_제안서.md 3-2절 가중치 표)
const RECO_WEIGHTS = {
  purchase: 5,
  cartAddUnpurchased: 3,
  wishlist: 2,
  review: 2,
  viewLongDwell: 1.5,
  view: 0.5,
  cartRemoveUnpurchased: -1,
  // 실시간 개인화(제안서 5절 "세션 내 즉각 반영") - 이번 세션에서 방금 본 상품에 주는 가중치.
  // viewLongDwell과 같은 크기로 둔다 - "방금, 지금" 봤다는 즉시성 자체가 진지하게 살펴본 것과 비슷한 무게의 신호이기 때문.
  sessionRecent: 1.5
};
// 클라이언트가 한 번에 보낼 수 있는 "이번 세션에서 본 상품" 개수 상한 - 남용/과도한 쿼리 부하 방지
const SESSION_RECENT_IDS_MAX = 5;
function parseSessionRecentIds(raw) {
  if (!raw) return [];
  return String(raw).split(',').map(s => s.trim()).filter(Boolean).slice(0, SESSION_RECENT_IDS_MAX);
}
const RECO_INTERACTION_WINDOW_DAYS = 90; // 오래된 클릭/장바구니 이력은 지금 관심사를 대표하지 못하므로 최근 90일만 반영
const RECO_LONG_DWELL_MS = 30000;

// 2단계: 브랜드 선호 + 가격대 선호 (제안서 4절)
// 브랜드는 카테고리와 같은 5개 신호·같은 가중치를 그대로 재사용하되, 카테고리보다 약한 보조 신호로 두기 위해
// BRAND_WEIGHT_SCALE만큼 낮춰 합산한다(브랜드 데이터가 아직 일부 상품에만 채워져 있어 - 브랜드 없는 상품은 이 신호에서 완전히 제외됨).
const BRAND_WEIGHT_SCALE = 0.6;
// 가격대 선호는 회원이 관심을 보인 상품들의 가격 분포(평균±표준편차) 안에 드는 후보에 소폭 가산점을 주는 방식으로,
// 카테고리/브랜드 신호를 뒤집지 않는 "미세 조정" 수준으로만 반영한다.
const PRICE_RANGE_MATCH_BONUS = 1;
const PRICE_RANGE_FALLBACK_RATIO = 0.3; // 가격 데이터가 1개뿐이라 표준편차를 구할 수 없을 때 ±30%를 대신 사용

// 신호 수집(기록)과 추천 계산(사용)을 분리하는 설계 원칙에 따라, 회원의 5개 행동 신호를 모아
// 카테고리 가중치로 변환하는 부분을 공용 함수로 뽑아둔다 - /api/me/recommendations와
// /api/me/home-sections(섹션형 홈 화면)가 이 계산 결과를 함께 재사용한다.
async function getPersonalizedSignals(userId, opts = {}) {
  const sessionRecentIds = new Set((opts.sessionRecentIds || []).map(String));
  const sinceIso = new Date(Date.now() - RECO_INTERACTION_WINDOW_DAYS * 24 * 60 * 60 * 1000).toISOString();

  const [{ data: orders }, { data: wishlistRows }, { data: interactionRows }, { data: reviewRows }] = await Promise.all([
    supabase.from('orders_with').select('items, created_at').eq('user_id', userId).not('status', 'in', '(cancelled,refunded)').order('created_at', { ascending: true }),
    supabase.from('wishlist_with').select('product_id').eq('user_id', userId),
    supabase.from('product_interactions_with').select('product_id, event_type, dwell_ms').eq('user_id', userId).gte('created_at', sinceIso),
    supabase.from('product_reviews').select('product_id').eq('user_id', userId)
  ]);

  const purchasedProductIds = new Set();
  // 상품별 구매 이력(수량 무관, 주문건 단위 날짜)을 모아둔다 - 재구매 주기 계산(3-4절)에 사용
  const purchaseDatesByProduct = {};
  (orders || []).forEach(o => (Array.isArray(o.items) ? o.items : []).forEach(it => {
    if (!it.product_id) return;
    const pid = String(it.product_id);
    purchasedProductIds.add(pid);
    if (!purchaseDatesByProduct[pid]) purchaseDatesByProduct[pid] = [];
    purchaseDatesByProduct[pid].push(o.created_at);
  }));
  const wishlistProductIds = new Set((wishlistRows || []).map(w => String(w.product_id)));
  const reviewedProductIds = new Set((reviewRows || []).map(r => String(r.product_id)));

  // 클릭/장바구니 이력은 상품별로 묶어 "본 적 있는지", "30초 이상 봤는지", "담았다가 뺐는지"를 판단한다.
  const viewedProductIds = new Set();
  const longDwellProductIds = new Set();
  const cartAddedProductIds = new Set();
  const cartRemovedProductIds = new Set();
  (interactionRows || []).forEach(ev => {
    const pid = String(ev.product_id);
    if (ev.event_type === 'view') viewedProductIds.add(pid);
    if (ev.event_type === 'view_end' && Number(ev.dwell_ms) >= RECO_LONG_DWELL_MS) longDwellProductIds.add(pid);
    if (ev.event_type === 'cart_add') cartAddedProductIds.add(pid);
    if (ev.event_type === 'cart_remove') cartRemovedProductIds.add(pid);
  });

  const ownedIds = new Set([...purchasedProductIds, ...wishlistProductIds]);
  const allSignalIds = new Set([
    ...purchasedProductIds, ...wishlistProductIds, ...reviewedProductIds,
    ...viewedProductIds, ...longDwellProductIds, ...cartAddedProductIds, ...cartRemovedProductIds,
    ...sessionRecentIds
  ]);

  let categoryOf = {};
  let brandOf = {};
  let priceOf = {};
  if (allSignalIds.size > 0) {
    const { data: signalProducts } = await supabase.from('products_with').select('id, category, brand, price').in('id', [...allSignalIds]);
    (signalProducts || []).forEach(p => {
      categoryOf[p.id] = p.category;
      if (p.brand) brandOf[p.id] = p.brand;
      priceOf[p.id] = Number(p.price);
    });
  }

  // 화면 예시(3-3절) 1번 섹션 "관심 있어 하는 상품"은 구매/찜이 아니라 순수하게 "최근 클릭/체류"만 반영한다.
  const browseCategoryWeight = {};
  const addBrowseWeight = (id, weight) => {
    const cat = categoryOf[id];
    if (cat) browseCategoryWeight[cat] = (browseCategoryWeight[cat] || 0) + weight;
  };
  longDwellProductIds.forEach(id => addBrowseWeight(id, RECO_WEIGHTS.viewLongDwell));
  viewedProductIds.forEach(id => { if (!longDwellProductIds.has(id)) addBrowseWeight(id, RECO_WEIGHTS.view); });

  // 2번 섹션 "회원님을 위한 추천"용 - 5개 신호를 모두 합산한 전체 가중치
  const categoryWeight = {};
  const addWeight = (id, weight) => {
    const cat = categoryOf[id];
    if (cat) categoryWeight[cat] = (categoryWeight[cat] || 0) + weight;
  };
  purchasedProductIds.forEach(id => addWeight(id, RECO_WEIGHTS.purchase));
  wishlistProductIds.forEach(id => addWeight(id, RECO_WEIGHTS.wishlist));
  reviewedProductIds.forEach(id => addWeight(id, RECO_WEIGHTS.review));
  cartAddedProductIds.forEach(id => { if (!purchasedProductIds.has(id)) addWeight(id, RECO_WEIGHTS.cartAddUnpurchased); });
  cartRemovedProductIds.forEach(id => { if (!purchasedProductIds.has(id)) addWeight(id, RECO_WEIGHTS.cartRemoveUnpurchased); });
  longDwellProductIds.forEach(id => addWeight(id, RECO_WEIGHTS.viewLongDwell));
  viewedProductIds.forEach(id => { if (!longDwellProductIds.has(id)) addWeight(id, RECO_WEIGHTS.view); });

  // 브랜드 선호 - 카테고리와 완전히 같은 계산이지만 브랜드 값이 있는 상품만 대상으로 하고, 최종 합산 시 약하게(BRAND_WEIGHT_SCALE) 반영한다
  const brandWeight = {};
  const addBrandWeight = (id, weight) => {
    const brand = brandOf[id];
    if (brand) brandWeight[brand] = (brandWeight[brand] || 0) + weight;
  };
  purchasedProductIds.forEach(id => addBrandWeight(id, RECO_WEIGHTS.purchase));
  wishlistProductIds.forEach(id => addBrandWeight(id, RECO_WEIGHTS.wishlist));
  reviewedProductIds.forEach(id => addBrandWeight(id, RECO_WEIGHTS.review));
  cartAddedProductIds.forEach(id => { if (!purchasedProductIds.has(id)) addBrandWeight(id, RECO_WEIGHTS.cartAddUnpurchased); });
  cartRemovedProductIds.forEach(id => { if (!purchasedProductIds.has(id)) addBrandWeight(id, RECO_WEIGHTS.cartRemoveUnpurchased); });
  longDwellProductIds.forEach(id => addBrandWeight(id, RECO_WEIGHTS.viewLongDwell));
  viewedProductIds.forEach(id => { if (!longDwellProductIds.has(id)) addBrandWeight(id, RECO_WEIGHTS.view); });

  // 실시간 개인화(제안서 5절 "세션 내 즉각 반영") - 클라이언트가 이번 세션에서 방금 본 상품 ID를 함께 보내오면,
  // 서버 이력(product_interactions_with)에 아직 반영되지 않았어도(네트워크 지연/유실, view_end 발생 전 이탈 등)
  // 곧바로 신호에 포함시킨다. 이미 기록된 조회 이력과 별개로 항상 더해준다 - "방금 봤다"는 즉시성 자체가 신호이기 때문.
  sessionRecentIds.forEach(id => {
    addBrowseWeight(id, RECO_WEIGHTS.sessionRecent);
    addWeight(id, RECO_WEIGHTS.sessionRecent);
    addBrandWeight(id, RECO_WEIGHTS.sessionRecent);
  });

  // 가격대 선호 - 관심을 보인 상품들의 가격 평균±표준편차로 "이 회원이 대략 이 가격대를 본다"는 범위를 구한다.
  // 데이터가 1개뿐이면 표준편차가 0이 되어 범위가 너무 좁아지므로, 그럴 땐 ±30%를 대신 사용한다.
  let priceRange = null;
  const signalPrices = [...allSignalIds].map(id => priceOf[id]).filter(p => Number.isFinite(p) && p > 0);
  if (signalPrices.length > 0) {
    const mean = signalPrices.reduce((a, b) => a + b, 0) / signalPrices.length;
    const variance = signalPrices.reduce((a, b) => a + (b - mean) * (b - mean), 0) / signalPrices.length;
    const stddev = Math.sqrt(variance);
    const halfRange = stddev > 0 ? stddev : mean * PRICE_RANGE_FALLBACK_RATIO;
    priceRange = { min: Math.max(0, mean - halfRange), max: mean + halfRange };
  }

  return {
    purchasedProductIds, wishlistProductIds, reviewedProductIds, purchaseDatesByProduct,
    viewedProductIds, longDwellProductIds, cartAddedProductIds, cartRemovedProductIds,
    ownedIds, allSignalIds, categoryOf, brandOf, browseCategoryWeight, categoryWeight, brandWeight, priceRange
  };
}

// 카테고리 가중치 맵을 받아 그 카테고리의 활성 상품 중 excludeIds에 없는 것을 점수순으로 추려준다.
// (섹션별로 "카테고리 가중치 → 후보 상품" 변환 로직이 반복되므로 공용 함수로 뽑아둔다)
async function pickProductsByCategoryWeight(categoryWeight, excludeIds, limit) {
  if (!categoryWeight || Object.keys(categoryWeight).length === 0) return [];
  const { data: candidates } = await supabase
    .from('products_with')
    .select(PRODUCT_SAFE_COLUMNS)
    .eq('status', 'active')
    .in('category', Object.keys(categoryWeight));

  return (candidates || [])
    .filter(p => !excludeIds || !excludeIds.has(String(p.id)))
    .map(p => ({ product: p, score: (categoryWeight[p.category] || 0) + Number(p.rating || 0) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map(s => s.product);
}

// "회원님을 위한 추천"용 - 카테고리 가중치에 브랜드 선호(약하게)와 가격대 선호(소폭 가산점)를 더해 점수를 매긴다.
// 브랜드값이 없는 상품/가격 데이터가 없는 회원은 그 부분 가산점이 0이 될 뿐 전체 로직은 그대로 동작한다(정직한 대체).
async function pickPersonalizedProducts(signals, excludeIds, limit) {
  const { categoryWeight, brandWeight, priceRange } = signals;
  if (!categoryWeight || Object.keys(categoryWeight).length === 0) return [];
  const { data: candidates } = await supabase
    .from('products_with')
    .select(PRODUCT_SAFE_COLUMNS)
    .eq('status', 'active')
    .in('category', Object.keys(categoryWeight));

  return (candidates || [])
    .filter(p => !excludeIds || !excludeIds.has(String(p.id)))
    .map(p => {
      let score = (categoryWeight[p.category] || 0) + Number(p.rating || 0);
      if (p.brand && brandWeight && brandWeight[p.brand]) score += brandWeight[p.brand] * BRAND_WEIGHT_SCALE;
      if (priceRange && Number(p.price) >= priceRange.min && Number(p.price) <= priceRange.max) score += PRICE_RANGE_MATCH_BONUS;
      return { product: p, score };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map(s => s.product);
}

// 3단계: 전체 회원 구매 패턴 기반 협업 필터링 (제안서 4절 "다른 회원의 구매 패턴 기반 추천").
// 회원 수가 아직 많지 않은 지금 단계에서는 완전한 회원간 유사도 행렬을 만드는 대신, "내가 구매한 상품들과
// 같은 주문에 함께 담겼던 다른 상품"의 빈도를 전체 주문에서 집계하는 아이템 기반 협업 필터링으로 구현한다.
// (frequently-bought-together와 계산 방식은 같지만, 상품 1개가 아니라 "이 회원이 산 모든 상품"을 기준으로
// 집계하므로 결과적으로 "나와 비슷하게 구매한 다른 회원들이 산 상품"과 같은 효과를 낸다 - 겹치는 상품이
// 많을수록(overlap.length) 더 강한 신호로 취급해, 우연히 1번 같이 산 것보다 여러 번 겹친 상품을 우선한다.)
const COLLABORATIVE_ORDER_SCAN_LIMIT = 1000;
async function pickCollaborativeProducts(purchasedProductIds, excludeIds, limit) {
  if (!purchasedProductIds || purchasedProductIds.size === 0) return [];

  const { data: orders } = await supabase
    .from('orders_with')
    .select('items')
    .not('status', 'in', '(cancelled,refunded)')
    .order('created_at', { ascending: false })
    .limit(COLLABORATIVE_ORDER_SCAN_LIMIT);

  const coScore = {};
  (orders || []).forEach(o => {
    const items = Array.isArray(o.items) ? o.items : [];
    const ids = items.map(it => it.product_id).filter(Boolean).map(String);
    const overlapCount = ids.filter(id => purchasedProductIds.has(id)).length;
    if (overlapCount === 0) return; // 이 주문이 내 구매 이력과 겹치는 상품을 하나도 안 담았으면 신호 없음
    ids.forEach(id => {
      if (purchasedProductIds.has(id)) return; // 이미 산 상품은 추천하지 않는다
      if (excludeIds && excludeIds.has(id)) return;
      coScore[id] = (coScore[id] || 0) + overlapCount;
    });
  });

  const topIds = Object.keys(coScore).sort((a, b) => coScore[b] - coScore[a]).slice(0, limit);
  if (topIds.length === 0) return [];

  const { data: products } = await supabase.from('products_with').select(PRODUCT_SAFE_COLUMNS).in('id', topIds).eq('status', 'active');
  const byId = {}; (products || []).forEach(p => { byId[p.id] = p; });
  return topIds.map(id => byId[id]).filter(Boolean);
}

app.get('/api/me/recommendations', authenticate, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 12, 30);
    const signals = await getPersonalizedSignals(req.user.id, { sessionRecentIds: parseSessionRecentIds(req.query.session_recent_ids) });

    if (signals.allSignalIds.size === 0) {
      const { data, basis } = await getBestsellingProducts(limit, signals.ownedIds);
      return res.json({ success: true, data, basis, timestamp: new Date().toISOString() });
    }

    const scored = await pickPersonalizedProducts(signals, signals.ownedIds, limit);
    if (scored.length === 0) {
      const { data, basis } = await getBestsellingProducts(limit, signals.ownedIds);
      return res.json({ success: true, data, basis, timestamp: new Date().toISOString() });
    }

    res.json({ success: true, data: scored, basis: 'personalized', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error building recommendations:', err);
    res.status(500).json({ error: 'Failed to build recommendations', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 비회원/방문자용 - 지금 잘 팔리는 상품 (인증 불필요)
app.get('/api/recommendations/popular', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 12, 30);
    const { data, basis } = await getBestsellingProducts(limit, null);
    res.json({ success: true, data, basis, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching popular products:', err);
    res.status(500).json({ error: 'Failed to fetch popular products', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 재구매 후보 계산: 2번 이상 산 상품은 평균 구매 간격으로 "예상 재구매일"을 추정하고, 얼마나 임박/지났는지로
// 정렬한다. 1번만 산 상품은 주기를 알 수 없으므로 최근 구매순으로만 정렬해 "다시 구매해보세요" 후보로 쓴다.
// (제안서 3-4절의 재구매 주기 공식과 동일: 평균 구매 간격 = (마지막 구매일 - 첫 구매일) / (구매 횟수 - 1))
function rankRepurchaseCandidates(purchaseDatesByProduct) {
  const now = Date.now();
  const DAY_MS = 24 * 60 * 60 * 1000;
  const repeat = [];
  const singlePurchase = [];
  Object.keys(purchaseDatesByProduct).forEach(pid => {
    const dates = (purchaseDatesByProduct[pid] || []).map(d => new Date(d).getTime()).filter(t => !isNaN(t)).sort((a, b) => a - b);
    if (dates.length === 0) return;
    const last = dates[dates.length - 1];
    if (dates.length >= 2) {
      const first = dates[0];
      const avgIntervalMs = (last - first) / (dates.length - 1);
      const expectedNext = last + avgIntervalMs;
      repeat.push({ productId: pid, purchaseCount: dates.length, expectedNext, daysUntilExpected: (expectedNext - now) / DAY_MS });
    } else {
      singlePurchase.push({ productId: pid, lastPurchasedAt: last });
    }
  });
  // 예상 재구매일이 임박했거나 이미 지난 상품을 우선(오름차순 - 가장 급한 것부터), 그다음 구매 횟수가 많은 순
  repeat.sort((a, b) => a.daysUntilExpected - b.daysUntilExpected || b.purchaseCount - a.purchaseCount);
  singlePurchase.sort((a, b) => b.lastPurchasedAt - a.lastPurchasedAt);
  return { repeat, singlePurchase };
}

// 개인화 홈 화면 - 알고리즘이 바뀌어도(규칙 기반 → AI 등) 화면 쪽을 다시 손대지 않도록,
// 상품 배열이 아니라 { section_key, title, subtitle, products } 섹션 목록으로 응답한다.
// 신호가 부족해 채울 수 없는 섹션은 억지로 채우지 않고 아예 숨긴다(정직한 추천).
// 로그인 여부와 무관하게 호출 가능 - 비로그인/신규 회원은 인기 상품 한 섹션만 내려준다.
app.get('/api/me/home-sections', optionalAuth, async (req, res) => {
  try {
    const sectionLimit = Math.min(parseInt(req.query.limit, 10) || 8, 20);
    const sections = [];

    if (!req.user) {
      const { data } = await getBestsellingProducts(sectionLimit, null);
      if (data.length > 0) sections.push({ section_key: 'popular', title: '🔥 지금 인기 있는 상품', subtitle: '많은 분들이 찾고 있어요', products: data });
      return res.json({ success: true, sections, timestamp: new Date().toISOString() });
    }

    const signals = await getPersonalizedSignals(req.user.id, { sessionRecentIds: parseSessionRecentIds(req.query.session_recent_ids) });

    if (signals.allSignalIds.size === 0) {
      // 완전 신규 회원(구매/찜/클릭 이력 없음) - 정직하게 인기 상품만 노출
      const { data } = await getBestsellingProducts(sectionLimit, null);
      if (data.length > 0) sections.push({ section_key: 'popular', title: '🔥 지금 인기 있는 상품', subtitle: '많은 분들이 찾고 있어요', products: data });
      return res.json({ success: true, sections, timestamp: new Date().toISOString() });
    }

    // 총 가중치(RECO_WEIGHTS 합산)를 공통 단위로 써서 섹션마다 "이 회원에게 얼마나 근거가 강한 섹션인지" 점수를 매긴다.
    // 이 점수로 아래에서 섹션 순서 자체를 회원별로 재배열한다(제안서 6절 "개인화 홈 = 회원마다 다른 화면" 권고 반영).
    const sumWeights = (weightMap) => Object.values(weightMap || {}).reduce((a, b) => a + b, 0);

    // 1) 👀 최근 클릭/체류 기반 관심 상품
    const interestProducts = await pickProductsByCategoryWeight(signals.browseCategoryWeight, signals.ownedIds, sectionLimit);
    if (interestProducts.length > 0) {
      sections.push({ section_key: 'browse_interest', title: '👀 회원님이 관심 있어 하는 상품', subtitle: '최근 살펴보신 상품들과 비슷해요', products: interestProducts, _priority: sumWeights(signals.browseCategoryWeight) });
    }

    // 2) 💄 구매+찜+클릭+장바구니+리뷰 5개 신호를 합산한 개인화 추천 - 신호가 가장 많이 모이는 섹션이라 보통 우선순위가 가장 높다
    const personalizedProducts = await pickPersonalizedProducts(signals, signals.ownedIds, sectionLimit);
    if (personalizedProducts.length > 0) {
      sections.push({ section_key: 'personalized', title: '💄 회원님을 위한 추천', subtitle: '취향에 맞춰 골라봤어요', products: personalizedProducts, _priority: sumWeights(signals.categoryWeight) });
    }

    // 3) 🛒 자주 구매하시는 상품 / 다시 구매하시겠어요? - 재구매 시점이 임박한 상품이 있으면 다른 신호 크기와 무관하게 최상단으로 올린다(긴급도 우선)
    const { repeat, singlePurchase } = rankRepurchaseCandidates(signals.purchaseDatesByProduct);
    const repurchaseOrdered = [...repeat.map(r => r.productId), ...singlePurchase.map(r => r.productId)].slice(0, sectionLimit);
    if (repurchaseOrdered.length > 0) {
      const { data: repurchaseProducts } = await supabase.from('products_with').select(PRODUCT_SAFE_COLUMNS).in('id', repurchaseOrdered).eq('status', 'active');
      const byId = {}; (repurchaseProducts || []).forEach(p => { byId[p.id] = p; });
      const ordered = repurchaseOrdered.map(id => byId[id]).filter(Boolean);
      if (ordered.length > 0) {
        const hasDueSoon = repeat.some(r => r.daysUntilExpected <= 3);
        sections.push({
          section_key: 'repurchase',
          title: hasDueSoon ? '🛒 다시 구매하실 때가 되지 않으셨나요?' : '🛒 자주 구매하시는 상품',
          subtitle: '지난번에 구매하셨던 상품이에요',
          products: ordered,
          _priority: (hasDueSoon ? 1e6 : 0) + repeat.length * RECO_WEIGHTS.purchase + singlePurchase.length * (RECO_WEIGHTS.purchase / 2)
        });
      }
    }

    // 4) 🤝 3단계 - 전체 회원 구매 패턴 기반 협업 필터링("나와 비슷하게 구매한 다른 회원들이 산 상품")
    const collaborativeProducts = await pickCollaborativeProducts(signals.purchasedProductIds, signals.ownedIds, sectionLimit);
    if (collaborativeProducts.length > 0) {
      sections.push({
        section_key: 'collaborative',
        title: '🤝 회원님과 비슷한 분들이 많이 구매한 상품',
        subtitle: '함께 구매했던 다른 회원들의 선택이에요',
        products: collaborativeProducts,
        _priority: Math.min(signals.purchasedProductIds.size, 5) * RECO_WEIGHTS.purchase
      });
    }

    // 5) 🔥 관심 카테고리 중 재고가 적거나 할인 중인 상품(한정수량 특가) - 마케팅성 섹션이라 같은 관심도라도 개인화 섹션보다는 살짝 낮게 둔다
    const interestCategories = Object.keys(signals.categoryWeight).length > 0 ? Object.keys(signals.categoryWeight) : Object.keys(signals.browseCategoryWeight);
    if (interestCategories.length > 0) {
      const { data: dealCandidates } = await supabase
        .from('products_with')
        .select(PRODUCT_SAFE_COLUMNS)
        .eq('status', 'active')
        .in('category', interestCategories)
        .or('stock.lte.20,discount_price.not.is.null');
      const deals = (dealCandidates || [])
        .filter(p => !signals.ownedIds.has(String(p.id)))
        .filter(p => Number(p.stock) <= 20 || (p.discount_price && Number(p.discount_price) < Number(p.price)))
        .sort((a, b) => Number(a.stock || 0) - Number(b.stock || 0))
        .slice(0, sectionLimit);
      if (deals.length > 0) {
        sections.push({ section_key: 'limited_deal', title: '🔥 회원님 취향의 한정수량 특가', subtitle: '얼마 남지 않았어요', products: deals, _priority: sumWeights(signals.categoryWeight) * 0.5 });
      }
    }

    // 신호는 있었지만 (예: 이미 다 구매한 카테고리라) 채울 섹션이 하나도 없는 경우 - 정직하게 인기 상품으로 대체
    if (sections.length === 0) {
      const { data } = await getBestsellingProducts(sectionLimit, signals.ownedIds);
      if (data.length > 0) sections.push({ section_key: 'popular', title: '🔥 지금 인기 있는 상품', subtitle: '많은 분들이 찾고 있어요', products: data, _priority: 0 });
    }

    // 섹션 순서를 관심도(_priority) 내림차순으로 재배열한 뒤, 응답에는 내부 계산용 필드를 노출하지 않는다.
    sections.sort((a, b) => (b._priority || 0) - (a._priority || 0));
    sections.forEach(s => { delete s._priority; });

    res.json({ success: true, sections, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error building home sections:', err);
    res.status(500).json({ error: 'Failed to build home sections', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 상품 상세 - 같은 공급자(판매자 계정, products_with.supplier_id)가 등록한 다른 판매중인 상품 (인증 불필요)
// 공급자가 없는 상품(관리자가 직접 등록한 상품 등)은 supplier: null, data: []로 정직하게 응답한다.
app.get('/api/products/:id/supplier-products', async (req, res) => {
  try {
    const productId = req.params.id;
    const limit = Math.min(parseInt(req.query.limit, 10) || 8, 20);

    const { data: current, error: curErr } = await supabasePublic
      .from('products_with')
      .select('id, supplier_id')
      .eq('id', productId)
      .maybeSingle();
    if (curErr) throw curErr;
    if (!current || !current.supplier_id) {
      return res.json({ success: true, supplier: null, data: [], timestamp: new Date().toISOString() });
    }

    // 공급자 이름은 서비스 롤로만 조회한다 - 공개 API에 email 등 다른 개인정보가 함께 노출되지 않도록 필요한 컬럼만 select
    const [{ data: supplierProfile }, { count: totalCount }, { data: products, error: prodErr }] = await Promise.all([
      supabase.from('profiles').select('id, full_name').eq('id', current.supplier_id).maybeSingle(),
      supabasePublic.from('products_with').select('id', { count: 'exact', head: true }).eq('supplier_id', current.supplier_id).eq('status', 'active'),
      supabasePublic.from('products_with').select(PRODUCT_SAFE_COLUMNS).eq('supplier_id', current.supplier_id).eq('status', 'active').neq('id', productId).order('created_at', { ascending: false }).limit(limit)
    ]);
    if (prodErr) throw prodErr;

    res.json({
      success: true,
      supplier: {
        id: current.supplier_id,
        name: (supplierProfile && supplierProfile.full_name) || '공급사',
        product_count: totalCount || 0
      },
      data: products || [],
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching supplier products:', err);
    res.status(500).json({ error: 'Failed to fetch supplier products', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 상품 상세 - 이 상품과 함께 구매된 상품 (동시구매 분석, 인증 불필요)
app.get('/api/products/:id/frequently-bought-together', async (req, res) => {
  try {
    const productId = req.params.id;
    const limit = Math.min(parseInt(req.query.limit, 10) || 6, 20);

    const { data: orders } = await supabase
      .from('orders_with')
      .select('items')
      .not('status', 'in', '(cancelled,refunded)')
      .order('created_at', { ascending: false })
      .limit(1000);

    const coCounts = {};
    (orders || []).forEach(o => {
      const items = Array.isArray(o.items) ? o.items : [];
      const ids = items.map(it => it.product_id).filter(Boolean);
      if (!ids.includes(productId)) return;
      ids.forEach(id => {
        if (id === productId) return;
        coCounts[id] = (coCounts[id] || 0) + 1;
      });
    });

    const topIds = Object.keys(coCounts).sort((a, b) => coCounts[b] - coCounts[a]).slice(0, limit);
    if (topIds.length === 0) {
      return res.json({ success: true, data: [], timestamp: new Date().toISOString() });
    }

    const { data: products } = await supabase.from('products_with').select(PRODUCT_SAFE_COLUMNS).in('id', topIds).eq('status', 'active');
    const byId = {}; (products || []).forEach(p => { byId[p.id] = p; });
    const ordered = topIds.map(id => byId[id]).filter(Boolean);

    res.json({ success: true, data: ordered, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching frequently-bought-together:', err);
    res.status(500).json({ error: 'Failed to fetch frequently-bought-together', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 상품 상세 - "비슷한 상품" (제안서 4절 "상품 유사도" - 2단계). AI/임베딩 없이 규칙 기반으로:
// 같은 카테고리 + 가격대 ±30% 이내면 가산점, 같은 브랜드면 더 큰 가산점, 평점 차이가 작을수록 가산점.
// "함께 구매한 상품"(frequently-bought-together, 실제 동시구매 이력 기반)과는 성격이 달라 - 이쪽은 주문 이력이
// 전혀 없는 신상품에도 즉시 동작한다(카테고리/가격/브랜드만으로 계산하므로).
app.get('/api/products/:id/similar', async (req, res) => {
  try {
    const productId = req.params.id;
    const limit = Math.min(parseInt(req.query.limit, 10) || 8, 20);

    const { data: base, error: baseErr } = await supabasePublic
      .from('products_with')
      .select('id, category, price, rating, brand')
      .eq('id', productId)
      .maybeSingle();
    if (baseErr) throw baseErr;
    if (!base) return res.json({ success: true, data: [], timestamp: new Date().toISOString() });

    const basePrice = Number(base.price) || 0;
    const priceMin = basePrice * 0.7;
    const priceMax = basePrice * 1.3;
    const baseRating = Number(base.rating || 0);

    const { data: candidates, error: candErr } = await supabasePublic
      .from('products_with')
      .select(PRODUCT_SAFE_COLUMNS)
      .eq('status', 'active')
      .eq('category', base.category)
      .neq('id', productId);
    if (candErr) throw candErr;

    const scored = (candidates || [])
      .map(p => {
        let score = 0;
        const price = Number(p.price) || 0;
        if (basePrice > 0 && price >= priceMin && price <= priceMax) score += 2;
        if (base.brand && p.brand && p.brand === base.brand) score += 3;
        score -= Math.abs(Number(p.rating || 0) - baseRating) * 0.5; // 평점이 비슷할수록 유사(차이가 크면 감점)
        return { product: p, score };
      })
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map(s => s.product);

    res.json({ success: true, data: scored, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching similar products:', err);
    res.status(500).json({ error: 'Failed to fetch similar products', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 가격 비교/최저가 이력 (제안서 6절) - 최근 N일간의 가격 스냅샷과, 지금 가격이 그 기간 최저가인지를 정직하게 알려준다.
// 스냅샷이 하나도 없으면(막 등록된 상품 등) 지금 가격만을 기준으로 "최저가"로 취급한다 - 있지도 않은 과거를 지어내지 않는다.
app.get('/api/products/:id/price-history', async (req, res) => {
  try {
    const productId = req.params.id;
    const days = Math.min(parseInt(req.query.days, 10) || 90, 365);
    const sinceIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

    const { data: product, error: productErr } = await supabasePublic
      .from('products_with')
      .select('price, discount_price')
      .eq('id', productId)
      .maybeSingle();
    if (productErr) throw productErr;
    if (!product) return res.json({ success: true, data: { days, history: [], lowest_price: null, current_price: null, is_lowest: false }, timestamp: new Date().toISOString() });

    const { data: rows, error: historyErr } = await supabasePublic
      .from('product_price_history_with')
      .select('price, discount_price, changed_at')
      .eq('product_id', productId)
      .gte('changed_at', sinceIso)
      .order('changed_at', { ascending: true });
    if (historyErr) throw historyErr;

    const currentEffective = effectivePriceOf(product);
    const historyEffectivePrices = (rows || []).map(r => effectivePriceOf(r));
    const lowestPrice = historyEffectivePrices.length > 0 ? Math.min(...historyEffectivePrices, currentEffective) : currentEffective;

    res.json({
      success: true,
      data: {
        days,
        history: rows || [],
        lowest_price: lowestPrice,
        current_price: currentEffective,
        is_lowest: currentEffective <= lowestPrice
      },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching price history:', err);
    res.status(500).json({ error: 'Failed to fetch price history', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 취소/반품/교환 셀프 신청 API
// - 카페24 관리자의 "취소/교환/반품/환불" 메뉴 구조를 참고해, 기존에 있던 반품/교환 셀프 신청에
//   "취소"(배송 시작 전 주문 취소)를 함께 추가했다. 카페24는 이 넷을 각각 별도 메뉴로 나누지만,
//   WITH+는 하나의 신청 테이블(request_type으로 구분)로 관리하면서 관리자 화면에서는 유형별로 볼 수 있게 했다.
// ============================================
const RETURN_REQUEST_TYPES = ['cancel', 'return', 'exchange'];
const RETURN_REQUEST_STATUSES = ['requested', 'approved', 'rejected', 'completed'];
// 취소는 아직 배송이 시작되지 않은 주문만, 반품/교환은 배송이 완료된 주문만 신청할 수 있다
const CANCELLABLE_ORDER_STATUSES = ['pending', 'paid', 'processing'];

// 내 반품/교환 신청 내역
app.get('/api/me/return-requests', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('return_requests')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    if (error) throw error;

    res.json({ success: true, data: data || [], count: data?.length || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching return requests:', err);
    res.status(500).json({ error: 'Failed to fetch return requests', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 취소/반품/교환 신청 (본인 주문만, 유형별로 신청 가능한 주문 상태가 다름)
app.post('/api/orders/:id/return-request', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { request_type, reason } = req.body;

    if (!RETURN_REQUEST_TYPES.includes(request_type)) {
      return res.status(400).json({ error: 'Bad Request', message: `request_type must be one of: ${RETURN_REQUEST_TYPES.join(', ')}`, timestamp: new Date().toISOString() });
    }
    if (!reason || !reason.trim()) {
      return res.status(400).json({ error: 'Bad Request', message: '신청 사유를 입력해주세요', timestamp: new Date().toISOString() });
    }

    const { data: order, error: orderErr } = await supabase
      .from('orders_with')
      .select('id, user_id, status')
      .eq('id', id)
      .single();
    if (orderErr || !order) {
      return res.status(404).json({ error: 'Not Found', message: '주문을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    }
    if (order.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden', message: '본인 주문만 신청할 수 있습니다', timestamp: new Date().toISOString() });
    }

    if (request_type === 'cancel') {
      if (!CANCELLABLE_ORDER_STATUSES.includes(order.status)) {
        return res.status(400).json({ error: 'Bad Request', message: '배송이 시작되기 전(주문접수/결제완료/준비중) 상태의 주문만 취소 신청이 가능합니다. 이미 배송이 시작됐다면 반품을 이용해주세요', timestamp: new Date().toISOString() });
      }
    } else {
      if (order.status !== 'delivered') {
        return res.status(400).json({ error: 'Bad Request', message: '배송 완료된 주문만 반품/교환 신청이 가능합니다', timestamp: new Date().toISOString() });
      }
    }

    const { data: existing } = await supabase
      .from('return_requests')
      .select('id')
      .eq('order_id', id)
      .in('status', ['requested', 'approved'])
      .maybeSingle();
    if (existing) {
      return res.status(400).json({ error: 'Bad Request', message: '이미 처리 중인 신청이 있습니다', timestamp: new Date().toISOString() });
    }

    const { data, error } = await supabase
      .from('return_requests')
      .insert({ order_id: id, user_id: req.user.id, request_type, reason: reason.trim() })
      .select()
      .single();
    if (error) throw error;

    const typeLabel = request_type === 'cancel' ? '취소' : request_type === 'exchange' ? '교환' : '반품';
    res.status(201).json({ success: true, data, message: `${typeLabel} 신청이 접수되었습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating return request:', err);
    res.status(500).json({ error: 'Failed to create return request', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 전체 반품/교환 신청 조회
app.get('/api/admin/return-requests', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { status } = req.query;
    let query = supabase.from('return_requests').select('*').order('created_at', { ascending: false });
    if (status) query = query.eq('status', status);
    const { data, error } = await query;
    if (error) throw error;

    // 주문 정보(주문번호) 및 회원 이메일을 함께 붙여서 반환
    const orderIds = [...new Set((data || []).map(r => r.order_id))];
    const userIds = [...new Set((data || []).map(r => r.user_id))];
    const [{ data: orders }, { data: profiles }] = await Promise.all([
      orderIds.length ? supabase.from('orders_with').select('id, order_number, final_price').in('id', orderIds) : Promise.resolve({ data: [] }),
      userIds.length ? supabase.from('profiles').select('id, email, full_name').in('id', userIds) : Promise.resolve({ data: [] })
    ]);
    const orderById = {}; (orders || []).forEach(o => { orderById[o.id] = o; });
    const profileById = {}; (profiles || []).forEach(p => { profileById[p.id] = p; });

    const result = (data || []).map(r => ({
      ...r,
      order: orderById[r.order_id] || null,
      requester: profileById[r.user_id] ? { email: profileById[r.user_id].email, full_name: profileById[r.user_id].full_name } : null
    }));

    res.json({ success: true, data: result, count: result.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin return requests:', err);
    res.status(500).json({ error: 'Failed to fetch return requests', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 반품/교환 신청 처리
app.patch('/api/admin/return-requests/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { status, admin_note } = req.body;
    if (status !== undefined && !RETURN_REQUEST_STATUSES.includes(status)) {
      return res.status(400).json({ error: 'Bad Request', message: `status must be one of: ${RETURN_REQUEST_STATUSES.join(', ')}`, timestamp: new Date().toISOString() });
    }

    // 완료 처리 시 재고 복구 + 주문상태 반영을 위해 처리 전 신청 건을 먼저 조회해둔다
    const { data: existingRequest, error: findErr } = await supabase
      .from('return_requests')
      .select('id, order_id, request_type, status')
      .eq('id', req.params.id)
      .maybeSingle();
    if (findErr) throw findErr;
    if (!existingRequest) {
      return res.status(404).json({ error: 'Not Found', message: 'Return request not found', timestamp: new Date().toISOString() });
    }

    const updates = { updated_at: new Date().toISOString() };
    if (status !== undefined) updates.status = status;
    if (admin_note !== undefined) updates.admin_note = admin_note;

    // 완료 처리로 전환하는 요청은 이 UPDATE 자체를 "아직 완료가 아닌 경우에만" 성립하도록 걸어
    // 동시에 두 번 눌리거나(중복 클릭·재시도) 두 관리자가 동시에 처리해도 둘 중 하나만 실제로
    // 반영되게 한다(TOCTOU 경쟁조건 차단 — 위 existingRequest 조회만으로는 두 요청 모두 통과할 수 있었음).
    let updateQuery = supabase.from('return_requests').update(updates).eq('id', req.params.id);
    if (status === 'completed') {
      updateQuery = updateQuery.neq('status', 'completed');
    }
    const { data, error } = await updateQuery.select().maybeSingle();
    if (error) throw error;
    if (!data) {
      // status==='completed' 분기에서 0행 매치는 "존재하지 않음"이 아니라 "동시 요청이 먼저 완료 처리함"을
      // 의미할 수 있으므로, 실제 현재 상태를 다시 조회해 정상 응답으로 돌려준다(재고 이중 복구 방지).
      const { data: current } = await supabase.from('return_requests').select('*').eq('id', req.params.id).maybeSingle();
      if (!current) {
        return res.status(404).json({ error: 'Not Found', message: 'Return request not found', timestamp: new Date().toISOString() });
      }
      return res.json({ success: true, data: current, sideEffect: null, message: '이미 처리된 요청입니다 (중복 처리 방지)', timestamp: new Date().toISOString() });
    }

    // "완료" 처리로 새로 전환되는 순간에만(이미 완료된 건을 다시 저장해도 중복 실행되지 않도록) 실제 재고/주문상태를 반영한다.
    // 취소 = 배송 전 주문 취소 → 재고 복구 + 주문상태 cancelled. 반품 = 배송 후 상품 반송 → 재고 복구 + 주문상태 refunded.
    // 교환은 새 상품으로 맞바꾸는 절차라 재고/주문상태를 자동으로 바꾸지 않고 관리자가 별도로 처리한다(정직하게 여기서는 다루지 않음).
    let sideEffect = null;
    if (status === 'completed' && existingRequest.status !== 'completed' && (existingRequest.request_type === 'cancel' || existingRequest.request_type === 'return')) {
      const { data: order } = await supabase
        .from('orders_with')
        .select('id, items, status')
        .eq('id', existingRequest.order_id)
        .maybeSingle();
      if (order) {
        const items = Array.isArray(order.items) ? order.items : [];
        for (const item of items) {
          if (!item.product_id) continue;
          const qty = Number(item.quantity) || 1;
          try {
            await supabase.rpc('adjust_stock_with', {
              p_product_id: item.product_id,
              p_variant_id: item.variant_id || null,
              p_delta: qty,
              p_reason: `${existingRequest.request_type === 'cancel' ? '주문 취소' : '반품'} 승인에 따른 재고 복구 (신청 ${existingRequest.id})`,
              p_order_id: order.id,
              p_created_by: req.user.id,
              p_scan_source: 'order_restore'
            });
            await supabase.rpc('release_channel_stock', { p_product_id: item.product_id, p_variant_id: item.variant_id || null, p_channel: 'live', p_qty: qty });
          } catch (restoreErr) { /* 재고 복구는 최선을 다해 시도하되, 하나가 실패해도 전체 처리를 막지 않는다 */ }
          if (item.variant_id) await syncProductStockFromVariants(item.product_id);
        }
        const newOrderStatus = existingRequest.request_type === 'cancel' ? 'cancelled' : 'refunded';
        await supabase.from('orders_with').update({ status: newOrderStatus }).eq('id', order.id);
        sideEffect = { order_status: newOrderStatus, stock_restored_items: items.length };
      }
    }

    const typeLabel = existingRequest.request_type === 'cancel' ? '취소' : existingRequest.request_type === 'exchange' ? '교환' : '반품';
    res.json({ success: true, data, sideEffect, message: `${typeLabel} 신청이 처리되었습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating return request:', err);
    res.status(500).json({ error: 'Failed to update return request', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🔍 SEO 기초 — robots.txt / sitemap.xml / 상품·카테고리 페이지 Open Graph + 구조화데이터(JSON-LD)
// 정직하게 짚어드리면, 지금까지 이 셋 다 전혀 없었습니다: robots.txt·sitemap.xml 라우트 자체가
// 없었고, 상품/카테고리 페이지는 완전한 클라이언트 렌더링(SPA) 방식이라 카카오톡/페이스북 등
// 링크 미리보기 봇이나 검색엔진이 실제 상품명·가격·이미지를 전혀 읽지 못하는 상태였습니다.
// (봇들은 대부분 자바스크립트를 실행하지 않고 첫 HTML 응답만 읽기 때문에, 지금까지는 상품을
// 카톡으로 공유해도 "상품 상세 - WITH+"라는 빈 제목만 뜨고 있었습니다.)
// 이번에 상품/카테고리 HTML의 <title> 태그를 요청마다 실제 데이터로 치환해 응답하도록
// 구현했습니다(서버 시작 시 템플릿을 1회만 읽어 캐시해두고, 요청마다 디스크를 다시 읽지 않음).
// ============================================
function escapeHtmlAttr(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
const escapeXml = escapeHtmlAttr;
function getBaseUrl(req) {
  // 도메인이 아직 연결되지 않아 지금은 EC2 IP 기준으로 나오지만, 요청 헤더에서 실제 접속
  // 호스트를 그대로 읽어오므로 나중에 도메인이 연결돼도 코드 변경 없이 자동으로 맞습니다.
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.get('host');
  return `${proto}://${host}`;
}

let PRODUCT_HTML_TEMPLATE = null;
let CATEGORY_HTML_TEMPLATE = null;
try {
  PRODUCT_HTML_TEMPLATE = fs.readFileSync(path.join(__dirname, 'public', 'product.html'), 'utf8');
  CATEGORY_HTML_TEMPLATE = fs.readFileSync(path.join(__dirname, 'public', 'category.html'), 'utf8');
} catch (e) {
  console.error('SEO용 HTML 템플릿 캐시 로드 실패 (SEO 메타태그 없이도 페이지 자체는 정상 동작합니다):', e.message);
}

app.get('/robots.txt', (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.type('text/plain').send(
`User-agent: *
Allow: /
Disallow: /admin
Disallow: /mypage
Disallow: /cart
Disallow: /api/

Sitemap: ${baseUrl}/sitemap.xml
`);
});

app.get('/sitemap.xml', async (req, res) => {
  try {
    const baseUrl = getBaseUrl(req);
    const nowDate = new Date().toISOString();
    const urls = [];

    // 정적 페이지 (검색/커뮤니티/로그인/가입 + 푸터 하위 정보 페이지)
    const staticSlugs = ['about', 'careers', 'press', 'sustainability', 'support', 'faq', 'contact',
      'returns', 'terms', 'privacy', 'cookie', 'guides', 'partner', 'seller', 'affiliate'];
    urls.push({ loc: `${baseUrl}/`, lastmod: nowDate, priority: '1.0' });
    ['/search', '/communities', '/login', '/join'].forEach(p => urls.push({ loc: `${baseUrl}${p}`, lastmod: nowDate, priority: '0.5' }));
    staticSlugs.forEach(slug => urls.push({ loc: `${baseUrl}/${slug}`, lastmod: nowDate, priority: '0.3' }));

    // 노출 중(is_active)인 카테고리
    const { data: categories, error: categoriesErr } = await supabasePublic
      .from('categories')
      .select('slug, updated_at')
      .eq('is_active', true);
    if (categoriesErr) {
      console.error('sitemap.xml: 카테고리 목록 조회 실패, 카테고리 URL 없이 생성됨:', categoriesErr.message);
    }
    (categories || []).forEach(c => {
      urls.push({ loc: `${baseUrl}/category/${c.slug}`, lastmod: c.updated_at || nowDate, priority: '0.7' });
    });

    // 판매중(active) 상품 - 사이트맵 표준 상한(5만 건)까지만 포함하고, 넘으면 정직하게 로그로 남김
    // 참고: products_with 테이블에는 updated_at 컬럼이 없어(있는 것은 created_at뿐) created_at을 사용한다.
    const { data: products, error: productsErr } = await supabasePublic
      .from('products_with')
      .select('id, created_at')
      .eq('status', 'active')
      .order('created_at', { ascending: false })
      .limit(50000);
    if (productsErr) {
      // 조용히 빈 목록으로 넘어가지 않고 반드시 로그로 남긴다 - 상품 URL이 통째로 빠진 사이트맵을
      // "정상"으로 오인하지 않기 위함
      console.error('sitemap.xml: 상품 목록 조회 실패, 상품 URL 없이 생성됨:', productsErr.message);
    }
    if (products && products.length >= 50000) {
      console.warn('sitemap.xml: 판매중 상품이 5만 건을 넘어 상한까지만 포함했습니다 (사이트맵 표준 제한)');
    }
    (products || []).forEach(p => {
      urls.push({ loc: `${baseUrl}/product/${p.id}`, lastmod: p.created_at || nowDate, priority: '0.8' });
    });

    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
      urls.map(u => `  <url>\n    <loc>${escapeXml(u.loc)}</loc>\n    <lastmod>${new Date(u.lastmod).toISOString().slice(0, 10)}</lastmod>\n    <priority>${u.priority}</priority>\n  </url>`).join('\n') +
      `\n</urlset>`;

    res.type('application/xml').send(xml);
  } catch (err) {
    console.error('Error generating sitemap:', err);
    res.status(500).type('text/plain').send('사이트맵을 만드는 중 오류가 발생했습니다');
  }
});

// ============================================
// 페이지 라우트 (카테고리 / 상품 상세)
// express.static이 처리 못하는 동적 경로를 각 정적 템플릿으로 연결
// ============================================
app.get('/category/:slug', async (req, res) => {
  try {
    if (!CATEGORY_HTML_TEMPLATE) {
      return res.sendFile(path.join(__dirname, 'public', 'category.html'));
    }
    const { slug } = req.params;
    const { data: category } = await supabasePublic
      .from('categories')
      .select('slug, label, is_active')
      .eq('slug', slug)
      .maybeSingle();

    // 존재하지 않거나 비노출 카테고리는 가짜 메타태그를 만들지 않고 기본 템플릿 그대로 응답
    // (실제 "카테고리를 찾을 수 없습니다" 안내는 클라이언트 스크립트가 그대로 처리)
    if (!category || !category.is_active) {
      return res.send(CATEGORY_HTML_TEMPLATE);
    }

    const baseUrl = getBaseUrl(req);
    const pageUrl = `${baseUrl}/category/${category.slug}`;
    const title = `${category.label} - WITH+`;
    const description = `WITH+에서 ${category.label} 카테고리 상품을 만나보세요.`;

    const metaBlock = [
      `<title>${escapeHtmlAttr(title)}</title>`,
      `<meta name="description" content="${escapeHtmlAttr(description)}">`,
      `<link rel="canonical" href="${escapeHtmlAttr(pageUrl)}">`,
      `<meta property="og:type" content="website">`,
      `<meta property="og:title" content="${escapeHtmlAttr(title)}">`,
      `<meta property="og:description" content="${escapeHtmlAttr(description)}">`,
      `<meta property="og:url" content="${escapeHtmlAttr(pageUrl)}">`,
      `<meta property="og:site_name" content="WITH+">`,
      `<meta name="twitter:card" content="summary">`,
      `<meta name="twitter:title" content="${escapeHtmlAttr(title)}">`,
      `<meta name="twitter:description" content="${escapeHtmlAttr(description)}">`
    ].join('\n    ');

    res.send(CATEGORY_HTML_TEMPLATE.replace('<title>카테고리 - WITH+</title>', metaBlock));
  } catch (err) {
    console.error('Error rendering category page meta:', err);
    res.sendFile(path.join(__dirname, 'public', 'category.html'));
  }
});

// 분양형 커뮤니티(조직) 랜딩페이지 - 브랜딩된 랜딩화면
app.get('/c/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'community-landing.html'));
});

// LIVE+ 고객용 채널 시청 페이지 - 딥링크/QR로 진입, 실시간 방송/상품핀/재고 확인 후 예약→주문까지 이어진다
app.get('/live/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'live-channel.html'));
});

app.get('/product/:id', async (req, res) => {
  try {
    if (!PRODUCT_HTML_TEMPLATE) {
      return res.sendFile(path.join(__dirname, 'public', 'product.html'));
    }
    const { id } = req.params;
    const { data: product } = await supabasePublic
      .from('products_with')
      .select('id, name, description, price, discount_price, images_urls, status, stock')
      .eq('id', id)
      .maybeSingle();

    // 존재하지 않거나 비활성 상품은 가짜 메타태그를 만들지 않고 기본 템플릿 그대로 응답
    // (검색엔진·링크 미리보기 봇에게 없는 상품을 있는 것처럼 보여주지 않기 위함 - 실제
    //  "상품을 찾을 수 없습니다" 안내는 클라이언트 스크립트가 그대로 처리)
    if (!product || product.status !== 'active') {
      return res.send(PRODUCT_HTML_TEMPLATE);
    }

    const baseUrl = getBaseUrl(req);
    const pageUrl = `${baseUrl}/product/${product.id}`;
    const displayPrice = product.discount_price != null ? product.discount_price : product.price;
    const rawDesc = String(product.description || '').replace(/\s+/g, ' ').trim();
    const ogDescription = (rawDesc || `${product.name} - WITH+에서 만나보세요`).slice(0, 150);
    // og:image는 카카오톡/페이스북 등 링크 미리보기 봇이 절대경로 URL을 요구하므로,
    // DB에 상대경로(/images/...)로 저장된 이미지는 여기서 절대 URL로 변환해준다
    let ogImage = (Array.isArray(product.images_urls) && product.images_urls[0]) ? String(product.images_urls[0]) : '';
    if (ogImage && !/^https?:\/\//i.test(ogImage)) {
      ogImage = `${baseUrl}${ogImage.startsWith('/') ? '' : '/'}${ogImage}`;
    }
    const title = `${product.name} - WITH+`;

    // 실제 공개(published) 리뷰의 평균 평점 - 리뷰가 하나도 없으면 가짜 평점을 만들지 않고
    // aggregateRating 자체를 생략한다 (리뷰 없는 상품에 별점이 뜨는 것을 방지)
    const { data: reviewRows } = await supabasePublic
      .from('product_reviews')
      .select('rating')
      .eq('product_id', id)
      .eq('status', 'published');

    const productLd = {
      '@context': 'https://schema.org',
      '@type': 'Product',
      name: product.name,
      description: ogDescription,
      url: pageUrl,
      offers: {
        '@type': 'Offer',
        url: pageUrl,
        priceCurrency: 'KRW',
        price: String(displayPrice),
        availability: (product.stock > 0) ? 'https://schema.org/InStock' : 'https://schema.org/OutOfStock'
      }
    };
    if (ogImage) productLd.image = [ogImage];
    if (reviewRows && reviewRows.length > 0) {
      const avg = reviewRows.reduce((s, r) => s + (r.rating || 0), 0) / reviewRows.length;
      productLd.aggregateRating = { '@type': 'AggregateRating', ratingValue: avg.toFixed(1), reviewCount: String(reviewRows.length) };
    }

    const metaBlock = [
      `<title>${escapeHtmlAttr(title)}</title>`,
      `<meta name="description" content="${escapeHtmlAttr(ogDescription)}">`,
      `<link rel="canonical" href="${escapeHtmlAttr(pageUrl)}">`,
      `<meta property="og:type" content="product">`,
      `<meta property="og:title" content="${escapeHtmlAttr(title)}">`,
      `<meta property="og:description" content="${escapeHtmlAttr(ogDescription)}">`,
      `<meta property="og:url" content="${escapeHtmlAttr(pageUrl)}">`,
      `<meta property="og:site_name" content="WITH+">`,
      ogImage ? `<meta property="og:image" content="${escapeHtmlAttr(ogImage)}">` : '',
      `<meta property="product:price:amount" content="${escapeHtmlAttr(displayPrice)}">`,
      `<meta property="product:price:currency" content="KRW">`,
      `<meta name="twitter:card" content="${ogImage ? 'summary_large_image' : 'summary'}">`,
      `<meta name="twitter:title" content="${escapeHtmlAttr(title)}">`,
      `<meta name="twitter:description" content="${escapeHtmlAttr(ogDescription)}">`,
      `<script type="application/ld+json">${JSON.stringify(productLd)}</script>`
    ].filter(Boolean).join('\n    ');

    res.send(PRODUCT_HTML_TEMPLATE.replace('<title>상품 상세 - WITH+</title>', metaBlock));
  } catch (err) {
    console.error('Error rendering product page meta:', err);
    res.sendFile(path.join(__dirname, 'public', 'product.html'));
  }
});

// 검색 결과 페이지 (?q=검색어)
app.get('/search', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'search.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

app.get('/join', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'join.html'));
});

app.get('/welcome', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'welcome.html'));
});

app.get('/verify-phone', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'verify-phone.html'));
});

app.get('/cart', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'cart.html'));
});

app.get('/mypage', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'mypage.html'));
});

app.get('/communities', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'communities.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 호스트용 방송 진행 화면 - admin.html의 "세션/재고 관리" 모달을 대체하는 별도 화면이 아니라, 방송 중
// 실시간으로 열어두고 볼 하나의 집중된 화면(핀 변경/재고 확인/채팅 모더레이션)이다. 페이지 자체는 정적
// 파일을 그대로 내려주고, 실제 권한 확인은 클라이언트에서 /api/me로 admin/super_admin 여부를 확인한 뒤
// 이 화면이 호출하는 모든 API는 기존 /api/admin/live/... 엔드포인트들이 이미 requireRole로 막고 있다.
app.get('/admin/live-host/:channelId', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'live-host-control.html'));
});

app.get('/notice', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'board.html'));
});

app.get('/board/:type', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'board.html'));
});

app.get('/board/:type/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'board-detail.html'));
});

// 푸터 하위 정보 페이지 (회사소개/고객지원/약관·정책/함께하기)
const STATIC_INFO_PAGES = [
  'about', 'careers', 'press', 'sustainability',
  'support', 'faq', 'contact', 'returns',
  'terms', 'privacy', 'cookie', 'guides',
  'partner', 'seller', 'affiliate', 'medical-voucher'
];
STATIC_INFO_PAGES.forEach(slug => {
  app.get('/' + slug, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', slug + '.html'));
  });
});

// ============================================
// LIVE+ 공식 채널(FAN+/CREATOR+/BRAND+ 공용) API
// ============================================
// 스타/크리에이터/브랜드가 전부 같은 channels_live 구조를 쓴다(설계 근거는 마이그레이션 주석 참고).
// is_official/verification_status는 여기서 누구도 임의로 true로 만들 수 없고, 관리자 전용 엔드포인트에서만
// 명시적으로 바꿀 수 있다 - 권리계약 없이 "공식"으로 표시되는 사고를 구조적으로 막기 위함이다.

// ============================================
// 채널별 가격 정책/계산 (WITH+에서 포팅)
// ------------------------------------------------------------
// WITH+의 "원가보호 + 채널별 가격정책(방안B)" 기능 중 계산 로직만 그대로 이식한다.
// channel_pricing_policies_with / product_channel_prices_with 테이블은 WITH+와 공유하는 동일 Supabase
// 프로젝트에 이미 존재하고, 전역 정책(online 30%/live 20%/wholesale 10%, 반올림단위 10)도 이미 시딩되어
// 있다. 여기서는 라이브 채널(channel='live') 판매가 계산에만 쓴다.
// 🔒 원가/마진율 자체는 이 함수들의 반환값에 포함되지 않는다(계산된 최종 판매가만 반환) - cost_price를
// 직접 조회/수정하는 관리 화면은 LIVE+에 아직 없다(이번 작업 범위는 원가가 새는 곳을 막고 채널가 계산을
// 실제 판매가에 연동하는 것까지 - 새 원가관리 UI를 만드는 것은 범위 밖이다).
// ============================================
const PRICING_CHANNELS = ['online', 'live', 'wholesale'];

// product-scope → category-scope → global-scope 순으로 적용 가능한 정책을 찾는다
async function findPricingPolicy(channel, productId, category) {
  if (productId) {
    const { data: productPolicy } = await supabase
      .from('channel_pricing_policies_with')
      .select('*')
      .eq('channel', channel).eq('scope', 'product').eq('product_id', productId).eq('is_active', true)
      .maybeSingle();
    if (productPolicy) return productPolicy;
  }
  if (category) {
    const { data: categoryPolicy } = await supabase
      .from('channel_pricing_policies_with')
      .select('*')
      .eq('channel', channel).eq('scope', 'category').eq('category', category).eq('is_active', true)
      .maybeSingle();
    if (categoryPolicy) return categoryPolicy;
  }
  const { data: globalPolicy } = await supabase
    .from('channel_pricing_policies_with')
    .select('*')
    .eq('channel', channel).eq('scope', 'global').eq('is_active', true)
    .maybeSingle();
  return globalPolicy || null;
}

function roundToUnit(value, unit) {
  const u = Number(unit) > 0 ? Number(unit) : 1;
  return Math.round(value / u) * u;
}

// price = costPrice * (1 + margin_rate/100), rounding_unit 단위로 반올림, min_margin_rate 미만으로는 내려가지 않게 하한 적용.
// 적용 가능한 정책이 하나도 없거나 costPrice가 없으면 null 반환(호출부에서 기존 판매가로 폴백하는 의미로 쓴다).
async function computeChannelPrice(costPrice, channel, productId, category) {
  if (costPrice === null || costPrice === undefined || !Number.isFinite(Number(costPrice))) return null;
  const policy = await findPricingPolicy(channel, productId, category);
  if (!policy) return null;
  const cost = Number(costPrice);
  let marginRate = Number(policy.margin_rate);
  if (policy.min_margin_rate !== null && policy.min_margin_rate !== undefined && marginRate < Number(policy.min_margin_rate)) {
    marginRate = Number(policy.min_margin_rate);
  }
  const raw = cost * (1 + marginRate / 100);
  return Math.max(0, roundToUnit(raw, policy.rounding_unit));
}

// cost_price 또는 관련 정책이 바뀌었을 때, 수동으로 고정(is_manual_override)되지 않은 채널가만 재계산해 반영한다.
// (LIVE+에는 현재 cost_price를 편집하는 관리 화면이 없어 오늘 당장 호출부가 없을 수 있지만, WITH+와
// 동일한 로직을 유지해두면 이 저장소에도 원가 관리 화면이 생기거나 배치 재계산이 필요할 때 그대로 재사용할 수 있다.)
async function recalcChannelPrices(productId, costPrice, category) {
  for (const channel of PRICING_CHANNELS) {
    // eslint-disable-next-line no-await-in-loop
    const price = await computeChannelPrice(costPrice, channel, productId, category);
    // eslint-disable-next-line no-await-in-loop
    const { data: existing } = await supabase
      .from('product_channel_prices_with')
      .select('id, is_manual_override')
      .eq('product_id', productId).eq('channel', channel).maybeSingle();
    if (existing && existing.is_manual_override) continue; // 수동 고정된 채널가는 자동 재계산에서 건드리지 않는다
    if (price === null) continue; // 적용할 정책이 없으면 기존 값을 그대로 둔다
    if (existing) {
      // eslint-disable-next-line no-await-in-loop
      await supabase.from('product_channel_prices_with').update({ price, is_manual_override: false, updated_at: new Date().toISOString() }).eq('id', existing.id);
    } else {
      // eslint-disable-next-line no-await-in-loop
      await supabase.from('product_channel_prices_with').insert([{ product_id: productId, channel, price, is_manual_override: false }]);
    }
  }
}

// 상품 여러 개의 "라이브 채널(channel='live') 최종 판매가"를 한 번에 구한다.
// 우선순위: 1) product_channel_prices_with에 이미 계산/수동고정된 값이 있으면 그 값을 그대로 쓰고,
// 2) 없으면 cost_price+정책으로 즉석 계산하며, 3) 원가가 없거나(현재 거의 모든 상품이 이 상태) 적용 가능한
// 정책이 없으면 호출부가 넘긴 폴백가(fallbackPrice - 표시용 호출은 discount_price||price, 결제 확정용
// 호출은 기존 결제 로직과 동일하게 price)로 안전하게 대체한다. cost_price/마진율 자체는 절대 반환하지 않는다.
// products: [{ id, cost_price, category, fallbackPrice }]
async function resolveLiveChannelPrices(products) {
  const ids = (products || []).map(p => p.id).filter(Boolean);
  let pinnedByProductId = {};
  if (ids.length > 0) {
    const { data: pinnedRows } = await supabase
      .from('product_channel_prices_with')
      .select('product_id, price')
      .eq('channel', 'live').in('product_id', ids);
    (pinnedRows || []).forEach(r => { pinnedByProductId[r.product_id] = Number(r.price); });
  }
  const result = {};
  for (const p of (products || [])) {
    if (!p || !p.id) continue;
    if (Object.prototype.hasOwnProperty.call(pinnedByProductId, p.id)) {
      result[p.id] = pinnedByProductId[p.id];
      continue;
    }
    // eslint-disable-next-line no-await-in-loop
    const computed = await computeChannelPrice(p.cost_price, 'live', p.id, p.category);
    result[p.id] = computed !== null ? computed : (Number(p.fallbackPrice) || 0);
  }
  return result;
}

const LIVE_FAN_ACTIVITY_POINTS = {
  live_view: 5,       // 라이브 방송 시청
  post_engage: 2,     // 게시물 좋아요/댓글
  share: 3,           // 공유
  purchase: 10,       // 구매(공식 굿즈/협업상품)
  review: 5,          // 구매 후기 작성
  invite: 4           // 신규 팬 초대
};

// 팬 활동 1건을 append-only 로그로 남기고, 멤버십 행의 누적 점수를 갱신한다.
// 멤버십 행이 없으면(아직 채널에 가입하지 않은 상태) 자동으로 만들지 않는다 - "가입"은 명시적 행동이어야
// 하고, 가입 안 한 사람의 활동을 점수로 쌓아주면 가입 자체의 의미가 없어지기 때문이다.
async function awardFanActivity(channelId, userId, actionType, refId = null) {
  const points = LIVE_FAN_ACTIVITY_POINTS[actionType];
  if (!points) throw new Error(`알 수 없는 팬 활동 유형: ${actionType}`);

  const { data: membership, error: mErr } = await supabase
    .from('channel_members_live')
    .select('id, fan_activity_score')
    .eq('channel_id', channelId)
    .eq('user_id', userId)
    .eq('status', 'active')
    .maybeSingle();
  if (mErr) throw mErr;
  if (!membership) return { awarded: false, reason: 'not_a_member' };

  // 중복 지급 방지: ref_id가 있는 활동(구매/후기 등 실제 이벤트 기반)은 (channel_id,user_id,action_type,ref_id)
  // 조합에 걸어둔 부분 유니크 인덱스가 이미 지급된 조합의 재insert를 거부한다 - 그 경우를 "이미 지급됨"으로 처리한다.
  const { error: logErr } = await supabase.from('channel_fan_activity_live').insert([{
    channel_id: channelId, user_id: userId, action_type: actionType, points, ref_id: refId
  }]);
  if (logErr) {
    if (logErr.code === '23505') return { awarded: false, reason: 'already_awarded' };
    throw logErr;
  }

  const { error: updErr } = await supabase
    .from('channel_members_live')
    .update({ fan_activity_score: (membership.fan_activity_score || 0) + points })
    .eq('id', membership.id);
  if (updErr) throw updErr;

  return { awarded: true, points };
}

// 채널 목록(공개) - 활성 채널만, 인증배지/타입으로 필터 가능
app.get('/api/live/channels', async (req, res) => {
  try {
    let query = supabase.from('channels_live')
      .select('id, slug, name, channel_type, tagline, logo_url, cover_image_url, primary_color, is_official, verification_status')
      .eq('status', 'active')
      .order('created_at', { ascending: false });
    if (req.query.channel_type) query = query.eq('channel_type', req.query.channel_type);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ success: true, data: data || [], count: (data || []).length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching live channels:', err);
    res.status(500).json({ error: 'Failed to fetch channels', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 채널 상세(공개) - 등급 목록과 멤버 수 포함
app.get('/api/live/channels/:slug', async (req, res) => {
  try {
    const { data: channel, error } = await supabase.from('channels_live')
      .select('*').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (error) throw error;
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const [{ data: tiers }, { count: memberCount }] = await Promise.all([
      supabase.from('channel_membership_tiers_live').select('*').eq('channel_id', channel.id).order('tier_order', { ascending: true }),
      supabase.from('channel_members_live').select('id', { count: 'exact', head: true }).eq('channel_id', channel.id).eq('status', 'active')
    ]);

    res.json({ success: true, data: { ...channel, tiers: tiers || [], member_count: memberCount || 0 }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching live channel detail:', err);
    res.status(500).json({ error: 'Failed to fetch channel', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 채널 가입(로그인 필요) - 기본 무료 등급(tier_id 없음)으로 가입, tier_id를 지정하면 해당 등급으로 가입
app.post('/api/live/channels/:slug/join', authenticate, async (req, res) => {
  try {
    const { data: channel, error: cErr } = await supabase.from('channels_live')
      .select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (cErr) throw cErr;
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    let tierId = null;
    if (req.body?.tier_id) {
      const { data: tier } = await supabase.from('channel_membership_tiers_live')
        .select('id, is_paid').eq('id', req.body.tier_id).eq('channel_id', channel.id).maybeSingle();
      if (!tier) return res.status(400).json({ error: 'Bad Request', message: '유효하지 않은 멤버십 등급입니다', timestamp: new Date().toISOString() });
      if (tier.is_paid === true) {
        // 유료 멤버십 등급: 결제 인프라가 아직 없으므로 무료 가입 경로로 우회되지 않도록 차단한다.
        return res.status(403).json({ error: 'Forbidden', message: '유료 등급은 결제 기능 준비중입니다', timestamp: new Date().toISOString() });
      }
      tierId = tier.id;
    }

    const { data: existing } = await supabase.from('channel_members_live')
      .select('id, status').eq('channel_id', channel.id).eq('user_id', req.user.id).maybeSingle();

    if (existing) {
      if (existing.status === 'active') {
        return res.json({ success: true, data: { already_member: true }, timestamp: new Date().toISOString() });
      }
      const { error: reactErr } = await supabase.from('channel_members_live')
        .update({ status: 'active', tier_id: tierId, joined_at: new Date().toISOString() }).eq('id', existing.id);
      if (reactErr) throw reactErr;
    } else {
      const { error: insErr } = await supabase.from('channel_members_live')
        .insert([{ channel_id: channel.id, user_id: req.user.id, tier_id: tierId }]);
      if (insErr) throw insErr;
    }

    res.json({ success: true, data: { joined: true }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error joining live channel:', err);
    res.status(500).json({ error: 'Failed to join channel', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 팬 활동 기록(로그인 필요) - 클라이언트가 발생시킨 활동을 점수로 반영한다.
// purchase/review처럼 실제 이벤트가 있어야 하는 활동은 클라이언트가 보낸 action_type을 그대로 믿지 않고,
// 그 이벤트를 가리키는 참조 ID(order_id/review_id)를 필수로 받아 서버가 실제로 본인 소유인지 검증한다
// (검증 자체가 불가능한 가벼운 활동 - view/share 등 - 은 대신 fanActivityLimiter로 남용을 막는다).
app.post('/api/live/channels/:slug/fan-activity', authenticate, fanActivityLimiter, async (req, res) => {
  try {
    const { action_type, order_id, review_id } = req.body || {};
    if (!LIVE_FAN_ACTIVITY_POINTS[action_type]) {
      return res.status(400).json({ error: 'Bad Request', message: '알 수 없는 활동 유형입니다', timestamp: new Date().toISOString() });
    }
    const { data: channel, error: cErr } = await supabase.from('channels_live')
      .select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (cErr) throw cErr;
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    let refId = null;
    if (action_type === 'purchase') {
      if (!order_id) return res.status(400).json({ error: 'Bad Request', message: 'order_id가 필요합니다', timestamp: new Date().toISOString() });
      const { data: order, error: oErr } = await supabase.from('orders_with')
        .select('id, user_id, status').eq('id', order_id).maybeSingle();
      if (oErr) throw oErr;
      if (!order || order.user_id !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden', message: '본인의 주문만 인정됩니다', timestamp: new Date().toISOString() });
      }
      if (['pending', 'cancelled', 'refunded'].includes(order.status)) {
        return res.status(400).json({ error: 'Bad Request', message: '결제가 완료된 구매만 인정됩니다', timestamp: new Date().toISOString() });
      }
      refId = order_id;
    } else if (action_type === 'review') {
      if (!review_id) return res.status(400).json({ error: 'Bad Request', message: 'review_id가 필요합니다', timestamp: new Date().toISOString() });
      const { data: review, error: rErr } = await supabase.from('product_reviews')
        .select('id, user_id').eq('id', review_id).maybeSingle();
      if (rErr) throw rErr;
      if (!review || review.user_id !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden', message: '본인의 후기만 인정됩니다', timestamp: new Date().toISOString() });
      }
      refId = review_id;
    }

    const result = await awardFanActivity(channel.id, req.user.id, action_type, refId);
    res.json({ success: true, data: result, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error recording fan activity:', err);
    res.status(500).json({ error: 'Failed to record activity', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 내가 가입한 채널 목록(로그인 필요)
app.get('/api/me/live/channels', authenticate, async (req, res) => {
  try {
    const { data: memberships, error } = await supabase.from('channel_members_live')
      .select('fan_activity_score, joined_at, tier_id, channels_live(id, slug, name, channel_type, logo_url, is_official)')
      .eq('user_id', req.user.id).eq('status', 'active').order('joined_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: memberships || [], count: (memberships || []).length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching my live channels:', err);
    res.status(500).json({ error: 'Failed to fetch my channels', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// LIVE+ 채널 관리 API - 관리자 전용
// ============================================
app.get('/api/admin/live/channels', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('channels_live').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], count: (data || []).length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin live channels:', err);
    res.status(500).json({ error: 'Failed to fetch channels', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/live/channels', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { slug, name, channel_type, owner_user_id, tagline, description, logo_url, cover_image_url, primary_color } = req.body || {};
    if (!slug || !name || !channel_type) {
      return res.status(400).json({ error: 'Bad Request', message: 'slug, name, channel_type은 필수입니다', timestamp: new Date().toISOString() });
    }
    if (!/^[a-z0-9-]+$/.test(slug)) {
      return res.status(400).json({ error: 'Bad Request', message: 'slug는 영문 소문자/숫자/하이픈만 가능합니다', timestamp: new Date().toISOString() });
    }
    // 새 채널은 항상 draft + unofficial/unverified로 시작한다 - 계약 확인 전 상태를 만들 방법이 없다.
    const { data, error } = await supabase.from('channels_live').insert([{
      slug, name, channel_type, owner_user_id: owner_user_id || null,
      tagline: tagline || null, description: description || null,
      logo_url: logo_url || null, cover_image_url: cover_image_url || null, primary_color: primary_color || null,
      status: 'draft', is_official: false, verification_status: 'unverified'
    }]).select().single();
    if (error) throw error;
    res.status(201).json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating live channel:', err);
    res.status(500).json({ error: 'Failed to create channel', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 채널 상태/공개여부 수정. is_official/verification_status 변경은 여기서만 가능하고, 반드시
// rights_contract_ref(내부 계약 참조번호)가 함께 있어야 verified로 바꿀 수 있게 막는다 - 근거 없이
// "검증됨"으로 표시되는 걸 막기 위한 최소한의 안전장치.
app.patch('/api/admin/live/channels/:id', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const updates = {};
    const allowedFields = ['name', 'tagline', 'description', 'logo_url', 'cover_image_url', 'primary_color', 'status', 'is_official', 'verification_status', 'rights_contract_ref'];
    allowedFields.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });

    if ((updates.verification_status === 'verified' || updates.is_official === true)) {
      const { data: current } = await supabase.from('channels_live').select('rights_contract_ref').eq('id', req.params.id).maybeSingle();
      const contractRef = updates.rights_contract_ref !== undefined ? updates.rights_contract_ref : current?.rights_contract_ref;
      if (!contractRef) {
        return res.status(400).json({ error: 'Bad Request', message: '권리계약 참조번호(rights_contract_ref) 없이는 공식/검증 상태로 바꿀 수 없습니다', timestamp: new Date().toISOString() });
      }
    }

    updates.updated_at = new Date().toISOString();
    const { data, error } = await supabase.from('channels_live').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating live channel:', err);
    res.status(500).json({ error: 'Failed to update channel', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/live/channels/:id/tiers', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { tier_key, tier_name, tier_order, is_paid, price_monthly, benefits_description } = req.body || {};
    if (!tier_key || !tier_name) {
      return res.status(400).json({ error: 'Bad Request', message: 'tier_key, tier_name은 필수입니다', timestamp: new Date().toISOString() });
    }
    const { data, error } = await supabase.from('channel_membership_tiers_live').insert([{
      channel_id: req.params.id, tier_key, tier_name, tier_order: tier_order || 0,
      is_paid: !!is_paid, price_monthly: price_monthly || null, benefits_description: benefits_description || null
    }]).select().single();
    if (error) throw error;
    res.status(201).json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating membership tier:', err);
    res.status(500).json({ error: 'Failed to create tier', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// LIVE+ 채널-상품 판매 연동 (라이브 세션 · 상품핀 · 주문 출처 추적)
// ============================================
// 상품 데이터는 복제하지 않고 기존 products_with을 그대로 참조한다 - 채널은 "무엇을 파는지"만 큐레이션.

// 채널이 판매하는 상품 목록(공개) - 상품 상세는 기존 products_with 그대로, 추천순은 is_featured 우선
app.get('/api/live/channels/:slug/products', async (req, res) => {
  try {
    const { data: channel, error: cErr } = await supabase.from('channels_live')
      .select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (cErr) throw cErr;
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const { data: links, error: lErr } = await supabase.from('channel_products_live')
      .select('is_featured, added_at, products_with(id, name, price, discount_price, images_urls, stock, status, category, cost_price)')
      .eq('channel_id', channel.id).order('is_featured', { ascending: false }).order('added_at', { ascending: false });
    if (lErr) throw lErr;

    const rawProducts = (links || [])
      .filter(l => l.products_with && l.products_with.status === 'active')
      .map(l => ({ ...l.products_with, is_featured: l.is_featured }));

    // 라이브 채널 가격정책(channel_pricing_policies_with/product_channel_prices_with)을 반영한 최종 판매가를
    // live_price로 함께 내려준다. 폴백 기준은 discount_price||price(기존 화면이 이미 쓰던 값)로 두어,
    // 아직 cost_price가 입력되지 않은 상품(현재 거의 전부)에서 기존에 보이던 할인가가 사라지지 않게 한다.
    // 🔒 cost_price 자체는 응답에서 제거한다 - 계산에만 쓰고 절대 노출하지 않는다.
    const livePriceById = await resolveLiveChannelPrices(rawProducts.map(p => ({
      id: p.id, cost_price: p.cost_price, category: p.category,
      fallbackPrice: (p.discount_price !== null && p.discount_price !== undefined && Number(p.discount_price) > 0) ? p.discount_price : p.price
    })));
    const products = rawProducts.map(p => {
      const { cost_price, ...safe } = p;
      return { ...safe, live_price: livePriceById[p.id] };
    });

    res.json({ success: true, data: products, count: products.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching channel products:', err);
    res.status(500).json({ error: 'Failed to fetch channel products', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/live/channels/:id/products', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { product_id, is_featured } = req.body || {};
    if (!product_id) return res.status(400).json({ error: 'Bad Request', message: 'product_id는 필수입니다', timestamp: new Date().toISOString() });
    const { data: product } = await supabase.from('products_with').select('id').eq('id', product_id).maybeSingle();
    if (!product) return res.status(400).json({ error: 'Bad Request', message: '존재하지 않는 상품입니다', timestamp: new Date().toISOString() });

    const { data, error } = await supabase.from('channel_products_live')
      .upsert([{ channel_id: req.params.id, product_id, is_featured: !!is_featured }], { onConflict: 'channel_id,product_id' })
      .select().single();
    if (error) throw error;
    res.status(201).json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error attaching product to channel:', err);
    res.status(500).json({ error: 'Failed to attach product', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.delete('/api/admin/live/channels/:id/products/:productId', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { error } = await supabase.from('channel_products_live')
      .delete().eq('channel_id', req.params.id).eq('product_id', req.params.productId);
    if (error) throw error;
    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error detaching product from channel:', err);
    res.status(500).json({ error: 'Failed to detach product', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자용 채널 상품 큐레이션 조회 - 공개 API(GET /api/live/channels/:slug/products)와 달리 채널이
// draft(비공개) 상태여도 조회 가능해야 관리자가 활성화 전에 미리 상품을 큐레이션할 수 있다.
app.get('/api/admin/live/channels/:id/products', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: links, error } = await supabase.from('channel_products_live')
      .select('product_id, is_featured, added_at, products_with(id, name, price, discount_price, images_urls, stock, status, category, cost_price)')
      .eq('channel_id', req.params.id).order('is_featured', { ascending: false }).order('added_at', { ascending: false });
    if (error) throw error;

    // 관리자 큐레이션 화면에도 라이브 채널가(live_price)를 함께 내려준다(원가는 노출하지 않는다).
    const livePriceById = await resolveLiveChannelPrices((links || []).filter(l => l.products_with).map(l => ({
      id: l.products_with.id, cost_price: l.products_with.cost_price, category: l.products_with.category,
      fallbackPrice: (l.products_with.discount_price !== null && l.products_with.discount_price !== undefined && Number(l.products_with.discount_price) > 0) ? l.products_with.discount_price : l.products_with.price
    })));
    const data = (links || []).map(l => {
      if (!l.products_with) return l;
      const { cost_price, ...safeProduct } = l.products_with;
      return { ...l, products_with: { ...safeProduct, live_price: livePriceById[l.products_with.id] } };
    });
    res.json({ success: true, data, count: data.length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin channel products:', err);
    res.status(500).json({ error: 'Failed to fetch channel products', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 지금 방송 중인 세션(공개) - 시청 화면이 이 값을 주기적으로 조회해 상품핀 변경을 따라간다
// 시청자가 실제로 볼 영상 소스를 결정한다 - 우선순위: 브라우저 원클릭 방송(WebRTC) > 자체 사이트 재생
// (Cloudflare Stream) > 유튜브 > 페이스북. 여러 목적지에 동시송출 중이어도 화면에는 대표로 하나만
// 골라 보여준다(여러 영상을 동시에 트는 건 오히려 혼란스럽다 - host-control 화면에는 전체 목록을 그대로 보여준다).
async function resolveSessionVideoInfo(session) {
  if (session.webrtc_active) {
    return { mode: 'webrtc', room: session.id };
  }
  const { data: targets } = await supabase.from('live_session_broadcast_targets_live')
    .select('platform, external_broadcast_id, playback_url')
    .eq('live_session_id', session.id).in('status', ['created', 'live'])
    .in('platform', ['cloudflare_stream', 'youtube', 'facebook']);
  if (!targets || targets.length === 0) return { mode: 'none' };
  const cf = targets.find(t => t.platform === 'cloudflare_stream' && t.playback_url);
  if (cf) return { mode: 'cloudflare_stream', hls_url: cf.playback_url };
  const yt = targets.find(t => t.platform === 'youtube' && t.external_broadcast_id);
  if (yt) return { mode: 'youtube', embed_url: `https://www.youtube.com/embed/${yt.external_broadcast_id}?autoplay=1&mute=1` };
  const fb = targets.find(t => t.platform === 'facebook' && t.external_broadcast_id);
  if (fb) return { mode: 'facebook', video_id: fb.external_broadcast_id };
  return { mode: 'none' };
}

app.get('/api/live/channels/:slug/sessions/live', async (req, res) => {
  try {
    const { data: channel, error: cErr } = await supabase.from('channels_live')
      .select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (cErr) throw cErr;
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const { data: session, error: sErr } = await supabase.from('live_sessions_live')
      .select('id, title, status, started_at, pinned_product_id, webrtc_active, products_with(id, name, price, discount_price, images_urls, stock, category, cost_price)')
      .eq('channel_id', channel.id).eq('status', 'live').order('started_at', { ascending: false }).maybeSingle();
    if (sErr) throw sErr;
    if (!session) return res.json({ success: true, data: null, timestamp: new Date().toISOString() });

    const video = await resolveSessionVideoInfo(session);

    // 상품핀(지금 소개중인 상품)에도 live_price를 함께 내려준다 - product.html/live-channel.html에서
    // 방금 소개중인 상품 가격을 직접 이 응답에서 읽는 경로가 있어 목록 조회와 동일하게 반영해야 한다.
    let sessionOut = session;
    if (session.products_with) {
      const pinnedProduct = session.products_with;
      const fallbackPrice = (pinnedProduct.discount_price !== null && pinnedProduct.discount_price !== undefined && Number(pinnedProduct.discount_price) > 0) ? pinnedProduct.discount_price : pinnedProduct.price;
      const livePriceById = await resolveLiveChannelPrices([{ id: pinnedProduct.id, cost_price: pinnedProduct.cost_price, category: pinnedProduct.category, fallbackPrice }]);
      const { cost_price, ...safePinned } = pinnedProduct;
      sessionOut = { ...session, products_with: { ...safePinned, live_price: livePriceById[pinnedProduct.id] } };
    }

    res.json({
      success: true,
      data: { ...sessionOut, video, deep_link: `/live/${req.params.slug}?session=${session.id}` },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching live session:', err);
    res.status(500).json({ error: 'Failed to fetch live session', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 다시보기(VOD) 쇼핑(공개) - 매출견인기능 격차분석 2-6. LIVE+는 자체 녹화/스트림 저장 인프라가 없으므로
// 새로운 녹화 파이프라인을 만들지 않고, 이미 있는 OmniCast 동시송출 기록(live_session_broadcast_targets_live)의
// external_broadcast_id를 재사용한다 - 유튜브는 라이브 방송 종료 후 같은 ID가 그대로 다시보기 VOD ID가 되므로
// 별도 처리 없이 시청 링크로 바로 쓸 수 있다(페이스북은 페이지ID 없이 만드는 범용 워치 링크라 최선노력 수준).
// 라이브 중이 아닐 때 이 채널의 가장 최근에 "종료된" 세션 하나를 돌려주고, 그 세션에서 만들어진 다시보기
// 링크가 있으면 함께 내려준다 - 상품 목록/구매는 이미 있는 평소 상품 API(GET .../products)를 그대로 쓴다.
app.get('/api/live/channels/:slug/sessions/replay', async (req, res) => {
  try {
    const { data: channel, error: cErr } = await supabase.from('channels_live')
      .select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (cErr) throw cErr;
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const { data: session, error: sErr } = await supabase.from('live_sessions_live')
      .select('id, title, started_at, ended_at, pinned_product_id')
      .eq('channel_id', channel.id).eq('status', 'ended')
      .order('ended_at', { ascending: false }).limit(1).maybeSingle();
    if (sErr) throw sErr;
    if (!session) return res.json({ success: true, data: null, timestamp: new Date().toISOString() });

    const { data: targets } = await supabase.from('live_session_broadcast_targets_live')
      .select('platform, external_broadcast_id, playback_url').eq('live_session_id', session.id)
      .in('platform', ['youtube', 'facebook', 'cloudflare_stream']);

    const replayLinks = (targets || []).map(t => {
      if (t.platform === 'youtube' && t.external_broadcast_id) return { platform: 'youtube', url: `https://www.youtube.com/watch?v=${t.external_broadcast_id}` };
      // 페이스북은 페이지ID를 함께 알아야 정확한 영구 링크가 나오는데 여기서는 보관하지 않으므로,
      // 페이지ID 없이도 대체로 동작하는 범용 워치 링크를 최선노력으로 사용한다(항상 보장되지는 않음).
      if (t.platform === 'facebook' && t.external_broadcast_id) return { platform: 'facebook', url: `https://www.facebook.com/watch/?v=${t.external_broadcast_id}` };
      // Cloudflare Stream은 녹화(recording.mode:'automatic')가 켜져 있어 방송이 끝나도 같은 HLS 주소가
      // 그대로 다시보기 영상으로 이어진다 - 별도 워치 링크가 아니라 우리 사이트 안에서 바로 재생 가능.
      if (t.platform === 'cloudflare_stream' && t.playback_url) return { platform: 'cloudflare_stream', hls_url: t.playback_url };
      return null;
    }).filter(Boolean);

    // 🎬 하이라이트 클립(B8) - AI 영상분석/자동편집 파이프라인 없이, 채팅이 가장 몰린 구간을 "하이라이트
    // 후보"로 근사한다. 실제 영상을 잘라내지 않고, 다시보기 영상의 해당 시각으로 바로 이동하는 타임스탬프
    // 링크만 제공한다(유튜브는 ?t=초 로 특정 시각부터 재생 가능) - 격차분석 보고서가 제안한 경량 대체안.
    let highlights = [];
    try {
      const { data: chatRows } = await supabase.from('live_session_chat_messages_live')
        .select('created_at').eq('live_session_id', session.id).eq('is_hidden', false);
      if (chatRows && chatRows.length > 0 && session.started_at) {
        const startMs = new Date(session.started_at).getTime();
        const BUCKET_SEC = 20;
        const buckets = {};
        chatRows.forEach(r => {
          const offsetSec = Math.max(0, Math.floor((new Date(r.created_at).getTime() - startMs) / 1000));
          const bucketIdx = Math.floor(offsetSec / BUCKET_SEC);
          buckets[bucketIdx] = (buckets[bucketIdx] || 0) + 1;
        });
        const HIGHLIGHT_MIN_COUNT = 3; // 최소 이 정도는 몰려야 "하이라이트 후보"로 인정(너무 조용한 방송에서 억지로 만들지 않음)
        const ranked = Object.entries(buckets)
          .map(([idx, count]) => ({ offset_seconds: Number(idx) * BUCKET_SEC, message_count: count }))
          .filter(b => b.message_count >= HIGHLIGHT_MIN_COUNT)
          .sort((a, b) => b.message_count - a.message_count)
          .slice(0, 5)
          .sort((a, b) => a.offset_seconds - b.offset_seconds);

        const youtubeTarget = (targets || []).find(t => t.platform === 'youtube');
        highlights = ranked.map(h => ({
          ...h,
          youtube_url: youtubeTarget ? `https://www.youtube.com/watch?v=${youtubeTarget.external_broadcast_id}&t=${h.offset_seconds}s` : null
        }));
      }
    } catch (hlErr) {
      console.error('Error computing highlight timestamps:', hlErr);
    }

    res.json({
      success: true,
      data: { ...session, replay_links: replayLinks, highlights, deep_link: `/live/${req.params.slug}?session=${session.id}` },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching replay session:', err);
    res.status(500).json({ error: 'Failed to fetch replay session', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/live/channels/:id/sessions', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_sessions_live')
      .select('*, products_with(id, name, images_urls)').eq('channel_id', req.params.id).order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], count: (data || []).length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching live sessions:', err);
    res.status(500).json({ error: 'Failed to fetch sessions', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/live/channels/:id/sessions', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { title, scheduled_at } = req.body || {};
    if (!title) return res.status(400).json({ error: 'Bad Request', message: 'title은 필수입니다', timestamp: new Date().toISOString() });
    const { data, error } = await supabase.from('live_sessions_live')
      .insert([{ channel_id: req.params.id, title, scheduled_at: scheduled_at || null, status: 'scheduled' }])
      .select().single();
    if (error) throw error;
    res.status(201).json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating live session:', err);
    res.status(500).json({ error: 'Failed to create session', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 세션 상태 전환(시작/종료) 및 상품핀 변경 - 호스트 관제화면의 핵심 엔드포인트.
// pinned_product_id는 해당 채널에 실제로 등록된 상품인지 확인 후에만 반영한다(엉뚱한 상품 고정 방지).
app.patch('/api/admin/live/channels/:id/sessions/:sessionId', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const updates = {};
    if (req.body.status !== undefined) {
      if (!['scheduled', 'live', 'ended'].includes(req.body.status)) {
        return res.status(400).json({ error: 'Bad Request', message: '유효하지 않은 status입니다', timestamp: new Date().toISOString() });
      }
      updates.status = req.body.status;
      if (req.body.status === 'live') updates.started_at = new Date().toISOString();
      // 방송 종료 시 브라우저 방송(WebRTC)도 함께 꺼둔다 - 세션이 끝났는데 webrtc_active만 계속 true로
      // 남아 시청자 화면에 죽은 영상을 계속 붙잡고 있는 것을 방지.
      if (req.body.status === 'ended') { updates.ended_at = new Date().toISOString(); updates.webrtc_active = false; }
    }
    const willGoLive = req.body.status === 'live';
    if (req.body.pinned_product_id !== undefined) {
      if (req.body.pinned_product_id !== null) {
        const { data: link } = await supabase.from('channel_products_live')
          .select('id').eq('channel_id', req.params.id).eq('product_id', req.body.pinned_product_id).maybeSingle();
        if (!link) return res.status(400).json({ error: 'Bad Request', message: '이 채널에 등록되지 않은 상품은 고정할 수 없습니다', timestamp: new Date().toISOString() });
      }
      updates.pinned_product_id = req.body.pinned_product_id;
    }

    const { data, error } = await supabase.from('live_sessions_live')
      .update(updates).eq('id', req.params.sessionId).eq('channel_id', req.params.id).select().single();
    if (error) throw error;

    // 채널(방송자) 팔로우 + 라이브 시작 알림 - 틱톡/유튜브 매출견인기능 격차분석 2번 항목.
    // 별도 "팔로우" 테이블을 새로 만들지 않고, 이미 있는 채널 가입(channel_members_live, status='active')을
    // 그대로 "팔로워"로 재사용한다 - 기존 재입고 알림(triggerRestockNotifications)과 동일한 패턴.
    if (willGoLive) {
      notifyChannelMembersLiveStarted(req.params.id, data, getBaseUrl(req)).catch(err => console.error('라이브 시작 알림 발송 오류:', err.message));
    }

    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating live session:', err);
    res.status(500).json({ error: 'Failed to update session', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 📩 카카오 알림톡(AlimTalk) - 알리고(Aligo) API 연동
// ============================================
// 형님이 카카오 비즈니스 채널(발신프로필)과 알리고 계정을 만들고 아래 설정(관리자 화면 → 라이브 방송
// 진행 화면의 "카카오 알림톡 설정")에 API키/USERID/발신프로필키/발신번호/템플릿코드를 등록하면 동작한다.
// 알림톡은 카카오 사전 심사를 통과한 "템플릿"으로만 보낼 수 있어서 자유 텍스트를 그대로 못 보낸다 -
// tpl_code_live_start에 등록한 템플릿 코드를 쓰고, 그 템플릿 심사 시 등록한 문구/변수 형식과 최대한
// 비슷하게 message를 구성해야 실제로 발송이 통과된다.
// 알림톡이 설정되어 있지 않거나 개별 발송이 실패해도 방송 시작 자체나 기존 인앱 알림에는 절대 영향을
// 주지 않는다 - 완전히 별개의 best-effort 경로다.
async function getKakaoAlimtalkConfig() {
  const { data } = await supabase.from('kakao_alimtalk_configs_live').select('*').order('created_at', { ascending: true }).limit(1).maybeSingle();
  return data || null;
}

async function sendKakaoAlimtalk({ phone, recvname, subject, message, failoverMessage, testMode }) {
  const cfg = await getKakaoAlimtalkConfig();
  if (!cfg || !cfg.enabled) throw new Error('카카오 알림톡이 아직 설정/활성화되지 않았습니다');
  const apiKey = decryptSecret(cfg.api_key);
  if (!apiKey || !cfg.user_id || !cfg.sender_key || !cfg.sender_phone || !cfg.tpl_code_live_start) {
    throw new Error('카카오 알림톡 설정이 불완전합니다 (API키/USERID/발신프로필키/발신번호/템플릿코드를 모두 등록해주세요)');
  }
  const digitsPhone = String(phone || '').replace(/[^0-9]/g, '');
  if (!digitsPhone) throw new Error('수신자 전화번호가 없습니다');

  const body = new URLSearchParams({
    apikey: apiKey, userid: cfg.user_id, senderkey: cfg.sender_key, tpl_code: cfg.tpl_code_live_start,
    sender: cfg.sender_phone, receiver_1: digitsPhone, subject_1: subject, message_1: message,
    testMode: testMode ? 'Y' : 'N'
  });
  if (recvname) body.set('recvname_1', recvname);
  // failover: 알림톡이 실패(카카오톡 미설치/알림톡 차단 등)하면 문자(SMS/LMS)로 대체 발송한다
  if (failoverMessage) {
    body.set('failover', 'Y');
    body.set('fsubject_1', subject);
    body.set('fmessage_1', failoverMessage);
  }

  const resp = await fetch('https://kakaoapi.aligo.in/akv10/alimtalk/send/', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(),
    signal: AbortSignal.timeout(15000)
  });
  const json = await resp.json().catch(() => null);
  if (!resp.ok || !json || Number(json.code) !== 0) {
    throw new Error(`알림톡 발송 실패: ${json?.message || resp.status}`);
  }
  return json;
}

async function notifyChannelMembersLiveStarted(channelId, session, baseUrl) {
  const { data: members } = await supabase.from('channel_members_live').select('user_id').eq('channel_id', channelId).eq('status', 'active');
  if (!members || members.length === 0) return;
  const { data: channel } = await supabase.from('channels_live').select('name, slug').eq('id', channelId).maybeSingle();
  if (!channel) return;
  const notifRows = members.map(m => ({
    user_id: m.user_id, type: 'live_started', title: '🔴 라이브 시작',
    message: `가입하신 "${channel.name}" 채널이 방금 라이브를 시작했습니다${session && session.title ? ` - ${session.title}` : ''}`,
    link: `/c/${channel.slug}`
  }));
  await supabase.from('notifications_with').insert(notifRows);

  // 📩 카카오 알림톡 - 단골(채널 가입자) 중 연락처를 등록하고 마케팅 수신에 동의한 회원에게만 보낸다.
  try {
    const cfg = await getKakaoAlimtalkConfig();
    if (cfg && cfg.enabled) {
      const userIds = members.map(m => m.user_id);
      const { data: recipients } = await supabase.from('profiles').select('id, full_name, phone, marketing_consent')
        .in('id', userIds).eq('marketing_consent', true).not('phone', 'is', null);
      const liveUrl = `${baseUrl || process.env.SITE_URL || ''}/live/${channel.slug}`;
      const subject = '라이브 시작 알림';
      for (const r of (recipients || [])) {
        const message = `[${channel.name}] 지금 라이브 방송이 시작되었어요!\n${session && session.title ? session.title : ''}\n\n지금 바로 보러 가기\n${liveUrl}`;
        await sendKakaoAlimtalk({
          phone: r.phone, recvname: r.full_name || undefined, subject, message,
          failoverMessage: `[${channel.name}] 라이브 시작! ${liveUrl}`
        }).catch(err => console.error(`알림톡 발송 실패 (user ${r.id}):`, err.message));
      }
    }
  } catch (err) {
    console.error('카카오 알림톡 일괄발송 처리 오류:', err.message);
  }
}

// ============================================
// 📅 방송 예약 알림 (경쟁사 기능 격차 백로그 2번) - 네이버쇼핑라이브 "방송 예정" 알림과 동일한 컨셉.
// ============================================
// 이 프로젝트는 지금까지 "스케줄러/지속연결 없이 읽는 시점에 처리" 원칙을 지켜왔지만, 장바구니 이탈
// 리마인더(runCartReminderScan)·재구매 알림 배치가 이미 node-cron 인프로세스 스케줄러를 쓰고 있으므로
// (완전히 새로운 인프라가 아니라 기존에 검증된 패턴) 동일하게 node-cron으로 주기 스캔한다.
// live_sessions_live.scheduled_at이 "이제부터 N분 이내"로 들어오면(관리자가 설정한 minutes_before),
// 아직 알림을 보낸 적 없는(reminder_sent_at IS NULL) 예정 세션을 찾아 채널 단골 전원에게 인앱 알림 +
// (설정되어 있으면) 카카오 알림톡을 보낸다. 한 세션당 정확히 한 번만 발송된다(reminder_sent_at로 방어).
const DEFAULT_LIVE_REMINDER_SETTINGS = { enabled: false, minutes_before: 30 };
let liveReminderSettingsCache = null;
let liveReminderSettingsCacheAt = 0;
const LIVE_REMINDER_SETTINGS_CACHE_TTL_MS = 30 * 1000;

function normalizeLiveReminderSettings(value) {
  const v = value && typeof value === 'object' ? value : {};
  return {
    enabled: !!v.enabled,
    minutes_before: Number.isFinite(Number(v.minutes_before)) ? Math.min(1440, Math.max(5, Math.floor(Number(v.minutes_before)))) : DEFAULT_LIVE_REMINDER_SETTINGS.minutes_before
  };
}

async function getLiveReminderSettings() {
  const now = Date.now();
  if (liveReminderSettingsCache && (now - liveReminderSettingsCacheAt) < LIVE_REMINDER_SETTINGS_CACHE_TTL_MS) {
    return liveReminderSettingsCache;
  }
  try {
    const { data, error } = await supabase.from('platform_settings').select('value').eq('key', 'live_reminder_settings').maybeSingle();
    const settings = normalizeLiveReminderSettings(error || !data ? null : data.value);
    liveReminderSettingsCache = settings;
    liveReminderSettingsCacheAt = now;
    return settings;
  } catch (err) {
    console.error('Error fetching live reminder settings:', err);
    return liveReminderSettingsCache || DEFAULT_LIVE_REMINDER_SETTINGS;
  }
}

// "방송 예정" 알림 버전 - notifyChannelMembersLiveStarted와 거의 같은 형태지만 문구가 "시작했습니다"가
// 아니라 "곧 시작합니다"이고, 실행 주체가 요청(req)이 아니라 cron이라 baseUrl을 SITE_URL로만 구한다.
async function notifyChannelMembersLiveReminder(channelId, session, channel) {
  const { data: members } = await supabase.from('channel_members_live').select('user_id').eq('channel_id', channelId).eq('status', 'active');
  if (!members || members.length === 0) return 0;

  const minutesLeft = Math.max(0, Math.round((new Date(session.scheduled_at).getTime() - Date.now()) / 60000));
  const notifRows = members.map(m => ({
    user_id: m.user_id, type: 'live_reminder', title: '📅 방송 예정 알림',
    message: `가입하신 "${channel.name}" 채널이 잠시 후(약 ${minutesLeft}분 뒤) 라이브를 시작합니다${session.title ? ` - ${session.title}` : ''}`,
    link: `/c/${channel.slug}`
  }));
  await supabase.from('notifications_with').insert(notifRows);

  try {
    const cfg = await getKakaoAlimtalkConfig();
    if (cfg && cfg.enabled) {
      const userIds = members.map(m => m.user_id);
      const { data: recipients } = await supabase.from('profiles').select('id, full_name, phone, marketing_consent')
        .in('id', userIds).eq('marketing_consent', true).not('phone', 'is', null);
      const liveUrl = `${process.env.SITE_URL || ''}/live/${channel.slug}`;
      const subject = '방송 예정 알림';
      for (const r of (recipients || [])) {
        const message = `[${channel.name}] 곧 라이브 방송이 시작돼요!\n${session.title || ''}\n약 ${minutesLeft}분 뒤 시작 예정\n\n미리 알림 받고 놓치지 마세요\n${liveUrl}`;
        await sendKakaoAlimtalk({
          phone: r.phone, recvname: r.full_name || undefined, subject, message,
          failoverMessage: `[${channel.name}] 곧 라이브 시작! ${liveUrl}`
        }).catch(err => console.error(`방송예정 알림톡 발송 실패 (user ${r.id}):`, err.message));
      }
    }
  } catch (err) {
    console.error('방송예정 카카오 알림톡 일괄발송 처리 오류:', err.message);
  }
  return members.length;
}

// 관리자 수동 실행(run-now)과 node-cron 정기 스캔 양쪽에서 호출된다 (cart reminder와 동일한 패턴).
async function runLiveSessionReminderScan(opts = {}) {
  const result = { scanned: 0, notified_sessions: 0, notified_members: 0 };
  const settings = await getLiveReminderSettings();
  if (!settings.enabled && !opts.force) return result;

  const windowEnd = new Date(Date.now() + settings.minutes_before * 60 * 1000).toISOString();
  const { data: sessions, error } = await supabase
    .from('live_sessions_live')
    .select('id, channel_id, title, scheduled_at')
    .eq('status', 'scheduled')
    .is('reminder_sent_at', null)
    .not('scheduled_at', 'is', null)
    .lte('scheduled_at', windowEnd);
  if (error) { console.error('Error scanning live session reminders:', error); return result; }

  for (const session of sessions || []) {
    result.scanned++;
    const { data: channel } = await supabase.from('channels_live').select('name, slug').eq('id', session.channel_id).maybeSingle();
    if (!channel) continue;
    try {
      const notifiedCount = await notifyChannelMembersLiveReminder(session.channel_id, session, channel);
      result.notified_sessions++;
      result.notified_members += notifiedCount;
    } catch (err) {
      console.error(`Error sending live reminder for session ${session.id}:`, err.message);
    }
    // 발송 성공/실패와 무관하게 세션당 딱 한 번만 시도하도록 항상 표시(무한 재시도로 도배되는 것을 방지) -
    // 장바구니 리마인더와 달리 "방송 시작 임박"은 재발송할 의미가 없는 1회성 알림이기 때문.
    await supabase.from('live_sessions_live').update({ reminder_sent_at: new Date().toISOString() }).eq('id', session.id);
  }
  return result;
}

// 5분마다 자동 스캔 (설정에서 꺼져있으면 runLiveSessionReminderScan 내부에서 즉시 빈 결과로 반환)
cron.schedule('*/5 * * * *', () => {
  runLiveSessionReminderScan().catch(err => console.error('Live session reminder cron error:', err));
});

// 공개: 방송 예약 알림 기능 활성화 여부만 (다른 공개 설정 엔드포인트와 동일하게 최소 정보만 노출)
app.get('/api/settings/live-reminder', async (req, res) => {
  try {
    const settings = await getLiveReminderSettings();
    res.json({ success: true, data: { enabled: settings.enabled, minutes_before: settings.minutes_before }, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch live reminder settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 방송 예약 알림 설정 + 지금 대기 중인(알림 발송 대상) 예정 세션 개수 조회
app.get('/api/admin/settings/live-reminder', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const settings = await getLiveReminderSettings();
    const windowEnd = new Date(Date.now() + settings.minutes_before * 60 * 1000).toISOString();
    const { count, error: countErr } = await supabase
      .from('live_sessions_live')
      .select('id', { count: 'exact', head: true })
      .eq('status', 'scheduled')
      .is('reminder_sent_at', null)
      .not('scheduled_at', 'is', null)
      .lte('scheduled_at', windowEnd);
    if (countErr) throw countErr;
    res.json({ success: true, data: settings, pending_count: count || 0, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching live reminder settings:', err);
    res.status(500).json({ error: 'Failed to fetch live reminder settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.patch('/api/admin/settings/live-reminder', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const settings = normalizeLiveReminderSettings(req.body);
    const { error } = await supabase.from('platform_settings').upsert({
      key: 'live_reminder_settings', value: settings, updated_at: new Date().toISOString(), updated_by: req.user.id
    }, { onConflict: 'key' });
    if (error) throw error;
    liveReminderSettingsCache = settings;
    liveReminderSettingsCacheAt = Date.now();
    res.json({ success: true, data: settings, message: '저장되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating live reminder settings:', err);
    res.status(500).json({ error: 'Failed to update live reminder settings', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 지금 즉시 스캔 실행 (설정이 꺼져있어도 강제 실행 - 테스트/수동 발송 목적)
app.post('/api/admin/live-reminder/run-now', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const result = await runLiveSessionReminderScan({ force: true });
    res.json({ success: true, data: result, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error running live reminder scan:', err);
    res.status(500).json({ error: 'Failed to run live reminder scan', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 카카오 알림톡 설정 조회 - api_key 원문은 절대 응답에 포함하지 않는다(has_api_key만 알려줌, pg_configs와 동일 패턴)
app.get('/api/admin/live/kakao-alimtalk/config', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const cfg = await getKakaoAlimtalkConfig();
    res.json({
      success: true,
      data: cfg ? {
        has_api_key: !!cfg.api_key, user_id: cfg.user_id || null, sender_key: cfg.sender_key || null,
        sender_phone: cfg.sender_phone || null, tpl_code_live_start: cfg.tpl_code_live_start || null,
        enabled: cfg.enabled, last_tested_at: cfg.last_tested_at, last_test_status: cfg.last_test_status, last_test_message: cfg.last_test_message
      } : { has_api_key: false, user_id: null, sender_key: null, sender_phone: null, tpl_code_live_start: null, enabled: false },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch kakao alimtalk config', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.patch('/api/admin/live/kakao-alimtalk/config', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const existing = await getKakaoAlimtalkConfig();
    const update = { updated_at: new Date().toISOString() };
    if (typeof req.body.api_key === 'string' && req.body.api_key.trim()) update.api_key = encryptSecret(req.body.api_key.trim());
    if (typeof req.body.user_id === 'string') update.user_id = req.body.user_id.trim() || null;
    if (typeof req.body.sender_key === 'string') update.sender_key = req.body.sender_key.trim() || null;
    if (typeof req.body.sender_phone === 'string') update.sender_phone = req.body.sender_phone.trim() || null;
    if (typeof req.body.tpl_code_live_start === 'string') update.tpl_code_live_start = req.body.tpl_code_live_start.trim() || null;
    if (typeof req.body.enabled === 'boolean') update.enabled = req.body.enabled;

    let data, error;
    if (existing) {
      ({ data, error } = await supabase.from('kakao_alimtalk_configs_live').update(update).eq('id', existing.id).select().single());
    } else {
      ({ data, error } = await supabase.from('kakao_alimtalk_configs_live').insert([update]).select().single());
    }
    if (error) throw error;
    res.json({ success: true, data: { has_api_key: !!data.api_key, user_id: data.user_id, sender_key: data.sender_key, sender_phone: data.sender_phone, tpl_code_live_start: data.tpl_code_live_start, enabled: data.enabled }, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update kakao alimtalk config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 내 계정(profiles.phone)으로 테스트 알림톡을 보내본다 - 실제 방송을 켜지 않고도 설정이 맞는지 확인 가능
app.post('/api/admin/live/kakao-alimtalk/test', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const phone = (req.body && req.body.phone) || null;
    let targetPhone = phone;
    let recvname;
    if (!targetPhone) {
      const { data: me } = await supabase.from('profiles').select('phone, full_name').eq('id', req.user.id).maybeSingle();
      targetPhone = me && me.phone;
      recvname = me && me.full_name;
    }
    if (!targetPhone) return res.status(400).json({ error: 'Bad Request', message: '테스트로 보낼 전화번호가 없습니다 (내 프로필에 연락처를 등록하거나 phone을 직접 넘겨주세요)', timestamp: new Date().toISOString() });

    const liveUrl = `${getBaseUrl(req)}/live/test`;
    await sendKakaoAlimtalk({
      phone: targetPhone, recvname,
      subject: '라이브 시작 알림', message: `[테스트 채널] 지금 라이브 방송이 시작되었어요!\n테스트 발송입니다\n\n지금 바로 보러 가기\n${liveUrl}`,
      failoverMessage: `[테스트 채널] 라이브 시작! ${liveUrl}`
    });
    const existing = await getKakaoAlimtalkConfig();
    if (existing) await supabase.from('kakao_alimtalk_configs_live').update({ last_tested_at: new Date().toISOString(), last_test_status: 'success', last_test_message: null }).eq('id', existing.id);
    res.json({ success: true, message: '테스트 알림톡을 발송했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    const existing = await getKakaoAlimtalkConfig().catch(() => null);
    if (existing) await supabase.from('kakao_alimtalk_configs_live').update({ last_tested_at: new Date().toISOString(), last_test_status: 'failed', last_test_message: err.message }).eq('id', existing.id);
    res.status(400).json({ error: 'Test Send Failed', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 주문에 채널 출처를 기록하고 정산 원장에 반영한다. POST /api/orders 성공 이후 fire-and-forget으로 호출되며,
// 실패해도 이미 성사된 주문 자체를 되돌리지 않는다(주문 흐름의 안정성이 정산 기록보다 우선).
async function recordChannelOrderAttribution(orderId, orderNumber, finalPrice, channelId, userId, attribution) {
  const attr = attribution || {};
  await supabase.from('channel_ledger_live').insert([{
    channel_id: channelId, order_ref: orderNumber, party_role: 'channel', amount: finalPrice, status: 'pending',
    source_platform: attr.source_platform || null, campaign: attr.campaign || null,
    referrer_code: attr.referrer_code || null, coupon_code: attr.coupon_code || null
  }]);
  // 구매자가 이 채널의 팬(가입자)이면 구매 활동점수도 함께 적립 - 미가입자의 구매는 채널 매출로는
  // 잡히지만 팬 활동점수는 쌓이지 않는다(가입은 명시적 행동이어야 한다는 원칙, 위 awardFanActivity와 동일).
  // ref_id(orderId)를 반드시 함께 넘겨야 한다 - 넘기지 않으면 ref_id가 null로 저장되어, 사용자가 직접
  // POST /fan-activity를 호출할 때 저장되는 ref_id=order_id와 값이 달라져 (channel_id,user_id,action_type,ref_id)
  // 유니크 인덱스가 중복 지급을 잡아내지 못하고 이중 적립되는 버그가 있었다.
  await awardFanActivity(channelId, userId, 'purchase', orderId).catch(() => {});

}

// ============================================
// LIVE+ 채널 업종별 자격/등록정보 관리 - 관리자 전용
// ============================================
// 이 엔드포인트들은 자격의 법적 유효성을 판단하지 않는다. 형님(운영자)이 실제 법적 검토를 마친 뒤
// "확인된 자격 정보를 기록"하는 용도이며, 서버는 어떤 상품 판매도 이 정보를 근거로 자동 허용/차단하지 않는다.
//
// 상태 모델: "입력됨"과 "검증완료"는 절대 같은 상태가 아니다. 생성 직후에는 항상 submitted(입력됨)이고,
// 관리자가 증빙(document_ref)과 함께 명시적으로 verified 전환 액션을 호출해야만 검증완료로 바뀐다.
// 만료예정/만료는 DB에 저장하지 않고 expires_at을 기준으로 조회 시점에 계산해서 얹어준다(스케줄러 불필요,
// 항상 최신 값 보장). 모든 상태 변경은 channel_license_status_history_live에 append-only로 기록한다.
const LIVE_CHANNEL_LICENSE_TYPES = ['insurance_broker', 'prepaid_funeral_registration', 'burial_facility_permit', 'real_estate_broker', 'elder_care_facility_permit', 'other'];
const LIVE_CHANNEL_LICENSE_STATUSES = ['submitted', 'pending_review', 'verified', 'needs_more_info', 'suspended', 'revoked'];
const LIVE_LICENSE_EXPIRY_WARNING_DAYS = 30;

// expires_at 값을 기준으로 만료예정/만료 여부를 계산해 각 레코드에 얹어준다. 저장된 status와는 독립적인
// 표시 전용 값이며(expiry_state), 실제 status가 revoked/suspended 등이어도 만료 정보는 그대로 함께 보여준다.
function withLicenseExpiryState(license) {
  if (!license) return license;
  let expiry_state = 'none';
  if (license.expires_at) {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const expires = new Date(license.expires_at);
    const daysLeft = Math.ceil((expires - today) / (1000 * 60 * 60 * 24));
    if (daysLeft < 0) expiry_state = 'expired';
    else if (daysLeft <= LIVE_LICENSE_EXPIRY_WARNING_DAYS) expiry_state = 'expiring_soon';
    else expiry_state = 'valid';
  }
  return { ...license, expiry_state };
}

async function recordLicenseStatusChange(licenseId, fromStatus, toStatus, changedBy, note) {
  if (fromStatus === toStatus) return;
  await supabase.from('channel_license_status_history_live').insert([{
    license_id: licenseId, from_status: fromStatus || null, to_status: toStatus, changed_by: changedBy, note: note || null
  }]);
}

app.get('/api/admin/live/channels/:id/licenses', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('channel_licenses_live')
      .select('*').eq('channel_id', req.params.id).order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: (data || []).map(withLicenseExpiryState), count: (data || []).length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching channel licenses:', err);
    res.status(500).json({ error: 'Failed to fetch licenses', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/live/channels/:id/licenses/:licenseId/history', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('channel_license_status_history_live')
      .select('*, profiles(full_name, email)').eq('license_id', req.params.licenseId).order('changed_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [], count: (data || []).length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching license status history:', err);
    res.status(500).json({ error: 'Failed to fetch license history', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/live/channels/:id/licenses', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const {
      license_type, license_number, license_holder_name, license_holder_org, issuing_authority,
      issued_at, expires_at, region_scope, product_scope, engagement_ref, document_ref, notes
    } = req.body || {};
    if (!LIVE_CHANNEL_LICENSE_TYPES.includes(license_type)) {
      return res.status(400).json({ error: 'Bad Request', message: '유효하지 않은 자격 유형입니다', timestamp: new Date().toISOString() });
    }
    // 입력 즉시 검증완료로 표시되지 않도록 항상 submitted(입력됨)로 시작한다 - verified_by/verified_at도 비워둔다.
    const { data, error } = await supabase.from('channel_licenses_live').insert([{
      channel_id: req.params.id, license_type,
      license_number: license_number || null, license_holder_name: license_holder_name || null,
      license_holder_org: license_holder_org || null, issuing_authority: issuing_authority || null,
      issued_at: issued_at || null, expires_at: expires_at || null,
      region_scope: region_scope || null, product_scope: product_scope || null, engagement_ref: engagement_ref || null,
      document_ref: document_ref || null, notes: notes || null,
      status: 'submitted', verified_by: null, verified_at: null
    }]).select().single();
    if (error) throw error;
    await recordLicenseStatusChange(data.id, null, 'submitted', req.user.id, '최초 등록');
    res.status(201).json({ success: true, data: withLicenseExpiryState(data), timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating channel license:', err);
    res.status(500).json({ error: 'Failed to create license', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 정보 수정(내용 필드)과 상태 전환(status)을 분리해서 처리한다.
// status를 'verified'로 바꾸려면 document_ref(증빙 참조)가 있어야 하고, 그 순간에만 verified_by/verified_at을 채운다.
// 그 외 상태로 바뀌면 verified_by/verified_at은 지운다(과거에 검증됐다는 흔적이 최신 상태와 혼동되지 않도록).
app.patch('/api/admin/live/channels/:id/licenses/:licenseId', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: current, error: curErr } = await supabase.from('channel_licenses_live')
      .select('status, document_ref').eq('id', req.params.licenseId).eq('channel_id', req.params.id).maybeSingle();
    if (curErr) throw curErr;
    if (!current) return res.status(404).json({ error: 'Not Found', message: '자격정보를 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const updates = {};
    const allowedFields = [
      'license_number', 'license_holder_name', 'license_holder_org', 'issuing_authority',
      'issued_at', 'expires_at', 'region_scope', 'product_scope', 'engagement_ref',
      'status', 'document_ref', 'notes', 'status_note'
    ];
    allowedFields.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });
    const statusNote = updates.status_note; delete updates.status_note;

    if (updates.status !== undefined) {
      if (!LIVE_CHANNEL_LICENSE_STATUSES.includes(updates.status)) {
        return res.status(400).json({ error: 'Bad Request', message: '유효하지 않은 상태입니다', timestamp: new Date().toISOString() });
      }
      const effectiveDocumentRef = updates.document_ref !== undefined ? updates.document_ref : current.document_ref;
      if (updates.status === 'verified') {
        if (!effectiveDocumentRef) {
          return res.status(400).json({ error: 'Bad Request', message: '증빙 참조번호(document_ref) 없이는 검증완료로 전환할 수 없습니다', timestamp: new Date().toISOString() });
        }
        updates.verified_by = req.user.id;
        updates.verified_at = new Date().toISOString();
      } else {
        updates.verified_by = null;
        updates.verified_at = null;
      }
    }

    updates.updated_at = new Date().toISOString();
    const { data, error } = await supabase.from('channel_licenses_live')
      .update(updates).eq('id', req.params.licenseId).eq('channel_id', req.params.id).select().single();
    if (error) throw error;

    if (updates.status !== undefined) {
      await recordLicenseStatusChange(req.params.licenseId, current.status, updates.status, req.user.id, statusNote);
    }

    res.json({ success: true, data: withLicenseExpiryState(data), timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating channel license:', err);
    res.status(500).json({ error: 'Failed to update license', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.delete('/api/admin/live/channels/:id/licenses/:licenseId', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { error } = await supabase.from('channel_licenses_live')
      .delete().eq('id', req.params.licenseId).eq('channel_id', req.params.id);
    if (error) throw error;
    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting channel license:', err);
    res.status(500).json({ error: 'Failed to delete license', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// LIVE+ 세션별 재고예약 (라이브 배정재고 · 장바구니/결제진행 예약 · 만료 · 확정 · 취소/복원)
// ============================================
// 동시주문 방지는 Postgres 함수(reserve/confirm/release_live_session_inventory) 내부의 단일
// UPDATE...WHERE로 원자적으로 처리한다. 만료는 스케줄러 없이 "조회/예약 시점에 지난 예약을 정리"하는
// 지연 방식(lazy sweep)으로 처리해 클라우드 재시작 등으로 스케줄이 유실될 걱정이 없게 했다.
const LIVE_RESERVATION_TTL_MS = { cart: 15 * 60 * 1000, checkout: 10 * 60 * 1000 };

function withAvailableQty(inv) {
  if (!inv) return inv;
  const available_qty = Math.max(inv.allocated_qty - inv.safety_stock - inv.reserved_qty - inv.sold_qty, 0);
  return { ...inv, available_qty };
}

// 만료 시각이 지난(cart/checkout 상태 그대로 남아있는) 예약들을 찾아 재고를 되돌리고 상태를 expired로 바꾼다.
async function expireStaleLiveReservations(liveSessionId, productId) {
  const { data: stale } = await supabase.from('live_session_reservations_live')
    .select('*').eq('live_session_id', liveSessionId).eq('product_id', productId)
    .in('status', ['cart', 'checkout']).lt('expires_at', new Date().toISOString());
  if (!stale || stale.length === 0) return;
  const { data: inv } = await supabase.from('live_session_inventory_live')
    .select('id').eq('live_session_id', liveSessionId).eq('product_id', productId).maybeSingle();
  for (const r of stale) {
    if (inv) {
      await supabase.rpc('release_live_session_inventory', { p_inventory_id: inv.id, p_qty: r.quantity });
      await supabase.from('live_session_inventory_log_live').insert([{
        inventory_id: inv.id, reservation_id: r.id, change_type: 'expire', delta_reserved: -r.quantity, note: '예약 시간 만료로 자동 해제'
      }]);
    }
    await supabase.from('live_session_reservations_live').update({ status: 'expired', updated_at: new Date().toISOString() }).eq('id', r.id);
  }
}

// 주문 생성이 성공한 뒤 호출된다 - 이미 reserved 상태로 재고를 선점해둔 예약을 sold로 확정한다.
// 소유자가 아니거나 이미 처리/만료된 예약 ID가 섞여 들어와도(악의적 조작 포함) 조용히 건너뛴다 -
// 재고 확정은 반드시 "실제로 이 사용자가 이 세션에서 잡아둔, 아직 유효한 예약"에 대해서만 일어나야 한다.
async function confirmLiveSessionReservations(reservationIds, userId, orderId) {
  for (const reservationId of reservationIds) {
    const { data: reservation } = await supabase.from('live_session_reservations_live').select('*').eq('id', reservationId).maybeSingle();
    if (!reservation || reservation.user_id !== userId) continue;
    if (!['cart', 'checkout'].includes(reservation.status)) continue;
    if (reservation.expires_at && new Date(reservation.expires_at) < new Date()) continue;

    const { data: inv } = await supabase.from('live_session_inventory_live')
      .select('id').eq('live_session_id', reservation.live_session_id).eq('product_id', reservation.product_id).maybeSingle();
    if (!inv) continue;

    await supabase.rpc('confirm_live_session_inventory', { p_inventory_id: inv.id, p_qty: reservation.quantity });
    await supabase.from('live_session_reservations_live')
      .update({ status: 'confirmed', order_id: orderId, updated_at: new Date().toISOString() }).eq('id', reservationId);
    await supabase.from('live_session_inventory_log_live').insert([{
      inventory_id: inv.id, reservation_id: reservationId, change_type: 'confirm',
      delta_reserved: -reservation.quantity, delta_sold: reservation.quantity, actor_user_id: userId, note: `주문 확정 - ${orderId}`
    }]);
  }
}

// 라이브 세션에 상품별 재고 풀을 배정/재배정한다. 채널에 이미 등록된 상품만 배정 가능.
// 주의: products_with.stock(전체 재고)과는 별개의 "이 세션에 얼마나 내주기로 했는지"를 관리하는 풀이며,
// 전체 재고와의 정합성(더 많이 배정하지 않기)은 운영자 책임 - 자동으로 상호 검증하지 않는다.
app.post('/api/admin/live/channels/:id/sessions/:sessionId/inventory', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { product_id, allocated_qty, safety_stock } = req.body || {};
    const allocQty = parseInt(allocated_qty, 10);
    const safety = safety_stock !== undefined ? parseInt(safety_stock, 10) : 0;
    if (!product_id) return res.status(400).json({ error: 'Bad Request', message: 'product_id는 필수입니다', timestamp: new Date().toISOString() });
    if (!Number.isInteger(allocQty) || allocQty < 0) return res.status(400).json({ error: 'Bad Request', message: 'allocated_qty는 0 이상의 정수여야 합니다', timestamp: new Date().toISOString() });
    if (!Number.isInteger(safety) || safety < 0) return res.status(400).json({ error: 'Bad Request', message: 'safety_stock는 0 이상의 정수여야 합니다', timestamp: new Date().toISOString() });

    const { data: link } = await supabase.from('channel_products_live').select('id').eq('channel_id', req.params.id).eq('product_id', product_id).maybeSingle();
    if (!link) return res.status(400).json({ error: 'Bad Request', message: '이 채널에 등록되지 않은 상품에는 재고를 배정할 수 없습니다', timestamp: new Date().toISOString() });

    const { data: existing } = await supabase.from('live_session_inventory_live')
      .select('*').eq('live_session_id', req.params.sessionId).eq('product_id', product_id).maybeSingle();

    const { data, error } = await supabase.from('live_session_inventory_live')
      .upsert([{ live_session_id: req.params.sessionId, product_id, allocated_qty: allocQty, safety_stock: safety }], { onConflict: 'live_session_id,product_id' })
      .select().single();
    if (error) throw error;

    await supabase.from('live_session_inventory_log_live').insert([{
      inventory_id: data.id, change_type: 'allocate',
      delta_allocated: allocQty - (existing?.allocated_qty || 0), actor_user_id: req.user.id,
      note: existing ? `재배정: 배정재고 ${existing.allocated_qty}→${allocQty}, 안전재고 ${existing.safety_stock}→${safety}` : `최초 배정: ${allocQty}개, 안전재고 ${safety}개`
    }]);

    res.status(201).json({ success: true, data: withAvailableQty(data), timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error allocating live session inventory:', err);
    res.status(500).json({ error: 'Failed to allocate inventory', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/live/channels/:id/sessions/:sessionId/inventory', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_session_inventory_live')
      .select('*, products_with(id, name, images_urls)').eq('live_session_id', req.params.sessionId).order('created_at', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: (data || []).map(withAvailableQty), count: (data || []).length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching live session inventory:', err);
    res.status(500).json({ error: 'Failed to fetch inventory', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공개 가용재고 조회 - 시청 화면에서 "N개 남음" 표시용. 관리자 내부 수치(sold_qty 등)는 노출하지 않는다.
app.get('/api/live/channels/:slug/sessions/:sessionId/inventory', async (req, res) => {
  try {
    const { data: channel } = await supabase.from('channels_live').select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const { data: rows, error } = await supabase.from('live_session_inventory_live')
      .select('product_id, allocated_qty, safety_stock, reserved_qty, sold_qty').eq('live_session_id', req.params.sessionId);
    if (error) throw error;
    for (const r of (rows || [])) await expireStaleLiveReservations(req.params.sessionId, r.product_id);
    const { data: freshRows } = await supabase.from('live_session_inventory_live')
      .select('product_id, allocated_qty, safety_stock, reserved_qty, sold_qty').eq('live_session_id', req.params.sessionId);
    const data = (freshRows || []).map(r => ({ product_id: r.product_id, available_qty: withAvailableQty(r).available_qty }));
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching public live session inventory:', err);
    res.status(500).json({ error: 'Failed to fetch inventory', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 타임세일 / 카운트다운 (매출견인기능 격차분석 2-2) — 방송 중 관리자가 "지금부터 N분간 이 상품 할인" 버튼을
// 누르면 이 상품의 결제 단가가 일시적으로 낮아지고, 시청 화면에는 남은 시간이 카운트다운으로 표시된다.
// 만료(ends_at 경과) 또는 취소(cancelled_at)되면 즉시 원래 라이브 채널가로 돌아간다 - 이미 있는 채널가격정책
// 엔진(product_channel_prices_with, channel='live')을 대체하는 게 아니라 "그 위에 시간 한정으로 얹는" 개념.
// ============================================
async function cancelActiveFlashSale(sessionId, productId) {
  await supabase.from('live_flash_sales_live')
    .update({ cancelled_at: new Date().toISOString() })
    .eq('live_session_id', sessionId).eq('product_id', productId)
    .is('cancelled_at', null).gt('ends_at', new Date().toISOString());
}

// 관리자: 타임세일 시작 - 같은 상품에 이미 진행 중인 타임세일이 있으면 먼저 종료시키고 새로 시작한다(조건 변경 가능하게).
app.post('/api/admin/live/channels/:id/sessions/:sessionId/flash-sales', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { product_id, discount_price, discount_percent, duration_minutes } = req.body || {};
    if (!product_id) {
      return res.status(400).json({ error: 'Bad Request', message: 'product_id는 필수입니다', timestamp: new Date().toISOString() });
    }
    const minutes = Number(duration_minutes) || 10;
    if (!Number.isFinite(minutes) || minutes < 1 || minutes > 180) {
      return res.status(400).json({ error: 'Bad Request', message: 'duration_minutes는 1~180 사이여야 합니다', timestamp: new Date().toISOString() });
    }

    const { data: session } = await supabase.from('live_sessions_live').select('id, status').eq('id', req.params.sessionId).eq('channel_id', req.params.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const { data: link } = await supabase.from('channel_products_live').select('id').eq('channel_id', req.params.id).eq('product_id', product_id).maybeSingle();
    if (!link) return res.status(400).json({ error: 'Bad Request', message: '이 채널에 등록되지 않은 상품입니다', timestamp: new Date().toISOString() });

    const { data: product } = await supabase.from('products_with').select('id, price, cost_price, category').eq('id', product_id).maybeSingle();
    if (!product) return res.status(404).json({ error: 'Not Found', message: '상품을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    // 기준가(원래 라이브 채널가)를 먼저 구해서, discount_percent로 넘어온 경우 이 값 기준으로 할인가를 계산한다.
    const basePrice = (await resolveLiveChannelPrices([{ id: product.id, cost_price: product.cost_price, category: product.category, fallbackPrice: product.price }]))[product.id];

    let discountPrice;
    if (discount_price !== undefined && discount_price !== null && discount_price !== '') {
      discountPrice = Number(discount_price);
    } else if (discount_percent !== undefined && discount_percent !== null && discount_percent !== '') {
      const pct = Number(discount_percent);
      if (!Number.isFinite(pct) || pct <= 0 || pct >= 100) {
        return res.status(400).json({ error: 'Bad Request', message: 'discount_percent는 0~100 사이여야 합니다', timestamp: new Date().toISOString() });
      }
      discountPrice = Math.round(basePrice * (1 - pct / 100));
    } else {
      return res.status(400).json({ error: 'Bad Request', message: 'discount_price 또는 discount_percent 중 하나는 필요합니다', timestamp: new Date().toISOString() });
    }
    if (!Number.isFinite(discountPrice) || discountPrice < 0) {
      return res.status(400).json({ error: 'Bad Request', message: '할인가가 올바르지 않습니다', timestamp: new Date().toISOString() });
    }
    if (discountPrice >= basePrice) {
      return res.status(400).json({ error: 'Bad Request', message: `할인가(${discountPrice})는 현재 판매가(${basePrice})보다 낮아야 합니다`, timestamp: new Date().toISOString() });
    }

    await cancelActiveFlashSale(req.params.sessionId, product_id);

    const startsAt = new Date();
    const endsAt = new Date(startsAt.getTime() + minutes * 60 * 1000);
    const { data, error } = await supabase.from('live_flash_sales_live').insert([{
      live_session_id: req.params.sessionId,
      product_id,
      discount_price: discountPrice,
      original_price: basePrice,
      starts_at: startsAt.toISOString(),
      ends_at: endsAt.toISOString(),
      created_by: req.user.id
    }]).select().single();
    if (error) throw error;

    res.status(201).json({ success: true, data, message: `${minutes}분간 타임세일을 시작했습니다`, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error starting flash sale:', err);
    res.status(500).json({ error: 'Failed to start flash sale', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 이 세션의 타임세일 이력 조회 (현재 진행중 + 과거분 전부)
app.get('/api/admin/live/channels/:id/sessions/:sessionId/flash-sales', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_flash_sales_live')
      .select('*, products_with(id, name, images_urls)')
      .eq('live_session_id', req.params.sessionId)
      .order('created_at', { ascending: false });
    if (error) throw error;
    const now = new Date().toISOString();
    const data2 = (data || []).map(f => ({ ...f, is_active: !f.cancelled_at && f.ends_at > now }));
    res.json({ success: true, data: data2, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching flash sales:', err);
    res.status(500).json({ error: 'Failed to fetch flash sales', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 타임세일 조기 종료
app.patch('/api/admin/live/channels/:id/sessions/:sessionId/flash-sales/:flashSaleId/cancel', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_flash_sales_live')
      .update({ cancelled_at: new Date().toISOString() })
      .eq('id', req.params.flashSaleId).eq('live_session_id', req.params.sessionId)
      .select().maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '타임세일을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({ success: true, data, message: '타임세일을 종료했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error cancelling flash sale:', err);
    res.status(500).json({ error: 'Failed to cancel flash sale', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공개: 현재 진행 중인 타임세일만 - 시청화면 카운트다운 표시용 (3~5초 폴링 예상). 관리자 내부 컬럼은 노출하지 않는다.
app.get('/api/live/channels/:slug/sessions/:sessionId/flash-sales', async (req, res) => {
  try {
    const { data: channel } = await supabase.from('channels_live').select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const now = new Date().toISOString();
    const { data, error } = await supabase.from('live_flash_sales_live')
      .select('id, product_id, discount_price, original_price, ends_at, products_with(id, name, images_urls)')
      .eq('live_session_id', req.params.sessionId)
      .is('cancelled_at', null)
      .gt('ends_at', now)
      .lte('starts_at', now);
    if (error) throw error;
    res.json({ success: true, data: data || [], timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching public flash sales:', err);
    res.status(500).json({ error: 'Failed to fetch flash sales', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 장바구니(cart) 또는 결제진행(checkout) 단계로 재고를 예약한다. 이미 가입된 팬이 아니어도 예약은 누구나 할 수 있다
// (구매 자체는 비회원도 가능한 정책과 동일 선상) - 팬 활동점수는 실제 결제 확정 시에만 반영된다.
app.post('/api/live/channels/:slug/sessions/:sessionId/reservations', authenticate, async (req, res) => {
  try {
    const { product_id, quantity, stage } = req.body || {};
    const qty = parseInt(quantity, 10);
    const reservationStage = stage === 'checkout' ? 'checkout' : 'cart';
    if (!product_id || !Number.isInteger(qty) || qty <= 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'product_id와 1 이상의 정수 quantity가 필요합니다', timestamp: new Date().toISOString() });
    }
    const { data: channel } = await supabase.from('channels_live').select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const { data: session } = await supabase.from('live_sessions_live').select('id, status').eq('id', req.params.sessionId).eq('channel_id', channel.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    // 세션별 재고예약은 "지금 방송 중인 세션"에 한해서만 새로 만들 수 있다 - scheduled(아직 시작 전)나
    // ended(이미 종료됨) 세션의 오래된 딥링크로 들어와도 예약이 되어버리는 걸 막는 최소한의 방어.
    // (이미 만들어진 예약을 결제까지 완료하는 것은 세션이 그 사이 종료돼도 막지 않는다 - 방송 중에 정당하게
    // 확보한 예약을 방송 종료 타이밍 때문에 취소시키는 건 나쁜 UX이므로 별개로 취급)
    if (session.status !== 'live') {
      return res.status(409).json({ error: 'Conflict', message: '현재 방송 중인 세션이 아니므로 재고를 예약할 수 없습니다', timestamp: new Date().toISOString() });
    }

    await expireStaleLiveReservations(req.params.sessionId, product_id);

    const { data: inv } = await supabase.from('live_session_inventory_live')
      .select('*').eq('live_session_id', req.params.sessionId).eq('product_id', product_id).maybeSingle();
    if (!inv) return res.status(400).json({ error: 'Bad Request', message: '이 세션에 배정된 재고가 없습니다', timestamp: new Date().toISOString() });

    // 매점(사재기) 방지: 계정 하나가 이 세션+상품에 대해 cart/checkout 상태로 보유할 수 있는 예약 수량에
    // 상한을 둔다 (배정재고의 30%, 최소 1개). 여러 번에 걸쳐 나눠서 예약해도 합산 기준으로 막는다.
    const perUserReservationCap = Math.max(1, Math.ceil(inv.allocated_qty * 0.3));
    const { data: existingUserReservations } = await supabase.from('live_session_reservations_live')
      .select('quantity').eq('live_session_id', req.params.sessionId).eq('product_id', product_id)
      .eq('user_id', req.user.id).in('status', ['cart', 'checkout']);
    const alreadyHeldQty = (existingUserReservations || []).reduce((sum, r) => sum + (Number(r.quantity) || 0), 0);
    if (alreadyHeldQty + qty > perUserReservationCap) {
      return res.status(400).json({
        error: 'Bad Request',
        message: `계정당 이 상품은 최대 ${perUserReservationCap}개까지만 예약할 수 있습니다 (현재 보유 ${alreadyHeldQty}개)`,
        timestamp: new Date().toISOString()
      });
    }

    const { data: reserved } = await supabase.rpc('reserve_live_session_inventory', { p_inventory_id: inv.id, p_qty: qty });

    // PostgREST가 SQL NULL을 "필드가 전부 null인 객체"로 내려줄 가능성까지 방어적으로 함께 확인한다 -
    // id가 없다는 것은 곧 WHERE 조건(가용재고 충분)을 만족하는 행이 없었다는 뜻(재고 부족).
    if (!reserved || !reserved.id) return res.status(409).json({ error: 'Conflict', message: '재고가 부족합니다', timestamp: new Date().toISOString() });

    const expiresAt = new Date(Date.now() + LIVE_RESERVATION_TTL_MS[reservationStage]).toISOString();
    const { data: reservation, error: rErr } = await supabase.from('live_session_reservations_live').insert([{
      live_session_id: req.params.sessionId, product_id, user_id: req.user.id, quantity: qty, status: reservationStage, expires_at: expiresAt
    }]).select().single();
    if (rErr) throw rErr;

    await supabase.from('live_session_inventory_log_live').insert([{
      inventory_id: inv.id, reservation_id: reservation.id, change_type: 'reserve', delta_reserved: qty, actor_user_id: req.user.id,
      note: `${reservationStage === 'checkout' ? '결제진행' : '장바구니'} 예약`
    }]);

    res.status(201).json({ success: true, data: { ...reservation, available_qty: withAvailableQty(reserved).available_qty }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating live session reservation:', err);
    res.status(500).json({ error: 'Failed to create reservation', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 예약 단계 전환(cart→checkout, 만료시간 연장) 또는 취소. 본인 예약만 조작 가능.
app.patch('/api/live/channels/:slug/sessions/:sessionId/reservations/:reservationId', authenticate, async (req, res) => {
  try {
    const { data: reservation } = await supabase.from('live_session_reservations_live')
      .select('*').eq('id', req.params.reservationId).eq('live_session_id', req.params.sessionId).maybeSingle();
    if (!reservation) return res.status(404).json({ error: 'Not Found', message: '예약을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (reservation.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden', message: '본인의 예약만 변경할 수 있습니다', timestamp: new Date().toISOString() });
    if (!['cart', 'checkout'].includes(reservation.status)) {
      return res.status(409).json({ error: 'Conflict', message: `이미 ${reservation.status} 상태인 예약은 변경할 수 없습니다`, timestamp: new Date().toISOString() });
    }

    const { data: inv } = await supabase.from('live_session_inventory_live')
      .select('*').eq('live_session_id', reservation.live_session_id).eq('product_id', reservation.product_id).maybeSingle();

    if (req.body?.action === 'cancel') {
      if (inv) {
        await supabase.rpc('release_live_session_inventory', { p_inventory_id: inv.id, p_qty: reservation.quantity });
        await supabase.from('live_session_inventory_log_live').insert([{
          inventory_id: inv.id, reservation_id: reservation.id, change_type: 'cancel', delta_reserved: -reservation.quantity, actor_user_id: req.user.id, note: '구매자 취소'
        }]);
      }
      const { data, error } = await supabase.from('live_session_reservations_live')
        .update({ status: 'cancelled', updated_at: new Date().toISOString() }).eq('id', reservation.id).select().single();
      if (error) throw error;
      return res.json({ success: true, data, timestamp: new Date().toISOString() });
    }

    const nextStage = req.body?.stage === 'checkout' ? 'checkout' : (req.body?.stage === 'cart' ? 'cart' : null);
    if (!nextStage) return res.status(400).json({ error: 'Bad Request', message: "action:'cancel' 또는 stage:'cart'|'checkout'가 필요합니다", timestamp: new Date().toISOString() });

    // stage 전환마다(cart↔checkout) TTL이 매번 새로 연장되는 것을 이용해 무제한으로 재고를 붙잡아두는 것을
    // 막기 위해, 최초 예약 생성 시각(created_at) 기준 절대 만료시각을 둔다 - 아무리 전환을 반복해도 이
    // 절대 만료시각을 넘어서 연장될 수는 없다(카운터 컬럼을 새로 추가하는 대신 이미 있는 created_at으로 계산).
    const LIVE_RESERVATION_ABSOLUTE_MAX_MS = 20 * 60 * 1000;
    const absoluteExpiryAt = new Date(new Date(reservation.created_at).getTime() + LIVE_RESERVATION_ABSOLUTE_MAX_MS);
    const proposedExpiryAt = new Date(Date.now() + LIVE_RESERVATION_TTL_MS[nextStage]);
    const expiresAt = (proposedExpiryAt > absoluteExpiryAt ? absoluteExpiryAt : proposedExpiryAt).toISOString();
    const { data, error } = await supabase.from('live_session_reservations_live')
      .update({ status: nextStage, expires_at: expiresAt, updated_at: new Date().toISOString() }).eq('id', reservation.id).select().single();
    if (error) throw error;

    if (inv) {
      await supabase.from('live_session_inventory_log_live').insert([{
        inventory_id: inv.id, reservation_id: reservation.id, change_type: 'extend', actor_user_id: req.user.id, note: `${reservation.status}→${nextStage} 전환, 만료시각 연장`
      }]);
    }
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating live session reservation:', err);
    res.status(500).json({ error: 'Failed to update reservation', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// LIVE+ 딥링크·QR 출처 추적
// ============================================
// 채널·세션·상품(고정핀)·호스트는 서버가 채워주고, 유입플랫폼/캠페인/추천인/쿠폰은 호출하는 쪽(공유 버튼,
// QR 생성기)이 쿼리스트링으로 지정한다. 이렇게 만들어진 링크를 그대로 주문 생성 시 live_attribution으로
// 되돌려보내면 orders_with·channel_ledger_live까지 출처가 그대로 보존된다.
app.get('/api/live/channels/:slug/sessions/:sessionId/deep-link', async (req, res) => {
  try {
    const { data: channel } = await supabase.from('channels_live').select('id, slug, owner_user_id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const { data: session } = await supabase.from('live_sessions_live').select('id, pinned_product_id').eq('id', req.params.sessionId).eq('channel_id', channel.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const params = new URLSearchParams();
    params.set('session', session.id);
    if (session.pinned_product_id) params.set('product', session.pinned_product_id);
    if (channel.owner_user_id) params.set('host', channel.owner_user_id);
    ['platform', 'campaign', 'ref', 'coupon'].forEach(k => { if (req.query[k]) params.set(k, String(req.query[k])); });

    res.json({ success: true, data: { deep_link: `/live/${channel.slug}?${params.toString()}` }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error building live deep link:', err);
    res.status(500).json({ error: 'Failed to build deep link', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 🎁 바이럴 공유쿠폰(소문내면 할인) - 회원: 이 세션에서 나만의 공유링크(코드)를 가져오거나 새로 만든다.
// 이미 만든 적이 있으면 새로 만들지 않고 그대로 재사용한다(계속 눌러도 같은 링크가 나옴).
app.get('/api/live/channels/:slug/sessions/:sessionId/share-coupon-link', authenticate, async (req, res) => {
  try {
    const settings = await getLiveShareCouponSettings();
    const { data: channel } = await supabase.from('channels_live').select('id, slug, owner_user_id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const { data: session } = await supabase.from('live_sessions_live').select('id, pinned_product_id').eq('id', req.params.sessionId).eq('channel_id', channel.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const shareCode = await getOrCreateShareLink(session.id, channel.id, req.user.id);
    const params = new URLSearchParams();
    params.set('session', session.id);
    if (session.pinned_product_id) params.set('product', session.pinned_product_id);
    if (channel.owner_user_id) params.set('host', channel.owner_user_id);
    params.set('share', shareCode);

    res.json({
      success: true,
      data: { share_code: shareCode, deep_link: `/live/${channel.slug}?${params.toString()}`, discount_percent: settings.discount_percent },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error creating share coupon link:', err);
    res.status(500).json({ error: 'Failed to create share coupon link', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// LIVE+ 세션별 실시간 채팅
// ============================================
// 방송을 보며 대화한다는 목적에 맞게 폴링(3초 간격, 클라이언트 쪽) 기반으로 단순하게 구현한다 - 이 프로젝트
// 전체가 지금까지 지켜온 "스케줄러/지속연결 없이 읽는 시점에 처리" 원칙과 동일 (클라우드 샌드박스가 지속
// 프로세스에 취약했던 전례 때문에 WebSocket/Realtime 구독 대신 REST 폴링을 선택).
const LIVE_CHAT_RATE_LIMIT_MS = 2000; // 같은 사용자가 이 시간 안에 다시 보내면 거부(도배 방지)

// 채팅에는 실명을 그대로 노출하지 않는다 - 상품평 공개 API(/api/reviews/recent)가 애초에 작성자 이름을
// 아예 내려주지 않는 것과 같은 이유(개인정보 보호). 채팅은 누가 말했는지 구분은 되어야 하므로 완전히
// 숨기는 대신 가운데를 마스킹한다 (예: "홍길동" → "홍*동", "이몽" → "이*").
function maskChatDisplayName(name) {
  const trimmed = (name || '').trim();
  if (!trimmed) return '방문자';
  if (trimmed.length === 1) return trimmed + '*';
  if (trimmed.length === 2) return trimmed[0] + '*';
  return trimmed[0] + '*'.repeat(trimmed.length - 2) + trimmed[trimmed.length - 1];
}

// 채팅 메시지 목록(공개) - 방송이 끝난 뒤에도 지나간 채팅 로그는 볼 수 있다(예약과 동일하게 "읽기"는 항상 허용,
// "새로 보내기"만 라이브 중으로 제한). after(ISO 시각)를 넘기면 그 이후에 새로 달린 메시지만 돌려준다(폴링용).
app.get('/api/live/channels/:slug/sessions/:sessionId/chat', optionalAuth, async (req, res) => {
  try {
    const { data: channel } = await supabase.from('channels_live').select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const { data: session } = await supabase.from('live_sessions_live').select('id').eq('id', req.params.sessionId).eq('channel_id', channel.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    // 세 가지 조회 모드를 하나의 엔드포인트가 담당한다:
    // - after: 폴링용. 이 시각 이후 새로 달린 메시지를 시간순으로(오래된 것부터) 가져온다.
    // - before: "이전 메시지 더 보기"용 페이지네이션. 이 시각보다 오래된 메시지를 최신순으로 limit개
    //   가져온 뒤(무한정 위로 스크롤해도 한 번에 조금씩만 불러오도록) 화면에 표시할 때는 시간순으로 뒤집는다.
    // - 파라미터 없음: 최초 로드. 가장 최근 limit개.
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
    let query = supabase.from('live_session_chat_messages_live')
      .select('id, message, created_at, user_id, message_type, profiles!live_session_chat_messages_live_user_id_fkey(full_name, email)')
      .eq('live_session_id', req.params.sessionId).eq('is_hidden', false);

    let mode;
    if (req.query.after) {
      mode = 'after';
      query = query.gt('created_at', req.query.after).order('created_at', { ascending: true }).limit(200);
    } else if (req.query.before) {
      mode = 'before';
      query = query.lt('created_at', req.query.before).order('created_at', { ascending: false }).limit(limit);
    } else {
      mode = 'initial';
      query = query.order('created_at', { ascending: false }).limit(limit);
    }
    const { data, error } = await query;
    if (error) throw error;

    let rows = data || [];
    const hasMore = mode !== 'after' && rows.length === limit; // 정확한 총 개수 대신 "요청한 만큼 꽉 찼다"는 근사치로 판단
    if (mode !== 'after') rows = rows.reverse(); // before/initial은 최신순으로 가져온 뒤 시간순으로 뒤집어서 반환한다

    // 🎤 라이트 멀티호스트(B8) - 이 세션에 지금 활동 중인 게스트의 user_id 집합을 미리 가져와서
    // 각 메시지가 게스트가 보낸 것인지 표시한다 (채팅 배지용)
    const userIdsInPage = [...new Set(rows.map(r => r.user_id).filter(Boolean))];
    let guestUserIds = new Set();
    if (userIdsInPage.length > 0) {
      const { data: activeGuests } = await supabase.from('live_session_guests_live')
        .select('user_id').eq('live_session_id', req.params.sessionId).eq('status', 'active').in('user_id', userIdsInPage);
      guestUserIds = new Set((activeGuests || []).map(g => g.user_id));
    }

    const messages = rows.map(r => ({
      id: r.id,
      message: r.message,
      created_at: r.created_at,
      is_mine: req.user ? r.user_id === req.user.id : false, // 비로그인 조회에서는 항상 false
      display_name: maskChatDisplayName(r.profiles ? (r.profiles.full_name || r.profiles.email) : null),
      message_type: r.message_type || 'normal',
      is_guest: guestUserIds.has(r.user_id)
    }));

    res.json({ success: true, data: messages, count: messages.length, has_more: hasMore, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching live chat messages:', err);
    res.status(500).json({ error: 'Failed to fetch chat messages', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 채팅 메시지 전송(로그인 필요) - 재고예약과 동일하게 "지금 방송 중"일 때만 새로 보낼 수 있다.
app.post('/api/live/channels/:slug/sessions/:sessionId/chat', authenticate, liveChatLimiter, async (req, res) => {

  try {
    const message = String(req.body?.message || '').trim();
    if (!message) return res.status(400).json({ error: 'Bad Request', message: '메시지를 입력해주세요', timestamp: new Date().toISOString() });
    if (message.length > 200) return res.status(400).json({ error: 'Bad Request', message: '메시지는 200자를 넘을 수 없습니다', timestamp: new Date().toISOString() });

    const { data: channel } = await supabase.from('channels_live').select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const { data: session } = await supabase.from('live_sessions_live').select('id, status').eq('id', req.params.sessionId).eq('channel_id', channel.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (session.status !== 'live') {
      return res.status(409).json({ error: 'Conflict', message: '현재 방송 중인 세션이 아니므로 채팅을 보낼 수 없습니다', timestamp: new Date().toISOString() });
    }

    // 도배 방지 - 같은 사용자가 이 세션에 방금 보낸 메시지가 있으면 거부
    const { data: lastMsg } = await supabase.from('live_session_chat_messages_live')
      .select('created_at').eq('live_session_id', req.params.sessionId).eq('user_id', req.user.id)
      .order('created_at', { ascending: false }).limit(1).maybeSingle();
    if (lastMsg && Date.now() - new Date(lastMsg.created_at).getTime() < LIVE_CHAT_RATE_LIMIT_MS) {
      return res.status(429).json({ error: 'Too Many Requests', message: '메시지를 너무 빠르게 보내고 있어요. 잠시 후 다시 시도해주세요', timestamp: new Date().toISOString() });
    }

    const { data: profile } = await supabase.from('profiles').select('full_name, email').eq('id', req.user.id).maybeSingle();
    const { data: inserted, error: insErr } = await supabase.from('live_session_chat_messages_live')
      .insert([{ live_session_id: req.params.sessionId, channel_id: channel.id, user_id: req.user.id, message }])
      .select('id, message, created_at').single();
    if (insErr) throw insErr;

    // ⚡ 실시간 퀴즈(매출견인기능 격차분석 2-4) - 이 세션에 지금 열려있는 퀴즈가 있고 이 메시지가 정답이면
    // 자동으로 라이브 전용 쿠폰을 발급한다. 채팅 메시지 자체는 항상 정상적으로 저장(다른 사용자도 그대로 봄)하고,
    // 그 위에 "정답이었다"는 결과만 이 응답에 추가로 실어 보낸다 - 채팅 자체가 실패하는 일은 없어야 하므로
      // 퀴즈 판정 중 오류가 나도 채팅 전송 자체는 이미 성공 처리된 뒤이다.
    let quizResult = null;
    try {
      quizResult = await tryAwardQuizWin(req.params.sessionId, req.user.id, message, inserted.id);
    } catch (quizErr) {
      console.error('Error evaluating quiz answer:', quizErr);
    }

    // 🎤 라이트 멀티호스트(B8) - 이 메시지를 보낸 사람이 지금 이 세션의 활동 중인 게스트인지 확인해 배지 표시용으로 실어보낸다
    let isGuest = false;
    try {
      const { data: guestRow } = await supabase.from('live_session_guests_live')
        .select('id').eq('live_session_id', req.params.sessionId).eq('user_id', req.user.id).eq('status', 'active').maybeSingle();
      isGuest = !!guestRow;
    } catch (guestErr) {
      console.error('Error checking live guest status:', guestErr);
    }

    res.status(201).json({
      success: true,
      data: { id: inserted.id, message: inserted.message, created_at: inserted.created_at, is_mine: true, display_name: maskChatDisplayName(profile ? (profile.full_name || profile.email) : null), message_type: quizResult ? 'quiz_correct' : 'normal', quiz_result: quizResult, is_guest: isGuest },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error posting live chat message:', err);
    res.status(500).json({ error: 'Failed to post chat message', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🎁 실시간 가상 선물/후원 (경쟁사 기능 격차분석 #6) — 새 PG/결제 연동 없이 기존 마일리지 시스템을
// "선물 재화"로 재사용한다. 시청자가 마일리지로 선물을 보내면 즉시 방송 채널 소유자에게 마일리지가
// 적립되고, 채팅창에 message_type:'gift' 메시지로 노출돼 기존 채팅 폴링 인프라를 그대로 재사용한다.
// ============================================
const DEFAULT_GIFT_CATALOG = [
  { key: 'heart', emoji: '❤️', label: '하트', cost: 100 },
  { key: 'rose', emoji: '🌹', label: '장미', cost: 500 },
  { key: 'coffee', emoji: '☕', label: '커피 한잔', cost: 1000 },
  { key: 'diamond', emoji: '💎', label: '다이아', cost: 5000 },
  { key: 'crown', emoji: '👑', label: '왕관', cost: 10000 }
];
let giftCatalogCache = null;
let giftCatalogCacheAt = 0;
const GIFT_CATALOG_CACHE_TTL_MS = 60 * 1000;

function normalizeGiftCatalog(value) {
  if (!Array.isArray(value) || value.length === 0) return DEFAULT_GIFT_CATALOG;
  const out = [];
  for (const item of value) {
    if (!item || typeof item !== 'object') continue;
    const key = String(item.key || '').trim();
    const emoji = String(item.emoji || '').trim();
    const label = String(item.label || '').trim();
    const cost = Number(item.cost);
    if (!key || !emoji || !label || !Number.isFinite(cost) || cost <= 0) continue;
    out.push({ key, emoji, label, cost: Math.round(cost) });
  }
  return out.length > 0 ? out : DEFAULT_GIFT_CATALOG;
}

async function getGiftCatalog() {
  const now = Date.now();
  if (giftCatalogCache && (now - giftCatalogCacheAt) < GIFT_CATALOG_CACHE_TTL_MS) return giftCatalogCache;
  try {
    const { data } = await supabase.from('platform_settings').select('value').eq('key', 'live_gift_catalog').maybeSingle();
    giftCatalogCache = normalizeGiftCatalog(data ? data.value : null);
  } catch (err) {
    console.error('선물 카탈로그 조회 오류:', err.message);
    giftCatalogCache = DEFAULT_GIFT_CATALOG;
  }
  giftCatalogCacheAt = now;
  return giftCatalogCache;
}

app.get('/api/settings/live-gift-catalog', async (req, res) => {
  try {
    const catalog = await getGiftCatalog();
    res.json({ success: true, data: catalog, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load gift catalog', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.patch('/api/admin/settings/live-gift-catalog', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const catalog = normalizeGiftCatalog(req.body.catalog);
    const { error } = await supabase.from('platform_settings').upsert({ key: 'live_gift_catalog', value: catalog, updated_at: new Date().toISOString() }, { onConflict: 'key' });
    if (error) throw error;
    giftCatalogCache = catalog;
    giftCatalogCacheAt = Date.now();
    res.json({ success: true, data: catalog, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update gift catalog', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/live/channels/:slug/sessions/:sessionId/gifts', authenticateToken, async (req, res) => {
  try {
    const { giftKey } = req.body;
    if (!giftKey) return res.status(400).json({ error: 'giftKey is required', timestamp: new Date().toISOString() });

    const { data: channel } = await supabase.from('channels_live').select('id, owner_user_id, name').eq('slug', req.params.slug).maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Channel not found', timestamp: new Date().toISOString() });

    const { data: session } = await supabase.from('live_sessions_live').select('id, status, channel_id').eq('id', req.params.sessionId).maybeSingle();
    if (!session || session.channel_id !== channel.id) return res.status(404).json({ error: 'Session not found', timestamp: new Date().toISOString() });
    if (session.status !== 'live') return res.status(400).json({ error: '방송 중에만 선물을 보낼 수 있습니다.', timestamp: new Date().toISOString() });

    const catalog = await getGiftCatalog();
    const gift = catalog.find(g => g.key === giftKey);
    if (!gift) return res.status(400).json({ error: '존재하지 않는 선물입니다.', timestamp: new Date().toISOString() });

    const balance = await getUserMileageBalance(req.user.id);
    if (balance < gift.cost) {
      return res.status(400).json({ error: `마일리지가 부족합니다. (보유: ${balance.toLocaleString('ko-KR')}, 필요: ${gift.cost.toLocaleString('ko-KR')})`, timestamp: new Date().toISOString() });
    }

    const { data: profile } = await supabase.from('profiles_with').select('full_name, email').eq('id', req.user.id).maybeSingle();
    const displayName = maskChatDisplayName(profile ? (profile.full_name || profile.email) : null);

    await creditMileageAdjustment(req.user.id, -gift.cost, 'live_gift_sent', session.id);
    if (channel.owner_user_id) {
      await creditMileageAdjustment(channel.owner_user_id, gift.cost, 'live_gift_received', session.id);
    }

    const { data: chatMsg, error: chatErr } = await supabase.from('live_session_chat_messages_live').insert({
      live_session_id: session.id,
      channel_id: channel.id,
      user_id: req.user.id,
      message: `${gift.emoji} ${displayName}님이 ${gift.label}(을)를 선물했습니다!`,
      message_type: 'gift'
    }).select().single();
    if (chatErr) console.error('선물 채팅 메시지 삽입 오류:', chatErr.message);

    const { error: giftErr } = await supabase.from('live_gifts_live').insert({
      session_id: session.id,
      channel_id: channel.id,
      sender_id: req.user.id,
      gift_key: gift.key,
      emoji: gift.emoji,
      label: gift.label,
      cost: gift.cost,
      chat_message_id: chatMsg ? chatMsg.id : null
    });
    if (giftErr) console.error('live_gifts_live 삽입 오류:', giftErr.message);

    res.status(201).json({
      success: true,
      data: { gift, chat_message: chatMsg || null, remaining_balance: balance - gift.cost },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('선물 전송 오류:', err);
    res.status(500).json({ error: 'Failed to send gift', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/live/channels/:id/sessions/:sessionId/gifts', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { data: gifts, error } = await supabase.from('live_gifts_live')
      .select('id, gift_key, emoji, label, cost, sender_id, created_at')
      .eq('session_id', req.params.sessionId)
      .order('created_at', { ascending: false });
    if (error) throw error;
    const totalCost = (gifts || []).reduce((sum, g) => sum + Number(g.cost || 0), 0);
    res.json({
      success: true,
      data: { total_count: (gifts || []).length, total_cost: totalCost, recent: (gifts || []).slice(0, 50) },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load gift summary', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// ⚡ 실시간 퀴즈/투표 (매출견인기능 격차분석 2-4) — 방송 중 관리자가 문제를 내고 정답을 서버에만 저장해두면,
// 채팅으로 정답을 맞춘 첫 N명에게 자동으로 라이브 전용 쿠폰(2-3에서 구현한 것과 동일한 세션 한정 쿠폰)이
// 발급된다. 확률형 럭키드로우/스핀휠 대신 "정답을 맞히는" 실력·참여 기반 방식을 택한 이유는, 격차분석
// 보고서가 지적한 대로 국내에서 확률형 경품 추첨은 사행성 규제 대상이 될 수 있기 때문이다.
// ============================================
function normalizeQuizAnswer(s) {
  return String(s || '').trim().toLowerCase().replace(/\s+/g, '');
}

async function generateUniqueCouponCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  function randomCode() {
    let code = 'QZ';
    for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
    return code;
  }
  let candidate = randomCode();
  for (let attempt = 0; attempt < 50; attempt++) {
    const { data: exists } = await supabase.from('coupons').select('id').eq('code', candidate).maybeSingle();
    if (!exists) return candidate;
    candidate = randomCode();
  }
  return randomCode() + Date.now().toString(36).toUpperCase();
}

// 이 세션에 지금 열려있는 퀴즈가 있고, message가 정답이며, 이 사용자가 아직 이 퀴즈를 맞히지 않았고,
// 정답자 한도(winner_limit)가 아직 남아있으면 쿠폰을 발급하고 당첨 기록을 남긴다. 그 외에는 null을 반환한다
// (오답이거나, 이미 맞혔거나, 정원이 찼거나, 열린 퀴즈 자체가 없는 경우 모두 조용히 null - 일반 채팅과 동일하게 처리).
async function tryAwardQuizWin(sessionId, userId, message, chatMessageId) {
  const { data: quiz } = await supabase.from('live_quizzes_live')
    .select('*').eq('live_session_id', sessionId).eq('status', 'open')
    .order('created_at', { ascending: false }).limit(1).maybeSingle();
  if (!quiz) return null;
  if (normalizeQuizAnswer(message) !== normalizeQuizAnswer(quiz.correct_answer)) return null;

  // 적대적 검증에서 실측된 레이스컨디션(정원 3명 설정에 10명 동시 요청 → 9명 당첨, 3배 초과) 수정.
  // "정원 확인 후 insert"를 애플리케이션 레이어에서 하면 두 단계 사이에 락이 없어 동시 요청에 취약하므로,
  // DB 함수(award_quiz_win RPC)가 live_quizzes_live 행에 FOR UPDATE 락을 걸어 동시 요청을 직렬화하고
  // 그 락을 쥔 채로 정원 재확인 + 당첨자 insert까지 하나의 트랜잭션에서 원자적으로 처리한다.
  const { data: rpcResult, error: rpcErr } = await supabase.rpc('award_quiz_win', {
    p_quiz_id: quiz.id, p_user_id: userId, p_chat_message_id: chatMessageId
  });
  if (rpcErr) throw rpcErr;
  if (!rpcResult || !rpcResult.success) return null;

  const winnerId = rpcResult.winner_id;
  const winnerCountAfter = rpcResult.winner_count;

  const couponCode = await generateUniqueCouponCode();
  const { data: coupon, error: couponErr } = await supabase.from('coupons').insert([{
    code: couponCode,
    label: `퀴즈 정답 축하 쿠폰 (${quiz.reward_discount_type === 'percent' ? quiz.reward_discount_value + '%' : Number(quiz.reward_discount_value).toLocaleString('ko-KR') + '원'} 할인)`,
    discount_type: quiz.reward_discount_type,
    discount_value: quiz.reward_discount_value,
    per_user_limit: 1,
    live_session_id: sessionId,
    is_active: true,
    created_by: quiz.created_by
  }]).select().single();
  if (couponErr) {
    // 쿠폰 생성 실패 - RPC가 이미 예약한 당첨 슬롯을 되돌린다(락 밖에서 실패했으므로 수동 롤백).
    await supabase.from('live_quiz_winners_live').delete().eq('id', winnerId);
    if (winnerCountAfter >= quiz.winner_limit) {
      await supabase.from('live_quizzes_live').update({ status: 'open', closed_at: null }).eq('id', quiz.id);
    }
    throw couponErr;
  }

  const { error: updateErr } = await supabase.from('live_quiz_winners_live').update({ coupon_code: couponCode }).eq('id', winnerId);
  if (updateErr) {
    await supabase.from('coupons').delete().eq('code', couponCode);
    await supabase.from('live_quiz_winners_live').delete().eq('id', winnerId);
    if (winnerCountAfter >= quiz.winner_limit) {
      await supabase.from('live_quizzes_live').update({ status: 'open', closed_at: null }).eq('id', quiz.id);
    }
    throw updateErr;
  }

  await supabase.from('live_session_chat_messages_live').update({ message_type: 'quiz_correct' }).eq('id', chatMessageId);

  return {
    correct: true,
    quiz_id: quiz.id,
    question: quiz.question,
    coupon_code: couponCode,
    discount_type: quiz.reward_discount_type,
    discount_value: quiz.reward_discount_value
  };
}

// 관리자: 퀴즈 시작 - 이 세션에 이미 열려있는 퀴즈가 있으면 먼저 자동으로 종료시키고 새로 시작한다(타임세일과 동일한 정책).
app.post('/api/admin/live/channels/:id/sessions/:sessionId/quizzes', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { question, correct_answer, winner_limit, reward_discount_type, reward_discount_value } = req.body || {};
    if (!question || !String(question).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: 'question은 필수입니다', timestamp: new Date().toISOString() });
    }
    if (!correct_answer || !String(correct_answer).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: 'correct_answer는 필수입니다', timestamp: new Date().toISOString() });
    }
    const winnerLimit = Number(winner_limit) || 3;
    if (!Number.isFinite(winnerLimit) || winnerLimit < 1 || winnerLimit > 50) {
      return res.status(400).json({ error: 'Bad Request', message: 'winner_limit은 1~50 사이여야 합니다', timestamp: new Date().toISOString() });
    }
    const discountType = ['percent', 'fixed'].includes(reward_discount_type) ? reward_discount_type : 'percent';
    const discountValue = Number(reward_discount_value) || 10;
    if (!Number.isFinite(discountValue) || discountValue <= 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'reward_discount_value가 올바르지 않습니다', timestamp: new Date().toISOString() });
    }

    const { data: session } = await supabase.from('live_sessions_live').select('id').eq('id', req.params.sessionId).eq('channel_id', req.params.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    // 기존에 열려있던 퀴즈가 있으면 먼저 종료
    await supabase.from('live_quizzes_live').update({ status: 'closed', closed_at: new Date().toISOString() })
      .eq('live_session_id', req.params.sessionId).eq('status', 'open');

    const { data, error } = await supabase.from('live_quizzes_live').insert([{
      live_session_id: req.params.sessionId,
      question: String(question).trim(),
      correct_answer: String(correct_answer).trim(),
      winner_limit: winnerLimit,
      reward_discount_type: discountType,
      reward_discount_value: discountValue,
      created_by: req.user.id
    }]).select().single();
    if (error) throw error;

    res.status(201).json({ success: true, data, message: '퀴즈를 시작했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error starting quiz:', err);
    res.status(500).json({ error: 'Failed to start quiz', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 이 세션의 퀴즈 이력 조회 (진행중+과거 전부, 당첨자 수 포함) - 정답은 관리자 화면에서만 노출된다
app.get('/api/admin/live/channels/:id/sessions/:sessionId/quizzes', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_quizzes_live')
      .select('*').eq('live_session_id', req.params.sessionId).order('created_at', { ascending: false });
    if (error) throw error;
    const quizzes = data || [];
    const quizIds = quizzes.map(q => q.id);
    let winnerCounts = {};
    if (quizIds.length > 0) {
      const { data: winners } = await supabase.from('live_quiz_winners_live').select('quiz_id').in('quiz_id', quizIds);
      (winners || []).forEach(w => { winnerCounts[w.quiz_id] = (winnerCounts[w.quiz_id] || 0) + 1; });
    }
    res.json({ success: true, data: quizzes.map(q => ({ ...q, winner_count: winnerCounts[q.id] || 0 })), timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching quizzes:', err);
    res.status(500).json({ error: 'Failed to fetch quizzes', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 퀴즈 조기 종료
app.patch('/api/admin/live/channels/:id/sessions/:sessionId/quizzes/:quizId/close', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_quizzes_live')
      .update({ status: 'closed', closed_at: new Date().toISOString() })
      .eq('id', req.params.quizId).eq('live_session_id', req.params.sessionId).eq('status', 'open')
      .select().maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '진행 중인 퀴즈를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({ success: true, data, message: '퀴즈를 종료했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error closing quiz:', err);
    res.status(500).json({ error: 'Failed to close quiz', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공개: 지금 열려있는 퀴즈의 질문만 노출 (정답/생성자 등 내부 정보는 절대 포함하지 않음) - 시청화면 폴링용
app.get('/api/live/channels/:slug/sessions/:sessionId/quiz/active', async (req, res) => {
  try {
    const { data: channel } = await supabase.from('channels_live').select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const { data: quiz } = await supabase.from('live_quizzes_live')
      .select('id, question, winner_limit, created_at').eq('live_session_id', req.params.sessionId).eq('status', 'open')
      .order('created_at', { ascending: false }).limit(1).maybeSingle();
    if (!quiz) return res.json({ success: true, data: null, timestamp: new Date().toISOString() });
    const { count: winnerCount } = await supabase.from('live_quiz_winners_live')
      .select('id', { count: 'exact', head: true }).eq('quiz_id', quiz.id);
    res.json({ success: true, data: { ...quiz, winner_count: winnerCount || 0 }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching active quiz:', err);
    res.status(500).json({ error: 'Failed to fetch active quiz', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🔨 실시간 경매(카운트다운 비딩) - 경쟁사 기능 격차 백로그 5번, Whatnot 방식.
// ============================================
// 퀴즈(live_quizzes_live)와 동일한 "세션당 열려있는 건 하나만" 정책 + "락으로 동시성 직렬화" 정책을 쓴다.
// 입찰(place_auction_bid RPC)과 종료확정(claim_auction_finalization RPC)은 각각 행 락(FOR UPDATE)으로
// 원자적으로 처리해, 동시 입찰이나 여러 시청자가 동시에 폴링해 마감을 마주치는 상황에서도 안전하다
// (퀴즈 정답 처리 때 실측된 레이스컨디션 버그를 애초에 방지하도록 설계).
// 낙찰자에게는 "원가 - 낙찰가"만큼 깎아주는 1인 전용 fixed 할인쿠폰을 발급한다(퀴즈 당첨 쿠폰과 동일한
// issueCouponForBatch 재사용) - 낙찰가 그대로 결제하려면 그 상품만 담아 쿠폰을 적용해야 한다.
async function finalizeAuctionIfEnded(auction) {
  if (!auction || auction.status !== 'open' || new Date(auction.ends_at).getTime() > Date.now()) return auction;

  const { data: claim } = await supabase.rpc('claim_auction_finalization', { p_auction_id: auction.id });
  if (!claim || !claim.claimed) {
    // 다른 요청이 먼저 확정을 가져갔거나(claimed:false), 이미 확정됨 - 최신 상태를 다시 읽어서 반환
    const { data: latest } = await supabase.from('live_auctions_live').select('*').eq('id', auction.id).maybeSingle();
    return latest || auction;
  }

  let winnerCouponCode = null;
  if (claim.current_bidder_id) {
    try {
      let normalPrice = Number(claim.current_price);
      if (claim.product_id) {
        const { data: product } = await supabase.from('products_with').select('price').eq('id', claim.product_id).maybeSingle();
        if (product && Number(product.price) > 0) normalPrice = Number(product.price);
      }
      const discountValue = Math.max(0, normalPrice - Number(claim.current_price));
      const template = {
        label: `🔨 실시간 경매 낙찰가 쿠폰 (${Number(claim.current_price).toLocaleString('ko-KR')}원)`,
        discount_type: 'fixed', discount_value: discountValue, per_user_limit: 1, valid_days: 1
      };
      const coupon = await issueCouponForBatch([claim.current_bidder_id], template, 'live_auction_win', {
        codePrefix: 'AUCTION', notifyTitle: '🔨 경매 낙찰을 축하합니다!',
        notifyMessage: `${Number(claim.current_price).toLocaleString('ko-KR')}원에 낙찰되었습니다! 24시간 안에 쿠폰을 사용해 결제를 완료해주세요(마이페이지에서 쿠폰 확인).`
      });
      winnerCouponCode = coupon ? coupon.code : null;
    } catch (err) {
      console.error('경매 낙찰 쿠폰 발급 오류:', err.message);
    }
  }

  const { data: updated, error } = await supabase.from('live_auctions_live').update({
    status: 'ended', winner_id: claim.current_bidder_id || null, winner_coupon_code: winnerCouponCode, ended_at: new Date().toISOString()
  }).eq('id', auction.id).select().maybeSingle();
  if (error) { console.error('경매 종료 확정 오류:', error.message); return auction; }
  return updated;
}

// 관리자: 경매 시작 (기존에 열려있던 경매가 있으면 먼저 강제 취소)
app.post('/api/admin/live/channels/:id/sessions/:sessionId/auctions', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { product_id, title, starting_price, bid_increment, duration_seconds, soft_close_seconds } = req.body || {};
    if (!title || !String(title).trim()) {
      return res.status(400).json({ error: 'Bad Request', message: 'title은 필수입니다', timestamp: new Date().toISOString() });
    }
    const startingPrice = Number(starting_price);
    if (!Number.isFinite(startingPrice) || startingPrice < 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'starting_price가 올바르지 않습니다', timestamp: new Date().toISOString() });
    }
    const bidIncrement = Number(bid_increment) > 0 ? Number(bid_increment) : 1000;
    const durationSeconds = Number(duration_seconds) > 0 ? Math.min(3600, Number(duration_seconds)) : 60;
    const softCloseSeconds = Number(soft_close_seconds) >= 0 ? Math.min(60, Number(soft_close_seconds)) : 10;

    const { data: session } = await supabase.from('live_sessions_live').select('id').eq('id', req.params.sessionId).eq('channel_id', req.params.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    // 기존에 열려있던 경매가 있으면 먼저 취소(낙찰자 없이 종료 - 타임세일/퀴즈와 동일한 정책)
    await supabase.from('live_auctions_live').update({ status: 'cancelled', ended_at: new Date().toISOString() })
      .eq('session_id', req.params.sessionId).eq('status', 'open');

    const { data, error } = await supabase.from('live_auctions_live').insert([{
      session_id: req.params.sessionId, product_id: product_id || null, title: String(title).trim(),
      starting_price: startingPrice, bid_increment: bidIncrement, current_price: startingPrice,
      ends_at: new Date(Date.now() + durationSeconds * 1000).toISOString(), soft_close_seconds: softCloseSeconds,
      created_by: req.user.id
    }]).select().single();
    if (error) throw error;

    res.status(201).json({ success: true, data, message: '경매를 시작했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error starting auction:', err);
    res.status(500).json({ error: 'Failed to start auction', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 이 세션의 경매 이력 조회 (진행중이면 먼저 종료시각 지났는지 확인해 필요 시 확정 처리)
app.get('/api/admin/live/channels/:id/sessions/:sessionId/auctions', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_auctions_live')
      .select('*').eq('session_id', req.params.sessionId).order('created_at', { ascending: false });
    if (error) throw error;
    const auctions = await Promise.all((data || []).map(a => finalizeAuctionIfEnded(a)));
    res.json({ success: true, data: auctions, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching auctions:', err);
    res.status(500).json({ error: 'Failed to fetch auctions', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 경매 조기 취소(입찰이 있었어도 강제 무효화 - 낙찰쿠폰 발급 없이 종료)
app.patch('/api/admin/live/channels/:id/sessions/:sessionId/auctions/:auctionId/cancel', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_auctions_live')
      .update({ status: 'cancelled', ended_at: new Date().toISOString() })
      .eq('id', req.params.auctionId).eq('session_id', req.params.sessionId).eq('status', 'open')
      .select().maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '진행 중인 경매를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({ success: true, data, message: '경매를 취소했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error cancelling auction:', err);
    res.status(500).json({ error: 'Failed to cancel auction', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공개: 지금 이 세션의 경매 상태(진행중인 것 또는 방금 끝난 것 1건) - 시청화면 폴링용. 종료시각이 지났는데
// 아직 'open'이면 여기서 lazy하게 확정 처리한다(이 프로젝트의 "읽는 시점에 처리" 원칙).
app.get('/api/live/channels/:slug/sessions/:sessionId/auction/active', async (req, res) => {
  try {
    const { data: channel } = await supabase.from('channels_live').select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    let { data: auction } = await supabase.from('live_auctions_live')
      .select('id, product_id, title, starting_price, bid_increment, current_price, current_bidder_id, bid_count, status, ends_at, soft_close_seconds, winner_id, ended_at')
      .eq('session_id', req.params.sessionId).in('status', ['open', 'finalizing'])
      .order('created_at', { ascending: false }).limit(1).maybeSingle();
    if (!auction) {
      // 진행 중인 게 없으면, 방금 끝난 것(5분 이내)을 대신 보여줘서 "낙찰!" 결과를 놓치지 않게 한다
      const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
      const { data: recentlyEnded } = await supabase.from('live_auctions_live')
        .select('id, product_id, title, starting_price, bid_increment, current_price, current_bidder_id, bid_count, status, ends_at, soft_close_seconds, winner_id, ended_at')
        .eq('session_id', req.params.sessionId).eq('status', 'ended').gte('ended_at', fiveMinAgo)
        .order('ended_at', { ascending: false }).limit(1).maybeSingle();
      return res.json({ success: true, data: recentlyEnded || null, timestamp: new Date().toISOString() });
    }

    auction = await finalizeAuctionIfEnded(auction);
    const { winner_coupon_code, created_by, ...safeAuction } = auction; // 낙찰쿠폰 코드는 본인 조회 API에서만 노출(전체공개 폴링엔 숨김)
    res.json({ success: true, data: safeAuction, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching active auction:', err);
    res.status(500).json({ error: 'Failed to fetch active auction', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 회원: 입찰하기
app.post('/api/live/channels/:slug/sessions/:sessionId/auction/:auctionId/bid', authenticate, async (req, res) => {
  try {
    const amount = Number(req.body?.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Bad Request', message: 'amount가 올바르지 않습니다', timestamp: new Date().toISOString() });
    }
    const { data: auction } = await supabase.from('live_auctions_live').select('id').eq('id', req.params.auctionId).eq('session_id', req.params.sessionId).maybeSingle();
    if (!auction) return res.status(404).json({ error: 'Not Found', message: '경매를 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const { data: result, error } = await supabase.rpc('place_auction_bid', { p_auction_id: req.params.auctionId, p_user_id: req.user.id, p_amount: amount });
    if (error) throw error;
    if (!result.success) {
      const reasonMessages = {
        not_open: '이미 종료된 경매입니다', ended: '입찰 마감 시각이 지났습니다',
        already_highest: '이미 최고 입찰자입니다', bid_too_low: `최소 ${Number(result.min_next).toLocaleString('ko-KR')}원 이상 입찰해주세요`,
        not_found: '경매를 찾을 수 없습니다'
      };
      return res.status(400).json({ error: 'Bad Request', message: reasonMessages[result.reason] || '입찰에 실패했습니다', data: result, timestamp: new Date().toISOString() });
    }
    res.json({ success: true, data: result, message: result.extended ? '입찰 완료! 막판 입찰로 마감시각이 연장되었습니다' : '입찰이 완료되었습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error placing auction bid:', err);
    res.status(500).json({ error: 'Failed to place bid', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 회원: 내가 이 경매의 낙찰자인 경우에만 낙찰쿠폰 코드를 확인 (본인 인증 필요 - 위 공개 폴링 API는 절대 노출하지 않음)
app.get('/api/live/channels/:slug/sessions/:sessionId/auction/:auctionId/my-result', authenticate, async (req, res) => {
  try {
    const { data: auction } = await supabase.from('live_auctions_live').select('*').eq('id', req.params.auctionId).eq('session_id', req.params.sessionId).maybeSingle();
    if (!auction) return res.status(404).json({ error: 'Not Found', message: '경매를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (auction.status !== 'ended' || auction.winner_id !== req.user.id) {
      return res.json({ success: true, data: { is_winner: false }, timestamp: new Date().toISOString() });
    }
    res.json({ success: true, data: { is_winner: true, winning_price: auction.current_price, coupon_code: auction.winner_coupon_code }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching auction result:', err);
    res.status(500).json({ error: 'Failed to fetch auction result', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 🎤 라이트 멀티호스트 - 게스트 초대 (매출견인기능 격차분석 2-9, B8)
// 실제 WebRTC 다자간 동시 송출은 별도 영상 인프라가 필요한 장기 과제라, 격차분석 보고서 자체가 제안한
// 경량 대체안을 구현한다: 관리자가 게스트 초대코드를 발급 → 게스트가 자기 계정으로 코드를 입력해 연결하면
// 그 세션 채팅에 "게스트" 배지가 붙고, 게스트 전용 고정상품이 시청화면에 함께 노출된다.
// (영상 송출 자체는 방송자가 별도 화면공유/합성 등으로 알아서 처리하는 것을 전제 - 이 기능은 그 위에서
//  "누가 게스트인지" 표시와 "게스트가 소개하는 상품" 노출만 돕는다.)
// ============================================
async function generateUniqueGuestInviteCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  function randomCode() {
    let code = 'GT';
    for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
    return code;
  }
  let candidate = randomCode();
  for (let attempt = 0; attempt < 50; attempt++) {
    const { data: exists } = await supabase.from('live_session_guests_live').select('id').eq('invite_code', candidate).maybeSingle();
    if (!exists) return candidate;
    candidate = randomCode();
  }
  return randomCode() + Date.now().toString(36).toUpperCase();
}

// 관리자: 이 세션에 게스트 초대코드 발급 (선택적으로 게스트 전용 고정상품 지정)
app.post('/api/admin/live/channels/:id/sessions/:sessionId/guests', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const guestName = String(req.body?.guest_name || '').trim();
    if (!guestName) return res.status(400).json({ error: 'Bad Request', message: 'guest_name은 필수입니다', timestamp: new Date().toISOString() });
    const pinnedProductId = req.body?.pinned_product_id || null;

    const { data: session } = await supabase.from('live_sessions_live').select('id').eq('id', req.params.sessionId).eq('channel_id', req.params.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    if (pinnedProductId) {
      const { data: product } = await supabase.from('products_with').select('id').eq('id', pinnedProductId).maybeSingle();
      if (!product) return res.status(400).json({ error: 'Bad Request', message: '존재하지 않는 상품입니다', timestamp: new Date().toISOString() });
    }

    const inviteCode = await generateUniqueGuestInviteCode();
    const { data, error } = await supabase.from('live_session_guests_live').insert([{
      live_session_id: req.params.sessionId,
      guest_name: guestName,
      invite_code: inviteCode,
      pinned_product_id: pinnedProductId,
      created_by: req.user.id
    }]).select().single();
    if (error) throw error;

    res.status(201).json({ success: true, data, message: '게스트 초대코드를 발급했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating live guest invite:', err);
    res.status(500).json({ error: 'Failed to create guest invite', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 이 세션의 게스트 목록 (상품명 조인)
app.get('/api/admin/live/channels/:id/sessions/:sessionId/guests', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_session_guests_live')
      .select('*, products_with(name)').eq('live_session_id', req.params.sessionId).order('created_at', { ascending: false });
    if (error) throw error;
    res.json({
      success: true,
      data: (data || []).map(g => ({ ...g, pinned_product_name: g.products_with ? g.products_with.name : null, products_with: undefined })),
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching live guests:', err);
    res.status(500).json({ error: 'Failed to fetch guests', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자: 게스트 퇴장 처리(배지/고정상품 노출 종료). 초대코드 자체를 지우지는 않고 상태만 종료로 바꾼다.
app.patch('/api/admin/live/channels/:id/sessions/:sessionId/guests/:guestId/end', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_session_guests_live')
      .update({ status: 'ended', ended_at: new Date().toISOString() })
      .eq('id', req.params.guestId).eq('live_session_id', req.params.sessionId).neq('status', 'ended')
      .select().maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '게스트를 찾을 수 없거나 이미 종료되었습니다', timestamp: new Date().toISOString() });
    res.json({ success: true, data, message: '게스트를 퇴장 처리했습니다', timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error ending live guest:', err);
    res.status(500).json({ error: 'Failed to end guest', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 로그인 사용자: 게스트 초대코드 입력(연결). 대기 중(pending)인 코드만 연결 가능 - 이미 연결됐거나
// 종료된 코드는 재사용할 수 없다(방송당 게스트 한 명이 코드를 한 번만 쓰도록).
app.post('/api/live/guests/redeem', authenticate, async (req, res) => {
  try {
    const inviteCode = String(req.body?.invite_code || '').trim().toUpperCase();
    if (!inviteCode) return res.status(400).json({ error: 'Bad Request', message: 'invite_code가 필요합니다', timestamp: new Date().toISOString() });

    const { data: guest } = await supabase.from('live_session_guests_live')
      .select('id, live_session_id, status').eq('invite_code', inviteCode).maybeSingle();
    if (!guest) return res.status(404).json({ error: 'Not Found', message: '유효하지 않은 초대코드입니다', timestamp: new Date().toISOString() });
    if (guest.status !== 'pending') {
      return res.status(409).json({ error: 'Conflict', message: '이미 사용되었거나 종료된 초대코드입니다', timestamp: new Date().toISOString() });
    }

    const { data: session } = await supabase.from('live_sessions_live').select('id, channel_id, status').eq('id', guest.live_session_id).maybeSingle();
    const { data: channel } = session ? await supabase.from('channels_live').select('slug').eq('id', session.channel_id).maybeSingle() : { data: null };

    const { data: updated, error } = await supabase.from('live_session_guests_live')
      .update({ status: 'active', activated_at: new Date().toISOString(), user_id: req.user.id })
      .eq('id', guest.id).eq('status', 'pending')
      .select().maybeSingle();
    if (error) throw error;
    if (!updated) return res.status(409).json({ error: 'Conflict', message: '이미 사용되었거나 종료된 초대코드입니다', timestamp: new Date().toISOString() });

    res.json({
      success: true,
      data: { ...updated, session_status: session ? session.status : null, channel_slug: channel ? channel.slug : null },
      message: '게스트로 연결되었습니다',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error redeeming live guest invite:', err);
    res.status(500).json({ error: 'Failed to redeem guest invite', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공개: 이 세션에 지금 활동 중인 게스트 목록(배지/고정상품 표시용) - 민감정보 없음
app.get('/api/live/channels/:slug/sessions/:sessionId/guests', async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_session_guests_live')
      .select('id, guest_name, pinned_product_id, user_id, products_with(name, price)')
      .eq('live_session_id', req.params.sessionId).eq('status', 'active');
    if (error) throw error;
    res.json({
      success: true,
      data: (data || []).map(g => ({
        guest_name: g.guest_name,
        user_id: g.user_id,
        pinned_product: g.products_with ? { id: g.pinned_product_id, name: g.products_with.name, price: g.products_with.price } : null
      })),
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching active live guests:', err);
    res.status(500).json({ error: 'Failed to fetch guests', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 👀 실시간 시청자 수 · 최근 구매 알림 - 틱톡/유튜브 매출견인기능 격차분석 1번 항목(사회적 증명)
// 로그인 여부와 무관하게(비로그인 시청자도 카운트되어야 하므로) optionalAuth를 사용한다.
// 하트비트는 30~60초 주기로 호출되는 것을 가정하고, 최근 90초 이내 하트비트가 있는 행만 "현재 시청자"로 센다.
// ============================================
const LIVE_VIEWER_HEARTBEAT_WINDOW_SEC = 90;

app.post('/api/live/channels/:slug/sessions/:sessionId/heartbeat', optionalAuth, async (req, res) => {
  try {
    const viewerKey = String(req.body?.viewer_key || '').trim();
    if (!viewerKey) return res.status(400).json({ error: 'Bad Request', message: 'viewer_key가 필요합니다', timestamp: new Date().toISOString() });

    const { data: channel } = await supabase.from('channels_live').select('id').eq('slug', req.params.slug).eq('status', 'active').maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    const { data: session } = await supabase.from('live_sessions_live').select('id').eq('id', req.params.sessionId).eq('channel_id', channel.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    await supabase.from('live_session_viewers_live').upsert(
      [{ live_session_id: req.params.sessionId, viewer_key: viewerKey, user_id: req.user ? req.user.id : null, last_seen_at: new Date().toISOString() }],
      { onConflict: 'live_session_id,viewer_key' }
    );
    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error recording live viewer heartbeat:', err);
    res.status(500).json({ error: 'Failed to record heartbeat', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/live/channels/:slug/sessions/:sessionId/viewer-count', async (req, res) => {
  try {
    const cutoff = new Date(Date.now() - LIVE_VIEWER_HEARTBEAT_WINDOW_SEC * 1000).toISOString();
    const { count, error } = await supabase.from('live_session_viewers_live')
      .select('id', { count: 'exact', head: true })
      .eq('live_session_id', req.params.sessionId).gte('last_seen_at', cutoff);
    if (error) throw error;
    res.json({ success: true, data: { viewer_count: count || 0 }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching live viewer count:', err);
    res.status(500).json({ error: 'Failed to fetch viewer count', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 최근 구매 토스트("OOO님 방금 구매") - 세션 한정재고 확정(sold) 로그를 그대로 재사용한다(새 테이블 없음).
app.get('/api/live/channels/:slug/sessions/:sessionId/recent-purchases', async (req, res) => {
  try {
    const { data: invRows } = await supabase.from('live_session_inventory_live').select('id, product_id').eq('live_session_id', req.params.sessionId);
    const invIds = (invRows || []).map(r => r.id);
    if (invIds.length === 0) return res.json({ success: true, data: [], timestamp: new Date().toISOString() });
    const invToProduct = {};
    (invRows || []).forEach(r => { invToProduct[r.id] = r.product_id; });

    const { data: logs, error } = await supabase.from('live_session_inventory_log_live')
      .select('inventory_id, delta_sold, actor_user_id, created_at')
      .in('inventory_id', invIds).eq('change_type', 'confirm').gt('delta_sold', 0)
      .order('created_at', { ascending: false }).limit(8);
    if (error) throw error;

    const productIds = [...new Set((logs || []).map(l => invToProduct[l.inventory_id]).filter(Boolean))];
    const userIds = [...new Set((logs || []).map(l => l.actor_user_id).filter(Boolean))];
    const [{ data: products }, { data: profiles }] = await Promise.all([
      productIds.length ? supabase.from('products_with').select('id, name').in('id', productIds) : Promise.resolve({ data: [] }),
      userIds.length ? supabase.from('profiles').select('id, full_name, email').in('id', userIds) : Promise.resolve({ data: [] })
    ]);
    const productById = {}; (products || []).forEach(p => { productById[p.id] = p.name; });
    const profileById = {}; (profiles || []).forEach(p => { profileById[p.id] = p; });

    const result = (logs || []).map(l => {
      const profile = l.actor_user_id ? profileById[l.actor_user_id] : null;
      return {
        product_name: productById[invToProduct[l.inventory_id]] || '상품',
        qty: l.delta_sold,
        buyer_name: maskChatDisplayName(profile ? (profile.full_name || profile.email) : null),
        created_at: l.created_at
      };
    });
    res.json({ success: true, data: result, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching recent live purchases:', err);
    res.status(500).json({ error: 'Failed to fetch recent purchases', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 관리자용 채팅 조회(숨김 메시지 포함) - 모더레이션 화면이 이 목록을 그대로 보여주고 숨기기/다시 보이기를 건다.
app.get('/api/admin/live/channels/:id/sessions/:sessionId/chat', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
    let query = supabase.from('live_session_chat_messages_live')
      .select('id, message, created_at, is_hidden, hidden_at, user_id, profiles!live_session_chat_messages_live_user_id_fkey(full_name, email)')
      .eq('live_session_id', req.params.sessionId).eq('channel_id', req.params.id);
    // before: "더 보기" 페이지네이션 - 이 시각보다 오래된 메시지를 최신순으로 더 가져온다(대형 방송에서
    // 채팅이 수천 건 쌓여도 한 번에 다 불러오지 않도록). 숨겨진 메시지도 모더레이션 화면에서는 계속 보여준다.
    if (req.query.before) query = query.lt('created_at', req.query.before);
    query = query.order('created_at', { ascending: false }).limit(limit);

    const { data, error } = await query;
    if (error) throw error;
    const messages = (data || []).map(r => ({
      id: r.id, message: r.message, created_at: r.created_at, is_hidden: r.is_hidden, hidden_at: r.hidden_at,
      sender_name: r.profiles ? (r.profiles.full_name || r.profiles.email) : '탈퇴한 회원' // 관리자 모더레이션 화면에서는 실명/이메일을 그대로 보여준다(악용 대응 목적)
    }));
    res.json({ success: true, data: messages, count: messages.length, has_more: messages.length === limit, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching admin live chat messages:', err);
    res.status(500).json({ error: 'Failed to fetch chat messages', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 채팅 메시지 숨기기/다시 보이기 - 하드 삭제 대신 소프트 삭제로 남겨서 분쟁/악용 시 근거를 보존한다.
app.patch('/api/admin/live/channels/:id/sessions/:sessionId/chat/:messageId', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const hidden = !!req.body?.is_hidden;
    const updates = hidden
      ? { is_hidden: true, hidden_by: req.user.id, hidden_at: new Date().toISOString() }
      : { is_hidden: false, hidden_by: null, hidden_at: null };
    const { data, error } = await supabase.from('live_session_chat_messages_live')
      .update(updates).eq('id', req.params.messageId).eq('live_session_id', req.params.sessionId).eq('channel_id', req.params.id)
      .select().single();
    if (error) throw error;
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error updating live chat message visibility:', err);
    res.status(500).json({ error: 'Failed to update chat message', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 📡 LIVE+ OmniCast (멀티플랫폼 동시송출) - "목적지 연결 관리형" MVP
// ============================================
// 설계 원칙(형님과 합의): 실제 영상 릴레이는 LIVE+ 서버가 하지 않는다. 호스트가 OBS 같은 방송 장비에서
// 멀티스트림 기능으로 한 번 송출하면, LIVE+가 미리 만들어둔 각 플랫폼의 RTMP 수신 정보(주소+키)를 그
// 멀티스트림 목적지로 등록해서 동시에 나가는 방식이다. LIVE+는 (1) 플랫폼 연결(OAuth)과 (2) 방송마다
// 그 플랫폼에 실제로 "이번 방송"을 생성해 RTMP 수신 정보를 발급받아 보여주는 것까지만 담당한다.
// 별도의 미디어 릴레이 서버(RTMP 수신+ffmpeg 재전송)는 인프라 규모가 완전히 다른 별개 작업이라
// 이번 MVP 범위에 포함하지 않았다.
//
// 유튜브/페이스북은 공식 Live Streaming API가 있어 코드로 완전히 구현했지만, 두 플랫폼 다 형님이
// Google Cloud Console / Meta for Developers에서 직접 OAuth 앱을 만들어 클라이언트ID/시크릿을
// 발급받아 아래 관리자 설정 화면에 등록해야만 실제로 동작한다(등록 전에는 "연동 설정 필요" 안내로
// 정직하게 막아둔다 - 카카오페이/네이버페이 때와 동일한 태도).
//
// 틱톡/인스타그램/X는 일반 개발자가 자유롭게 발급받을 수 있는 공식 "라이브 생성" API가 없다(틱톡은
// 별도 파트너 심사, 인스타그램/X는 사실상 일반 서드파티에 공개돼 있지 않음). 로드맵 메모에서 "공식
// 권한이 있는 경우에만 연결, 비공식 API·우회 자동화 금지"로 합의했으므로, 이 세 플랫폼은 목적지
// 목록에는 존재하지만 "연동 준비중" 상태로만 두고 실제 연결 기능은 만들지 않았다.
const OMNICAST_PLATFORM_INFO = {
  youtube: { name: '유튜브 라이브', oauth: true, implemented: true },
  facebook: { name: '페이스북 라이브', oauth: true, implemented: true },
  custom_rtmp: { name: '커스텀 RTMP', oauth: false, implemented: true },
  // Cloudflare Stream: 다른 플랫폼과 달리 "우리 사이트 안에서 직접 재생"이 목적이다. RTMP 수신은
  // Cloudflare가 담당하지만(우리 서버가 영상을 직접 릴레이하지 않는다는 기존 설계 원칙은 그대로 유지),
  // 재생은 유튜브/페이스북처럼 외부 사이트로 보내지 않고 이 플랫폼이 내려주는 HLS 주소를 우리 시청 페이지에
  // 그대로 <video>로 재생한다 - live-channel.html의 영상 우선순위에서 가장 먼저 고려된다.
  cloudflare_stream: { name: '자체 사이트 재생(Cloudflare Stream)', oauth: false, implemented: true },
  tiktok: { name: '틱톡', oauth: true, implemented: false },
  instagram: { name: '인스타그램', oauth: true, implemented: false },
  x: { name: 'X (트위터)', oauth: true, implemented: false }
};

async function getOmnicastPlatformConfig(providerKey) {
  const { data, error } = await supabase.from('omnicast_platform_configs').select('*').eq('provider_key', providerKey).maybeSingle();
  if (error) throw error;
  return data;
}

// state 파라미터 서명 - signNaverState/verifyNaverState와 동일한 HMAC 방식이되, 어느 채널·어느
// 관리자가 연결을 시작했는지(channelId/adminUserId)까지 함께 왕복시켜야 해서 payload를 실어 확장했다.
function signOmnicastState(data) {
  const nonce = crypto.randomBytes(16).toString('hex');
  const ts = Date.now().toString();
  const payload = Buffer.from(JSON.stringify(data)).toString('base64url');
  const base = `${nonce}.${ts}.${payload}`;
  const sig = crypto.createHmac('sha256', process.env.JWT_SECRET || RUNTIME_FALLBACK_SECRET).update(base).digest('hex');
  return `${base}.${sig}`;
}
function verifyOmnicastState(state) {
  if (!state || typeof state !== 'string') return null;
  const parts = state.split('.');
  if (parts.length !== 4) return null;
  const [nonce, ts, payload, sig] = parts;
  const base = `${nonce}.${ts}.${payload}`;
  const expected = crypto.createHmac('sha256', process.env.JWT_SECRET || RUNTIME_FALLBACK_SECRET).update(base).digest('hex');
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const age = Date.now() - Number(ts);
  if (!Number.isFinite(age) || age < 0 || age > 10 * 60 * 1000) return null; // 10분 초과 시 만료
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); } catch (e) { return null; }
}

// 목적지 목록 응답에서는 access_token/refresh_token/stream_key 원문을 절대 내려주지 않는다(pg_configs와
// 동일한 태도). custom_rtmp의 rtmp_url 자체는 비밀이 아니라(어차피 공개 서버 주소) 그대로 보여준다.
function maskOmnicastDestination(d) {
  return {
    id: d.id, channel_id: d.channel_id, platform: d.platform, label: d.label,
    external_account_id: d.external_account_id, external_account_name: d.external_account_name,
    rtmp_url: d.platform === 'custom_rtmp' ? d.rtmp_url : null,
    has_key: !!(d.stream_key || d.access_token),
    status: d.status, last_error: d.last_error,
    created_at: d.created_at, updated_at: d.updated_at
  };
}

// 관리자: 플랫폼별 OAuth 앱 인증정보 조회 (시크릿 원문은 내려주지 않음)
app.get('/api/admin/live/omnicast/platforms', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('omnicast_platform_configs').select('*').order('provider_key');
    if (error) throw error;
    res.json({
      success: true,
      data: (data || []).map(c => ({
        provider_key: c.provider_key, provider_name: c.provider_name,
        implemented: OMNICAST_PLATFORM_INFO[c.provider_key]?.implemented || false,
        client_key: c.client_key || null, has_secret_key: !!c.secret_key, redirect_uri: c.redirect_uri || null,
        enabled: c.enabled, extra_config: c.extra_config || {}
      })),
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error fetching omnicast platform configs:', err);
    res.status(500).json({ error: 'Failed to fetch omnicast platform configs', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.patch('/api/admin/live/omnicast/platforms/:provider', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const provider = req.params.provider;
    if (!OMNICAST_PLATFORM_INFO[provider] || provider === 'custom_rtmp') {
      return res.status(404).json({ error: 'Not Found', message: '지원하지 않는 플랫폼입니다', timestamp: new Date().toISOString() });
    }
    if (!OMNICAST_PLATFORM_INFO[provider].implemented) {
      return res.status(400).json({ error: 'Bad Request', message: '이 플랫폼은 아직 자동 연결을 지원하지 않습니다 (공식 API 접근 권한 확보 후 지원 예정)', timestamp: new Date().toISOString() });
    }
    const update = { updated_at: new Date().toISOString() };
    if (typeof req.body.client_key === 'string') update.client_key = req.body.client_key.trim() || null;
    if (typeof req.body.secret_key === 'string') update.secret_key = req.body.secret_key.trim() || null;
    if (typeof req.body.redirect_uri === 'string') update.redirect_uri = req.body.redirect_uri.trim() || null;
    if (typeof req.body.enabled === 'boolean') update.enabled = req.body.enabled;

    const { data, error } = await supabase.from('omnicast_platform_configs').update(update).eq('provider_key', provider).select().single();
    if (error) throw error;
    res.json({
      success: true,
      data: { provider_key: data.provider_key, client_key: data.client_key, has_secret_key: !!data.secret_key, redirect_uri: data.redirect_uri, enabled: data.enabled },
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Error updating omnicast platform config:', err);
    res.status(500).json({ error: 'Failed to update omnicast platform config', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 채널의 송출 목적지 목록/추가(커스텀 RTMP만 직접 추가)/삭제
app.get('/api/admin/live/channels/:id/omnicast/destinations', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_channel_broadcast_destinations_live')
      .select('*').eq('channel_id', req.params.id).order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: (data || []).map(maskOmnicastDestination), count: (data || []).length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching omnicast destinations:', err);
    res.status(500).json({ error: 'Failed to fetch omnicast destinations', message: err.message, timestamp: new Date().toISOString() });
  }
});

// platform을 생략하면 예전처럼 커스텀 RTMP로 동작(하위호환). Cloudflare Stream은 OAuth가 아니라
// API 토큰 방식이라(유튜브/페이스북과 다름) 커스텀 RTMP처럼 이 엔드포인트로 바로 등록한다 - 다만 필요한
// 필드가 rtmp_url/stream_key가 아니라 Cloudflare 계정ID/API토큰이라 플랫폼별로 검증을 분기한다.
app.post('/api/admin/live/channels/:id/omnicast/destinations', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const platform = req.body?.platform === 'cloudflare_stream' ? 'cloudflare_stream' : 'custom_rtmp';
    const { label } = req.body || {};
    if (!label || !String(label).trim()) return res.status(400).json({ error: 'Bad Request', message: '목적지 이름(label)은 필수입니다', timestamp: new Date().toISOString() });

    const { data: channel } = await supabase.from('channels_live').select('id').eq('id', req.params.id).maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    let insertRow;
    if (platform === 'cloudflare_stream') {
      const { account_id, api_token } = req.body || {};
      if (!account_id || !String(account_id).trim()) return res.status(400).json({ error: 'Bad Request', message: 'Cloudflare 계정 ID는 필수입니다', timestamp: new Date().toISOString() });
      if (!api_token || !String(api_token).trim()) return res.status(400).json({ error: 'Bad Request', message: 'Cloudflare API 토큰은 필수입니다', timestamp: new Date().toISOString() });
      insertRow = {
        channel_id: req.params.id, platform: 'cloudflare_stream', label: String(label).trim(),
        external_account_id: String(account_id).trim(), access_token: encryptSecret(String(api_token).trim()),
        status: 'connected', connected_by: req.user.id
      };
    } else {
      const { rtmp_url, stream_key } = req.body || {};
      if (!rtmp_url || !String(rtmp_url).trim()) return res.status(400).json({ error: 'Bad Request', message: 'RTMP 서버 주소는 필수입니다', timestamp: new Date().toISOString() });
      if (!stream_key || !String(stream_key).trim()) return res.status(400).json({ error: 'Bad Request', message: '스트림 키는 필수입니다', timestamp: new Date().toISOString() });
      insertRow = {
        channel_id: req.params.id, platform: 'custom_rtmp', label: String(label).trim(),
        rtmp_url: String(rtmp_url).trim(), stream_key: encryptSecret(String(stream_key).trim()),
        status: 'connected', connected_by: req.user.id
      };
    }

    const { data, error } = await supabase.from('live_channel_broadcast_destinations_live').insert([insertRow]).select().single();

    if (error) throw error;
    res.status(201).json({ success: true, data: maskOmnicastDestination(data), timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error adding omnicast destination:', err);
    res.status(500).json({ error: 'Failed to add omnicast destination', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 목적지가 실제로 갖고 있는 RTMP 접속정보를 확인(OBS에 그대로 옮겨 적기 위함) - admin 전용, 목록 조회와
// 분리해서 꼭 필요할 때만 원문을 내려준다
app.get('/api/admin/live/channels/:id/omnicast/destinations/:destId/reveal', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_channel_broadcast_destinations_live')
      .select('platform, rtmp_url, stream_key').eq('id', req.params.destId).eq('channel_id', req.params.id).maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '목적지를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (data.platform !== 'custom_rtmp') return res.status(400).json({ error: 'Bad Request', message: '이 플랫폼은 방송을 시작할 때마다 새 접속정보가 발급됩니다. 세션의 송출 목록에서 확인해주세요.', timestamp: new Date().toISOString() });
    res.json({ success: true, data: { rtmp_url: data.rtmp_url, stream_key: decryptSecret(data.stream_key) }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error revealing omnicast destination:', err);

    res.status(500).json({ error: 'Failed to reveal omnicast destination', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.delete('/api/admin/live/channels/:id/omnicast/destinations/:destId', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { error } = await supabase.from('live_channel_broadcast_destinations_live').delete().eq('id', req.params.destId).eq('channel_id', req.params.id);
    if (error) throw error;
    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting omnicast destination:', err);
    res.status(500).json({ error: 'Failed to delete omnicast destination', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 유튜브/페이스북 연결 시작 - 관리자 설정이 안 돼있으면 정직하게 막고, 돼있으면 인가 URL을 돌려준다
// (프론트엔드가 이 URL로 새 탭/리다이렉트를 열면 구글/페이스북 로그인 화면으로 이동)
app.get('/api/admin/live/channels/:id/omnicast/:platform/connect', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const platform = req.params.platform;
    const info = OMNICAST_PLATFORM_INFO[platform];
    if (!info || !info.oauth) return res.status(404).json({ error: 'Not Found', message: '지원하지 않는 플랫폼입니다', timestamp: new Date().toISOString() });
    if (!info.implemented) return res.status(400).json({ error: 'Bad Request', message: `${info.name}은 아직 자동 연결을 지원하지 않습니다 (공식 API 접근 권한 확보 후 지원 예정)`, timestamp: new Date().toISOString() });

    const { data: channel } = await supabase.from('channels_live').select('id').eq('id', req.params.id).maybeSingle();
    if (!channel) return res.status(404).json({ error: 'Not Found', message: '채널을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const config = await getOmnicastPlatformConfig(platform);
    if (!config || !config.enabled || !config.client_key || !config.secret_key || !config.redirect_uri) {
      return res.status(400).json({ error: 'Bad Request', message: `${info.name} 연동이 아직 설정되지 않았습니다. 관리자 환경설정에서 OAuth 클라이언트ID/시크릿/리디렉션 URI를 먼저 등록해주세요.`, timestamp: new Date().toISOString() });
    }

    const state = signOmnicastState({ channelId: req.params.id, adminUserId: req.user.id, platform });
    let authorizeUrl;
    if (platform === 'youtube') {
      authorizeUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
        client_id: config.client_key, redirect_uri: config.redirect_uri, response_type: 'code',
        scope: 'https://www.googleapis.com/auth/youtube https://www.googleapis.com/auth/youtube.force-ssl',
        access_type: 'offline', prompt: 'consent', state
      }).toString();
    } else if (platform === 'facebook') {
      authorizeUrl = 'https://www.facebook.com/v19.0/dialog/oauth?' + new URLSearchParams({
        client_id: config.client_key, redirect_uri: config.redirect_uri,
        scope: 'pages_show_list,pages_read_engagement,pages_manage_posts,publish_video', state
      }).toString();
    } else {
      return res.status(400).json({ error: 'Bad Request', message: '지원하지 않는 플랫폼입니다', timestamp: new Date().toISOString() });
    }
    res.json({ success: true, data: { authorize_url: authorizeUrl }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error starting omnicast connect:', err);
    res.status(500).json({ error: 'Failed to start omnicast connect', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 유튜브/페이스북 OAuth 콜백 - 구글/페이스북이 브라우저를 이 주소로 직접 리다이렉트하므로 인증 미들웨어를
// 걸 수 없다(관리자 로그인 세션이 아니라 state 서명으로 위변조를 막는다 - 네이버 로그인 콜백과 동일한 방식).
app.get('/api/admin/live/omnicast/:platform/callback', async (req, res) => {
  const platform = req.params.platform;
  const { code, state, error: oauthError } = req.query;
  // channelId를 try 블록 바깥(함수 스코프)에 선언해둔다 - 예전에는 try 블록 안의 const로만 있어서,
  // state 파싱 이후 단계(토큰 교환 등)에서 예외가 나면 catch 블록이 channelId를 몰라 무조건
  // failRedirect(null, ...)을 호출했다. 그 결과 존재하지 않는 "/admin/live-host/"(빈 id) 로
  // 리다이렉트되어 404 페이지가 떴다 - 이번에 실제로 사용자가 겪은 문제.
  let channelId = null;
  // channelId를 끝내 알아낼 수 없을 때(state 자체가 위조/만료라 파싱조차 안 될 때)는
  // 존재하지도 않는 "/admin/live-host/"로 보내 무조건 404를 띄우는 대신, 항상 존재하는
  // 관리자 홈으로 보낸다.
  const failRedirect = (cid, msg) => res.redirect((cid ? `/admin/live-host/${cid}` : '/admin') + '?omnicast_error=' + encodeURIComponent(msg));
  try {
    const parsedState = verifyOmnicastState(state);
    if (!parsedState) return failRedirect(null, '연결 요청이 만료되었거나 올바르지 않습니다. 다시 시도해주세요.');
    const { adminUserId, platform: statedPlatform } = parsedState;
    channelId = parsedState.channelId;
    if (statedPlatform !== platform) return failRedirect(channelId, '요청이 올바르지 않습니다.');
    if (oauthError) return failRedirect(channelId, '연결이 취소되었거나 거부되었습니다.');
    if (!code) return failRedirect(channelId, '인가코드를 받지 못했습니다.');

    const config = await getOmnicastPlatformConfig(platform);
    if (!config || !config.enabled) return failRedirect(channelId, '연동 설정을 찾을 수 없습니다.');

    if (platform === 'youtube') {
      const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code: String(code), client_id: config.client_key, client_secret: config.secret_key,
          redirect_uri: config.redirect_uri, grant_type: 'authorization_code'
        }).toString(), signal: AbortSignal.timeout(15000)
      });
      const tokenJson = await tokenResp.json().catch(() => null);
      if (!tokenResp.ok || !tokenJson?.access_token) { console.error('YouTube token exchange failed:', tokenJson); return failRedirect(channelId, '유튜브 인증 서버 응답에 실패했습니다.'); }

      const chResp = await fetch('https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true', {
        headers: { Authorization: `Bearer ${tokenJson.access_token}` }, signal: AbortSignal.timeout(15000)
      });
      const chJson = await chResp.json().catch(() => null);
      const ytChannel = chJson?.items?.[0];
      if (!chResp.ok || !ytChannel) { console.error('YouTube channel fetch failed:', chJson); return failRedirect(channelId, '유튜브 채널 정보를 가져오지 못했습니다. 이 계정에 라이브 스트리밍이 가능한 유튜브 채널이 있는지 확인해주세요.'); }

      const expiresAt = tokenJson.expires_in ? new Date(Date.now() + tokenJson.expires_in * 1000).toISOString() : null;
      await supabase.from('live_channel_broadcast_destinations_live').insert([{
        channel_id: channelId, platform: 'youtube', label: ytChannel.snippet?.title || '유튜브 채널',
        external_account_id: ytChannel.id, external_account_name: ytChannel.snippet?.title || null,
        access_token: encryptSecret(tokenJson.access_token), refresh_token: encryptSecret(tokenJson.refresh_token || null), token_expires_at: expiresAt,
        status: 'connected', connected_by: adminUserId
      }]);
      return res.redirect(`/admin/live-host/${channelId}?omnicast_connected=youtube`);

    }

    if (platform === 'facebook') {
      const tokenResp = await fetch('https://graph.facebook.com/v19.0/oauth/access_token?' + new URLSearchParams({
        client_id: config.client_key, client_secret: config.secret_key, redirect_uri: config.redirect_uri, code: String(code)
      }).toString(), { signal: AbortSignal.timeout(15000) });
      const tokenJson = await tokenResp.json().catch(() => null);
      if (!tokenResp.ok || !tokenJson?.access_token) { console.error('Facebook token exchange failed:', tokenJson); return failRedirect(channelId, '페이스북 인증 서버 응답에 실패했습니다.'); }

      const pagesResp = await fetch(`https://graph.facebook.com/v19.0/me/accounts?access_token=${encodeURIComponent(tokenJson.access_token)}`, { signal: AbortSignal.timeout(15000) });
      const pagesJson = await pagesResp.json().catch(() => null);
      const pages = pagesJson?.data || [];
      if (!pagesResp.ok || pages.length === 0) { console.error('Facebook pages fetch failed:', pagesJson); return failRedirect(channelId, '이 계정으로 관리 중인 페이스북 페이지를 찾지 못했습니다. 라이브를 진행할 페이지의 관리자 권한이 있는지 확인해주세요.'); }

      if (pages.length === 1) {
        const page = pages[0];
        await supabase.from('live_channel_broadcast_destinations_live').insert([{
          channel_id: channelId, platform: 'facebook', label: page.name || '페이스북 페이지',
          external_account_id: page.id, external_account_name: page.name || null,
          access_token: encryptSecret(page.access_token), status: 'connected', connected_by: adminUserId
        }]);
        return res.redirect(`/admin/live-host/${channelId}?omnicast_connected=facebook`);

      }

      // 관리 중인 페이지가 여러 개면 임의로 첫 페이지를 골라버리지 않고, 어느 페이지를 라이브에 쓸지
      // 관리자가 직접 고르게 한다. 페이지별 access_token은 15분짜리 임시 테이블에만 담아두고, 실제
      // 목적지로 확정될 때에만 live_channel_broadcast_destinations_live에 저장한다.
      const { data: pending, error: pendingErr } = await supabase.from('omnicast_pending_facebook_selections').insert([{
        channel_id: channelId, admin_user_id: adminUserId,
        pages: pages.map(p => ({ id: p.id, name: p.name, access_token: p.access_token }))
      }]).select('id').single();
      if (pendingErr) { console.error('Error storing pending facebook selection:', pendingErr); return failRedirect(channelId, '페이지 선택 정보를 저장하지 못했습니다.'); }
      return res.redirect(`/admin/live-host/${channelId}?omnicast_facebook_select=${pending.id}`);
    }

    return failRedirect(channelId, '지원하지 않는 플랫폼입니다.');
  } catch (err) {
    console.error(`Error in omnicast ${platform} callback:`, err);
    return failRedirect(channelId, '연결 처리 중 오류가 발생했습니다.');
  }
});

async function getPendingFacebookSelection(selectionId) {
  const { data, error } = await supabase.from('omnicast_pending_facebook_selections').select('*').eq('id', selectionId).maybeSingle();
  if (error) throw error;
  if (!data) return null;
  if (new Date(data.expires_at).getTime() < Date.now()) return null; // 15분 만료 - 조회 시점에 걸러낸다(스케줄러로 청소하지 않음)
  return data;
}

// 페이스북 계정이 여러 페이지를 관리 중일 때, 어떤 페이지를 골라야 할지 보여주기 위한 목록(access_token은
// 절대 내려주지 않는다 - 실제 확정은 choose 엔드포인트에서 서버가 직접 처리)
app.get('/api/admin/live/omnicast/facebook/pending/:selectionId', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const pending = await getPendingFacebookSelection(req.params.selectionId);
    if (!pending) return res.status(404).json({ error: 'Not Found', message: '선택 요청이 만료되었거나 존재하지 않습니다. 다시 연결해주세요.', timestamp: new Date().toISOString() });
    // 이 연결을 시작한 관리자 본인만 대기 중인 페이지 선택 정보를 볼 수 있다 (다른 관리자가 selectionId를
    // 추측/열람해 이 연결의 access_token이 어떤 페이지로 확정되는지 알거나 가로채지 못하도록).
    if (pending.admin_user_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden', message: '본인이 시작한 연결만 조회할 수 있습니다', timestamp: new Date().toISOString() });
    }
    res.json({ success: true, data: { channel_id: pending.channel_id, pages: (pending.pages || []).map(p => ({ id: p.id, name: p.name })) }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching pending facebook selection:', err);
    res.status(500).json({ error: 'Failed to fetch pending facebook selection', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/live/omnicast/facebook/pending/:selectionId/choose', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { page_id } = req.body || {};
    if (!page_id) return res.status(400).json({ error: 'Bad Request', message: 'page_id는 필수입니다', timestamp: new Date().toISOString() });
    const pending = await getPendingFacebookSelection(req.params.selectionId);
    if (!pending) return res.status(404).json({ error: 'Not Found', message: '선택 요청이 만료되었거나 존재하지 않습니다. 다시 연결해주세요.', timestamp: new Date().toISOString() });
    // 이 연결을 시작한 관리자 본인만 페이지를 확정할 수 있다.
    if (pending.admin_user_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden', message: '본인이 시작한 연결만 확정할 수 있습니다', timestamp: new Date().toISOString() });
    }
    const page = (pending.pages || []).find(p => p.id === page_id);
    if (!page) return res.status(400).json({ error: 'Bad Request', message: '목록에 없는 페이지입니다', timestamp: new Date().toISOString() });

    const { data, error } = await supabase.from('live_channel_broadcast_destinations_live').insert([{
      channel_id: pending.channel_id, platform: 'facebook', label: page.name || '페이스북 페이지',
      external_account_id: page.id, external_account_name: page.name || null,
      access_token: encryptSecret(page.access_token), status: 'connected', connected_by: pending.admin_user_id
    }]).select().single();
    if (error) throw error;
    await supabase.from('omnicast_pending_facebook_selections').delete().eq('id', req.params.selectionId);

    res.status(201).json({ success: true, data: maskOmnicastDestination(data), timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error choosing facebook page:', err);
    res.status(500).json({ error: 'Failed to choose facebook page', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 구글 access_token은 보통 1시간이면 만료된다. 목적지를 연결해두고 한참 뒤에(예: 다음날 방송) 다시
// 쓰면 access_token만으로는 401이 나므로, 만료됐거나 곧 만료될 때(2분 여유)는 refresh_token으로 새
// access_token을 발급받아 DB에도 갱신해둔다 - 이렇게 하지 않으면 "연결은 됐는데 방송 시작이 계속
// 실패하는" 현상이 생긴다. refresh_token이 없거나 갱신 자체가 실패하면 원래 access_token을 그대로
// 돌려주고(있는 그대로 시도) 실제 API 호출에서 401로 실패하게 둔다 - 여기서 예외를 던지지 않는다.
async function getFreshYoutubeAccessToken(dest) {
  const expiresAt = dest.token_expires_at ? new Date(dest.token_expires_at).getTime() : 0;
  const stillValid = expiresAt && (expiresAt - Date.now() > 2 * 60 * 1000);
  const currentAccessToken = decryptSecret(dest.access_token);
  if (stillValid || !dest.refresh_token) return currentAccessToken;
  try {
    const config = await getOmnicastPlatformConfig('youtube');
    if (!config || !config.client_key || !config.secret_key) return currentAccessToken;
    const resp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: config.client_key, client_secret: config.secret_key,
        refresh_token: decryptSecret(dest.refresh_token), grant_type: 'refresh_token'
      }).toString(), signal: AbortSignal.timeout(15000)
    });
    const json = await resp.json().catch(() => null);
    if (!resp.ok || !json?.access_token) { console.error('YouTube token refresh failed:', json); return currentAccessToken; }
    const newExpiresAt = json.expires_in ? new Date(Date.now() + json.expires_in * 1000).toISOString() : null;
    await supabase.from('live_channel_broadcast_destinations_live')
      .update({ access_token: encryptSecret(json.access_token), token_expires_at: newExpiresAt, updated_at: new Date().toISOString() })
      .eq('id', dest.id);
    return json.access_token;
  } catch (err) {
    console.error('Error refreshing YouTube access token:', err);
    return currentAccessToken;
  }
}

// 목적지별로 실제 플랫폼에 "이번 방송" 생성을 시도한다 - 절대 예외를 던지지 않고(호출부가 항상 행 하나를
// 만들 수 있도록) 실패하면 status:'error'+error_message를 채워 돌려준다. custom_rtmp는 외부 호출이
// 없으므로 저장해둔 값을 그대로 복사한다.
async function createOmnicastBroadcast(dest, session) {
  if (dest.platform === 'custom_rtmp') {
    return { status: 'created', ingest_rtmp_url: dest.rtmp_url, ingest_stream_key: decryptSecret(dest.stream_key) };
  }

  if (dest.platform === 'youtube') {
    try {
      const accessToken = await getFreshYoutubeAccessToken(dest);
      const bResp = await fetch('https://www.googleapis.com/youtube/v3/liveBroadcasts?part=snippet,status,contentDetails', {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          snippet: { title: session.title, scheduledStartTime: new Date().toISOString() },
          status: { privacyStatus: 'public' },
          contentDetails: { enableAutoStart: true, enableAutoStop: true }
        }), signal: AbortSignal.timeout(15000)
      });
      const bJson = await bResp.json().catch(() => null);
      if (!bResp.ok || !bJson?.id) return { status: 'error', error_message: `유튜브 방송 생성 실패: ${bJson?.error?.message || bResp.status}` };

      const sResp = await fetch('https://www.googleapis.com/youtube/v3/liveStreams?part=snippet,cdn', {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ snippet: { title: session.title }, cdn: { frameRate: 'variable', ingestionType: 'rtmp', resolution: 'variable' } }), signal: AbortSignal.timeout(15000)
      });
      const sJson = await sResp.json().catch(() => null);
      if (!sResp.ok || !sJson?.id) return { status: 'error', error_message: `유튜브 스트림 생성 실패: ${sJson?.error?.message || sResp.status}`, external_broadcast_id: bJson.id };

      await fetch(`https://www.googleapis.com/youtube/v3/liveBroadcasts/bind?id=${bJson.id}&streamId=${sJson.id}&part=id,contentDetails`, {
        method: 'POST', headers: { Authorization: `Bearer ${accessToken}` }, signal: AbortSignal.timeout(15000)
      });

      return {
        status: 'created', external_broadcast_id: bJson.id,
        ingest_rtmp_url: sJson.cdn?.ingestionInfo?.ingestionAddress || null,
        ingest_stream_key: sJson.cdn?.ingestionInfo?.streamName || null
      };
    } catch (err) {
      return { status: 'error', error_message: `유튜브 연동 오류: ${err.message}` };
    }
  }
  if (dest.platform === 'facebook') {
    try {
      const lvResp = await fetch(`https://graph.facebook.com/v19.0/${dest.external_account_id}/live_videos`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: session.title, status: 'LIVE_NOW', access_token: decryptSecret(dest.access_token) }), signal: AbortSignal.timeout(15000)
      });
      const lvJson = await lvResp.json().catch(() => null);

      if (!lvResp.ok || !lvJson?.id) return { status: 'error', error_message: `페이스북 라이브 생성 실패: ${lvJson?.error?.message || lvResp.status}` };
      // 페이스북은 서버 주소와 키가 분리되지 않고 stream_url 하나에 합쳐서 발급된다 - OBS 서버란에 이 값을
      // 통째로 넣으면 된다(키를 따로 입력할 필요 없음). 화면에는 ingest_rtmp_url 하나만 안내한다.
      return { status: 'created', external_broadcast_id: lvJson.id, ingest_rtmp_url: lvJson.secure_stream_url || lvJson.stream_url || null, ingest_stream_key: null };
    } catch (err) {
      return { status: 'error', error_message: `페이스북 연동 오류: ${err.message}` };
    }
  }
  // Cloudflare Stream: 방송마다 새 "Live Input"을 하나 만들어 RTMP 수신정보(OBS에 붙여넣을 주소+키)와
  // 재생용 HLS 주소를 함께 발급받는다. 유튜브와 마찬가지로 인풋 하나가 곧 이번 방송 1회분이다.
  if (dest.platform === 'cloudflare_stream') {
    try {
      const apiToken = decryptSecret(dest.access_token);
      const resp = await fetch(`https://api.cloudflare.com/client/v4/accounts/${dest.external_account_id}/stream/live_inputs`, {
        method: 'POST', headers: { Authorization: `Bearer ${apiToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ meta: { name: session.title }, recording: { mode: 'automatic', timeoutSeconds: 60 } }),
        signal: AbortSignal.timeout(15000)
      });
      const json = await resp.json().catch(() => null);
      if (!resp.ok || !json?.success || !json?.result?.uid) {
        return { status: 'error', error_message: `Cloudflare Stream 라이브 입력 생성 실패: ${json?.errors?.[0]?.message || resp.status}` };
      }
      const r = json.result;
      return {
        status: 'created', external_broadcast_id: r.uid,
        ingest_rtmp_url: r.rtmps?.url || null, ingest_stream_key: r.rtmps?.streamKey || null,
        playback_url: r.playback?.hls || null
      };
    } catch (err) {
      return { status: 'error', error_message: `Cloudflare Stream 연동 오류: ${err.message}` };
    }
  }
  return { status: 'error', error_message: '이 플랫폼은 아직 지원하지 않습니다.' };
}

// ============================================
// 📹 LIVE+ 브라우저 원클릭 방송(WebRTC) - LiveKit Cloud 연동
// ============================================
// OmniCast(유튜브/페이스북/Cloudflare Stream)는 전부 "호스트가 OBS 같은 별도 방송 장비로 RTMP 송출"을
// 전제로 한다. 이 방식은 상품을 들고 카메라 앞에서 바로 설명하는 가벼운 라이브(폰/노트북 웹캠으로 즉석
// 방송)에는 진입장벽이 높다. 그래서 브라우저 카메라를 바로 쓰는 별도 경로를 추가한다 - 실시간 영상 릴레이
// 자체는 여기서도 LIVE+ 서버가 하지 않고(기존 설계 원칙 유지), LiveKit Cloud라는 WebRTC 전용 SaaS가
// 담당한다. 이 서버는 (1) 누가 방송을 켰는지(세션당 1개, live_sessions_live.webrtc_active) 기록하고
// (2) 호스트/시청자별 접속 토큰만 발급한다. jsonwebtoken 같은 별도 라이브러리를 쓰지 않는다는 파일 상단
// 방침과 동일하게, LiveKit 토큰 규격(HS256 JWT + video grant)도 crypto로 직접 서명한다.
function base64urlEncode(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function mintLiveKitToken({ identity, name, room, canPublish }) {
  const apiKey = process.env.LIVEKIT_API_KEY;
  const apiSecret = process.env.LIVEKIT_API_SECRET;
  if (!apiKey || !apiSecret) return null;
  const now = Math.floor(Date.now() / 1000);
  const header = base64urlEncode(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const payload = base64urlEncode(Buffer.from(JSON.stringify({
    iss: apiKey, sub: identity, name: name || identity, iat: now, nbf: now, exp: now + 6 * 3600,
    video: { room, roomJoin: true, canPublish: !!canPublish, canSubscribe: true, canPublishData: !!canPublish }
  })));
  const sig = base64urlEncode(crypto.createHmac('sha256', apiSecret).update(`${header}.${payload}`).digest());
  return `${header}.${payload}.${sig}`;
}
function isLiveKitConfigured() {
  return !!(process.env.LIVEKIT_URL && process.env.LIVEKIT_API_KEY && process.env.LIVEKIT_API_SECRET);
}

// 관리자: LiveKit 연동이 설정되어 있는지(환경변수 등록 여부) - 호스트 화면에서 "브라우저로 방송 시작"
// 버튼을 보여줄지 판단하는 용도. URL 자체는 비밀이 아니라 그대로 내려준다.
app.get('/api/admin/live/webrtc/status', authenticate, requireRole(['admin', 'super_admin']), (req, res) => {
  res.json({ success: true, data: { configured: isLiveKitConfigured(), livekit_url: process.env.LIVEKIT_URL || null }, timestamp: new Date().toISOString() });
});

// 호스트: 브라우저 방송 시작 - 세션이 이미 "방송 중(live)" 상태여야 한다(먼저 평소처럼 "방송 시작"을
// 눌러야 함 - 상태 모델을 하나로 유지). webrtc_active를 켜고, 발행(publish) 가능한 호스트 토큰을 돌려준다.
app.post('/api/admin/live/channels/:id/sessions/:sessionId/webrtc/start', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    if (!isLiveKitConfigured()) return res.status(400).json({ error: 'Bad Request', message: '브라우저 방송(WebRTC) 연동이 아직 설정되지 않았습니다. LiveKit Cloud 가입 후 LIVEKIT_URL/LIVEKIT_API_KEY/LIVEKIT_API_SECRET을 환경변수로 등록해주세요.', timestamp: new Date().toISOString() });
    const { data: session } = await supabase.from('live_sessions_live').select('id, status').eq('id', req.params.sessionId).eq('channel_id', req.params.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (session.status !== 'live') return res.status(400).json({ error: 'Bad Request', message: '먼저 "방송 시작"으로 세션을 방송 중 상태로 전환한 뒤 브라우저 방송을 켜주세요.', timestamp: new Date().toISOString() });

    await supabase.from('live_sessions_live').update({ webrtc_active: true }).eq('id', session.id);
    const token = mintLiveKitToken({ identity: `host_${req.user.id}`, name: '호스트', room: session.id, canPublish: true });
    res.json({ success: true, data: { livekit_url: process.env.LIVEKIT_URL, token }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error starting webrtc broadcast:', err);
    res.status(500).json({ error: 'Failed to start webrtc broadcast', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/live/channels/:id/sessions/:sessionId/webrtc/stop', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_sessions_live').update({ webrtc_active: false })
      .eq('id', req.params.sessionId).eq('channel_id', req.params.id).select('id').maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error stopping webrtc broadcast:', err);
    res.status(500).json({ error: 'Failed to stop webrtc broadcast', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 공개: 시청자용 구독 전용 토큰 - 누구나(비로그인 포함) 호출 가능. 호출할 때마다 새 익명 identity를
// 발급한다(로그인 여부를 굳이 따지지 않음 - 시청은 원래 비로그인으로도 가능한 공개 정보였다).
app.get('/api/live/channels/:slug/sessions/:sessionId/webrtc/viewer-token', async (req, res) => {
  try {
    if (!isLiveKitConfigured()) return res.status(400).json({ error: 'Bad Request', message: '브라우저 방송 연동이 설정되지 않았습니다.', timestamp: new Date().toISOString() });
    const { data: session } = await supabase.from('live_sessions_live').select('id, webrtc_active').eq('id', req.params.sessionId).maybeSingle();
    if (!session || !session.webrtc_active) return res.status(404).json({ error: 'Not Found', message: '지금 진행 중인 브라우저 방송이 없습니다', timestamp: new Date().toISOString() });
    const viewerId = `viewer_${crypto.randomBytes(6).toString('hex')}`;
    const token = mintLiveKitToken({ identity: viewerId, name: '시청자', room: session.id, canPublish: false });
    res.json({ success: true, data: { livekit_url: process.env.LIVEKIT_URL, token }, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error minting webrtc viewer token:', err);
    res.status(500).json({ error: 'Failed to mint viewer token', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.get('/api/admin/live/channels/:id/sessions/:sessionId/omnicast/targets', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_session_broadcast_targets_live')
      .select('*, live_channel_broadcast_destinations_live(label, platform)').eq('live_session_id', req.params.sessionId).order('created_at', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data || [], count: (data || []).length, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error fetching omnicast targets:', err);
    res.status(500).json({ error: 'Failed to fetch omnicast targets', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.post('/api/admin/live/channels/:id/sessions/:sessionId/omnicast/targets', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { destination_id } = req.body || {};
    if (!destination_id) return res.status(400).json({ error: 'Bad Request', message: 'destination_id는 필수입니다', timestamp: new Date().toISOString() });

    const { data: session } = await supabase.from('live_sessions_live').select('id, title, channel_id').eq('id', req.params.sessionId).eq('channel_id', req.params.id).maybeSingle();
    if (!session) return res.status(404).json({ error: 'Not Found', message: '세션을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    const { data: dest } = await supabase.from('live_channel_broadcast_destinations_live').select('*').eq('id', destination_id).eq('channel_id', req.params.id).maybeSingle();
    if (!dest) return res.status(404).json({ error: 'Not Found', message: '목적지를 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (dest.status !== 'connected') return res.status(400).json({ error: 'Bad Request', message: '연결이 끊긴 목적지입니다. 다시 연결한 뒤 시도해주세요.', timestamp: new Date().toISOString() });

    const { data: existing } = await supabase.from('live_session_broadcast_targets_live').select('id').eq('live_session_id', session.id).eq('destination_id', destination_id).maybeSingle();
    if (existing) return res.status(409).json({ error: 'Conflict', message: '이미 이 세션에 추가된 목적지입니다', timestamp: new Date().toISOString() });

    const result = await createOmnicastBroadcast(dest, session);
    const { data, error } = await supabase.from('live_session_broadcast_targets_live').insert([{
      live_session_id: session.id, destination_id, platform: dest.platform,
      external_broadcast_id: result.external_broadcast_id || null,
      ingest_rtmp_url: result.ingest_rtmp_url || null, ingest_stream_key: result.ingest_stream_key || null,
      playback_url: result.playback_url || null,
      status: result.status, error_message: result.error_message || null
    }]).select().single();
    if (error) throw error;
    res.status(result.status === 'error' ? 502 : 201).json({ success: result.status !== 'error', data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error creating omnicast target:', err);
    res.status(500).json({ error: 'Failed to create omnicast target', message: err.message, timestamp: new Date().toISOString() });
  }
});

// 송출 종료 - 유튜브/페이스북은 최선을 다해 원격 방송도 함께 종료를 시도하지만(실패해도 로컬 기록은
// 그대로 종료 처리한다 - 이미 끝난 방송을 다시 못 끝내서 우리 화면에 영원히 "진행중"으로 남는 것을 방지),
// 목적지 자체가 이미 지워졌거나 토큰이 만료된 경우까지 고려해 항상 로컬 상태는 갱신한다.
app.patch('/api/admin/live/channels/:id/sessions/:sessionId/omnicast/targets/:targetId', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    if (req.body?.status !== 'ended') return res.status(400).json({ error: 'Bad Request', message: "status는 'ended'만 지원합니다", timestamp: new Date().toISOString() });
    const { data: target } = await supabase.from('live_session_broadcast_targets_live').select('*').eq('id', req.params.targetId).eq('live_session_id', req.params.sessionId).maybeSingle();
    if (!target) return res.status(404).json({ error: 'Not Found', message: '송출 대상을 찾을 수 없습니다', timestamp: new Date().toISOString() });

    if (target.status !== 'ended' && target.external_broadcast_id) {
      const { data: dest } = await supabase.from('live_channel_broadcast_destinations_live').select('*').eq('id', target.destination_id).maybeSingle();
      try {
        if (dest && target.platform === 'youtube') {
          const accessToken = await getFreshYoutubeAccessToken(dest);
          await fetch(`https://www.googleapis.com/youtube/v3/liveBroadcasts/transition?broadcastStatus=complete&id=${target.external_broadcast_id}&part=id,status`, {
            method: 'POST', headers: { Authorization: `Bearer ${accessToken}` }, signal: AbortSignal.timeout(15000)
          });
        } else if (dest && target.platform === 'facebook') {
          await fetch(`https://graph.facebook.com/v19.0/${target.external_broadcast_id}`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ end_live_video: true, access_token: decryptSecret(dest.access_token) }), signal: AbortSignal.timeout(15000)
          });
        }
      } catch (remoteErr) {

        console.error('Error ending remote broadcast (로컬 상태는 그대로 종료 처리):', remoteErr);
      }
    }

    const { data, error } = await supabase.from('live_session_broadcast_targets_live')
      .update({ status: 'ended', ended_at: new Date().toISOString() }).eq('id', req.params.targetId).select().single();
    if (error) throw error;
    res.json({ success: true, data, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error ending omnicast target:', err);
    res.status(500).json({ error: 'Failed to end omnicast target', message: err.message, timestamp: new Date().toISOString() });
  }
});

app.delete('/api/admin/live/channels/:id/sessions/:sessionId/omnicast/targets/:targetId', authenticate, requireRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { data: target } = await supabase.from('live_session_broadcast_targets_live').select('status').eq('id', req.params.targetId).eq('live_session_id', req.params.sessionId).maybeSingle();
    if (!target) return res.status(404).json({ error: 'Not Found', message: '송출 대상을 찾을 수 없습니다', timestamp: new Date().toISOString() });
    if (target.status === 'live') return res.status(409).json({ error: 'Conflict', message: '송출 중인 목적지입니다. 먼저 종료해주세요.', timestamp: new Date().toISOString() });
    const { error } = await supabase.from('live_session_broadcast_targets_live').delete().eq('id', req.params.targetId);
    if (error) throw error;
    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Error deleting omnicast target:', err);
    res.status(500).json({ error: 'Failed to delete omnicast target', message: err.message, timestamp: new Date().toISOString() });
  }
});

// ============================================
// 404 핸들러
// - 브라우저 탐색(HTML 요청)은 사용자 친화적인 404 페이지로 안내
// - API/프로그램 요청은 기존처럼 JSON으로 응답
// ============================================
app.use((req, res) => {
  if (req.accepts('html') && !req.path.startsWith('/api')) {
    return res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.path} not found`,
    timestamp: new Date().toISOString()
  });
});

// ============================================
// 에러 핸들러
// ============================================
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    timestamp: new Date().toISOString()
  });
});

// ============================================
// 서버 시작
// ============================================
app.listen(PORT, () => {
  console.log(`✅ WITH+ API running on http://localhost:${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔌 Supabase Connected: ${supabaseUrl}`);
  console.log(`📊 Database: GMWOS (통합 모드)`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  process.exit(0);
});
