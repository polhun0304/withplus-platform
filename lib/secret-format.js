// 관리자 화면 외부 연동 키 입력 형식 검사 — 잘못된 칸에 다른 값(예: 키 칸에 이메일 주소)을 넣는 실수 방지.
// 저장 직전 서버에서 검사한다(화면 검사만 믿지 않음). 통과 못 하면 이유 문구, 통과하면 null.
const EMAIL_RE = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;
const HOST_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

function validateAnthropicKey(v) {
  if (!v) return null;
  if (v.includes('@')) return '이메일 주소가 아니라 Anthropic API 키(sk-ant- 로 시작)를 넣어 주세요.';
  if (!v.startsWith('sk-ant-')) return 'Anthropic API 키는 sk-ant- 로 시작합니다.';
  return null;
}

function validateSupplierKey(v) {
  if (!v) return null;
  if (v.includes('@')) return '이 칸은 이메일 주소가 아니라 API 키를 넣는 곳입니다.';
  if (/\s/.test(v)) return 'API 키에는 공백이 들어가지 않습니다.';
  return null;
}

// 메일(SMTP) 설정 — 이번에 바꾸는 칸만 넘긴다(기존에 저장된 값 때문에 다른 저장이 막히지 않게).
// effective_host: Resend 여부 판정용 저장 후 서버 주소(이번 변경 없으면 기존 값)
function validateEmailConfig(c) {
  const host = (c.smtp_host || '').trim();
  const effHost = (c.effective_host != null ? c.effective_host : host).trim();
  if (host) {
    if (host.includes('@')) return 'SMTP 서버 칸에는 이메일 주소가 아니라 서버 주소(예: smtp.naver.com)를 넣어 주세요.';
    if (/^[a-z]+:\/\//i.test(host) || !HOST_RE.test(host)) return 'SMTP 서버는 smtp.naver.com 처럼 주소만 넣어 주세요(https:// 없이).';
  }
  if (c.from_email && !EMAIL_RE.test(c.from_email)) return '보내는 주소는 이메일 주소 형식으로 넣어 주세요(예: noreply@withplus.co.kr).';
  if (c.smtp_port != null && c.smtp_port !== '' && !(Number.isInteger(Number(c.smtp_port)) && Number(c.smtp_port) > 0 && Number(c.smtp_port) < 65536)) return 'SMTP 포트는 465·587 같은 숫자로 넣어 주세요.';
  const isResend = /(^|\.)resend\.com$/i.test(effHost);
  if (isResend && c.smtp_user && c.smtp_user !== 'resend') return 'Resend SMTP 의 아이디는 resend 입니다(이메일 주소가 아님).';
  if (c.smtp_pass_new) {
    if (isResend && !c.smtp_pass_new.startsWith('re_')) return c.smtp_pass_new.includes('@') ? '이메일 주소가 아니라 Resend API 키(re_ 로 시작)를 비밀번호 칸에 넣어 주세요.' : 'Resend SMTP 비밀번호는 Resend API 키(re_ 로 시작)입니다.';
    if (EMAIL_RE.test(c.smtp_pass_new)) return '비밀번호 칸에 이메일 주소가 들어갔습니다. 메일 계정 비밀번호(또는 앱 비밀번호)를 넣어 주세요.';
  }
  return null;
}

module.exports = { validateAnthropicKey, validateSupplierKey, validateEmailConfig };
