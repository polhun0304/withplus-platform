// 관리자 연동 키 입력 형식 검사 단위 시험(외부 호출·DB 없음). 실행: node scripts/test-secret-format.js
const assert = require('node:assert/strict');
const { validateAnthropicKey, validateSupplierKey, validateEmailConfig } = require('../lib/secret-format');

let n = 0;
const t = (name, fn) => { fn(); n++; console.log(`  ✓ ${name}`); };

t('Anthropic 키 칸에 이메일 주소 차단·sk-ant- 필수', () => {
  assert.match(validateAnthropicKey('no-reply@withplus.co.kr'), /이메일 주소가 아니라/);
  assert.match(validateAnthropicKey('abc123'), /sk-ant-/);
  assert.equal(validateAnthropicKey('sk-ant-api03-x'), null);
  assert.equal(validateAnthropicKey(undefined), null); // 키를 안 바꾸는 저장(활성화만)
});
t('도매꾹 키 칸에 이메일 주소·공백 차단', () => {
  assert.match(validateSupplierKey('me@example.com'), /이메일 주소가 아니라/);
  assert.match(validateSupplierKey('ab cd'), /공백/);
  assert.equal(validateSupplierKey('a1b2c3d4'), null);
  assert.equal(validateSupplierKey(null), null); // 지우기
});
t('SMTP 서버·보내는 주소·포트 형식', () => {
  assert.match(validateEmailConfig({ smtp_host: 'withplus@naver.com' }), /서버 주소/);
  assert.match(validateEmailConfig({ smtp_host: 'https://smtp.naver.com' }), /https:\/\/ 없이/);
  assert.match(validateEmailConfig({ smtp_host: 'smtp.naver.com', from_email: 'withplus' }), /이메일 주소 형식/);
  assert.match(validateEmailConfig({ smtp_host: 'smtp.naver.com', smtp_port: 'abc' }), /포트/);
  assert.equal(validateEmailConfig({ smtp_host: 'smtp.naver.com', smtp_port: 465, smtp_user: 'withplus@naver.com', from_email: 'noreply@withplus.co.kr', smtp_pass_new: 'app-pass-1234' }), null);
});
t('Resend SMTP — 비밀번호 칸에 이메일 주소 차단(re_ 필수), 아이디는 resend', () => {
  assert.match(validateEmailConfig({ smtp_host: 'smtp.resend.com', smtp_user: 'resend', smtp_pass_new: 'no-reply@mail.withplus.co.kr' }), /이메일 주소가 아니라 Resend API 키/);
  assert.match(validateEmailConfig({ smtp_host: 'smtp.resend.com', smtp_user: 'resend', smtp_pass_new: 'abcdef' }), /re_/);
  assert.match(validateEmailConfig({ smtp_host: 'smtp.resend.com', smtp_user: 'me@withplus.co.kr' }), /아이디는 resend/);
  assert.equal(validateEmailConfig({ smtp_host: 'smtp.resend.com', smtp_user: 'resend', smtp_pass_new: 're_abc123' }), null);
});
t('비밀번호만 바꿀 때도 기존 서버가 Resend 면 re_ 검사, 바꾸지 않은 칸은 검사 안 함', () => {
  assert.match(validateEmailConfig({ smtp_pass_new: 'no-reply@mail.withplus.co.kr', effective_host: 'smtp.resend.com' }), /Resend API 키/);
  assert.equal(validateEmailConfig({ effective_host: 'not a host' }), null);
});
t('일반 SMTP 비밀번호 칸에 이메일 주소 차단', () => {
  assert.match(validateEmailConfig({ smtp_host: 'smtp.naver.com', smtp_pass_new: 'withplus@naver.com' }), /이메일 주소가 들어갔습니다/);
});
console.log(`secret-format: ${n}/${n} 통과`);
