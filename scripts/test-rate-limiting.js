// Rate Limiting 검증: 격차분석에서 지적된 "API 남용 방어(Rate Limiting) 전무" 항목 해결 확인.
// 쿠폰 코드 API처럼 무작위 대입이 가능한 엔드포인트가 일정 횟수 이상 요청 시 429로 막히는지 확인한다.
const API = 'http://localhost:3003';

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log('✅', msg); }
  else { fail++; console.log('❌', msg); }
}

async function main() {
  // ============================================
  // 1) 쿠폰 검증 API - 로그인 없이도 호출되는 공개 엔드포인트라 무작위 대입 공격의 대상이 되기 쉽다.
  //    couponLimiter의 max=20(15분)이므로, 21번째 요청부터는 429가 떠야 한다.
  // ============================================
  const results = [];
  for (let i = 0; i < 25; i++) {
    const res = await fetch(`${API}/api/coupons/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: `RANDOM-CODE-${i}` })
    });
    results.push(res.status);
  }
  const rateLimited = results.filter(s => s === 429);
  assert(rateLimited.length > 0, `20회를 초과한 쿠폰 코드 시도는 429(Too Many Requests)로 차단됨 (25회 중 ${rateLimited.length}회 차단됨)`);
  assert(results.slice(0, 20).every(s => s !== 429), '처음 20회 이내 요청은 정상적으로 처리됨(429 아님)');

  // ============================================
  // 2) 429 응답에 표준 rate-limit 헤더가 포함되는지, 응답 메시지가 한국어로 친절하게 안내되는지
  // ============================================
  const overRes = await fetch(`${API}/api/coupons/validate`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: 'ONE-MORE' })
  });
  assert(overRes.status === 429, '추가 요청도 계속 429로 차단됨');
  const overJson = await overRes.json();
  assert(overJson.message && overJson.message.includes('너무 많습니다'), `429 응답에 한국어 안내 메시지 포함 (실제: ${overJson.message})`);
  assert(overRes.headers.get('ratelimit-limit') !== null || overRes.headers.get('x-ratelimit-limit') !== null, '표준 RateLimit 관련 헤더가 포함됨');

  // ============================================
  // 3) 일반 API(예: /api/categories)는 훨씬 여유로운 한도(15분당 600회)라 소량 반복 호출로는 차단되지 않음
  // ============================================
  const generalResults = [];
  for (let i = 0; i < 15; i++) {
    const res = await fetch(`${API}/api/categories`);
    generalResults.push(res.status);
  }
  assert(generalResults.every(s => s === 200), '일반 API(카테고리 조회)는 소량 반복 호출로는 차단되지 않고 정상 응답함');

  console.log(`\n결과: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(err => { console.error('테스트 실행 중 오류:', err); process.exit(1); });
