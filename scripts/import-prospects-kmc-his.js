// 기독교대한감리회(KMC) 역사정보자료실 "교회주소록 검색 서비스"(https://his.kmc.or.kr/address)에서
// 전국 감리교회 주소록을 수집해 community_prospects 스테이징 테이블에 적재하는 스크립트.
//
// 이 사이트는 공공데이터포털과 달리 교단이 직접 운영하는 전국 단위 교회 주소록으로,
// /address/church?page=1..344 형태의 서버렌더링 테이블에 연회/지방/교회명/담임/전화/주소/홈페이지가
// 그대로 노출되어 있다(로그인 불필요, robots.txt도 /api/, /users/ 외에는 전부 허용).
// 단, 표의 "연회"/"지방" 컴럼은 감리교단 내부 행정구역(예: 서울연회 종로지방)이라 대한민국
// 시/도·시/군/구와 1:1로 대응하지 않는다 - 그래서 region_sido/region_sigungu는 이 컴럼이 아니라
// "주소" 컴럼(우편번호 + 실제 도로명주소)을 직접 파싱해서 뿑아낸다.
//
// 실행: node scripts/import-prospects-kmc-his.js [--start 1] [--end 344] [--dry-run] [--delay-ms 600]
// 예:   node scripts/import-prospects-kmc-his.js --start 1 --end 5 --dry-run   (5페이지만 미리보기)
//       node scripts/import-prospects-kmc-his.js --start 1 --end 344          (전체 수집)

const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, serviceKey);

const DRY_RUN = process.argv.includes('--dry-run');
function argVal(flag, def) {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : def;
}
const START_PAGE = Number(argVal('--start', '1'));
const END_PAGE = Number(argVal('--end', '344'));
const DELAY_MS = Number(argVal('--delay-ms', '600'));
const BASE_URL = 'https://his.kmc.or.kr/address/church';

// 전국 17개 시/도 표준 명칭 - 주소 문자열 맨 앞(우편번호 다음)에서 이 중 하나를 찾아 region_sido로 사용.
// 줄여쓴 표기(서울/서울시)도 함께 인식해서 정식 명칭으로 정규화한다.
const SIDO_ALIASES = [
  [/^서울(특별시|시)?/, '서울특별시'],
  [/^부산(광역시|시)?/, '부산광역시'],
  [/^대구(광역시|시)?/, '대구광역시'],
  [/^인천(광역시|시)?/, '인천광역시'],
  [/^광주(광역시|시)?/, '광주광역시'],
  [/^대전(광역시|시)?/, '대전광역시'],
  [/^울산(광역시|시)?/, '울산광역시'],
  [/^세종(특별자치시|시)?/, '세종특별자치시'],
  [/^경기(도)?/, '경기도'],
  [/^강원(특별자치도|도)?/, '강원특별자치도'],
  [/^충청북도|^충북/, '충청북도'],
  [/^충청남도|^충남/, '충청남도'],
  [/^전라북도|^전북(특별자치도)?/, '전북특별자치도'],
  [/^전라남도|^전남/, '전라남도'],
  [/^경상북도|^경북/, '경상북도'],
  [/^경상남도|^경남/, '경상남도'],
  [/^제주(특별자치도|도)?/, '제주특별자치도'],
];

function stripTags(html) {
  return html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

// dedup_key 계산 - server.js computeDedupKeyForProspect()와 동일 로직(스크립트 간에 항상 동일하게 유지)
function computeDedupKey(orgType, name, address) {
  const normalize = (s) => String(s || '').replace(/\s+/g, '').trim();
  return `${orgType}_${normalize(name)}_${normalize(address).slice(0, 30)}`;
}

// "03162 서울시 종로구 인사동 5길 25(인사동)" 같은 문자열에서 우편번호를 떼어내고
// 시/도·시/군/구를 추출한다. 시/군/구는 주소 안에서 "OO시/OO군", "OO군", 특별시/광역시 산하 "OO구" 등 다양한 표기 대응
function parseAddress(raw) {
  if (!raw) return null;
  let addr = raw.trim().replace(/^\d{5}\s*/, ''); // 우편번호(5자리) 제거
  if (!addr) return null;

  let sido = null;
  for (const [re, canonical] of SIDO_ALIASES) {
    if (re.test(addr)) { sido = canonical; break; }
  }

  // 시/군/구 추출: 경기도 "성남시 중원구"처럼 시+구가 함께 있는 경우 묶어서 잡고,
  // 그 외엔 "OO군"/"OO구" 단독, 특별시·광역시 산하 "OO구" 등을 순서대로 시도한다.
  let sigungu = null;
  const sidoWords = ['서울시', '부산시', '대구시', '인천시', '광주시', '대전시', '울산시', '세종시'];
  const compound = addr.match(/([가-힣]{2,6}시)\s+([가-힣]{2,6}구)(?=\s|$)/);
  if (compound && !sidoWords.includes(compound[1])) {
    sigungu = `${compound[1]} ${compound[2]}`;
  } else {
    const sigunguMatch = addr.match(/([가-힣]{2,6}(시|군|구))(?=\s|$)/g);
    if (sigunguMatch) {
      const candidates = sigunguMatch.filter(w => !sidoWords.includes(w));
      if (candidates.length > 0) sigungu = candidates[0];
    }
  }

  return { address: addr, sido, sigungu };
}

async function fetchPage(page) {
  const res = await fetch(`${BASE_URL}?page=${page}`, {
    headers: { 'User-Agent': 'Mozilla/5.0 (withplus-prospect-collector; contact via withplus admin)' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

// <tr>...</tr> 단위로 잘라 <td> 셀들을 뿑아낸다. 그룹 헤더 행("소속없음 (3)")은 주소 칸이 비어있어 자동 스킵된다.
function parseRows(html) {
  const rows = [];
  const trMatches = html.match(/<tr[^>]*>[\s\S]*?<\/tr>/g) || [];
  for (const tr of trMatches) {
    const tds = tr.match(/<td[^>]*>[\s\S]*?<\/td>/g);
    if (!tds || tds.length < 7) continue;
    const cells = tds.map(td => stripTags(td));
    const [, , , nameRaw, pastor, phone, addressRaw, website] = cells;
    let name = (nameRaw || '').replace(/\(소속목회자\)/, '').replace(/\(\s*\d+\s*\)\s*$/, '').trim();
    if (!name || !addressRaw) continue; // 그룹 헤더 행 등 스킵
    // 이 사이트는 컴럼 자체가 "교회"라서 이름을 "중앙"처럼 줄여서만 저장함 - 우리 쪽 표시/검색에서
    // 자연스럽도록(다른 소스와도 이름 형태를 맞추도록) "교회" 접미사를 보정해서 붙인다.
    if (!/(교회|성당|사찰|선교회|교당)$/.test(name)) name += '교회';
    rows.push({ name, pastor: pastor || null, phone: phone || null, addressRaw, website: website || null });
  }
  return rows;
}

async function main() {
  const allRows = [];
  let noAddressCount = 0;
  for (let page = START_PAGE; page <= END_PAGE; page++) {
    let html;
    let lastErr;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try { html = await fetchPage(page); break; }
      catch (e) { lastErr = e; await new Promise(r => setTimeout(r, 2000 * attempt)); }
    }
    if (!html) { console.error(`페이지 ${page} 실패(3회 재시도 후): ${lastErr && lastErr.message}`); continue; }

    const rows = parseRows(html);
    for (const r of rows) {
      const parsed = parseAddress(r.addressRaw);
      if (!parsed || !parsed.sido) { noAddressCount++; continue; }
      const phone = (r.phone || '').trim() || null;
      allRows.push({
        name: r.name,
        org_type: 'church',
        address: parsed.address,
        region_sido: parsed.sido,
        region_sigungu: parsed.sigungu,
        phone,
        latitude: null,
        longitude: null,
        source: 'kmc_his',
        source_url: `${BASE_URL}?page=${page}`,
        dedup_key: computeDedupKey('church', r.name, parsed.address),
        status: 'prospect',
        admin_note: r.pastor ? `담임: ${r.pastor}` : null,
      });
    }
    if (page % 20 === 0 || page === END_PAGE) {
      console.log(`진행: ${page}/${END_PAGE}페이지, 누적 ${allRows.length}건`);
    }
    if (page < END_PAGE) await new Promise(r => setTimeout(r, DELAY_MS));
  }

  console.log(`\n수집 완료: ${allRows.length}건 (주소 파싱 실패로 제외 ${noAddressCount}건)`);
  const bySido = allRows.reduce((acc, r) => { acc[r.region_sido] = (acc[r.region_sido] || 0) + 1; return acc; }, {});
  console.log('시/도별 분포:', bySido);

  if (DRY_RUN) {
    console.log('\n--dry-run 모드 - DB에 반영하지 않고 상위 5건만 미리보기:');
    console.log(allRows.slice(0, 5));
    return;
  }
  if (allRows.length === 0) { console.log('적재할 행이 없습니다.'); return; }

  // 대량이라 500건씩 나눈 upsert (Supabase 요청 크기 제한 대비)
  let totalInserted = 0;
  for (let i = 0; i < allRows.length; i += 500) {
    const chunk = allRows.slice(i, i + 500);
    const { data, error } = await supabase
      .from('community_prospects')
      .upsert(chunk, { onConflict: 'dedup_key', ignoreDuplicates: true })
      .select('id');
    if (error) { console.error(`적재 오류(청크 ${i}):`, error.message); process.exit(1); }
    totalInserted += (data || []).length;
  }
  console.log(`\n적재 완료: 신규 ${totalInserted}건, 중복 스킵 ${allRows.length - totalInserted}건 (전체 요청 ${allRows.length}건)`);
}

main().catch(err => { console.error('스크립트 실행 오류:', err); process.exit(1); });
