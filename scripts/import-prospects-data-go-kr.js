// 공공데이터포털(data.go.kr) 지자체별 "종교시설 현황" CSV를 community_prospects 스테이징 테이블로
// 수집·적재하는 스크립트. (계획 문서: nationwide_religious_org_import_plan.md 3절 "수집 파이프라인" 참고)
//
// 데이터 출처: 각 지자체가 공공데이터포털에 개별 등록한 파일(예: "서울특별시 중구_종교시설_20210806").
// 시군구 단위로 쪼개져 있어(전국 약 250개) 파일별로 이 스크립트를 반복 실행해 누적한다.
// 공공데이터포털은 공공누리(공공저작물 자유이용) 라이선스로 재사용을 전제로 공개하는 데이터라
// (참고로 천주교 쪽 공식 디렉토리인 maria.catholic.or.kr는 robots.txt가 AI 봇 크롤링을 명시적으로
//  차단하고 있어 자동 수집 대상에서 제외했다 - 사람이 브라우저로 보는 것과 자동화 수집은 다르게 취급해야 한다)
// community_prospects는 공개 테이블(communities)과 완전히 분리된 비공개 스테이징이라,
// 이 스크립트가 적재해도 관리자가 "공개 전환" 체크박스를 누르기 전까지는 어떤 공개 화면에도 노출되지 않는다.
//
// 지자체마다 컬럼명이 제각각이라(서울 25개 구를 실제로 받아본 결과) 후보 목록 중 매칭되는
// 첫 컬럼을 쓰는 방식으로 유연하게 처리한다. 인코딩도 UTF-8/CP949(EUC-KR)가 섞여 있어 자동 감지한다.
//
// 실행: node scripts/import-prospects-data-go-kr.js <csv파일경로> <region_sido> <region_sigungu> <source_url> [--dry-run]
// 예:   node scripts/import-prospects-data-go-kr.js /tmp/claude/junggu.csv 서울특별시 중구 "https://www.data.go.kr/data/3080385/fileData.do"

const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const iconv = (() => { try { return require('iconv-lite'); } catch { return null; } })();
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, serviceKey);

const DRY_RUN = process.argv.includes('--dry-run');
// 일부 지자체 파일은 "구분" 컬럼 자체가 없이 애초에 한 종교만 다룬다(예: "OO구_교회현황",
// "OO구_전통사찰 인허가정보"). 그런 파일은 --org-type-override로 전체 행에 고정 종교를 지정한다.
const overrideIdx = process.argv.indexOf('--org-type-override');
const orgTypeOverride = overrideIdx !== -1 ? process.argv[overrideIdx + 1] : null;
const args = process.argv.slice(2).filter((a, i, arr) => !a.startsWith('--') && arr[i - 1] !== '--org-type-override');
const [csvPath, regionSido, regionSigungu, sourceUrl] = args;

if (!csvPath || !regionSido || !regionSigungu) {
  console.error('사용법: node scripts/import-prospects-data-go-kr.js <csv파일경로> <region_sido> <region_sigungu> [source_url] [--dry-run] [--org-type-override church|catholic|buddhist|other]');
  process.exit(1);
}
if (orgTypeOverride && !['church', 'catholic', 'buddhist', 'other'].includes(orgTypeOverride)) {
  console.error('--org-type-override는 church/catholic/buddhist/other 중 하나여야 합니다');
  process.exit(1);
}

// 구분값(지자체마다 표기가 다름: 종교 카테고리 그대로 쓰기도, 시설 유형으로 쓰기도 함) →
// community_prospects.org_type(ORG_TYPES = church/catholic/buddhist/other)
const ORG_TYPE_MAP = {
  '개신교': 'church', '기독교': 'church', '교회': 'church', '기도원': 'church', '선교센터': 'church', '교당': 'church',
  '천주교': 'catholic', '가톨릭': 'catholic', '성당': 'catholic', '수도회': 'catholic',
  '불교': 'buddhist', '사찰': 'buddhist',
  '원불교': 'other', '유교': 'other', '기타': 'other', '기타종교시설': 'other', '증산교': 'other',
  '대순진리회': 'other', '국제창가학회': 'other', '천도교': 'other', '천부교': 'other', '통일교': 'other',
};

// server.js의 computeDedupKeyForProspect()와 완전히 동일한 로직 - 기존에 수기로 넣어둔
// 파일럿 3건(명동성당 등)과 정확히 같은 방식으로 중복판정되도록 절대 변형하지 않는다.
function computeDedupKey(orgType, name, address) {
  const normalize = (s) => String(s || '').replace(/\s+/g, '').trim();
  return `${orgType}_${normalize(name)}_${normalize(address).slice(0, 30)}`;
}

// 공공데이터포털 CSV는 필드 안에 콤마가 들어있는 경우(주소에 "2,3층" 등) 큰따옴표로 감싸져 있음 - 최소 CSV 파서
function parseCsvLine(line) {
  const cells = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; } else { inQuotes = false; }
      } else {
        cur += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      cells.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  cells.push(cur);
  return cells;
}

// UTF-8로 읽었을 때 깨짐(치환문자 다발)이 보이면 CP949(EUC-KR)로 재시도 - 지자체 파일 상당수가 CP949
function readCsvSmart(path) {
  const buf = fs.readFileSync(path);
  const utf8 = buf.toString('utf8');
  const replacementCount = (utf8.match(/�/g) || []).length;
  if (replacementCount === 0) return utf8.replace(/^﻿/, '');
  if (!iconv) {
    console.warn('경고: UTF-8 디코딩에 깨진 문자가 있는데 iconv-lite가 없어 CP949 재시도를 못 합니다. npm i iconv-lite 후 재실행하세요.');
    return utf8;
  }
  return iconv.decode(buf, 'cp949');
}

function findColumn(header, candidates) {
  for (const c of candidates) {
    const idx = header.findIndex(h => h.replace(/\s+/g, '') === c.replace(/\s+/g, ''));
    if (idx !== -1) return idx;
  }
  return -1;
}

async function main() {
  const raw = readCsvSmart(csvPath);
  const lines = raw.split(/\r?\n/).filter(l => l.trim().length > 0);
  const header = parseCsvLine(lines[0]).map(h => h.trim());
  const idx = {
    gubun: findColumn(header, ['구분', '종교구분', '구 분', '종교분류']),
    name: findColumn(header, ['시설명', '명칭', '기관명', '교회명', '교회명칭', '전통사찰명', '사업장명']),
    roadAddr: findColumn(header, ['도로명주소', '소재지(도로명 주소)', '소재지', '주소']),
    jibunAddr: findColumn(header, ['지번주소', '지번 주소']),
    phone: findColumn(header, ['전화번호', '대표번호', '연락처']),
    lat: findColumn(header, ['위도']),
    lng: findColumn(header, ['경도']),
    // "전통사찰 인허가정보" 같은 인허가 데이터는 지정취소(Y/N)된 건이 섞여있어 걸러내야 함
    cancelled: findColumn(header, ['지정취소']),
  };
  if (idx.name === -1) {
    console.error('CSV 헤더 형식이 예상과 다릅니다(시설명 계열 컬럼을 찾을 수 없음):', header);
    process.exit(1);
  }
  if (idx.gubun === -1 && !orgTypeOverride) {
    console.error('이 파일에는 "구분" 컬럼이 없습니다(한 종교만 다루는 파일로 보임). --org-type-override church|catholic|buddhist|other 를 지정해 다시 실행하세요. 헤더:', header);
    process.exit(1);
  }

  const rows = [];
  let skippedUnknownType = 0;
  let skippedCancelled = 0;
  const unknownTypeSamples = new Set();
  for (let i = 1; i < lines.length; i++) {
    const cells = parseCsvLine(lines[i]);
    const name = (cells[idx.name] || '').trim();
    if (!name) continue;
    if (idx.cancelled !== -1 && (cells[idx.cancelled] || '').trim() === 'Y') { skippedCancelled++; continue; }
    let orgType;
    if (orgTypeOverride) {
      orgType = orgTypeOverride;
    } else {
      const gubun = (cells[idx.gubun] || '').trim();
      orgType = ORG_TYPE_MAP[gubun];
      if (!orgType) { skippedUnknownType++; unknownTypeSamples.add(gubun); continue; }
    }
    const rawAddress = (cells[idx.roadAddr] || cells[idx.jibunAddr] || '').trim();
    // 지자체마다 시/도·시/군/구 접두어를 통째로 빼고 도로명만 적어둔 경우가 흔해서(예: 관악구는
    // "관악로10길 6"만 있음) 지역 필터링이 정확히 동작하도록 빠진 접두어를 보정해서 채운다.
    let address = rawAddress || null;
    if (address) {
      // "서울시"처럼 줄여쓴 표기도 이미 시/도가 있는 것으로 인정 - 안 그러면 "서울특별시 서울시 ..."처럼 중복됨
      const sidoAliasRe = regionSido === '서울특별시' ? /서울(특별시|시)/ : null;
      const hasSido = address.includes(regionSido) || (sidoAliasRe && sidoAliasRe.test(address));
      const hasSigungu = address.includes(regionSigungu);
      if (!hasSido && !hasSigungu) address = `${regionSido} ${regionSigungu} ${address}`;
      else if (!hasSido) address = `${regionSido} ${address}`;
      else if (!hasSigungu) address = address.replace(regionSido, `${regionSido} ${regionSigungu}`);
    }
    const phone = (cells[idx.phone] || '').trim() || null;
    const lat = idx.lat !== -1 && cells[idx.lat] ? Number(cells[idx.lat]) : null;
    const lng = idx.lng !== -1 && cells[idx.lng] ? Number(cells[idx.lng]) : null;
    rows.push({
      name,
      org_type: orgType,
      address,
      region_sido: regionSido,
      region_sigungu: regionSigungu,
      phone,
      latitude: Number.isFinite(lat) ? lat : null,
      longitude: Number.isFinite(lng) ? lng : null,
      source: 'data_go_kr',
      source_url: sourceUrl || null,
      dedup_key: computeDedupKey(orgType, name, address),
      status: 'prospect',
      admin_note: null,
    });
  }

  console.log(`CSV 파싱 완료: ${lines.length - 1}행 중 ${rows.length}건 적재 대상 (분류 불명 ${skippedUnknownType}건, 지정취소 ${skippedCancelled}건 제외${unknownTypeSamples.size ? ' - 불명 값: ' + [...unknownTypeSamples].join(',') : ''})`);
  const byType = rows.reduce((acc, r) => { acc[r.org_type] = (acc[r.org_type] || 0) + 1; return acc; }, {});
  console.log('종교별 분포:', byType);

  if (DRY_RUN) {
    console.log('\n--dry-run 모드 - DB에 반영하지 않고 상위 5건만 미리보기:');
    console.log(rows.slice(0, 5));
    return;
  }

  // 이미 있는 dedup_key와의 충돌은 upsert(ignoreDuplicates)로 조용히 스킵 - server.js의
  // bulk-import 엔드포인트와 완전히 동일한 정책(POST /api/admin/prospects/bulk-import 참고)
  const { data, error } = await supabase
    .from('community_prospects')
    .upsert(rows, { onConflict: 'dedup_key', ignoreDuplicates: true })
    .select('id');
  if (error) { console.error('DB 적재 오류:', error.message); process.exit(1); }

  const inserted = (data || []).length;
  console.log(`\n적재 완료: 신규 ${inserted}건, 중복 스킵 ${rows.length - inserted}건 (전체 요청 ${rows.length}건)`);
}

main().catch(err => { console.error('스크립트 실행 오류:', err); process.exit(1); });
