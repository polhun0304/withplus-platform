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
// CSV 컬럼(공공데이터포털 표준 포맷): 번호,구분,시설명,도로명주소,지번주소,전화번호,데이터기준일자
//
// 실행: node scripts/import-prospects-data-go-kr.js <csv파일경로> <region_sido> <region_sigungu> <source_url> [--dry-run]
// 예:   node scripts/import-prospects-data-go-kr.js /tmp/claude/junggu.csv 서울특별시 중구 "https://www.data.go.kr/data/3080385/fileData.do"

const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, serviceKey);

const DRY_RUN = process.argv.includes('--dry-run');
const args = process.argv.slice(2).filter(a => !a.startsWith('--'));
const [csvPath, regionSido, regionSigungu, sourceUrl] = args;

if (!csvPath || !regionSido || !regionSigungu) {
  console.error('사용법: node scripts/import-prospects-data-go-kr.js <csv파일경로> <region_sido> <region_sigungu> [source_url] [--dry-run]');
  process.exit(1);
}

// 구분(공공데이터포털 원본 분류) → community_prospects.org_type(ORG_TYPES = church/catholic/buddhist/other)
const ORG_TYPE_MAP = {
  '개신교': 'church',
  '기독교': 'church',
  '천주교': 'catholic',
  '가톨릭': 'catholic',
  '불교': 'buddhist',
  '원불교': 'other',
  '유교': 'other',
  '기타': 'other',
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

async function main() {
  const raw = fs.readFileSync(csvPath, 'utf8').replace(/^﻿/, ''); // BOM 제거
  const lines = raw.split(/\r?\n/).filter(l => l.trim().length > 0);
  const header = parseCsvLine(lines[0]).map(h => h.trim());
  const idx = {
    gubun: header.indexOf('구분'),
    name: header.indexOf('시설명'),
    roadAddr: header.indexOf('도로명주소'),
    jibunAddr: header.indexOf('지번주소'),
    phone: header.indexOf('전화번호'),
  };
  if (idx.gubun === -1 || idx.name === -1) {
    console.error('CSV 헤더 형식이 예상과 다릅니다(구분/시설명 컬럼을 찾을 수 없음):', header);
    process.exit(1);
  }

  const rows = [];
  let skippedUnknownType = 0;
  for (let i = 1; i < lines.length; i++) {
    const cells = parseCsvLine(lines[i]);
    const gubun = (cells[idx.gubun] || '').trim();
    const name = (cells[idx.name] || '').trim();
    if (!name) continue;
    const orgType = ORG_TYPE_MAP[gubun];
    if (!orgType) { skippedUnknownType++; continue; }
    const address = (cells[idx.roadAddr] || cells[idx.jibunAddr] || '').trim() || null;
    const phone = (cells[idx.phone] || '').trim() || null;
    rows.push({
      name,
      org_type: orgType,
      address,
      region_sido: regionSido,
      region_sigungu: regionSigungu,
      phone,
      latitude: null,
      longitude: null,
      source: 'data_go_kr',
      source_url: sourceUrl || null,
      dedup_key: computeDedupKey(orgType, name, address),
      status: 'prospect',
      admin_note: null,
    });
  }

  console.log(`CSV 파싱 완료: ${lines.length - 1}행 중 ${rows.length}건 적재 대상 (분류 불명 ${skippedUnknownType}건 제외)`);
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
