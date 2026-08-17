// 이카운트(ERP) 품목등록 데이터를 WITH+ 플랫폼의 products_with 테이블로 일괄 가져오는 스크립트.
//
// 원본: 이카운트 "품목등록" 화면 Excel 내보내기 (829개 실제 판매 품목, 전량 ㈜위더스 자사 재고).
// 처리 방식(형님 확인 사항):
//  - 재고(stock)는 0으로 등록한다. 이카운트 "재고현황" 리포트에 입고 이력이 전혀 없어(등록된 데이터 없음),
//    실제 보유 수량을 알 수 없기 때문에 임의의 추정치를 넣지 않고 정직하게 0으로 시작한다.
//  - 상품 사진이 전혀 없으므로, 사진/설명이 준비되기 전까지 고객에게 노출되지 않도록
//    status를 'inactive'로 등록한다 (관리자만 상품관리 화면에서 확인 가능, 고객 화면 상품목록/상세는 status='active'만 조회하므로 자동으로 숨겨짐).
//  - 카테고리 매핑: 건강→health, 잡화→lifestyle, 뷰티→cosmetics, 패션→fashion, 간식→snack(신규 추가된 카테고리)
//  - 공급가액/부가세는 판매가(제품단가, 부가세 포함가로 간주)를 표준 10%로 역산해 자동 채운다.
//  - 이카운트의 "창고위치/제품위치" 텍스트는 실제 랙/빈 좌표가 없어 WMS 디지털트윈 로케이션으로 정밀 매핑할 수 없으므로,
//    상품 설명 하단에 참고용 메모로 남겨 관리자가 나중에 실사 후 정확한 로케이션을 배정할 수 있게 한다.
//
// 실행: node scripts/import-ecount-products.js           (실제 반영)
//       node scripts/import-ecount-products.js --dry-run  (반영 없이 미리보기만)

const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, serviceKey);

const DRY_RUN = process.argv.includes('--dry-run');

function slugify(name, suffix) {
  const base = String(name)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9가-힣\s-]/g, '')
    .replace(/\s+/g, '-')
    .slice(0, 60);
  return `${base || 'product'}-${suffix}`;
}

function computeVatSplit(price) {
  const p = Number(price) || 0;
  const supply = Math.round(p / 1.1);
  return { supply_amount: supply, vat_amount: p - supply };
}

async function main() {
  const dataPath = path.join(__dirname, 'ecount-import-data.json');
  const items = JSON.parse(fs.readFileSync(dataPath, 'utf-8'));
  console.log(`총 ${items.length}개 품목 로드 완료${DRY_RUN ? ' (DRY RUN - DB 반영 없음)' : ''}`);

  const results = { created: 0, skipped_duplicate_barcode: 0, failed: [] };

  // 이미 같은 barcode(품목코드)로 등록된 상품은 건너뛴다 (재실행 시 중복 방지)
  const { data: existing, error: existingErr } = await supabase.from('products_with').select('barcode').not('barcode', 'is', null);
  if (existingErr) throw existingErr;
  const existingBarcodes = new Set((existing || []).map(r => r.barcode));

  let idx = 0;
  for (const item of items) {
    idx++;
    if (existingBarcodes.has(item.barcode)) {
      results.skipped_duplicate_barcode++;
      continue;
    }
    const vatSplit = computeVatSplit(item.price);
    const locationNote = (item.warehouse_code || item.location_note)
      ? `\n\n[이카운트 창고정보 - 참고용] 창고: ${item.warehouse_code || '-'} / 위치: ${item.location_note || '-'}${item.detail_location ? ' / 상세: ' + item.detail_location : ''}`
      : '';
    const record = {
      name: item.name,
      slug: slugify(item.name, item.barcode.toLowerCase()),
      description: `이카운트 ERP에서 이전된 상품입니다. 상품 사진/상세설명 등록 후 판매를 시작해주세요.${locationNote}`,
      long_description: '',
      price: item.price,
      discount_price: null,
      category: item.category,
      stock: 0,
      barcode: item.barcode,
      expiry_date: item.expiry_date,
      spec: null,
      supply_amount: vatSplit.supply_amount,
      vat_amount: vatSplit.vat_amount,
      images_urls: [],
      detail_sections: [],
      supplier_id: null, // 자체재고 - 외부 공급사 없음
      vendor_id: null,
      subscription_available: false,
      status: 'inactive' // 비공개(검토용) - 형님 확인 사항
    };

    if (DRY_RUN) {
      results.created++;
      if (idx <= 5) console.log('DRY RUN 샘플:', record.name, record.barcode, record.category, record.price);
      continue;
    }

    const { error } = await supabase.from('products_with').insert([record]);
    if (error) {
      results.failed.push({ barcode: item.barcode, name: item.name, error: error.message });
    } else {
      results.created++;
    }
    if (idx % 100 === 0) console.log(`진행: ${idx}/${items.length}`);
  }

  console.log('\n=== 결과 ===');
  console.log('생성:', results.created);
  console.log('중복 건너뜀(이미 등록된 barcode):', results.skipped_duplicate_barcode);
  console.log('실패:', results.failed.length);
  if (results.failed.length) console.log(JSON.stringify(results.failed.slice(0, 20), null, 2));
}

main().then(() => process.exit(0)).catch(err => {
  console.error('가져오기 실패:', err);
  process.exit(1);
});
