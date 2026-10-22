# WITH+ 앱 스토어 출시 안내 (형님이 직접 하실 일)

WITH+ 는 이미 **설치형 앱(PWA)** 입니다. 지금도 고객은 아래처럼 "앱"으로 쓸 수 있습니다.

| 고객 환경 | 설치 방법 (사이트가 자동 안내) |
|---|---|
| 안드로이드 크롬·삼성 인터넷, PC 크롬·엣지 | 메뉴 **📱 앱 설치** → 브라우저 설치 창 → "설치" |
| 아이폰·아이패드 사파리 | 메뉴 **📱 앱 설치** → 공유 버튼 → "홈 화면에 추가" 그림 안내 |
| 카카오톡·네이버·인스타그램 앱 안 | "다른 브라우저로 열기" 안내 + 주소 복사 |

"앱 설치" 버튼 위치: 왼쪽 위 ☰ 메뉴(맨 위), PC 홈 상단 링크, 마이페이지 카드. 앱으로 실행 중이면 자동으로 숨겨집니다.

아래는 **구글 Play 스토어에 정식 앱으로 올리는 방법**입니다. 앱 껍데기(TWA, Trusted Web Activity)가 사이트를 그대로 띄우는 방식이라, **사이트를 고치면 앱도 자동으로 바뀝니다**(앱 재심사 불필요).

---

## 1단계 — 구글 Play 개발자 계정 만들기 (1회, $25)

1. https://play.google.com/console 접속 → 회사 구글 계정으로 로그인
2. 계정 유형 **"조직"** 선택(사업자 명의 권장) → D-U-N-S 번호 필요(없으면 무료 발급, 1~2주)
3. 등록비 **$25** 1회 결제 → 본인 확인(신분증) 완료까지 며칠 걸릴 수 있음

> 개인 계정으로 새로 만들면 "테스터 12명 × 14일 비공개 테스트"를 거쳐야 출시할 수 있습니다. 조직 계정은 이 조건이 없습니다.

## 2단계 — 안드로이드 앱 파일 만들기 (PWABuilder, 코딩 없이 10분)

1. https://www.pwabuilder.com 접속 → 운영 주소(예: `https://사이트주소`) 입력 → **Start**
2. 점수 화면에서 **Package For Stores → Android → Generate Package**
3. 옵션 입력
   - **Package ID**: `kr.withplus.app` (한 번 정하면 영구히 못 바꿈 — 원하는 이름으로 확정)
   - **App name**: `WITH+` / **Launcher name**: `WITH+`
   - **Theme color** `#D32F5B`, **Background** `#FFFFFF`, **Start URL** `/?pwa=1`
   - **Signing key**: "Create new" (새 서명키 생성)
4. 내려받은 zip 안의 파일을 **안전한 곳 2군데 이상**에 보관
   - `app-release-bundle.aab` → Play 스토어에 올릴 파일
   - `signing.keystore` + `signing-key-info.txt`(비밀번호) → **잃어버리면 앱 업데이트 불가**. 절대 저장소(GitHub)에 올리지 마세요.
   - `assetlinks.json` → 3단계에서 지문 확인용

> 개발자가 직접 하려면 Bubblewrap(구글 공식 CLI)도 같은 결과물을 만듭니다:
> `npm i -g @bubblewrap/cli` → `bubblewrap init --manifest https://사이트주소/manifest.webmanifest` → `bubblewrap build`

## 3단계 — 사이트와 앱 연결 (주소창 없는 진짜 앱 화면)

연결이 안 되면 앱 위쪽에 주소창이 보입니다. 서버 환경변수 2개만 넣으면 됩니다(Render 대시보드 → Environment).

```
TWA_PACKAGE_NAME=kr.withplus.app
TWA_SHA256_FINGERPRINTS=지문1,지문2
```

- **지문1**: PWABuilder 의 `assetlinks.json` 안 `sha256_cert_fingerprints` 값(업로드 키)
- **지문2**: Play Console → 앱 → **설정 › 앱 무결성 › 앱 서명** 의 "앱 서명 키 인증서 SHA-256" (구글이 다시 서명하므로 반드시 추가)
- 형식: `AB:CD:...` (콜론으로 구분된 32쌍)

저장 후 재배포 → 브라우저에서 `https://사이트주소/.well-known/assetlinks.json` 을 열어 값이 보이면 성공입니다. (환경변수가 비어 있으면 `[]` 가 보이는 게 정상)

## 4단계 — Play Console 에 앱 등록 → 내부 테스트 → 출시

1. Play Console → **앱 만들기**: 이름 `WITH+`, 기본 언어 한국어, 앱(게임 아님), 무료
2. **스토어 등록정보**: 짧은 설명(80자), 자세한 설명, 아이콘 512×512(`public/images/icons/icon-512.png`), 그래픽 이미지 1024×500, 휴대폰 스크린샷 2장 이상
3. **앱 콘텐츠** 설문: 개인정보처리방침 URL(`https://사이트주소/privacy`), 광고 포함 여부, 데이터 보안(이메일·이름·주소·결제 정보 수집 표시), 콘텐츠 등급, 타깃 연령(성인)
4. **테스트 › 내부 테스트** → 새 버전 → `app-release-bundle.aab` 업로드 → 테스터(본인 이메일) 추가 → 휴대폰에 설치해 확인
   - 주소창이 보이면 3단계 지문2가 빠진 것 → 추가 후 재배포
   - 로그인·장바구니·결제(카드/간편결제 창)·알림이 정상인지 확인
5. 문제 없으면 **프로덕션 › 새 버전 만들기** → 같은 aab 로 출시 검토 제출 → 보통 1~7일 심사

## 아이폰(App Store) 참고

- 애플은 "웹사이트를 감싸기만 한 앱"을 자주 반려합니다(심사 지침 4.2). 그래서 **지금은 사파리 "홈 화면에 추가"(사이트가 그림으로 안내)** 가 가장 현실적입니다. iOS 16.4 이상은 홈 화면 앱에서 푸시 알림도 됩니다.
- 그래도 올리려면: Apple Developer Program **연 $99** 가입 → PWABuilder 의 **iOS 패키지** 생성 → Mac + Xcode 에서 빌드 → App Store Connect 제출. 앱 전용 기능(푸시, 바코드 스캔 등)을 넣어야 통과 가능성이 높습니다.
- 앱 안에서 디지털 상품(멤버십 등)을 팔면 인앱결제 수수료 규정이 적용됩니다. 실물 상품 판매는 해당 없음.

## 체크리스트

- [ ] Play 개발자 계정($25) 승인
- [ ] Package ID 확정 (`kr.withplus.app` 권장)
- [ ] 서명키(`signing.keystore`) + 비밀번호 안전 보관 2곳
- [ ] 환경변수 `TWA_PACKAGE_NAME`, `TWA_SHA256_FINGERPRINTS` 입력·재배포
- [ ] `/.well-known/assetlinks.json` 확인
- [ ] 내부 테스트 설치 확인(주소창 안 보임) → 프로덕션 출시
