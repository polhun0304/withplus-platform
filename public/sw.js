// WITH+ 서비스워커 — PWA(홈 화면 설치, 오프라인 기본 지원)를 위한 최소 구현.
// 원칙: 가격/재고/주문처럼 정확성이 중요한 API(/api/*)는 절대 캐시하지 않고 항상 네트워크로만 처리한다.
// 정적 리소스(이미지/CSS/JS/아이콘)는 캐시 우선으로 빠르게, HTML 페이지는 네트워크 우선(항상 최신 시도) +
// 실패 시 캐시 → 그마저 없으면 오프라인 안내 페이지로 대체한다.

const CACHE_VERSION = 'v1';
const CACHE_NAME = `withplus-${CACHE_VERSION}`;
const OFFLINE_URL = '/offline.html';

const PRECACHE_URLS = [
  OFFLINE_URL,
  '/manifest.json',
  '/images/icons/icon-192.png',
  '/images/icons/icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

function isApiRequest(url) {
  return url.pathname.startsWith('/api/');
}

function isStaticAsset(request, url) {
  return request.destination === 'image'
    || request.destination === 'style'
    || request.destination === 'script'
    || request.destination === 'font'
    || /\.(png|jpg|jpeg|gif|svg|webp|css|js|woff2?|ttf)$/i.test(url.pathname);
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return; // 쓰기 요청(POST/PATCH/DELETE 등)은 절대 가로채지 않음

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return; // 외부 요청(CDN 등)은 브라우저 기본 동작에 맡김

  // API는 항상 네트워크로만 — 캐시된 가격/재고/주문 데이터를 보여주는 것은 절대 안 됨
  if (isApiRequest(url)) return;

  // HTML 네비게이션 요청: 네트워크 우선, 실패 시 캐시 → 그마저 없으면 오프라인 페이지
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          return response;
        })
        .catch(() => caches.match(request).then((cached) => cached || caches.match(OFFLINE_URL)))
    );
    return;
  }

  // 정적 리소스: 캐시 우선(빠른 응답), 백그라운드에서 갱신
  if (isStaticAsset(request, url)) {
    event.respondWith(
      caches.match(request).then((cached) => {
        const fetchPromise = fetch(request).then((response) => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          return response;
        }).catch(() => cached);
        return cached || fetchPromise;
      })
    );
  }
});
