// WITH+ 서비스워커 — PWA(홈 화면 설치, 오프라인 기본 지원)를 위한 최소 구현.
// 원칙: 가격/재고/주문처럼 정확성이 중요한 API(/api/*)는 절대 캐시하지 않고 항상 네트워크로만 처리한다.
// 정적 리소스(이미지/CSS/JS/아이콘)는 캐시 우선으로 빠르게, HTML 페이지는 네트워크 우선(캐시하지 않음),
// 실패 시 오프라인 안내 페이지로 대체한다.

const CACHE_VERSION = 'v7'; // 설치형 앱(PWA) 표준 v1: 페이지(HTML) 캐시 중단·/auth 제외 — 옛 페이지 캐시 정리
const CACHE_NAME = `withplus-${CACHE_VERSION}`;
const OFFLINE_URL = '/offline.html';

const PRECACHE_URLS = [
  OFFLINE_URL,
  '/manifest.json',
  '/images/icons/icon-192.png',
  '/images/icons/icon-512.png',
  '/pwa-install.js'
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

// 설치형 앱(PWA) 표준 v1: 데이터·인증 경로는 절대 가로채지 않는다(/api·/auth)
function isApiRequest(url) {
  return /^\/(api|auth)(\/|$)/.test(url.pathname);
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

  // HTML 네비게이션 요청: 항상 네트워크 우선, 끊기면 오프라인 안내 페이지.
  // (설치형 앱(PWA) 표준 v1) 페이지는 캐시하지 않는다 — 로그인 사용자 화면이 기기에 남거나 옛 화면이 보이는 일을 막는다.
  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).catch(() => caches.match(OFFLINE_URL)));
    return;
  }

  // 스크립트/스타일: 네트워크 우선(실패 시 캐시) — 배포 직후 재방문자가 옛 공통 JS로 화면이 깨져 보이던 문제 방지.
  // (캐시 우선이면 새 버전 배포 후 첫 방문 1회는 항상 예전 스크립트가 실행된다)
  if (request.destination === 'script' || request.destination === 'style' || /\.(js|css)$/i.test(url.pathname)) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          return response;
        })
        .catch(() => caches.match(request))
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

// 📣 푸시 알림 수신 — 서버가 보낸 제목/내용을 알림으로 띄우고, 누르면 해당 화면을 연다
self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) { data = { title: 'WITH+', body: event.data ? event.data.text() : '' }; }
  const title = data.title || 'WITH+';
  event.waitUntil(self.registration.showNotification(title, {
    body: data.body || '',
    icon: '/images/icons/icon-192.png',
    badge: '/images/icons/icon-192.png',
    tag: data.tag || undefined,
    data: { url: data.url || '/' }
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if (c.url && new URL(c.url).origin === self.location.origin && 'focus' in c) { c.navigate(target); return c.focus(); }
      }
      return self.clients.openWindow(target);
    })
  );
});
