const CACHE_NAME = "livenet-v3";

const APP_SHELL = [
  "/",
  "/index.html",
  "/manifest.json"
];

// Установка Service Worker
self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

// Активация
self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

// Обработка запросов
self.addEventListener("fetch", event => {
  const request = event.request;

  // Не трогаем POST и другие не-GET запросы
  if (request.method !== "GET") {
    return;
  }

  const url = new URL(request.url);

  // API и авторизацию не кэшируем
  if (
    url.pathname.startsWith("/api/") ||
    url.pathname.startsWith("/auth/")
  ) {
    return;
  }

  // Сначала пытаемся получить свежую версию из интернета.
  // Если интернета нет — используем кэш.
  event.respondWith(
    fetch(request)
      .then(response => {
        const responseCopy = response.clone();

        caches.open(CACHE_NAME)
          .then(cache => {
            cache.put(request, responseCopy);
          });

        return response;
      })
      .catch(() => {
        return caches.match(request);
      })
  );
});
