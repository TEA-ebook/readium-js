var config = {
  version: 'ninja-7',
  epubPattern: /\w\.epub\/(.*)$/
};

var mimeTypeMap = {
  default: 'application/octet-stream',
  css: 'text/css',
  epub: 'application/epub+zip',
  gif: 'image/gif',
  htm: 'text/html',
  html: 'text/html',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  mp3: 'audio/mpeg',
  ncx: 'application/x-dtbncx+xml',
  opf: 'application/oebps-package+xml',
  png: 'image/png',
  svg: 'image/svg+xml',
  xhtml: 'application/xhtml+xml'
};

self.addEventListener('message', function (event) {
  self.epub = event.data;
});

self.addEventListener('install', function(event) {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', function(event) {
  function onActivate(version) {
    return caches.keys()
      .then(function(cacheKeys) {
        const oldCacheKeys = cacheKeys.filter(function(key) { return key.indexOf(version) !== 0; });
        const deletePromises = oldCacheKeys.map(function(oldKey) { return caches.delete(oldKey); });
        return Promise.all(deletePromises);
      });
  }

  event.waitUntil(onActivate(config.version).then(function() {
    return self.clients.claim();
  }));
});

self.addEventListener('fetch', function (event) {
  function shouldHandleFetch(event, opts) {
    var request = event.request;
    var url = new URL(request.url);
    var criteria = {
      matchesPathPattern: opts.epubPattern.test(url.pathname),
      isGETRequest: request.method === 'GET',
      isFromMyOrigin: url.origin === self.location.origin
    };
    var failingCriteria = Object.keys(criteria).filter(function (criteriaKey) {
      return !criteria[criteriaKey];
    });
    return !failingCriteria.length;
  }

  function onFetch(event) {
    var request = event.request;
    var epubFileMatch = request.url.match(/(.*\.epub)\/(.*)$/);
    if (epubFileMatch && epubFileMatch.length > 2) {
      var epubUrl = epubFileMatch[1];
      var filePath = epubFileMatch[2];
      event.respondWith(
        fetchFromCache(request)
          .catch(function() { return getFileInEpub(epubUrl, filePath); })
          .then(function(response) { return addToCache(config.version, request, response); })
          .catch(notFoundResponse())
      );
    }
  }

  if (shouldHandleFetch(event, config)) {
    onFetch(event, config);
  }
});

function addToCache(cacheKey, request, response) {
  if (response.ok) {
    const copy = response.clone();
    caches.open(cacheKey).then(function(cache) {
      cache.put(request, copy);
    });
  }
  return response;
}

function fetchFromCache(request) {
  return caches.match(request).then(function(response) {
    if (!response) {
      return Promise.reject();
    }
    return response;
  });
}

function notFoundResponse(error) {
  return new Response(error, { status: 404 });
}

function getZipResponse(mimeType, arrayBuffer) {
  var init = {
    status: 200,
    statusText: 'OK',
    headers: {
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'public',
      'Content-Type': mimeType,
      'Content-Length': arrayBuffer.byteLength
    }
  };
  return new Response(new Blob([arrayBuffer], { type: mimeType }), init);
}

function getEpubBlob(epubUrl) {
  if (self.epub instanceof Blob) {
    return Promise.resolve(self.epub);
  }
  return fetch(epubUrl).then(function (response) {
    return response.blob();
  });
}

function getFileInEpub(epubUrl, filePath) {
  return getEpubBlob(epubUrl)
    .then(function (blob) {
      return JSZip.loadAsync(blob);
    })
    .then(function (zip) {
      var zipFile = zip.file(filePath);
      if (!zipFile) {
        throw new Error(filePath + ' not found in zip file');
      }
      return zipFile.async('arraybuffer');
    })
    .then(function(data) { return getZipResponse(getMimeTypeFromFileExtension(filePath), data); })
    .catch(function(error) { return new Response(error, { status: 404 }); });
}

function getMimeTypeFromFileExtension(filePath) {
  var fileExtMatch = filePath.match(/\.(\w*)$/);
  if (fileExtMatch && fileExtMatch.length > 1) {
    return mimeTypeMap[fileExtMatch[1]] || mimeTypeMap.default;
  }
  return mimeTypeMap.default;
}
