/*global define, ReadiumSDK, window*/

//  Copyright (c) 2014 Readium Foundation and/or its licensees. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification,
//  are permitted provided that the following conditions are met:
//  1. Redistributions of source code must retain the above copyright notice, this
//  list of conditions and the following disclaimer.
//  2. Redistributions in binary form must reproduce the above copyright notice,
//  this list of conditions and the following disclaimer in the documentation and/or
//  other materials provided with the distribution.
//  3. Neither the name of the organization nor the names of its contributors may be
//  used to endorse or promote products derived from this software without specific
//  prior written permission.

define(function () {
  "use strict";

  var srcObserver, iframe, spineItem, currentPublicationFetcher,
    blobUrlTest = /^blob/;

  /**
   * Init mutation observer
   * Test if new src is not a blob URL
   * Then requests a new blob url
   */
  var createObserver = function () {
    srcObserver = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        var newSrc = mutation.target.getAttribute('src');
        if (blobUrlTest.test(mutation.oldValue) && !blobUrlTest.test(newSrc)) {
          srcObserver.disconnect();
          getBlobUrl({
            id: mutation.target.id,
            url: newSrc
          }, setBlobUrl);
        }
      });
    });
  };

  /**
   * Start dom observation on src attribute
   */
  var startSrcObserve = function () {
    srcObserver.observe(iframe.document.body, {
      attributeFilter: [ 'src' ],
      attributeOldValue: true,
      attributes: true,
      subtree: true
    });
  };

  /**
   * Generate a blob URL for a resource
   *
   * @param event
   */
  var getBlobUrl = function (data, callback) {
    var resourceUriRelativeToPackageDocument = (new URI(data.url)).absoluteTo(spineItem.href).toString();
    currentPublicationFetcher.relativeToPackageFetchFileContents(resourceUriRelativeToPackageDocument, "blob", function (blob) {
      callback({
        id: data.id,
        url: window.URL.createObjectURL(blob)
      });
    }, function (e) {
      console.error(e);
    });
  };

  /**
   * Set the blob URL to the dom element
   */
  var setBlobUrl = function (data) {
    iframe.document.querySelector('#' + data.id).setAttribute('src', data.url);
    startSrcObserve();
  };

  /**
   * Constructor
   *
   * @param reader
   */
  var dynamicResourceLoader = function (reader, publicationFetcher) {

    this.initialize = function () {
      reader.on(ReadiumSDK.Events.CONTENT_DOCUMENT_LOADED, function (iframes) {
        iframe = iframes[0].contentWindow;
        startSrcObserve();
      });

      reader.on(ReadiumSDK.Events.PAGINATION_CHANGED, function (pageInfo) {
        spineItem = pageInfo.spineItem;
      });

      currentPublicationFetcher = publicationFetcher;

      createObserver();
    };
  };

  return dynamicResourceLoader;
});
