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

define(['require', 'module', './lcp_handler', 'cryptoJs/sha1'], function (require, module, LcpHandler, CryptoJS_SHA1) {

    var EncryptionHandler = function (encryptionData, onError) {
        var self = this;

        var LCP_RETRIEVAL_KEY = 'license.lcpl#/encryption/content_key';

        var lcpHandler = encryptionData.infos && isLcpEncryptionSpecified() ? new LcpHandler(encryptionData.infos, onError) : false;

        var ENCRYPTION_METHODS = {
            'http://www.idpf.org/2008/embedding': embeddedFontDeobfuscateIdpf,
            'http://ns.adobe.com/pdf/enc#RC': embeddedFontDeobfuscateAdobe,
            'http://www.w3.org/2001/04/xmlenc#aes256-cbc': lcpHandler ? lcpHandler.decryptContent : undefined
        };


        // INTERNAL FUNCTIONS

        function blob2BinArray(blob, callback) {
            var fileReader = new FileReader();
            fileReader.onload = function () {
                var arrayBuffer = this.result;
                callback(new Uint8Array(arrayBuffer));
            };
            fileReader.readAsArrayBuffer(blob);
        }

        function xorObfuscatedBlob(obfuscatedResourceBlob, prefixLength, xorKey, callback) {
            var obfuscatedPrefixBlob = obfuscatedResourceBlob.slice(0, prefixLength);
            blob2BinArray(obfuscatedPrefixBlob, function (bytes) {
                var masklen = xorKey.length;
                for (var i = 0; i < prefixLength; i++) {
                    bytes[i] = bytes[i] ^ (xorKey[i % masklen]);
                }
                var deobfuscatedPrefixBlob = new Blob([bytes], { type: obfuscatedResourceBlob.type });
                var remainderBlob = obfuscatedResourceBlob.slice(prefixLength);
                var deobfuscatedBlob = new Blob([deobfuscatedPrefixBlob, remainderBlob],
                    { type: obfuscatedResourceBlob.type });

                callback(deobfuscatedBlob);
            });
        }

        function embeddedFontDeobfuscateIdpf(obfuscatedResourceBlob, callback) {

            var prefixLength = 1040;
            // Shamelessly copied from
            // https://github.com/readium/readium-chrome-extension/blob/26d4b0cafd254cfa93bf7f6225887b83052642e0/scripts/models/path_resolver.js#L102 :

            xorObfuscatedBlob(obfuscatedResourceBlob, prefixLength, encryptionData.uidHash, callback);
        }

        function urnUuidToByteArray(id) {
            var uuidRegexp = /(urn:uuid:)?([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})/i;
            var matchResults = uuidRegexp.exec(id);
            var rawUuid = matchResults[2] + matchResults[3] + matchResults[4] + matchResults[5] + matchResults[6];
            if (!rawUuid || rawUuid.length != 32) {
                console.error('Bad UUID format for ID :' + id);
            }
            var byteArray = [];
            for (var i = 0; i < 16; i++) {
                var byteHex = rawUuid.substr(i * 2, 2);
                var byteNumber = parseInt(byteHex, 16);
                byteArray.push(byteNumber);
            }
            return byteArray;
        }

        function embeddedFontDeobfuscateAdobe(obfuscatedResourceBlob, callback) {

            // extract the UUID and convert to big-endian binary form (16 bytes):
            var uidWordArray = urnUuidToByteArray(encryptionData.uid);
            var prefixLength = 1024;

            xorObfuscatedBlob(obfuscatedResourceBlob, prefixLength, uidWordArray, callback)
        }

        function isLcpEncryptionSpecified() {
            if (self.isLcpEncryption === undefined) {
                self.isLcpEncryption = encryptionData && encryptionData.retrievalKeys && Object.keys(encryptionData.retrievalKeys).some(function (uri) {
                    return encryptionData.retrievalKeys[uri] === LCP_RETRIEVAL_KEY;
                });
            }
            return self.isLcpEncryption;
        }

        // PUBLIC API

        this.isLcpEncryptionSpecified = isLcpEncryptionSpecified;

        this.isEncryptionSpecified = function () {
            return encryptionData && encryptionData.encryptions;
        };

        this.getEncryptionMethodForRelativePath = function (pathRelativeToRoot) {
            if (self.isEncryptionSpecified()) {
                return encryptionData.encryptions[pathRelativeToRoot];
            } else {
                return undefined;
            }
        };

        this.getDecryptionFunctionForRelativePath = function (pathRelativeToRoot) {

            var encryptionMethod = self.getEncryptionMethodForRelativePath(pathRelativeToRoot);

            //console.debug(pathRelativeToRoot + " -- " + encryptionMethod + " ... " + typeof ENCRYPTION_METHODS[encryptionMethod]);

            if (encryptionMethod && ENCRYPTION_METHODS[encryptionMethod]) {
                return ENCRYPTION_METHODS[encryptionMethod];
            } else {
                return undefined;
            }
        };

        this.checkLicense = function (license, callback, error) {
            if (lcpHandler && this.isLcpEncryption) {
                lcpHandler.checkLicense(license, callback, error);
            } else {
                error("no handler available for this license");
            }
        };
    };

    EncryptionHandler.CreateEncryptionData =  function(id, encryptionDom, encryptionInfos) {

        var txt = unescape(encodeURIComponent(id.trim()));
        var sha = CryptoJS_SHA1(txt);

        //console.debug(sha.toString(CryptoJS.enc.Hex));

        var byteArray = [];

        for (var i = 0; i < sha.sigBytes; i++) {
            byteArray.push((sha.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
        }

        // for (var i = 0; i < sha.words.length; ++i) {
        //     for (var j = 3; j >= 0; --j) {
        //         byteArray.push((sha.words[i] >> 8 * j) & 0xFF);
        //     }
        // }

        var encryptionData = {
            uid: id,
            uidHash: byteArray,
            encryptions: undefined,
            infos: encryptionInfos
        };

        var encryptedData = $(encryptionDom).find("enc\\:EncryptedData, EncryptedData");
        encryptedData.each(function (index, encryptedData) {
          var data = $(encryptedData);
          var encryptionAlgorithm = data.find("enc\\:EncryptionMethod, EncryptionMethod").first().attr('Algorithm');

          var retrievalMethod = false;
          var retrievalMethods = $('RetrievalMethod', encryptedData);
          if (retrievalMethods.length > 0) {
            retrievalMethod = retrievalMethods.first().attr('URI');
          }

          // For some reason, jQuery selector "" against XML DOM sometimes doesn't match properly
          var cipherReference = data.find("enc\\:CipherReference, CipherReference");
          cipherReference.each(function (index, CipherReference) {

            //var cipherReferenceURI = "/" + $(CipherReference).attr('URI');
            var cipherReferenceURI = $(CipherReference).attr('URI');

            console.log('Encryption/obfuscation algorithm ' + encryptionAlgorithm + ' specified for ' + cipherReferenceURI);

            if (!encryptionData.retrievalKeys) {
              encryptionData.retrievalKeys = {};
            }

            if (!encryptionData.encryptions) {
              encryptionData.encryptions = {};
            }

            encryptionData.encryptions[cipherReferenceURI] = encryptionAlgorithm;
            encryptionData.retrievalKeys[cipherReferenceURI] = retrievalMethod;
          });
        });

        return encryptionData;
    };

    return EncryptionHandler;
});
