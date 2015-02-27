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

define(['require', 'module', './lcp_handler', 'cryptoJs'], function (require, module, LcpHandler) {

    var EncryptionHandler = function (encryptionData) {
        var self = this;

        var lcpHandler = encryptionData.userKey ? new LcpHandler(encryptionData.userKey, encryptionData.encryptions) : false;

        var ENCRYPTION_METHODS = {
            'http://www.idpf.org/2008/embedding': embeddedFontDeobfuscateIdpf,
            'http://ns.adobe.com/pdf/enc#RC': embeddedFontDeobfuscateAdobe,
            'http://www.w3.org/2001/04/xmlenc#aes256-cbc': lcpHandler ? lcpHandler.decryptContent : undefined
        };

        var LCP_RETRIEVAL_KEY = 'license.lcpl#/encryption/content_key';

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


        // PUBLIC API

        this.isEncryptionSpecified = function () {
            return encryptionData && encryptionData.encryptions;
        };

        this.isLcpEncryptionSpecified = function () {
            if(this.isLcpEncryption === undefined) {
                this.isLcpEncryption = encryptionData && encryptionData.retrievalKeys && Object.keys(encryptionData.retrievalKeys).every(function (uri) {
                    return encryptionData.retrievalKeys[uri] === LCP_RETRIEVAL_KEY;
                });
            }
            return this.isLcpEncryption;
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
            if (encryptionMethod && ENCRYPTION_METHODS[encryptionMethod]) {
                return ENCRYPTION_METHODS[encryptionMethod];
            } else {
                return undefined;
            }
        };

        this.checkLicence = function (licence, callback, error) {
            if (lcpHandler && this.isLcpEncryption) {
                lcpHandler.checkLicence(licence, callback, error);
            } else {
                error("no handler available for this licence");
            }
        };
    };

    EncryptionHandler.CreateEncryptionData = function (id, encryptionDom, userKey) {

        var encryptionData = {
            uid: id,
            userKey: userKey,
            uidHash: window.Crypto.SHA1(unescape(encodeURIComponent(id.trim())), { asBytes: true }),
            encryptions: undefined
        };

        var encryptedData = $('EncryptedData', encryptionDom);
        encryptedData.each(function (index, encryptedData) {
            var encryptionAlgorithm = $('EncryptionMethod', encryptedData).first().attr('Algorithm');

            var retrievalMethod = false;
            var retrievalMethods = $('RetrievalMethod', encryptedData);
            if (retrievalMethods.length > 0) {
                retrievalMethod = retrievalMethods.first().attr('URI');
            }

            // For some reason, jQuery selector "" against XML DOM sometimes doesn't match properly
            var cipherReference = $('CipherReference', encryptedData);
            cipherReference.each(function (index, CipherReference) {
                var cipherReferenceURI = $(CipherReference).attr('URI');
                console.log('Encryption/obfuscation algorithm ' + encryptionAlgorithm + ' specified for ' + cipherReferenceURI + (retrievalMethod ? ' with key ' + retrievalMethod : ''));

                if (!encryptionData.encryptions) {
                    encryptionData.encryptions = {};
                }

                if (!encryptionData.retrievalKeys) {
                    encryptionData.retrievalKeys = {};
                }

                encryptionData.encryptions[cipherReferenceURI] = encryptionAlgorithm;
                encryptionData.retrievalKeys[cipherReferenceURI] = retrievalMethod;
            });
        });

        return encryptionData;
    };

    return EncryptionHandler;
});