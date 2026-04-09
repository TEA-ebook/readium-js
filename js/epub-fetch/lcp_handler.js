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

define(['forge', 'promise', 'pako'], function (forge, es6Promise, pako) {

  var LCP_BASIC_PROFILE = 'http://readium.org/lcp/basic-profile';
  var LCP_PROFILE_1_0 = 'http://readium.org/lcp/profile-1.0';

  var lcpProfiles = [LCP_BASIC_PROFILE, LCP_PROFILE_1_0];

  var LCP_TEA_EBOOK_PROVIDERS = ['www.tea-ebook.com', 'www.tea-ebook.com-PP'];

  var IV_BYTES_SIZE = 16;
  var CBC_CHUNK_SIZE = 1024 * 32; // best perf with 32ko chunks

  var READ_AS_BINARY_STRING_AVAILABLE = typeof FileReader.prototype.readAsBinaryString === 'function';

  es6Promise.polyfill();
  objectPolyfill();

  var LcpHandler = function (encryptionData, lcpChannel, onError) {

    // private vars
    var userKey;
    var contentKey;
    var encryptionInfos = encryptionData.infos;
    var useOfficialLib = false;

    try {
      userKey = forge.util.hexToBytes(encryptionInfos.hash);
    } catch (e) {
      onError("encryption key is null or not defined");
    }

    // LCP lib channel
    var lcpRequests = {};
    lcpChannel.onmessage = handleDecryptResponse;

    // LCP step by step verification functions

    function isOfficialLcp(license) {
      return !LCP_TEA_EBOOK_PROVIDERS.includes(license.provider) && license.encryption.profile === LCP_PROFILE_1_0;
    }

    function checkUserKey(license) {
      return new Promise(function (resolve, reject) {
        // Official LCP -> key is already checked
        if (isOfficialLcp(license)) {
          resolve(license);
          return;
        }

        var userKeyCheck = license.encryption.user_key.key_check;

        // Decrypt and compare it to license ID
        decipher(userKey, atob(userKeyCheck)).then(function (userKeyCheckDecryptedData) {
          if (license.id === userKeyCheckDecryptedData) {
            resolve(license);
          } else {
            reject(new Error("User key is invalid"));
          }
        }).catch(reject);
      });
    }

    function checkLicenseFields(license) {
      return new Promise(function (resolve, reject) {
        var errors = [];

        // mandatory fields
        var mandatoryFields = ['id', 'issued', 'provider', 'encryption', 'encryption/profile',
          'encryption/content_key', 'encryption/content_key/algorithm', 'encryption/content_key/encrypted_value',
          'encryption/user_key', 'encryption/user_key/algorithm', 'encryption/user_key/key_check',
          'encryption/user_key/text_hint', 'links', 'signature', 'signature/algorithm', 'signature/certificate',
          'signature/value'];
        mandatoryFields.forEach(function (fieldPath) {
          var basePath = '';
          var licensePart = license;
          do {
            var fieldValues = fieldPath.match(/(\w+)\//) || [fieldPath, fieldPath];
            if (fieldValues && !licensePart[fieldValues[1]]) {
              errors.push("License must contain '" + basePath + fieldValues[1] + "'");
            }
            fieldPath = fieldPath.slice(fieldValues[0].length);
            licensePart = licensePart[fieldValues[1]];
            basePath += fieldValues[0];
          } while (fieldPath);
        });

        // encryption profile
        if (lcpProfiles.indexOf(license.encryption.profile) === -1) {
          errors.push("Unknown encryption profile '" + license.encryption.profile + "'");
        }

        // rights
        if (license.rights) {
          if (license.rights.start) {
            var rightsStart = new Date(license.rights.start);
            if (rightsStart.getTime() > Date.now()) {
              errors.push("License rights are not valid yet");
            }
          }

          if (license.rights.end) {
            var rightsEnd = new Date(license.rights.end);
            if (rightsEnd.getTime() < Date.now()) {
              errors.push("License rights have expired");
            }
          }
        }

        if (errors.length > 0) {
          reject(Error(errors.join(', ')));
          return;
        }

        resolve(license);
      });
    }

    function checkLicenseSignature(license) {
      return new Promise(function (resolve, reject) {
        var certificate = forge.pki.certificateFromAsn1(forge.asn1.fromDer(atob(license.signature.certificate)));

        var notBefore = new Date(certificate.validity.notBefore);
        var notAfter = new Date(certificate.validity.notAfter);
        var licenseUpdated = new Date(license.updated || license.issued);

        if (licenseUpdated.getTime() < notBefore.getTime()) {
          return reject('License issued/updated before the certificate became valid');
        }
        if (licenseUpdated.getTime() > notAfter.getTime()) {
          return reject('License issued/updated after the certificate became valid');
        }

        var licenseWithoutSignature = Object.assign({}, license);
        delete licenseWithoutSignature.signature;

        var md = forge.md.sha256.create();
        md.update(forge.util.encodeUtf8(JSON.stringify(jsonSort(licenseWithoutSignature))));

        if (!certificate.publicKey.verify(md.digest().bytes(), atob(license.signature.value))) {
          return reject('Invalid Signature');
        }

        resolve(license);
      });
    }

    function getContentKey(license) {
      var contentKeyEncrypted = atob(license.encryption.content_key.encrypted_value);
      return decipher(userKey, contentKeyEncrypted);
    }

    function decipher(key, encryptedData, dataType) {
      if (dataType === 'arraybuffer') {
        return aesCbcDecipher(key, arrayBufferToString(encryptedData));
      }
      if (dataType === 'blob') {
        return blobToBinary(encryptedData).then(function (binaryData) {
          return aesCbcDecipher(key, binaryData);
        });
      }
      return aesCbcDecipher(key, encryptedData);
    }

    function aesCbcDecipher(key, encryptedBytes) {
      return new Promise(function (resolve, reject) {
        try {
          var decipher = forge.cipher.createDecipher('AES-CBC', key);
          decipher.start({iv: encryptedBytes.substring(0, IV_BYTES_SIZE)});

          var length = encryptedBytes.length;
          var chunkSize = CBC_CHUNK_SIZE;
          var index = IV_BYTES_SIZE;
          var decrypted = '';

          do {
            decrypted += decipher.output.getBytes();
            var buf = forge.util.createBuffer(encryptedBytes.substr(index, chunkSize));
            decipher.update(buf);
            index += chunkSize;
          } while (index < length);

          decipher.finish();
          decrypted += decipher.output.getBytes();

          resolve(decrypted);
        } catch (e) {
          reject("Key is invalid: " + e.message);
        }
      });
    }

    // Utility functions

    function arrayBufferToString(buffer) {
      return intArrayToString(new Uint8Array(buffer));
    }

    function intArrayToString(intArray) {
      var binary = '';
      var length = intArray.byteLength;
      for (var i = 0; i < length; i++) {
        binary += String.fromCharCode(intArray[i]);
      }
      return binary;
    }

    function binaryStringToUint8Array(binaryString) {
      var length = binaryString.length;
      var uint8Array = new Uint8Array(length);
      for (var i = 0; i < length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i);
      }
      return uint8Array;
    }

    function jsonSort(object) {
      if (object instanceof Array) {
        var ret = [];
        for (var i = 0; i < object.length; i++) {
          var value = object[i];
          if (value instanceof Object) {
            value = jsonSort(value);
          } else if (value instanceof Array) {
            value = jsonSort(value);
          }
          ret.push(value)
        }
        return ret;
      } else if (object instanceof Object) {
        var ret = {};
        var keys = Object.keys(object);
        keys.sort();
        for (var k = 0; k < keys.length; k++) {
          var key = keys[k];
          var value = object[key];
          if (value instanceof Object) {
            value = jsonSort(value);
          } else if (value instanceof Array) {
            value = jsonSort(value);
          }
          ret[key] = value;
        }
        return ret;
      }
      return object;
    }

    function blobToArrayBuffer(blob) {
      return new Promise(function (resolve, reject) {
        var fileReader = new FileReader();
        fileReader.onload = function () {
          resolve(this.result);
        };
        fileReader.onerror = reject;
        fileReader.readAsArrayBuffer(blob);
      });
    }

    function blobToBinary(blob) {
      if (!READ_AS_BINARY_STRING_AVAILABLE) {
        return blobToArrayBuffer(blob).then(arrayBufferToString);
      }

      return new Promise(function (resolve, reject) {
        var fileReader = new FileReader();
        fileReader.onload = function () {
          resolve(this.result);
        };
        fileReader.onerror = reject;
        fileReader.readAsBinaryString(blob);
      });
    }

    function getTypeOfData(data) {
      if (data instanceof Blob) {
        return 'blob';
      }
      if (data instanceof ArrayBuffer) {
        return 'arraybuffer';
      }
      return 'binary';
    }

    function unzip(data, fetchMode, compression) {
      compression = compression || 8;
      if (compression === 8) {
        try {
          var options = (fetchMode === 'blob') ? null : {to: 'string'};
          return pako.inflateRaw(data, options);
        } catch (error) {
          console.warn(error);
          return data;
        }
      }
      return data;
    }

    function decipherCare(path, dataType, encryptedAes256cbcContent, fetchMode) {
      return decipher(contentKey, encryptedAes256cbcContent, dataType)
        .then(function (data) {
          if (encryptionData.compressionMethods[path] === 8) {
            return unzip(data, fetchMode);
          }
          if (fetchMode === 'blob') {
            return binaryStringToUint8Array(data);
          }
          return data;
        });
    }

    function decipherLcp(path, dataType, encryptedAes256cbcContent, fetchMode) {
      return new Promise(function (resolve) {
          if (!(path in lcpRequests)) {
            lcpRequests[path] = {
              resolvers: [],
              fetchMode
            };
          }
          lcpRequests[path].resolvers.push(resolve);

          // we ask the electron app to decrypt data with lcp.node lib
          lcpChannel.postMessage({
            type: ReadiumSDK.Events.REMOTE_DECRYPT_DATA,
            path: path,
            content: encryptedAes256cbcContent
          });
        }
      );
    }

    function decodeUtf8(data) {
      var decodedData;
      try {
        decodedData = forge.util.decodeUtf8(data);
      } catch (err) {
        // we will try to encode data first
      }

      if (!decodedData) {
        try {
          decodedData = forge.util.decodeUtf8(forge.util.encodeUtf8(data));
        } catch (err) {
          console.warn('Can’t decode utf8 content', err);
          return data;
        }
      }
      return decodedData;
    }

    function handleDecryptResponse(event) {
      var response = event.data;
      var request = lcpRequests[response.path];

      if (!request) {
        console.warn('no request found for ' + response.path);
        return;
      }

      if (request.fetchMode === 'text') {
        const data = intArrayToString(response.content).trim();
        request.resolvers.forEach(function (resolve) {
          resolve(data);
        });
      } else {
        request.resolvers.forEach(function (resolve) {
          resolve(response.content);
        });
      }
      delete lcpRequests[response.path];
    }

// PUBLIC API

    this.checkLicense = function (license, callback, error) {
      if (isOfficialLcp(license)) {
        checkLicenseFields(license)
          .then(function () {
            useOfficialLib = true;
            callback();
          })
          .catch(error);
        return;
      }

      checkUserKey(license)
        .then(checkLicenseFields)
        .then(checkLicenseSignature)
        .then(getContentKey)
        .then(function (bookContentKey) {
          contentKey = bookContentKey;
          callback();
        })
        .catch(error);
    };

    this.decryptContent = function (path, encryptedAes256cbcContent, callback, fetchMode, mimeType) {
      var dataType = getTypeOfData(encryptedAes256cbcContent);

      if (!mimeType && dataType === 'blob') {
        mimeType = encryptedAes256cbcContent.type;
      }

      var decipherMethod = useOfficialLib === true ? decipherLcp : decipherCare;

      decipherMethod(path, dataType, encryptedAes256cbcContent, fetchMode)
        .then(function (decryptedBinaryData) {
          if (fetchMode === 'text') {
            // BOM removal
            if (decryptedBinaryData.charCodeAt(0) === 0xFEFF) {
              decryptedBinaryData = decryptedBinaryData.substr(1);
            }
            var data = decryptedBinaryData.replace(/^ï»¿/, '');

            // convert UTF-8 decoded data to UTF-16 javascript string
            if (/html/.test(mimeType)) {
              data = decodeUtf8(data);

              // trimming bad data at the end the spine
              var lastClosingTagIndex = data.lastIndexOf('>');
              if (lastClosingTagIndex > 0) {
                data = data.substring(0, lastClosingTagIndex + 1);
              }
            }
            callback(data);
          } else if (fetchMode === 'data64') {
            // convert into a data64 string
            callback(forge.util.encode64(decryptedBinaryData.data));
          } else {
            // convert into a blob
            callback(new Blob([decryptedBinaryData], {type: mimeType}));
          }
        }).catch(function (error) {
        console.error("Can't decrypt LCP content", error);
      });
    };
  };

  return LcpHandler;
});

function objectPolyfill() {
  if (typeof Object.assign !== 'function') {
    // Must be writable: true, enumerable: false, configurable: true
    Object.defineProperty(Object, "assign", {
      value: function assign(target, varArgs) { // .length of function is 2
        'use strict';
        if (target == null) { // TypeError if undefined or null
          throw new TypeError('Cannot convert undefined or null to object');
        }

        var to = Object(target);

        for (var index = 1; index < arguments.length; index++) {
          var nextSource = arguments[index];

          if (nextSource != null) { // Skip over if undefined or null
            for (var nextKey in nextSource) {
              // Avoid bugs when hasOwnProperty is shadowed
              if (Object.prototype.hasOwnProperty.call(nextSource, nextKey)) {
                to[nextKey] = nextSource[nextKey];
              }
            }
          }
        }
        return to;
      },
      writable: true,
      configurable: true
    });
  }
}
