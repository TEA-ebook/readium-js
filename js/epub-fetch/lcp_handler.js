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

    const LCP_BASIC_PROFILE = 'http://readium.org/lcp/basic-profile';
    const LCP_PROFILE_1_0 = 'http://readium.org/lcp/profile-1.0';

    const lcpProfiles = [LCP_BASIC_PROFILE, LCP_PROFILE_1_0];

    var IV_BYTES_SIZE = 16;
    var CBC_CHUNK_SIZE = 1024 * 32; // best perf with 32ko chunks

    var READ_AS_BINARY_STRING_AVAILABLE = typeof FileReader.prototype.readAsBinaryString === 'function';

    es6Promise.polyfill();

    var LcpHandler = function (encryptionData, onError) {

        // private vars
        var userKey;
        var contentKey;
        var encryptionInfos = encryptionData.infos;

        try {
            userKey = forge.util.hexToBytes(encryptionInfos.hash);
        } catch (e) {
            onError("encryption key is null or not defined");
        }

        // LCP step by step verification functions

        function checkUserKey(license) {
            return new Promise(function (resolve, reject) {
                var userKeyCheck = license.encryption.user_key.key_check;

                // Decrypt and compare it to license ID
                decipher(userKey, atob(userKeyCheck)).then(function (userKeyCheckDecryptedData) {
                    if (license.id === userKeyCheckDecryptedData) {
                        resolve(license);
                    } else {
                        reject(Error("User key is invalid"));
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
                if (!lcpProfiles.includes(license.encryption.profile)) {
                    errors.push("Unknown encryption profile '" + license.encryption.profile + "'");
                }

                // rights dates
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
                md.update(JSON.stringify(jsonSort(licenseWithoutSignature)));

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
                return aesCbcDecipher(key, arrayBuffer2Binary(encryptedData));
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

        function arrayBuffer2Binary(buffer) {
            var binary = '';
            var bytes = new Uint8Array(buffer);
            var length = bytes.byteLength;
            for (var i = 0; i < length; i++) {
                binary += String.fromCharCode(bytes[i]);
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
                    }
                    else if (value instanceof Array) {
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
                    }
                    else if (value instanceof Array) {
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
                return blobToArrayBuffer(blob).then(arrayBuffer2Binary);
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

        function unzip(data, fetchMode, compression = 8) {
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

        // PUBLIC API

        this.checkLicense = function (license, callback, error) {
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
            var dataType = getTypeOfData(encryptedAes256cbcContent), data;

            if (!mimeType && dataType === 'blob') {
                mimeType = encryptedAes256cbcContent.type;
            }

            decipher(contentKey, encryptedAes256cbcContent, dataType)
                .then(function (data) {
                    if (encryptionData.compressionMethods[path] === 8) {
                        return unzip(data, fetchMode);
                    }
                    if (fetchMode === 'blob') {
                        return binaryStringToUint8Array(data);
                    }
                    return data;
                })
                .then(function (decryptedBinaryData) {
                    if (fetchMode === 'text') {
                        // convert UTF-8 decoded data to UTF-16 javascript string (with BOM removal)
                        data = decryptedBinaryData.replace(/^ï»¿/, '');
                        if (/html/.test(mimeType)) {
                            try {
                                data = forge.util.decodeUtf8(data);
                            } catch (err) {
                                console.warn('Can’t decode utf8 content', err);
                            }
                        }
                        callback(data);
                    } else if (fetchMode === 'data64') {
                        // convert into a data64 string
                        callback(forge.util.encode64(decryptedBinaryData.data));
                    } else {
                        // convert into a blob
                        callback(new Blob([decryptedBinaryData], { type: mimeType }));
                    }
                }).catch(function (error) {
                console.error("Can't decrypt LCP content", error);
            });
        };
    };

    return LcpHandler;
});
