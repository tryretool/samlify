"use strict";
var __read = (this && this.__read) || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
};
var __spread = (this && this.__spread) || function () {
    for (var ar = [], i = 0; i < arguments.length; i++) ar = ar.concat(__read(arguments[i]));
    return ar;
};
Object.defineProperty(exports, "__esModule", { value: true });
/**
* @file utility.ts
* @author tngan
* @desc  Library for some common functions (e.g. de/inflation, en/decoding)
*/
var node_forge_1 = require("node-forge");
var deflate_js_1 = require("deflate-js");
var BASE64_STR = 'base64';
/**
 * @desc Mimic lodash.zipObject
 * @param arr1 {string[]}
 * @param arr2 {[]}
 */
function zipObject(arr1, arr2) {
    return arr1.reduce(function (res, l, i) {
        res[l] = arr2[i];
        return res;
    }, {});
}
exports.zipObject = zipObject;
/**
 * @desc Alternative to lodash.flattenDeep
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_flattendeep
 * @param input {[]}
 */
function flattenDeep(input) {
    return Array.isArray(input)
        ? input.reduce(function (a, b) { return a.concat(flattenDeep(b)); }, [])
        : [input];
}
exports.flattenDeep = flattenDeep;
/**
 * @desc Alternative to lodash.last
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_last
 * @param input {[]}
 */
function last(input) {
    return input.slice(-1)[0];
}
exports.last = last;
/**
 * @desc Alternative to lodash.uniq
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_uniq
 * @param input {string[]}
 */
function uniq(input) {
    var set = new Set(input);
    return __spread(set);
}
exports.uniq = uniq;
/**
 * @desc Alternative to lodash.get
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_get
 * @param obj
 * @param path
 * @param defaultValue
 */
function get(obj, path, defaultValue) {
    return path.split('.')
        .reduce(function (a, c) { return (a && a[c] ? a[c] : (defaultValue || null)); }, obj);
}
exports.get = get;
/**
 * @desc Check if the input is string
 * @param {any} input
 */
function isString(input) {
    return typeof input === 'string';
}
exports.isString = isString;
/**
* @desc Encode string with base64 format
* @param  {string} message                       plain-text message
* @return {string} base64 encoded string
*/
function base64Encode(message) {
    return new Buffer(message).toString(BASE64_STR);
}
/**
* @desc Decode string from base64 format
* @param  {string} base64Message                 encoded string
* @param  {boolean} isBytes                      determine the return value type (True: bytes False: string)
* @return {bytes/string}  decoded bytes/string depends on isBytes, default is {string}
*/
function base64Decode(base64Message, isBytes) {
    var bytes = new Buffer(base64Message, BASE64_STR);
    return Boolean(isBytes) ? bytes : bytes.toString();
}
exports.base64Decode = base64Decode;
/**
* @desc Compress the string
* @param  {string} message
* @return {string} compressed string
*/
function deflateString(message) {
    return deflate_js_1.deflate(Array.prototype.map.call(message, function (char) { return char.charCodeAt(0); }));
}
/**
* @desc Decompress the compressed string
* @param  {string} compressedString
* @return {string} decompressed string
*/
function inflateString(compressedString) {
    return deflate_js_1.inflate(Array.prototype.map.call(new Buffer(compressedString, BASE64_STR).toString('binary'), function (char) { return char.charCodeAt(0); }))
        .map(function (byte) { return String.fromCharCode(byte); })
        .join('');
}
exports.inflateString = inflateString;
/**
* @desc Abstract the normalizeCerString and normalizePemString
* @param {buffer} File stream or string
* @param {string} String for header and tail
* @return {string} A formatted certificate string
*/
function _normalizeCerString(bin, format) {
    return bin.toString().replace(/\n/g, '').replace(/\r/g, '').replace("-----BEGIN " + format + "-----", '').replace("-----END " + format + "-----", '').replace(/ /g, '');
}
/**
* @desc Parse the .cer to string format without line break, header and footer
* @param  {string} certString     declares the certificate contents
* @return {string} certificiate in string format
*/
function normalizeCerString(certString) {
    return _normalizeCerString(certString, 'CERTIFICATE');
}
/**
* @desc Normalize the string in .pem format without line break, header and footer
* @param  {string} pemString
* @return {string} private key in string format
*/
function normalizePemString(pemString) {
    return _normalizeCerString(pemString.toString(), 'RSA PRIVATE KEY');
}
/**
* @desc Return the complete URL
* @param  {object} req                   HTTP request
* @return {string} URL
*/
function getFullURL(req) {
    return req.protocol + "://" + req.get('host') + req.originalUrl;
}
/**
* @desc Parse input string, return default value if it is undefined
* @param  {string/boolean}
* @return {boolean}
*/
function parseString(str, defaultValue) {
    if (defaultValue === void 0) { defaultValue = ''; }
    return str || defaultValue;
}
/**
* @desc Override the object by another object (rtl)
* @param  {object} default object
* @param  {object} object applied to the default object
* @return {object} result object
*/
function applyDefault(obj1, obj2) {
    return Object.assign({}, obj1, obj2);
}
/**
* @desc Get public key in pem format from the certificate included in the metadata
* @param {string} x509 certificate
* @return {string} public key fetched from the certificate
*/
function getPublicKeyPemFromCertificate(x509Certificate) {
    var certDerBytes = node_forge_1.util.decode64(x509Certificate);
    var obj = node_forge_1.asn1.fromDer(certDerBytes);
    var cert = node_forge_1.pki.certificateFromAsn1(obj);
    return node_forge_1.pki.publicKeyToPem(cert.publicKey);
}
/**
* @desc Read private key from pem-formatted string
* @param {string | Buffer} keyString pem-formattted string
* @param {string} protected passphrase of the key
* @return {string} string in pem format
* If passphrase is used to protect the .pem content (recommend)
*/
function readPrivateKey(keyString, passphrase, isOutputString) {
    return isString(passphrase) ? this.convertToString(node_forge_1.pki.privateKeyToPem(node_forge_1.pki.decryptRsaPrivateKey(String(keyString), passphrase)), isOutputString) : keyString;
}
exports.readPrivateKey = readPrivateKey;
/**
* @desc Inline syntax sugar
*/
function convertToString(input, isOutputString) {
    return Boolean(isOutputString) ? String(input) : input;
}
/**
 * @desc Check if the input is an array with non-zero size
 */
function isNonEmptyArray(a) {
    return Array.isArray(a) && a.length > 0;
}
exports.isNonEmptyArray = isNonEmptyArray;
function notEmpty(value) {
    return value !== null && value !== undefined;
}
exports.notEmpty = notEmpty;
var utility = {
    isString: isString,
    base64Encode: base64Encode,
    base64Decode: base64Decode,
    deflateString: deflateString,
    inflateString: inflateString,
    normalizeCerString: normalizeCerString,
    normalizePemString: normalizePemString,
    getFullURL: getFullURL,
    parseString: parseString,
    applyDefault: applyDefault,
    getPublicKeyPemFromCertificate: getPublicKeyPemFromCertificate,
    readPrivateKey: readPrivateKey,
    convertToString: convertToString,
    isNonEmptyArray: isNonEmptyArray,
};
exports.default = utility;
//# sourceMappingURL=utility.js.map