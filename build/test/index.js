"use strict";
var __assign = (this && this.__assign) || Object.assign || function(t) {
    for (var s, i = 1, n = arguments.length; i < n; i++) {
        s = arguments[i];
        for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
            t[p] = s[p];
    }
    return t;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
var esaml2 = require("../index");
var fs_1 = require("fs");
var ava_1 = require("ava");
var lodash_1 = require("lodash");
var validator_1 = require("../src/validator");
var identityProvider = esaml2.IdentityProvider, serviceProvider = esaml2.ServiceProvider, idpMetadata = esaml2.IdPMetadata, spMetadata = esaml2.SPMetadata, utility = esaml2.Utility, libsaml = esaml2.SamlLib, ref = esaml2.Constants;
var binding = ref.namespace.binding;
var algorithms = ref.algorithms;
var wording = ref.wording;
var signatureAlgorithms = algorithms.signature;
var _spKeyFolder = './test/key/sp/';
var _spPrivPem = String(fs_1.readFileSync(_spKeyFolder + 'privkey.pem'));
var _spPrivKeyPass = 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px';
var defaultIdpConfig = {
    privateKey: fs_1.readFileSync('./test/key/idp/privkey.pem'),
    privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
    isAssertionEncrypted: true,
    encPrivateKey: fs_1.readFileSync('./test/key/idp/encryptKey.pem'),
    encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
    metadata: fs_1.readFileSync('./test/misc/idpmeta.xml'),
};
var defaultSpConfig = {
    privateKey: fs_1.readFileSync('./test/key/sp/privkey.pem'),
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
    isAssertionEncrypted: true,
    encPrivateKey: fs_1.readFileSync('./test/key/sp/encryptKey.pem'),
    encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
    metadata: fs_1.readFileSync('./test/misc/spmeta.xml'),
};
var idp = identityProvider(defaultIdpConfig);
var sp = serviceProvider(defaultSpConfig);
var IdPMetadata = idpMetadata(fs_1.readFileSync('./test/misc/idpmeta.xml'));
var SPMetadata = spMetadata(fs_1.readFileSync('./test/misc/spmeta.xml'));
var sampleSignedResponse = fs_1.readFileSync('./test/misc/response_signed.xml').toString();
var wrongResponse = fs_1.readFileSync('./test/misc/invalid_response.xml').toString();
var spCertKnownGood = fs_1.readFileSync('./test/key/sp/knownGoodCert.cer').toString().trim();
var spPemKnownGood = fs_1.readFileSync('./test/key/sp/knownGoodEncryptKey.pem').toString().trim();
function writer(str) {
    fs_1.writeFileSync('test.txt', str);
}
ava_1.default('base64 encoding returns encoded string', function (t) {
    t.is(utility.base64Encode('Hello World'), 'SGVsbG8gV29ybGQ=');
});
ava_1.default('base64 decoding returns decoded string', function (t) {
    t.is(utility.base64Decode('SGVsbG8gV29ybGQ='), 'Hello World');
});
ava_1.default('deflate + base64 encoded', function (t) {
    t.is(utility.base64Encode(utility.deflateString('Hello World')), '80jNyclXCM8vykkBAA==');
});
ava_1.default('base64 decoded + inflate', function (t) {
    t.is(utility.inflateString('80jNyclXCM8vykkBAA=='), 'Hello World');
});
ava_1.default('parse cer format resulting clean certificate', function (t) {
    t.is(utility.normalizeCerString(fs_1.readFileSync('./test/key/sp/cert.cer')), spCertKnownGood);
});
ava_1.default('normalize pem key returns clean string', function (t) {
    var ekey = fs_1.readFileSync('./test/key/sp/encryptKey.pem').toString();
    t.is(utility.normalizePemString(ekey), spPemKnownGood);
});
ava_1.default('getAssertionConsumerService with one binding', function (t) {
    var expectedPostLocation = 'https:sp.example.org/sp/sso/post';
    var _sp = serviceProvider({
        privateKey: './test/key/sp/privkey.pem',
        privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
        isAssertionEncrypted: true,
        encPrivateKey: './test/key/sp/encryptKey.pem',
        encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
        assertionConsumerService: [{
                Binding: binding.post,
                Location: expectedPostLocation,
            }],
        singleLogoutService: [{
                Binding: binding.redirect,
                Location: 'https:sp.example.org/sp/slo',
            }],
    });
    t.is(_sp.entityMeta.getAssertionConsumerService(wording.binding.post), expectedPostLocation);
});
ava_1.default('getAssertionConsumerService with two bindings', function (t) {
    var expectedPostLocation = 'https:sp.example.org/sp/sso/post';
    var expectedArtifactLocation = 'https:sp.example.org/sp/sso/artifact';
    var _sp = serviceProvider({
        privateKey: './test/key/sp/privkey.pem',
        privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
        isAssertionEncrypted: true,
        encPrivateKey: './test/key/sp/encryptKey.pem',
        encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
        assertionConsumerService: [{
                Binding: binding.post,
                Location: expectedPostLocation,
            }, {
                Binding: binding.artifact,
                Location: expectedArtifactLocation,
            }],
        singleLogoutService: [{
                Binding: binding.redirect,
                Location: 'https:sp.example.org/sp/slo',
            }, {
                Binding: binding.post,
                Location: 'https:sp.example.org/sp/slo',
            }],
    });
    t.is(_sp.entityMeta.getAssertionConsumerService(wording.binding.post), expectedPostLocation);
    t.is(_sp.entityMeta.getAssertionConsumerService(wording.binding.artifact), expectedArtifactLocation);
});
(function () {
    var _originRequest = String(fs_1.readFileSync('./test/misc/request.xml'));
    var _decodedResponse = String(fs_1.readFileSync('./test/misc/response_signed.xml'));
    var _falseDecodedRequestSHA1 = String(fs_1.readFileSync('./test/misc/false_signed_request_sha1.xml'));
    var _decodedRequestSHA256 = String(fs_1.readFileSync('./test/misc/signed_request_sha256.xml'));
    var _falseDecodedRequestSHA256 = String(fs_1.readFileSync('./test/misc/false_signed_request_sha256.xml'));
    var _decodedRequestSHA512 = String(fs_1.readFileSync('./test/misc/signed_request_sha512.xml'));
    var _falseDecodedRequestSHA512 = String(fs_1.readFileSync('./test/misc/false_signed_request_sha512.xml'));
    var octetString = 'SAMLRequest=fVNdj9MwEHxH4j9Yfm%2Fi5PpBrLaotEJUOrioKTzwgoy9oZZiO9ibu%2FLvcXLtKUhHnyzZM7Mzu+tlEKZp+abDkz3A7w4CkrNpbODDw4p23nIngg7cCgOBo+TV5vM9zxPGW+%2FQSdfQEeU2Q4QAHrWzlOx3K%2FrjHSsWbFEzdsfETDE2z5ksVKHqYlHP84WooVBS5lNKvoEPkbeiUYaS0rtHrcB%2FiRVWtCoJRuNRM4QO9jagsBiRLJtO2GKSzY%2F5HZ%2FlfDr7TskuIrUVOIidEFueplq1CZyFaRtIpDNpVT1U4B+1hKQ9tUO5IegHbZW2v25n%2FPkMCvzT8VhOyofqSMnmmnvrbOgM+Iv818P9i4nwrwcFxmVp1IJzb+K9kIGu374hZNm3mQ9R%2Ffp1rgEUSqBYpmPsC7nlfd%2F2u9I1Wv4hH503Av8fKkuy4UarST1AORihm41SHkKI4ZrGPW09CIyzQN8BTce1LmsFaliy2ACEM5KtM63wOvRTiNYlPoe7xhtjt01cmwPU65ubJbnscfG6jMeT8+qS%2FlWpwV96w2BEXN%2FHn2P9Fw%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1';
    var octetStringSHA256 = 'SAMLRequest=fZJbTwIxEIX%2Fyqbvy3Yv3BogQYiRBJWw6INvY3eAJt0WO10v%2F966YIKJkPRpek7nfDMdEdT6IKaN35s1vjVIPvqstSHRXoxZ44ywQIqEgRpJeCnK6f1SZB0uDs56K61mZ5brDiBC55U1LFrMx2wrB8P%2BIB%2FGeQHbuOgVwxigB3EqewXfDjDPZJ9Fz%2BgoWMYsvBB8RA0uDHkwPpR42o1THvNswzMRTtHtpEX2wqJ5QFEGfOvce38QSaKtBL235EXOeZoQ2aRUZqexVDvzaEp070pikveG3W5otTrx3ShTBdl1tNejiMTdZrOKV4%2FlhkXTX9yZNdTU6E4dntbLfzIVnGdtJpDEJqOfaYqW1k0ua2v0UIGHUXKuHx3X%2BhBSLuYrq5X8im6tq8Ffhkg7aVtRVbxtpQJrUHpaVQ6JAozW9mPmEDyGzYEmZMnk2PbvB5p8Aw%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256';
    var octetStringSHA512 = 'SAMLRequest=fZJfT8IwFMW%2FytL3sY5tCA0jQYiRBIUw9MG3a3cnTboWezv%2FfHvr0AQT9fX2nJ7zu%2B2UoNVHMe%2F8wezwuUPy0VurDYn%2BoGSdM8ICKRIGWiThpajmN2sxHHBxdNZbaTU7s%2FzvACJ0XlnDotWyZFBkDcAE47wZjeNcXqTxGAsZy0lR1EUzAiwaFt2jo2ApWbgh%2BIg6XBnyYHwY8bSIUx7z4Z4PRZaLbDLg4%2FyBRcuAogz43nnw%2FiiSRFsJ%2BmDJi4zzNCGySaXMk8ZKPZmNqdC9KIlJNgr5IWr7xXepTB1k%2F6M9nkQkrvf7bbzdVHsWzb9xF9ZQ16L7SrjbrX%2FplHM%2B7DuBJDabfm5T9LRu9re2RQ81eJgm5%2Frp6VlvQ8vVcmu1ku%2FRlXUt%2BL8h0kHaT1QdN71UYAtKz%2BvaIVGA0dq%2BLhyCx5I1oAlZMjvF%2FvxAsw8%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha512';
    var signatureB64SHA512 = 'pLoxKnpOVA1mvLpOZCyzCyB/P01Qcy7cEFskzycm5sdNFYjmZAMGT6yxCgTRvzIloX2J7abZdAkU1dA8kY2yPQrWCuQFOxeSCqnGpHg5/bBKzFiGwWtlyHgh7LXEEo2zKWspJh7BhwRIbtOAnN3XvCPDO58wKHnEdxo9TneTyFmy5hcfYKcF7LlI8jSFkmsPvCsMMJ8TawgnKlwdIU0Ze/cp64Y24cpYxVIKtCC950VRuxAt3bmr7pqtIEsHKkqTOrPv5pWo2XqRG0UhvzjYCbpC8aGOuqLe8hfTfgpQ6ebUkqrgAufkLrinOGpZrlQQDFr0iVIKR30bInDGjg2G+g==';
    var signatureB64SHA256 = 'iC7RXfHuIu4gBLGABv0qtt96XFvyC7QSX8cDyLjJj+WNOTRMO5J/AYKelVhuc2AZuyGcf/sfeeVmcW7wyKTBHiGS+AWUCljmG43mPWERPfsa7og+GxrsHDSFh5nD70mQF44bXvpo/oVOxHx/lPiDG5LZg2KBccNXqJxMVUhnyU6xeGBctYY5ZQ4y7MGOx7hWTWjHyv+wyFd44Bcq0kpunTls91z03GkYo/Oxd4KllbfR5D2v6awjrc79wMYL1CcZiKZ941ter6tHOHCwtZRhTqV3Dl42zOKUOCyGcjJnVzJre1QBA7hrn3WB5/fu5kE6/E9ENRWp8ZRJLbU8C2Oogg==';
    var signatureB64SHA1 = 'UKPzYQivZOavFV3QjOH/B9AwKls9n5hZIzOL+V93Yi7lJ7siNkAA9WZgErtFVpDTN6ngSwvlfP/hXZcS33RcCGBWi1SX+xuwuk2U7bZgdkkw4tIH8zcgiRy8bK0IpMoXmLbApU2QsiNwRDMZq3iQdlaMhlsJh85VI+90SQk7fewseiw5Ui6BIpFSH96gLYjWMDPpwk+0GkhkkVaP5vo+I6mBQryD9YPFRu7JfCrnw2T6gldXlGu0IN326+qajKheAGmPSLWBmeFYhquJ5ipgfQGU/KCNIEUr6hkW8NU0+6EVaZl/A9Fyfs1+8KCQ6HxZ7FGyewQjJIx3a8XvBM5vDg==';
    var dummySignRequest = 'PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzgwOTcwN2YwMDMwYTVkMDA2MjBjOWQ5ZGY5N2Y2MjdhZmU5ZGNjMjQiIFZlcnNpb249IjIuMCIgUHJvdmlkZXJOYW1lPSJTUCB0ZXN0IiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTZUMjM6NTI6NDVaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2lkcC5leGFtcGxlLmNvbS9TU09TZXJ2aWNlLnBocCIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vc3AuZXhhbXBsZS5vcmcvc3Avc3NvIj48c2FtbDpJc3N1ZXIgSWQ9Il8wIj5odHRwczovL3NwLmV4YW1wbGUub3JnL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjxzYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0iZXhhY3QiPjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0PjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxSZWZlcmVuY2UgVVJJPSIjXzAiPjxUcmFuc2Zvcm1zPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L1RyYW5zZm9ybXM+PERpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PERpZ2VzdFZhbHVlPnRRRGlzQlhLVFErOU9YSk81cjdLdUpnYStLST08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+b3hSa3ZhdTdVdllnRkVaN1lOQVVOZjMwNjdWN1RuNUM5WFNJaWV0MWFadzJGWWV2Tlc1YlV5LzBteHAzYWo2QXZmRmpubXB6QWI4OEJqZHdBejJCRXJEVG9tUmN1WkI3TGIwZllUZjMxTjJvWk9YME1pUGlRT0g1NEk2M3FKVzRYbzNWcWRGN0dCdUZaWkh5bGxmU0J2N2dmQ3RqSkR3RlNDeldLNzBCOXIzY0ZNUkpaTGhDSjlvUGVuKzRVOXNjU1lPNmcrc3pCWkxsNkFpSjA2UEhjOGp6RUtHd2ZRcmNaazhrREtVbHZOZkpNVUx5cThkcHgyVnZVQXg0cDVld2ZNT3dCOVczSGwzUFBhMGRPNzd6WmlmM0NnbHBjTjA2ZittNlVZRy93bm9UUUV5S1c5aE9lKzJ2R004MFc3N2VXdTBkbWlhUHVxVDFvazhMWFB1cTFBPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSURvekNDQW91Z0F3SUJBZ0lKQUtOc21MOFFiZnB3TUEwR0NTcUdTSWIzRFFFQkN3VUFNR2d4Q3pBSkJnTlZCQVlUQWtoTE1SSXdFQVlEVlFRSURBbEliMjVuSUV0dmJtY3hDekFKQmdOVkJBY01Ba2hMTVJNd0VRWURWUVFLREFwdWIyUmxMWE5oYld3eU1TTXdJUVlKS29aSWh2Y05BUWtCRmhSdWIyUmxMbk5oYld3eVFHZHRZV2xzTG1OdmJUQWVGdzB4TlRBM01EVXhOelUyTkRkYUZ3MHhPREEzTURReE56VTJORGRhTUdneEN6QUpCZ05WQkFZVEFraExNUkl3RUFZRFZRUUlEQWxJYjI1bklFdHZibWN4Q3pBSkJnTlZCQWNNQWtoTE1STXdFUVlEVlFRS0RBcHViMlJsTFhOaGJXd3lNU013SVFZSktvWklodmNOQVFrQkZoUnViMlJsTG5OaGJXd3lRR2R0WVdsc0xtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNUUpBQjhKcnNMUWJVdUphOGFrekxxTzFFWnFDbFMwdFFwK3crNXdndWZwMDdXd0duL3NobWE4ZGNRTmoxZGJqc3pJNUhCZVZGak9LSXhsZmptTkI5b3ZoUVBzdEJqUC9VUFFZcDFJcDJJb0hDWVg5SERnTXozeHlYS2JIdGhVelphRUN6K3ArN1d0Z3doY3pSa0JMRE9tMmsxNXFoUFlHUHcwdkgyemJWUkdXVUJTOWR5Mk1wM3RxbFZiUDB4WjlDRE5raENKa1Y5U01OZm9DVlcvVllQcUsyUUJvN2tpNG9ibTV4NWl4RlFTU0hzS2JWQVJWenlRSDVpTmpGZTFUZEFwM3JEd3JFNUxjMU5RbFFheFI1R25iMk5aQXBET1JSWklWbE52MldVZGk5UXZNMHlDempROTBqUDBPQW9nSGhSWWF4ZzAvdmdORXllNDZoK1BpWTBDQXdFQUFhTlFNRTR3SFFZRFZSME9CQllFRkVWa2pjTEFJVG5ka3kwOTBBeTc0UXFDbVFLSU1COEdBMVVkSXdRWU1CYUFGRVZramNMQUlUbmRreTA5MEF5NzRRcUNtUUtJTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRzRsWVgzS1FYZW5lejRMcERuWmhjRkJFWmk5WXN0VUtQRjVFS2QrV3BscFZiY1RRYzFBMy9aK3VIUm15VjhoK3BRemVGNkxpb2IzN0c4N1lwYWNQcGxKSTY2Y2YyUmo3ajhoU0JOYmRyKzY2RTJxcGNFaEFGMWlKbXpCTnloYi95ZGxFdVZwbjgvRXNvUCtIdkJlaURsNWdvbjM1NjJNelpJZ1YvcExkVGZ4SHlXNmh6QVFoakdxMlVoY3ZSK2dYTlZKdkhQMmVTNGpsSG5Ka0I5YmZvMGt2Zjg3UStENlhLWDNxNWMzbU84dHFXNlVwcUhTQyt1TEVwelppTkxldUZhNFRVSWhnQmdqRGpsUnJOREt1OG5kYW5jU24zeUJIWW5xSjJ0OWNSK2NvRm5uallBQlFwTnJ2azRtdG1YWThTWG9CellHOVkrbHFlQXVuNiswWXlFPTwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE+PC9LZXlJbmZvPjwvU2lnbmF0dXJlPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg==';
    var dummySignRequestSHA256 = 'PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzgwOTcwN2YwMDMwYTVkMDA2MjBjOWQ5ZGY5N2Y2MjdhZmU5ZGNjMjQiIFZlcnNpb249IjIuMCIgUHJvdmlkZXJOYW1lPSJTUCB0ZXN0IiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTZUMjM6NTI6NDVaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2lkcC5leGFtcGxlLmNvbS9TU09TZXJ2aWNlLnBocCIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vc3AuZXhhbXBsZS5vcmcvc3Avc3NvIj48c2FtbDpJc3N1ZXIgSWQ9Il8wIj5odHRwczovL3NwLmV4YW1wbGUub3JnL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjxzYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0iZXhhY3QiPjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0PjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48UmVmZXJlbmNlIFVSST0iI18wIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48RGlnZXN0VmFsdWU+d3VKWlJSdWlGb0FQZVZXVllReXhOWXpjbUpJdXB0dTZmaE10MVZuQVZQbz08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+V0VUTUtaL1pzTm5pbDVjVCtHeTFKbmJWMVVscUN2N205SlppZ1NLTXFhbFlOL1ZDclMxelpFMkVOekxFSjhCN1ZaVkMyRVJBT2pHL1lHbWJ4Si95K2Z6YVR1bGh0blhrYUZncytmNEdJZDBISDY0MldKRnRBeUg2RS81SUVVWUVXYUk0TzA5MWgvd2EvM2EyNEJZK3R5L0ExSmIxLzM5NXpXVi84NUZETXFNemdVRDdRYkQ4TG5mcThkS1hJZDdQWmdnVnpQTFpvRHo0YXpaL3V4VG9aUkxwKy9XVjZHQy91Y2lLMmVmR1hMb09NMm1wcElDc05qVk9mT1NEM2pXS3BjQk11bDBRMjJZMGFoaXlKWDlFcnZkSEcwV0RMcXI0RXc5TGFqVVNydFovaGNqR1ZIemhZZCs1YklYSXp6ZWlmbUF6Snp4WFM4cmhjNGVoV25OYTJ3PT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSURvekNDQW91Z0F3SUJBZ0lKQUtOc21MOFFiZnB3TUEwR0NTcUdTSWIzRFFFQkN3VUFNR2d4Q3pBSkJnTlZCQVlUQWtoTE1SSXdFQVlEVlFRSURBbEliMjVuSUV0dmJtY3hDekFKQmdOVkJBY01Ba2hMTVJNd0VRWURWUVFLREFwdWIyUmxMWE5oYld3eU1TTXdJUVlKS29aSWh2Y05BUWtCRmhSdWIyUmxMbk5oYld3eVFHZHRZV2xzTG1OdmJUQWVGdzB4TlRBM01EVXhOelUyTkRkYUZ3MHhPREEzTURReE56VTJORGRhTUdneEN6QUpCZ05WQkFZVEFraExNUkl3RUFZRFZRUUlEQWxJYjI1bklFdHZibWN4Q3pBSkJnTlZCQWNNQWtoTE1STXdFUVlEVlFRS0RBcHViMlJsTFhOaGJXd3lNU013SVFZSktvWklodmNOQVFrQkZoUnViMlJsTG5OaGJXd3lRR2R0WVdsc0xtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNUUpBQjhKcnNMUWJVdUphOGFrekxxTzFFWnFDbFMwdFFwK3crNXdndWZwMDdXd0duL3NobWE4ZGNRTmoxZGJqc3pJNUhCZVZGak9LSXhsZmptTkI5b3ZoUVBzdEJqUC9VUFFZcDFJcDJJb0hDWVg5SERnTXozeHlYS2JIdGhVelphRUN6K3ArN1d0Z3doY3pSa0JMRE9tMmsxNXFoUFlHUHcwdkgyemJWUkdXVUJTOWR5Mk1wM3RxbFZiUDB4WjlDRE5raENKa1Y5U01OZm9DVlcvVllQcUsyUUJvN2tpNG9ibTV4NWl4RlFTU0hzS2JWQVJWenlRSDVpTmpGZTFUZEFwM3JEd3JFNUxjMU5RbFFheFI1R25iMk5aQXBET1JSWklWbE52MldVZGk5UXZNMHlDempROTBqUDBPQW9nSGhSWWF4ZzAvdmdORXllNDZoK1BpWTBDQXdFQUFhTlFNRTR3SFFZRFZSME9CQllFRkVWa2pjTEFJVG5ka3kwOTBBeTc0UXFDbVFLSU1COEdBMVVkSXdRWU1CYUFGRVZramNMQUlUbmRreTA5MEF5NzRRcUNtUUtJTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRzRsWVgzS1FYZW5lejRMcERuWmhjRkJFWmk5WXN0VUtQRjVFS2QrV3BscFZiY1RRYzFBMy9aK3VIUm15VjhoK3BRemVGNkxpb2IzN0c4N1lwYWNQcGxKSTY2Y2YyUmo3ajhoU0JOYmRyKzY2RTJxcGNFaEFGMWlKbXpCTnloYi95ZGxFdVZwbjgvRXNvUCtIdkJlaURsNWdvbjM1NjJNelpJZ1YvcExkVGZ4SHlXNmh6QVFoakdxMlVoY3ZSK2dYTlZKdkhQMmVTNGpsSG5Ka0I5YmZvMGt2Zjg3UStENlhLWDNxNWMzbU84dHFXNlVwcUhTQyt1TEVwelppTkxldUZhNFRVSWhnQmdqRGpsUnJOREt1OG5kYW5jU24zeUJIWW5xSjJ0OWNSK2NvRm5uallBQlFwTnJ2azRtdG1YWThTWG9CellHOVkrbHFlQXVuNiswWXlFPTwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE+PC9LZXlJbmZvPjwvU2lnbmF0dXJlPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg==';
    var dummySignRequestSHA512 = 'PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzgwOTcwN2YwMDMwYTVkMDA2MjBjOWQ5ZGY5N2Y2MjdhZmU5ZGNjMjQiIFZlcnNpb249IjIuMCIgUHJvdmlkZXJOYW1lPSJTUCB0ZXN0IiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTZUMjM6NTI6NDVaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2lkcC5leGFtcGxlLmNvbS9TU09TZXJ2aWNlLnBocCIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vc3AuZXhhbXBsZS5vcmcvc3Avc3NvIj48c2FtbDpJc3N1ZXIgSWQ9Il8wIj5odHRwczovL3NwLmV4YW1wbGUub3JnL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjxzYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0iZXhhY3QiPjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0PjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGE1MTIiLz48UmVmZXJlbmNlIFVSST0iI18wIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGE1MTIiLz48RGlnZXN0VmFsdWU+RWN3emlpSzZmazFNK2RETkpHNVlFeWpGY3Fjc0dzRmZNNGFDUkJKcENWTlltVWs4NWJxQk8rblRFN3RmRnd5Uk1yOUZBODBpSnN3MlFwM3R4QTE1Q2c9PTwvRGlnZXN0VmFsdWU+PC9SZWZlcmVuY2U+PC9TaWduZWRJbmZvPjxTaWduYXR1cmVWYWx1ZT5MVmFYajQ3MlZEalBvQU1hZ1BNcEswdGwvckV1c2llVXc4SXZrVVJmVVJDKzl1YXNqRXgxZjR4S1dkYUJLa09zQUhIZ1RMVlpxUnBNY1RBVnJTWDM5SnN1TmRDZnlycXBZTWlBY0w0RXhTM3dOSXdBenFCY1RiUlgxdEY2Nzk5cENYVXVOTE84NVdyN3FwZG5RTnFkTWc1L0E5a0xzUjFSc2dOeFhtandPM1dKUDhucFJ5dXYrVjJvNXhvN01FOVYyaVE4ODRhWVhnNUJodWQ5S1huSU5TZWw5YjN2NnV6T3V2VlFSM1ZCTlFWUXhRaGNUNlFpZ1BkR1hqZDl0cEU4TXV0UG5ZS1NNbHJKc1Ird2wzV2ZacmhwQ2E4U2JGS0RjNnBja1lmVUJYV3pRVVFJVkpXRm5icXBlemJsSUk2NmtlNlRvSzVseVpiajRSajFEcytjMHc9PTwvU2lnbmF0dXJlVmFsdWU+PEtleUluZm8+PFg1MDlEYXRhPjxYNTA5Q2VydGlmaWNhdGU+TUlJRG96Q0NBb3VnQXdJQkFnSUpBS05zbUw4UWJmcHdNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1HZ3hDekFKQmdOVkJBWVRBa2hMTVJJd0VBWURWUVFJREFsSWIyNW5JRXR2Ym1jeEN6QUpCZ05WQkFjTUFraExNUk13RVFZRFZRUUtEQXB1YjJSbExYTmhiV3d5TVNNd0lRWUpLb1pJaHZjTkFRa0JGaFJ1YjJSbExuTmhiV3d5UUdkdFlXbHNMbU52YlRBZUZ3MHhOVEEzTURVeE56VTJORGRhRncweE9EQTNNRFF4TnpVMk5EZGFNR2d4Q3pBSkJnTlZCQVlUQWtoTE1SSXdFQVlEVlFRSURBbEliMjVuSUV0dmJtY3hDekFKQmdOVkJBY01Ba2hMTVJNd0VRWURWUVFLREFwdWIyUmxMWE5oYld3eU1TTXdJUVlKS29aSWh2Y05BUWtCRmhSdWIyUmxMbk5oYld3eVFHZHRZV2xzTG1OdmJUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1RSkFCOEpyc0xRYlV1SmE4YWt6THFPMUVacUNsUzB0UXArdys1d2d1ZnAwN1d3R24vc2htYThkY1FOajFkYmpzekk1SEJlVkZqT0tJeGxmam1OQjlvdmhRUHN0QmpQL1VQUVlwMUlwMklvSENZWDlIRGdNejN4eVhLYkh0aFV6WmFFQ3orcCs3V3Rnd2hjelJrQkxET20yazE1cWhQWUdQdzB2SDJ6YlZSR1dVQlM5ZHkyTXAzdHFsVmJQMHhaOUNETmtoQ0prVjlTTU5mb0NWVy9WWVBxSzJRQm83a2k0b2JtNXg1aXhGUVNTSHNLYlZBUlZ6eVFINWlOakZlMVRkQXAzckR3ckU1TGMxTlFsUWF4UjVHbmIyTlpBcERPUlJaSVZsTnYyV1VkaTlRdk0weUN6alE5MGpQME9Bb2dIaFJZYXhnMC92Z05FeWU0NmgrUGlZMENBd0VBQWFOUU1FNHdIUVlEVlIwT0JCWUVGRVZramNMQUlUbmRreTA5MEF5NzRRcUNtUUtJTUI4R0ExVWRJd1FZTUJhQUZFVmtqY0xBSVRuZGt5MDkwQXk3NFFxQ21RS0lNQXdHQTFVZEV3UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFHNGxZWDNLUVhlbmV6NExwRG5aaGNGQkVaaTlZc3RVS1BGNUVLZCtXcGxwVmJjVFFjMUEzL1ordUhSbXlWOGgrcFF6ZUY2TGlvYjM3Rzg3WXBhY1BwbEpJNjZjZjJSajdqOGhTQk5iZHIrNjZFMnFwY0VoQUYxaUptekJOeWhiL3lkbEV1VnBuOC9Fc29QK0h2QmVpRGw1Z29uMzU2Mk16WklnVi9wTGRUZnhIeVc2aHpBUWhqR3EyVWhjdlIrZ1hOVkp2SFAyZVM0amxIbkprQjliZm8wa3ZmODdRK0Q2WEtYM3E1YzNtTzh0cVc2VXBxSFNDK3VMRXB6WmlOTGV1RmE0VFVJaGdCZ2pEamxSck5ES3U4bmRhbmNTbjN5QkhZbnFKMnQ5Y1IrY29Gbm5qWUFCUXBOcnZrNG10bVhZOFNYb0J6WUc5WStscWVBdW42KzBZeUU9PC9YNTA5Q2VydGlmaWNhdGU+PC9YNTA5RGF0YT48L0tleUluZm8+PC9TaWduYXR1cmU+PC9zYW1scDpBdXRoblJlcXVlc3Q+';
    /*
    writer(utility.base64Decode(libsaml.constructSAMLSignature({
      rawSamlMessage: _originResponse,
      referenceTagXPath: libsaml.createXPath('Issuer'),
      signingCert: IdPMetadata.getX509Certificate('signing'),
      privateKey: _idpPrivPem,
      privateKeyPass: _idpPrivKeyPass,
      signatureAlgorithm: signatureAlgorithms.RSA_SHA1,
      signatureConfig: {
        prefix: 'ds',
        location: { reference: '/samlp:Response/saml:Issuer', action: 'after' },
      },
    })));
    */
    ava_1.default('sign a SAML message with RSA-SHA1', function (t) {
        t.is(libsaml.constructMessageSignature(octetString, _spPrivPem, _spPrivKeyPass).toString('base64'), signatureB64SHA1);
    });
    ava_1.default('sign a SAML message with RSA-SHA256', function (t) {
        t.is(libsaml.constructMessageSignature(octetStringSHA256, _spPrivPem, _spPrivKeyPass, null, signatureAlgorithms.RSA_SHA256).toString('base64'), signatureB64SHA256);
    });
    ava_1.default('sign a SAML message with RSA-SHA512', function (t) {
        t.is(libsaml.constructMessageSignature(octetStringSHA512, _spPrivPem, _spPrivKeyPass, null, signatureAlgorithms.RSA_SHA512).toString('base64'), signatureB64SHA512);
    });
    ava_1.default('verify binary SAML message signed with RSA-SHA1', function (t) {
        var signature = libsaml.constructMessageSignature(octetString, _spPrivPem, _spPrivKeyPass, false);
        t.is(libsaml.verifyMessageSignature(SPMetadata, octetString, signature), true);
    });
    ava_1.default('verify binary SAML message signed with RSA-SHA256', function (t) {
        var signature = libsaml.constructMessageSignature(octetStringSHA256, _spPrivPem, _spPrivKeyPass, false, signatureAlgorithms.RSA_SHA256);
        t.is(libsaml.verifyMessageSignature(SPMetadata, octetStringSHA256, signature, signatureAlgorithms.RSA_SHA256), true);
    });
    ava_1.default('verify binary SAML message signed with RSA-SHA512', function (t) {
        var signature = libsaml.constructMessageSignature(octetStringSHA512, _spPrivPem, _spPrivKeyPass, false, signatureAlgorithms.RSA_SHA512);
        t.is(libsaml.verifyMessageSignature(SPMetadata, octetStringSHA512, signature, signatureAlgorithms.RSA_SHA512), true);
    });
    ava_1.default('verify stringified SAML message signed with RSA-SHA1', function (t) {
        var signature = libsaml.constructMessageSignature(octetString, _spPrivPem, _spPrivKeyPass);
        t.is(libsaml.verifyMessageSignature(SPMetadata, octetString, new Buffer(signature, 'base64')), true);
    });
    ava_1.default('verify stringified SAML message signed with RSA-SHA256', function (t) {
        var signature = libsaml.constructMessageSignature(octetStringSHA256, _spPrivPem, _spPrivKeyPass);
        t.is(libsaml.verifyMessageSignature(SPMetadata, octetStringSHA256, new Buffer(signature, 'base64')), true);
    });
    ava_1.default('verify stringified SAML message signed with RSA-SHA512', function (t) {
        var signature = libsaml.constructMessageSignature(octetStringSHA512, _spPrivPem, _spPrivKeyPass);
        t.is(libsaml.verifyMessageSignature(SPMetadata, octetStringSHA512, new Buffer(signature, 'base64')), true);
    });
    ava_1.default('construct signature with RSA-SHA1', function (t) {
        t.is(libsaml.constructSAMLSignature({
            rawSamlMessage: _originRequest,
            referenceTagXPath: libsaml.createXPath('Issuer'),
            signingCert: SPMetadata.getX509Certificate('signing'),
            privateKey: _spPrivPem,
            privateKeyPass: _spPrivKeyPass,
            signatureAlgorithm: signatureAlgorithms.RSA_SHA1,
        }), dummySignRequest);
    });
    ava_1.default('construct signature with RSA-SHA256', function (t) {
        t.is(libsaml.constructSAMLSignature({
            rawSamlMessage: _originRequest,
            referenceTagXPath: libsaml.createXPath('Issuer'),
            signingCert: SPMetadata.getX509Certificate('signing'),
            privateKey: _spPrivPem,
            privateKeyPass: _spPrivKeyPass,
            signatureAlgorithm: signatureAlgorithms.RSA_SHA256,
        }), dummySignRequestSHA256);
    });
    ava_1.default('construct signature with RSA-SHA512', function (t) {
        t.is(libsaml.constructSAMLSignature({
            rawSamlMessage: _originRequest,
            referenceTagXPath: libsaml.createXPath('Issuer'),
            signingCert: SPMetadata.getX509Certificate('signing'),
            privateKey: _spPrivPem,
            privateKeyPass: _spPrivKeyPass,
            signatureAlgorithm: signatureAlgorithms.RSA_SHA512,
        }), dummySignRequestSHA512);
    });
    ava_1.default('verify a XML signature signed by RSA-SHA1 with metadata', function (t) {
        t.is(libsaml.verifySignature(_decodedResponse, { cert: IdPMetadata })[0], true);
    });
    ava_1.default('integrity check for request signed with RSA-SHA1', function (t) {
        try {
            libsaml.verifySignature(_falseDecodedRequestSHA1, { cert: SPMetadata, signatureAlgorithm: signatureAlgorithms.RSA_SHA1 });
        }
        catch (e) {
            t.is(e.message, 'ERR_FAILED_TO_VERIFY_SIGNATURE');
        }
    });
    ava_1.default('verify a XML signature signed by RSA-SHA256 with metadata', function (t) {
        t.is(libsaml.verifySignature(_decodedRequestSHA256, { cert: SPMetadata, signatureAlgorithm: signatureAlgorithms.RSA_SHA256 })[0], true);
    });
    ava_1.default('integrity check for request signed with RSA-SHA256', function (t) {
        try {
            libsaml.verifySignature(_falseDecodedRequestSHA256, { cert: SPMetadata, signatureAlgorithm: signatureAlgorithms.RSA_SHA256 });
        }
        catch (e) {
            t.is(e.message, 'ERR_FAILED_TO_VERIFY_SIGNATURE');
        }
    });
    ava_1.default('verify a XML signature signed by RSA-SHA512 with metadata', function (t) {
        t.is(libsaml.verifySignature(_decodedRequestSHA512, { cert: SPMetadata, signatureAlgorithm: signatureAlgorithms.RSA_SHA512 })[0], true);
    });
    ava_1.default('integrity check for request signed with RSA-SHA512', function (t) {
        try {
            libsaml.verifySignature(_falseDecodedRequestSHA512, { cert: SPMetadata, signatureAlgorithm: signatureAlgorithms.RSA_SHA512 });
        }
        catch (e) {
            t.is(e.message, 'ERR_FAILED_TO_VERIFY_SIGNATURE');
        }
    });
    ava_1.default('verify a XML signature signed by RSA-SHA1 with .cer keyFile', function (t) {
        var xml = String(fs_1.readFileSync('./test/misc/signed_request_sha1.xml'));
        t.is(libsaml.verifySignature(xml, { keyFile: './test/key/sp/cert.cer' })[0], true);
    });
    ava_1.default('verify a XML signature signed by RSA-SHA256 with .cer keyFile', function (t) {
        var xml = String(fs_1.readFileSync('./test/misc/signed_request_sha256.xml'));
        t.is(libsaml.verifySignature(xml, { keyFile: './test/key/sp/cert.cer' })[0], true);
    });
    ava_1.default('verify a XML signature signed by RSA-SHA512 with .cer keyFile', function (t) {
        var xml = String(fs_1.readFileSync('./test/misc/signed_request_sha512.xml'));
        t.is(libsaml.verifySignature(xml, { keyFile: './test/key/sp/cert.cer' })[0], true);
    });
    ava_1.default('encrypt assertion test passes', function (t) { return __awaiter(_this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, t.notThrows(libsaml.encryptAssertion(idp, sp, sampleSignedResponse))];
                case 1:
                    _a.sent();
                    return [2 /*return*/];
            }
        });
    }); });
    ava_1.default('encrypt assertion response without assertion returns error', function (t) { return __awaiter(_this, void 0, void 0, function () {
        var error;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, t.throws(libsaml.encryptAssertion(idp, sp, wrongResponse))];
                case 1:
                    error = _a.sent();
                    t.is(error.message, 'ERR_MULTIPLE_ASSERTION');
                    return [2 /*return*/];
            }
        });
    }); });
    ava_1.default('encrypt assertion with invalid xml syntax returns error', function (t) { return __awaiter(_this, void 0, void 0, function () {
        var error;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, t.throws(libsaml.encryptAssertion(idp, sp, 'This is not a xml format string'))];
                case 1:
                    error = _a.sent();
                    t.is(error.message, 'ERR_MULTIPLE_ASSERTION');
                    return [2 /*return*/];
            }
        });
    }); });
    ava_1.default('encrypt assertion with empty string returns error', function (t) { return __awaiter(_this, void 0, void 0, function () {
        var error;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, t.throws(libsaml.encryptAssertion(idp, sp, ''))];
                case 1:
                    error = _a.sent();
                    t.is(error.message, 'ERR_UNDEFINED_ASSERTION');
                    return [2 /*return*/];
            }
        });
    }); });
    ava_1.default('encrypt assertion with undefined string returns error', function (t) { return __awaiter(_this, void 0, void 0, function () {
        var error;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, t.throws(libsaml.encryptAssertion(idp, sp, undefined))];
                case 1:
                    error = _a.sent();
                    t.is(error.message, 'ERR_UNDEFINED_ASSERTION');
                    return [2 /*return*/];
            }
        });
    }); });
    ava_1.default('building attribute statement with one attribute', function (t) {
        var attributes = [{
                name: 'email',
                valueTag: 'user.email',
                nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
                valueXsiType: 'xs:string',
            }];
        var expectedStatement = '<saml:AttributeStatement><saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">{attrUserEmail}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>';
        t.is(libsaml.attributeStatementBuilder(attributes), expectedStatement);
    });
    ava_1.default('building attribute statement with multiple attributes', function (t) {
        var attributes = [{
                name: 'email',
                valueTag: 'user.email',
                nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
                valueXsiType: 'xs:string',
            }, {
                name: 'firstname',
                valueTag: 'user.firstname',
                nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
                valueXsiType: 'xs:string',
            }];
        var expectedStatement = '<saml:AttributeStatement><saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">{attrUserEmail}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="firstname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">{attrUserFirstname}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>';
        t.is(libsaml.attributeStatementBuilder(attributes), expectedStatement);
    });
})();
(function () {
    var baseConfig = {
        signingCert: fs_1.readFileSync('./test/key/sp/cert.cer'),
        privateKey: fs_1.readFileSync('./test/key/sp/privkey.pem'),
        privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
        entityID: 'http://sp',
        nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
        assertionConsumerService: [{
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                Location: 'http://sp/acs',
                Index: 1,
            }],
        singleLogoutService: [{
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                Location: 'http://sp/slo',
                Index: 1,
            }],
    };
    ava_1.default('sp metadata with default elements order', function (t) {
        t.is(serviceProvider(baseConfig).getMetadata(), '<EntityDescriptor entityID="http://sp" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:assertion="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIDozCCAougAwIBAgIJAKNsmL8QbfpwMA0GCSqGSIb3DQEBCwUAMGgxCzAJBgNVBAYTAkhLMRIwEAYDVQQIDAlIb25nIEtvbmcxCzAJBgNVBAcMAkhLMRMwEQYDVQQKDApub2RlLXNhbWwyMSMwIQYJKoZIhvcNAQkBFhRub2RlLnNhbWwyQGdtYWlsLmNvbTAeFw0xNTA3MDUxNzU2NDdaFw0xODA3MDQxNzU2NDdaMGgxCzAJBgNVBAYTAkhLMRIwEAYDVQQIDAlIb25nIEtvbmcxCzAJBgNVBAcMAkhLMRMwEQYDVQQKDApub2RlLXNhbWwyMSMwIQYJKoZIhvcNAQkBFhRub2RlLnNhbWwyQGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQJAB8JrsLQbUuJa8akzLqO1EZqClS0tQp+w+5wgufp07WwGn/shma8dcQNj1dbjszI5HBeVFjOKIxlfjmNB9ovhQPstBjP/UPQYp1Ip2IoHCYX9HDgMz3xyXKbHthUzZaECz+p+7WtgwhczRkBLDOm2k15qhPYGPw0vH2zbVRGWUBS9dy2Mp3tqlVbP0xZ9CDNkhCJkV9SMNfoCVW/VYPqK2QBo7ki4obm5x5ixFQSSHsKbVARVzyQH5iNjFe1TdAp3rDwrE5Lc1NQlQaxR5Gnb2NZApDORRZIVlNv2WUdi9QvM0yCzjQ90jP0OAogHhRYaxg0/vgNEye46h+PiY0CAwEAAaNQME4wHQYDVR0OBBYEFEVkjcLAITndky090Ay74QqCmQKIMB8GA1UdIwQYMBaAFEVkjcLAITndky090Ay74QqCmQKIMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAG4lYX3KQXenez4LpDnZhcFBEZi9YstUKPF5EKd+WplpVbcTQc1A3/Z+uHRmyV8h+pQzeF6Liob37G87YpacPplJI66cf2Rj7j8hSBNbdr+66E2qpcEhAF1iJmzBNyhb/ydlEuVpn8/EsoP+HvBeiDl5gon3562MzZIgV/pLdTfxHyW6hzAQhjGq2UhcvR+gXNVJvHP2eS4jlHnJkB9bfo0kvf87Q+D6XKX3q5c3mO8tqW6UpqHSC+uLEpzZiNLeuFa4TUIhgBgjDjlRrNDKu8ndancSn3yBHYnqJ2t9cR+coFnnjYABQpNrvk4mtmXY8SXoBzYG9Y+lqeAun6+0YyE=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat><SingleLogoutService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://sp/slo"></SingleLogoutService><AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sp/acs"></AssertionConsumerService></SPSSODescriptor></EntityDescriptor>');
    });
    ava_1.default('sp metadata with shibboleth elements order', function (t) {
        var spToShib = serviceProvider(lodash_1.assign(baseConfig, { elementsOrder: ref.elementsOrder.shibboleth }));
        t.is(spToShib.getMetadata(), '<EntityDescriptor entityID="http://sp" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:assertion="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIDozCCAougAwIBAgIJAKNsmL8QbfpwMA0GCSqGSIb3DQEBCwUAMGgxCzAJBgNVBAYTAkhLMRIwEAYDVQQIDAlIb25nIEtvbmcxCzAJBgNVBAcMAkhLMRMwEQYDVQQKDApub2RlLXNhbWwyMSMwIQYJKoZIhvcNAQkBFhRub2RlLnNhbWwyQGdtYWlsLmNvbTAeFw0xNTA3MDUxNzU2NDdaFw0xODA3MDQxNzU2NDdaMGgxCzAJBgNVBAYTAkhLMRIwEAYDVQQIDAlIb25nIEtvbmcxCzAJBgNVBAcMAkhLMRMwEQYDVQQKDApub2RlLXNhbWwyMSMwIQYJKoZIhvcNAQkBFhRub2RlLnNhbWwyQGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQJAB8JrsLQbUuJa8akzLqO1EZqClS0tQp+w+5wgufp07WwGn/shma8dcQNj1dbjszI5HBeVFjOKIxlfjmNB9ovhQPstBjP/UPQYp1Ip2IoHCYX9HDgMz3xyXKbHthUzZaECz+p+7WtgwhczRkBLDOm2k15qhPYGPw0vH2zbVRGWUBS9dy2Mp3tqlVbP0xZ9CDNkhCJkV9SMNfoCVW/VYPqK2QBo7ki4obm5x5ixFQSSHsKbVARVzyQH5iNjFe1TdAp3rDwrE5Lc1NQlQaxR5Gnb2NZApDORRZIVlNv2WUdi9QvM0yCzjQ90jP0OAogHhRYaxg0/vgNEye46h+PiY0CAwEAAaNQME4wHQYDVR0OBBYEFEVkjcLAITndky090Ay74QqCmQKIMB8GA1UdIwQYMBaAFEVkjcLAITndky090Ay74QqCmQKIMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAG4lYX3KQXenez4LpDnZhcFBEZi9YstUKPF5EKd+WplpVbcTQc1A3/Z+uHRmyV8h+pQzeF6Liob37G87YpacPplJI66cf2Rj7j8hSBNbdr+66E2qpcEhAF1iJmzBNyhb/ydlEuVpn8/EsoP+HvBeiDl5gon3562MzZIgV/pLdTfxHyW6hzAQhjGq2UhcvR+gXNVJvHP2eS4jlHnJkB9bfo0kvf87Q+D6XKX3q5c3mO8tqW6UpqHSC+uLEpzZiNLeuFa4TUIhgBgjDjlRrNDKu8ndancSn3yBHYnqJ2t9cR+coFnnjYABQpNrvk4mtmXY8SXoBzYG9Y+lqeAun6+0YyE=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><SingleLogoutService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://sp/slo"></SingleLogoutService><NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat><AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sp/acs"></AssertionConsumerService></SPSSODescriptor></EntityDescriptor>');
    });
})();
ava_1.default('verify time', function (t) {
    var now = new Date();
    var timeBefore5Mins = new Date(new Date().setMinutes(now.getMinutes() - 5)).toISOString();
    var timeAfter5Mins = new Date(new Date().setMinutes(now.getMinutes() + 5)).toISOString();
    t.true(validator_1.verifyTime(timeBefore5Mins, timeAfter5Mins));
    t.false(validator_1.verifyTime(undefined, timeBefore5Mins));
    t.false(validator_1.verifyTime(timeAfter5Mins));
    t.true(validator_1.verifyTime());
});
ava_1.default('metadata with multiple entity descriptors is invalid', function (t) {
    try {
        identityProvider(__assign({}, defaultIdpConfig, { metadata: fs_1.readFileSync('./test/misc/multiple_entitydescriptor.xml') }));
        t.fail();
    }
    catch (_a) {
        var message = _a.message;
        t.is(message, 'ERR_MULTIPLE_METADATA_ENTITYDESCRIPTOR');
    }
});
ava_1.default('undefined x509 key in metadata should return null', function (t) {
    t.is(idp.entityMeta.getX509Certificate('undefined'), null);
    t.is(sp.entityMeta.getX509Certificate('undefined'), null);
});
ava_1.default('get name id format in metadata', function (t) {
    t.is(sp.entityMeta.getNameIDFormat(), 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
    t.is(Array.isArray(idp.entityMeta.getNameIDFormat()), true);
});
ava_1.default('get entity setting', function (t) {
    t.is(typeof idp.getEntitySetting(), 'object');
    t.is(typeof sp.getEntitySetting(), 'object');
});
ava_1.default('contains shared certificate for both signing and encryption in metadata', function (t) {
    var metadata = idpMetadata(fs_1.readFileSync('./test/misc/idpmeta_share_cert.xml'));
    var signingCertificate = metadata.getX509Certificate('signing');
    var encryptionCertificate = metadata.getX509Certificate('encryption');
    t.not(signingCertificate, null);
    t.not(encryptionCertificate, null);
    t.is(signingCertificate, encryptionCertificate);
});
ava_1.default('contains explicit certificate declaration for signing and encryption in metadata', function (t) {
    var signingCertificate = IdPMetadata.getX509Certificate('signing');
    var encryptionCertificate = IdPMetadata.getX509Certificate('encryption');
    t.not(signingCertificate, null);
    t.not(encryptionCertificate, null);
    t.not(signingCertificate, encryptionCertificate);
});
//# sourceMappingURL=index.js.map