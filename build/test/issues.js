"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var esaml2 = require("../index");
var fs_1 = require("fs");
var ava_1 = require("ava");
var fs = require("fs");
var url = require("url");
var xmldom_1 = require("xmldom");
var xml_crypto_1 = require("xml-crypto");
var _ = require("lodash");
var extractor_1 = require("../src/extractor");
var identityProvider = esaml2.IdentityProvider, serviceProvider = esaml2.ServiceProvider, idpMetadata = esaml2.IdPMetadata, spMetadata = esaml2.SPMetadata, utility = esaml2.Utility, libsaml = esaml2.SamlLib, ref = esaml2.Constants;
var getQueryParamByType = libsaml.getQueryParamByType;
var wording = ref.wording;
ava_1.default('#31 query param for sso/slo is SamlRequest', function (t) {
    t.is(getQueryParamByType('SAMLRequest'), wording.urlParams.samlRequest);
    t.is(getQueryParamByType('LogoutRequest'), wording.urlParams.samlRequest);
});
ava_1.default('#31 query param for sso/slo is SamlResponse', function (t) {
    t.is(getQueryParamByType('SAMLResponse'), wording.urlParams.samlResponse);
    t.is(getQueryParamByType('LogoutResponse'), wording.urlParams.samlResponse);
});
ava_1.default('#31 query param for sso/slo returns error', function (t) {
    try {
        getQueryParamByType('samlRequest');
        t.fail();
    }
    catch (e) {
        t.pass();
    }
});
(function () {
    var spcfg = {
        entityID: 'sp.example.com',
        nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
        assertionConsumerService: [{
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                Location: 'sp.example.com/acs',
            }, {
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                Location: 'sp.example.com/acs',
            }],
        singleLogoutService: [{
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                Location: 'sp.example.com/slo',
            }, {
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                Location: 'sp.example.com/slo',
            }],
    };
    var idpcfg = {
        entityID: 'idp.example.com',
        nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
        singleSignOnService: [{
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                Location: 'idp.example.com/sso',
            }, {
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                Location: 'idp.example.com/sso',
            }],
        singleLogoutService: [{
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                Location: 'idp.example.com/sso/slo',
            }, {
                Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                Location: 'idp.example.com/sso/slo',
            }],
    };
    var idp = identityProvider(idpcfg);
    var sp = serviceProvider(spcfg);
    var spxml = sp.getMetadata();
    var idpxml = idp.getMetadata();
    var acs = extractor_1.extract(spxml, [
        {
            key: 'assertionConsumerService',
            localPath: ['EntityDescriptor', 'SPSSODescriptor', 'AssertionConsumerService'],
            attributes: ['Binding', 'Location', 'isDefault', 'index'],
        }
    ]);
    var spslo = extractor_1.extract(spxml, [
        {
            key: 'singleLogoutService',
            localPath: ['EntityDescriptor', 'SPSSODescriptor', 'SingleLogoutService'],
            attributes: ['Binding', 'Location', 'isDefault', 'index'],
        }
    ]);
    var sso = extractor_1.extract(idpxml, [
        {
            key: 'singleSignOnService',
            localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleSignOnService'],
            attributes: ['Binding', 'Location', 'isDefault', 'index'],
        }
    ]);
    var idpslo = extractor_1.extract(idpxml, [
        {
            key: 'singleLogoutService',
            localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleLogoutService'],
            attributes: ['Binding', 'Location', 'isDefault', 'index'],
        }
    ]);
    var sp98 = serviceProvider({ metadata: fs.readFileSync('./test/misc/sp_metadata_98.xml') });
    ava_1.default('#33 sp metadata acs index should be increased by 1', function (t) {
        t.is(acs.assertionConsumerService.length, 2);
        t.is(acs.assertionConsumerService[0].index, '0');
        t.is(acs.assertionConsumerService[1].index, '1');
    });
    ava_1.default('#33 sp metadata slo index should be increased by 1', function (t) {
        t.is(spslo.singleLogoutService.length, 2);
        t.is(spslo.singleLogoutService[0].index, '0');
        t.is(spslo.singleLogoutService[1].index, '1');
    });
    ava_1.default('#33 idp metadata sso index should be increased by 1', function (t) {
        t.is(sso.singleSignOnService.length, 2);
        t.is(sso.singleSignOnService[0].index, '0');
        t.is(sso.singleSignOnService[1].index, '1');
    });
    ava_1.default('#33 idp metadata slo index should be increased by 1', function (t) {
        t.is(idpslo.singleLogoutService.length, 2);
        t.is(idpslo.singleLogoutService[0].index, '0');
        t.is(idpslo.singleLogoutService[1].index, '1');
    });
    ava_1.default('#86 duplicate issuer throws error', function (t) {
        var xml = fs_1.readFileSync('./test/misc/dumpes_issuer_response.xml');
        var issuer = extractor_1.extract(xml.toString(), [{
                key: 'issuer',
                localPath: [
                    ['Response', 'Issuer'],
                    ['Response', 'Assertion', 'Issuer']
                ],
                attributes: []
            }]).issuer;
        t.is(issuer.length, 1);
        t.is(issuer.every(function (i) { return i === 'http://www.okta.com/dummyIssuer'; }), true);
    });
    ava_1.default('#87 add existence check for signature verification', function (t) {
        try {
            libsaml.verifySignature(fs_1.readFileSync('./test/misc/response.xml').toString(), {});
            t.fail();
        }
        catch (_a) {
            var message = _a.message;
            t.is(message, 'ERR_ZERO_SIGNATURE');
        }
    });
    ava_1.default('#91 idp gets single sign on service from the metadata', function (t) {
        t.is(idp.entityMeta.getSingleSignOnService('post'), 'idp.example.com/sso');
    });
    ava_1.default('#98 undefined AssertionConsumerServiceURL with redirect request', function (t) {
        var _a = sp98.createLoginRequest(idp, 'redirect'), id = _a.id, context = _a.context;
        var originalURL = url.parse(context, true);
        var request = originalURL.query.SAMLRequest;
        var rawRequest = utility.inflateString(decodeURIComponent(request));
        var xml = new xmldom_1.DOMParser().parseFromString(rawRequest);
        var authnRequest = xml_crypto_1.xpath(xml, "/*[local-name(.)='AuthnRequest']")[0];
        var acsUrl = _.find(authnRequest.attributes, function (a) { return a.nodeName === 'AssertionConsumerServiceURL'; }).nodeValue;
        t.is(acsUrl, 'https://example.org/response');
    });
})();
//# sourceMappingURL=issues.js.map