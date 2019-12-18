"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// This test file includes all the units related to the extractor
var ava_1 = require("ava");
var esaml2 = require("../index");
var fs_1 = require("fs");
var extractor_1 = require("../src/extractor");
var libsaml = esaml2.SamlLib, spMetadata = esaml2.SPMetadata;
var _decodedResponse = String(fs_1.readFileSync('./test/misc/response_signed.xml'));
var _spmeta = String(fs_1.readFileSync('./test/misc/spmeta.xml'));
(function () {
    ava_1.default('fetch multiple attributes', function (t) {
        var result = extractor_1.extract(_decodedResponse, [
            {
                key: 'response',
                localPath: ['Response'],
                attributes: ['ID', 'Destination']
            }
        ]);
        t.is(result.response.id, '_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6');
        t.is(result.response.destination, 'http://sp.example.com/demo1/index.php?acs');
    });
    ava_1.default('fetch single attributes', function (t) {
        var result = extractor_1.extract(_decodedResponse, [
            {
                key: 'statusCode',
                localPath: ['Response', 'Status', 'StatusCode'],
                attributes: ['Value'],
            }
        ]);
        t.is(result.statusCode, 'urn:oasis:names:tc:SAML:2.0:status:Success');
    });
    ava_1.default('fetch the inner context of leaf node', function (t) {
        var result = extractor_1.extract(_decodedResponse, [
            {
                key: 'audience',
                localPath: ['Response', 'Assertion', 'Conditions', 'AudienceRestriction', 'Audience'],
                attributes: []
            }
        ]);
        t.is(result.audience, 'https://sp.example.com/metadata');
    });
    ava_1.default('fetch the entire context of a non-existing node ', function (t) {
        var result = extractor_1.extract(_decodedResponse, [
            {
                key: 'assertionSignature',
                localPath: ['Response', 'Assertion', 'Signature'],
                attributes: [],
                context: true
            }
        ]);
        t.is(result.assertionSignature, null);
    });
    ava_1.default('fetch the entire context of an existed node', function (t) {
        var result = extractor_1.extract(_decodedResponse, [
            {
                key: 'messageSignature',
                localPath: ['Response', 'Signature'],
                attributes: [],
                context: true
            }
        ]);
        t.not(result.messageSignature, null);
    });
    ava_1.default('fetch the unique inner context of multiple nodes', function (t) {
        var result = extractor_1.extract(_decodedResponse, [
            {
                key: 'issuer',
                localPath: [
                    ['Response', 'Issuer'],
                    ['Response', 'Assertion', 'Issuer']
                ],
                attributes: []
            }
        ]);
        t.is(result.issuer.length, 1);
        t.is(result.issuer.every(function (i) { return i === 'https://idp.example.com/metadata'; }), true);
    });
    ava_1.default('fetch the attribute with wildcard local path', function (t) {
        var result = extractor_1.extract(_spmeta, [
            {
                key: 'certificate',
                localPath: ['EntityDescriptor', '~SSODescriptor', 'KeyDescriptor'],
                index: ['use'],
                attributePath: ['KeyInfo', 'X509Data', 'X509Certificate'],
                attributes: []
            }
        ]);
        t.not(result.certificate.signing, null);
        t.not(result.certificate.encryption, null);
    });
    ava_1.default('fetch the attribute with non-wildcard local path', function (t) {
        var result = extractor_1.extract(_decodedResponse, [
            {
                key: 'attributes',
                localPath: ['Response', 'Assertion', 'AttributeStatement', 'Attribute'],
                index: ['Name'],
                attributePath: ['AttributeValue'],
                attributes: []
            }
        ]);
        t.is(result.attributes.uid, 'test');
        t.is(result.attributes.mail, 'test@example.com');
        t.is(result.attributes.eduPersonAffiliation.length, 2);
    });
    ava_1.default('fetch with one attribute as key, another as value', function (t) {
        var result = extractor_1.extract(_spmeta, [
            {
                key: 'singleSignOnService',
                localPath: ['EntityDescriptor', '~SSODescriptor', 'AssertionConsumerService'],
                index: ['Binding'],
                attributePath: [],
                attributes: ['Location']
            }
        ]);
        var postEndpoint = result.singleSignOnService['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'];
        var artifactEndpoint = result.singleSignOnService['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'];
        t.is(postEndpoint, 'https://sp.example.org/sp/sso');
        t.is(artifactEndpoint, 'https://sp.example.org/sp/sso');
    });
})();
//# sourceMappingURL=extractor.js.map