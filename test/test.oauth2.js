"use strict";

var _url = require("url");

var _url2 = _interopRequireDefault(_url);

var _assert = require("assert");

var _assert2 = _interopRequireDefault(_assert);

var _querystring = require("querystring");

var _querystring2 = _interopRequireDefault(_querystring);

var _fs = require("fs");

var _fs2 = _interopRequireDefault(_fs);

var _googleauth = require("../lib/auth/googleauth.js");

var _crypto = require("crypto");

var _crypto2 = _interopRequireDefault(_crypto);

var _nock = require("nock");

var _nock2 = _interopRequireDefault(_nock);

var _authclient = require("../lib/auth/authclient.js");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

_nock2.default.disableNetConnect();

describe('OAuth2 client', function () {

  var CLIENT_ID = 'CLIENT_ID';
  var CLIENT_SECRET = 'CLIENT_SECRET';
  var REDIRECT_URI = 'REDIRECT';
  var ACCESS_TYPE = 'offline';
  var SCOPE = 'scopex';
  var SCOPE_ARRAY = ['scopex', 'scopey'];

  it('should generate a valid consent page url', function (done) {
    var opts = {
      access_type: ACCESS_TYPE,
      scope: SCOPE,
      response_type: 'code token'
    };

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    var generated = oauth2client.generateAuthUrl(opts);
    var parsed = _url2.default.parse(generated);
    var query = _querystring2.default.parse(parsed.query);

    _assert2.default.equal(query.response_type, 'code token');
    _assert2.default.equal(query.access_type, ACCESS_TYPE);
    _assert2.default.equal(query.scope, SCOPE);
    _assert2.default.equal(query.client_id, CLIENT_ID);
    _assert2.default.equal(query.redirect_uri, REDIRECT_URI);
    done();
  });

  it('should throw if using AuthClient directly', function () {
    var authClient = new _authclient.AuthClient();
    _assert2.default.throws(function () {
      authClient.request();
    }, 'Not implemented yet.');
  });

  it('should allow scopes to be specified as array', function (done) {
    var opts = {
      access_type: ACCESS_TYPE,
      scope: SCOPE_ARRAY,
      response_type: 'code token'
    };

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    var generated = oauth2client.generateAuthUrl(opts);
    var parsed = _url2.default.parse(generated);
    var query = _querystring2.default.parse(parsed.query);

    _assert2.default.equal(query.scope, SCOPE_ARRAY.join(' '));
    done();
  });

  it('should set response_type param to code if none is given while' + 'generating the consent page url', function (done) {
    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    var generated = oauth2client.generateAuthUrl();
    var parsed = _url2.default.parse(generated);
    var query = _querystring2.default.parse(parsed.query);

    _assert2.default.equal(query.response_type, 'code');
    done();
  });

  // jason: keep
  /*
  it('should return err no access or refresh token is set before making a request', function(done) {
    var auth = new GoogleAuth();
    var oauth2client = new googleapis.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    new googleapis.GoogleApis()
      .urlshortener('v1').url.get({ shortUrl: '123', auth: oauth2client }, function(err, result) {
        assert.equal(err.message, 'No access or refresh token is set.');
        assert.equal(result, null);
        done();
      });
  });
  
  it('should not throw any exceptions if only refresh token is set', function() {
    var oauth2client = new googleapis.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    oauth2client.credentials = { refresh_token: 'refresh_token' };
    assert.doesNotThrow(function() {
      var google = new googleapis.GoogleApis();
      var options = { auth: oauth2client, shortUrl: '...' };
      google.urlshortener('v1').url.get(options, noop);
    });
  });
    it('should set access token type to Bearer if none is set', function(done) {
    var oauth2client = new googleapis.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    oauth2client.credentials = { access_token: 'foo', refresh_token: '' };
      var scope = nock('https://www.googleapis.com').get('/urlshortener/v1/url/history').reply(200);
      var google = new googleapis.GoogleApis();
    var urlshortener = google.urlshortener('v1');
    urlshortener.url.list({ auth: oauth2client }, function(err) {
      assert.equal(oauth2client.credentials.token_type, 'Bearer');
      scope.done();
      done(err);
    });
  });
  */

  it('should verify a valid certificate against a jwt', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + maxLifetimeSecs / 2;

    var idToken = '{' + '"iss":"testissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + now + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    var login = oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience');

    _assert2.default.equal(login.getUserId(), '123456789');
    done();
  });

  it('should fail due to invalid audience', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + maxLifetimeSecs / 2;

    var idToken = '{' + '"iss":"testissuer",' + '"aud":"wrongaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + now + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience');
    }, /Wrong recipient/);
    done();
  });

  it('should fail due to invalid array of audiences', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + maxLifetimeSecs / 2;

    var idToken = '{' + '"iss":"testissuer",' + '"aud":"wrongaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + now + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var validAudiences = ['testaudience', 'extra-audience'];
    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, validAudiences);
    }, /Wrong recipient/);
    done();
  });

  it('should fail due to invalid signature', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var idToken = '{' + '"iss":"testissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":1393241597,' + '"exp":1393245497' + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    //Originally: data += '.'+signature;
    data += signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience');
    }, /Wrong number of segments/);

    done();
  });

  it('should fail due to invalid envelope', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + maxLifetimeSecs / 2;

    var idToken = '{' + '"iss":"testissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + now + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid"' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience');
    }, /Can\'t parse token envelope/);

    done();
  });

  it('should fail due to invalid payload', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + maxLifetimeSecs / 2;

    var idToken = '{' + '"iss":"testissuer"' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + now + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience');
    }, /Can\'t parse token payload/);

    done();
  });

  it('should fail due to invalid signature', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + maxLifetimeSecs / 2;

    var idToken = '{' + '"iss":"testissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + now + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64') + '.' + 'broken-signature';

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience');
    }, /Invalid token signature/);

    done();
  });

  it('should fail due to no expiration date', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var now = new Date().getTime() / 1000;

    var idToken = '{' + '"iss":"testissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + now + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience');
    }, /No expiration time/);

    done();
  });

  it('should fail due to no issue time', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + maxLifetimeSecs / 2;

    var idToken = '{' + '"iss":"testissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience');
    }, /No issue time/);

    done();
  });

  it('should fail due to certificate with expiration date in future', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + 2 * maxLifetimeSecs;
    var idToken = '{' + '"iss":"testissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + now + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience');
    }, /Expiration time too far in future/);

    done();
  });

  it('should pass due to expiration date in future with adjusted max expiry', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + 2 * maxLifetimeSecs;
    var maxExpiry = 3 * maxLifetimeSecs;
    var idToken = '{' + '"iss":"testissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + now + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience', ['testissuer'], maxExpiry);

    done();
  });

  it('should fail due to token being used to early', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var clockSkews = 300;
    var now = new Date().getTime() / 1000;
    var expiry = now + maxLifetimeSecs / 2;
    var issueTime = now + clockSkews * 2;
    var idToken = '{' + '"iss":"testissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + issueTime + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience');
    }, /Token used too early/);

    done();
  });

  it('should fail due to token being used to late', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var clockSkews = 300;
    var now = new Date().getTime() / 1000;
    var expiry = now - maxLifetimeSecs / 2;
    var issueTime = now - clockSkews * 2;
    var idToken = '{' + '"iss":"testissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + issueTime + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience');
    }, /Token used too late/);

    done();
  });

  it('should fail due to invalid issuer', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + maxLifetimeSecs / 2;
    var idToken = '{' + '"iss":"invalidissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + now + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    _assert2.default.throws(function () {
      oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience', ['testissuer']);
    }, /Invalid issuer/);

    done();
  });

  it('should pass due to valid issuer', function (done) {
    var publicKey = _fs2.default.readFileSync('./test/fixtures/public.pem', 'utf-8');
    var privateKey = _fs2.default.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + maxLifetimeSecs / 2;
    var idToken = '{' + '"iss":"testissuer",' + '"aud":"testaudience",' + '"azp":"testauthorisedparty",' + '"email_verified":"true",' + '"id":"123456789",' + '"sub":"123456789",' + '"email":"test@test.com",' + '"iat":' + now + ',' + '"exp":' + expiry + '}';
    var envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

    var data = new Buffer(envelope).toString('base64') + '.' + new Buffer(idToken).toString('base64');

    var signer = _crypto2.default.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    oauth2client.verifySignedJwtWithCerts(data, { keyid: publicKey }, 'testaudience', ['testissuer']);

    done();
  });

  it('should be able to retrieve a list of Google certificates', function (done) {
    var scope = (0, _nock2.default)('https://www.googleapis.com').get('/oauth2/v1/certs').replyWithFile(200, __dirname + '/fixtures/oauthcerts.json');
    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    oauth2client.getFederatedSignonCerts(function (err, certs) {
      _assert2.default.equal(err, null);
      _assert2.default.equal(Object.keys(certs).length, 2);
      _assert2.default.notEqual(certs.a15eea964ab9cce480e5ef4f47cb17b9fa7d0b21, null);
      _assert2.default.notEqual(certs['39596dc3a3f12aa74b481579e4ec944f86d24b95'], null);
      scope.done();
      done();
    });
  });

  it('should be able to retrieve a list of Google certificates from cache again', function (done) {
    var scope = (0, _nock2.default)('https://www.googleapis.com').defaultReplyHeaders({
      'Cache-Control': 'public, max-age=23641, must-revalidate, no-transform',
      'Content-Type': 'application/json'
    }).get('/oauth2/v1/certs').once().replyWithFile(200, __dirname + '/fixtures/oauthcerts.json');
    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    oauth2client.getFederatedSignonCerts(function (err, certs) {
      _assert2.default.equal(err, null);
      _assert2.default.equal(Object.keys(certs).length, 2);
      scope.done(); // has retrieved from nock... nock no longer will reply
      oauth2client.getFederatedSignonCerts(function (err, certs) {
        _assert2.default.equal(err, null);
        _assert2.default.equal(Object.keys(certs).length, 2);
        scope.done();
        done();
      });
    });
  });

  it('should set redirect_uri if not provided in options', function () {
    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    var generated = oauth2client.generateAuthUrl({});
    var parsed = _url2.default.parse(generated);
    var query = _querystring2.default.parse(parsed.query);
    _assert2.default.equal(query.redirect_uri, REDIRECT_URI);
  });

  it('should set client_id if not provided in options', function () {
    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    var generated = oauth2client.generateAuthUrl({});
    var parsed = _url2.default.parse(generated);
    var query = _querystring2.default.parse(parsed.query);
    _assert2.default.equal(query.client_id, CLIENT_ID);
  });

  it('should override redirect_uri if provided in options', function () {
    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    var generated = oauth2client.generateAuthUrl({ redirect_uri: 'overridden' });
    var parsed = _url2.default.parse(generated);
    var query = _querystring2.default.parse(parsed.query);
    _assert2.default.equal(query.redirect_uri, 'overridden');
  });

  it('should override client_id if provided in options', function () {
    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    var generated = oauth2client.generateAuthUrl({ client_id: 'client_override' });
    var parsed = _url2.default.parse(generated);
    var query = _querystring2.default.parse(parsed.query);
    _assert2.default.equal(query.client_id, 'client_override');
  });

  it('should return error in callback on request', function (done) {
    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    oauth2client.request({}, function (err, result) {
      _assert2.default.equal(err.message, 'No access or refresh token is set.');
      _assert2.default.equal(result, null);
      done();
    });
  });

  it('should return error in callback on refreshAccessToken', function (done) {
    var auth = new _googleauth.GoogleAuth();
    var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    oauth2client.refreshAccessToken(function (err, result) {
      _assert2.default.equal(err.message, 'No refresh token is set.');
      _assert2.default.equal(result, null);
      done();
    });
  });

  /* Jason: keep
  it('should refresh if access token is expired', function(done) {
    var scope = nock('https://accounts.google.com')
        .post('/o/oauth2/token')
        .reply(200, { access_token: 'abc123', expires_in: 1 });
    var oauth2client = new googleapis.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    var google = new googleapis.GoogleApis();
    var drive = google.drive({ version: 'v2', auth: oauth2client });
    var now = (new Date()).getTime();
    var twoSecondsAgo = now - 2000;
    oauth2client.credentials = { refresh_token: 'abc', expiry_date: twoSecondsAgo };
    drive.files.get({ fileId: 'wat' }, function() {
      var expiry_date = oauth2client.credentials.expiry_date;
      assert.notEqual(expiry_date, undefined);
      assert(expiry_date > now);
      assert(expiry_date < now + 5000);
      assert.equal(oauth2client.credentials.refresh_token, 'abc');
      assert.equal(oauth2client.credentials.access_token, 'abc123');
      assert.equal(oauth2client.credentials.token_type, 'Bearer');
      scope.done();
      done();
    });
  });
    it('should make request if access token not expired', function(done) {
    var scope = nock('https://accounts.google.com')
        .post('/o/oauth2/token')
        .reply(200, { access_token: 'abc123', expires_in: 10000 });
    var oauth2client = new googleapis.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    var google = new googleapis.GoogleApis();
    var drive = google.drive({ version: 'v2', auth: oauth2client });
    var now = (new Date()).getTime();
    var tenSecondsFromNow = now + 10000;
    oauth2client.credentials = {
      access_token: 'abc123',
      refresh_token: 'abc',
      expiry_date: tenSecondsFromNow
    };
    drive.files.get({ fileId: 'wat' }, function() {
      assert.equal(JSON.stringify(oauth2client.credentials), JSON.stringify({
        access_token: 'abc123',
        refresh_token: 'abc',
        expiry_date: tenSecondsFromNow,
        token_type: 'Bearer'
      }));
        assert.throws(function() {
        scope.done();
      }, 'AssertionError');
      nock.cleanAll();
      done();
    });
  });
    it('should refresh if have refresh token but no access token', function(done) {
    var scope = nock('https://accounts.google.com')
        .post('/o/oauth2/token')
        .reply(200, { access_token: 'abc123', expires_in: 1 });
    var oauth2client = new googleapis.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    var google = new googleapis.GoogleApis();
    var drive = google.drive({ version: 'v2', auth: oauth2client });
    var now = (new Date()).getTime();
    oauth2client.credentials = { refresh_token: 'abc' };
    drive.files.get({ fileId: 'wat' }, function() {
      var expiry_date = oauth2client.credentials.expiry_date;
      assert.notEqual(expiry_date, undefined);
      assert(expiry_date > now);
      assert(expiry_date < now + 4000);
      assert.equal(oauth2client.credentials.refresh_token, 'abc');
      assert.equal(oauth2client.credentials.access_token, 'abc123');
      assert.equal(oauth2client.credentials.token_type, 'Bearer');
      scope.done();
      done();
    });
  });
  */

  describe('revokeCredentials()', function () {
    it('should revoke credentials if access token present', function (done) {
      var scope = (0, _nock2.default)('https://accounts.google.com').get('/o/oauth2/revoke?token=abc').reply(200, { success: true });
      var auth = new _googleauth.GoogleAuth();
      var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
      oauth2client.credentials = { access_token: 'abc', refresh_token: 'abc' };
      oauth2client.revokeCredentials(function (err, result) {
        _assert2.default.equal(err, null);
        _assert2.default.equal(result.success, true);
        _assert2.default.equal(JSON.stringify(oauth2client.credentials), '{}');
        scope.done();
        done();
      });
    });

    it('should clear credentials and return error if no access token to revoke', function (done) {
      var auth = new _googleauth.GoogleAuth();
      var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
      oauth2client.credentials = { refresh_token: 'abc' };
      oauth2client.revokeCredentials(function (err, result) {
        _assert2.default.equal(err.message, 'No access token to revoke.');
        _assert2.default.equal(result, null);
        _assert2.default.equal(JSON.stringify(oauth2client.credentials), '{}');
        done();
      });
    });
  });

  describe('getToken()', function () {
    it('should return expiry_date', function (done) {
      var now = new Date().getTime();
      var scope = (0, _nock2.default)('https://accounts.google.com').post('/o/oauth2/token').reply(200, { access_token: 'abc', refresh_token: '123', expires_in: 10 });
      var auth = new _googleauth.GoogleAuth();
      var oauth2client = new auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
      oauth2client.getToken('code here', function (err, tokens) {
        (0, _assert2.default)(tokens.expiry_date >= now + 10 * 1000);
        (0, _assert2.default)(tokens.expiry_date <= now + 15 * 1000);
        scope.done();
        done();
      });
    });
  });
});