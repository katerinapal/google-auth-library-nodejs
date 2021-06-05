"use strict";

var _assert = require("assert");

var _assert2 = _interopRequireDefault(_assert);

var _fs = require("fs");

var _fs2 = _interopRequireDefault(_fs);

var _googleauth = require("../lib/auth/googleauth.js");

var _jws = require("jws");

var _jws2 = _interopRequireDefault(_jws);

var _keypair = require("keypair");

var _keypair2 = _interopRequireDefault(_keypair);

var _nock = require("nock");

var _nock2 = _interopRequireDefault(_nock);

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

// Creates a standard JSON credentials object for testing.
function createJSON() {
  return {
    'private_key_id': 'key123',
    'private_key': 'privatekey',
    'client_email': 'hello@youarecool.com',
    'client_id': 'client123',
    'type': 'service_account'
  };
}

describe('Initial credentials', function () {

  it('should create a dummy refresh token string', function () {
    // It is important that the compute client is created with a refresh token value filled
    // in, or else the rest of the logic will not work.
    var auth = new _googleauth.GoogleAuth();
    var jwt = new auth.JWT();
    _assert2.default.equal('jwt-placeholder', jwt.credentials.refresh_token);
  });
});

describe('JWT auth client', function () {

  describe('.authorize', function () {

    it('should get an initial access token', function (done) {
      var auth = new _googleauth.GoogleAuth();
      var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');
      jwt.gToken = function (opts) {
        _assert2.default.equal('foo@serviceaccount.com', opts.iss);
        _assert2.default.equal('/path/to/key.pem', opts.keyFile);
        _assert2.default.deepEqual(['http://bar', 'http://foo'], opts.scope);
        _assert2.default.equal('bar@subjectaccount.com', opts.sub);
        return {
          key: 'private-key-data',
          iss: 'foo@subjectaccount.com',
          getToken: function getToken(opt_callback) {
            return opt_callback(null, 'initial-access-token');
          }
        };
      };
      jwt.authorize(function () {
        _assert2.default.equal('initial-access-token', jwt.credentials.access_token);
        _assert2.default.equal('jwt-placeholder', jwt.credentials.refresh_token);
        _assert2.default.equal('private-key-data', jwt.key);
        _assert2.default.equal('foo@subjectaccount.com', jwt.email);
        done();
      });
    });

    it('should accept scope as string', function (done) {
      var auth = new _googleauth.GoogleAuth();
      var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, 'http://foo', 'bar@subjectaccount.com');

      jwt.gToken = function (opts) {
        _assert2.default.equal('http://foo', opts.scope);
        done();
        return {
          getToken: function getToken() {}
        };
      };

      jwt.authorize();
    });
  });

  describe('.getAccessToken', function () {

    describe('when scopes are set', function () {

      it('can get obtain new access token', function (done) {
        var auth = new _googleauth.GoogleAuth();
        var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

        jwt.credentials = {
          refresh_token: 'jwt-placeholder'
        };

        var want = 'abc123';
        jwt.gtoken = {
          getToken: function getToken(callback) {
            return callback(null, want);
          }
        };

        jwt.getAccessToken(function (err, got) {
          _assert2.default.strictEqual(null, err, 'no error was expected: got\n' + err);
          _assert2.default.strictEqual(want, got, 'the access token was wrong: ' + got);
          done();
        });
      });
    });
  });

  describe('.getRequestMetadata', function () {

    describe('when scopes are set', function () {

      it('can obtain new access token', function (done) {
        var auth = new _googleauth.GoogleAuth();
        var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

        jwt.credentials = {
          refresh_token: 'jwt-placeholder'
        };

        var wanted_token = 'abc123';
        jwt.gtoken = {
          getToken: function getToken(callback) {
            return callback(null, wanted_token);
          }
        };
        var want = 'Bearer ' + wanted_token;
        var retValue = 'dummy';
        var unusedUri = null;
        var res = jwt.getRequestMetadata(unusedUri, function (err, got) {
          _assert2.default.strictEqual(null, err, 'no error was expected: got\n' + err);
          _assert2.default.strictEqual(want, got.Authorization, 'the authorization header was wrong: ' + got.Authorization);
          done();
          return retValue;
        });
        _assert2.default.strictEqual(res, retValue);
      });
    });

    describe('when scopes are not set, but a uri is provided', function () {

      it('gets a jwt header access token', function (done) {
        var keys = (0, _keypair2.default)(1024 /* bitsize of private key */);
        var email = 'foo@serviceaccount.com';
        var auth = new _googleauth.GoogleAuth();
        var jwt = new auth.JWT('foo@serviceaccount.com', null, keys['private'], null, 'ignored@subjectaccount.com');

        jwt.credentials = {
          refresh_token: 'jwt-placeholder'
        };

        var testUri = 'http:/example.com/my_test_service';
        var retValue = 'dummy';
        var res = jwt.getRequestMetadata(testUri, function (err, got) {
          _assert2.default.strictEqual(null, err, 'no error was expected: got\n' + err);
          _assert2.default.notStrictEqual(null, got, 'the creds should be present');
          var decoded = _jws2.default.decode(got.Authorization.replace('Bearer ', ''));
          _assert2.default.strictEqual(email, decoded.payload.iss);
          _assert2.default.strictEqual(email, decoded.payload.sub);
          _assert2.default.strictEqual(testUri, decoded.payload.aud);
          done();
          return retValue;
        });
        _assert2.default.strictEqual(res, retValue);
      });
    });
  });

  describe('.request', function () {

    it('should refresh token if missing access token', function (done) {
      var auth = new _googleauth.GoogleAuth();
      var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

      jwt.credentials = {
        refresh_token: 'jwt-placeholder'
      };

      jwt.gtoken = {
        getToken: function getToken(callback) {
          callback(null, 'abc123');
        }
      };

      jwt.request({ uri: 'http://bar' }, function () {
        _assert2.default.equal('abc123', jwt.credentials.access_token);
        done();
      });
    });

    it('should refresh token if expired', function (done) {
      var auth = new _googleauth.GoogleAuth();
      var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'woot',
        refresh_token: 'jwt-placeholder',
        expiry_date: new Date().getTime() - 1000
      };

      jwt.gtoken = {
        getToken: function getToken(callback) {
          return callback(null, 'abc123');
        }
      };

      jwt.request({ uri: 'http://bar' }, function () {
        _assert2.default.equal('abc123', jwt.credentials.access_token);
        done();
      });
    });

    it('should refresh token if the server returns 403', function (done) {
      (0, _nock2.default)('http://example.com').log(console.log).get('/access').reply(403);

      var auth = new _googleauth.GoogleAuth();
      var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://example.com'], 'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'woot',
        refresh_token: 'jwt-placeholder',
        expiry_date: new Date().getTime() + 5000
      };

      jwt.gtoken = {
        getToken: function getToken(callback) {
          return callback(null, 'abc123');
        }
      };

      jwt.request({ uri: 'http://example.com/access' }, function () {
        _assert2.default.equal('abc123', jwt.credentials.access_token);
        _nock2.default.cleanAll();
        done();
      });
    });

    it('should not refresh if not expired', function (done) {
      var scope = (0, _nock2.default)('https://accounts.google.com').log(console.log).post('/o/oauth2/token', '*').reply(200, { access_token: 'abc123', expires_in: 10000 });

      var auth = new _googleauth.GoogleAuth();
      var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'jwt-placeholder',
        expiry_date: new Date().getTime() + 5000
      };

      jwt.request({ uri: 'http://bar' }, function () {
        _assert2.default.equal('initial-access-token', jwt.credentials.access_token);
        _assert2.default.equal(false, scope.isDone());
        _nock2.default.cleanAll();
        done();
      });
    });

    it('should assume access token is not expired', function (done) {
      var scope = (0, _nock2.default)('https://accounts.google.com').log(console.log).post('/o/oauth2/token', '*').reply(200, { access_token: 'abc123', expires_in: 10000 });

      var auth = new _googleauth.GoogleAuth();
      var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'jwt-placeholder'
      };

      jwt.request({ uri: 'http://bar' }, function () {
        _assert2.default.equal('initial-access-token', jwt.credentials.access_token);
        _assert2.default.equal(false, scope.isDone());
        _nock2.default.cleanAll();
        done();
      });
    });
  });

  it('should return expiry_date in milliseconds', function (done) {
    var auth = new _googleauth.GoogleAuth();
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    jwt.credentials = {
      refresh_token: 'jwt-placeholder'
    };

    var dateInMillis = new Date().getTime();

    jwt.gtoken = {
      getToken: function getToken(callback) {
        return callback(null, 'token');
      },
      expires_at: dateInMillis
    };

    jwt.refreshToken_({ uri: 'http://bar' }, function (err, creds) {
      _assert2.default.equal(dateInMillis, creds.expiry_date);
      done();
    });
  });
});

describe('.createScoped', function () {
  // set up the auth module.
  var auth;
  beforeEach(function () {
    auth = new _googleauth.GoogleAuth();
  });

  it('should clone stuff', function () {
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    var clone = jwt.createScoped('x');

    _assert2.default.equal(jwt.email, clone.email);
    _assert2.default.equal(jwt.keyFile, clone.keyFile);
    _assert2.default.equal(jwt.key, clone.key);
    _assert2.default.equal(jwt.subject, clone.subject);
  });

  it('should handle string scope', function () {
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    var clone = jwt.createScoped('newscope');
    _assert2.default.equal('newscope', clone.scopes);
  });

  it('should handle array scope', function () {
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    var clone = jwt.createScoped(['gorilla', 'chimpanzee', 'orangutan']);
    _assert2.default.equal(3, clone.scopes.length);
    _assert2.default.equal('gorilla', clone.scopes[0]);
    _assert2.default.equal('chimpanzee', clone.scopes[1]);
    _assert2.default.equal('orangutan', clone.scopes[2]);
  });

  it('should handle null scope', function () {
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    var clone = jwt.createScoped();
    _assert2.default.equal(null, clone.scopes);
  });

  it('should set scope when scope was null', function () {
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, null, 'bar@subjectaccount.com');

    var clone = jwt.createScoped('hi');
    _assert2.default.equal('hi', clone.scopes);
  });

  it('should handle nulls', function () {
    var jwt = new auth.JWT();

    var clone = jwt.createScoped('hi');
    _assert2.default.equal(jwt.email, null);
    _assert2.default.equal(jwt.keyFile, null);
    _assert2.default.equal(jwt.key, null);
    _assert2.default.equal(jwt.subject, null);
    _assert2.default.equal('hi', clone.scopes);
  });

  it('should not return the original instance', function () {
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    var clone = jwt.createScoped('hi');
    _assert2.default.notEqual(jwt, clone);
  });
});

describe('.createScopedRequired', function () {
  // set up the auth module.
  var auth;
  beforeEach(function () {
    auth = new _googleauth.GoogleAuth();
  });

  it('should return true when scopes is null', function () {
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, null, 'bar@subjectaccount.com');

    _assert2.default.equal(true, jwt.createScopedRequired());
  });

  it('should return true when scopes is an empty array', function () {
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, [], 'bar@subjectaccount.com');

    _assert2.default.equal(true, jwt.createScopedRequired());
  });

  it('should return true when scopes is an empty string', function () {
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, '', 'bar@subjectaccount.com');

    _assert2.default.equal(true, jwt.createScopedRequired());
  });

  it('should return false when scopes is a filled-in string', function () {
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, 'http://foo', 'bar@subjectaccount.com');

    _assert2.default.equal(false, jwt.createScopedRequired());
  });

  it('should return false when scopes is a filled-in array', function () {
    var auth = new _googleauth.GoogleAuth();
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    _assert2.default.equal(false, jwt.createScopedRequired());
  });

  it('should return false when scopes is not an array or a string, but can be used as a string', function () {

    var auth = new _googleauth.GoogleAuth();
    var jwt = new auth.JWT('foo@serviceaccount.com', '/path/to/key.pem', null, 2, 'bar@subjectaccount.com');

    _assert2.default.equal(false, jwt.createScopedRequired());
  });
});

describe('.fromJson', function () {
  // set up the test json and the jwt instance being tested.
  var jwt, json;
  beforeEach(function () {
    json = createJSON();
    var auth = new _googleauth.GoogleAuth();
    jwt = new auth.JWT();
  });

  it('should error on null json', function (done) {
    jwt.fromJSON(null, function (err) {
      _assert2.default.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on empty json', function (done) {
    jwt.fromJSON({}, function (err) {
      _assert2.default.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing client_email', function (done) {
    delete json.client_email;

    jwt.fromJSON(json, function (err) {
      _assert2.default.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing private_key', function (done) {
    delete json.private_key;

    jwt.fromJSON(json, function (err) {
      _assert2.default.equal(true, err instanceof Error);
      done();
    });
  });

  it('should create JWT with client_email', function (done) {
    jwt.fromJSON(json, function (err) {
      _assert2.default.equal(null, err);
      _assert2.default.equal(json.client_email, jwt.email);
      done();
    });
  });

  it('should create JWT with private_key', function (done) {
    jwt.fromJSON(json, function (err) {
      _assert2.default.equal(null, err);
      _assert2.default.equal(json.private_key, jwt.key);
      done();
    });
  });

  it('should create JWT with null scopes', function (done) {
    jwt.fromJSON(json, function (err) {
      _assert2.default.equal(null, err);
      _assert2.default.equal(null, jwt.scopes);
      done();
    });
  });

  it('should create JWT with null subject', function (done) {
    jwt.fromJSON(json, function (err) {
      _assert2.default.equal(null, err);
      _assert2.default.equal(null, jwt.subject);
      done();
    });
  });

  it('should create JWT with null keyFile', function (done) {
    jwt.fromJSON(json, function (err) {
      _assert2.default.equal(null, err);
      _assert2.default.equal(null, jwt.keyFile);
      done();
    });
  });
});

describe('.fromStream', function () {
  // set up the jwt instance being tested.
  var jwt;
  beforeEach(function () {
    var auth = new _googleauth.GoogleAuth();
    jwt = new auth.JWT();
  });

  it('should error on null stream', function (done) {
    jwt.fromStream(null, function (err) {
      _assert2.default.equal(true, err instanceof Error);
      done();
    });
  });

  it('should read the stream and create a jwt', function (done) {
    // Read the contents of the file into a json object.
    var fileContents = _fs2.default.readFileSync('./test/fixtures/private.json', 'utf-8');
    var json = JSON.parse(fileContents);

    // Now open a stream on the same file.
    var stream = _fs2.default.createReadStream('./test/fixtures/private.json');

    // And pass it into the fromStream method.
    jwt.fromStream(stream, function (err) {
      _assert2.default.equal(null, err);

      // Ensure that the correct bits were pulled from the stream.
      _assert2.default.equal(json.private_key, jwt.key);
      _assert2.default.equal(json.client_email, jwt.email);
      _assert2.default.equal(null, jwt.keyFile);
      _assert2.default.equal(null, jwt.subject);
      _assert2.default.equal(null, jwt.scope);

      done();
    });
  });
});