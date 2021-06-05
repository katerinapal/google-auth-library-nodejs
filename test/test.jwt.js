import ext_assert_assert from "assert";
import ext_fs_fs from "fs";
import { GoogleAuth as googleauth_GoogleAuth } from "../lib/auth/googleauth.js";
import ext_jws_jws from "jws";
import ext_keypair_keypair from "keypair";
import ext_nock_nock from "nock";
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

ext_nock_nock.disableNetConnect();

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

describe('Initial credentials', function() {

  it('should create a dummy refresh token string', function () {
    // It is important that the compute client is created with a refresh token value filled
    // in, or else the rest of the logic will not work.
    var auth = new googleauth_GoogleAuth();
    var jwt = new auth.JWT();
    ext_assert_assert.equal('jwt-placeholder', jwt.credentials.refresh_token);
  });

});

describe('JWT auth client', function() {

  describe('.authorize', function() {

    it('should get an initial access token', function(done) {
      var auth = new googleauth_GoogleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://bar', 'http://foo'],
          'bar@subjectaccount.com');
      jwt.gToken = function(opts) {
        ext_assert_assert.equal('foo@serviceaccount.com', opts.iss);
        ext_assert_assert.equal('/path/to/key.pem', opts.keyFile);
        ext_assert_assert.deepEqual(['http://bar', 'http://foo'], opts.scope);
        ext_assert_assert.equal('bar@subjectaccount.com', opts.sub);
        return {
          key: 'private-key-data',
          iss: 'foo@subjectaccount.com',
          getToken: function(opt_callback) {
            return opt_callback(null, 'initial-access-token');
          }
        };
      };
      jwt.authorize(function() {
        ext_assert_assert.equal('initial-access-token', jwt.credentials.access_token);
        ext_assert_assert.equal('jwt-placeholder', jwt.credentials.refresh_token);
        ext_assert_assert.equal('private-key-data', jwt.key);
        ext_assert_assert.equal('foo@subjectaccount.com', jwt.email);
        done();
      });
    });

    it('should accept scope as string', function(done) {
      var auth = new googleauth_GoogleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          'http://foo',
          'bar@subjectaccount.com');

      jwt.gToken = function(opts) {
        ext_assert_assert.equal('http://foo', opts.scope);
        done();
        return {
          getToken: function() {}
        };
      };

      jwt.authorize();
    });

  });

  describe('.getAccessToken', function() {

    describe('when scopes are set', function() {

      it('can get obtain new access token', function(done) {
        var auth = new googleauth_GoogleAuth();
        var jwt = new auth.JWT(
            'foo@serviceaccount.com',
            '/path/to/key.pem',
            null,
            ['http://bar', 'http://foo'],
            'bar@subjectaccount.com');

        jwt.credentials = {
          refresh_token: 'jwt-placeholder'
        };

        var want = 'abc123';
        jwt.gtoken = {
          getToken: function(callback) {
            return callback(null, want);
          }
        };

        jwt.getAccessToken(function(err, got) {
          ext_assert_assert.strictEqual(null, err, 'no error was expected: got\n' + err);
          ext_assert_assert.strictEqual(want, got, 'the access token was wrong: ' + got);
          done();
        });
      });

    });

  });

  describe('.getRequestMetadata', function() {

    describe('when scopes are set', function() {

      it('can obtain new access token', function(done) {
        var auth = new googleauth_GoogleAuth();
        var jwt = new auth.JWT(
            'foo@serviceaccount.com',
            '/path/to/key.pem',
            null,
            ['http://bar', 'http://foo'],
            'bar@subjectaccount.com');

        jwt.credentials = {
          refresh_token: 'jwt-placeholder'
        };

        var wanted_token = 'abc123';
        jwt.gtoken = {
          getToken: function(callback) {
            return callback(null, wanted_token);
          }
        };
        var want = 'Bearer ' + wanted_token;
        var retValue = 'dummy';
        var unusedUri = null;
        var res = jwt.getRequestMetadata(unusedUri, function(err, got) {
          ext_assert_assert.strictEqual(null, err, 'no error was expected: got\n' + err);
          ext_assert_assert.strictEqual(want, got.Authorization,
                             'the authorization header was wrong: ' + got.Authorization);
          done();
          return retValue;
        });
        ext_assert_assert.strictEqual(res, retValue);
      });

    });

    describe('when scopes are not set, but a uri is provided', function() {

      it('gets a jwt header access token', function(done) {
        var keys = ext_keypair_keypair(1024 /* bitsize of private key */);
        var email = 'foo@serviceaccount.com';
        var auth = new googleauth_GoogleAuth();
        var jwt = new auth.JWT(
            'foo@serviceaccount.com',
            null,
            keys['private'],
            null,
            'ignored@subjectaccount.com');

        jwt.credentials = {
          refresh_token: 'jwt-placeholder'
        };

        var testUri = 'http:/example.com/my_test_service';
        var retValue = 'dummy';
        var res = jwt.getRequestMetadata(testUri, function(err, got) {
          ext_assert_assert.strictEqual(null, err, 'no error was expected: got\n' + err);
          ext_assert_assert.notStrictEqual(null, got, 'the creds should be present');
          var decoded = ext_jws_jws.decode(got.Authorization.replace('Bearer ', ''));
          ext_assert_assert.strictEqual(email, decoded.payload.iss);
          ext_assert_assert.strictEqual(email, decoded.payload.sub);
          ext_assert_assert.strictEqual(testUri, decoded.payload.aud);
          done();
          return retValue;
        });
        ext_assert_assert.strictEqual(res, retValue);
      });

    });

  });

  describe('.request', function() {

    it('should refresh token if missing access token', function(done) {
      var auth = new googleauth_GoogleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://bar', 'http://foo'],
          'bar@subjectaccount.com');

      jwt.credentials = {
        refresh_token: 'jwt-placeholder'
      };

      jwt.gtoken = {
        getToken: function(callback) {
          callback(null, 'abc123');
        }
      };

      jwt.request({ uri : 'http://bar' }, function() {
        ext_assert_assert.equal('abc123', jwt.credentials.access_token);
        done();
      });
    });

    it('should refresh token if expired', function(done) {
      var auth = new googleauth_GoogleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://bar', 'http://foo'],
          'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'woot',
        refresh_token: 'jwt-placeholder',
        expiry_date: (new Date()).getTime() - 1000
      };

      jwt.gtoken = {
        getToken: function(callback) {
          return callback(null, 'abc123');
        }
      };

      jwt.request({ uri : 'http://bar' }, function() {
        ext_assert_assert.equal('abc123', jwt.credentials.access_token);
        done();
      });
    });

    it('should refresh token if the server returns 403', function(done) {
      ext_nock_nock('http://example.com')
          .log(console.log)
          .get('/access')
          .reply(403);

      var auth = new googleauth_GoogleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://example.com'],
          'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'woot',
        refresh_token: 'jwt-placeholder',
        expiry_date: (new Date()).getTime() + 5000
      };

      jwt.gtoken = {
        getToken: function(callback) {
          return callback(null, 'abc123');
        }
      };

      jwt.request({ uri : 'http://example.com/access' }, function() {
        ext_assert_assert.equal('abc123', jwt.credentials.access_token);
        ext_nock_nock.cleanAll();
        done();
      });
    });

    it('should not refresh if not expired', function(done) {
      var scope = ext_nock_nock('https://accounts.google.com')
          .log(console.log)
          .post('/o/oauth2/token', '*')
          .reply(200, { access_token: 'abc123', expires_in: 10000 });

      var auth = new googleauth_GoogleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://bar', 'http://foo'],
          'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'jwt-placeholder',
        expiry_date: (new Date()).getTime() + 5000
      };

      jwt.request({ uri : 'http://bar' }, function() {
        ext_assert_assert.equal('initial-access-token', jwt.credentials.access_token);
        ext_assert_assert.equal(false, scope.isDone());
        ext_nock_nock.cleanAll();
        done();
      });
    });

    it('should assume access token is not expired', function(done) {
      var scope = ext_nock_nock('https://accounts.google.com')
          .log(console.log)
          .post('/o/oauth2/token', '*')
          .reply(200, { access_token: 'abc123', expires_in: 10000 });

      var auth = new googleauth_GoogleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://bar', 'http://foo'],
          'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'jwt-placeholder'
      };

      jwt.request({ uri : 'http://bar' }, function() {
        ext_assert_assert.equal('initial-access-token', jwt.credentials.access_token);
        ext_assert_assert.equal(false, scope.isDone());
        ext_nock_nock.cleanAll();
        done();
      });
    });

  });

  it('should return expiry_date in milliseconds', function(done) {
    var auth = new googleauth_GoogleAuth();
    var jwt = new auth.JWT(
        'foo@serviceaccount.com',
        '/path/to/key.pem',
        null,
        ['http://bar', 'http://foo'],
        'bar@subjectaccount.com');

    jwt.credentials = {
      refresh_token: 'jwt-placeholder'
    };

    var dateInMillis = (new Date()).getTime();

    jwt.gtoken = {
      getToken: function(callback) {
        return callback(null, 'token');
      },
      expires_at: dateInMillis
    };

    jwt.refreshToken_({ uri : 'http://bar' }, function(err, creds) {
      ext_assert_assert.equal(dateInMillis, creds.expiry_date);
      done();
    });
  });

});

describe('.createScoped', function() {
  // set up the auth module.
  var auth;
  beforeEach(function() {
    auth = new googleauth_GoogleAuth();
  });

  it('should clone stuff', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    var clone = jwt.createScoped('x');

    ext_assert_assert.equal(jwt.email, clone.email);
    ext_assert_assert.equal(jwt.keyFile, clone.keyFile);
    ext_assert_assert.equal(jwt.key, clone.key);
    ext_assert_assert.equal(jwt.subject, clone.subject);
  });

  it('should handle string scope', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    var clone = jwt.createScoped('newscope');
    ext_assert_assert.equal('newscope', clone.scopes);
  });

  it('should handle array scope', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    var clone = jwt.createScoped(['gorilla', 'chimpanzee', 'orangutan']);
    ext_assert_assert.equal(3, clone.scopes.length);
    ext_assert_assert.equal('gorilla', clone.scopes[0]);
    ext_assert_assert.equal('chimpanzee', clone.scopes[1]);
    ext_assert_assert.equal('orangutan', clone.scopes[2]);
  });

  it('should handle null scope', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    var clone = jwt.createScoped();
    ext_assert_assert.equal(null, clone.scopes);
  });

  it('should set scope when scope was null', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      null,
      'bar@subjectaccount.com');

    var clone = jwt.createScoped('hi');
    ext_assert_assert.equal('hi', clone.scopes);
  });

  it('should handle nulls', function() {
    var jwt = new auth.JWT();

    var clone = jwt.createScoped('hi');
    ext_assert_assert.equal(jwt.email, null);
    ext_assert_assert.equal(jwt.keyFile, null);
    ext_assert_assert.equal(jwt.key, null);
    ext_assert_assert.equal(jwt.subject, null);
    ext_assert_assert.equal('hi', clone.scopes);
  });

  it('should not return the original instance', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    var clone = jwt.createScoped('hi');
    ext_assert_assert.notEqual(jwt, clone);
  });

});

describe('.createScopedRequired', function() {
  // set up the auth module.
  var auth;
  beforeEach(function() {
    auth = new googleauth_GoogleAuth();
  });

  it('should return true when scopes is null', function () {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      null,
      'bar@subjectaccount.com');

    ext_assert_assert.equal(true, jwt.createScopedRequired());
  });

  it('should return true when scopes is an empty array', function () {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      [],
      'bar@subjectaccount.com');

    ext_assert_assert.equal(true, jwt.createScopedRequired());
  });

  it('should return true when scopes is an empty string', function () {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      '',
      'bar@subjectaccount.com');

    ext_assert_assert.equal(true, jwt.createScopedRequired());
  });

  it('should return false when scopes is a filled-in string', function () {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      'http://foo',
      'bar@subjectaccount.com');

    ext_assert_assert.equal(false, jwt.createScopedRequired());
  });

  it('should return false when scopes is a filled-in array', function () {
    var auth = new googleauth_GoogleAuth();
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    ext_assert_assert.equal(false, jwt.createScopedRequired());
  });

  it('should return false when scopes is not an array or a string, but can be used as a string',
    function () {

      var auth = new googleauth_GoogleAuth();
      var jwt = new auth.JWT(
        'foo@serviceaccount.com',
        '/path/to/key.pem',
        null,
        2,
        'bar@subjectaccount.com');

      ext_assert_assert.equal(false, jwt.createScopedRequired());
    });
});

describe('.fromJson', function () {
  // set up the test json and the jwt instance being tested.
  var jwt, json;
  beforeEach(function() {
    json = createJSON();
    var auth = new googleauth_GoogleAuth();
    jwt = new auth.JWT();
  });

  it('should error on null json', function (done) {
    jwt.fromJSON(null, function (err) {
      ext_assert_assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on empty json', function (done) {
    jwt.fromJSON({}, function (err) {
      ext_assert_assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing client_email', function (done) {
    delete json.client_email;

    jwt.fromJSON(json, function (err) {
      ext_assert_assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing private_key', function (done) {
    delete json.private_key;

    jwt.fromJSON(json, function (err) {
      ext_assert_assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should create JWT with client_email', function (done) {
    jwt.fromJSON(json, function (err) {
      ext_assert_assert.equal(null, err);
      ext_assert_assert.equal(json.client_email, jwt.email);
      done();
    });
  });

  it('should create JWT with private_key', function (done) {
    jwt.fromJSON(json, function (err) {
      ext_assert_assert.equal(null, err);
      ext_assert_assert.equal(json.private_key, jwt.key);
      done();
    });
  });

  it('should create JWT with null scopes', function (done) {
    jwt.fromJSON(json, function (err) {
      ext_assert_assert.equal(null, err);
      ext_assert_assert.equal(null, jwt.scopes);
      done();
    });
  });

  it('should create JWT with null subject', function (done) {
    jwt.fromJSON(json, function (err) {
      ext_assert_assert.equal(null, err);
      ext_assert_assert.equal(null, jwt.subject);
      done();
    });
  });

  it('should create JWT with null keyFile', function (done) {
    jwt.fromJSON(json, function (err) {
      ext_assert_assert.equal(null, err);
      ext_assert_assert.equal(null, jwt.keyFile);
      done();
    });
  });

});

describe('.fromStream', function () {
  // set up the jwt instance being tested.
  var jwt;
  beforeEach(function() {
    var auth = new googleauth_GoogleAuth();
    jwt = new auth.JWT();
  });

  it('should error on null stream', function (done) {
    jwt.fromStream(null, function (err) {
      ext_assert_assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should read the stream and create a jwt', function (done) {
    // Read the contents of the file into a json object.
    var fileContents = ext_fs_fs.readFileSync('./test/fixtures/private.json', 'utf-8');
    var json = JSON.parse(fileContents);

    // Now open a stream on the same file.
    var stream = ext_fs_fs.createReadStream('./test/fixtures/private.json');

    // And pass it into the fromStream method.
    jwt.fromStream(stream, function (err) {
      ext_assert_assert.equal(null, err);

      // Ensure that the correct bits were pulled from the stream.
      ext_assert_assert.equal(json.private_key, jwt.key);
      ext_assert_assert.equal(json.client_email, jwt.email);
      ext_assert_assert.equal(null, jwt.keyFile);
      ext_assert_assert.equal(null, jwt.subject);
      ext_assert_assert.equal(null, jwt.scope);

      done();
    });
  });

});
