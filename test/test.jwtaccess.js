import ext_jws from "jws";
import ext_keypair from "keypair";
import imp_GoogleAuth from "../lib/auth/googleauth.js";
import ext_fs from "fs";
import ext_assert from "assert";
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

var assert = ext_assert;
var fs = ext_fs;
var GoogleAuth = imp_GoogleAuth;
var keypair = ext_keypair;
var jws = ext_jws;


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

describe('.getRequestMetadata', function() {

  it('create a signed JWT token as the access token', function(done) {
    var keys = keypair(1024 /* bitsize of private key */);
    var testUri = 'http:/example.com/my_test_service';
    var email = 'foo@serviceaccount.com';
    var auth = new GoogleAuth();
    var client = new auth.JWTAccess(email, keys['private']);

    var retValue = 'dummy';
    var expectAuth = function(err, creds) {
      assert.strictEqual(null, err, 'no error was expected: got\n' + err);
      assert.notStrictEqual(null, creds, 'an creds object should be present');
      var decoded = jws.decode(creds.Authorization.replace('Bearer ', ''));
      assert.strictEqual(email, decoded.payload.iss);
      assert.strictEqual(email, decoded.payload.sub);
      assert.strictEqual(testUri, decoded.payload.aud);
      done();
      return retValue;
    };
    var res = client.getRequestMetadata(testUri, expectAuth);
    assert.strictEqual(res, retValue);
  });

});

describe('.createScopedRequired', function() {

  it('should return false', function () {
    var auth = new GoogleAuth();
    var client = new auth.JWTAccess(
      'foo@serviceaccount.com',
      null);

    assert.equal(false, client.createScopedRequired());
  });

});

describe('.fromJson', function () {
  // set up the test json and the client instance being tested.
  var json, client;
  beforeEach(function() {
    json = createJSON();
    var auth = new GoogleAuth();
    client = new auth.JWTAccess();
  });

  it('should error on null json', function (done) {
    client.fromJSON(null, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on empty json', function (done) {
    client.fromJSON({}, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing client_email', function (done) {
    delete json.client_email;

    client.fromJSON(json, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing private_key', function (done) {
    delete json.private_key;

    client.fromJSON(json, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should create JWT with client_email', function (done) {
    client.fromJSON(json, function (err) {
      assert.equal(null, err);
      assert.equal(json.client_email, client.email);
      done();
    });
  });

  it('should create JWT with private_key', function (done) {
    client.fromJSON(json, function (err) {
      assert.equal(null, err);
      assert.equal(json.private_key, client.key);
      done();
    });
  });

});

describe('.fromStream', function () {
  // set up the client instance being tested.
  var client;
  beforeEach(function() {
    var auth = new GoogleAuth();
    client = new auth.JWTAccess();
  });

  it('should error on null stream', function (done) {
    client.fromStream(null, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should construct a JWT Header instance from a stream', function (done) {
    // Read the contents of the file into a json object.
    var fileContents = fs.readFileSync('./test/fixtures/private.json', 'utf-8');
    var json = JSON.parse(fileContents);

    // Now open a stream on the same file.
    var stream = fs.createReadStream('./test/fixtures/private.json');

    // And pass it into the fromStream method.
    client.fromStream(stream, function (err) {
      assert.equal(null, err);

      // Ensure that the correct bits were pulled from the stream.
      assert.equal(json.private_key, client.key);
      assert.equal(json.client_email, client.email);
      done();
    });
  });

});
