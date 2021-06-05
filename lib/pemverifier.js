'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.PemVerifier = undefined;

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var mod_PemVerifier = PemVerifier;

/**
 * Copyright 2014 Google Inc. All Rights Reserved.
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

function PemVerifier() {
  this.verify = function (pubkey, data, signature, encoding) {
    var verifier = _crypto2.default.createVerify('sha256');
    verifier.update(data);
    return verifier.verify(pubkey, signature, encoding);
  };
}

exports.PemVerifier = mod_PemVerifier;