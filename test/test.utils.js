"use strict";

var _utils = require("../lib/utils.js");

var _utils2 = _interopRequireDefault(_utils);

var _assert = require("assert");

var _assert2 = _interopRequireDefault(_assert);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

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

var assert = _assert2.default;
var utils = _utils2.default;

describe('Utils', function () {

    it('should not extend functions on the prototype', function () {

        var object = {
            property: 'test'
        };

        /* jshint ignore:start */
        Object.prototype.entries = function () {};
        /* jshint ignore:end */

        var newObject = utils.extend({}, object);

        assert.equal('entries' in newObject, true);
        assert.equal(newObject.hasOwnProperty('entries'), false);

        assert.equal('property' in newObject, true);
        assert.equal(newObject.hasOwnProperty('property'), true);

        delete Object.prototype.entries;
    });
});