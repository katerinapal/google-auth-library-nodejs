import ext_assert_assert from "assert";
import { LoginTicket as loginticket_LoginTicket } from "../lib/auth/loginticket.js";
/**
 * Copyright 2015 Google Inc. All Rights Reserved.
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

describe('LoginTicket', function() {

  it('should return null userId even if no payload', function() {
    var ticket = new loginticket_LoginTicket(null, null);
    ext_assert_assert.equal(ticket.getUserId(), null);
  });

  it('should return envelope', function() {
    var ticket = new loginticket_LoginTicket('myenvelope');
    ext_assert_assert.equal(ticket.getEnvelope(), 'myenvelope');
  });

  it('should return attributes from getAttributes', function() {
    var ticket = new loginticket_LoginTicket('myenvelope', 'mypayload');
    ext_assert_assert.deepEqual(ticket.getAttributes(), {
      envelope: 'myenvelope',
      payload: 'mypayload'
    });

  });

});
