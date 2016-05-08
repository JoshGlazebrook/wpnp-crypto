/*
 Copyright (c) 2013 Josh Glazebrook
 Copyright (c) 2009 Michael Combs

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

/**
 Mocha tests covering everything important.
 */

var wpnp = require('../lib/wpnp-crypto');
var assert = new require('assert');

describe('WPNP Encryption', function () {
    describe('FrontCode', function () {
        describe('encryptFrontCode', function () {
            it('should return a 132 byte buffer when given a 120 byte buffer', function () {
                var buff = new Buffer(120);
                assert.strictEqual(132, wpnp.encryptFrontCode(buff).length);
            });
        });

        describe('decryptFrontCode', function () {
            it('should return a 120 byte buffer when given a 132 byte buffer', function () {
                var buff = new Buffer(132);
                assert.strictEqual(120, wpnp.decryptFrontCode(buff).length);
            });
        });

        describe('FrontCode Encryption Process', function () {
            it('should return a buffer after encryption and decryption that is equal to the original.', function () {
                var buff = new Buffer(120);
                for (var i = 0; i < 120; i++)
                    buff[i] = Math.floor(Math.random() * 256);

                var encrypted = wpnp.encryptFrontCode(buff);
                var decrypted = wpnp.decryptFrontCode(encrypted);

                assert.deepEqual(buff, decrypted);
            });
        });
    });

    describe('CryptKeys', function () {
        describe('Crypt Key Creation', function () {
            it('should create a 16 byte buffer', function () {
                var key = wpnp.createCryptKeyBlock(0x50);
                assert.strictEqual(16, key.length);
            });

        });

        describe('Crypt Key Type Validation', function () {
            it('should create a valid key block that has the given keytype embedded.', function () {
                assert.strictEqual(0x50, wpnp.getCryptKeyType(wpnp.createCryptKeyBlock(0x50)));
                assert.strictEqual(0x51, wpnp.getCryptKeyType(wpnp.createCryptKeyBlock(0x51)));
                assert.strictEqual(0x52, wpnp.getCryptKeyType(wpnp.createCryptKeyBlock(0x52)));
                assert.strictEqual(0x53, wpnp.getCryptKeyType(wpnp.createCryptKeyBlock(0x53)));
                assert.strictEqual(0x54, wpnp.getCryptKeyType(wpnp.createCryptKeyBlock(0x54)));
                assert.strictEqual(0x57, wpnp.getCryptKeyType(wpnp.createCryptKeyBlock(0x57)));
                assert.strictEqual(0x58, wpnp.getCryptKeyType(wpnp.createCryptKeyBlock(0x58)));
            });
        });

        describe('Crypt Key Mangle', function () {
            it('should not return the original key type after being run through mangle.', function () {
                var key = wpnp.createCryptKeyBlock(0x50);
                wpnp.mangle(key);
                assert.notStrictEqual(0x50, wpnp.getCryptKeyType(key));
            });

            it('should return the original key type after being run through mangle twice.', function () {
                var key = wpnp.createCryptKeyBlock(0x50);
                wpnp.mangle(key);
                wpnp.mangle(key);
                assert.strictEqual(0x50, wpnp.getCryptKeyType(key));
            });
        });

        describe('Crypt Key Extraction', function () {
            var key = new Buffer([0xB8, 0x9D, 0x3B, 0x49, 0x71, 0xD6, 0xD1, 0x35, 0x07, 0xE7, 0x20, 0xF6, 0xA0, 0x49, 0x34, 0xAF]);
            var upkey = 3605481865, downkey = 3511224208;

            it('should return a valid 0x52 crypt key type.', function () {
                assert.strictEqual(0x52, wpnp.getCryptKeyType(key));
            });

            it('should return valid up and downkeys.', function () {
                assert.strictEqual(upkey, wpnp.getCryptKey(key, false).value);
                assert.strictEqual(downkey, wpnp.getCryptKey(key, true).value);
            });
        });
    });

    describe('TCP Encryption', function () {
        describe('TCP Encryption Routine', function () {
            it('should result in the same buffer as originally created.', function (done) {
                var buff = new Buffer(1024), original = new Buffer(1024),
                    i;
                for (i = 0; i < 1024; i++)
                    buff[i] = Math.floor(Math.random() * 256);

                buff.copy(original);

                // Create 0x58 (Chat Server) key block.
                var key = wpnp.createCryptKeyBlock(0x58);

                // Server "upstream" Key
                var serverupkey = wpnp.getCryptKey(key, false);

                // Client "downstream" Key
                var clientdownkey = wpnp.getCryptKey(key, false);

                for (i = 0; i < 16; i++) {
                    wpnp.encryptMXTCP(buff, serverupkey);
                    wpnp.decryptMXTCP(buff, clientdownkey);
                }

                assert.deepEqual(original, buff);
                assert.strictEqual(serverupkey.value, clientdownkey.value);
                done();
            });
        });
    });

    describe('UDP Encryption', function () {
        describe('UDP Encryption Routine', function () {
            it('should result in the same buffer (value wise) as originally created.', function (done) {
                var buff = new Buffer(1024), original = new Buffer(1024), i;

                for (i = 0; i < 1024; i++)
                    buff[i] = Math.floor(Math.random() * 256);

                buff.copy(original);

                for (i = 0; i < 16; i++)
                    wpnp.encryptMXUDP(buff);

                for (i = 0; i < 16; i++)
                    wpnp.decryptMXUDP(buff);

                assert.deepEqual(original, buff);

                done();
            });
        });
    });

    describe('Genac Functions', function () {
        describe('Genac Validation', function () {
            it('should validate a valid genac key and invalidate an invalid genac key.', function () {


                var validgenackey = new Buffer([0x4e, 0xe7, 0x91, 0xc2, 0x95, 0x9d]);
                var invalidgenackey = new Buffer([0xe4, 0x2f, 0x33, 0x00, 0x23, 0xee]);

                assert.strictEqual(true, wpnp.validateGenacKey(validgenackey));
                assert.strictEqual(false, wpnp.validateGenacKey(invalidgenackey));
            });
        });

        describe('Genac Creation', function () {
            it('should create valid genac keys that can be verified.', function () {
                for (var i = 0; i < 16; i++) {
                    var key = wpnp.createGenacKey();
                    assert.strictEqual(true, wpnp.validateGenacKey(key));
                }
            });
        });
    });
});