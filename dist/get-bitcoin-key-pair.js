"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getBitcoinAddress = void 0;

var _require = require('crypto'),
    randomBytes = _require.randomBytes;

var secp256k1 = require('secp256k1/elliptic');

var sha256 = require('sha256');

var ByteBuffer = require('bytebuffer');

var bs58 = require('bs58');

var RIPEMD160 = require('ripemd160');

var SecureRandom = require('secure-random'); //n-1.1578*10**77
//console.log(msg);


var getBitcoinAddress = function getBitcoinAddress(_randomString) {
  var addrVer = Buffer.alloc(1, 0x00);
  var wifByte = Buffer.alloc(1, 0x80);
  var randomHexFromRandomString = sha256(_randomString);
  var randomByteFromRandomHex = Buffer.from(randomHexFromRandomString, 'hex');

  if (_randomString && secp256k1.privateKeyVerify(randomByteFromRandomHex)) {
    var publicKey = secp256k1.publicKeyCreate(randomByteFromRandomHex);
    var wifBufPriv = Buffer.concat([wifByte, randomByteFromRandomHex], wifByte.length + randomByteFromRandomHex.length);
    var wifHashFirst = sha256(wifBufPriv);
    var wifHashSecond = Buffer.from(sha256(wifHashFirst), 'hex');
    var wifHashSig = wifHashSecond.slice(0, 4);
    var wifBuf = Buffer.concat([wifBufPriv, wifHashSig], wifBufPriv.length + wifHashSig.length);
    var wifFinal = bs58.encode(wifBuf);
    var publicKeyInitialHash = sha256(Buffer.from(publicKey, 'hex'));
    var publicKeyRIPEHash = new RIPEMD160().update(Buffer.from(publicKeyInitialHash, 'hex')).digest('hex');
    var hashBuffer = Buffer.from(publicKeyRIPEHash, 'hex');
    var concatHash = Buffer.concat([addrVer, hashBuffer], addrVer.length + hashBuffer.length);
    var hashExtRipe = Buffer.from(sha256(concatHash), 'hex');
    var hashExtRipe2 = Buffer.from(sha256(hashExtRipe), 'hex');
    var hashSig = hashExtRipe2.slice(0, 4);
    var bitcoinBinaryStr = Buffer.concat([concatHash, hashSig], concatHash.length + hashSig.length);
    var bitcoinAddress = bs58.encode(Buffer.from(bitcoinBinaryStr));
    return {
      bitcoinAddress: bitcoinAddress,
      bitCoinPrivateKey: wifFinal
    };
  } else {
    console.log('The string cannot be used. Try other string');
    throw {
      error: 'The string cannot be used as key. Try others'
    };
  }
};

exports.getBitcoinAddress = getBitcoinAddress;