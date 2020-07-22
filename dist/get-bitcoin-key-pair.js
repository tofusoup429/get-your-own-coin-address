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

var secureRandom = require('secure-random');

var crypto = require('crypto'); //n-1.1578*10**77
//console.log(msg);


function hasha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

var getBitcoinAddress = function getBitcoinAddress(_randomString) {
  var verByte = Buffer.alloc(1, 0x00);
  var wifByte = Buffer.alloc(1, 0x80);
  var compByte = Buffer.alloc(1, 0x01);
  var randomHexFromRandomString = hasha256(_randomString);
  var randomByteFromRandomHex = Buffer.from(randomHexFromRandomString, 'hex');
  console.log(randomHexFromRandomString);
  var checksum = hasha256(randomHexFromRandomString).slice(0, 8);
  console.log('checksum', checksum);
  var checkSumByte = Buffer.from(checksum, 'hex'); //let randomByteFromRandomHex = secureRandom.randomBuffer(32);

  if (!secp256k1.privateKeyVerify(randomByteFromRandomHex)) {
    throw 'the provided string cannot be private key';
  }

  var wifBufPriv = Buffer.concat([wifByte, randomByteFromRandomHex, compByte, checkSumByte], wifByte.length + randomByteFromRandomHex.length + compByte.length, checkSumByte.length);
  var wifHashFirst = hasha256(wifBufPriv);
  var wifHashSecond = Buffer.from(hasha256(wifHashFirst), 'hex');
  var wifHashSig = wifHashSecond.slice(0, 4);
  var wifBuf = Buffer.concat([wifBufPriv, wifHashSig], wifBufPriv.length + wifHashSig.length);
  var wifFinal = bs58.encode(wifBuf);
  var publicKey = secp256k1.publicKeyCreate(randomByteFromRandomHex);
  var publicKeyInitialHash = hasha256(Buffer.from(publicKey, 'hex'));
  var publicKeyRIPEHash = new RIPEMD160().update(Buffer.from(publicKeyInitialHash, 'hex')).digest('hex');
  var hashBuffer = Buffer.from(publicKeyRIPEHash, 'hex');
  var concatHash = Buffer.concat([verByte, hashBuffer], verByte.length + hashBuffer.length);
  var hashExtRipe = Buffer.from(hasha256(concatHash), 'hex');
  var hashExtRipe2 = Buffer.from(hasha256(hashExtRipe), 'hex');
  var hashSig = hashExtRipe2.slice(0, 4);
  var bitcoinBinaryStr = Buffer.concat([concatHash, hashSig], concatHash.length + hashSig.length);
  var bitcoinAddress = bs58.encode(Buffer.from(bitcoinBinaryStr));
  console.log(wifFinal.length);
  console.log(bitcoinAddress.length);
  return {
    bitcoinAddress: bitcoinAddress,
    bitCoinPrivateKey: wifFinal
  };
};

exports.getBitcoinAddress = getBitcoinAddress;