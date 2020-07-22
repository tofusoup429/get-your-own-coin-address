const { randomBytes } = require('crypto');
const secp256k1 = require('secp256k1/elliptic');
const sha256 = require('sha256');
const ByteBuffer = require('bytebuffer');
const bs58 = require('bs58');
const RIPEMD160 = require('ripemd160');
const crypto = require('crypto');

//n-1.1578*10**77
//console.log(msg);

const addrVer = Buffer.alloc(1, 0x00);
const wifByte = Buffer.alloc(1, 0x80);

let privKeyHex;
let privKeyByte;
do {
    privKeyHex  = sha256('a');
    privKeyByte = Buffer.from(privKeyHex, 'hex');
}while(!secp256k1.privateKeyVerify((privKeyByte)));

let pubKey = secp256k1.publicKeyCreate(privKeyByte);
let wifBufPriv = Buffer.concat([wifByte, privKeyByte],wifByte.length+privKeyByte.length)
let wifHashFirst = sha256(wifBufPriv);
let wifHashSecond = Buffer.from(sha256(wifHashFirst), 'hex');
let wifHashSig = wifHashSecond.slice(0,4);
let wifBuf = Buffer.concat([wifBufPriv, wifHashSig], wifBufPriv.length + wifHashSig.length);
let wifFinal = bs58.encode(wifBuf);
/*************************************************/
let publicKeyInitialHash = sha256(Buffer.from(pubKey, 'hex'));
let publicKeyRIPEHash = new RIPEMD160().update(Buffer.from(publicKeyInitialHash, 'hex')).digest('hex');
let hashBuffer = Buffer.from(publicKeyRIPEHash, 'hex');

let concatHash = Buffer.concat([addrVer, hashBuffer], addrVer.length + hashBuffer.length);
let hashExtRipe = Buffer.from(sha256(concatHash),'hex');
let hashExtRipe2 = Buffer.from(sha256(hashExtRipe),'hex');
let hashSig = hashExtRipe2.slice(0, 4);
let bitcoinBinaryStr = Buffer.concat([concatHash, hashSig], concatHash.length + hashSig.length);
let bitcoinWifAddress = wifFinal.toString('hex');
let bitcoinAddress = bs58.encode(Buffer.from(bitcoinBinaryStr));
console.log(bitcoinWifAddress)
console.log('private key', wifFinal);
console.log('address', bitcoinAddress);
console.log('address2', bitcoinWifAddress)