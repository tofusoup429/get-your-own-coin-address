const { randomBytes } = require('crypto');
const secp256k1 = require('secp256k1/elliptic');
const sha256 = require('sha256');
const ByteBuffer = require('bytebuffer');
const bs58 = require('bs58');
const RIPEMD160 = require('ripemd160');
const secureRandom = require('secure-random');
const crypto = require('crypto')
//n-1.1578*10**77
//console.log(msg);

function hasha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}

export const getBitcoinAddress = (_randomString) => {
    let verByte = Buffer.alloc(1, 0x00);
    let wifByte = Buffer.alloc(1, 0x80);
    let compByte = Buffer.alloc(1,0x01);
    let randomHexFromRandomString = hasha256(_randomString)
    let randomByteFromRandomHex=Buffer.from(randomHexFromRandomString,'hex');
    console.log(randomHexFromRandomString)
    let checksum = hasha256(randomHexFromRandomString).slice(0,8);
    console.log('checksum', checksum)
    let checkSumByte = Buffer.from(checksum,'hex');
    //let randomByteFromRandomHex = secureRandom.randomBuffer(32);
    if(!secp256k1.privateKeyVerify(randomByteFromRandomHex)){
        throw 'the provided string cannot be private key'
    }

    let wifBufPriv = Buffer.concat([wifByte, randomByteFromRandomHex, compByte, checkSumByte], wifByte.length+randomByteFromRandomHex.length+compByte.length, checkSumByte.length);
    let wifHashFirst = hasha256(wifBufPriv);
    let wifHashSecond = Buffer.from(hasha256(wifHashFirst), 'hex');
    let wifHashSig = wifHashSecond.slice(0,4);
    let wifBuf = Buffer.concat([wifBufPriv, wifHashSig], wifBufPriv.length+wifHashSig.length);
    let wifFinal = bs58.encode(wifBuf);

    let publicKey = secp256k1.publicKeyCreate(randomByteFromRandomHex);
    let publicKeyInitialHash = hasha256(Buffer.from(publicKey, 'hex'));
    let publicKeyRIPEHash = new RIPEMD160().update(Buffer.from(publicKeyInitialHash, 'hex')).digest('hex');
    let hashBuffer = Buffer.from(publicKeyRIPEHash, 'hex');

    let concatHash = Buffer.concat([verByte, hashBuffer], verByte.length + hashBuffer.length);
    let hashExtRipe = Buffer.from(hasha256(concatHash),'hex');
    let hashExtRipe2 = Buffer.from(hasha256(hashExtRipe),'hex');
    let hashSig = hashExtRipe2.slice(0, 4);
    let bitcoinBinaryStr = Buffer.concat([concatHash, hashSig], concatHash.length + hashSig.length);
    let bitcoinAddress = bs58.encode(Buffer.from(bitcoinBinaryStr));
    console.log(wifFinal.length);
    console.log(bitcoinAddress.length);

    return {bitcoinAddress:bitcoinAddress, bitCoinPrivateKey:wifFinal}
};



