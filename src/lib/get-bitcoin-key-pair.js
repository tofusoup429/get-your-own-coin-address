const { randomBytes } = require('crypto');
const secp256k1 = require('secp256k1/elliptic');
const sha256 = require('sha256');
const ByteBuffer = require('bytebuffer');
const bs58 = require('bs58');
const RIPEMD160 = require('ripemd160');
const SecureRandom = require('secure-random');

//n-1.1578*10**77
//console.log(msg);

export const getBitcoinAddress = (_randomString) => {
    let addrVer = Buffer.alloc(1, 0x00);
    let wifByte = Buffer.alloc(1, 0x80);
    let randomHexFromRandomString = sha256(_randomString)
    let randomByteFromRandomHex = Buffer.from(randomHexFromRandomString, 'hex');
    if(_randomString && secp256k1.privateKeyVerify(randomByteFromRandomHex)){
        let publicKey = secp256k1.publicKeyCreate(randomByteFromRandomHex);
        let wifBufPriv = Buffer.concat([wifByte, randomByteFromRandomHex], wifByte.length+randomByteFromRandomHex.length);
        let wifHashFirst = sha256(wifBufPriv);
        let wifHashSecond = Buffer.from(sha256(wifHashFirst), 'hex');
        let wifHashSig = wifHashSecond.slice(0,4);
        let wifBuf = Buffer.concat([wifBufPriv, wifHashSig], wifBufPriv.length+wifHashSig.length);
        let wifFinal = bs58.encode(wifBuf);
        let publicKeyInitialHash = sha256(Buffer.from(publicKey, 'hex'));
        let publicKeyRIPEHash = new RIPEMD160().update(Buffer.from(publicKeyInitialHash, 'hex')).digest('hex');
        let hashBuffer = Buffer.from(publicKeyRIPEHash, 'hex');

        let concatHash = Buffer.concat([addrVer, hashBuffer], addrVer.length + hashBuffer.length);
        let hashExtRipe = Buffer.from(sha256(concatHash),'hex');
        let hashExtRipe2 = Buffer.from(sha256(hashExtRipe),'hex');
        let hashSig = hashExtRipe2.slice(0, 4);
        let bitcoinBinaryStr = Buffer.concat([concatHash, hashSig], concatHash.length + hashSig.length);
        let bitcoinAddress = bs58.encode(Buffer.from(bitcoinBinaryStr));
        return {bitcoinAddress:bitcoinAddress, bitCoinPrivateKey:wifFinal}
    }else{
        console.log('The string cannot be used. Try other string');
        throw {error:'The string cannot be used as key. Try others'}
    }
};

