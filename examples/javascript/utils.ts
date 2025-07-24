import { bech32m } from 'bech32';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { ECPairFactory } from 'ecpair';
const ECPair = ECPairFactory(ecc);
bitcoin.initEccLib(ecc);
const network = bitcoin.networks.testnet;

export function smallestOutpoint(prevouts: string[]): Buffer {
    const prevoutsBuffer: Buffer[] = [];
    for (const prev of prevouts) {
        const [txid, vout] = prev.split(':');
        const txidBytes = Buffer.from(txid, 'hex').reverse();
        const voutBytes = Buffer.alloc(4);
        voutBytes.writeUInt32LE(Number(vout));
        prevoutsBuffer.push(Buffer.concat([txidBytes, voutBytes]));
    }

    return prevoutsBuffer.sort(Buffer.compare)[0];
}

export function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  return Buffer.concat(arrays);
}

export function uint8ArrayToHex(uint8Arr: Uint8Array): string {
  return Buffer.from(uint8Arr).toString('hex');
}

export function decodeSpAddress(address: string): Buffer[] {
    const words = bech32m.decode(address, 1023).words;
    words.shift(); // drop version
    const addressDec = bech32m.fromWords(words); // base32 to decimal
    const addressBytes = Buffer.from(addressDec);
    const bobScanPubkey = addressBytes.subarray(0, 33);
    const bobSpendPubkey = addressBytes.subarray(33);

    return [bobScanPubkey, bobSpendPubkey];
}

export function taggedHash(tag: string, data: Buffer): Buffer {
    const tagHash = bitcoin.crypto.sha256(Buffer.from(tag, 'utf8'));
    return bitcoin.crypto.sha256(Buffer.concat([tagHash, tagHash, data]));
}

export function sumPrivKeys(keys: (boolean | string)[][]): Buffer {
    const actualKeys: Buffer[] = [];
    for (const tuple of keys) {
        const ecpair = ECPair.fromWIF(tuple[0] as string, network);
        const isTaproot = tuple[1] as boolean;

        let priv = ecpair.privateKey as Buffer;
        if (isTaproot) {
            const tweakedECPair = ecpair.tweak(bitcoin.crypto.taggedHash('TapTweak', ecpair.publicKey.subarray(1)));
            if (tweakedECPair.publicKey[0] === 0x03) {
                priv = Buffer.from(ecc.privateNegate(tweakedECPair.privateKey as Buffer));
            } else {
                priv = tweakedECPair.privateKey as Buffer;
            }
        }

        actualKeys.push(priv);
    }

    let sum = actualKeys[0];
    if (actualKeys.length === 1) {
        return sum;
    }

    for (let i = 1; i < actualKeys.length; i++) {
        sum = Buffer.from(ecc.privateAdd(sum, actualKeys[i]) as Uint8Array);
    }

    return sum;
}