/**
 * BIP-352 Silent Payments - Wallet Implementation Reference
 * 
 * This script demonstrates silent payment wallet scanning algorithm
 * following BIP-352 specification for educational purposes.
 */

//TODO: add support for scanning when labels are used

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { BIP32Factory } from 'bip32';
import * as bip39 from 'bip39';
import { ECPairFactory } from 'ecpair';
import * as utils from './utils';

const ECPair = ECPairFactory(ecc);
const bip32 = BIP32Factory(ecc);
bitcoin.initEccLib(ecc);

// ================================================================================
// BIP-352 Cryptographic Primitives
// ================================================================================

/**
 * Serialize elliptic curve point's x-coordinate for taproot outputs.
 * 
 * According to BIP-352, we only need the x-coordinate (32 bytes) 
 * for silent payment output matching.
 */
function serializeXCoordinate(point: Uint8Array): Buffer {
    // Extract x-coordinate from compressed public key (skip first byte)
    return Buffer.from(point.subarray(1));
}

/**
 * BIP-352: Compute ECDH shared secrets between scan key and input public keys.
 * 
 * For each input public key P_input in the transaction:
 * shared_secret = scan_private_key * P_input
 * 
 * This is the core of silent payment detection - without the correct
 * scan key, these shared secrets cannot be computed.
 */
function computeECDHSharedSecrets(tweaks: string[], scanPrivateKey: Buffer): Buffer[] {
    const sharedSecrets: Buffer[] = [];
    
    console.log("\n######## Computed ECDH secrets");

    for (const tweak of tweaks) {
        // Parse the input public key from the transaction
        const tweakPubkey = Buffer.from(tweak, 'hex');
        
        // Compute ECDH: shared_secret = scan_private_key * input_public_key
        const sharedSecretPoint = ecc.pointMultiply(tweakPubkey, scanPrivateKey) as Uint8Array;
        const sharedSecretBytes = Buffer.from(sharedSecretPoint);
        
        console.log("shared secret:", utils.uint8ArrayToHex(sharedSecretBytes));
        sharedSecrets.push(sharedSecretBytes);
    }
    
    return sharedSecrets;
}

/**
 * BIP-352: Generate a single candidate output key for a given shared secret and output index.
 * 
 * output_key_tweak = TaggedHash("BIP0352/SharedSecret", shared_secret || output_index)
 * output_pubkey = spend_pubkey + tweak*G
 * 
 * This generates keys on-demand based on actual transaction output positions.
 */
function generateCandidateOutputKey(sharedSecret: Buffer, spendPublicKey: Buffer, outputIndex: number): {
    outputIndex: number;
    outputPubkey: Buffer;
    outputKeyTweak: string;
} {
    // Generate the output key tweak using BIP-352 tagged hash
    const outputIndexBuffer = Buffer.alloc(4);
    outputIndexBuffer.writeUInt32BE(outputIndex);
    const outputKeyTweak = utils.taggedHash("BIP0352/SharedSecret", Buffer.concat([sharedSecret, outputIndexBuffer]));
    
    // Calculate the expected output public key: spend_pubkey + tweak*G
    const tweakPoint = ECPair.fromPrivateKey(outputKeyTweak).publicKey;
    const expectedOutputPoint = ecc.pointAdd(spendPublicKey, tweakPoint) as Uint8Array;
    const expectedOutputPubkey = serializeXCoordinate(expectedOutputPoint);
    
    return {
        outputIndex: outputIndex,
        outputPubkey: expectedOutputPubkey,
        outputKeyTweak: utils.uint8ArrayToHex(outputKeyTweak)
    };
}

// ================================================================================
// BIP-352 Wallet Setup - Derive Silent Payment Keys
// ================================================================================

console.log("######## Wallet key material");

// Generate deterministic wallet from mnemonic
const seed = bip39.mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");
const root = bip32.fromSeed(seed);

// BIP-352 key derivation paths
const scanPath = "m/352'/1'/0'/1'/0";    // Used for detecting payments
const spendPath = "m/352'/1'/0'/0'/0";   // Used for spending detected outputs

// Derive the scan private key (kept secret, used for detection)
const scanNode = root.derivePath(scanPath);
const scanPrivateKey = scanNode.privateKey as Buffer;
console.log("scan key:", utils.uint8ArrayToHex(scanPrivateKey));

// Derive public keys (these can be shared in the silent payment address)
const scanPublicKey = scanNode.publicKey;
console.log("scan pub:", utils.uint8ArrayToHex(scanPublicKey));

const spendNode = root.derivePath(spendPath);
const spendPublicKey = spendNode.publicKey;
console.log("spend pub:", utils.uint8ArrayToHex(spendPublicKey));

// ================================================================================
// BIP-352 Input Data - A indexing service reduces wallet workload by computing
// a partial shared secret minus the scan_key. By summing all input public keys
// for the transaction, derive the input_hash and performing a tweak
// Indexing service computes a tweak as follows:
//   A = sum of public keys for transaction inputs
//   input_hash = hashBIP0352/Inputs(outpointL || A)
//   tweak = input_hash·A  
//   *Note: bscan is missing from: ecdh_shared_secret = input_hash·bscan·A
// ================================================================================
const tweaksForBlock = [
    "02f7904afe2add2d97ea03fce2c96fe495c0de63c7d3edc6bd91a33cd90805cd3c",
    "0228e0467cbfb382d39224e0188c08d61144dc596eb48a51f2190eb41ed1489acd",
    "0228e0467cbfb382d39224e0188c08d611ccdc596eb48a51f2190eb41ed1489acd",
    "0377507bdbb89cc566a3b70d2e48960d9989cc27321b6f803c4a1a84c4f887c6a3"
];

// Step 1: Compute shared secrets with each transaction's input keys
const ecdhSharedSecrets = computeECDHSharedSecrets(tweaksForBlock, scanPrivateKey);

// ================================================================================
// BIP-352 Simulated Data - Block Transactions with Outputs
// Sample transaction outputs to scan for silent payments (normally from blockchain data)
// Each output represents a potential silent payment to detect
// ================================================================================
interface TransactionOutput {
    scriptPubKey: Buffer;
    value: number;
}

interface BlockTransaction {
    txid: string;
    outputs: TransactionOutput[];
    inputs: [];
}

const blockTransactions: BlockTransaction[] = [
    {
        'txid': 'abc123',
        'outputs': [
            {
                'scriptPubKey': Buffer.from("5120690daead18e35f65625f69c147e79584c36d2e3790a25cb4ab734ab19bf7097d", "hex"),
                'value': 50000
            },
            {
                'scriptPubKey': Buffer.from("512001ee984af98ade273fdd4546c143f684ef57e3cb57cf5b5acd9f21c30d150e00", "hex"),
                'value': 97690067
            }
        ],
        'inputs' : []
    },
    {
        'txid': 'xyz321',
        'outputs': [
            {
                'scriptPubKey': Buffer.from("51200000000000000000000000000000000000000000000000000000000000000000", "hex"),
                'value': 100
            },
            {
                'scriptPubKey': Buffer.from("51205e6c6909d0704ffead26c869ebd8d4589fec1b1aa01e0bee0d5fe740a85e531d", "hex"),
                'value': 4000
            }
        ],
        'inputs' : []
    },
    {
        'txid': 'no match',
        'outputs': [
            {
                'scriptPubKey': Buffer.from("51200000000000000000000000000000000000000000000000000000000000000000", "hex"),
                'value': 100
            }
        ],
        'inputs' : []
    }
];

// ================================================================================
// BIP-352 Silent Payment Scanning Algorithm
// ================================================================================
console.log("\n######## Scan Transactions");

interface MatchedUTXO {
    txid: string;
    vout: number;
    value: number;
    spTweak: string;
    scriptPubKey: Buffer;
}

// Step 2: For each shared secret and transaction, generate candidate keys for actual output positions
const matchedUtxos: MatchedUTXO[] = [];

for (const tx of blockTransactions) {
    console.log(`Process txn: ${tx.txid}`);
    for (const sharedSecret of ecdhSharedSecrets) {
        // Generate candidate keys based on actual number of outputs in this transaction
        for (let outputIndex = 0; outputIndex < tx.outputs.length; outputIndex++) {
            const output = tx.outputs[outputIndex];
            
            // Generate the candidate key for this specific output position (BIP-352 k value)
            const candidateKey = generateCandidateOutputKey(sharedSecret, spendPublicKey, outputIndex);
            const expectedOutputPubkey = candidateKey.outputPubkey;
            
            // Check if this output's scriptPubKey matches our expected silent payment
            const scriptPubkey = output.scriptPubKey;
            if (scriptPubkey.length === 34 && scriptPubkey.subarray(0, 2).equals(Buffer.from("5120", "hex"))) {
                // Extract x-coordinate from taproot scriptPubKey (OP_1 + 32 bytes)
                const actualOutputPubkey = scriptPubkey.subarray(2, 34);
                
                if (actualOutputPubkey.equals(expectedOutputPubkey)) {
                    console.log(` Found match! actual scriptPubKey: ${utils.uint8ArrayToHex(actualOutputPubkey)}`);
                    matchedUtxos.push({
                        txid: tx.txid,
                        vout: outputIndex,
                        value: output.value,
                        spTweak: candidateKey.outputKeyTweak,
                        scriptPubKey: candidateKey.outputPubkey
                    });
                }
            }
        }
    }
}

// ================================================================================
// BIP-352 Results - Display Detected Silent Payments
// ================================================================================

console.log("\n######## Matched UTXOs");
// Display any silent payments detected for this wallet
if (matchedUtxos.length > 0) {
    for (const utxo of matchedUtxos) {
        console.log(`Matched UTXO: txid=${utxo.txid}, vout=${utxo.vout}, value=${utxo.value}, tweak=${utxo.spTweak}, script=${utils.uint8ArrayToHex(utxo.scriptPubKey)}`);
    }
} else {
    console.log("No matching UTXOs found");
}