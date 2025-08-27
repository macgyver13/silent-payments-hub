//! BIP-352 Silent Payments - Wallet Implementation Reference
//! 
//! This program demonstrates silent payment wallet scanning algorithm
//! following BIP-352 specification for educational purposes.

//TODO: add support for scanning when labels are used

use std::str::FromStr;
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey, Scalar};
use bitcoin::bip32::{Xpriv, DerivationPath};
use bitcoin::hashes::{Hash, sha256};
use bip39::{Mnemonic, Language};

/// BIP-352 Cryptographic Primitives
mod bip352 {
    use super::*;

    /// Serialize elliptic curve point's x-coordinate for taproot outputs.
    /// 
    /// According to BIP-352, we only need the x-coordinate (32 bytes) 
    /// for silent payment output matching.
    pub fn serialize_x_coordinate(point: &PublicKey) -> [u8; 32] {
        let serialized = point.serialize();
        let mut x_coord = [0u8; 32];
        x_coord.copy_from_slice(&serialized[1..33]);
        x_coord
    }

    /// BIP-340 tagged hash implementation used in BIP-352.
    /// 
    /// Creates domain-separated hashes to prevent cross-protocol attacks.
    /// Formula: SHA256(SHA256(tag) || SHA256(tag) || data)
    pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
        let tag_hash = sha256::Hash::hash(tag.as_bytes());
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(tag_hash.as_byte_array());
        hasher_input.extend_from_slice(tag_hash.as_byte_array());
        hasher_input.extend_from_slice(data);
        
        sha256::Hash::hash(&hasher_input).to_byte_array()
    }

    /// BIP-352: Compute ECDH shared secrets between scan key and input public keys.
    /// 
    /// For each input public key P_input in the transaction:
    /// shared_secret = scan_private_key * P_input
    /// 
    /// This is the core of silent payment detection - without the correct
    /// scan key, these shared secrets cannot be computed.
    pub fn compute_ecdh_shared_secrets(
        tweaks: &[&str],
        scan_private_key: &SecretKey,
        secp: &Secp256k1<bitcoin::secp256k1::All>
    ) -> Vec<[u8; 33]> {
        let mut shared_secrets = Vec::new();

        println!("\n######## Computed ECDH secrets");
        
        for tweak in tweaks {
            // Parse the input public key from the transaction
            let tweak_pubkey = PublicKey::from_str(tweak)
                .expect("Invalid public key format");
            
            // Compute ECDH: shared_secret = scan_private_key * input_public_key
            let shared_secret_point = tweak_pubkey.mul_tweak(secp, &Scalar::from(*scan_private_key))
                .expect("ECDH computation failed");
            
            // Serialize the shared secret for further processing
            let shared_secret_bytes = shared_secret_point.serialize();
            println!("shared secret: {}", hex::encode(shared_secret_bytes));
            shared_secrets.push(shared_secret_bytes);
        }
        
        shared_secrets
    }

    /// BIP-352: Generate a single candidate output key for a given shared secret and output index.
    /// 
    /// output_key_tweak = TaggedHash("BIP0352/SharedSecret", shared_secret || output_index)
    /// output_pubkey = spend_pubkey + tweak*G
    /// 
    /// This generates keys on-demand based on actual transaction output positions.
    pub fn generate_candidate_output_key(
        shared_secret: &[u8; 33],
        spend_public_key: &PublicKey,
        output_index: u32,
        secp: &Secp256k1<bitcoin::secp256k1::All>
    ) -> CandidateKey {
        // Generate the output key tweak using BIP-352 tagged hash
        let mut tweak_input = Vec::new();
        tweak_input.extend_from_slice(shared_secret);
        tweak_input.extend_from_slice(&output_index.to_be_bytes());
        
        let output_key_tweak = tagged_hash("BIP0352/SharedSecret", &tweak_input);
        
        // Calculate the expected output public key: spend_pubkey + tweak*G
        let tweak_scalar = Scalar::from_be_bytes(output_key_tweak)
            .expect("Invalid tweak scalar");
        let expected_output_point = spend_public_key.add_exp_tweak(secp, &tweak_scalar)
            .expect("Failed to add tweak");
        let expected_output_pubkey = serialize_x_coordinate(&expected_output_point);
        
        CandidateKey {
            output_pubkey: expected_output_pubkey,
            output_key_tweak: hex::encode(output_key_tweak),
        }
    }

    pub struct CandidateKey {
        pub output_pubkey: [u8; 32],
        pub output_key_tweak: String,
    }
}

/// Transaction output structure for scanning
#[derive(Debug)]
struct TransactionOutput {
    script_pubkey: Vec<u8>,
    value: u64,
}

/// Transaction structure containing outputs
#[derive(Debug)]
struct Transaction {
    txid: String,
    outputs: Vec<TransactionOutput>,
    inputs: Vec<u8>
}

/// Matched UTXO result
#[derive(Debug)]
struct MatchedUtxo {
    txid: String,
    vout: u32,
    value: u64,
    sp_tweak: String,
    script_pub_key: String,
}

fn main() {
    let secp = Secp256k1::new();
    
    println!("######## Wallet key material");
    
    // Generate deterministic wallet from mnemonic
    let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
        .expect("Invalid mnemonic phrase");
    let seed = mnemonic.to_seed("");
    
    // Create extended private key from seed
    let xprv = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed)
        .expect("Failed to create extended private key");
    
    // BIP-352 key derivation paths
    let scan_path = DerivationPath::from_str("m/352'/1'/0'/1'/0")
        .expect("Invalid scan derivation path");
    let spend_path = DerivationPath::from_str("m/352'/1'/0'/0'/0")
        .expect("Invalid spend derivation path");
    
    // Derive the scan private key (kept secret, used for detection)
    let scan_xprv = xprv.derive_priv(&secp, &scan_path)
        .expect("Failed to derive scan private key");
    let scan_private_key = scan_xprv.private_key;
    println!("scan key: {}", hex::encode(scan_private_key.secret_bytes()));
    
    // Derive public keys (these can be shared in the silent payment address)
    let scan_public_key = PublicKey::from_secret_key(&secp, &scan_private_key);
    println!("scan pub: {}", hex::encode(scan_public_key.serialize()));
    
    let spend_xprv = xprv.derive_priv(&secp, &spend_path)
        .expect("Failed to derive spend private key");
    let spend_private_key = spend_xprv.private_key;
    let spend_public_key = PublicKey::from_secret_key(&secp, &spend_private_key);
    println!("spend pub: {}", hex::encode(spend_public_key.serialize()));
    
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
    let tweaks_for_block = vec![
        "02f7904afe2add2d97ea03fce2c96fe495c0de63c7d3edc6bd91a33cd90805cd3c",
        "0228e0467cbfb382d39224e0188c08d61144dc596eb48a51f2190eb41ed1489acd",
        "0228e0467cbfb382d39224e0188c08d611ccdc596eb48a51f2190eb41ed1489acd",
        "0377507bdbb89cc566a3b70d2e48960d9989cc27321b6f803c4a1a84c4f887c6a3"
    ];
    
    // Step 1: Compute shared secrets with each transaction's input keys
    let ecdh_shared_secrets = bip352::compute_ecdh_shared_secrets(
        &tweaks_for_block,
        &scan_private_key,
        &secp
    );
    
    // Sample transaction outputs to scan for silent payments (normally from blockchain data)
    // Each output represents a potential silent payment to detect
    let block_transactions = vec![
        Transaction {
            txid: "abc123".to_string(),
            outputs: vec![
                TransactionOutput {
                    script_pubkey: hex::decode("5120690daead18e35f65625f69c147e79584c36d2e3790a25cb4ab734ab19bf7097d")
                        .expect("Invalid hex"),
                    value: 50000,
                },
                TransactionOutput {
                    script_pubkey: hex::decode("512001ee984af98ade273fdd4546c143f684ef57e3cb57cf5b5acd9f21c30d150e00")
                        .expect("Invalid hex"),
                    value: 97690067,
                },
            ],
            inputs: vec![]
        },
        Transaction {
            txid: "xyz321".to_string(),
            outputs: vec![
                TransactionOutput {
                    script_pubkey: hex::decode("51200000000000000000000000000000000000000000000000000000000000000000")
                        .expect("Invalid hex"),
                    value: 100,
                },
                TransactionOutput {
                    script_pubkey: hex::decode("51205e6c6909d0704ffead26c869ebd8d4589fec1b1aa01e0bee0d5fe740a85e531d")
                        .expect("Invalid hex"),
                    value: 4000,
                },
            ],
            inputs: vec![]
        },
        Transaction {
            txid: "no match".to_string(),
            outputs: vec![
                TransactionOutput {
                    script_pubkey: hex::decode("51200000000000000000000000000000000000000000000000000000000000000000")
                        .expect("Invalid hex"),
                    value: 100,
                },
            ],
            inputs: vec![]
        },
    ];
    
    println!("\n######## Scan Transactions");
    
    // Step 2: For each shared secret and transaction, generate candidate keys for actual output positions
    let mut matched_utxos = Vec::new();
    
    for tx in &block_transactions {
        println!("Process txn: {}", tx.txid);
        for shared_secret in &ecdh_shared_secrets {
            // Generate candidate keys based on actual number of outputs in this transaction
            for (output_index, output) in tx.outputs.iter().enumerate() {
                // Generate the candidate key for this specific output position (BIP-352 k value)
                let candidate_key = bip352::generate_candidate_output_key(
                    shared_secret,
                    &spend_public_key,
                    output_index as u32,
                    &secp
                );
                let expected_output_pubkey = candidate_key.output_pubkey;
                
                // Check if this output's scriptPubKey matches our expected silent payment
                let script_pubkey = &output.script_pubkey;
                if script_pubkey.len() == 34 && script_pubkey[0..2] == [0x51, 0x20] {
                    // Extract x-coordinate from taproot scriptPubKey (OP_1 + 32 bytes)
                    let actual_output_pubkey: [u8; 32] = script_pubkey[2..34].try_into()
                        .expect("Invalid scriptPubKey length");
                    
                    if actual_output_pubkey == expected_output_pubkey {
                        println!(" Found match! actual scriptPubKey: {}", hex::encode(actual_output_pubkey));
                        matched_utxos.push(MatchedUtxo {
                            txid: tx.txid.clone(),
                            vout: output_index as u32,
                            value: output.value,
                            sp_tweak: candidate_key.output_key_tweak,
                            script_pub_key: hex::encode(candidate_key.output_pubkey),
                        });
                    }
                }
            }
        }
    }
    
    println!("\n######## Matched UTXOs");
    // Display any silent payments detected for this wallet
    if !matched_utxos.is_empty() {
        for utxo in &matched_utxos {
            println!("Matched UTXO: txid={}, vout={}, value={}, tweak={}, script={}", 
                utxo.txid, utxo.vout, utxo.value, utxo.sp_tweak, utxo.script_pub_key);
        }
    } else {
        println!("No matching UTXOs found");
    }
}