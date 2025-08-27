"""
BIP-352 Silent Payments - Wallet Implementation Reference

This script demonstrates silent payment wallet scanning algorithm
following BIP-352 specification for educational purposes.
"""

#TODO: add support for scanning when labels are used

import hashlib
from mnemonic import Mnemonic
from bip32 import BIP32
from ecdsa import SECP256k1, VerifyingKey, SigningKey

mnemo = Mnemonic("english")

# ================================================================================
# BIP-352 Cryptographic Primitives
# ================================================================================

def serialize_x_coordinate(point):
    """
    Serialize elliptic curve point's x-coordinate for taproot outputs.
    
    According to BIP-352, we only need the x-coordinate (32 bytes) 
    for silent payment output matching.
    """
    x_coordinate = point.x()
    return x_coordinate.to_bytes(32, 'big')

def tagged_hash(tag, data):
    """
    BIP-340 tagged hash implementation used in BIP-352.
    
    Creates domain-separated hashes to prevent cross-protocol attacks.
    Formula: SHA256(SHA256(tag) || SHA256(tag) || data)
    """
    tag_hash = hashlib.sha256(tag.encode('utf-8')).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()

def compute_ecdh_shared_secrets(tweaks, scan_private_key):
    """
    BIP-352: Compute ECDH shared secrets between scan key and tweak public keys.
    
    For each tweak public key P_tweak in the block:
    shared_secret = scan_private_key * P_tweak
    
    This is the core of silent payment detection - without the correct
    scan key, these shared secrets cannot be computed.
    """

    print("\n######## Computed ECDH secrets")

    shared_secrets = []
    for tweak in tweaks:
        # Parse the tweak public key from the indexer service
        tweak_pubkey = VerifyingKey.from_string(bytes.fromhex(tweak), curve=SECP256k1)
        
        # Compute ECDH: shared_secret = scan_private_key * tweak_public_key  
        shared_secret_point = scan_private_key.privkey.secret_multiplier * tweak_pubkey.pubkey.point
        
        # Serialize the shared secret for further processing
        shared_secret_bytes = VerifyingKey.from_public_point(shared_secret_point, curve=SECP256k1).to_string("compressed")
        print("shared secret:", shared_secret_bytes.hex())
        shared_secrets.append(shared_secret_bytes)
    
    return shared_secrets

def generate_candidate_output_key(shared_secret, spend_public_key, output_index):
    """
    BIP-352: Generate a single candidate output key for a given shared secret and output index.
    
    output_key_tweak = TaggedHash("BIP0352/SharedSecret", shared_secret || output_index)
    output_pubkey = spend_pubkey + tweak*G
    
    This generates keys on-demand based on actual transaction output positions.
    """
    # Generate the output key tweak using BIP-352 tagged hash
    output_key_tweak = tagged_hash("BIP0352/SharedSecret", shared_secret + output_index.to_bytes(4, "big"))
    
    # Calculate the expected output public key: spend_pubkey + tweak * G
    tweak_scalar = SigningKey.from_string(output_key_tweak, curve=SECP256k1)
    expected_output_point = spend_public_key.pubkey.point + tweak_scalar.privkey.secret_multiplier * SECP256k1.generator
    expected_output_pubkey = serialize_x_coordinate(expected_output_point)
    
    return {
        'output_pubkey': expected_output_pubkey,
        'output_key_tweak': output_key_tweak.hex()
    }

# ================================================================================
# BIP-352 Wallet Setup - Derive Silent Payment Keys
# ================================================================================

print("######## Wallet key material")

# Generate deterministic wallet from mnemonic
seed = mnemo.to_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", passphrase="")
bip32 = BIP32.from_seed(seed)

# BIP-352 key derivation paths
scan_path = "m/352'/1'/0'/1'/0"    # Used for detecting payments
spend_path = "m/352'/1'/0'/0'/0"   # Used for spending detected outputs

# Derive the scan private key (kept secret, used for detection)
scan_private_key_bytes = bip32.get_privkey_from_path(scan_path) 
print("scan key:", scan_private_key_bytes.hex())

# Derive public keys (these can be shared in the silent payment address)
scan_public_key_bytes = bip32.get_pubkey_from_path(scan_path)
print("scan pub:", scan_public_key_bytes.hex())

spend_public_key_bytes = bip32.get_pubkey_from_path(spend_path)
print("spend pub:", spend_public_key_bytes.hex())

# Create key objects for cryptographic operations
scan_private_key = SigningKey.from_string(scan_private_key_bytes, curve=SECP256k1)
spend_public_key = VerifyingKey.from_string(spend_public_key_bytes, curve=SECP256k1)

# ================================================================================
# BIP-352 Input Data - A indexing service reduces wallet workload by computing
# a partial shared secret minus the scan_key. By summing all input public keys
# for the transaction, derive the input_hash and performing a tweak
# Indexing service computes a tweak as follows:
#   A = sum of public keys for transaction inputs
#   input_hash = hashBIP0352/Inputs(outpointL || A)
#   tweak = input_hash·A  
#   *Note: bscan is missing from: ecdh_shared_secret = input_hash·bscan·A
# ================================================================================
tweaks_for_block = [
    "02f7904afe2add2d97ea03fce2c96fe495c0de63c7d3edc6bd91a33cd90805cd3c",
    "0228e0467cbfb382d39224e0188c08d61144dc596eb48a51f2190eb41ed1489acd",
    "0228e0467cbfb382d39224e0188c08d611ccdc596eb48a51f2190eb41ed1489acd",
    "0377507bdbb89cc566a3b70d2e48960d9989cc27321b6f803c4a1a84c4f887c6a3"
]

# Step 1: Compute possible shared secret for a given transaction with 
# scan_key and each tweak provided for a block
ecdh_shared_secrets = compute_ecdh_shared_secrets(tweaks_for_block, scan_private_key)

# ================================================================================
# BIP-352 Simulated Data - Block Transactions with Outputs
# Sample transaction outputs to scan for silent payments (normally from blockchain data)
# Each output represents a potential silent payment to detect
# ================================================================================
block_transactions = [
    {
        'txid': 'abc123',
        'outputs': [
            {
                'scriptPubKey': bytes.fromhex("5120690daead18e35f65625f69c147e79584c36d2e3790a25cb4ab734ab19bf7097d"),
                'value': 50000
            },
            {
                'scriptPubKey': bytes.fromhex("512001ee984af98ade273fdd4546c143f684ef57e3cb57cf5b5acd9f21c30d150e00"),
                'value': 97690067
            }
        ],
        'inputs' : []
    },
    {
        'txid': 'xyz321',
        'outputs': [
            {
                'scriptPubKey': bytes.fromhex("51200000000000000000000000000000000000000000000000000000000000000000"),
                'value': 100
            },
            {
                'scriptPubKey': bytes.fromhex("51205e6c6909d0704ffead26c869ebd8d4589fec1b1aa01e0bee0d5fe740a85e531d"),
                'value': 4000
            }
        ],
        'inputs' : []
    },
    {
        'txid': 'no match',
        'outputs': [
            {
                'scriptPubKey': bytes.fromhex("51200000000000000000000000000000000000000000000000000000000000000000"),
                'value': 100
            }
        ],
        'inputs' : []
    }
]

# ================================================================================
# BIP-352 Silent Payment Scanning Algorithm
# ================================================================================
print("\n######## Scan Transactions")

# Step 2: For each shared secret and transaction, generate candidate script pub keys for actual output
matched_utxos = []

for tx in block_transactions:
    print(f"Process txn: {tx["txid"]}")
    for shared_secret in ecdh_shared_secrets:
        # Generate candidate keys based on actual number of outputs in this transaction
        for output_index, output_data in enumerate(tx['outputs']):
            # Generate the candidate key for this specific output position (BIP-352 k value)
            candidate_key_data = generate_candidate_output_key(shared_secret, spend_public_key, output_index)
            expected_output_pubkey = candidate_key_data['output_pubkey']
            
            # Check if this output's scriptPubKey matches our expected silent payment
            script_pubkey = output_data['scriptPubKey']
            if len(script_pubkey) == 34 and script_pubkey[0:2] == bytes.fromhex("5120"):
                # Extract x-coordinate from taproot scriptPubKey (OP_1 + 32 bytes)
                actual_output_pubkey = script_pubkey[2:34]
                
                if actual_output_pubkey == expected_output_pubkey:
                    print(f" Found match! actual scriptPubKey: {actual_output_pubkey.hex()}")
                    matched_utxos.append({
                        'txid': tx['txid'],
                        'vout': output_index,
                        'value': output_data['value'],
                        'scriptPubKey': output_data['scriptPubKey'],
                        'sp_tweak': candidate_key_data['output_key_tweak']
                    })

# ================================================================================
# BIP-352 Results - Display Detected Silent Payments
# ================================================================================

print("\n######## Matched UTXOs")
# Display any silent payments detected for this wallet
if matched_utxos:
    for utxo in matched_utxos:
        print(f"Matched UTXO: txid={utxo['txid']}, vout={utxo['vout']}, value={utxo['value']}, tweak={utxo['sp_tweak']}, script={utxo['scriptPubKey'].hex()}")
else:
    print("No matching UTXOs found")
