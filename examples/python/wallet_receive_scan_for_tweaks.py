"""
BIP-352 Silent Payments - Wallet Implementation Reference

This script demonstrates silent payment wallet scanning algorithm
following BIP-352 specification for educational purposes.
"""

import hashlib
from mnemonic import Mnemonic
from bip32 import BIP32, HARDENED_INDEX
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

def compute_ecdh_shared_secrets(input_public_keys, scan_private_key):
    """
    BIP-352: Compute ECDH shared secrets between scan key and input public keys.
    
    For each input public key P_input in the transaction:
    shared_secret = scan_private_key * P_input
    
    This is the core of silent payment detection - without the correct
    scan key, these shared secrets cannot be computed.
    """
    shared_secrets = []
    for input_pubkey_hex in input_public_keys:
        # Parse the input public key from the transaction
        input_pubkey = VerifyingKey.from_string(bytes.fromhex(input_pubkey_hex), curve=SECP256k1)
        
        # Compute ECDH: shared_secret = scan_private_key * input_public_key  
        shared_secret_point = scan_private_key.privkey.secret_multiplier * input_pubkey.pubkey.point
        
        # Serialize the shared secret for further processing
        shared_secret_bytes = VerifyingKey.from_public_point(shared_secret_point, curve=SECP256k1).to_string("compressed")
        print("shared_secret:", shared_secret_bytes.hex())
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
    
    # Calculate the expected output public key: spend_pubkey + tweak*G
    tweak_scalar = SigningKey.from_string(output_key_tweak, curve=SECP256k1)
    expected_output_point = spend_public_key.pubkey.point + tweak_scalar.privkey.secret_multiplier * SECP256k1.generator
    expected_output_pubkey = serialize_x_coordinate(expected_output_point)
    
    return {
        'output_index': output_index,
        'output_pubkey': expected_output_pubkey,
        'output_key_tweak': output_key_tweak.hex()
    }

# ================================================================================
# BIP-352 Key Derivation 
# ================================================================================

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
# BIP-352 Input Data - Transaction Input Public Keys  
# ================================================================================

# Input public keys from transactions (normally provided by indexer service)
# These represent the sum of input public keys for each transaction
input_public_keys_for_block = [
    "02f7904afe2add2d97ea03fce2c96fe495c0de63c7d3edc6bd91a33cd90805cd3c",
    "0228e0467cbfb382d39224e0188c08d61144dc596eb48a51f2190eb41ed1489acd",
    "0228e0467cbfb382d39224e0188c08d611ccdc596eb48a51f2190eb41ed1489acd"
]

print("\n######## Computed ECDH secrets")

# Step 1: Compute shared secrets with each transaction's input keys
ecdh_shared_secrets = compute_ecdh_shared_secrets(input_public_keys_for_block, scan_private_key)

# ================================================================================
# BIP-352 Simulated Data - Block Transactions with Outputs
# Sample transaction outputs to scan (normally from blockchain data)
# ================================================================================
block_transactions = [
    {
        'txid': 'abc123',
        'outputs': [
            {
                'vout': 0,
                'scriptPubKey': bytes.fromhex("5120690daead18e35f65625f69c147e79584c36d2e3790a25cb4ab734ab19bf7097d"),
                'value': 50000
            },
            {
                'vout': 2,
                'scriptPubKey': bytes.fromhex("512001ee984af98ade273fdd4546c143f684ef57e3cb57cf5b5acd9f21c30d150e00"),
                'value': 97690067
            }
        ]
    },
    {
        'txid': 'xyz321',
        'outputs': [
            {
                'vout': 0,
                'scriptPubKey': bytes.fromhex("51200000000000000000000000000000000000000000000000000000000000000000"),
                'value': 100
            },
            {
                'vout': 1,
                'scriptPubKey': bytes.fromhex("51205e6c6909d0704ffead26c869ebd8d4589fec1b1aa01e0bee0d5fe740a85e531d"),
                'value': 4000
            }
        ]
    },
    {
        'txid': 'no match',
        'outputs': [
            {
                'vout': 0,
                'scriptPubKey': bytes.fromhex("51200000000000000000000000000000000000000000000000000000000000000000"),
                'value': 100
            }
        ]
    }
]

# ================================================================================
# BIP-352 Silent Payment Scanning Algorithm
# ================================================================================
print("\n######## Scan Transactions")

# Step 2: For each shared secret and transaction, generate candidate keys for actual output positions
matched_utxos = []

for tx in block_transactions:
    print(f"Process txn: {tx["txid"]}")
    for shared_secret in ecdh_shared_secrets:
        # Generate candidate keys based on actual number of outputs in this transaction
        for output_index, output in enumerate(tx['outputs']):
            # Generate the candidate key for this specific output position
            candidate_key = generate_candidate_output_key(shared_secret, spend_public_key, output_index)
            expected_output_pubkey = candidate_key['output_pubkey']
            # print(f"Checking output {output_index}: expected={expected_output_pubkey.hex()}")
            
            # Check if this output matches our expected silent payment
            script_pubkey = output['scriptPubKey']
            if len(script_pubkey) == 34 and script_pubkey[0:2] == bytes.fromhex("5120"):
                # Extract x-coordinate from taproot scriptPubKey (OP_1 + 32 bytes)
                actual_output_pubkey = script_pubkey[2:34]
                
                if actual_output_pubkey == expected_output_pubkey:
                    print(f" Found match! actual scriptPubKey: {actual_output_pubkey.hex()}")
                    matched_utxos.append({
                        'txid': tx['txid'],
                        'vout': output['vout'],
                        'value': output['value'],
                        'output_key_tweak': candidate_key['output_key_tweak'],
                        'output_pub_key': candidate_key['output_pubkey'],
                        'output_index': candidate_key['output_index']
                    })
                    # break

# ================================================================================
# BIP-352 Results - Display Detected Silent Payments
# ================================================================================

print("\n######## Matched UTXOs")
# Display any silent payments detected for this wallet
if matched_utxos:
    for utxo in matched_utxos:
        print(f"Matched UTXO: txid={utxo['txid']}, vout={utxo['vout']}, value={utxo['value']}, tweak={utxo['output_key_tweak']}, output_key={utxo['output_pub_key'].hex()}")
else:
    print("No matching UTXOs found")
