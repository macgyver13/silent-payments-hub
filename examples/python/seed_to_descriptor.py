#!/usr/bin/env python3
"""
Convert BIP39 seed phrase to Bitcoin Core descriptors
WARNING: This is for educational purposes. Handle seed and descriptors securely!
"""
import bip32utils
from descriptors import descsum_create
import json
from mnemonic import Mnemonic
import sys


def seed_to_descriptors(seed_phrase, passphrase="", network="signet"):
    """
    Convert BIP39 seed phrase to Bitcoin Core descriptors
    
    Args:
        seed_phrase: Space-separated BIP39 words
        passphrase: Optional BIP39 passphrase  
        network: "mainnet", "testnet", or "signet"
    """
    
    # Validate and convert seed phrase to seed
    mnemo = Mnemonic("english")
    if not mnemo.check(seed_phrase):
        raise ValueError("Invalid seed phrase")
    
    seed = mnemo.to_seed(seed_phrase, passphrase)
    
    # Create master key
    master_key = bip32utils.BIP32Key.fromEntropy(seed, testnet=(network!="mainnet"))
    
    # Network-specific derivation paths
    if network == "mainnet":
        coin_type = "0"
    else:  # testnet/signet
        coin_type = "1"
    
    # Standard derivation paths for different address types
    paths = {
        "legacy": f"44'/{coin_type}'/0'",   # P2PKH
        "nested": f"49'/{coin_type}'/0'",   # P2SH-P2WPKH
        "segwit": f"84'/{coin_type}'/0'",   # P2WPKH 
        "tr":     f"86'/{coin_type}'/0'",   # P2TR 
        "sp":     f"352'/{coin_type}'/0'"   # SP
    }
    
    descriptors = []
    
    for addr_type, base_path in paths.items():
        # Derive account key
        account_key = master_key.ChildKey(44 + 2**31)  # 44'
        account_key = account_key.ChildKey(int(coin_type) + 2**31)  # coin_type'
        account_key = account_key.ChildKey(0 + 2**31)  # 0'
        
        # Get extended public key
        xpriv = account_key.ExtendedKey(private=True)
        fingerprint = master_key.Fingerprint().hex()

        # Create descriptors for external and internal chains
        if addr_type == "legacy":
            desc_external_base = f"pkh([{fingerprint}/{base_path}]{xpriv}/0/*)"
            desc_internal_base = f"pkh([{fingerprint}/{base_path}]{xpriv}/1/*)"
        elif addr_type == "nested":
            desc_external_base = f"sh(wpkh([{fingerprint}/{base_path}]{xpriv}/0/*))"
            desc_internal_base = f"sh(wpkh([{fingerprint}/{base_path}]{xpriv}/1/*))"
        elif addr_type == "segwit":
            desc_external_base = f"wpkh([{fingerprint}/{base_path}]{xpriv}/0/*)"
            desc_internal_base = f"wpkh([{fingerprint}/{base_path}]{xpriv}/1/*)"
        elif addr_type == "tr":
            desc_external_base = f"tr([{fingerprint}/{base_path}]{xpriv}/0/*)"
            desc_internal_base = f"tr([{fingerprint}/{base_path}]{xpriv}/1/*)"
        elif addr_type == "sp":
            # For Silent Payments, use WIF for scan and spend keys:
            sp_key = master_key.ChildKey(352 + 2**31)  # 325'
            sp_key = sp_key.ChildKey(int(coin_type) + 2**31)  # coin_type'
            sp_key = sp_key.ChildKey(0 + 2**31)  # 0'
            scan_sk = sp_key.ChildKey(1 + 2**31).ChildKey(0) # Derive scan /1'/0
            spend_sk = sp_key.ChildKey(0 + 2**31).ChildKey(0) # Derive spend /0'/0
            desc_internal_base = f"sp([{fingerprint}/{base_path}/1'/0]{scan_sk.WalletImportFormat()},[{fingerprint}/{base_path}/0'/0]{spend_sk.WalletImportFormat()})"

        # Add checksums
        desc_external = f"{descsum_create(desc_external_base)}" if addr_type != "sp" else "N/A"
        desc_internal = f"{descsum_create(desc_internal_base)}"

        descriptors.append({
            "type": addr_type,
            "external": desc_external,
            "internal": desc_internal
        })
    
    return descriptors

def generate_import_command(descriptors, timestamp="now"):
    """Generate bitcoin-cli importdescriptors command"""
    
    import_array = []
    
    for desc_set in descriptors:

        if desc_set["type"] != "sp":
            # External addresses
            import_array.append({
                "desc": desc_set["external"],
                "timestamp": timestamp,
                "active": True,
                "watchonly": False,
                "keypool": True,
                "internal": False
            })
        
        # Internal (change) addresses  
        import_array.append({
            "desc": desc_set["internal"],
            "timestamp": timestamp,
            "active": True,
            "watchonly": False,
            "keypool": True,
            "internal": True
        })
    
    return f"bitcoin-cli -signet importdescriptors '{json.dumps(import_array, indent=2)}'"

if __name__ == "__main__":
    try:
        network="signet" if len(sys.argv) < 3 else sys.argv[2]
        descriptors = seed_to_descriptors(sys.argv[1], network=network)
        
        print("Generated descriptors:")
        for desc_set in descriptors:
            print(f"\n{desc_set['type'].upper()}:")
            print(f"External: {desc_set['external']}")
            print(f"Internal: {desc_set['internal']}")
        
        print("\n" + "="*50)
        print("Bitcoin Core import command:")
        print(generate_import_command(descriptors))
        
    except Exception as e:
        print(f"Error: {e}")