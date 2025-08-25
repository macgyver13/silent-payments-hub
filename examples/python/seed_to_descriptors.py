#!/usr/bin/env python3
"""
Convert BIP39 seed phrase to Bitcoin Core descriptors including Silent Payments.

This script generates wallet descriptors for multiple address types from a seed phrase:
- Legacy (P2PKH) 
- Nested SegWit (P2SH-P2WPKH)
- Native SegWit (P2WPKH)
- Taproot (P2TR)
- Silent Payments (SP)

Example usage:
    python seed_to_descriptors.py "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    python seed_to_descriptors.py "your seed phrase here" signet

WARNING: This is for educational purposes only. Handle seeds and descriptors securely!
Never share your seed phrase or private keys in production environments.
"""
import bip32utils
import json
import sys
from typing import Dict, List, Any

from mnemonic import Mnemonic
from util.descriptors import descsum_create

def seed_to_descriptors(seed_phrase: str, passphrase: str = "", network: str = "signet") -> List[Dict[str, Any]]:
    """
    Convert BIP39 seed phrase to Bitcoin Core descriptors for multiple address types.
    
    Args:
        seed_phrase: Space-separated BIP39 words (12 or 24 words)
        passphrase: Optional BIP39 passphrase (empty string if none)
        network: Target network - "mainnet", "testnet", or "signet"
    
    Returns:
        List of descriptor dictionaries, each containing 'type', 'external', and 'internal' keys
    
    Raises:
        ValueError: If seed phrase is invalid
        
    Example:
        >>> descriptors = seed_to_descriptors("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        >>> print(descriptors[0]['type'])  # 'legacy'
    """
    
    # Validate network parameter
    if network not in ["mainnet", "testnet", "signet"]:
        raise ValueError(f"Invalid network: {network}. Must be 'mainnet', 'testnet', or 'signet'")
    
    # Validate and convert seed phrase to seed
    mnemo = Mnemonic("english")
    if not mnemo.check(seed_phrase):
        raise ValueError("Invalid BIP39 seed phrase")
    
    seed = mnemo.to_seed(seed_phrase, passphrase)
    
    # Create master key
    master_key = bip32utils.BIP32Key.fromEntropy(seed, testnet=(network != "mainnet"))
    
    # Network-specific coin type for BIP44 derivation
    coin_type = 0 if network == "mainnet" else 1
    
    # Standard BIP derivation paths for different address types
    derivation_paths = {
        "legacy": (44, f"44'/{coin_type}'/0'"),   # BIP44 - P2PKH
        "nested": (49, f"49'/{coin_type}'/0'"),   # BIP49 - P2SH-P2WPKH  
        "segwit": (84, f"84'/{coin_type}'/0'"),   # BIP84 - P2WPKH
        "tr":     (86, f"86'/{coin_type}'/0'"),   # BIP86 - P2TR
        "sp":     (352, f"352'/{coin_type}'/0'")  # BIP352 - Silent Payments
    }
    
    descriptors = []
    
    for addr_type, (purpose, base_path) in derivation_paths.items():
        # Derive account key using correct BIP purpose number
        account_key = master_key.ChildKey(purpose + 2**31)  # purpose'
        account_key = account_key.ChildKey(coin_type + 2**31)  # coin_type'
        account_key = account_key.ChildKey(0 + 2**31)  # account' (always 0 for first account)
        
        # Get extended private key and master fingerprint
        xpriv = account_key.ExtendedKey(private=True)
        master_fingerprint = master_key.Fingerprint().hex()

        # Create descriptors for external (receive) and internal (change) chains
        if addr_type == "legacy":
            desc_external_base = f"pkh([{master_fingerprint}/{base_path}]{xpriv}/0/*)"
            desc_internal_base = f"pkh([{master_fingerprint}/{base_path}]{xpriv}/1/*)"
        elif addr_type == "nested":
            desc_external_base = f"sh(wpkh([{master_fingerprint}/{base_path}]{xpriv}/0/*))"
            desc_internal_base = f"sh(wpkh([{master_fingerprint}/{base_path}]{xpriv}/1/*))"
        elif addr_type == "segwit":
            desc_external_base = f"wpkh([{master_fingerprint}/{base_path}]{xpriv}/0/*)"
            desc_internal_base = f"wpkh([{master_fingerprint}/{base_path}]{xpriv}/1/*)"
        elif addr_type == "tr":
            desc_external_base = f"tr([{master_fingerprint}/{base_path}]{xpriv}/0/*)"
            desc_internal_base = f"tr([{master_fingerprint}/{base_path}]{xpriv}/1/*)"
        elif addr_type == "sp":
            # Silent Payments: derive scan and spend keys according to BIP352
            silent_payments_key = master_key.ChildKey(352 + 2**31)  # 352'
            silent_payments_key = silent_payments_key.ChildKey(coin_type + 2**31)  # coin_type'  
            silent_payments_key = silent_payments_key.ChildKey(0 + 2**31)  # account 0'
            
            # BIP352: scan key at m/352'/coin_type'/0'/1'/0, spend key at m/352'/coin_type'/0'/0'/0
            scan_private_key = silent_payments_key.ChildKey(1 + 2**31).ChildKey(0)  # /1'/0 (scan)
            spend_private_key = silent_payments_key.ChildKey(0 + 2**31).ChildKey(0)  # /0'/0 (spend)
            
            desc_internal_base = f"sp([{master_fingerprint}/{base_path}/1'/0]{scan_private_key.WalletImportFormat()},[{master_fingerprint}/{base_path}/0'/0]{spend_private_key.WalletImportFormat()})"

        # Add checksums to descriptors (Silent Payments only have internal/change descriptors)
        if addr_type != "sp":
            desc_external = descsum_create(desc_external_base)
        else:
            desc_external = "N/A"  # Silent Payments don't have external descriptors
            
        desc_internal = descsum_create(desc_internal_base)

        descriptors.append({
            "type": addr_type,
            "external": desc_external,
            "internal": desc_internal
        })
    
    return descriptors

def generate_import_command(descriptors: List[Dict[str, Any]], timestamp: str = "now") -> str:
    """
    Generate bitcoin-cli importdescriptors command for the given descriptors.
    
    Args:
        descriptors: List of descriptor dictionaries from seed_to_descriptors()
        timestamp: Import timestamp - "now" for current time, or Unix timestamp
        
    Returns:
        Formatted bitcoin-cli command string ready for execution
    """
    
    import_array = []
    
    for desc_set in descriptors:
        # Add external (receive) descriptors for all types except Silent Payments
        if desc_set["type"] != "sp":
            import_array.append({
                "desc": desc_set["external"],
                "timestamp": timestamp,
                "active": True,
                "watchonly": False,
                "keypool": True,
                "internal": False  # External/receive addresses
            })
        
        # Add internal (change) descriptors for all types
        import_array.append({
            "desc": desc_set["internal"],
            "timestamp": timestamp,
            "active": True,
            "watchonly": False,
            "keypool": True,
            "internal": True  # Internal/change addresses
        })
    
    return f"bitcoin-cli -signet importdescriptors '{json.dumps(import_array, indent=2)}'"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python seed_to_descriptors.py \"<BIP39_seed_phrase>\" [network]")
        print("  network: mainnet, testnet, or signet (default: signet)")
        print("  Example: python seed_to_descriptors.py \"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\"")
        sys.exit(1)
        
    try:
        seed_phrase = sys.argv[1]
        network = sys.argv[2] if len(sys.argv) > 2 else "signet"
        
        descriptors = seed_to_descriptors(seed_phrase, network=network)
        
        print(f"Generated descriptors for {network}:")
        print("=" * 60)
        
        for desc_set in descriptors:
            print(f"\n{desc_set['type'].upper()} ({desc_set['type']}):")
            if desc_set['external'] != "N/A":
                print(f"  External (receive): {desc_set['external']}")
            print(f"  Internal (change):  {desc_set['internal']}")
        
        print("\n" + "=" * 60)
        print("Bitcoin Core import command:")
        print(generate_import_command(descriptors))
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)