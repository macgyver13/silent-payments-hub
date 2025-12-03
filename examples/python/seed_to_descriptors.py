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
    python seed_to_descriptors.py
    python seed_to_descriptors.py --seed "your seed phrase here" --network signet
    python seed_to_descriptors.py --seed "your seed phrase here" --network mainnet --birthdate 926312
    python seed_to_descriptors.py --seed "your seed phrase here" --labels 1 3 5
    python seed_to_descriptors.py --seed "your seed phrase here" --generate_import

WARNING: This is for educational purposes only. Handle seeds and descriptors securely!
Never share your seed phrase or private keys in production environments.
"""

import json
import sys
import argparse
from typing import Dict, List, Any

import bip32utils
from mnemonic import Mnemonic
from util.descriptors import descsum_create, encode_sp
from bip0352.secp256k1 import ECPubKey


def seed_to_descriptors(seed_phrase: str, passphrase: str = "", network: str = "signet", birthdate: int = 842579, labels: list[int] = None) -> List[Dict[str, Any]]:
    """
    Convert BIP39 seed phrase to Bitcoin Core descriptors for multiple address types.

    Args:
        seed_phrase: Space-separated BIP39 words (12 or 24 words)
        passphrase: Optional BIP39 passphrase (empty string if none)
        network: Target network - "mainnet", "testnet", or "signet"
        birthdate: Block height when the wallet was created (default: 842579)
        labels: List of positive integers for labels (default: None)

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
        xpub = account_key.ExtendedKey(private=False)
        master_fingerprint = master_key.Fingerprint().hex()
        print("fingerprint ", master_fingerprint)
        print("xpub ", xpub)

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

            # Get raw private key bytes and public key bytes
            scan_privkey_bytes = scan_private_key.PrivateKey()
            spend_privkey_bytes = spend_private_key.PrivateKey()
            spend_pubkey_bytes = spend_private_key.PublicKey()

            # Determine HRP based on network
            spscan_hrp = "spscan" if network == "mainnet" else "tspscan"
            spspend_hrp = "spspend" if network == "mainnet" else "tspspend"

            # Encode using new spscan and spspend formats
            spscan_encoded = encode_sp(scan_privkey_bytes, spend_pubkey_bytes, spscan_hrp)
            spspend_encoded = encode_sp(scan_privkey_bytes, spend_privkey_bytes, spspend_hrp)

            # Validate and sort labels (must be positive integers > 0)
            labels_str = ""
            if labels:
                if not all(isinstance(label, int) and label > 0 for label in labels):
                    raise ValueError("All labels must be positive integers greater than 0")

                # Sort labels in ascending order
                sorted_labels = sorted(labels)
                labels_str = ",".join(str(label) for label in sorted_labels)

            # Create descriptors using new format: sp(KEY[,BIRTHDAY][,LABEL,...])
            # Only include birthdate if it's greater than default (842579)
            # Only include labels if provided
            desc_params = ""
            if birthdate > 842579:
                desc_params += f",{birthdate}"
                if labels_str:
                    desc_params += f",{labels_str}"
            elif labels_str:
                # If birthdate is default but labels are provided, still need birthdate
                desc_params += f",{birthdate},{labels_str}"

            desc_external_base = f"sp([{master_fingerprint}/{base_path}]{spscan_encoded}{desc_params})"
            desc_internal_base = f"sp([{master_fingerprint}/{base_path}]{spspend_encoded}{desc_params})"

        # Add checksums to descriptors
        desc_external = descsum_create(desc_external_base)
        desc_internal = descsum_create(desc_internal_base)

        descriptors.append({
            "type": addr_type,
            "external": desc_external,
            "internal": desc_internal
        })
    
    return descriptors

def generate_import_command(descriptors: List[Dict[str, Any]], network: str = "signet", timestamp: str = "now") -> str:
    """
    Generate bitcoin-cli importdescriptors command for the given descriptors.

    Args:
        descriptors: List of descriptor dictionaries from seed_to_descriptors()
        network: Target network - "mainnet", "testnet", or "signet"
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

    # Determine network flag
    network_flag = ""
    if network == "signet":
        network_flag = "-signet"
    elif network == "testnet":
        network_flag = "-testnet"
    # mainnet has no flag

    return f"bitcoin-cli {network_flag} importdescriptors '{json.dumps(import_array, indent=2)}'"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate Bitcoin Core descriptors from BIP39 seed phrases.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python seed_to_descriptors.py
  python seed_to_descriptors.py --seed "your seed phrase here" --network signet
  python seed_to_descriptors.py --seed "your seed phrase here" --network mainnet --birthdate 926312
  python seed_to_descriptors.py --seed "your seed phrase here" --labels 1 3 5
  python seed_to_descriptors.py --seed "your seed phrase here" --generate_import
        """
    )

    parser.add_argument(
        "--seed",
        default="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        help="BIP39 seed phrase (12 or 24 words)"
    )
    parser.add_argument(
        "--network",
        default="signet",
        choices=["mainnet", "testnet", "signet"],
        help="Target network (default: signet)"
    )
    parser.add_argument(
        "--birthdate",
        type=int,
        default=842579,
        help="Block height when the wallet was created (default: 842579)"
    )
    parser.add_argument(
        "--labels",
        type=int,
        nargs="+",
        help="List of positive integer labels > 0 (will be sorted)"
    )
    parser.add_argument(
        "--generate_import",
        action="store_true",
        help="Generate Bitcoin Core importdescriptors command"
    )

    args = parser.parse_args()

    try:
        # Validate labels if provided
        if args.labels:
            if not all(label > 0 for label in args.labels):
                print("Error: All labels must be positive integers greater than 0")
                sys.exit(1)

        descriptors = seed_to_descriptors(
            args.seed,
            network=args.network,
            birthdate=args.birthdate,
            labels=args.labels
        )

        print(f"Generated descriptors for {args.network}:")
        print("=" * 60)

        for desc_set in descriptors:
            print(f"\n{desc_set['type'].upper()} ({desc_set['type']}):")
            if desc_set['external'] != "N/A":
                print(f"  External (receive): {desc_set['external']}")
            print(f"  Internal (change):  {desc_set['internal']}")

        if args.generate_import:
            print("\n" + "=" * 60)
            print("Bitcoin Core import command:")
            print(generate_import_command(descriptors, network=args.network))

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)