#!/usr/bin/env python3
"""
Generate Silent Payment addresses from BIP39 seed phrases.

This educational script demonstrates how to:
- Convert BIP39 seed phrases to Silent Payment keys according to BIP352
- Derive scan and spend public keys using proper BIP32 derivation paths
- Generate Silent Payment addresses for different networks

Example usage:
    python create_silent_payment_address.py
    python create_silent_payment_address.py "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    python create_silent_payment_address.py "your seed phrase here" signet
    python create_silent_payment_address.py "your seed phrase here" mainnet
    python create_silent_payment_address.py "your seed phrase here" signet --birthdate 926312
    python create_silent_payment_address.py "your seed phrase here" signet --labels 1 3 5
    python create_silent_payment_address.py "your seed phrase here" mainnet --birthdate 850000 --labels 1 2

WARNING: This is for educational purposes only. Handle seeds securely!
Never share your seed phrase or private keys in production environments.
"""

import sys
import argparse

import bip32utils
from mnemonic import Mnemonic
from util.descriptors import descsum_create, encode_sp
from bip0352.bech32m import convertbits, bech32_encode, Encoding
from bip0352.secp256k1 import ECPubKey


def encode_silent_payment_address(scan_pubkey: ECPubKey, spend_pubkey: ECPubKey, hrp: str = "tsp") -> str:
    """
    Encode scan and spend public keys into a Silent Payment address.
    
    Args:
        scan_pubkey: 33-byte compressed scan public key
        spend_pubkey: 33-byte compressed spend public key
    
    Returns:
        Silent Payment address string (sp1...)
    """
    # Silent Payment address format: scan_pubkey + spend_pubkey = 66 bytes
    data = scan_pubkey.get_bytes(False) + spend_pubkey.get_bytes(False)
    
    # Convert to 5-bit groups for bech32m encoding
    converted = convertbits(data, 8, 5)
    if converted is None:
        raise ValueError("Failed to convert data for bech32m encoding")
    
    # Encode as bech32m with "sp" or "tsp" HRP (Human Readable Part) w/ version 0
    address = bech32_encode(hrp, [0] + converted, Encoding.BECH32M)
    if address is None:
        raise ValueError("Failed to encode Silent Payment address")
    
    return address


def seed_to_silent_payment_address(seed_phrase: str, passphrase: str = "", network: str = "signet", birthdate: int = 842579, labels: list[int] = None) -> str:
    """
    Convert BIP39 seed phrase to Silent Payment address.

    Args:
        seed_phrase: Space-separated BIP39 words (12 or 24 words)
        passphrase: Optional BIP39 passphrase (empty string if none)
        network: Target network - "mainnet", "testnet", or "signet"
        birthdate: Block height when the wallet was created (default: 842579)
        labels: List of positive integers for labels (default: [1, 3])

    Returns:
        Silent Payment address string
        
    Raises:
        ValueError: If seed phrase is invalid or network is unsupported
        
    Example:
        >>> addr = seed_to_silent_payment_address("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        >>> print(addr)  # sp1qqw6vczcfpdh5nf5y2ky9jn0d4p8hngmzcwhadrqyrjqpwktlfgqmrqx5q6...
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
    master_fingerprint = master_key.Fingerprint().hex()
    
    # Network-specific coin type for BIP44 derivation
    coin_type = 0 if network == "mainnet" else 1
    hrp = "sp" if network == "mainnet" else "tsp"
    base_path = f"352'/{coin_type}'/0'"
    
    # BIP352: Silent Payments derivation path m/352'/coin_type'/0'
    account_key = master_key.ChildKey(352 + 2**31)  # 352'
    account_key = account_key.ChildKey(coin_type + 2**31)  # coin_type'  
    account_key = account_key.ChildKey(0 + 2**31)  # account 0'
    
    # BIP352: scan key at m/352'/coin_type'/0'/1'/0, spend key at m/352'/coin_type'/0'/0'/0
    scan_private_key = account_key.ChildKey(1 + 2**31).ChildKey(0)  # /1'/0 (scan)
    spend_private_key = account_key.ChildKey(0 + 2**31).ChildKey(0)  # /0'/0 (spend)
    
    # Get public keys from private keys
    scan_pubkey_bytes = scan_private_key.PublicKey()
    spend_pubkey_bytes = spend_private_key.PublicKey()
    
    # Create ECPubKey objects for Silent Payment address encoding
    scan_pubkey = ECPubKey().set(scan_pubkey_bytes)
    spend_pubkey = ECPubKey().set(spend_pubkey_bytes)

    print(f"Scan private key: {scan_private_key.PrivateKey().hex()}")
    print(f"Scan public key:  {scan_pubkey_bytes.hex()}")
    print(f"Spend public key: {spend_pubkey_bytes.hex()}")

    # Get raw private key bytes for descriptor
    scan_privkey_bytes = scan_private_key.PrivateKey()
    spend_privkey_bytes = spend_private_key.PrivateKey()

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
    
    print("")
    print("=== Secure like watch-only ===")
    print(descsum_create(desc_external_base))
    print("=== Secure like seed phrase ===")
    print(descsum_create(desc_internal_base))
    
    # Generate Silent Payment address
    print("=== Share with anyone ===")
    # TODO: derive payment addresses for each label argument
    return encode_silent_payment_address(scan_pubkey, spend_pubkey, hrp)


def print_detailed_info(seed_phrase: str, network: str = "signet", birthdate: int = 842579, labels: list[int] = None) -> None:
    """Print detailed information about the Silent Payment derivation process."""

    print(f"=== Silent Payment Address Generation ===")
    print(f"Network: {network}")
    print(f"Seed phrase: {seed_phrase}")
    print(f"Derivation path: m/352'/{'0' if network == 'mainnet' else '1'}'/0'")
    print(f"Scan path: m/352'/{'0' if network == 'mainnet' else '1'}'/0'/1'/0")
    print(f"Spend path: m/352'/{'0' if network == 'mainnet' else '1'}'/0'/0'/0")
    print(f"Birthdate: {birthdate}")
    if labels:
        print(f"Labels: {sorted(labels)}")
    print()

    try:
        address = seed_to_silent_payment_address(seed_phrase, network=network, birthdate=birthdate, labels=labels)
        print(f"Silent Payment Address: {address}")

    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate Silent Payment addresses from BIP39 seed phrases.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python create_silent_payment_address.py "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  python create_silent_payment_address.py "your seed phrase here" signet
  python create_silent_payment_address.py "your seed phrase here" mainnet --birthdate 926312
  python create_silent_payment_address.py "your seed phrase here" signet --labels 1 3 5
  python create_silent_payment_address.py "your seed phrase here" mainnet --birthdate 850000 --labels 1 2
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

    args = parser.parse_args()

    # If no seed phrase provided, show educational example
    if not args.seed:
        print("Educational example with test seed phrase:")
        print()
        print_detailed_info(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            network=args.network,
            birthdate=args.birthdate,
            labels=args.labels
        )
        sys.exit(0)

    try:
        # Validate labels if provided
        if args.labels:
            if not all(label > 0 for label in args.labels):
                print("Error: All labels must be positive integers greater than 0")
                sys.exit(1)

        print_detailed_info(args.seed, args.network, args.birthdate, args.labels)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
