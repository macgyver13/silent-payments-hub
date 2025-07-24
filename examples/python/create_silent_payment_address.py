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

WARNING: This is for educational purposes only. Handle seeds securely!
Never share your seed phrase or private keys in production environments.
"""

import bip32utils
from mnemonic import Mnemonic
import sys

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
    # Get compressed public key bytes (33 bytes each)
    scan_bytes = bytes(scan_pubkey.get_bytes())
    spend_bytes = bytes(spend_pubkey.get_bytes())
    
    # Silent Payment address format: version (0) + scan_pubkey + spend_pubkey
    # Remove the 0x02/0x03 prefix from compressed pubkeys to get 32-byte x-coordinates
    scan_x = scan_bytes[1:]  # Remove compression prefix
    spend_x = spend_bytes[1:]  # Remove compression prefix
    
    # Combine: version (0) + scan_x (32 bytes) + spend_x (32 bytes) = 65 bytes
    data = bytes([0]) + scan_x + spend_x
    
    # Convert to 5-bit groups for bech32m encoding
    converted = convertbits(data, 8, 5)
    if converted is None:
        raise ValueError("Failed to convert data for bech32m encoding")
    
    # Encode as bech32m with "sp" or "tsp" HRP (Human Readable Part)
    address = bech32_encode(hrp, converted, Encoding.BECH32M)
    if address is None:
        raise ValueError("Failed to encode Silent Payment address")
    
    return address


def seed_to_silent_payment_address(seed_phrase: str, passphrase: str = "", network: str = "signet") -> str:
    """
    Convert BIP39 seed phrase to Silent Payment address.
    
    Args:
        seed_phrase: Space-separated BIP39 words (12 or 24 words)
        passphrase: Optional BIP39 passphrase (empty string if none)
        network: Target network - "mainnet", "testnet", or "signet"
    
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
    
    # Network-specific coin type for BIP44 derivation
    coin_type = 0 if network == "mainnet" else 1
    hrp = "sp" if network == "mainnet" else "tsp"
    
    # BIP352: Silent Payments derivation path m/352'/coin_type'/0'
    silent_payments_key = master_key.ChildKey(352 + 2**31)  # 352'
    silent_payments_key = silent_payments_key.ChildKey(coin_type + 2**31)  # coin_type'  
    silent_payments_key = silent_payments_key.ChildKey(0 + 2**31)  # account 0'
    
    # BIP352: scan key at m/352'/coin_type'/0'/1'/0, spend key at m/352'/coin_type'/0'/0'/0
    scan_private_key = silent_payments_key.ChildKey(1 + 2**31).ChildKey(0)  # /1'/0 (scan)
    spend_private_key = silent_payments_key.ChildKey(0 + 2**31).ChildKey(0)  # /0'/0 (spend)
    
    # Get public keys from private keys
    scan_pubkey_bytes = scan_private_key.PublicKey()
    spend_pubkey_bytes = spend_private_key.PublicKey()
    
    # Create ECPubKey objects for Silent Payment address encoding
    scan_pubkey = ECPubKey().set(scan_pubkey_bytes)
    spend_pubkey = ECPubKey().set(spend_pubkey_bytes)
    
    # Generate Silent Payment address
    return encode_silent_payment_address(scan_pubkey, spend_pubkey, hrp)


def print_detailed_info(seed_phrase: str, network: str = "signet") -> None:
    """Print detailed information about the Silent Payment derivation process."""
    
    print(f"=== Silent Payment Address Generation ===")
    print(f"Network: {network}")
    print(f"Seed phrase: {seed_phrase}")
    print(f"Derivation path: m/352'/{'0' if network == 'mainnet' else '1'}'/0'")
    print(f"Scan path: m/352'/{'0' if network == 'mainnet' else '1'}'/0'/1'/0")
    print(f"Spend path: m/352'/{'0' if network == 'mainnet' else '1'}'/0'/0'/0")
    print()
    
    try:
        address = seed_to_silent_payment_address(seed_phrase, network=network)
        print(f"Silent Payment Address: {address}")

    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python create_silent_payment_address.py \"<BIP39_seed_phrase>\" [network]")
        print("  network: mainnet, testnet, or signet (default: signet)")
        print("  Example: python create_silent_payment_address.py \"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\"")
        print()
        print("Educational example with test seed phrase:")
        print_detailed_info("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        sys.exit(1)
        
    try:
        seed_phrase = sys.argv[1]
        network = sys.argv[2] if len(sys.argv) > 2 else "signet"
        
        print_detailed_info(seed_phrase, network)
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
