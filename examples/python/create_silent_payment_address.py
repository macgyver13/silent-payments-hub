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
    python create_silent_payment_address.py "your seed phrase here" signet --labels 1-10,15,20-25
    python create_silent_payment_address.py "your seed phrase here" mainnet --birthdate 850000 --labels 1,3,5

WARNING: This is for educational purposes only. Handle seeds securely!
Never share your seed phrase or private keys in production environments.
"""

import sys
import argparse
import re

import bip32utils
from mnemonic import Mnemonic
from util.descriptors import descsum_create, encode_sp
from bip0352.bech32m import convertbits, bech32_encode, Encoding
from bip0352.secp256k1 import ECPubKey, ECKey, TaggedHash
from bip0352.bitcoin_utils import ser_uint32


def parse_label_ranges(labels_str: str) -> list[int]:
    """Parse label range notation into a list of individual label integers.
    
    Args:
        labels_str: Comma-separated labels and ranges (e.g., "1-10,15,20-25")
    
    Returns:
        Sorted list of unique label integers
        
    Examples:
        >>> parse_label_ranges("1-10,15,20-25")
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 21, 22, 23, 24, 25]
        >>> parse_label_ranges("1,3,5")
        [1, 3, 5]
    """
    labels = set()
    
    # Split by comma and process each part
    for part in labels_str.split(','):
        part = part.strip()
        if not part:
            continue
            
        # Check if it's a range (e.g., "1-10")
        if '-' in part:
            match = re.match(r'^(\d+)-(\d+)$', part)
            if not match:
                raise ValueError(f"Invalid label range format: '{part}'. Expected format like '1-10'")
            start, end = int(match.group(1)), int(match.group(2))
            if start < 1 or end < 1:
                raise ValueError(f"Label values must be positive integers > 0. Got range: {start}-{end}")
            if start > end:
                raise ValueError(f"Invalid range: {start}-{end}. Start must be <= end.")
            labels.update(range(start, end + 1))
        else:
            # Single label
            try:
                label = int(part)
            except ValueError:
                raise ValueError(f"Invalid label: '{part}'. Labels must be positive integers.")
            if label < 1:
                raise ValueError(f"Label values must be positive integers > 0. Got: {label}")
            labels.add(label)
    
    return sorted(list(labels))


def format_label_ranges(labels: list[int]) -> str:
    """Format a sorted list of labels into compact range notation.
    
    Args:
        labels: Sorted list of label integers
    
    Returns:
        Compact range notation string (e.g., "1-10,15,20-25")
        
    Examples:
        >>> format_label_ranges([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 21, 22, 23, 24, 25])
        '1-10,15,20-25'
        >>> format_label_ranges([1, 3, 5])
        '1,3,5'
    """
    if not labels:
        return ""
    
    ranges = []
    start = labels[0]
    end = labels[0]
    
    for i in range(1, len(labels)):
        if labels[i] == end + 1:
            # Continue the current range
            end = labels[i]
        else:
            # End the current range and start a new one
            if start == end:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{end}")
            start = end = labels[i]
    
    # Add the final range
    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{end}")
    
    return ",".join(ranges)


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


def generate_label(b_scan: ECKey, m: int) -> bytes:
    """Generate a label tweak for a given label index.
    
    Args:
        b_scan: The scan private key
        m: Label index (positive integer)
    
    Returns:
        32-byte label tweak
    """
    return TaggedHash("BIP0352/Label", b_scan.get_bytes() + ser_uint32(m))


def create_labeled_silent_payment_address(b_scan: ECKey, scan_pubkey: ECPubKey, spend_pubkey: ECPubKey, m: int, hrp: str = "tsp") -> str:
    """Create a labeled Silent Payment address.
    
    Args:
        b_scan: The scan private key
        scan_pubkey: The scan public key (unchanged for labels)
        spend_pubkey: The base spend public key
        m: Label index (positive integer)
        hrp: Human-readable part ("sp" for mainnet, "tsp" for testnet/signet)
    
    Returns:
        Labeled Silent Payment address string
    """
    # Generate the label tweak and add it to the spend public key
    G = ECKey().set(1).get_pubkey()
    B_m = spend_pubkey + generate_label(b_scan, m) * G
    
    # Encode with the same scan key but tweaked spend key
    return encode_silent_payment_address(scan_pubkey, B_m, hrp)


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

        # Sort labels in ascending order and format as compact ranges
        sorted_labels = sorted(labels)
        labels_str = format_label_ranges(sorted_labels)

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
    
    # Generate base address (unlabeled)
    base_address = encode_silent_payment_address(scan_pubkey, spend_pubkey, hrp)
    print(f"Base address (no label): {base_address}")
    
    # Derive payment addresses for each label
    if labels:
        print("\nLabeled addresses:")
        # Create ECKey from scan private key bytes for label generation
        scan_privkey = ECKey().set(scan_privkey_bytes)
        
        for label_idx in sorted(labels):
            labeled_address = create_labeled_silent_payment_address(
                scan_privkey, scan_pubkey, spend_pubkey, label_idx, hrp
            )
            print(f"  Label {label_idx}: {labeled_address}")
    
    return base_address


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
  python create_silent_payment_address.py "your seed phrase here" signet --labels 1-10,15,20-25
  python create_silent_payment_address.py "your seed phrase here" mainnet --birthdate 850000 --labels 1,3,5
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
        type=str,
        help="Label ranges and/or individual labels (e.g., '1-10,15,20-25' or '1,3,5')"
    )

    args = parser.parse_args()

    # Parse labels if provided
    labels = None
    if args.labels:
        try:
            labels = parse_label_ranges(args.labels)
        except ValueError as e:
            print(f"Error parsing labels: {e}")
            sys.exit(1)

    # If no seed phrase provided, show educational example
    if not args.seed:
        print("Educational example with test seed phrase:")
        print()
        print_detailed_info(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            network=args.network,
            birthdate=args.birthdate,
            labels=labels
        )
        sys.exit(0)

    try:
        print_detailed_info(args.seed, args.network, args.birthdate, labels)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
