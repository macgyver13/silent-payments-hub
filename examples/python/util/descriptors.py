#!/usr/bin/env python3
# Copyright (c) 2019 Pieter Wuille
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Utility functions related to output descriptors"""

import re
from bip0352.bech32m import bech32_encode, convertbits, Encoding

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]

def descsum_polymod(symbols):
    """Internal function that computes the descriptor checksum."""
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7ffffffff) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk

def descsum_expand(s):
    """Internal function that does the character to symbol expansion"""
    groups = []
    symbols = []
    for c in s:
        if not c in INPUT_CHARSET:
            return None
        v = INPUT_CHARSET.find(c)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols

def descsum_create(s):
    """Add a checksum to a descriptor without"""
    symbols = descsum_expand(s) + [0, 0, 0, 0, 0, 0, 0, 0]
    checksum = descsum_polymod(symbols) ^ 1
    return s + '#' + ''.join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))

def descsum_check(s, require=True):
    """Verify that the checksum is correct in a descriptor"""
    if not '#' in s:
        return not require
    if s[-9] != '#':
        return False
    if not all(x in CHECKSUM_CHARSET for x in s[-8:]):
        return False
    symbols = descsum_expand(s[:-9]) + [CHECKSUM_CHARSET.find(x) for x in s[-8:]]
    return descsum_polymod(symbols) == 1

def drop_origins(s):
    '''Drop the key origins from a descriptor'''
    desc = re.sub(r'\[.+?\]', '', s)
    if '#' in s:
        desc = desc[:desc.index('#')]
    return descsum_create(desc)


def encode_sp(scan_privkey_bytes: bytes, spend_bytes: bytes, hrp: str = "tspscan") -> str:
    """
    Encode scan private key and spend public key into spscan format.

    Args:
        scan_privkey_bytes: 32-byte scan private key
        spend_pubkey_bytes: 33-byte compressed spend public key
        hrp: Human-readable part ("spscan" for mainnet, "tspscan" for testnets)

    Returns:
        spscan encoded string (e.g., "spscan1q..." or "tspscan1q...")
    """
    # Payload: ser_256(b_scan) || ser_P(B_spend)
    # ser_256 is 32 bytes for private key, ser_P is 33 bytes compressed public key
    data = scan_privkey_bytes + spend_bytes

    # Convert to 5-bit groups for bech32m encoding
    converted = convertbits(data, 8, 5)
    if converted is None:
        raise ValueError("Failed to convert data for bech32m encoding")

    # Encode as bech32m with version 0 (character "q")
    encoded = bech32_encode(hrp, [0] + converted, Encoding.BECH32M)
    if encoded is None:
        raise ValueError("Failed to encode spscan")

    return encoded
