#!/usr/bin/env python3
"""
Kalyna-512/512 key-recovery reproducibility code.

Paper:
"Integral Propagation under Modulo-Addition Whitening with Application
to Reduced-Round Kalyna"

Authors: Nitish Kumar, Ranit Dutta, and Bimal Mandal

This file implements the column-wise 64-bit last-round recovery used by
Algorithms 1 and 2 of the paper for Kalyna-512/512.

It also contains the official Kalyna-512/512 key expansion and validates
the implementation against the DSTU 7624:2014 test vector:

    key =
      000102030405060708090a0b0c0d0e0f
      101112131415161718191a1b1c1d1e1f
      202122232425262728292a2b2c2d2e2f
      303132333435363738393a3b3c3d3e3f

    plaintext =
      404142434445464748494a4b4c4d4e4f
      505152535455565758595a5b5c5d5e5f
      606162636465666768696a6b6c6d6e6f
      707172737475767778797a7b7c7d7e7f

    ciphertext =
      4a26e31b811c356aa61dd6ca0596231a
      67ba8354aa47f3a13e1deec320eb56b8
      95d0f417175bab662fd6f134bb15c86c
      cb906a26856efeb7c5bc6472940dd9d9

The paper's literal attack searches 2^64 candidates for each 64-bit
last-round key column.  The default executable mode instead tests a
small deterministic sample of genuine 64-bit candidates containing the
true candidate.  Use --full to express the literal 2^64 search loop.
"""


from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from itertools import product
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

RED_POLY = 0x1D

MDS = [
    [0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04],
    [0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07],
    [0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06],
    [0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08],
    [0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01],
    [0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05],
    [0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01],
    [0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01],
]

SBOXES = [
    [
        0xA8, 0x43, 0x5F, 0x06, 0x6B, 0x75, 0x6C, 0x59, 0x71, 0xDF, 0x87, 0x95, 0x17, 0xF0, 0xD8, 0x09,
        0x6D, 0xF3, 0x1D, 0xCB, 0xC9, 0x4D, 0x2C, 0xAF, 0x79, 0xE0, 0x97, 0xFD, 0x6F, 0x4B, 0x45, 0x39,
        0x3E, 0xDD, 0xA3, 0x4F, 0xB4, 0xB6, 0x9A, 0x0E, 0x1F, 0xBF, 0x15, 0xE1, 0x49, 0xD2, 0x93, 0xC6,
        0x92, 0x72, 0x9E, 0x61, 0xD1, 0x63, 0xFA, 0xEE, 0xF4, 0x19, 0xD5, 0xAD, 0x58, 0xA4, 0xBB, 0xA1,
        0xDC, 0xF2, 0x83, 0x37, 0x42, 0xE4, 0x7A, 0x32, 0x9C, 0xCC, 0xAB, 0x4A, 0x8F, 0x6E, 0x04, 0x27,
        0x2E, 0xE7, 0xE2, 0x5A, 0x96, 0x16, 0x23, 0x2B, 0xC2, 0x65, 0x66, 0x0F, 0xBC, 0xA9, 0x47, 0x41,
        0x34, 0x48, 0xFC, 0xB7, 0x6A, 0x88, 0xA5, 0x53, 0x86, 0xF9, 0x5B, 0xDB, 0x38, 0x7B, 0xC3, 0x1E,
        0x22, 0x33, 0x24, 0x28, 0x36, 0xC7, 0xB2, 0x3B, 0x8E, 0x77, 0xBA, 0xF5, 0x14, 0x9F, 0x08, 0x55,
        0x9B, 0x4C, 0xFE, 0x60, 0x5C, 0xDA, 0x18, 0x46, 0xCD, 0x7D, 0x21, 0xB0, 0x3F, 0x1B, 0x89, 0xFF,
        0xEB, 0x84, 0x69, 0x3A, 0x9D, 0xD7, 0xD3, 0x70, 0x67, 0x40, 0xB5, 0xDE, 0x5D, 0x30, 0x91, 0xB1,
        0x78, 0x11, 0x01, 0xE5, 0x00, 0x68, 0x98, 0xA0, 0xC5, 0x02, 0xA6, 0x74, 0x2D, 0x0B, 0xA2, 0x76,
        0xB3, 0xBE, 0xCE, 0xBD, 0xAE, 0xE9, 0x8A, 0x31, 0x1C, 0xEC, 0xF1, 0x99, 0x94, 0xAA, 0xF6, 0x26,
        0x2F, 0xEF, 0xE8, 0x8C, 0x35, 0x03, 0xD4, 0x7F, 0xFB, 0x05, 0xC1, 0x5E, 0x90, 0x20, 0x3D, 0x82,
        0xF7, 0xEA, 0x0A, 0x0D, 0x7E, 0xF8, 0x50, 0x1A, 0xC4, 0x07, 0x57, 0xB8, 0x3C, 0x62, 0xE3, 0xC8,
        0xAC, 0x52, 0x64, 0x10, 0xD0, 0xD9, 0x13, 0x0C, 0x12, 0x29, 0x51, 0xB9, 0xCF, 0xD6, 0x73, 0x8D,
        0x81, 0x54, 0xC0, 0xED, 0x4E, 0x44, 0xA7, 0x2A, 0x85, 0x25, 0xE6, 0xCA, 0x7C, 0x8B, 0x56, 0x80
    ],
    [
        0xCE, 0xBB, 0xEB, 0x92, 0xEA, 0xCB, 0x13, 0xC1, 0xE9, 0x3A, 0xD6, 0xB2, 0xD2, 0x90, 0x17, 0xF8,
        0x42, 0x15, 0x56, 0xB4, 0x65, 0x1C, 0x88, 0x43, 0xC5, 0x5C, 0x36, 0xBA, 0xF5, 0x57, 0x67, 0x8D,
        0x31, 0xF6, 0x64, 0x58, 0x9E, 0xF4, 0x22, 0xAA, 0x75, 0x0F, 0x02, 0xB1, 0xDF, 0x6D, 0x73, 0x4D,
        0x7C, 0x26, 0x2E, 0xF7, 0x08, 0x5D, 0x44, 0x3E, 0x9F, 0x14, 0xC8, 0xAE, 0x54, 0x10, 0xD8, 0xBC,
        0x1A, 0x6B, 0x69, 0xF3, 0xBD, 0x33, 0xAB, 0xFA, 0xD1, 0x9B, 0x68, 0x4E, 0x16, 0x95, 0x91, 0xEE,
        0x4C, 0x63, 0x8E, 0x5B, 0xCC, 0x3C, 0x19, 0xA1, 0x81, 0x49, 0x7B, 0xD9, 0x6F, 0x37, 0x60, 0xCA,
        0xE7, 0x2B, 0x48, 0xFD, 0x96, 0x45, 0xFC, 0x41, 0x12, 0x0D, 0x79, 0xE5, 0x89, 0x8C, 0xE3, 0x20,
        0x30, 0xDC, 0xB7, 0x6C, 0x4A, 0xB5, 0x3F, 0x97, 0xD4, 0x62, 0x2D, 0x06, 0xA4, 0xA5, 0x83, 0x5F,
        0x2A, 0xDA, 0xC9, 0x00, 0x7E, 0xA2, 0x55, 0xBF, 0x11, 0xD5, 0x9C, 0xCF, 0x0E, 0x0A, 0x3D, 0x51,
        0x7D, 0x93, 0x1B, 0xFE, 0xC4, 0x47, 0x09, 0x86, 0x0B, 0x8F, 0x9D, 0x6A, 0x07, 0xB9, 0xB0, 0x98,
        0x18, 0x32, 0x71, 0x4B, 0xEF, 0x3B, 0x70, 0xA0, 0xE4, 0x40, 0xFF, 0xC3, 0xA9, 0xE6, 0x78, 0xF9,
        0x8B, 0x46, 0x80, 0x1E, 0x38, 0xE1, 0xB8, 0xA8, 0xE0, 0x0C, 0x23, 0x76, 0x1D, 0x25, 0x24, 0x05,
        0xF1, 0x6E, 0x94, 0x28, 0x9A, 0x84, 0xE8, 0xA3, 0x4F, 0x77, 0xD3, 0x85, 0xE2, 0x52, 0xF2, 0x82,
        0x50, 0x7A, 0x2F, 0x74, 0x53, 0xB3, 0x61, 0xAF, 0x39, 0x35, 0xDE, 0xCD, 0x1F, 0x99, 0xAC, 0xAD,
        0x72, 0x2C, 0xDD, 0xD0, 0x87, 0xBE, 0x5E, 0xA6, 0xEC, 0x04, 0xC6, 0x03, 0x34, 0xFB, 0xDB, 0x59,
        0xB6, 0xC2, 0x01, 0xF0, 0x5A, 0xED, 0xA7, 0x66, 0x21, 0x7F, 0x8A, 0x27, 0xC7, 0xC0, 0x29, 0xD7
    ],
    [
        0x93, 0xD9, 0x9A, 0xB5, 0x98, 0x22, 0x45, 0xFC, 0xBA, 0x6A, 0xDF, 0x02, 0x9F, 0xDC, 0x51, 0x59,
        0x4A, 0x17, 0x2B, 0xC2, 0x94, 0xF4, 0xBB, 0xA3, 0x62, 0xE4, 0x71, 0xD4, 0xCD, 0x70, 0x16, 0xE1,
        0x49, 0x3C, 0xC0, 0xD8, 0x5C, 0x9B, 0xAD, 0x85, 0x53, 0xA1, 0x7A, 0xC8, 0x2D, 0xE0, 0xD1, 0x72,
        0xA6, 0x2C, 0xC4, 0xE3, 0x76, 0x78, 0xB7, 0xB4, 0x09, 0x3B, 0x0E, 0x41, 0x4C, 0xDE, 0xB2, 0x90,
        0x25, 0xA5, 0xD7, 0x03, 0x11, 0x00, 0xC3, 0x2E, 0x92, 0xEF, 0x4E, 0x12, 0x9D, 0x7D, 0xCB, 0x35,
        0x10, 0xD5, 0x4F, 0x9E, 0x4D, 0xA9, 0x55, 0xC6, 0xD0, 0x7B, 0x18, 0x97, 0xD3, 0x36, 0xE6, 0x48,
        0x56, 0x81, 0x8F, 0x77, 0xCC, 0x9C, 0xB9, 0xE2, 0xAC, 0xB8, 0x2F, 0x15, 0xA4, 0x7C, 0xDA, 0x38,
        0x1E, 0x0B, 0x05, 0xD6, 0x14, 0x6E, 0x6C, 0x7E, 0x66, 0xFD, 0xB1, 0xE5, 0x60, 0xAF, 0x5E, 0x33,
        0x87, 0xC9, 0xF0, 0x5D, 0x6D, 0x3F, 0x88, 0x8D, 0xC7, 0xF7, 0x1D, 0xE9, 0xEC, 0xED, 0x80, 0x29,
        0x27, 0xCF, 0x99, 0xA8, 0x50, 0x0F, 0x37, 0x24, 0x28, 0x30, 0x95, 0xD2, 0x3E, 0x5B, 0x40, 0x83,
        0xB3, 0x69, 0x57, 0x1F, 0x07, 0x1C, 0x8A, 0xBC, 0x20, 0xEB, 0xCE, 0x8E, 0xAB, 0xEE, 0x31, 0xA2,
        0x73, 0xF9, 0xCA, 0x3A, 0x1A, 0xFB, 0x0D, 0xC1, 0xFE, 0xFA, 0xF2, 0x6F, 0xBD, 0x96, 0xDD, 0x43,
        0x52, 0xB6, 0x08, 0xF3, 0xAE, 0xBE, 0x19, 0x89, 0x32, 0x26, 0xB0, 0xEA, 0x4B, 0x64, 0x84, 0x82,
        0x6B, 0xF5, 0x79, 0xBF, 0x01, 0x5F, 0x75, 0x63, 0x1B, 0x23, 0x3D, 0x68, 0x2A, 0x65, 0xE8, 0x91,
        0xF6, 0xFF, 0x13, 0x58, 0xF1, 0x47, 0x0A, 0x7F, 0xC5, 0xA7, 0xE7, 0x61, 0x5A, 0x06, 0x46, 0x44,
        0x42, 0x04, 0xA0, 0xDB, 0x39, 0x86, 0x54, 0xAA, 0x8C, 0x34, 0x21, 0x8B, 0xF8, 0x0C, 0x74, 0x67
    ],
    [
        0x68, 0x8D, 0xCA, 0x4D, 0x73, 0x4B, 0x4E, 0x2A, 0xD4, 0x52, 0x26, 0xB3, 0x54, 0x1E, 0x19, 0x1F,
        0x22, 0x03, 0x46, 0x3D, 0x2D, 0x4A, 0x53, 0x83, 0x13, 0x8A, 0xB7, 0xD5, 0x25, 0x79, 0xF5, 0xBD,
        0x58, 0x2F, 0x0D, 0x02, 0xED, 0x51, 0x9E, 0x11, 0xF2, 0x3E, 0x55, 0x5E, 0xD1, 0x16, 0x3C, 0x66,
        0x70, 0x5D, 0xF3, 0x45, 0x40, 0xCC, 0xE8, 0x94, 0x56, 0x08, 0xCE, 0x1A, 0x3A, 0xD2, 0xE1, 0xDF,
        0xB5, 0x38, 0x6E, 0x0E, 0xE5, 0xF4, 0xF9, 0x86, 0xE9, 0x4F, 0xD6, 0x85, 0x23, 0xCF, 0x32, 0x99,
        0x31, 0x14, 0xAE, 0xEE, 0xC8, 0x48, 0xD3, 0x30, 0xA1, 0x92, 0x41, 0xB1, 0x18, 0xC4, 0x2C, 0x71,
        0x72, 0x44, 0x15, 0xFD, 0x37, 0xBE, 0x5F, 0xAA, 0x9B, 0x88, 0xD8, 0xAB, 0x89, 0x9C, 0xFA, 0x60,
        0xEA, 0xBC, 0x62, 0x0C, 0x24, 0xA6, 0xA8, 0xEC, 0x67, 0x20, 0xDB, 0x7C, 0x28, 0xDD, 0xAC, 0x5B,
        0x34, 0x7E, 0x10, 0xF1, 0x7B, 0x8F, 0x63, 0xA0, 0x05, 0x9A, 0x43, 0x77, 0x21, 0xBF, 0x27, 0x09,
        0xC3, 0x9F, 0xB6, 0xD7, 0x29, 0xC2, 0xEB, 0xC0, 0xA4, 0x8B, 0x8C, 0x1D, 0xFB, 0xFF, 0xC1, 0xB2,
        0x97, 0x2E, 0xF8, 0x65, 0xF6, 0x75, 0x07, 0x04, 0x49, 0x33, 0xE4, 0xD9, 0xB9, 0xD0, 0x42, 0xC7,
        0x6C, 0x90, 0x00, 0x8E, 0x6F, 0x50, 0x01, 0xC5, 0xDA, 0x47, 0x3F, 0xCD, 0x69, 0xA2, 0xE2, 0x7A,
        0xA7, 0xC6, 0x93, 0x0F, 0x0A, 0x06, 0xE6, 0x2B, 0x96, 0xA3, 0x1C, 0xAF, 0x6A, 0x12, 0x84, 0x39,
        0xE7, 0xB0, 0x82, 0xF7, 0xFE, 0x9D, 0x87, 0x5C, 0x81, 0x35, 0xDE, 0xB4, 0xA5, 0xFC, 0x80, 0xEF,
        0xCB, 0xBB, 0x6B, 0x76, 0xBA, 0x5A, 0x7D, 0x78, 0x0B, 0x95, 0xE3, 0xAD, 0x74, 0x98, 0x3B, 0x36,
        0x64, 0x6D, 0xDC, 0xF0, 0x59, 0xA9, 0x4C, 0x17, 0x7F, 0x91, 0xB8, 0xC9, 0x57, 0x1B, 0xE0, 0x61
    ]
]

State = List[int]


# ---------------------------------------------------------------------------
# GF(2^8)
# ---------------------------------------------------------------------------

def gf_mul(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= RED_POLY
        b >>= 1
    return out & 0xFF


def gf_pow(a: int, e: int) -> int:
    result = 1
    base = a & 0xFF
    while e:
        if e & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        e >>= 1
    return result


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("0 has no multiplicative inverse")
    return gf_pow(a, 254)


def invert_matrix_gf256(mat: Sequence[Sequence[int]]) -> List[List[int]]:
    n = len(mat)
    aug = []
    for i in range(n):
        row = [int(x) & 0xFF for x in mat[i]] + [0] * n
        row[n + i] = 1
        aug.append(row)

    for col in range(n):
        pivot = next((r for r in range(col, n) if aug[r][col] != 0), None)
        if pivot is None:
            raise ValueError("Matrix is not invertible")
        if pivot != col:
            aug[col], aug[pivot] = aug[pivot], aug[col]

        invp = gf_inv(aug[col][col])
        aug[col] = [gf_mul(x, invp) for x in aug[col]]

        for r in range(n):
            if r == col:
                continue
            f = aug[r][col]
            if f:
                aug[r] = [x ^ gf_mul(f, y) for x, y in zip(aug[r], aug[col])]

    return [row[n:] for row in aug]


INV_MDS = invert_matrix_gf256(MDS)

# Precompute the finite-field products used by MDS / inverse-MDS.
_MUL_COEFFS = sorted({x for row in MDS for x in row} | {x for row in INV_MDS for x in row})
MUL_TABLE = {a: [gf_mul(a, x) for x in range(256)] for a in _MUL_COEFFS}


def build_inverse_sboxes() -> List[List[int]]:
    result = []
    for sb in SBOXES:
        inv = [0] * 256
        for x, y in enumerate(sb):
            inv[y] = x
        result.append(inv)
    return result


INV_SBOXES = build_inverse_sboxes()


# ---------------------------------------------------------------------------
# Variant/state helpers
# ---------------------------------------------------------------------------

def nbytes(block_bits: int) -> int:
    if block_bits not in (128, 256, 512):
        raise ValueError("block_bits must be 128, 256, or 512")
    return block_bits // 8


def ncols(block_bits: int) -> int:
    return block_bits // 64


def validate_state(state: Sequence[int], block_bits: int) -> None:
    if len(state) != nbytes(block_bits):
        raise ValueError(f"state must contain {nbytes(block_bits)} bytes")
    if any(not (0 <= x <= 255) for x in state):
        raise ValueError("state bytes must be in 0..255")


def validate_key(key: Sequence[int], block_bits: int, name: str = "key") -> None:
    if len(key) != nbytes(block_bits):
        raise ValueError(f"{name} must contain {nbytes(block_bits)} bytes")
    if any(not (0 <= x <= 255) for x in key):
        raise ValueError(f"{name} bytes must be in 0..255")


def rc_to_pos(row: int, col: int) -> int:
    """Column-major Kalyna byte numbering: position = 8*column + row."""
    return 8 * col + row


def pos_to_rc(pos: int) -> Tuple[int, int]:
    return pos % 8, pos // 8


def matrix_string(state_or_symbols: Sequence[object], block_bits: int) -> str:
    cols = ncols(block_bits)
    rows = []
    for r in range(8):
        row = []
        for c in range(cols):
            row.append(str(state_or_symbols[rc_to_pos(r, c)]))
        rows.append(" ".join(f"{x:>3}" for x in row))
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Kalyna layers
# ---------------------------------------------------------------------------

def sub_bytes(state: Sequence[int], block_bits: int) -> State:
    validate_state(state, block_bits)
    return [SBOXES[i % 8 % 4][v] for i, v in enumerate(state)]


def inv_sub_bytes(state: Sequence[int], block_bits: int) -> State:
    validate_state(state, block_bits)
    return [INV_SBOXES[i % 8 % 4][v] for i, v in enumerate(state)]


def row_shift(row: int, block_bits: int) -> int:
    # delta_i = floor(i * block_size / 512)
    return (row * block_bits) // 512


def shift_rows(state: Sequence[int], block_bits: int) -> State:
    validate_state(state, block_bits)
    cols = ncols(block_bits)
    out = [0] * len(state)
    for r in range(8):
        s = row_shift(r, block_bits)
        for c in range(cols):
            out[rc_to_pos(r, (c + s) % cols)] = state[rc_to_pos(r, c)]
    return out


def inv_shift_rows(state: Sequence[int], block_bits: int) -> State:
    validate_state(state, block_bits)
    cols = ncols(block_bits)
    out = [0] * len(state)
    for r in range(8):
        s = row_shift(r, block_bits)
        for c in range(cols):
            out[rc_to_pos(r, c)] = state[rc_to_pos(r, (c + s) % cols)]
    return out


def mix_single_column(col: Sequence[int], mat: Sequence[Sequence[int]]) -> List[int]:
    if len(col) != 8:
        raise ValueError("Kalyna columns contain exactly 8 bytes")
    out = [0] * 8
    for r in range(8):
        acc = 0
        for k in range(8):
            acc ^= MUL_TABLE[mat[r][k]][col[k]]
        out[r] = acc & 0xFF
    return out


def mix_columns(state: Sequence[int], block_bits: int) -> State:
    validate_state(state, block_bits)
    out = [0] * len(state)
    for c in range(ncols(block_bits)):
        base = 8 * c
        out[base:base + 8] = mix_single_column(state[base:base + 8], MDS)
    return out


def inv_mix_columns(state: Sequence[int], block_bits: int) -> State:
    validate_state(state, block_bits)
    out = [0] * len(state)
    for c in range(ncols(block_bits)):
        base = 8 * c
        out[base:base + 8] = mix_single_column(state[base:base + 8], INV_MDS)
    return out


def xor_key(state: Sequence[int], key: Sequence[int], block_bits: int) -> State:
    validate_state(state, block_bits)
    validate_key(key, block_bits, "round key")
    return [x ^ k for x, k in zip(state, key)]


def add64_per_column(state: Sequence[int], key: Sequence[int], block_bits: int) -> State:
    validate_state(state, block_bits)
    validate_key(key, block_bits, "whitening key")
    out = [0] * len(state)
    for c in range(ncols(block_bits)):
        base = 8 * c
        x = int.from_bytes(bytes(state[base:base + 8]), "little")
        k = int.from_bytes(bytes(key[base:base + 8]), "little")
        y = (x + k) & 0xFFFFFFFFFFFFFFFF
        out[base:base + 8] = y.to_bytes(8, "little")
    return list(out)


def sub64_per_column(state: Sequence[int], key: Sequence[int], block_bits: int) -> State:
    validate_state(state, block_bits)
    validate_key(key, block_bits, "whitening key")
    out = [0] * len(state)
    for c in range(ncols(block_bits)):
        base = 8 * c
        x = int.from_bytes(bytes(state[base:base + 8]), "little")
        k = int.from_bytes(bytes(key[base:base + 8]), "little")
        y = (x - k) & 0xFFFFFFFFFFFFFFFF
        out[base:base + 8] = y.to_bytes(8, "little")
    return list(out)


def forward_round(state: Sequence[int], round_key: Sequence[int], block_bits: int) -> State:
    s = sub_bytes(state, block_bits)
    s = shift_rows(s, block_bits)
    s = mix_columns(s, block_bits)
    s = xor_key(s, round_key, block_bits)
    return s


def inverse_round(state: Sequence[int], round_key: Sequence[int], block_bits: int) -> State:
    s = xor_key(state, round_key, block_bits)
    s = inv_mix_columns(s, block_bits)
    s = inv_shift_rows(s, block_bits)
    s = inv_sub_bytes(s, block_bits)
    return s


# ---------------------------------------------------------------------------
# Integral statistics
# ---------------------------------------------------------------------------

class ByteStats:
    def __init__(self) -> None:
        self.counts = [0] * 256
        self.total = 0

    def add(self, value: int) -> None:
        self.counts[value & 0xFF] += 1
        self.total += 1

    def xor_sum(self) -> int:
        x = 0
        for value, count in enumerate(self.counts):
            if count & 1:
                x ^= value
        return x

    def is_constant(self) -> bool:
        return sum(c > 0 for c in self.counts) == 1

    def is_all(self) -> bool:
        # Todo's strict ALL: every byte value appears equally often.
        return self.total > 0 and len(set(self.counts)) == 1

    def symbol(self) -> str:
        if self.is_constant():
            return "C"
        if self.is_all():
            return "A"
        if self.xor_sum() == 0:
            return "B"
        return "U"


def summarize_states(states: Iterable[Sequence[int]], block_bits: int) -> Tuple[List[str], int]:
    stats = [ByteStats() for _ in range(nbytes(block_bits))]
    count = 0
    for state in states:
        validate_state(state, block_bits)
        count += 1
        for i, v in enumerate(state):
            stats[i].add(v)
    return [s.symbol() for s in stats], count


def balanced_positions(symbols: Sequence[str]) -> List[int]:
    return [i for i, s in enumerate(symbols) if s in ("A", "B")]


# ---------------------------------------------------------------------------
# Multisets
# ---------------------------------------------------------------------------

def constants_state(block_bits: int, constants: Optional[Sequence[int]] = None) -> State:
    if constants is None:
        return [0] * nbytes(block_bits)
    validate_state(constants, block_bits)
    return list(constants)


def single_active_multiset(
    block_bits: int,
    active_pos: int,
    constants: Optional[Sequence[int]] = None,
) -> Iterator[State]:
    base = constants_state(block_bits, constants)
    if not (0 <= active_pos < len(base)):
        raise ValueError("active_pos out of range")
    for a in range(256):
        s = base.copy()
        s[active_pos] = a
        yield s


def two_independent_active_multiset(
    block_bits: int,
    pos1: int,
    pos2: int,
    constants: Optional[Sequence[int]] = None,
) -> Iterator[State]:
    base = constants_state(block_bits, constants)
    if pos1 == pos2:
        raise ValueError("active positions must be distinct")
    if not (0 <= pos1 < len(base) and 0 <= pos2 < len(base)):
        raise ValueError("active position out of range")
    for a, b in product(range(256), repeat=2):
        s = base.copy()
        s[pos1] = a
        s[pos2] = b
        yield s


def inverse_round_multiset(
    states: Iterable[Sequence[int]],
    block_bits: int,
    round_key: Sequence[int],
    times: int = 1,
) -> Iterator[State]:
    for state in states:
        s = list(state)
        for _ in range(times):
            s = inverse_round(s, round_key, block_bits)
        yield s


# ---------------------------------------------------------------------------
# Reduced-round tracing
# ---------------------------------------------------------------------------

def deterministic_key(block_bits: int, seed: int) -> State:
    """Deterministic nonzero fixed key used only for reproducible tests."""
    return [((seed + 29 * i + 17 * (i * i)) & 0xFF) for i in range(nbytes(block_bits))]


def zero_key(block_bits: int) -> State:
    return [0] * nbytes(block_bits)


def trace_one(
    state: Sequence[int],
    block_bits: int,
    rounds: int,
    prewhitening_key: Optional[Sequence[int]],
    round_keys: Sequence[Sequence[int]],
) -> State:
    s = list(state)
    if prewhitening_key is not None:
        s = add64_per_column(s, prewhitening_key, block_bits)
    for r in range(rounds):
        s = forward_round(s, round_keys[r], block_bits)
    return s


def trace_multiset(
    states: Iterable[Sequence[int]],
    block_bits: int,
    rounds: int,
    prewhitening_key: Optional[Sequence[int]],
    round_keys: Sequence[Sequence[int]],
) -> Iterator[State]:
    for state in states:
        yield trace_one(state, block_bits, rounds, prewhitening_key, round_keys)


def print_result(name: str, block_bits: int, symbols: Sequence[str], texts: int) -> None:
    bal = balanced_positions(symbols)
    print("=" * 78)
    print(name)
    print("=" * 78)
    print(f"block size       : {block_bits}")
    print(f"texts            : {texts}")
    print(f"balanced bytes   : {len(bal)}/{nbytes(block_bits)}")
    print("A/C/B/U matrix:")
    print(matrix_string(symbols, block_bits))
    print()







MASK64 = (1 << 64) - 1
BLOCK_BITS = 512
COLS = 8
NR_512_512 = 18

OFFICIAL_TEST_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f"
)
OFFICIAL_TEST_PLAINTEXT = bytes.fromhex(
    "404142434445464748494a4b4c4d4e4f"
    "505152535455565758595a5b5c5d5e5f"
    "606162636465666768696a6b6c6d6e6f"
    "707172737475767778797a7b7c7d7e7f"
)
OFFICIAL_TEST_CIPHERTEXT = bytes.fromhex(
    "4a26e31b811c356aa61dd6ca0596231a"
    "67ba8354aa47f3a13e1deec320eb56b8"
    "95d0f417175bab662fd6f134bb15c86c"
    "cb906a26856efeb7c5bc6472940dd9d9"
)


def core_round(state: Sequence[int]) -> State:
    s = sub_bytes(state, 512)
    s = shift_rows(s, 512)
    s = mix_columns(s, 512)
    return s


def final_round(state: Sequence[int], final_key: Sequence[int]) -> State:
    """
    Final Kalyna round:
        SB -> SR -> MC -> (+ mod 2^64) K_r.
    """
    return add64_per_column(core_round(state), final_key, 512)


# ---------------------------------------------------------------------------
# Official Kalyna-512/512 key schedule
# ---------------------------------------------------------------------------

def words_from_bytes_le(data: Sequence[int]) -> List[int]:
    if len(data) % 8:
        raise ValueError("byte length must be a multiple of 8")
    return [
        int.from_bytes(bytes(data[i:i+8]), "little")
        for i in range(0, len(data), 8)
    ]


def bytes_from_words_le(words: Sequence[int]) -> State:
    out: State = []
    for word in words:
        out.extend((word & MASK64).to_bytes(8, "little"))
    return list(out)


def add_words_mod64(a: Sequence[int], b: Sequence[int]) -> List[int]:
    return [((x + y) & MASK64) for x, y in zip(a, b)]


def xor_words(a: Sequence[int], b: Sequence[int]) -> List[int]:
    return [(x ^ y) & MASK64 for x, y in zip(a, b)]


def core_round_words(words: Sequence[int]) -> List[int]:
    return words_from_bytes_le(core_round(bytes_from_words_le(words)))


def rotate_left_bytes(state: Sequence[int], n: int) -> State:
    n %= len(state)
    return list(state[n:]) + list(state[:n])


def rotate_right_bytes(state: Sequence[int], n: int) -> State:
    n %= len(state)
    return list(state[-n:]) + list(state[:-n])


def odd_round_key_from_even(even_key: Sequence[int]) -> State:
    """
    Official KeyExpandOdd relation.

    For Kalyna-512, N_b=8, so the byte rotation is
        2*N_b + 3 = 19 bytes.
    """
    return rotate_left_bytes(even_key, 19)


def even_round_key_from_odd(odd_key: Sequence[int]) -> State:
    return rotate_right_bytes(odd_key, 19)


def kalyna512_512_key_expand(master_key: Sequence[int]) -> List[State]:
    """
    Port of the official reference key expansion for block=512, key=512.

    Returns K0,...,K18.
    """
    if len(master_key) != 64:
        raise ValueError("Kalyna-512/512 master key must contain 64 bytes")

    key_words = words_from_bytes_le(master_key)
    nb = nk = 8

    # KeyExpandKt.
    state = [0] * nb
    state[0] = nb + nk + 1  # 17

    k0 = key_words.copy()
    k1 = key_words.copy()

    state = add_words_mod64(state, k0)
    state = core_round_words(state)
    state = xor_words(state, k1)
    state = core_round_words(state)
    state = add_words_mod64(state, k0)
    state = core_round_words(state)
    kt = state.copy()

    # KeyExpandEven.
    initial_data = key_words.copy()
    tmv = [0x0001000100010001] * nb
    round_keys: List[Optional[State]] = [None] * (NR_512_512 + 1)

    round_index = 0
    while True:
        kt_round = add_words_mod64(kt, tmv)

        state = add_words_mod64(initial_data, kt_round)
        state = core_round_words(state)
        state = xor_words(state, kt_round)
        state = core_round_words(state)
        state = add_words_mod64(state, kt_round)

        round_keys[round_index] = bytes_from_words_le(state)

        if round_index == NR_512_512:
            break

        round_index += 2
        tmv = [((word << 1) & MASK64) for word in tmv]

        # Official Rotate(ctx->nk, initial_data): one 64-bit word left.
        initial_data = initial_data[1:] + initial_data[:1]

    # KeyExpandOdd.
    for r in range(1, NR_512_512, 2):
        even_key = round_keys[r - 1]
        assert even_key is not None
        round_keys[r] = odd_round_key_from_even(even_key)

    assert all(k is not None for k in round_keys)
    return [list(k) for k in round_keys if k is not None]


def kalyna512_512_encrypt_block(
    plaintext: Sequence[int],
    round_keys: Sequence[Sequence[int]],
) -> State:
    if len(plaintext) != 64:
        raise ValueError("plaintext must contain 64 bytes")
    if len(round_keys) != 19:
        raise ValueError("Kalyna-512/512 requires K0,...,K18")

    s = add64_per_column(plaintext, round_keys[0], 512)

    for r in range(1, 18):
        s = forward_round(s, round_keys[r], 512)

    s = core_round(s)
    s = add64_per_column(s, round_keys[18], 512)
    return s


def official_self_test() -> None:
    """
    End-to-end validation of the cipher primitive and full key schedule.
    """
    round_keys = kalyna512_512_key_expand(OFFICIAL_TEST_KEY)
    ciphertext = kalyna512_512_encrypt_block(
        OFFICIAL_TEST_PLAINTEXT,
        round_keys,
    )
    assert bytes(ciphertext) == OFFICIAL_TEST_CIPHERTEXT

    for r in range(1, 18, 2):
        assert round_keys[r] == odd_round_key_from_even(round_keys[r - 1])
        assert round_keys[r - 1] == even_round_key_from_odd(round_keys[r])


# ---------------------------------------------------------------------------
# Fast final-column partial decryption
# ---------------------------------------------------------------------------

INV_MDS_MUL = [
    [
        [gf_mul(x, INV_MDS[row][col]) for x in range(256)]
        for col in range(8)
    ]
    for row in range(8)
]


def column_u64(state: Sequence[int], column: int) -> int:
    base = 8 * column
    return int.from_bytes(bytes(state[base:base+8]), "little")


def u64_to_column(x: int) -> List[int]:
    return list((x & MASK64).to_bytes(8, "little"))


def set_column(state: State, column: int, value: int) -> None:
    base = 8 * column
    state[base:base+8] = u64_to_column(value)


def key_hex(key: Sequence[int]) -> str:
    return bytes(key).hex()


def inverse_final_column_bytes(cword: int, key_guess: int) -> List[int]:
    """
    Algorithm 1, one 64-bit ciphertext column:

        C_j - K_j -> MC^{-1} -> SR^{-1} -> SB^{-1}.

    SR^{-1} changes positions only, so the eight balance sums can be
    accumulated by row without materializing a full 64-byte state.
    """
    u = (cword - key_guess) & MASK64
    b = [(u >> (8*i)) & 0xFF for i in range(8)]

    out = [0] * 8
    for row in range(8):
        tables = INV_MDS_MUL[row]
        v = (
            tables[0][b[0]] ^ tables[1][b[1]]
            ^ tables[2][b[2]] ^ tables[3][b[3]]
            ^ tables[4][b[4]] ^ tables[5][b[5]]
            ^ tables[6][b[6]] ^ tables[7][b[7]]
        )
        out[row] = INV_SBOXES[row % 4][v]
    return out


def recovered_positions_for_column(column: int) -> List[int]:
    """
    I_j from Algorithm 1 after undoing Kalyna-512 ShiftRows.
    """
    positions = []
    for row in range(8):
        src_col = (column - row_shift(row, 512)) % COLS
        positions.append(rc_to_pos(row, src_col))
    return positions


def candidate_survives_column_sets(
    ciphertext_column_sets: Sequence[Sequence[int]],
    key_guess: int,
) -> bool:
    for cwords in ciphertext_column_sets:
        sums = [0] * 8

        for cword in cwords:
            vals = inverse_final_column_bytes(cword, key_guess)
            for row in range(8):
                sums[row] ^= vals[row]

        if any(sums):
            return False

    return True


def demo_candidate_space(
    true_value: int,
    count: int,
    seed: int,
) -> List[int]:
    if count < 1:
        raise ValueError("candidate count must be positive")

    values = {true_value & MASK64}
    x = (0x9E3779B97F4A7C15 ^ seed) & MASK64

    while len(values) < count:
        x = (
            6364136223846793005 * x
            + 1442695040888963407
        ) & MASK64
        values.add(x)

    return sorted(values)


def recover_last_round_key(
    ciphertext_sets: Sequence[Sequence[Sequence[int]]],
    true_last_key: Sequence[int],
    full: bool,
    demo_candidates: int,
) -> State:
    """
    ciphertext_sets[set_index][column] contains the 64-bit ciphertext
    words for one column of one integral multiset.
    """
    recovered = [0] * 64

    for column in range(COLS):
        true_col = column_u64(true_last_key, column)

        print()
        print(f"Column {column}")
        print(
            "Recovered positions : "
            + ",".join(str(x) for x in recovered_positions_for_column(column))
        )
        print("Paper search space : 2^64 candidates for this 64-bit column")

        if full:
            candidates: Iterable[int] = range(1 << 64)
            print("Search mode        : complete paper search")
        else:
            candidates = demo_candidate_space(
                true_col,
                demo_candidates,
                0x512000 + column,
            )
            print(
                "Search mode        : demo over "
                f"{demo_candidates} sampled 64-bit candidates"
            )

        survivors: List[int] = []
        column_sets = [dataset[column] for dataset in ciphertext_sets]

        for guess in candidates:
            if candidate_survives_column_sets(column_sets, guess):
                survivors.append(guess)

        print(f"Surviving candidates: {len(survivors)}")
        for value in survivors[:8]:
            print(f"  {value:016x}")

        if len(survivors) != 1:
            raise RuntimeError(
                f"column {column}: expected one survivor in this run, "
                f"observed {len(survivors)}"
            )

        set_column(recovered, column, survivors[0])

    return recovered


# ---------------------------------------------------------------------------
# Integral structures from Sections 5.1--5.3
# ---------------------------------------------------------------------------

M4_REQUIRED_ZERO_CONSTANTS = (
    16, 17, 18, 19, 20, 21, 24,
    25, 26, 27, 28, 32, 33, 34,
    35, 40, 41, 42, 48, 49, 56,
)

M4_ACTIVE_POSITIONS = (
    0, 15, 22, 29, 36, 43, 50, 57,
)


def iter_standard_m3(seed: int) -> Iterator[State]:
    """
    Section 5.1 representative M^(3)_512:
    byte 7 active, all other bytes constant, size 2^8.
    """
    constants = [
        ((seed + 13*i + 7*i*i) & 0xFF)
        for i in range(64)
    ]

    for a in range(256):
        s = constants.copy()
        s[7] = a
        yield s


def make_m4_weak_prewhitening_key() -> State:
    """
    Concrete nonzero member of the paper's 2^448 K_pw weak-key space.
    """
    key = deterministic_key(512, 17)
    for p in M4_ACTIVE_POSITIONS:
        key[p] = 0
    return key


def build_m3_template_for_m4_constraints(
    kpw: Sequence[int],
    k1: Sequence[int],
    seed: int,
) -> State:
    """
    Select fixed M^(3)_512 bytes so that inverse propagation and removal
    of K_pw produce exactly the fixed-zero plaintext constants stated in
    Section 5.2.
    """
    template = [0] * 64
    z_columns: List[List[Optional[int]]] = [
        [None] * 8 for _ in range(COLS)
    ]

    for p in M4_REQUIRED_ZERO_CONSTANTS:
        row = p % 8
        col = p // 8

        desired_after_prew_byte = kpw[p]
        before_inv_s = SBOXES[row % 4][desired_after_prew_byte]

        shifted_col = (col + row_shift(row, 512)) % COLS
        z_columns[shifted_col][row] = before_inv_s

    for c in range(COLS):
        z = []
        for row, value in enumerate(z_columns[c]):
            if value is None:
                value = (31*seed + 23*c + 19*row + 7) & 0xFF
            z.append(value)

        w = mix_single_column(z, MDS)  # w = M3_col xor K1_col
        base = 8 * c
        template[base:base+8] = [
            w[i] ^ k1[base+i]
            for i in range(8)
        ]

    return template


def iter_weak_m4_plaintexts(
    kpw: Sequence[int],
    k1: Sequence[int],
    seed: int,
) -> Iterator[State]:
    """
    Exact Section 5.2 M^(4)_512 plaintext multiset, size 2^8.
    """
    template = build_m3_template_for_m4_constraints(kpw, k1, seed)

    for a in range(256):
        m3 = template.copy()
        m3[7] = a

        after_prew = inverse_round(m3, k1, 512)
        plaintext = sub64_per_column(after_prew, kpw, 512)

        for p in M4_REQUIRED_ZERO_CONSTANTS:
            assert plaintext[p] == 0

        yield plaintext


def iter_no_prew_m5_plaintexts(
    k1: Sequence[int],
    k2: Sequence[int],
    seed: int,
) -> Iterator[State]:
    """
    Exact Section 5.3 M^(5)_512 construction.

    Start from the representative M^(3)_512 structure and propagate
    backward through two inverse rounds using the same K2 and K1 later
    used by forward encryption:

        M4 = R^{-1}_{K2}(M3)
        M5 = R^{-1}_{K1}(M4).

    Pre-whitening is omitted in the six-round key-recovery experiment.
    """
    for m3 in iter_standard_m3(seed):
        m4 = inverse_round(m3, k2, 512)
        m5 = inverse_round(m4, k1, 512)

        assert forward_round(m5, k1, 512) == m4
        assert forward_round(m4, k2, 512) == m3

        yield m5


# ---------------------------------------------------------------------------
# Reduced-round encryption and streaming attack-set preparation
# ---------------------------------------------------------------------------

def state_before_final_round(
    plaintext: Sequence[int],
    target_rounds: int,
    round_keys: Sequence[Sequence[int]],
    use_prewhitening: bool,
    prewhitening_key: Optional[Sequence[int]] = None,
) -> State:
    s = list(plaintext)

    if use_prewhitening:
        kpw = round_keys[0] if prewhitening_key is None else prewhitening_key
        s = add64_per_column(s, kpw, 512)

    for r in range(1, target_rounds):
        s = forward_round(s, round_keys[r], 512)

    return s


def prepare_attack_set(
    plaintexts: Iterable[Sequence[int]],
    target_rounds: int,
    round_keys: Sequence[Sequence[int]],
    use_prewhitening: bool,
    prewhitening_key: Optional[Sequence[int]] = None,
) -> Tuple[int, int, List[List[int]]]:
    """
    Stream one chosen-plaintext multiset and retain only ciphertext
    64-bit columns needed by the recovery stage.
    """
    xor_sums = [0] * 64
    ciphertext_columns = [[] for _ in range(COLS)]
    count = 0

    for plaintext in plaintexts:
        pre_final = state_before_final_round(
            plaintext,
            target_rounds,
            round_keys,
            use_prewhitening,
            prewhitening_key,
        )

        for i, value in enumerate(pre_final):
            xor_sums[i] ^= value

        ciphertext = final_round(
            pre_final,
            round_keys[target_rounds],
        )

        for column in range(COLS):
            ciphertext_columns[column].append(
                column_u64(ciphertext, column)
            )

        count += 1

    balanced = sum(1 for x in xor_sums if x == 0)
    assert balanced == 64
    return count, balanced, ciphertext_columns


def parse_args(default_demo: int = 128) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--full",
        action="store_true",
        help=(
            "enumerate all 2^64 candidates for every 64-bit column; "
            "this is the literal paper search and is computationally "
            "infeasible in ordinary Python"
        ),
    )
    parser.add_argument(
        "--demo-candidates",
        type=int,
        default=default_demo,
        help="sampled full 64-bit candidates per column in demo mode",
    )
    return parser.parse_args()


def main() -> None:
    """
    Kalyna-512/512 6-round recovery without pre-whitening.

    Underlying distinguisher : 5-round no-prewhitening integral
    Algorithm                : Algorithm 1
    Data                     : 2^9 chosen plaintexts
    Theoretical work         : ~2^76 partial-decryption operations
    """
    args = parse_args(default_demo=128)
    official_self_test()

    round_keys = kalyna512_512_key_expand(OFFICIAL_TEST_KEY)

    n1, b1, cset1 = prepare_attack_set(
        iter_no_prew_m5_plaintexts(
            round_keys[1],
            round_keys[2],
            1,
        ),
        6,
        round_keys,
        False,
    )
    n2, b2, cset2 = prepare_attack_set(
        iter_no_prew_m5_plaintexts(
            round_keys[1],
            round_keys[2],
            2,
        ),
        6,
        round_keys,
        False,
    )

    print("=" * 72)
    print("Kalyna-512/512: 6-round key recovery without pre-whitening")
    print("=" * 72)
    print(
        "Official DSTU test : "
        "4a26e31b811c356aa61dd6ca0596231a"
        "67ba8354aa47f3a13e1deec320eb56b8"
        "95d0f417175bab662fd6f134bb15c86c"
        "cb906a26856efeb7c5bc6472940dd9d9"
    )
    print("Algorithm          : Algorithm 1")
    print(f"Two multisets      : {n1} + {n2} = 2^9 chosen plaintexts")
    print("Theoretical work   : ~2^76 partial-decryption operations")
    print("Pre-whitening      : omitted")
    print("Input              : exact inverse-propagated M^(5)_512")
    print(f"Balanced before R6 : {b1}/64 and {b2}/64")
    print("Recovery unit      : one 64-bit final-key column")

    recovered_k6 = recover_last_round_key(
        [cset1, cset2],
        round_keys[6],
        args.full,
        args.demo_candidates,
    )

    assert recovered_k6 == round_keys[6]

    print()
    print("Recovered K6       :", key_hex(recovered_k6))


if __name__ == "__main__":
    main()
