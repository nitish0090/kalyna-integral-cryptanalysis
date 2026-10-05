#!/usr/bin/env python3
"""
Kalyna-128/256 key-recovery reproducibility code.

Paper:
"Integral Propagation under Modulo-Addition Whitening with Application
to Reduced-Round Kalyna"

Authors: Nitish Kumar, Ranit Dutta, and Bimal Mandal

This file implements the two-round key-recovery extensions for the
Kalyna-b/2b family described by Algorithms 3 and 4 of the paper.

The official Kalyna-128/256 key schedule is implemented according to
the Kalyna reference implementation. The implementation is checked
against the DSTU 7624:2014 ECB test vector

    key =
      000102030405060708090a0b0c0d0e0f
      101112131415161718191a1b1c1d1e1f
    plaintext =
      202122232425262728292a2b2c2d2e2f
    ciphertext =
      58ec3e091000158a1148f7166f334f14

The paper's literal outer search uses all 2^128 last-round subkeys.
The default executable mode uses only a deterministic sample of full
128-bit candidates containing the true candidate.
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
BLOCK_BITS = 128
BLOCK_BYTES = BLOCK_BITS // 8
NB = BLOCK_BITS // 64
KEY_BITS = 2 * BLOCK_BITS
KEY_BYTES = KEY_BITS // 8
NK = KEY_BITS // 64
NR = 14
ODD_ROTATE_BYTES = 2 * NB + 3

OFFICIAL_TEST_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
OFFICIAL_TEST_PLAINTEXT = bytes.fromhex("202122232425262728292a2b2c2d2e2f")
OFFICIAL_TEST_CIPHERTEXT = bytes.fromhex("58ec3e091000158a1148f7166f334f14")


def core_round(state: Sequence[int]) -> State:
    s = sub_bytes(state, BLOCK_BITS)
    s = shift_rows(s, BLOCK_BITS)
    s = mix_columns(s, BLOCK_BITS)
    return s


def final_round(state: Sequence[int], final_key: Sequence[int]) -> State:
    return add64_per_column(core_round(state), final_key, BLOCK_BITS)


def inverse_final_round(
    ciphertext: Sequence[int],
    final_key: Sequence[int],
) -> State:
    s = sub64_per_column(ciphertext, final_key, BLOCK_BITS)
    s = inv_mix_columns(s, BLOCK_BITS)
    s = inv_shift_rows(s, BLOCK_BITS)
    s = inv_sub_bytes(s, BLOCK_BITS)
    return s


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


def rotate_left_bytes(state: Sequence[int], amount: int) -> State:
    amount %= len(state)
    return list(state[amount:]) + list(state[:amount])


def rotate_right_bytes(state: Sequence[int], amount: int) -> State:
    amount %= len(state)
    return list(state[-amount:]) + list(state[:-amount])


def odd_round_key_from_even(even_key: Sequence[int]) -> State:
    return rotate_left_bytes(even_key, ODD_ROTATE_BYTES)


def even_round_key_from_odd(odd_key: Sequence[int]) -> State:
    return rotate_right_bytes(odd_key, ODD_ROTATE_BYTES)


def kalyna_double_key_expand(master_key: Sequence[int]) -> List[State]:
    """
    Exact KeyExpandKt + KeyExpandEven + KeyExpandOdd for nk=2*nb.
    """
    if len(master_key) != KEY_BYTES:
        raise ValueError(
            f"master key must contain {KEY_BYTES} bytes"
        )

    key_words = words_from_bytes_le(master_key)

    state = [0] * NB
    state[0] = NB + NK + 1

    k0 = key_words[:NB]
    k1 = key_words[NB:2*NB]

    state = add_words_mod64(state, k0)
    state = core_round_words(state)
    state = xor_words(state, k1)
    state = core_round_words(state)
    state = add_words_mod64(state, k0)
    state = core_round_words(state)
    kt = state.copy()

    initial_data = key_words.copy()
    tmv = [0x0001000100010001] * NB
    round_keys: List[Optional[State]] = [None] * (NR + 1)

    round_index = 0
    while True:
        kt_round = add_words_mod64(kt, tmv)

        state = add_words_mod64(initial_data[:NB], kt_round)
        state = core_round_words(state)
        state = xor_words(state, kt_round)
        state = core_round_words(state)
        state = add_words_mod64(state, kt_round)
        round_keys[round_index] = bytes_from_words_le(state)

        if round_index == NR:
            break

        round_index += 2
        tmv = [((x << 1) & MASK64) for x in tmv]
        kt_round = add_words_mod64(kt, tmv)

        state = add_words_mod64(initial_data[NB:2*NB], kt_round)
        state = core_round_words(state)
        state = xor_words(state, kt_round)
        state = core_round_words(state)
        state = add_words_mod64(state, kt_round)
        round_keys[round_index] = bytes_from_words_le(state)

        if round_index == NR:
            break

        round_index += 2
        tmv = [((x << 1) & MASK64) for x in tmv]
        initial_data = initial_data[1:] + initial_data[:1]

    for r in range(1, NR, 2):
        even_key = round_keys[r - 1]
        assert even_key is not None
        round_keys[r] = odd_round_key_from_even(even_key)

    assert all(k is not None for k in round_keys)
    return [list(k) for k in round_keys if k is not None]


def full_encrypt(
    plaintext: Sequence[int],
    round_keys: Sequence[Sequence[int]],
) -> State:
    s = add64_per_column(plaintext, round_keys[0], BLOCK_BITS)
    for r in range(1, NR):
        s = forward_round(s, round_keys[r], BLOCK_BITS)
    return final_round(s, round_keys[NR])


def official_self_test() -> None:
    round_keys = kalyna_double_key_expand(OFFICIAL_TEST_KEY)
    ciphertext = full_encrypt(OFFICIAL_TEST_PLAINTEXT, round_keys)
    assert bytes(ciphertext) == OFFICIAL_TEST_CIPHERTEXT

    for r in range(1, NR, 2):
        assert round_keys[r] == odd_round_key_from_even(round_keys[r - 1])
        assert round_keys[r - 1] == even_round_key_from_odd(round_keys[r])



def make_standard_structure(seed: int) -> List[State]:
    constants = [
        ((seed + 13*i + 7*i*i) & 0xFF)
        for i in range(16)
    ]
    out: List[State] = []

    for a in range(256):
        s = constants.copy()
        s[7] = a
        out.append(s)

    return out


def make_weak_prewhitening_key() -> State:
    key = deterministic_key(128, 13)
    for i in (0, 1, 2, 3, 12, 13, 14, 15):
        key[i] = 0
    return key


def build_weak_m3_plaintexts(
    kpw: Sequence[int],
    k1: Sequence[int],
    seed: int,
) -> List[State]:
    template = [0] * 16

    for p in range(4, 8):
        template[p] = (37*seed + 19*p + 11) & 0xFF

    for p in range(8, 12):
        template[p] = kpw[p]

    fixed_round1_output = forward_round(template, k1, 128)
    fixed_second_column = fixed_round1_output[8:16]

    plaintexts: List[State] = []

    for a in range(256):
        m2 = [0] * 16
        m2[7] = a
        m2[8:16] = fixed_second_column

        after_prew = inverse_round(m2, k1, 128)
        plaintext = sub64_per_column(after_prew, kpw, 128)

        assert plaintext[8:12] == [0, 0, 0, 0]
        plaintexts.append(plaintext)

    return plaintexts


def build_no_prew_m4_plaintexts(
    auxiliary_kpw: Sequence[int],
    k1: Sequence[int],
    k2: Sequence[int],
    seed: int,
) -> List[State]:
    template = [0] * 16

    for p in range(4, 8):
        template[p] = (37*seed + 19*p + 11) & 0xFF

    for p in range(8, 12):
        template[p] = auxiliary_kpw[p]

    fixed_round2_output = forward_round(template, k2, 128)
    fixed_second_column = fixed_round2_output[8:16]

    m3_states: List[State] = []

    for a in range(256):
        m2 = [0] * 16
        m2[7] = a
        m2[8:16] = fixed_second_column
        m3_states.append(inverse_round(m2, k2, 128))

    m4 = [
        inverse_round(s, k1, 128)
        for s in m3_states
    ]

    for x, y in zip(m4, m3_states):
        assert forward_round(x, k1, 128) == y

    return m4



def state_after_rounds(
    plaintext: Sequence[int],
    rounds: int,
    round_keys: Sequence[Sequence[int]],
    use_prewhitening: bool,
    prewhitening_key: Optional[Sequence[int]] = None,
) -> State:
    s = list(plaintext)

    if use_prewhitening:
        kpw = (
            round_keys[0]
            if prewhitening_key is None
            else prewhitening_key
        )
        s = add64_per_column(s, kpw, BLOCK_BITS)

    for r in range(1, rounds + 1):
        s = forward_round(s, round_keys[r], BLOCK_BITS)

    return s


def prepare_two_round_attack_set(
    plaintexts: Iterable[Sequence[int]],
    distinguisher_rounds: int,
    target_rounds: int,
    round_keys: Sequence[Sequence[int]],
    use_prewhitening: bool,
    prewhitening_key: Optional[Sequence[int]] = None,
) -> Tuple[int, int, List[State]]:
    if target_rounds != distinguisher_rounds + 2:
        raise ValueError("Algorithms 3/4 require a two-round extension")

    sums = [0] * BLOCK_BYTES
    ciphertexts: List[State] = []
    count = 0

    for plaintext in plaintexts:
        x = state_after_rounds(
            plaintext,
            distinguisher_rounds,
            round_keys,
            use_prewhitening,
            prewhitening_key,
        )

        for i, value in enumerate(x):
            sums[i] ^= value

        x = forward_round(
            x,
            round_keys[target_rounds - 1],
            BLOCK_BITS,
        )
        c = final_round(
            x,
            round_keys[target_rounds],
        )

        ciphertexts.append(c)
        count += 1

    balanced = sum(1 for x in sums if x == 0)
    assert balanced == BLOCK_BYTES

    return count, balanced, ciphertexts


def sampled_full_key_candidates(
    true_key: Sequence[int],
    count: int,
    seed: int,
) -> List[State]:
    if count < 1:
        raise ValueError("candidate count must be positive")

    true_bytes = bytes(true_key)
    found = {true_bytes}
    x = (0x9E3779B97F4A7C15 ^ seed) & MASK64

    while len(found) < count:
        out = bytearray()
        while len(out) < BLOCK_BYTES:
            x = (
                6364136223846793005 * x
                + 1442695040888963407
            ) & MASK64
            out.extend(x.to_bytes(8, "little"))
        found.add(bytes(out[:BLOCK_BYTES]))

    return [list(x) for x in sorted(found)]


def full_key_space_iterator() -> Iterator[State]:
    for value in range(1 << BLOCK_BITS):
        yield list(value.to_bytes(BLOCK_BYTES, "little"))


def partially_decrypt_two_rounds_algorithm3(
    ciphertext: Sequence[int],
    last_key: Sequence[int],
    previous_key: Sequence[int],
) -> State:
    x = inverse_final_round(ciphertext, last_key)
    x = inverse_round(x, previous_key, BLOCK_BITS)
    return x


def algorithm3_candidate_survives(
    ciphertext_sets: Sequence[Sequence[Sequence[int]]],
    last_key_guess: Sequence[int],
) -> Tuple[bool, State]:
    previous_key_guess = even_round_key_from_odd(last_key_guess)

    for ciphertexts in ciphertext_sets:
        sums = [0] * BLOCK_BYTES

        for c in ciphertexts:
            x = partially_decrypt_two_rounds_algorithm3(
                c,
                last_key_guess,
                previous_key_guess,
            )
            for i, value in enumerate(x):
                sums[i] ^= value

        if any(sums):
            return False, previous_key_guess

    return True, previous_key_guess


def run_algorithm3_demo(
    ciphertext_sets: Sequence[Sequence[Sequence[int]]],
    true_last_key: Sequence[int],
    demo_candidates: int,
    full: bool,
) -> Tuple[State, State]:
    print(
        f"Paper outer space  : 2^{BLOCK_BITS} complete "
        f"{BLOCK_BITS}-bit last-round subkeys"
    )

    candidates = (
        full_key_space_iterator()
        if full
        else sampled_full_key_candidates(
            true_last_key,
            demo_candidates,
            0xA30000 + BLOCK_BITS,
        )
    )

    if full:
        print("Search mode        : complete paper outer search")
    else:
        print(
            "Search mode        : demo over "
            f"{demo_candidates} sampled {BLOCK_BITS}-bit candidates"
        )

    survivors: List[Tuple[State, State]] = []

    for guess in candidates:
        ok, previous = algorithm3_candidate_survives(
            ciphertext_sets,
            guess,
        )
        if ok:
            survivors.append((guess, previous))

    print(f"Surviving pairs    : {len(survivors)}")

    if len(survivors) != 1:
        raise RuntimeError(
            "expected one surviving pair in this executable run"
        )

    return survivors[0]


def equivalent_previous_key(previous_key: Sequence[int]) -> State:
    return inv_shift_rows(
        inv_mix_columns(previous_key, BLOCK_BITS),
        BLOCK_BITS,
    )


def reconstruct_previous_key(equivalent_key: Sequence[int]) -> State:
    return mix_columns(
        shift_rows(equivalent_key, BLOCK_BITS),
        BLOCK_BITS,
    )


def algorithm4_y_state(
    ciphertext: Sequence[int],
    last_key_guess: Sequence[int],
) -> State:
    x = inverse_final_round(ciphertext, last_key_guess)
    y = inv_mix_columns(x, BLOCK_BITS)
    y = inv_shift_rows(y, BLOCK_BITS)
    return y


def parity_masks_for_algorithm4(
    ciphertext_sets: Sequence[Sequence[Sequence[int]]],
    last_key_guess: Sequence[int],
) -> List[List[int]]:
    all_masks: List[List[int]] = []

    for ciphertexts in ciphertext_sets:
        masks = [0] * BLOCK_BYTES

        for c in ciphertexts:
            y = algorithm4_y_state(c, last_key_guess)
            for i, value in enumerate(y):
                masks[i] ^= (1 << value)

        all_masks.append(masks)

    return all_masks


def xor_inverse_sbox_over_parity_mask(
    mask: int,
    byte_position: int,
    key_byte_guess: int,
) -> int:
    row = byte_position % 8
    invs = INV_SBOXES[row % 4]

    total = 0
    while mask:
        lsb = mask & -mask
        value = lsb.bit_length() - 1
        total ^= invs[value ^ key_byte_guess]
        mask ^= lsb

    return total


def recover_equivalent_key_algorithm4(
    ciphertext_sets: Sequence[Sequence[Sequence[int]]],
    last_key_guess: Sequence[int],
) -> Optional[State]:
    masks = parity_masks_for_algorithm4(
        ciphertext_sets,
        last_key_guess,
    )

    equivalent = [0] * BLOCK_BYTES

    for i in range(BLOCK_BYTES):
        survivors: List[int] = []

        for g in range(256):
            ok = True

            for one_set_masks in masks:
                if xor_inverse_sbox_over_parity_mask(
                    one_set_masks[i],
                    i,
                    g,
                ) != 0:
                    ok = False
                    break

            if ok:
                survivors.append(g)

        if len(survivors) != 1:
            return None

        equivalent[i] = survivors[0]

    return equivalent


def run_algorithm4_demo(
    ciphertext_sets: Sequence[Sequence[Sequence[int]]],
    true_last_key: Sequence[int],
    true_previous_key: Sequence[int],
    demo_candidates: int,
    full: bool,
) -> Tuple[State, State, State, State]:
    print(
        f"Paper outer space  : 2^{BLOCK_BITS} complete "
        f"{BLOCK_BITS}-bit last-round subkeys"
    )
    print(
        f"Inner recovery     : {BLOCK_BYTES} equivalent-key bytes, "
        "256 guesses per byte"
    )

    candidates = (
        full_key_space_iterator()
        if full
        else sampled_full_key_candidates(
            true_last_key,
            demo_candidates,
            0xA40000 + BLOCK_BITS,
        )
    )

    if full:
        print("Search mode        : complete paper outer search")
    else:
        print(
            "Search mode        : demo over "
            f"{demo_candidates} sampled {BLOCK_BITS}-bit candidates"
        )

    survivors: List[Tuple[State, State, State, State]] = []

    for last_guess in candidates:
        kf = recover_equivalent_key_algorithm4(
            ciphertext_sets,
            last_guess,
        )

        if kf is None:
            continue

        previous = reconstruct_previous_key(kf)
        preceding_even = even_round_key_from_odd(previous)

        survivors.append(
            (last_guess, kf, previous, preceding_even)
        )

    print(f"Surviving tuples   : {len(survivors)}")

    if len(survivors) != 1:
        raise RuntimeError(
            "expected one surviving tuple in this executable run"
        )

    last_guess, kf, previous, preceding_even = survivors[0]

    assert last_guess == list(true_last_key)
    assert previous == list(true_previous_key)
    assert kf == equivalent_previous_key(true_previous_key)

    return survivors[0]


def key_hex(key: Sequence[int]) -> str:
    return bytes(key).hex()


def parse_args(default_demo: int) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--full",
        action="store_true",
        help=(
            "use the literal 2^b outer key search from the paper; "
            "computationally infeasible in ordinary Python"
        ),
    )
    parser.add_argument(
        "--demo-candidates",
        type=int,
        default=default_demo,
        help="number of sampled full b-bit outer candidates",
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args(default_demo=2)
    official_self_test()
    round_keys = kalyna_double_key_expand(OFFICIAL_TEST_KEY)

    n1, b1, c1 = prepare_two_round_attack_set(
        make_standard_structure(1), 2, 4, round_keys, True
    )
    n2, b2, c2 = prepare_two_round_attack_set(
        make_standard_structure(2), 2, 4, round_keys, True
    )

    print("=" * 72)
    print("Kalyna-128/256: 4-round integral key recovery")
    print("=" * 72)
    print("Official DSTU test : 58ec3e091000158a1148f7166f334f14")
    print("Algorithm          : Algorithm 4")
    print(f"Two multisets      : {n1} + {n2} = 2^9 chosen plaintexts")
    print("Theoretical work   : ~2^149 basic operations")
    print(f"Balanced after R2  : {b1}/16 and {b2}/16")

    k4, kf3, k3, k2 = run_algorithm4_demo(
        [c1, c2], round_keys[4], round_keys[3],
        args.demo_candidates, args.full
    )
    assert k2 == round_keys[2]

    print()
    print("Recovered K4       :", key_hex(k4))
    print("Recovered Kf3      :", key_hex(kf3))
    print("Reconstructed K3   :", key_hex(k3))
    print("Derived K2         :", key_hex(k2))


if __name__ == "__main__":
    main()
