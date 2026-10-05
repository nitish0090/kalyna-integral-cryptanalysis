#!/usr/bin/env python3
"""
Kalyna-256/256 key-recovery reproducibility code.

Paper:
"Integral Propagation under Modulo-Addition Whitening with Application
to Reduced-Round Kalyna"

Authors: Nitish Kumar, Ranit Dutta, and Bimal Mandal

This file implements the 64-bit-column last-round recovery used by
Algorithms 1 and 2 of the paper for Kalyna-256/256.

It also contains the official Kalyna-256/256 key expansion and checks
the implementation against the DSTU 7624:2014 encryption vector:

    key =
      000102030405060708090a0b0c0d0e0f
      101112131415161718191a1b1c1d1e1f

    plaintext =
      202122232425262728292a2b2c2d2e2f
      303132333435363738393a3b3c3d3e3f

    ciphertext =
      f66e3d570ec92135aedae323dcbd2a8c
      a03963ec206a0d5a88385c24617fd92c

The paper's literal attack searches 2^64 candidates for each 64-bit
last-round key column.  The default executable mode uses a small,
deterministic sample of genuine 64-bit candidates containing the true
candidate.  Use --full to express the literal 2^64 search loop.
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
BLOCK_BITS = 256
COLS = 4
NR_256_256 = 14

OFFICIAL_TEST_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
OFFICIAL_TEST_PLAINTEXT = bytes.fromhex(
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f"
)
OFFICIAL_TEST_CIPHERTEXT = bytes.fromhex(
    "f66e3d570ec92135aedae323dcbd2a8c"
    "a03963ec206a0d5a88385c24617fd92c"
)


def core_round(state: Sequence[int]) -> State:
    s = sub_bytes(state, 256)
    s = shift_rows(s, 256)
    s = mix_columns(s, 256)
    return s


def final_round(state: Sequence[int], final_key: Sequence[int]) -> State:
    return add64_per_column(core_round(state), final_key, 256)


# ---------------------------------------------------------------------------
# Official Kalyna-256/256 key schedule
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
    Official relation used by KeyExpandOdd.

    For Kalyna-256, N_b=4, hence RotateLeft uses
        2*N_b + 3 = 11 bytes.
    """
    return rotate_left_bytes(even_key, 11)


def even_round_key_from_odd(odd_key: Sequence[int]) -> State:
    return rotate_right_bytes(odd_key, 11)


def kalyna256_256_key_expand(master_key: Sequence[int]) -> List[State]:
    """
    Port of the official reference key expansion for block=256, key=256.

    Returns K0,...,K14.
    """
    if len(master_key) != 32:
        raise ValueError("Kalyna-256/256 master key must contain 32 bytes")

    key_words = words_from_bytes_le(master_key)
    nb = nk = 4

    # KeyExpandKt.
    state = [0] * nb
    state[0] = nb + nk + 1  # 9

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
    round_keys: List[Optional[State]] = [None] * (NR_256_256 + 1)

    round_index = 0
    while True:
        kt_round = add_words_mod64(kt, tmv)

        state = add_words_mod64(initial_data, kt_round)
        state = core_round_words(state)
        state = xor_words(state, kt_round)
        state = core_round_words(state)
        state = add_words_mod64(state, kt_round)

        round_keys[round_index] = bytes_from_words_le(state)

        if round_index == NR_256_256:
            break

        round_index += 2
        tmv = [((word << 1) & MASK64) for word in tmv]

        # Official Rotate(ctx->nk, initial_data): one 64-bit word left.
        initial_data = initial_data[1:] + initial_data[:1]

    # KeyExpandOdd.
    for r in range(1, NR_256_256, 2):
        even_key = round_keys[r - 1]
        assert even_key is not None
        round_keys[r] = odd_round_key_from_even(even_key)

    assert all(k is not None for k in round_keys)
    return [list(k) for k in round_keys if k is not None]


def kalyna256_256_encrypt_block(
    plaintext: Sequence[int],
    round_keys: Sequence[Sequence[int]],
) -> State:
    if len(plaintext) != 32:
        raise ValueError("plaintext must contain 32 bytes")
    if len(round_keys) != 15:
        raise ValueError("Kalyna-256/256 requires K0,...,K14")

    s = add64_per_column(plaintext, round_keys[0], 256)

    for r in range(1, 14):
        s = forward_round(s, round_keys[r], 256)

    s = core_round(s)
    s = add64_per_column(s, round_keys[14], 256)
    return s


def official_self_test() -> None:
    round_keys = kalyna256_256_key_expand(OFFICIAL_TEST_KEY)
    ciphertext = kalyna256_256_encrypt_block(
        OFFICIAL_TEST_PLAINTEXT,
        round_keys,
    )
    assert bytes(ciphertext) == OFFICIAL_TEST_CIPHERTEXT

    for r in range(1, 14, 2):
        assert round_keys[r] == odd_round_key_from_even(round_keys[r - 1])
        assert round_keys[r - 1] == even_round_key_from_odd(round_keys[r])


# ---------------------------------------------------------------------------
# Fast final-column partial decryption
# ---------------------------------------------------------------------------

# Precompute multiplication tables used by MC^{-1}.
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
    Compute the eight byte values recovered from one ciphertext column:

        C_j - K_j  -> MC^{-1} -> SR^{-1} -> SB^{-1}.

    SR^{-1} only changes positions.  Since Algorithm 1 checks all eight
    recovered bytes, the balanced sums can be accumulated row by row
    without explicitly materializing the full state.
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
    The I_j positions after SR^{-1}, included for correspondence with
    Algorithm 1 of the paper.
    """
    positions = []
    for row in range(8):
        src_col = (column - row_shift(row, 256)) % COLS
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
    ciphertext_sets[set_index][column] is the list of 64-bit ciphertext
    words from that column for one integral multiset.
    """
    recovered = [0] * 32

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
                0x256000 + column,
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
# Integral structures
# ---------------------------------------------------------------------------

def iter_standard_m2(seed: int) -> Iterator[State]:
    """
    M^(2)_256: byte 7 active, all other bytes fixed.
    Size = 2^8.
    """
    constants = [
        ((seed + 13*i + 7*i*i) & 0xFF)
        for i in range(32)
    ]

    for a in range(256):
        s = constants.copy()
        s[7] = a
        yield s


def iter_weak_m3(seed: int) -> Iterator[State]:
    """
    M^(3)_256 from Section 4.2:
    independent active bytes at positions 7 and 24.
    Size = 2^16.
    """
    constants = [
        ((29*seed + 17*i + 5*i*i) & 0xFF)
        for i in range(32)
    ]

    for a, b in product(range(256), repeat=2):
        s = constants.copy()
        s[7] = a
        s[24] = b
        yield s


M4_WEAK_KEY_ZERO_POSITIONS = (
    0, 1, 6, 7,
    12, 13, 14, 15,
    18, 19, 20, 21,
    24, 25, 26, 27,
)

M4_ZERO_CONSTANT_POSITIONS = (
    2, 3, 4, 5,
    8, 9, 10, 11,
    16, 17,
)


def make_m3_weak_prewhitening_key() -> State:
    """
    Concrete nonzero member of the Section 4.2 weak-key space:
        k24 = 0.
    """
    key = deterministic_key(256, 13)
    key[24] = 0
    return key


def make_m4_weak_prewhitening_key() -> State:
    """
    Concrete nonzero member of the Section 4.3 weak-key space.
    """
    key = deterministic_key(256, 17)
    for p in M4_WEAK_KEY_ZERO_POSITIONS:
        key[p] = 0
    return key


def build_m3_template_for_m4_constraints(
    kpw: Sequence[int],
    k1: Sequence[int],
    seed: int,
) -> State:
    """
    Choose the fixed M^(3)_256 bytes so that inverse propagation followed
    by removal of K_pw gives the exact plaintext restrictions

        c2=c3=c4=c5=c8=c9=c10=c11=c16=c17=0.
    """
    template = [0] * 32
    z_columns: List[List[Optional[int]]] = [
        [None] * 8 for _ in range(COLS)
    ]

    for p in M4_ZERO_CONSTANT_POSITIONS:
        row = p % 8
        col = p // 8

        desired_after_prew_byte = kpw[p]
        before_inv_s = SBOXES[row % 4][desired_after_prew_byte]

        shifted_col = (col + row_shift(row, 256)) % COLS
        z_columns[shifted_col][row] = before_inv_s

    for c in range(COLS):
        # Unconstrained z bytes can be different for the two independent
        # structures; constrained bytes remain exactly fixed.
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
    Exact Section 4.3 M^(4)_256 plaintext construction, size 2^16.
    """
    template = build_m3_template_for_m4_constraints(kpw, k1, seed)

    for a, b in product(range(256), repeat=2):
        m3 = template.copy()
        m3[7] = a
        m3[24] = b

        after_prew = inverse_round(m3, k1, 256)
        plaintext = sub64_per_column(after_prew, kpw, 256)

        for p in M4_ZERO_CONSTANT_POSITIONS:
            assert plaintext[p] == 0

        yield plaintext


# ---------------------------------------------------------------------------
# Reduced-round encryption and attack-set preparation
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
        s = add64_per_column(s, kpw, 256)

    for r in range(1, target_rounds):
        s = forward_round(s, round_keys[r], 256)

    return s


def prepare_attack_set(
    plaintexts: Iterable[Sequence[int]],
    target_rounds: int,
    round_keys: Sequence[Sequence[int]],
    use_prewhitening: bool,
    prewhitening_key: Optional[Sequence[int]] = None,
) -> Tuple[int, int, List[List[int]]]:
    """
    Stream one chosen-plaintext multiset.

    Returns:
        number of plaintexts,
        number of balanced byte positions immediately before the
        attacked final round,
        ciphertext words grouped by the four 64-bit columns.
    """
    xor_sums = [0] * 32
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
    assert balanced == 32
    return count, balanced, ciphertext_columns


def parse_args(default_demo: int) -> argparse.Namespace:
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
    Kalyna-256/256 5-round weak-key recovery.

    Underlying distinguisher : 4-round weak-key integral
    Algorithm                : Algorithm 2
    Data                     : 2^17 chosen plaintexts
    Theoretical work         : ~2^83 partial-decryption operations

    The paper's Section 4.3 weak conditions and fixed plaintext
    constants are enforced exactly.
    """
    args = parse_args(default_demo=2)
    official_self_test()

    round_keys = kalyna256_256_key_expand(OFFICIAL_TEST_KEY)
    kpw = make_m4_weak_prewhitening_key()

    # Verify the paper's weak-key conditions.
    for p in M4_WEAK_KEY_ZERO_POSITIONS:
        assert kpw[p] == 0

    n1, b1, cset1 = prepare_attack_set(
        iter_weak_m4_plaintexts(kpw, round_keys[1], 1),
        5,
        round_keys,
        True,
        kpw,
    )
    n2, b2, cset2 = prepare_attack_set(
        iter_weak_m4_plaintexts(kpw, round_keys[1], 2),
        5,
        round_keys,
        True,
        kpw,
    )

    print("=" * 72)
    print("Kalyna-256/256: 5-round weak-key recovery")
    print("=" * 72)
    print(
        "Official DSTU test : "
        "f66e3d570ec92135aedae323dcbd2a8c"
        "a03963ec206a0d5a88385c24617fd92c"
    )
    print("Algorithm          : Algorithm 2")
    print(f"Two multisets      : {n1} + {n2} = 2^17 chosen plaintexts")
    print("Theoretical work   : ~2^83 partial-decryption operations")
    print("Weak-key zeros     :")
    print("  k0=k1=k6=k7=k12=k13=k14=k15=0")
    print("  k18=k19=k20=k21=k24=k25=k26=k27=0")
    print("Weak-key space     : 2^128 at the K_pw subkey level")
    print("Plaintext constants:")
    print("  c2=c3=c4=c5=c8=c9=c10=c11=c16=c17=0")
    print(f"Balanced before R5 : {b1}/32 and {b2}/32")
    print("Recovery unit      : one 64-bit final-key column")
    print("Key model          : paper weak-K_pw reduced-round model")

    recovered_k5 = recover_last_round_key(
        [cset1, cset2],
        round_keys[5],
        args.full,
        args.demo_candidates,
    )
    recovered_k4 = even_round_key_from_odd(recovered_k5)

    assert recovered_k5 == round_keys[5]
    assert recovered_k4 == round_keys[4]

    print()
    print("Recovered K5       :", key_hex(recovered_k5))
    print("Derived K4         :", key_hex(recovered_k4))


if __name__ == "__main__":
    main()
