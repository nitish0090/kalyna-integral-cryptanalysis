#!/usr/bin/env python3
"""
Kalyna-256 integral distinguisher reproducibility code.

Paper:
"Integral Propagation under Modulo-Addition Whitening with Application
to Reduced-Round Kalyna"

Authors: Nitish Kumar, Ranit Dutta, and Bimal Mandal

The program prints the A/C/B/U propagation after every transformation:
Input, Pre-whitening, and then SB, SR, MC, XOR for each round.

No third-party Python packages are required.
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




BLOCK_BITS = 256
ZERO256 = [0] * 32

EXPECTED_INV_MDS = [
    [0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA],
    [0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7],
    [0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F, 0x49],
    [0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8, 0x2F],
    [0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76, 0xA8],
    [0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95, 0x76],
    [0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD, 0x95],
    [0x95, 0x76, 0xA8, 0x2F, 0x49, 0xD7, 0xCA, 0xAD],
]


def primitive_self_test() -> None:
    assert INV_MDS == EXPECTED_INV_MDS

    for sb, inv in zip(SBOXES, INV_SBOXES):
        assert len(sb) == 256
        assert sorted(sb) == list(range(256))
        for x in range(256):
            assert inv[sb[x]] == x

    s = [((37 * i + 11) & 0xFF) for i in range(32)]
    k = [((19 * i + 7) & 0xFF) for i in range(32)]

    assert inv_sub_bytes(sub_bytes(s, 256), 256) == s
    assert inv_shift_rows(shift_rows(s, 256), 256) == s
    assert inv_mix_columns(mix_columns(s, 256), 256) == s
    assert sub64_per_column(add64_per_column(s, k, 256), k, 256) == s
    assert inverse_round(forward_round(s, k, 256), k, 256) == s


def all_balanced(symbols: Sequence[str]) -> bool:
    return all(x in ("A", "B") for x in symbols)


def stepwise_trace(
    states: Sequence[Sequence[int]],
    round_keys: Sequence[Sequence[int]],
    prewhitening_key: Optional[Sequence[int]],
) -> Tuple[List[State], List[Tuple[str, List[str]]]]:
    current = [list(s) for s in states]
    trace: List[Tuple[str, List[str]]] = []

    symbols, _ = summarize_states(current, 256)
    trace.append(("Input", symbols))

    if prewhitening_key is not None:
        current = [
            add64_per_column(s, prewhitening_key, 256)
            for s in current
        ]
        symbols, _ = summarize_states(current, 256)
        trace.append(("Pre-whitening", symbols))

    for r, rk in enumerate(round_keys, start=1):
        current = [sub_bytes(s, 256) for s in current]
        symbols, _ = summarize_states(current, 256)
        trace.append((f"Round {r} SB", symbols))

        current = [shift_rows(s, 256) for s in current]
        symbols, _ = summarize_states(current, 256)
        trace.append((f"Round {r} SR", symbols))

        current = [mix_columns(s, 256) for s in current]
        symbols, _ = summarize_states(current, 256)
        trace.append((f"Round {r} MC", symbols))

        current = [xor_key(s, rk, 256) for s in current]
        symbols, _ = summarize_states(current, 256)
        trace.append((f"Round {r} XOR", symbols))

    return current, trace


def print_trace(trace: Sequence[Tuple[str, Sequence[str]]]) -> None:
    for label, symbols in trace:
        print()
        print(label)
        print(matrix_string(symbols, 256))



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


def expected_m3_pattern() -> List[str]:
    out = ["C"] * 32
    out[7] = "A"
    out[24] = "A"
    return out


def expected_m4_pattern() -> List[str]:
    rows = [
        ("A", "C", "C", "A"),
        ("A", "C", "C", "A"),
        ("C", "C", "A", "A"),
        ("C", "C", "A", "A"),
        ("C", "A", "A", "C"),
        ("C", "A", "A", "C"),
        ("A", "A", "C", "C"),
        ("A", "A", "C", "C"),
    ]
    out = ["C"] * 32
    for r in range(8):
        for c in range(4):
            out[8 * c + r] = rows[r][c]
    return out


def make_reference_prewhitening_key() -> State:
    """
    A concrete nonzero member of the paper's 2^128 weak-key space.
    """
    key = deterministic_key(256, 13)
    for p in M4_WEAK_KEY_ZERO_POSITIONS:
        key[p] = 0
    return key


KPW_REFERENCE = make_reference_prewhitening_key()
K1_REFERENCE = deterministic_key(256, 31)
K2_REFERENCE = deterministic_key(256, 50)
K3_REFERENCE = deterministic_key(256, 69)
K4_REFERENCE = deterministic_key(256, 88)


def build_m3_template_for_paper_constraints() -> State:
    """
    Choose the fixed bytes of M^(3)_256 so that, after one inverse
    round and subtraction of K_pw, the resulting plaintext M^(4)_256
    satisfies exactly

        c2=c3=c4=c5=c8=c9=c10=c11=c16=c17=0.

    The active bytes of M^(3)_256 are positions 7 and 24.
    """
    template = [0] * 32
    cols = 4

    # z = MC^{-1}(M3 xor K1).
    # For plaintext byte p to be zero, the corresponding byte of the
    # post-prewhitening state must equal K_pw[p].  The weak-key zero
    # conditions prevent carries into these selected constant bytes.
    z_columns = [[None] * 8 for _ in range(cols)]

    for p in M4_ZERO_CONSTANT_POSITIONS:
        row = p % 8
        col = p // 8

        desired_after_prew_byte = KPW_REFERENCE[p]
        before_inv_s = SBOXES[row % 4][desired_after_prew_byte]

        shifted_col = (col + row_shift(row, 256)) % cols
        z_columns[shifted_col][row] = before_inv_s

    for c in range(cols):
        if any(v is not None for v in z_columns[c]):
            z = [0 if v is None else v for v in z_columns[c]]
            w = mix_single_column(z, MDS)  # w = M3_col xor K1_col
            base = 8 * c
            template[base:base + 8] = [
                w[i] ^ K1_REFERENCE[base + i]
                for i in range(8)
            ]

    return template


def build_exact_m4_plaintexts() -> Tuple[List[State], List[State], List[State]]:
    """
    Construct the exact paper-oriented 2^16-text M^(4)_256 plaintext
    multiset.

    Returns:
        plaintexts,
        states after pre-whitening,
        M^(3)_256 states reached after round 1.
    """
    template = build_m3_template_for_paper_constraints()

    m3_states: List[State] = []
    after_prew_states: List[State] = []
    plaintexts: List[State] = []

    for a, b in product(range(256), repeat=2):
        m3 = template.copy()
        m3[7] = a
        m3[24] = b

        after_prew = inverse_round(m3, K1_REFERENCE, 256)
        plaintext = sub64_per_column(after_prew, KPW_REFERENCE, 256)

        m3_states.append(m3)
        after_prew_states.append(after_prew)
        plaintexts.append(plaintext)

    plain_symbols, n_plain = summarize_states(plaintexts, 256)
    prew_symbols, n_prew = summarize_states(after_prew_states, 256)
    m3_symbols, n_m3 = summarize_states(m3_states, 256)

    assert n_plain == 65536
    assert n_prew == 65536
    assert n_m3 == 65536

    assert plain_symbols == expected_m4_pattern()
    assert prew_symbols == expected_m4_pattern()
    assert m3_symbols == expected_m3_pattern()

    # Exact paper plaintext constants.
    for s in plaintexts:
        for p in M4_ZERO_CONSTANT_POSITIONS:
            assert s[p] == 0

    # Exact paper weak-key restrictions.
    for p in M4_WEAK_KEY_ZERO_POSITIONS:
        assert KPW_REFERENCE[p] == 0

    # Exact pre-whitening and first-round relations.
    for p, q, m3 in zip(plaintexts, after_prew_states, m3_states):
        assert add64_per_column(p, KPW_REFERENCE, 256) == q
        assert forward_round(q, K1_REFERENCE, 256) == m3

    return plaintexts, after_prew_states, m3_states


def main() -> None:
    """
    Section 4.3 / Appendix G:
    Kalyna-256 4-round weak-key integral distinguisher.

    Data complexity:
        2^16.

    Weak-key conditions:
        k0=k1=k6=k7=0,
        k12=k13=k14=k15=0,
        k18=k19=k20=k21=0,
        k24=k25=k26=k27=0.

    Weak-key space:
        2^128.

    Fixed plaintext constants:
        c2=c3=c4=c5=c8=c9=c10=c11=c16=c17=0.
    """
    primitive_self_test()

    plaintexts, _, _ = build_exact_m4_plaintexts()

    round_keys = [
        K1_REFERENCE,
        K2_REFERENCE,
        K3_REFERENCE,
        K4_REFERENCE,
    ]

    outputs, trace = stepwise_trace(
        plaintexts,
        round_keys,
        KPW_REFERENCE,
    )

    output_symbols, count = summarize_states(outputs, 256)

    print("=" * 72)
    print("Kalyna-256: 4-round weak-key integral distinguisher")
    print("=" * 72)
    print(f"Number of texts    : {count} = 2^16")
    print("Weak-key space     : 2^128")
    print("Weak-key zeros     :")
    print("  k0=k1=k6=k7=k12=k13=k14=k15=0")
    print("  k18=k19=k20=k21=k24=k25=k26=k27=0")
    print("Plaintext constants:")
    print("  c2=c3=c4=c5=c8=c9=c10=c11=c16=c17=0")
    print_trace(trace)
    print()
    print(f"Balanced bytes     : {len(balanced_positions(output_symbols))}/32")

    assert all_balanced(output_symbols)


if __name__ == "__main__":
    main()
