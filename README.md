# Integral Cryptanalysis of Reduced-Round Kalyna

Reproducibility code for the paper:

**Integral Propagation under Modulo-Addition Whitening with Application to Reduced-Round Kalyna**

**Authors:** Nitish Kumar, Ranit Dutta, and Bimal Mandal

This repository contains Python implementations of the integral distinguishers and key-recovery attacks for reduced-round Kalyna.

## Repository Structure

- `kalyna_distinguishers/` — 9 integral-distinguisher programs
- `kalyna_key_recovery_b_b/` — 9 key-recovery programs for Kalyna-b/b
- `kalyna_key_recovery_b_2b/` — 6 key-recovery programs for Kalyna-b/2b

Total: **24 Python programs**.

## Requirements

Python 3.x

## Usage

Run any script directly, for example:

```bash
python kalyna_distinguishers/kalyna128_2round_distinguisher.py
