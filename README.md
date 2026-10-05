# Integral Cryptanalysis of Reduced-Round Kalyna

This repository contains reproducibility code for the paper:

**Integral Propagation under Modulo-Addition Whitening with Application to Reduced-Round Kalyna**

Authors: Nitish Kumar, Ranit Dutta, and Bimal Mandal.

The repository contains 24 Python programs:

- 9 integral-distinguisher programs
- 9 key-recovery programs for Kalyna-b/b
- 6 key-recovery programs for Kalyna-b/2b

## Repository Structure

### `kalyna_distinguishers/`

Contains the 9 distinguisher implementations for Kalyna-128,
Kalyna-256, and Kalyna-512.

### `kalyna_key_recovery_b_b/`

Contains the 9 key-recovery implementations for:

- Kalyna-128/128
- Kalyna-256/256
- Kalyna-512/512

### `kalyna_key_recovery_b_2b/`

Contains the 6 key-recovery implementations for:

- Kalyna-128/256
- Kalyna-256/512

## Requirements

Python 3.x

No external Python packages are required.

## Running the Code

Each experiment can be executed directly. For example:

```bash
python kalyna_distinguishers/kalyna128_2round_distinguisher.py
