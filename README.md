# Integral Cryptanalysis of Reduced-Round Kalyna

Reproducibility code for the paper:

**Integral Propagation under Modulo-Addition Whitening with Application to Reduced-Round Kalyna**

**Authors:** Nitish Kumar, Ranit Dutta, and Bimal Mandal

This repository contains Python implementations of the integral distinguishers
and key-recovery attacks studied for reduced-round Kalyna.

## Repository Structure

```text
kalyna-integral-cryptanalysis/
├── kalyna_distinguishers/        # 9 distinguisher programs
├── kalyna_key_recovery_b_b/      # 9 key-recovery programs for Kalyna-b/b
├── kalyna_key_recovery_b_2b/     # 6 key-recovery programs for Kalyna-b/2b
├── README.md
└── LICENSE
```

In total, the repository contains **24 Python programs**.

### `kalyna_distinguishers/`

Integral distinguishers for Kalyna-128, Kalyna-256, and Kalyna-512,
including standard, weak-key, and no-pre-whitening settings.

### `kalyna_key_recovery_b_b/`

Key-recovery experiments for:

- Kalyna-128/128
- Kalyna-256/256
- Kalyna-512/512

### `kalyna_key_recovery_b_2b/`

Key-recovery experiments for:

- Kalyna-128/256
- Kalyna-256/512

## Requirements

Python 3.x

No external Python packages are required.

## Usage

Run any script directly. For example:

```bash
python kalyna_distinguishers/kalyna128_2round_distinguisher.py
```

```bash
python kalyna_key_recovery_b_b/kalyna256_4round_weakkey_key_recovery.py
```

```bash
python kalyna_key_recovery_b_2b/kalyna128_256_5round_weakkey_key_recovery.py
```

## Note on Key-Recovery Experiments

The theoretical attacks involve very large search spaces such as
$2^{64}$, $2^{128}$, or $2^{256}$.

For practical execution, the default programs use a small sampled candidate
set containing the correct candidate to verify the recovery and filtering
procedure.

The scripts clearly report both the theoretical search space and the
demonstration search mode.

Experiments labeled **no pre-whitening** apply only to the reduced models
defined in the paper.

## License

MIT License.
