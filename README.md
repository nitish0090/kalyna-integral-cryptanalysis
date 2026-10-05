# Integral Cryptanalysis of Reduced-Round Kalyna

This repository contains the reproducibility code accompanying the paper

**Integral Propagation under Modulo-Addition Whitening with Application to Reduced-Round Kalyna**

**Authors:** Nitish Kumar, Ranit Dutta, and Bimal Mandal

The repository provides executable implementations for the integral
distinguishers and the corresponding key-recovery procedures studied for
reduced-round variants of Kalyna.

The code covers both Kalyna parameter families:

- Kalyna-$b/b$: Kalyna-128/128, Kalyna-256/256, and Kalyna-512/512.
- Kalyna-$b/2b$: Kalyna-128/256 and Kalyna-256/512.

In total, the repository contains **24 Python programs**:

- 9 integral-distinguisher programs,
- 9 key-recovery programs for Kalyna-$b/b$,
- 6 key-recovery programs for Kalyna-$b/2b$.

---

## Repository Structure

```text
kalyna-integral-cryptanalysis/
│
├── README.md
├── LICENSE
├── .gitignore
│
├── kalyna_distinguishers/
│   ├── README.md
│   ├── kalyna128_2round_distinguisher.py
│   ├── kalyna128_3round_weakkey_distinguisher.py
│   ├── kalyna128_4round_no_prewhitening_distinguisher.py
│   ├── kalyna256_2round_distinguisher.py
│   ├── kalyna256_3round_weakkey_distinguisher.py
│   ├── kalyna256_4round_weakkey_distinguisher.py
│   ├── kalyna512_3round_distinguisher.py
│   ├── kalyna512_4round_weakkey_distinguisher.py
│   └── kalyna512_5round_no_prewhitening_distinguisher.py
│
├── kalyna_key_recovery_b_b/
│   ├── README.md
│   ├── kalyna128_3round_key_recovery.py
│   ├── kalyna128_4round_weakkey_key_recovery.py
│   ├── kalyna128_5round_no_prewhitening_key_recovery.py
│   ├── kalyna256_3round_key_recovery.py
│   ├── kalyna256_4round_weakkey_key_recovery.py
│   ├── kalyna256_5round_weakkey_key_recovery.py
│   ├── kalyna512_4round_key_recovery.py
│   ├── kalyna512_5round_weakkey_key_recovery.py
│   └── kalyna512_6round_no_prewhitening_key_recovery.py
│
└── kalyna_key_recovery_b_2b/
    ├── README.md
    ├── kalyna128_256_4round_key_recovery.py
    ├── kalyna128_256_5round_weakkey_key_recovery.py
    ├── kalyna128_256_6round_no_prewhitening_key_recovery.py
    ├── kalyna256_512_4round_key_recovery.py
    ├── kalyna256_512_5round_weakkey_key_recovery.py
    └── kalyna256_512_6round_weakkey_key_recovery.py
```

---

## 1. Integral Distinguishers

The directory

```text
kalyna_distinguishers/
```

contains the nine integral-distinguisher experiments.

| Variant | Rounds | Setting | Data |
|---|---:|---|---:|
| Kalyna-128 | 2 | Standard | $2^8$ |
| Kalyna-128 | 3 | Weak key | $2^8$ |
| Kalyna-128 | 4 | No pre-whitening | $2^8$ |
| Kalyna-256 | 2 | Standard | $2^8$ |
| Kalyna-256 | 3 | Weak key | $2^{16}$ |
| Kalyna-256 | 4 | Weak key | $2^{16}$ |
| Kalyna-512 | 3 | Standard | $2^8$ |
| Kalyna-512 | 4 | Weak key | $2^8$ |
| Kalyna-512 | 5 | No pre-whitening | $2^8$ |

The scripts display the integral state after the relevant transformations
and verify the expected Balanced property.

The symbols used in the distinguisher output are:

```text
A : All
C : Constant
B : Balanced
U : Unknown
```

For example, the final output may contain

```text
Balanced bytes : 16/16
```

for Kalyna-128,

```text
Balanced bytes : 32/32
```

for Kalyna-256, or

```text
Balanced bytes : 64/64
```

for Kalyna-512.

---

## 2. Key Recovery for Kalyna-b/b

The directory

```text
kalyna_key_recovery_b_b/
```

contains nine key-recovery experiments for

```text
Kalyna-128/128
Kalyna-256/256
Kalyna-512/512
```

These experiments implement the column-wise last-round key-recovery
procedures described by Algorithms 1 and 2 of the paper.

| Variant | Target rounds | Setting | Algorithm | Data | Theoretical time |
|---|---:|---|---:|---:|---:|
| Kalyna-128/128 | 3 | Standard | 2 | $2^9$ | about $2^{74}$ |
| Kalyna-128/128 | 4 | Weak key | 1 | $2^9$ | about $2^{74}$ |
| Kalyna-128/128 | 5 | No pre-whitening | 2 | $2^9$ | about $2^{74}$ |
| Kalyna-256/256 | 3 | Standard | 2 | $2^9$ | about $2^{75}$ |
| Kalyna-256/256 | 4 | Weak key | 1 | $2^{17}$ | about $2^{83}$ |
| Kalyna-256/256 | 5 | Weak key | 2 | $2^{17}$ | about $2^{83}$ |
| Kalyna-512/512 | 4 | Standard | 1 | $2^9$ | about $2^{76}$ |
| Kalyna-512/512 | 5 | Weak key | 2 | $2^9$ | about $2^{76}$ |
| Kalyna-512/512 | 6 | No pre-whitening | 1 | $2^9$ | about $2^{76}$ |

For the Kalyna-$b/b$ family, the last-round key is recovered column by
column. Each guessed column contains 64 key bits.

Two independent integral multisets are used for candidate filtering.

---

## 3. Key Recovery for Kalyna-b/2b

The directory

```text
kalyna_key_recovery_b_2b/
```

contains six key-recovery experiments for

```text
Kalyna-128/256
Kalyna-256/512
```

These programs implement Algorithms 3 and 4 of the paper.

| Variant | Target rounds | Setting | Algorithm | Data | Theoretical time |
|---|---:|---|---:|---:|---:|
| Kalyna-128/256 | 4 | Standard | 4 | $2^9$ | about $2^{149}$ |
| Kalyna-128/256 | 5 | Weak key | 3 | $2^9$ | about $2^{137}$ |
| Kalyna-128/256 | 6 | No pre-whitening | 4 | $2^9$ | about $2^{149}$ |
| Kalyna-256/512 | 4 | Standard | 4 | $2^9$ | about $2^{278}$ |
| Kalyna-256/512 | 5 | Weak key | 3 | $2^{17}$ | about $2^{273}$ |
| Kalyna-256/512 | 6 | Weak key | 4 | $2^{17}$ | about $2^{286}$ |

For Algorithm 3, the complete $b$-bit last-round subkey is guessed and
the preceding round key is obtained through the Kalyna key-schedule
relation.

For Algorithm 4, after guessing the complete last-round key, the
equivalent preceding-round key is recovered byte by byte and then
transformed back into the corresponding round key.

---

## Requirements

The programs require

```text
Python 3.x
```

No external Python packages are required.

---

## Running the Distinguisher Programs

Run a distinguisher directly from the repository root. For example,

```bash
python kalyna_distinguishers/kalyna128_2round_distinguisher.py
```

or

```bash
python kalyna_distinguishers/kalyna512_4round_weakkey_distinguisher.py
```

The scripts display the integral propagation through the reduced-round
cipher and report the final number of Balanced bytes.

---

## Running the Key-Recovery Programs

For a Kalyna-$b/b$ experiment, for example,

```bash
python kalyna_key_recovery_b_b/kalyna256_4round_weakkey_key_recovery.py
```

For a Kalyna-$b/2b$ experiment, for example,

```bash
python kalyna_key_recovery_b_2b/kalyna128_256_5round_weakkey_key_recovery.py
```

Each script reports the relevant distinguisher balance before the attacked
round or rounds, the theoretical search space, the executable search mode,
the surviving candidates, and the recovered round subkey.

---

## Key-Recovery Demonstration Mode

The theoretical attacks described in the paper require exhaustive searches
over large key spaces such as

```text
2^64
2^128
2^256
```

Such exhaustive searches are computationally infeasible to execute as
ordinary Python demonstrations.

Therefore, by default, the key-recovery programs use a small deterministic
sample of full-width key candidates. The correct candidate is deliberately
included in this sample so that the candidate-testing and filtering
procedures can be reproduced directly.

The output explicitly distinguishes between the theoretical search space
and the executable demonstration. For example,

```text
Paper search space : 2^64 candidates for this 64-bit column
Search mode        : demo over 256 sampled 64-bit candidates
```

or

```text
Paper outer space  : 2^256 complete 256-bit last-round subkeys
Search mode        : demo over 2 sampled 256-bit candidates
```

Thus, a reported unique survivor in the default execution means a unique
survivor within the sampled demonstration candidate set. It does not mean
that the complete theoretical key space was exhaustively searched.

The key-recovery scripts also provide a

```text
--full
```

option corresponding to the literal exhaustive loop described in the
paper. This option is included for completeness and is not expected to
terminate in practical time for the reported attack complexities.

---

## Weak-Key Experiments

The weak-key experiments instantiate the restrictions on the
pre-whitening subkey specified in the paper.

Examples include:

```text
Kalyna-128:
k0=k1=k2=k3=k12=k13=k14=k15=0

Kalyna-256, 3 rounds:
k24=0

Kalyna-256, 4 rounds:
k0=k1=k6=k7=k12=k13=k14=k15=
k18=k19=k20=k21=k24=k25=k26=k27=0

Kalyna-512, 4 rounds:
k0=k15=k22=k29=k36=k43=k50=k57=0
```

The corresponding weak-key-space sizes are reported by the individual
programs.

These experiments should be interpreted at the reduced-round subkey level
used in the paper unless a corresponding full master-key restriction is
explicitly established.

---

## No-Pre-Whitening Experiments

The following distinguishers intentionally omit the initial
modulo-$2^{64}$ pre-whitening operation:

```text
kalyna128_4round_no_prewhitening_distinguisher.py
kalyna512_5round_no_prewhitening_distinguisher.py
```

The corresponding key-recovery experiments are:

```text
kalyna128_5round_no_prewhitening_key_recovery.py
kalyna512_6round_no_prewhitening_key_recovery.py
kalyna128_256_6round_no_prewhitening_key_recovery.py
```

These experiments apply only to the explicitly defined reduced models
without initial pre-whitening and should not be interpreted as attacks on
the full standardized Kalyna cipher.

For backward-extended experiments, the code constructs concrete
representative input multisets by applying the inverse round
transformations under the reference round keys used in the experiment.
These programs therefore provide executable verification of the stated
integral propagation for the instantiated reduced-round model.

---

## Implementation Checks

The implementations include consistency checks for the Kalyna round
transformations and their inverses.

The key-recovery programs also use published Kalyna test vectors where
appropriate to check the implementation of the cipher and key schedule.

For the Kalyna-$b/2b$ programs, the executable experiments additionally
verify that the reconstructed preceding round keys agree with the round
keys generated by the implemented Kalyna key schedule.

---

## Reproducibility

The intended workflow is:

```text
1. Run the corresponding distinguisher program.
2. Verify the expected Balanced property.
3. Run the associated key-recovery program.
4. Confirm the balance before the attacked round or rounds.
5. Verify that the sampled candidate search retains the correct round key.
6. Compare the reported theoretical data and time complexities with the
   corresponding result in the paper.
```

The individual folder `README.md` files provide more specific information
for each family of experiments.

---

## Scope

The repository is intended to provide transparent and executable
verification of the reduced-round integral propagation and key-recovery
procedures described in the accompanying paper.

The experimental demonstrations do not claim to perform the complete
high-complexity exhaustive searches required by the theoretical attacks.

---

## License

This repository is released under the MIT License.
