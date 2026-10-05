# Kalyna Integral Distinguishers

This folder contains the reproducibility code for the integral distinguishers presented in the paper:

**Integral Propagation under Modulo-Addition Whitening with Application to Reduced-Round Kalyna**

The code covers the three standard Kalyna block sizes: Kalyna-128, Kalyna-256, and Kalyna-512. Each script constructs the corresponding plaintext multiset, applies the reduced-round encryption, and verifies the expected integral propagation and final Balanced property.

## Files

### Kalyna-128

- `kalyna128_2round_distinguisher.py`  
  2-round standard integral distinguisher with data complexity \(2^8\).

- `kalyna128_3round_weakkey_distinguisher.py`  
  3-round weak-key integral distinguisher with data complexity \(2^8\) and weak pre-whitening-key space \(2^{64}\).

- `kalyna128_4round_no_prewhitening_distinguisher.py`  
  4-round integral distinguisher for the reduced model without pre-whitening, with data complexity \(2^8\).

### Kalyna-256

- `kalyna256_2round_distinguisher.py`  
  2-round standard integral distinguisher with data complexity \(2^8\).

- `kalyna256_3round_weakkey_distinguisher.py`  
  3-round weak-key integral distinguisher with data complexity \(2^{16}\) and weak pre-whitening-key space \(2^{248}\).

- `kalyna256_4round_weakkey_distinguisher.py`  
  4-round weak-key integral distinguisher with data complexity \(2^{16}\) and weak pre-whitening-key space \(2^{128}\).

### Kalyna-512

- `kalyna512_3round_distinguisher.py`  
  3-round standard integral distinguisher with data complexity \(2^8\).

- `kalyna512_4round_weakkey_distinguisher.py`  
  4-round weak-key integral distinguisher with data complexity \(2^8\) and weak pre-whitening-key space \(2^{448}\).

- `kalyna512_5round_no_prewhitening_distinguisher.py`  
  5-round integral distinguisher for the reduced model without pre-whitening, with data complexity \(2^8\).

## Running the Code

Each file can be executed directly with Python 3. 
