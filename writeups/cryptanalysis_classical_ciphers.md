# Why Classical Ciphers Fail: A Cryptanalysis Perspective

**Author:** Krishna Aggarwal  
**Date:** June 2026  
**Related Code:** [`caesar_cipher.c`](../caesar_cipher.c) · [`vigenere_cipher.c`](../vigenere_cipher.c) · [`xor_cipher.c`](../xor_cipher.c)

---

## The Point of This Writeup

I did not implement Caesar, Vigenère, and XOR ciphers to claim I know cryptography.  
I implemented them to understand **exactly why they fail** — because understanding failure is the entire job in security.

This writeup documents what I learned. Not from a textbook summary, but from implementing each cipher and then thinking through what an attacker would do.

---

## 1. Caesar Cipher — Broken in 25 Guesses (Maximum)

### How It Works

Shift every letter by a fixed key `k`. `A` becomes `D` if `k = 3`. Decryption shifts back.

```
Encrypt: C = (P + k) mod 26
Decrypt: P = (C - k + 26) mod 26
```

My implementation handles both cases, preserves non-alpha characters, and correctly handles `k = 26` (identity — produces the original text).

### Why It Fails: Brute Force

There are exactly **25 non-trivial keys** (1–25). A human can visually scan 25 candidate plaintexts in seconds. A computer checks all 25 in microseconds.

There is no key space to protect. A cipher with 25 possible keys is not a cipher — it is a delay.

### Why It Fails: Frequency Analysis

Even without trying every key, a single tool breaks Caesar: **letter frequency analysis.**

In English text, letters are not uniformly distributed:
- `E` appears ~12.7% of the time
- `T` ~9.1%, `A` ~8.2%, `O` ~7.5%
- `Z` ~0.07%

A Caesar cipher **preserves this distribution.** If the most frequent letter in ciphertext is `H`, then `H = E + 3`, so `k = 3`.

One count of letter frequencies. One lookup. Cipher broken.

### What This Teaches About Modern Encryption

Modern ciphers (AES) use **substitution-permutation networks** with key-dependent, full-diffusion substitution. Flipping one input bit changes ~50% of output bits (the avalanche effect). There is no frequency signal left in the ciphertext because the same plaintext byte maps to different ciphertext bytes in every block.

---

## 2. Vigenère Cipher — Broken by Key Length Repetition

### How It Works

Use a **repeating keyword** instead of a single shift.

```
Key:    K  E  Y  K  E  Y  K  E  Y  ...
Plain:  A  T  T  A  C  K  A  T  D  ...
Cipher: K  X  R  K  G  W  K  X  B  ...
```

Each letter is shifted by the corresponding key letter (`A=0, B=1, ..., Z=25`).

This defeats naive frequency analysis because the same plaintext letter (`A`) produces different ciphertext letters depending on position.

### Why It Fails: Kasiski Examination

The weakness is **key repetition.** If the keyword is length `n`, every `n`-th character is shifted by the same amount. The ciphertext effectively becomes `n` interleaved Caesar ciphers.

**Kasiski (1863) showed:** find repeated sequences in the ciphertext. Their spacing is likely a multiple of the key length. Factor those spacings → probable key lengths.

**Index of Coincidence (Friedman, 1925):** for each candidate key length `n`, split ciphertext into `n` groups (positions 0, n, 2n, ... | 1, n+1, 2n+1, ... | ...). Compute the Index of Coincidence for each group:

```
IC = Σ(ni × (ni - 1)) / (N × (N - 1))
```

For English text: IC ≈ 0.065. For random: IC ≈ 0.038.  
When you've guessed the right `n`, each group is a Caesar cipher, and IC jumps to ~0.065.

Then frequency analysis on each group independently reveals the key letter for that position.

### What This Teaches About Modern Encryption

Vigenère's flaw is **periodic key reuse**. Modern stream ciphers (ChaCha20) use a keystream that never repeats for the same key+nonce pair and is computationally indistinguishable from random.

The lesson: the moment any pattern exists in a keystream, it can be exploited.

---

## 3. XOR Cipher — Secure Only Once

### How It Works

XOR each plaintext byte with the corresponding key byte:

```
Ciphertext[i] = Plaintext[i] XOR Key[i]
Plaintext[i]  = Ciphertext[i] XOR Key[i]   (same operation)
```

XOR is self-inverse. No separate decryption algorithm needed.

### The Only Truly Secure Cipher: OTP

If the key is:
- **Truly random** (not pseudorandom)
- **At least as long as the message**
- **Never reused**
- **Kept secret**

This is a **One-Time Pad (OTP)**, and it is **information-theoretically secure**. Even with infinite computational power, an attacker learns nothing about the plaintext. Shannon proved this in 1949.

### Why XOR Ciphers Always Fail in Practice

**Problem 1: Key reuse**

```
C1 = P1 XOR K
C2 = P2 XOR K
C1 XOR C2 = P1 XOR P2
```

If you XOR two ciphertexts encrypted with the same key, the key cancels out. You get `P1 XOR P2`, which leaks the relationship between plaintexts.

With enough cribbing (known plaintext guesses), both `P1` and `P2` can be recovered. This broke Project VENONA (1940s Soviet communications encrypted with partially reused one-time pads).

**Problem 2: Short/pseudorandom keys**

A key generated by `rand()` (linear congruential generator) is not truly random. If an attacker can guess the seed (e.g., current time), they can reproduce the entire keystream. The cipher is broken.

**Problem 3: Known-plaintext attacks**

If an attacker knows any plaintext portion: `K = C XOR P`. Key exposed.

### What This Teaches About Modern Encryption

Modern stream ciphers (RC4 — now deprecated; ChaCha20 — current) use pseudorandom keystreams, but with **cryptographically secure PRNGs** seeded with secret key material. The output is computationally indistinguishable from true random even without knowing the key.

The key lesson: **security does not come from the operation (XOR is fine). It comes from the key generation and management.**

---

## Summary: The Progression

| Cipher | Key Space | Frequency Resistant | Key Reuse Safe | Practical? |
|--------|-----------|---------------------|----------------|------------|
| Caesar | 25 keys | No | No | No |
| Vigenère | Large | Partially | No | No |
| OTP (XOR) | ∞ effective | Yes | No (fatal) | No (key distribution) |
| AES-256 | 2²⁵⁶ | Yes | Yes (with IV) | Yes |

The journey from Caesar to AES is a series of attacks found and defences built.  
**Every weakness listed above was discovered by someone who thought like an attacker first.**

That is the mindset I bring to cybersecurity.

---

## References

- Shannon, C.E. (1949). *Communication Theory of Secrecy Systems*. Bell System Technical Journal.
- Kasiski, F.W. (1863). *Die Geheimschriften und die Dechiffrir-Kunst*.
- Friedman, W.F. (1925). *The Index of Coincidence and Its Applications in Cryptanalysis*.
- NIST FIPS 197 — Advanced Encryption Standard (AES)
- Bernstein, D.J. (2008). *ChaCha, a variant of Salsa20*
