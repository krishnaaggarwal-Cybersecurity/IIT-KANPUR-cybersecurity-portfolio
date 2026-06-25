# LSB Steganography: How It Works, How It's Used, How It's Detected

**Author:** Krishna Aggarwal  
**Date:** June 2026  
**Related Code:** [`lsb_steganography.c`](../lsb_steganography.c)

---

## Why Steganography Belongs in Cybersecurity

Steganography is the practice of **hiding communication inside innocent-looking data**. Unlike encryption (which makes data unreadable), steganography makes the data **invisible** — an attacker looking at the carrier file doesn't even know there's a secret to find.

In cybersecurity, this is not a historical curiosity. It is active tradecraft:

- **APT malware** downloads instructions by reading pixel data from images hosted on legitimate CDNs or social media platforms (CnC over Instagram, Twitter, Imgur).
- **Data exfiltration bypasses DLP** (Data Loss Prevention) by hiding stolen data inside image files that pass keyword-based inspection.
- **Malware loaders** hide shellcode in image files that antivirus engines scan but don't extract hidden payloads from.

Understanding steganography is prerequisite knowledge for malware analysis, threat hunting, and network forensics.

---

## How LSB Steganography Works

### The Human Visual System's Limitation

The human eye cannot distinguish between RGB(200, 100, 50) and RGB(201, 100, 50). A 1-unit change in any channel across 0–255 is invisible.

In binary:
```
200 = 11001000
201 = 11001001
```

The only difference is the **Least Significant Bit** (bit 0, the rightmost). Flipping it changes the value by exactly 1.

### The Encoding Process

We hide data by replacing the LSB of each pixel channel byte with one bit of our secret message.

For a 24-bit BMP image (3 bytes per pixel: Blue, Green, Red):
```
Original pixel bytes:
  B: 11001000  (200)
  G: 01110101  (117)
  R: 11110010  (242)

Message bits to hide: 1  0  1

Modified pixel bytes:
  B: 11001001  (201)  ← bit changed
  G: 01110100  (116)  ← bit changed
  R: 11110011  (243)  ← bit changed
```

Three bits of hidden data. Colour change: imperceptible.

### Storage Capacity

For an image of width W × height H:
```
Capacity = W × H × 3 channels × 1 bit per channel ÷ 8 bits per byte
         = W × H × 3 ÷ 8 characters
```

For a 1920×1080 image:
```
Capacity = 1920 × 1080 × 3 ÷ 8 = 777,600 characters ≈ 760 KB of hidden text
```

A single full-HD image can carry an entire stolen document — invisibly.

### Embedding Algorithm (from my implementation)

```
For each bit i of the message (MSB-first within each byte):
    bit = (message[i/8] >> (7 - i%8)) & 1
    pixel[i] = (pixel[i] & 0xFE) | bit
```

`0xFE` = `11111110` — zeroes the LSB without touching the other 7 bits.  
`| bit` sets the LSB to our message bit.

### Extraction Algorithm

```
For each pixel byte i:
    bit = pixel[i] & 1
    message[i/8] |= bit << (7 - i%8)
Stop when null byte is encountered.
```

No key is needed in basic LSB. Anyone who knows the method can extract the message. For actual covert communication, the message itself is encrypted before embedding.

---

## Why This Choice of Carrier (BMP)

I implemented this for **uncompressed 24-bit BMP** files specifically because:

- BMP uses **no compression** — the pixel bytes are stored exactly as written. The LSBs we embed are preserved perfectly in the saved file.
- JPEG uses **lossy compression** — it discards small differences in pixel values during the DCT/quantisation step. Our 1-bit LSB changes would be wiped out on save.
- PNG uses **lossless compression** — LSBs survive, but the compression algorithm detects the unusual LSB patterns we introduce (natural images compress better than steg'd images), which is itself a detection signal.

BMP is the cleanest carrier for understanding the concept. Real-world steg tools use PNG or dedicated JPEG-domain methods (F5 algorithm) that embed data in the DCT coefficients rather than pixels.

---

## How LSB Steganography Is Detected

### 1. Chi-Square Attack

**Observation:** In natural images, each pixel channel value tends to cluster around even numbers more than odd numbers (smooth gradients round down). Pairs of values differing by 1 (called **PoVs** — Pairs of Values) should have unequal frequency.

After LSB embedding, the attacker forces equal frequency between every pair `(2k, 2k+1)` because the LSB is overwritten with random message bits → the two values in each pair become equally likely.

The chi-square test measures whether the observed frequency of PoVs matches the expected 50/50 distribution. High chi-square score → likely steg.

My `--analyze` flag implements the LSB distribution check that approximates this test.

### 2. RS Analysis (Fridrich et al., 2001)

Divide image into groups. Flip LSBs of some pixels. Measure how much the "smoothness" of the image changes. In natural images, flipping LSBs increases roughness. In steg images, some LSBs are already message bits, so the expected roughness change doesn't occur. The asymmetry reveals the embedding rate.

### 3. Tool Detection

- **StegExpose** — automated statistical detection (chi-square + RS + others)
- **zsteg** — LSB analysis for PNG/BMP, reports suspicious patterns
- **stegsolve** — visual LSB plane viewer (isolates the LSB layer as a separate image)
- **Binwalk** — embedded file detection (for cases where whole files are hidden)

### What This Means for Defenders

Network traffic analysis alone cannot detect steganographic exfiltration — the carrier file passes standard content inspection. Defenders need:

1. **Statistical analysis** of outbound images (file size vs. expected size, entropy anomalies)
2. **DLP policies** that inspect file content, not just keywords
3. **Threat hunting** for processes that read image files before making outbound connections
4. **Endpoint behaviour analysis** — unexpected image reads by non-image applications

---

## Real-World APT Usage

- **APT28 (Fancy Bear):** Used Zebrocy malware that downloaded images from compromised sites, extracted C2 commands from pixels.
- **Duqu 2.0:** Hid configuration in JPEG EXIF headers.
- **Turla Group:** Exfiltrated data via images uploaded to Instagram, commands embedded in image comments and pixel data.
- **COMpfun:** Received C2 instructions via HTTP response codes mapped to keylogging commands — a non-pixel covert channel demonstrating the same principle.

The common thread: **the transport (image) is trusted. The payload (hidden data) is invisible.**

---

## What I Learned

Building this tool taught me more about malware behaviour than reading about it would have. I now understand:

- Why malware analysts use `zsteg` and `stegsolve` as first-pass tools on suspicious attachments
- Why DLP tools fail against steg-based exfiltration
- Why high-entropy JPEG files are suspicious even if they open correctly as images
- The specific mathematics (chi-square, IC) that detection tools use

The tool in this repo is educational. Understanding how covert channels work is how you detect and prevent them.

---

## References

- Fridrich, J., Goljan, M., Du, R. (2001). *Reliable Detection of LSB Steganography in Color and Grayscale Images.* IEEE Multimedia.
- Westfeld, A., Pfitzmann, A. (1999). *Attacks on Steganographic Systems.*
- StegExpose: [github.com/b3dk7/StegExpose](https://github.com/b3dk7/StegExpose)
- SANS: *Steganography in Contemporary Cyberattacks* (2019)
