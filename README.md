# Krishna Aggarwal — Cybersecurity Portfolio

**INSPIRE MANAK Awardee 2023 · Department of Science & Technology, Govt. of India**  
C/C++ Certified (Grade A) · IIT Kanpur B.Cyber Applicant 2026  
Ghaziabad, NCR | [thetechnophile2023@gmail.com](mailto:thetechnophile2023@gmail.com) | [Portfolio Website](https://krishnaaggarwal-cybersecurity.github.io/IIT-KANPUR-cybersecurity-portfolio/)

---

## Who I Am

I build systems from first principles and then figure out how to break them.

At 14, I built a working portable washing machine — no kit, no instructions — selected by DST, Govt. of India for the INSPIRE MANAK Award. The lesson I took wasn't that I had built something impressive. It was that **every system has a failure mode, and the person who finds it first wins.** That single insight is why I pursue cybersecurity.

Since then: C/C++ (Grade A), cryptography tools, network security programs, forensics utilities, and steganography — all implemented from scratch, documented publicly, and explained with genuine understanding of *why* each concept matters to an attacker or defender.

---

## Security Tools — Implemented in C

### Network Security

| Tool | Description | Concepts |
|------|-------------|----------|
| [`port_scanner.c`](port_scanner.c) | TCP Connect port scanner with service banner identification, configurable range, non-blocking sockets with timeout | TCP handshake, socket programming, `select()`, network enumeration |
| [`file_integrity.c`](file_integrity.c) | File integrity monitor using Adler-32 checksums — detects unauthorized modifications to monitored files | HIDS concepts, checksum algorithms, tamper detection, baseline comparison |

### Digital Forensics

| Tool | Description | Concepts |
|------|-------------|----------|
| [`hex_dump.c`](hex_dump.c) | Binary hex dump utility with file signature analysis, offset/range viewing, and string search | Magic bytes, file format analysis, binary inspection, forensic artifact examination |
| [`lsb_steganography.c`](lsb_steganography.c) | LSB steganography in 24-bit BMP images — embed and extract hidden messages imperceptibly | Covert channels, BMP file format, pixel manipulation, steg detection awareness |

### Cryptography (Classical → Why They Fail)

| Tool | Description | Why It Matters |
|------|-------------|----------------|
| [`caesar_cipher.c`](caesar_cipher.c) | Shift cipher encoder/decoder with key=26 identity test | Understands *why* monoalphabetic ciphers break under frequency analysis |
| [`vigenere_cipher.c`](vigenere_cipher.c) | Polyalphabetic cipher with variable keyword | Understands Kasiski examination and why key repetition is fatal |
| [`xor_cipher.c`](xor_cipher.c) | XOR cipher demonstrating OTP fundamentals | Understands stream cipher basis and key reuse vulnerability |
| [`password_strength.c`](password_strength.c) | Entropy-based password strength evaluator | Character set entropy, pattern detection, actionable feedback |

---

## Security Research & Writeups

| Writeup | Summary |
|---------|---------|
| [`writeups/cryptanalysis_classical_ciphers.md`](writeups/cryptanalysis_classical_ciphers.md) | Why Caesar fails in 25 guesses, why Vigenère breaks with Kasiski, why XOR without true randomness is not secure — the progression from substitution to modern symmetric encryption |
| [`writeups/lsb_steganography_explained.md`](writeups/lsb_steganography_explained.md) | How LSB steganography works, why it evades visual detection, how it's detected (chi-square analysis, StegExpose), and its role in malware C2 communication |

---

## Achievements

| Year | Achievement |
|------|-------------|
| 2023 | **INSPIRE MANAK Award** — ₹10,000 cash prize, Department of Science & Technology, Govt. of India. Portable Automatic Washing Machine, built solo at age 14. |
| 2024 | **State Level Exhibition** — District/State Level Science Project Competition, GNCT Delhi, Directorate of Education |
| 2024 | **C & C++ Certificate** — Grade A, ICE Computer Education, Sahibabad |
| 2025 | **EMC 2025** — Led 6-member team (Team Technophile) at Engineering Model Competition with Germicidal Washing Machine featuring UV-C safety logic |
| 2025–26 | **DCAP** — Diploma in Computer Applications & Programming (In Progress), IICS Gokulpuri. Networking protocols, OS fundamentals |

---

## Technical Stack

```
Languages     : C, C++, HTML, CSS
Security       : Classical cryptography, network scanning, file forensics,
                  LSB steganography, checksum-based integrity monitoring
Networking     : TCP/IP stack, socket programming, port enumeration,
                  service identification (covered in C programs + DCAP)
OS & Systems   : Linux terminal, process concepts, file systems (DCAP)
Hardware       : Electromechanical prototyping, DC/AC conversion, motor
                  control, relay circuits (INSPIRE & EMC projects)
Forensics      : Binary analysis, file signature identification,
                  hex dump inspection, covert channel detection
```

---

## Why Cybersecurity

India's digital infrastructure is expanding faster than its defences. I understand hardware at a circuit level. I understand logic at a code level. I want to use both to find the gaps that attackers exploit before they do — starting with the rigorous foundation that IIT Kanpur's B.Cybersecurity program provides.

Every tool in this repository was built to answer a real question: *How does this work? How does it fail? How would an attacker use this, and how do I stop them?*

---

*All tools are for educational purposes and authorized testing only.*
