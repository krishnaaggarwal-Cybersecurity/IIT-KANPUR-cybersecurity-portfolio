# Statement of Purpose
## B.Tech in Cybersecurity | WSAIS, IIT Kanpur | 2026
**Applicant: Krishna Aggarwal**

---

At 14, I built a portable automatic washing machine from scratch — no kit, no instructions. The Department of Science & Technology selected it for the INSPIRE MANAK Award. What I took from that experience was not pride in what I had built. It was a single uncomfortable question: *how would someone break it?*

That question is why I want to study cybersecurity at IIT Kanpur.

---

**What I have built so far**

I program in C and C++. Not because a course required it, but because I wanted to understand systems at the level where memory, pointers, and bit operations are not abstracted away. The GitHub repository linked in this application contains tools I built entirely from first principles:

A **TCP Connect port scanner** that performs non-blocking socket connections using `select()` to enumerate open ports and identify services — the first step in any network reconnaissance. A **file integrity monitor** that computes Adler-32 checksums over monitored files and alerts on modification — the core concept behind HIDS tools like Tripwire. A **binary hex dump utility** with file signature identification and Shannon entropy analysis, which I use to inspect binary files the way a malware analyst would. A **LSB steganography tool** for 24-bit BMP images — not because steganography is a toy but because APT groups hide C2 instructions inside CDN-hosted images, and I wanted to understand exactly how.

I also implemented Caesar, Vigenère, and XOR ciphers — but the point was not the implementations. The point was to break them. I wrote a full cryptanalysis writeup (in the repository) documenting frequency analysis, Kasiski examination, and why XOR is only secure as a One-Time Pad. Understanding failure modes is the only honest way to understand security.

---

**What I understand about cybersecurity**

Security is not about building better locks. It is about anticipating how a determined attacker thinks. Every defensive control exists because someone found the attack first.

I understand why monoalphabetic substitution fails to frequency analysis, and why that led to polyalphabetic encryption. I understand why LSB steganography evades visual inspection but fails the chi-square test. I understand why a port scanner works by completing TCP three-way handshakes, and what SYN-ACK tells you about a filtered versus closed port. I understand why a file that checksums correctly against a stored baseline is still not trustworthy if the baseline itself is on the same writable medium.

These are not textbook summaries. These are things I understand because I implemented them, found the edge cases, and asked what an attacker would do with each one.

---

**Why IIT Kanpur**

IIT Kanpur's B.Cybersecurity curriculum covers exactly what I believe is missing from every other program I have researched: it treats cybersecurity as a first-principles engineering discipline, not a checklist of tools. Web security, reverse engineering, malware analysis, network forensics — these require the same rigour as systems programming, not just familiarity with Kali Linux.

I am 17. My formal credentials are thin. My JEE rank does not reflect what I am capable of in a domain where I am genuinely motivated. What I am asking for is the chance to demonstrate that in the admission test — because that is the one place where the actual work matters.

---

**What I intend to do with this degree**

India's critical infrastructure — power grids, banking systems, government databases — is expanding faster than its defences. I want to work in offensive security research: finding vulnerabilities before adversaries do, publishing responsible disclosures, contributing to the defences of systems that millions of people depend on.

IIT Kanpur is where that preparation begins correctly.

---

*Portfolio: https://krishnaaggarwal-cybersecurity.github.io/cybersecurity-portfolio/*  
*GitHub: https://github.com/krishnaaggarwal-Cybersecurity/cybersecurity-portfolio*
