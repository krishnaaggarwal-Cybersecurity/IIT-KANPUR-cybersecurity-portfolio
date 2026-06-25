# DEPLOY NOW — Exact Commands to Run

## Your deadline is TODAY. Do these steps in order. No skipping.

---

## STEP 0 — Install Git (if not already)
Download from https://git-scm.com/download/win (Windows) or run:
```bash
# Ubuntu/Debian
sudo apt install git

# Check if already installed
git --version
```

---

## STEP 1 — Clone your existing repo

```bash
git clone https://github.com/krishnaaggarwal-Cybersecurity/cybersecurity-portfolio.git
cd cybersecurity-portfolio
```

---

## STEP 2 — Copy all new files into the repo folder

Copy these files from where you downloaded them into the `cybersecurity-portfolio/` folder:

**Root folder (cybersecurity-portfolio/):**
- README.md        ← REPLACE existing one
- port_scanner.c   ← NEW
- file_integrity.c ← NEW
- hex_dump.c       ← NEW
- lsb_steganography.c ← NEW
- index.html       ← REPLACE existing one

**Create a writeups/ subfolder and put these in it:**
- writeups/cryptanalysis_classical_ciphers.md ← NEW
- writeups/lsb_steganography_explained.md     ← NEW

---

## STEP 3 — Stage and commit everything

```bash
# From inside cybersecurity-portfolio/ folder:

git add .

git commit -m "Add security tools: port scanner, file integrity monitor, hex dump, LSB steganography

New tools:
- port_scanner.c: TCP connect scanner with non-blocking sockets and service ID
- file_integrity.c: HIDS file integrity monitor using Adler-32 checksums
- hex_dump.c: Binary forensics tool with file signature analysis and entropy
- lsb_steganography.c: LSB steganography in 24-bit BMP with detection analysis

New research writeups:
- writeups/cryptanalysis_classical_ciphers.md
- writeups/lsb_steganography_explained.md

Updated README.md and portfolio website (index.html)"

git push origin main
```

If `main` doesn't work, try `master`:
```bash
git push origin master
```

---

## STEP 4 — Verify everything is live

1. Go to: https://github.com/krishnaaggarwal-Cybersecurity/cybersecurity-portfolio
   → You should see all new files and the updated README

2. Wait ~2 minutes, then go to:
   https://krishnaaggarwal-cybersecurity.github.io/cybersecurity-portfolio/
   → You should see the new portfolio website

If website doesn't update, go to repo → Settings → Pages → check it's set to deploy from main/master branch

---

## STEP 5 — Apply to IIT Kanpur (IF NOT DONE YET)

URL: https://pingala.iitk.ac.in/CYBER_UGADM/login

When asked for cybersecurity evidence, paste:
- GitHub: https://github.com/krishnaaggarwal-Cybersecurity/cybersecurity-portfolio
- Portfolio: https://krishnaaggarwal-cybersecurity.github.io/cybersecurity-portfolio/

For the Statement of Purpose field, use the text from:
SOP_IITKanpur_Krishna_Aggarwal.md

---

## STEP 6 — Create TryHackMe account RIGHT NOW

URL: https://tryhackme.com

Create account → Start "Pre-Security" learning path → Complete at least 3 rooms today.

This takes 2 hours. Do it tonight after applying. 
Add your TryHackMe profile URL to your application if there's a field for it.

---

## If you get a Git authentication error:

GitHub removed password auth. Use a Personal Access Token:
1. GitHub.com → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate new token → check "repo" scope → copy the token
3. Use the token as your password when git asks

Or use GitHub Desktop (GUI): https://desktop.github.com

---

## Checklist (tick these off):

- [ ] Applied at pingala.iitk.ac.in (DEADLINE TODAY)
- [ ] All 6+ .c files pushed to GitHub
- [ ] writeups/ folder pushed to GitHub
- [ ] README.md updated (shows all tools)
- [ ] index.html updated (portfolio website live)
- [ ] TryHackMe account created, first rooms started
- [ ] GitHub link submitted in application
