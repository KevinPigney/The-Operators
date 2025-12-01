# The Operators - Simple File Integrity & Change Detection

HashCheck is a **file integrity verification tool** designed for Digital Forensics & Incident Response (DFIR) workflows.

It lets you:

- Create a **baseline** of file hashes from a folder (manifest)
- Later **verify** that folder against the baseline
- Instantly see which files are **unchanged, modified, new, or missing**
- Export results to **CSV** for further analysis

Built with Python and Tkinter, HashCheck provides a clean, dark-mode GUI that’s easy enough for students to use and realistic enough for IR-style workflows.

---

## Features

- **Cryptographic hashing**
  - Supports common algorithms: `SHA-256`, `SHA-1`, `MD5`
- **Recursive directory scanning**
  - Optionally scans all subfolders, not just the top-level directory
- **Baseline & verify workflow**
  - **Scan mode**: generate a manifest of files + hashes
  - **Verify mode**: compare current files against a previous manifest
- **Visual, color-coded results**
  - Normal – unchanged files  
  - **MISMATCH** – file content changed  
  - **NEW** – file wasn’t in the original baseline  
  - **MISSING** – file was in the baseline but no longer exists  
  - **ERROR** – file couldn’t be read/hashed
- **Analyst-friendly CSV export**
  - Exports results to CSV for review in Excel, SIEM, or other tools
- **Dark mode UI**
  - Borderless, modern look with slightly larger fonts for readability

---

## Why HashCheck?

### 1. What problem does it solve?

In cybersecurity and forensics, you often need to answer questions like:

- *“Which files changed after this incident?”*  
- *“What did the malware encrypt or modify?”*  
- *“Is this evidence still in its original state?”*

Manually checking files or eyeballing timestamps doesn’t scale.  
**HashCheck** automates this by using cryptographic hashes and a simple baseline/verify workflow.

---

### 2. Why is it important?

Hash-based integrity checks are used in:

- **Incident response** – Identify tampered, encrypted, or deleted files  
- **Ransomware investigations** – See exactly what was impacted  
- **Digital forensics** – Verify that evidence hasn’t changed  
- **System administration** – Detect configuration drift or unexpected changes

HashCheck provides these capabilities in a way that’s:

- Free
- Easy to run
- Visual and approachable for students & junior analysts

---

### 3. Why would others want to use it?

For fellow students, HashCheck is:

- **Perfect for labs & projects**
  - Malware labs, IR simulations, forensics assignments
- **Beginner-friendly**
  - No command-line required, everything is in the GUI
- **Good for reports**
  - CSV output works great in Excel or as an appendix in lab reports
- **Real-world relevant**
  - Mimics workflows used by real IR and forensics teams

---

## Project Structure

Suggested layout:

```bash
hashcheck/
├─ hashcheck.py            # Core hashing & manifest logic (backend)
├─ hashcheck_frontend.py   # Tkinter GUI (frontend)
├─ README.md               # This file
└─ requirements.txt        # (Optional) Python dependencies
