# The Operators - Simple File Integrity & Change Detection

## Project Overview
HashCheck is a simple file integrity verification tool designed to detect changes in files over time.  
It allows a user to create a **baseline** of cryptographic hashes for all files in a selected folder, and later **verify** the current state of that folder against the original baseline.

This helps identify whether files have been:
- Modified  
- Added  
- Deleted  
- Or left unchanged  

HashCheck is useful for cybersecurity students, incident response practice, digital forensics labs, and anyone who needs a clear view of how files change between two points in time.

---

## Platform Support
HashCheck is currently designed for **Windows systems only**.  
Linux and macOS may require additional configuration and have **not been tested**.

---

## Features

- **Baseline Scan**  
  Generate a CSV manifest of files, including paths, sizes, last modified timestamps, and hashes.

- **Verification Scan**  
  Compare current files to a previous baseline and detect:
  - **OK** – Unchanged  
  - **MISMATCH** – File modified  
  - **NEW** – File added  
  - **MISSING** – File deleted  
  - **ERROR** – File unreadable or hashing failed  

- **User Interface**  
  Clean & Simple interface with color-coded results.

- **Recursive Scanning**  
  Option to include all subfolders during scans.

- **CSV Export**  
  Save baseline or verification results for further analysis or documentation.

---

## Setup & Run Instructions

### 1. Install Python
Ensure you have **Python (3.9 is recommended)** installed on Windows.


### 3. Download the Project Files
Place the following files together in the same directory:
- hashcheck.py
- hashcheck_gui.py

### 4. Run Hashcheck
Open a command prompt or PowerShell window in the project directory and run

---

## How to Use HashCheck
Creating a Baseline
  1. Launch the application
  2. Select a target file or folder
  3. Choose where you want your scan results (manifest) to be stored
  4. Select a hashing algorithm (e.g., SHA-256)
  5. Enable recursive if you want to include subfolders
  6. Click "Run Scan"
  7. You can either review results in a CSV or within the HashCheck GUI itself

---

## Verifying File Integrity
1. Switch to the Verify tab
2. Select the same folder
3. Choose your previously created or most recent baseline CSV
4. Click "Run Verify"

### HashCheck will compare the current state of the directory to the baseline and show results with color-coded statuses:
- Normal | No color
- Mismatch | Red
- New File | Orange
- Missing File | Gray
- Error | Magenta/Purple

  
