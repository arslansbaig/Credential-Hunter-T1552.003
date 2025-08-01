# T1552.003 – Script Credential Hunter

This repository contains a PowerShell script that searches for hardcoded credentials, API keys, connection strings, and password references inside script files (e.g., `.ps1`, `.bat`, `.vbs`, `.cmd`) on a target system.

This script aligns with the MITRE ATT&CK technique **T1552.003 – Credentials in Scripts**, commonly used in red teaming and adversary emulation exercises.

---

## 🛠 Script Details

- **Script Name**: `T1552.003-ScriptCredentialHunter.ps1`
- **MITRE ATT&CK ID**: [T1552.003 – Credentials in Files: Scripts](https://attack.mitre.org/techniques/T1552/003/)
- **Author**: Arslan Baig
- **Category**: Credential Access
- **Function**: Scans for potential credentials and secrets hardcoded in scripts across common file paths.

---

## 🔍 What It Does

- Recursively scans the following directories:
  - `C:\Users`
  - `C:\Scripts`
  - `C:\ProgramData`
- Looks for script files with extensions: `.ps1`, `.bat`, `.vbs`, `.cmd`
- Searches for keywords like:
  - `password`, `pwd`, `secret`, `apikey`, `key`, `token`, `connectionstring`, `auth`
- Extracts lines containing these patterns and logs them
- Outputs results to `C:\Temp\Artifacts\ScriptCredentialHunter.txt`

---

## ⚙️ Prerequisites
> PowerShell 5.1+
> Read access to target folders
> No external dependencies

---

## 📁 Folder Structure

```text
C:\
└── Temp\
    └── Artifacts\
        └── T1552.003-CredentialsInScripts.txt
