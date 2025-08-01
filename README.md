# T1552.003 – Credential Hunter

This repository contains a PowerShell script that searches for hardcoded credentials, API keys, connection strings, and password references inside script files (e.g., `.ps1`, `.bat`, `.vbs`, `.cmd`) on a target system.

This script aligns with the MITRE ATT&CK technique **T1552.003 – Credentials in Scripts**, commonly used in red teaming and adversary emulation exercises.

---

## 🛠 Script Details

- **Script Name**: `T1552.003-ScriptCredentialHunter.ps1`
- **MITRE ATT&CK ID**: [T1552.003 – Credentials in Files
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

## 🧾 Output Sample
```text
[+] Scanning for credential artifacts in scripts...
Found potential credential in C:\Users\admin\startup.ps1:
Line 12: $dbPassword = "SuperSecret123!"
```

---

## ⚙️ Prerequisites
 - PowerShell 5.1+
 - Read access to target folders
 - No external dependencies

---

## 📁 Folder Structure

```text
C:\
└── Temp\
    └── Artifacts\
        └── T1552.003-CredentialsInScripts.txt
```

## ✅ Use Cases
- Red team credential discovery
- Blue team detection tuning (e.g., matching Sysmon Event ID 1 for script access)
- Compliance scanning for insecure coding practices
