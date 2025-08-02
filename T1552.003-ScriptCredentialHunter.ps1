<#
.SYNOPSIS
    Simulates MITRE ATT&CK T1552.003 by searching for credentials in script files.

.DESCRIPTION
    - Searches *.ps1 and *.bat files in user's Desktop, Documents, and entire C:\ drive
    - Looks for keywords like password, secret, admin_pass, token
    - Saves findings to C:\Temp\Artifacts\T1552.003-CredentialsInScripts.txt

.AUTHOR
    Arslan Baig
#>

# Set folders to search
$searchPaths = @(
    "C:\"
)

# Output path
$artifactDir = "C:\Temp\Artifacts"
$artifactFile = "$artifactDir\T1552.003-CredentialsInScripts.txt"

# Ensure output folder
if (-not (Test-Path $artifactDir)) {
    New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
}

# Initialize output
New-Item -ItemType File -Path $artifactFile -Force | Out-Null
Add-Content $artifactFile "=== [ MITRE ATT&CK T1552.003 – Credentials in Scripts ] ==="
Add-Content $artifactFile "Scan Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

# Patterns and file types
$fileTypes = @("*.ps1", "*.bat")
$patterns = "password", "passwd", "admin_pass", "ADMIN_PASS", "secret", "token"

# Perform search
foreach ($path in $searchPaths) {
    foreach ($ext in $fileTypes) {
        Get-ChildItem -Path $path -Include $ext -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object {
                foreach ($word in $patterns) {
                    try {
                        Select-String -Path $_.FullName -Pattern $word -SimpleMatch |
                            ForEach-Object {
                                Add-Content $artifactFile "File: $($_.Path)"
                                Add-Content $artifactFile "Line $($_.LineNumber): $($_.Line.Trim())`n"
                            }
                    } catch {}
                }
            }
    }
}

Add-Content $artifactFile "Scan completed on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "[+] Script credential scan completed. Check $artifactFile"
