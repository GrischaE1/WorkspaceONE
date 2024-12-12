param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "File Hash of the ws1_autorepair.ps1 file")]
    [ValidatePattern("^[a-fA-F0-9]{64}$")]
    [String] $FileHash
)

$InstallDir = "C:\Windows\UEMRecovery"
$TargetFile = "$InstallDir\ws1_autorepair.ps1"

# Validate that the installation directory exists
if (-not (Test-Path $InstallDir)) {
    Write-Host "Installation directory not found: $InstallDir" -ForegroundColor Red
    Exit 404  # Return code for directory not found
}

# Validate that the target file exists
if (-not (Test-Path $TargetFile)) {
    Write-Host "Target file not found: $TargetFile" -ForegroundColor Red
    Exit 404  # Return code for file not found
}

# Calculate the file hash and compare
try {
    $InstalledFileHash = (Get-FileHash $TargetFile -ErrorAction Stop).Hash

    if ($FileHash -eq $InstalledFileHash) {
        Write-Host "File hash matches. Installation verified successfully." -ForegroundColor Green
        Exit 0
    } else {
        Write-Host "File hash does not match. Installation verification failed." -ForegroundColor Yellow
        Exit 4321  # Return code for hash mismatch
    }
} catch {
    Write-Host "Error while calculating file hash: $_" -ForegroundColor Red
    Exit 1  # General error code
}

	

