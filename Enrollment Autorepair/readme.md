# Workspace ONE Recovery Solution

## Overview
This solution automates the installation, validation, unenrollment, and re-enrollment of Workspace ONE on Windows devices. It ensures that devices remain properly enrolled in the Workspace ONE environment while addressing potential issues with MDM configurations or related services.

---

## Components
The solution comprises the following PowerShell scripts:

1. **`Install.ps1`**:
   - Sets up the solution by copying required files and creating a scheduled task for automated execution.

2. **`ws1_autorepair.ps1`**:
   - Validates the device's MDM enrollment status, Workspace ONE services, and scheduled tasks.
   - Automatically triggers recovery actions if issues are detected.

3. **`recovery.ps1`**:
   - Handles unenrollment and complete cleanup of Workspace ONE configurations, services, and artifacts.
   - Re-enrolls the device into Workspace ONE and restores a clean operational state.

---

## Features
- **Automated Installation**:
  - Installs Workspace ONE Intelligent Hub and related services.
- **Validation**:
  - Checks the MDM enrollment status, scheduled task functionality, and Workspace ONE Intelligent Hub processes.
- **Unenrollment and Cleanup**:
  - Removes existing configurations, applications, registry entries, scheduled tasks, and certificates.
- **Re-enrollment**:
  - Automatically downloads and installs the Workspace ONE Agent.
  - Configures the device for re-enrollment using staging credentials.
- **Logging and Error Handling**:
  - Centralized logging with severity levels (`INFO`, `WARNING`, `ERROR`).
  - Validates script integrity using hash comparison.
- **Security Features**:
  - Locks the workstation during critical operations.
  - Cleans sensitive information like staging user credentials after re-enrollment.

---

## Usage

### Installation
Run `Install.ps1` to set up the solution:
```powershell
.\Install.ps1 -ExpectedHash "<YourScriptHash>" -DayOfWeek "Monday" -TimeOfDay "14:00:00" -DestinationPath "C:\Path\To\Destination"
```
# Workspace ONE Recovery Solution

## Scheduled Validation and Recovery
The scheduled task created by `Install.ps1` will automatically execute `ws1_autorepair.ps1` to validate and repair the Workspace ONE environment. It checks for:
- Enrollment issues.
- Misconfigured or missing scheduled tasks.
- Failed or stopped services and processes.

If no issues are detected, the script exits. If issues are found, it triggers `recovery.ps1`.

---

## Manual Execution
You can manually trigger any script if necessary:
- **Validation**: Run `ws1_autorepair.ps1` to check the device's status.
- **Recovery**: Run `recovery.ps1` to unenroll and re-enroll the device.

---

## Prerequisites
- PowerShell 5.1 or higher.
- Administrative privileges on the device.
- Internet connectivity to download the Workspace ONE Agent.
- Access to Workspace ONE server credentials and organizational group ID.

---

## Key Configuration Parameters

### `Install.ps1`
- **`DayOfWeek`**: Specifies the day to run the scheduled task (default: `Thursday`).
- **`TimeOfDay`**: Specifies the time to run the scheduled task (default: `08:00:00`).
- **`DestinationPath`**: Path where recovery scripts will be stored (default: `C:\Windows\UEMRecovery`).
- **`ExpectedHash`**: SHA-256 hash of the script to validate its integrity.

### `ws1_autorepair.ps1`
- **`providerID`**: MDM provider ID (default: `AirwatchMDM`).
- **`logFilePath`**: Path for saving logs (default: `C:\Windows\UEMRecovery\Logs\MDM_WNS_Validation_Log.txt`).
- **`ExpectedHash`**: Expected hash of the script for integrity verification.

---

## Security Notes
- **Hardcoded Credentials**:
  - The staging user credentials in `recovery.ps1` should be replaced with a secure method, such as fetching credentials dynamically or using a secret manager.
- **Log Security**:
  - Store logs securely to prevent exposure of sensitive information.
- **Secure Recovery Directory**:
  - Delete or secure the recovery directory (`C:\Windows\UEMRecovery`) after deployment.

---

## Troubleshooting
- **Validation Fails**: Check the logs at the specified path for detailed error messages.
- **Enrollment Timeout**: Ensure the Workspace ONE server is reachable, and credentials are correct.
- **Script Integrity Error**: Verify that the provided hash matches the hash of the script.

---

## Acknowledgments
This solution was designed to enhance the reliability and resilience of Workspace ONE deployments by automating recovery tasks and reducing manual intervention.
