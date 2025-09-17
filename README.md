# 🔍 PowerShell System Health & Security Monitor

A PowerShell script for automated **system health monitoring, remediation, and security event auditing** on Windows.  
Built as part of a lab project, but packaged here for anyone who wants a lightweight monitoring solution.

---

## ✨ Features
- **CPU Monitoring**
  - Detects sustained CPU usage above a threshold (default 80%).
  - Identifies the top process and safely terminates if not a protected system process.

- **Memory Monitoring**
  - Warns when RAM usage exceeds a configurable threshold (default 85%).
  - Lists top 3 memory-hungry processes.

- **Disk Monitoring**
  - Alerts when `C:` free space falls below 15%.
  - Attempts automatic cleanup of `C:\Temp`.

- **Security Event Monitoring**
  - Detects multiple failed logon attempts (Event ID 4625).
  - Detects account lockouts (Event ID 4740).
  - Alerts on unexpected service stops (7034/7036).

- **Logging**
  - Writes to console, daily log file (`C:\Logs\Lab1_<date>.log`),  
    Windows Application log, and a custom Event Log (`Lab1-Monitoring`).

---

## ⚙️ Configuration
You can tweak thresholds at the top of the script:

```powershell
$CPU_THRESHOLD   = 80      # CPU usage %
$MEM_WARN_USED   = 85      # Memory usage %
$DISK_MIN_FREE   = 15      # Min % free on C:
$SAMPLE_INTERVAL = 5       # CPU sample interval (seconds)
$SUSTAIN_WINDOW  = 30      # Sustained CPU window (seconds)
$CYCLE_SLEEP     = 60      # Time between cycles (seconds)
