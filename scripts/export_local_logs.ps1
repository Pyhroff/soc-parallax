# Export YOUR machine's own logs as benign evaluation data (run in an elevated PowerShell).
#   powershell -ExecutionPolicy Bypass -File scripts\export_local_logs.ps1 -Out C:\logs\benign
# Then:  python scripts/metrics.py --benign-evtx C:\logs\benign --attack <EVTX-ATTACK-SAMPLES dir>
# Review the files before sharing them anywhere: they contain usernames, hostnames and command lines.
param([string]$Out = ".\benign_evtx", [int]$Days = 14)
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$ms = $Days * 24 * 3600 * 1000
$channels = @{
  "Microsoft-Windows-Sysmon/Operational"     = "sysmon.evtx"
  "Security"                                  = "security.evtx"
  "Microsoft-Windows-PowerShell/Operational"  = "powershell.evtx"
  "System"                                    = "system.evtx"
}
foreach ($c in $channels.Keys) {
  $dest = Join-Path $Out $channels[$c]
  if (Test-Path $dest) { Remove-Item $dest }
  wevtutil epl $c $dest /q:"*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]" 2>$null
  if ($LASTEXITCODE -eq 0) { Write-Host "exported $c" } else { Write-Host "skipped $c (not present or no access)" }
}
