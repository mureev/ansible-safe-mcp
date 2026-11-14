# ansible-safe-mcp guard for Windows (Windows PowerShell 5.1). Lives in C:\ProgramData\asm-guard (SYSTEM and
# administrators only). Commit-confirmed: snapshot what a change will touch, register a one-time scheduled task (as
# SYSTEM, StartWhenAvailable, so a reboot or sleep inside the window still runs it) that restores the snapshot unless
# the change is confirmed in time.
#   -Action arm -Id ID -Seconds N -PathsB64 <base64 of a JSON list: registry keys (HKLM:\...) and files or folders>
#   -Action confirm [-Id ID]      keep the change: remove the task, drop the snapshot
#   -Action revert [-Why WHY]     restore now (the task runs: -Action revert -Why timeout)
#   -Action status
# Output: key=value lines.
param(
  [string]$Action = 'status',
  [string]$Id = '',
  [int]$Seconds = 0,
  [string]$PathsB64 = '',
  [string]$Why = 'manual'
)
$ErrorActionPreference = 'Stop'
$D = Join-Path $env:ProgramData 'asm-guard'
$Snap = Join-Path $D 'snap'
$Armed = Join-Path $D 'armed'
$Reverting = Join-Path $D 'reverting'
$TaskPath = '\ansible-safe\'
$TaskName = 'asm-guard-revert'

function Stamp { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Note([string]$t) { Set-Content -LiteralPath (Join-Path $D 'last') -Value $t -Encoding UTF8 }
function Log([string]$t) { Add-Content -LiteralPath (Join-Path $D 'guard.log') -Value ((Stamp) + ' ' + $t) -Encoding UTF8 }
function Last { $f = Join-Path $D 'last'; if (Test-Path -LiteralPath $f) { 'last=' + (Get-Content -LiteralPath $f -Raw).Trim() } }
function RegPath([string]$p) { ($p -replace '^(HKLM|HKCU|HKCR|HKU|HKCC):', '$1').TrimEnd('\') }
function IsReg([string]$p) { $p -match '^(HKLM|HKCU|HKCR|HKU|HKCC):?\\' }
function Unregister { Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue }

switch ($Action) {
  'arm' {
    if ((Test-Path -LiteralPath $Armed) -or (Test-Path -LiteralPath $Reverting)) {
      'error=another change is armed here; confirm or revert it first'; exit 3
    }
    if ($Id -notmatch '^[A-Za-z0-9_.-]{1,64}$') { 'error=bad id'; exit 2 }
    if ($Seconds -lt 5 -or $Seconds -gt 86400) { 'error=seconds must be 5..86400'; exit 2 }
    $paths = @()
    if ($PathsB64) { $paths = @([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PathsB64)) | ConvertFrom-Json) }
    if (Test-Path -LiteralPath $Snap) { Remove-Item -LiteralPath $Snap -Recurse -Force }
    New-Item -ItemType Directory -Force $Snap | Out-Null
    $manifest = @()
    $i = 0
    foreach ($p in $paths) {
      $i++
      if (IsReg $p) {
        $rp = RegPath $p
        $file = Join-Path $Snap ('reg' + $i + '.reg')
        & reg.exe query $rp *> $null
        if ($LASTEXITCODE -eq 0) {
          & reg.exe export $rp $file /y *> $null
          if ($LASTEXITCODE -ne 0) { Remove-Item -LiteralPath $Snap -Recurse -Force; "error=could not export $rp"; exit 4 }
          $manifest += New-Object PSObject -Property @{ type = 'reg'; path = $rp; file = $file; present = $true }
        } else {
          $manifest += New-Object PSObject -Property @{ type = 'reg'; path = $rp; file = ''; present = $false }
        }
      } else {
        $full = [IO.Path]::GetFullPath($p)
        if ($full -match '^[A-Za-z]:\\?$' -or $full.StartsWith($D, [StringComparison]::OrdinalIgnoreCase)) {
          Remove-Item -LiteralPath $Snap -Recurse -Force; "error=refusing to snapshot $full"; exit 2
        }
        if (Test-Path -LiteralPath $full) {
          $dst = Join-Path $Snap ('file' + $i)
          Copy-Item -LiteralPath $full -Destination $dst -Recurse -Force
          $manifest += New-Object PSObject -Property @{ type = 'file'; path = $full; file = $dst; present = $true }
        } else {
          $manifest += New-Object PSObject -Property @{ type = 'file'; path = $full; file = ''; present = $false }
        }
      }
    }
    ConvertTo-Json -InputObject @($manifest) -Depth 4 | Set-Content -LiteralPath (Join-Path $Snap 'manifest.json') -Encoding UTF8
    $deadline = (Get-Date).AddSeconds($Seconds)
    Set-Content -LiteralPath $Armed -Value ($Id + ' ' + $deadline.ToUniversalTime().ToString('o')) -Encoding UTF8
    $ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $act = New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $D 'guard.ps1') + '" -Action revert -Why timeout')
    $trig = New-ScheduledTaskTrigger -Once -At $deadline
    $set = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    $who = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    try {
      Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Action $act -Trigger $trig -Settings $set -Principal $who -Force | Out-Null
    } catch {
      Remove-Item -LiteralPath $Armed -Force; Remove-Item -LiteralPath $Snap -Recurse -Force
      'error=could not register the revert task: ' + $_.Exception.Message; exit 5
    }
    if (-not (Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue)) {
      Remove-Item -LiteralPath $Armed -Force; Remove-Item -LiteralPath $Snap -Recurse -Force
      'error=the revert task is not there after registering it'; exit 5
    }
    Log "armed $Id for ${Seconds}s"
    'state=armed'; "id=$Id"; 'deadline_iso=' + $deadline.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); 'backend=scheduled-task'
  }
  'confirm' {
    if (-not (Test-Path -LiteralPath $Armed)) {
      if (Test-Path -LiteralPath $Reverting) { 'error=too late: the host is reverting this change'; exit 5 }
      'state=idle'; Last; exit 0
    }
    $cur = ((Get-Content -LiteralPath $Armed -Raw).Trim() -split ' ')[0]
    if ($Id -and $Id -ne $cur) { "error=the armed change is $cur, not $Id"; exit 3 }
    Unregister
    Remove-Item -LiteralPath $Armed -Force
    if (Test-Path -LiteralPath $Snap) { Remove-Item -LiteralPath $Snap -Recurse -Force }
    Log "confirmed $cur"; Note ("confirmed " + (Stamp) + " $cur ")
    'state=confirmed'; "id=$cur"; Last
  }
  'revert' {
    if (-not (Test-Path -LiteralPath $Armed)) { 'state=idle'; Last; exit 0 }
    try { Rename-Item -LiteralPath $Armed -NewName 'reverting' } catch { 'state=idle'; Last; exit 0 }
    $cur = ((Get-Content -LiteralPath $Reverting -Raw).Trim() -split ' ')[0]
    $fail = @()
    $manifest = @(Get-Content -LiteralPath (Join-Path $Snap 'manifest.json') -Raw | ConvertFrom-Json)
    foreach ($e in $manifest) {
      try {
        if ($e.type -eq 'reg') {
          & reg.exe query $e.path *> $null
          if ($LASTEXITCODE -eq 0) { & reg.exe delete $e.path /f *> $null }
          if ($e.present) { & reg.exe import $e.file *> $null; if ($LASTEXITCODE -ne 0) { $fail += $e.path } }
        } else {
          if (Test-Path -LiteralPath $e.path) { Remove-Item -LiteralPath $e.path -Recurse -Force }
          if ($e.present) { Copy-Item -LiteralPath $e.file -Destination $e.path -Recurse -Force }
        }
      } catch { $fail += ($e.path + ': ' + $_.Exception.Message) }
    }
    if ($Why -ne 'timeout') { Unregister }
    if ($fail.Count) {
      Log "revert of $cur ($Why) had errors: $($fail -join '; ')"
      Note ("revert-failed " + (Stamp) + " $cur ($Why): snapshot kept in $Snap ")
      'state=revert-failed'; "id=$cur"; Last; exit 7
    }
    Remove-Item -LiteralPath $Reverting -Force
    Remove-Item -LiteralPath $Snap -Recurse -Force
    Log "reverted $cur ($Why)"; Note ("reverted " + (Stamp) + " $cur ($Why) ")
    'state=reverted'; "id=$cur"; Last
  }
  default {
    if (Test-Path -LiteralPath $Armed) {
      $a = (Get-Content -LiteralPath $Armed -Raw).Trim() -split ' '
      'state=armed'; 'id=' + $a[0]; 'deadline_iso=' + ([datetime]::Parse($a[1]).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
      $t = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
      'timer_alive=' + $(if ($t) { 'yes' } else { 'no' })
    } elseif (Test-Path -LiteralPath $Reverting) { 'state=reverting' } else { 'state=idle' }
    Last
  }
}
