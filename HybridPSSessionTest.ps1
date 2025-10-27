# HybridPSSessionTest.ps1
# Standalone test script for hybrid PowerShell remoting: Windows (WinRM) <-> macOS (SSH)
# Requires PowerShell 7+
# Requires -Version 7.0

#Requires -RunAsAdministrator  # Optional: For Windows TrustedHosts

CLS
$ScriptVer = '1.0-Test'
$LogDir = if ($IsWindows) { "C:\DesktopSupportTools\RemoteScriptExecutionLog" } else { "$env:HOME/DesktopSupportTools/RemoteScriptExecutionLog" }

# OS Detection
$IsWindows = $PSVersionTable.OS -like "*Windows*"
$IsMacOS = $PSVersionTable.OS -like "*Darwin*"
if (-not $IsWindows -and -not $IsMacOS) {
    Write-Error "Unsupported OS. Optimized for Windows/macOS."
    exit 1
}
Write-Host "Running on: $(if ($IsMacOS) { 'macOS (SSH Remoting)' } else { 'Windows (WinRM Remoting)' })" -ForegroundColor Green

# Create Log Dir
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
$LogFile = "$LogDir\HybridTest_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

Write-Log "Hybrid PSSession Test started (v$ScriptVer). PS Version: $($PSVersionTable.PSVersion)"

# Cross-platform Port Test
function Test-Port {
    param([string]$ComputerName, [int]$Port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.ReceiveTimeout = 5000
        $tcp.SendTimeout = 5000
        $tcp.Connect($ComputerName, $Port)
        $tcp.Close()
        return $true
    } catch {
        return $false
    }
}

# Main Test
$Target = Read-Host "Enter target Windows hostname/IP (e.g., PC123 or 10.32.240.84)"
if (-not $Target) { Write-Log "No target provided. Exiting."; exit 1 }

Write-Log "Testing connectivity to $Target..."

# Ping Test
if (-not (Test-Connection -ComputerName $Target -Count 2 -Quiet)) {
    Write-Error "Cannot ping $Target. Check network/VPN."
    exit 1
}
Write-Log "Ping OK."

# Port Test
$Port = if ($IsMacOS) { 22 } else { 5985 }
if (-not (Test-Port -ComputerName $Target -Port $Port)) {
    Write-Warning "Port $Port not open on $Target. Ensure WinRM/SSH enabled."
    $Continue = Read-Host "Continue anyway? (y/N)"
    if ($Continue -notlike "y*") { exit 1 }
}

# Get Credential (interactive, supports AAD username@tenant.com)
$Cred = Get-Credential -UserName "Enter username (local admin or AAD admin)" -Message "Enter password when prompted."

# Create Session
$SessionOption = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 60000
$MaxRetries = 3
$Session = $null

for ($i = 1; $i -le $MaxRetries; $i++) {
    try {
        if ($IsWindows) {
            # Windows client: WinRM
            Write-Log "Creating WinRM session to $Target..."
            $Session = New-PSSession -ComputerName $Target -Credential $Cred -SessionOption $SessionOption
        } else {
            # macOS client: SSH (prompts password interactively if needed)
            Write-Log "Creating SSH session to $Target (Username: $($Cred.UserName))..."
            $Session = New-PSSession -HostName $Target -UserName $Cred.UserName -SSHTransport -SessionOption $SessionOption
        }
        Write-Log "Session created successfully!"
        break
    } catch {
        Write-Log "Attempt $i failed: $($_.Exception.Message)"
        if ($i -eq $MaxRetries) { throw }
        Start-Sleep 5
    }
}

# Test Commands
try {
    # Basic info
    $Info = Invoke-Command -Session $Session -ScriptBlock { 
        [PSCustomObject]@{
            HostName = hostname
            User = whoami
            PSVersion = $PSVersionTable.PSVersion
            OS = (Get-CimInstance Win32_OperatingSystem).Caption
        }
    }
    Write-Log "Remote Info: $($Info | ConvertTo-Json)"

    # Create remote dir (matches original script)
    Invoke-Command -Session $Session -ScriptBlock { 
        New-Item -Path "C:\DesktopSupportTools" -ItemType Directory -Force | Out-Null 
    }

    # Copy test file
    $TestScript = @'
Write-Host "Test script executed remotely at $(Get-Date)" -ForegroundColor Green
Get-Process -Name pwsh | Select-Object Id, ProcessName, CPU
'@ | Out-File -FilePath "$env:TEMP\test.ps1" -Encoding UTF8
Copy-Item -Path "$env:TEMP\test.ps1" -Destination "C:\DesktopSupportTools\test.ps1" -ToSession $Session
Write-Log "Test file copied."

    # Run test file
    $RunResult = Invoke-Command -Session $Session -ScriptBlock { 
        & "C:\DesktopSupportTools\test.ps1"
    }
    Write-Log "Test script executed successfully."

    Write-Host "`n=== REMOTE TEST SUCCESS ===" -ForegroundColor Green
    $Info | Format-List
} catch {
    Write-Error "Test failed: $($_.Exception.Message)"
} finally {
    # Cleanup
    Invoke-Command -Session $Session -ScriptBlock { Remove-Item "C:\DesktopSupportTools\test.ps1" -Force -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue
    Remove-PSSession $Session
    Remove-Item "$env:TEMP\test.ps1" -Force -ErrorAction SilentlyContinue
}

Write-Host "`nLog: $LogFile" -ForegroundColor Yellow
Read-Host "Press Enter to exit"