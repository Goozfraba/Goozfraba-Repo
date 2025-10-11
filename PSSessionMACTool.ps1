# Powershell Remote Session Tool for macOS (Console-Based) - Framework by Nic Fuentes, Ported for Cross-Platform
CLS
# Function to write to log file (defined first to avoid scoping issues)
function Write-Log {
    param (
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$Timestamp - $Message"
    Write-Host $LogMessage
    $LogDir = Join-Path $env:HOME "DesktopSupportTools/RemoteScriptExecutionLog"
    if (-not (Test-Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }
    $LogFile = Join-Path $LogDir "RemoteScriptExecution_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    Add-Content -Path $LogFile -Value $LogMessage -ErrorAction SilentlyContinue
}

try {
    Write-Host "Script starting at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Log "Initializing script execution."
    $LogDir = Join-Path $env:HOME "DesktopSupportTools"
    if (-not (Test-Path $LogDir)) {
        Write-Host "Creating directory $LogDir"
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        Write-Log "Directory $LogDir created."
    } else {
        Write-Log "Directory $LogDir already exists."
    }
    $LogSubDir = Join-Path $LogDir "RemoteScriptExecutionLog"
    if (-not (Test-Path $LogSubDir)) {
        Write-Host "Creating directory $LogSubDir"
        New-Item -Path $LogSubDir -ItemType Directory -Force | Out-Null
        Write-Log "Directory $LogSubDir created."
    } else {
        Write-Log "Directory $LogSubDir already exists."
    }
    $LogFile = Join-Path $LogSubDir "RemoteScriptExecution_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    Write-Host "Log file will be created at: $LogFile"
    Write-Log "Log file path set to: $LogFile"
} catch {
    Write-Log "ERROR: Failed to create or access log directory. Error: $($_.Exception.Message)"
    throw
}

# No .NET assemblies for Forms on macOS, so skipped

# Function to check and set execution policy
function Set-ExecutionPolicyIfNeeded {
    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction Stop
    Write-Log "Current execution policy: $currentPolicy"
    if ($currentPolicy -ne "Unrestricted" -and $currentPolicy -ne "Bypass") {
        Write-Host "The current execution policy ($currentPolicy) restricts script execution. Do you want to set it to 'Unrestricted'? (Y/N)"
        $result = Read-Host
        if ($result -eq "Y") {
            try {
                Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force -ErrorAction Stop
                Write-Log "Execution policy set to Unrestricted successfully."
                Write-Host "Execution policy set to Unrestricted. Please restart the script."
                exit 0
            } catch {
                Write-Log "ERROR: Failed to set execution policy. Error: $($_.Exception.Message)"
                Write-Host "Failed to set execution policy. Please run 'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force' as Administrator."
                exit 1
            }
        } else {
            Write-Log "User declined to change execution policy. Exiting."
            Write-Host "Please run 'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force' to proceed."
            exit 1
        }
    } else {
        Write-Log "Execution policy is acceptable: $currentPolicy"
    }
}

# Function to validate IP address or computer name (unchanged)
function Test-ValidIPAddress {
    param (
        [string]$IPAddress
    )
    try {
        $ip = [System.Net.IPAddress]::Parse($IPAddress)
        return $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
    } catch {
        return $true
    }
}

# Function to test VPN or domain connection status (adapted for macOS)
function Test-ConnectionStatus {
    if ($PSVersionTable.OS -like "*darwin*") {
        # macOS-specific VPN check (assuming Palo Alto GlobalProtect)
        $vpnStatus = & scutil --nc list | Select-String "Connected" | Select-String "PANGP" # Adjust for your VPN name
        if ($vpnStatus) {
            Write-Log "VPN connected on macOS."
            return $true
        }
        # Fallback domain check
        if (Test-Connection -ComputerName $DC -Count 1 -Quiet) {
            Write-Log "Domain connected on macOS."
            return $true
        }
        return $false
    } else {
        # Original Windows logic
        $vpnAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq $MIGVPNAdapter -and $_.Status -eq 'Up' }
        if ($vpnAdapter) {
            $ipv4Address = (Get-NetIPAddress -InterfaceIndex $vpnAdapter.InterfaceIndex -AddressFamily IPv4).IPAddress
            if ($ipv4Address -like $VPNIPR) {
                return $true
            }
        }
        $domainAdapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        if ($domainAdapter) {
            $ipv4Address = (Get-NetIPAddress -InterfaceIndex $domainAdapter.InterfaceIndex -AddressFamily IPv4).IPAddress
            if ($ipv4Address -like $DOMAINIPR) {
                if (Test-Connection -ComputerName $DC -Count 1 -Quiet) {
                    return $true
                }
            }
        }
        return $false
    }
}

# Function to check computer name to IP address (unchanged)
function Test-MIGConnection {
    param (
        [string]$MachineList,
        [string]$DomainSuffix
    )
    Remove-Variable -Name FinalArray, BadArray -Force -ErrorAction SilentlyContinue
    $Global:FinalArray = @()
    $Global:BadArray = @()
    $Machines = $MachineList -split ","
    $AzureADMachines = @()
    foreach ($Machine in $Machines) {
        $FQDN = "$Machine.$DomainSuffix"
        $DomainJoined = Test-Connection -ComputerName $FQDN -Count 1 -ErrorAction SilentlyContinue
        if ($DomainJoined) {
            $Global:FinalArray += $FQDN
            Write-Log -Message "$FQDN is routable (Domain Joined)"
        } else {
            $AzureADMachines += $Machine
        }
    }
    Write-Log -Message "AD Machines: $Global:FinalArray"
    if ($AzureADMachines.Count -gt 0) {
        $AzureADMachinesString = $AzureADMachines -join "|"
        Write-Log -Message "AzureAD Machines to process: $AzureADMachinesString"
        Start-Sleep -Seconds $Seconds
        foreach ($Machine in $AzureADMachines) {
            Write-Log -Message "Processing AzureAD Machine: $Machine (skipping IP resolution)"
            $Global:BadArray += $Machine
        }
        Write-Log -Message "Azure Machines Good: $Global:FinalArray"
        Write-Log -Message "Azure Machines Bad: $Global:BadArray"
    }
}

# Function to get IP address from console (replaced GUI)
function Get-IPAddressFromDialog {
    Write-Host "Enter the target computer name or IP address (e.g., PC-PC12345L or 10.32.240.84):"
    $IPAddress = Read-Host
    if ($IPAddress -eq "") {
        return $null
    }
    return $IPAddress
}

# Function to select a local file via console (replaced GUI)
function Get-FilePath {
    Write-Host "Enter the full path to the file to copy (script or executable):"
    $FilePath = Read-Host
    if (Test-Path $FilePath) {
        return $FilePath
    }
    Write-Host "File not found."
    return $null
}

# Function to select a file to run from the remote machine via console (replaced GUI)
function Select-FileToRun {
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    $Files = Invoke-Command -Session $Session -ScriptBlock {
        Get-ChildItem -Path "C:\DesktopSupportTools" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    }
    if (-not $Files) {
        Write-Log -Message "ERROR: No files found in C:\DesktopSupportTools on $TargetIP."
        Write-Host "No files found in C:\DesktopSupportTools on $TargetIP."
        return $null
    }
    Write-Host "Available files on remote machine:"
    for ($i = 0; $i -lt $Files.Count; $i++) {
        if ($Files[$i] -match "\.exe$|\.ps1$") {
            Write-Host "$($i+1): $($Files[$i])"
        }
    }
    Write-Host "Enter the number of the file to run (or 0 to cancel):"
    $choice = Read-Host
    if ($choice -eq 0 -or $choice -gt $Files.Count) {
        return $null
    }
    $SelectedFile = $Files[$choice - 1]
    # Check for .exe and user session (unchanged)
    if ($SelectedFile -like "*.exe") {
        $UserSession = Invoke-Command -Session $Session -ScriptBlock {
            quser 2>&1
        } -ErrorAction SilentlyContinue
        if ($UserSession -match "No User exists" -or -not $UserSession) {
            Write-Log -Message "WARNING: No interactive user session on $TargetIP. GUI-based EXE may not display."
            Write-Host "WARNING: No interactive user session on $TargetIP. Proceeding anyway."
        }
    }
    return $SelectedFile
}

# Function to input and run PowerShell commands via console (replaced GUI)
function Run-PowerShellCommand {
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    Write-Host "Enter PowerShell command to run on the remote machine:"
    $Command = Read-Host
    if ($Command) {
        try {
            Write-Log -Message "Running PowerShell command on remote machine: $Command"
            $CommandResult = Invoke-Command -Session $Session -ScriptBlock {
                param($Cmd)
                Invoke-Expression $Cmd 2>&1
            } -ArgumentList $Command -ErrorAction Stop
            Write-Log -Message "Command executed successfully. Output: $CommandResult"
            Write-Host "Command executed successfully. Output: $CommandResult"
        } catch {
            Write-Log -Message "ERROR: Failed to run PowerShell command. Error: $($_.Exception.Message)"
            Write-Host "Failed to run command. Error: $($_.Exception.Message)"
        }
    } else {
        Write-Log -Message "No command entered."
    }
}

# Function to delete a file from the remote machine via console (replaced GUI)
function Delete-File {
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    $Files = Invoke-Command -Session $Session -ScriptBlock {
        Get-ChildItem -Path "C:\DesktopSupportTools" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    }
    if (-not $Files) {
        Write-Log -Message "ERROR: No files found in C:\DesktopSupportTools on $TargetIP."
        Write-Host "No files found in C:\DesktopSupportTools on $TargetIP."
        return
    }
    Write-Host "Available files on remote machine:"
    for ($i = 0; $i -lt $Files.Count; $i++) {
        Write-Host "$($i+1): $($Files[$i])"
    }
    Write-Host "Enter the number of the file to delete (or 0 to cancel):"
    $choice = Read-Host
    if ($choice -eq 0 -or $choice -gt $Files.Count) {
        return
    }
    $SelectedFile = $Files[$choice - 1]
    try {
        Invoke-Command -Session $Session -ScriptBlock {
            param($Path)
            Remove-Item -Path "C:\DesktopSupportTools\$Path" -Force -ErrorAction Stop
        } -ArgumentList $SelectedFile -ErrorAction Stop
        Write-Log -Message "Deleted file '$SelectedFile' successfully from $TargetIP."
        Write-Host "Deleted $SelectedFile successfully."
    } catch {
        Write-Log -Message "ERROR: Failed to delete file '$SelectedFile' on $TargetIP. Error: $($_.Exception.Message)"
        Write-Host "Failed to delete file. Error: $($_.Exception.Message)"
    }
}

# Function to check logged-in users (unchanged, output to console)
function Check-LoggedInUser {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetIP,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    try {
        $Result = Invoke-Command -Session $Session -ScriptBlock {
            quser 2>&1
        }
        $Output = $Result | Out-String
        if ($Output -match "No User exists" -or -not $Result) {
            Write-Log -Message "No logged-in users on $TargetIP."
            Write-Host "No user is currently logged in on $TargetIP."
        } else {
            $Users = $Output -split "`n" | Where-Object { $_ -match "^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$" } | ForEach-Object {
                $Matches[1] + " (Session: " + $Matches[2] + ", ID: " + $Matches[3] + ", State: " + $Matches[4] + ", Idle: " + $Matches[5] + ", Logon: " + $Matches[6] + ")"
            }
            $Message = "Currently logged-in users on ${TargetIP}:`n`n" + ($Users -join "`n")
            Write-Log -Message "Logged-in users found on $TargetIP."
            Write-Host $Message
        }
    } catch {
        Write-Log -Message "ERROR: Failed to check logged-in users on $TargetIP. Error: $($_.Exception.Message)"
        Write-Host "Failed to check logged-in users. Error: $($_.Exception.Message)"
    }
}

# Function to prompt initial action via console (replaced GUI)
function Prompt-InitialAction {
    Write-Host "Select an action:"
    Write-Host "1: Start Session"
    Write-Host "2: Exit"
    $choice = Read-Host "Enter choice (1 or 2)"
    if ($choice -eq 1) {
        return [System.Windows.Forms.DialogResult]::Yes  # Simulate
    } else {
        return [System.Windows.Forms.DialogResult]::No
    }
}

# Function to prompt for another session via console (replaced GUI)
function Prompt-ForAnotherSession {
    Write-Host "Start a session or action on another computer? (Y/N)"
    $result = Read-Host
    if ($result -eq "Y") {
        return [System.Windows.Forms.DialogResult]::Yes
    } else {
        return [System.Windows.Forms.DialogResult]::No
    }
}

# Function to prompt session action via console (replaced GUI)
function Prompt-SessionAction {
    Write-Host "Select an action for the current session:"
    Write-Host "1: Copy File"
    Write-Host "2: Run File"
    Write-Host "3: Run PS Command"
    Write-Host "4: Delete File"
    Write-Host "5: Logged In User"
    Write-Host "6: Exit Session"
    $choice = Read-Host "Enter choice (1-6)"
    switch ($choice) {
        1 { return [System.Windows.Forms.DialogResult]::Yes }
        2 { return [System.Windows.Forms.DialogResult]::OK }
        3 { return [System.Windows.Forms.DialogResult]::Ignore }
        4 { return [System.Windows.Forms.DialogResult]::Retry }
        5 { return [System.Windows.Forms.DialogResult]::No }
        6 { return [System.Windows.Forms.DialogResult]::Cancel }
        default { return [System.Windows.Forms.DialogResult]::Cancel }
    }
}

# Define environment variables (unchanged)
$ScriptVer = '3.0'
$ScriptEnv = "Powershell Remote Session Tool using Framework by Nic Fuentes"
$MIGVPNAdapter = 'PANGP Virtual Ethernet Adapter Secure'
$VPNIPR = '10.*'
$DOMAINIPR = '10.32.*'
$DC = 'brprdc01.int.mgc.com'
$MIGDomain = "int.mgc.com"
$Seconds = '10'

# Main script (unchanged logic, but with console)
try {
    Set-ExecutionPolicyIfNeeded
    Write-Log -Message "Script started. Log file: $LogFile"
    Write-Log -Message "Checking for MIG or VPN connection..."
    if (-not (Test-ConnectionStatus)) {
        Write-Log -Message "ERROR: MIG or VPN connection is not active."
        Write-Host "MIG or VPN connection is not active. Please connect and try again."
        exit 1
    }
    Write-Log -Message "Connection is active."
    do {
        $InitialAction = Prompt-InitialAction
        Write-Log "Initial action result: $InitialAction"
        switch ($InitialAction) {
            ([System.Windows.Forms.DialogResult]::Yes) {
                Write-Log -Message "User chose to start a new session."
                $TargetIP = Get-IPAddressFromDialog
                if (-not $TargetIP) {
                    Write-Log -Message "No computer name or IP provided. Returning to main menu."
                    continue
                }
                if (-not (Test-ValidIPAddress -IPAddress $TargetIP)) {
                    Write-Log -Message "Input '$TargetIP' is not an IP address. Attempting to resolve..."
                    Test-MIGConnection -MachineList $TargetIP -DomainSuffix $MIGDomain
                    if ($Global:FinalArray -and $Global:FinalArray.Count -gt 0) {
                        $TargetIP = $Global:FinalArray[0]
                        Write-Log -Message "Resolved '$TargetIP' to $TargetIP."
                    } else {
                        Write-Log -Message "ERROR: Could not resolve '$TargetIP' to an IP address."
                        Write-Host "Could not resolve '$TargetIP' to an IP address."
                        continue
                    }
                }
                Write-Log -Message "Target computer name/IP: $TargetIP"
                $MaxPingRetries = 3
                $PingRetryCount = 0
                $PingSuccess = $false
                while (-not $PingSuccess -and $PingRetryCount -lt $MaxPingRetries) {
                    Write-Log -Message "Testing connectivity to $TargetIP (Attempt $($PingRetryCount + 1)/$MaxPingRetries)..."
                    if (Test-Connection -ComputerName $TargetIP -Count 1 -Quiet) {
                        Write-Log -Message "Successfully pinged $TargetIP."
                        $PingSuccess = $true
                    } else {
                        $PingRetryCount++
                        Write-Log -Message "ERROR: Failed to reach $TargetIP (Attempt $PingRetryCount/$MaxPingRetries)."
                        if ($PingRetryCount -lt $MaxPingRetries) {
                            Write-Log -Message "Retrying in 5 seconds..."
                            Start-Sleep -Seconds 5
                        }
                    }
                }
                if (-not $PingSuccess) {
                    Write-Log -Message "ERROR: Cannot reach $TargetIP after $MaxPingRetries attempts."
                    Write-Host "Cannot reach $TargetIP after $MaxPingRetries attempts."
                    continue
                }
                Write-Log -Message "Checking TrustedHosts configuration..."
                $TrustedHosts = (Get-Item -Path WSMan:\localhost\Client\TrustedHosts).Value
                Write-Log -Message "Current TrustedHosts: $TrustedHosts"
                if ($TrustedHosts -notlike "*$TargetIP*") {
                    try {
                        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "" -Force -ErrorAction Stop
                        Write-Log -Message "Cleared existing TrustedHosts."
                        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $TargetIP -Force -ErrorAction Stop
                        Write-Log -Message "Added $TargetIP to TrustedHosts."
                    } catch {
                        Write-Log -Message "ERROR: Failed to update TrustedHosts. Error: $($_.Exception.Message)"
                        continue
                    }
                }
                Write-Log -Message "Testing WinRM connectivity to $TargetIP on port 5985..."
                $NetTest = Test-NetConnection -ComputerName $TargetIP -Port 5985 -ErrorAction Stop
                Write-Log -Message "Network Test: TcpTestSucceeded = $($NetTest.TcpTestSucceeded)"
                if (-not $NetTest.TcpTestSucceeded) {
                    Write-Log -Message "ERROR: Port 5985 is not accessible on $TargetIP. Check firewall or VPN settings."
                    Write-Host "Port 5985 is not accessible on $TargetIP. Check firewall or VPN settings."
                    continue
                }
                Write-Log -Message "Establishing PowerShell session to $TargetIP..."
                $MaxRetries = 5
                $RetryCount = 0
                $Session = $null
                $SessionOption = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000
                while (-not $Session -and $RetryCount -lt $MaxRetries) {
                    try {
                        $Session = New-PSSession -ComputerName $TargetIP -SessionOption $SessionOption -ErrorAction Stop
                        Write-Log -Message "PowerShell session established successfully."
                        $Status = Invoke-Command -Session $Session -ScriptBlock {
                            $WinRM = Get-Service -Name WinRM | Select-Object -Property Status
                            $UAC = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -ErrorAction SilentlyContinue
                            $UACStatus = if ($UAC -and $UAC.LocalAccountTokenFilterPolicy -eq 1) { "UAC allows remote admin access" } else { "UAC may block remote admin access" }
                            return @{ WinRMStatus = $WinRM.Status; UACStatus = $UACStatus }
                        }
                        Write-Log -Message "WinRM Status: $($Status.WinRMStatus)"
                        Write-Log -Message "UAC Status: $($Status.UACStatus)"
                        break
                    } catch {
                        $RetryCount++
                        Write-Log -Message "ERROR: Failed to establish session to $TargetIP (Attempt $RetryCount/$MaxRetries). Error: $($_.Exception.Message)"
                        if ($RetryCount -lt $MaxRetries) {
                            Write-Log -Message "Retrying in 10 seconds..."
                            Start-Sleep -Seconds 10
                        }
                    }
                }
                if (-not $Session) {
                    Write-Log -Message "ERROR: Failed to establish session after $MaxRetries attempts."
                    Write-Host "Failed to establish session after $MaxRetries attempts."
                    continue
                }
                do {
                    if (-not $Session -or $Session.State -ne 'Opened') {
                        Write-Log -Message "ERROR: Session is null or not open. Attempting to reconnect to $TargetIP..."
                        try {
                            Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
                            $Session = New-PSSession -ComputerName $TargetIP -SessionOption $SessionOption -ErrorAction Stop
                            Write-Log -Message "Reconnected session successfully."
                        } catch {
                            Write-Log -Message "ERROR: Failed to reconnect session to $TargetIP. Error: $($_.Exception.Message)"
                            break
                        }
                    }
                    $SessionAction = Prompt-SessionAction
                    Write-Log "Session action result: $SessionAction"
                    switch ($SessionAction) {
                        ([System.Windows.Forms.DialogResult]::Yes) {
                            Write-Log -Message "User chose to copy a file."
                            $FilePath = Get-FilePath
                            if ($FilePath) {
                                try {
                                    Copy-Item -Path $FilePath -Destination "C:\DesktopSupportTools\" -ToSession $Session -ErrorAction Stop
                                    Write-Log -Message "Successfully copied file '$($FilePath.Split([System.IO.Path]::DirectorySeparatorChar)[-1])' to C:\DesktopSupportTools on $TargetIP."
                                    Write-Host "Successfully copied '$($FilePath.Split([System.IO.Path]::DirectorySeparatorChar)[-1])' to C:\DesktopSupportTools."
                                } catch {
                                    Write-Log -Message "ERROR: Failed to copy file to $TargetIP. Error: $($_.Exception.Message)"
                                    Write-Host "Failed to copy file. Error: $($_.Exception.Message)"
                                }
                            } else {
                                Write-Log -Message "No file selected for copying."
                            }
                        }
                        ([System.Windows.Forms.DialogResult]::OK) {
                            Write-Log -Message "User chose to run a file."
                            $SelectedFile = Select-FileToRun -Session $Session
                            if ($SelectedFile) {
                                try {
                                    $FilePath = "C:\DesktopSupportTools\$SelectedFile"
                                    Write-Log -Message "Running file '$SelectedFile' on $TargetIP..."
                                    $Result = Invoke-Command -Session $Session -ScriptBlock {
                                        param($Path)
                                        try {
                                            New-Item -Path "C:\DesktopSupportTools" -ItemType Directory -Force -ErrorAction SilentlyContinue
                                            if ($Path -like "*.ps1") {
                                                $Output = & $Path 2>&1
                                                $ExitCode = $LASTEXITCODE
                                            } else {
                                                $Process = Start-Process -FilePath $Path -NoNewWindow -PassThru -Wait -RedirectStandardOutput "C:\DesktopSupportTools\exe_output.txt" -RedirectStandardError "C:\DesktopSupportTools\exe_error.txt" -Verb RunAs -ErrorAction Stop
                                                $Output = Get-Content "C:\DesktopSupportTools\exe_output.txt" -Raw -ErrorAction SilentlyContinue
                                                $ErrorOutput = Get-Content "C:\DesktopSupportTools\exe_error.txt" -Raw -ErrorAction SilentlyContinue
                                                $ExitCode = $Process.ExitCode
                                                return @{ Success = ($ExitCode -eq 0); Output = ($Output, $ErrorOutput | Out-String); ExitCode = $ExitCode; ProcessId = $Process.Id }
                                            }
                                            return @{ Success = ($ExitCode -eq 0); Output = $Output; ExitCode = $ExitCode }
                                        } catch {
                                            return @{ Success = $false; Output = "Exception: $($_.Exception.Message)"; ExitCode = -1 }
                                        }
                                    } -ArgumentList $FilePath -ErrorAction Stop
                                    if ($Result.Success) {
                                        Write-Log -Message "File '$SelectedFile' executed successfully on $TargetIP. PID: $($Result.ProcessId). Output: $($Result.Output)"
                                        Write-Host "File '$SelectedFile' executed successfully. PID: $($Result.ProcessId). Output: $($Result.Output)"
                                    } else {
                                        Write-Log -Message "ERROR: File '$SelectedFile' failed with exit code $($Result.ExitCode). Output: $($Result.Output)"
                                        Write-Host "File '$SelectedFile' failed with exit code $($Result.ExitCode). Output: $($Result.Output)"
                                    }
                                } catch {
                                    Write-Log -Message "ERROR: Failed to run file '$SelectedFile' on $TargetIP. Error: $($_.Exception.Message)"
                                    Write-Host "Failed to run file. Error: $($_.Exception.Message)"
                                }
                            } else {
                                Write-Log -Message "No file selected or interactive session required but not present."
                            }
                        }
                        ([System.Windows.Forms.DialogResult]::Ignore) {
                            Write-Log -Message "User chose to run a PowerShell command."
                            Run-PowerShellCommand -Session $Session
                        }
                        ([System.Windows.Forms.DialogResult]::Retry) {
                            Write-Log -Message "User chose to delete a file."
                            Delete-File -Session $Session
                        }
                        ([System.Windows.Forms.DialogResult]::No) {
                            Write-Log -Message "User chose to check logged-in users."
                            Check-LoggedInUser -TargetIP $TargetIP -Session $Session
                        }
                        ([System.Windows.Forms.DialogResult]::Cancel) {
                            Write-Log -Message "User chose to exit the session."
                            break
                        }
                        default {
                            Write-Log "WARNING: Invalid choice, defaulting to exit."
                            break
                        }
                    }
                } while ($SessionAction -ne [System.Windows.Forms.DialogResult]::Cancel)
                Write-Log -Message "Closing session to $TargetIP..."
                try {
                    Remove-PSSession -Session $Session -ErrorAction Stop
                    Write-Log -Message "Session closed successfully."
                } catch {
                    Write-Log -Message "ERROR: Failed to close session. Error: $($_.Exception.Message)"
                }
                $Session = $null
            }
            ([System.Windows.Forms.DialogResult]::No) {
                Write-Log -Message "User chose to exit. Terminating script."
                exit 0
            }
            default {
                Write-Log "WARNING: Invalid initial action, defaulting to exit."
                exit 0
            }
        }
        Write-Log -Message "Prompting user to start another action or session..."
        $Continue = Prompt-ForAnotherSession
        Write-Log "Continue result: $Continue"
    } while ($Continue -eq [System.Windows.Forms.DialogResult]::Yes)
    Write-Log -Message "Script execution completed."
} catch {
    Write-Log -Message "Critical error in main: $($_.Exception.Message)"
    Write-Host "Critical error: $($_.Exception.Message)"
    exit 1
}