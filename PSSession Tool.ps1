# Powershell Remote Session Tool using Framework by Nic Fuentes
CLS
# Function to write to log file (defined first to avoid scoping issues)
function Write-Log {
    param (
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$Timestamp - $Message"
    Write-Host $LogMessage
    $LogFile = "C:\DesktopSupportTools\RemoteScriptExecutionLog\RemoteScriptExecution_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    if (-not (Test-Path $LogFile)) {
        # Silently handle inaccessible log file without warning
        return
    }
    Add-Content -Path $LogFile -Value $LogMessage -ErrorAction SilentlyContinue
}

try {
    Write-Host "Script starting at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') on 10:20 PM PDT, Thursday, September 25, 2025"
    Write-Log "Initializing script execution."
    # Define log file path
    $LogFile = "C:\DesktopSupportTools\RemoteScriptExecutionLog\RemoteScriptExecution_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    try {
        if (-not (Test-Path "C:\DesktopSupportTools")) {
            Write-Host "Creating directory C:\DesktopSupportTools"
            New-Item -Path "C:\DesktopSupportTools" -ItemType Directory -Force | Out-Null
            Write-Log "Directory C:\DesktopSupportTools created."
        } else {
            Write-Log "Directory C:\DesktopSupportTools already exists."
        }
        if (-not (Test-Path "C:\DesktopSupportTools\RemoteScriptExecutionLog")) {
            Write-Host "Creating directory C:\DesktopSupportTools\RemoteScriptExecutionLog"
            New-Item -Path "C:\DesktopSupportTools\RemoteScriptExecutionLog" -ItemType Directory -Force | Out-Null
            Write-Log "Directory C:\DesktopSupportTools\RemoteScriptExecutionLog created."
        } else {
            Write-Log "Directory C:\DesktopSupportTools\RemoteScriptExecutionLog already exists."
        }
        Write-Host "Log file will be created at: $LogFile"
        Write-Log "Log file path set to: $LogFile"
    } catch {
        Write-Log "ERROR: Failed to create or access C:\DesktopSupportTools\RemoteScriptExecutionLog. Error: ${_.Exception.Message}"
        throw
    }
} catch {
    Write-Error "Failed to initialize script: ${_.Exception.Message}"
    [System.Windows.Forms.MessageBox]::Show("Failed to initialize script. Error: ${_.Exception.Message} Please ensure admin rights and try again.", "Initialization Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}

# Load required .NET assemblies with error handling
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    Write-Log "Successfully loaded System.Windows.Forms and System.Drawing assemblies."
} catch {
    Write-Log "ERROR: Failed to load required .NET assemblies. Error: ${_.Exception.Message}"
    [System.Windows.Forms.MessageBox]::Show("Failed to load required .NET assemblies. Please ensure PowerShell environment supports GUI. Error: ${_.Exception.Message}", "Assembly Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}

# Function to check and set execution policy
function Set-ExecutionPolicyIfNeeded {
    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction Stop
    Write-Log "Current execution policy: $currentPolicy"
    if ($currentPolicy -ne "Unrestricted" -and $currentPolicy -ne "Bypass") {
        $result = [System.Windows.Forms.MessageBox]::Show(
            "The current execution policy ($currentPolicy) restricts script execution. Do you want to set it to 'Unrestricted' automatically? (Requires admin privileges)",
            "Execution Policy Check",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            try {
                if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                    Write-Log "ERROR: Must run as Administrator to set execution policy."
                    [System.Windows.Forms.MessageBox]::Show("Please run this script as Administrator to set the execution policy.", "Admin Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                    exit 1
                }
                Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force -ErrorAction Stop
                Write-Log "Execution policy set to Unrestricted successfully."
                [System.Windows.Forms.MessageBox]::Show("Execution policy set to Unrestricted. Please restart the script.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                exit 0
            } catch {
                Write-Log "ERROR: Failed to set execution policy. Error: ${_.Exception.Message}"
                [System.Windows.Forms.MessageBox]::Show("Failed to set execution policy. Please run 'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force' as Administrator. Error: ${_.Exception.Message}", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                exit 1
            }
        } else {
            Write-Log "User declined to change execution policy. Exiting."
            [System.Windows.Forms.MessageBox]::Show("Please run 'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force' as Administrator to proceed.", "Execution Policy Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            exit 1
        }
    } else {
        Write-Log "Execution policy is acceptable: $currentPolicy"
    }
}

# Function to validate IP address or computer name
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

# Function to test VPN or domain connection status
function Test-ConnectionStatus {
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

# Function to check computer name to IP address
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

# Function to show GUI input dialog for computer name/IP address
function Get-IPAddressFromDialog {
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Enter Target Computer Name or IP Address"
    $Form.Size = New-Object System.Drawing.Size(400,200)
    $Form.StartPosition = "CenterScreen"
    $Form.FormBorderStyle = "FixedDialog"
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Point(10,20)
    $Label.Size = New-Object System.Drawing.Size(340,25)
    $Label.Text = "Enter the target computer name or IP address (e.g., PC-PC12345L or 10.32.240.84):"
    $Form.Controls.Add($Label)
    $TextBox = New-Object System.Windows.Forms.TextBox
    $TextBox.Location = New-Object System.Drawing.Point(10,50)
    $TextBox.Size = New-Object System.Drawing.Size(260,20)
    $Form.Controls.Add($TextBox)
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(150,120)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = "OK"
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $Form.AcceptButton = $OKButton
    $Form.Controls.Add($OKButton)
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(230,120)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = "Cancel"
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $Form.CancelButton = $CancelButton
    $Form.Controls.Add($CancelButton)
    $Result = $Form.ShowDialog()
    $IPAddress = $null
    if ($Result -eq [System.Windows.Forms.DialogResult]::OK) {
        $IPAddress = $TextBox.Text
    }
    $Form.Dispose()
    return $IPAddress
}

# Function to select a local file (script or executable) via GUI
function Get-FilePath {
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "Select File to Copy (Script or Executable)"
    $OpenFileDialog.Filter = "All Files (*.*)|*.*|PowerShell Scripts (*.ps1)|*.ps1|Executables (*.exe)|*.exe"
    $OpenFileDialog.InitialDirectory = "\\brnas\pcsupport\Applications\Tech Support Tools\Powershell Scripts"
    $Result = $OpenFileDialog.ShowDialog()
    if ($Result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $OpenFileDialog.FileName
    }
    return $null
}

# Function to select a file to run from the remote machine
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
        [System.Windows.Forms.MessageBox]::Show("No files found in C:\DesktopSupportTools on $TargetIP.", "No Files", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return $null
    }
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Select File to Run"
    $Form.Size = New-Object System.Drawing.Size(300,150)
    $Form.StartPosition = "CenterScreen"
    $Form.FormBorderStyle = "FixedDialog"
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Point(10,20)
    $Label.Size = New-Object System.Drawing.Size(260,20)
    $Label.Text = "Select a file to run on the remote machine:"
    $Form.Controls.Add($Label)
    $ComboBox = New-Object System.Windows.Forms.ComboBox
    $ComboBox.Location = New-Object System.Drawing.Point(10,40)
    $ComboBox.Size = New-Object System.Drawing.Size(260,20)
    $ComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $Files | ForEach-Object { 
        if ($_.EndsWith(".exe") -or $_.EndsWith(".ps1")) { $ComboBox.Items.Add($_) } 
    } | Out-Null
    if ($ComboBox.Items.Count -eq 0) {
        Write-Log -Message "ERROR: No executable or script files found in C:\DesktopSupportTools on $TargetIP."
        [System.Windows.Forms.MessageBox]::Show("No executable or script files found in C:\DesktopSupportTools on $TargetIP.", "No Valid Files", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        $Form.Dispose()
        return $null
    }
    $ComboBox.SelectedIndex = 0
    $Form.Controls.Add($ComboBox)
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(100,80)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = "Run"
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $Form.AcceptButton = $OKButton
    $Form.Controls.Add($OKButton)
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(180,80)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = "Cancel"
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $Form.CancelButton = $CancelButton
    $Form.Controls.Add($CancelButton)
    $Result = $Form.ShowDialog()
    $SelectedFile = $null
    if ($Result -eq [System.Windows.Forms.DialogResult]::OK) {
        $SelectedFile = $ComboBox.SelectedItem
        if ($SelectedFile -like "*.exe") {
            $UserSession = Invoke-Command -Session $Session -ScriptBlock {
                quser 2>&1
            } -ErrorAction SilentlyContinue
            if ($UserSession -match "No User exists" -or -not $UserSession) {
                Write-Log -Message "WARNING: No interactive user session on $TargetIP. GUI-based EXE may not display. Proceeding with non-GUI execution if possible."
            }
        }
    }
    $Form.Dispose()
    return $SelectedFile
}

# Function to input and run PowerShell commands
function Run-PowerShellCommand {
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Enter PowerShell Command"
    $Form.Size = New-Object System.Drawing.Size(400,200)
    $Form.StartPosition = "CenterScreen"
    $Form.FormBorderStyle = "FixedDialog"
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Point(10,20)
    $Label.Size = New-Object System.Drawing.Size(360,20)
    $Label.Text = "Enter PowerShell command to run on the remote machine:"
    $Form.Controls.Add($Label)
    $TextBox = New-Object System.Windows.Forms.TextBox
    $TextBox.Location = New-Object System.Drawing.Point(10,40)
    $TextBox.Size = New-Object System.Drawing.Size(360,80)
    $TextBox.Multiline = $true
    $TextBox.AcceptsReturn = $true
    $Form.Controls.Add($TextBox)
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(150,140)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = "Run"
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $Form.AcceptButton = $OKButton
    $Form.Controls.Add($OKButton)
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(230,140)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = "Cancel"
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $Form.CancelButton = $CancelButton
    $Form.Controls.Add($CancelButton)
    $Result = $Form.ShowDialog()
    $Command = $null
    if ($Result -eq [System.Windows.Forms.DialogResult]::OK) {
        $Command = $TextBox.Text
    }
    $Form.Dispose()
    if ($Command) {
        try {
            Write-Log -Message "Running PowerShell command on remote machine: $Command"
            $CommandResult = Invoke-Command -Session $Session -ScriptBlock {
                param($Cmd)
                Invoke-Expression $Cmd 2>&1
            } -ArgumentList $Command -ErrorAction Stop
            Write-Log -Message "Command executed successfully. Output: $CommandResult"
            [System.Windows.Forms.MessageBox]::Show("Command executed successfully. Output: $CommandResult", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            Write-Log -Message "ERROR: Failed to run PowerShell command. Error: ${_.Exception.Message}"
            [System.Windows.Forms.MessageBox]::Show("Failed to run command. Error: ${_.Exception.Message}", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        Write-Log -Message "No command entered or dialog cancelled."
    }
}

# Function to delete a file from the remote machine
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
        [System.Windows.Forms.MessageBox]::Show("No files found in C:\DesktopSupportTools on $TargetIP.", "No Files", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Delete File"
    $Form.Size = New-Object System.Drawing.Size(300,150)
    $Form.StartPosition = "CenterScreen"
    $Form.FormBorderStyle = "FixedDialog"
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Point(10,20)
    $Label.Size = New-Object System.Drawing.Size(260,20)
    $Label.Text = "Select a file to delete from the remote machine:"
    $Form.Controls.Add($Label)
    $ComboBox = New-Object System.Windows.Forms.ComboBox
    $ComboBox.Location = New-Object System.Drawing.Point(10,40)
    $ComboBox.Size = New-Object System.Drawing.Size(260,20)
    $ComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $Files | ForEach-Object { $ComboBox.Items.Add($_) } | Out-Null
    $ComboBox.SelectedIndex = 0
    $Form.Controls.Add($ComboBox)
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(100,80)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = "Delete"
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $Form.AcceptButton = $OKButton
    $Form.Controls.Add($OKButton)
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(180,80)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = "Cancel"
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $Form.CancelButton = $CancelButton
    $Form.Controls.Add($CancelButton)
    $Result = $Form.ShowDialog()
    if ($Result -eq [System.Windows.Forms.DialogResult]::OK) {
        $SelectedFile = $ComboBox.SelectedItem
        try {
            Invoke-Command -Session $Session -ScriptBlock {
                param($Path)
                Remove-Item -Path "C:\DesktopSupportTools\$Path" -Force -ErrorAction Stop
            } -ArgumentList $SelectedFile -ErrorAction Stop
            Write-Log -Message "Deleted file '$SelectedFile' successfully from $TargetIP."
            [System.Windows.Forms.MessageBox]::Show("Deleted $SelectedFile successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            Write-Log -Message "ERROR: Failed to delete file '$SelectedFile' on $TargetIP. Error: ${_.Exception.Message}"
            [System.Windows.Forms.MessageBox]::Show("Failed to delete file. Error: ${_.Exception.Message}", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
    $Form.Dispose()
}

# Function to check logged-in users
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
            [System.Windows.Forms.MessageBox]::Show("No user is currently logged in on $TargetIP.", "No Logged-In User", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            $Users = $Output -split "`n" | Where-Object { $_ -match "^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$" } | ForEach-Object {
                $Matches[1] + " (Session: " + $Matches[2] + ", ID: " + $Matches[3] + ", State: " + $Matches[4] + ", Idle: " + $Matches[5] + ", Logon: " + $Matches[6] + ")"
            }
            $Message = "Currently logged-in users on ${TargetIP}:`n`n" + ($Users -join "`n")
            Write-Log -Message "Logged-in users found on $TargetIP."
            [System.Windows.Forms.MessageBox]::Show($Message, "Logged-In Users", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } catch {
        Write-Log -Message "ERROR: Failed to check logged-in users on $TargetIP. Error: ${_.Exception.Message}"
        [System.Windows.Forms.MessageBox]::Show("Failed to check logged-in users. Error: ${_.Exception.Message}", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Function to prompt initial action
function Prompt-InitialAction {
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Python Toolkit Choose Action"
    $Form.Size = New-Object System.Drawing.Size(400,250)
    $Form.StartPosition = "CenterScreen"
    $Form.FormBorderStyle = "FixedDialog"
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Point(10,20)
    $Label.Size = New-Object System.Drawing.Size(360,20)
    $Label.Text = "Select an action:"
    $Form.Controls.Add($Label)
    $StartButton = New-Object System.Windows.Forms.Button
    $StartButton.Location = New-Object System.Drawing.Point(150,80)
    $StartButton.Size = New-Object System.Drawing.Size(100,30)
    $StartButton.Text = "Start Session"
    $StartButton.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $Form.Controls.Add($StartButton)
    $ExitButton = New-Object System.Windows.Forms.Button
    $ExitButton.Location = New-Object System.Drawing.Point(150,120)
    $ExitButton.Size = New-Object System.Drawing.Size(100,30)
    $ExitButton.Text = "Exit"
    $ExitButton.DialogResult = [System.Windows.Forms.DialogResult]::No
    $Form.Controls.Add($ExitButton)
    $Form.Controls.Add($Label) # Ensure label is added last to avoid overlap
    Write-Log "Displaying initial action dialog with Start Session and Exit options."
    $Result = $Form.ShowDialog()
    if ($Result -eq [System.Windows.Forms.DialogResult]::None) {
        Write-Log "WARNING: Dialog closed without valid result, defaulting to Cancel."
        $Result = [System.Windows.Forms.DialogResult]::Cancel
    }
    Write-Log "User selected action: $Result"
    $Form.Dispose()
    return $Result
}

# Function to prompt for another session
function Prompt-ForAnotherSession {
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Continue?"
    $Form.Size = New-Object System.Drawing.Size(300,150)
    $Form.StartPosition = "CenterScreen"
    $Form.FormBorderStyle = "FixedDialog"
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Point(10,20)
    $Label.Size = New-Object System.Drawing.Size(260,20)
    $Label.Text = "Start a session or action on another computer?"
    $Form.Controls.Add($Label)
    $YesButton = New-Object System.Windows.Forms.Button
    $YesButton.Location = New-Object System.Drawing.Point(100,80)
    $YesButton.Size = New-Object System.Drawing.Size(75,23)
    $YesButton.Text = "Yes"
    $YesButton.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $Form.Controls.Add($YesButton)
    $NoButton = New-Object System.Windows.Forms.Button
    $NoButton.Location = New-Object System.Drawing.Point(180,80)
    $NoButton.Size = New-Object System.Drawing.Size(75,23)
    $NoButton.Text = "No"
    $NoButton.DialogResult = [System.Windows.Forms.DialogResult]::No
    $Form.Controls.Add($NoButton)
    $Form.Controls.Add($Label) # Ensure label is added last to avoid overlap
    Write-Log "Displaying continue dialog with Yes and No options."
    $Result = $Form.ShowDialog()
    if ($Result -eq [System.Windows.Forms.DialogResult]::None) {
        Write-Log "WARNING: Dialog closed without valid result, defaulting to No."
        $Result = [System.Windows.Forms.DialogResult]::No
    }
    $Form.Dispose()
    return $Result
}

# Function to prompt session action
function Prompt-SessionAction {
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Session Actions"
    $Form.Size = New-Object System.Drawing.Size(900,300) # Wider (900) and taller (300)
    $Form.StartPosition = "CenterScreen"
    $Form.FormBorderStyle = "FixedDialog"
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Point(10,20)
    $Label.Size = New-Object System.Drawing.Size(860,20)
    $Label.Text = "Select an action for the current session:"
    $Form.Controls.Add($Label)
    $CopyButton = New-Object System.Windows.Forms.Button
    $CopyButton.Location = New-Object System.Drawing.Point(50,50)
    $CopyButton.Size = New-Object System.Drawing.Size(150,40)
    $CopyButton.Text = "Copy File"
    $CopyButton.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $Form.Controls.Add($CopyButton)
    $RunFileButton = New-Object System.Windows.Forms.Button
    $RunFileButton.Location = New-Object System.Drawing.Point(220,50)
    $RunFileButton.Size = New-Object System.Drawing.Size(150,40)
    $RunFileButton.Text = "Run File"
    $RunFileButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $Form.Controls.Add($RunFileButton)
    $RunPSCommandButton = New-Object System.Windows.Forms.Button
    $RunPSCommandButton.Location = New-Object System.Drawing.Point(390,50)
    $RunPSCommandButton.Size = New-Object System.Drawing.Size(150,40)
    $RunPSCommandButton.Text = "Run PS Command"
    $RunPSCommandButton.DialogResult = [System.Windows.Forms.DialogResult]::Ignore
    $Form.Controls.Add($RunPSCommandButton)
    $DeleteButton = New-Object System.Windows.Forms.Button
    $DeleteButton.Location = New-Object System.Drawing.Point(560,50)
    $DeleteButton.Size = New-Object System.Drawing.Size(150,40)
    $DeleteButton.Text = "Delete File"
    $DeleteButton.DialogResult = [System.Windows.Forms.DialogResult]::Retry
    $Form.Controls.Add($DeleteButton)
    $CheckUserButton = New-Object System.Windows.Forms.Button
    $CheckUserButton.Location = New-Object System.Drawing.Point(50,120)
    $CheckUserButton.Size = New-Object System.Drawing.Size(150,40)
    $CheckUserButton.Text = "Logged In User"
    $CheckUserButton.DialogResult = [System.Windows.Forms.DialogResult]::No
    $Form.Controls.Add($CheckUserButton)
    $ExitButton = New-Object System.Windows.Forms.Button
    $ExitButton.Location = New-Object System.Drawing.Point(220,120)
    $ExitButton.Size = New-Object System.Drawing.Size(150,40)
    $ExitButton.Text = "Exit Session"
    $ExitButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $Form.Controls.Add($ExitButton)
    $Form.Controls.Add($Label) # Ensure label is added last to avoid overlap
    Write-Log "Displaying session action dialog with various options."
    $Result = $Form.ShowDialog()
    if ($Result -eq [System.Windows.Forms.DialogResult]::None) {
        Write-Log "WARNING: Dialog closed without valid result, defaulting to Cancel."
        $Result = [System.Windows.Forms.DialogResult]::Cancel
    }
    $Form.Dispose()
    return $Result
}

# Function to force reboot
<#
function Force-Reboot {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetIP,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    $Confirm = [System.Windows.Forms.MessageBox]::Show(
        "Are you sure you want to force a reboot on the remote machine? This will terminate all processes and restart immediately.",
        "Confirm Reboot",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($Confirm -eq [System.Windows.Forms.DialogResult]::No) {
        Write-Log -Message "User cancelled the reboot operation."
        return
    }
    try {
        Invoke-Command -Session $Session -ScriptBlock {
            shutdown /r /f /t 0
        } -ErrorAction Stop
        Write-Log -Message "Reboot command sent successfully to $TargetIP."
        [System.Windows.Forms.MessageBox]::Show("Reboot command sent successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Write-Log -Message "ERROR: Failed to force reboot on $TargetIP. Error: ${_.Exception.Message}"
        [System.Windows.Forms.MessageBox]::Show("Failed to force reboot. Error: ${_.Exception.Message}", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}
#>

# Define environment variables
$ScriptVer = '3.0'
$ScriptEnv = "Powershell Remote Session Tool using Framework by Nic Fuentes"
$MIGVPNAdapter = 'PANGP Virtual Ethernet Adapter Secure'
$VPNIPR = '10.*'
$DOMAINIPR = '10.32.*'
$DOMAINIPRALt = '10.32'
$DC = 'brprdc01.int.mgc.com'
$MIGDomain = "int.mgc.com"
$Seconds = '10'

# Main script
try {
    Set-ExecutionPolicyIfNeeded
    Write-Log -Message "Script started. Log file: $LogFile"
    Write-Log -Message "Checking for MIG or VPN connection..."
    if (-not (Test-ConnectionStatus)) {
        Write-Log -Message "ERROR: MIG or VPN connection is not active."
        [System.Windows.Forms.MessageBox]::Show("MIG or VPN connection is not active. Please connect and try again.", "Connection Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
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
                    Write-Log -Message "No computer name or IP provided or dialog cancelled. Returning to main menu."
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
                        [System.Windows.Forms.MessageBox]::Show("Could not resolve '$TargetIP' to an IP address.", "Resolution Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
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
                    [System.Windows.Forms.MessageBox]::Show("Cannot reach $TargetIP after $MaxPingRetries attempts.", "Connection Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
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
                        Write-Log -Message "ERROR: Failed to update TrustedHosts. Error: ${_.Exception.Message}"
                        continue
                    }
                }
                Write-Log -Message "Testing WinRM connectivity to $TargetIP on port 5985..."
                $NetTest = Test-NetConnection -ComputerName $TargetIP -Port 5985 -ErrorAction Stop
                Write-Log -Message "Network Test: TcpTestSucceeded = $($NetTest.TcpTestSucceeded)"
                if (-not $NetTest.TcpTestSucceeded) {
                    Write-Log -Message "ERROR: Port 5985 is not accessible on $TargetIP. Check firewall or VPN settings."
                    [System.Windows.Forms.MessageBox]::Show("Port 5985 is not accessible on $TargetIP. Check firewall or VPN settings.", "WinRM Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
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
                        Write-Log -Message "ERROR: Failed to establish session to $TargetIP (Attempt $RetryCount/$MaxRetries). Error: ${_.Exception.Message}"
                        if ($_.Exception.Message -match "Access is denied") {
                        } elseif ($_.Exception.Message -match "WinRM") {
                            Write-Log -Message "WinRM error. Ensure WinRM is enabled on $TargetIP and port 5985 is open."
                        }
                        if ($RetryCount -lt $MaxRetries) {
                            Write-Log -Message "Retrying in 10 seconds..."
                            Start-Sleep -Seconds 10
                        }
                    }
                }
                if (-not $Session) {
                    Write-Log -Message "ERROR: Failed to establish session after $MaxRetries attempts."
                    [System.Windows.Forms.MessageBox]::Show("Failed to establish session after $MaxRetries attempts.", "Session Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
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
                            Write-Log -Message "ERROR: Failed to reconnect session to $TargetIP. Error: ${_.Exception.Message}"
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
                                    Write-Log -Message "Successfully copied file '$($FilePath.Split('\')[-1])' to C:\DesktopSupportTools on $TargetIP."
                                    [System.Windows.Forms.MessageBox]::Show("Successfully copied '$($FilePath.Split('\')[-1])' to C:\DesktopSupportTools.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                                } catch {
                                    Write-Log -Message "ERROR: Failed to copy file to $TargetIP. Error: ${_.Exception.Message}"
                                    [System.Windows.Forms.MessageBox]::Show("Failed to copy file. Error: ${_.Exception.Message}", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
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
                                            return @{ Success = $false; Output = "Exception: ${_.Exception.Message}"; ExitCode = -1 }
                                        }
                                    } -ArgumentList $FilePath -ErrorAction Stop
                                    if ($Result.Success) {
                                        Write-Log -Message "File '$SelectedFile' executed successfully on $TargetIP. PID: $($Result.ProcessId). Output: $($Result.Output)"
                                        [System.Windows.Forms.MessageBox]::Show("File '$SelectedFile' executed successfully. PID: $($Result.ProcessId). Output: $($Result.Output)", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                                    } else {
                                        Write-Log -Message "ERROR: File '$SelectedFile' failed with exit code $($Result.ExitCode). Output: $($Result.Output)"
                                        [System.Windows.Forms.MessageBox]::Show("File '$SelectedFile' failed with exit code $($Result.ExitCode). Output: $($Result.Output)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                                    }
                                } catch {
                                    Write-Log -Message "ERROR: Failed to run file '$SelectedFile' on $TargetIP. Error: ${_.Exception.Message}"
                                    [System.Windows.Forms.MessageBox]::Show("Failed to run file. Error: ${_.Exception.Message}", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
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
                            Write-Log "WARNING: Invalid or null DialogResult encountered, defaulting to Cancel."
                            break
                        }
                    }
                } while ($SessionAction -ne [System.Windows.Forms.DialogResult]::Cancel)
                Write-Log -Message "Closing session to $TargetIP..."
                try {
                    Remove-PSSession -Session $Session -ErrorAction Stop
                    Write-Log -Message "Session closed successfully."
                } catch {
                    Write-Log -Message "ERROR: Failed to close session. Error: ${_.Exception.Message}"
                }
                $Session = $null
            }
            ([System.Windows.Forms.DialogResult]::No) {
                Write-Log -Message "User chose to exit. Terminating script."
                exit 0
            }
            default {
                Write-Log "WARNING: Invalid or null initial action result, defaulting to exit."
                exit 0
            }
        }
        Write-Log -Message "Prompting user to start another action or session..."
        $Continue = Prompt-ForAnotherSession
        Write-Log "Continue result: $Continue"
    } while ($Continue -eq [System.Windows.Forms.DialogResult]::Yes)
    Write-Log -Message "Script execution completed."
} catch {
    Write-Log -Message "Critical error in main: ${_.Exception.Message}"
    [System.Windows.Forms.MessageBox]::Show("Critical error: ${_.Exception.Message}", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}