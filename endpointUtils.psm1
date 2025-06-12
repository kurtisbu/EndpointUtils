# EndpointUtils.psm1
# Module for Endpoint Health & Inventory Checks

#region Function Get-EndpointComplianceStatus
function Get-EndpointComplianceStatus {
    [CmdletBinding()]
    param(
        [Parameter()]
        [Version]$MinimumOSBuild = '10.0.19045.0', # Example: Windows 10 22H2. Adjust as needed.

        [Parameter()]
        [String[]]$RequiredServiceNames = @(
            'CcmExec',                           # SCCM/MECM Client
            'IntuneManagementExtension',         # Microsoft Intune Management Extension
            'MsSense',                           # Microsoft Defender for Endpoint (MDE Sensor)
            'WinDefend'                          # Windows Defender Antivirus Service
            # Add Additional Services as needed
            # e.g., 'btjumpclient_dg'
        ),

        [Parameter()]
        [switch]$CheckBitlockerStatus = $true, # Default to checking Bitlocker

        [Parameter()]
        [System.Collections.Hashtable]$CheckRegistryKeys
    )

    $Result = [PSCustomObject]@{
        CheckedTimestamp      = Get-Date
        ComputerName          = $env:COMPUTERNAME
        OSBuildCompliant      = $null
        OverallServicesStatus = $null 
        NonRunningServices    = [System.Collections.Generic.List[string]]::new()
        BitlockerCompliant    = $null
        RegistryCompliant     = $null 
        IsCompliant           = $false 
        Details               = [System.Collections.Generic.List[string]]::new()
    }

    # --- 1. OS Build Check ---
    Write-Verbose "Checking OS Build..."
    try {
        $CurrentOS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $CurrentBuild = [Version]$CurrentOS.BuildNumber
        $Result.OSBuildCompliant = $CurrentBuild -ge $MinimumOSBuild
        if (-not $Result.OSBuildCompliant) {
            $msg = "OS Build Non-Compliant: Current is $($CurrentOS.Caption) Build $CurrentBuild, Required minimum is Build $MinimumOSBuild."
            $Result.Details.Add($msg)
            Write-Warning $msg
        } else {
            $Result.Details.Add("OS Build Compliant: $($CurrentOS.Caption) Build $CurrentBuild.")
            Write-Verbose "OS Build is compliant."
        }
    } catch {
        $errMsg = "Failed to check OS Build: $($_.Exception.Message)"
        Write-Warning $errMsg
        $Result.OSBuildCompliant = $false
        $Result.Details.Add($errMsg)
    }

    # --- 2. Required Services Check ---
    Write-Verbose "Checking Required Services..."
    if ($RequiredServiceNames.Count -gt 0) {
        $Result.OverallServicesStatus = $true 
        foreach ($ServiceName in $RequiredServiceNames) {
            Write-Verbose "Checking service: $ServiceName"
            try {
                $Service = Get-Service -Name $ServiceName -ErrorAction Stop
                if ($Service.Status -ne 'Running') {
                    $Result.OverallServicesStatus = $false
                    $Result.NonRunningServices.Add("$ServiceName (Status: $($Service.Status))")
                    $Result.Details.Add("Service Non-Compliant: $ServiceName is $($Service.Status).")
                    Write-Warning "Service $ServiceName is not running (Status: $($Service.Status))."
                } else {
                     Write-Verbose "Service $ServiceName is Running."
                }
            } catch {
                $errMsg = "Failed to get status for service '$ServiceName': $($_.Exception.Message)"
                Write-Warning $errMsg
                $Result.OverallServicesStatus = $false
                $Result.NonRunningServices.Add("$ServiceName (Error: Not Found or Access Denied)")
                $Result.Details.Add("Service Non-Compliant: $ServiceName - $($_.Exception.Message)")
            }
        }
        if ($Result.OverallServicesStatus) {
            $Result.Details.Add("All required services are running.")
            Write-Verbose "All specified services are running."
        }
    } else {
        $Result.OverallServicesStatus = $true 
        $Result.Details.Add("No specific services were checked.")
        Write-Verbose "No services listed in `$RequiredServiceNames to check."
    }

    # --- 3. Bitlocker Status Check ---
    if ($CheckBitlockerStatus) {
        Write-Verbose "Checking Bitlocker Status for OS Drive..."
        try {
            $OSDriveLetter = $env:SystemDrive.Trim(':')
            $Volume = Get-CimInstance -Namespace root\cimv2\security\microsoftvolumeencryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter = '$OSDriveLetter'" -ErrorAction Stop

            if ($Volume) {
                if ($Volume.ProtectionStatus -eq 1) {
                    $Result.BitlockerCompliant = $true
                    $Result.Details.Add("Bitlocker Compliant: OS Drive ($OSDriveLetter) is Encrypted and Protected.")
                    Write-Verbose "Bitlocker is enabled and protection is on for $OSDriveLetter"
                } else {
                    $Result.BitlockerCompliant = $false
                    $ProtectionStatusText = switch ($Volume.ProtectionStatus) {
                        0       {"Protection Off"}
                        2       {"Protection Unknown (Possibly Suspended, Encrypting, or Decrypting)"}
                        default {"Status $($Volume.ProtectionStatus)"}
                    }
                    $msg = "Bitlocker Non-Compliant: OS Drive ($OSDriveLetter) Protection Status is $ProtectionStatusText."
                    $Result.Details.Add($msg)
                    Write-Warning $msg
                }
            } else {
                $Result.BitlockerCompliant = $false
                $msg = "Bitlocker Non-Compliant: Could not find OS Drive ($OSDriveLetter) information in Win32_EncryptableVolume."
                $Result.Details.Add($msg)
                Write-Warning $msg
            }
        } catch {
            $errMsg = "Failed to check Bitlocker status: $($_.Exception.Message)"
            Write-Warning $errMsg
            $Result.BitlockerCompliant = $false
            $Result.Details.Add($errMsg)
        }
    } else {
        $Result.BitlockerCompliant = $null 
        $Result.Details.Add("Bitlocker check was skipped.")
        Write-Verbose "Bitlocker check skipped as per parameter."
    }

    # --- 4. Registry Key Check ---
    if ($PSBoundParameters.ContainsKey('CheckRegistryKeys') -and $CheckRegistryKeys -and $CheckRegistryKeys.Count -gt 0) {
        Write-Verbose "Checking Registry Keys..."
        $Result.RegistryCompliant = $true 
        $Result.Details.Add("Registry check is a placeholder for future implementation.")
        Write-Warning "Registry key checking logic is not fully implemented in this version."
    } else {
        $Result.RegistryCompliant = $null 
        $Result.Details.Add("No registry keys were specified for checking.")
        Write-Verbose "No registry keys specified to check."
    }

    # --- Determine Overall Compliance ---
    $complianceChecksPerformed = @(
        $Result.OSBuildCompliant,
        $Result.OverallServicesStatus,
        $Result.BitlockerCompliant 
    ) | Where-Object { $null -ne $_ }

    if ($complianceChecksPerformed.Count -gt 0) {
        $Result.IsCompliant = -not ($complianceChecksPerformed -contains $false)
    } else {
        $Result.IsCompliant = $true 
        $Result.Details.Add("Warning: No actual compliance checks were performed.")
    }

    Write-Verbose "Overall Compliance: $($Result.IsCompliant)"
    return $Result
}
#endregion

#region Function Get-InstalledSoftwareAdvanced
function Get-InstalledSoftwareAdvanced {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$NameFilter = "*",

        [Parameter()]
        [switch]$IncludeUserInstalls,

        [Parameter()]
        [switch]$ShowAllProperties
    )

    $Paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    if ($IncludeUserInstalls) {
        # Ensure HKCU path is accessible
        try {
            $UserUninstallPath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall"
            if (Test-Path $UserUninstallPath) {
                $Paths += $UserUninstallPath
            } else {
                Write-Warning "HKCU Uninstall path not found or not accessible: $UserUninstallPath"
            }
        } catch {
            Write-Warning "Error accessing HKCU Uninstall path: $($_.Exception.Message)"
        }
    }

    $InstalledSoftware = [System.Collections.Generic.List[PSCustomObject]]::new()
    $UniqueKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) # Case-insensitive check for unique keys

    foreach ($Path in $Paths) {
        Write-Verbose "Checking path: $Path"
        if (-not (Test-Path $Path)) {
            Write-Verbose "Path not found: $Path"
            continue
        }
        Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {
            $Props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            $DisplayName = $Props.DisplayName
            $DisplayVersion = $Props.DisplayVersion

            if (-not [string]::IsNullOrWhiteSpace($DisplayName) -and $DisplayName -like $NameFilter) {
                # Basic filter for system components/updates (can be expanded)
                if (($Props.PSObject.Properties.Name -contains 'SystemComponent' -and $Props.SystemComponent -eq 1) -or 
                    ($Props.PSObject.Properties.Name -contains 'ParentKeyName') -or
                    ($Props.PSObject.Properties.Name -contains 'ReleaseType' -and $Props.ReleaseType -in @('Hotfix', 'Update Rollup', 'Security Update'))) {
                    Write-Verbose "Skipping likely system component/update: $DisplayName"
                    continue
                }

                $UniqueKey = "$($DisplayName)::$($DisplayVersion)"
                if ($UniqueKeys.Add($UniqueKey)) { 
                    $OutputObject = [PSCustomObject]@{
                        Name        = $DisplayName
                        Version     = $DisplayVersion
                        Publisher   = $Props.Publisher
                        InstallDate = $Props.InstallDate 
                        SourcePath  = $Path.Replace('Registry::', '')
                    }
                    if ($ShowAllProperties) {
                        $OutputObject | Add-Member -MemberType NoteProperty -Name InstallLocation -Value $Props.InstallLocation
                        $OutputObject | Add-Member -MemberType NoteProperty -Name UninstallString -Value $Props.UninstallString
                        if ($Props.PSObject.Properties.Name -contains 'EstimatedSize') {
                             $OutputObject | Add-Member -MemberType NoteProperty -Name EstimatedSizeMB -Value ([math]::Round($Props.EstimatedSize / 1MB, 2))
                        }
                    }
                    $InstalledSoftware.Add($OutputObject)
                }
            }
        }
    }
    Write-Verbose "Found $($InstalledSoftware.Count) unique software entries."
    return $InstalledSoftware | Sort-Object Name
}
#endregion

#region Function Test-CommonNetworkPorts
function Test-CommonNetworkPorts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$TargetHosts,

        [Parameter()]
        [int[]]$Ports = @(53, 88, 135, 389, 445, 636, 3268, 3269), # Common AD/File Share Ports

        [Parameter()]
        [int]$TimeoutSeconds = 2,

        [Parameter()]
        [switch]$PingFirst
    )

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($HostName in $TargetHosts) {
        Write-Verbose "Testing host: $HostName"
        $PingStatus = $null # Initialize to null
        if ($PingFirst.IsPresent) { # Check if the switch was actually used
            try {
                $PingStatus = Test-Connection -ComputerName $HostName -Count 1 -Quiet -ErrorAction Stop
                Write-Verbose "Ping result for ${HostName}: $PingStatus" 
            } catch {
                Write-Warning "Ping failed for $HostName : $($_.Exception.Message)"
                $PingStatus = $false # Set to false on error
            }
        }

        foreach ($Port in $Ports) {
            Write-Verbose "Testing port $Port on $HostName..."
            $PortTestSucceeded = $false 
            try {
                # Test-NetConnection returns $true on success with -InformationLevel Quiet, throws on failure
                $PortTestSucceeded = Test-NetConnection -ComputerName $HostName -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop -TimeoutSeconds $TimeoutSeconds
                Write-Verbose "Port $Port on $HostName test result: $PortTestSucceeded"
            } catch {
                # Error means connection failed
                Write-Verbose "Connection to $HostName on port $Port failed: $($_.Exception.Message)"
                $PortTestSucceeded = $false
            }
            
            $Results.Add([PSCustomObject]@{
                TargetHost       = $HostName
                Port             = $Port
                TcpTestSucceeded = $PortTestSucceeded
                PingSucceeded    = if($PingFirst.IsPresent) { $PingStatus } else { $null } # Only include if PingFirst was used
            })
        }
    }
    return $Results
}
#endregion

#region Function Get-SystemUptimeFormatted
function Get-SystemUptimeFormatted {
    [CmdletBinding()]
    [OutputType([PSCustomObject])] # Declare the output type
    param(
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME 
    )

    try {
        Write-Verbose "Querying Win32_OperatingSystem on '$ComputerName'..."
        $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
        
        $RawLastBootUpTime = $OSInfo.LastBootUpTime
        Write-Verbose "Raw LastBootUpTime value from WMI for '$ComputerName': '$RawLastBootUpTime' (Type: $($RawLastBootUpTime.GetType().FullName))"

        $BootTime = $null

        if ($null -eq $RawLastBootUpTime) {
            Write-Error "LastBootUpTime value for '$ComputerName' is null. Cannot calculate uptime."
            return $null
        }

        # Check if LastBootUpTime is already a DateTime object (ideal scenario)
        if ($RawLastBootUpTime -is [datetime]) {
            $BootTime = $RawLastBootUpTime
            Write-Verbose "Used LastBootUpTime directly as it is already a DateTime object for '$ComputerName': $BootTime"
        } 
        # If it's a string, attempt to parse it directly.
        elseif ($RawLastBootUpTime -is [string]) {
            Write-Verbose "LastBootUpTime for '$ComputerName' is a string ('$RawLastBootUpTime'). Attempting direct parsing..."
            try {
                $BootTime = [datetime]$RawLastBootUpTime
                Write-Verbose "Successfully parsed LastBootUpTime string for '$ComputerName': $BootTime"
            } catch {
                Write-Error "Failed to parse LastBootUpTime string '$RawLastBootUpTime' for '$ComputerName'. Error: $($_.Exception.Message)"
                return $null
            }
        } 
        # If it's neither DateTime nor String, it's an unexpected type.
        else {
            Write-Error "LastBootUpTime for '$ComputerName' is an unexpected type: $($RawLastBootUpTime.GetType().FullName). Value: '$RawLastBootUpTime'. Cannot calculate uptime."
            return $null
        }
        
        # Ensure BootTime was successfully determined
        if ($null -eq $BootTime) {
            Write-Error "Could not determine a valid BootTime for '$ComputerName' after parsing attempts."
            return $null
        }

        $Uptime = (Get-Date) - $BootTime
        Write-Verbose "Calculated TimeSpan for '$ComputerName': $Uptime"

        $FormattedUptimeString = "System uptime: $($Uptime.Days) days, $($Uptime.Hours) hours, $($Uptime.Minutes) minutes, $($Uptime.Seconds) seconds"
        
        # Construct and return an object with both pieces of information
        $Output = [PSCustomObject]@{
            ComputerName          = $ComputerName
            LastBootTime          = $BootTime # This is the actual DateTime object for last boot
            Uptime                = $Uptime # This is the TimeSpan object
            FormattedUptimeString = $FormattedUptimeString
        }
        
        return $Output

    } catch {
        # This outer catch handles errors from Get-CimInstance or other unexpected issues
        Write-Error "Failed to get uptime for '$ComputerName': $($_.Exception.Message)"
        return $null
    }
}
#endregion

# --- Export Module Members ---
# Explicitly export the functions you want to be available to the user.
Export-ModuleMember -Function Get-EndpointComplianceStatus
Export-ModuleMember -Function Get-InstalledSoftwareAdvanced
Export-ModuleMember -Function Test-CommonNetworkPorts
Export-ModuleMember -Function Get-SystemUptimeFormatted

Write-Host "EndpointUtils module (version 0.1.5) loaded." -ForegroundColor Cyan
