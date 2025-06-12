# **EndpointUtils PowerShell Module**

A collection of PowerShell functions designed to assist IT professionals and desktop technicians with common endpoint health checks, inventory gathering, and diagnostic tasks.

## **Overview**

This module provides easy-to-use cmdlets for quickly assessing the state of a Windows endpoint. It's built to be simple, lightweight, and useful for day-to-day administration and troubleshooting.

## **Key Features**

* **Get-EndpointComplianceStatus**: Performs a high-level check against predefined baselines, including OS build version, status of critical services, and Bitlocker encryption status.  
* **Get-InstalledSoftwareAdvanced**: Generates a more comprehensive list of installed software than the standard "Apps & Features" utility by querying the registry directly.  
* **Test-CommonNetworkPorts**: Quickly verifies TCP connectivity to essential network resources (like domain controllers or file shares) on standard ports.  
* **Get-SystemUptimeFormatted**: Retrieves the system's last boot time and provides a human-readable uptime string.

## **Installation**

### **Prerequisites**

* PowerShell 5.1 or later.

### **Option 1: From GitHub (Recommended)**

1. Clone this repository to your local machine:  
   git clone https://github.com/YourUsername/EndpointUtils.git

2. Place the EndpointUtils folder into one of your PowerShell module paths. You can find these paths by running $env:PSModulePath in PowerShell. A common location is:  
   C:\\Users\\YourUsername\\Documents\\WindowsPowerShell\\Modules\\

### **Option 2: Manual Download**

1. Download the repository as a ZIP file from the GitHub page.  
2. Unzip the file.  
3. Rename the resulting folder from EndpointUtils-main to EndpointUtils.  
4. Move the EndpointUtils folder to one of your PowerShell module paths as described above.

Once the module is in place, you can import it into your session:  
Import-Module EndpointUtils

## **Usage Examples**

### **Get-EndpointComplianceStatus**

Run a quick compliance check on the local machine.  
PS\> $report \= Get-EndpointComplianceStatus \-Verbose  
VERBOSE: Checking OS Build...  
VERBOSE: OS Build is compliant.  
VERBOSE: Checking Required Services...  
VERBOSE: All specified services are running.  
VERBOSE: Checking Bitlocker Status for OS Drive...  
VERBOSE: Bitlocker is enabled and protection is on for C  
VERBOSE: Overall Compliance: True

PS\> $report | Format-List

CheckedTimestamp      : 6/12/2025 8:15:00 AM  
ComputerName          : YOUR-PC  
OSBuildCompliant      : True  
OverallServicesStatus : True  
NonRunningServices    : {}  
BitlockerCompliant    : True  
RegistryCompliant     :  
IsCompliant           : True  
Details               : {OS Build Compliant: Microsoft Windows 11 Pro Build 22621., All required services are running., Bitlocker Compliant: OS Drive (C) is Encrypted and Protected., No registry keys were specified for checking.}

### **Get-SystemUptimeFormatted**

Get the last boot time and a formatted uptime string.  
PS\> $uptime \= Get-SystemUptimeFormatted  
PS\> $uptime

ComputerName          : YOUR-PC  
LastBootTime          : 6/10/2025 4:30:15 PM  
Uptime                : 1.15:45:10.1234567  
FormattedUptimeString : System uptime: 1 days, 15 hours, 45 minutes, 10 seconds

PS\> "This computer last rebooted on: $($uptime.LastBootTime)"  
This computer last rebooted on: 06/10/2025 16:30:15

### **Get-InstalledSoftwareAdvanced**

Find all installed software from a specific publisher.  
PS\> Get-InstalledSoftwareAdvanced | Where-Object Publisher \-like "\*Microsoft\*"

Name                                     Version         Publisher                      InstallDate SourcePath  
\----                                     \-------         \---------                      \----------- \----------  
Microsoft 365 \- en-us                    16.0.15128.20248 Microsoft Corporation        20220615    HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall  
Microsoft Edge                           102.0.1245.33   Microsoft Corporation        20220610    HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall  
Microsoft Edge WebView2 Runtime          102.0.1245.33   Microsoft Corporation        20220610    HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall  
Microsoft Visual C++ 2015-2022...        14.32.31326.0   Microsoft Corporation        20220610    HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall

### **Test-CommonNetworkPorts**

Check connectivity to domain controllers and a file server.  
PS\> Test-CommonNetworkPorts \-TargetHosts "DC01", "DC02", "FileServer01" \-PingFirst

TargetHost   Port TcpTestSucceeded PingSucceeded  
\----------   \---- \---------------- \-------------  
DC01           53             True          True  
DC01           88             True          True  
DC01          135             True          True  
...  
DC02           53             True          True  
...  
FileServer01  445             True          True  
FileServer01  636            False          True

## **License**

This project is licensed under the **MIT License**. See the LICENSE file for details.