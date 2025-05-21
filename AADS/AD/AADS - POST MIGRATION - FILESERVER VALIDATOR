<#
.SYNOPSIS
    Performs comprehensive client-side diagnostics for troubleshooting Single Sign-On (SSO),
    Kerberos, and permission issues, particularly after a domain migration or when accessing
    resources in a new domain like Azure AD Domain Services (Azure AD DS).
.DESCRIPTION
    This script checks:
    - Azure AD Join & Primary Refresh Token (PRT) status.
    - Current user context.
    - DNS client configuration and resolution of critical SRV records.
    - Network connectivity to specified Domain Controller IP addresses.
    - Kerberos ticket status (klist) before and after a conceptual resource access attempt.
    - Recent relevant Kerberos and SMB client event log entries for errors.
    - Provides guidance on server-side checks and permission validation.
.NOTES
    Run this script on the client machine experiencing SSO or permission issues.
    MODIFY the configuration variables at the top to match your environment.
    Run as Administrator to access all event logs and perform all network tests.
#>

#region Configuration - !!! MODIFY THESE VALUES TO MATCH YOUR ENVIRONMENT !!!
# --- Target Domain Details (e.g., the new Azure AD DS domain) ---
$TargetDomainNetBiosName = "AADSCONTOSO" # e.g., NetBIOS name of your Azure AD DS domain
$TargetDomainFqdn        = "aaddscontoso.com" # e.g., FQDN of your Azure AD DS domain
$TargetDcIpAddresses     = @("10.0.0.4", "10.0.0.5") # IP Addresses of DCs for $TargetDomainFqdn

# --- Example Resource to Test (e.g., a file server in the target domain) ---
$TestResourceNetBiosName = "MYFILESERVER"
$TestResourceFqdn        = "$TestResourceNetBiosName.$TargetDomainFqdn"
$TestResourceShareUnc    = "\\$TestResourceFqdn\sharedfolder" # Example UNC path

# --- Event Log Settings ---
$MaxEventsToFetch = 20 # Max recent events to fetch for each log query
$TimeWindowHours  = 24  # Look for events in the last X hours
#endregion Configuration

Clear-Host
Write-Host "========================================================================================" -ForegroundColor White
Write-Host " Comprehensive Post-Migration / SSO / Kerberos Client Diagnostic Script" -ForegroundColor White
Write-Host "----------------------------------------------------------------------------------------"
Write-Host " Target Domain          : $TargetDomainFqdn (NetBIOS: $TargetDomainNetBiosName)" -ForegroundColor Cyan
Write-Host " Example Test Resource  : $TestResourceShareUnc" -ForegroundColor Cyan
Write-Host "========================================================================================"
Write-Host "INFO: Running as Administrator is recommended for full diagnostic capabilities."
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Script not running as Administrator. Some checks (like full event log access) might be limited."
}
Write-Host ""
Start-Sleep -Seconds 1

# --- Helper Function for Section Headers ---
function Write-SectionHeader { param ([string]$Title, [string]$SectionNumber) Write-Host "`n--- [$SectionNumber] $Title ---" -ForegroundColor Yellow }
function Write-SubHeader { param ([string]$Title) Write-Host "`n `b`b-> $Title" -ForegroundColor Cyan }
function Test-Condition { param ([bool]$Condition, [string]$PassMessage, [string]$FailMessage) if ($Condition) { Write-Host "[PASS] $PassMessage" -ForegroundColor Green } else { Write-Host "[FAIL] $FailMessage" -ForegroundColor Red } }

# --- 1. Current User and Client Machine Context ---
Write-SectionHeader -Title "Current User & Client Machine Context" -SectionNumber "1"
Write-SubHeader "User Information"
Write-Host "Current User (whoami)      : $(whoami)"
Write-Host "Current User (env:USERNAME): $($env:USERNAME)"
Write-Host "User Domain (env:USERDOMAIN): $($env:USERDOMAIN)"
Write-Host "Logon Server (env:LOGONSERVER): $($env:LOGONSERVER)"
Get-CimInstance Win32_UserAccount | Where-Object {$_.Name -eq $env:USERNAME} | Select-Object Name, Domain, SID, Disabled, Lockout, PasswordRequired, PasswordExpires, PasswordChangeable

Write-SubHeader "Azure AD Device Status (dsregcmd)"
$dsregOutput = dsregcmd /status
Test-Condition ($dsregOutput -match "AzureAdJoined : YES") "Device is Azure AD Joined." "Device is NOT Azure AD Joined. (Check AzureAdJoined value)"
Test-Condition ($dsregOutput -match "AzureAdPrt : YES") "Azure AD PRT is Present." "Azure AD PRT is NOT Present. (Check AzureAdPrt value - CRITICAL for AAD SSO)"
$dsregOutput | Select-String "DomainJoined", "WorkplaceJoined", "TenantName", "TenantId", "AzureAdPrtUpdateTime", "AzureAdPrtExpiryTime"

Write-SubHeader "Operating System Information"
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture, CsDomain, CsDomainType

# --- 2. DNS Client Configuration & Resolution Health ---
Write-SectionHeader -Title "DNS Client Configuration & Target Domain Resolution" -SectionNumber "2"
Write-SubHeader "Client DNS Server Configuration"
$dnsServers = (Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses
Write-Host "Configured Client DNS Servers (IPv4): $($dnsServers -join ', ')"
$dnsMatch = $false; $TargetDcIpAddresses | ForEach-Object { if ($dnsServers -contains $_) { $dnsMatch = $true } }
Test-Condition $dnsMatch "Client DNS includes at least one specified Target DC IP." "Client DNS DOES NOT include any specified Target DC IP. CRITICAL for resolving target domain resources."

Write-SubHeader "Connectivity & SRV Record Lookup for '$TargetDomainFqdn'"
$srvRecordsToTest = @{
    "Kerberos SRV (_kerberos._tcp.dc._msdcs)" = "_kerberos._tcp.dc._msdcs.$TargetDomainFqdn"
    "LDAP SRV (_ldap._tcp.dc._msdcs)"         = "_ldap._tcp.dc._msdcs.$TargetDomainFqdn"
}
$allSrvResolved = $true
foreach ($srvEntry in $srvRecordsToTest.GetEnumerator()) {
    Write-Host "Attempting to resolve $($srvEntry.Key): $($srvEntry.Value)"
    try {
        $resolvedSrv = Resolve-DnsName -Name $srvEntry.Value -Type SRV -ErrorAction Stop -DnsOnly
        Test-Condition ($resolvedSrv -ne $null) "$($srvEntry.Key) SRV records resolved." "$($srvEntry.Key) SRV records NOT FOUND."
        if ($resolvedSrv) { $resolvedSrv | Format-Table Name, Type, NameTarget, Port, Priority, Weight -AutoSize }
        else { $allSrvResolved = $false }
    } catch { Write-Host "[FAIL] ERROR resolving $($srvEntry.Key) SRV record: $($_.Exception.Message.Split('.')[0])"; $allSrvResolved = $false }
}
Test-Condition $allSrvResolved "All critical SRV records for target domain resolved." "One or more critical SRV records for target domain FAILED to resolve. Check client DNS settings & DNS server health."

Write-SubHeader "Target Resource FQDN Resolution ($TestResourceFqdn)"
try {
    $resolvedResource = Resolve-DnsName -Name $TestResourceFqdn -ErrorAction Stop -DnsOnly
    Test-Condition ($resolvedResource -ne $null) "Test Resource FQDN '$TestResourceFqdn' resolved to: $($resolvedResource.IPAddress -join ', ')." "Test Resource FQDN '$TestResourceFqdn' FAILED to resolve."
    if ($resolvedResource) { $resolvedResource | Format-Table Name, Type, IPAddress, TTL -AutoSize }
} catch { Write-Host "[FAIL] ERROR resolving Test Resource FQDN '$TestResourceFqdn': $($_.Exception.Message.Split('.')[0])" }

# --- 3. Network Connectivity to Target Domain Controllers ---
Write-SectionHeader -Title "Network Connectivity to Target Domain Controllers ($($TargetDcIpAddresses -join ', '))" -SectionNumber "3"
$allPortsReachable = $true
foreach ($dcIp in $TargetDcIpAddresses) {
    Write-SubHeader "Testing connectivity to DC: $dcIp"
    $portsToTest = @{
        "Kerberos (TCP 88)" = @{ Port = 88; Protocol = "TCP" }
        "LDAP (TCP 389)"    = @{ Port = 389; Protocol = "TCP" }
        "SMB (TCP 445)"     = @{ Port = 445; Protocol = "TCP" } # For file shares, DC sysvol
        "DNS (UDP 53)"      = @{ Port = 53; Protocol = "UDP" } # For DNS queries
    }
    foreach ($portInfoEntry in $portsToTest.GetEnumerator()) {
        Write-Host "  Testing $($portInfoEntry.Name)... " -NoNewline
        try {
            $testResult = Test-NetConnection -ComputerName $dcIp -Port $portInfoEntry.Value.Port -Protocol $portInfoEntry.Value.Protocol -InformationLevel Quiet -ErrorAction Stop
            if (($portInfoEntry.Value.Protocol -eq "TCP" -and $testResult.TcpTestSucceeded) -or ($portInfoEntry.Value.Protocol -eq "UDP" -and $testResult)) {
                Write-Host "[PASS] Open" -ForegroundColor Green
            } else { Write-Host "[FAIL] Closed/Unreachable" -ForegroundColor Red; $allPortsReachable = $false }
        } catch { Write-Host "[FAIL] BLOCKED or Error: $($_.Exception.Message.Split('.')[0])" -ForegroundColor Red; $allPortsReachable = $false }
    }
}
Test-Condition $allPortsReachable "All tested essential ports appear reachable to specified Target DCs." "One or more essential ports to Target DCs are BLOCKED/UNREACHABLE. Check NSGs, Firewalls (Windows/Network), VNet Peering."

# --- 4. Kerberos Ticket Diagnostics ---
Write-SectionHeader -Title "Kerberos Ticket Diagnostics" -SectionNumber "4"
Write-SubHeader "Initial Kerberos Tickets (klist)"
klist

Write-SubHeader "Attempting Kerberos Ticket Acquisition for '$TestResourceShareUnc'"
Write-Host "INFO: Purging existing Kerberos tickets to force a fresh request..."
klist purge | Out-Null
Write-Host "INFO: Attempting to list contents of '$TestResourceShareUnc' to trigger ticket request..."
Write-Host "      (This may succeed, fail with an error, or prompt for credentials depending on the issue)"
Get-ChildItem -Path $TestResourceShareUnc -ErrorAction SilentlyContinue -ErrorVariable smbError | Out-Null # Attempt access
if ($smbError) { Write-Warning "Error during test access to $TestResourceShareUnc : $($smbError[0].Exception.Message)" }

Write-SubHeader "Kerberos Tickets After Access Attempt (klist)"
klist
$targetSpnForSmb = "cifs/$TestResourceFqdn"
$klistOutputAfter = klist
Test-Condition ($klistOutputAfter -match [regex]::Escape($targetSpnForSmb)) "Kerberos ticket for '$targetSpnForSmb' FOUND after access attempt." "Kerberos ticket for '$targetSpnForSmb' NOT FOUND after access attempt. This is a key SSO failure point."
if (-not ($klistOutputAfter -match [regex]::Escape($targetSpnForSmb))) {
    Write-Host "  Common reasons for no ticket:"
    Write-Host "  - Password Hash Not Synced to Target Domain (especially for cloud-only AAD users needing to access AADDS)."
    Write-Host "  - Client DNS misconfiguration (cannot find KDCs for '$TargetDomainFqdn')."
    Write-Host "  - Network connectivity issues to Target Domain Controllers."
    Write-Host "  - SPN for '$targetSpnForSmb' missing or incorrect on '$TestResourceFqdn' computer object in '$TargetDomainFqdn'."
    Write-Host "  - Time skew between client and Domain Controllers > 5 minutes."
}

# --- 5. Recent Security & SMB Client Event Log Errors ---
Write-SectionHeader -Title "Recent Relevant Client Event Log Errors (Last $($TimeWindowHours)hrs, Max $MaxEventsToFetch events per query)" -SectionNumber "5"
$StartTime = (Get-Date).AddHours(-$TimeWindowHours)

Write-SubHeader "Kerberos Client Errors (Event Log: System)"
# Common Kerberos error Event IDs in System Log: Many KDC errors, SPN issues might log here.
# More specific Kerberos logs are under Applications and Services Logs, but System often shows critical failures.
# Example: Event ID 4 (KRB_AP_ERR_MODIFIED), Event ID 7 (KDC_ERR_S_PRINCIPAL_UNKNOWN for SPN issues)
# For AAD Kerberos specific logs, check: Microsoft-Windows-AAD/Operational
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kerberos-Key-Distribution-Center'; Level=1,2,3; StartTime=$StartTime} -MaxEvents $MaxEventsToFetch -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize -Wrap
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Security-Kerberos'; Level=1,2,3; StartTime=$StartTime} -MaxEvents $MaxEventsToFetch -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize -Wrap
Write-Host "INFO: Also check 'Applications and Services Logs > Microsoft > Windows > AAD > Operational' for Azure AD related issues."
Write-Host "INFO: And 'Applications and Services Logs > Microsoft > Windows > Security-Kerberos > Operational' (needs enabling via wevtutil or GPO for verbose client tracing)."


Write-SubHeader "SMB Client Errors (Event Log: Microsoft-Windows-SmbClient/Connectivity & Security)"
# Event ID 30804: TCP connection established (good)
# Event ID 30805: Connection disconnected
# Event ID 30806: Session setup failed (often auth related)
# Event ID 30807: Share connect failed
# Event ID 30808: Tree disconnected
# Event ID 31010: Kerberos auth failed, NTLM tried
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-SmbClient/Connectivity'; Level=1,2,3; StartTime=$StartTime} -MaxEvents $MaxEventsToFetch -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize -Wrap
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-SmbClient/Security'; Level=1,2,3; StartTime=$StartTime} -MaxEvents $MaxEventsToFetch -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize -Wrap

# --- 6. Key Server-Side & Policy Checks (Reminders) ---
Write-SectionHeader -Title "Key Server-Side & Policy Configuration Checks (Reminders)" -SectionNumber "6"
Write-Host "INFO: The following require checks on servers or in policy management consoles (Intune/GPMC)." -ForegroundColor Cyan

Write-SubHeader "Target Domain ($TargetDomainFqdn - e.g., Azure AD DS) - On DCs / Management VM"
Write-Host "  - [CRITICAL] Password Hash Synchronization: Enabled AND user password changed (if cloud-only AAD user) *after* PHS to AADDS enabled."
Write-Host "  - DNS Records: Ensure A records for file servers and SRV records (_kerberos, _ldap) are correct in '$TargetDomainFqdn' DNS."
Write-Host "  - Kerberos Policy (GPO): Max ticket lifetimes, encryption types (AES preferred, RC4 deprecated)."
Write-Host "  - NTLM Policy (GPO): Current NTLM restriction levels."

Write-SubHeader "File Server ('$TestResourceFqdn' - Joined to '$TargetDomainFqdn')"
Write-Host "  - [CRITICAL] SPN: `cifs/$TestResourceFqdn` registered to the file server's computer account in '$TargetDomainFqdn'."
Write-Host "    (Check with: `setspn -L $TestResourceNetBiosName` on a domain-joined machine)"
Write-Host "  - Windows Firewall: Allows SMB (TCP 445) and potentially other AD traffic if it's also a DC."
Write-Host "  - Share Permissions: Correct users/groups from '$TargetDomainFqdn' have access."
Write-Host "  - NTFS Permissions: Correct users/groups from '$TargetDomainFqdn' have access."
Write-Host "  - SMB Server Configuration: (e.g., `Get-SmbServerConfiguration | select EncryptData, RejectUnencryptedAccess`)."

Write-SubHeader "Client Policies (Intune for Azure AD Joined Devices)"
Write-Host "  - Windows Hello for Business: If used, check 'Configure Kerberos cloud trust for on-premises authentication' policy."
Write-Host "  - Hardened UNC Paths: Check configuration for paths like `\\$TestResourceFqdn\*` or `\\*.$TargetDomainFqdn\`. Mutual auth requires working Kerberos."
Write-Host "  - NTLM Client Restrictions: Check policies like 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers'."
Write-Host "  - DNS Configuration: Ensure client is reliably getting DNS servers that can resolve '$TargetDomainFqdn'."

# --- 7. Further Troubleshooting Steps ---
Write-SectionHeader -Title "Further Troubleshooting Steps" -SectionNumber "7"
Write-Host "  - Time Synchronization: Ensure client, file server, and target domain DCs are time-synchronized (Kerberos is time-sensitive, typically < 5 min skew)."
Write-Host "  - Duplicate SPNs: Check for duplicate SPNs in the '$TargetDomainFqdn' forest (`setspn -X` from a DC)."
Write-Host "  - User Account Status: Ensure the user account in '$TargetDomainFqdn' (synced from AAD) is not locked out, disabled, or expired."
Write-Host "  - Network Traces (Wireshark/Netmon): Capture traffic on client and server during connection attempt for deep analysis of Kerberos/SMB handshake."

Write-Host "`n========================================================================================"
Write-Host " Comprehensive Client Diagnostic Script Complete. Review all output." -ForegroundColor Green
Write-Host "========================================================================================"
