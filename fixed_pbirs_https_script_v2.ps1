#Requires -RunAsAdministrator

<#
.SYNOPSIS
Creates a Self-Signed Root CA and a Server Certificate (with specific and wildcard SANs)
signed by the Root CA. Configures an existing PBIRS instance reliably for HTTPS using
the new certificate. Exports certificates and performs validation checks.

.DESCRIPTION
This script aims to provide a rock-solid setup for PBIRS HTTPS using internal
certificates, correcting previous script errors and following best practices.
It uses proper XML manipulation for config changes and avoids IIS/hosts file edits.

.NOTES
- Run as Administrator on the PBIRS server.
- REVIEW and UPDATE variables in the CONFIGURATION section before running.
- Ensure REAL DNS is configured for all hostnames intended for client use.
- The exported Root CA (.cer) MUST be installed on client machines.
#>

# ------ CONFIGURATION ------

# --- PBIRS Details (VERIFY THESE) ---
$pbirsServiceName = "PowerBIReportServer"
# !!! CRITICAL: Verify this path matches your PBIRS installation !!!
$pbirsConfigPath = "C:\Program Files\Microsoft Power BI Report Server\PBIRS\ReportServer\rsreportserver.config"
# $pbirsConfigPath = "C:\Program Files\Microsoft Power BI Report Server\ReportServer\rsreportserver.config" # Possible alternative path

# --- Certificate Details ---
$rootCaSubject = "CN=AccessLex Internal Root CA $(Get-Date -Format 'yyyy-MM-dd')" # Descriptive Root CA name
$rootCaValidityYears = 10

# --- Define the primary FQDN users should ideally use for PBIRS ---
$primaryHostname = "pbirs.aads.accesslex.org"
$serverCertSubject = "CN=$primaryHostname" # CN should usually match the primary hostname
$serverCertValidityYears = 2

# --- List ALL DNS names (Specific FQDNs & Wildcards) the Server Cert should cover ---
$serverCertDnsNames = @(
    $primaryHostname,               # *MUST* include the primary specific FQDN
    "*.aads.accesslex.org",          # Wildcard for primary subdomain
    "aads.accesslex.org",            # Base domain
    "*.accesslex.org",               # Wildcard for parent domain
    "accesslex.org",                 # Parent base domain
    "alexpowerbi.accessgroup.org",   # Specific legacy FQDN (if still needed)
    "alexpowerbi",                   # Specific legacy short name (Needs DNS!)
    "*.agi.accessgroup.org",         # Wildcard for legacy subdomain (if needed)
    "*.accessgroup.org"              # Wildcard for legacy parent domain
    # Add any other specific server names required, e.g., "reports.aads.accesslex.org"
)

# --- Output Folders & Logging ---
$baseOutputFolder = "C:\Certificates"
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputFolderName = "PBIRS_Setup_$timestamp"
$certOutputFolder = Join-Path -Path $baseOutputFolder -ChildPath $outputFolderName
$logFile = Join-Path -Path $certOutputFolder -ChildPath "setup_and_config.log"

# --- PFX Export Password ---
# Set to 'N/A', $null, or an empty string for NO password. Otherwise, enter the desired password.
$pfxPasswordInput = "N/A" # Example: "YourP@ssw0rd!" or $null or "N/A"

# ------ SCRIPT START ------

# --- Initial Setup ---
# Create Output Folders
Write-Verbose "Creating output base folder: $baseOutputFolder" -Verbose
if (-not (Test-Path $baseOutputFolder)) { New-Item -Path $baseOutputFolder -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null }
Write-Verbose "Creating specific output folder: $certOutputFolder" -Verbose
try {
    New-Item -Path $certOutputFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Error "FATAL: Failed to create output folder '$certOutputFolder'. Check permissions. Error: $($_.Exception.Message)"
    Read-Host "Press Enter to exit"; return
}

# Start Logging
try {
    Start-Transcript -Path $logFile -Append -ErrorAction Stop
} catch {
    Write-Error "FATAL: Failed to start transcript logging to '$logFile'. Check permissions. Error: $($_.Exception.Message)"
    Read-Host "Press Enter to exit"; return
}

Write-Host ("-" * 60)
Write-Host "--- Starting PBIRS Certificate and HTTPS Configuration ---"
Write-Host "Timestamp: $timestamp"
Write-Host "Log File: $logFile"
Write-Host "Output Folder: $certOutputFolder"
Write-Host ("-" * 60)

# --- Validate PBIRS Config Path ---
if (-not (Test-Path $pbirsConfigPath)) {
    Write-Error "FATAL: PBIRS Configuration file not found at specified path:"
    Write-Error "  '$pbirsConfigPath'"
    Write-Error "Please verify the `$pbirsConfigPath variable is correct for your installation."
    Stop-Transcript; Read-Host "Press Enter to exit"; return
} else {
     Write-Host "[INFO] PBIRS Config file found at: $pbirsConfigPath"
}


# --- STEP 1: Create Certificates (Correct Order) ---
Write-Host "`n[Step 1/5] Generating Certificates..."
$rootCA = $null
$serverCert = $null

try {
    # 1a. Create Root CA in 'My' store
    Write-Verbose "Creating Root CA '$rootCaSubject' in LocalMachine\My..." -Verbose
    $rootCA = New-SelfSignedCertificate `
        -Subject $rootCaSubject `
        -KeyUsage CertSign, CRLSign `
        -KeyLength 2048 ` -KeyAlgorithm RSA ` -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears($rootCaValidityYears) `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -Verbose:$false -ErrorAction Stop
    Write-Host " -> Root CA created (Temporary location). Thumbprint: $($rootCA.Thumbprint)"

    # 1b. Create Server Cert in 'My' store, signed by Root CA (which is also in 'My')
    Write-Verbose "Creating Server Cert '$serverCertSubject' signed by Root CA..." -Verbose
    $serverCert = New-SelfSignedCertificate `
        -Subject $serverCertSubject `
        -DnsName $serverCertDnsNames `
        -Signer $rootCA ` # Signing works now!
        -KeyLength 2048 ` -KeyAlgorithm RSA ` -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears($serverCertValidityYears) `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") ` # EKU: Server Authentication
        -Verbose:$false -ErrorAction Stop
    Write-Host " -> Server Cert created. Thumbprint: $($serverCert.Thumbprint)"
    Write-Verbose "    SANs: $($serverCert.DnsNameList.Unicode -join ', ')" -Verbose

    # 1c. Move Root CA to 'Root' store
    Write-Verbose "Moving Root CA to LocalMachine\Root..." -Verbose
    Move-Item -Path $rootCA.PSPath -Destination "Cert:\LocalMachine\Root" -Force -ErrorAction Stop
    $rootCA = Get-ChildItem "Cert:\LocalMachine\Root\$($rootCA.Thumbprint)" # Refresh object
    Write-Host " -> Root CA moved to Trusted Root store."

    Write-Host "[SUCCESS] Certificates generated successfully."

} catch {
    Write-Error "!!! FAILED during Certificate Generation!"
    Write-Error "Error: $($_.Exception.Message)"
    Write-Error "Check permissions and previous log messages."
    Stop-Transcript; Read-Host "Press Enter to exit"; return
}

# --- STEP 2: Export Certificate Files ---
Write-Host "`n[Step 2/5] Exporting Certificate Files..."
# Process PFX Password
$pfxPasswordSecure = $null
if ($pfxPasswordInput -ne 'N/A' -and $pfxPasswordInput -ne $null -and $pfxPasswordInput -ne '') {
    $pfxPasswordSecure = ConvertTo-SecureString -String $pfxPasswordInput -AsPlainText -Force
    Write-Verbose "PFX will be password protected." -Verbose
} else { Write-Verbose "PFX will not be password protected." -Verbose }

# Export Root CA (.cer)
$rootCaCerPath = Join-Path -Path $certOutputFolder -ChildPath "PBIRS_RootCA_Public.cer"
try {
    Write-Verbose "Exporting Root CA to '$rootCaCerPath'..." -Verbose
    Export-Certificate -Cert $rootCA -FilePath $rootCaCerPath -Type CERT -Force -ErrorAction Stop
    Write-Host " -> Root CA Exported (.cer): $rootCaCerPath"
} catch { Write-Error " -> FAILED to export Root CA (.cer)! Error: $($_.Exception.Message)" }

# Export Server Cert (.pfx)
$serverPfxPath = Join-Path -Path $certOutputFolder -ChildPath "PBIRS_ServerCert_PrivateKey.pfx"
try {
    Write-Verbose "Exporting Server Cert to '$serverPfxPath'..." -Verbose
    Export-PfxCertificate -Cert $serverCert.PSPath -FilePath $serverPfxPath -Password $pfxPasswordSecure -Force -ErrorAction Stop
    Write-Host " -> Server Cert Exported (.pfx): $serverPfxPath $(if($pfxPasswordSecure){'(Protected)'}else{'(NOT Protected)'})"
} catch { Write-Error " -> FAILED to export Server Cert (.pfx)! Error: $($_.Exception.Message)" }


# --- STEP 3: Configure PBIRS rsreportserver.config (XML Method) ---
Write-Host "`n[Step 3/5] Configuring PBIRS '$($pbirsConfigPath.Split('\')[-1])'..."

# Define primary HTTPS URL for reservation (must match primary hostname)
$primaryHttpsUrlToReserve = "https://$($primaryHostname):443"
# Define UrlRoot
$urlRootValue = "https://$($primaryHostname)/reportserver"

# Backup current config
$backupPath = "$pbirsConfigPath.backup.$timestamp"
Write-Verbose "Backing up current config to '$backupPath'..." -Verbose
try {
    Copy-Item -Path $pbirsConfigPath -Destination $backupPath -Force -ErrorAction Stop
} catch {
    Write-Error "!!! FAILED to backup config file '$pbirsConfigPath'!"
    Write-Error "Error: $($_.Exception.Message)"
    Stop-Transcript; Read-Host "Press Enter to exit"; return
}

# Modify using XML
try {
    Write-Verbose "Loading config file as XML..." -Verbose
    [xml]$configXml = Get-Content -Path $pbirsConfigPath -Encoding UTF8 -ErrorAction Stop

    # Update Service Section
    Write-Verbose "Updating Service section..." -Verbose
    $serviceNode = $configXml.SelectSingleNode("//Configuration/Service")
    if (-not $serviceNode) { 
        $serviceNode = $configXml.CreateElement("Service")
        $configXml.Configuration.AppendChild($serviceNode) | Out-Null
        Write-Verbose "Created Service node." -Verbose 
    }
    
    # -- SslCertificateThumbprint --
    $sslThumbprintNode = $serviceNode.SelectSingleNode("SslCertificateThumbprint")
    if (-not $sslThumbprintNode) { 
        $sslThumbprintNode = $configXml.CreateElement("SslCertificateThumbprint")
        $serviceNode.AppendChild($sslThumbprintNode) | Out-Null
        Write-Verbose "Added SslCertificateThumbprint node." -Verbose 
    }
    $sslThumbprintNode.InnerText = $serverCert.Thumbprint
    Write-Verbose "Set SslCertificateThumbprint: $($serverCert.Thumbprint)" -Verbose
    
    # -- UrlRoot --
    $urlRootNode = $serviceNode.SelectSingleNode("UrlRoot")
    if (-not $urlRootNode) { 
        $urlRootNode = $configXml.CreateElement("UrlRoot")
        $serviceNode.AppendChild($urlRootNode) | Out-Null
        Write-Verbose "Added UrlRoot node." -Verbose 
    }
    $urlRootNode.InnerText = $urlRootValue
    Write-Verbose "Set UrlRoot: $urlRootValue" -Verbose

    # Update URLReservations Section
    Write-Verbose "Updating URLReservations section..." -Verbose
    $urlReservationNode = $configXml.SelectSingleNode("//Configuration/URLReservations")
    if (-not $urlReservationNode) { 
        $urlReservationNode = $configXml.CreateElement("URLReservations")
        $configXml.Configuration.AppendChild($urlReservationNode) | Out-Null
        Write-Verbose "Created URLReservations node." -Verbose 
    }
    
    $appNames = @("ReportServerWebService", "ReportServerWebApp")
    foreach($appName in $appNames){
        Write-Verbose "Processing reservations for '$appName'..." -Verbose
        $appNode = $urlReservationNode.SelectSingleNode("Application[Name='$appName']")
        if (-not $appNode) { 
            $appNode = $configXml.CreateElement("Application")
            $nameNode = $configXml.CreateElement("Name")
            $nameNode.InnerText = $appName
            $appNode.AppendChild($nameNode) | Out-Null
            $urlsNode = $configXml.CreateElement("URLs")
            $appNode.AppendChild($urlsNode) | Out-Null
            $urlReservationNode.AppendChild($appNode) | Out-Null
            Write-Verbose "Created Application Name='$appName' node." -Verbose 
        }
        
        $urlsNode = $appNode.SelectSingleNode("URLs")
        if (-not $urlsNode) { 
            $urlsNode = $configXml.CreateElement("URLs")
            $appNode.AppendChild($urlsNode) | Out-Null
            Write-Verbose "Created URLs node in $appName." -Verbose 
        }

        # Remove existing HTTPS reservations specifically
        $httpsUrlsToRemove = $urlsNode.SelectNodes("URL[starts-with(UrlString, 'https:')]")
        if($httpsUrlsToRemove.Count -gt 0) { 
            Write-Verbose "Removing $($httpsUrlsToRemove.Count) existing HTTPS URL(s) from $appName..." -Verbose
            $httpsUrlsToRemove | ForEach-Object { $_.ParentNode.RemoveChild($_) } | Out-Null 
        }

        # Add the NEW primary HTTPS reservation
        Write-Verbose "Adding reservation '$primaryHttpsUrlToReserve' to $appName..." -Verbose
        $newUrlNode = $configXml.CreateElement("URL")
        $newUrlStringNode = $configXml.CreateElement("UrlString")
        $newUrlStringNode.InnerText = $primaryHttpsUrlToReserve
        $newUrlNode.AppendChild($newUrlStringNode) | Out-Null
        $urlsNode.AppendChild($newUrlNode) | Out-Null
    }
    Write-Verbose "NOTE: Existing HTTP reservations (like http://+:80) were not modified." -Verbose

    # Save Config
    Write-Verbose "Saving updated config file..." -Verbose
    $configXml.Save($pbirsConfigPath)
    Write-Host " -> SUCCESS: PBIRS configuration file updated."

} catch {
    Write-Error "!!! FAILED to modify PBIRS config file!"
    Write-Error "Error: $($_.Exception.Message)"
    Write-Warning "Restore config from backup '$backupPath' if PBIRS fails."
    Stop-Transcript; Read-Host "Press Enter to exit"; return
}

# --- STEP 4: Restart PBIRS Service ---
Write-Host "`n[Step 4/5] Restarting PBIRS Service '$pbirsServiceName'..."
try {
    Restart-Service -Name $pbirsServiceName -Force -Verbose:$false -ErrorAction Stop
    Write-Host " -> Restart command sent. Waiting 20 seconds..."
    Start-Sleep -Seconds 20
    $status = (Get-Service -Name $pbirsServiceName).Status
    Write-Host " -> Current service status: $status"
    if($status -ne 'Running'){ Write-Warning "   WARNING: Service did not reach Running state! Check Event Viewer (Application Log)."}
} catch {
    Write-Error "!!! FAILED to restart PBIRS service!"
    Write-Error "Error: $($_.Exception.Message)"
    Write-Warning "   Check service status manually and review Event Viewer."
}

# --- STEP 5: Final Validation (Basic Checks) ---
Write-Host "`n[Step 5/5] Performing Final Validation Checks..."
$validationPassed = $true

# Check SSL Binding
Write-Verbose "Checking netsh http sslcert for port 443..." -Verbose
$bindingInfo = netsh http show sslcert ipport=0.0.0.0:443
if ($bindingInfo -match "Certificate Hash\s+:\s+($([regex]::Escape($serverCert.Thumbprint)))") {
    Write-Host " -> OK: Correct certificate thumbprint is bound to 0.0.0.0:443."
} else {
    Write-Warning " -> FAIL: Expected certificate thumbprint ($($serverCert.Thumbprint)) NOT found bound to 0.0.0.0:443!"
    Write-Verbose $bindingInfo -Verbose
    $validationPassed = $false
}

# Check Local Connection
$testPortalUrl = "https://$primaryHostname/reports" # Standard portal path
Write-Verbose "Testing local connection to '$testPortalUrl'..." -Verbose
try {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Ignore self-signed error locally
    Invoke-WebRequest -Uri $testPortalUrl -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop | Out-Null
    Write-Host " -> OK: Local connection test to '$testPortalUrl' succeeded."
} catch {
    Write-Warning " -> FAIL: Local connection test to '$testPortalUrl' failed!"
    Write-Warning "    Error: $($_.Exception.Message)"
    $validationPassed = $false
} finally {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null # Reset validation
}

# --- Script End ---
Write-Host ""
Write-Host ("-" * 60)
if ($validationPassed) {
    Write-Host "--- PBIRS Setup and Configuration Finished Successfully ---"
} else {
     Write-Warning "--- PBIRS Setup and Configuration Finished with WARNINGS/FAILURES ---"
     Write-Warning "Review messages above carefully. Check log file: $logFile"
}
Write-Host ("-" * 60)
Write-Host "*** Action Required: ***"
Write-Host "1. CLIENT DNS: Ensure '$primaryHostname' and any other required names resolve correctly on CLIENT machines."
Write-Host "2. CLIENT ROOT CA: Install Root CA '$rootCaCerPath' into 'Local Machine -> Trusted Root Certification Authorities'."
Write-Host "3. CLIENT TEST: Browse to '$testPortalUrl' (and other SAN URLs) from a client with the Root CA installed."
Write-Host ("-" * 60)
Stop-Transcript
