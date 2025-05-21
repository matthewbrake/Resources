<#
.SYNOPSIS
    Orchestrates the complete setup of an Azure Private DNS solution, including
    networking, Private DNS Zones, VNet links, and imports records from a CSV
    using Service Principal authentication.

.DESCRIPTION
    This script provides an end-to-end automated solution for deploying Azure
    Private DNS infrastructure and populating it with records.
    Key operations include:
    1.  Securely authenticating to Azure using a Service Principal.
    2.  Creating or verifying the existence of a target Resource Group.
    3.  Creating or verifying a Virtual Network and a dedicated Subnet.
    4.  Reading DNS record data from a specified CSV file.
    5.  For each unique DNS zone identified in the CSV:
        a. Creating or verifying the Azure Private DNS Zone.
        b. Creating or verifying a Virtual Network Link to the deployed VNet.
    6.  For each DNS record in the CSV (supporting A, AAAA, CNAME):
        a. Validating data format (e.g., IP address for A/AAAA records).
        b. Performing CNAME target rewriting based on configuration.
        c. Checking if the record set (name + type) already exists; if so, skipping.
        d. Adding new, valid records to the respective Azure Private DNS Zone.
    The script emphasizes robust logging, detailed error handling, clear console
    output with progress indicators, and generates a comprehensive deployment report.

.NOTES
    Author: Assistant (Based on user request)
    Version: 3.1 (Brace Structure Review)
    Date:   2023-10-28

    CRITICAL PREREQUISITES:
        - Azure PowerShell 'Az' module (Az.Accounts, Az.Resources, Az.Network, Az.Dns)
          must be installed and up-to-date. Run: Install-Module Az -Scope CurrentUser -Force
        - An Azure App Registration (Service Principal) must be created with a Client Secret.
        - The Service Principal requires 'Contributor' role (or more fine-grained specific
          roles like Network Contributor, Private DNS Zone Contributor) on the target
          Azure Subscription (if creating the RG) or on the target Resource Group
          (if the RG already exists).
        - Input CSV file must be 7 columns, NO HEADER ROW, with format:
          "ZoneName","RecordName","RecordType","FQDN","RecordData","TTLString","Timestamp"
          'RecordData' for A/AAAA records MUST be a valid IP address.

    SECURITY WARNING:
        - The $Script:ClientSecretPlain variable holds a plaintext secret. This is
          highly insecure for production. For production, retrieve secrets from
          Azure Key Vault at runtime or use certificate-based SPN authentication.
          NEVER commit plaintext secrets to source control.

    IDEMPOTENCY:
        - The script attempts to be idempotent by checking for the existence of
          Resource Group, VNet, Subnet, Private DNS Zones, and VNet Links before
          attempting creation. Record import skips existing record sets (name+type).

    EXECUTION:
        - Test thoroughly in a non-production environment first.
        - Use -WhatIf for Azure resource creation cmdlets during initial tests:
          .\Orchestrate-AzurePrivateDnsSetup.ps1 -WhatIf -Verbose -Debug
#>

#Requires -Modules Az.Accounts, Az.Resources, Az.Network, Az.Dns
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

# --- Script Configuration ---
# >>> REVIEW AND EDIT ALL VALUES IN THIS SECTION CAREFULLY <<<

# --- Azure Service Principal Credentials (MANDATORY) ---
# >>> REVIEW AND EDIT ALL VALUES IN THIS SECTION CAREFULLY <<<
$Script:TenantId = "7749b712-035b-48cd-8dfd-0c83a422f61b"                     # <-- SET Azure AD Tenant ID
$Script:ApplicationId = "bd234c13-ae9a-4189--4d72b372e711" # <-- SET Service Principal App (Client) ID
# For Client Secret, it's best to load from Azure Key Vault or prompt securely.
# For this example, it's a variable. **NEVER COMMIT A SCRIPT WITH A PLAINTEXT SECRET TO SOURCE CONTROL.**
$Script:ClientSecretPlain = "   # <-- SET Service Principal Client Secret Value

# --- Azure Subscription and Location ---
$Script:SubscriptionId = "d7adb6e1-864e-4fe0-9492-1d7d49a4ceb8"     # <-- SET Your Target Subscription ID

# --- Resource Naming & Configuration (MANDATORY - Customize as needed) ---
$Script:ResourceGroupName   = "rg-MyAzurePrivateDns"
$Script:VNetName            = "vnet-DnsHub"
$Script:VNetAddressPrefix   = "10.200.0.0/16"
$Script:SubnetName          = "snet-PrivateEndpointsAndDns" # Example usage
$Script:SubnetAddressPrefix = "10.200.0.0/24"

# --- DNS Import Configuration (MANDATORY) ---
$Script:CsvFilePath         = "C:\temp\DnsExportForAzure-20250518-203305.csv" # 7 columns, NO header
$Script:CnameTargetDomain   = "cloudpioneers.net" # e.g., aads.contoso.com
$Script:ExcludeRecordTypes  = @('SOA', 'NS') # SRV, MX, TXT not handled by this script version's import logic

# --- Logging and Reporting (Optional - Customize if needed) ---
$Script:BaseLogReportDir    = "C:\temp\AzureAutomationLogs"
# --- End of Script Configuration ---

# --- Script Initialization ---
Set-StrictMode -Version Latest
$Global:ErrorActionPreference = "Stop" # Set globally for the script session

$ScriptStartTime = Get-Date
$Timestamp = $ScriptStartTime.ToString('yyyyMMdd_HHmmss')
$Script:LogReportDir = Join-Path -Path $Script:BaseLogReportDir -ChildPath "AzureDnsDeploy-$Timestamp"
$LogFileName = "Deployment-$Timestamp.log"
$ReportFileName = "DeploymentReport-$Timestamp.txt"
$Script:LogFilePath = $null
$Script:ReportFilePath = $null
$InputCsvHeaders = @('ZoneName', 'RecordName', 'RecordType', 'FQDN', 'RecordData', 'TTLString', 'Timestamp')

$GlobalStats = @{
    ResourceGroupCreated = 0; ResourceGroupExisted = 0;
    VNetCreated = 0; VNetExisted = 0; SubnetAddedToExistingVNet = 0; SubnetCreatedWithNewVNet = 0; SubnetExisted = 0;
    ZonesCreated = 0; ZonesExisting = 0; ZonesFailed = 0;
    VNetLinksCreated = 0; VNetLinksExisting = 0; VNetLinksFailed = 0;
    RecordsRead = 0; RecordsProcessed = 0; RecordsAttemptedAdd = 0;
    RecordsAddedOk = 0; RecordsExisted = 0; RecordsSkippedInvalid = 0; RecordsSkippedExcludedType = 0; RecordsFailedAdd = 0
}

# --- Core Functions ---

function Write-LogAndReport {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG', 'FATAL', 'REPORT', 'STEP', 'SUCCESS')][string]$Level = 'INFO',
        [Parameter(Mandatory = $false)][switch]$NoConsole,
        [Parameter(Mandatory = $false)][System.Exception]$ExceptionForLog
    )
    $LogTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Prefix = switch ($Level) {
        'STEP'   { "[--- STEP ---]" }
        'SUCCESS'{ "[SUCCESS]" }
        'DEBUG'  { "[DEBUG]" }
        default  { "[$($Level.ToUpper())]" }
    }
    $LogEntry = "$LogTime $Prefix $Message"
    if ($ExceptionForLog) { $LogEntry += "`nEXCEPTION DETAILS:`n$($ExceptionForLog | Format-List * -Force | Out-String)" }

    if ($Script:LogFilePath) { try { Add-Content -Path $Script:LogFilePath -Value $LogEntry -Encoding UTF8 } catch {} } # Best effort for logging
    if ($Level -eq 'REPORT' -and $Script:ReportFilePath) { try { Add-Content -Path $Script:ReportFilePath -Value $Message -Encoding UTF8 } catch {} }

    if (-not $NoConsole) {
        $ConsoleColor = switch ($Level) {
            'STEP'   { "Green" }
            'SUCCESS'{ "Green" }
            'WARN'   { "Yellow" }
            'ERROR'  { "Red" } # Non-terminating errors shown to console
            'FATAL'  { "Red" } # Terminating errors also shown
            'REPORT' { "Cyan" }
            default  { $null }
        }
        if ($ConsoleColor) { Write-Host $LogEntry -ForegroundColor $ConsoleColor }
        else {
            if ($Level -eq 'INFO') { Write-Verbose $LogEntry }
            elseif ($Level -eq 'DEBUG') { Write-Debug $LogEntry }
        }
    }
} # End Function Write-LogAndReport

function Initialize-Logging {
    if (-not (Test-Path -Path $Script:BaseLogReportDir -PathType Container)) {
        Write-Verbose "Creating base log/report directory: $($Script:BaseLogReportDir)"
        New-Item -Path $Script:BaseLogReportDir -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path -Path $Script:LogReportDir -PathType Container)) {
        Write-Verbose "Creating specific log/report directory: $($Script:LogReportDir)"
        New-Item -Path $Script:LogReportDir -ItemType Directory -Force | Out-Null
    }
    $Script:LogFilePath = Join-Path -Path $Script:LogReportDir -ChildPath $LogFileName
    $Script:ReportFilePath = Join-Path -Path $Script:LogReportDir -ChildPath $ReportFileName

    Write-LogAndReport -Level INFO -Message "Script execution started. Version: 3.1 (Brace Structure Review)"
    Write-LogAndReport -Level INFO -Message "Detailed Log File will be: $Script:LogFilePath"
    Write-LogAndReport -Level INFO -Message "Summary Report File will be: $Script:ReportFilePath"
    Write-LogAndReport -Level REPORT -Message "--- Azure Private DNS Deployment Log ---"
    Write-LogAndReport -Level REPORT -Message "Start Time: $(Get-Date)"
    Write-LogAndReport -Level REPORT -Message "Configuration Used:"
    Get-Variable -Scope Script -Name "SubscriptionId", "AzureLocation", "ResourceGroupName", "VNetName", "VNetAddressPrefix", "SubnetName", "SubnetAddressPrefix", "CsvFilePath", "CnameTargetDomain" |
        ForEach-Object { Write-LogAndReport -Level REPORT -Message ("  {0,-28}: {1}" -f $_.Name, $_.Value) }
    Write-LogAndReport -Level REPORT -Message ("  {0,-28}: {1}" -f "ExcludeRecordTypes", ($Script:ExcludeRecordTypes -join ', '))
    Write-LogAndReport -Level REPORT -Message "-----------------------------------------"
} # End Function Initialize-Logging

function Connect-ToAzureWithSPN {
    Write-LogAndReport -Level STEP -Message "Authenticating to Azure using Service Principal..."
    if ([string]::IsNullOrWhiteSpace($Script:TenantId) -or [string]::IsNullOrWhiteSpace($Script:ApplicationId) -or [string]::IsNullOrWhiteSpace($Script:ClientSecretPlain)) {
        throw "Azure SPN credentials (TenantId, ApplicationId, ClientSecretPlain) are not configured in the script."
    }
    $ClientSecretSecure = ConvertTo-SecureString -String $Script:ClientSecretPlain -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($Script:ApplicationId, $ClientSecretSecure)

    Write-LogAndReport -Level DEBUG -Message "Attempting Connect-AzAccount with SPN (AppID: $($Script:ApplicationId), TenantID: $($Script:TenantId))..."
    Connect-AzAccount -ServicePrincipal -Credential $Credential -Tenant $Script:TenantId -ErrorAction Stop | Out-Null
    Write-LogAndReport -Level INFO -Message "Successfully authenticated to Azure using Service Principal '$($Script:ApplicationId)'."

    Write-LogAndReport -Level DEBUG -Message "Setting Azure context to Subscription ID: $($Script:SubscriptionId)..."
    Set-AzContext -SubscriptionId $Script:SubscriptionId -ErrorAction Stop | Out-Null
    $Script:CurrentAzureContext = Get-AzContext
    Write-LogAndReport -Level SUCCESS -Message "Azure context set to Subscription: $($Script:CurrentAzureContext.Subscription.Name) ($($Script:CurrentAzureContext.Subscription.Id))."
} # End Function Connect-ToAzureWithSPN

function Ensure-AzResourceGroup {
    param([string]$Name, [string]$Location)
    Write-LogAndReport -Level STEP -Message "Ensuring Resource Group '$Name' in '$Location'..."
    $ExistingRg = Get-AzResourceGroup -Name $Name -ErrorAction SilentlyContinue
    if ($ExistingRg) {
        Write-LogAndReport -Level INFO -Message "Resource Group '$Name' already exists in location '$($ExistingRg.Location)'."
        if ($ExistingRg.Location -ne $Location) { Write-LogAndReport -Level WARN -Message "Existing RG location '$($ExistingRg.Location)' differs from configured '$Location'. Using existing RG." }
        $GlobalStats.ResourceGroupExisted++
        return $ExistingRg
    } else {
        Write-LogAndReport -Level INFO -Message "Resource Group '$Name' not found. Creating..."
        if ($PSCmdlet.ShouldProcess("Resource Group '$Name' in location '$Location'", "Create Azure Resource Group")) {
            $NewRg = New-AzResourceGroup -Name $Name -Location $Location -ErrorAction Stop
            Write-LogAndReport -Level SUCCESS -Message "Successfully created Resource Group '$Name'."
            $GlobalStats.ResourceGroupCreated++
            return $NewRg
        } else { throw "Resource Group '$Name' creation skipped. Cannot proceed." }
    }
} # End Function Ensure-AzResourceGroup

function Ensure-AzVNetAndSubnet {
    param([string]$VNetName, [string]$RgName, [string]$Location, [string]$VNetPrefix, [string]$SubnetName, [string]$SubnetPrefix)
    Write-LogAndReport -Level STEP -Message "Ensuring Virtual Network '$VNetName' and Subnet '$SubnetName' in RG '$RgName'..."
    $VNet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $RgName -ErrorAction SilentlyContinue
    if ($VNet) {
        Write-LogAndReport -Level INFO -Message "Virtual Network '$VNetName' already exists."
        $GlobalStats.VNetExisted++
        $Subnet = $VNet | Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -ErrorAction SilentlyContinue
        if (-not $Subnet) {
            Write-LogAndReport -Level WARN -Message "Subnet '$SubnetName' not found in existing VNet '$VNetName'. Adding..."
            if ($PSCmdlet.ShouldProcess("Subnet '$SubnetName' with prefix '$SubnetPrefix' to VNet '$VNetName'", "Add Subnet")) {
                Add-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VNet -AddressPrefix $SubnetPrefix -ErrorAction Stop | Out-Null
                $VNet | Set-AzVirtualNetwork -ErrorAction Stop | Out-Null
                $VNet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $RgName # Refresh VNet object
                Write-LogAndReport -Level SUCCESS -Message "Successfully added Subnet '$SubnetName' to VNet '$VNetName'."
                $GlobalStats.SubnetAddedToExistingVNet++
            } else { throw "Subnet creation skipped. Problematic for VNet links if subnet is required by other resources." }
        } else { Write-LogAndReport -Level INFO -Message "Subnet '$SubnetName' with prefix '$($Subnet.AddressPrefix)' already exists in VNet '$VNetName'."; $GlobalStats.SubnetExisted++ }
    } else {
        Write-LogAndReport -Level INFO -Message "Virtual Network '$VNetName' not found. Creating with Subnet '$SubnetName'..."
        if ($PSCmdlet.ShouldProcess("VNet '$VNetName' (Prefix: $VNetPrefix) with Subnet '$SubnetName' (Prefix: $SubnetPrefix)", "Create Azure Virtual Network")) {
            $SubnetConfig = New-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix $SubnetPrefix -ErrorAction Stop
            $VNet = New-AzVirtualNetwork -Name $VNetName -ResourceGroupName $RgName -Location $Location -AddressPrefix $VNetPrefix -Subnet $SubnetConfig -ErrorAction Stop
            Write-LogAndReport -Level SUCCESS -Message "Successfully created VNet '$VNetName' with Subnet '$SubnetName'."
            $GlobalStats.VNetCreated++; $GlobalStats.SubnetCreatedWithNewVNet++
        } else { throw "VNet creation skipped. Cannot proceed." }
    }
    return $VNet
} # End Function Ensure-AzVNetAndSubnet

function Ensure-AzPrivateDnsZone {
    param([string]$ZoneName, [string]$RgName)
    Write-LogAndReport -Level DEBUG -Message "Ensuring Azure Private DNS Zone '$ZoneName' in RG '$RgName'..."
    $PrivateDnsZone = Get-AzPrivateDnsZone -ResourceGroupName $RgName -Name $ZoneName -ErrorAction SilentlyContinue
    if ($PrivateDnsZone) {
        Write-LogAndReport -Level INFO -Message "  Private DNS Zone '$ZoneName' already exists."
        $GlobalStats.ZonesExisting++
    } else {
        Write-LogAndReport -Level INFO -Message "  Private DNS Zone '$ZoneName' not found. Creating..."
        if ($PSCmdlet.ShouldProcess("Private DNS Zone '$ZoneName' in RG '$RgName'", "Create Azure Private DNS Zone")) {
            $PrivateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $RgName -Name $ZoneName -ErrorAction Stop
            Write-LogAndReport -Level SUCCESS -Message "  Successfully created Private DNS Zone '$ZoneName'."
            $GlobalStats.ZonesCreated++
        } else {
            Write-LogAndReport -Level WARN -Message "  Private DNS Zone '$ZoneName' creation skipped. Records for this zone cannot be imported."
            $GlobalStats.ZonesFailed++
            return $null
        }
    }
    return $PrivateDnsZone
} # End Function Ensure-AzPrivateDnsZone

function Ensure-AzPrivateDnsVNetLink {
    param([string]$ZoneName, [string]$RgName, [string]$VNetId, [string]$VNetNameForLink)
    $LinkName = "link-to-$($VNetNameForLink.ToLowerInvariant().Replace('.','-').Replace(' ','-'))"
    Write-LogAndReport -Level DEBUG -Message "  Ensuring VNet Link '$LinkName' for Zone '$ZoneName' to VNet '$VNetNameForLink'..."
    $ExistingLink = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $RgName -ZoneName $ZoneName -Name $LinkName -ErrorAction SilentlyContinue
    if ($ExistingLink) {
        Write-LogAndReport -Level INFO -Message "   VNet Link '$LinkName' already exists for Zone '$ZoneName'."
        $GlobalStats.VNetLinksExisting++
    } else {
        Write-LogAndReport -Level INFO -Message "   VNet Link '$LinkName' for Zone '$ZoneName' to VNet (ID: $VNetId) does not exist. Creating..."
        $LinkParams = @{ ResourceGroupName = $RgName; ZoneName = $ZoneName; Name = $LinkName; VirtualNetworkId = $VNetId; EnableRegistration = $false; ErrorAction = 'Stop' }
        if ($PSCmdlet.ShouldProcess("VNet Link '$LinkName' (Zone: '$ZoneName', VNet: '$VNetNameForLink')", "Create Azure Private DNS VNet Link")) {
            Write-LogAndReport -Level DEBUG -Message ("   Attempting New-AzPrivateDnsVirtualNetworkLink with VNetID: {0}, EnableReg: {1}" -f $LinkParams.VirtualNetworkId, $LinkParams.EnableRegistration)
            New-AzPrivateDnsVirtualNetworkLink @LinkParams | Out-Null
            Write-LogAndReport -Level SUCCESS -Message "   Successfully created VNet Link '$LinkName'."
            $GlobalStats.VNetLinksCreated++
        } else { Write-LogAndReport -Level WARN -Message "   Skipped creation of VNet Link '$LinkName'."; $GlobalStats.VNetLinksFailed++ }
    }
} # End Function Ensure-AzPrivateDnsVNetLink

function Parse-TtlStringToSeconds {
    param([string]$TtlString, [string]$RecordIdentifierForLog)
    try { return ([System.TimeSpan]::Parse($TtlString)).TotalSeconds }
    catch { Write-LogAndReport -Level WARN -Message "Invalid TTL '$TtlString' for record '$RecordIdentifierForLog'. Using default 3600s."; return 3600 }
} # End Function Parse-TtlStringToSeconds

function Import-DnsRecordsToAzure {
    param([System.Collections.ObjectModel.Collection[PSObject]]$DnsRecords, [string]$RgName) # Changed type for $DnsRecords
    Write-LogAndReport -Level STEP -Message "Starting DNS record import into Azure Private DNS Zones..."
    $ActivityId = "ImportDNS-$(Get-Random -Maximum 99999)"
    Write-Progress -Activity "Importing DNS Records to Azure" -Status "Preparing..." -PercentComplete 0 -Id $ActivityId
    $TotalRecordsToProcess = $DnsRecords.Count
    $CurrentRecordIndex = 0

    foreach ($RecordRaw in $DnsRecords) {
        $CurrentRecordIndex++
        Write-Progress -Activity "Importing DNS Records to Azure" -Status "Processing record $CurrentRecordIndex of $TotalRecordsToProcess ($($RecordRaw.ZoneName) - $($RecordRaw.RecordName))" -PercentComplete (($CurrentRecordIndex / $TotalRecordsToProcess) * 100) -Id $ActivityId
        $GlobalStats.RecordsProcessed++; $SkipThisRecord = $false

        $CurrentZoneName = $RecordRaw.ZoneName.Trim(); $RecordNameInCsv = $RecordRaw.RecordName.Trim(); $RecordType = $RecordRaw.RecordType.Trim().ToUpperInvariant(); $RecordDataFromCsv = $RecordRaw.RecordData.Trim(); $TtlString = $RecordRaw.TTLString.Trim()
        $AzureRecordName = if ($RecordNameInCsv -eq '@') { '@' } else { $RecordNameInCsv }

        if ([string]::IsNullOrWhiteSpace($CurrentZoneName) -or [string]::IsNullOrWhiteSpace($RecordNameInCsv) -or [string]::IsNullOrWhiteSpace($RecordType) -or [string]::IsNullOrWhiteSpace($TtlString) -or ([string]::IsNullOrWhiteSpace($RecordDataFromCsv) -and $RecordType -ne "CNAME")) { Write-LogAndReport -Level WARN -Message "Skipping line ${CurrentRecordIndex} (Original): Missing essential CSV fields. Data: $($RecordRaw | Format-Table | Out-String)"; $GlobalStats.RecordsSkippedInvalid++; continue }
        if ($RecordType -in $Script:ExcludeRecordTypes) { Write-LogAndReport -Level INFO -Message "Skipping line ${CurrentRecordIndex}: Type '$RecordType' for '$($RecordNameInCsv).$CurrentZoneName' excluded."; $GlobalStats.RecordsSkippedExcludedType++; continue }
        if (-not (Get-AzPrivateDnsZone -ResourceGroupName $RgName -Name $CurrentZoneName -ErrorAction SilentlyContinue)) { Write-LogAndReport -Level WARN -Message "Skipping records for '$($RecordNameInCsv).$CurrentZoneName': Azure Zone '$CurrentZoneName' seems to be missing (creation skipped/failed)."; $GlobalStats.RecordsSkippedInvalid++; continue }

        $RecordIdentifier = "$RecordType record '$AzureRecordName' in Azure Zone '$CurrentZoneName'"; Write-LogAndReport -Level DEBUG -Message "Processing: $RecordIdentifier (CSV Data: '$RecordDataFromCsv')"
        $TtlInSeconds = Parse-TtlStringToSeconds -TtlString $TtlString -RecordIdentifierForLog $RecordIdentifier; $RecordDataFinal = $RecordDataFromCsv

        switch ($RecordType) {
            'A' { if ($RecordDataFromCsv -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { Write-LogAndReport -Level WARN -Message "DATA ERROR (A): $RecordIdentifier. Invalid IPv4 '$RecordDataFromCsv'. FIX CSV."; $GlobalStats.RecordsSkippedInvalid++; $SkipThisRecord = $true } else { $RecordDataFinal = $RecordDataFromCsv } }
            'AAAA' { if ($RecordDataFromCsv -notmatch '^[0-9a-fA-F:.]+$') {Write-LogAndReport -Level WARN -Message "DATA ERROR (AAAA): $RecordIdentifier. Invalid IPv6 '$RecordDataFromCsv'. FIX CSV."; $GlobalStats.RecordsSkippedInvalid++; $SkipThisRecord = $true } else { $RecordDataFinal = $RecordDataFromCsv } }
            'CNAME' { if ($AzureRecordName -eq '@') { Write-LogAndReport -Level WARN -Message "Invalid CNAME ${RecordIdentifier}: Apex ('@') not recommended. Skipped."; $GlobalStats.RecordsSkippedInvalid++; $SkipThisRecord = $true } else { $SafeCnameTargetDomain = $Script:CnameTargetDomain; if (-not $SafeCnameTargetDomain.EndsWith('.')) { $SafeCnameTargetDomain += '.' }; $NewCnameTarget = "$RecordNameInCsv.$SafeCnameTargetDomain"; if (-not $NewCnameTarget.EndsWith('.')) { $NewCnameTarget += '.' }; Write-LogAndReport -Level INFO -Message "Rewriting CNAME $RecordIdentifier to target '$NewCnameTarget'"; $RecordDataFinal = $NewCnameTarget } }
            default { Write-LogAndReport -Level WARN -Message "Unhandled record type '$RecordType' for import logic $RecordIdentifier. Skipped."; $GlobalStats.RecordsSkippedInvalid++; $SkipThisRecord = $true }
        }
        if ($SkipThisRecord) { continue }

        Write-LogAndReport -Level DEBUG -Message "Checking if $RecordIdentifier exists in Azure..."
        if (Get-AzPrivateDnsRecordSet -ResourceGroupName $RgName -ZoneName $CurrentZoneName -Name $AzureRecordName -RecordType $RecordType -ErrorAction SilentlyContinue) {
            Write-LogAndReport -Level INFO -Message "Skipping Add: $RecordIdentifier already exists in Azure Zone '$CurrentZoneName'."; $GlobalStats.RecordsExisted++; continue
        }

        $GlobalStats.RecordsAttemptedAdd++
        $RecordSetParams = @{ ResourceGroupName = $RgName; ZoneName = $CurrentZoneName; Name = $AzureRecordName; RecordType = $RecordType; Ttl = $TtlInSeconds; ErrorAction = 'Stop' }
        $DnsRecordsToSet = switch ($RecordType) {
            'A' { New-AzPrivateDnsARecordConfig -IPv4Address $RecordDataFinal }
            'AAAA' { New-AzPrivateDnsAAAARecordConfig -IPv6Address $RecordDataFinal }
            'CNAME' { New-AzPrivateDnsCnameRecordConfig -Cname $RecordDataFinal }
            default { Write-LogAndReport -Level ERROR -Message "FATAL Internal: Add block for unhandled type '$RecordType' for $RecordIdentifier."; $GlobalStats.RecordsFailedAdd++; continue }
        }
        $RecordSetParams.PrivateDnsRecords = $DnsRecordsToSet
        $TargetDisplayValue = ""
        try { $TargetDisplayValue = $DnsRecordsToSet.Value | Select-Object -ExpandProperty ($DnsRecordsToSet.Value.PSObject.Properties.Name | Where-Object {$_ -ne 'PSObject'}) | Out-String -Stream | ForEach-Object {$_.Trim()} } catch {$TargetDisplayValue = $DnsRecordsToSet.Value}
        $ShouldProcessMessage = "Create $RecordType record '$AzureRecordName' pointing to '$TargetDisplayValue' in Azure Zone '$CurrentZoneName'"

        if ($PSCmdlet.ShouldProcess($ShouldProcessMessage, "Create Azure Private DNS Record Set")) {
            Write-LogAndReport -Level DEBUG -Message "Attempting New-AzPrivateDnsRecordSet for $RecordIdentifier. TTL: $TtlInSeconds. Data: $TargetDisplayValue"
            try { New-AzPrivateDnsRecordSet @RecordSetParams | Out-Null; Write-LogAndReport -Level SUCCESS -Message "Successfully added $RecordIdentifier."; $GlobalStats.RecordsAddedOk++ }
            catch { Write-LogAndReport -Level ERROR -Message "Failed to add $RecordIdentifier to Azure." -ExceptionForLog $_.Exception; $GlobalStats.RecordsFailedAdd++ }
        } else { Write-LogAndReport -Level WARN -Message "Skipped Add $RecordIdentifier to Azure (-WhatIf)."; $GlobalStats.RecordsSkippedInvalid++ } # Count as skipped invalid if -WhatIf
    }
    Write-Progress -Activity "Importing DNS Records to Azure" -Completed -Id $ActivityId
} # End Function Import-DnsRecordsToAzure

function Generate-FinalReport {
    param([string]$RgName, [string]$VNetName, [string]$VNetId, [array]$UniqueZoneNames, [hashtable]$Statistics)
    Write-LogAndReport -Level STEP -Message "Generating final deployment report details..."
    Write-LogAndReport -Level REPORT -Message "`n--- Azure DNS Deployment & Import Verification ---"
    Write-LogAndReport -Level REPORT -Message "Completion Time: $(Get-Date)"
    Write-LogAndReport -Level REPORT -Message "Target Subscription ID: $($Script:CurrentAzureContext.Subscription.Id)"
    Write-LogAndReport -Level REPORT -Message "Resource Group: '$RgName' (Location: '$($Script:AzureLocation)')"
    Get-AzResourceGroup -Name $RgName | Select-Object ResourceGroupName, Location, ProvisioningState, Tags |
        Format-List | Out-String | ForEach-Object { if (-not [string]::IsNullOrWhiteSpace($_)) {Write-LogAndReport -Level REPORT -Message $_.TrimEnd()} }

    Write-LogAndReport -Level REPORT -Message "`nVirtual Network: '$VNetName'"
    Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $RgName | Select-Object Name, AddressSpace, Subnets, DnsServers, ProvisioningState, Id, Tags |
        Format-List | Out-String | ForEach-Object { if (-not [string]::IsNullOrWhiteSpace($_)) {Write-LogAndReport -Level REPORT -Message $_.TrimEnd()} }

    Write-LogAndReport -Level REPORT -Message "`nPrivate DNS Zones in '$RgName':"
    $PrivateZonesInRg = Get-AzPrivateDnsZone -ResourceGroupName $RgName
    if ($PrivateZonesInRg) {
        $PrivateZonesInRg | ForEach-Object {
            Write-LogAndReport -Level REPORT -Message ("- Zone: {0} (Record Sets: {1}, VNet Links: {2})" -f $_.Name, $_.NumberOfRecordSets, $_.NumberOfVirtualNetworkLinks)
            $Links = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $RgName -ZoneName $_.Name
            if ($Links) {
                $Links | ForEach-Object { Write-LogAndReport -Level REPORT -Message ("    Linked to: {0} (Link: {1}, Status: {2})" -f ($_.VirtualNetworkId.Split('/')[-1]), $_.Name, $_.ProvisioningState) }
            } else { Write-LogAndReport -Level REPORT -Message "    No VNet links found for this zone."}
            Write-LogAndReport -Level REPORT -Message "    Sample Records (up to 5):"
            Get-AzPrivateDnsRecordSet -ZoneName $_.Name -ResourceGroupName $RgName -Top 5 -ErrorAction SilentlyContinue | ForEach-Object {
                $RecordDataString = $_.Records | ForEach-Object {
                    # Dynamically get property name for data (e.g., IPv4Address, Cname, etc.)
                    $DataPropertyName = ($_.PSObject.Properties.Name | Where-Object {$_ -notin @("Etag", "IsAutoRegistered", "PSObject")})
                    if ($DataPropertyName.Count -eq 1) {
                        "$($DataPropertyName): $($_.($DataPropertyName))"
                    } else {
                        "ComplexData: ($($DataPropertyName -join ', '))" # Fallback for multi-property data like MX/SRV
                    }
                } | Out-String
                Write-LogAndReport -Level REPORT -Message ("      {0} ({1}) TTL: {2} Data: {3}" -f $_.Name, $_.RecordType, $_.Ttl, ($RecordDataString.Trim() -replace "`n"," | "))
            } # End Foreach RecordSet sample
        } # End Foreach Zone
    } else { Write-LogAndReport -Level REPORT -Message "  No Private DNS Zones found in Resource Group." }

    Write-LogAndReport -Level REPORT -Message "`nDNS Record Import Script Statistics:"
    $Statistics.GetEnumerator() | Sort-Object Name | ForEach-Object {
        Write-LogAndReport -Level REPORT -Message ("  {0,-35}: {1}" -f $_.Name, $_.Value)
    }
    Write-LogAndReport -Level REPORT -Message "----------------------------------------"
} # End Function Generate-FinalReport


# --- Main Orchestration Block ---
# This is where the main script logic will reside, calling the functions above.
# It's wrapped in a try/catch/finally for top-level error management.
try {
    Initialize-Logging
    Connect-ToAzureWithSPN
    $CreatedRg = Ensure-AzResourceGroup -Name $Script:ResourceGroupName -Location $Script:AzureLocation
    $CreatedVNet = Ensure-AzVNetAndSubnet -VNetName $Script:VNetName -RgName $CreatedRg.ResourceGroupName -Location $CreatedRg.Location -VNetPrefix $Script:VNetAddressPrefix -SubnetName $Script:SubnetName -SubnetPrefix $Script:SubnetAddressPrefix
    $CreatedVNetId = $CreatedVNet.Id

    Write-LogAndReport -Level STEP -Message "Reading DNS records from CSV '$($Script:CsvFilePath)' for zone processing..."
    $DnsRecordsRawForProcessing = Import-Csv -Path $Script:CsvFilePath -Header $InputCsvHeaders -ErrorAction Stop
    $GlobalStats.RecordsRead = $DnsRecordsRawForProcessing.Count
    if ($GlobalStats.RecordsRead -eq 0) { throw "Input CSV is empty. Nothing to import." }

    $UniqueZoneNames = $DnsRecordsRawForProcessing | Select-Object -ExpandProperty ZoneName -Unique | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    Write-LogAndReport -Level INFO -Message "Found $($UniqueZoneNames.Count) unique zone names for processing: $($UniqueZoneNames -join ', ')"

    foreach ($ZoneToProcess in $UniqueZoneNames) {
        Write-LogAndReport -Level STEP -Message "Processing setup for Azure Private DNS Zone: '$ZoneToProcess'..."
        $CurrentPrivateZone = Ensure-AzPrivateDnsZone -ZoneName $ZoneToProcess -RgName $CreatedRg.ResourceGroupName
        if ($CurrentPrivateZone) {
            Ensure-AzPrivateDnsVNetLink -ZoneName $CurrentPrivateZone.Name -RgName $CreatedRg.ResourceGroupName -VNetId $CreatedVNetId -VNetNameForLink $CreatedVNet.Name
        } else {
            Write-LogAndReport -Level WARN -Message "Skipping VNet link and record import for zone '$ZoneToProcess' as zone object was not obtained (likely skipped or failed creation)."
        }
    } # End foreach ZoneToProcess

    Import-DnsRecordsToAzure -DnsRecords $DnsRecordsRawForProcessing -RgName $CreatedRg.ResourceGroupName
    Generate-FinalReport -RgName $CreatedRg.ResourceGroupName -VNetName $CreatedVNet.Name -VNetId $CreatedVNetId -UniqueZoneNames $UniqueZoneNames -Statistics $GlobalStats

    # --- Determine Overall Script Success for Logging (inside main try) ---
    if ($GlobalStats.RecordsFailedAdd -gt 0 -or $GlobalStats.ZonesFailed -gt 0 -or $GlobalStats.VNetLinksFailed -gt 0) {
        Write-LogAndReport -Level WARN -Message "OVERALL SCRIPT COMPLETED WITH CRITICAL ERRORS. Check report and logs."
    } elseif ($GlobalStats.RecordsExisted -gt 0 -or $GlobalStats.RecordsSkippedInvalid -gt 0 -or $GlobalStats.RecordsSkippedExcludedType -gt 0) {
        Write-LogAndReport -Level WARN -Message "Script completed. Some records were skipped or already existed. Review report and logs."
    } else {
        Write-LogAndReport -Level SUCCESS -Message "Script completed successfully. All eligible new records processed without reported errors."
    }

} catch { # Main script try...catch
    $FatalErrorMessage = if ($_.Exception) { $_.Exception.ToString() } else { $_.ToString() } # Get full exception
    Write-LogAndReport -Level FATAL -Message "TOP LEVEL SCRIPT ERROR: $FatalErrorMessage"
    if ($Script:ReportFilePath -and (Test-Path (Split-Path $Script:ReportFilePath -Parent))) { try { Add-Content -Path $Script:ReportFilePath -Value "`nFATAL SCRIPT ERROR AT TOP LEVEL: $FatalErrorMessage" } catch {} }
    exit 1 # Exit with an error code
} finally {
    $ScriptEndTime = Get-Date
    $Duration = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
    Write-LogAndReport -Level DEBUG -Message "Script execution finished. Total duration: $($Duration.ToString('c'))" -NoConsole
    if ($Script:ReportFilePath -and (Test-Path (Split-Path $Script:ReportFilePath -Parent))) {
        try {
            Add-Content -Path $Script:ReportFilePath -Value "`nScript Execution Duration: $($Duration.ToString('c'))"
            Add-Content -Path $Script:ReportFilePath -Value "Detailed Full Log: $Script:LogFilePath"
        } catch {}
    }
    Write-LogAndReport -Level INFO -Message "Script execution concluded at $(Get-Date). Duration: $($Duration.ToString('c'))"
}

# --- Final Console Summary Output ---
Write-Host "`n--- Main Script Execution Concluded ---" -ForegroundColor Green
Write-Host "Detailed Log File: $Script:LogFilePath"
Write-Host "Summary Report File: $Script:ReportFilePath"
if ($GlobalStats.RecordsFailedAdd -gt 0 -or $GlobalStats.ZonesFailed -gt 0 -or $GlobalStats.VNetLinksFailed -gt 0) {
    Write-Warning "Execution finished with one or more CRITICAL ERRORS. Please check logs and report file."
} elseif ($GlobalStats.RecordsExisted -gt 0 -or $GlobalStats.RecordsSkippedInvalid -gt 0 -or $GlobalStats.RecordsSkippedExcludedType -gt 0) {
    Write-Warning "Execution finished. Some records already existed or were skipped (e.g., invalid data, excluded type). Check logs and report."
} else {
    Write-Host "Execution appears to have completed successfully based on script statistics."
}
Write-Host "Review the report file for details of created/verified Azure resources and import statistics."
Write-Host "--------------------------------------------------------------------"
