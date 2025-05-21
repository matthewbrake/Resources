<#
.SYNOPSIS
    Exports DNS records to a 7-column CSV format (NO HEADER ROW) suitable for
    the Deploy-AzurePrivateDnsSolution_SPN_Fixed.ps1 import script.

.DESCRIPTION
    Retrieves DNS records from specified zones (or all non-system forward zones by default)
    on a target DNS server. Excludes specified record types and internal A records
    pointing to non-internal IPs based on prefixes.
    Formats the output into a 7-column CSV string format:
    "ZoneName","RecordName","RecordType","FQDN","RecordData","TTLString","Timestamp"
    NO HEADER ROW is included in the output file itself.

.NOTES
    Author: Assistant (Based on user request, adapted from user's script)
    Date:   2023-10-28
    Requires: DnsServer module. Run with permissions to query DNS.
#>
[CmdletBinding()]
param()

# --- Configuration ---
$Script:SourceDnsServer = "127.0.0.1" # IP of your CURRENT internal AD DNS server

# Option 1: Specify zones explicitly
# $Script:ZonesToExport = @("agi.accessgroup.org", "accessgroup.org")
# Option 2: Use '*' to export all non-system zones
$Script:ZonesToExport = @("*") # <-- Set to specific list or "*"

$Script:OutputDir = "C:\temp\AzureDnsExports" # Changed to a more specific folder
$Script:TimestampFileFormat = Get-Date -Format "yyyyMMdd-HHmmss"
$Script:OutputCsvFile = Join-Path -Path $Script:OutputDir -ChildPath "DnsExportForAzure-$($Script:TimestampFileFormat).csv"

# Define internal IP prefixes (used to filter A records - export only internal ones)
$Script:InternalIpPrefixes = @("172.16.", "10.", "192.168.")

# Record types to EXCLUDE from this export (these won't be in the output file)
$Script:ExcludeRecordTypesFromExport = @(
    "SOA", # Typically not imported
    "WINS" # Example
    # Add "MX", "TXT", "SRV" here if you don't want to export them for Azure Private DNS
)

# Record types explicitly handled for RecordData formatting. Others might be skipped or generically stringified.
$HandledRecordTypesForDataFormat = @('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT')
# --- End Configuration ---

# --- Script Body ---
$ExportTimestamp = (Get-Date).ToString("o") # ISO 8601 Timestamp for the 'Timestamp' column

Import-Module DNSServer -ErrorAction Stop

if (-not (Test-Path $Script:OutputDir)) {
    Write-Host "Creating output directory: $($Script:OutputDir)"
    New-Item -ItemType Directory -Path $Script:OutputDir -Force | Out-Null
}

$CsvOutputLines = [System.Collections.Generic.List[string]]::new()

Write-Host "Connecting to DNS Server: $($Script:SourceDnsServer)" -ForegroundColor Cyan

# Get Zones based on selection
$DnsZones = $null
if ($Script:ZonesToExport -contains '*') {
    Write-Host "Exporting all non-system forward lookup zones..."
    $SystemZonePatterns = @("..TrustAnchors", "_msdcs.*", "..RootHints", "RootDNSServers")
    try {
        $AllZones = Get-DnsServerZone -ComputerName $Script:SourceDnsServer -ErrorAction Stop
        $DnsZones = $AllZones | Where-Object {
            $_.IsReverseLookupZone -eq $false -and
            $_.ZoneType -ne 'Cache' -and
            $_.ZoneName -ne '.' -and
            ($SystemZonePatterns | ForEach-Object { $_.ZoneName -notlike $_ } | Measure-Object -Sum).Sum -eq $SystemZonePatterns.Count
        }
    } catch {
        Write-Error "Could not retrieve all zones from '$($Script:SourceDnsServer)'. Error: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "Exporting specified zones: $($Script:ZonesToExport -join ', ')"
    try {
        $DnsZones = Get-DnsServerZone -ComputerName $Script:SourceDnsServer | Where-Object { $Script:ZonesToExport -contains $_.ZoneName }
    } catch {
        Write-Error "Could not retrieve specified zones from '$($Script:SourceDnsServer)'. Error: $($_.Exception.Message)"
        exit 1
    }
}

if (!$DnsZones) {
    Write-Error "No matching zones found on '$($Script:SourceDnsServer)'."
    exit 1
}

Write-Host "Found zones for export: $($DnsZones.ZoneName -join ', ')"
Write-Host "Processing records..."

foreach ($zone in $DnsZones) {
    Write-Host " Processing Zone: $($zone.ZoneName)"
    $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ComputerName $Script:SourceDnsServer -ErrorAction SilentlyContinue

    foreach ($record in $records) {
        $recordTypeStr = $record.RecordType.ToString().ToUpperInvariant()
        $hostname = $record.HostName # This is '@' or the relative name
        $ttlString = $record.TimeToLive.ToString() # Format "HH:mm:ss"

        # 1. Filter by $Script:ExcludeRecordTypesFromExport
        if ($Script:ExcludeRecordTypesFromExport -contains $recordTypeStr) {
            Write-Verbose "  Skipping (Excluded Type): $hostname ($recordTypeStr) in $($zone.ZoneName)"
            continue
        }

        # 2. Filter root NS records
        if ($recordTypeStr -eq 'NS' -and $hostname -eq '@') {
            Write-Verbose "  Skipping (Root NS): @ NS in $($zone.ZoneName)"
            continue
        }

        # --- Prepare data for the 7 columns ---
        $OutZoneName = $zone.ZoneName
        $OutRecordName = $hostname
        $OutRecordType = $recordTypeStr
        $OutFQDN = if ($hostname -eq '@') { $zone.ZoneName } else { "$hostname.$($zone.ZoneName)" }
        if (-not $OutFQDN.EndsWith('.')) { $OutFQDN += '.' }

        $OutRecordData = ""
        $OutTimestampForCsv = $ExportTimestamp # Consistent timestamp for this export run

        # Process RecordData based on type
        $SkipThisRecordDueToData = $false
        switch ($record.RecordType) {
            'A' {
                $ip = $record.RecordData.IPv4Address.IPAddressToString
                $isInternal = $false
                foreach ($prefix in $Script:InternalIpPrefixes) { if ($ip.StartsWith($prefix)) { $isInternal = $true; break } }
                if ($isInternal) { $OutRecordData = $ip }
                else { Write-Verbose "  Skipping (External A): $hostname -> $ip in $($zone.ZoneName)"; $SkipThisRecordDueToData = $true }
            }
            'AAAA'  { $OutRecordData = $record.RecordData.IPv6Address.IPAddressToString } # Assuming all AAAA are desired
            'CNAME' { $OutRecordData = $record.RecordData.HostNameAlias }
            'MX'    { $OutRecordData = "$($record.RecordData.Preference) $($record.RecordData.MailExchange)" }
            'NS'    { $OutRecordData = $record.RecordData.NameServer } # For delegations
            'PTR'   { $OutRecordData = $record.RecordDdata.PtrDomainName }
            'SRV'   { $OutRecordData = "$($record.RecordData.Priority) $($record.RecordData.Weight) $($record.RecordData.Port) $($record.RecordData.DomainName)" } # Fixed $_. to $record.
            'TXT'   { $OutRecordData = ($record.RecordData.DescriptiveText -join ';').Trim() } # Join multiple TXT strings with semicolon
            default {
                Write-Warning "  Unhandled RecordType for data formatting: $($record.RecordType) for $hostname in $($zone.ZoneName). Skipping this record."
                $SkipThisRecordDueToData = $true
            }
        }

        if ($SkipThisRecordDueToData) { continue }
        if ([string]::IsNullOrWhiteSpace($OutRecordData) -and $OutRecordType -ne "CNAME") { # CNAME can have its RecordData generated by import script
             Write-Verbose "  Skipping (Empty Processed RecordData for non-CNAME): $hostname ($recordTypeStr) in $($zone.ZoneName)"
             continue
        }


        # Escape double quotes within data fields
        $OutZoneName,$OutRecordName,$OutRecordType,$OutFQDN,$OutRecordData,$ttlString,$OutTimestampForCsv =
        ($OutZoneName -replace '"', '""'), ($OutRecordName -replace '"', '""'), ($OutRecordType -replace '"', '""'),
        ($OutFQDN -replace '"', '""'), ($OutRecordData -replace '"', '""'), ($ttlString -replace '"', '""'),
        ($OutTimestampForCsv -replace '"', '""')

        $CsvLine = """$OutZoneName"",""$OutRecordName"",""$OutRecordType"",""$OutFQDN"",""$OutRecordData"",""$ttlString"",""$OutTimestampForCsv"""
        $CsvOutputLines.Add($CsvLine)
    }
}

# Export the filtered records (NO HEADER)
if ($CsvOutputLines.Count -gt 0) {
    Set-Content -Path $Script:OutputCsvFile -Value $CsvOutputLines -Encoding UTF8 -ErrorAction Stop
    Write-Host "--------------------------------------------------" -ForegroundColor Cyan
    Write-Host "$($CsvOutputLines.Count) DNS records exported successfully (NO HEADER ROW) to $($Script:OutputCsvFile)" -ForegroundColor Green
} else {
    Write-Warning "No records were eligible for export based on the criteria."
}
Write-Host "--------------------------------------------------" -ForegroundColor Cyan
