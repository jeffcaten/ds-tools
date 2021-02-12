<#
.SYNOPSIS
Powershell script to generate a computer report from T0 and Tn in a multi-tenant Deep Security Environment.

.DESCRIPTION
The multiTenantComputerReport script will log use an API key from T0 to get a list of active tenants.  
The script will then create and ApiKey for that tenant then use that new Apikey to get a list of computers from that tenant.  
The newly create tenant Apikey will be deleted and the script will move on to the next tenant.
The script will output the list of computers with certain fields to a CSV.

.PARAMETER manager
The -manager parameter requires a hostname or IP and port in the format hostname.local:4119 or 198.51.100.10:443

.PARAMETER apikey
The -apikey parameter requires a Deep Security Manager API key with the full access role.

.EXAMPLE
.\multiTenantComputerReport.ps1 -manager <DSM Hostname> -apikey <API-Key>

.NOTES
Example Script Output:

    tenantName -createTenantApiKey - computerReport - deleteTenantApiKey
    jeff - Success - Success - Success
    test-1 - Success - Success - Success
    T0 - N/A - Success - N/A

Script Output file:
    .\mtComputerReport.csv

This script should clean up the ApiKeys that it creates.  If the script can't delete the ComputerReport ApiKey for some reason an adminitrator will need to clean up the left over ApiKey from the effected tenants.
#>
#requires -version 5.0

param (
    [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey
)

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Headers to use for all Api queries to T0
$headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
}

$reportTime = get-date -f yyyy-MM-dd-HHmmss
$reportName = "mtComputerReport - $reportTime"

$reportFile = $reportName + ".csv"

<#
if ((Test-Path $reportFile) -eq $true){
    $BackupDate          = get-date -format MMddyyyy-HHmm
    $BackupReportName    = $reportName + "_" + $BackupDate + ".csv"
    copy-item -Path $reportFile -Destination $BackupReportName
    Remove-item $reportFile
}
#>

$ReportHeader = 'TenantName, Host_ID, HostName, DisplayName, AgentStatus, AgentVersion, Platform, AntiMalwareState, WebReputationState, FirewallState, IntrusionPreventionState, IntrusionPreventionStatus, IntegrityMnitoringState, LogInspectionState, ApplicaionControlState, lastIPUsed, ipAddress, macAddress'

try{
    Add-Content -Path $reportFile -Value $ReportHeader -ErrorAction Stop
}catch{
    $Error[0]
    Write-Warning "$_"
    Continue
}

function tenatSearchFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager
    )

    $tenantSearchURL = "https://$manager/api/tenants/search"

    $tenantSearchHash = @{
    maxItems = '5000'
    searchCriteria = @(
            @{
                choiceValue = 'active'
                choiseTest = 'equal'
                fieldName = 'tenantState'
            }
        )
    }
    $tenantSearchBody = $tenantSearchHash | ConvertTo-Json
    
    $tenantSearchResults = Invoke-WebRequest -Uri $tenantSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $tenantSearchBody   | ConvertFrom-Json

    return $tenantSearchResults
}

function createTenantApiKeyFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Tenant ID")][string]$tenantID
    )

    $createTenantApiKeyURL = "https://$manager/api/tenants/$tenantID/apikeys"

    [long]$timestamp = (([datetime]::UtcNow)-(Get-Date -Date '1/1/1970')).TotalMilliseconds + 2000000

    $createTenantApiKeyHash = @{
        keyName = 'ComputerReport'
        description = 'Temp API Key for Computer Report'
        locale = 'en-US'
        timeZone = 'America/Chicago'
        active = 'true'
        expiryDate = $timestamp
    }
    $createTenantApiKeyBody = $createTenantApiKeyHash | ConvertTo-Json
    
    try {
        $createTenantApiKeyResults = Invoke-WebRequest -Uri $createTenantApiKeyURL -Method Post -ContentType "application/json" -Headers $headers -Body $createTenantApiKeyBody  | ConvertFrom-Json
    }
    catch {
        $tenantApiKeyCreateStatus = "Failed"
    }

    if ($createTenantApiKeyResults.secretKey) {
        $tenantApiKeyCreateStatus = "Success"
    }
    else {
        $tenantApiKeyCreateStatus = "Failed"
    }

    $tenantApiKeyID = $createTenantApiKeyResults.ID
    $tenantApiKey = $createTenantApiKeyResults.secretKey
    $returnArray = @()

    $returnArray += $tenantApiKeyID
    $returnArray += $tenantApiKey
    $returnArray += $tenantApiKeyCreateStatus

    return ,$returnArray

}

function ComputerReportFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey
    )

    $headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
    }

    $TenantName = "T0"
    
    $computerSearchURL = "https://$manager/api/computers/search"

    $computerSearchHash = @{
        maxItems = "5000"
        searchCriteria = @(
            @{
                idValue = '0'
                idTest = 'greater-than'
            }
        )
    }
    $computerSearchBody = $computerSearchHash | ConvertTo-Json
    
    try {
        $computerSearchResults = Invoke-WebRequest -Uri $computerSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $computerSearchBody  | ConvertFrom-Json
    }
    catch {
        $computerSearchResultStatus = "Failed"
    }
    
    if ($computerSearchResults) {
        foreach ($Item in $computerSearchResults.computers){
            $Host_ID					        = $Item.ID
            $HostName					        = $Item.hostName
            $DisplayNameCommas			        = $Item.displayName
            $DisplayName				        = $DisplayNameCommas -replace "," -replace ""
            $AgentStatusCommas				    = $Item.computerStatus.agentStatusMessages
            $AgentStatus				        = $AgentStatusCommas -replace "," -replace ""
            $AgentVersionCommas			        = $Item.agentVersion
            $AgentVersion				        = $AgentVersionCommas -replace "," -replace ""
            $PlatformCommas                     = $Item.platform
            $Platform                           = $PlatformCommas -replace "," -replace ""
            $AntiMalwareStateCommas			    = $Item.antiMalware.state
            $AntiMalwareState			        = $AntiMalwareStateCommas -replace "," -replace ""
            $WebReputationStateCommas	        = $Item.webReputation.state
            $WebReputationState			        = $WebReputationStateCommas -replace "," -replace ""
            $FirewallStateCommas		        = $Item.firewall.state 
            $FirewallState				        = $FirewallStateCommas -replace "," -replace ""
            $IntrusionPreventionStateCommas     = $Item.intrusionPrevention.state
            $IntrusionPreventionState	        = $IntrusionPreventionStateCommas -replace "," -replace ""
            $IntrusionPreventionStatusCommas	= $Item.intrusionPrevention.moduleStatus.agentStatusMessage
            $IntrusionPreventionStatus          = $IntrusionPreventionStatusCommas -replace "," -replace ""
            $IntegrityMnitoringStateCommas      = $Item.integrityMonitoring.state
            $IntegrityMnitoringState	        = $IntegrityMnitoringStateCommas -replace "," -replace ""
            $LogInspectionStateCommas	        = $Item.logInspection.state
            $LogInspectionState			        = $LogInspectionStateCommas -replace "," -replace ""
            $ApplicaionControlStateCommas       = $Item.applicationControl.state
            $ApplicaionControlState		        = $ApplicaionControlStateCommas -replace "," -replace ""
            $lastIPUsed                         = $Item.lastIPUsed
            [string]$ipAddress                  = $Item.interfaces.interfaces.IPs
            [string]$macAddress                 = $Item.interfaces.interfaces.MAC


            $ReportData =  "$TenantName, $Host_ID, $HostName, $DisplayName, $AgentStatus, $AgentVersion, $Platform , $AntiMalwareState, $WebReputationState, $FirewallState, $IntrusionPreventionState, $IntrusionPreventionStatus, $IntegrityMnitoringState, $LogInspectionState, $ApplicaionControlState, $lastIPUsed, $ipAddress, $macAddress"
            Add-Content -Path $reportFile -Value $ReportData
        }
        $computerSearchResultStatus = "Success"
    }
    else {
        $computerSearchResultStatus = "Failed"
    }
    return $computerSearchResultStatus
}

function tenantComputerReportFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$tenantApiKey,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$TenantName
    )

    $headers = @{
    "api-version" = "v1"
    "api-secret-key" = $tenantApiKey
    }
    
    $computerSearchURL = "https://$manager/api/computers/search"

    $computerSearchHash = @{
        maxItems = "5000"
        searchCriteria = @(
            @{
                idValue = '0'
                idTest = 'greater-than'
            }
        )
    }
    $computerSearchBody = $computerSearchHash | ConvertTo-Json
    
    try {
        $computerSearchResults = Invoke-WebRequest -Uri $computerSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $computerSearchBody  | ConvertFrom-Json   
    }
    catch {
        $computerSearchResultStatus = "Failed"
    }

    if ($computerSearchResults) {
        foreach ($Item in $computerSearchResults.computers){
            $Host_ID					        = $Item.ID
            $HostName					        = $Item.hostName
            $DisplayNameCommas			        = $Item.displayName
            $DisplayName				        = $DisplayNameCommas -replace "," -replace ""
            $AgentStatusCommas				    = $Item.computerStatus.agentStatusMessages
            $AgentStatus				        = $AgentStatusCommas -replace "," -replace ""
            $AgentVersionCommas			        = $Item.agentVersion
            $AgentVersion				        = $AgentVersionCommas -replace "," -replace ""
            $PlatformCommas                     = $Item.platform
            $Platform                           = $PlatformCommas -replace "," -replace ""
            $AntiMalwareStateCommas			    = $Item.antiMalware.state
            $AntiMalwareState			        = $AntiMalwareStateCommas -replace "," -replace ""
            $WebReputationStateCommas	        = $Item.webReputation.state
            $WebReputationState			        = $WebReputationStateCommas -replace "," -replace ""
            $FirewallStateCommas		        = $Item.firewall.state 
            $FirewallState				        = $FirewallStateCommas -replace "," -replace ""
            $IntrusionPreventionStateCommas     = $Item.intrusionPrevention.state
            $IntrusionPreventionState	        = $IntrusionPreventionStateCommas -replace "," -replace ""
            $IntrusionPreventionStatusCommas	= $Item.intrusionPrevention.moduleStatus.agentStatusMessage
            $IntrusionPreventionStatus          = $IntrusionPreventionStatusCommas -replace "," -replace ""
            $IntegrityMnitoringStateCommas      = $Item.integrityMonitoring.state
            $IntegrityMnitoringState	        = $IntegrityMnitoringStateCommas -replace "," -replace ""
            $LogInspectionStateCommas	        = $Item.logInspection.state
            $LogInspectionState			        = $LogInspectionStateCommas -replace "," -replace ""
            $ApplicaionControlStateCommas       = $Item.applicationControl.state
            $ApplicaionControlState		        = $ApplicaionControlStateCommas -replace "," -replace ""
            $lastIPUsed                         = $Item.lastIPUsed
            [string]$ipAddress                  = $Item.interfaces.interfaces.IPs
            [string]$macAddress                 = $Item.interfaces.interfaces.MAC
    
            $ReportData =  "$TenantName, $Host_ID, $HostName, $DisplayName, $AgentStatus, $AgentVersion, $Platform, $AntiMalwareState, $WebReputationState, $FirewallState, $IntrusionPreventionState, $IntrusionPreventionStatus, $IntegrityMnitoringState, $LogInspectionState, $ApplicaionControlState, $lastIPUsed, $ipAddress, $macAddress"
            Add-Content -Path $reportFile -Value $ReportData
        }
        $computerSearchResultStatus = "Success"
    }
    else {
        $computerSearchResultStatus = "Failed"
    }
    return $computerSearchResultStatus
}

function deleteTenantApiKey {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$tenantApiKey,
        [Parameter(Mandatory=$true, HelpMessage="Tenant API Key ID")][string]$apiKeyID
    )

    $deleteTenantApiKeyheaders = @{
        "api-version" = "v1"
        "api-secret-key" = $tenantApiKey
    }

    $deleteTenantApiKeyURL = "https://$manager/api/apikeys/$apiKeyID"
    try {
        $deleteTenantApiKeyResults = Invoke-WebRequest -Uri $deleteTenantApiKeyURL -Method DELETE -ContentType "application/json" -Headers $deleteTenantApiKeyheaders
    }
    catch {
        $deleteTenantApiKeyStatus = "Failed"
    }

    $statusCodeResults = $deleteTenantApiKeyResults.StatusCode
    if ($statusCodeResults -eq 204) {
        $deleteTenantApiKeyStatus = "Success"
    }
    else {
        $deleteTenantApiKeyStatus = "Failed"
    }
    return $deleteTenantApiKeyStatus
}


# Search for all tenants in T0
$tenantSearchResults = tenatSearchFunction $manager

if ($tenantSearchResults) {
    write-host "tenantName -createTenantApiKey - computerReport - deleteTenantApiKey"

    foreach ($i in $tenantSearchResults.tenants) {
        $tenantID = $i.ID
        $TenantName = $i.name

        # Create an API key for each tenant
        $tenantApiKeyArray = createTenantApiKeyFunction $manager $tenantID
        if ($tenantApiKeyArray[0]) {
            $apiKeyID = $tenantApiKeyArray[0]
            $tenantApiKey = $tenantApiKeyArray[1]
            $tenantApiKeyCreateStatus = $tenantApiKeyArray[2]
            # Get computer list and output to report file.
            
            $tenantComputerReportStatus = tenantComputerReportFunction $manager $tenantApiKey $TenantName
            
            # Delete the API key from each tenant.
            $deleteTenantApiKeyStatus =  deleteTenantApiKey $manager $tenantApiKey $apiKeyID
            write-host "$TenantName - $tenantApiKeyCreateStatus - $tenantComputerReportStatus - $deleteTenantApiKeyStatus"
        }
        Start-Sleep -m 40
    }

    # Get computer list from T0 and output to report file.
    $ComputerReportStatus = ComputerReportFunction $manager $apikey
    write-host "T0 - N/A - $ComputerReportStatus - N/A" 
}
