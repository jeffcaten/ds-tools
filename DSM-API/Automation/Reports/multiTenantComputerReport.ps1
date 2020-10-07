<#
Example to run:
.\multiTenantComputerReport.ps1 -manager <DSM Hostname> -apikey <API-Key>
#>

param (
    [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey
)

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Headers to use for all rest queries
$headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
}


$REPORTNAME = "mtComputerReport"

$REPORTFILE = $REPORTNAME + ".csv"

<#
if ((Test-Path $REPORTFILE) -eq $true){
    $BackupDate          = get-date -format MMddyyyy-HHmm
    $BackupReportName    = $REPORTNAME + "_" + $BackupDate + ".csv"
    copy-item -Path $REPORTFILE -Destination $BackupReportName
    Remove-item $REPORTFILE
}
#>

$ReportHeader = 'TenantName, Host_ID, HostName, DisplayName, AgentStatus, AgentVersion, AntiMalwareState, WebReputationState, FirewallState, IntrusionPreventionState, IntegrityMnitoringState, LogInspectionState, ApplicaionControlState'
Add-Content -Path $REPORTFILE -Value $ReportHeader



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
    
    $tenantSearchResults = Invoke-WebRequest -Uri $tenantSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $tenantSearchBody  | ConvertFrom-Json
    #write-host $tenantSearchResults.tenants.name
    #write-host $tenantSearchResults.tenants.ID


    

    #$tenantID =  $tenantSearchResults.tenants.ID
    #return $tenantID
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
    
    $createTenantApiKeyResults = Invoke-WebRequest -Uri $createTenantApiKeyURL -Method Post -ContentType "application/json" -Headers $headers -Body $createTenantApiKeyBody  | ConvertFrom-Json
    #write-host $createTenantApiKeyResults.secretKey
    #write-host $createTenantApiKeyResults.ID
    $tenantApiKeyID = $createTenantApiKeyResults.ID
    $tenantApiKey = $createTenantApiKeyResults.secretKey
     $returnArray = @()

    $returnArray += $tenantApiKeyID
    $returnArray += $tenantApiKey

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
            $Host_ID					= $Item.ID
            $HostName					= $Item.hostName
            $DisplayName				= $Item.displayName
            $AgentStatus				= $Item.computerStatus.agentStatusMessages
            $AgentVersion				= $Item.agentVersion
            $AntiMalwareState			= $Item.antiMalware.state
            $WebReputationState			= $Item.webReputation.state
            $FirewallState				= $Item.firewall.state 
            $IntrusionPreventionState	= $Item.intrusionPrevention.state
            $IntegrityMnitoringState	= $Item.integrityMonitoring.state
            $LogInspectionState			= $Item.logInspection.state
            $ApplicaionControlState		= $Item.applicationControl.state

            $ReportData =  "$TenantName, $Host_ID, $HostName, $DisplayName, $AgentStatus, $AgentVersion, $AntiMalwareState, $WebReputationState, $FirewallState, $IntrusionPreventionState, $IntegrityMnitoringState, $LogInspectionState, $ApplicaionControlState"
            Add-Content -Path $REPORTFILE -Value $ReportData
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
            $Host_ID					= $Item.ID
            $HostName					= $Item.hostName
            $DisplayName				= $Item.displayName
            $AgentStatus				= $Item.computerStatus.agentStatusMessages
            $AgentVersion				= $Item.agentVersion
            $AntiMalwareState			= $Item.antiMalware.state
            $WebReputationState			= $Item.webReputation.state
            $FirewallState				= $Item.firewall.state 
            $IntrusionPreventionState	= $Item.intrusionPrevention.state
            $IntegrityMnitoringState	= $Item.integrityMonitoring.state
            $LogInspectionState			= $Item.logInspection.state
            $ApplicaionControlState		= $Item.applicationControl.state
    
            $ReportData =  "$TenantName, $Host_ID, $HostName, $DisplayName, $AgentStatus, $AgentVersion, $AntiMalwareState, $WebReputationState, $FirewallState, $IntrusionPreventionState, $IntegrityMnitoringState, $LogInspectionState, $ApplicaionControlState"
            Add-Content -Path $REPORTFILE -Value $ReportData
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

foreach ($i in $tenantSearchResults.tenants) {
    $tenantID = $i.ID
    $TenantName = $i.name

    # Create an API key for each tenant
    $tenantApiKeyArray = createTenantApiKeyFunction $manager $tenantID
    if ($tenantApiKeyArray[0]) {
        $apiKeyID = $tenantApiKeyArray[0]
        $tenantApiKey = $tenantApiKeyArray[1]
        # Get computer list and output to report file.
        
        $tenantComputerReportStatus = tenantComputerReportFunction $manager $tenantApiKey $TenantName
        
        # Delete the API key from each tenant.
        $deleteTenantApiKeyStatus =  deleteTenantApiKey $manager $tenantApiKey $apiKeyID
        write-host "$TenantName - $tenantComputerReportStatus - $deleteTenantApiKeyStatus"
    }

}

# Get computer list from T0 and output to repot file.
$ComputerReportStatus = ComputerReportFunction $manager $apikey
write-host "T0 - $ComputerReportStatus"