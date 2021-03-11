<#
.SYNOPSIS
Powershell script to generate a computer report from a Deep Security Environment.

.DESCRIPTION
The script will output the list of computers with certain fields to a CSV.

.PARAMETER manager
The -manager parameter requires a hostname or IP and port in the format hostname.local:4119 or 198.51.100.10:443

.PARAMETER apikey
The -apikey parameter requires a Deep Security Manager API key with the full access role.

.EXAMPLE
.\singleTenantComputerReport.ps1 -manager <DSM Hostname> -apikey <API-Key>

.NOTES
Example Script Output:

Script Output file:
    .\computerReport.csv
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

# Setting variables for CSV and CSV headers
$reportTime = get-date -f yyyy-MM-dd-HHmmss
$reportName = "computerReport - $reportTime"
$reportFile = $reportName + ".csv"
$ReportHeader = 'Host_ID, HostName, DisplayName, AgentStatus, lastAgentCommunication, AgentVersion, agentPlatform, groupID, agentPolicy, AntiMalwareState, WebReputationState, FirewallState, IntrusionPreventionState, IntrusionPreventionStatus, IntegrityMnitoringState, LogInspectionState, ApplicaionControlState, lastIPUsed, smartScanAgentPattern'

# Writing out the CSV and CSV headers.
# Try cat to throw a warning if the file can't be created
try{
    Add-Content -Path $reportFile -Value $ReportHeader -ErrorAction Stop
}catch{
    $Error[0]
    Write-Warning "$_"
    Continue
}

# Function to search for computers and output the results the CSV created above.
function ComputerReportFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey
    )

    $headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
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
            $lastAgentCommunication             = $Item.lastAgentCommunication
            $AgentVersionCommas			        = $Item.agentVersion
            $AgentVersion				        = $AgentVersionCommas -replace "," -replace ""
            $agentPlatform                      = $Item.platform
            $groupID                            = $Item.groupID
            $agentPolicy                        = $Item.policyID
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
            $smartScanAgentPattern              = $item.securityUpdates.antiMalware | Where-Object {$_.name -eq "Smart Scan Agent Pattern"} | ForEach-Object {$_.version}

            $ReportData =  "$Host_ID, $HostName, $DisplayName, $AgentStatus, $lastAgentCommunication, $AgentVersion, $agentPlatform, $groupID, $agentPolicy, $AntiMalwareState, $WebReputationState, $FirewallState, $IntrusionPreventionState, $IntrusionPreventionStatus, $IntegrityMnitoringState, $LogInspectionState, $ApplicaionControlState, $lastIPUsed, $smartScanAgentPattern"
            Add-Content -Path $reportFile -Value $ReportData

        }
        $computerSearchResultStatus = "Success"
    }
    else {
        $computerSearchResultStatus = "Failed"
    }
    return $computerSearchResultStatus
}

$ComputerReportStatus = ComputerReportFunction $manager $apikey
write-host "Report Status: " $ComputerReportStatus 