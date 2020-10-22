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
.\awsAzureComputerReport.ps1 -manager <DSM Hostname> -apikey <API-Key>

.NOTES

Script Output file:
    .\awsAzureComputerReport.csv

#>

#requires -version 5.0

param (
    [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey
)

#$manager = "app.deepsecurity.trendmicro.com"

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Headers to use for all Api queries to T0
$headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
}

$reportTime = get-date -f yyyy-MM-dd-HHmmss
$reportName = "awsAzureComputerReport - $reportTime"

$reportFile = $reportName + ".csv"

$ReportHeader = 'hostID, awsInstanceID, azureInstanceID, hostName, DisplayName, agentStatus, agentVersion, operatingSystem, policyID, awsMetaDataName, awsMetaDataValue'


try{
    Add-Content -Path $reportFile -Value $ReportHeader -ErrorAction Stop
}catch{
    $Error[0]
    Write-Warning "$_"
    Continue
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
            $hostID					            = $Item.ID
            $awsInstanceID                      = $Item.ec2VirtualMachineSummary.instanceID
            $azureInstanceID                    = $Item.azureVMVirtualMachineSummary.instanceID
            $HostName					        = $Item.hostName
            $DisplayNameCommas			        = $Item.displayName
            $DisplayName				        = $DisplayNameCommas -replace "," -replace ""
            $AgentStatusCommas				    = $Item.computerStatus.agentStatusMessages
            $AgentStatus				        = $AgentStatusCommas -replace "," -replace ""
            $AgentVersionCommas			        = $Item.agentVersion
            $AgentVersion				        = $AgentVersionCommas -replace "," -replace ""
            $operatingSystem                    = $Item.platform
            $policyID                           = $Item.policyID
            $awsMetaDataName                        = $Item.ec2VirtualMachineSummary.metadata.name
            $awsMetaDataValue                        = $Item.ec2VirtualMachineSummary.metadata.value

            $ReportData =  "$hostID, $awsInstanceID, $AzureInstanceID, $HostName, $DisplayName, $AgentStatus, $AgentVersion, $operatingSystem, $policyID, $awsMetaDataName, $awsMetaDataValue"
            Add-Content -Path $reportFile -Value $ReportData
        }
        $computerSearchResultStatus = "Success"
    }
    else {
        $computerSearchResultStatus = "Failed"
    }
    return $computerSearchResultStatus
}

ComputerReportFunction $manager $apikey



