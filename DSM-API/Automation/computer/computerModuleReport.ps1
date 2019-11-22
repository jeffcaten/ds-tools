param (
    [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="DeepSecurity Manager API Key")][string]$apikey
)

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Initial API endpoint variables
$urlSearch = "https://$manager/api/computers/search?expand=allSecurityModules"

$ID = 0
$pageSize = 500
$groupDetailsResults =  @()

# Headers to use for all rest queries
$headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
}

do {

    $hashComputersSearch = @{
    maxItems = $pageSize
    searchCriteria = @(
        @{
        idTest = 'greater-than'
        idValue = $ID
        }
    )
    }
    $paramsSearch = $hashComputersSearch | ConvertTo-Json

    $searchResults = Invoke-WebRequest -Uri $urlSearch -Method Post -ContentType "application/json" -Headers $headers -Body $paramsSearch | ConvertFrom-Json

    $lastIDCount =  $searchResults.Computers.ID | Select-Object -Last 1
    write-host $lastIDCount
    $endLoop = $searchResults.Computers.ID.count

    $i = 0
    do {


    if ($searchResults.Computers.id[$i]) {
        $groupDetails = @{
        imStatus = $searchResults.Computers.integrityMonitoring.moduleStatus.agentStatusMessage[$i]
        ipsStatus = $searchResults.Computers.intrusionPrevention.moduleStatus.agentStatusMessage[$i]
        computerID = $searchResults.Computers.ID[$i] 
        name = $searchResults.Computers.Hostname[$i]
        lastIPUsed = $searchResults.Computers.lastIPUsed[$i]

        }                           
        $groupDetailsResults += New-Object PSObject -Property $groupDetails
    }
    #write-host $i
    $i++
    }
    until ($i -eq $endLoop)
    $ID +=$pageSize
    #write-host $ID
    Start-Sleep -m 40
}
until ($endLoop -le 499)
$groupDetailsResults | export-csv -path .\computerReport.csv -NoTypeInformation -Append