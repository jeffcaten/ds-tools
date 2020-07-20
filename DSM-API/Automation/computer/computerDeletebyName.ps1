<#
Example usage:
.\computerDeletebyName.ps1 -manager app.deepsecurity.trendmicro.com -apikey <API-Key> -computername test

#>

param (
    [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey,
    [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$computerName
)

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Headers to use for all rest queries
$headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
}

function computerSearchByNameFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Policy Name")][string]$computerName
    )

    $computerSearchURL = "https://$manager/api/computers/search"

    $computerSearchHash = @{
        maxItems = "1"
        searchCriteria = @(
            @{
                fieldName = 'hostName'
                stringTest = 'equal'
                stringValue = $computerName
            }
        )
    }
    $computerSearchBody = $computerSearchHash | ConvertTo-Json
    
    $computerSearchResults = Invoke-WebRequest -Uri $computerSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $computerSearchBody  | ConvertFrom-Json

    if($computerSearchResults.computers.ID) {
        #write-host $computerSearchResults.computers.ID
        $deleteHostID = $computerSearchResults.computers.ID
        #write-host $computerSearchResults.computers.hostName
    }
    else {
        Write-Host "Unable to find computer with that host ID"
    }


    return $deleteHostID
}

function deleteComputer {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Computer host ID")][string]$deleteHostID
    )

    $computerSearchURL = "https://$manager/api/computers/$deleteHostID"
    
    $computerDeleteResults = Invoke-WebRequest -Uri $computerSearchURL -Method Delete -ContentType "application/json" -Headers $headers | ConvertFrom-Json

}


$deleteHostID = computerSearchByNameFunction $manager $computerName
#write-host $deleteHostID

if($deleteHostID) {
    deleteComputer $manager $deleteHostID
    Write-Host "The following computer was deleted from the DSM:" $computerName
}
else {
    Write-Host "Unable to delete computer.  The following Computer may not exist in the DSM:"$computerName
}