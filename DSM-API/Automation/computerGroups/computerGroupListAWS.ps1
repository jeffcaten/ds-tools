param (
  [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
  [Parameter(Mandatory=$true, HelpMessage="DeepSecurity Manager API Key")][string]$apikey
)

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Initial API endpoint variables
$urlSearch = "https://$manager/api/computergroups/search"

$ID = 0
$groupDetailsResults =  @()

# Headers to use for all rest queries
$headers = @{
  "api-version" = "v1"
  "api-secret-key" = $apikey
}

do {

  $hashComputersSearch = @{
    maxItems = "500"
    searchCriteria = @(
      @{
        idTest = 'greater-than'
        idValue = $ID
      },
      @{
        numericValue = '0'
        numericTest = 'not-equal'
        fieldName = 'amazonAccountID'
      }
    )
  }
  $paramsSearch = $hashComputersSearch | ConvertTo-Json
  
  $searchResults = Invoke-WebRequest -Uri $urlSearch -Method Post -ContentType "application/json" -Headers $headers -Body $paramsSearch | ConvertFrom-Json

  write-host $searchResults.ComputerGroups.ID.count
  $endLoop = $searchResults.ComputerGroups.ID.count

  $i = 0
  do {


    if ($searchResults.ComputerGroups.amazonAccountID[$i]) {
      $groupDetails = @{
        GroupID = $searchResults.ComputerGroups.ID[$i]                
        Type = $searchResults.ComputerGroups.type[$i]
        name = $searchResults.ComputerGroups.name[$i]
        amazonAccountID = $searchResults.ComputerGroups.amazonAccountID[$i]
      }                           
      $groupDetailsResults += New-Object PSObject -Property $groupDetails
    }
    #write-host $i
    $i++
  }
  until ($i -eq $endLoop)
  $ID +=500
  write-host $ID
  Start-Sleep -m 40
}
until ($endLoop -le 499)
$groupDetailsResults | export-csv -path .\computerGroups.csv -NoTypeInformation -Append