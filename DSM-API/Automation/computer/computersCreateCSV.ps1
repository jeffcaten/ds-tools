param (
  [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
  [Parameter(Mandatory=$true, HelpMessage="DeepSecurity Manager API Key")][string]$apikey
)

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Initial API endpoint variables
$endPoint = "computers"
$urlCreate = "https://$manager/api/$endPoint"
$urlSearch = "https://$manager/api/$endPoint/search?expand=none"

# Headers to use for all rest queries
$headers = @{
  "api-version" = "v1"
  "api-secret-key" = $apikey
}

# Import list of computers located in the same directory as this script
$computers = Import-Csv ".\computersCreateCSV.csv"

# Loop through above CSV to do the following:
#   Look up computer by hostname in DSM to see if it exists.
#   If the computer does not exist, create the computer object.
ForEach ($computer in $computers)
{
  # Variable to lookup computer hostname
  $computerSearchHash = $computer.hostName

  # Search Critearia used to see if the host exists.
  $hashComputersSearch = @{
    maxItems = "1"
    searchCriteria = @(
      @{
        fieldName = 'hostName'
        stringTest = 'equal'
        stringValue = $computerSearchHash
      }
    )
  }
  $paramsSearch = $hashComputersSearch | ConvertTo-Json

  # Check to see if $computerSearchHash exists in the DSM
  $searchResults = Invoke-WebRequest -Uri $urlSearch -Method Post -ContentType "application/json" -Headers $headers -Body $paramsSearch | ConvertFrom-Json

  # If $computerSearchHash exists write out confirmation
  # If $computerSearchHash does not exist, create the computer object.
  If ($searchResults.computers.hostname) {
    Write-Host "Compuster object with hostname already exists: $computerSearchHash"
  }
  else {
  
    # Body used to create the computer object
    $hashComputers = @{
      "hostName"= $computer.hostName;
      "displayName"= $computer.displayName;
      "description"= $computer.description;
      "groupID"= $computer.groupID;
      "policyID"= $computer.policyID;
      "assetImportanceID"= 0;
      "relayListID"= 0
    }
    $paramsCreate = $hashComputers | convertto-json

    # Create Computer Object
    Invoke-WebRequest -Uri $urlCreate -Method Post -ContentType "application/json" -Headers $headers -Body $paramsCreate | out-null
    Write-Host "Compuster object created: $computerSearchHash"
    
  }
  # This sleep is used to avoid API rate limiting.  If you run into API rate limiting increase this number.
  Start-Sleep -m 40
}

