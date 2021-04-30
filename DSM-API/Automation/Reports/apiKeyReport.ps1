<#
.SYNOPSIS
Powershell script to output API Key details for Deep Security.

.DESCRIPTION

.PARAMETER manager
Not Required.
The -manager parameter requires a hostname or IP and port in the format hostname.local:4119 or 198.51.100.10:443.
If this parameter is not supplied this script will assume you are trying to use C1WS.

.PARAMETER apikey
Required
The -apikey parameter requires a Deep Security Manager API key with the full access role.

.EXAMPLE
.\apiKeyReport.ps1 -apikey <API-Key>

.NOTES
Example Script Output:

.\apiKeyReport - 2021-04-30-121904.csv
APIKey_ID, keyName, roleID, lockedOut, createTime, expiryDate, unsuccessfulSignInAttempts, description

#>

#requires -version 5.0

param (
    [Parameter(Mandatory=$false, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey
)

# If the $manager parameter is blank this script assumes you are trying to the C1WS/DSaaS manager.
if(!$manager) {
    Write-Host "Manager is blank, assuming C1WS."
    $manager = "app.deepsecurity.trendmicro.com"
}


# Set Certificate verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Headers to use for all rest queries.
$headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
}

# Setting up the report file and the headers for the report.
$reportTime = get-date -f yyyy-MM-dd-HHmmss
$reportName = ".\apiKeyReport - $reportTime"
$reportFile = $reportName + ".csv"
$ReportHeader = 'APIKey_ID, keyName, roleID, lockedOut, createTime, expiryDate, unsuccessfulSignInAttempts, description'

# Create the report file.
try{
    Add-Content -Path $reportFile -Value $ReportHeader -ErrorAction Stop
}
catch{
    $Error[0]
    Write-Warning "$_"
    Continue
}

function apiKeySearchFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager
    )
    # This function will list the first 5000 API keys and output certain fields to a CSV.

    $apiKeySearchURL = "https://$manager/api/apikeys/search"

    $apiKeySearchHash = @{
        maxItems = 5000
        searchCriteria = @(
            @{
                idValue = 0
                idTest = 'greater-than'
            }
        )
    }
    $apiKeySearchBody = $apiKeySearchHash | ConvertTo-Json
    
    try {
        $apiKeySearchResults = Invoke-WebRequest -Uri $apiKeySearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $apiKeySearchBody  | ConvertFrom-Json
        if ($apiKeySearchResults.apiKeys.ID) {
            
            foreach ($Item in $apiKeySearchResults.apiKeys){
                # These two lines are used to convert epoch time with milliseconds to a time/date format.
                $apikeyCreatedTime = (Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromMilliSeconds($Item.created))
                $apikeyExpiryDate = (Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromMilliSeconds($Item.expiryDate))
                
                $APIKey_ID					        = $Item.ID
                $keyName					        = $Item.keyName
                $roleID         				    = $Item.roleID
                $lockedOut         			        = $Item.active
                $createTime        			        = $apikeyCreatedTime
                $expiryDate        			        = $apikeyExpiryDate
                $descriptionCommas			        = $Item.description
                $unsuccessfulSignInAttempts         = $Item.unsuccessfulSignInAttempts
                $description				        = $descriptionCommas -replace "," -replace ""

                # Check to see if the exiration date is this past value to try to remove noise from the output.
                if ($expiryDate -eq " 12/31/1969 18:00:00") {
                    $expiryDate = "NA"
                }
    
                # Ouptut API call results to report file.
                $ReportData =  "$APIKey_ID, $keyName, $roleID, $lockedOut, $createTime, $expiryDate, $unsuccessfulSignInAttempts, $description"
                Add-Content -Path $reportFile -Value $ReportData
            }
        }
        else {
            Write-Host "No API Key IDs were returned.  May need to verify the API key has enough permission."
        }
    }
    catch {
       "Unable to complete request due to an error."
    }
}

apiKeySearchFunction $manager