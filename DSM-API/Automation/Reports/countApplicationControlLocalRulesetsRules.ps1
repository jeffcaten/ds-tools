<#
.SYNOPSIS
PowerShell script to count Application Control ruleset rules.

.DESCRIPTION
This script will loop through up to 5000 application control ruleset rules in a deep security manager or deep security as a servcie account.
It will then output the ruleset ID, ruleset name and count of the rules in the ruleset.  Example:
Ruleset_ID, Name, Count
204, ip-172-31-33-145.ec2.internal, 5585

.PARAMETER manager
Not Required.
The -manager parameter requires a hostname or IP and port in the format hostname.local:4119 or 198.51.100.10:443.
If this parameter is not supplied this script will assume you are trying to use DSaaS.

.PARAMETER apikey
Required
The -apikey parameter requires a Deep Security Manager API key with the full access role.

.EXAMPLE
.\countApplicationControlLocalRulesetsRules.ps1 -apikey <API-Key>

.NOTES
Example Script Output:
RuleSetID 204
Name ip-172-31-33-145.ec2.internal
RuleCount 5585
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

$ProgressPreference = 'SilentlyContinue' # Remove progress bar for web requests

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Disabled the progress bar for invoke-webrequest.  This speeds up the request.
$ProgressPreference = 'SilentlyContinue'

# Headers to use for all rest queries
$headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
}


$reportTime = get-date -f yyyy-MM-dd-HHmmss
$reportName = "ACruleSetRuleReport - $reportTime"
$reportFile = $reportName + ".csv"
$ReportHeader = 'Ruleset_ID, Name, Count'

try{
    Add-Content -Path $reportFile -Value $ReportHeader -ErrorAction Stop
}catch{
    $Error[0]
    Write-Warning "$_"
    Continue
}

function rulesetRuleCountFunction {
    param (
        [Parameter(Mandatory=$true)][string]$manager
    )

    $rulesetSearchURL = "https://$manager/api/rulesets/search"

    $rulesetSearchHash = @{
        maxItems = "5000"
        searchCriteria = @(
            @{
                idValue = '0'
                idTest = 'greater-than'
            }
        )
    }
    $rulesetSearchBody = $rulesetSearchHash | ConvertTo-Json
    
    $rulesetSearchResults = Invoke-WebRequest -Uri $rulesetSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $rulesetSearchBody  | ConvertFrom-Json

    foreach ($item in $rulesetSearchResults.rulesets) {
        write-host "RuleSetID" $item.ID
        write-host "Name"$item.name
        $rulesetID = $item.ID
        $rulesetName = $item.name

        $lastRuleSetRuleID = 0
        $ruleSetRuleIDSearch = 0
        $ruleSetRuleCount = 0
        do {
            #while ($lastRuleSetRuleID -ne $null) {
                $rulesetRuleSearchURL = "https://$manager/api/rulesets/$rulesetID/rules/search"
                $rulesetRuleSearchHash = @{
                    maxItems = "5000"
                    searchCriteria = @(
                        @{
                            idValue = $ruleSetRuleIDSearch
                            idTest = 'greater-than'
                        }
                    )
                }
                $rulesetRuleSearchBody = $rulesetRuleSearchHash | ConvertTo-Json
                $rulesetRuleSearchResults = Invoke-WebRequest -Uri $rulesetRuleSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $rulesetRuleSearchBody  | ConvertFrom-Json
                foreach ($item in $rulesetRuleSearchResults.applicationControlRules) {
                    $lastRuleSetRuleID = $item.ID
                }
                $ruleSetRuleCount += @($rulesetRuleSearchResults.applicationControlRules).Count
                $rulesetRuleTest = @($rulesetRuleSearchResults.applicationControlRules).Count
                #write-host $ruleSetRuleCount
                if ($rulesetRuleTest -eq 0) {
                    #Write-Host "BreakLoop"
                    $breakLoop = "True"
                }
                
                #Write-Host "lastID" $lastRuleSetRuleID
                $ruleSetRuleIDSearch = $lastRuleSetRuleID
            #}
        } until ($breakLoop -eq "True")
        write-host "RuleCount" $rulesetRuleCount
        
        $ReportData = "$rulesetID, $rulesetName, $rulesetRuleCount"
        Add-Content -Path $reportFile -Value $ReportData
    }




    
}

rulesetRuleCountFunction $manager