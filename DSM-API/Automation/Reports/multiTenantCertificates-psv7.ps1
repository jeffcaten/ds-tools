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
#requires -version 7.0

param (
    [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey
)

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Disabled the progress bar for invoke-webrequest.  This speeds up the request.
$ProgressPreference = 'SilentlyContinue'

# Headers to use for all Api queries to T0
$headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
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
    
    $tenantSearchResults = Invoke-WebRequest -Uri $tenantSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $tenantSearchBody -SkipCertificateCheck   | ConvertFrom-Json

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
    
    #try {
        $createTenantApiKeyResults = Invoke-WebRequest -Uri $createTenantApiKeyURL -Method Post -ContentType "application/json" -Headers $headers -Body $createTenantApiKeyBody -SkipCertificateCheck  | ConvertFrom-Json
    #}
    #catch {
    #    $tenantApiKeyCreateStatus = "Failed"
    #}

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


function tenantCertificateReportFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$tenantApiKey,
        [Parameter(Mandatory=$false, HelpMessage="Deep Security Manager API Key")][string]$TenantName
    )

    $headers = @{
    "api-version" = "v1"
    "api-secret-key" = $tenantApiKey
    }
    
    $computerSearchURL = "https://$manager/api/certificates"

    <#
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
    #>

    $computerSearchResults = Invoke-WebRequest -Uri $computerSearchURL -Method Get -ContentType "application/json" -Headers $headers -SkipCertificateCheck  | ConvertFrom-Json  
    
    #Write-Host $computerSearchResults.certificates.certificateDetails.serialNumber
    #Write-Host $TenantName
    $certificateSerialNumber = $computerSearchResults.certificates.certificateDetails.serialNumber
    $certificateCount = 0
    foreach ($item in $computerSearchResults.certificates) {
        $certificateCount+=1
    }

    return $certificateCount
}

function addCertificate{
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$tenantApiKey,
        [Parameter(Mandatory=$false, HelpMessage="Certificate")][string]$certificate
    )

    $addCertificatehURL = "https://$manager/api/certificates"
    $headers = @{
    "api-version" = "v1"
    "api-secret-key" = $tenantApiKey
    "Content-Type" = "application/json"
    }
    
    $bodyHas = @{
        "certificate" = $certificate
        "trusted" = "true"
        "purpose" = "SSL"
    }
    $body = $bodyHas | ConvertTo-Json

    try {
        $addCertificateResults = Invoke-WebRequest $addCertificatehURL -Method 'POST' -Headers $headers -Body $body -SkipCertificateCheck -SkipHttpErrorCheck  
    }
    catch {
        $addCertificateStatus = "Failed to add certificate"
    }
    return $addCertificateStatus  
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
        $deleteTenantApiKeyResults = Invoke-WebRequest -Uri $deleteTenantApiKeyURL -Method DELETE -ContentType "application/json" -Headers $deleteTenantApiKeyheaders -SkipCertificateCheck
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


# Search for all active tenants in T0
$tenantSearchResults = tenatSearchFunction $manager

if ($tenantSearchResults) {
    write-host "tenantName, createTenantApiKey, Number of Certificates, deleteTenantApiKey"

    foreach ($tenant in $tenantSearchResults.tenants) {
        $tenantID = $tenant.ID
        $TenantName = $tenant.name

        # Create an API key for each tenant
        $tenantApiKeyArray = createTenantApiKeyFunction $manager $tenantID
        Write-Host $tenantApiKeyArray
        if ($tenantApiKeyArray[0]) {
            $apiKeyID = $tenantApiKeyArray[0]
            $tenantApiKey = $tenantApiKeyArray[1]
            $tenantApiKeyCreateStatus = $tenantApiKeyArray[2]
            
            # Get certificate list and output to report file.
            [string]$certificate = get-content 'C:\temp\certs\cert01.cer'
            $addCertificateStatus = addCertificate $manager $tenantApiKey $certificate
            Write-Host $addCertificateStatus
            $tenantCertStatus = tenantCertificateReportFunction $manager $tenantApiKey $TenantName
            
            # Delete the API key from each tenant.
            $deleteTenantApiKeyStatus =  deleteTenantApiKey $manager $tenantApiKey $apiKeyID
            write-host "$TenantName, $tenantApiKeyCreateStatus, $tenantCertStatus, $deleteTenantApiKeyStatus"
        }
        Start-Sleep -m 40
    }

    # Get computer list from T0 and output to report file.
    #$ComputerReportStatus = tenantCertificateReportFunction $manager $apikey
    #write-host "T0, N/A, $ComputerReportStatus, N/A" 
}