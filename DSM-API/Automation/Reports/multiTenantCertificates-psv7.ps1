<#
.SYNOPSIS
Powershell script adds trusted certificates to all active tenants and T0 in a multi-tenant Deep Security deployment

.DESCRIPTION
The multiTenantCertificates script will login use an API key from T0 to get a list of active tenants.  
The script will then create and ApiKey for that tenant then use that new Apikey to add all of the certificates from a specified directory.  
The newly create tenant Apikey will be deleted and the script will move on to the next tenant.

.PARAMETER manager
The -manager parameter requires a hostname or IP and port in the format hostname.local:4119 or 198.51.100.10:443

.PARAMETER apikey
The -apikey parameter requires a Deep Security Manager API key with the full access role.

.PARAMETER certificateDirectory
The -certificateDirectory parameter requires a directory path like c:\temp\certificates\.  The trailing slash must be included.

.EXAMPLE
.\multiTenantCertificates-psv7.ps1 -manager <DSM Hostname> -apikey <API-Key> -certificateDirectory c:\temp\certs\

.NOTES
Example Script Output:
    tenantName, createTenantApiKey, Number of Certificates, deleteTenantApiKey
    test1, Success, 4, Success
    test3, Success, 4, Success
    test4, Success, 4, Success
    test5, Success, 4, Success
    T0, Success, 4, Success

This script should clean up the ApiKeys that it creates.  If the script can't delete the AddCertificate ApiKey for some reason an adminitrator will need to clean up the left over ApiKey from the effected tenants.
#>
#requires -version 7.0

param (
    [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey,
    [Parameter(Mandatory=$false, HelpMessage="Directory that contains all of the certificates; ex c:\temp\certificates\")][string]$certificateDirectory,
    [switch]$deletedExpired
)

#$certificateDirectory = "C:\temp\certs\"

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
        keyName = 'AddCertificate'
        description = 'Temp API Key used to add certificates to this tenant'
        locale = 'en-US'
        timeZone = 'America/Chicago'
        active = 'true'
        expiryDate = $timestamp
    }
    $createTenantApiKeyBody = $createTenantApiKeyHash | ConvertTo-Json
    
    try {
        $createTenantApiKeyResults = Invoke-WebRequest -Uri $createTenantApiKeyURL -Method Post -ContentType "application/json" -Headers $headers -Body $createTenantApiKeyBody -SkipCertificateCheck  | ConvertFrom-Json
    }
    catch {
        $tenantApiKeyCreateStatus = "Failed"
    }

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
    
    $certificateSearchURL = "https://$manager/api/certificates"

    $certificateSearchResults = Invoke-WebRequest -Uri $certificateSearchURL -Method Get -ContentType "application/json" -Headers $headers -SkipCertificateCheck  | ConvertFrom-Json  

    $certificateSerialNumber = $certificateSearchResults.certificates.certificateDetails.serialNumber
    $certificateCount = 0
    foreach ($item in $certificateSearchResults.certificates) {
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

function deleteExpiredCertificate {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$tenantApiKey
    )

    $headers = @{
        "api-version" = "v1"
        "api-secret-key" = $tenantApiKey
    }
    
    $certificateSearchURL = "https://$manager/api/certificates"

    $certificateSearchResults = Invoke-WebRequest -Uri $certificateSearchURL -Method Get -ContentType "application/json" -Headers $headers -SkipCertificateCheck  | ConvertFrom-Json  
    $currentTime = [int64](([datetime]::UtcNow)-(get-date "1/1/1970")).TotalMilliseconds
    foreach ($item in $certificateSearchResults.certificates) {
        $apikeyCreatedTime = (Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromMilliSeconds($item.certificateDetails.notAfter))
        
        #write-host $item.certificateDetails.notAfter

        if ($item.certificateDetails.notAfter -le $currentTime) {
            write-host "Certificate is expired this is the ID: "$item.ID
        }
        else {
            Write-host "Certificate is still valid"
        }
        
    }
    
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

    # Loop through each tenant
    foreach ($tenant in $tenantSearchResults.tenants) {
        $tenantID = $tenant.ID
        $TenantName = $tenant.name

        # Create an API key for each tenant
        $tenantApiKeyArray = createTenantApiKeyFunction $manager $tenantID

        if ($tenantApiKeyArray[0]) {
            $apiKeyID = $tenantApiKeyArray[0]
            $tenantApiKey = $tenantApiKeyArray[1]
            $tenantApiKeyCreateStatus = $tenantApiKeyArray[2]
            
            if ($certificateDirectory) {
                # Get certificate a list of the certificate file names
                $localCertificates = Get-ChildItem -Path $certificateDirectory -Filter *.cer -Recurse -File -Name

                # Loop through each certificate and add each certificate to the tenant
                foreach ($item in $localCertificates) {
                    [string]$certificate = get-content $certificateDirectory$item
                    $addCertificateStatus = addCertificate $manager $tenantApiKey $certificate
                }
            }
            
            if ($deletedExpired) {
                deleteExpiredCertificate $manager $tenantApiKey
            }            

            # Count the number of certificates in the tenant
            #$tenantCertStatus = tenantCertificateReportFunction $manager $tenantApiKey $TenantName
            
            # Delete the API key from the tenant.
            $deleteTenantApiKeyStatus =  deleteTenantApiKey $manager $tenantApiKey $apiKeyID

            write-host "$TenantName, $tenantApiKeyCreateStatus, $tenantCertStatus, $deleteTenantApiKeyStatus"
        }
        Start-Sleep -m 40
    } 
}

# Add certificates to T0
$localCertificates = Get-ChildItem -Path $certificateDirectory -Filter *.cer -Recurse -File -Name
foreach ($item in $localCertificates) {
    [string]$certificate = get-content $certificateDirectory$item
    $addCertificateStatus = addCertificate $manager $apikey $certificate
}
$TenantName = "T0"
$tenantCertStatus = tenantCertificateReportFunction $manager $apikey $TenantName
write-host "$TenantName, $tenantApiKeyCreateStatus, $tenantCertStatus, $deleteTenantApiKeyStatus"