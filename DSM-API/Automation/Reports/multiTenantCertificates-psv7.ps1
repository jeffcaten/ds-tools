<#
.SYNOPSIS
Powershell script adds/deletes trusted certificates in all active tenants and T0 in a multi-tenant Deep Security deployment

.DESCRIPTION
The multiTenantCertificates-psv7.ps1 script will retrieve all trusted certificates from each tenant and show if there are any expired certificates. 
Using the -certificateDirectory parameter you can add trusted certificates to each tenant and T0
Using the -deletedExpired switch, the script will delete any certificates that are expired at the time the script is run.
This help center article has more detail about managing trusted certificates in the deep security manager: 
https://help.deepsecurity.trendmicro.com/20_0/on-premise/trusted-certificates.html?Highlight=trusted%20certificates

.PARAMETER manager
The -manager parameter requires a hostname or IP and port in the format hostname.local:4119 or 198.51.100.10:443

.PARAMETER apikey
The -apikey parameter requires a Deep Security Manager API key with the full access role.

.PARAMETER certificateDirectory
The -certificateDirectory parameter requires a directory path like c:\temp\certificates\.  The trailing slash must be included.

The script is only looking for files with a .cer extension.  This can be changed by updating the $certificateFileExtensionFilter variable.

.PARAMETER deletedExpired
If this switch is set when the script is run the script will check each trusted certificated in each tenant to see if it is expired.  If the certificate is expired the script will delete the expired certificate.
See Example

.PARAMETER report
If this switch is set when the script is run the script will output a CSV report with all of the trusted certificates from each tenant and T0.  Example report data:

TenantName, ID, issuerDN, subjectDN, notBefore, notAfter, serialNumber, sha1Fingerprint, sha256Fingerprint, trusted, purpose, rawCertificate
test01, 22, CN=example.com, CN=example.com, 04/08/2022 10:37:19, 04/13/2022 10:37:19, 52:F8:06:85:EE:E3:4E:E7:8F:C2:C6:A3:5B:F4:23:BB:C3:FD:81:7B, B5:61:D0:16:A3:34:04:9F:33:99:30:0E:B7:8E:2D:E1:66:4B:A4:D9, 55:65:7A:C5:18:7C:59:07:9A:BC:05:68:DC:48:B9:7E:82:50:8D:5C:9E:78:91:BF:21:09:69:BA:1D:95:47:24, True, SSL, -----BEGIN CERTIFICATE-----MIIC...-----END CERTIFICATE-----

Important note:
If the report switch is set the report will be generated before any certificates are added or deleted.  This could be used as a backup of the existing certificates.
If you take the data from the rawCertificate field in the report and put it in a .cer file you could use that .cer file to add the certificate back you deleted the wrong certificate by accident.


.EXAMPLE
Output count of trusted certificates:
.\multiTenantCertificates-psv7.ps1 -manager <DSM Hostname> -apikey <API-Key>
Add trusted certificates:
.\multiTenantCertificates-psv7.ps1 -manager <DSM Hostname> -apikey <API-Key> -certificateDirectory c:\temp\certs\
Add trusted certificates and delete expired certificates:
.\multiTenantCertificates-psv7.ps1 -manager <DSM Hostname> -apikey <API-Key> -certificateDirectory c:\temp\certs\ -deletedExpired
Add trusted certificates and delete expired certificates and output report:
.\multiTenantCertificates-psv7.ps1 -manager <DSM Hostname> -apikey <API-Key> -certificateDirectory c:\temp\certs\ -deletedExpired -report
Delete expired certificates
.\multiTenantCertificates-psv7.ps1 -manager <DSM Hostname> -apikey <API-Key> -deletedExpired
Output report only
.\multiTenantCertificates-psv7.ps1 -manager <DSM Hostname> -apikey <API-Key> -report



.NOTES
Example Script Output:
    tenantName, createTenantApiKey, Number of Certificates, Expired Certificates, deleteTenantApiKey
    test01, Success, 120, 0, Success
    test02, Success, 140, 20, Success
    T0, Success, 135, 15, Success

This script should clean up the ApiKeys that it creates.  If the script can't delete the 'Trusted Certificate' ApiKey for some reason an adminitrator will need to clean up the left over ApiKey from the effected tenants.
#>
#requires -version 7.0

param (
    [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey,
    [Parameter(Mandatory=$false, HelpMessage="Directory that contains all of the certificates; ex c:\temp\certificates\")][string]$certificateDirectory,
    [Parameter(Mandatory=$false, HelpMessage="Serial Number to delete by serial number")][string]$certToDeleteBySerialNumber,
    [switch]$deletedExpired,
    [switch]$report
)

#$certificateDirectory = "C:\temp\certs\"
$certificateFileExtensionFilter = "*.cer"

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
    try {
        $tenantSearchResults = Invoke-WebRequest -Uri $tenantSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $tenantSearchBody -SkipCertificateCheck   | ConvertFrom-Json        
    }
    catch {
        $e = $Error[0]
        $line = $_.InvocationInfo.ScriptLineNumber
        Write-Host -ForegroundColor Red "caught exception: $e at line $line"
    }

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
        keyName = 'Trusted Certificate'
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
        $e = $Error[0]
        $line = $_.InvocationInfo.ScriptLineNumber
        Write-Host -ForegroundColor Red "caught exception: $e at line $line"
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

    try {
        $certificateSearchResults = Invoke-WebRequest -Uri $certificateSearchURL -Method Get -ContentType "application/json" -Headers $headers -SkipCertificateCheck  | ConvertFrom-Json  
    }
    catch {
        $e = $Error[0]
        $line = $_.InvocationInfo.ScriptLineNumber
        Write-Host -ForegroundColor Red "caught exception: $e at line $line"
    }
    
    $currentTime = [int64](([datetime]::UtcNow)-(get-date "1/1/1970")).TotalMilliseconds
    $certificateSerialNumber = $certificateSearchResults.certificates.certificateDetails.serialNumber
    $certificateCountTotal = 0
    $certificateCountExpired = 0
    foreach ($item in $certificateSearchResults.certificates) {
        $certificateCountTotal+=1
        if ($item.certificateDetails.notAfter -le $currentTime){
            $certificateCountExpired+=1
        }
    }

    $returnArray = @()
    $returnArray += $certificateCountTotal
    $returnArray += $certificateCountExpired
    $returnArray += $certificateSearchResults

    return ,$returnArray

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
        $e = $Error[0]
        $line = $_.InvocationInfo.ScriptLineNumber
        Write-Host -ForegroundColor Red "caught exception: $e at line $line"
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
    
    $certificateListURL = "https://$manager/api/certificates"
    $certificateDeletehURL = "https://$manager/api/certificates"

    $certificateListResults = Invoke-WebRequest -Uri $certificateListURL -Method Get -ContentType "application/json" -Headers $headers -SkipCertificateCheck  | ConvertFrom-Json  
    $currentTime = [int64](([datetime]::UtcNow)-(get-date "1/1/1970")).TotalMilliseconds
    foreach ($item in $certificateListResults.certificates) {
        #$apikeyCreatedTime = (Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromMilliSeconds($item.certificateDetails.notAfter))
        #write-host $item.certificateDetails.notAfter

        if ($item.certificateDetails.notAfter -le $currentTime) {
            $certificateID = $item.ID
            #write-host "Certificate is expired this is the ID: "$certificateID
            $certificateDeleteResults = Invoke-WebRequest -Uri $certificateDeletehURL/$certificateID -Method Delete -ContentType "application/json" -Headers $headers -SkipCertificateCheck  | ConvertFrom-Json
        }
        else {
            #Write-host "Certificate is still valid"
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
        $e = $Error[0]
        $line = $_.InvocationInfo.ScriptLineNumber
        Write-Host -ForegroundColor Red "caught exception: $e at line $line"
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

function deleteCertificate{
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$tenantApiKey,
        [Parameter(Mandatory=$false, HelpMessage="Certificate ID")][string]$certificateID
    )

    $deleteCertificatehURL = "https://$manager/api/certificates/$certificateID"
    $headers = @{
    "api-version" = "v1"
    "api-secret-key" = $tenantApiKey
    "Content-Type" = "application/json"
    }

    try {
        $deleteCertificateResults = Invoke-WebRequest $deleteCertificatehURL -Method 'DELETE' -Headers $headers -SkipCertificateCheck -SkipHttpErrorCheck  
    }
    catch {
        $deleteCertificateResults = "Failed to delete certificateID $certificateID"
        $e = $Error[0]
        $line = $_.InvocationInfo.ScriptLineNumber
        Write-Host -ForegroundColor Red "caught exception: $e at line $line"
    }
}


#  --------------------TN Start--------------------
# Search for all active tenants in T0
$tenantSearchResults = tenatSearchFunction $manager

# Count the number of certificates in the $certificateDirectory to give the user some output.
if ($certificateDirectory) {
    $localCertificates = Get-ChildItem -Path $certificateDirectory -Filter *.cer -Recurse -File -Name
    $localCertificatesCount = $localCertificates.count
    write-host "Found $localCertificatesCount certificate(s) in the local directory"
}

# If the report switch is set write out report file with headers
if ($report) {
    $reportTime = get-date -f yyyy-MM-dd-HHmmss
    $reportName = "c:\temp\certificateReport - $reportTime"
    $reportFile = $reportName + ".csv"
    $ReportHeader = 'TenantName, ID, issuerDN, subjectDN, notBefore, notAfter, serialNumber, sha1Fingerprint, sha256Fingerprint, trusted, purpose, rawCertificate'

    # Writing out the CSV and CSV headers.
    # Try catch to throw a warning if the file can't be created
    try{
        Add-Content -Path $reportFile -Value $ReportHeader -ErrorAction Stop
    }catch{
        $Error[0]
        Write-Warning "$_"
        Continue
    }
}

if ($tenantSearchResults.tenants) {
    write-host "tenantName, createTenantApiKey, Number of Certificates, Expired Certificates, deleteTenantApiKey"

    # Loop through each tenant
    foreach ($tenant in $tenantSearchResults.tenants) {
        $tenantID = $tenant.ID
        $TenantName = $tenant.name

        # Create an API key for each tenant
        $tenantApiKeyArray = createTenantApiKeyFunction $manager $tenantID
        
        # Check if there are any results from createTenantApiKeyFunction
        if ($tenantApiKeyArray[0]) {
            $apiKeyID = $tenantApiKeyArray[0]
            $tenantApiKey = $tenantApiKeyArray[1]
            $tenantApiKeyCreateStatus = $tenantApiKeyArray[2]

            # If the report switch is set loop through all certificates in tenant and output to $repotFile
            if ($report) {
                $tenantCerts = tenantCertificateReportFunction $manager $tenantApiKey $TenantName
                $tenantCertList = $tenantCerts[2]

                foreach ($certificate in $tenantCertList.certificates){
                    $apikeyCreatedTime = (Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromMilliSeconds($Item.created))

                    $TenantName = $TenantName
                    $ID = $certificate.ID
                    $issuerDNCommas = $certificate.certificateDetails.issuerDN
                    $issuerDN = $issuerDNCommas -replace "," -replace ""
                    $subjectDNCommas = $certificate.certificateDetails.subjectDN
                    $subjectDN = $subjectDNCommas -replace "," -replace ""
                    $notBefore = (Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromMilliSeconds($certificate.certificateDetails.notBefore))
                    $notAfter = (Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromMilliSeconds($certificate.certificateDetails.notAfter))
                    $serialNumber = $certificate.certificateDetails.serialNumber
                    $sha1Fingerprint = $certificate.certificateDetails.sha1Fingerprint
                    $sha256Fingerprint = $certificate.certificateDetails.sha256Fingerprint
                    $trusted = $certificate.trusted
                    $purpose = $certificate.purpose
                    $rawCertificateLineBreaks = $certificate.certificate
                    $rawCertificate = $rawCertificateLineBreaks -replace "\n" -replace ""

                    $ReportData =  "$TenantName, $ID, $issuerDN, $subjectDN, $notBefore, $notAfter, $serialNumber, $sha1Fingerprint, $sha256Fingerprint, $trusted, $purpose, $rawCertificate"
                    Add-Content -Path $reportFile -Value $ReportData
                }
            }

            # Check if $certificateDirectory was populated by the user
            #   If it is loop through all of the local certificates and add each certificate to the current tenant.
            if ($certificateDirectory) {
                # Get a list of the local certificate file names
                $localCertificates = Get-ChildItem -Path $certificateDirectory -Filter $certificateFileExtensionFilter -Recurse -File -Name
                
                # Loop through each certificate and add each certificate to the tenant
                foreach ($item in $localCertificates) {
                    [string]$certificate = get-content $certificateDirectory$item
                    $addCertificateStatus = addCertificate $manager $tenantApiKey $certificate
                }
            }
            
            # Check if the $deletedExpired switch is set.  If it is run the deleteExpiredCertificate function
            if ($deletedExpired) {
                deleteExpiredCertificate $manager $tenantApiKey
            }
            
            # Check to see if if there is a cert to delete by serial number.
            if ($certToDeleteBySerialNumber) {
                # Get list of certificates from tenant
                $tenantCerts = tenantCertificateReportFunction $manager $tenantApiKey $TenantName
                $tenantCertList = $tenantCerts[2]

                # Loop through the list of certificate
                foreach ($certificate in $tenantCertList.certificates) {
                    # Check to see if the cert serial number matches the cert serial number provided by the user via $certToDeleteBySerialNumber
                    if ($certToDeleteBySerialNumber -eq $certificate.certificateDetails.serialNumber) {
                        write-host "Found certificate with serial number: "$certificate.certificateDetails.serialNumber
                        write-host $certificate.ID
                        $certificateID = $certificate.ID
                        deleteCertificate $manager $tenantApiKey $certificateID
                    }
                }
            }

            # Count the number of certificates in the tenant
            $tenantCertStatus = tenantCertificateReportFunction $manager $tenantApiKey $TenantName
            $totalCertCount = $tenantCertStatus[0]
            $expiredCertCount = $tenantCertStatus[1]
            
            # Delete the API key from the tenant.
            $deleteTenantApiKeyStatus =  deleteTenantApiKey $manager $tenantApiKey $apiKeyID

            write-host "$TenantName, $tenantApiKeyCreateStatus, $totalCertCount, $expiredCertCount, $deleteTenantApiKeyStatus"
        }
        Start-Sleep -m 40
    } 
}

#  --------------------TN End--------------------


#  --------------------T0 Start--------------------
# Add certificates to T0

if ($certificateDirectory) {
    $localCertificates = Get-ChildItem -Path $certificateDirectory -Filter $certificateFileExtensionFilter -Recurse -File -Name
    foreach ($item in $localCertificates) {
        [string]$certificate = get-content $certificateDirectory$item
        $addCertificateStatus = addCertificate $manager $apikey $certificate
    }
}
if ($deletedExpired) {
    deleteExpiredCertificate $manager $apikey
} 
$TenantName = "T0"
$tenantCertStatus = tenantCertificateReportFunction $manager $apikey $TenantName
$totalCertCount = $tenantCertStatus[0]
$expiredCertCount = $tenantCertStatus[1]
write-host "$TenantName, $tenantApiKeyCreateStatus, $totalCertCount, $expiredCertCount, $deleteTenantApiKeyStatus"

#  --------------------T0 End--------------------