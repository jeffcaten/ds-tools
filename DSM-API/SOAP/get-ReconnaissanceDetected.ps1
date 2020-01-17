param (
    [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="DeepSecurity Manager Username with api access--")][string]$user,
    [Parameter(Mandatory=$true, HelpMessage="Start Date for search in format mm/dd/yyyy; ex 12/31/1970--")][string]$fromDate,
    [Parameter(Mandatory=$true, HelpMessage="End Date for search in format mm/dd/yyyy; ex 12/31/1970--")][string]$toDate,
    [Parameter(Mandatory=$true, HelpMessage="Filename for csv output; if existing data will be appended--")][string]$filename,
    [Parameter(Mandatory=$false)][string]$tenant
)

$passwordinput = Read-host "Password for Deep Security Manager" -AsSecureString
$password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordinput))

[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
$DSMSoapService = New-WebServiceProxy -uri "https://$manager/webservice/Manager?WSDL" -Namespace "DSSOAP" -ErrorAction Stop
$DSM = New-Object DSSOAP.ManagerService
$SID = ""
try {
    if (!$tenant) {
        $SID = $DSM.authenticate($user, $password)
        }
    else {
        $SID = $DSM.authenticateTenant($tenant, $user, $password)
        }
}
catch {
    Write-Output "An error occurred during authentication. Verify username and password and try again. `nError returned was: $($_.Exception.Message)"
    exit
}

$hft = New-Object DSSOAP.HostFilterTransport
$hft.type = [DSSOAP.EnumHostFilterType]::ALL_HOSTS
$tft = New-Object DSSOAP.TimeFilterTransport
$tft.rangeFrom = [datetime]"$fromDate"
$tft.rangeTo = [datetime]"$toDate"
$tft.type = [DSSOAP.EnumTimeFilterType]::CUSTOM_RANGE
$idft = New-Object DSSOAP.IdFilterTransport2
$idft.operator = [DSSOAP.EnumOperator]::EQUAL


$shortdesc = $DSM.systemEventRetrieveShortDescription($tft, $hft, $null, $false, $SID)

if (Test-Path $filename) {
    Write-Output "File already exists.. Cancelling report"
}
else {
    Write-Output "Writing report"
    foreach ($evt in $shortdesc.systemEvents) {
        if ($evt.eventID -eq 851) {
            $idft.id = $evt.systemEventID
            $fullevents = $DSM.systemEventRetrieve2($tft, $hft, $idft, $false, $SID)
            $regex = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b\d{1,2}\/\d{1,2}\/\d{4}\b'
            $eventDescrion =$fullevents.systemEvents[0].description
            $trafficFromIP = Select-String -InputObject $eventDescrion -Pattern $regex | % { $_.Matches } | % { $_.Value } 
            $report = @()
            $report += New-Object psobject -Property @{Computer=$fullevents.systemEvents[0].target;RemoteIP=$trafficFromIP;Time=$fullevents.systemEvents[0].time}
            $report | Select-Object "Time", "Computer", "RemoteIP" | export-csv $filename -Append -NoTypeInformation
        }
    }
    Write-Output "Report saved as $filename"
}

$DSMSoapService.endSession($SID)