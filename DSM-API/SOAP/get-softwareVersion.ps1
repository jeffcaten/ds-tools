param (
    [Parameter(Mandatory=$true)][string]$manager,
    [Parameter(Mandatory=$true)][string]$user,
    [Parameter(Mandatory=$false)][string]$tenant
)

$passwordinput = Read-host "Password for Deep Security Manager" -AsSecureString
$password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordinput))

[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
$Global:DSMSoapService = New-WebServiceProxy -uri "https://$manager/webservice/Manager?WSDL" -Namespace "DSSOAP" -ErrorAction Stop
$Global:DSM = New-Object DSSOAP.ManagerService
try {
    if (!$tenant) {
        $Global:SID = $DSM.authenticate($user, $password)
        }
    else {
        $Global:SID = $DSM.authenticateTenant($tenant, $user, $password)
        }
}
catch {
    Write-Output "An error occurred during authentication. Verify username and password and try again. `nError returned was: $($_.Exception.Message)"
    exit
}

    $importedSoftware = $DSM.softwareRetrieveAll($SID)

foreach($i in $importedSoftware.ID)
{
    write-host ($importedSoftware.ID - $importedSoftware.version - $importedSoftware.platform)
}
    #echo  "$($importedSoftware.version) - $($importedSoftware.imported)"
    #$softwareRetrieve = $DSM.softwareApplyToHosts(7, '11.0.0.707', $SID)
$DSM.endSession($SID)