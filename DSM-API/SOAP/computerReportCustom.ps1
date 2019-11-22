param (
    [Parameter(Mandatory=$true)][string]$manager,
    [Parameter(Mandatory=$true)][string]$user,
    [Parameter(Mandatory=$false)][string]$tenant
)

$passwordinput = Read-host "Password for Deep Security Manager" -AsSecureString
$password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordinput))

[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
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
    echo "An error occurred during authentication. Verify username and password and try again. `nError returned was: $($_.Exception.Message)"
    exit
}

$hft = new-object DSSOAP.HostFilterTransport
$hft.type = [DSSOAP.EnumHostFilterType]::ALL_HOSTS
$response = $DSM.hostDetailRetrieve(2, [DSSOAP.EnumHostDetailLevel]::LOW, $SID) | Select-Object name, overallStatus, lastIPUsed, OverallDpiStatus, overallIntegrityMonitoringStatus
$response | Export-Csv -Path .\computerReport.csv -Append -NoTypeInformation

$DSM.endSession($SID)


<#
Additional fields can be added after Select-Object

antiMalwareClassicPatternVersion
antiMalwareEngineVersion              
antiMalwareIntelliTrapExceptionVersion
antiMalwareIntelliTrapVersion         
antiMalwareSmartScanPatternVersion    
antiMalwareSpywarePatternVersion      
cloudObjectImageId                    
cloudObjectInstanceId                 
cloudObjectInternalUniqueId           
cloudObjectSecurityGroupIds           
cloudObjectType                       
componentKlasses                      
componentNames                        
componentTypes                        
componentVersions                     
hostGroupName                         
hostInterfaces                        
hostLight                             
lastAnitMalwareScheduledScan          
lastAntiMalwareEvent                  
lastAntiMalwareManualScan             
lastDpiEvent                          
lastFirewallEvent                     
lastIPUsed                            
lastIntegrityMonitoringEvent          
lastLogInspectionEvent                
lastWebReputationEvent                
light                                 
locked                                
overallAntiMalwareStatus              
overallDpiStatus                      
overallFirewallStatus                 
overallIntegrityMonitoringStatus      
overallLastRecommendationScan         
overallLastSuccessfulCommunication    
overallLastSuccessfulUpdate           
overallLastUpdateRequired             
overallLogInspectionStatus            
overallStatus                         
overallVersion                        
overallWebReputationStatus            
securityProfileName                   
virtualName                           
virtualUuid                           
displayName                           
external                              
externalID                            
hostGroupID                           
hostType                              
platform                              
securityProfileID                     
ID                                    
description                           
name
#>