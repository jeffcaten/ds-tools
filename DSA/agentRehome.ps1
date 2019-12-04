<powershell>
#requires -version 4.0
# This script detects platform and architecture.  It then downloads and installs the relevant Deep Security Agent 10 package
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
   Write-Warning "You are not running as an Administrator. Please try again with admin privileges."
   exit 1 }
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
$env:LogPath = "$env:appdata\Trend Micro\Deep Security Agent\installer"
New-Item -path $env:LogPath -type directory
Start-Transcript -path "$env:LogPath\dsa_deploy.log" -append
Write-Host "$(Get-Date -format T) - DSA download started"

& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -r
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -a dsm://dsm.lab.local:4120/ #"policyid:1"
Stop-Transcript
Write-Host "$(Get-Date -format T) - DSA Rehome Finished"
</powershell>