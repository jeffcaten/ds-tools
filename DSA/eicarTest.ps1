$httpUrl = "http://2016.eicar.org/download/eicar.com"
$outputHTTP = "$PSScriptRoot\eicar.http.com"
$start_time = Get-Date

Invoke-WebRequest -Uri $httpUrl -OutFile $outputHTTP
Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"


$httpsUrl = "https://secure.eicar.org/eicar.com"
$outputHTTPS = "$PSScriptRoot\eicar.https.com"
$start_time = Get-Date

Invoke-WebRequest -Uri $httpsUrl -OutFile $outputHTTPS
Write-Output "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"



& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -m