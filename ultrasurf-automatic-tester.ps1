Try
{
    $datetime=Get-Date -Format yyyyMMddHHmmss
    $appfullpath="C:\Users\Admin\Desktop\u-13.04\u1304.exe"
    $tmpdirpath="C:\Users\Admin\Desktop\u-13.04\utmp"
    $tmpconfpath="C:\Users\Admin\Desktop\u-13.04\u.ini"
    $processname="u1304.exe"
    $nicname="Local Area Connection"
    $subnet="192.168.56."
    $netmask="255.255.255.0"
    $gateway="192.168.56.101"
    $startip=103
    $samplesize=100 # MAX (102, 254]
    $waitperiod=2*60 # Sleep period in seconds
    
    cls
    Write-Host $datetime

    for ($i=0; $i -lt $samplesize; $i++)
    {
        netsh interface set interface name=$nicname admin=disabled >$null # Disable NIC
        Start-Sleep -s 5
        netsh interface set interface name=$nicname admin=enabled >$null # Enable NIC
        Start-Sleep -s 5
        netsh interface ip set address name=$nicname static "$subnet$($i+$startip)" $netmask $gateway  >$null # Change IP (increment by i)
        Start-Sleep -s 5
        ipconfig /flushdns >$null # Flush DNS
        Start-Sleep -s 5
        If (Test-Path $tmpdirpath) { RD -Recurse -Force $tmpdirpath >$null }  # Force Delete UltraSurf Temp Folder
        If (Test-Path $tmpconfpath) { RD -Recurse -Force $tmpconfpath >$null } # Force Delete UltraSurf Configurations File
        Write-Host "$subnet$($i+$startip)"
        & $appfullpath # Run Ultrasurf Client
        Start-Sleep -s $waitperiod # Sleep for n seconds
        taskkill /F /T /IM $processname /IM "iexplore.exe" >$null # Force Kill UltraSurf Process
    }
}
Catch [Exception]
{
    Write-Host $_.Exception.Message
}
Finally
{
    $datetime=Get-Date -Format yyyyMMddHHmmss
    Write-Host $datetime
}
