
Write-Output (New-Object psobject |
        Add-Member (Get-ReconUsername) -PassThru |
        Add-Member (Get-ReconDomain) -PassThru | 
        Add-Member (Get-ReconComputername) -PassThru) | ft * -AutoSize

Write-Output "Current User is in following groups:"
Get-ReconCurrentUserGroupMembership | ft Domain, Name -AutoSize

Write-Output "Users in Domain Admins Group:"
Get-ReconDomainAdministrators | ft Domain, Name -AutoSize

Write-Output "IPConfig:"
Get-ReconIPConfig | ft DNSServerSearchOrder, IPAddress, DefaultIPGateway, MACAddress -AutoSize 

Write-Output "Listening Ports"
Get-ReconNetTCPConnections -State Listen | where LocalAddress -ne '127.0.0.1' | ft * -AutoSize

Write-Output "Established Connections"
Get-ReconNetTCPConnections -State Established | where RemoteAddress -ne '127.0.0.1' | ft * -AutoSize

Write-Output "DNS Cache"
Get-ReconDNSCache -Everything | ft * -AutoSize

Write-Output "Antivirus Product Name and Status"
Get-ReconAV | ft * -AutoSize

Write-Output "Info about Domain Controller"
Get-ReconDomainController | ft DnsForestName, DomainControllerAddress, DomainControllerName, DomainName -AutoSize

Write-Output "OS:"
Get-WmiObject -Class Win32_OperatingSystem | ft Caption, OSArchitecture -AutoSize

Write-Output "System:"
Get-WmiObject -Class Win32_ComputerSystem | ft Manufacturer, Model, SystemType -AutoSize

Write-Output "BIOS:"
Get-WmiObject -Class Win32_BIOS 

Write-Output "Installed Software:"
Get-ReconInstalledAppsByRegistry | ft * -AutoSize

Write-Output "Domain Computers Info:"
$computers = Get-ReconDomainComputers 
$computers | ft * -AutoSize 

Write-Output "Enabled Domain Users Info"
Get-ReconDomainUsers | where 'Normal Account' -eq $true | ft Name, Description, 'Last Password Change', 'Last Logon', 'Enabled', 'Groups' -AutoSize

Write-Output "Running under privileged  context:"
Get-ReconAmIAdmin | ft -AutoSize
