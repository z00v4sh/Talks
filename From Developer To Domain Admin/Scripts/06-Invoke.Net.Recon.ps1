
$activeHosts = Get-MACAddr -IPAddresses (($computers | select 'IP Address').'IP Address') 
Write-Output "Get MAC Address of local network"
$activeHosts | ft * -AutoSize



Write-Output "Online hosts on local networks"
$activeHosts | where ResponseType -eq 'Success' | ft * -AutoSize

$onlineIPs = ($activeHosts | where ResponseType -eq 'Success').IPAddress

Write-Output "Pinging Local Network"
Send-Ping -ComputerName $onlineIPs | ft * -AutoSize

Write-Output "Scan Online Hosts and show only open ports"
Send-PortScan -ComputerName $onlineIPs -ShowOnlyOpen | ft * -AutoSize

