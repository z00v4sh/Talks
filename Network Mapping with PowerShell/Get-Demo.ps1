#region Find local IP Configuration


# Cmdlet
# https://msdn.microsoft.com/powershell/reference/5.1/Microsoft.PowerShell.Management/Test-Connection

help Get-NetIPConfiguration

$ipConfig = Get-NetIPConfiguration

$ipConfig

$ipConfig | Format-List *

$ipConfig.IPv4Address


# .Net classes
# https://msdn.microsoft.com/en-us/library/system.net.networkinformation.networkinterface(v=vs.110).aspx

[System.Net.NetworkInformation.NetworkInterface] | Get-Member -Static

[System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()

$networkInterface = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()[0]

$networkInterface

$networkInterface.GetIPProperties()

$networkInterface.GetIPProperties().UnicastAddresses

$networkInterface.GetIPProperties().UnicastAddresses[1]


# WMI
# https://msdn.microsoft.com/en-us/library/aa394217(v=vs.85).aspx

Get-WmiObject -List -Class *network*

Get-WmiObject -Class Win32_NetworkAdapterConfiguration

Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=$true"

Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=$true" | Format-List *

$networkAdapterConfiguration = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=$true" 

$networkAdapterConfiguration | select IPAddress, IPSubnet


#endregion

#region IP Range


$ipRange = 1..254 | foreach { "192.168.13.$PSItem" }

$ipRange

$ipRange = @(
    '192.168.13.5'    
    '192.168.13.13'
    '192.168.13.50'
    '192.168.13.100'
    '192.168.13.101'
    '192.168.13.102'
    '192.168.13.103'
    '192.168.13.104'
    '192.168.13.105'
    '192.168.13.150'
    '192.168.13.205'
)

$ipRange


#endregion

#region Send ICMP Echo Requests (Ping)


# Cmdlet
# https://msdn.microsoft.com/powershell/reference/5.1/Microsoft.PowerShell.Management/Test-Connection

help Test-Connection

help Test-Connection -Examples

Test-Connection -Count 1 -ComputerName $ipRange[$(Get-Random -Minimum 0 -Maximum $($ipRange.Length-1))] -Quiet

$ip = $ipRange[$(Get-Random -Minimum 0 -Maximum $($ipRange.Length-1))]

$ip

$sb = {
    if(Test-Connection -Count 1 -ComputerName $ip -Quiet -Delay 1){

        [pscustomobject]([ordered]@{IPAddress=$ip; Status='up'})
        #Write-Output $("{0,-15} up" -f $ip)

    } else {

        [pscustomobject]([ordered]@{IPAddress=$ip; Status='down'})
        #Write-Output $("{0,-15} down" -f $ip)
    }
}

& $sb

foreach($ip in $ipRange){
    & $sb
}

# .Net
# https://msdn.microsoft.com/en-us/library/system.net.networkinformation.ping(v=vs.110).aspx

[System.Net.NetworkInformation.Ping].GetMethods() | Format-Table -AutoSize

$ping = New-Object System.Net.NetworkInformation.Ping

$ping.Send('192.168.13.200')
$ping.Send('192.168.13.100')
$ping.Send('192.168.13.101')

$ping.Send('192.168.13.200', 100)
$ping.Send('192.168.13.100', 100)
$ping.Send('192.168.13.101', 100)

foreach($ip in $ipRange){

    if( $ping.Send($ip, 100).Status -eq 'Success' ){

        [pscustomobject]([ordered]@{IPAddress=$ip; Status='up'})
        #Write-Output $("{0,-15} up" -f $ip)

    } else {

        [pscustomobject]([ordered]@{IPAddress=$ip; Status='down'})              
        #Write-Output $("{0,-15} down" -f $ip)

    }
}

# WMI 
# https://msdn.microsoft.com/en-us/library/aa394350(v=vs.85).aspx

Get-WmiObject -List -Class *ping*

Get-WmiObject -Class Win32_PingStatus

[wmiclass]'Win32_PingStatus'

[wmiclass]'Win32_PingStatus' | fl *

[wmiclass]'Win32_PingStatus' | select -ExpandProperty Properties | Format-Table

Get-WmiObject -Class Win32_PingStatus -Filter "Address='192.168.13.100'"

$wmiPing = Get-WmiObject -Class Win32_PingStatus -Filter "Address='192.168.13.102'"

$wmiPing | Format-List

$wmiPing.StatusCode

Get-WmiObject -Class Win32_PingStatus -Filter "Address='192.168.13.101' AND Timeout=100" -Property StatusCode

Get-WmiObject -Class Win32_PingStatus -Filter "Address='192.168.13.102' AND Timeout=100" -Property StatusCode


Get-WmiObject -Query "Select * FROM Win32_PingStatus Where Address='192.168.13.102'"

Get-WmiObject -Query "Select * FROM Win32_PingStatus Where (Timeout=100) AND (Address='192.168.13.101')" 

Get-WmiObject -Query "Select StatusCode FROM Win32_PingStatus Where Address='192.168.13.100'"

Get-WmiObject -Query "Select * FROM Win32_PingStatus Where Timeout=100 AND (Address='192.168.13.100' OR Address='192.168.13.101')"

Get-WmiObject -Query "Select * FROM Win32_PingStatus Where Timeout=100 AND (Address='192.168.13.100' OR Address='192.168.13.101')" | select Address, StatusCode

$filter = "Address='" + $($ipRange -join "' OR Address='") + "'"

$filter

Get-WmiObject -Class Win32_PingStatus -Filter "Timeout=100 AND $filter" | where StatusCode -eq 0


#endregion

#region Port Scanners
# https://msdn.microsoft.com/en-us/library/system.net.sockets.socket(v=vs.110).aspx
# https://msdn.microsoft.com/en-us/library/system.net.sockets.tcpclient(v=vs.110).aspx
# https://msdn.microsoft.com/en-us/library/system.net.sockets.udpclient(v=vs.110).aspx

[System.Net.Sockets.Socket]

[System.Net.Sockets.TcpClient]

[System.Net.Sockets.UdpClient]

# TCP Scanner

$tcpClient = New-Object System.Net.Sockets.TcpClient

$tcpClient | Get-Member 

$tcpClient.Connect('192.168.13.100', 100)

$tcpClient.Connected

$tcpClient.Connect('192.168.13.100', 5985)

$tcpClient.Connected

$tcpClient.Close()


$tcpClient = New-Object System.Net.Sockets.TcpClient

$wait = $tcpClient.BeginConnect('192.168.13.100', 100, $null, $null)

$r = $wait.AsyncWaitHandle.WaitOne(100, $false)

$tcpClient.Connected

$tcpClient.Close()

$commonPorts = 20, 21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 135, 137, 138, 139, 389, 443, 445, 3389, 5985, 5986

$ip = '192.168.13.100'

$sb = {
    foreach($port in $commonPorts){

        $tcpClient = New-Object System.Net.Sockets.TcpClient

        $wait = $tcpClient.BeginConnect($ip, $port, $null, $null)

        $r = $wait.AsyncWaitHandle.WaitOne(100, $false)

        if($tcpClient.Connected){            
            [pscustomobject]([ordered]@{IPAddress=$ip; Port=$port; Status='Open'})
            # Write-Output $("IP {0,-15} : port {1,-5} open" -f $ip, $port)
            $tcpClient.Close()
        } 
    }

}

& $sb

$r = @()

foreach($ip in $ipRange){
    $r += & $sb 
}

$r

# UDP Scanner

foreach($ip in $ipRange){

    foreach($port in $commonPorts){

        $udpClient = New-Object System.Net.Sockets.UdpClient

        $udpClient.Connect($ip, $port)
     
        $data = [System.Text.ASCIIEncoding]::ASCII.GetBytes("$(Get-Date)")

        [void]$udpClient.Send($data, $data.Length)

        $udpClient.Client.ReceiveTimeout = 100

        $remoteTarget = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        
        try {
            $receiveBytes = $udpClient.Receive([ref]$remoteTarget)

            [pscustomobject]([ordered]@{IPAddress=$ip; Port=$port; Status='Open'})

            # Write-Output $("IP {0,-15} : port {1,-5} open" -f $ip, $port)
        } catch {
        } finally {
            $udpClient.Close()        
        }
    }
}

#endregion

#region Get Network Connections


# Cmdlet 
# https://technet.microsoft.com/library/fdf635b0-3f62-48ae-bde6-1dac120dd52d(v=wps.630).aspx

help Get-NetTCPConnection

Get-NetTCPConnection

Get-NetTCPConnection -State Established -LocalAddress '192.168.13.101' | select RemoteAddress -Unique

# .Net
# https://msdn.microsoft.com/en-us/library/system.net.networkinformation.ipglobalproperties(v=vs.110).aspx


[System.Net.NetworkInformation.IPGlobalProperties].GetMethods() | Format-Table

$ipGlobalProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()

$ipGlobalProperties | Get-Member

$ipGlobalProperties.GetActiveTcpConnections()

$ipGlobalProperties.GetActiveTcpConnections().LocalEndPoint

($ipGlobalProperties.GetActiveTcpConnections() | where { $_.State -eq 'Established' -and $_.LocalEndPoint.Address -eq '192.168.1.24' }).RemoteEndPoint

# WMI
# https://msdn.microsoft.com/en-us/library/hh872450(v=vs.85).aspx

Get-WmiObject -Class MSFT_NetTCPConnection -Namespace root\StandardCimv2

Get-WmiObject -Class MSFT_NetTCPConnection -Namespace root\StandardCimv2 | Format-Table *

[wmiclass]'\root\StandardCimv2:MSFT_NetTCPConnection'

([wmiclass]'\root\StandardCimv2:MSFT_NetTCPConnection').Properties | Format-Table

<#

Get-WmiObject -Class MSFT_NetTCPConnection -Namespace root\StandardCimv2 | ft LocalAddress, LocalPort, RemoteAddress, RemotePort, State

Get-WmiObject -Class MSFT_NetTCPConnection -Namespace root\StandardCimv2 -Filter "State=5 AND LocalAddress='192.168.13.13'" | ft LocalAddress, LocalPort, RemoteAddress, RemotePort, State

#>

$wmiSearcher = New-Object wmisearcher

$wmiSearcher | Get-Member

$wmiSearcher.Scope = '\\.\root\StandardCimv2'

$wmiSearcher.Query | Get-Member 

$wmiSearcher.Query.QueryLanguage

$wmiSearcher.Query.QueryString = "Select * From MSFT_NetTCPConnection Where State=5 AND LocalAddress='192.168.1.24'"

$wmiSearcher.Get() | select LocalAddress, LocalPort, RemoteAddress, RemotePort

$wmiSearcher.Get() | select LocalAddress, LocalPort, RemoteAddress, RemotePort, 
                        @{Name='PID'; Expression={ $_.OwningProcess }}, 
                        @{Name='Process'; Expression={ (Get-Process -Id $_.OwningProcess).Name }} | Out-GridView


#endregion

#region Reverse DNS

# Cmdlet
# https://technet.microsoft.com/en-us/library/jj590781(v=wps.630).aspx 

help Resolve-DnsName # PowerShell 4.0

Resolve-DnsName -Name 192.168.13.13 -Type PTR -Server 192.168.13.13

foreach($ip in $ipRange){

    Resolve-DnsName -Name $ip -Type PTR -Server 192.168.13.13  2> $null | select NameHost, @{Name='IPAddress'; Expression={$ip}}      

}

# .Net 
# https://msdn.microsoft.com/en-us/library/system.net.dns(v=vs.110).aspx

[System.Net.Dns] | Get-Member -Static

[System.Net.Dns]::GetHostByAddress('192.168.13.50')
    
foreach($ip in $ipRange){
    try {

        [System.Net.Dns]::GetHostByAddress($ip)

    } catch {}
}

#endregion

#region ARP Scanner
# http://pinvoke.net/default.aspx/iphlpapi/SendARP.html


$typedefinition = @"

[DllImport("iphlpapi.dll", ExactSpelling=true)]
public static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);

"@

help Add-Type

Add-Type -MemberDefinition $typedefinition -Name ARP -Namespace NetDiscovery

[NetDiscovery.ARP]

[NetDiscovery.ARP].GetMethods() | ft

$ip = [ipaddress]'192.168.13.100'

$ip.GetAddressBytes()

$ipBytesToUInt = [System.BitConverter]::ToUInt32($ip.GetAddressBytes(), 0)

$ipBytesToUInt

$macAddress = New-Object byte[] 6

$macAddress

$response = [NetDiscovery.ARP]::SendARP($ipBytesToUInt, 0, $macAddress, [ref]6)

$response

$macAddress

[System.BitConverter]::ToString($macAddress)

foreach($ip in $ipRange){
    $ipBytesToUInt = [System.BitConverter]::ToUInt32( ([ipaddress]$ip).GetAddressBytes(), 0)

    $response = [NetDiscovery.ARP]::SendARP($ipBytesToUInt, 0, $macAddress, [ref]6)

    if(!$response){
        [pscustomobject]([ordered]@{
            IPAddress=$ip
            MACAddress=[System.BitConverter]::ToString($macAddress)
        })
    }
}
#endregion

