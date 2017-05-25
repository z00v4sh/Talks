Function Get-MACAddr {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ipaddress[]]$IPAddresses
    )
    Begin {
        $memberDefinition = '
					[DllImport("iphlpapi.dll", ExactSpelling=true)]
  					public static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
					  '
        Add-Type -MemberDefinition $memberDefinition -Name ARP -Namespace NetRecon
		
    }
    Process {
        foreach ($ipAddr in $IPAddresses) {

            $DestIP = [System.BitConverter]::ToUInt32($ipAddr.GetAddressBytes(), 0)
            $macAddr = New-Object byte[] 6
			
            $responseCode = [NetRecon.ARP]::SendARP($DestIP, 0, $macAddr, [ref]6)

			
            switch ($responseCode) {
                0 { $response = 'Success' }
                67 { $response = 'ERROR_NOT_FOUND' }
                Default { $response = 'Unknown Error' }
            }
            $properties = @{
                IPAddress = $ipAddr
                MACAddress = [System.BitConverter]::ToString($macAddr)
                ResponseType = $response
            }
            New-Object -TypeName psobject -Property $properties
				
        }	
    }

    End {}

}

Function Send-Ping {
    [CmdletBinding()]
    Param(

        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$ComputerName,

        [Parameter()]
        [uint32]$Count = 1,

        [Parameter()]
        [ValidateRange(10, [uint32]::MaxValue)]
        [uint32]$Delay = 100
		
    )

    Process {
        foreach ($Computer in $ComputerName) {

            try {
                $ipAddr = Validate-IPAddress -ComputerName $Computer
                $ping = New-Object System.Net.NetworkInformation.Ping
                for ($i = 0; $i -lt $Count; $i++) {
                    $response = $ping.Send($ipAddr, $Delay)

                    $properties = @{
                        ComputerName = $Computer
                        Status = $response.Status
                    }

                    New-Object -TypeName psobject -Property $properties
                }
                $ping.Dispose()
            } catch {}	

        }			
    }
}

Function Get-TCPPortScan {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ipaddress]$ipAddress,

        [Parameter()]
        [ValidateRange(0, 65535)]
        [uint32[]]$PortNumber = @(21, 22, 23, 25, 80, 110, 139, 443, 445, 3389),

        [Parameter()]
        [ValidateRange(10, [uint32]::MaxValue)]
        [uint32]$Delay = 100
    )

    Begin {
        $results = @()
    }

    Process {
        foreach ($Port in $PortNumber) {

            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($ipAddress, $port, $null, $null)
            $r = $asyncResult.AsyncWaitHandle.WaitOne($Delay, $false)
			
            $properties = [ordered]@{
                IPAddress = $ipAddress
                Port = $Port
                State = & {
                    if ($tcpClient.Connected) {
                        'Open'
                    }
                    else {
                        'Closed'
                    }
                } 
            }
				
            $results += New-Object -TypeName psobject -Property $properties
            $tcpClient.Dispose()	
        } #foreach		
    } #Process

    End {
        $results
    }
	 
}

Function Get-UDPPortScan {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ipaddress]$ipAddress,

        [Parameter()]
        [ValidateRange(0, 65535)]
        [uint32[]]$PortNumber = @(53, 67, 123, 135, 137, 138, 161, 445, 631, 1434),

        [Parameter()]
        [ValidateRange(10, [uint32]::MaxValue)]
        [uint32]$Delay = 1000
    )

    Begin {
        $results = @()
    }

    Process {
        foreach ($Port in $PortNumber) {
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $udpClient.Client.ReceiveTimeout = $Delay
            $udpClient.Connect($ipAddress, $Port)

            $data = [System.Text.ASCIIEncoding]::ASCII.GetBytes("$(Get-Date)")

            [void]$udpClient.Send($data, $($data.Length))

            $remoteTarget = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)

            try {
                $receivedBytes = $udpClient.Receive([ref]$remoteTarget)
                $PortState = 'Open'
            } catch {
                $PortState = 'Closed'				
            } finally {
                $properties = [ordered]@{
                    IPAddress = $ipAddress
                    Port = $Port
                    State = $PortState
                }
                $results += New-Object psobject -Property $properties
                $udpClient.Dispose()
            }
        }
    }

    End {
        $results
    }
}

Function Send-PortScan {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript( { Validate-IPAddress $_ })]
        [string[]]$ComputerName,

        [Parameter()]
        [ValidateRange(0, 65535)]
        [uint32[]]$Port,

        [Parameter()]
        [ValidateSet('TCP', 'UDP', 'All')]
        [string]$Type = 'TCP',

        [Parameter()]
        [ValidateRange(10, [uint32]::MaxValue)]
        [uint32]$Delay,

        [Parameter()]
        [switch]$ShowOnlyOpen
    )

    Begin {
        $UDPPorts = @(53, 67, 123, 135, 137, 138, 161, 445, 631, 1434)
        $TCPPorts = @(21, 22, 23, 25, 80, 110, 139, 443, 445, 3389)
        $TCPDelay = 100
        $UDPDelay = 1000
        $scanResults = @()

        switch ($Type) {		
            'TCP' {
                if ($Port) {
                    $TCPPorts = $Port
                } #endif
                if ($Delay) {
                    $TCPDelay = $Delay
                } #endif
            } #endTCP
            'UDP' {
                if ($Port) {
                    $UDPPorts = $Port
                } #if
                if ($Delay) {
                    $UDPDelay = $Delay
                } #if 
            } #endUDP				
            'All' {
                if ($Port) {
                    $UDPPorts = $Port
                    $TCPPorts = $Port
                } 
                if ($Delay) {
                    $UDPDelay = $Delay
                    $TCPDelay = $Delay
                }
            } #endAll
        } #endswitch

    }
    Process {
        foreach ($Computer in $ComputerName) {

            $ipAddr = Validate-IPAddress -ComputerName $Computer

            switch ($Type) {

                'TCP' {
                    $tcpResults = Get-TCPPortScan -ipAddress $ipAddr -PortNumber $TCPPorts -Delay $TCPDelay
                    $tcpResults | Add-Member -NotePropertyMembers @{
                        ComputerName = $Computer
                        Type = 'TCP'
                    }
                    $scanResults += $tcpResults
					
                }
                'UDP' {
                    $udpResults = Get-UDPPortScan -ipAddress $ipAddr -PortNumber $UDPPorts -Delay $UDPDelay
                    $udpResults | Add-Member -NotePropertyMembers @{
                        ComputerName = $Computer
                        Type = 'UDP'
                    }
                    $scanResults += $udpResults
												
                }
                'All' {
                    $tcpResults = Get-TCPPortScan -ipAddress $ipAddr -PortNumber $TCPPorts -Delay $TCPDelay
                    $tcpResults | Add-Member -NotePropertyMembers @{
                        ComputerName = $Computer
                        Type = 'TCP'
                    }
                    $scanResults += $tcpResults

                    $udpResults = Get-UDPPortScan -ipAddress $ipAddr -PortNumber $UDPPorts -Delay $UDPDelay
                    $udpResults | Add-Member -NotePropertyMembers @{
                        ComputerName = $Computer
                        Type = 'UDP'
                    }
                    $scanResults += $udpResults

														
                }
            } #endswitch		
        } #foreach
    } #process
    End {
        if ($ShowOnlyOpen) {
            $scanResults | Where-Object State -eq 'Open' | Select-Object IPAddress, ComputerName, Port, Type
        }
        else {
            $scanResults
        }
    }

} 

Function Validate-IPAddress {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$ComputerName
    )

    Process {
        if ($ComputerName -as [ipaddress]) {
            return $ComputerName
        }
        else {
            try {
                return $( ([System.Net.Dns]::GetHostEntry($ComputerName)).AddressList )[-1]
            } catch {
                Write-Error "$ComputerName - Invalid IP Address or HostName cannot be resolved"
            }
        }
    }
}

