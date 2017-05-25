Function Clean-bypassUAC {
	
    $exefilePath = "HKCU:\Software\Classes\exefile"
    if (Test-Path $exefilePath) {
        Remove-Item $exefilePath -Recurse -Force
        Write-Output "Removed registry entries"
    }
    else {
        Write-Output "Nothing here"
    }
}

Function Clean-PayloadFile {

    $path = 'C:\Users\cnlocal\AppData\Local\Temp\rts.txt'
    if (Test-Path $path) {
        Remove-Item $path
        Write-Output "File $path removed"
    }
    else {
        Write-Output 'Nothing here ...'
    }
}

Clean-bypassUAC
Clean-PayloadFile