& {

    #create event filter
    $instanceFilter = ([wmiclass]'\\.\root\subscription:__EventFilter').CreateInstance()
    $instanceFilter.QueryLanguage = 'WQL'
    $instanceFilter.Query = "Select * From __InstanceModificationEvent Within 5 Where TargetInstance ISA 'Win32_LocalTime' And (TargetInstance.Second=0 Or TargetInstance.Second=10 Or TargetInstance.Second=20 Or TargetInstance.Second=30 Or TargetInstance.Second=40 Or TargetInstance.Second=50)"
    #$instanceFilter.Query = "Select * From __InstanceModificationEvent Within 5 Where TargetInstance ISA 'Win32_Process' And TargetInstance.Name='Code.exe'"
    $instanceFilter.EventNamespace = 'root\cimv2'
    $instanceFilter.Name = 'FilterProgram'
    $result = $instanceFilter.Put()
    $filter = $result.Path

    #create event consumer
    $command = {Get-WmiObject -Query "Select * From Win32_Process Where Name='Code.exe'" | Remove-WmiObject}.ToString()
    [byte[]]$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $encodedCommand = [System.Convert]::ToBase64String($bytes)
    $exeCommand = "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -WindowStyle Hidden -encodedCommand $encodedCommand"
    $instanceConsumer = ([wmiclass]'\\.\root\subscription:CommandLineEventConsumer').CreateInstance()
    $instanceConsumer.Name = 'BlockExe'
    $instanceConsumer.CommandLineTemplate = $exeCommand
    $result = $instanceConsumer.Put()
    $consumer1 = $result.Path

    <# 
    # Log events
    $instanceConsumer = ([wmiclass]'\\.\root\subscription:LogFileEventConsumer').CreateInstance()
    $instanceConsumer.Name = 'LogEvents'
    $instanceConsumer.FileName = 'C:\Users\cnlocal\Desktop\LogEvents.log'
    $instanceConsumer.Text = "$(Get-Date) - %TargetInstance.ProcessName% - %TargetInstance.ProcessId% - %TargetInstance.ParentProcessId% `n"
    $result = $instanceConsumer.Put()
    $consumer2 = $result.Path	

	#bind event filter to consumer
	$instanceBinding = ([wmiclass]'\\.\root\subscription:__FilterToConsumerBinding').CreateInstance()
	$instanceBinding.Filter = $filter
	$instanceBinding.Consumer = $consumer2
	$result = $instanceBinding.Put()
	$binding = $result.Path

	#>

    #bind event filter to consumer
    $instanceBinding = ([wmiclass]'\\.\root\subscription:__FilterToConsumerBinding').CreateInstance()
    $instanceBinding.Filter = $filter
    $instanceBinding.Consumer = $consumer1
    $result = $instanceBinding.Put()
    $binding = $result.Path


}



