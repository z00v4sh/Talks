Function Clean-Persistance {

	
	# Check
	Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='FilterPersistance'" 
	Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='ConsumerExe'" 
	$filterName = '\\.\root\subscription:__EventFilter.Name="FilterPersistance"'
	Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | where { $_.Filter -eq $filterName } 

	# Clean
	Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='FilterPersistance'" | Remove-WmiObject
	Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='ConsumerExe'" | Remove-WmiObject
	$filterName = '\\.\root\subscription:__EventFilter.Name="FilterPersistance"'
	Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | where { $_.Filter -eq $filterName } | Remove-WmiObject

	Write-Output "Persistance cleaned"

	# Check
	Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='FilterPersistance'" 
	Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='ConsumerExe'" 
	$filterName = '\\.\root\subscription:__EventFilter.Name="FilterPersistance"'
	Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | where { $_.Filter -eq $filterName } 

}

Clean-Persistance

# Check
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='FilterProgram'" 
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='BlockExe'" 
$filterName = '\\.\root\subscription:__EventFilter.Name="FilterProgram"'
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | where { $_.Filter -eq $filterName } 
