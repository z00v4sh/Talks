Function Get-ReconUsername {
    @{
        Username = $env:USERNAME
    }
}

Function Get-ReconDomain {
    @{
        Domain = $env:USERDOMAIN
    }
}

Function Get-ReconComputername {
    @{
        Computername = $env:COMPUTERNAME
    }
}

Function Get-ReconUserGroupMembership {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Username = $env:USERNAME
    )
    try {
        Get-WmiObject -Query "Associators of {Win32_UserAccount.Name='$Username',Domain='$env:USERDOMAIN'} Where ResultClass=Win32_Group" -ErrorAction Stop
    } catch {
        Write-Error "Username not found"
    }
}

Function Get-ReconCurrentUserGroupMembership {

    $username = $env:USERNAME

    Get-ReconUserGroupMembership -Username $username

}

Function Get-ReconGroupMembers {
    [CmdletBinding()]
    Param(

        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Group,

        [Parameter(Mandatory, ParameterSetName = 'Domain')]
        [switch]$Domain,

        [Parameter(Mandatory, ParameterSetName = 'Local')]
        [switch]$Local,

        [Parameter()]
        [switch]$OnlyEnabled
    )

    switch ($PSCmdlet.ParameterSetName) {
        'Domain' { $win32GroupDomain = $env:USERDOMAIN }
        'Local' { $win32GroupDomain = $env:COMPUTERNAME }
    }
    try {

    
        $users = Get-WmiObject -Query "Associators of {Win32_Group.Name='$Group',Domain='$win32GroupDomain'} Where ResultClass=Win32_UserAccount" -ErrorAction Stop

        if ($OnlyEnabled) {
            $users | where Disabled -eq $false
        }
        else {
            $users
        }
    } catch {
        Write-Error "Group not found"
    }
}

Function Get-ReconLocalAdministrators {
    Get-ReconGroupMembers -Group Administrators -Local -OnlyEnabled
}

Function Get-ReconDomainAdministrators {
    Get-ReconGroupMembers -Group 'Domain Admins' -Domain -OnlyEnabled
}

Function Get-ReconIPConfig {
    [CmdletBinding()]
    Param(
        [Parameter()]
        [switch]$All
    )

    $ipConfig = Get-WmiObject -Query "Select * From Win32_NetworkAdapterConfiguration"
    if (-not $All) {
        $ipConfig | where IPEnabled -eq $true
    }
    else {
        $ipConfig
    }
}

Function Get-ReconNetTCPConnections {
    [CmdletBinding()]
    Param(
        [Parameter()]
        [ValidateSet(
            'Closed', 
            'Listen', 
            'SynSent', 
            'SynReceived', 
            'Established', 
            'FinWait1', 
            'FinWait2', 
            'CloseWait',
            'Closing',
            'LastAck',
            'TimeWait',
            'DeleteTCB'
        )]
        [string]$State = 'Established',

        [Parameter()]
        [switch]$AllInfo
    )

    $TCPConnectionStates = @{
        'Closed' = 1
        'Listen' = 2
        'SynSent' = 3 
        'SynReceived' = 4  
        'Established' = 5 
        'FinWait1' = 6 
        'FinWait2' = 7
        'CloseWait' = 8 
        'Closing' = 9
        'LastAck' = 10
        'TimeWait' = 11
        'DeleteTCB' = 12
    }

    $NetTCPConnections = Get-WmiObject -Namespace root\StandardCimv2 -Query "Select * From MSFT_NetTCPConnection"
    $stateCode = $TCPConnectionStates[$State]

    if (-not $AllInfo) {
        $NetTCPConnections | Where State -ceq $stateCode | select LocalAddress, LocalPort, RemoteAddress, RemotePort, 
        @{N = 'OwningProcessID'; E = {$_.OwningProcess}}, 
        @{N = 'OwningProcess'; E = {
                (Get-WmiObject -Query "Select Name From Win32_Process Where Handle=$($_.OwningProcess)").Name
            }
        }, 
        @{N = "Status"; E = {$State}}
    }
    else {
        $NetTCPConnections | Where State -ceq $stateCode
    }

}

Function Get-ReconDNSCache {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ParameterSetName = 'Specific')]
        [ValidateSet(
            'A',
            'NS',
            'CNAME',
            'SOA',
            'PTR',
            'MX',
            'AAAA',
            'SRV'
        )]
        [string]$Type = 'A',

        [Parameter(Mandatory, ParameterSetName = 'Everything')]
        [switch]$Everything,

        [Parameter()]
        [switch]$AllInfo
    )

    $dnsTypeMeaning = @{
        1 = 'A' 
        2 = 'NS'
        5 = 'CNAME'
        6 = 'SOA'
        12 = 'PTR'
        15 = 'MX'
        28 = 'AAAA'
        33 = 'SRV'
    }

    $dnsTypeValue = New-Object hashtable
    
    foreach ($key in ($dnsTypeMeaning.Keys)) {
        $value = $dnsTypeMeaning[$key]
        $dnsTypeValue[$value] = $key
    }

    $dnsRecords = Get-WmiObject -Namespace root\StandardCimv2 -Query "Select * From MSFT_DNSClientCache"

    switch ($PSCmdlet.ParameterSetName) {
        'Specific' {
            $typeCode = $dnsTypeValue[$Type]
            $dnsCache = $dnsRecords | where Type -ceq $typeCode            
        }
        'Everything' {
            $dnsCache = $dnsRecords
        }
    }
    
    if (-not $AllInfo) {
        $dnsCache | select Data, Entry, @{N = 'Type'; E = {$dnsTypeMeaning[[int]($_.Type)]}}
    }
    else {
        $dnsCache
    }
}

Function Get-ReconAV {
    try {
        $avs = Get-WmiObject -Namespace root\SecurityCenter2 -Query "Select * From AntiVirusProduct" -ErrorAction Stop
        
        foreach ($av in $avs) {
            [string]$productState = [System.convert]::ToString($av.productState, 16)
            $enabledCode = $productState.Substring(1, 2)
            $updatedCode = $productState.Substring(3, 2)
    
            $enabled = & {
                if ($enabledCode -ceq '10' -or $enabledCode -eq '11') {
                    return $true
                }
                else {
                    return $false
                }
            }

            $updated = & {
                if ($updatedCode -ceq '00') { 
                    return $true
                }
                else {
                    return $false
                }
            }

            [pscustomobject]@{
                Product = $av.displayName
                Enabled = $enabled
                Updated = $updated
            }
        }
    } catch {
        Write-Output "This is not a workstation"
    }
}

Function Get-ReconDomainController {
    Get-WmiObject -Class Win32_NTDomain
}

Function Get-ReconInstalledAppsByRegistry {

    $apps64 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate 

    $apps32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

    $apps64 | Add-Member @{'Type' = 'x64'}
    $apps32 | Add-Member @{'Type' = 'x86'}

    $apps64 + $apps32 | where DisplayName -ne $null
}

Function Get-ReconAmIAdmin {
    ([Security.Principal.WindowsPrincipal] ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 
}

Function Get-ReconDomainComputers {

    $adsiSearcher = [adsisearcher]'(objectclass=computer)'
    $computers = $adsiSearcher.FindAll()

    foreach ($computer in $computers) {

        New-Object -TypeName psobject -Property ([ordered]@{
                'Computername' = $computer.Properties.cn[0]
                'Full DnsHostName' = $computer.properties.dnshostname[0]
                'IP Address' = & {
                    $computername = $computer.properties.dnshostname[0]
                    try {
                        $ip = ([System.Net.Dns]::GetHostByName($computername)).AddressList
                    } catch {
                        $ip = 'Could not get IP Address'
                    }
                    return $ip
                }
                'Operating System' = $computer.properties.operatingsystem[0]
                'Operating System Version' = $computer.properties.operatingsystemversion[0]        
            })
     
    }    
}

Function Get-ReconDomainUsers {
    $adsisearcher = [adsisearcher]'(objectclass=user)'
    $users = $adsisearcher.FindAll()

    foreach ($user in $users) {
        $properties = [hashtable]$user.Properties

        $useraccountcontrol = $properties['useraccountcontrol'][0]

        New-Object -TypeName psobject -Property ([ordered]@{
                
                Name = $properties['name'][0]
                'Distinguished Name' = $properties['distinguishedname'][0]
                Description = & {
                    if ($properties.ContainsKey('description')) {
                        return $properties['description'][0]
                    }
                    else {
                        return 'Description not found'
                    }
                }
                'Last Password Change' = & {
                    if ($properties['pwdlastset'][0] -ne 0) {
                        return (Get-Date 1/1/1601).AddSeconds($properties['pwdlastset'][0] / 10000000)
                    }
                    else {
                        return 'User must change password at next logon'
                    }
                }				
                'Password Expired' = [bool]($useraccountcontrol -band 8388608)
                'User Creation Time' = $properties['whencreated'][0]
                'Last Logon' = & {
                    if ($properties.ContainsKey('lastlogon') -and $properties['lastlogon'][0] -ne 0 ) {
                        return (Get-Date 1/1/1601).AddSeconds($properties['lastlogon'][0] / 10000000)
                    }
                    else {
                        return 'Last Logon not found'
                    }
                }
                'Last Logon Timestamp' = & {
                    if ($properties.ContainsKey('lastlogontimestamp') -and $properties['lastlogontimestamp'][0] -ne 0 ) {
                        return (Get-Date 1/1/1601).AddSeconds($properties['lastlogontimestamp'][0] / 10000000)
                    }
                    else {
                        return 'Last Logon Timestamp not found'
                    }
                }
                'Groups' = & {
                    if ($properties.ContainsKey('memberof')) {
                        return $properties['memberof']
                    }
                    else {
                        return 'Groups not found'
                    }
                }
                Enabled = -not [bool]($useraccountcontrol -band 2)
                'Normal Account' = [bool]($useraccountcontrol -band 512)
            })
    }

}
