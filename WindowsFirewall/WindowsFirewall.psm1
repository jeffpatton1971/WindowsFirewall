Add-Type @"
namespace PTECH
{
    namespace Networking
    {
        namespace Firewall
        {
            public class Rule
            {
                public const int NET_FW_ACTION_BLOCK = 0;
                public const int NET_FW_ACTION_ALLOW = 1;
                public const int NET_FW_RULE_DIR_IN = 1;
                public const int NET_FW_RULE_DIR_OUT = 2;

                public enum Profiles
                {
                    Domain = 1,
                    Private = 2,
                    Public = 4,
                    Any = 2147483647,
                }

                private string _Name;
                private string _DisplayName;
                private string _DisplayGroup;
                private string _Access;
                private string _State;
                private string _Profile;
                private string _Direction;
                private string[] _RemotePort;
                private string[] _LocalPort;
                private string _Protocol;
                private string _Description;
                private string _ApplicationPath;
                private string _Service;

                public string Name
                {
                    get { return _Name; }
                    set { _Name = value; }
                }
                public string DisplayName
                {
                    get { return _DisplayName; }
                    set { _DisplayName = value; }
                }
                public string DisplayGroup
                {
                    get { return _DisplayGroup; }
                    set { _DisplayGroup = value; }
                }
                public string Access
                {
                    get { return _Access; }
                    set 
                    {
                        switch (System.Convert.ToInt16(value))
                        {
                            case NET_FW_ACTION_ALLOW :
                                _Access = "Allow";
                                break;
                            case NET_FW_ACTION_BLOCK :
                                _Access = "Block";
                                break;
                            default :
                                _Access = "Not Configured";
                                break;
                        }
                    }
                }
                public string State
                {
                    get { return _State; }
                    set 
                    {
                        if (System.Convert.ToBoolean(value) == true)
                        {
                            _State = "Enabled";
                        }
                        else
                        {
                            _State = "Disabled";
                        }
                    }
                }
                public string Profile
                {
                    get { return _Profile; }
                    set
                    {
                        if (value.Contains(" ") == false)
                        {
                            switch (value)
                            {
                                case "Domain":
                                    _Profile = "1";
                                    break;
                                case "Private":
                                    _Profile = "2";
                                    break;
                                case "Public":
                                    _Profile = "4";
                                    break;
                                case "Any":
                                    _Profile = "2147483647";
                                    break;
                                default:
                                    _Profile = value;
                                    break;
                            }
                        }
                        else
                        {
                            string[] Values = value.Split(new char[] {' '});
                            int NewValue = 0;
                            foreach (string item in Values)
                            {
                                if (item.ToLower() == "domain")
                                {
                                    NewValue += 1;
                                }
                                if (item.ToLower() == "private")
                                {
                                    NewValue += 2;
                                }
                                if (item.ToLower() == "public")
                                {
                                    NewValue += 4;
                                }
                                if (item.ToLower() == "any")
                                {
                                    _Profile = "2147483647";
                                }
                            }
                            _Profile = NewValue.ToString();
                        }
                    }
                }
                public string Direction
                {
                    get { return _Direction; }
                    set 
                    {
                        switch (System.Convert.ToInt16(value))
                        {
                            case NET_FW_RULE_DIR_IN:
                                _Direction = "Inbound";
                                break;
                            case NET_FW_RULE_DIR_OUT:
                                _Direction = "Outbound";
                                break;
                        }
                    }
                }
                public string[] RemotePort
                {
                    get { return _RemotePort; }
                    set { _RemotePort = value; }
                }
                public string[] LocalPort
                {
                    get { return _LocalPort; }
                    set { _LocalPort = value; }
                }
                public string Protocol
                {
                    get { return _Protocol; }
                    set { _Protocol = value; }
                }
                public string Description
                {
                    get { return _Description; }
                    set { _Description = value; }
                }
                public string ApplicationPath
                {
                    get { return _ApplicationPath; }
                    set { _ApplicationPath = value; }
                }
                public string Service
                {
                    get { return _Service; }
                    set { _Service = value; }
                }

                public string[] GetProfiles()
                {
                    string[] Result;
                    switch (System.Convert.ToInt64(this._Profile))
                    {
                        case (long)Profiles.Domain:
                            Result = new string[] { "Domain" };
                            break;
                        case (long)Profiles.Private:
                            Result = new string[] { "Private" };
                            break;
                        case ((long)Profiles.Domain + (long)Profiles.Private):
                            Result = new string[] { "Domain", "Private" };
                            break;
                        case (long)Profiles.Public:
                            Result = new string[] { "Public" };
                            break;
                        case ((long)Profiles.Domain + (long)Profiles.Public):
                            Result = new string[] { "Domain", "Public" };
                            break;
                        case ((long)Profiles.Private + (long)Profiles.Public):
                            Result = new string[] { "Private", "Public" };
                            break;
                        case ((long)Profiles.Domain + (long)Profiles.Private + (long)Profiles.Public):
                            Result = new string[] { "Domain", "Private", "Public" };
                            break;
                        case (long)Profiles.Any:
                            Result = new string[] { "Any" };
                            break;
                        default:
                            Result = new string[] { "" };
                            break;
                    }
                    return Result;
                }

                public Rule()
                {
                }

                public Rule(string Name)
                {
                    this._Name = Name;
                }
            }
        }
    }
}
"@
$FwPolicy = New-Object -ComObject "HNetCfg.FwPolicy2";
$FwMgr = New-Object -ComObject "HNetCfg.FwMgr";

Function Get-FirewallRule
{
    [CmdletBinding()]
    [OutputType([PTECH.Networking.Firewall.Rule])]
    param
    (
    [string]$Name
    )
    Begin
    {
        #$FwPolicy = New-Object -ComObject HNetCfg.FwPolicy2
        $CurrentProfiles = $FwPolicy.CurrentProfileTypes
        if ($Name)
        {
            $RuleObjects = $FwPolicy.Rules |Where-Object {$_.Name -eq $Name}
            }
        else
        {
            $RuleObjects = $FwPolicy.Rules
            }
        }
    Process
    {
        return $RuleObjects
        }
    End
    {
        }
    }
Function New-FirewallRule
{
    [CmdletBinding()]
    Param
    (
    $Rule
    )
    Begin
    {
        # Direction
        #$FwPolicy = New-Object -ComObject HNetCfg.FwPolicy2
        $RuleObjects = $FwPolicy.Rules
        }
    Process
    {
        }
    End
    {
        $RuleObjects.Add($Rule)
        }
    }
Function Remove-FirewallRule
{
    [CmdletBinding()]
    Param
    (
        [System.String]
		$Name
    )
    Begin
    {
        #$FwPolicy = New-Object -ComObject HNetCfg.FwPolicy2
        $RuleObjects = $FwPolicy.Rules
        $CurrentProfiles = $FwPolicy.CurrentProfileTypes
        $FwRule = Get-FirewallRule -Name $Name
        }
    Process
    {
        $RuleObjects.Remove($FwRule.Name)
        }
    End
    {
        }
    }
Function Test-FirewallRule
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
    [PTECH.Networking.Firewall.Rule]$FirewallRule1,
    [PTECH.Networking.Firewall.Rule]$FirewallRule2
    )
    Begin
    {
        $Result = $true
        }
    Process
    {
        $Properties = $FirewallRule1 |Get-Member -MemberType Properties |Select-Object -Property Name
        foreach ($Property in $Properties)
        {
            $Compare = Compare-Object -ReferenceObject $FirewallRule1 -DifferenceObject $FirewallRule2 -Property $Property.Name
            if ($Compare)
            {
                $Result = $false
                }
            }
        }
    End
    {
        return $Result
        }
    }
Function ConvertTo-FwRule
{
    param
    (
    [Parameter(Mandatory=$true)]
    [PTECH.Networking.Firewall.Rule]$Rule
    )
    Begin
    {
        # Direction
        $NET_FW_RULE_DIR_IN = 1
        $NET_FW_RULE_DIR_OUT = 2

        # Action
        $NET_FW_ACTION_BLOCK = 0
        $NET_FW_ACTION_ALLOW = 1

        # Protocol
        $ProtocolLookup = @{1=”ICMPv4”;2=”IGMP”;6=”TCP”;17=”UDP”;41=”IPv6”;43=”IPv6Route”;44=”IPv6Frag”;47=”GRE”;58=”ICMPv6”;59=”IPv6NoNxt”;60=”IPv6Opts”;112=”VRRP”;113=”PGM”;115=”L2TP”;
                         ”ICMPv4”=1;”IGMP”=2;”TCP”=6;”UDP”=17;”IPv6”=41;”IPv6Route”=43;”IPv6Frag”=44;”GRE”=47;”ICMPv6”=48;”IPv6NoNxt”=59;”IPv6Opts”=60;”VRRP”=112;”PGM”=113;”L2TP”=115}

        $FwRule = New-Object -ComObject HNetCfg.FWRule
        }
    Process
    {
        $FwRule.Name = $Rule.Name
        $FwRule.Description = $Rule.Description
        $FwRule.ApplicationName = $Rule.ApplicationPath
        $FwRule.serviceName = $Rule.Service
        $FwRule.Grouping = $Rule.DisplayGroup
        $FwRule.Profiles = $Rule.Profile
        [int]$Protocol = $ProtocolLookup.Keys |Where-Object {$_ -eq $Rule.Protocol} |ForEach-Object {$ProtocolLookup.Item($_)}
        $FwRule.Protocol = $Protocol
        $FwRule.RemotePorts = [string]$Rule.RemotePort
        $FwRule.LocalPorts = [string]$Rule.LocalPort
        switch ($Rule.Access)
        {
            'Block'
            {
                $FwRule.Action = $NET_FW_ACTION_BLOCK
                }
            'Allow'
            {
                $FwRule.Action = $NET_FW_ACTION_ALLOW
                }
            default
            {
                $FwRule.Action = 'Not Configured'
                }
            }

        if ($Rule.State -eq 'Enabled')
        {
            $FwRule.Enabled = $true
            }
        else
        {
            $FwRule.Enabled = $false
            }

        $Rule.Profile = $Profile
    
        switch ($Rule.Direction)
        {
            'Inbound'
            {
                $FwRule.Direction = $NET_FW_RULE_DIR_IN
                }
            'Outbound'
            {
                $FwRule.Direction = $NET_FW_RULE_DIR_OUT
                }
            }
        }
    End
    {
        return $FwRule
        }
    }
Function ConvertTo-Rule
{
    Param
    (
    $FwRule
    )
    Begin
    {
        }
    Process
    {
        [PTECH.Networking.Firewall.Rule]$Rule = New-Object PTECH.Networking.Firewall.Rule($FwRule.Name)
        $Rule.DisplayGroup = $FwRule.Grouping
        $Rule.Access = $FwRule.Action
        $Rule.State = $FwRule.Enabled
        $Rule.Profile = $FwRule.Profiles
        $Rule.Direction = $FwRule.Direction
        $Rule.RemotePort = $FwRule.RemotePorts
        $Rule.LocalPort = $FwRule.LocalPorts
        $Rule.Protocol = $FwRule.Protocol
        $Rule.Description = $FwRule.Description
        $Rule.ApplicationPath = $FwRule.ApplicationName
        $Rule.Service = $FwRule.serviceName
        Write-Output $Rule
        }
    End
    {
        }
    }
Function Get-FWServices
{
    <#
        .SYNOPSIS
            Return a list of services allowed through the firewall
        .DESCRIPTION
            This function returns a list of services and related ports that are allowed through the Windows Firewall
        .EXAMPLE
            Get-FWServices |Format-Table

            Property  Name           Type Customize IpVersion     Scope RemoteAdd   Enabled Protocol  Port
                                                    d                     resses
            --------  ----           ---- --------- ---------     ----- ---------   ------- --------  ----
            Service   File a...         0     False         2         1 LocalS...      True -         -
            Port      File a...         -         -         2         1 LocalS...      True 17        138
            Service   Networ...         1     False         2         1 LocalS...     False -         -
            Port      Networ...         -         -         2         1 LocalS...     False 6         2869
            Service   Remote...         2     False         2         0 *             False -         -
            Port      Remote...         -         -         2         0 *             False 6         3389

            Description
            -----------
            This example shows the output of the function piped through Format-Table
        .NOTES
        .LINK
            https://code.google.com/p/mod-posh/wiki/WindowsFirewallManagement#Get-FWServices
    #>
    [CmdletBinding()]
    Param
        (
        [Parameter(Mandatory=$true)]
        [__ComObject]$Profile
        )
    Begin
    {
        #$FwMgr = New-Object -ComObject "HNetCfg.FwMgr"
        #$FirewallPolicy = $FwMgr.LocalPolicy.CurrentProfile 
        }
    Process
    {
        }
    End
    {
        Return $Profile.Services
        }
    }
Function Get-FWApplications
{
    <#
        .SYNOPSIS
            Return a list of applicaitons allowed
        .DESCRIPTION
            This function returns a list of applications that have been authorized through the Windows Firewall.
        .EXAMPLE
            Get-FWApplications |Format-Table

            ProcessImageFi Name               IpVersion Property      RemoteAddress       Enabled         Scope
            leName                                                    es
            -------------- ----               --------- --------      -------------       -------         -----
            C:\Program ... VMware Authd               2 Application   *                      True             0
            C:\Program ... Bonjour Ser...             2 Application   *                      True             0
            C:\users\je... dropbox.exe                2 Application   *                      True             0
            C:\program ... Opera Inter...             2 Application   *                      True             0
            C:\program ... Microsoft O...             2 Application   *                      True             0

            Description
            -----------
            Sample output piped through Format-Table
        .NOTES
        .LINK
            https://code.google.com/p/mod-posh/wiki/WindowsFirewallManagement#Get-FWApplications
    #>
    [CmdletBinding()]
    Param
        (
        [Parameter(Mandatory=$true)]
        [__ComObject]$Profile
        )
    Begin
    {
        #$FwMgr = New-Object -ComObject "HNetCfg.FwMgr"
        #$FirewallPolicy = $FwMgr.LocalPolicy.CurrentProfile 
        }
    Process
    {
        }
    End
    {
        Return $Profile.AuthorizedApplications
        }
    }
Function Get-FWGloballyOpenPorts
{
    <#
        .SYNOPSIS
            Return ports that are open across all profiles.
        .DESCRIPTION
            This function returns a list of Globally Open Ports that are available on the Windows Firewall
        .EXAMPLE
            Get-FWGloballyOpenPorts |Format-Table

            RemoteAddres Name            IpVersion         Port       Scope    Protocol     Enabled     BuiltIn
            ses
            ------------ ----            ---------         ----       -----    --------     -------     -------
            *            Allowed P...            2          456           0          17        True       False
            *            Allowed P...            2          123           0           6        True       False

            Description
            -----------
            Sample output piped through Format-Table
        .NOTES
        .LINK
            https://code.google.com/p/mod-posh/wiki/WindowsFirewallManagement#Get-FWGloballyOpenPorts
    #>
    [CmdletBinding()]
    Param
        (
        [Parameter(Mandatory=$true)]
        [__ComObject]$Profile
        )
    Begin
    {
        #$FwMgr = New-Object -ComObject "HNetCfg.FwMgr"
        #$FirewallPolicy = $FwMgr.LocalPolicy.CurrentProfile 
        }
    Process
    {
        }
    End
    {
        Return $Profile.GloballyOpenPorts
        }
    }
Function New-FWPortOpening
{
    <#
        .SYNOPSIS
            Create a port opening in Windows Firewall.
        .DESCRIPTION
            This function creates a port opening in the Windows Firewall.
        .EXAMPLE
            New-FWPortOpening -RuleName Rule1 -RuleProtocol 6 -RulePort 123 -RuleRemoteAddresses *
                
            Get-FWGloballyOpenPorts

            RemoteAddresses : *
            Name            : Rule1
            IpVersion       : 2
            Port            : 123
            Scope           : 0
            Protocol        : 6
            Enabled         : False
            BuiltIn         : False
                
            Description
            -----------
            This example shows setting a portopening, and then viewing the newly created rule.
        .NOTES
            In order for this function to work properly you will need to run this function in an elevated PowerShell
            prompt, as well as have the permissions to modify the firewall.
        .LINK
            https://code.google.com/p/mod-posh/wiki/WindowsFirewallManagement#New-FWPortOpening
    #>
    [CmdletBinding()]
    Param
        (
        [string]$RuleName,
        [int]$RuleProtocol,
        [double]$RulePort,
        [string]$RuleRemoteAddresses,
        [bool]$RuleEnabled
        )
    Begin
    {
        #$FwMgr = New-Object -ComObject HNetCfg.FwMgr
        $FwProfile = $FwMgr.LocalPolicy.CurrentProfile
        }
    Process
    {
        $FwPort = New-Object -ComObject HNetCfg.FwOpenPort
        $FwPort.Name = $RuleName
        $FwPort.Protocol = $RuleProtocol
        $FwPort.Port = $RulePort
        $FwPort.RemoteAddresses = $RuleRemoteAddresses
        $FwPort.Enabled = $RuleEnabled
        }
    End
    {
        $FwProfile.GloballyOpenPorts.Add($FwPort)
        }
    }
function Get-FirewallProfile
{
    Param
    (
    [ValidateSet('Domain','Public','Private','Current')]
    [string]$Type
    )
    Begin
    {
        switch ($Type)
        {
            'Domain'
            {
                $FwMgr.LocalPolicy.GetProfileByType(0)
                }
            'Private'
            {
                $FwMgr.LocalPolicy.GetProfileByType(1)
                }
            'Public'
            {
                $FwMgr.LocalPolicy.GetProfileByType(2)
                }
            default
            {
                $FwMgr.LocalPolicy.CurrentProfile
                }
            }
        }
    Process
    {
        }
    End
    {
        }
    }