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
        $FwPolicy = New-Object -ComObject HNetCfg.FwPolicy2
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
        $FwPolicy = New-Object -ComObject HNetCfg.FwPolicy2
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
        $FwPolicy = New-Object -ComObject HNetCfg.FwPolicy2
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
Function Get-FirewallProfile
{
    [CmdletBinding()]
    Param
    (
    $Profile
    )
    Begin
    {
        # Profiles
        $NET_FW_PROFILE2_DOMAIN = 1
        $NET_FW_PROFILE2_PRIVATE = 2
        $NET_FW_PROFILE2_PUBLIC = 4
        $NET_FW_PROFILE2_ALL = 2147483647
        
        $Profiles = @{1 = 'Domain'; 2 = 'Private'; 4 = 'Public'}
        }
    Process
    {
        if ($Profile -ne $NET_FW_PROFILE2_ALL)
        {
            Return $Profiles.Keys |Where-Object {$_ -band $Profile} |ForEach-Object {$Profiles.Item($_)}
            }
        else
        {
            Return "All"
            }
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