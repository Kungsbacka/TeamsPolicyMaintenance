Import-Module -Name 'SkypeOnlineConnector'

. "$PSScriptRoot\Config.ps1"

$credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
    $Script:Config.TeamsUser
    $Script:Config.TeamsPassword | ConvertTo-SecureString
)

if (-not $session) {
    $session = New-CsOnlineSession -Credential $credential
    $params = @{
        Session = $session
        AllowClobber = $true
        CommandName = @(
            'Get-CsOnlineUser'
            'Grant-CsTeamsAppPermissionPolicy'
            'Grant-CsTeamsAppSetupPolicy'
        )
    }
    $null = Import-PSSession @params
}

$policyMapping = @{}
foreach ($mapping in $Script:Config.PolicyMapping) {
    foreach($user in (Get-ADUser -Filter $mapping.Filter)) {
        if (-not $policyMapping.ContainsKey($user.UserPrincipalName)) {
            $policyMapping.Add($user.UserPrincipalName, $mapping.Policy)
        }
    }
}

foreach ($csUser in (Get-CsOnlineUser -ResultSize Unlimited -WarningAction 'SilentlyContinue')) {
    $teamsAppPermissionPolicy = $Script:Config.DefaultPolicy.TeamsAppPermissionPolicy
    $teamsAppSetupPolicy = $Script:Config.DefaultPolicy.TeamsAppSetupPolicy
    $policy = $policyMapping[$csUser.UserPrincipalName]
    if ($policy) {
        $teamsAppPermissionPolicy = $policy.TeamsAppPermissionPolicy
        $teamsAppSetupPolicy = $policy.TeamsAppSetupPolicy
    }
    if ($csUser.TeamsAppPermissionPolicy -ne $teamsAppPermissionPolicy) {
        Grant-CsTeamsAppPermissionPolicy -Identity $csUser.Identity -PolicyName $teamsAppPermissionPolicy
    }
    if ($csUser.TeamsAppSetupPolicy -ne $teamsAppSetupPolicy) {
        Grant-CsTeamsAppSetupPolicy -Identity $csUser.Identity -PolicyName $teamsAppSetupPolicy
    }
}
