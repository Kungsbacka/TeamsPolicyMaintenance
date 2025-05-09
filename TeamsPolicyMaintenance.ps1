﻿Import-Module -Name 'MicrosoftTeams'

. "$PSScriptRoot\Config.ps1"

function Write-Log
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Message,
        [Parameter(Mandatory=$false)]
        [string]
        $Target

    )

    if ((Test-Path -Path $Script:Config.LogPath)) {
        $path = Join-Path -Path $Script:Config.LogPath ('TeamsPolicyMaintenance_' + (Get-Date -Format 'yyyy-MM-dd') + '.log')
        $line = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $line += ' '
        if ($Target) {
            $line += $Target
            $line += ' '
        }
        $line += $Message
        Out-File -FilePath $path -InputObject $line -Encoding UTF8 -Append
    }

}

$credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
    $Script:Config.TeamsUser
    $Script:Config.TeamsPassword | ConvertTo-SecureString
)

Connect-MicrosoftTeams -Credential $credential

$policyMapping = @{}
foreach ($mapping in $Script:Config.PolicyMapping) {
    foreach($user in (Get-ADUser -Filter $mapping.Filter)) {
        if (-not $policyMapping.ContainsKey($user.UserPrincipalName)) {
            $policyMapping.Add($user.UserPrincipalName, $mapping.Policy)
        }
    }
}

foreach ($csUser in (Get-CsOnlineUser -WarningAction 'SilentlyContinue')) {
    $teamsAppSetupPolicy = $Script:Config.DefaultPolicy.TeamsAppSetupPolicy
    $policy = $policyMapping[$csUser.UserPrincipalName]
    if ($policy) {
        $teamsAppSetupPolicy = $policy.TeamsAppSetupPolicy
    }
    $teamsAppSetupPolicyName = $teamsAppSetupPolicy -replace '^Tag:', ''
    if ($teamsAppSetupPolicyName -eq '') {
        $teamsAppSetupPolicyName = $null
    }
    if ($csUser.TeamsAppSetupPolicy.Name -ne $teamsAppSetupPolicyName) {
        try {
            Grant-CsTeamsAppSetupPolicy -Identity $csUser.Identity -PolicyName $teamsAppSetupPolicy -ErrorAction 'Stop'
        }
        catch {
            # Skip users without license
            if ($_.ToString() -notlike 'Management object not found*') {
                Write-Log -Target $csUser.UserPrincipalName -Message "Error: failed to change Teams App Setup Policy: $($_.ToString())"
            }
            continue
        }
        Write-Log -Target $csUser.UserPrincipalName -Message ('Changed Teams App Setup Policy from "' + $csUser.TeamsAppSetupPolicy + '" to "' + $teamsAppSetupPolicyName + '"')
    }
}
