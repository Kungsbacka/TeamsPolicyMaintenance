$Script:Config = @{
    TeamsUser = 'TeamsAdmin@tenant.microsoftonline.com'
    TeamsPassword = '<Encrypted password>'
    DefaultPolicy = @{
        TeamsAppPermissionPolicy = $null
        TeamsAppSetupPolicy = $null
    }
    PolicyMapping = @(
        @{
            Filter = "Department -eq 'HR'"
            Policy = @{
                TeamsAppPermissionPolicy = 'Tag:HR policy'
                TeamsAppSetupPolicy = 'Tag:HR policy'
            }
        }
        @{
            Filter = "Department -eq 'Finance' -and Title -eq 'CFO'"
            Policy = @{
                TeamsAppPermissionPolicy = 'Tag:Executive policy'
                TeamsAppSetupPolicy = 'Tag:Executive policy'
            }
        }
    )
}
