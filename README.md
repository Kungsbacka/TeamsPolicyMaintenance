# TeamsPolicyMaintenance

Sets Teams app permission and setup policy based on user filters. For our purposes the filtering
is done in our on-prem AD, but the script is easy to adapt to other sources.

Get encrypted password with Get-Credential or Read-Host -AsSecureString.

```PowerShell
Read-Host -AsSecureString | ConvertFrom-SecureString | Set-Clipboard
```

If you run the script as a scheduled task with a gMSA, you can use [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) to start a PowerShell prompt to get the password encrypted with the gMSA credentials.

```Batchfile
psexec.exe -i -u DOMAIN\gmsa$ powershell.exe
```
