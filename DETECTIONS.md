# CyberLab SOC Detection Searches

## Failed User Logins

``` spl
index=windows host=WIN11-01 EventCode=4625
| eval TargetAccount=mvindex(Account_Name,1)
| where isnotnull(TargetAccount) AND TargetAccount!="" AND TargetAccount!="-" AND NOT like(TargetAccount,"%$")
| stats count AS failed_logins
```

## Failed Logins by Account

``` spl
index=windows host=WIN11-01 EventCode=4625
| eval TargetAccount=mvindex(Account_Name,1)
| where isnotnull(TargetAccount) AND TargetAccount!="" AND TargetAccount!="-" AND NOT like(TargetAccount,"%$")
| stats count AS failed_attempts by TargetAccount
| sort - failed_attempts
| head 10
```

## Suspicious PowerShell

``` spl
index=windows host=WIN11-01
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<SysmonEventID>\d+)</EventID>"
| where SysmonEventID="1"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| where like(lower(Image), "%powershell.exe")
| eval suspicious=if(
    like(lower(CommandLine), "%executionpolicy bypass%")
    OR like(lower(CommandLine), "%-encodedcommand%")
    OR like(lower(CommandLine), "% -enc %")
    OR like(lower(CommandLine), "%downloadstring%")
    OR like(lower(CommandLine), "%invoke-webrequest%")
    OR like(lower(CommandLine), "%invoke-expression%"),
    1,
    0
)
| stats sum(suspicious) AS suspicious_powershell_events
```

## PowerShell Network Connections
```
index=windows host=WIN11-01
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<SysmonEventID>\d+)</EventID>"
| where SysmonEventID="3"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)"
| where like(lower(Image), "%powershell.exe")
| table _time User DestinationIp DestinationPort
| sort - _time
```
