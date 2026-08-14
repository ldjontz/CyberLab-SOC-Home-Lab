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
