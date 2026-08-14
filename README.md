# CyberLab SOC Home Lab

A hands-on Security Operations Center (SOC) home lab built to collect
Windows telemetry, enrich endpoint visibility with Sysmon, develop
Splunk detections, validate alerts, and present security activity
through a SOC dashboard.

## Project Overview

This project simulates a small SOC monitoring workflow. A Windows
endpoint generates native Windows Security events and Sysmon telemetry,
a Splunk Universal Forwarder sends the data to Splunk Enterprise, and
SPL searches turn that telemetry into detections, alerts, and dashboard
panels.

The project focuses on practical blue-team skills: log onboarding,
Windows authentication analysis, endpoint telemetry, SPL development,
detection engineering, alert validation, troubleshooting, and dashboard
creation.

## Architecture

``` mermaid
flowchart LR
    W[Windows 11 Endpoint\nWIN11-01] -->|Windows Event Logs| UF[Splunk Universal Forwarder]
    S[Sysmon] -->|Sysmon Operational Log| UF
    UF -->|Forwarded telemetry| SP[Splunk Enterprise]
    SP --> D[Detection Searches]
    D --> A[Scheduled Alerts]
    SP --> DB[CyberLab SOC Dashboard]
```

## Technologies

-   Splunk Enterprise
-   Splunk Universal Forwarder
-   Microsoft Windows 11
-   Windows Security Event Logs
-   Sysmon
-   Sysmon Modular configuration
-   PowerShell
-   SPL (Search Processing Language)

## Detection Coverage

  ------------------------------------------------------------------------
  Detection        Telemetry                     Severity Purpose
  ---------------- ---------------- --------------------- ----------------
  Repeated failed  Windows Event ID                Medium Identify
  logins           4625                                   repeated
                                                          authentication
                                                          failures against
                                                          user accounts

  Suspicious       Sysmon Event ID                   High Detect
  PowerShell       1                                      PowerShell
  execution                                               command lines
                                                          containing
                                                          suspicious
                                                          execution
                                                          patterns

  PowerShell       Sysmon Event ID                   High Detect
  spawning command 1                                      PowerShell
  shell                                                   launching
                                                          `cmd.exe`

  PowerShell       Sysmon Event ID          Investigative Surface outbound
  network activity 3                                      network
                                                          connections
                                                          initiated by
                                                          PowerShell
  ------------------------------------------------------------------------

## 1. Windows Log Collection

The Windows endpoint was configured with the Splunk Universal Forwarder
to send Security, Application, and System event logs to the Splunk
server. Successful ingestion was validated in Splunk by grouping events
by source and sourcetype.

![Windows telemetry in Splunk](images/02-windows-events-splunk.png)

## 2. Failed Login Detection

Windows Event ID **4625** was used to monitor failed authentication
attempts. Test failures were generated and then investigated in Splunk
using account name, logon type, source network address, and workstation
fields.

A key troubleshooting discovery was that `Account_Name` was multivalue
in the ingested events. The first value could represent the machine
account while the second represented the failed target account. The
final dashboard logic therefore selects the target account rather than
blindly expanding every value.

### Failed user login count

``` spl
index=windows host=WIN11-01 EventCode=4625
| eval TargetAccount=mvindex(Account_Name,1)
| where isnotnull(TargetAccount) AND TargetAccount!="" AND TargetAccount!="-" AND NOT like(TargetAccount,"%$")
| stats count AS failed_logins
```

### Failed logins by account

``` spl
index=windows host=WIN11-01 EventCode=4625
| eval TargetAccount=mvindex(Account_Name,1)
| where isnotnull(TargetAccount) AND TargetAccount!="" AND TargetAccount!="-" AND NOT like(TargetAccount,"%$")
| stats count AS failed_attempts by TargetAccount
| sort - failed_attempts
| head 10
```

## 3. Sysmon Deployment and Forwarding

Sysmon was installed on the Windows endpoint using a modular
configuration to provide richer endpoint telemetry. The Sysmon
Operational event channel was then added to the Universal Forwarder
configuration and validated in Splunk.

During setup, the forwarder initially failed to subscribe to the Sysmon
channel with an access error. Troubleshooting included validating the
event channel locally, checking the effective Splunk input configuration
with `btool`, reviewing `splunkd.log`, and correcting the forwarder's
access before confirming ingestion.

## 4. Process Creation --- Sysmon Event ID 1

Sysmon Event ID **1** provided process creation telemetry including
image path, command line, user, and parent process. This allowed
PowerShell execution to be investigated with much more context than
native process counts alone.

### Suspicious PowerShell search

``` spl
index=windows host=WIN11-01 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<SysmonEventID>\\d+)</EventID>"
| where SysmonEventID="1"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)"
| where like(lower(Image), "%powershell.exe")
| eval detection_reason=case(
    like(lower(CommandLine), "%executionpolicy bypass%"), "Execution Policy Bypass",
    like(lower(CommandLine), "%encodedcommand%"), "Encoded Command",
    like(lower(CommandLine), "% -enc %"), "Encoded Command",
    like(lower(CommandLine), "%downloadstring%"), "DownloadString",
    like(lower(CommandLine), "%invoke-webrequest%"), "Web Request",
    like(lower(CommandLine), "%invoke-expression%"), "Invoke-Expression"
  )
| where isnotnull(detection_reason)
| table _time User detection_reason Image CommandLine ParentImage
| sort - _time
```

![Suspicious PowerShell detection](images/07-suspicious-powershell.png)

## 5. Network Connections --- Sysmon Event ID 3

Sysmon Event ID **3** was used to identify network connections initiated
by processes. PowerShell network activity was filtered to show the
initiating user, source IP, destination IP, protocol, and destination
port.

``` spl
index=windows host=WIN11-01 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<SysmonEventID>\\d+)</EventID>"
| where SysmonEventID="3"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)"
| rex field=_raw "<Data Name='Protocol'>(?<Protocol>[^<]+)"
| rex field=_raw "<Data Name='SourceIp'>(?<SourceIp>[^<]+)"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)"
| where like(lower(Image), "%powershell.exe")
| table _time User Image Protocol SourceIp DestinationIp DestinationPort
| sort - _time
```

![PowerShell network
connections](images/06-sysmon-network-connections.png)

## 6. Alerting

The detections were converted into scheduled Splunk alerts. Repeated
failed logins were assigned **Medium** severity, while suspicious
PowerShell execution and PowerShell-to-command-shell activity were
assigned **High** severity.

The alerts were tested by generating controlled activity on the Windows
endpoint and confirming that Splunk recorded the triggered alerts.

![Triggered Splunk alerts](images/08-triggered-alerts.png)

## 7. SOC Dashboard

The final **CyberLab SOC Overview** dashboard provides a compact
operational view of authentication and endpoint activity. The left side
summarizes failed user authentication, while the right side summarizes
suspicious PowerShell activity and network connections.

Dashboard panels:

-   Failed User Logins
-   Failed Logins by Account
-   Suspicious PowerShell Events
-   PowerShell Network Connections

![CyberLab SOC Overview](images/09-soc-dashboard.png)

## Troubleshooting Highlights

Several issues required investigation rather than simple configuration
changes:

-   Sysmon events existed locally but initially did not appear in
    Splunk.
-   `splunkd.log` exposed a Windows Event Log subscription/access error.
-   Effective Universal Forwarder settings were validated using `btool`.
-   Sysmon XML events did not initially expose `EventCode` as expected,
    so fields were extracted from `_raw` XML for reliable searches.
-   Windows 4625 `Account_Name` was multivalue, which initially produced
    misleading account counts when `mvexpand` was used.
-   Dashboard searches were refined so the failed-login KPI and account
    chart measure the same population.

These troubleshooting steps were an important part of the project
because they demonstrate validation of the complete telemetry pipeline
rather than assuming that configuration alone means collection is
working.

## Skills Demonstrated

-   SIEM administration and log onboarding
-   Splunk SPL search development
-   Windows Event Log analysis
-   Sysmon deployment and telemetry analysis
-   Detection engineering
-   Alert development and validation
-   PowerShell behavior analysis
-   Authentication monitoring
-   Endpoint network telemetry analysis
-   Troubleshooting log pipelines
-   SOC dashboard development

## Key Takeaway

This lab demonstrates an end-to-end detection workflow: **generate
activity → collect telemetry → investigate events → develop detections →
create alerts → visualize results**. It also documents the
troubleshooting required to make the pipeline reliable, which is a
critical part of real SOC engineering work.

## Repository Notes

The activity in this repository was generated in an isolated home-lab
environment for defensive security learning and detection validation.
Hostnames, usernames, addresses, and event data shown in screenshots
belong to the lab environment.
