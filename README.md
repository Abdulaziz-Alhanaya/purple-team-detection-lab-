Purple Team Detection Lab

A hands-on cybersecurity home lab demonstrating attack simulation, detection engineering, and automated alerting using Windows 11, Sysmon, and Splunk.

Objective

Simulate a known MITRE ATT&CK technique, investigate its endpoint telemetry, develop a Splunk detection query, and configure an automated alert.

Technique: T1059.001 – Command and Scripting Interpreter: PowerShell

Lab Architecture

* Attacker: Kali Linux
* Victim: Windows 11 virtual machine running in VirtualBox
* Endpoint monitoring: Sysmon
* SIEM: Splunk Enterprise
* Log collection: Splunk Universal Forwarder
* Attack simulation: Atomic Red Team
* Network: Isolated internal network for attack simulation, with a separate internet-enabled adapter on the victim for tool installation when required.

Step 1 — Troubleshooting Sysmon Log Ingestion

Sysmon was generating events locally, but the events were not reaching Splunk. Investigation of the Universal Forwarder’s logs revealed the following error:

WinEventLogChannel::init: Init failed, unable to subscribe to Windows Event Log channel
'Microsoft-Windows-Sysmon/Operational': errorCode=5

Root cause: Windows error code 5 indicates Access Denied. The Splunk Universal Forwarder service account did not have sufficient permissions to read the Sysmon event channel.

Resolution: Changed the service account to LocalSystem and restarted the service:

sc.exe config SplunkForwarder obj= LocalSystem
Restart-Service SplunkForwarder

After the change, I verified that Sysmon events were being ingested into Splunk.

Step 2 — Simulating Encoded PowerShell Execution

I used Atomic Red Team to simulate technique T1059.001 with the test T1059.001-17, which exercises encoded PowerShell execution.

Invoke-AtomicTest T1059.001-17

Microsoft Defender initially quarantined the test file. For controlled testing, I configured a narrowly scoped exclusion for the lab directory and restored the required Atomic Red Team test files.

The test subsequently executed, allowing me to investigate the resulting process-creation telemetry.

Security note: The Defender exclusion was limited to the isolated lab environment. Exclusions should not be applied broadly on production systems.

Step 3 — Investigating Sysmon Events in Splunk

Sysmon Event ID 1 records process creation. I searched for PowerShell executions during the test window using the following SPL query:

index=main sourcetype=*sysmon* EventCode=1 CommandLine=*powershell* NOT CommandLine=*splunk*
| table _time, ParentImage, Image, CommandLine
| sort 0 _time

The investigation identified the following process activity:

Time	Parent process	Observed command
06:09:28	explorer.exe	Interactive PowerShell session
06:10:16	powershell.exe	cmd.exe /c powershell.exe -e <base64>
06:10:17	cmd.exe	powershell.exe -e <base64>

These events illustrated the importance of reviewing process ancestry and command-line arguments when investigating potentially suspicious PowerShell activity.

Note: The timestamps and process relationships above represent the observed lab results.

Step 4 — Developing the Detection Rule

I created a targeted detection query to identify PowerShell processes launched with common encoded-command arguments.

index=main sourcetype=*sysmon* EventCode=1
| eval cmd_lc=lower(CommandLine)
| where like(cmd_lc,"% -e %")
    OR like(cmd_lc,"% -enc %")
    OR like(cmd_lc,"% -encodedcommand %")
| table _time, host, ParentImage, Image, CommandLine
| sort 0 - _time

The query uses case normalization and checks command-line arguments for common encoded-command patterns.

Observed result: The test returned one matching event in the selected search window.

This result demonstrates detection of the tested command pattern, rather than comprehensive detection of every encoded PowerShell execution technique.

Step 5 — Configuring Automated Alerting

I saved the detection search as a scheduled Splunk alert named:

PowerShell Encoded Command – T1059.001

Alert configuration:

* Schedule: Every minute
* Search window: Previous 15 minutes
* Trigger condition: Number of matching results greater than zero

During testing, the overlapping search windows caused repeated alerts for the same event.

Improvement identified: Configure alert throttling or suppression using appropriate event fields and a suitable time interval to reduce duplicate notifications. In production, the alert should also account for legitimate administrative activity and event deduplication.

Challenges and Troubleshooting

This project involved practical troubleshooting across endpoint monitoring, log collection, attack simulation, and alert configuration.

* Sysmon log ingestion failure: Diagnosed errorCode=5 through the Universal Forwarder’s logs and corrected the service-account permissions.
* Network connectivity: Resolved ICMP connectivity issues between Kali Linux and Windows using a scoped Windows Firewall inbound rule.
* PowerShell execution policy: Addressed script execution restrictions during Atomic Red Team installation.
* Microsoft Defender quarantine: Investigated the quarantine event and used a narrowly scoped exclusion for the controlled lab test.
* Duplicate alerts: Identified repeated alert triggers caused by the one-minute schedule and overlapping 15-minute search window.

Limitations and Security Considerations

* Splunk trial license: The availability of scheduled searches and other capabilities depends on the license and version in use.
* Signature-based detection: The current rule focuses on encoded-command arguments and may miss obfuscated commands using other execution methods.
* Potential false positives: Legitimate administrative scripts may use encoded PowerShell commands.
* Detection coverage: This lab validates a specific test case, not comprehensive detection of all PowerShell abuse.
* Network isolation: Attack simulation was conducted in a controlled virtual lab environment.

Future Improvements

* Detect suspicious parent-child process relationships, such as unexpected applications spawning PowerShell.
* Improve command-line detection with additional patterns and appropriate field normalization.
* Tune alert suppression and investigate matching events with process ancestry and related endpoint telemetry.
* Expand coverage to additional MITRE ATT&CK techniques, following the same attack, detection, investigation, and alerting workflow.

Key Takeaways

This lab provided practical experience with:

* Sysmon process-creation telemetry and Windows event logs.
* Splunk Universal Forwarder troubleshooting.
* SPL search development and detection engineering.
* MITRE ATT&CK technique mapping.
* Scheduled alert configuration and duplicate-alert troubleshooting.
* Controlled attack simulation and security monitoring.

The project demonstrates a repeatable workflow for validating endpoint detections and translating observed activity into actionable SIEM alerts.

