
# Purple Team Detection Lab

A hands-on home lab simulating a real MITRE ATT&CK technique end-to-end: attack execution, detection engineering, and automated alerting — built on top of a Windows 11 + Kali Linux environment monitored by Sysmon and Splunk.

## Objective

Move beyond passive log collection to active detection engineering: execute a known adversary technique, confirm its footprint in Sysmon logs, write a Splunk detection rule to catch it, and turn that rule into an automated alert.

**Technique covered:** [T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) (MITRE ATT&CK)

## Lab Architecture

- **Attacker:** Kali Linux
- **Victim:** Windows 11 (VirtualBox), monitored by **Sysmon**
- **SIEM:** Splunk Enterprise + Splunk Universal Forwarder
- **Attack simulation tool:** [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam) (Invoke-AtomicTest)
- Victim and attacker connected on an isolated internal network, with a second adapter on the victim for internet access (tool installation only)

## Step 1 — Diagnosing the Sysmon → Splunk Pipeline

Sysmon was running and logging locally, but events were not reaching Splunk. Checking the Splunk Forwarder's own log revealed the real cause:

