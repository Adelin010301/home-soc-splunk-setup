# Home SOC Lab: Segmented Network with Splunk-Based Detection

A self-hosted security operations lab built to practice log collection, endpoint telemetry analysis, and detection engineering against a simulated attacker. The environment uses pfSense for network segmentation, a Splunk Enterprise indexer/search head, and a Windows 10 target instrumented with Sysmon and the Splunk Universal Forwarder. A Kali Linux VM serves as the attacker platform.

This document covers the full build: network design, Splunk deployment, forwarder configuration, and a real troubleshooting case (Sysmon events failing to reach Splunk) — including root cause analysis and resolution.

---

## Table of Contents

1. [Lab Objectives](#lab-objectives)
2. [Architecture Overview](#architecture-overview)
3. [Network Segmentation with pfSense](#network-segmentation-with-pfsense)
4. [Splunk Enterprise Setup](#splunk-enterprise-setup)
5. [Splunk Universal Forwarder Deployment (Windows 10 Target)](#splunk-universal-forwarder-deployment-windows-10-target)
6. [Sysmon Installation](#sysmon-installation)
7. [Troubleshooting Case Study: Sysmon Events Not Reaching Splunk](#troubleshooting-case-study-sysmon-events-not-reaching-splunk)
8. [Verification](#verification)
9. [Lessons Learned](#lessons-learned)
10. [Next Steps](#next-steps)

---

## Lab Objectives

- Build a segmented, isolated virtual network that mirrors basic enterprise network zoning practices.
- Stand up a Splunk Enterprise instance as a central log repository and detection platform.
- Forward Windows Event Logs and Sysmon telemetry from a target endpoint into Splunk.
- Practice identifying and resolving real-world log collection failures (permissions, service accounts, event channel ACLs).
- Prepare the environment for offensive/defensive exercises: attacking the Windows target from Kali and detecting the activity in Splunk.

---

## Architecture Overview

```
                                   ┌────────────────────────┐
                                   │        pfSense          │
                                   │   (Firewall / Router)   │
                                   │                          │
                    WAN ──────────┤  em0 → DHCP (Internet)   │
                                   │  em1 → LAN  192.168.10.0/24
                                   │  em2 → OPT1 192.168.20.0/24 (MGMT)
                                   └───────────┬─────────────┘
                                               │
                ┌──────────────────────────────┼───────────────────────────────┐
                │                              │                               │
        LAN (192.168.10.0/24)                  │                    OPT1 / MGMT (192.168.20.0/24)
                │                              │                               │
   ┌────────────┴────────────┐      ┌──────────┴──────────┐        ┌───────────┴────────────┐
   │   Ubuntu VM (Splunk)     │      │  Windows 10 Target   │        │  Ubuntu MGMT VM         │
   │   192.168.10.104         │      │  (Sysmon + UF)       │        │  (isolated management   │
   │   Splunk Web  :8000      │◄─────┤  Universal Forwarder │        │   access to pfSense GUI)│
   │   Receiving   :9997      │      │  → 192.168.10.104:9997│       │                         │
   └───────────────────────────┘      └───────────────────────┘      └─────────────────────────┘
                │
   ┌────────────┴────────────┐
   │   Kali Linux (Attacker)  │
   │   LAN 192.168.10.0/24    │
   └───────────────────────────┘
```

**Roles:**

| Component | Role |
|---|---|
| pfSense | Firewall/router providing network segmentation between LAN, WAN, and an isolated management network (OPT1) |
| Ubuntu VM | Hosts Splunk Enterprise (indexer, search head, web interface) |
| Windows 10 VM | Attack target; runs Sysmon and the Splunk Universal Forwarder |
| Kali Linux VM | Attacker platform for generating offensive traffic against the Windows target |
| Ubuntu MGMT VM | Isolated administrative access point to the pfSense GUI, separated from the main LAN |

---

## Network Segmentation with pfSense

pfSense was configured with three interfaces to separate general lab traffic from administrative/management access:

| Interface | Network | Purpose |
|---|---|---|
| WAN (em0) | DHCP (upstream/internet) | External connectivity |
| LAN (em1) | `192.168.10.0/24` | Main lab network — Splunk server, Windows target, Kali attacker |
| OPT1 (em2) | `192.168.20.0/24` | Isolated management network — administrative access to pfSense only |

**Design rationale:**
- Keeping the management network (`192.168.20.0/24`) separate from the main LAN (`192.168.10.0/24`) prevents a compromised host on the LAN (e.g., during an attack simulation) from having direct access to the pfSense administrative interface.
- A dedicated Ubuntu VM was placed on the management network specifically to reach the pfSense GUI, rather than allowing GUI access from the general LAN.
- Firewall rules on pfSense were reviewed to ensure only intended traffic could cross between segments, consistent with standard network zoning practice.

This mirrors, at a small scale, common enterprise practices of separating production/user network segments from out-of-band management networks.

---

## Splunk Enterprise Setup

Splunk Enterprise was installed on an Ubuntu VM (`192.168.10.104`) to serve as the central log collection and search platform.

### Installation & Initial Access

- Installed Splunk Enterprise under a dedicated Linux user (`aladin`).
- Verified the `splunkd` process ownership and service user matched the account being used to manage the installation, to avoid permission conflicts (see [Troubleshooting](#troubleshooting-case-study-sysmon-events-not-reaching-splunk) for a related permissions incident encountered during setup).
- Confirmed Splunk Web accessible at:
  ```
  http://192.168.10.104:8000
  ```

### Enabling the Receiving Port

For the Splunk instance to accept data from forwarders, a receiving port was enabled:

```bash
/opt/splunk/bin/splunk enable listen 9997 -auth admin:<password>
```

Verified the port was listening on all interfaces:

```bash
sudo ss -tlnp | grep 9997
# LISTEN 0 128 0.0.0.0:9997 users:((splunkd,pid=3268,...))
```

### Licensing Note

The instance initially ran on the Splunk Enterprise trial license. Upon expiry (license lapsed after the trial period), search functionality was blocked with a "license expired" error. This is expected trial behavior. Resolution:

1. Navigate to **Settings → Licensing → Change license group**.
2. Select the **Free** license group.
3. Restart Splunk:
   ```bash
   /opt/splunk/bin/splunk restart
   ```

The Free license (500MB/day indexing, single-user, no distributed search/alerting) is sufficient for this lab's scale — one Windows forwarder generating Event Log and Sysmon telemetry stays well within that limit.

### File/Directory Permissions Issue During Setup

Early in setup, Splunk logged repeated warnings:

```
Cannot create /opt/splunk/var/log/splunk...
Failed to start KV Store process...
```

Root cause: `/opt/splunk/var` and subdirectories were owned by a `splunk` service user/group with restrictive permissions (`drwx--x---`), while Splunk was actually being operated as the `aladin` user — a mismatch left over from the initial install method.

Resolution:
```bash
sudo chown -R aladin:aladin /opt/splunk
```
Splunk was subsequently always started/stopped as `aladin` (never via `sudo`) to avoid re-introducing root-owned files.

### Known Limitation: KV Store

The KV Store component (used by apps such as Splunk Enterprise Security, ITSI, and some app-level lookup storage) failed to initialize with `Illegal instruction (signal 4)`. Root cause investigation traced this to the embedded MongoDB process requiring AVX CPU instructions that were not exposed to the VirtualBox guest, even though the physical host CPU supports AVX.

Attempted mitigation: switching the VM's Paravirtualization Interface from *Default* to *KVM* in VirtualBox settings (Settings → System → Acceleration) — did not resolve the issue in this environment.

**Impact assessment:** KV Store is not required for core Splunk functionality (indexing, search, Universal Forwarder data collection) and was determined to be non-blocking for this lab's detection-engineering goals. It would only become relevant if apps like Splunk Enterprise Security are installed later.

---

## Splunk Universal Forwarder Deployment (Windows 10 Target)

The Splunk Universal Forwarder (UF) was installed on the Windows 10 target to ship Windows Event Logs and Sysmon telemetry to the Splunk indexer.

### Installation

1. Downloaded the Windows x64 Universal Forwarder `.msi` installer from Splunk.
2. During installation:
   - **Deployment Server**: left blank (not needed for a single-forwarder lab; this field is only for centrally managing multiple forwarders).
   - **Receiving Indexer**: set to `192.168.10.104:9997` (the Splunk indexer's IP on the forwarder receiving port — distinct from port `8000`, which is the web UI).
   - Installed to run as the default forwarder service account, **`NT SERVICE\SplunkForwarder`** (a Windows virtual service account, not `LocalSystem`).

### Data Inputs Configuration

Configured in:
```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

```ini
[WinEventLog://Security]
disabled = 0
index = main

[WinEventLog://System]
disabled = 0
index = main

[WinEventLog://Application]
disabled = 0
index = main

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
```

### Verification of Connectivity

Confirmed network reachability from the Windows target to the indexer before troubleshooting anything at the application layer:

```powershell
Test-NetConnection -ComputerName 192.168.10.104 -Port 9997
# TcpTestSucceeded : True
```

Confirmed the forwarder was actively connected in `splunkd.log`:

```
INFO AutoLoadBalancedConnectionStrategy [TcpOutEloop] - Connected to idx=192.168.10.104:9997:0, pset=0, reuse=0. autoBatch=1
```

Security, System, and Application Windows Event Logs began appearing in Splunk (`index=main host="Windows10-Sandb"`) immediately after service restart — confirming the base forwarder pipeline was functioning correctly before Sysmon was added.

---

## Sysmon Installation

[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (System Monitor, part of Sysinternals) was installed on the Windows 10 target to capture rich endpoint telemetry — process creation with full command lines, parent/child process relationships, network connections, and file/registry activity — that standard Windows Event Logs do not provide.

### Installation Steps

1. Downloaded Sysmon from the official Microsoft Sysinternals page.
2. Downloaded the community-maintained [SwiftOnSecurity Sysmon configuration](https://github.com/SwiftOnSecurity/sysmon-config) (`sysmonconfig-export.xml`) as a detection-oriented baseline configuration, rather than running Sysmon with default (minimal) logging.
3. Extracted the Sysmon archive and installed with the configuration applied:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

4. Verified the service was running:

```powershell
Get-Service Sysmon64
# Status: Running
```

5. Verified event generation directly from the Windows Event Log:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Sysmon was confirmed to be logging correctly (167 records present) at this stage — the subsequent issue was isolated entirely to the forwarder's ability to read that channel, not Sysmon itself.

---

## Troubleshooting Case Study: Sysmon Events Not Reaching Splunk

After adding the `[WinEventLog://Microsoft-Windows-Sysmon/Operational]` stanza to `inputs.conf` and restarting the forwarder, Splunk searches for Sysmon data returned no results, while Security/System/Application logs continued to work normally.

### Diagnostic Process

**1. Confirmed Sysmon itself was healthy (ruled out as the cause):**
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```
Events were present — Sysmon was functioning correctly.

**2. Confirmed the forwarder's effective configuration recognized the input (ruled out a config typo/mismatch):**
```powershell
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk.exe btool inputs list --debug
```
`btool` confirmed the `[WinEventLog://Microsoft-Windows-Sysmon/Operational]` stanza was correctly merged from `etc\system\local\inputs.conf`, with `disabled = 0` and `index = main`.

**3. Confirmed network/indexer connectivity was healthy (ruled out as the cause):**
The forwarder was actively connected to `192.168.10.104:9997` per `splunkd.log`, and other WinEventLog sources were flowing normally.

**4. Searched the full forwarder log for the specific failure — this isolated the root cause:**
```powershell
Select-String -Path "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log" -Pattern "WinEventLog"
```

This surfaced the actual error:

```
ERROR ExecProcessor - message from "splunk-winevtlog.exe" splunk-winevtlog -
WinEventLogChannel::subscribeToEvtChannel: Could not subscribe to Windows Event Log channel
'Microsoft-Windows-Sysmon/Operational'

ERROR ExecProcessor - message from "splunk-winevtlog.exe" splunk-winevtlog -
WinEventLogChannel::init: Init failed, unable to subscribe to Windows Event Log channel
'Microsoft-Windows-Sysmon/Operational': errorCode=5
```

`errorCode=5` corresponds to the Windows API error `ERROR_ACCESS_DENIED`.

### Root Cause

Inspecting the Sysmon channel's access control list revealed the cause:

```powershell
wevtutil gl Microsoft-Windows-Sysmon/Operational
```

```
channelAccess: O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)
```

Unlike the default Security/System/Application logs, the Sysmon Operational channel uses a **restricted, custom ACL** that only grants read access to:
- `SY` – Local System
- `BA` – Administrators
- `BO` – Backup Operators
- `SO` – Server Operators
- `S-1-5-32-573` – **Event Log Readers** group

The Splunk Universal Forwarder service runs under the virtual service account **`NT SERVICE\SplunkForwarder`**, which was not a member of any of these groups — hence `ERROR_ACCESS_DENIED` when attempting to subscribe to the channel.

### Resolution

1. Added the forwarder's service account to the **Event Log Readers** group:
   ```powershell
   net localgroup "Event Log Readers" "NT SERVICE\SplunkForwarder" /add
   ```

2. A simple `Restart-Service SplunkForwarder` was **not sufficient** — the error persisted across three subsequent restarts after the group change. This is because Windows access tokens for service accounts are typically generated at logon/service start and do not dynamically pick up new group memberships mid-session for already-established sessions in this configuration.

3. Performed a **full VM reboot** to force regeneration of the service account's access token:
   ```powershell
   Restart-Computer
   ```

4. Post-reboot, the `errorCode=5` no longer appeared in `splunkd.log`, and Sysmon events (EventCode=1 process creation, with `CommandLine`, `ParentImage`, `ParentCommandLine`, `Hashes`, `ProcessGuid`, etc.) began appearing in Splunk within `index=main`, `sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational`.

### Summary Table

| Step | Finding |
|---|---|
| Sysmon service status | Running, generating events |
| `inputs.conf` config | Correctly present and enabled (`btool`-verified) |
| Network/indexer connectivity | Healthy, forwarder connected on 9997 |
| Forwarder log (`splunkd.log`) | `errorCode=5` (ACCESS_DENIED) subscribing to Sysmon channel |
| Channel ACL (`wevtutil gl`) | Restricted to SYSTEM/Admins/Backup Operators/Server Operators/Event Log Readers |
| Forwarder service account | `NT SERVICE\SplunkForwarder` — not in Event Log Readers |
| Fix | Add account to Event Log Readers group **+ full reboot** to refresh access token |

---

## Verification

Final state confirmed via Splunk Web search:

```
index=main host="Windows10-Sandb" sourcetype=*sysmon*
```

Returned live Sysmon EventCode=1 (process creation) events with full field extraction, including `CommandLine`, `ParentCommandLine`, `Image`, `Hashes`, `ProcessGuid`, and `IntegrityLevel` — confirming the full pipeline (Sysmon → Universal Forwarder → Splunk indexer → search) is operational end-to-end, alongside existing Security/System/Application log ingestion.

---

## Lessons Learned

- **Ownership mismatches between install-time and run-time users** (e.g., a `splunk` system account vs. an interactive `aladin` user) are a common source of silent permission failures in self-managed Splunk installs — worth locking down a single consistent operating user early.
- **Not all Windows Event Log channels share the same default ACL.** Application/System/Security are broadly readable, but specialized channels like Sysmon's Operational log are intentionally locked down and require explicit group membership (Event Log Readers) for non-privileged/service accounts to read them.
- **Windows service account group membership changes do not always apply to a running or freshly-restarted service.** A full reboot (not just a service restart) may be required to force regeneration of the access token for virtual service accounts such as `NT SERVICE\<name>`.
- **Systematic elimination** (verify the source is healthy → verify config is loaded → verify network path → inspect the actual error in logs) is far faster than guessing; the specific `errorCode=5` in `splunkd.log` was the single piece of evidence that pinpointed the true root cause after several plausible-but-incorrect hypotheses (stale config, forwarder not restarted, wrong channel name).
- Hardware/virtualization-layer issues (the KV Store's AVX requirement) can look like configuration bugs but are actually environment limitations — worth identifying early and scoping around rather than over-investing in a fix that may not be achievable in a given VM/host combination.

---

## Next Steps

- [ ] Generate offensive traffic from the Kali VM against the Windows 10 target (e.g., Nmap scans, brute-force login attempts, a reverse shell payload).
- [ ] Build detection searches in Splunk for common attack patterns:
  - Failed logon bursts (`EventCode=4625`) → brute-force detection
  - Suspicious parent/child process chains (e.g., `winword.exe` spawning `powershell.exe`) via Sysmon EventCode=1
  - Unusual outbound network connections via Sysmon EventCode=3
- [ ] Forward pfSense firewall/DNS logs via syslog for network-layer visibility alongside endpoint telemetry.
- [ ] Document detection rules and sample searches (`.spl`) in a dedicated `/detections` folder for reuse.
- [ ] (Optional/future) Revisit Splunk Enterprise Security once KV Store's AVX limitation is resolved or a different virtualization host is available.

---

## Environment Summary

| Component | Details |
|---|---|
| Hypervisor | Oracle VirtualBox |
| Firewall/Router | pfSense 2.9.0-BETA |
| SIEM | Splunk Enterprise 10.4.0 (Free license) |
| Log Forwarding | Splunk Universal Forwarder |
| Endpoint Telemetry | Sysmon (SwiftOnSecurity configuration) |
| Attacker Platform | Kali Linux |
| Target OS | Windows 10 |
| Splunk Server OS | Ubuntu |
