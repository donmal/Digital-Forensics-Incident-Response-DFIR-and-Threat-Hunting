# 04 - Velociraptor Threat Hunting

## Executive Summary

This investigation documents a hands-on endpoint threat-hunting investigation conducted through Velociraptor against the authorized Windows lab endpoint `E-CORP`. The scenario began with suspected data exfiltration from an unusual process. Five targeted artifact collections identified suspicious executable memory in `reverse.exe`, a configured C2 IP address, Run-key persistence, Mimikatz-related files, and a recently accessed Microsoft Word document. These findings collectively support a suspicious endpoint activity hypothesis while preserving the distinction between observed artifacts and unverified attacker actions.

## Investigation Objectives

- Identify a suspicious process through VAD-based memory analysis.
- Extract the C2 address from suspected implant configuration.
- Determine the Windows Registry persistence location.
- Locate Mimikatz-related files using YARA scanning.
- Identify a recently accessed Word document through RecentDocs artifacts.

## Background

Velociraptor is an endpoint visibility, digital forensics, and incident response platform. It performs targeted collections from enrolled clients and returns structured forensic artifacts. The lab scenario describes possible data exfiltration, but the provided screenshots focus on endpoint and configuration evidence rather than packet-level proof of exfiltration.

## Investigation Scenario

| Field | Value |
|---|---|
| Investigation focus | Endpoint threat hunting and forensic artifact correlation |
| Access method | RDP to the authorized training target |
| Target address | `10.129.228.172` |
| Velociraptor interface | `https://127.0.0.1:8889/app/index.html#/search/all` |
| Selected client | `E-CORP` |
| Client ID | `C.e0967723979c1134` |
| Investigation scope | VAD analysis, C2 configuration, persistence, YARA detection, RecentDocs |

## Data Sources

| Evidence source | Velociraptor artifact | Investigative value |
|---|---|---|
| VAD and executable memory | `Exchange.Windows.Detection.Malfind` | Suspicious executable memory and process identification |
| Implant configuration | `Windows.Carving.CobaltStrike` | Potential C2 settings extracted from memory |
| Startup configuration | `Windows.Sys.StartupItems` | Run-key persistence and startup command |
| Disk content | `Windows.Search.Yara` | Signature matches for Mimikatz-related files |
| User activity | `Windows.Registry.RecentDocs` | Recently referenced document names |

## Investigation Methodology

The investigation followed an evidence-driven collection workflow: identify the active endpoint, launch narrowly scoped artifacts, inspect their Results tabs, correlate process and persistence evidence, and document each conclusion with screenshot references. Collections were performed in an authorized lab environment.

## Client Discovery and Endpoint Selection

The Velociraptor web interface was opened on the authorized lab host. The client inventory initially showed 105 matching clients. Filtering to online clients isolated the connected endpoint `E-CORP`, which was selected for subsequent artifact collections.

### Endpoint workflow

1. Connect to the lab target using RDP.
2. Open the local Velociraptor interface and authenticate using the supplied lab credentials.
3. Filter the client list to online endpoints, select `E-CORP`, and open **Collected**.

Suggested evidence — Figure 1: Velociraptor client inventory showing the selected online E-CORP endpoint and its collection interface.

## Phase 1 — VAD-Based Process Injection Triage

A new collection was launched with `Exchange.Windows.Detection.Malfind`, a client artifact that inspects suspicious executable memory regions using Virtual Address Descriptor (VAD) information. The result identified `reverse.exe` with an executable memory section (`xrw` shown in the result). This is a process-injection indicator, not a complete attribution of the underlying payload.

### Evidence interpretation

**Finding**: VAD-based memory analysis identified **reverse.exe** as a process containing a suspicious executable-memory region with **xrw** permissions.

The reported executable-memory region warrants further validation through process lineage, image signing, network telemetry, and memory acquisition.

The finding supports prioritizing **reverse.exe** for further investigation, but does not independently confirm process injection or identify the payload's execution history.

Suggested evidence — Figure 2: Velociraptor Malfind results showing reverse.exe and its suspicious executable-memory region, including the reported memory permissions.

## Phase 2 — Cobalt Strike Configuration Carving

The `Windows.Carving.CobaltStrike` artifact was collected to extract suspected Cobalt Strike configuration material from memory or other byte streams. The collection result displayed `C2Server` as `3.19.219.4` and additional HTTP configuration fields, including a POST URI `/submit.php`. This supports identification of a configured C2 endpoint; the screenshot does not independently prove successful network contact or exfiltration.

### Extracted configuration

| Configuration field | Observed value |
|---|---|
| `C2Server` | `3.19.219.4` |
| `PostURI` | `/submit.php` |

**Finding**: Configuration carving identified **3.19.219.4** as the configured command-and-control server address, with **/submit.php** recorded as the HTTP POST URI.

Evidence limitation: The extracted configuration establishes the presence of C2-related settings, but successful outbound communication or data exfiltration would require independent validation through network telemetry.

Suggested evidence — Figure 3: Velociraptor Cobalt Strike configuration-carving output showing C2Server: 3.19.219.4 and PostURI: /submit.php.

## Phase 3 — Persistence via Startup Registry

The `Windows.Sys.StartupItems` collection enumerated startup entries. The suspicious entry named `reverse` referenced `C:\Users\j0seph\AppData\Local\reverse.exe` and appeared under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. This is a Windows Run-key persistence mechanism that may execute the configured binary at user logon.

### Registry evidence

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Value: reverse
Data: C:\Users\j0seph\AppData\Local\reverse.exe
```

**Finding**: Registry startup analysis identified a Run-key entry named **reverse**, configured to launch **C:\Users\j0seph\AppData\Local\reverse.exe**.

The relationship between the suspicious memory region and the Run-key executable strengthens the persistence hypothesis, although the registry entry alone does not confirm that the executable was launched through this mechanism.

Suggested evidence — Figure 4: Velociraptor StartupItems results showing the reverse registry value, its executable path, and the HKLM Run-key location.

## Phase 4 — Mimikatz Artifact Discovery with YARA

The `Windows.Search.Yara` artifact was configured with a filename regex and the provided Mimikatz YARA rule derived from the public `kiwi_passwords.yar` signature. The collection produced matches in Mimikatz-related executable and DLL files under `C:\Users\j0seph\AppData\Local\mimik`. A YARA match supports file identification but does not, by itself, demonstrate credential dumping.

### Detection configuration

The collection used a filename filter matching common executable, text, DLL, and PHP extensions, alongside a Mimikatz YARA rule. The provided rule includes architecture-specific executable patterns, DLL patterns, and driver patterns; the complete source should be maintained separately when reproducing the scan.

```text
nameRegex: (exe|txt|dll|php)$
yaraRule: rule mimikatz { ... }
```
**Finding**: YARA scanning identified Mimikatz-related executable and DLL artifacts within **C:\Users\j0seph\AppData\Local\mimik**.

These results indicate the presence of files matching Mimikatz-related detection patterns. They do not independently establish execution of Mimikatz, successful credential extraction, or credential compromise.

Suggested evidence — Figure 5: Velociraptor YARA collection configuration showing the Mimikatz detection rule and filename filter.

Suggested evidence — Figure 6: YARA scan results showing Mimikatz-related file matches under C:\Users\j0seph\AppData\Local\mimik.

## Phase 5 — Recent Document Access

The `Windows.Registry.RecentDocs` artifact enumerated the Windows RecentDocs MRU registry data for the user. Expanding `MruEntries` revealed `insurance.DOCX` among the document entries. The registry artifact identifies it as a recently referenced Word document; MRU evidence indicates recent interaction, not necessarily the exact time the file was opened.

### Registry evidence

**Finding**: RecentDocs analysis identified **insurance.DOCX** among the user's recently referenced documents.

The available registry evidence supports recent document interaction but does not independently establish the exact last-opened timestamp or whether the document was accessed by an attacker.

Suggested evidence — Figure 7: Velociraptor RecentDocs results displaying insurance.DOCX within the MruEntries registry data.

## Consolidated Findings

| Investigation area | Evidence | Observed finding |
|---|---|---|
| Suspicious process via VAD | Malfind collection returned an executable memory region | `reverse.exe` |
| C2 server address | Cobalt Strike configuration `C2Server` field | `3.19.219.4` |
| Persistence registry key | StartupItems Run-key entry | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| Mimikatz-related folder | YARA hits in local application directory | `C:\Users\j0seph\AppData\Local\mimik` |
| Recently accessed Word document | RecentDocs `MruEntries` | `insurance.DOCX` |

## MITRE ATT&CK Mapping

| Technique | ID | Evidence and qualification |
|---|---|---|
| Process Injection | T1055 | Suspicious executable VAD region; injection suspected, not conclusively reconstructed |
| Application Layer Protocol | T1071 | C2 HTTP configuration fields observed; live communications not independently verified |
| Registry Run Keys / Startup Folder | T1547.001 | StartupItems entry in HKLM Run |
| OS Credential Dumping | T1003 | Mimikatz-related files discovered; actual credential dumping not demonstrated |

## Detection and Response Opportunities

- Investigate `reverse.exe` process lineage, executable-memory protections, and corresponding EDR events.
- Correlate connections to `3.19.219.4` with firewall, DNS, proxy, and network sensor logs.
- Review and preserve the `reverse` Run-key value before any remediation.
- Quarantine and hash suspicious Mimikatz-related files after forensic preservation.
- Validate access to `insurance.DOCX` using document access telemetry, if available.

## Investigation Outcome

The five lab questions were answered using separate Velociraptor collections and correlated into an endpoint-focused threat-hunting narrative. 

Five targeted Velociraptor artifact collections were used to investigate suspicious endpoint activity across memory, configuration, registry persistence, filesystem artifacts, and recent user-document references.

The most compelling combined evidence is the suspicious `reverse.exe` memory region, a matching Run-key persistence entry, and an extracted C2 configuration. The YARA and RecentDocs results provide additional context for potential credential-access tooling and user activity.

## Conclusion

This investigation demonstrates practical Velociraptor threat hunting through targeted memory inspection, configuration carving, registry analysis, YARA-based file discovery, and RecentDocs examination. The documented evidence supports prioritizing `reverse.exe` for deeper incident response and highlights the importance of distinguishing configuration artifacts from proven attacker actions.
