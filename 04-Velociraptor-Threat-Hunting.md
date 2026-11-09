# 04 - Velociraptor Threat Hunting

## Executive Summary

This investigation documents a hands-on endpoint threat-hunting assessment conducted through Velociraptor against the authorized Windows lab endpoint `E-CORP`. The scenario began with suspected data exfiltration from an unusual process. Five targeted artifact collections identified suspicious executable memory in `reverse.exe`, a configured C2 IP address, Run-key persistence, Mimikatz-related files, and a recently accessed Microsoft Word document. These findings collectively support a suspicious endpoint activity hypothesis while preserving the distinction between observed artifacts and unverified attacker actions.

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
| Lab theme | Velociraptor Threat Hunting / Skills Assessment |
| Access method | RDP to the authorized training target |
| Target address | `10.129.228.172` |
| Velociraptor interface | `https://127.0.0.1:8889/app/index.html#/search/all` |
| Selected client | `E-CORP` |
| Client ID | `C.e0967723979c1134` |
| Assessment scope | VAD analysis, C2 configuration, persistence, YARA detection, RecentDocs |

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

![Figure 01 — Client Discovery and Endpoint Selection](images/figure-01.png)

*Figure 01. Velociraptor evidence captured during client discovery and endpoint selection.*

![Figure 02 — Client Discovery and Endpoint Selection](images/figure-02.png)

*Figure 02. Velociraptor evidence captured during client discovery and endpoint selection.*

![Figure 03 — Client Discovery and Endpoint Selection](images/figure-03.png)

*Figure 03. Velociraptor evidence captured during client discovery and endpoint selection.*

## Phase 1 — VAD-Based Process Injection Triage

A new collection was launched with `Exchange.Windows.Detection.Malfind`, a client artifact that inspects suspicious executable memory regions using Virtual Address Descriptor (VAD) information. The result identified `reverse.exe` with an executable memory section (`xrw` shown in the result). This is a process-injection indicator, not a complete attribution of the underlying payload.

### Evidence interpretation

The suspicious process is `reverse.exe`. The reported executable-memory region warrants further validation through process lineage, image signing, network telemetry, and memory acquisition.

![Figure 04 — Phase 1 — VAD-Based Process Injection Triage](images/figure-04.png)

*Figure 04. Velociraptor evidence captured during phase 1 — vad-based process injection triage.*

![Figure 05 — Phase 1 — VAD-Based Process Injection Triage](images/figure-05.png)

*Figure 05. Velociraptor evidence captured during phase 1 — vad-based process injection triage.*

## Phase 2 — Cobalt Strike Configuration Carving

The `Windows.Carving.CobaltStrike` artifact was collected to extract suspected Cobalt Strike configuration material from memory or other byte streams. The collection result displayed `C2Server` as `3.19.219.4` and additional HTTP configuration fields, including a POST URI `/submit.php`. This supports identification of a configured C2 endpoint; the screenshot does not independently prove successful network contact or exfiltration.

### Extracted configuration

| Configuration field | Observed value |
|---|---|
| `C2Server` | `3.19.219.4` |
| `PostURI` | `/submit.php` |

The configured IP is the lab answer; outbound connections should be corroborated separately before claiming communication.

![Figure 06 — Phase 2 — Cobalt Strike Configuration Carving](images/figure-06.png)

*Figure 06. Velociraptor evidence captured during phase 2 — cobalt strike configuration carving.*

![Figure 07 — Phase 2 — Cobalt Strike Configuration Carving](images/figure-07.png)

*Figure 07. Velociraptor evidence captured during phase 2 — cobalt strike configuration carving.*

## Phase 3 — Persistence via Startup Registry

The `Windows.Sys.StartupItems` collection enumerated startup entries. The suspicious entry named `reverse` referenced `C:\Users\j0seph\AppData\Local\reverse.exe` and appeared under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. This is a Windows Run-key persistence mechanism that may execute the configured binary at user logon.

### Registry evidence

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Value: reverse
Data: C:\Users\j0seph\AppData\Local\reverse.exe
```

![Figure 08 — Phase 3 — Persistence via Startup Registry](images/figure-08.png)

*Figure 08. Velociraptor evidence captured during phase 3 — persistence via startup registry.*

![Figure 09 — Phase 3 — Persistence via Startup Registry](images/figure-09.png)

*Figure 09. Velociraptor evidence captured during phase 3 — persistence via startup registry.*

## Phase 4 — Mimikatz Artifact Discovery with YARA

The `Windows.Search.Yara` artifact was configured with a filename regex and the provided Mimikatz YARA rule derived from the public `kiwi_passwords.yar` signature. The collection produced matches in Mimikatz-related executable and DLL files under `C:\Users\j0seph\AppData\Local\mimik`. A YARA match supports file identification but does not, by itself, demonstrate credential dumping.

### Detection configuration

The collection used a filename filter matching common executable, text, DLL, and PHP extensions, alongside a Mimikatz YARA rule. The provided rule includes architecture-specific executable patterns, DLL patterns, and driver patterns; the complete source should be maintained separately when reproducing the scan.

```text
nameRegex: (exe|txt|dll|php)$
yaraRule: rule mimikatz { ... }
```

Source rule: https://github.com/gentilkiwi/mimikatz/blob/master/kiwi_passwords.yar

![Figure 10 — Phase 4 — Mimikatz Artifact Discovery with YARA](images/figure-10.png)

*Figure 10. Velociraptor evidence captured during phase 4 — mimikatz artifact discovery with yara.*

![Figure 11 — Phase 4 — Mimikatz Artifact Discovery with YARA](images/figure-11.png)

*Figure 11. Velociraptor evidence captured during phase 4 — mimikatz artifact discovery with yara.*

![Figure 12 — Phase 4 — Mimikatz Artifact Discovery with YARA](images/figure-12.png)

*Figure 12. Velociraptor evidence captured during phase 4 — mimikatz artifact discovery with yara.*

![Figure 13 — Phase 4 — Mimikatz Artifact Discovery with YARA](images/figure-13.png)

*Figure 13. Velociraptor evidence captured during phase 4 — mimikatz artifact discovery with yara.*

![Figure 14 — Phase 4 — Mimikatz Artifact Discovery with YARA](images/figure-14.png)

*Figure 14. Velociraptor evidence captured during phase 4 — mimikatz artifact discovery with yara.*

![Figure 15 — Phase 4 — Mimikatz Artifact Discovery with YARA](images/figure-15.png)

*Figure 15. Velociraptor evidence captured during phase 4 — mimikatz artifact discovery with yara.*

## Phase 5 — Recent Document Access

The `Windows.Registry.RecentDocs` artifact enumerated the Windows RecentDocs MRU registry data for the user. Expanding `MruEntries` revealed `insurance.DOCX` among the document entries. The lab answer identifies this as the requested recently accessed Word document; MRU evidence indicates recent interaction, not necessarily the exact time the file was opened.

### Registry evidence

The `MruEntries` list includes `insurance.DOCX` and other recent items. The lab-provided answer is `insurance.DOCX`; the screenshot does not establish an exact last-opened timestamp.

![Figure 16 — Phase 5 — Recent Document Access](images/figure-16.png)

*Figure 16. Velociraptor evidence captured during phase 5 — recent document access.*

![Figure 17 — Phase 5 — Recent Document Access](images/figure-17.png)

*Figure 17. Velociraptor evidence captured during phase 5 — recent document access.*

![Figure 18 — Phase 5 — Recent Document Access](images/figure-18.png)

*Figure 18. Velociraptor evidence captured during phase 5 — recent document access.*

## Consolidated Findings

| Assessment question | Evidence | Answer |
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

## Limitations and Evidentiary Confidence

The screenshots document Velociraptor collection results but do not include a full forensic image, complete process memory, verified network session logs, or a chain-of-custody record. Therefore, findings about exfiltration, execution of Mimikatz, and confirmed C2 communications must remain hypotheses unless corroborated by additional telemetry. The local Velociraptor URL is a loopback management interface, not the C2 address.

## Investigation Outcome

The five lab questions were answered using separate Velociraptor collections and correlated into an endpoint-focused threat-hunting narrative. The most compelling combined evidence is the suspicious `reverse.exe` memory region, a matching Run-key persistence entry, and an extracted C2 configuration. The YARA and RecentDocs results provide additional context for potential credential-access tooling and user activity.

## Conclusion

This assessment demonstrates practical Velociraptor threat hunting through targeted memory inspection, configuration carving, registry analysis, YARA-based file discovery, and RecentDocs examination. The documented evidence supports prioritizing `reverse.exe` for deeper incident response and highlights the importance of distinguishing configuration artifacts from proven attacker actions.

## References

- [Velociraptor Documentation](https://docs.velociraptor.app/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Mimikatz YARA rule](https://github.com/gentilkiwi/mimikatz/blob/master/kiwi_passwords.yar)


