# 01 - Evidence Acquisition and Windows Artifact Analysis

## Executive Summary

This portfolio investigation documents four practical digital-forensics exercises from a controlled training environment: remote evidence acquisition with Velociraptor and KAPE, NTFS artifact analysis to trace a renamed executable, Windows event-log analysis to identify scheduled-task creation, and API Monitor examination of suspicious process activity. The exercises demonstrate an evidence-led workflow across collection, parsing, searching, correlation, and interpretation. **They are distinct lab exercises and should not be interpreted as one continuous intrusion.**

## Investigation Objectives

1. Acquire Windows forensic artifacts using Velociraptor's `Windows.KapeFiles.Targets` artifact with the `_SANS_Triage` target configuration.
2. Correlate NTFS metadata and `Zone.Identifier` information to identify a renamed executable.
3. Parse Windows event logs and identify suspicious scheduled-task creation.
4. Review API Monitor captures for process-creation and potential injection-related behavior.
5. Record what is confirmed, what is inferred, and what remains unverified.

## Scope and Lab Environment

| Component | Purpose |
|---|---|
| Velociraptor | Remote endpoint collection and forensic artifact retrieval |
| KAPE targets (`Windows.KapeFiles.Targets`) | Windows forensic triage acquisition |
| MFTECmd | Parse NTFS `$MFT` and USN Journal (`$J`) artifacts into CSV |
| Timeline Explorer | Search and correlate parsed forensic CSV files |
| EvtxECmd | Convert Windows EVTX records into searchable CSV |
| API Monitor | Examine captured Windows API calls and process behavior |
| FreeRDP | Connect to the authorized training hosts |

**Environment note:** The screenshots show separate training targets and a locally hosted Velociraptor console (`https://127.0.0.1:8889`). The IPs and login details are lab-specific and not reusable production instructions. The original prompt also mentions port `8899`, but the screenshots and successful browser sessions use **`8889`**.

---

## Investigation 1 — Endpoint Evidence Acquisition with Velociraptor (Module Question 1.A)

### Investigation Scenario

Collect the `Windows.KapeFiles.Targets` artifact from the online endpoint using the `_SANS_Triage` configuration, retrieve the collected data, and identify a scheduled task whose name begins with `A` and ends with `g`.

### Phase 1 — Remote Access and Velociraptor Console

The analyst connected to the authorized lab endpoint over RDP and opened the local Velociraptor web interface:

```powershell
xfreerdp /v:<LAB_TARGET_IP> /u:Administrator /p:<LAB_PASSWORD> /dynamic-resolution
```

```text
https://127.0.0.1:8889/app/index.html#/search/all
```

The browser displayed a certificate trust warning (`NET::ERR_CERT_AUTHORITY_INVALID`). In this isolated training environment, the analyst selected **Advanced → Proceed to 127.0.0.1 (unsafe)** to reach the lab console. This is not a general recommendation for unknown or production websites.

![Local Velociraptor certificate warning](images/acquisition-01.png)

![Chrome advanced warning option](images/acquisition-02.png)

![Proceed to the trusted lab service](images/acquisition-03.png)

![Velociraptor client search](images/acquisition-04.png)

![Online E-CORP endpoint](images/acquisition-05.png)

![Selected endpoint and Collected tab](images/acquisition-06.png)

### Phase 2 — Artifact Collection

The analyst filtered for the online client, opened its **Collected** tab, and started a new collection using the **+** control. The artifact **`Windows.KapeFiles.Targets`** was selected. Under **Configure Parameters**, the **`_SANS_Triage`** target group was enabled and the collection was launched.

![Collected view and new collection](images/acquisition-07.png)

![Artifact selection dialog](images/acquisition-08.png)

![Selected KAPE targets artifact](images/acquisition-09.png)

![Artifact parameter configuration](images/acquisition-10.png)

![SANS triage target configuration](images/acquisition-11.png)

### Phase 3 — Collection Review and Export

The collection progressed from running to finished, after which the analyst prepared and downloaded the archive and extracted it to the desktop for local inspection. The finished collection screen reports approximately **1,343 MB uncompressed**, **264 MB compressed**, and **1,329 container files**. These are collection statistics, not proof of malicious activity.

![Collection in progress](images/acquisition-12.png)

![Completed collection and download](images/acquisition-13.png)

![Downloaded archive in Explorer](images/acquisition-14.png)

![Archive extraction options](images/acquisition-15.png)

### Scheduled Task Examination

The extracted archive was examined under the Windows scheduled-task artifact path:

```text
uploads/auto/C%3A/Windows/System32/Tasks/
```

**Result:** The final scheduled-task name beginning with `A` and ending with `g` was **not provided or visible in the supplied screenshots**. The collection and export steps are documented, but this answer remains **pending confirmation**. A screenshot of the task directory and the task file's contents would complete this phase.

---

## Investigation 2 — NTFS File Rename and Zone.Identifier Correlation (Module Question 3.A)

### Investigation Scenario

Determine the new name of a file previously observed as `uninstall.exe`, using NTFS artifacts and `Zone.Identifier` information.

### Phase 1 — Parse NTFS Artifacts

Using Eric Zimmerman's `MFTECmd`, the analyst converted the USN Journal and Master File Table into CSV datasets for review:

```powershell
cd C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6

.\MFTECmd.exe -f "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$Extend\$J" --csv "C:\Users\johndoe\Desktop\forensic_data\mft_analysis" --csvf MFT-J.csv

.\MFTECmd.exe -f "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT" --csv "C:\Users\johndoe\Desktop\forensic_data\mft_analysis" --csvf MFT.csv
```

The PowerShell output confirms that both `UsnJournal` and `Mft` input types were processed and CSV outputs were generated.

![MFTECmd parses USN Journal and MFT](images/triage-01.png)

![Zimmerman Tools directory](images/triage-02.png)

![Opening parsed MFT CSV](images/triage-03.png)

![Timeline Explorer search for uninstall.exe](images/triage-04.png)

### Phase 2 — Correlate File Name and Alternate Data Stream

In **Timeline Explorer**, a search for `uninstall.exe` exposed an entry associated with the alternate data stream:

```text
microsoft.windowskits.feedback.exe:Zone.Identifier
```

**Finding:** `microsoft.windowskits.feedback.exe` is the renamed executable identified by the lab's artifact correlation. The `Zone.Identifier` stream is useful contextual metadata; the screenshot supports the name association, while a full USN rename sequence would provide stronger chronological proof.

---

## Investigation 3 — Scheduled Task Creation from Windows Event Logs (Module Question 3.B)

### Investigation Scenario

Identify a scheduled task whose name begins with `M` and ends with `r`, using a Windows event-log artifact and Timeline Explorer.

### Phase 1 — Convert EVTX to CSV

The analyst used **EvtxECmd** to parse the collected Windows event log into a CSV file:

```powershell
C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxECmd\EvtxECmd.exe -f "C:\Users\johndoe\Desktop\forensic_data\kape_output\D\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx" --csv "C:\Users\johndoe\Desktop\forensic_data\event_logs\csv_timeline" --csvf kape_event_log.csv
```

**Filename verification:** The source notes contain inconsistent names (`System`, `Sysmon`, `%4Operational`, and `%40Operational`). The screenshot confirms successful parsing of one EVTX file but does not independently establish the exact source filename. The command above preserves the path variant recorded in the analyst's notes; verify the actual filename in File Explorer before re-running.

![EvtxECmd event log conversion and summary](images/triage-05.png)

### Phase 2 — Search for Scheduled Task Creation

The CSV was opened in Timeline Explorer and searched for `schtasks`. The **Executable Info** column contained task-creation commands, including:

```text
schtasks /Create /TN "Microsoft-Windows-UpdateTask" ...
schtasks /Create /TN "Microsoft-Windows-DiagnosticDataCollector" ...
```

![Timeline Explorer schtasks results and task names](images/triage-06.png)

**Finding:** The requested task is **`Microsoft-Windows-DiagnosticDataCollector`**. The command lines demonstrate task-creation activity; determining malicious intent would additionally require examining the task action, executable path, creator, and surrounding events.

---

## Investigation 4 — Suspicious Process Activity in API Monitor (Module Question 3.C)

### Investigation Scenario

Inspect a saved API Monitor capture associated with `discord.exe` and identify another process reportedly targeted during process-injection activity.

### Phase 1 — Load the API Capture

The analyst launched the 64-bit API Monitor application and opened the capture:

```text
C:\Users\johndoe\Desktop\forensic_data\APMX64\discord.apmx64
```

The source prompt contains a `.apmx53` typo; the screenshots show the `.apmx64` capture. The loaded session contains API call records and monitored processes, including `discord.exe`.

![Launching API Monitor](images/triage-07.png)

![Opening discord.apmx64](images/triage-08.png)

![API Monitor capture with CreateProcessA call](images/triage-09.png)

![API Monitor loaded process list](images/triage-10.png)

### Phase 2 — Process Activity and Injection Hypothesis

A `CreateProcessA` call is visible in the supplied capture, with an application path referencing `C:\Windows\System32\comp.exe`. The analyst's notes subsequently identify **`cmdkey.exe`** as the answer to the lab question, but the supplied screenshots do not show a conclusive injection chain into that process.

**Recorded lab answer:** `cmdkey.exe` — **not independently verified by the screenshots**.

**Analytical distinction:** `CreateProcessA` establishes process creation, **not process injection by itself**. To substantiate injection, examine the full call sequence for relevant cross-process APIs such as `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` (or equivalent techniques), including the target PID and return values. This exercise remains partially verified.

---

## Evidence Summary

| Exercise | Data source | Confirmed observation | Status |
|---|---|---|---|
| 1.A — Acquisition | Velociraptor / KAPE collection | `_SANS_Triage` collection completed and archive downloaded | Collection verified; scheduled-task name pending |
| 3.A — Rename | `$MFT`, USN Journal, `Zone.Identifier` | `microsoft.windowskits.feedback.exe:Zone.Identifier` associated with `uninstall.exe` search | Renamed filename identified |
| 3.B — Scheduled tasks | EVTX → CSV, Timeline Explorer | `schtasks /Create` for `Microsoft-Windows-DiagnosticDataCollector` | Task name verified |
| 3.C — Process behavior | `discord.apmx64` | `CreateProcessA` call and `comp.exe` path visible | `cmdkey.exe` noted; injection not independently verified |

## MITRE ATT&CK Considerations

The following are **investigative hypotheses**, not confirmed technique attributions:

| Technique | ID | Relevance | Evidence limitation |
|---|---|---|---|
| Scheduled Task/Job: Scheduled Task | T1053.005 | Task-creation commands observed in parsed event data | Execution purpose and adversary attribution not established |
| Masquerading: Rename System Utilities | T1036.003 | A renamed executable was investigated | Need to establish whether the renamed file actually impersonated a system utility |
| Process Injection | T1055 | API Monitor exercise asks about injection | Supplied screenshot shows process creation, not the complete injection sequence |

## Detection and Investigation Opportunities

- Monitor Windows scheduled-task registration and `schtasks /Create` activity, correlating the task name, action, author, parent process, and timestamp.
- Preserve `$MFT`, USN Journal, and alternate data streams when investigating file rename or masquerading hypotheses.
- Correlate suspicious executable names with their original filenames, file hashes, signatures, and provenance metadata.
- Distinguish process creation from process injection; seek cross-process memory-write and execution evidence before escalating a T1055 finding.
- Preserve collection metadata, acquisition timestamps, tool versions, and file hashes to strengthen forensic reproducibility.

## Investigation Outcome

The exercises demonstrate successful remote evidence collection, NTFS metadata parsing, event-log conversion, and API-call inspection. The clearest findings are the renamed executable **`microsoft.windowskits.feedback.exe`** and scheduled task **`Microsoft-Windows-DiagnosticDataCollector`**. The first exercise's requested task name and the fourth exercise's claimed injection target need additional evidence before being treated as independently confirmed.

## Conclusion

This project demonstrates foundational endpoint DFIR capabilities across evidence acquisition, filesystem metadata, Windows event logs, and behavioral API traces. By documenting both results and verification gaps, it emphasizes a core forensic principle: **observed artifacts must be distinguished from inferred attacker behavior**.

## Evidence Handling Note

This is an authorized training-lab write-up. Screenshots are included for reproducibility; original forensic archives and memory or disk evidence should not be published to a public GitHub repository. In real investigations, record acquisition times, source identifiers, tool versions, hashes, and chain-of-custody details.


