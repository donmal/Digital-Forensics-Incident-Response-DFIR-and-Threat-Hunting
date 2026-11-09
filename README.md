# Digital Forensics & Incident Response (DFIR) — Investigation Portfolio
| Hack-the-Box Academy |

## Overview

This repository documents four practical, lab-based Digital Forensics and Incident Response (DFIR) investigations. The projects progress from endpoint evidence acquisition and Windows artifact analysis to memory forensics, multi-source attack reconstruction, and Velociraptor-based threat hunting.

Each case study describes its investigative objectives, data sources, methodology, supporting evidence, findings, detection opportunities, and limitations. The emphasis is on reproducible analyst workflows and separating directly observed artifacts from unverified conclusions.

> **Scope:** These are authorized training-lab investigations, not claims of production incident response. Some findings are supported by screenshots or artifact previews rather than complete raw evidence sets.

## Investigation Index

| # | Investigation | Primary focus | Tools and evidence |
|---|---|---|---|
| 01 | [Evidence Acquisition & Windows Artifact Analysis](01-Evidence-Acquisition-and-Windows-Artifact-Analysis/README.md) | Endpoint collection, NTFS metadata, scheduled tasks, API traces | Velociraptor, KAPE, NTFS artifacts, EVTX, Timeline Explorer, API Monitor |
| 02 | [Windows Memory Forensics & WannaCry Investigation](02-Windows-Memory-Forensics-and-WannaCry-Investigation/README.md) | Process ancestry, file handles, loaded modules | Volatility, Windows memory image, process and DLL artifacts |
| 03 | [Advanced DFIR & Attack Reconstruction](03-Advanced-DFIR-and-Attack-Reconstruction/README.md) | PowerShell memory, YARA corroboration, USN/Autopsy/Sysmon correlation | Volatility 3, Sysinternals Strings, YARA, USN Journal, Autopsy, Sysmon |
| 04 | [Velociraptor Threat Hunting](04-Velociraptor-Threat-Hunting/README.md) | VAD anomalies, C2 configuration, persistence, YARA, recent documents | Velociraptor, Malfind, Cobalt Strike carving, Registry, YARA |

## Case Studies

### 01 — Evidence Acquisition & Windows Artifact Analysis

**Objective:** Acquire endpoint evidence and investigate suspicious Windows activity using filesystem, event-log, and behavioral artifacts.

**Work performed:** Velociraptor/KAPE acquisition; NTFS rename and `Zone.Identifier` correlation; scheduled-task creation analysis using EVTX-derived data; and API Monitor process-behavior review.

**Key findings:** A renamed `microsoft.windowskits.feedback.exe` artifact and the `Microsoft-Windows-DiagnosticDataCollector` scheduled task were identified.

The available evidence did not independently confirm the suspected process-injection behavior or establish all details of the scheduled-task activity.

### 02 — Windows Memory Forensics & WannaCry Investigation

**Objective:** Reconstruct ransomware-themed process relationships and examine memory-resident artifacts.

**Work performed:** Process-tree analysis, file-handle inspection, and loaded-module enumeration.

**Key findings:** `tasksche.exe` was identified as the parent of `@WanaDecryptor`; a handle referenced `hibsys.WNCRYT`; and `zlib1.dll` appeared in the `taskhsvc.exe` module listing (PID `3012`). The available evidence does not independently establish the initial infection vector or a complete encryption timeline.

### 03 — Advanced DFIR & Attack Reconstruction

**Objective:** Examine a suspicious PowerShell process and correlate filesystem and event evidence to investigate the introduction of a scanning utility.

**Work performed:** Extracted memory pages for PowerShell PID `6744`, reviewed printable strings, validated PowerView indicators using YARA, parsed the NTFS USN Journal, and correlated an archive through Autopsy and Sysmon evidence.

**Key findings:** Three YARA string matches supported the presence of **PowerView** in the memory dump. `advanced_ip_scanner.exe` was associated with `advanced.zip`, and the available Sysmon preview associated `rundll32.exe` with archive activity. String presence does not by itself prove PowerView execution, and the exact transfer mechanism was not established.

### 04 — Velociraptor Threat Hunting

**Objective:** Triage a suspicious endpoint following indications of possible data exfiltration and investigate memory, command-and-control configuration, persistence, and user activity.

**Work performed:** Velociraptor collections for VAD/Malfind analysis, Cobalt Strike configuration carving, startup-item inspection, YARA file scanning, and RecentDocs analysis.

**Key findings:** `reverse.exe` was flagged for suspicious executable memory; the carved configuration contained C2 address `3.19.219.4`; an HKLM Run-key entry indicated persistence; Mimikatz-related files were found under `C:\Users\j0seph\AppData\Local\mimik`; and RecentDocs listed `insurance.DOCX`. A configured C2 address does not alone establish active communications or successful exfiltration.

## Technical Skills Demonstrated

- **Evidence acquisition and triage:** targeted endpoint collection, preservation of Windows artifacts, and review of collected evidence.
- **Windows filesystem forensics:** NTFS metadata, USN Journal analysis, alternate data streams, archive correlation, and file introduction timelines.
- **Memory forensics:** process trees, parent-child relationships, handles, loaded DLLs, process-memory extraction, and VAD anomaly triage.
- **Detection and threat hunting:** YARA-based scanning, malicious-tool indicators, suspicious executable-memory regions, and persistence discovery.
- **Cross-source correlation:** linking memory, registry, filesystem, Sysmon, and forensic-tool outputs into a coherent investigative narrative.
- **Reporting:** evidence-backed findings, limitations, and actionable detection opportunities.

## Tools and Technologies

`Velociraptor` · `KAPE` · `Volatility / Volatility 3` · `Sysinternals Strings` · `YARA` · `Autopsy` · `Sysmon` · `USN Journal Parser` · `Timeline Explorer` · `API Monitor` · `Windows Registry` · `EVTX` · `NTFS`

## Investigative Standards and Evidence Limitations

The case studies distinguish **observed evidence** from **analytical interpretation**. Memory-resident strings, YARA matches, file-presence indicators, and configuration artifacts are valuable leads, but do not automatically prove tool execution, credential theft, network exfiltration, or a complete intrusion sequence. Where only partial event records or screenshots are available, conclusions are qualified accordingly.

For real-world investigations, evidence collection should additionally document timestamps, system identifiers, acquisition method, tool versions, cryptographic hashes, and chain-of-custody records. Raw sensitive memory images and confidential endpoint data should not be uploaded to a public repository.

## Purpose

This portfolio demonstrates practical junior SOC / Blue Team and DFIR investigation skills, with a focus on methodical evidence analysis, defensible conclusions, and clear technical communication.

