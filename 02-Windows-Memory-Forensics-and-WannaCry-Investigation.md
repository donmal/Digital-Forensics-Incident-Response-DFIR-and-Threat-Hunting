# 02 - Windows Memory Forensics and WannaCry Investigation

## Executive Summary

This investigation examines a Windows 7 SP1 x64 memory image using Volatility 2.6.1 to reconstruct process relationships, identify a suspicious ransomware-associated file handle, and attribute a loaded compression library to a process. The three exercises use the same memory image, `/home/htb-student/MemoryDumps/Win7-2515534d.vmem`, and are presented as one cohesive memory-forensics case study. Evidence links `@WanaDecryptor` (PID 1060) to its parent `tasksche.exe` (PID 1792), identifies an open handle to `hibsys.WNCRYT`, and associates `zlib1.dll` with `taskhsvc.exe` (PID 3012).

The results establish process ancestry, a file-object reference, and a loaded module in the captured memory. They do not independently prove initial infection vector, successful encryption, or external communication.

## Investigation Objectives

1. Identify the parent process of `@WanaDecryptor` (PID 1060) using a process tree.
2. Enumerate file handles held by `tasksche.exe` (PID 1792) and locate a `.WNCRYT` artifact.
3. Identify the process that loaded `zlib1.dll` and report its PID.
4. Correlate memory artifacts and distinguish direct observations from investigative interpretations.

## Background

Volatility is a memory-forensics framework used to inspect process structures and artifacts preserved in a memory image. The `pstree` plugin displays process parent-child relationships, `handles` enumerates kernel object handles, and `dlllist` enumerates loaded dynamic-link libraries. The names `@WanaDecryptor` and `.WNCRYT` are consistent with the WannaCry-related scenario supplied by the lab; names alone are not sufficient to establish every stage of a ransomware incident.

## Investigation Scenario and Data Sources

| Field | Value |
|---|---|
| Training environment | Authorized HTB Academy / REMnux lab |
| Evidence source | Windows virtual memory image (`.vmem`) |
| Memory image | `/home/htb-student/MemoryDumps/Win7-2515534d.vmem` |
| Operating system profile | `Win7SP1x64` |
| Forensic framework | Volatility Framework 2.6.1 (`vol.py`) |
| Plugins | `pstree`, `handles`, `dlllist` |
| Access method | SSH to the designated training host |
| Scope | Module questions 2.A, 2.B, and 2.C |

## Investigation Methodology

The analyst accessed the authorized remote analysis environment, ran Volatility against the supplied memory image, inspected the process tree for parent-child relationships, enumerated the file handles of the identified parent process, and searched the loaded-module listing for `zlib1.dll`. Screenshots are retained as evidence of the commands and displayed results.

---

## Investigation 1 — Process Ancestry of @WanaDecryptor (Question 2.A)

### Objective

Identify the parent executable of `@WanaDecryptor` (PID 1060).

### Phase 1 — Connect to the Analysis Host

```bash
ssh htb-student@<LAB_TARGET_IP>
```

The memory image was examined on the REMnux host. Lab credentials and temporary target addresses are intentionally excluded from the public report.

### Phase 2 — Enumerate the Process Tree

```bash
vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 pstree
```

Volatility 2.6.1 produced a process tree containing the relevant sequence:

```text
tasksche.exe      PID 1792
  @WanaDecryptor   PID 1060   PPID 1792
    taskhsvc.exe   PID 3012   PPID 1060
```

The `@WanaDecryptor` row explicitly reports **PPID 1792**, and the process tree identifies **`tasksche.exe`** as PID 1792. The same tree also places `taskhsvc.exe` (PID 3012) beneath `@WanaDecryptor` (PID 1060), an observation relevant to the later DLL investigation.

**Finding 2.A:** `tasksche.exe`.

### Evidence — Process Tree

![Volatility process-tree output, capture 1](images/memory-01.png)

![Volatility process-tree output, capture 2](images/memory-02.png)

![Volatility process-tree output, capture 3](images/memory-03.png)

![Volatility process-tree output, capture 4](images/memory-04.png)

![Volatility process-tree output, capture 5](images/memory-05.png)

![Volatility process-tree output, capture 6](images/memory-06.png)

![Volatility process-tree output, capture 7](images/memory-07.png)

---

## Investigation 1 — Process Ancestry of @WanaDecryptor (Question 2.A)

### Objective

Identify the parent executable of `@WanaDecryptor` (PID 1060).

### Phase 1 — Connect to the Analysis Host

```bash
ssh htb-student@<LAB_TARGET_IP>
```

The memory image was examined on the REMnux host. Lab credentials and temporary target addresses are intentionally excluded from the public report.

### Phase 2 — Enumerate the Process Tree

```bash
vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 pstree
```

Volatility 2.6.1 produced a process tree containing the relevant sequence:

```text
tasksche.exe      PID 1792
  @WanaDecryptor   PID 1060   PPID 1792
    taskhsvc.exe   PID 3012   PPID 1060
```

The `@WanaDecryptor` row explicitly reports **PPID 1792**, and the process tree identifies **`tasksche.exe`** as PID 1792. The same tree also places `taskhsvc.exe` (PID 3012) beneath `@WanaDecryptor` (PID 1060), an observation relevant to the later DLL investigation.

**Finding 2.A:** `tasksche.exe`.

### Evidence — Process Tree

![Volatility process-tree output, capture 1](images/memory-01.png)

![Volatility process-tree output, capture 2](images/memory-02.png)

![Volatility process-tree output, capture 3](images/memory-03.png)

![Volatility process-tree output, capture 4](images/memory-04.png)

![Volatility process-tree output, capture 5](images/memory-05.png)

![Volatility process-tree output, capture 6](images/memory-06.png)

![Volatility process-tree output, capture 7](images/memory-07.png)

---


## Investigation 2 — Suspicious File Handles (Question 2.B)

### Objective

Identify the suspicious file ending in `.WNCRYT` referenced by `tasksche.exe` (PID 1792).

### Phase 1 — Enumerate File Handles

```bash
vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 handles -p 1792 -t File
```

The `handles` plugin restricts the search to PID 1792; `-t File` filters for file-type kernel objects. In the output, a handle points to:

```text
\Device\HarddiskVolume2\Windows\Temp\hibsys.WNCRYT
```

The same output includes references to the directory `\Device\HarddiskVolume2\ProgramData\ggzstcat367` and a file named `00000000.eky`. These are contextual artifacts and do not, on their own, establish their purpose.

**Finding 2.B:** `hibsys.WNCRYT`.

### Evidence — File Handles

![File handles for tasksche.exe, capture 8](images/memory-08.png)

![File handles for tasksche.exe, capture 9](images/memory-09.png)

---


## Investigation 3 — Loaded zlib1.dll Module (Question 2.C)

### Objective

Identify the PID of the process associated with the loaded `zlib1.dll` library.

### Phase 1 — Search the DLL Listing

```bash
vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 dlllist | grep 'zlib1.dll' -A 5 -B 35
```

The `dlllist` plugin enumerates DLLs mapped into processes. The `grep` context options display nearby lines so that the matching DLL can be associated with its process header. The observed process header reads:

```text
taskhsvc.exe pid: 3012
Command line : TaskData\Tor\taskhsvc.exe
```

The DLL listing includes:

```text
C:\ProgramData\ggzstcat367\TaskData\Tor\zlib1.dll
```

The `zlib1.dll` library is a compression-related DLL. Its presence in a process module list confirms that it was loaded or mapped in the captured process context; it does **not** by itself show that the process downloaded the DLL, nor does the DLL name alone prove maliciousness. The process path and the surrounding artifacts provide the investigative context.

**Finding 2.C:** `3012` (`taskhsvc.exe`).

### Evidence — Loaded Modules

![DLL listing and process context, capture 10](images/memory-10.png)

![DLL listing and process context, capture 11](images/memory-11.png)

![DLL listing and process context, capture 12](images/memory-12.png)

![DLL listing and process context, capture 13](images/memory-13.png)

![DLL listing and process context, capture 14](images/memory-14.png)

---


## Evidence Summary

| Question | Forensic technique | Key evidence | Confirmed result |
|---|---|---|---|
| 2.A | `pstree` | `@WanaDecryptor` PID 1060 has PPID 1792 | `tasksche.exe` |
| 2.B | `handles -p 1792 -t File` | File handle to `\Windows\Temp\hibsys.WNCRYT` | `hibsys.WNCRYT` |
| 2.C | `dlllist` with context search | `zlib1.dll` under `taskhsvc.exe` process listing | PID `3012` |

## Investigation Findings and Interpretation

The process tree links the `@WanaDecryptor` process to `tasksche.exe` and places `taskhsvc.exe` downstream of `@WanaDecryptor`. The parent process also held a handle to a `.WNCRYT` file under the Windows temporary directory. A separate module search attributes `zlib1.dll` to `taskhsvc.exe`, with the library located under a `ProgramData` directory. Taken together, these observations form a coherent memory-based picture of the ransomware-themed lab activity.

The available screenshots do not show full malware execution traces, network traffic, or a complete encryption timeline. No assertion is made about the infection entry point, data exfiltration, or the total number of encrypted files.

## MITRE ATT&CK Considerations

| Technique | Relevance | Evidence status |
|---|---|---|
| T1057 — Process Discovery | Relevant to the analyst's process inspection, but the screenshots do not demonstrate attacker process discovery | Not established as adversary behavior |
| T1486 — Data Encrypted for Impact | Ransomware-themed context and `.WNCRYT` artifact warrant investigation | Encryption impact not independently verified |

ATT&CK mappings above are investigative considerations, not claims that all technique criteria were observed.

## Detection and Investigation Opportunities

- Correlate unexpected process ancestry with command-line and executable-path telemetry, especially unusual descendants of executables in user-writable locations.
- Investigate `.WNCRYT` artifacts alongside file creation, modification, and ransomware impact indicators.
- Monitor DLL loads from unusual application directories and correlate them with the associated process identity and behavior.
- Preserve volatile memory early and correlate findings with Windows event logs, EDR, and network evidence where available.

## Limitations

- Analysis is based on a supplied lab memory image and screenshots rather than an independently acquired forensic image.
- The selected Windows profile was supplied by the lab; no separate profile-validation result is documented.
- Volatility emits Python 2 cryptography deprecation notices and DLL-listing warnings. The relevant output remains visible, but these warnings should be considered when assessing completeness.
- The screenshots do not provide image hashes, acquisition timestamps, or full chain-of-custody documentation.

## Conclusion

Volatility analysis of the Windows 7 memory image identified **`tasksche.exe`** as the parent of `@WanaDecryptor` (PID 1060), recovered the suspicious file name **`hibsys.WNCRYT`** from handles belonging to `tasksche.exe` (PID 1792), and associated **`zlib1.dll`** with **`taskhsvc.exe`** (PID 3012). This case study demonstrates process-tree reconstruction, file-handle analysis, and loaded-module attribution as complementary techniques in Windows memory forensics.

---

*Portfolio note: This report documents authorized training-lab analysis. All conclusions are limited to the evidence displayed in the provided captures.*


