# 03 - Advanced DFIR & Attack Reconstruction

## Executive Summary

This investigation combines process-memory analysis, signature-based validation, NTFS change-journal review, and host-artifact correlation to reconstruct two suspicious activities on a Windows endpoint. The first investigation examined a PowerShell process (PID 6744), extracted its resident memory with Volatility 3, and identified **PowerView**, a PowerSploit reconnaissance component, using string inspection and YARA. The second investigation traced the appearance of `advanced_ip_scanner.exe` through NTFS USN Journal records, an `advanced.zip` archive, Autopsy artifacts, and Sysmon event data. The available evidence identifies **`rundll32.exe`** as the associated process in the archive-creation sequence.

The findings support the presence of PowerView-related content in the PowerShell process and a relationship between `rundll32.exe`, `advanced.zip`, and the scanner executable. They do not, in isolation, establish which PowerView functions ran, the precise archive extraction mechanism, or the full scope of attacker activity.

## Investigation Objectives

1. Identify the PowerSploit tool represented in the memory of PowerShell PID 6744.
2. Validate the memory finding with reproducible YARA signatures.
3. Reconstruct how `advanced_ip_scanner.exe` appeared on the compromised endpoint.
4. Correlate file-system activity with archived content and Sysmon telemetry.
5. Distinguish directly observed evidence from investigative inference.

## Background and Investigation Scenario

The investigation was performed in a controlled Hack The Box Academy Windows DFIR environment. The analyst accessed a Windows examination host over RDP, worked with a previously acquired physical memory image, and examined NTFS artifacts collected by KAPE. Tools included **Volatility 3**, **Sysinternals Strings**, **YARA**, a **USN Journal parser**, **LibreOffice Calc**, and **Autopsy**. The public PowerSploit repository was consulted to validate tool attribution.

## Data Sources and Tools

| Source / Tool | Investigative purpose |
|---|---|
| `PhysicalMemory.raw` | Memory image used to extract resident pages for PowerShell PID 6744 |
| Volatility 3 `windows.memmap` | Map and dump memory pages associated with the specified process |
| Sysinternals `strings.exe` | Recover printable text from the process dump |
| PowerSploit GitHub repository | Reference for identifying PowerView as a PowerSploit component |
| YARA 4.3.2 | Search the dump for PowerView / Invoke-Shellcode indicators |
| NTFS `$UsnJrnl:$J` | Record file-system changes involving the scanner and its archive |
| USN Journal Parser | Export journal records to CSV |
| LibreOffice Calc | Search and review the exported journal timeline |
| Autopsy case `MalwareAttack.aut` | Correlate archive contents and indexed forensic artifacts |
| `Microsoft-Windows-Sysmon%4Operational.evtx` | Investigate process and file activity associated with `advanced.zip` |

## Investigation Methodology

### Phase 1 — Reference Identification: PowerSploit

The analyst consulted the archived `PowerShellMafia/PowerSploit` repository and reviewed its **v3.0.0** release notes. The release notes explicitly reference **PowerView** and **PowerUp**, providing a grounded list of candidate tool names for memory inspection. The repository being archived and the release being old are provenance details; they do not by themselves establish use on the examined endpoint.

Suggested evidence — Figure 1: PowerSploit repository or release documentation identifying PowerView as a PowerSploit component.

### Phase 2 — Preparing Sysinternals Strings

On the analyst's Linux host, the Sysinternals Suite was downloaded for subsequent use on the Windows examination machine:

```bash
wget https://download.sysinternals.com/files/SysinternalsSuite.zip
```

The analyst then connected to the lab Windows host with an RDP shared drive, transferred and extracted the archive, and launched `strings.exe`, accepting its license terms. The share name and connection target are environment-specific and must be substituted as appropriate.

```bash
xfreerdp /v:<TARGET_IP> /u:johndoe /p:<LAB_PASSWORD> /dynamic-resolution /drive:share,<LOCAL_SHARED_DIRECTORY>
```

### Phase 3 — Extracting PowerShell PID 6744 Memory

From the Windows command prompt, the analyst ran Volatility 3 against the acquired physical-memory image, selecting PID 6744 and requesting a dump of mapped memory pages:

```cmd
cd C:\Users\johndoe\Desktop\volatility3-develop
python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.memmap --pid 6744 --dump
```

The resulting artifact was identified as `pid.6744.dmp` in the Volatility working directory. This step extracts memory content associated with the selected process rather than generating a new live-memory capture.

Suggested evidence — Figure 2: Volatility 3 output showing memory extraction for PowerShell PID 6744 and the generated process dump.

### Phase 4 — String-Based Memory Examination

The analyst used Sysinternals Strings to extract readable sequences from the binary process dump, then inspected the output in Notepad:

```cmd
C:\Users\johndoe\Desktop\SysinternalsSuite\strings.exe pid.6744.dmp > a.txt
notepad a.txt
```

The screenshot of the resulting text includes PowerShell content, and a text search reveals the string **`PowerView`** within PowerShell source-like material, including references such as `PowerView.RDPSessionInfo`. This is evidence of PowerView-related content resident in the dumped memory.

### Figure 7 - PowerView Strings in Process Memory

![Figure 1 - PowerSploit PowerView Reference](/Digital-Forensics-Incident-Response-DFIR-and-Threat-Hunting/images/advanced-dfir-and-attack-reconstruction/powersploit-powerview-reference.jpeg)

### Phase 5 — YARA Corroboration

The analyst created a small YARA rule to look for either of two PowerSploit-related strings in ASCII or UTF-16LE-style wide representation:

```yara
rule ExampleRule
{
    strings:
        $s1 = "PowerView" wide ascii
        $s2 = "Invoke-Shellcode" wide ascii
    condition:
        1 of ($s*)
}
```

The rule was saved as `powerview.yar` and executed against the process dump.

The following command was used to scan the extracted memory dump with the YARA rule:

```cmd
cd C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64
yara64.exe -s C:\Users\johndoe\Desktop\powerview.yar C:\Users\johndoe\Desktop\volatility3-develop\pid.6744.dmp
```

The YARA output displayed **three matches** for `$s1`, at offsets `0x1508478f`, `0x15084ce7`, and `0x15084ea9`. The output showed wide-character bytes (`P\x00o\x00...`), consistent with a UTF-16LE representation of `PowerView`. These are three string occurrences, **not** three proven executions of PowerView. No `$s2` match is visible in the provided result.

### Figure 8 - YARA PowerView Detection 

![Figure 2 - YARA PowerView Detection](/Digital-Forensics-Incident-Response-DFIR-and-Threat-Hunting/images/advanced-dfir-and-attack-reconstruction/yara-powerview-detection.jpeg)

**Finding**: Memory-string inspection and YARA scanning identified PowerView-related content in the extracted memory of PowerShell PID **6744**. Three string occurrences corroborated the identification of PowerView as a PowerSploit-related artifact. The available evidence supports the presence of PowerView-related content in memory but does not independently confirm which functions, if any, were executed.

**Investigation answer 1: `PowerView`.**

### Phase 6 — Parsing the NTFS USN Journal

The second investigation focused on how `advanced_ip_scanner.exe` was introduced to the endpoint. The analyst parsed the collected NTFS USN Journal into a CSV file. The path to the journal contains percent-encoded components and must match the collected artifact exactly.

```cmd
python C:\Users\johndoe\Desktop\files\USN-Journal-Parser-master\usnparser\usn.py -f "C:\Users\johndoe\Desktop\kapefiles\ntfs\%5C%5C.%5CC%3A\$Extend\$UsnJrnl%3A$J" -o C:\Users\johndoe\Desktop\usn_output.csv -c
```

The exported `usn_output.csv` was opened in LibreOffice Calc. In the screenshot, the import dialog shows **Fixed width** selected, resulting in the CSV records appearing together in a single visible column. This still permitted text search, although comma-separated import would be preferable for column-wise analysis.

Suggested evidence — Figure 5: USN Journal parser output confirming extraction of NTFS change records into usn_output.csv.

### Phase 7 — Correlating the Executable with an Archive

A search for `advanced_ip_scanner.exe` in the journal export showed file-system entries for the executable and related artifacts. The analyst also identified **`advanced.zip`** in the investigative timeline, providing a plausible archive source for the executable. Temporal proximity alone does not prove a parent-child process relationship.

### Figure 9 - USN Journal Scanner Artifacts 

![Figure 3 - USN Journal Scanner Artifacts](/Digital-Forensics-Incident-Response-DFIR-and-Threat-Hunting/images/advanced-dfir-and-attack-reconstruction/usn-journal-scanner-artifacts.jpeg)

The analyst opened the existing Autopsy case at:

```text
C:\Users\johndoe\Desktop\MalwareAttack\MalwareAttack.aut
```

An Autopsy keyword search for `advanced.zip` returned 17 results in the displayed case view. The archive was located, extracted for inspection, and its contents were reviewed in Windows File Explorer. The archive contained **`advanced_ip_scanner.exe`**, directly supporting the archive-to-executable relationship.

### Figure 10 - Advanced IP Scanner Archive Contents 

![Figure 4 - Advanced IP Scanner Archive Contents](/Digital-Forensics-Incident-Response-DFIR-and-Threat-Hunting/images/advanced-dfir-and-attack-reconstruction/advanced-ip-scanner-archive-contents.jpeg)

### Phase 8 — Sysmon Correlation and Process Attribution

The analyst then reviewed the indexed `Microsoft-Windows-Sysmon%4Operational.evtx` artifact in Autopsy. The visible keyword-preview content associates `advanced.zip` with `C:\Windows\System32\rundll32.exe`, alongside host and timestamp information. This supports **`rundll32.exe`** as the process associated with the archive-creation activity described by the lab.

### Figure 11 - Sysmon and Rundll32 Correlation 

![Figure 5 - Sysmon Rundll32 Correlation](/Digital-Forensics-Incident-Response-DFIR-and-Threat-Hunting/images/advanced-dfir-and-attack-reconstruction/sysmon-and-rundll32-correlation.jpeg)

The screenshots show indexed text/keyword previews rather than the complete decoded Sysmon event fields. Consequently, the exact event ID, process GUID, file-creation field names, and complete causal chain cannot be independently verified from the images alone. A full event-level review would be needed to confirm whether `rundll32.exe` created, wrote, or otherwise handled the archive and whether a separate process extracted its contents.


**Finding**: Cross-source correlation of NTFS USN Journal records, Autopsy artifacts, and indexed Sysmon content identified **rundll32.exe** as a process associated with activity involving **advanced.zip**. The archive contained **advanced_ip_scanner.exe**, supporting a relationship between the archive and the executable. The precise archive-creation, transfer, and extraction sequence remains unverified.

## Consolidated Evidence and Findings

| Finding | Evidence | Assessment |
|---|---|---|
| PowerView content present in PowerShell PID 6744 | Memory dump, extracted strings, YARA `$s1` matches | Supported by direct string evidence |
| Three `PowerView` string occurrences | YARA offsets `0x1508478f`, `0x15084ce7`, `0x15084ea9` | Confirmed string matches; execution count unknown |
| `advanced_ip_scanner.exe` associated with `advanced.zip` | USN Journal search, Autopsy search, extracted archive contents | Supported by artifact correlation |
| `rundll32.exe` associated with archive activity | Autopsy-indexed Sysmon text | Supported at preview level; full event validation recommended |

## MITRE ATT&CK Mapping

| Technique | ID | Relationship to observed evidence |
|---|---|---|
| PowerShell | T1059.001 | Suspicious PowerShell process memory was examined; script content was present |
| System Network Configuration Discovery | T1016 | Potential capability of PowerView; **not confirmed as executed** in this evidence |
| Remote System Discovery | T1018 | Potential capability of PowerView and IP-scanning software; **not confirmed as executed** |
| Ingress Tool Transfer | T1105 | A plausible interpretation of scanner introduction; transfer method **not established** |
| System Binary Proxy Execution: Rundll32 | T1218.011 | `rundll32.exe` was associated with archive activity; proxy-execution behavior **not independently established** |

## Detection and Investigation Opportunities

- Correlate suspicious PowerShell processes with script-block logging, process command lines, and memory-derived indicators where legally and operationally appropriate.
- Search for PowerView function names, but treat static string matches as triage indicators rather than standalone proof of execution.
- Monitor `rundll32.exe` for unusual command lines, unexpected child processes, and file operations involving archives or reconnaissance utilities.
- Correlate NTFS USN Journal file-creation records with Sysmon process and file-creation events and the extracted contents of relevant archives.
- Preserve original forensic artifacts and record hashes, collection time, tool versions, and chain of custody in a production investigation.

## Investigation Outcome

The investigation produced two principal findings:

**Memory-based tool identification**: PowerView-related strings were identified within the extracted memory of PowerShell PID **6744**, with three corroborating YARA matches. These findings establish the presence of identifiable tool-related content without independently proving execution of specific PowerView functions.

**Filesystem and process correlation**: NTFS journal analysis and Autopsy examination associated **advanced_ip_scanner.exe** with **advanced.zip**. Indexed Sysmon evidence further associated **rundll32.exe** with the archive activity, although the complete sequence of file introduction and extraction could not be independently reconstructed.

## Conclusion

This case demonstrates a multi-source DFIR workflow: extracting process memory, inspecting embedded PowerShell-related strings, corroborating indicators with YARA, and reconstructing file introduction through NTFS, archive, and Sysmon artifacts. The observed evidence identifies **PowerView** in PowerShell PID 6744 and associates **`rundll32.exe`** with the archive that contained `advanced_ip_scanner.exe`. The analysis deliberately separates these observed artifacts from broader claims about confirmed script execution, network reconnaissance, and the precise file-transfer mechanism.

