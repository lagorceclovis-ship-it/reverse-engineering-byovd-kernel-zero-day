# Analysis of a BYOVD-based Kernel Driver Loading Chain

**Author:** Clovis Lagorce
**Date:** May 2026
**Contact:** lagorceclovis@gmail.com
**Type:** Independent security research — Responsible Disclosure

> (c) 2026 Clovis Lagorce. All rights reserved.
> Partial or full reproduction without written permission is prohibited.
> This document was timestamped prior to publication.

---

## Disclaimer

This analysis was conducted on a binary obtained for research purposes only. No malicious use was made of the techniques described. Findings were responsibly disclosed to the affected vendor. Specific technical indicators (hashes, URLs, pseudonyms, driver names) have been intentionally omitted from this public write-up and reserved for the private disclosure report.

---

## Abstract

This write-up documents the analysis of a Windows x86-64 binary protected by VMProtect. The analysis revealed a multi-stage kernel driver loading chain leveraging a Bring Your Own Vulnerable Driver (BYOVD) technique to bypass Driver Signature Enforcement (DSE), ultimately loading a custom unsigned kernel-mode driver. The malicious driver sample was undetected by all major antivirus engines at the time of submission. Additionally, the binary was found to implement physical memory access techniques to bypass a commercial anti-cheat solution operating in user-mode.

This document distinguishes between confirmed observations, reasonable inferences, and unverified hypotheses.

---

## Environment & Tooling

| Tool | Purpose |
|---|---|
| IDA Free 8.x | Static analysis, string extraction, cross-references |
| x64dbg (latest) | Dynamic analysis, process attachment, memory dump |
| ScyllaHide plugin | Anti-debug bypass (VMProtect profile) |
| PowerShell 5.1 | Automated string extraction, registry forensics |
| Python 3.x | Binary parsing, ASCII/UTF-16 string extraction |
| VirusTotal | Sample reputation lookup |

Analysis was performed on an isolated Windows 10 x64 system.

---

## 1. Static Analysis

### 1.1 Observations

The binary is approximately 12 MB and targets the x86-64 architecture. Upon loading in IDA Free, the auto-analysis enters a loop over a specific address range, preventing normal completion. This behavior is consistent with VMProtect virtualization, which replaces native instructions with a proprietary bytecode executed by an embedded virtual machine.

Attempting Hex-Rays decompilation on the identified entry function fails with:

```
Error: stack frame is too big
```

Inspection of the function metadata reveals an abnormally large declared stack frame. This is a documented VMProtect anti-decompilation technique that artificially inflates the frame size to exceed decompiler limits.

### 1.2 Limitations

Due to VMProtect protection, the following could not be reliably determined through static analysis alone:

- Runtime-decrypted string values (including network endpoints)
- Precise control flow of virtualized functions
- Complete list of APIs resolved at runtime

---

## 2. Dynamic Analysis

### 2.1 Anti-debug observations

Upon execution under a debugger, the binary displays an alert indicating debugger detection. Three distinct mechanisms were identified:

1. Standard Windows API check (user-mode)
2. Direct PEB field inspection, bypassing the API layer
3. Additional checks appearing to be implemented within the VMProtect virtual machine, resistant to standard hooking

### 2.2 Bypass methodology

The binary was launched without a debugger. x64dbg was subsequently attached to the running process with ScyllaHide (VMProtect profile). This approach is effective against checks (1) and (2). Check (3) had already executed by attachment time.

**Note:** This methodology does not guarantee complete anti-debug bypass.

---

## 3. Memory Acquisition & String Analysis

### 3.1 Memory dump

With the debugger attached and the process awaiting user input, a memory snapshot of the PE image sections was acquired via the x64dbg console. Dump size: approximately 21 MB. At this point, VMProtect-encrypted strings have already been decrypted in memory.

### 3.2 String extraction

A custom Python script extracted printable ASCII and UTF-16 LE sequences from the dump. Total: approximately 23,700 strings, of which approximately 300 matched security-relevant keywords.

### 3.3 Notable findings

**Debug symbol paths (PDB):**
Two PDB paths were identified. Their presence indicates debug symbols were not stripped from the binary at build time. The paths suggest two separate components compiled on developer machines, and include pseudonyms embedded in the filesystem paths.

**Error message strings:**
Several strings suggest a DSE disabling mechanism with error handling. Messages reference failure conditions for DSE enable/disable operations and a command-line usage string accepting a target driver path.

**Kernel function references:**
Three logging-style strings were identified:

```
[DRIVER] BruteforceCR3: FOUND CR3=0x%llX
[DRIVER] ReadFunc: MmMapIoSpaceEx
PsGetProcessSectionBaseAddress
```

These appear to be debug output embedded in the kernel driver component. Their presence suggests, but does not conclusively prove, runtime use of these techniques.

---

## 4. Network Infrastructure

### 4.1 Methodology

The license server URL was absent from the memory dump in plaintext, indicating runtime decryption. DNS cache analysis was used:

1. DNS resolver cache flushed
2. Binary executed with test input submitted
3. DNS cache inspected for new entries

### 4.2 Findings

A subdomain of a known Backend-as-a-Service platform appeared in the cache post-execution. The subdomain contains a unique project identifier that could allow the platform provider to associate the project with a registered account through appropriate legal channels.

Resolved IP addresses belong to a major CDN acting as a reverse proxy, obscuring the backend infrastructure.

*Full domain, project identifier, and IP addresses are omitted and reserved for the private disclosure report.*

---

## 5. Kernel Driver Loading Chain

### 5.1 Observed artifacts

**Filesystem:**
- One or more `.sys` files with randomly generated hexadecimal filenames written to a user-writable temporary directory
- A second `.sys` written to a system temporary directory (subsequently deleted; registry artifacts remain)

**Registry:**
Services created under `HKLM\SYSTEM\CurrentControlSet\Services`:

```
Type  : 0x1  (SERVICE_KERNEL_DRIVER)
Start : 0x4  (SERVICE_DISABLED)
```

Setting `Start` to `SERVICE_DISABLED` post-load is consistent with an attempt to reduce forensic visibility.

### 5.2 Inferred loading chain

**The driver loading sequence was not directly observed at runtime** due to a license validation gate preventing full execution with test inputs. The following is inferred from filesystem, registry, and string artifacts.

**Stage 1 — Vulnerable signed driver:**
A driver signed by a legitimate software vendor is loaded. This driver is referenced in the LOLDrivers database and is known to expose kernel memory read/write primitives via IOCTL. Its legitimate signature allows loading under normal DSE enforcement.

**Stage 2 — DSE bypass:**
The vulnerable driver is used to modify a kernel enforcement variable. This is inferred from extracted error strings referencing DSE operations.

**Stage 3 — Custom driver loading:**
A driver bearing a WDK test certificate is loaded. On a system where `testsigning` is disabled (confirmed via bcdedit), such a certificate would normally prevent loading. Its presence provides indirect evidence of a prior DSE bypass.

**Stage 4 — Cleanup:**
Vulnerable driver file deleted from disk. Service entries set to DISABLED.

*Specific driver names, IOCTL codes, and kernel addresses are omitted.*

---

## 6. Custom Driver Sample

### 6.1 Authenticode signature

The custom `.sys` files carry the following signature:

```
Certificate type : WDK Test Certificate (development use only)
Common Name      : "WDKTestCert [pseudonym], [serial]"
```

A WDK test certificate is self-signed and intended for development only. Windows rejects such certificates unless the system is in test signing mode or DSE has been bypassed. The Common Name field contains a developer pseudonym — an operational security failure constituting an attribution indicator.

### 6.2 VirusTotal result

SHA-256 submitted to VirusTotal: **0 detections across 72 engines** at time of submission.

This is a point-in-time observation. It does not imply permanent evasion capability, and detection rates may change following vendor notification.

*Hash omitted from this public write-up.*

---

## 7. Physical Memory Access

### 7.1 Context

The binary targets a process protected by a commercial anti-cheat solution operating primarily in user-mode, monitoring standard Windows memory access APIs.

### 7.2 Indicators

The following strings suggest physical memory access techniques. **These were not confirmed through direct runtime observation.**

```
[DRIVER] BruteforceCR3: FOUND CR3=0x%llX
[DRIVER] ReadFunc: MmMapIoSpaceEx
PsGetProcessSectionBaseAddress
```

**CR3:** Holds the physical base address of the page directory for the active process. Enumerating CR3 values is a documented technique for locating a target process's physical memory without using monitored virtual memory APIs (see: Spookware, VDM, and related prior art in public kernel research).

**MmMapIoSpaceEx:** Maps a physical address range into virtual address space. Use here, in conjunction with CR3 enumeration, is consistent with physical memory reading documented in public security research.

**PsGetProcessSectionBaseAddress:** Returns a process executable base address, used to locate the target in memory.

### 7.3 Assessment

If implemented as suggested, this approach operates entirely in kernel-mode and would not generate user-mode API calls monitored by the observed anti-cheat solution. However, this was **not confirmed through direct runtime observation**.

---

## 8. Attribution Indicators

No active OSINT or account enumeration was conducted. Two passive indicators were identified:

| Indicator type | Observation |
|---|---|
| PDB path in binary | Developer pseudonym A embedded in filesystem path of a compiled component |
| Authenticode CN | Developer pseudonym B used to generate the WDK test certificate |

A two-person development effort is suggested, though a single developer using multiple pseudonyms cannot be excluded.

*Full pseudonyms reserved for private disclosure report.*

---

## 9. Limitations

- **Runtime execution was incomplete.** The license gate prevented full execution. Kernel driver loading and physical memory access were not directly observed. Conclusions in sections 5 and 7 are inferences.
- **Partial memory coverage.** The dump covers PE image sections only. Heap and stack were not captured.
- **No kernel debugging.** Driver behavior is inferred from extracted strings, not observed execution.
- **Single sample, single execution.** Behavior may vary across versions or system configurations.
- **VirusTotal snapshot.** Detection rate reflects a single point in time.

---

## 10. Summary of Findings

| Finding | Confidence | Basis |
|---|---|---|
| VMProtect obfuscation | High | Static analysis |
| Multi-layer anti-debug | High | Dynamic observation |
| Memory dump — 21 MB, 23,700+ strings | High | Direct artifact |
| C2 domain identified | High | DNS cache |
| .sys files in %TEMP% | High | Filesystem |
| Kernel driver services in registry | High | Registry |
| WDKTestCert with developer pseudonym | High | Authenticode |
| 0/72 VirusTotal at submission | High | VT report |
| DSE bypass | Medium | Indirect — testsigning=No + WDKTestCert loaded |
| BYOVD chain | Medium | String artifacts + registry |
| Physical memory access | Medium | String artifacts — not runtime confirmed |
| Two-developer attribution | Low-Medium | PDB path + certificate CN |

---

## 11. Responsible Disclosure

Findings were disclosed to the affected vendor including full technical indicators omitted here. AV vendors were notified for signature creation.

---

## References

- LOLDrivers project — loldrivers.io
- MITRE ATT&CK: T1014 (Rootkit), T1068, T1562.001
- Microsoft documentation: Driver Signature Enforcement, WDK Test Certificates
- VDM / physical memory reading prior art — public kernel research community

---

*(c) 2026 Clovis Lagorce — lagorceclovis@gmail.com*
*Reproduction prohibited without written authorization.*
