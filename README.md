# Universal Network Diagnostic Suite (Sentinel Edition)

A fully self-contained, zero-install PowerShell toolkit designed for Systems Engineers, Network Administrators, and IT infrastructure professionals. 

This suite provides deep, automated network diagnostics, Layer-2 discovery, security posture mapping, deep domain reconnaissance, and executive-level reporting. It is engineered for maximum compatibility, gracefully falling back between modern PowerShell 7+ native commands and legacy Windows PowerShell 5.1 asynchronous .NET tasks.

## 🚀 Key Features

* **Smart CIDR Subnet Sweeper & Diff Engine:** Automatically calculates your current subnet, executes a multi-threaded async ping sweep, maps the ARP cache against an embedded MAC vendor dictionary, and compares results to historical baselines to identify **Rogue Devices** or offline hardware.
* **Deep Domain OSINT & Reconnaissance:** Bypasses legacy WHOIS by utilizing modern RDAP and REST APIs to seamlessly map domain infrastructure, resolve DNS records, geolocate hosting providers, and execute stealth service scans on external targets without relying on third-party web scrapers.
* **Local Attack Surface Analyzer:** Maps local listening TCP/UDP ports to specific PIDs and process names to detect dangerously exposed services (e.g., RDP/SMB open to 0.0.0.0).
* **Network Vulnerability Matrix:** Sweeps the local segment for top-risk management ports (Telnet, FTP, HTTP, RDP, SMB) and generates a visual risk matrix for the entire subnet.
* **Executive Document Generation:** Automatically generates cleanly formatted, professional HTML/Word reports detailing network health, dropping pure telemetry data into client-ready formats with visual progress bars.
* **Dynamic TCP Bandwidth Tester:** A native, two-node bandwidth tester that runs a pre-flight link check and dynamically scales its TCP payload to accurately saturate and measure both 10Mbps legacy lines and 10Gbps fiber backbones.
* **Automated Layer 3 MTR:** Traces the routing path to a target and simultaneously tests latency and packet loss at every single hop to pinpoint ISP choke points.
* **WMI/CIM OS Inspection:** Queries remote Windows endpoints to pull OS version, system uptime, and primary storage capacity without requiring an RDP session.

## 🛠️ Usage

No installation or external modules are required. Simply download the script and execute it in an elevated PowerShell console.

.\Advanced-NetDiag.ps1

**State Memory Engine:** The script features persistent memory across modules. You can manually enter target IPs, or drag-and-drop a `.csv` or `.txt` file into the console to execute bulk diagnostics against hundreds of endpoints simultaneously without re-typing them.

## 🛡️ EDR / Antivirus Notice

**This is an authorized administrative tool, but it utilizes techniques commonly flagged by Endpoint Detection and Response (EDR) agents.** Due to the nature of network diagnostics, this script:
1. Performs broad subnet ICMP sweeping (Reconnaissance).
2. Opens dynamic TCP listening ports (C2/Exfiltration behavior).
3. Executes WMI queries and interactive SSH sessions (Lateral Movement).

If you are running Datto EDR, Sophos MDR, CrowdStrike, or SentinelOne, ensure the directory from which you run this script is whitelisted, or digitally sign the script with your organization's internal CA to prevent SOC alerts.

## 🧰 Included Modules

1. **Sequential Path Analyzer:** Measures latency added between physical routed hops.
2. **Automated Layer 3 MTR:** Automated route mapping and hop-by-hop latency analysis.
3. **Stability & Jitter Test:** 50-packet burst to calculate network jitter and packet loss.
4. **Continuous Drop Monitor:** Infinite ping loop that only logs timeout drops with timestamps.
5. **Smart CIDR Subnet Sweep:** Discovery, ARP mapping, and baseline diffing.
6. **Reverse MAC Address Resolver:** Offline ARP cache to Vendor translation.
7. **Rogue DHCP/Gateway Scanner:** Detects unauthorized network appliances routing traffic.
8. **DNS & HTTP Reachability:** Tests for DNS hijacking and HTTP firewall blocks.
9. **Local Attack Surface Map:** Maps open ports to local PIDs and processes.
10. **Network Vulnerability Matrix:** Subnet-wide sweep for risky management ports.
11. **Native TCP Bandwidth Tester:** Dynamic line-saturation throughput testing.
12. **Async TCP Port Scanner:** High-speed multi-threaded port sweeping.
13. **Local Adapter Health:** Queries NIC hardware for discarded packets and link speed.
14. **WMI/CIM OS Inspection:** Remote querying of OS, Uptime, and Disk Space.
15. **Native SSH Quick-Connect:** Embedded SSH session launcher.
16. **Wake-on-LAN (WoL) Integrator:** Crafts and broadcasts UDP magic packets.
17. **Smart IP & DNS Configurator:** Rapidly switch adapters between DHCP and Static.
18. **Modern Domain Check (RDAP):** Queries ICANN's RDAP database for clean domain registration and WHOIS data.
19. **Deep Domain Dossier (OSINT):** Enumerates DNS, maps IP geolocation/ASN, and runs stealth port scans on external domains.
20. **Open Exports Folder:** Quick access to generated reports.
21. **Pack & Go:** Zips all generated reports and securely wipes the raw export directory.

## 📄 License
This project is licensed under the MIT License - see the `LICENSE` file for details.
<img width="822" height="483" alt="Image" src="https://github.com/user-attachments/assets/b26e33b6-2965-4667-9913-01dec40c7dbf" />
<img width="1081" height="812" alt="Image" src="https://github.com/user-attachments/assets/641a0d36-dbbf-418e-9f0e-88013c806cb3" />
