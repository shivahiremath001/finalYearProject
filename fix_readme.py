import re

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Numbers
    content = content.replace("70.3", "80.3")
    content = content.replace("5.76 + 5.60 = 11.36", "5.76 + 7.20 = 12.96")
    content = content.replace("11.36 / 80.3", "12.96 / 80.3")
    content = content.replace("16.16", "16.14")
    content = content.replace("12.5/100", "4.0/100")
    content = content.replace("12.5", "4.0")
    content = content.replace('"risk_score": 68.5', '"risk_score": 72.0')
    content = content.replace("Estimated Score: 68.5", "Estimated Score: 72.0")
    content = content.replace("z_score\": 4.82", "z_score\": 56.0")
    
    # 2. Contradictions
    content = content.replace("[20, 40, 70]", "[25, 50, 75]")
    content = content.replace("20 / 40 / 70", "25 / 50 / 75")
    content = content.replace("guarantees a minimum score floor of 50.0", "guarantees a minimum score floor of 50.0 and raises the classification to HIGH RISK")
    
    content = re.sub(r"It does not invent a risk score:.*the local score is shown as unavailable and local findings may include parameters excluded by server policy\. ", "", content)
    
    content = content.replace("disable_smb1", "disable_smb_v1")
    content = content.replace("PENDING / EXECUTING / COMPLETED", "PENDING / DELIVERED / EXECUTED")
    content = content.replace("EXECUTING", "DELIVERED")
    content = content.replace("COMPLETED", "EXECUTED")
    content = content.replace("output_log", "output")
    content = content.replace("/api/v1/machines", "/machines")
    content = content.replace("fleet-wide rolling Z-scores", "per-host rolling Z-scores")
    content = content.replace("Background/Service", "Background Agent")
    content = content.replace("Three concurrent threads", "A ThreadPoolExecutor")
    content = content.replace("BIOS UUID", "hardware MAC address, then hostname")
    
    # 3. Factual Errors
    content = content.replace("MAC addresses (which randomize on Windows 10/11 Wi-Fi)", "MAC addresses (which can randomize on Windows Wi-Fi if enabled)")
    content = content.replace("immutable Windows Cryptography", "installation-specific Windows Cryptography")
    content = content.replace("persistent 128-bit UUID generated during Windows operating system installation", "128-bit UUID generated during Windows OS installation (note: cloned VMs without Sysprep share the same GUID)")
    content = content.replace("wmic csproduct get uuid", "Get-CimInstance Win32_ComputerSystemProduct")
    
    content = content.replace("Mimikatz, Cobalt Strike, BlackSuit", "BlackSuit, RansomHub, Phobos")
    content = content.replace("Scattered Spider (Scatter Swine / UNC3944)", "Akira, BlackByte")
    
    content = content.replace("rather than exotic zero-day vulnerabilities", "often alongside N-day or zero-day vulnerabilities")
    content = content.replace("#1 vector, 60%+", "a leading vector")
    content = content.replace("They serve as vulnerability scanners", "While they perform vulnerability and compliance scanning")
    
    content = content.replace("Event ID 1123 text", "Event ID 1123")
    content = content.replace("RunAsPPL != 1", "RunAsPPL not in (1, 2)")
    content = content.replace("set to 1", "enabled")
    content = content.replace("DisableTamperProtection", "Windows Defender\\\\Features\\\\TamperProtection")
    content = content.replace("zero shadow copies", "deleted or zero shadow copies")
    content = content.replace("O(N^2)", "O(N)")
    content = content.replace("Isolation Forest requires at least 100", "Isolation Forest typically requires sufficient")
    
    content = content.replace("260,000 iterations", "600,000 iterations") # Since I set it to 260,000 earlier, I will set it to 600,000 now.
    
    # 4. Citations
    content = re.sub(r"Tansey & Yu \(2024\)[^\|]*\|", "Industry Best Practices |", content)
    content = content.replace("D3-DT", "D3-DF")
    content = content.replace("EAC0018: Honeytoken", "MITRE Engage: Decoy")
    content = content.replace("ATT&CK v15", "ATT&CK v15 (legacy)")
    content = content.replace("Verizon DBIR  3.2 (Credential Access)", "Verizon DBIR")
    content = content.replace("CISA KEV (CVE-2017-0144", "CISA Advisory (CVE-2017-0144")
    content = content.replace("T1490", "T1047") 
    content = content.replace("Strictly derived from threat intelligence", "Informed by threat intelligence")
    content = content.replace("Two-dimensional tensor", "weighted parameters")
    
    # 5. Design flaws
    content = content.replace("Weight 5.0", "Weight 4.0") 
    content = content.replace("HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "Task Scheduler with highest privileges")
    content = content.replace("time.sleep(1)", "threading.Event().wait(1)")
    content = content.replace("cannot inject arbitrary code", "can only trigger allowlisted actions")
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

process_file('README_DEEP.md')
