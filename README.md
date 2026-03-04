# Unauthorized Year-End Compensation Data Access

## Technology Used
This simulation was performed using **Kusto Query Language (KQL)** via **Microsoft Sentinel** Log Analytics

##  Scenario

In early December, security monitoring detected irregular activity during year-end compensation and performance review processes that initially appeared consistent with legitimate administrative access. Further investigation revealed a multi-stage sequence involving unauthorized script execution, access to sensitive compensation data, data staging, persistence mechanisms, and attempted outbound communication. Correlation of endpoint telemetry across multiple users and systems enabled reconstruction of the full access chain, demonstrating how year-end bonus and performance data was accessed and prepared for potential exfiltration, highlighting elevated risk during high-trust business cycles.

---

## Procedure 

### 1. Initial Endpoint Association

The earliest actions attributed to account `5y51-d3p7` point to the initial endpoint involved which is **sys1-dept.**

**Query used:**

```kql
DeviceProcessEvents
| where AccountName =~ "5y51-d3p7"
| summarize FirstSeen=min(TimeGenerated) by DeviceName
| order by FirstSeen asc

```
<img width="937" height="217" alt="image" src="https://github.com/user-attachments/assets/5f6afe9a-9ede-47f7-8ec9-1f3c150ad37c" />

---

### 2. Remote Session Source Attribution

The initial remote session source IP address accessing the endpoint is **192.168.0.110.**

**Query used:**

```kql

DeviceNetworkEvents
| where InitiatingProcessAccountName == "5y51-d3p7"
| project InitiatingProcessRemoteSessionIP, InitiatingProcessAccountName, RemotePort
```
<img width="1390" height="360" alt="image" src="https://github.com/user-attachments/assets/7be2e453-501b-4d1a-a5f1-8dc166b04278" />

---

### 3. Support Script Execution

Here is a support-themed PowerShell script that has been executed under the user profile:

```
"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1
```
**Query used:**

```kql
DeviceProcessEvents
| where DeviceName =~ "sys1-dept"
| where ProcessCommandLine has "Downloads"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```
<img width="1802" height="335" alt="image" src="https://github.com/user-attachments/assets/3760c951-d0bf-4c99-b971-06d656d9d658" />

---

### 4. System Reconnaissance

The first reconnaissance action attemepted via command:
```
"whoami.exe" /all
```

**Query used:**

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where ProcessCommandLine has_any ("whoami", "hostname", "systeminfo", "query user", "tasklist","Get-Process", "$env:USERNAME", "$env:COMPUTERNAME")
| sort by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```
<img width="1635" height="332" alt="image" src="https://github.com/user-attachments/assets/d73523cf-6dcd-4c14-a27f-65679912f11c" />
  
---

### 5. Sensitive Bonus-Related File Exposure

The first sensitive file likely targeted is **BonusMatrix_Draft_v3.xlsx**

**Query used:**

```kql
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where FileName contains "bonus"
| sort by TimeGenerated asc
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName

```
<img width="1835" height="270" alt="image" src="https://github.com/user-attachments/assets/248780b8-f34e-43d8-8b11-be1ab79bae94" />
  
---

### 6. Data Staging Activity Confirmation

There has been some file creation activity associated with archiving/exporting sensitive data. The ID of the initiating unique process was **2533274790396713.**

**Query used:**

```kql
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where ActionType == "FileCreated"
| where FileName endswith ".zip"
    or FileName endswith ".csv"
    or FileName endswith ".xlsx"
| sort by TimeGenerated asc
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessUniqueId

```
 <img width="1832" height="435" alt="image" src="https://github.com/user-attachments/assets/1a0f6e88-fe81-421b-aa11-58b7cec1501a" />
 
---

### 7. Outbbound Connectivity Test

There was a Powershell-driven outbound network connection test found at **2025-12-03T06:27:31.1857946Z**.

**Query Used:**

```kql
DeviceNetworkEvents
| where DeviceName == "sys1-dept"
| where InitiatingProcessCommandLine contains "powershell"
| project TimeGenerated, RemoteIP, RemoteUrl, InitiatingProcessCommandLine, DeviceName
| order by TimeGenerated asc
```
<img width="1292" height="485" alt="image" src="https://github.com/user-attachments/assets/15036851-fd02-4415-abba-17fd1a770018" />

---

### 8. Registry-Based Persisitence

A registry modification indicating an auto-start mechanism has been discovered using a user Run key:
```
HKEY_CURRENT_USER\S-1-5-21-805396643-3920266184-3816603331-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

**Query Used:**

```kql
DeviceRegistryEvents
| where DeviceName == "sys1-dept"
| where RegistryKey contains @"\Microsoft\Windows\CurrentVersion\Run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
| order by TimeGenerated asc

```
<img width="1825" height="470" alt="image" src="https://github.com/user-attachments/assets/56628fb7-b71e-4f91-a2eb-26a6e81b5193" />

---

### 9. Scheduled Task Persistence

A scheduled task was created to automate recurring execution via command line. The Task Name value is **BonusReviewAssist.**

**Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where ProcessCommandLine contains "schtasks"
| project TimeGenerated, InitiatingProcessCommandLine
| order by TimeGenerated asc

```

---

### 10. Secondary Employee Scorecard Access

A remote session device has been found to have accessed an employee-related scorecard. The user in question is **YE-HELPDESKTECH.**

**Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where FileName contains "Scorecard"
| project TimeGenerated, InitiatingProcessAccountName, DeviceName, FileName
| order by TimeGenerated asc

```

---

### 11. Bonus Matrix Activity

Another remote session device has been associated withg higher level related activities related to bonus payout related artifacts. The user found is **YE-HRPLANNER.**

**Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where FileName contains "Bonus"
| project TimeGenerated, DeviceName InitiatingProcessAccountName, FileName, InitiatingProcessCommandLine, RemoteIP
| order by TimeGenerated asc

```

---

### 12. Performance Review Access Validation 

Repeated behavior of performance review directory access has been found accrosss departments. One instance of access of a similar employee related file happened at **2025-12-03T07:25:15.6288106Z.**

**Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where ProcessCommandLine contains "review"
| project TimeGenerated, InitiatingProcessCommandLine, DeviceName
| order by TimeGenerated asc

```
<img width="1235" height="280" alt="image" src="https://github.com/user-attachments/assets/a785552a-c740-44b6-8065-019bb0f4d0ea" />

---

### 13. Approved/Final Bonus Artifact Access

Access to finalized year-end bonus file with sensitive-read classification occurred at **2025-12-03T07:25:39.1653621Z
.**

**Query Used:**

```kql
DeviceEvents
| where DeviceName == "sys1-dept"
| where ActionType contains "Sensitive"
| project TimeGenerated, ActionType, FileName
| order by TimeGenerated asc

```
<img width="865" height="205" alt="image" src="https://github.com/user-attachments/assets/7266970b-cd22-4ae3-ba87-4b3e151d043e" />

---

### 14. Candidate Archive Creation Location

A suspicious candiate-related archive was created via path:
```
C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip
```

**Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where FileName contains "candidate"
| project TimeGenerated, FolderPath, DeviceName
| order by TimeGenerated asc

```
<img width="1120" height="255" alt="image" src="https://github.com/user-attachments/assets/7f97dc0b-4b19-4bfa-8ee4-190d9566ac57" />

---

### 15.  Outbound Transfer Attempt Timestamp

An outbound transfer attempt for POST testing occured at **2025-12-03T07:26:28.5959592Z** after staging activity. 

**Query Used:**

```kql
DeviceNetworkEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated >= todatetime("2025-12-03T07:26:03.9765516Z")
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl
| order by TimeGenerated asc

```
<img width="1592" height="250" alt="image" src="https://github.com/user-attachments/assets/253fd002-9303-4683-9083-ffbfc3daa781" />

---

### 16. Local Log Clearing Attempt

A comnmand for local log clearing has been executed:
```
"wevtutil.exe" cl Microsoft-Windows-PowerShell/Operational
```

**Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where FileName =~ "wevtutil.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1277" height="200" alt="image" src="https://github.com/user-attachments/assets/f4c4c78f-8ef0-424f-a715-f684f0d5c76a" />

---

### 17. Secondary Endpoint Scope Confirmation

Another machine has been compromised based on similar telemtry patterns. The device name in question is **main1-srvr.**

**Query Used:**

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("bonus","review","scorecard")
| summarize FirstSeen=min(TimeGenerated) by DeviceName
| order by FirstSeen asc

```
<img width="1480" height="177" alt="image" src="https://github.com/user-attachments/assets/d34bf879-f8a1-4a10-b593-110bd694dadd" />

---

### 18. Approved Bonus Artifact Access on Second Endpoint

The approved bonus artifact has been accessed again on the second machine at **2025-12-04T03:11:58.6027696Z.**

**Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "main1-srvr"
| where ProcessCommandLine contains "Bonus"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine
| order by TimeGenerated asc

```

---

### 19. Employee Scorecard Access on Second Endpoint

Employee scorecard has been accessed again on the second machine by remote session device **YE-FINANCEREVIE.**

**Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "main1-srvr"
| where FileName contains "Scorecard"
| project TimeGenerated, FileName, InitiatingProcessAccountName, RemoteIP, RemoteURL
| order by TimeGenerated asc

```

---

### 20. Staging Directory Identification on Second Endpoint

A directory used for consolidation of internal reference materials and archived content was in via path:
```
C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip
```
**Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "main1-srvr"
| where FolderPath contains @"\InternalReferences\ArchiveBundles\"
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc

```
<img width="1805" height="395" alt="image" src="https://github.com/user-attachments/assets/d9faafbd-e358-4d20-a362-2e31cc734896" />

---

### 21. Staging Activity Timing on Second Endpoint

Staging activity occurred on the secondf endpoint at **2025-12-04T03:15:29.2597235Z.**

**Query Used:**

```kql
DeviceFileEvents
| where DeviceName == "main1-srvr"
| where FolderPath contains "ArchiveBundles"
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc

```
<img width="1782" height="370" alt="image" src="https://github.com/user-attachments/assets/65ff1f9e-5955-495d-8e81-0257e76fc7b4" />

---

### 22. Outbound Connection Remote IP (Final Phase)

The final outbound connection is associated with the remote IP of **54.83.21.156.**

**Query Used:**

```kql
DeviceNetworkEvents
| where DeviceName == "main1-srvr"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl
| order by TimeGenerated asc

```
<img width="1140" height="240" alt="image" src="https://github.com/user-attachments/assets/0d9ff6f3-96eb-4973-b893-69f4bf1f6577" />
