# CICSA Capstone Practice Lab 2 — SOC Investigation Walkthrough

> **Purpose:** Evidence-led walkthrough of 10 incident briefs using OpenSearch Discover and DQL.
>
> **Environment:** OpenSearch Dashboards → Discover  
> **Investigation date:** October 12, 2026  
> **Indexes:** `soc-incident-logs-01`, `soc-incident-logs-02`  
> **Time range:** `2026-10-12 00:00:00` to `2026-10-12 23:59:59`
>
> This guide records the evidence confirmed during the investigation. Where an event or command was not observed, it is explicitly marked as unconfirmed rather than guessed.

## Table of Contents

1. [Before You Start](#before-you-start)
2. [Investigation Workflow](#investigation-workflow)
3. [Incident 01 — Domain Controller Authentication Anomaly](#incident-01--domain-controller-authentication-anomaly)
4. [Incident 02 — Perimeter Gateway Traffic Spike](#incident-02--perimeter-gateway-traffic-spike)
5. [Incident 03 — Unauthorized Outbound Data Transfer](#incident-03--unauthorized-outbound-data-transfer)
6. [Incident 04 — IDS Port Scan](#incident-04--ids-port-scan)
7. [Incident 05 — Suspicious Execution and Defense Evasion](#incident-05--suspicious-execution-and-defense-evasion)
8. [Incident 06 — Unauthorized Service Creation](#incident-06--unauthorized-service-creation)
9. [Incident 07 — Target Account Lockout](#incident-07--target-account-lockout)
10. [Incident 08 — Recurring C2 Egress](#incident-08--recurring-c2-egress)
11. [Incident 09 — Security Audit Log Clearing](#incident-09--security-audit-log-clearing)
12. [Incident 10 — Phishing to Data Staging Chain](#incident-10--phishing-to-data-staging-chain)
13. [Consolidated Results](#consolidated-results)
14. [Analyst Notes and Limitations](#analyst-notes-and-limitations)

---

## Before You Start

1. Open **OpenSearch Dashboards → Discover**.
2. Select the data view/index containing the incident logs.
3. Set the absolute time range to **October 12, 2026, 00:00:00–23:59:59**.
4. Use the appropriate index:
   - Incidents 01–05: `soc-incident-logs-01`
   - Incidents 06–10: `soc-incident-logs-02`
5. Run one DQL query at a time.
6. Expand matching documents and inspect fields such as `@timestamp`, `hostname`, `username`, `event_category`, `event_id`, `process_name`, `parent_process_name`, `command_line`, `src_ip`, `dest_ip`, `message`, `description`, `token`, and `flag`.

> **Troubleshooting:** If a field-specific query returns no results, search by hostname first and inspect the actual field names in the returned documents. Field names can differ by mapping.

## Investigation Workflow

For every incident:

1. **Scope:** Select the correct index and time range.
2. **Filter:** Search by hostname and a distinctive event field.
3. **Validate:** Check the timestamp, host, user, event ID/category, and message.
4. **Correlate:** Search for related authentication, process, network, or file events.
5. **Record:** Copy indicators, tokens, flags, and document IDs exactly.
6. **Qualify:** Separate confirmed evidence from hypotheses. One event may suggest a technique without proving the complete attack chain.

---

## Incident 01 — Domain Controller Authentication Anomaly

**Index:** `soc-incident-logs-01` · **Host:** `WIN-AD2`

### Step 1 — Search for failed logons

```text
hostname: "WIN-AD2" AND event_id: 4625
```

If this does not match the field mapping, start with:

```text
hostname: "WIN-AD2"
```

### Step 2 — Inspect the event

| Field | Confirmed value |
|---|---|
| Timestamp | `2026-10-12 04:14:22` |
| Hostname | `WIN-AD2` |
| Username | `finance_temp_admin` |
| Event ID | `4625` |
| Source IP | `198.51.100.45` |
| Destination IP | `10.10.1.15` |
| Destination port | `3389` |
| Process | `lsass.exe` |
| Message | Bad credentials / authentication anomaly |
| Indicator | `auth_attempt{adeffcfa1deb}` |

### Step 3 — Interpret

Windows Event ID `4625` indicates a failed logon. The lab description characterizes the pattern as password spraying from one untrusted source. The record confirms a failed authentication; confirming the full spray pattern requires related failures or alert evidence.

**Indicator:**

```text
auth_attempt{adeffcfa1deb}
```

---

## Incident 02 — Perimeter Gateway Traffic Spike

**Index:** `soc-incident-logs-01` · **Host:** `FW-GW01`

### Step 1 — Search

```text
hostname: "FW-GW01"
```

Open the anomaly event and inspect its network fields.

### Step 2 — Inspect the event

| Field | Confirmed value |
|---|---|
| Timestamp | `2026-10-12 05:15:00` |
| Hostname | `FW-GW01` |
| Source IP | `203.0.113.88` |
| Destination IP | `10.10.1.1` |
| Protocol / port | UDP / `53` |
| Packet size | `1420` |
| Baseline | `48,200 pps` |
| Description | Perimeter gateway state-exhaustion anomaly |
| Indicator | `traffic_anomaly{30217d302aa0}` |

### Step 3 — Interpret

The event describes a traffic spike and gateway state-exhaustion anomaly. UDP/53 is commonly associated with DNS, but the record alone does not establish the exact traffic purpose or prove a successful denial of service.

**Indicator:**

```text
traffic_anomaly{30217d302aa0}
```

---

## Incident 03 — Unauthorized Outbound Data Transfer

**Index:** `soc-incident-logs-01` · **Host:** `LINUX-BACKUP01`

### Step 1 — Search

```text
hostname: "LINUX-BACKUP01"
```

If supported by the mapping, narrow to the transfer category:

```text
hostname: "LINUX-BACKUP01" AND event_category: "data_transfer"
```

### Step 2 — Inspect the event

| Field | Confirmed value |
|---|---|
| Timestamp | `2026-10-12 07:42:10` |
| Hostname | `LINUX-BACKUP01` |
| Source IP | `10.10.5.20` |
| Destination IP | `194.26.29.112` |
| Username | `backupsvc` |
| Process | `scp` |
| Event ID | `FILE_TRANSFER` |
| Transfer volume | `485 MB` |
| Packet size | `1480` |
| Description | Anomalous egress volume outside scheduled backup maintenance |
| Indicator | `data_volume_shift{f8b2023ed0c4}` |

### Step 3 — Interpret

The log records an `scp` transfer of 485 MB to an external-looking destination outside the expected maintenance window. Verify destination ownership, backup schedules, and authorization before concluding that data theft occurred.

**Indicator:**

```text
data_volume_shift{f8b2023ed0c4}
```

---

## Incident 04 — IDS Port Scan

**Index:** `soc-incident-logs-01` · **Host:** `IDS01`

### Step 1 — Search

```text
hostname: "IDS01"
```

If supported by the mapping:

```text
hostname: "IDS01" AND event_id: "IDS-PORTSCAN"
```

### Step 2 — Inspect the event

| Field | Confirmed value |
|---|---|
| Timestamp | `2026-10-12 06:04:27` |
| Hostname | `IDS01` |
| Event ID | `IDS-PORTSCAN` |
| Category | `network_scan` |
| Source IP | `185.220.101.5` |
| Destination IP | `10.10.1.15` |
| Protocol / port | TCP / `3389` |
| Description | Suricata automated port-scan pattern alert |
| Indicator | `portscan_trace{5e8484246edf}` |

### Step 3 — Interpret

The IDS generated an alert for a port-scan pattern targeting TCP/3389. Correlate surrounding network events and firewall telemetry to determine scope and whether any connection succeeded.

**Indicator:**

```text
portscan_trace{5e8484246edf}
```

---

## Incident 05 — Suspicious Execution and Defense Evasion

**Index:** `soc-incident-logs-01` · **Host:** `WIN-ENDP3`

### Step 1 — Search for process creation

```text
hostname: "WIN-ENDP3" AND event_id: 4688
```

If no result appears:

```text
hostname: "WIN-ENDP3"
```

### Step 2 — Inspect the event

| Field | Confirmed value |
|---|---|
| Timestamp | `2026-10-12 08:20:15` |
| Hostname | `WIN-ENDP3` |
| Username | `user12` |
| Event ID | `4688` |
| Category | `process_creation` |
| Process | `svhost32.exe` |
| Launcher / parent | `powershell.exe` |
| Arguments / flags | `-ExecutionPolicy Bypass`, `-WindowStyle Hidden` |
| Indicator | `execution_chain[5014e1bf35b5]` |

### Step 3 — Interpret

The executable name `svhost32.exe`, PowerShell launch context, execution-policy bypass, and hidden window are suspicious. These details alone do not prove the binary is malicious. Validate the file path, signature, hash, parent process, and nearby endpoint telemetry.

**Indicator:**

```text
execution_chain[5014e1bf35b5]
```

---

## Incident 06 — Unauthorized Service Creation

**Index:** `soc-incident-logs-02` · **Host:** `HOST-07`

### Step 1 — Search

```text
hostname: "HOST-07"
```

If supported:

```text
hostname: "HOST-07" AND event_id: 7045
```

### Step 2 — Inspect the event

| Field | Confirmed value |
|---|---|
| Timestamp | `2026-10-12 09:14:45` |
| Hostname | `HOST-07` |
| Username | `local_admin` |
| Event ID | `7045` |
| Category | `process_execution` |
| Service | `NetDriverFilter32` |
| Binary path | `C:\Windows\Temp\osniedge.exe` |
| Process | `services.exe` |
| Description | Persistence mechanism in an unapproved binary directory |
| Indicator | `exec_vector{aa2138c3c28c}` |

### Step 3 — Interpret

A service configured to run a binary from `C:\Windows\Temp\` is suspicious and may indicate persistence. Verify the service configuration, file signature/hash, creation time, and whether the service was authorized.

**Indicator:**

```text
exec_vector{aa2138c3c28c}
```

---

## Incident 07 — Target Account Lockout

**Index:** `soc-incident-logs-02` · **Host:** `HOST-11`

### Step 1 — Search for account lockout

```text
hostname: "HOST-11" AND event_id: 4740
```

If this does not match the index mapping:

```text
hostname: "HOST-11"
```

### Step 2 — Inspect the event

| Field | Confirmed value |
|---|---|
| Timestamp | `2026-10-12 10:05:10` |
| Hostname | `HOST-11` |
| Username | `helen.carter` |
| Event ID | `4740` |
| Category | `password_change` |
| Source IP | `10.0.3.11` |
| Description | Brute-force velocity exceeded threshold |
| Indicator | `cred_cycle{68180313e5b9}` |

### Step 3 — Interpret

The lab describes a lockout associated with a high rate of failed authentication attempts. Correlate authentication failures by username and source to distinguish brute force from a stale password, misconfigured service, or legitimate user error.

**Indicator:**

```text
cred_cycle{68180313e5b9}
```

---

## Incident 08 — Recurring C2 Egress

**Index:** `soc-incident-logs-02` · **Host:** `HOST-14`

### Step 1 — Search for network events

```text
hostname: "HOST-14" AND event_id: 5156
```

If no results appear:

```text
hostname: "HOST-14"
```

### Step 2 — Inspect the event

| Field | Confirmed value |
|---|---|
| Timestamp | `2026-10-12 11:00:01` |
| Hostname | `HOST-14` |
| Username | `user14` |
| Event ID | `5156` |
| Category | `network_transfer` |
| Source IP | `10.0.2.14` |
| Destination IP | `194.135.25.99` |
| Domain | `c2.darknode-defense.com` |
| Protocol / port | TCP / `443` |
| Description | Anomalous periodic egress beacon |
| Indicator | `cipher_mark{c1cb00786ddb}` |

### Step 3 — Interpret

The event describes periodic outbound traffic to a domain labeled as C2 in the lab. Validate periodicity and domain context with DNS, proxy, firewall, and endpoint telemetry. TCP/443 alone does not prove malicious activity.

**Indicator:**

```text
cipher_mark{c1cb00786ddb}
```

---

## Incident 09 — Security Audit Log Clearing

**Index:** `soc-incident-logs-02` · **Host:** `HOST-09`

### Step 1 — Search the host

```text
hostname: "HOST-09"
```

### Step 2 — Find the audit-clearing event

```text
hostname: "HOST-09" AND event_id: 1102
```

This query returned the event below:

| Field | Confirmed value |
|---|---|
| Timestamp | `2026-10-12 11:18:30` |
| Hostname | `HOST-09` |
| Username | `intern_dev` |
| Event ID | `1102` |
| Category | `file_share` |
| Process | `wevtutil.exe` |
| VLAN | `VLAN50` |
| Message | The audit log was cleared by an administrative utility |
| Description | Anti-forensics defense evasion behavior detected |
| Document ID | `s2-q9-wipe-11079872917447228793` |
| Indicator | `tamper_event{d7e77df71f81}` |

### Step 3 — Try to find the command line

```text
hostname: "HOST-09" AND process_name: "wevtutil.exe"
```

If this returns only the same event, try:

```text
hostname: "HOST-09" AND event_id: 4688
```

Then inspect all host events:

```text
hostname: "HOST-09"
```

Look for fields such as `command_line`, `process_path`, and `parent_process_name` if present.

### Step 4 — Interpret

The event confirms audit-log clearing and associates the activity with the `intern_dev` account and `wevtutil.exe`. The exact command line was **not confirmed** in the records examined. A logged username does not by itself prove which person operated the account.

**Indicator:**

```text
tamper_event{d7e77df71f81}
```

---

## Incident 10 — Phishing to Data Staging Chain

**Index:** `soc-incident-logs-02` · **Host:** `HOST-04`

### Step 1 — Search host events

```text
hostname: "HOST-04"
```

Use the full-day time range and sort by `@timestamp` ascending to inspect the timeline.

### Step 2 — Inspect the process-creation event

The confirmed event at `2026-10-12 11:51:30` contained:

| Field | Confirmed value |
|---|---|
| Hostname | `HOST-04` |
| Username | `sarah.jenkins` |
| Event ID | `4688` |
| Category | `process_execution` |
| Process | `cmd.exe` |
| Parent process | `excel.exe` |
| Process ID | `7824` |
| Description | Attacker exfiltration compression execution spawned by weaponized macro |
| Flag | `CTF{8y5yqtiFTrjhzxd5ocyHF3Y9O}` |
| Document ID | `s2-q10-flag-capstone-11079872917447228793` |

### Step 3 — Inspect the command line

```powershell
cmd.exe /c powershell.exe -enc -Command Compress-Archive C:\Confidential\* -Key CTF{8y5yqtiFTrjhzxd5ocyHF3Y9O}
```

What stands out:

- `excel.exe` is the parent process.
- `cmd.exe` launches PowerShell.
- `-enc` is commonly used as a PowerShell encoded-command option.
- `Compress-Archive` is intended to package files into an archive.
- `C:\Confidential\*` is the target path in the logged command.

The lab event labels this as exfiltration staging. This event suggests data preparation, but it does not prove that the data was successfully transmitted outside the network.

### Step 4 — Record the flag

```text
CTF{8y5yqtiFTrjhzxd5ocyHF3Y9O}
```

### Step 5 — Correlate the timeline

Search all `HOST-04` events and inspect activity before `11:51:30` for related email-security, document, or process events. A standard marketing email event at `11:59:22` occurred **after** the process event and does not establish the phishing origin without corroborating evidence.

---

## Consolidated Results

| # | Incident | Host | Confirmed indicator / flag |
|---:|---|---|---|
| 01 | Domain controller authentication anomaly | `WIN-AD2` | `auth_attempt{adeffcfa1deb}` |
| 02 | Perimeter gateway traffic spike | `FW-GW01` | `traffic_anomaly{30217d302aa0}` |
| 03 | Unauthorized outbound data transfer | `LINUX-BACKUP01` | `data_volume_shift{f8b2023ed0c4}` |
| 04 | IDS port scan | `IDS01` | `portscan_trace{5e8484246edf}` |
| 05 | Suspicious execution / defense evasion | `WIN-ENDP3` | `execution_chain[5014e1bf35b5]` |
| 06 | Unauthorized service creation | `HOST-07` | `exec_vector{aa2138c3c28c}` |
| 07 | Target account lockout | `HOST-11` | `cred_cycle{68180313e5b9}` |
| 08 | Recurring C2 egress | `HOST-14` | `cipher_mark{c1cb00786ddb}` |
| 09 | Security audit log clearing | `HOST-09` | `tamper_event{d7e77df71f81}` |
| 10 | Phishing to data staging chain | `HOST-04` | `CTF{8y5yqtiFTrjhzxd5ocyHF3Y9O}` |

## Analyst Notes and Limitations

- Use the field names actually present in the index mapping. A field-specific DQL query may return no results if the field name or type differs.
- Treat incident descriptions as the lab's interpretation; distinguish them from raw event fields.
- A suspicious event does not always prove a complete attack chain. Correlate nearby logs before asserting initial access, persistence, lateral movement, or successful exfiltration.
- Incident 09: audit-log clearing was confirmed, but the exact command line and human operator were not established from the records shared.
- Incident 10: the process event and flag were confirmed. The standard marketing email at `11:59:22` occurred after the process event and does not establish the phishing origin.
- Preserve timestamps, hostnames, usernames, document IDs, indicators, and flags exactly as displayed in the lab.
