# OpenSearch SIEM Practice Lab — Walkthrough

**Lab:** `soc-practice-drills-01`  
**Date used in the exercises:** October 12, 2026  
**Platform:** OpenSearch Dashboards → Discover  
**Goal:** Practice DQL filtering, time-range selection, field inspection, sorting, and investigation pivots.

> **Note:** Verification tokens below are included only where they were visible in the supplied lab results. For drills whose results were not provided, retrieve the token from the matching event's `message` field.

---

## Before You Start

1. Open **OpenSearch Dashboards → Discover**.
2. Set the index pattern to `soc-practice-drills-01`.
3. Use the DQL search bar at the top to enter queries.
4. Click **Update** or press **Enter** to run a query.
5. Expand a result with the `>` arrow to inspect all fields.
6. To set an exact time range, open the time picker, select **Absolute**, enter the start and end, and click **Apply**.

### Absolute time range for October 12

- **Start:** `2026-10-12 00:00:00`
- **End:** `2026-10-12 23:59:59`

Use the specified time range for drills that target October 12 telemetry.

---

## Drill 1 — Absolute Time Range Filtering (Gateway Sync)

**Objective:** Isolate gateway network telemetry on the incident date.

### Steps

1. Set the absolute time range to October 12, 2026, from `00:00:00` through `23:59:59`.
2. Run this DQL query:

```text
event_category : "network" and hostname : "FW-GW01"
```

3. Find the event at **14:22:15**.
4. Expand the event and inspect `message`.
5. Record the token in the format `drill_01{...}`.

**Check:** Confirm the timestamp is `14:22:15`; do not use a different `FW-GW01` event by mistake.

**Token:** Not captured in the supplied results.

---

## Drill 2 — Practice Index & Baseline System Event

**Objective:** Verify the index pattern and inspect the baseline system audit event.

### Steps

1. Confirm the index pattern is `soc-practice-drills-01`.
2. Run:

```text
event_category : "system" and event_id : 100
```

3. Expand the matching document.
4. Read the `message` field and record `drill_02{...}`.

**Token:** Not captured in the supplied results.

---

## Drill 3 — Event Category Filter

**Objective:** Find authentication telemetry for `auditor_sec`.

### DQL

```text
event_category : "authentication" and username : "auditor_sec"
```

### Observed result

Two events matched. The relevant Kerberos authentication event showed:

- **Timestamp:** `2026-10-12 04:15:00`
- **Event category:** `authentication`
- **Event ID:** `4624`
- **Hostname:** `WIN-AD1`
- **Message:** `Security Kerberos ticket granted for auditor_sec. Verification: drill_03{fda7d65c}`
- **Token:** `drill_03{fda7d65c}`

**Tip:** There were two hits, so inspect the message field and use the Kerberos event containing the verification token.

---

## Drill 4 — Event ID Filter (Logon Failures)

**Objective:** Isolate failed logons for `finance_temp_admin`.

### DQL

```text
event_category : "authentication" and event_id : "4625" and username : "finance_temp_admin"
```

### Steps

1. Run the query.
2. Expand the matching event.
3. Inspect `message`.
4. Record the token in the format `drill_04{...}`.

**Token:** Not captured in the supplied results.

**Concept:** Windows Security Event ID `4625` represents a failed logon.

---

## Drill 5 — Add Investigation Columns

**Objective:** Add useful fields to the results table and find process ID `9999`.

### Steps

1. In **Available fields**, add:
   - `src_ip`
   - `username`
   - `process_id`
2. Run:

```text
process_id : 9999
```

3. Confirm the three columns appear in the table.
4. Expand the matching event and read `message`.
5. Record `drill_05{...}`.

**Token:** Not captured in the supplied results.

---

## Drill 6 — Chronological Event Sorting

**Objective:** Sort events from oldest to newest.

### Steps

1. Clear the DQL search bar.
2. Click the `@timestamp` column header to sort ascending (oldest first).
3. Inspect the first row.
4. Confirm it has `event_id: 6005`.
5. Expand it and read the token from `message`.

**Token:** Not captured in the supplied results.

---

## Drill 7 — Top Values Distribution

**Objective:** Identify a high-volume source IP and investigate a beacon event.

### Steps

1. Click the `src_ip` field in the left sidebar.
2. Inspect **Top 5 Values** and identify `10.10.99.77`.
3. Run:

```text
src_ip : "10.10.99.77" and message : *beacon*
```

4. Expand the matching event.
5. Read `message` and record `drill_07{...}`.

**Token:** Not captured in the supplied results.

---

## Drill 8 — Numeric Range Boundaries

**Objective:** Find a packet whose size is between 750 and 775 bytes, inclusive.

### DQL

```text
packet_size >= 750 and packet_size <= 775
```

### Observed result

The matching event in the supplied screenshot showed:

- **Timestamp:** `2026-10-12 07:18:00`
- **Event category:** `network`
- **Hostname:** `FW-GW01`
- **Packet size:** `762` bytes
- **Message:** `UDP transmission envelope matched boundary rules (762 bytes). Verification: drill_08{90dd1da9}`
- **Token:** `drill_08{90dd1da9}`

---

## Drill 9 — Compound Boolean OR Syntax

**Objective:** Search for either of two suspicious executable names.

### DQL

```text
process_name : ("mimikatz.exe" or "psexec.exe")
```

### Steps

1. Run the query.
2. Find the `mimikatz.exe` result.
3. Expand the event.
4. Inspect `message` and record `drill_09{...}`.

**Token:** Not captured in the supplied results.

---

## Drill 10 — Search & Pivot Workflow (Final Capstone)

**Objective:** Start from a security alert, pivot to endpoint process telemetry, and retrieve the official CTF flag.

### Step A — Find the alert

Run:

```text
message : *pivot*
```

The alert found in the supplied results was:

| Field | Value |
|---|---|
| Timestamp | `2026-10-12 09:05:00` |
| Event category | `authentication` |
| Event ID | `4625` (failed logon) |
| Hostname | `WIN-AD1` |
| Source IP | `10.10.10.201` |
| Username | `pivot_suspect_user` |
| Description | Initial pivot hint for `pivot_suspect_user` |
| Index | `soc-practice-drills-01` |

The alert message instructs the analyst to pivot to endpoint execution logs.

### Step B — Pivot to the suspect user

Clear the previous query and run:

```text
username : "pivot_suspect_user"
```

Locate the process-creation event where `process_name` is `cmd.exe`.

### Step C — Inspect the process event

The matching event showed:

| Field | Value |
|---|---|
| Timestamp | `2026-10-12 09:12:00` |
| Event category | `process_creation` |
| Event ID | `4688` |
| Hostname | `SRV-FILE-01` |
| Source IP | `10.10.10.201` |
| Username | `pivot_suspect_user` |
| Process name | `cmd.exe` |
| Process ID | `6844` |
| Event ID / document ID | `evt-proc-cmd-capstone-5381140653106709088` |

The `command_line`, `message`, `flag`, and `description` fields all contained the same official flag.

### Official flag

```text
CTF{TcQo4faCiXXQ34kYIlvp4AHt8}
```

If the lab's submission interface rejects this exact value, check that the validator's configured answer matches the event's `flag` field exactly, including capitalization and braces.

---

## Quick DQL Reference

| Task | DQL |
|---|---|
| Gateway network events | `event_category : "network" and hostname : "FW-GW01"` |
| Baseline system event | `event_category : "system" and event_id : 100` |
| Authentication for auditor | `event_category : "authentication" and username : "auditor_sec"` |
| Failed logons for finance account | `event_category : "authentication" and event_id : "4625" and username : "finance_temp_admin"` |
| Process ID 9999 | `process_id : 9999` |
| Beacon from source IP | `src_ip : "10.10.99.77" and message : *beacon*` |
| Packet-size range | `packet_size >= 750 and packet_size <= 775` |
| Suspicious executables | `process_name : ("mimikatz.exe" or "psexec.exe")` |
| Pivot alert | `message : *pivot*` |
| Pivot to suspect user | `username : "pivot_suspect_user"` |

---

## Investigation Tips

- **Time picker:** A correct query can return unexpected results if the time range excludes the event. Set absolute time boundaries when the exercise requires a specific incident date.
- **Inspect the full document:** Verification tokens and flags may be in `message`, `command_line`, or a dedicated `flag` field.
- **Multiple hits:** Read timestamps and event details instead of assuming the first result is the intended one.
- **Numeric fields:** Use numeric comparisons for fields such as `packet_size` and `process_id`.
- **DQL syntax:** Use the exact field names and values specified by the lab. If a query returns no results, confirm the index pattern and time range first.
- **Flag rejected:** Compare the submitted value with the event's `flag` field and the answer configured in the lab validator. Do not add quotes, spaces, or Markdown backticks when submitting.
