# Sentinel Guard — Technical Project Report
**Prepared for:** Team Member (returning from absence)
**Project:** Sentinel Guard — Endpoint Security Monitoring System
**Codebase Location:** `C:\Users\senat\PycharmProjects\Sentinel\`

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture and File Structure](#2-architecture-and-file-structure)
3. [The Communication Layer](#3-the-communication-layer)
4. [The Agent](#4-the-agent)
5. [The Controller](#5-the-controller)
6. [The Baseline System](#6-the-baseline-system)
7. [The Monitoring Engines](#7-the-monitoring-engines)
8. [The ML Detection System — Before and After](#8-the-ml-detection-system--before-and-after)
9. [The Alert System](#9-the-alert-system)
10. [Configuration System](#10-configuration-system)
11. [Response Capabilities](#11-response-capabilities)
12. [Data Flow — End to End](#12-data-flow--end-to-end)
13. [Project Folder Structure](#13-project-folder-structure)

---

## 1. Project Overview

Sentinel Guard is a host-based intrusion detection system (HIDS) built in Python. It runs as two separate programs that communicate over a TCP network connection:

- **The Agent** (`sentinel_agent.py`) — runs on the machine being monitored. It collects system data, runs detection logic, and sends alerts back to the operator.
- **The Controller** (`sentinel_controller.py`) — runs on the operator's machine. It receives alerts, displays them, and allows the operator to issue response commands (kill processes, block IPs, quarantine files, etc.).

The system monitors three threat surfaces:
1. **Processes** — detects suspicious executables running on the machine
2. **Network connections** — detects suspicious outbound connections
3. **File Integrity** — detects when sensitive files are created, modified, or deleted

Detection started as pure rule-based logic and was later significantly improved by integrating ML models (Isolation Forests) that learn what "normal" looks like on a specific machine and flag deviations from that baseline.

---

## 2. Architecture and File Structure

The project is organised into the following directories:

```
Sentinel/
├── sentinel_agent.py         — Agent entry point (run on monitored machine)
├── sentinel_controller.py    — Controller entry point (run by operator)
├── agent_config.json         — Agent configuration (auto-created on first run)
├── sentinel_baseline.json    — Saved baseline snapshot (created by BASELINE_CREATE)
│
├── core/                     — Shared utilities used by both agent and controller
│   ├── sentinel_alerts.py    — Alert schema builders (make_process_alert, etc.)
│   ├── sentinel_baseline.py  — Baseline collection and persistence
│   ├── sentinel_config.py    — Config loading, saving, and defaults
│   ├── sentinel_protocol.py  — TCP message framing (length-prefixed JSON)
│   └── sentinel_sysinfo.py   — System information collector
│
├── monitors/                 — The three detection engines
│   ├── sentinel_process_monitor.py  — Process anomaly detection
│   ├── sentinel_network_monitor.py  — Network anomaly detection
│   └── sentinel_fim_monitor.py      — File integrity monitoring
│
├── training/                 — ML model training scripts
│   ├── train_process_model.py       — Trains the process Isolation Forest
│   └── train_network_model.py       — Trains the network Isolation Forest
│
├── tests/
│   ├── test_network_model.py        — Two-layer network detection test suite
│   └── test_sock.py                 — Scratch/archived code
│
└── models/
    ├── process_model.pkl     — Trained process Isolation Forest (generated)
    └── network_model.pkl     — Trained network Isolation Forest (generated)
```

---

## 3. The Communication Layer

**File:** `core/sentinel_protocol.py`

The agent and controller talk to each other over a TCP socket. The fundamental problem with raw TCP is that it is a *stream* — if you send two messages back-to-back, the receiver may read both at once, or half of each. To solve this, every message is framed with a 4-byte length header.

### How a message is sent (`send_message`, line 56)

1. The Python dict is serialised to a compact JSON string using `json.dumps`.
2. The string is encoded to UTF-8 bytes.
3. The byte length of the payload is packed into 4 bytes (`struct.pack('>I', length)`) using big-endian unsigned int format.
4. Header and payload are sent together via `sock.sendall()`.

### How a message is received (`recv_message`, line 88)

1. Read exactly 4 bytes — the length header — using `_recv_exact()`.
2. Unpack those 4 bytes to get `N`, the number of bytes in the payload.
3. Read exactly `N` more bytes.
4. Decode from UTF-8 and parse the JSON back into a Python dict.

The `_recv_exact()` helper (line 28) loops on `sock.recv()` until it has accumulated the exact number of bytes requested — this handles TCP's tendency to deliver data in fragments.

A 10 MB cap (`MAX_MESSAGE_SIZE`) prevents memory exhaustion from malformed or malicious messages.

This protocol is used universally: the agent's hello message, all commands from the controller, all command results from the agent, and all alerts are all sent using `send_message` / `recv_message`.

---

## 4. The Agent

**File:** `sentinel_agent.py`

The agent is the heart of the system. It is a long-running process that runs on the machine being monitored.

### Startup sequence (`main()`, line 1900)

When the agent starts:
1. `load_or_create_config()` — loads `agent_config.json`, or creates it with defaults if missing.
2. `load_baseline()` — loads `sentinel_baseline.json` from disk into the global `CURRENT_BASELINE` variable. If no baseline exists yet, monitoring still runs in fallback mode.
3. `load_network_model()` / `load_process_model()` — loads the trained Isolation Forest models from `models/network_model.pkl` and `models/process_model.pkl`. If these files do not exist, the globals `NETWORK_MODEL` and `PROCESS_MODEL` remain `None`, and detection falls back to rule-based logic automatically.
4. `apply_fim_auditing_from_config()` — configures Windows file auditing (via `auditpol`) for paths listed in `cfg["fim_paths"]` so that file changes generate events in the Windows Security log.
5. `run_agent_forever()` is called, which loops forever reconnecting to the controller.

### Connection session (`_run_single_session()`, line 1710)

Each time the agent successfully connects to the controller:
1. It opens a TCP socket to `cfg["controller_host"]` on `cfg["controller_port"]` (default 9000).
2. It sends a `hello` message containing its `agent_id` and `display_name`.
3. It enters the **main receive loop**, which runs two tasks on every iteration:

**Monitoring ticks** — every `monitor_interval_seconds` (default 30 seconds):
- `run_process_monitor_tick()` — scans all running processes and sends any alerts
- `run_network_monitor_tick()` — scans all current TCP/UDP connections and sends alerts
- `run_fim_monitor_tick()` — checks each file in `fim_paths` for changes and sends alerts

**Command handling** — `recv_message(sock, timeout=5)` waits up to 5 seconds for a command from the controller. If a command arrives, it is dispatched to `handle_command()`.

If the connection drops, `_run_single_session()` returns. The outer `run_agent_forever()` loop then waits `reconnect_interval_seconds` before trying again.

### Cooldown logic

Each monitoring tick could potentially generate the same alert repeatedly. To prevent spam, each monitor uses a dictionary mapping a stable "dedup key" to the timestamp of the last alert sent:
- **Process monitor:** `LAST_PROCESS_ALERT_TIMES` — key is `name|exe|username`, cooldown is 300 seconds
- **Network monitor:** `LAST_NETWORK_ALERT_TIMES` — key is `processname|exe|user|remoteip|remoteport`, cooldown is 300 seconds
- **FIM monitor:** `LAST_FIM_ALERT_TIMES` + `LAST_FIM_OBSERVED_STATE` — cooldown is 30 seconds. FIM additionally uses *edge-trigger suppression*: it tracks the actual SHA-256 hash of the "after" state so that if a file stays modified, the alert fires only once and not again until the state changes further.

### Command handlers (`handle_command()`, line 155)

The agent handles the following commands from the controller:

| Command | What the agent does |
|---|---|
| `PING` | Responds with `pong` |
| `SYSINFO` | Calls `get_system_info()` and sends the result |
| `BASELINE_CREATE` | Runs `collect_full_baseline()`, saves to disk, sends a summary |
| `BASELINE_GET` | Sends a summary of the current in-memory baseline |
| `CONFIG_GET` | Sends the full current config dict |
| `CONFIG_UPDATE` | Updates FIM paths, feature toggles, or CPU/RAM thresholds in the live config |
| `PROC_SCAN` | Runs a one-shot process scan and returns all current alerts |
| `KILL_PROCESS` | Calls `psutil.Process(pid).terminate()` then `.kill()` if needed |
| `WHITELIST_PROCESS` | Adds a process entry to `cfg["process_whitelist"]` |
| `BLOCK_IP` | Adds Windows Firewall rules blocking inbound and outbound to an IP |
| `UNBLOCK_IP` | Removes those firewall rules |
| `GET_BLOCKED_IPS` | Returns the list of currently blocked IPs |
| `ADD_IP_WHITELIST` | Adds an IP to the network monitor's allow-list |
| `REMOVE_IP_WHITELIST` | Removes an IP from the allow-list |
| `CLEAR_IP_WHITELIST` | Clears the entire network allow-list |
| `FIM_UPDATE_BASELINE_ITEM` | Accepts a FIM change by recomputing and updating the baseline for one file path |
| `FIM_LOCKDOWN_FILE` | Uses `takeown` + `icacls` to restrict file access to SYSTEM and Administrators only |
| `FIM_QUARANTINE_FILE` | Moves a suspicious file to the quarantine directory and locks it down |

### File quarantine (`quarantine_file()`, line 96)

When asked to quarantine a file, the agent:
1. Creates `cfg["fim_quarantine_dir"]` (default `C:\ProgramData\Sentinel\quarantine`) if it does not exist.
2. Moves the file there with a timestamped name (e.g. `hosts.20250408_142033.quarantine`).
3. Immediately calls `lockdown_file_admins_only()` to strip all permissions except SYSTEM and Administrators, using `takeown` and `icacls`.

---

## 5. The Controller

**File:** `sentinel_controller.py`

The controller is the operator's interface. It:
- Starts a TCP server on port 9000 that listens for agents
- Accepts multiple agent connections simultaneously in a background thread (`_accept_loop()`, line 232)
- Provides a CLI for the operator to issue commands, view alerts, and trigger responses
- Integrates with the **AbuseIPDB** API (`abuseipdb_check_ip()`, line 40) to look up the crowd-sourced abuse reputation of suspicious IPs flagged by the network monitor
- Integrates with a **Groq LLM** (configurable via `LLM_API_URL` / `LLM_API_KEY` environment variables) to automatically triage process alerts — benign alerts are hidden from the main list by default to reduce analyst fatigue

### Agent connection lifecycle (`_accept_loop()`, line 232)

The accept loop runs in a daemon background thread:
1. Blocks on `self._server_sock.accept()` waiting for a new TCP connection.
2. Reads the `hello` message from the connecting agent.
3. Extracts `agent_id` and `display_name`.
4. If an agent with the same `agent_id` is already in `self.agents` (a reconnect), the old socket is closed and replaced — preventing zombie entries.
5. The new agent is wrapped in an `AgentConnection` dataclass and appended to `self.agents`.

### Sending commands

Commands are sent as JSON dicts with keys `type: "command"`, `command`, `command_id`, and optionally `params`. The `command_id` is an incrementing counter from `next_command_id()` used to match responses to their requests. After sending, the controller calls `recv_message(agent.sock, timeout=N)` and waits for the matching `command_result`.

---

## 6. The Baseline System

**File:** `core/sentinel_baseline.py`

The baseline is a snapshot of the machine's "normal" state taken at a moment when the machine is known to be clean. Everything the monitors do is relative to this snapshot.

### What a baseline contains

When `collect_full_baseline(cfg)` is called (triggered by the controller sending `BASELINE_CREATE`), it records:

- **`sysinfo`** — hostname, OS, hardware info
- **`resources`** — CPU and RAM usage sampled over the baseline window: average, max, min, standard deviation
- **`processes`** — every running process with: name, PID, exe path, username, cmdline, parent name, parent PID, CPU usage
- **`network`** — all current TCP/UDP connections (remote IP, port, process info) and all currently open listening ports
- **`files`** — the state of each file listed in `cfg["fim_paths"]`: existence, size in bytes, last-modified time, SHA-256 hash

The baseline is saved to `sentinel_baseline.json` in the project root. `BASELINE_FILE = Path(__file__).parent.parent / "sentinel_baseline.json"` (line 35 of `core/sentinel_baseline.py`). The agent loads it from disk at startup and holds it in memory in `CURRENT_BASELINE`.

### Why the baseline matters

- The process ML model is trained directly on the process list from the baseline.
- The network ML model is trained on the connection list from the baseline.
- The FIM monitor compares live file state directly to baseline file records.
- CPU/RAM resource monitors use baseline averages as the "normal" reference point for threshold calculations.

---

## 7. The Monitoring Engines

### 7.1 Process Monitor

**File:** `monitors/sentinel_process_monitor.py`

The process monitor runs on every monitoring tick. It calls `psutil.process_iter()` to get all running processes and evaluates each one.

#### Process info collection (`_build_process_info()`, line 126)

Uses psutil's `oneshot()` context manager so all fields (name, PID, exe path, username, cmdline, parent name, CPU usage) are fetched in a single OS system call rather than separate calls per field. Returns `None` if the process has already exited or access is denied — this is normal and handled gracefully.

#### Whitelist check (line 239)

Before any detection logic runs, processes matching an entry in `cfg["process_whitelist"]` (matched on name + exe + username) are skipped entirely — no ML, no hard rules.

#### Detection layers

See Section 8 for the full ML explanation. In summary:
- **Layer 1 (Hard rules):** exe path contains `\temp\`, `\tmp\`, `\downloads\`, or `\desktop\` → alert immediately. CPU above threshold → alert immediately.
- **Layer 2A (ML model):** if no hard rule fired and a trained model exists, score with Isolation Forest.
- **Layer 2B (Fallback):** if no model exists, check whether the process name+exe was in the baseline.

#### Dedup key

Each alert gets `dedup_key = f'{name}|{exe}|{user}'` (line 356) so the agent's cooldown logic can suppress re-alerting the same process on every tick.

---

### 7.2 Network Monitor

**File:** `monitors/sentinel_network_monitor.py`

The network monitor calls `psutil.net_connections(kind='inet')` to enumerate all current TCP and UDP sockets with remote addresses.

#### Filtering (lines 271–296)

Before evaluation, connections are skipped if:
- They have no remote address (listening sockets)
- The remote IP is loopback (`127.0.0.1` or `::1`)
- The remote IP is in `cfg["network_ip_whitelist"]`
- The connection has no PID

#### Process resolution (`_proc_info_for_pid()`, line 155)

`net_connections()` only returns PIDs. The monitor resolves each PID to a name, exe path, and username using `psutil.Process(pid)` so the information can be included in the alert and fed to the ML feature extractor.

#### DNS enrichment (`_reverse_dns_lookup()`, line 51)

For public IPs, the monitor attempts a reverse DNS lookup (PTR record) to convert the raw IP into a human-readable hostname (e.g. `lb-142.googleusercontent.com`). Results are cached in `DNS_CACHE` for the entire agent session lifetime. The cache is trimmed to 2000 entries by `_dns_cache_housekeep()` (line 90) to prevent unbounded memory growth in long-running sessions.

#### Detection layers

- **Layer 1 (Hard rules):** port in `SUSPICIOUS_PORTS` (4444, 1337, 31337, 9001, 6666, 6667, 5555, 1234) → alert. Exe from a Temp folder connecting to a public IP → alert.
- **System service exemption (line 338):** `svchost.exe` and other services in `SYSTEM_SERVICES` on well-known ports (80, 443, 22, etc.) are exempted from ML scoring entirely because the small training set cannot reliably distinguish their patterns from anomalies.
- **Layer 2A (ML model):** if no hard rule fired and the connection is not exempt, the Isolation Forest scores it.
- **Layer 2B (Fallback):** if no model exists, checks whether the remote IP was seen in the baseline connections list.

---

### 7.3 File Integrity Monitor (FIM)

**File:** `monitors/sentinel_fim_monitor.py`

The FIM monitors a specific list of exact file paths from `cfg["fim_paths"]`. It does not scan directories — only the exact files listed.

#### How it works (`detect_fim_changes()`, line 186)

For each path:
1. Build a `before` dict from the baseline record (size, mtime, SHA-256 hash).
2. Build an `after` dict by reading the file's current state (`_get_current_file_state()`, line 126), which always computes a fresh SHA-256 hash.
3. Compare using `_event_type_for_change()` (line 154):
   - `CREATED` — not in baseline but exists now
   - `DELETED` — in baseline but missing now
   - `MODIFIED` — both exist but SHA-256 hashes differ (falls back to size/mtime comparison if hashes are unavailable)
   - `None` — no change detected; skip this path
4. If a change is detected, call `make_fim_alert()` to build the standardised alert dict.

#### Attribution (`get_windows_fim_attribution()` in `sentinel_agent.py`, line 1313)

When a FIM alert fires, the agent attempts to identify *who* changed the file by running a PowerShell script that queries the Windows Security event log for Event ID 4663 (object access auditing). The script fetches the most recent matching events for the file path and scores each event:
- +50 points if the access mask indicates a write-like operation (WriteData, AppendData, DELETE)
- +5 for read-like access (lower confidence but still possible)
- -20 if the actor is SYSTEM (usually OS background activity)
- -15 if the process is a known noisy watcher (OneDrive, SearchIndexer, Explorer)
- +5 each for having a user name and process name

The highest-scoring event is returned as the attribution, with confidence `"high"` for write-like events and `"low"` for read-like.

#### Accepting changes (`FIM_UPDATE_BASELINE_ITEM`)

When an operator decides a FIM alert is legitimate (a planned software update, for example), they send `FIM_UPDATE_BASELINE_ITEM`. The agent recomputes the current file state using `collect_sensitive_files_baseline()`, updates that one entry in `CURRENT_BASELINE["files"]["items"]`, and saves the updated baseline to disk (lines 1143–1207 of `sentinel_agent.py`). Future monitoring now treats the new file state as normal.

---

## 8. The ML Detection System — Before and After

### 8.1 How Detection Worked Before ML

**Process detection (before):** Every process whose `name|exe` combination was not present in the baseline process list triggered an alert. On a real Windows machine this is catastrophically noisy — background services start and stop, app updaters launch, browser tabs spawn helper processes, and Python scripts create short-lived interpreter instances. Hundreds of false positive alerts per monitoring cycle were common, making the system effectively unusable.

**Network detection (before):** Every outbound connection to a remote IP that was not seen in the baseline triggered an alert. Cloud services (Google, Microsoft, Cloudflare CDNs) rotate through hundreds of different IP addresses, so every legitimate browser request to a new CDN IP generated an alert. The monitor was practically useless at this stage.

### 8.2 The Isolation Forest Algorithm

**Training files:** `training/train_network_model.py`, `training/train_process_model.py`

An **Isolation Forest** is an unsupervised anomaly detection algorithm from scikit-learn. "Unsupervised" means it requires no labelled data — you do not manually mark anything as "malicious". You feed it examples of normal behaviour and it learns the shape of that cluster.

#### How it works internally

The algorithm builds many random decision trees. For each data point it repeatedly picks a random feature and a random split value within the observed range, recursively partitioning the data until the point is isolated in its own leaf node.

The fundamental insight:

> **Normal points** are in a dense cluster — they take **many** random splits to isolate from their neighbours.
> **Anomalous points** are sparse, far from the cluster — they are isolated in **very few** splits.

The model computes an anomaly score based on the average path length across all trees:
- `score > 0` = comfortably inside the normal cluster (normal)
- `score ≈ 0` = on the boundary
- `score < 0` = outside the normal cluster (anomalous)
- `score << 0` = highly anomalous, far from anything seen during training

Two outputs are used in the monitors:
- `model.predict(X)` → `+1` (normal) or `-1` (anomaly)
- `model.decision_function(X)` → the continuous float score

#### Training parameters

The **process model** (`train_process_model.py`, line 491):
- `n_estimators=200` — 200 trees for stable scoring; the process feature space (19 features) is larger and more varied than the network space
- `contamination=0.05` — assumes ~5% of baseline processes may already be borderline unusual
- `random_state=42` — fixed random seed for fully reproducible results

The **network model** (`train_network_model.py`, line 449):
- `n_estimators=100` — 100 trees; the network feature space (13 features) is smaller
- `contamination=0.1` — 10%, slightly more lenient because small network training sets (fewer than 50 connections) calibrate too tightly at 5%, causing genuine anomalies to slip through
- `random_state=42`

#### Training workflow

Both models are trained from the saved baseline:

```
python training/train_process_model.py
python training/train_network_model.py
```

Each script:
1. Loads `sentinel_baseline.json` via `load_baseline()`
2. Iterates the baseline process list or connection list
3. Calls `_extract_process_features()` / `_extract_connection_features()` on each entry to produce a numeric row
4. Assembles the rows into a NumPy 2D matrix
5. Calls `model.fit(X)` — this is where the learning happens
6. Saves the trained model to `models/process_model.pkl` or `models/network_model.pkl` using `pickle`
7. Runs a sanity check: scores the training data back through the model; ~5-10% should be flagged

The models only need to be retrained when the feature vectors change (i.e., after a code change like the ones recently made) or when a new baseline is created after significant machine configuration changes.

### 8.3 How Detection Works After ML

**Process detection (after):** Instead of asking "have I seen this exact name+exe before?", the system asks "do the *characteristics* of this process look normal?". A new app installed in `Program Files` and launched by `explorer.exe` scores well on nearly every feature even if it was installed after the baseline was taken — it is accepted. A random-named exe (`xk3jlq.exe`) running from `AppData\Local\Temp`, launched by `powershell.exe`, with no vowels in its name, scores poorly on many features simultaneously — it is flagged.

**Network detection (after):** Instead of checking the specific remote IP, the system evaluates the *behaviour* of the connection — which process made it, on what port, from where on disk. Chrome connecting to a new CDN IP on port 443 looks identical to every other Chrome HTTPS connection the model was trained on — it is accepted. An exe from a Temp folder connecting on port 4444 is nothing like any connection in the baseline cluster — it is flagged.

### 8.4 Feature Engineering

Feature engineering converts raw data (strings, file paths, process names) into the numeric vectors the ML model can work with. The same functions are called during training (on baseline data) and during live monitoring (on current data). The order of features in the vector is fixed — changing it requires retraining.

#### Process features (19 features, `_extract_process_features()` in `training/train_process_model.py`, line 316)

| Index | Feature | What it captures |
|---|---|---|
| 0 | `is_system_dir` | Exe path contains `\windows\` |
| 1 | `is_program_files` | Exe path contains `program files` |
| 2 | `is_temp_dir` | Exe path contains `\temp\` or `\tmp\` — strongest single red flag |
| 3 | `is_appdata_programs` | Exe in `AppData\Local\Programs`, `AppData\Roaming`, or `AppData\Local\JetBrains` (legitimate install paths) |
| 4 | `is_appdata_other` | Exe in AppData but NOT in the Programs subfolder or Temp — a mild signal |
| 5 | `is_windows_special` | Exe in `WindowsApps` or `DriverStore` (Microsoft system paths) |
| 6 | `path_depth` | Number of directory levels in the exe path — deeply nested paths are unusual |
| 7 | `name_vowel_ratio` | Fraction of vowels in the process name. Randomly generated names have almost none (`xk3jlq` = 0.0); real software names have natural vowels (`explorer` = 0.50) |
| 8 | `name_rare_ratio` | Fraction of rare letters (z, x, j, k, q). Over-represented in random strings, under-represented in real words |
| 9 | `name_digit_ratio` | Fraction of digits. Malware names often mix numbers heavily (`svc32fk3`) |
| 10 | `name_length_norm` | Name length normalised to 0-1 (capped at 25 chars). Very short or very long names are statistically unusual |
| 11 | `is_known_process` | Name appears in the `KNOWN_LEGITIMATE_PROCESSES` set (300+ known good process names) |
| 12 | `is_system_account` | Running as `NT AUTHORITY\SYSTEM`, `LocalService`, or `NetworkService` |
| 13 | `parent_is_explorer` | Launched by `explorer.exe` — typical for apps a user double-clicked |
| 14 | `parent_is_shell` | Launched by `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, or `bash.exe` — a mild signal on its own |
| 15 | `cpu_percent` | Current CPU usage percentage |
| 16 | `has_no_exe` | No exe path — normal for kernel processes like `System` and `Idle` |
| 17 | `parent_is_service` | Launched by `services.exe`, `svchost.exe`, `lsass.exe`, or `wininit.exe` — the Windows service infrastructure. A process with this parent is almost certainly a legitimate Windows service |
| 18 | `cmdline_obfuscation` | The process command line contains PowerShell obfuscation markers: `-EncodedCommand`, `-enc `, `Invoke-Expression`, `iex(`, `FromBase64String(`, `DownloadString(`, `DownloadFile(`, `WebClient`, or `hidden -`. Legitimate processes essentially never use these patterns in their arguments |

Features 17 and 18 were added specifically to address noise. Feature 17 prevents the model from misclassifying legitimate background Windows services (which often have unusual-looking paths or parents) as anomalies. Feature 18 gives the model an almost zero-false-positive indicator for living-off-the-land attack techniques — the kind attackers use to execute malicious code via trusted Windows tools.

#### Network features (13 features, `_extract_connection_features()` in `training/train_network_model.py`, line 213)

| Index | Feature | What it captures |
|---|---|---|
| 0 | `is_well_known_port` | Port is in `WELL_KNOWN_PORTS` (21, 22, 25, 53, 80, 443, 3389, 8080, etc.) |
| 1 | `is_suspicious_port` | Port is in `SUSPICIOUS_PORTS` (4444, 1337, 31337, 9001, 6666, etc.) |
| 2 | `is_high_port` | Port is above 10000 — sometimes used by C2 tools to blend in with ephemeral traffic |
| 3 | `is_private_ip` | Remote IP is in a private range (RFC 1918: 10.x, 172.16-31.x, 192.168.x) — less concerning than public internet connections |
| 4 | `proc_is_browser` | Process is a known browser (Chrome, Brave, Firefox, Edge, Opera, IE) |
| 5 | `proc_is_system` | Process is a Windows system service (svchost, lsass, services, etc.) |
| 6 | `proc_from_pgf` | Exe lives under `Program Files` |
| 7 | `proc_from_temp` | Exe lives in a Temp folder — one of the strongest red flags for network connections |
| 8 | `vowel_ratio` | Vowel fraction of the process name |
| 9 | `browser_on_non_web_port` | A known browser connecting to something other than port 80 or 443. This is the pattern of a hijacked browser connecting to a C2 server |
| 10 | `system_to_public` | A Windows system service connecting to a public internet IP. System services do legitimately do this (Windows Update via svchost) but it is worth capturing |
| 11 | `proc_from_appdata_programs` | Exe is in `AppData\Local\Programs`, `AppData\Roaming`, or `AppData\Local\JetBrains` — legitimate user-installed app paths |
| 12 | `proc_is_known` | Process name is in the `KNOWN_LEGITIMATE_PROCESSES` set from `training/train_process_model.py` — both models share the same ground truth |

Features 11 and 12 were added to reduce noise from update helpers, synchronisation clients, and user-installed apps (Python, Ollama, Claude, Slack, Discord, JetBrains tools, Free Download Manager) that make outbound connections but were previously flagged because their exe paths looked unusual to a model trained only on system processes and browsers.

### 8.5 The Layered Detection Architecture

Both monitors implement the same two-layer architecture, mirroring how real security products work:

```
For each process / connection:
│
├── LAYER 1: HARD RULES (always fire, model not needed)
│   Tight, high-confidence patterns with essentially zero false positives.
│   If any hard rule fires → alert immediately, skip ML entirely.
│
│   Process hard rules:
│     • exe path contains \Temp\, \Tmp\, \Downloads\, or \Desktop\
│     • CPU usage exceeds cfg["cpu_spike_percent_over_baseline"]
│
│   Network hard rules:
│     • remote port in SUSPICIOUS_PORTS {4444, 1337, 31337, 9001, ...}
│     • exe from Temp folder connecting to a public internet IP
│
├── LAYER 2A: ML MODEL (if model is loaded and no hard rule fired)
│   Isolation Forest scores the 19- or 13-float feature vector.
│   Score floor applied first:
│     if score >= -0.03 → skip (borderline, not meaningful)
│   If score < -0.03 AND predict() returned -1 → alert
│   Severity mapping:
│     score < -0.05 → high severity (confidently anomalous)
│     -0.05 ≤ score < -0.03 → medium severity
│
└── LAYER 2B: FALLBACK (if no trained model file exists)
    Original rule-based logic (noisy but functional):
    Process: name+exe not found in baseline process list → alert
    Network: remote IP not found in baseline connection list → alert
```

### 8.6 Noise Reduction Improvements

Several targeted improvements were made after the initial ML integration to tighten the signal:

#### Score floor (`-0.03`)

**Files:** `monitors/sentinel_process_monitor.py` (line 317), `monitors/sentinel_network_monitor.py` (line 364)

The Isolation Forest's `predict()` returns `-1` for *any* score below the contamination boundary, including borderline values like `-0.001` that are statistically almost indistinguishable from normal. The score floor drops these:

```python
if score >= -0.03:
    continue   # borderline — skip, don't alert
```

This is the highest-impact single change for noise reduction. It eliminates the entire class of weak false positives where the model classifies something as anomalous but only very weakly — the process or connection looks nearly identical to normal traffic.

#### `parent_is_service` feature (process model, feature [17])

`svchost.exe` and `services.exe` legitimately launch hundreds of background Windows services. Without this feature the model saw "AppData exe launched by an unusual parent" and flagged it. With it the model learns that the service host infrastructure is a completely normal launch chain and groups those processes with the normal cluster.

#### `cmdline_obfuscation` feature (process model, feature [18])

Implemented in `_has_cmdline_obfuscation()` in `training/train_process_model.py` (line 269). Checks the process command line for a list of PowerShell obfuscation and download-and-execute patterns. Legitimate user processes never use `-EncodedCommand` or `Invoke-Expression` in their arguments — malicious PowerShell stagers almost always do. This gives the model a near-zero-false-positive signal for entire categories of attack technique.

#### `proc_from_appdata_programs` + `proc_is_known` (network model, features [11] and [12])

Without feature 11, the model treated all AppData exes as equally suspicious (since the baseline was populated mainly by system processes and browsers). Apps like Python, Slack, Discord, JetBrains IDE toolboxes, and Free Download Manager all install in `AppData\Local\Programs` and make network connections — but they were flagged. Feature 11 gives the model a way to recognise this as a normal install location. Feature 12 provides a shared ground truth list of known-good process names across both the process and network models.

---

## 9. The Alert System

**File:** `core/sentinel_alerts.py`

All alerts, regardless of type, share a common schema built by `_base_alert()` (line 47):

```json
{
  "type": "alert",
  "alert_type": "process | network | fim",
  "alert_id": "proc-<uuid>",
  "created_at": "2025-04-08T14:20:33.123456Z",
  "status": "NEW",
  "agent_id": "sentinel-AGENT-abc12345",
  "agent_name": "SENATOR-PC",
  "severity": "low | medium | high",
  "summary": "Human-readable one-line description",
  "reasons": ["list", "of", "reason", "codes"]
}
```

Each alert type adds type-specific fields on top of this base:

- **Process alert** (`make_process_alert()`, line 102): adds `process` (the running process info dict) and `baseline` (the matching baseline entry if one was found)
- **Network alert** (`make_network_alert()`, line 132): adds `connection` (remote IP, port, DNS hostname, status, protocol type) and `process` (the process that made the connection)
- **FIM alert** (`make_fim_alert()`, line 162): adds `path`, `event_type` (CREATED, MODIFIED, or DELETED), `before` (baseline file state), `after` (current file state), and `attribution`

All alerts also carry a `dedup_key` field (set by each monitor) used by the agent's cooldown dictionaries to suppress repeated alerts.

Alerts travel from the agent to the controller as raw JSON messages over the TCP socket. The controller stores them in `self.alerts` via `add_alert()` (line 162 of `sentinel_controller.py`), wrapping each in a record with a controller-level integer ID, an agent label, and fields for LLM triage results.

---

## 10. Configuration System

**File:** `core/sentinel_config.py`

The agent config is stored in `agent_config.json` at the project root. Key fields and their defaults:

| Key | Default | Purpose |
|---|---|---|
| `agent_id` | `sentinel-AGENT-<8 hex chars>` | Unique agent identifier, generated once on first run |
| `display_name` | Machine hostname | Human-readable label shown in the controller |
| `controller_host` | `127.0.0.1` | Controller IP the agent connects to |
| `controller_port` | `9000` | Controller TCP port |
| `reconnect_interval_seconds` | `5` | How long to wait between reconnect attempts |
| `monitor_interval_seconds` | `30` | How often the monitoring tick runs |
| `enable_process_monitor` | `true` | Toggle process detection |
| `enable_network_monitor` | `true` | Toggle network detection |
| `enable_fim` | `true` | Toggle file integrity monitoring |
| `enable_vulncheck` | `true` | Toggle vulnerability checking |
| `cpu_spike_percent_over_baseline` | `50` | Hard rule: alert if CPU is this many percent above baseline average |
| `ram_spike_percent_over_baseline` | `50` | Hard rule: alert if RAM is this many percent above baseline average |
| `monitor_interval_seconds` | `30` | Seconds between monitoring ticks |
| `fim_paths` | `[]` | Exact file paths FIM should monitor |
| `fim_quarantine_dir` | `C:\ProgramData\Sentinel\quarantine` | Where quarantined files are moved to |
| `network_ip_whitelist` | `[]` | IPs the network monitor ignores |
| `process_whitelist` | `[]` | Processes (name + exe + username) the process monitor skips |
| `blocked_ips` | `[]` | IPs currently blocked via Windows Firewall |

`load_or_create_config()` (line 115) uses `apply_defaults()` to add any missing keys from `get_default_config()` without overwriting existing user values. The config is saved back to disk after every load so that newly added default fields are persisted immediately.

---

## 11. Response Capabilities

When the controller receives an alert, the operator has a range of response actions available, all implemented as commands sent from controller to agent:

### Process responses
- **`KILL_PROCESS`** — terminates the flagged process using `psutil.Process.terminate()`. If the process does not stop within 5 seconds, `psutil.Process.kill()` is used to force it. After killing, the cooldown entry for that process is cleared so the agent can re-alert immediately if the same exe relaunches.
- **`WHITELIST_PROCESS`** — adds the process's name, exe, and username to `cfg["process_whitelist"]`. That entry is never evaluated again.

### Network responses
- **`BLOCK_IP`** — runs two `netsh advfirewall firewall add rule` commands to block both inbound and outbound traffic to the target IP via Windows Firewall. The IP is recorded in `cfg["blocked_ips"]` so the controller can list and manage blocked addresses.
- **`UNBLOCK_IP`** — deletes the corresponding Sentinel firewall rules.
- **`ADD_IP_WHITELIST`** — adds the IP to the network monitor's allow-list so future connections to it are never flagged.
- **AbuseIPDB lookup** — the operator can call `abuseipdb_check_ip(ip)` from the controller CLI to retrieve the IP's abuse confidence score, total number of community reports, and country of origin before deciding whether to block.

### FIM responses
- **`FIM_UPDATE_BASELINE_ITEM`** — accepts the detected change as legitimate. The agent recomputes the current file state and saves it as the new baseline entry for that path. Future monitoring will not alert on this state.
- **`FIM_LOCKDOWN_FILE`** — strips all file permissions except SYSTEM and Administrators using `takeown` (to take ownership) and `icacls /inheritance:r` + `/grant:r SYSTEM:(F) Administrators:(F)`. Useful for protecting critical files from further modification.
- **`FIM_QUARANTINE_FILE`** — moves the file to a timestamped `.quarantine` copy in `cfg["fim_quarantine_dir"]` and immediately locks it down with `FIM_LOCKDOWN_FILE` logic.

---

## 12. Data Flow — End to End

Here is the complete journey from a suspicious process starting on the monitored machine to an alert appearing in the controller, illustrating how all the components fit together:

```
1. A suspicious exe launches on the monitored machine.

2. The agent's monitoring timer fires (every monitor_interval_seconds).

3. run_process_monitor_tick() is called with the current config,
   baseline, and open TCP socket to the controller.

4. detect_suspicious_processes() iterates psutil.process_iter():

   For each process:
   a. _build_process_info() uses psutil.oneshot() to collect:
      name, PID, exe, username, cmdline, parent_name, cpu_percent.

   b. Whitelist check: if name|exe|username matches cfg["process_whitelist"],
      skip this process entirely.

   c. LAYER 1 — Hard rules:
      - _is_suspicious_path(exe) → True if exe is in Temp/Downloads/Desktop
      - cpu_percent >= cpu_spike_percent_over_baseline → high CPU

   d. LAYER 2A — ML (if model loaded and no hard rule fired):
      features = _extract_process_features(info)  # → 19 floats
      X = np.array(features).reshape(1, -1)
      label = PROCESS_MODEL.predict(X)[0]          # +1 or -1
      if label == -1:
          score = PROCESS_MODEL.decision_function(X)[0]
          if score < -0.03:                        # score floor
              reasons.append("ml_anomaly_detected")
              severity = "high" if score < -0.05 else "medium"

   e. make_process_alert() builds the standardised alert dict.

   f. alert["dedup_key"] = f'{name}|{exe}|{user}'

5. Back in run_process_monitor_tick():

   For each alert:
   - key = _process_alert_key(proc)
   - if (now - LAST_PROCESS_ALERT_TIMES.get(key, 0)) < 300:
       continue  # in cooldown, suppress
   - LAST_PROCESS_ALERT_TIMES[key] = now
   - send_message(sock, alert)  # → TCP to controller

6. The alert travels over TCP using the length-prefixed JSON protocol.
   The 4-byte header ensures the controller reads the complete message
   even if TCP fragments it.

7. The controller receives the alert in its monitoring loop.
   controller.add_alert(alert, agent) stores it with a controller ID.

8. Optionally, the Groq LLM triages the alert:
   - "suspicious" → shown in main alerts list
   - "benign" → hidden from main list (accessible via --benign flag)
   - "unknown" → shown in main list

9. The operator reviews the alert in the controller CLI and responds:
   - KILL_PROCESS → agent terminates the process
   - WHITELIST_PROCESS → agent adds to whitelist, never alerts again
   - No action → alert stays in the queue for review
```

---

## 13. Project Folder Structure

The project was recently reorganised from a flat layout (all files in the root) into a structured package layout. The reorganisation and all associated import updates were completed without any functional changes to detection logic.

All intra-project imports now use full package paths:
- `from core.sentinel_baseline import load_baseline`
- `from monitors.sentinel_network_monitor import detect_suspicious_connections`
- `from training.train_network_model import load_network_model`

The training scripts add the project root to `sys.path` in their `__main__` block so they can be run directly from the command line:

```
python training/train_process_model.py
python training/train_network_model.py
```

The two entry points (`sentinel_agent.py` and `sentinel_controller.py`) remain at the project root and are run from there:

```
python sentinel_agent.py
python sentinel_controller.py
```

---

*End of report.*
