# train_network_model.py
# ----------------------
# ML model training for Sentinel network anomaly detection.
#
# WHY THIS FILE EXISTS:
#   The original sentinel_network_monitor.py flagged EVERY connection whose
#   remote IP wasn't seen in the baseline. This is extremely noisy because
#   cloud services (Google, Microsoft, Spotify, etc.) rotate through hundreds
#   of different IPs — so every legitimate browser request triggered an alert.
#
#   This file replaces that approach with an Isolation Forest — an ML model
#   that learns what "normal" connection BEHAVIOUR looks like (port used,
#   which process made it, where that process lives on disk, etc.) rather than
#   caring about the specific IP address. A new IP on port 443 from Chrome is
#   fine. An unknown exe from your Temp folder connecting to port 4444 is not.
#
# HOW IT FITS INTO THE PROJECT:
#   1. After a baseline is created (via 'baseline N' in the controller), run
#      this file once to train and save the model  →  models/network_model.pkl
#   2. sentinel_network_monitor.py imports load_network_model() and
#      _extract_connection_features() from here, loads the saved model at
#      startup, and uses it to score every live connection.
#
# CAN BE RUN DIRECTLY:
#   python train_network_model.py
#   This triggers the self-test at the bottom of the file, which trains,
#   saves, and runs a sanity-check against the baseline data.

from __future__ import annotations

import pickle                          # used to save and load the trained model to/from disk
from pathlib import Path               # cross-platform file path handling
from typing import Any, Dict, List, Optional

import numpy as np                     # converts our list of feature rows into a matrix the model can read
from sklearn.ensemble import IsolationForest  # the ML algorithm — explained in detail below

# ---------------------------------------------------------------------------
# WHERE THE MODEL FILE LIVES ON DISK
#
# Path(__file__).parent is the project root (where this script lives).
# Models are stored in a dedicated subdirectory so the root stays tidy.
# So if this script is at:
#   C:\Users\senat\PycharmProjects\Sentinel\training\train_network_model.py
# the model will be saved to:
#   C:\Users\senat\PycharmProjects\Sentinel\models\network_model.pkl
# ---------------------------------------------------------------------------
NETWORK_MODEL_PATH = Path(__file__).parent.parent / "models" / "network_model.pkl"

# How many usable baseline connections we need before training is worthwhile.
# With fewer than 5 samples the model has nothing meaningful to learn from.
MIN_TRAINING_SAMPLES = 5

# ---------------------------------------------------------------------------
# PORT LISTS
#
# WHY WE CARE ABOUT PORTS:
#   A port number tells us *what kind* of traffic is being sent.
#   Port 443 = HTTPS (encrypted web) — used by virtually every app.
#   Port 4444 = Metasploit's default listener — used by almost no legitimate app.
#   By labelling ports as well-known or suspicious, we give the model a strong
#   signal without it needing to understand networking itself.
# ---------------------------------------------------------------------------

# Ports that appear in the vast majority of legitimate everyday traffic.
# If a connection uses one of these ports it scores as more "normal".
WELL_KNOWN_PORTS = {
    21,    # FTP  — file transfers
    22,    # SSH  — remote terminal access
    25,    # SMTP — sending email
    53,    # DNS  — domain name lookups (every app does this)
    80,    # HTTP — unencrypted web
    110,   # POP3 — receiving email (old)
    143,   # IMAP — receiving email (modern)
    443,   # HTTPS — encrypted web (most common port on any machine)
    587,   # SMTP submission — email clients sending mail
    993,   # IMAPS — encrypted IMAP
    995,   # POP3S — encrypted POP3
    3389,  # RDP  — Windows Remote Desktop
    8080,  # HTTP alt — dev servers, proxies
    8443,  # HTTPS alt — dev servers, proxies
}

# Ports historically associated with malware, C2 (command-and-control) frameworks,
# or exploit kits. A connection to ANY of these will ALWAYS raise an alert,
# regardless of what the model says — these are hard rules, not ML judgements.
SUSPICIOUS_PORTS = {
    4444,   # Metasploit Framework default reverse shell listener
    1337,   # "leet" — used by many C2 tools and backdoors
    31337,  # "elite" — Back Orifice RAT and others
    9001,   # Tor relay OR common custom C2 port
    6666,   # IRC-based malware / botnets
    6667,   # IRC-based malware / botnets (standard IRC port)
    5555,   # Android ADB over TCP — abused by mobile malware
    1234,   # Generic placeholder port used in malware PoCs
}

# ---------------------------------------------------------------------------
# PROCESS LISTS
#
# WHY WE CARE ABOUT WHICH PROCESS MADE THE CONNECTION:
#   The process tells us WHO is talking to the internet.
#   Chrome connecting to port 443 is expected. Notepad connecting to
#   anything external is not. We classify processes into groups so the
#   model understands the CONTEXT of the connection, not just the numbers.
# ---------------------------------------------------------------------------

# Known web browsers — these make constant outbound connections and that is
# completely expected behaviour. Chrome on port 443 = normal.
BROWSER_PROCESSES = {
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",   # Microsoft Edge
    "opera.exe",
    "brave.exe",
    "iexplore.exe", # Internet Explorer (legacy)
}

# Core Windows system processes — these run as SYSTEM and manage OS internals.
# They do make network connections (e.g. svchost handles Windows Update),
# but certain combinations (like connecting to a suspicious port) are still
# worth flagging even for these trusted processes.
SYSTEM_SERVICES = {
    "svchost.exe",   # Windows Service Host — runs dozens of background services
    "lsass.exe",     # Local Security Authority — handles logins and credentials
    "services.exe",  # Windows Services Control Manager
    "wininit.exe",   # Windows Initialization — starts at boot
    "csrss.exe",     # Client/Server Runtime — manages console windows
    "winlogon.exe",  # Handles user logon/logoff
    "smss.exe",      # Session Manager — first user-mode process to start
    "system",        # The Windows kernel itself
    "ntoskrnl.exe",  # Windows kernel image
}

# ---------------------------------------------------------------------------
# PRIVATE IP HELPER
#
# WHY THIS IS DUPLICATED HERE (instead of importing from sentinel_network_monitor):
#   If this file imported from sentinel_network_monitor.py, and
#   sentinel_network_monitor.py imported from this file, Python would hit a
#   circular import error and refuse to load either file. Duplicating this
#   small helper avoids that problem entirely.
#
# HOW IT WORKS:
#   IPv4 private ranges are defined by RFC 1918:
#     10.0.0.0/8       → any IP starting with 10.
#     172.16.0.0/12    → 172.16.x.x through 172.31.x.x
#     192.168.0.0/16   → 192.168.x.x (your home/office router range)
#   127.x.x.x is loopback (the machine talking to itself).
#   IPv6 addresses contain ":" — we skip those for simplicity.
# ---------------------------------------------------------------------------

def _is_private_ip(ip: str) -> bool:
    """Return True if the IP address is in a private or loopback range."""
    if not ip or ":" in ip:
        # Empty string or IPv6 — treat as not private for safety
        return False

    parts = ip.split(".")
    if len(parts) != 4:
        # Malformed — not a valid IPv4 address
        return False

    try:
        a, b, c, d = [int(x) for x in parts]
    except ValueError:
        # One of the octets wasn't a number
        return False

    if a == 127:
        return True   # Loopback (127.0.0.1 etc.)
    if a == 10:
        return True   # Class A private (10.x.x.x)
    if a == 172 and 16 <= b <= 31:
        return True   # Class B private (172.16-31.x.x)
    if a == 192 and b == 168:
        return True   # Class C private (192.168.x.x)

    return False      # Public IP

# ---------------------------------------------------------------------------
# FEATURE HELPERS
# ---------------------------------------------------------------------------

def _name_vowel_ratio(name: str) -> float:
    """
    Return the fraction of vowels in a process name as a number from 0.0 to 1.0.

    WHY THIS MATTERS:
        Malware authors often use randomly generated executable names like
        "xk3jlq.exe" or "bqzfn.exe" to avoid detection. Real software names
        are (almost always) human-readable words or abbreviations, which means
        they naturally contain vowels: "brave", "spotify", "svchost".

        A vowel ratio of 0.0 means NO vowels — highly suspicious.
        A vowel ratio around 0.3-0.5 is typical for real software names.

    The .exe extension is stripped first so it doesn't skew the ratio.

    Examples:
        "brave"    → strip .exe → "brave"   → 2 vowels / 5 chars = 0.40
        "svchost"  → strip .exe → "svchost" → 1 vowel  / 7 chars = 0.14
        "xk3jlq"   → strip .exe → "xk3jlq"  → 0 vowels / 6 chars = 0.00
    """
    name = (name or "").lower().replace(".exe", "").strip()
    if not name:
        return 0.0  # Empty name — return 0 as a safe default
    vowels = sum(1 for c in name if c in "aeiou")
    return vowels / len(name)


def _extract_connection_features(
        rip: str,
        rport: int,
        pinfo: Optional[Dict[str, Any]],
) -> List[float]:
    """
    Convert one network connection into a fixed-length list of numbers (a feature vector).

    WHY WE DO THIS:
        The Isolation Forest (and all ML models) cannot work with raw strings like
        "brave.exe" or "192.168.0.1". They only understand numbers. This function
        is the bridge — it takes one connection and produces 11 numbers that capture
        everything meaningful about it.

        The model is then trained on hundreds of these 11-number rows so it learns
        what combinations of values are "normal" for this machine.

    HANDLING TWO DIFFERENT DICT FORMATS:
        The baseline (saved to sentinel_baseline.json) stores process info with
        keys 'path' and 'user'.
        The live monitor (sentinel_network_monitor.py) uses keys 'exe' and 'username'.
        We check for both so this function works in both contexts.

    Parameters:
        rip   - remote IP address string  e.g. "142.250.80.46"
        rport - remote port number        e.g. 443
        pinfo - process info dict, or None if the OS couldn't identify the process

    Returns:
        A list of exactly 13 floats, always in the same order:
        [0]  is_well_known_port          — 1.0 if port is in WELL_KNOWN_PORTS, else 0.0
        [1]  is_suspicious_port          — 1.0 if port is in SUSPICIOUS_PORTS, else 0.0
        [2]  is_high_port                — 1.0 if port > 10000, else 0.0
        [3]  is_private_ip               — 1.0 if IP is private/internal, else 0.0
        [4]  proc_is_browser             — 1.0 if process is a known browser, else 0.0
        [5]  proc_is_system              — 1.0 if process is a Windows system service
        [6]  proc_from_program_files     — 1.0 if exe lives under Program Files
        [7]  proc_from_temp              — 1.0 if exe lives in a Temp folder (suspicious)
        [8]  proc_name_vowel_ratio       — vowel fraction of the process name (0.0–1.0)
        [9]  browser_on_non_web_port     — 1.0 if browser is NOT using port 80 or 443
        [10] system_to_public_ip         — 1.0 if a system service is reaching a public IP
        [11] proc_from_appdata_programs  — 1.0 if exe is in AppData\Programs/Roaming (legit)
        [12] proc_is_known               — 1.0 if process name is in known-legitimate list
    """
    # If we have no process info, use an empty dict so all .get() calls
    # return None safely instead of raising an AttributeError.
    if pinfo is None:
        pinfo = {}

    # Pull the process name and exe path, normalising to lowercase.
    # We check both 'path' (baseline format) and 'exe' (live monitor format).
    pname = (pinfo.get("name") or "").lower()
    exe   = (pinfo.get("exe") or pinfo.get("path") or "").lower().replace("/", "\\")

    # ------------------------------------------------------------------
    # PORT FEATURES
    # What type of service is this connection reaching?
    # ------------------------------------------------------------------

    # Is this a port we'd expect to see in normal everyday traffic?
    is_well_known_port = 1.0 if rport in WELL_KNOWN_PORTS else 0.0

    # Is this a port specifically associated with malware/C2 tools?
    is_suspicious_port = 1.0 if rport in SUSPICIOUS_PORTS else 0.0

    # ------------------------------------------------------------------
    # IP FEATURES
    # Is the destination inside the local network or out on the internet?
    # ------------------------------------------------------------------

    # Connections staying inside the private network are generally less
    # concerning than connections going out to the public internet.
    is_private = 1.0 if _is_private_ip(rip) else 0.0

    # ------------------------------------------------------------------
    # PROCESS IDENTITY FEATURES
    # Who is making this connection and where do they live on disk?
    # ------------------------------------------------------------------

    # Is the connecting process a web browser?
    # Browsers make constant outbound connections — that is expected.
    proc_is_browser = 1.0 if pname in BROWSER_PROCESSES else 0.0

    # Is it a core Windows system service?
    # System processes do make network connections but certain behaviours
    # (e.g. connecting to a suspicious port) are still worth flagging.
    proc_is_system  = 1.0 if pname in SYSTEM_SERVICES else 0.0

    # Is the executable installed in Program Files?
    # Legitimate software installed by a proper installer lives here.
    # Malware dropped by another process usually does NOT.
    proc_from_pgf   = 1.0 if "program files" in exe else 0.0

    # Is the executable running from a Temp folder?
    # This is one of the strongest single signals — legitimate software
    # almost never runs persistently from a Temp directory.
    proc_from_temp  = 1.0 if ("\\temp\\" in exe or "\\tmp\\" in exe) else 0.0

    # How "word-like" is the process name? Low ratio = suspicious.
    vowel_ratio     = _name_vowel_ratio(pname)

    # ------------------------------------------------------------------
    # COMBINATION FEATURES
    # These capture suspicious COMBINATIONS that no single feature catches.
    # ------------------------------------------------------------------

    # A browser connecting to something other than port 80 or 443 is unusual.
    # Browsers speak HTTP/HTTPS. If one is connecting to port 4444 something
    # has hijacked it (e.g. malicious browser extension or exploit).
    browser_on_non_web_port = 1.0 if (proc_is_browser and rport not in {80, 443}) else 0.0

    # A Windows system service connecting to a public (non-private) IP.
    # System services do this legitimately (e.g. Windows Update via svchost),
    # but it's worth capturing as a feature so the model can weight it
    # together with other signals like an unusual port.
    system_to_public = 1.0 if (proc_is_system and not _is_private_ip(rip)) else 0.0

    # Is the port in the high/ephemeral range (above 10000)?
    # High ports are sometimes used by C2 tools to blend in with ephemeral traffic.
    # We use this INSTEAD of the raw port number because raw port values (0-65535)
    # have a huge numeric scale that dominates distance calculations and drowns out
    # the binary features. Two binary flags (well-known + high) capture port behaviour
    # much more cleanly.
    is_high_port = 1.0 if rport > 10000 else 0.0

    # Is the exe in AppData\Local\Programs, AppData\Roaming, or known JetBrains path?
    # Many legitimate user-installed apps (Python, Claude, Slack, Discord, JetBrains
    # tools) live here. Without this feature the model can't distinguish them from
    # random AppData exes, leading to false positives on update helpers and launchers.
    proc_from_appdata_programs = 1.0 if (
        "\\appdata\\local\\programs\\" in exe or
        "\\appdata\\roaming\\" in exe or
        "\\appdata\\local\\jetbrains\\" in exe
    ) else 0.0

    # Is this a process we know to be legitimate by name?
    # Import the same set used by the process model so both detectors agree.
    # This normalises common apps (browsers, IDEs, system tools) so the model
    # can learn that even an unusual-looking connection is expected for known processes.
    from training.train_process_model import KNOWN_LEGITIMATE_PROCESSES as _KNOWN
    proc_is_known = 1.0 if pname in _KNOWN else 0.0

    # Return all 13 features as floats in a consistent, fixed order.
    # The order MUST stay the same between training and inference —
    # if you add or move a feature here you must retrain the model.
    return [
        is_well_known_port,          # [0]  is this a normal everyday port?
        is_suspicious_port,          # [1]  is this a known malware/C2 port?
        is_high_port,                # [2]  is the port above 10000?
        is_private,                  # [3]  internal network connection?
        proc_is_browser,             # [4]  is the process a browser?
        proc_is_system,              # [5]  is it a Windows system service?
        proc_from_pgf,               # [6]  exe lives in Program Files?
        proc_from_temp,              # [7]  exe lives in Temp? (strong red flag)
        vowel_ratio,                 # [8]  how word-like is the process name?
        browser_on_non_web_port,     # [9]  browser on a non-HTTP/S port?
        system_to_public,            # [10] system service to public internet?
        proc_from_appdata_programs,  # [11] exe in AppData\Programs/Roaming (legit install)?
        proc_is_known,               # [12] process name in known-legitimate list?
    ]

# ---------------------------------------------------------------------------
# MODEL TRAINING
#
# WHAT IS AN ISOLATION FOREST?
#   An Isolation Forest is an unsupervised anomaly detection algorithm.
#   "Unsupervised" means you do NOT need labelled data (no need to manually
#   mark connections as "malicious" or "benign"). You just give it examples
#   of normal behaviour and it learns the shape of that cluster.
#
# HOW DOES IT WORK?
#   It builds many random decision trees. For each data point (connection),
#   it keeps splitting the data on random features until that point is
#   isolated on its own. The key insight is:
#
#     Normal points sit in a DENSE cluster → need MANY splits to isolate
#     Anomalies sit far from the cluster  → isolated in VERY FEW splits
#
#   The fewer splits needed, the more anomalous the point.
#   This "isolation score" is what we use to decide whether to raise an alert.
#
# PARAMETERS EXPLAINED:
#   n_estimators=100   → build 100 trees; more trees = more stable scores
#   contamination=0.05 → we assume at most 5% of baseline connections are
#                        already unusual (e.g. uTorrent was open at baseline time).
#                        This sets the threshold between "normal" and "anomaly".
#   random_state=42    → fixed random seed so training is reproducible —
#                        re-running produces the exact same model.
# ---------------------------------------------------------------------------

def train_network_model(baseline: Dict[str, Any]) -> Optional[IsolationForest]:
    """
    Build and train an Isolation Forest using the network connections
    stored in the baseline snapshot.

    Parameters:
        baseline - the full baseline dict loaded from sentinel_baseline.json

    Returns:
        A trained IsolationForest ready to score live connections,
        or None if there weren't enough baseline connections to train on.
    """
    # Navigate to the network section of the baseline.
    # The baseline structure is:  baseline → network → connections (list)
    net         = baseline.get("network") or {}
    connections = net.get("connections") or []

    if not connections:
        print("[NET MODEL] No connections in baseline — cannot train.")
        return None

    # Build the training matrix — one row of 11 numbers per connection.
    rows: List[List[float]] = []

    for conn in connections:
        rip   = conn.get("remote_ip")    # the IP the machine was talking to
        rport = conn.get("remote_port")  # the port on the remote side
        proc  = conn.get("process")      # process info dict (may be None)

        # Skip connections that have no remote address.
        # These are typically UDP sockets listening locally (e.g. mDNS, DHCP)
        # — they never reach the internet so they're not useful for training.
        if not rip or rport is None:
            continue

        # Skip loopback addresses (127.x.x.x).
        # These are connections from one process to another on the same machine
        # (e.g. the Sentinel agent talking to the controller on port 9000).
        # They tell us nothing about external threat behaviour.
        if _is_private_ip(rip) and rip.startswith("127."):
            continue

        # Ensure the port is an integer — the JSON may have stored it as a string.
        try:
            rport = int(rport)
        except (ValueError, TypeError):
            continue   # unparseable port — skip this connection

        # Convert the connection to a row of numbers and add it to the matrix.
        features = _extract_connection_features(rip, rport, proc)
        rows.append(features)

    # If we don't have enough rows the model would be unreliable — bail out.
    if len(rows) < MIN_TRAINING_SAMPLES:
        print(
            f"[NET MODEL] Only {len(rows)} usable connection(s) in baseline "
            f"(minimum {MIN_TRAINING_SAMPLES}) — skipping training."
        )
        return None

    # Convert the list of rows into a NumPy 2D array (matrix).
    # Shape: (number_of_connections, 11)
    # This is the format scikit-learn expects.
    X = np.array(rows, dtype=float)

    print(f"[NET MODEL] Training Isolation Forest on {len(rows)} baseline connections...")

    model = IsolationForest(
        n_estimators=100,   # 100 trees gives stable, reliable scores
        contamination=0.1,  # expect ~10% of baseline rows to be borderline unusual.
                            # Raised from 0.05 because with small training sets (< 50
                            # connections) a 5% threshold is calibrated too tightly —
                            # novel anomalies score above it and slip through.
                            # 10% gives a more useful boundary without being too noisy.
        random_state=42,    # reproducible results across runs
    )

    # .fit() is where the actual learning happens.
    # The model builds 100 random trees over the training data.
    # After this call the model knows what "normal" looks like for this machine.
    model.fit(X)

    print("[NET MODEL] Training complete.")
    return model

# ---------------------------------------------------------------------------
# SAVE AND LOAD
#
# WHY WE SAVE TO DISK:
#   Training takes a moment and should only happen once (when the baseline
#   is created or refreshed). The sentinel agent then loads the saved model
#   at startup and reuses it for every monitoring scan without retraining.
#
# WHY PICKLE:
#   scikit-learn models are Python objects. Pickle is Python's built-in way
#   to serialise any object to bytes and write those bytes to a file.
#   The .pkl extension is the conventional name for pickle files.
#
# SECURITY NOTE:
#   Pickle files can execute arbitrary code if tampered with. The model file
#   sits in the project folder and should be treated like any other config file —
#   don't load .pkl files from untrusted sources.
# ---------------------------------------------------------------------------

def save_network_model(
        model: IsolationForest,
        path: Path = NETWORK_MODEL_PATH,
) -> bool:
    """
    Write the trained model to disk as a pickle file.

    Parameters:
        model - the trained IsolationForest returned by train_network_model()
        path  - where to save it (defaults to models/network_model.pkl)

    Returns:
        True if the file was written successfully, False if an OS error occurred.
    """
    try:
        # "wb" = write binary — pickle produces bytes, not text
        with open(path, "wb") as f:
            pickle.dump(model, f)
        print(f"[NET MODEL] Model saved to {path}")
        return True
    except OSError as e:
        print(f"[NET MODEL] Failed to save model: {e}")
        return False


def load_network_model(path: Path = NETWORK_MODEL_PATH) -> Optional[IsolationForest]:
    """
    Load a previously saved model from disk.

    Called by sentinel_network_monitor.py at agent startup so the model
    is ready before the first monitoring scan runs.

    Parameters:
        path - where to look for the model file (defaults to models/network_model.pkl)

    Returns:
        The loaded IsolationForest, or None if the file doesn't exist or is
        corrupted. The caller (sentinel_network_monitor.py) falls back to
        rule-based detection when None is returned — nothing breaks.
    """
    if not Path(path).exists():
        # No model on disk yet — this is expected on first run before
        # train_network_model.py has been executed.
        print("[NET MODEL] No saved model found — rule-based fallback will be used.")
        return None
    try:
        # "rb" = read binary
        with open(path, "rb") as f:
            model = pickle.load(f)
        print(f"[NET MODEL] Model loaded from {path}")
        return model
    except Exception as e:
        # Covers corrupt files, version mismatches, etc.
        # We never want a broken model file to crash the whole agent.
        print(f"[NET MODEL] Failed to load model ({e}) — rule-based fallback will be used.")
        return None

# ---------------------------------------------------------------------------
# SELF-TEST
#
# Run this file directly to train a fresh model from the current baseline
# and immediately verify it works:
#
#   python train_network_model.py
#
# WHAT THE SANITY CHECK TELLS YOU:
#   We score the same connections the model was trained on back through itself.
#   A good model should flag roughly contamination% of its own training data
#   (so ~5% with contamination=0.05). If it flags far more, the training data
#   itself is noisy. If it flags 0%, the threshold may be too loose.
#
#   Score range interpretation:
#     Positive score  → comfortably inside the normal cluster
#     Score near 0    → on the edge of normal
#     Negative score  → anomalous; the more negative, the more suspicious
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys as _sys
    from pathlib import Path as _Path
    _root = str(_Path(__file__).parent.parent)
    if _root not in _sys.path:
        _sys.path.insert(0, _root)
    from core.sentinel_baseline import load_baseline

    print("=" * 60)
    print("  Sentinel — Network Model Training Self-Test")
    print("=" * 60)

    # Load the baseline that was previously created by the agent.
    # If no baseline exists yet, tell the user to create one first.
    baseline = load_baseline()
    if baseline is None:
        print("\n[!] No baseline found on disk.")
        print("    Run 'baseline N' from the controller first, then retry.")
        raise SystemExit(1)

    # Train the model on the baseline network connections.
    model = train_network_model(baseline)
    if model is None:
        print("\n[!] Training failed — see messages above.")
        raise SystemExit(1)

    # Persist the trained model so sentinel_network_monitor.py can load it.
    saved = save_network_model(model)
    if not saved:
        print("\n[!] Could not save model to disk.")
        raise SystemExit(1)

    # ------------------------------------------------------------------
    # Sanity check: score the training connections back through the model.
    # This tells us whether the model is behaving sensibly before we
    # wire it into the live monitoring pipeline.
    # ------------------------------------------------------------------
    net   = baseline.get("network") or {}
    conns = net.get("connections") or []

    rows = []
    for conn in conns:
        rip   = conn.get("remote_ip")
        rport = conn.get("remote_port")
        proc  = conn.get("process")

        # Apply the same filters used during training so we compare apples to apples.
        if not rip or rport is None:
            continue
        if _is_private_ip(rip) and rip.startswith("127."):
            continue
        try:
            rows.append(_extract_connection_features(rip, int(rport), proc))
        except Exception:
            pass

    if rows:
        X = np.array(rows, dtype=float)

        # decision_function() returns a score per row:
        #   positive → normal, negative → anomalous
        scores = model.decision_function(X)

        # predict() returns +1 (normal) or -1 (anomaly) per row.
        labels = model.predict(X)

        flagged = int((labels == -1).sum())  # count anomalies

        print("\n--- Sanity check (baseline scored against itself) ---")
        print(f"  Connections scored : {len(rows)}")
        print(f"  Flagged anomalous  : {flagged}  ({100 * flagged / len(rows):.1f}%)")
        print(f"  Flagged normal     : {len(rows) - flagged}")
        print(f"  Score range        : {scores.min():.4f}  to  {scores.max():.4f}")
        print(f"  (contamination=0.05 means ~{int(len(rows) * 0.05)} flagged is expected)")

    print("\n[OK] Self-test complete.")
