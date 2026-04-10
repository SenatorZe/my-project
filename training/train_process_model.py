# train_process_model.py
# ----------------------
# ML model training for Sentinel process anomaly detection.
#
# WHY THIS FILE EXISTS:
#   The original sentinel_process_monitor.py flagged EVERY process whose
#   name+exe combination wasn't seen at baseline time. On a normal Windows
#   machine this fires constantly — app updates, background services, new
#   browser tabs spawning helpers, Python scripts — all generate alerts.
#
#   This file trains an Isolation Forest on the baseline process list.
#   Instead of asking "have I seen this exact process before?", the model
#   asks "do the CHARACTERISTICS of this process look normal?" — things like
#   where it lives on disk, what launched it, how word-like its name is, and
#   how much CPU it uses.
#
#   A new legitimate app installed in Program Files launched by explorer.exe
#   looks normal even if it wasn't there at baseline time — the model accepts
#   it. A random-named exe running from AppData\Local\Temp launched by
#   PowerShell looks nothing like the baseline cluster — the model flags it.
#
# HOW IT FITS INTO THE PROJECT:
#   1. After a baseline is created ('baseline N' in the controller), run
#      this file once to train and save the model  ->  models/process_model.pkl
#   2. sentinel_process_monitor.py imports load_process_model() and
#      _extract_process_features() from here, loads the model at agent
#      startup, and uses it to score every live process.
#
# CAN BE RUN DIRECTLY:
#   python train_process_model.py
#   Trains, saves, and runs a sanity-check against the baseline data.

from __future__ import annotations

import pickle                           # save/load model to/from disk
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional

_OS = platform.system()   # "Windows", "Darwin", or "Linux"

import numpy as np
from sklearn.ensemble import IsolationForest

# ---------------------------------------------------------------------------
# WHERE THE MODEL FILE LIVES
# Stored in the models/ subdirectory to keep the project root tidy.
#   C:\Users\senat\PycharmProjects\Sentinel\models\process_model.pkl
# ---------------------------------------------------------------------------
PROCESS_MODEL_PATH = Path(__file__).parent.parent / "models" / "process_model.pkl"

# Minimum baseline processes needed to train a meaningful model.
MIN_TRAINING_SAMPLES = 10

# ---------------------------------------------------------------------------
# ACCOUNT LISTS
#
# WHY WE CARE ABOUT USERNAME:
#   The account running a process tells us a lot about its legitimacy.
#   Core Windows services run as SYSTEM or LOCAL SERVICE — that's normal.
#   Malware often tries to run as the logged-in user to inherit their
#   permissions and blend in with user-launched processes.
#   Flagging the combination of "running as SYSTEM from a Temp folder"
#   is far more powerful than flagging either signal alone.
# ---------------------------------------------------------------------------

# Windows built-in service accounts — processes running as these are
# expected to be low-level OS components.
SYSTEM_ACCOUNTS = {
    "nt authority\\system",
    "nt authority\\localservice",
    "nt authority\\networkservice",
    "system",
}

# ---------------------------------------------------------------------------
# KNOWN LEGITIMATE PROCESS NAMES
#
# WHY THIS MATTERS:
#   Without this list, common processes like python.exe, cmd.exe, and
#   conhost.exe get flagged because their AppData paths or parent processes
#   look slightly unusual to the model. By explicitly marking well-known
#   process names as "known", we give the model a strong normalising signal
#   that overrides mild anomalies in other features.
#
#   This is NOT a whitelist — a known process can still be flagged if
#   other features are sufficiently anomalous (e.g. cmd.exe from a Temp
#   folder with a PowerShell parent scores high on many other features).
#   It's one feature among 17, not a bypass.
# ---------------------------------------------------------------------------
KNOWN_LEGITIMATE_PROCESSES = {
    # Core Windows system processes
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "taskhostw.exe", "taskeng.exe", "spoolsv.exe", "ctfmon.exe",
    "conhost.exe", "cmd.exe", "dllhost.exe", "msiexec.exe", "wuauclt.exe",
    "searchindexer.exe", "searchhost.exe", "sihost.exe", "fontdrvhost.exe",
    "audiodg.exe", "dashost.exe", "runtimebroker.exe", "settingsynchost.exe",
    "applicationframehost.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "systemsettings.exe", "securityhealthservice.exe",
    "msmpeng.exe", "nissrv.exe", "antimalwareserviceexecutable.exe",
    "wermgr.exe", "werfault.exe", "backgroundtaskhost.exe",
    "registry", "memory compression",

    # Common shells and runtimes
    "powershell.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "python.exe", "python3.exe", "pythonw.exe",
    "node.exe", "java.exe", "javaw.exe", "dotnet.exe",

    # Common browsers
    "chrome.exe", "brave.exe", "firefox.exe", "msedge.exe",
    "iexplore.exe", "opera.exe",

    # Common developer tools
    "code.exe", "code - insiders.exe", "pycharm64.exe", "idea64.exe",
    "webstorm64.exe", "datagrip64.exe", "clion64.exe", "rider64.exe",
    "jetbrains-toolbox.exe", "jetbrainsd.exe", "fsnotifier.exe",
    "git.exe", "git-remote-https.exe", "ssh.exe",

    # Common user applications
    "claude.exe", "ollama.exe", "ollama app.exe",
    "discord.exe", "slack.exe", "teams.exe", "zoom.exe",
    "spotify.exe", "steam.exe", "epicgameslauncher.exe",
    "onedrive.exe", "dropbox.exe",
    "winrar.exe", "7z.exe", "7zg.exe",
    "vlc.exe", "wmplayer.exe",

    # Common system utilities and drivers
    "igfxem.exe", "igfxhk.exe", "igfxtray.exe",  # Intel graphics
    "rzsdkserver.exe", "razer.exe",               # Razer peripherals
    "apoint.exe", "apmsgfwd.exe",                 # Dell touchpad
    "rtkngui64.exe", "rtkaudioservice64.exe",     # Realtek audio
    "xboxpcappft.exe", "gameinputsvc.exe",        # Xbox / Windows Gaming
    "utweb.exe",                                   # uTorrent Web
    "embeddings-server.exe",                       # JetBrains AI
    "figma_agent.exe",                             # Figma
    "fdm.exe",                                     # Free Download Manager
}

# ---------------------------------------------------------------------------
# PARENT PROCESS LISTS
#
# WHY WE CARE ABOUT THE PARENT:
#   The parent process tells us HOW something was launched.
#   Most user-facing apps are launched by explorer.exe (you double-clicked them).
#   System services are typically launched by services.exe or svchost.exe.
#   When something is launched by cmd.exe, powershell.exe, or wscript.exe
#   it means it was spawned by a script — which is worth noting.
#   Malware often uses PowerShell or WScript as a launchpad.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# PARENT PROCESS LISTS
#
# WHY WE CARE ABOUT THE PARENT:
#   The parent process tells us HOW something was launched.
#   Most user-facing apps are launched by explorer.exe (you double-clicked them).
#   System services are typically launched by services.exe or svchost.exe.
#   When something is launched by cmd.exe, powershell.exe, or wscript.exe
#   it means it was spawned by a script — which is worth noting.
#   Malware often uses PowerShell or WScript as a launchpad.
# ---------------------------------------------------------------------------

# Processes that commonly and legitimately spawn child processes via scripts.
# Being launched by one of these is a mild signal, not a hard rule.
SHELL_PROCESSES = {
    "cmd.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "wscript.exe",       # Windows Script Host — runs .vbs/.js files
    "cscript.exe",       # Command-line Windows Script Host
    "mshta.exe",         # Microsoft HTML Application Host — runs .hta files
    "bash.exe",          # WSL bash
}

# Windows service host processes — they legitimately spawn many background
# services. A process launched by one of these is a normal service, not a threat.
SERVICE_HOST_PROCESSES = {
    "services.exe",   # Service Control Manager — top-level service launcher
    "svchost.exe",    # Generic service host — runs most Windows background services
    "lsass.exe",      # Local Security Authority — spawns credential helpers
    "wininit.exe",    # Windows Initialization — spawns early boot services
}

# PowerShell obfuscation markers in the command line.
# These appear in living-off-the-land attacks and malicious scripts.
# Legitimate use of -EncodedCommand is extremely rare in normal user sessions.
OBFUSCATION_MARKERS = [
    "-enc ",           # short form of -EncodedCommand
    "-encodedcommand", # full form
    "iex(",            # Invoke-Expression — used to execute downloaded code
    "invoke-expression",
    "frombase64string(",  # [System.Convert]::FromBase64String — classic obfuscation
    "::frombase64",
    "hidden -",        # -WindowStyle Hidden — hides a shell window from the user
    "-nop -",          # -NoProfile combined with other flags — common in malware stagers
    "downloadstring(", # (New-Object Net.WebClient).DownloadString() — downloads+runs code
    "downloadfile(",   # similar download-and-execute pattern
    "webclient",       # Net.WebClient — used for in-memory payload delivery
]

# ---------------------------------------------------------------------------
# FEATURE HELPERS
# ---------------------------------------------------------------------------

def _name_vowel_ratio(name: str) -> float:
    """
    Return the fraction of vowels in a process name (0.0 to 1.0).
    Strips the .exe extension first.

    WHY THIS MATTERS:
        Malware authors frequently use randomly generated names like
        "bqzfn.exe" or "xk3jlq.exe" to evade signature-based detection.
        Real software names are human-readable words or abbreviations
        and almost always contain vowels: "chrome", "svchost", "python".

        A vowel ratio of 0.0 means NO vowels — highly suspicious.
        A ratio of 0.3-0.5 is typical for legitimate software.

    Examples:
        "explorer"  -> 4 vowels / 8 chars  = 0.50
        "svchost"   -> 1 vowel  / 7 chars  = 0.14
        "bqzfnk"    -> 0 vowels / 6 chars  = 0.00
    """
    name = (name or "").lower().replace(".exe", "").strip()
    if not name:
        return 0.0
    vowels = sum(1 for c in name if c in "aeiou")
    return vowels / len(name)


def _name_digit_ratio(name: str) -> float:
    """
    Return the fraction of digit characters in a process name (0.0 to 1.0).
    Strips .exe first.

    WHY THIS MATTERS:
        Randomly generated malware names often mix letters and numbers
        heavily: "svc32fk3.exe", "win64ab7.exe". Real software names use
        digits sparingly — usually just a version suffix like "pycharm64"
        or "python312". A high digit ratio (above ~0.3) is suspicious.

    Examples:
        "explorer"   -> 0 digits / 8 chars = 0.00
        "pycharm64"  -> 2 digits / 9 chars = 0.22
        "svc32fk3"   -> 3 digits / 8 chars = 0.38  (suspicious)
    """
    name = (name or "").lower().replace(".exe", "").strip()
    if not name:
        return 0.0
    digits = sum(1 for c in name if c.isdigit())
    return digits / len(name)


def _name_length_norm(name: str) -> float:
    """
    Return the length of a process name normalised to 0.0-1.0.
    Strips .exe and caps at 25 characters.

    WHY THIS MATTERS:
        Real software names cluster in a typical length range (4-15 chars).
        Very short names (<3 chars) can indicate random generation.
        Very long names (>20 chars) are also unusual for executables.
        By normalising we give the model a smooth numeric signal rather
        than a raw integer that could dominate other features.

    Examples:
        "a"          -> 1 / 25 = 0.04  (suspiciously short)
        "svchost"    -> 7 / 25 = 0.28  (normal)
        "explorer"   -> 8 / 25 = 0.32  (normal)
        "a1b2c3d4e5f6g7h8i9j0" -> capped at 1.0 (suspiciously long)
    """
    name = (name or "").lower().replace(".exe", "").strip()
    return min(len(name) / 25.0, 1.0)


def _name_rare_letter_ratio(name: str) -> float:
    """
    Return the fraction of rare English letters (z, x, j, k, q) in
    a process name (0.0 to 1.0). Strips .exe first.

    WHY THIS MATTERS:
        Randomly generated strings over-represent rare letters because
        all characters are equally likely. In real English words, z/x/j/k/q
        appear far less often than a/e/t/s/n. A process name heavy with
        these letters is statistically unlikely to be a real word.

    Examples:
        "explorer"  -> 0 rare letters / 8 chars = 0.00
        "xk3jlqz"   -> 4 rare letters / 7 chars = 0.57
    """
    name = (name or "").lower().replace(".exe", "").strip()
    if not name:
        return 0.0
    rare = sum(1 for c in name if c in "zxjkq")
    return rare / len(name)


def _has_cmdline_obfuscation(cmdline) -> float:
    """
    Return 1.0 if the process command line contains known PowerShell obfuscation
    or living-off-the-land markers; 0.0 otherwise.

    WHY THIS MATTERS:
        Malware that runs PowerShell stagers almost always uses -EncodedCommand
        or Invoke-Expression to hide the real payload from plain-text scanning.
        Legitimate scripts and interactive shells essentially never use these
        patterns in their argv — so this is a very low false-positive signal.

    cmdline is either a list of strings (from psutil.cmdline()) or None.
    We join it and lowercase before checking.
    """
    if not cmdline:
        return 0.0
    if isinstance(cmdline, list):
        joined = " ".join(str(x) for x in cmdline).lower()
    else:
        joined = str(cmdline).lower()

    for marker in OBFUSCATION_MARKERS:
        if marker in joined:
            return 1.0
    return 0.0


def _extract_process_features(proc: Dict[str, Any]) -> List[float]:
    """
    Convert one process info dict into a fixed-length numeric feature vector.

    WHY WE DO THIS:
        The Isolation Forest only understands numbers. This function is the
        bridge — it reads the raw process dict (name, exe, username, parent)
        and produces 12 numbers that capture the process's behaviour profile.

        The same function is called during training (on baseline processes)
        and during live monitoring. The model compares the live vector to
        the cluster it learned at training time.

    FIELD COMPATIBILITY:
        The baseline stores processes with keys: name, exe, username, parent_name
        The live monitor (_build_process_info) also uses these same keys.
        Both are handled identically here.

    Returns a list of exactly 19 floats, always in the same order:
        [0]  is_system_dir          — exe lives under C:\\Windows\\
        [1]  is_program_files       — exe lives under C:\\Program Files
        [2]  is_temp_dir            — exe lives in a Temp/Tmp folder (red flag)
        [3]  is_appdata_programs    — exe in AppData\\Local\\Programs or Roaming (legit install)
        [4]  is_appdata_other       — exe in AppData but NOT Programs/Temp (mild signal)
        [5]  is_windows_special     — exe in WindowsApps or DriverStore (MS system paths)
        [6]  path_depth             — how many folders deep the exe is
        [7]  name_vowel_ratio       — fraction of vowels in process name (0-1)
        [8]  name_rare_ratio        — fraction of rare letters z/x/j/k/q (0-1)
        [9]  name_digit_ratio       — fraction of digits in process name (0-1)
        [10] name_length_norm       — normalised name length (len/25, capped at 1)
        [11] is_known_process       — name is in KNOWN_LEGITIMATE_PROCESSES list
        [12] is_system_account      — running as SYSTEM/LocalService/etc
        [13] parent_is_explorer     — launched by explorer.exe (normal user app)
        [14] parent_is_shell        — launched by cmd/powershell/wscript
        [15] cpu_percent            — current CPU usage (0-100)
        [16] has_no_exe             — exe path is None/empty (kernel processes)
        [17] parent_is_service      — launched by services.exe/svchost.exe (legit service)
        [18] cmdline_obfuscation    — cmdline contains PowerShell obfuscation markers
    """
    name        = (proc.get("name") or "").lower()
    # Normalise to forward slashes so the same keyword checks work on
    # Windows, macOS, and Linux without separate branches below.
    exe         = (proc.get("exe") or "").lower().replace("\\", "/")
    username    = (proc.get("username") or "").lower()
    parent_name = (proc.get("parent_name") or "").lower()
    cpu         = proc.get("cpu_percent") or 0.0
    cmdline     = proc.get("cmdline")

    # ------------------------------------------------------------------
    # EXE LOCATION FEATURES
    # Where on disk does this process live?
    # Path strings use forward slashes on all platforms after normalisation.
    # ------------------------------------------------------------------

    if _OS == "Windows":
        is_system_dir       = 1.0 if "/windows/" in exe else 0.0
        is_program_files    = 1.0 if "program files" in exe else 0.0
        is_temp_dir         = 1.0 if ("/appdata/local/temp/" in exe or "/temp/" in exe or "/tmp/" in exe) else 0.0
        is_appdata_programs = 1.0 if (
            "/appdata/local/programs/" in exe or
            "/appdata/roaming/" in exe or
            "/appdata/local/jetbrains/" in exe
        ) else 0.0
        is_appdata_other    = 1.0 if (
            "/appdata/" in exe and
            "/temp/" not in exe and
            "/appdata/local/programs/" not in exe and
            "/appdata/roaming/" not in exe and
            "/appdata/local/jetbrains/" not in exe
        ) else 0.0
        is_windows_special  = 1.0 if ("/windowsapps/" in exe or "/driverstore/" in exe) else 0.0

    elif _OS == "Darwin":   # macOS
        is_system_dir       = 1.0 if (
            exe.startswith("/usr/") or exe.startswith("/bin/") or
            exe.startswith("/sbin/") or exe.startswith("/system/")
        ) else 0.0
        is_program_files    = 1.0 if ("/applications/" in exe or "/usr/local/" in exe) else 0.0
        is_temp_dir         = 1.0 if ("/tmp/" in exe or "/var/tmp/" in exe) else 0.0
        is_appdata_programs = 1.0 if ("/.local/share/" in exe or "/library/" in exe) else 0.0
        is_appdata_other    = 1.0 if ("/.config/" in exe) else 0.0
        is_windows_special  = 0.0   # not applicable on macOS

    else:   # Linux
        is_system_dir       = 1.0 if (
            exe.startswith("/usr/") or exe.startswith("/bin/") or
            exe.startswith("/sbin/") or exe.startswith("/lib/")
        ) else 0.0
        is_program_files    = 1.0 if ("/opt/" in exe or "/usr/local/" in exe) else 0.0
        is_temp_dir         = 1.0 if ("/tmp/" in exe or "/var/tmp/" in exe or "/dev/shm/" in exe) else 0.0
        is_appdata_programs = 1.0 if ("/.local/" in exe or "/.config/" in exe) else 0.0
        is_appdata_other    = 0.0   # Linux doesn't have an AppData equivalent
        is_windows_special  = 0.0

    # How deep in the directory tree is this exe?
    # System processes tend to be shallow; malware can be buried many levels deep.
    path_depth = float(exe.count("/")) if exe else 0.0

    # ------------------------------------------------------------------
    # NAME FEATURES
    # What does the process name tell us?
    # ------------------------------------------------------------------

    name_vowel_ratio = _name_vowel_ratio(name)
    name_rare_ratio  = _name_rare_letter_ratio(name)

    # Fraction of digits in the name — randomly generated names mix in
    # numbers heavily (e.g. "svc32fk3"). Real names use digits sparingly.
    name_digit_ratio = _name_digit_ratio(name)

    # Normalised name length — very short or very long names are unusual.
    name_length_norm = _name_length_norm(name)

    # Is this a well-known legitimate process name?
    # This gives a strong normalising signal for common processes that might
    # otherwise look borderline due to AppData paths or shell parents.
    # It is ONE feature among 17 — not a bypass of the other signals.
    is_known_process = 1.0 if name in KNOWN_LEGITIMATE_PROCESSES else 0.0

    # ------------------------------------------------------------------
    # ACCOUNT FEATURE
    # Who is this process running as?
    # ------------------------------------------------------------------

    is_system_account = 1.0 if username in SYSTEM_ACCOUNTS else 0.0

    # ------------------------------------------------------------------
    # PARENT PROCESS FEATURES
    # How was this process launched?
    # ------------------------------------------------------------------

    parent_is_explorer = 1.0 if parent_name == "explorer.exe" else 0.0

    # Script interpreters as parents — ransomware and RATs often use
    # PowerShell or WScript as their launchpad.
    parent_is_shell = 1.0 if parent_name in SHELL_PROCESSES else 0.0

    # Windows service infrastructure as parent — svchost.exe and services.exe
    # legitimately spawn hundreds of background services. A process whose
    # parent is one of these is almost certainly a normal Windows service,
    # not a threat. Without this feature the model sees an AppData exe with
    # an unusual parent and flags it; with it, the pattern is recognised as
    # the normal service-launch path.
    parent_is_service = 1.0 if parent_name in SERVICE_HOST_PROCESSES else 0.0

    # ------------------------------------------------------------------
    # RESOURCE FEATURE
    # ------------------------------------------------------------------

    try:
        cpu_val = float(cpu)
    except (TypeError, ValueError):
        cpu_val = 0.0

    # ------------------------------------------------------------------
    # KERNEL / NO-EXE FEATURE
    # System, Idle, and kernel threads have no exe path.
    # These are normal and the model should group them together.
    # ------------------------------------------------------------------
    has_no_exe = 1.0 if not exe else 0.0

    # ------------------------------------------------------------------
    # OBFUSCATION FEATURE
    # Detect PowerShell obfuscation markers in the command line.
    # Legitimate processes essentially never use -EncodedCommand or iex()
    # in their argv. When present, this is a strong single indicator.
    # ------------------------------------------------------------------
    cmdline_obf = _has_cmdline_obfuscation(cmdline)

    return [
        is_system_dir,          # [0]   exe in C:\Windows\
        is_program_files,       # [1]   exe in Program Files
        is_temp_dir,            # [2]   exe in Temp (strong red flag)
        is_appdata_programs,    # [3]   exe in AppData\Programs or Roaming (legit install)
        is_appdata_other,       # [4]   exe in AppData but not Programs (mild signal)
        is_windows_special,     # [5]   exe in WindowsApps or DriverStore
        path_depth,             # [6]   directory depth of exe
        name_vowel_ratio,       # [7]   vowel fraction (low = suspicious)
        name_rare_ratio,        # [8]   rare letter fraction (high = suspicious)
        name_digit_ratio,       # [9]   digit fraction (high = suspicious)
        name_length_norm,       # [10]  normalised name length
        is_known_process,       # [11]  name in known-legitimate list
        is_system_account,      # [12]  running as SYSTEM/LocalService
        parent_is_explorer,     # [13]  launched by explorer.exe
        parent_is_shell,        # [14]  launched by cmd/powershell/wscript
        cpu_val,                # [15]  CPU usage %
        has_no_exe,             # [16]  no exe path (kernel process)
        parent_is_service,      # [17]  launched by services.exe/svchost (legit service)
        cmdline_obf,            # [18]  cmdline has obfuscation markers (red flag)
    ]

# ---------------------------------------------------------------------------
# MODEL TRAINING
#
# HOW ISOLATION FOREST WORKS (brief recap):
#   It builds random decision trees. Normal processes sit in a dense cluster
#   and take many splits to isolate. Anomalous processes sit far from the
#   cluster and get isolated in very few splits. The fewer splits needed,
#   the more anomalous the score.
#
# WHY contamination=0.05:
#   We assume at most 5% of baseline processes are already borderline unusual.
#   With 321 baseline processes that's about 16 — which is realistic given that
#   some background processes may already have odd characteristics.
#   This gives the model a useful decision boundary without being too strict.
# ---------------------------------------------------------------------------

def train_process_model(baseline: Dict[str, Any]) -> Optional[IsolationForest]:
    """
    Train an Isolation Forest on the process list in the baseline.

    Parameters:
        baseline - the full baseline dict from load_baseline() /
                   collect_full_baseline()

    Returns:
        A trained IsolationForest, or None if there aren't enough samples.
    """
    processes = baseline.get("processes") or []

    if not processes:
        print("[PROC MODEL] No processes found in baseline — cannot train.")
        return None

    rows: List[List[float]] = []

    for proc in processes:
        # Skip processes with no meaningful information — they'd all produce
        # identical zero vectors and skew the model.
        if not proc.get("name"):
            continue

        features = _extract_process_features(proc)
        rows.append(features)

    if len(rows) < MIN_TRAINING_SAMPLES:
        print(
            f"[PROC MODEL] Only {len(rows)} usable processes in baseline "
            f"(minimum {MIN_TRAINING_SAMPLES}) — skipping training."
        )
        return None

    # Convert list of rows into a 2D NumPy matrix.
    # Shape: (number_of_processes, 12)
    X = np.array(rows, dtype=float)

    print(f"[PROC MODEL] Training Isolation Forest on {len(rows)} baseline processes...")

    model = IsolationForest(
        n_estimators=200,   # more trees than the network model because the
                            # process feature space is larger and more varied
        contamination=0.05, # ~5% of baseline may already be borderline unusual
        random_state=42,    # fixed seed for reproducible results
    )

    # .fit() builds all 200 trees over the training data.
    # After this the model knows what a "normal" process profile looks like
    # for this specific machine.
    model.fit(X)

    print("[PROC MODEL] Training complete.")
    return model

# ---------------------------------------------------------------------------
# SAVE / LOAD
# ---------------------------------------------------------------------------

def save_process_model(
        model: IsolationForest,
        path: Path = PROCESS_MODEL_PATH,
) -> bool:
    """
    Persist the trained model to disk using pickle.
    Returns True on success, False on failure.
    """
    try:
        with open(path, "wb") as f:
            pickle.dump(model, f)
        print(f"[PROC MODEL] Model saved to {path}")
        return True
    except OSError as e:
        print(f"[PROC MODEL] Failed to save model: {e}")
        return False


def load_process_model(path: Path = PROCESS_MODEL_PATH) -> Optional[IsolationForest]:
    """
    Load a previously saved process model from disk.

    Returns the model if found and valid, None otherwise.
    The caller (sentinel_process_monitor.py) falls back to rule-based
    detection when None is returned — nothing breaks.
    """
    if not Path(path).exists():
        print("[PROC MODEL] No saved model found — rule-based fallback will be used.")
        return None
    try:
        with open(path, "rb") as f:
            model = pickle.load(f)
        print(f"[PROC MODEL] Model loaded from {path}")
        return model
    except Exception as e:
        print(f"[PROC MODEL] Failed to load model ({e}) — rule-based fallback will be used.")
        return None

# ---------------------------------------------------------------------------
# SELF-TEST  (python train_process_model.py)
#
# WHAT THE SANITY CHECK TELLS YOU:
#   We score the baseline processes back through the model.
#   A well-trained model should flag roughly contamination% of its own
#   training data (~5% = ~16 processes out of 321).
#   Score range: positive = comfortably normal, negative = anomalous.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys as _sys
    from pathlib import Path as _Path
    _root = str(_Path(__file__).parent.parent)
    if _root not in _sys.path:
        _sys.path.insert(0, _root)
    from core.sentinel_baseline import load_baseline

    print("=" * 60)
    print("  Sentinel — Process Model Training Self-Test")
    print("=" * 60)

    baseline = load_baseline()
    if baseline is None:
        print("\n[!] No baseline found on disk.")
        print("    Run 'baseline N' from the controller first, then retry.")
        raise SystemExit(1)

    model = train_process_model(baseline)
    if model is None:
        print("\n[!] Training failed — see messages above.")
        raise SystemExit(1)

    saved = save_process_model(model)
    if not saved:
        print("\n[!] Could not save model to disk.")
        raise SystemExit(1)

    # ------------------------------------------------------------------
    # Sanity check: score all baseline processes through the model.
    # ------------------------------------------------------------------
    processes = baseline.get("processes") or []
    rows = []
    names = []

    for proc in processes:
        if not proc.get("name"):
            continue
        rows.append(_extract_process_features(proc))
        names.append(proc.get("name", "unknown"))

    if rows:
        X      = np.array(rows, dtype=float)
        scores = model.decision_function(X)
        labels = model.predict(X)
        flagged_idx = [i for i, l in enumerate(labels) if l == -1]
        flagged = len(flagged_idx)

        print("\n--- Sanity check (baseline scored against itself) ---")
        print(f"  Processes scored   : {len(rows)}")
        print(f"  Flagged anomalous  : {flagged}  ({100 * flagged / len(rows):.1f}%)")
        print(f"  Flagged normal     : {len(rows) - flagged}")
        print(f"  Score range        : {scores.min():.4f}  to  {scores.max():.4f}")
        print(f"  (contamination=0.05 means ~{int(len(rows) * 0.05)} flagged is expected)")

        if flagged_idx:
            print("\n  Processes the model already finds borderline in the baseline:")
            for i in flagged_idx[:10]:   # show at most 10
                print(f"    score={scores[i]:.4f}  {names[i]}")

    print("\n[OK] Self-test complete.")
