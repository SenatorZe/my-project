# test_network_model.py
# ---------------------
# Safe, evidence-based test that proves the full detection system works.
#
# THE LAYERED ARCHITECTURE:
#   Detection is not done by ML alone. It uses two layers:
#
#   LAYER 1 — Hard rules (always fire, no model needed):
#       - Connection to a known C2/malware port (SUSPICIOUS_PORTS)
#       - Executable running from a Temp folder to a public IP
#
#   LAYER 2 — ML model (Isolation Forest):
#       - Catches the gray area that hard rules don't cover
#       - Flags unusual COMBINATIONS of features (wrong process for the port,
#         unusual exe location, random-looking process names, etc.)
#       - System services on well-known ports are EXEMPT from ML scoring
#         because those are expected OS behaviour that the small training set
#         tends to flag as borderline
#
#   This mirrors how real security tools work: tight deterministic rules for
#   high-confidence threats, ML for the subtler patterns.
#
# TWO TESTS:
#   TEST 1 — ML unit test: what does the raw model say about each connection?
#   TEST 2 — Pipeline test: does the full detect_suspicious_connections() flag
#             the right things using both layers together?
#
# HOW TO RUN:
#   python test_network_model.py
#
# REQUIREMENTS:
#   - sentinel_baseline.json must exist
#   - models/network_model.pkl must exist
#   Run train_network_model.py first if either is missing.

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import numpy as np

# Ensure the project root is on sys.path so package imports resolve when
# this file is run directly (python tests/test_network_model.py).
_root = str(Path(__file__).parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from training.train_network_model import load_network_model, _extract_connection_features
from monitors.sentinel_network_monitor import detect_suspicious_connections

# ---------------------------------------------------------------------------
# TEST 1 CASES — pure ML scoring
#
# These test what the Isolation Forest model says about each connection
# IN ISOLATION — before hard rules or exemptions are applied.
#
# "caught_by" tells us which layer is responsible for the final outcome
# in the real pipeline, so the test expectations are honest.
# ---------------------------------------------------------------------------

ML_TEST_CASES = [
    # ------------------------------------------------------------------
    # Cases the ML model should pass (score > 0 = inside normal cluster)
    # ------------------------------------------------------------------
    {
        "label":      "Brave browser -> Google HTTPS",
        "expected":   "normal",
        "caught_by":  "n/a — genuinely normal",
        "rip":        "142.250.80.46",
        "rport":      443,
        "pinfo": {
            "name":     "brave.exe",
            "exe":      "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
            "username": "SENATOR\\senat",
        },
    },
    {
        "label":      "Python script -> local network",
        "expected":   "normal",
        "caught_by":  "n/a — genuinely normal",
        "rip":        "192.168.0.1",
        "rport":      80,
        "pinfo": {
            "name":     "python.exe",
            "exe":      "C:\\Users\\senat\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
            "username": "SENATOR\\senat",
        },
    },

    # ------------------------------------------------------------------
    # Cases the ML model should flag (score < 0 = outside normal cluster)
    # These are caught by the ML layer in the full pipeline.
    # ------------------------------------------------------------------
    {
        "label":      "Brave browser -> C2 port 1337 (hijacked browser)",
        "expected":   "anomalous",
        "caught_by":  "ML + hard rule (suspicious port)",
        "rip":        "185.220.101.45",
        "rport":      1337,
        "pinfo": {
            "name":     "brave.exe",
            "exe":      "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
            "username": "SENATOR\\senat",
        },
    },
    # ------------------------------------------------------------------
    # Cases caught by HARD RULES, not ML.
    # The ML score may be positive here — that is expected and correct.
    # The full pipeline catches them via Layer 1 before ML even runs.
    # ------------------------------------------------------------------
    {
        "label":      "Random exe from Temp -> port 4444 [HARD RULE: suspicious port + temp]",
        "expected":   "hard_rule",   # not an ML catch — Layer 1 fires first
        "caught_by":  "hard rules: SUSPICIOUS_PORTS + proc_from_temp",
        "rip":        "5.188.206.14",
        "rport":      4444,
        "pinfo": {
            "name":     "xk3jlq.exe",
            "exe":      "C:\\Users\\senat\\AppData\\Local\\Temp\\xk3jlq.exe",
            "username": "SENATOR\\senat",
        },
    },
    {
        "label":      "Vowel-less exe from Temp -> port 8888 [HARD RULE: proc_from_temp]",
        "expected":   "hard_rule",
        "caught_by":  "hard rule: proc_from_temp + public IP",
        "rip":        "91.220.101.45",
        "rport":      8888,
        "pinfo": {
            "name":     "svcfk32.exe",
            "exe":      "C:\\Users\\senat\\AppData\\Local\\Temp\\svcfk32.exe",
            "username": "SENATOR\\senat",
        },
    },
    # ------------------------------------------------------------------
    # Cases EXEMPTED from ML scoring (system services on well-known ports).
    # The ML may score these as borderline anomalous due to limited
    # training data — but the monitor skips ML for this category.
    # They do not raise alerts in the full pipeline.
    # ------------------------------------------------------------------
    {
        "label":      "svchost -> Microsoft HTTPS [EXEMPT: system service on well-known port]",
        "expected":   "exempt",
        "caught_by":  "n/a — exempted from ML, no hard rule fires",
        "rip":        "20.189.173.17",
        "rport":      443,
        "pinfo": {
            "name":     "svchost.exe",
            "exe":      "C:\\Windows\\System32\\svchost.exe",
            "username": "NT AUTHORITY\\SYSTEM",
        },
    },
]


def divider(char="-", width=70):
    print(char * width)


# ---------------------------------------------------------------------------
# TEST 1 — ML unit test
# ---------------------------------------------------------------------------

def run_unit_test(model) -> tuple[int, int]:
    """
    Score each case directly through the model and verify the result
    matches what we expect from the ML layer alone.

    Cases marked 'hard_rule' or 'exempt' are scored for visibility
    but are not counted as ML pass/fail — they're handled by other layers.
    """
    print("\n" + "=" * 70)
    print("  TEST 1 — ML unit test: raw Isolation Forest scoring")
    print("=" * 70)
    print(
        "  Scores each connection through the model directly.\n"
        "  Score > 0  = inside normal cluster (model says normal)\n"
        "  Score < 0  = outside cluster (model says anomalous)\n"
        "  Cases marked [HARD RULE] or [EXEMPT] are NOT counted in pass/fail\n"
        "  because those cases are handled by a different layer.\n"
    )

    passed = 0
    total  = 0   # only count ML-layer cases

    for case in ML_TEST_CASES:
        divider()
        print(f"  Connection : {case['label']}")
        print(f"  Expected   : {case['expected'].upper()}   (caught by: {case['caught_by']})")
        print(f"  Remote     : {case['rip']}:{case['rport']}")
        print(f"  Process    : {case['pinfo']['name']}  ({case['pinfo']['exe']})")

        features = _extract_connection_features(case["rip"], case["rport"], case["pinfo"])
        feature_names = [
            "is_well_known_port", "is_suspicious_port", "is_high_port",
            "is_private_ip", "proc_is_browser", "proc_is_system",
            "proc_from_pgf", "proc_from_temp", "vowel_ratio",
            "browser_non_web", "system_to_public",
            "proc_from_appdata_programs", "proc_is_known",
        ]
        print("  Features   :", end="")
        for name, val in zip(feature_names, features):
            print(f"\n               {name:<24} = {round(val, 4)}")

        X     = np.array(features, dtype=float).reshape(1, -1)
        score = model.decision_function(X)[0]
        label = model.predict(X)[0]
        ml_result = "anomalous" if label == -1 else "normal"

        print(f"\n  ML Score   : {score:.4f}  (more negative = more suspicious)")
        print(f"  ML Label   : {label}  (+1 = normal, -1 = anomaly)")
        print(f"  ML Result  : {ml_result.upper()}")

        # Only evaluate pass/fail for cases the ML layer is responsible for.
        expected = case["expected"]
        if expected in ("hard_rule", "exempt"):
            print(f"  Test       : SKIP — handled by {'hard rules' if expected == 'hard_rule' else 'ML exemption'}, not raw ML scoring")
        else:
            total += 1
            ok = (ml_result == expected)
            print(f"  Test       : {'PASS [OK]' if ok else 'FAIL [!!]'}  (expected ML to say {expected.upper()})")
            if ok:
                passed += 1

    divider()
    print(f"\n  ML unit test result: {passed}/{total} ML-layer cases passed\n")
    return passed, total


# ---------------------------------------------------------------------------
# TEST 2 — Pipeline test: the full detect_suspicious_connections()
# ---------------------------------------------------------------------------

def _make_fake_conn(rip, rport, pid, status="ESTABLISHED"):
    conn        = MagicMock()
    conn.raddr  = MagicMock()
    conn.raddr.ip   = rip
    conn.raddr.port = rport
    conn.laddr  = MagicMock()
    conn.laddr.ip   = "192.168.0.24"
    conn.laddr.port = 50000
    conn.pid    = pid
    conn.status = status
    conn.type   = 1
    return conn


def run_pipeline_test(model) -> tuple[int, int]:
    """
    Inject a controlled set of fake connections and verify the full
    detect_suspicious_connections() flags exactly the right ones.

    This covers both layers:
      - PID 1001: Brave on 443       -> should NOT alert (normal)
      - PID 1002: xk3jlq from Temp on 4444 -> should alert (hard rules: suspicious port + temp)
      - PID 1003: svcfk32 from Temp on 8888 -> should alert (hard rule: temp + public IP)
      - PID 1004: Brave on 1337      -> should alert (ML: browser on C2 port)
      - PID 1005: svchost on 443     -> should NOT alert (exempted from ML)
    """
    print("\n" + "=" * 70)
    print("  TEST 2 — Pipeline test: full detect_suspicious_connections()")
    print("=" * 70)
    print(
        "  Injects 5 fake connections via monkey-patching psutil.\n"
        "  Verifies the correct ones are flagged across both layers.\n"
    )

    fake_conns = [
        _make_fake_conn("142.250.80.46",   443,  pid=1001),  # normal
        _make_fake_conn("5.188.206.14",   4444,  pid=1002),  # hard rule
        _make_fake_conn("91.220.101.45",  8888,  pid=1003),  # hard rule
        _make_fake_conn("185.220.101.45", 1337,  pid=1004),  # ML + hard rule
        _make_fake_conn("20.189.173.17",   443,  pid=1005),  # exempt
    ]

    fake_procs = {
        1001: {"name": "brave.exe",    "exe": "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", "username": "SENATOR\\senat", "pid": 1001},
        1002: {"name": "xk3jlq.exe",  "exe": "C:\\Users\\senat\\AppData\\Local\\Temp\\xk3jlq.exe",                      "username": "SENATOR\\senat", "pid": 1002},
        1003: {"name": "svcfk32.exe", "exe": "C:\\Users\\senat\\AppData\\Local\\Temp\\svcfk32.exe",                      "username": "SENATOR\\senat", "pid": 1003},
        1004: {"name": "brave.exe",    "exe": "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", "username": "SENATOR\\senat", "pid": 1004},
        1005: {"name": "svchost.exe",  "exe": "C:\\Windows\\System32\\svchost.exe",                                       "username": "NT AUTHORITY\\SYSTEM", "pid": 1005},
    }

    cfg = {
        "enable_network_monitor":         True,
        "network_ip_whitelist":           [],
        "network_dns_lookup_enabled":     False,
        "network_alert_cooldown_seconds": 0,
        "agent_id":                       "test-agent",
        "display_name":                   "Test Agent",
    }
    baseline = {"network": {"connections": [], "listening_ports": []}}

    with patch("monitors.sentinel_network_monitor.psutil.net_connections", return_value=fake_conns), \
         patch("monitors.sentinel_network_monitor._proc_info_for_pid",
               side_effect=lambda pid: fake_procs.get(pid, {"pid": pid})):
        alerts = detect_suspicious_connections(cfg, baseline, model=model)

    alerted_pids = set()
    for alert in alerts:
        proc = alert.get("process") or {}
        alerted_pids.add(proc.get("pid"))

    # Print what came back
    divider()
    print("  Injected connections:")
    print("    PID 1001  brave.exe      port 443   -> expected: NO alert  (normal)")
    print("    PID 1002  xk3jlq.exe     port 4444  -> expected: ALERT     (hard rule)")
    print("    PID 1003  svcfk32.exe    port 8888  -> expected: ALERT     (hard rule)")
    print("    PID 1004  brave.exe      port 1337  -> expected: ALERT     (hard rule)")
    print("    PID 1005  svchost.exe    port 443   -> expected: NO alert  (exempt)")
    divider()
    print(f"\n  Alerts raised: {len(alerts)}")
    for alert in alerts:
        proc = alert.get("process") or {}
        print(f"    -> {alert.get('summary'):<45}  severity={alert.get('severity')}  reasons={alert.get('reasons')}")

    # Assertions
    cases = [
        (1001, False, "Brave on 443        (should be NO alert)"),
        (1002, True,  "xk3jlq on 4444     (should alert — hard rule)"),
        (1003, True,  "svcfk32 on 8888    (should alert — hard rule)"),
        (1004, True,  "Brave on 1337      (should alert — hard rule)"),
        (1005, False, "svchost on 443     (should be NO alert — exempt)"),
    ]

    passed = 0
    print()
    for pid, expect_alert, description in cases:
        actual = pid in alerted_pids
        ok     = (actual == expect_alert)
        status = "PASS [OK]" if ok else "FAIL [!!]"
        print(f"  {status}  PID {pid}  {description}")
        if ok:
            passed += 1

    total = len(cases)
    divider()
    print(f"\n  Pipeline test result: {passed}/{total} passed\n")
    return passed, total


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  Sentinel — Network Detection Test Suite")
    print("=" * 70)
    print(
        "\n  This test validates the full two-layer detection system:\n"
        "    Layer 1: Hard rules  (suspicious ports, exe from Temp folder)\n"
        "    Layer 2: ML model    (Isolation Forest — catches gray area)\n"
    )

    model = load_network_model()
    if model is None:
        print("\n[!] No trained model found.")
        print("    Run:  python train_network_model.py  first.")
        sys.exit(1)

    print("  Model loaded successfully.\n")

    u_pass, u_total = run_unit_test(model)
    p_pass, p_total = run_pipeline_test(model)

    total_pass  = u_pass + p_pass
    total_tests = u_total + p_total

    print("=" * 70)
    print(f"  OVERALL: {total_pass}/{total_tests} tests passed")
    if total_pass == total_tests:
        print("  ALL TESTS PASSED — detection system working correctly.")
    else:
        print("  SOME TESTS FAILED — review output above.")
    print("=" * 70 + "\n")

    sys.exit(0 if total_pass == total_tests else 1)
