from __future__ import annotations

# sentinel_network_monitor.py
# ---------------------------
# Detects suspicious outbound network connections by comparing live traffic
# against what the Isolation Forest model learned from the baseline.
#
# HOW THIS FILE CHANGED (ML integration):
#   BEFORE: Every connection whose remote IP wasn't in the baseline fired an
#           alert. Cloud services rotate IPs constantly, so this produced
#           hundreds of false positives per scan.
#
#   AFTER:  We extract 11 numeric features from each connection (port type,
#           process identity, exe location, etc.) and ask the trained model
#           whether the BEHAVIOUR looks anomalous — not just the IP.
#           Chrome on port 443 to a new IP = normal. An exe from Temp on
#           port 4444 = anomalous. The model makes that distinction.
#
# FALLBACK BEHAVIOUR:
#   If no trained model is available (models/network_model.pkl hasn't been created
#   yet), the function falls back to the original rule-based logic so nothing
#   breaks on first run.

from typing import Any, Dict, List, Optional, Tuple
import socket
import psutil

from core.sentinel_alerts import make_network_alert

# Import the ML helpers from the training module.
# _extract_connection_features  : converts one connection to a numeric vector
# load_network_model            : loads the saved Isolation Forest from disk
# SUSPICIOUS_PORTS              : hard-rule port blocklist (always alert)
# SYSTEM_SERVICES / WELL_KNOWN_PORTS : used to exempt OS services from ML scoring
from training.train_network_model import (
    _extract_connection_features,
    load_network_model,
    SUSPICIOUS_PORTS,
    SYSTEM_SERVICES,
    WELL_KNOWN_PORTS,
)

import numpy as np   # needed to wrap a single feature row before passing to the model

# ---------------------------------------------------------------------------
# DNS CACHE
#
# Reverse DNS lookups (IP → hostname) can be slow.
# We cache results so each IP is only looked up once per agent session.
# ---------------------------------------------------------------------------
DNS_CACHE: Dict[str, Optional[str]] = {}


def _reverse_dns_lookup(ip: str, timeout_seconds: float = 1.5) -> Optional[str]:
    """
    Best-effort reverse DNS (PTR) lookup for an IP address.
    Returns a hostname string (e.g. "lb-192.googleusercontent.com") or None.

    WHY THIS IS USEFUL:
        Raw IPs like "142.250.80.46" are hard to read in an alert.
        A hostname gives immediate context ("that's Google").

    Notes:
      - Uses the OS resolver via socket.gethostbyaddr() — no extra libraries.
      - We cap the wait time so a slow DNS server doesn't stall the whole scan.
      - Results are cached in DNS_CACHE for the lifetime of the agent session.
    """
    ip = (ip or "").strip()
    if not ip:
        return None

    # Return the cached result immediately (including cached None for failed lookups).
    if ip in DNS_CACHE:
        return DNS_CACHE[ip]

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_seconds)
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            host = (host or "").strip()
            DNS_CACHE[ip] = host if host else None
        except Exception:
            # Lookup failed (NXDOMAIN, timeout, etc.) — cache None so we don't retry.
            DNS_CACHE[ip] = None
    finally:
        # Always restore the original timeout so other socket code isn't affected.
        socket.setdefaulttimeout(old_timeout)

    return DNS_CACHE[ip]


def _dns_cache_housekeep(max_items: int = 2000) -> None:
    """
    Prevent the DNS cache from growing forever in long-running agent sessions.
    When it exceeds max_items, drop the oldest half.
    """
    if len(DNS_CACHE) <= max_items:
        return
    keys = list(DNS_CACHE.keys())
    for k in keys[: len(keys) // 2]:
        DNS_CACHE.pop(k, None)


# ---------------------------------------------------------------------------
# IP / USER HELPERS
# ---------------------------------------------------------------------------

def _normalize_ip(ip: str) -> str:
    return (ip or '').strip()


def _is_localhost(ip: str) -> bool:
    """Return True if the IP is the loopback address."""
    return ip in ('127.0.0.1', '::1')


def _is_private_ip(ip: str) -> bool:
    """
    Return True if the IP is in a private (RFC 1918) or loopback range.
    Private IPs stay inside the local network and are less interesting
    from a threat-detection standpoint than public internet connections.
    """
    if not ip or ':' in ip:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        a, b, c, d = [int(x) for x in parts]
    except ValueError:
        return False

    if a == 10:            return True   # 10.x.x.x
    if a == 172 and 16 <= b <= 31: return True   # 172.16-31.x.x
    if a == 192 and b == 168:      return True   # 192.168.x.x
    return False


def _is_system_user(username: str) -> bool:
    """
    Return True if the username is a Windows built-in system identity.
    These accounts run background services and are expected to make
    network connections as part of normal OS operation.
    """
    u = (username or '').lower()
    return (
        u in ("nt authority\\system", "system", "nt authority\\localservice",
              "nt authority\\networkservice")
        or u.endswith("\\system")
    )


# ---------------------------------------------------------------------------
# PROCESS INFO HELPER
# ---------------------------------------------------------------------------

def _proc_info_for_pid(pid: int) -> Dict[str, Any]:
    """
    Resolve a PID to its process metadata (name, exe path, username).

    WHY WE NEED THIS:
        psutil's net_connections() returns PIDs, not process names.
        We look up the name/path so we can include it in the alert and
        pass it to _extract_connection_features() for ML scoring.

    Returns a dict with at least {'pid': pid}. Other fields are filled in
    where accessible — some system processes deny access to their info.
    """
    info: Dict[str, Any] = {'pid': pid}
    try:
        p = psutil.Process(pid)
        info['name'] = p.name()
        try:
            info['exe'] = p.exe()
        except Exception:
            info['exe'] = None
        try:
            info['username'] = p.username()
        except Exception:
            info['username'] = None
    except Exception:
        # Process may have exited between net_connections() and now — that's fine.
        info.setdefault('name', None)
        info.setdefault('exe', None)
        info.setdefault('username', None)
    return info


# ---------------------------------------------------------------------------
# MAIN DETECTION FUNCTION
# ---------------------------------------------------------------------------

def detect_suspicious_connections(
        cfg: Dict[str, Any],
        baseline: Optional[Dict[str, Any]],
        model=None,   # trained IsolationForest from train_network_model.py, or None
) -> List[Dict[str, Any]]:
    """
    Scan all current network connections and return a list of alert dicts
    for anything that looks suspicious.

    HOW SCORING WORKS (when model is provided):
        For each outbound connection we call _extract_connection_features()
        to produce an 11-number vector, then ask the model two questions:

          model.predict()           → +1 (normal) or -1 (anomaly)
          model.decision_function() → a float score:
                                        positive  = comfortably normal
                                        near zero = borderline
                                        negative  = anomalous
                                        very negative = highly suspicious

        Only connections where predict() == -1 are flagged.
        The score drives severity:
            score < -0.05  → high
            score < 0      → medium

    HARD RULES (always apply, even without a model):
        - Connections to SUSPICIOUS_PORTS always raise an alert.
          These ports (Metasploit, Back Orifice, etc.) have no legitimate use.

    FALLBACK (when model=None):
        Falls back to the original rule-based logic:
          - remote IP not seen in baseline → alert
          - non-system user making a connection → alert
        This ensures the monitor still works before a model has been trained.

    Parameters:
        cfg      - agent config dict
        baseline - baseline dict (from sentinel_baseline.json), or None
        model    - trained IsolationForest, or None to use rule-based fallback
    """
    alerts: List[Dict[str, Any]] = []

    # Respect the kill-switch in config — if network monitoring is disabled, do nothing.
    if not cfg.get('enable_network_monitor', True):
        return alerts

    agent_id   = cfg.get('agent_id', 'unknown-agent')
    agent_name = cfg.get('display_name') or agent_id

    # IP whitelist from config — connections to these IPs are always ignored.
    ip_allow = set(cfg.get('network_ip_whitelist') or [])

    # Fetch all current TCP/UDP connections from the OS.
    try:
        conns = psutil.net_connections(kind='inet')
    except Exception:
        # If we can't read connections (e.g. missing admin rights) just return empty.
        return alerts

    # -----------------------------------------------------------------------
    # FALLBACK: build baseline IP set for rule-based mode (no model).
    # Only constructed when model is None — not needed otherwise.
    # -----------------------------------------------------------------------
    baseline_ips: set = set()
    if model is None and baseline:
        net  = baseline.get('network') or {}
        for c in (net.get('connections') or []):
            r  = c.get('raddr') or {}
            ip = r.get('ip') or r.get('host') or r.get('addr')
            if ip:
                baseline_ips.add(_normalize_ip(ip))

    # -----------------------------------------------------------------------
    # SCORE EACH LIVE CONNECTION
    # -----------------------------------------------------------------------
    for c in conns:

        # Only process connections that have a remote endpoint.
        # Listening sockets (LISTEN state) and local-only sockets have no raddr.
        if not c.raddr:
            continue

        # Extract remote IP and port — raddr can be a named tuple or a plain tuple.
        try:
            rip   = _normalize_ip(c.raddr.ip)
            rport = int(c.raddr.port)
        except Exception:
            try:
                rip   = _normalize_ip(c.raddr[0])
                rport = int(c.raddr[1])
            except Exception:
                continue   # malformed address — skip

        # Skip if the IP is empty or is just the machine talking to itself.
        if not rip or _is_localhost(rip):
            continue

        # Skip if the IP is in the user-configured whitelist.
        if rip in ip_allow:
            continue

        # Skip connections with no identifiable PID (some kernel connections).
        pid = c.pid
        if pid is None:
            continue

        # Resolve the PID to a process name / exe path for the alert and features.
        pinfo    = _proc_info_for_pid(pid)
        username = pinfo.get('username') or ''
        pname    = pinfo.get('name') or 'unknown'

        reasons: List[str] = []
        severity = 'medium'

        # -------------------------------------------------------------------
        # HARD RULE 1: suspicious port
        #
        # Ports like 4444 (Metasploit), 31337 (Back Orifice), etc. have no
        # legitimate everyday use. We always flag these regardless of the model
        # because the rule is tight enough to never produce false positives.
        # -------------------------------------------------------------------
        if rport in SUSPICIOUS_PORTS:
            reasons.append('connection_to_suspicious_port')
            severity = 'high'

        # -------------------------------------------------------------------
        # HARD RULE 2: executable running from a Temp folder making an
        # outbound connection to a public IP.
        #
        # Legitimate installed software does not run persistently from Temp.
        # Malware dropped by an exploit or downloader almost always does.
        # This rule is tight enough to fire with very few false positives.
        # -------------------------------------------------------------------
        exe_path = (pinfo.get('exe') or '').lower().replace('/', '\\')
        if ('\\temp\\' in exe_path or '\\tmp\\' in exe_path) and not _is_private_ip(rip):
            if 'proc_from_temp_public_connection' not in reasons:
                reasons.append('proc_from_temp_public_connection')
                severity = 'high'

        # -------------------------------------------------------------------
        # ML PATH: score the connection with the Isolation Forest.
        # Skipped if a hard rule already fired (no need to double-flag),
        # and skipped for system services on well-known ports — those are
        # expected OS behaviour and the model may flag them as borderline
        # due to limited training data (system_to_public=1 is rare in baselines).
        # -------------------------------------------------------------------
        pname_lower = pname.lower()
        is_system_on_well_known = (
            pname_lower in {s.lower() for s in SYSTEM_SERVICES}
            and rport in WELL_KNOWN_PORTS
        )

        if model is not None and not reasons and not is_system_on_well_known:
            # Build the 11-number feature vector for this connection.
            features = _extract_connection_features(rip, rport, pinfo)

            # np.array(...).reshape(1, -1) wraps our single row into the 2D
            # matrix shape that scikit-learn's predict/decision_function expect.
            X = np.array(features, dtype=float).reshape(1, -1)

            # predict() returns +1 for normal, -1 for anomaly.
            label = model.predict(X)[0]

            if label == -1:
                # decision_function() gives us a continuous score.
                # More negative = further from the normal cluster = more suspicious.
                score = model.decision_function(X)[0]

                # SCORE FLOOR: suppress borderline ML alerts (score near zero).
                # predict() == -1 fires for anything below the contamination
                # boundary, including scores like -0.001 that are effectively
                # indistinguishable from normal traffic. Require score < -0.03
                # so only genuine anomalies (well outside the normal cluster) alert.
                if score >= -0.03:
                    continue   # borderline — skip

                reasons.append('ml_anomaly_detected')

                # Map the score to a severity level.
                # -0.05 is a loose threshold — anything below it is confidently anomalous.
                if score < -0.05:
                    severity = 'high'
                else:
                    severity = 'medium'

        # -------------------------------------------------------------------
        # FALLBACK PATH: original rule-based logic (no model available)
        # -------------------------------------------------------------------
        elif model is None:

            # Rule A: remote IP not seen during baseline snapshot.
            # NOTE: this is the noisy rule that fires on every new CDN IP.
            # It only runs here as a last resort when no model is trained yet.
            if baseline and rip not in baseline_ips:
                reasons.append('remote_ip_not_in_baseline')
                severity = 'high'

            # Rule B: non-system user making an outbound connection.
            # Also noisy on its own — only kept in fallback mode.
            if username and not _is_system_user(username):
                reasons.append('connection_by_non_system_user')
                if severity != 'high':
                    severity = 'medium'

            # No baseline at all — flag non-system processes on public IPs.
            if not baseline:
                if username and not _is_system_user(username) and not _is_private_ip(rip):
                    reasons.append('public_ip_by_non_system_user')
                    severity = 'high'

        # If neither the hard rule nor the model flagged this connection, skip it.
        if not reasons:
            continue

        # -------------------------------------------------------------------
        # REVERSE DNS LOOKUP
        # Attempt to resolve the raw IP to a human-readable hostname so the
        # alert summary is easier to read ("google.com" vs "142.250.80.46").
        # Only done for public IPs — private IPs don't usually have PTR records.
        # -------------------------------------------------------------------
        dns_name: Optional[str] = None

        dns_enabled = cfg.get("network_dns_lookup_enabled", True)
        dns_timeout = cfg.get("network_dns_lookup_timeout_seconds", 1.5)
        try:
            dns_timeout = float(dns_timeout)
        except Exception:
            dns_timeout = 1.5

        if dns_enabled and not _is_localhost(rip) and not _is_private_ip(rip):
            dns_name = _reverse_dns_lookup(rip, timeout_seconds=dns_timeout)

        # Keep the cache from growing without bound across a long agent session.
        _dns_cache_housekeep(max_items=2000)

        # Build a readable one-line summary for the alert list.
        # Format:  "brave.exe -> 104.18.39.21:443 (cloudflare.com)"
        if dns_name:
            summary = f"{pname} -> {rip}:{rport} ({dns_name})"
        else:
            summary = f"{pname} -> {rip}:{rport}"

        # Assemble the full alert dict using the shared alert helper.
        alert = make_network_alert(
            agent_id=agent_id,
            agent_display_name=agent_name,
            severity=severity,
            summary=summary,
            reasons=reasons,
            connection={
                'remote_ip':   rip,
                'remote_port': rport,
                'dns_name':    dns_name,
                'status':      getattr(c, 'status', None),
                'family':      str(getattr(c, 'type', '')),
                'type':        str(getattr(c, 'type', '')),
                'local_addr':  getattr(c, 'laddr', None),
            },
            process=pinfo,
        )

        # Stable dedup key used by the agent's cooldown logic so the same
        # connection doesn't spam repeated alerts on every monitoring tick.
        alert["dedup_key"] = (
            f"{pname.lower()}"
            f"|{(pinfo.get('exe') or '').lower()}"
            f"|{(pinfo.get('username') or '').lower()}"
            f"|{rip}|{rport}"
        )

        alerts.append(alert)

    return alerts
