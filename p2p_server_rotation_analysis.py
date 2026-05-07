#!/usr/bin/env python3
"""
P2P / Torrent Delivery & Server Rotation Analysis
==================================================
Companion script to static_analysis.py.

Scans decompiled APK directories (apktool output: smali + resources) for:

  1. P2P / Torrent Delivery Evidence
     - TorrentDownloadActivity and related torrent component classes
     - BitTorrent / libtorrent / WebTorrent SDK signatures
     - Magnet URI schemes and .torrent file references
     - DHT / tracker-announce / peer-wire protocol strings
     - P2P library native (.so) artifacts
     - Torrent-related permissions (INTERNET + direct peer sockets)
     - Peer-ID / info-hash construction patterns in smali
     - WebRTC data-channel usage (browser-based P2P)

  2. Server Rotation Evidence
     - Hardcoded server lists (arrays of hostnames / IPs)
     - Failover / fallback / mirror / CDN rotation logic in smali
     - Dynamic DNS and DGA-style host construction
     - Config-pull patterns (remote URL list fetched at runtime)
     - Retry-with-next-server loops
     - SharedPreferences / assets / raw resources used as server registries
     - Domain-fronting indicators
     - Multiple base-URL constants pointing to different TLDs / IPs

Output: JSON + Excel workbook with one sheet per finding category.

Usage:
  python p2p_server_rotation_analysis.py [--folder apks/] [--output report.xlsx]
"""

import argparse
import json
import logging
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Optional openpyxl for Excel export
# ---------------------------------------------------------------------------
try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants – P2P / Torrent indicators
# ---------------------------------------------------------------------------

# Class / package name fragments (matched against smali .class directives)
P2P_CLASS_FRAGMENTS = [
    "torrent", "Torrent",
    "TorrentDownload", "TorrentActivity",
    "libtorrent", "LibTorrent",
    "webtorrent", "WebTorrent",
    "bittorrent", "BitTorrent",
    "p2pdownload", "P2PDownload",
    "com/mxtech/torrent",
    "com/frostwire",
    "com/tord",
    "org/gudy/azureus",
    "com/vuze",
    "com/aelitis",          # Azureus / Vuze
    "com/biglybt",
    "com/turn/ttorrent",    # ttorrent Java lib
    "io/ably/lib",          # Ably realtime (sometimes used for P2P signaling)
    "com/webrtc",
    "org/webrtc",
    "io/github/webrtc",
    "com/meshenger",
]

# String literals / constants (smali const-string, .annotation values, res strings)
P2P_STRING_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("magnet_uri",         re.compile(r"magnet:\?xt=urn:btih:", re.I)),
    ("torrent_file_ext",   re.compile(r"\.torrent", re.I)),
    ("tracker_announce",   re.compile(r"/announce(?:\b|$)", re.I)),
    ("dht_bootstrap",      re.compile(r"\bdht\b", re.I)),
    ("peer_wire_header",   re.compile(r"BitTorrent protocol", re.I)),
    ("info_hash",          re.compile(r"\binfo[_-]?hash\b", re.I)),
    ("peer_id",            re.compile(r"\bpeer[_-]?id\b", re.I)),
    ("piece_length",       re.compile(r"\bpiece[_-]?length\b", re.I)),
    ("bencoding",          re.compile(r"\bbencode\b|\bbdecode\b", re.I)),
    ("udp_tracker",        re.compile(r"udp://[^\s'\"]{4,}", re.I)),
    ("wss_tracker",        re.compile(r"wss://[^\s'\"]{4,}tracker", re.I)),
    ("webrtc_sdp",         re.compile(r"a=candidate|offer|answer", re.I)),
    ("webrtc_ice",         re.compile(r"stun:|turn:", re.I)),
    ("p2p_download",       re.compile(r"p2p[_\s]?download|download[_\s]?p2p", re.I)),
    ("libtorrent_native",  re.compile(r"libtorrent[_\-]jni|libtorrent\.so", re.I)),
]

# Native library names (.so files in lib/)
P2P_NATIVE_LIBS = [
    "libtorrent",
    "libjlibtorrent",
    "libwebtorrent",
    "libdatachannel",
    "librtc",
    "libwebrtc",
    "libp2p",
    "libbtclient",
]

# Smali opcode patterns for P2P protocol construction
P2P_SMALI_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("dex_class_torrent",      re.compile(r"\.class.*(torrent|Torrent|BitTorrent)", re.I)),
    ("source_torrent",         re.compile(r"\.source\s+\".*[Tt]orrent.*\.java\"")),
    ("source_p2p",             re.compile(r"\.source\s+\".*[Pp]2[Pp].*\.java\"")),
    ("invoke_announce",        re.compile(r"invoke-\w+\s+\{[^}]*\},\s*L\S+;->announce\(")),
    ("invoke_connect_peer",    re.compile(r"invoke-\w+\s+\{[^}]*\},\s*L\S+;->connect\S*Peer\(")),
    ("invoke_download_torrent",re.compile(r"invoke-\w+\s+\{[^}]*\},\s*L\S+;->download\S*[Tt]orrent\(")),
    ("const_btih",             re.compile(r'const-string\s+\S+,\s*"btih"')),
    ("const_magnet",           re.compile(r'const-string\s+\S+,\s*"magnet"')),
    ("const_tracker_url",      re.compile(r'const-string\s+\S+,\s*"[^"]*announce[^"]*"')),
    ("socket_bind_port",       re.compile(r"invoke-\w+.*\bServerSocket\b.*\b(6881|6882|6889)\b")),
]

# Manifest component names
P2P_MANIFEST_COMPONENTS = [
    "TorrentDownloadActivity",
    "TorrentService",
    "TorrentReceiver",
    "P2PDownloadService",
    "P2PActivity",
    "BTDownloadService",
    "BTActivity",
    "WebTorrentActivity",
]

# ---------------------------------------------------------------------------
# Constants – Server Rotation indicators
# ---------------------------------------------------------------------------

# Smali patterns for server-list / rotation logic
ROTATION_SMALI_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Arrays / lists of server strings being constructed
    ("new_string_array",       re.compile(r"new-array\s+\S+,\s*\S+,\s*\[Ljava/lang/String;")),
    ("filled_new_array_str",   re.compile(r"filled-new-array.+\[Ljava/lang/String;")),
    # Index-based fallback: arr[i++] or idx++ patterns near URL strings
    ("array_put_url",          re.compile(r"aput-object.+\"https?://")),
    # Explicit rotation / fallback method names
    ("method_rotate",          re.compile(r"\.method.*(?:rotate|Rotate|ROTATE).*Server", re.I)),
    ("method_failover",        re.compile(r"\.method.*(?:failover|fallback|switchServer|nextServer|retryServer|backupServer|mirrorServer)", re.I)),
    ("method_get_server_list", re.compile(r"\.method.*(?:getServer|getHost|getEndpoint|getBaseUrl|getApiUrl)s?\(", re.I)),
    ("method_get_mirror",      re.compile(r"\.method.*(?:getMirror|selectMirror|pickServer|chooseCdn)", re.I)),
    # Server index tracking in SharedPreferences
    ("pref_server_index",      re.compile(r'const-string\s+\S+,\s*"(?:server_index|host_index|current_server|active_server|server_retry|endpoint_index|mirror_index|cdn_index)"', re.I)),
    ("pref_server_url",        re.compile(r'const-string\s+\S+,\s*"(?:server_url|base_url|api_url|stream_url|server_host|active_host|current_host|backup_host)"', re.I)),
    # Config-pull: remote list fetch
    ("fetch_config_url",       re.compile(r'const-string\s+\S+,\s*"https?://[^"]+(?:config|servers?|hosts?|endpoints?|mirrors?)[^"]*\.(?:json|xml|txt|m3u8?)"', re.I)),
    # Dynamic host construction (string concat of base + suffix)
    ("host_concat",            re.compile(r"invoke-virtual.*StringBuilder.*->append.*https?://")),
    # Retry loop: catch IOException then increment server pointer
    ("retry_loop_ioexception",  re.compile(r"\.catch Ljava/io/IOException;")),
    ("retry_loop_exception",    re.compile(r"\.catch Ljava/net/ConnectException;")),
    # DNS-over-HTTPS / custom DNS resolvers (DGA evasion)
    ("custom_dns",             re.compile(r"invoke-\w+.*\b(?:DnsResolver|CustomDns|DohResolver|OkHttpDns)\b")),
    ("doh_endpoint",           re.compile(r'const-string\s+\S+,\s*"https://(?:cloudflare-dns\.com|dns\.google|doh\.[^"]+)/dns-query"')),
    # Domain-fronting indicators
    ("domain_fronting_header", re.compile(r'const-string\s+\S+,\s*"(?:X-Forwarded-Host|Host-Override|X-Host)"', re.I)),
]

# String-level server rotation patterns (across all string constants)
ROTATION_STRING_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("multiple_base_urls",    re.compile(r"https?://[a-zA-Z0-9.\-]+\.[a-z]{2,}")),
    ("backup_server_key",     re.compile(r"backup[_\-]?(server|host|url|endpoint)", re.I)),
    ("failover_key",          re.compile(r"failover[_\-]?(server|host|url|endpoint)", re.I)),
    ("mirror_url",            re.compile(r"mirror[_\-]?(server|host|url|[0-9])", re.I)),
    ("cdn_rotate",            re.compile(r"cdn[_\-]?(rotate|switch|list|failover)", re.I)),
    ("server_list_json_key",  re.compile(r'"(?:servers|hosts|endpoints|mirrors|cdn_list|server_list|host_list)"\s*:', re.I)),
    ("round_robin",           re.compile(r"round[_\-]?robin", re.I)),
    ("load_balance",          re.compile(r"load[_\-]?balan", re.I)),
    ("server_rotation_key",   re.compile(r"server[_\-]?rotation|rotat[ei]+[_\-]?server", re.I)),
    ("config_server_url",     re.compile(r"https?://[^\s'\"<>]{4,}(?:config|serverlist|hostlist|endpoints)[^\s'\"<>]*", re.I)),
    ("dynamic_dns",           re.compile(r"(?:no-?ip\.com|dyn\.com|duckdns\.org|changeip\.com|freedns\.afraid\.org)", re.I)),
    ("ngrok_tunnel",          re.compile(r"\.ngrok\.(io|app)", re.I)),
    ("tor_onion",             re.compile(r"\.onion\b", re.I)),
]

# Asset / resource files that may contain server lists
SERVER_LIST_ASSET_NAMES = [
    "servers.json", "server_list.json", "hosts.json", "endpoints.json",
    "config.json", "remote_config.json", "cdn.json", "mirrors.json",
    "servers.xml", "hosts.xml", "config.xml", "remote.xml",
    "servers.txt", "hosts.txt", "serverlist.txt",
    "builddatas.json",  # seen in IPTV app assets
]

# Manifest patterns for server rotation (provider authorities, meta-data)
ROTATION_MANIFEST_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("meta_server_url",        re.compile(r'android:name="[^"]*(?:server|host|endpoint|api|base_url)[^"]*"[^>]+android:value="https?://', re.I)),
    ("provider_server_auth",   re.compile(r'android:authorities="[^"]*(?:server|host|config)[^"]*"', re.I)),
]

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _walk_smali(apk_dir: Path):
    """Yield (relative_path, absolute_path) for every .smali file."""
    for root, _, files in os.walk(apk_dir):
        for fname in files:
            if fname.endswith(".smali"):
                abs_path = Path(root) / fname
                yield abs_path.relative_to(apk_dir), abs_path


def _walk_all_text(apk_dir: Path, extensions=(".smali", ".xml", ".json", ".txt", ".html", ".js")):
    """Yield (relative_path, absolute_path) for every text-like file."""
    for root, _, files in os.walk(apk_dir):
        for fname in files:
            if any(fname.endswith(ext) for ext in extensions):
                abs_path = Path(root) / fname
                yield abs_path.relative_to(apk_dir), abs_path


def _read_safe(path: Path, max_bytes: int = 2_000_000) -> str:
    """Read a file up to max_bytes, returning empty string on error."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(max_bytes)
    except Exception:
        return ""


def _extract_urls(text: str) -> list[str]:
    """Return all HTTP/HTTPS URLs found in text."""
    return re.findall(r"https?://[^\s'\"<>]{5,}", text)


def _extract_class_name(smali_text: str) -> str:
    """Return the declared class name from a smali file."""
    m = re.search(r"^\.class\s+\S+\s+(\S+);", smali_text, re.MULTILINE)
    return m.group(1) if m else "unknown"


# ---------------------------------------------------------------------------
# P2P Analysis
# ---------------------------------------------------------------------------

def analyze_p2p(apk_dir: Path) -> dict[str, Any]:
    """
    Scan a decompiled APK directory for all P2P / torrent delivery evidence.
    Returns a structured findings dict.
    """
    findings: dict[str, Any] = {
        "torrent_components_in_manifest": [],
        "torrent_smali_classes": [],
        "torrent_string_hits": defaultdict(list),   # pattern_name -> [file:line, ...]
        "torrent_smali_opcode_hits": defaultdict(list),
        "p2p_native_libs": [],
        "p2p_class_fragment_hits": [],
        "webrtc_evidence": [],
        "torrent_asset_files": [],
        "summary": {},
    }

    # 1. AndroidManifest.xml — component names
    manifest_path = apk_dir / "AndroidManifest.xml"
    manifest_text = _read_safe(manifest_path)
    for component in P2P_MANIFEST_COMPONENTS:
        if component in manifest_text:
            findings["torrent_components_in_manifest"].append(component)
    # Also grab full activity/service lines mentioning torrent
    for line in manifest_text.splitlines():
        if re.search(r"torrent|p2p|bittorrent|webtorrent", line, re.I):
            findings["torrent_components_in_manifest"].append(line.strip())

    # 2. Native libraries
    lib_dir = apk_dir / "lib"
    if lib_dir.exists():
        for root, _, files in os.walk(lib_dir):
            for fname in files:
                for lib_name in P2P_NATIVE_LIBS:
                    if lib_name in fname.lower():
                        rel = str(Path(root).relative_to(apk_dir) / fname)
                        findings["p2p_native_libs"].append(rel)

    # 3. Assets — .torrent files or magnet config
    assets_dir = apk_dir / "assets"
    if assets_dir.exists():
        for root, _, files in os.walk(assets_dir):
            for fname in files:
                if re.search(r"\.torrent$|torrent|p2p|magnet", fname, re.I):
                    findings["torrent_asset_files"].append(fname)

    # 4. Smali scan — class names, source annotations, opcodes, strings
    for rel_path, abs_path in _walk_smali(apk_dir):
        text = _read_safe(abs_path, max_bytes=500_000)
        if not text:
            continue

        # 4a. Class-fragment match (fast path before line scan)
        class_name = _extract_class_name(text)
        for frag in P2P_CLASS_FRAGMENTS:
            if frag.lower() in class_name.lower():
                findings["p2p_class_fragment_hits"].append(
                    {"class": class_name, "fragment": frag, "file": str(rel_path)}
                )
                break

        # 4b. Line-by-line scan
        for lineno, line in enumerate(text.splitlines(), 1):
            ref = f"{rel_path}:{lineno}"

            # String constant hits
            for pat_name, pat in P2P_STRING_PATTERNS:
                if pat.search(line):
                    snippet = line.strip()[:120]
                    findings["torrent_string_hits"][pat_name].append(
                        {"ref": ref, "snippet": snippet}
                    )

            # Smali opcode / structural hits
            for pat_name, pat in P2P_SMALI_PATTERNS:
                if pat.search(line):
                    snippet = line.strip()[:120]
                    findings["torrent_smali_opcode_hits"][pat_name].append(
                        {"ref": ref, "snippet": snippet}
                    )

            # WebRTC specifically (separate bucket)
            if re.search(r"webrtc|WebRTC|RTCPeerConnection|DataChannel|IceCandidate", line):
                findings["webrtc_evidence"].append(
                    {"ref": ref, "snippet": line.strip()[:120]}
                )

    # 5. Non-smali assets (JSON/XML configs)
    for rel_path, abs_path in _walk_all_text(apk_dir, extensions=(".json", ".xml")):
        text = _read_safe(abs_path, max_bytes=200_000)
        for pat_name, pat in P2P_STRING_PATTERNS:
            if pat.search(text):
                findings["torrent_string_hits"][pat_name].append(
                    {"ref": str(rel_path), "snippet": pat.search(text).group(0)[:120]}
                )

    # 6. Summary flags
    findings["summary"] = {
        "has_torrent_manifest_component": bool(findings["torrent_components_in_manifest"]),
        "has_p2p_class": bool(findings["p2p_class_fragment_hits"]),
        "has_p2p_native_lib": bool(findings["p2p_native_libs"]),
        "has_magnet_uri": bool(findings["torrent_string_hits"].get("magnet_uri")),
        "has_tracker_announce": bool(findings["torrent_string_hits"].get("tracker_announce")),
        "has_dht": bool(findings["torrent_string_hits"].get("dht_bootstrap")),
        "has_bencoding": bool(findings["torrent_string_hits"].get("bencoding")),
        "has_webrtc": bool(findings["webrtc_evidence"]),
        "torrent_string_hit_count": sum(len(v) for v in findings["torrent_string_hits"].values()),
        "torrent_opcode_hit_count": sum(len(v) for v in findings["torrent_smali_opcode_hits"].values()),
        "p2p_confidence": "NONE",  # set below
    }

    # Confidence scoring
    score = 0
    s = findings["summary"]
    if s["has_torrent_manifest_component"]: score += 4
    if s["has_p2p_class"]:                 score += 3
    if s["has_p2p_native_lib"]:            score += 5
    if s["has_magnet_uri"]:                score += 4
    if s["has_tracker_announce"]:          score += 3
    if s["has_dht"]:                       score += 3
    if s["has_bencoding"]:                 score += 4
    if s["has_webrtc"]:                    score += 2
    score += min(s["torrent_string_hit_count"] // 5, 5)
    score += min(s["torrent_opcode_hit_count"] // 3, 5)

    if score >= 10:
        confidence = "HIGH"
    elif score >= 5:
        confidence = "MEDIUM"
    elif score >= 2:
        confidence = "LOW"
    else:
        confidence = "NONE"

    findings["summary"]["p2p_confidence"] = confidence
    findings["summary"]["p2p_score"] = score

    # Convert defaultdicts for JSON serialisation
    findings["torrent_string_hits"] = dict(findings["torrent_string_hits"])
    findings["torrent_smali_opcode_hits"] = dict(findings["torrent_smali_opcode_hits"])

    return findings


# ---------------------------------------------------------------------------
# Server Rotation Analysis
# ---------------------------------------------------------------------------

def analyze_server_rotation(apk_dir: Path) -> dict[str, Any]:
    """
    Scan a decompiled APK directory for server rotation / failover evidence.
    Returns a structured findings dict.
    """
    findings: dict[str, Any] = {
        "rotation_smali_hits": defaultdict(list),   # pattern_name -> [hit, ...]
        "rotation_string_hits": defaultdict(list),
        "server_list_assets": [],        # asset files that look like server registries
        "base_url_constants": [],        # all distinct base-URL strings found
        "server_pref_keys": [],          # SharedPrefs keys that store server state
        "manifest_server_meta": [],      # <meta-data> entries with server URLs
        "multi_host_array_classes": [],  # smali classes that build string arrays of URLs
        "config_fetch_urls": [],         # URLs used to pull remote server config
        "retry_exception_classes": [],   # classes containing connection retry logic
        "domain_diversity": {},          # unique TLD / IP counts
        "summary": {},
    }

    all_urls: list[str] = []

    # 1. AndroidManifest.xml
    manifest_path = apk_dir / "AndroidManifest.xml"
    manifest_text = _read_safe(manifest_path)
    for pat_name, pat in ROTATION_MANIFEST_PATTERNS:
        for m in pat.finditer(manifest_text):
            findings["manifest_server_meta"].append(
                {"pattern": pat_name, "snippet": m.group(0)[:200]}
            )
    all_urls.extend(_extract_urls(manifest_text))

    # 2. Assets — look for server-list config files
    assets_dir = apk_dir / "assets"
    if assets_dir.exists():
        for root, _, files in os.walk(assets_dir):
            for fname in files:
                if fname.lower() in SERVER_LIST_ASSET_NAMES:
                    abs_path = Path(root) / fname
                    text = _read_safe(abs_path, max_bytes=500_000)
                    urls_in_file = _extract_urls(text)
                    # Flag if file contains 2+ distinct URLs (server list candidate)
                    unique_urls = list(set(urls_in_file))
                    if len(unique_urls) >= 2:
                        findings["server_list_assets"].append({
                            "file": fname,
                            "url_count": len(unique_urls),
                            "urls": unique_urls[:20],
                        })
                    all_urls.extend(urls_in_file)
                    # Also run rotation string patterns
                    for pat_name, pat in ROTATION_STRING_PATTERNS:
                        for m in pat.finditer(text):
                            findings["rotation_string_hits"][pat_name].append(
                                {"ref": fname, "snippet": m.group(0)[:120]}
                            )

    # 3. res/raw and res/xml — embedded configs
    for sub in ("raw", "xml"):
        res_dir = apk_dir / "res" / sub
        if not res_dir.exists():
            continue
        for fname in os.listdir(res_dir):
            abs_path = res_dir / fname
            text = _read_safe(abs_path, max_bytes=500_000)
            urls_in_file = _extract_urls(text)
            if len(set(urls_in_file)) >= 2:
                findings["server_list_assets"].append({
                    "file": f"res/{sub}/{fname}",
                    "url_count": len(set(urls_in_file)),
                    "urls": list(set(urls_in_file))[:20],
                })
            all_urls.extend(urls_in_file)

    # 4. Smali scan
    # Track classes that have both a new-array and multiple URL const-strings
    # (strong indicator of hardcoded server list)
    class_url_counts: dict[str, int] = defaultdict(int)
    class_has_array: set[str] = set()
    class_has_retry: set[str] = set()

    for rel_path, abs_path in _walk_smali(apk_dir):
        text = _read_safe(abs_path, max_bytes=500_000)
        if not text:
            continue

        class_name = _extract_class_name(text)

        # Count URL constants per class
        url_hits = re.findall(r'const-string\s+\S+,\s*"(https?://[^\s"]{5,})"', text)
        if url_hits:
            class_url_counts[class_name] += len(url_hits)
            all_urls.extend(url_hits)

        # Smali pattern hits (line-by-line for context)
        has_array_in_class = False
        has_retry_in_class = False

        for lineno, line in enumerate(text.splitlines(), 1):
            ref = f"{rel_path}:{lineno}"

            for pat_name, pat in ROTATION_SMALI_PATTERNS:
                if pat.search(line):
                    snippet = line.strip()[:120]

                    # Bucket server-pref keys separately for readability
                    if pat_name in ("pref_server_index", "pref_server_url"):
                        m = re.search(r'"([^"]+)"', line)
                        if m:
                            findings["server_pref_keys"].append(
                                {"key": m.group(1), "class": class_name, "ref": ref}
                            )
                    elif pat_name == "fetch_config_url":
                        m = re.search(r'"(https?://[^"]+)"', line)
                        if m:
                            findings["config_fetch_urls"].append(
                                {"url": m.group(1), "class": class_name, "ref": ref}
                            )
                    else:
                        findings["rotation_smali_hits"][pat_name].append(
                            {"ref": ref, "class": class_name, "snippet": snippet}
                        )

                    if pat_name == "new_string_array":
                        has_array_in_class = True
                    if pat_name in ("retry_loop_ioexception", "retry_loop_exception"):
                        has_retry_in_class = True

            if has_array_in_class:
                class_has_array.add(class_name)
            if has_retry_in_class:
                class_has_retry.add(class_name)

        # String rotation patterns in smali
        for pat_name, pat in ROTATION_STRING_PATTERNS:
            for m in pat.finditer(text):
                snippet = m.group(0)[:120]
                findings["rotation_string_hits"][pat_name].append(
                    {"ref": str(rel_path), "class": class_name, "snippet": snippet}
                )

    # 5. Classes with multiple URL constants AND a string array → strong server-list signal
    for class_name, url_count in class_url_counts.items():
        if url_count >= 3 and class_name in class_has_array:
            findings["multi_host_array_classes"].append(
                {"class": class_name, "url_const_count": url_count}
            )

    # 6. Classes with retry exception handlers
    for class_name in class_has_retry:
        if class_url_counts.get(class_name, 0) >= 2:
            findings["retry_exception_classes"].append(
                {"class": class_name, "url_const_count": class_url_counts[class_name]}
            )

    # 7. Deduplicate and catalogue all base URLs
    seen_urls: set[str] = set()
    for url in all_urls:
        # Normalise to scheme + host
        m = re.match(r"(https?://[a-zA-Z0-9.\-:]+)", url)
        if m:
            seen_urls.add(m.group(1))

    findings["base_url_constants"] = sorted(seen_urls)

    # 8. Domain diversity analysis
    tlds: dict[str, int] = defaultdict(int)
    raw_ips: list[str] = []
    for url in seen_urls:
        m = re.match(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", url)
        if m:
            raw_ips.append(m.group(1))
        else:
            m2 = re.search(r"\.([a-z]{2,})(?::\d+)?$", url)
            if m2:
                tlds[m2.group(1)] += 1

    findings["domain_diversity"] = {
        "unique_base_urls": len(seen_urls),
        "tld_distribution": dict(tlds),
        "raw_ip_endpoints": raw_ips,
        "has_raw_ip_endpoints": bool(raw_ips),
        "has_dynamic_dns": bool(
            findings["rotation_string_hits"].get("dynamic_dns")
        ),
        "has_tor_onion": bool(
            findings["rotation_string_hits"].get("tor_onion")
        ),
        "has_ngrok": bool(
            findings["rotation_string_hits"].get("ngrok_tunnel")
        ),
    }

    # 9. Summary flags and confidence score
    smali_hit_count  = sum(len(v) for v in findings["rotation_smali_hits"].values())
    string_hit_count = sum(len(v) for v in findings["rotation_string_hits"].values())

    score = 0
    if findings["server_list_assets"]:              score += 5
    if findings["multi_host_array_classes"]:        score += 4
    if findings["config_fetch_urls"]:               score += 4
    if findings["server_pref_keys"]:                score += 3
    if findings["retry_exception_classes"]:         score += 2
    if findings["domain_diversity"]["has_raw_ip_endpoints"]: score += 2
    if findings["domain_diversity"]["unique_base_urls"] >= 5: score += 3
    if findings["domain_diversity"]["unique_base_urls"] >= 15: score += 3
    if findings["manifest_server_meta"]:            score += 2
    score += min(smali_hit_count  // 10, 5)
    score += min(string_hit_count // 10, 5)
    score += min(len(findings["domain_diversity"].get("tld_distribution", {})), 4)

    if score >= 12:
        confidence = "HIGH"
    elif score >= 6:
        confidence = "MEDIUM"
    elif score >= 2:
        confidence = "LOW"
    else:
        confidence = "NONE"

    findings["summary"] = {
        "server_list_asset_count":     len(findings["server_list_assets"]),
        "multi_host_array_class_count": len(findings["multi_host_array_classes"]),
        "config_fetch_url_count":      len(findings["config_fetch_urls"]),
        "server_pref_key_count":       len(findings["server_pref_keys"]),
        "retry_class_count":           len(findings["retry_exception_classes"]),
        "unique_base_url_count":       findings["domain_diversity"]["unique_base_urls"],
        "raw_ip_count":                len(findings["domain_diversity"]["raw_ip_endpoints"]),
        "rotation_smali_hit_count":    smali_hit_count,
        "rotation_string_hit_count":   string_hit_count,
        "rotation_confidence":         confidence,
        "rotation_score":              score,
    }

    # Convert defaultdicts for JSON
    findings["rotation_smali_hits"]  = dict(findings["rotation_smali_hits"])
    findings["rotation_string_hits"] = dict(findings["rotation_string_hits"])

    return findings


# ---------------------------------------------------------------------------
# Per-APK orchestrator
# ---------------------------------------------------------------------------

def analyze_apk_dir(apk_dir: Path) -> dict[str, Any]:
    app_name = apk_dir.name
    log.info(f"Analysing: {app_name}")

    p2p = analyze_p2p(apk_dir)
    rotation = analyze_server_rotation(apk_dir)

    return {
        "app": app_name,
        "apk_dir": str(apk_dir),
        "p2p": p2p,
        "server_rotation": rotation,
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _cap(lst, n=30):
    """Cap a list to n entries for readability in reports."""
    return lst[:n] if isinstance(lst, list) else lst


def generate_json_report(all_results: list[dict], output_path: str):
    """Write a compact but complete JSON report."""
    # Cap large per-file hit lists before serialising
    for r in all_results:
        for bucket in r["p2p"]["torrent_string_hits"].values():
            del bucket[30:]
        for bucket in r["p2p"]["torrent_smali_opcode_hits"].values():
            del bucket[20:]
        for bucket in r["server_rotation"]["rotation_smali_hits"].values():
            del bucket[30:]
        for bucket in r["server_rotation"]["rotation_string_hits"].values():
            del bucket[30:]

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2, ensure_ascii=False)
    log.info(f"JSON report written → {output_path}")


def generate_excel_report(all_results: list[dict], output_path: str):
    if not HAS_OPENPYXL:
        log.warning("openpyxl not installed — skipping Excel report.")
        return

    wb = openpyxl.Workbook()
    wb.remove(wb.active)  # remove default sheet

    HEADER_FILL   = PatternFill("solid", fgColor="1F4E79")
    HEADER_FONT   = Font(bold=True, color="FFFFFF")
    HIGH_FILL     = PatternFill("solid", fgColor="FF0000")
    MEDIUM_FILL   = PatternFill("solid", fgColor="FFA500")
    LOW_FILL      = PatternFill("solid", fgColor="FFFF00")
    NONE_FILL     = PatternFill("solid", fgColor="D9D9D9")
    CONF_FILLS    = {"HIGH": HIGH_FILL, "MEDIUM": MEDIUM_FILL,
                     "LOW": LOW_FILL, "NONE": NONE_FILL}

    def _h(ws, headers):
        ws.append(headers)
        for cell in ws[1]:
            cell.font = HEADER_FONT
            cell.fill = HEADER_FILL

    def _safe(v):
        if v is None:
            return ""
        s = str(v)
        s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", s)
        return s[:32000]

    # ── Sheet 1: Summary ─────────────────────────────────────────────────────
    ws = wb.create_sheet("Summary")
    _h(ws, [
        "App", "P2P Confidence", "P2P Score",
        "Has TorrentComponent", "Has P2P Class", "Has Native Lib",
        "Has Magnet URI", "Has DHT", "Has Bencoding", "Has WebRTC",
        "Torrent String Hits", "Torrent Opcode Hits",
        "Rotation Confidence", "Rotation Score",
        "Unique Base URLs", "Raw IP Endpoints",
        "Server List Assets", "Config Fetch URLs",
        "Server Pref Keys", "Retry Classes",
    ])
    for r in all_results:
        ps = r["p2p"]["summary"]
        rs = r["server_rotation"]["summary"]
        row = ws.append([
            r["app"],
            ps["p2p_confidence"], ps["p2p_score"],
            ps["has_torrent_manifest_component"], ps["has_p2p_class"],
            ps["has_p2p_native_lib"], ps["has_magnet_uri"],
            ps["has_dht"], ps["has_bencoding"], ps["has_webrtc"],
            ps["torrent_string_hit_count"], ps["torrent_opcode_hit_count"],
            rs["rotation_confidence"], rs["rotation_score"],
            rs["unique_base_url_count"], rs["raw_ip_count"],
            rs["server_list_asset_count"], rs["config_fetch_url_count"],
            rs["server_pref_key_count"], rs["retry_class_count"],
        ])
        # Colour P2P confidence column (B)
        last_row = ws.max_row
        ws.cell(last_row, 2).fill = CONF_FILLS.get(ps["p2p_confidence"], NONE_FILL)
        ws.cell(last_row, 13).fill = CONF_FILLS.get(rs["rotation_confidence"], NONE_FILL)

    ws.column_dimensions["A"].width = 40
    for col in "BCDEFGHIJKLMNOPQRST":
        ws.column_dimensions[col].width = 18

    # ── Sheet 2: P2P Torrent Components ──────────────────────────────────────
    ws2 = wb.create_sheet("P2P_Components")
    _h(ws2, ["App", "Type", "Detail"])
    for r in all_results:
        p = r["p2p"]
        for comp in p["torrent_components_in_manifest"]:
            ws2.append([r["app"], "ManifestComponent", _safe(comp)])
        for hit in p["p2p_class_fragment_hits"]:
            ws2.append([r["app"], "SmaliClass",
                        _safe(f"{hit['class']} (fragment: {hit['fragment']})")])
        for lib in p["p2p_native_libs"]:
            ws2.append([r["app"], "NativeLib", _safe(lib)])
        for f in p["torrent_asset_files"]:
            ws2.append([r["app"], "AssetFile", _safe(f)])
        for ev in _cap(p["webrtc_evidence"]):
            ws2.append([r["app"], "WebRTC", _safe(ev["snippet"])])

    # ── Sheet 3: P2P String & Opcode Hits ────────────────────────────────────
    ws3 = wb.create_sheet("P2P_StringHits")
    _h(ws3, ["App", "Pattern", "File:Line", "Snippet"])
    for r in all_results:
        for pat_name, hits in r["p2p"]["torrent_string_hits"].items():
            for h in _cap(hits, 20):
                ws3.append([r["app"], pat_name, _safe(h["ref"]), _safe(h["snippet"])])
        for pat_name, hits in r["p2p"]["torrent_smali_opcode_hits"].items():
            for h in _cap(hits, 10):
                ws3.append([r["app"], f"OPCODE:{pat_name}",
                             _safe(h["ref"]), _safe(h["snippet"])])

    # ── Sheet 4: Server List Assets ──────────────────────────────────────────
    ws4 = wb.create_sheet("ServerList_Assets")
    _h(ws4, ["App", "File", "URL Count", "URLs (first 10)"])
    for r in all_results:
        for asset in r["server_rotation"]["server_list_assets"]:
            ws4.append([
                r["app"],
                _safe(asset["file"]),
                asset["url_count"],
                _safe(", ".join(asset["urls"][:10])),
            ])

    # ── Sheet 5: Base URL Constants ──────────────────────────────────────────
    ws5 = wb.create_sheet("BaseURL_Constants")
    _h(ws5, ["App", "Base URL"])
    for r in all_results:
        for url in r["server_rotation"]["base_url_constants"]:
            ws5.append([r["app"], _safe(url)])

    # ── Sheet 6: Raw IP Endpoints ─────────────────────────────────────────────
    ws6 = wb.create_sheet("RawIP_Endpoints")
    _h(ws6, ["App", "IP Endpoint"])
    for r in all_results:
        for ip in r["server_rotation"]["domain_diversity"]["raw_ip_endpoints"]:
            ws6.append([r["app"], _safe(ip)])

    # ── Sheet 7: Server Pref Keys ─────────────────────────────────────────────
    ws7 = wb.create_sheet("ServerPref_Keys")
    _h(ws7, ["App", "Pref Key", "Class", "Ref"])
    for r in all_results:
        for entry in r["server_rotation"]["server_pref_keys"]:
            ws7.append([r["app"], _safe(entry["key"]),
                        _safe(entry["class"]), _safe(entry["ref"])])

    # ── Sheet 8: Config Fetch URLs ────────────────────────────────────────────
    ws8 = wb.create_sheet("ConfigFetch_URLs")
    _h(ws8, ["App", "URL", "Class", "Ref"])
    for r in all_results:
        for entry in r["server_rotation"]["config_fetch_urls"]:
            ws8.append([r["app"], _safe(entry["url"]),
                        _safe(entry["class"]), _safe(entry["ref"])])

    # ── Sheet 9: Rotation Smali Hits ─────────────────────────────────────────
    ws9 = wb.create_sheet("Rotation_SmaliHits")
    _h(ws9, ["App", "Pattern", "Class", "File:Line", "Snippet"])
    for r in all_results:
        for pat_name, hits in r["server_rotation"]["rotation_smali_hits"].items():
            for h in _cap(hits, 20):
                ws9.append([r["app"], pat_name,
                             _safe(h.get("class", "")),
                             _safe(h["ref"]), _safe(h["snippet"])])

    # ── Sheet 10: Rotation String Hits ───────────────────────────────────────
    ws10 = wb.create_sheet("Rotation_StringHits")
    _h(ws10, ["App", "Pattern", "File", "Snippet"])
    for r in all_results:
        for pat_name, hits in r["server_rotation"]["rotation_string_hits"].items():
            for h in _cap(hits, 20):
                ws10.append([r["app"], pat_name,
                              _safe(h["ref"]), _safe(h["snippet"])])

    # ── Sheet 11: Multi-Host Array Classes ───────────────────────────────────
    ws11 = wb.create_sheet("MultiHost_Classes")
    _h(ws11, ["App", "Class", "URL Constant Count"])
    for r in all_results:
        for entry in r["server_rotation"]["multi_host_array_classes"]:
            ws11.append([r["app"], _safe(entry["class"]), entry["url_const_count"]])

    # ── Sheet 12: Retry / Failover Classes ────────────────────────────────────
    ws12 = wb.create_sheet("Retry_Classes")
    _h(ws12, ["App", "Class", "URL Constant Count"])
    for r in all_results:
        for entry in r["server_rotation"]["retry_exception_classes"]:
            ws12.append([r["app"], _safe(entry["class"]), entry["url_const_count"]])

    # ── Sheet 13: Domain Diversity ───────────────────────────────────────────
    ws13 = wb.create_sheet("Domain_Diversity")
    _h(ws13, ["App", "Unique Base URLs", "TLD Distribution",
               "Raw IPs", "Has Dynamic DNS", "Has Tor", "Has Ngrok"])
    for r in all_results:
        dd = r["server_rotation"]["domain_diversity"]
        ws13.append([
            r["app"],
            dd["unique_base_urls"],
            _safe(json.dumps(dd["tld_distribution"])),
            _safe(", ".join(dd["raw_ip_endpoints"][:20])),
            dd["has_dynamic_dns"],
            dd["has_tor_onion"],
            dd["has_ngrok"],
        ])

    wb.save(output_path)
    log.info(f"Excel report written → {output_path}")


def print_terminal_summary(all_results: list[dict]):
    """Print a concise human-readable summary to stdout."""
    SEP = "─" * 72
    CONF_ICONS = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "NONE": "⚪"}

    print(f"\n{'═'*72}")
    print("  P2P / TORRENT DELIVERY & SERVER ROTATION — ANALYSIS SUMMARY")
    print(f"{'═'*72}\n")

    for r in all_results:
        app    = r["app"]
        ps     = r["p2p"]["summary"]
        rs     = r["server_rotation"]["summary"]
        p_icon = CONF_ICONS.get(ps["p2p_confidence"], "⚪")
        r_icon = CONF_ICONS.get(rs["rotation_confidence"], "⚪")

        print(f"  {app}")
        print(SEP)

        # P2P section
        print(f"  P2P / Torrent Delivery  {p_icon} {ps['p2p_confidence']} (score: {ps['p2p_score']})")
        flags = []
        if ps["has_torrent_manifest_component"]: flags.append("TorrentComponent-in-Manifest")
        if ps["has_p2p_class"]:                  flags.append("P2P-Smali-Class")
        if ps["has_p2p_native_lib"]:             flags.append("P2P-Native-Lib")
        if ps["has_magnet_uri"]:                 flags.append("Magnet-URI")
        if ps["has_tracker_announce"]:           flags.append("Tracker-Announce")
        if ps["has_dht"]:                        flags.append("DHT")
        if ps["has_bencoding"]:                  flags.append("Bencoding")
        if ps["has_webrtc"]:                     flags.append("WebRTC")
        if flags:
            print(f"    Signals  : {', '.join(flags)}")
        print(f"    Hits     : {ps['torrent_string_hit_count']} string / {ps['torrent_opcode_hit_count']} opcode")

        # Torrent components detail
        comps = r["p2p"]["torrent_components_in_manifest"]
        if comps:
            for c in comps[:5]:
                print(f"    Component: {c[:80]}")

        print()

        # Server rotation section
        print(f"  Server Rotation         {r_icon} {rs['rotation_confidence']} (score: {rs['rotation_score']})")
        print(f"    Unique base URLs : {rs['unique_base_url_count']}")
        print(f"    Raw IP endpoints : {rs['raw_ip_count']}")
        print(f"    ServerList assets: {rs['server_list_asset_count']}")
        print(f"    Config fetch URLs: {rs['config_fetch_url_count']}")
        print(f"    Server pref keys : {rs['server_pref_key_count']}")
        print(f"    Retry classes    : {rs['retry_class_count']}")

        # Config fetch URL samples
        for cf in r["server_rotation"]["config_fetch_urls"][:3]:
            print(f"    ConfigURL: {cf['url'][:80]}")

        # Server pref key samples
        for pk in r["server_rotation"]["server_pref_keys"][:3]:
            print(f"    PrefKey  : {pk['key']}")

        # Base URL sample (first 5)
        urls = r["server_rotation"]["base_url_constants"][:5]
        if urls:
            print(f"    BaseURLs (sample): {', '.join(u[:40] for u in urls)}")

        dd = r["server_rotation"]["domain_diversity"]
        extras = []
        if dd["has_dynamic_dns"]: extras.append("DynamicDNS")
        if dd["has_tor_onion"]:   extras.append("Tor/.onion")
        if dd["has_ngrok"]:       extras.append("Ngrok-tunnel")
        if dd["has_raw_ip_endpoints"]:
            extras.append(f"RawIPs({len(dd['raw_ip_endpoints'])})")
        if extras:
            print(f"    Evasion signals: {', '.join(extras)}")

        print()

    print(f"{'═'*72}\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyse decompiled APK folders for P2P/torrent delivery and server rotation."
    )
    parser.add_argument(
        "--folder", "-f",
        default="apks",
        help="Directory containing apktool-decompiled APK subdirectories (default: apks/)",
    )
    parser.add_argument(
        "--output", "-o",
        default="p2p_server_rotation_report",
        help="Output base path — .json and .xlsx will be appended (default: p2p_server_rotation_report)",
    )
    parser.add_argument(
        "--app", "-a",
        default=None,
        help="Analyse only this subdirectory name (for quick single-app runs)",
    )
    args = parser.parse_args()

    base_dir = Path(args.folder)
    if not base_dir.exists():
        log.error(f"Folder not found: {base_dir}")
        sys.exit(1)

    # Discover decompiled APK dirs (they contain AndroidManifest.xml)
    if args.app:
        candidates = [base_dir / args.app]
    else:
        candidates = sorted([
            d for d in base_dir.iterdir()
            if d.is_dir() and (d / "AndroidManifest.xml").exists()
        ])

    if not candidates:
        log.error(f"No decompiled APK directories found under {base_dir}. "
                  "Run apktool first (see README).")
        sys.exit(1)

    log.info(f"Found {len(candidates)} decompiled APK directories.")

    all_results = []
    for apk_dir in candidates:
        try:
            result = analyze_apk_dir(apk_dir)
            all_results.append(result)
        except Exception as exc:
            log.error(f"Failed to analyse {apk_dir.name}: {exc}", exc_info=True)

    # Print terminal summary
    print_terminal_summary(all_results)

    # JSON report
    json_path = args.output + ".json"
    generate_json_report(all_results, json_path)

    # Excel report
    xlsx_path = args.output + ".xlsx"
    generate_excel_report(all_results, xlsx_path)

    log.info("Done.")


if __name__ == "__main__":
    main()
