#!/usr/bin/env python3
"""
IPTV APK Static Analysis Script
================================
Validates claims from:
  "All Hands on Deck! Understanding the End-to-End Lifecycle of Illicit IPTV Services"
  (CCS '26)

Maps directly to the paper's vulnerability taxonomy:
  - Table 3: Consolidated Vulnerability Summary (CWE-based)
  - Table 4: Endpoint Analysis (databases, credentials, API keys, servers)
  - Table 7: Unencrypted Databases
  - Table 8: WebView Components & JS Interfaces
  - Table 9: Excessive Permissions

Usage:
  python iptv_static_analysis.py [--folder <apk_dir>] [--output <report.json>]

Requires: androguard, pandas
"""

import os
import re
import json
import sys
import logging
import argparse
import shutil
import tempfile
import zipfile
from collections import defaultdict

import pandas as pd
from androguard.misc import AnalyzeAPK

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

logging.getLogger("androguard").setLevel(logging.CRITICAL)

# Androguard uses loguru, not stdlib logging. Silence it explicitly so the
# console isn't flooded with millions of DEBUG lines per APK.
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
except Exception:
    pass

# openpyxl rejects ASCII control characters. Strip them before writing cells.
_ILLEGAL_XLSX_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _xlsx_safe(value):
    """Sanitise a single cell value for openpyxl."""
    if value is None:
        return ""
    if isinstance(value, (int, float, bool)):
        return value
    s = str(value)
    return _ILLEGAL_XLSX_CHARS.sub("", s)

# ---------------------------------------------------------------------------
# APKM / split-APK bundle support
# ---------------------------------------------------------------------------
# APKMirror bundles (.apkm) are ZIP archives containing base.apk plus
# split_config.*.apk fragments for density, language, and ABI.
# All code, manifest, and core resources live in base.apk.

_apkm_tmp_dirs = []  # cleaned up at exit


def extract_base_from_apkm(apkm_path):
    """Extract base.apk from an .apkm bundle and return its path.

    Creates a temporary directory that persists until process exit.
    """
    tmp_dir = tempfile.mkdtemp(prefix="apkm_")
    _apkm_tmp_dirs.append(tmp_dir)
    base_apk = os.path.join(tmp_dir, "base.apk")
    with zipfile.ZipFile(apkm_path, "r") as zf:
        if "base.apk" not in zf.namelist():
            raise FileNotFoundError(
                f"No base.apk found inside {os.path.basename(apkm_path)}. "
                f"Contents: {zf.namelist()[:10]}"
            )
        zf.extract("base.apk", tmp_dir)
    print(f"    [apkm] Extracted base.apk from {os.path.basename(apkm_path)} "
          f"({os.path.getsize(base_apk) / 1e6:.1f} MB)")
    return base_apk


import atexit

def _cleanup_apkm_temps():
    for d in _apkm_tmp_dirs:
        shutil.rmtree(d, ignore_errors=True)

atexit.register(_cleanup_apkm_temps)


ANDROID_NS = "http://schemas.android.com/apk/res/android"
DEFAULT_FOLDER = "apks"
DEFAULT_OUTPUT = "iptv_vulnerability_report.json"
CSV_OUTPUT = "iptv_vulnerability_report.csv"

# ---------------------------------------------------------------------------
# Paper-defined constants (from Tables 3, 7, 8, 9)
# ---------------------------------------------------------------------------

# Table 9: Excessive permissions flagged by the paper (CWE-250)
DANGEROUS_IPTV_PERMISSIONS = [
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
]

# Boot persistence permission (covert behavior, all 5 apps)
BOOT_PERMISSION = "android.permission.RECEIVE_BOOT_COMPLETED"

# Known IPTV-related unencrypted database names (Table 7)
KNOWN_IPTV_DB_NAMES = [
    "google_app_measurement.db",
    "google_app_measurement_local.db",
    "google_analytics_v4.db",
    "filedownloader.db",
    "aptoide.db",
    "OfflineUpload.db",
    "iptv.db",
    "tvg.db",
    "medias.db",
    "history.db",
    "transfer_history.db",
    "mx-tracking.db",
    "default.realm",
    "io.realm",
    "com.google.android.gms.ads.db",
]

# Patterns for identifying server types (Table 4)
ANALYTICS_DOMAINS = [
    "google-analytics.com",
    "app-measurement.com",
    "firebase",
    "indicative.com",
    "amplitude.com",
    "mixpanel.com",
    "segment.io",
    "appsflyer.com",
    "adjust.com",
    "branch.io",
    "flurry.com",
]

AD_SERVER_DOMAINS = [
    "googlesyndication.com",
    "pagead2.googlesyndication.com",
    "doubleclick.net",
    "admob",
    "adcolony.com",
    "applovin.com",
    "mopub.com",
    "unity3d.com/ads",
    "inmobi.com",
    "ironsource.com",
    "facebook.com/audience",
    "adserver",
]

# Well-known first-party or benign domains to exclude from "unknown"
BENIGN_DOMAINS = [
    "schemas.android.com",
    "xmlpull.org",
    "w3.org",
    "apache.org",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "android.com",
    "mozilla.org",
    "example.com",
    "localhost",
]

# Crypto detection regexes
ECB_REGEX = re.compile(r"/ECB(?:/|$)", re.I)
CBC_REGEX = re.compile(r"/CBC(?:/|$)", re.I)
URL_REGEX = re.compile(r"(https?://[^\s'\"<>]+)")
DOMAIN_REGEX = re.compile(
    r"https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)"
)

# Logcat logging sinks (CWE-532)
LOGCAT_SINKS = [
    "Landroid/util/Log;->v(",
    "Landroid/util/Log;->d(",
    "Landroid/util/Log;->i(",
    "Landroid/util/Log;->w(",
    "Landroid/util/Log;->e(",
    "Landroid/util/Log;->wtf(",
    "Ljava/lang/System;->out",   # System.out.println
    "Ljava/lang/System;->err",   # System.err.println
]

# SQL injection sinks (CWE-89)
SQL_INJECTION_SINKS = [
    "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(",
    "Landroid/database/sqlite/SQLiteDatabase;->execSQL(",
    "Landroid/database/sqlite/SQLiteDatabase;->compileStatement(",
    "Landroid/content/ContentResolver;->query(",
]

# Parameterized / safe SQL patterns (not vulnerable)
SQL_SAFE_PATTERNS = [
    "Landroid/database/sqlite/SQLiteDatabase;->query(",
    "Landroid/database/sqlite/SQLiteDatabase;->insert(",
    "Landroid/database/sqlite/SQLiteDatabase;->update(",
    "Landroid/database/sqlite/SQLiteDatabase;->delete(",
    "Landroid/database/sqlite/SQLiteQueryBuilder;",
]

# Hardcoded secret patterns (CWE-798)
SECRET_KEY_PATTERNS = [
    re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", re.I),
    re.compile(r"(?:secret|token|password|auth)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{16,}['\"]", re.I),
    re.compile(r"AIza[A-Za-z0-9_\-]{35}"),              # Google API key
    re.compile(r"sk_live_[A-Za-z0-9]{24,}"),             # Stripe secret key
    re.compile(r"ghp_[A-Za-z0-9]{36}"),                  # GitHub PAT
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
]

# Certificate pinning indicators
CERT_PINNING_INDICATORS = [
    "Lokhttp3/CertificatePinner",
    "Lokhttp3/CertificatePinner$Builder;->add(",
    "Lcom/datatheorem/android/trustkit/",
    "Landroid/security/NetworkSecurityPolicy;",
    "Lorg/conscrypt/TrustManagerImpl;",
    "sha256/",  # common pin prefix in strings
]

# WebView JS interface (Table 8)
WEBVIEW_JS_INTERFACE_SINK = "Landroid/webkit/WebView;->addJavascriptInterface("

# Boot receiver indicators
BOOT_ACTIONS = [
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.QUICKBOOT_POWERON",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
]

# ---------------------------------------------------------------------------
# Taint analysis (sources & sinks)
#
# Lightweight taint propagation: locate methods that reference a source API,
# locate methods that reference a sink API, then check whether any sink is
# reachable from a source within a bounded number of forward-callgraph hops
# using Androguard's xref-from / xref-to data.
# ---------------------------------------------------------------------------

TAINT_SOURCES = {
    # User-controllable Intent / Bundle data — the most exploitable entry point
    "intent_extras": [
        "Landroid/content/Intent;->getStringExtra(",
        "Landroid/content/Intent;->getCharSequenceExtra(",
        "Landroid/content/Intent;->getIntExtra(",
        "Landroid/content/Intent;->getLongExtra(",
        "Landroid/content/Intent;->getBooleanExtra(",
        "Landroid/content/Intent;->getBundleExtra(",
        "Landroid/content/Intent;->getParcelableExtra(",
        "Landroid/content/Intent;->getSerializableExtra(",
        "Landroid/content/Intent;->getData(",
        "Landroid/content/Intent;->getDataString(",
        "Landroid/content/Intent;->getAction(",
        "Landroid/content/Intent;->getExtras(",
        "Landroid/net/Uri;->getQueryParameter(",
        "Landroid/os/Bundle;->getString(",
        "Landroid/os/Bundle;->getCharSequence(",
        "Landroid/os/Bundle;->getInt(",
        "Landroid/os/Bundle;->getBundle(",
        "Landroid/os/Bundle;->getParcelable(",
    ],
    # User input from UI
    "user_input": [
        "Landroid/widget/EditText;->getText(",
        "Landroid/widget/TextView;->getText(",
        "Landroid/widget/AutoCompleteTextView;->getText(",
    ],
    # Network input
    "network": [
        "Ljava/net/HttpURLConnection;->getInputStream(",
        "Ljava/net/URL;->openStream(",
        "Lokhttp3/Response;->body(",
        "Lokhttp3/ResponseBody;->string(",
        "Lokhttp3/ResponseBody;->bytes(",
    ],
    # Persistent storage reads
    "shared_prefs": [
        "Landroid/content/SharedPreferences;->getString(",
        "Landroid/content/SharedPreferences;->getInt(",
        "Landroid/content/SharedPreferences;->getBoolean(",
        "Landroid/content/SharedPreferences;->getAll(",
    ],
    # Sensors / device identifiers (privacy-sensitive sources)
    "device_id": [
        "Landroid/telephony/TelephonyManager;->getDeviceId(",
        "Landroid/telephony/TelephonyManager;->getImei(",
        "Landroid/telephony/TelephonyManager;->getSubscriberId(",
        "Landroid/telephony/TelephonyManager;->getLine1Number(",
        "Landroid/telephony/TelephonyManager;->getSimSerialNumber(",
        "Landroid/provider/Settings$Secure;->getString(",
        "Landroid/net/wifi/WifiInfo;->getMacAddress(",
        "Landroid/bluetooth/BluetoothAdapter;->getAddress(",
        "Landroid/accounts/AccountManager;->getAccounts(",
    ],
    "location": [
        "Landroid/location/LocationManager;->getLastKnownLocation(",
        "Landroid/location/Location;->getLatitude(",
        "Landroid/location/Location;->getLongitude(",
        "Lcom/google/android/gms/location/FusedLocationProviderClient;",
    ],
    "audio_camera": [
        "Landroid/media/AudioRecord;-><init>(",
        "Landroid/media/MediaRecorder;->start(",
        "Landroid/hardware/Camera;->open(",
        "Landroid/hardware/camera2/CameraManager;->openCamera(",
    ],
    "contacts_sms": [
        "Landroid/provider/ContactsContract",
        "Landroid/provider/Telephony$Sms",
        "Landroid/telephony/SmsManager;",
    ],
}

TAINT_SINKS = {
    # Network exfiltration
    "network_send": [
        "Ljava/net/HttpURLConnection;->getOutputStream(",
        "Ljava/net/URL;->openConnection(",
        "Lokhttp3/Request$Builder;->url(",
        "Lokhttp3/OkHttpClient;->newCall(",
        "Lretrofit2/Retrofit;",
    ],
    # SQL execution (raw — vulnerable to injection)
    "sql_exec": [
        "Landroid/database/sqlite/SQLiteDatabase;->rawQuery(",
        "Landroid/database/sqlite/SQLiteDatabase;->execSQL(",
        "Landroid/database/sqlite/SQLiteDatabase;->compileStatement(",
    ],
    # File system writes
    "file_write": [
        "Ljava/io/FileOutputStream;-><init>(",
        "Ljava/io/FileWriter;-><init>(",
        "Ljava/io/RandomAccessFile;-><init>(",
        "Ljava/nio/file/Files;->write(",
    ],
    # Logcat (information disclosure)
    "log": [
        "Landroid/util/Log;->v(",
        "Landroid/util/Log;->d(",
        "Landroid/util/Log;->i(",
        "Landroid/util/Log;->w(",
        "Landroid/util/Log;->e(",
        "Landroid/util/Log;->wtf(",
    ],
    # Reflection / dynamic code load (RCE potential)
    "reflection": [
        "Ljava/lang/Class;->forName(",
        "Ljava/lang/reflect/Method;->invoke(",
        "Ldalvik/system/DexClassLoader;-><init>(",
        "Ldalvik/system/PathClassLoader;-><init>(",
    ],
    # Native command execution
    "exec": [
        "Ljava/lang/Runtime;->exec(",
        "Ljava/lang/ProcessBuilder;->start(",
    ],
    # WebView (XSS / open redirect)
    "webview_load": [
        "Landroid/webkit/WebView;->loadUrl(",
        "Landroid/webkit/WebView;->loadData(",
        "Landroid/webkit/WebView;->loadDataWithBaseURL(",
        "Landroid/webkit/WebView;->postUrl(",
    ],
    # Outbound Intent dispatch (intent redirection)
    "intent_dispatch": [
        "Landroid/content/Context;->startActivity(",
        "Landroid/app/Activity;->startActivityForResult(",
        "Landroid/content/Context;->sendBroadcast(",
        "Landroid/content/Context;->startService(",
        "Landroid/app/PendingIntent;->getActivity(",
        "Landroid/app/PendingIntent;->getBroadcast(",
        "Landroid/app/PendingIntent;->getService(",
    ],
    # Crypto sinks (key/IV reuse, hardcoded inputs)
    "crypto": [
        "Ljavax/crypto/Cipher;->doFinal(",
        "Ljavax/crypto/Mac;->doFinal(",
    ],
    # Deserialization
    "deserialize": [
        "Ljava/io/ObjectInputStream;->readObject(",
        "Landroid/os/Parcel;->readSerializable(",
    ],
}

# Severity weights for exploit-chain classification
EXPLOIT_SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
}


# ===========================================================================
# Helper functions
# ===========================================================================

def _method_sig(m):
    """Return stable Lpkg/Class;->name(desc) for MethodAnalysis."""
    em = m.get_method() if hasattr(m, "get_method") else m
    return f"{em.get_class_name()}->{em.get_name()}{em.get_descriptor()}"


def _all_callees(m):
    """Yield string representations of all callees from method m."""
    try:
        for _, callee, _ in m.get_xref_to():
            yield str(callee)
    except Exception:
        return


def _all_strings(analysis):
    """Yield (raw_value: str) from all StringAnalysis objects."""
    for sa in analysis.get_strings():
        try:
            yield sa.get_value() if hasattr(sa, "get_value") else str(sa)
        except Exception:
            yield str(sa)


# ===========================================================================
# Table 3 – Manifest & Configuration Weaknesses
# ===========================================================================

def check_manifest_config(apk, analysis):
    """
    Paper claims (Table 3, row group 'Manifest & Config'):
      - CWE-250: Dangerous Permissions – 4/5 apps
      - CWE-926: Unprotected Exported Components – 4/5 apps
      - CWE-749: Data Backup Enabled – 3/5 apps
    """
    findings = {}

    # ---- CWE-250: Dangerous Permissions ----
    all_perms = set(apk.get_permissions())
    dangerous_found = sorted(all_perms & set(DANGEROUS_IPTV_PERMISSIONS))
    findings["cwe250_dangerous_permissions"] = dangerous_found
    findings["cwe250_has_dangerous_perms"] = bool(dangerous_found)

    # Separate list for Table 9 reproduction
    findings["excessive_permissions"] = dangerous_found

    # ---- CWE-749: allowBackup enabled ----
    try:
        app_tag = apk.get_android_manifest_xml().find("application")
        backup_val = app_tag.get(f"{{{ANDROID_NS}}}allowBackup", "true")
        findings["cwe749_backup_enabled"] = backup_val.lower() == "true"
    except Exception:
        findings["cwe749_backup_enabled"] = True  # Android default

    # ---- CWE-926: Unprotected Exported Components ----
    # Capture rich detail per component: actions, schemes, grantUriPermissions,
    # taskAffinity, launchMode, custom-permission protectionLevel, etc.
    exported_unprotected = []
    exported_details = {"activities": [], "services": [], "receivers": [], "providers": []}
    exported_components_full = []  # rich entry per exported component
    component_map = {
        "activity": "activities",
        "activity-alias": "activities",
        "service": "services",
        "receiver": "receivers",
        "provider": "providers",
    }

    # Build map of custom permission protection levels (for misconfig detection)
    custom_perm_protection = {}
    try:
        for perm_elem in apk.get_android_manifest_xml().findall("permission"):
            pname = perm_elem.get(f"{{{ANDROID_NS}}}name")
            plevel = perm_elem.get(f"{{{ANDROID_NS}}}protectionLevel", "normal")
            if pname:
                custom_perm_protection[pname] = plevel
    except Exception:
        pass

    try:
        manifest_root = apk.get_android_manifest_xml()
        app_element = manifest_root.find("application")
        if app_element is not None:
            for tag, key in component_map.items():
                for elem in app_element.findall(tag):
                    name = elem.get(f"{{{ANDROID_NS}}}name")
                    if not name:
                        continue

                    exported_attr = elem.get(f"{{{ANDROID_NS}}}exported")
                    has_filter = elem.find("intent-filter") is not None
                    perm = elem.get(f"{{{ANDROID_NS}}}permission")
                    grant_uri = elem.get(f"{{{ANDROID_NS}}}grantUriPermissions")
                    task_affinity = elem.get(f"{{{ANDROID_NS}}}taskAffinity")
                    launch_mode = elem.get(f"{{{ANDROID_NS}}}launchMode")
                    authorities = elem.get(f"{{{ANDROID_NS}}}authorities")
                    read_perm = elem.get(f"{{{ANDROID_NS}}}readPermission")
                    write_perm = elem.get(f"{{{ANDROID_NS}}}writePermission")

                    # Collect actions / categories / data schemes
                    actions, categories, schemes, hosts = [], [], [], []
                    for intf in elem.findall("intent-filter"):
                        for a in intf.findall("action"):
                            an = a.get(f"{{{ANDROID_NS}}}name")
                            if an:
                                actions.append(an)
                        for c in intf.findall("category"):
                            cn = c.get(f"{{{ANDROID_NS}}}name")
                            if cn:
                                categories.append(cn)
                        for d in intf.findall("data"):
                            sch = d.get(f"{{{ANDROID_NS}}}scheme")
                            hst = d.get(f"{{{ANDROID_NS}}}host")
                            if sch:
                                schemes.append(sch)
                            if hst:
                                hosts.append(hst)

                    is_exported = (exported_attr == "true") or (
                        exported_attr is None and has_filter
                    )
                    if not is_exported:
                        continue

                    exported_details[key].append(name)

                    # Classify protection
                    protection_level = None
                    if perm and perm in custom_perm_protection:
                        protection_level = custom_perm_protection[perm]
                    elif perm:
                        protection_level = "platform/unknown"

                    # Risk reasons
                    risks = []
                    # Provider with no read/write permission and no custom perm
                    if tag == "provider" and not (perm or read_perm or write_perm):
                        risks.append("Unprotected ContentProvider (data access)")
                    if tag == "provider" and grant_uri == "true":
                        risks.append("grantUriPermissions=true (URI-based access bypass)")
                    # Activity with BROWSABLE category — accepts deep links from any app/web
                    if "android.intent.category.BROWSABLE" in categories:
                        risks.append("BROWSABLE deep link (web-reachable)")
                    # Custom URL scheme — non-https deep link
                    non_std_schemes = [s for s in schemes if s not in ("https", "http")]
                    if non_std_schemes:
                        risks.append(f"Custom URL scheme(s): {','.join(sorted(set(non_std_schemes)))}")
                    # Receiver listening to BOOT_COMPLETED while exported
                    if tag == "receiver" and any(a in BOOT_ACTIONS for a in actions):
                        risks.append("Exported BOOT_COMPLETED receiver")
                    # Misuse of weak custom permission (normal/dangerous instead of signature)
                    if perm and protection_level and protection_level not in (
                        "signature",
                        "signatureOrSystem",
                        "signature|privileged",
                    ):
                        risks.append(
                            f"Custom permission with weak protectionLevel='{protection_level}'"
                        )
                    # singleTask + exported activity — task hijacking risk
                    if tag in ("activity", "activity-alias") and (
                        launch_mode in ("singleTask", "singleInstance")
                    ):
                        risks.append(f"launchMode={launch_mode} on exported activity (task hijacking)")
                    # Unprotected exported component (no permission at all)
                    if not perm and tag != "provider":
                        risks.append("No permission attribute (caller can be any app)")

                    entry = {
                        "type": tag,
                        "name": name,
                        "exported_explicit": exported_attr,
                        "permission": perm,
                        "protection_level": protection_level,
                        "grant_uri_permissions": grant_uri,
                        "authorities": authorities,
                        "read_permission": read_perm,
                        "write_permission": write_perm,
                        "actions": sorted(set(actions)),
                        "categories": sorted(set(categories)),
                        "schemes": sorted(set(schemes)),
                        "hosts": sorted(set(hosts)),
                        "task_affinity": task_affinity,
                        "launch_mode": launch_mode,
                        "risks": risks,
                    }
                    exported_components_full.append(entry)

                    if not perm and not (read_perm and write_perm):
                        exported_unprotected.append(f"{tag}:{name}")
    except Exception:
        pass

    findings["cwe926_exported_unprotected"] = exported_unprotected
    findings["cwe926_exported_unprotected_count"] = len(exported_unprotected)
    findings["exported_details"] = exported_details
    findings["exported_components_full"] = exported_components_full
    findings["exported_components_count"] = len(exported_components_full)
    findings["custom_permissions"] = custom_perm_protection

    return findings


# ===========================================================================
# Table 3 – Cryptographic Weaknesses
# ===========================================================================

def check_cryptographic(apk, analysis):
    """
    Paper claims (Table 3, row group 'Cryptographic'):
      - CWE-327: Weak Signature / Janus (V1-only) – 2/5 apps
      - CWE-330: Insecure RNG (java.util.Random) – 4/5 apps
      - CWE-327: AES in ECB/CBC mode – 4/5 apps
      - Lack of Certificate Pinning – 4/5 apps
    """
    findings = {}

    # ---- CWE-327: Signature scheme (Janus vulnerability) ----
    try:
        v1 = apk.is_signed_v1()
        v2 = apk.is_signed_v2()
        v3 = getattr(apk, "is_signed_v3", lambda: False)()
        findings["cwe327_v1_only_signature"] = v1 and not v2 and not v3
        findings["signature_schemes"] = {"v1": v1, "v2": v2, "v3": v3}
    except Exception:
        findings["cwe327_v1_only_signature"] = False
        findings["signature_schemes"] = {}

    # ---- CWE-330: Insecure RNG ----
    uses_java_random = False
    uses_secure_random_seeded = False
    for m in analysis.get_methods():
        for callee_str in _all_callees(m):
            if "Ljava/util/Random;" in callee_str:
                uses_java_random = True
            if any(
                sig in callee_str
                for sig in (
                    "Ljava/security/SecureRandom;->setSeed(",
                    "Ljava/security/SecureRandom;-><init>([B)V",
                    "Ljava/security/SecureRandom;-><init>(J)V",
                )
            ):
                uses_secure_random_seeded = True
    findings["cwe330_insecure_rng"] = uses_java_random or uses_secure_random_seeded
    findings["cwe330_java_util_random"] = uses_java_random
    findings["cwe330_secure_random_seeded"] = uses_secure_random_seeded

    # ---- CWE-327: AES in ECB/CBC mode ----
    # Collect cipher transformations from methods calling Cipher.getInstance
    cipher_callers = set()
    md_callers = set()
    for m in analysis.get_methods():
        for callee_str in _all_callees(m):
            if "Ljavax/crypto/Cipher;->getInstance(" in callee_str:
                cipher_callers.add(_method_sig(m))
            if "Ljava/security/MessageDigest;->getInstance(" in callee_str:
                md_callers.add(_method_sig(m))

    weak_algos = set()
    non_aead_modes = set()

    for sa in analysis.get_strings():
        s_val = sa.get_value() if hasattr(sa, "get_value") else str(sa)
        s_up = s_val.upper().strip()

        for ref in sa.get_xref_from():
            ref_sig = _method_sig(ref[1])
            if ref_sig in cipher_callers or ref_sig in md_callers:
                # Weak hash algorithms
                if "MD5" in s_up:
                    weak_algos.add("MD5")
                if s_up.replace(" ", "") in ("SHA-1", "SHA1"):
                    weak_algos.add("SHA-1")
                # Weak symmetric ciphers
                if re.search(r"\bDESEDE\b", s_up) or "3DES" in s_up:
                    weak_algos.add("3DES")
                elif re.search(r"\bDES\b", s_up):
                    weak_algos.add("DES")
                if "RC4" in s_up:
                    weak_algos.add("RC4")
                # Insecure modes
                if ECB_REGEX.search(s_val):
                    weak_algos.add("AES/ECB")
                    non_aead_modes.add("ECB")
                if CBC_REGEX.search(s_val):
                    non_aead_modes.add("AES/CBC")

    # Fallback: broad scan if no getInstance callers found
    if not weak_algos and not non_aead_modes:
        for s_val in _all_strings(analysis):
            s_up = s_val.upper().strip()
            if ECB_REGEX.search(s_val):
                weak_algos.add("AES/ECB")
                non_aead_modes.add("ECB")
            if CBC_REGEX.search(s_val):
                non_aead_modes.add("AES/CBC")
            if "MD5" in s_up:
                weak_algos.add("MD5")
            if s_up.replace(" ", "") in ("SHA-1", "SHA1"):
                weak_algos.add("SHA-1")

    findings["cwe327_weak_algos"] = sorted(weak_algos)
    findings["cwe327_ecb_cbc_used"] = bool(non_aead_modes)
    findings["cwe327_non_aead_modes"] = sorted(non_aead_modes)

    # ---- Lack of Certificate Pinning ----
    has_pinning = False
    # Check code-level pinning
    for m in analysis.get_methods():
        for callee_str in _all_callees(m):
            if any(ind in callee_str for ind in CERT_PINNING_INDICATORS[:3]):
                has_pinning = True
                break
        if has_pinning:
            break

    # Check strings for pin hashes
    if not has_pinning:
        for s_val in _all_strings(analysis):
            if any(ind in s_val for ind in CERT_PINNING_INDICATORS[3:]):
                has_pinning = True
                break

    # Check network_security_config.xml reference
    if not has_pinning:
        try:
            app_tag = apk.get_android_manifest_xml().find("application")
            nsc = app_tag.get(f"{{{ANDROID_NS}}}networkSecurityConfig")
            if nsc:
                # If NSC is set, check its content for pin-set
                try:
                    nsc_content = apk.get_file("res/xml/network_security_config.xml")
                    if nsc_content and b"pin-set" in nsc_content:
                        has_pinning = True
                except Exception:
                    pass
        except Exception:
            pass

    findings["no_certificate_pinning"] = not has_pinning

    return findings


# ===========================================================================
# Table 3 – Network & Storage
# ===========================================================================

def check_network_storage(apk, analysis):
    """
    Paper claims (Table 3, row group 'Network & Storage'):
      - CWE-319: Cleartext HTTP Traffic – 1/5 apps
      - CWE-312: Unencrypted Local Storage – 4/5 apps
      - CWE-798: Hardcoded Secrets – 1/5 apps
    """
    findings = {}

    # ---- CWE-319: Cleartext HTTP Traffic ----
    try:
        app_tag = apk.get_android_manifest_xml().find("application")
        ct_val = app_tag.get(f"{{{ANDROID_NS}}}usesCleartextTraffic", "false")
        findings["cwe319_cleartext_traffic"] = ct_val.lower() == "true"
    except Exception:
        findings["cwe319_cleartext_traffic"] = False

    # Also look for explicit http:// RTSP/HTTP URLs in code (paper mentions RTSP)
    cleartext_urls = set()
    for s_val in _all_strings(analysis):
        if s_val.startswith("http://") or s_val.startswith("rtsp://"):
            # Filter out XML namespace noise
            if "schemas.android.com" not in s_val and "xmlpull.org" not in s_val:
                cleartext_urls.add(s_val)
    findings["cleartext_urls_found"] = sorted(cleartext_urls)[:50]  # cap for readability

    # ---- CWE-312: Unencrypted Local Storage ----
    # Detect database files referenced as strings (Table 7)
    db_files = set()
    for s_val in _all_strings(analysis):
        sv = s_val.strip()
        if sv.endswith(".db") or sv.endswith(".db3") or ".sqlite" in sv.lower():
            db_files.add(sv)
        if sv.endswith(".realm"):
            db_files.add(sv)
        # Check known IPTV DB names
        for known in KNOWN_IPTV_DB_NAMES:
            if known in sv:
                db_files.add(known)

    findings["cwe312_unencrypted_databases"] = sorted(db_files)
    findings["cwe312_unencrypted_db_count"] = len(db_files)

    # Check if any DB is written to external storage
    ext_storage_db = False
    for m in analysis.get_methods():
        callees_joined = " ".join(_all_callees(m))
        has_db_sink = any(
            sink in callees_joined
            for sink in (
                "SQLiteDatabase;->openOrCreateDatabase(",
                "SQLiteOpenHelper;->getWritableDatabase(",
                "SQLiteOpenHelper;->getReadableDatabase(",
                "room/Room;->databaseBuilder(",
            )
        )
        has_ext_api = any(
            tok in callees_joined
            for tok in (
                "getExternalFilesDir(",
                "getExternalStorageDirectory(",
                "getExternalCacheDir(",
            )
        )
        if has_db_sink and has_ext_api:
            ext_storage_db = True
            break

    findings["database_in_external_storage"] = ext_storage_db

    # ---- CWE-798: Hardcoded Secrets ----
    hardcoded_secrets = []
    for s_val in _all_strings(analysis):
        for pat in SECRET_KEY_PATTERNS:
            if pat.search(s_val):
                # Truncate for safety
                snippet = s_val[:80] + ("..." if len(s_val) > 80 else "")
                hardcoded_secrets.append(snippet)
                break

    findings["cwe798_hardcoded_secrets"] = hardcoded_secrets
    findings["cwe798_has_hardcoded_secrets"] = bool(hardcoded_secrets)
    findings["cwe798_hardcoded_credentials_count"] = 0  # will be refined below
    findings["cwe798_api_keys_count"] = 0

    # Separate credentials vs API keys
    cred_count = 0
    key_count = 0
    for s_val in _all_strings(analysis):
        s_low = s_val.lower()
        if any(
            w in s_low
            for w in ("password", "passwd", "secret", "auth_token", "bearer")
        ):
            for pat in SECRET_KEY_PATTERNS:
                if pat.search(s_val):
                    cred_count += 1
                    break
        if any(w in s_low for w in ("api_key", "apikey", "api-key")):
            for pat in SECRET_KEY_PATTERNS:
                if pat.search(s_val):
                    key_count += 1
                    break

    findings["cwe798_hardcoded_credentials_count"] = cred_count
    findings["cwe798_api_keys_count"] = key_count

    return findings


# ===========================================================================
# Table 3 – Code-Level Risks
# ===========================================================================

def check_code_level_risks(apk, analysis):
    """
    Paper claims (Table 3, row group 'Code-Level Risks'):
      - CWE-89: SQL Injection – 4/5 apps
      - CWE-532: Sensitive Logging to Logcat – 5/5 apps
    """
    findings = {}

    # ---- CWE-89: SQL Injection ----
    # Detect rawQuery/execSQL usage (potential SQLi when inputs not parameterized)
    sql_injection_sites = []
    for m in analysis.get_methods():
        for callee_str in _all_callees(m):
            for sink in SQL_INJECTION_SINKS:
                if sink in callee_str:
                    sql_injection_sites.append(
                        {
                            "method": _method_sig(m),
                            "sink": callee_str.strip(),
                        }
                    )
                    break

    # Deduplicate by method
    seen = set()
    deduped = []
    for site in sql_injection_sites:
        key = site["method"]
        if key not in seen:
            seen.add(key)
            deduped.append(site)

    findings["cwe89_sql_injection_sites"] = deduped
    findings["cwe89_has_sql_injection_risk"] = bool(deduped)

    # ---- CWE-532: Sensitive Logging to Logcat ----
    logcat_logging = False
    log_call_count = 0
    log_classes = set()
    for m in analysis.get_methods():
        for callee_str in _all_callees(m):
            for sink in LOGCAT_SINKS:
                if sink in callee_str:
                    logcat_logging = True
                    log_call_count += 1
                    # Track which classes are logging
                    try:
                        cls = m.get_method().get_class_name()
                        log_classes.add(cls)
                    except Exception:
                        pass
                    break

    findings["cwe532_sensitive_logging"] = logcat_logging
    findings["cwe532_log_call_count"] = log_call_count
    findings["cwe532_logging_classes_sample"] = sorted(log_classes)[:20]

    return findings


# ===========================================================================
# Table 3 – Covert Behaviors
# ===========================================================================

def check_covert_behaviors(apk, analysis):
    """
    Paper claims (Table 3, row group 'Covert Behaviors'):
      - Unauthorized Audio/Location Capture – 1/5 apps (■ affects user)
      - Auto-Restart on Boot – 5/5 apps (▲ affects developer)

    The paper specifically notes App-B serializes GPS into HTTP params
    via AdsRepository/GetAdsRequest, and stages audio/location telemetry
    in local DBs before exfiltration.
    """
    findings = {}
    all_perms = set(apk.get_permissions())

    # ---- Unauthorized Audio/Location Capture ----
    has_audio_perm = "android.permission.RECORD_AUDIO" in all_perms
    has_fine_loc = "android.permission.ACCESS_FINE_LOCATION" in all_perms
    has_coarse_loc = "android.permission.ACCESS_COARSE_LOCATION" in all_perms
    has_camera = "android.permission.CAMERA" in all_perms

    # Check if the permission is actually used in code (not just declared)
    audio_api_used = False
    location_api_used = False
    camera_api_used = False

    AUDIO_APIS = (
        "Landroid/media/AudioRecord;",
        "Landroid/media/MediaRecorder;",
    )
    LOCATION_APIS = (
        "Landroid/location/LocationManager;->requestLocationUpdates(",
        "Landroid/location/LocationManager;->getLastKnownLocation(",
        "Lcom/google/android/gms/location/FusedLocationProviderClient;",
        "Lcom/google/android/gms/location/LocationRequest;",
    )
    CAMERA_APIS = (
        "Landroid/hardware/Camera;->open(",
        "Landroid/hardware/camera2/CameraManager;->openCamera(",
    )

    for m in analysis.get_methods():
        for callee_str in _all_callees(m):
            if any(api in callee_str for api in AUDIO_APIS):
                audio_api_used = True
            if any(api in callee_str for api in LOCATION_APIS):
                location_api_used = True
            if any(api in callee_str for api in CAMERA_APIS):
                camera_api_used = True

    findings["unauthorized_audio_capture"] = has_audio_perm and audio_api_used
    findings["unauthorized_location_capture"] = (
        has_fine_loc or has_coarse_loc
    ) and location_api_used
    findings["unauthorized_camera_access"] = has_camera and camera_api_used

    # Permission–feature mismatch: permission declared but no corresponding
    # functional code found (paper §3.3 point 4)
    perm_feature_mismatches = []
    if has_audio_perm and not audio_api_used:
        perm_feature_mismatches.append("RECORD_AUDIO declared but no audio API used")
    if has_fine_loc and not location_api_used:
        perm_feature_mismatches.append(
            "ACCESS_FINE_LOCATION declared but no location API used"
        )
    if has_camera and not camera_api_used:
        perm_feature_mismatches.append("CAMERA declared but no camera API used")
    findings["permission_feature_mismatches"] = perm_feature_mismatches

    # ---- Auto-Restart on Boot ----
    has_boot_perm = BOOT_PERMISSION in all_perms

    # Check manifest for BOOT_COMPLETED receivers
    boot_receivers = []
    try:
        manifest_root = apk.get_android_manifest_xml()
        app_element = manifest_root.find("application")
        if app_element is not None:
            for recv in app_element.findall("receiver"):
                for intf in recv.findall("intent-filter"):
                    for action in intf.findall("action"):
                        act_name = action.get(f"{{{ANDROID_NS}}}name", "")
                        if act_name in BOOT_ACTIONS:
                            recv_name = recv.get(f"{{{ANDROID_NS}}}name", "unknown")
                            boot_receivers.append(recv_name)
    except Exception:
        pass

    findings["auto_restart_on_boot"] = has_boot_perm or bool(boot_receivers)
    findings["boot_receivers"] = boot_receivers

    return findings


# ===========================================================================
# Table 4 – Endpoint Analysis
# ===========================================================================

def check_endpoint_analysis(apk, analysis):
    """
    Paper's Table 4 counts per app:
      - Unencrypted Databases
      - Hardcoded Credentials
      - API Keys Exposed
      - Analytics Tracking Servers
      - Ad Servers
      - Unknown API Servers
    """
    findings = {}

    # Collect all URLs/domains from strings
    all_domains = set()
    all_urls = set()
    for s_val in _all_strings(analysis):
        for url_match in URL_REGEX.finditer(s_val):
            url = url_match.group(1)
            all_urls.add(url)
            dm = DOMAIN_REGEX.search(url)
            if dm:
                all_domains.add(dm.group(1).lower())

    # Classify domains
    analytics_servers = set()
    ad_servers = set()
    unknown_servers = set()

    for domain in all_domains:
        is_benign = any(b in domain for b in BENIGN_DOMAINS)
        if is_benign:
            continue

        is_analytics = any(a in domain for a in ANALYTICS_DOMAINS)
        is_ad = any(a in domain for a in AD_SERVER_DOMAINS)

        if is_analytics:
            analytics_servers.add(domain)
        elif is_ad:
            ad_servers.add(domain)
        else:
            unknown_servers.add(domain)

    findings["analytics_tracking_servers"] = sorted(analytics_servers)
    findings["analytics_tracking_server_count"] = len(analytics_servers)
    findings["ad_servers"] = sorted(ad_servers)
    findings["ad_server_count"] = len(ad_servers)
    findings["unknown_api_servers"] = sorted(unknown_servers)
    findings["unknown_api_server_count"] = len(unknown_servers)
    findings["all_extracted_urls"] = sorted(all_urls)[:100]  # cap

    return findings


# ===========================================================================
# Table 8 – WebView Components & JavaScript Interfaces
# ===========================================================================

def check_webview_components(apk, analysis):
    """
    Paper's Table 8: WebView Components used to load HTTP content.
    Identifies classes containing WebView.loadUrl/loadData and
    addJavascriptInterface calls.
    """
    findings = {
        "webview_components": [],
        "javascript_interfaces": [],
        "webview_loads_http": False,
        "webview_loads_https": False,
    }

    LOAD_SINKS = (
        "Landroid/webkit/WebView;->loadUrl(",
        "Landroid/webkit/WebView;->loadData(",
        "Landroid/webkit/WebView;->loadDataWithBaseURL(",
    )

    for m in analysis.get_methods():
        for callee_str in _all_callees(m):
            if any(sink in callee_str for sink in LOAD_SINKS):
                try:
                    comp = _method_sig(m)
                    findings["webview_components"].append(comp)
                except Exception:
                    pass

            if WEBVIEW_JS_INTERFACE_SINK in callee_str:
                try:
                    comp = _method_sig(m)
                    findings["javascript_interfaces"].append(comp)
                except Exception:
                    pass

    findings["webview_components"] = sorted(set(findings["webview_components"]))
    findings["javascript_interfaces"] = sorted(set(findings["javascript_interfaces"]))

    # Check for HTTP content loading in WebViews
    for s_val in _all_strings(analysis):
        if "http://" in s_val and "schemas.android.com" not in s_val:
            findings["webview_loads_http"] = True
        if "https://" in s_val:
            findings["webview_loads_https"] = True

    return findings


# ===========================================================================
# SSL / TLS Vulnerabilities (supplements Table 3 certificate pinning)
# ===========================================================================

def check_ssl_vulnerabilities(analysis):
    """
    Detect insecure HostnameVerifier and WebViewClient SSL error handlers.
    Paper notes WebView HTTP loading without validation enables MITM attacks.
    """
    findings = {
        "insecure_hostname_verifier": False,
        "insecure_ssl_error_handler": False,
        "ssl_issues": [],
    }

    for cls in analysis.get_classes():
        cname = getattr(cls, "name", "")

        # Permissive HostnameVerifier
        if "HostnameVerifier" in cname:
            for m in cls.get_methods():
                mname = getattr(m.get_method(), "name", "")
                if mname == "verify":
                    try:
                        src = m.get_method().source()
                    except Exception:
                        src = ""
                    text = (src or str(m)).lower()
                    if "return true" in text or "return 1" in text:
                        findings["insecure_hostname_verifier"] = True
                        findings["ssl_issues"].append(
                            f"Permissive HostnameVerifier in {cname}"
                        )

        # WebViewClient.onReceivedSslError -> proceed()
        if "WebViewClient" in cname:
            for m in cls.get_methods():
                mname = getattr(m.get_method(), "name", "")
                if "onReceivedSslError" in mname:
                    try:
                        src = m.get_method().source()
                    except Exception:
                        src = ""
                    text = (src or str(m)).lower()
                    if "proceed" in text:
                        findings["insecure_ssl_error_handler"] = True
                        findings["ssl_issues"].append(
                            f"WebView SSL error handler calls proceed() in {cname}"
                        )

    return findings


# ===========================================================================
# Streaming-specific checks (IPTV functionality validation)
# ===========================================================================

def check_iptv_streaming_indicators(analysis):
    """
    Validate that the app is indeed an IPTV streaming app by checking for
    HLS/DASH streaming logic, DRM hooks, and IPTV-specific patterns.
    Paper §3.3 point 2: 'confirming core IPTV functions by tracing HLS/DASH
    streaming logic through call graph analysis and identifying DRM hooks
    via API call patterns.'
    """
    findings = {
        "hls_dash_detected": False,
        "drm_hooks_detected": False,
        "streaming_protocols": [],
        "iptv_indicators": [],
    }

    HLS_INDICATORS = ("m3u8", ".m3u", "HlsMediaSource", "HLS", "hls")
    DASH_INDICATORS = ("mpd", "DashMediaSource", "DASH", "dash")
    RTSP_INDICATORS = ("rtsp://", "RtspMediaSource", "RTSP")
    DRM_INDICATORS = (
        "MediaDrm",
        "Widevine",
        "widevine",
        "com.widevine",
        "DrmSessionManager",
        "ExoMediaDrm",
        "FrameworkMediaDrm",
    )
    IPTV_KEYWORDS = (
        "iptv",
        "epg",          # Electronic Program Guide
        "m3u",
        "playlist",
        "channel",
        "live_tv",
        "livetv",
        "tvguide",
        "catchup",
        "timeshift",
        "vod",
    )

    for s_val in _all_strings(analysis):
        s_low = s_val.lower()
        if any(ind.lower() in s_low for ind in HLS_INDICATORS):
            findings["hls_dash_detected"] = True
            if "HLS" not in findings["streaming_protocols"]:
                findings["streaming_protocols"].append("HLS")
        if any(ind.lower() in s_low for ind in DASH_INDICATORS):
            findings["hls_dash_detected"] = True
            if "DASH" not in findings["streaming_protocols"]:
                findings["streaming_protocols"].append("DASH")
        if any(ind.lower() in s_low for ind in RTSP_INDICATORS):
            if "RTSP" not in findings["streaming_protocols"]:
                findings["streaming_protocols"].append("RTSP")
        if any(ind.lower() in s_low for ind in DRM_INDICATORS):
            findings["drm_hooks_detected"] = True
        for kw in IPTV_KEYWORDS:
            if kw in s_low:
                if kw not in findings["iptv_indicators"]:
                    findings["iptv_indicators"].append(kw)

    return findings


# ===========================================================================
# Taint Flow Analysis (lightweight, callgraph-bounded)
# ===========================================================================

def _flatten(d):
    """Yield (label, pattern) for every pattern in a {label: [patterns]} dict."""
    for label, pats in d.items():
        for p in pats:
            yield label, p


def check_taint_flows(analysis, max_depth=4, per_chain_cap=200):
    """
    Detect source-to-sink taint chains using Androguard's call graph.

    Strategy:
      1) Identify methods that *contain a callee* matching any taint source.
      2) Identify methods that *contain a callee* matching any taint sink.
      3) For each sink-bearing method, BFS the reverse-call graph (xref-from)
         up to `max_depth` levels. If any visited method is also source-bearing
         (or *is* a source-bearing method itself), record it as a taint chain.

    Output is summarised by (source_label, sink_label) pairs and lists up to
    `per_chain_cap` example chains for each pair.
    """
    findings = {
        "taint_source_categories": [],
        "taint_sink_categories": [],
        "taint_chains": [],
        "taint_chain_count": 0,
        "taint_chain_summary": {},   # "source_label->sink_label" -> count
    }

    # Map: method_signature -> set of source labels reached by that method
    src_methods = defaultdict(set)
    # Map: method_signature -> set of (sink_label, sink_callee_string)
    sink_methods = defaultdict(set)
    # Map: method_signature -> MethodAnalysis object (for xref traversal)
    sig_to_method = {}

    src_patterns = list(_flatten(TAINT_SOURCES))
    sink_patterns = list(_flatten(TAINT_SINKS))

    for m in analysis.get_methods():
        sig = _method_sig(m)
        sig_to_method[sig] = m
        for callee_str in _all_callees(m):
            for label, pat in src_patterns:
                if pat in callee_str:
                    src_methods[sig].add(label)
            for label, pat in sink_patterns:
                if pat in callee_str:
                    sink_methods[sig].add(label)

    findings["taint_source_categories"] = sorted({lbl for s in src_methods.values() for lbl in s})
    findings["taint_sink_categories"] = sorted({lbl for s in sink_methods.values() for lbl in s})

    chains = []
    summary = defaultdict(int)

    # For each sink-bearing method, BFS backwards via xref-from; if we hit
    # a source-bearing method (or the sink-bearing method is itself source-bearing),
    # record one chain per (src_label, sink_label) pair.
    for sink_sig, sink_labels in sink_methods.items():
        if len(chains) >= 5000:  # global guard
            break

        # Direct source/sink overlap
        if sink_sig in src_methods:
            for sl in src_methods[sink_sig]:
                for kl in sink_labels:
                    key = f"{sl}->{kl}"
                    summary[key] += 1
                    if summary[key] <= per_chain_cap:
                        chains.append({
                            "source_label": sl,
                            "sink_label": kl,
                            "depth": 0,
                            "path": [sink_sig],
                        })
            continue

        # BFS reverse callgraph
        visited = {sink_sig}
        frontier = [(sink_sig, [sink_sig])]
        depth = 0
        found_for_this_sink = False
        while frontier and depth < max_depth and not found_for_this_sink:
            new_frontier = []
            for cur_sig, path in frontier:
                cur_m = sig_to_method.get(cur_sig)
                if cur_m is None:
                    continue
                try:
                    callers = list(cur_m.get_xref_from())
                except Exception:
                    callers = []
                for entry in callers:
                    # entry is typically (class, method, offset) tuple
                    try:
                        caller_m = entry[1] if len(entry) >= 2 else entry
                    except Exception:
                        continue
                    try:
                        c_sig = _method_sig(caller_m)
                    except Exception:
                        continue
                    if c_sig in visited:
                        continue
                    visited.add(c_sig)
                    new_path = path + [c_sig]
                    if c_sig in src_methods:
                        for sl in src_methods[c_sig]:
                            for kl in sink_labels:
                                key = f"{sl}->{kl}"
                                summary[key] += 1
                                if summary[key] <= per_chain_cap:
                                    chains.append({
                                        "source_label": sl,
                                        "sink_label": kl,
                                        "depth": depth + 1,
                                        # Reverse so it reads source -> ... -> sink
                                        "path": list(reversed(new_path)),
                                    })
                        found_for_this_sink = True
                    new_frontier.append((c_sig, new_path))
            frontier = new_frontier
            depth += 1

    findings["taint_chains"] = chains[:per_chain_cap * 5]
    findings["taint_chain_count"] = sum(summary.values())
    findings["taint_chain_summary"] = dict(summary)
    return findings


# ===========================================================================
# Per-app Exploit Chain Analysis
# ===========================================================================

def check_exploit_chains(apk, analysis, accumulated):
    """
    Combine all per-app findings into named exploit chain reports.
    Each chain has a type, severity, description, and the evidence that
    triggered it. This is the closest static analysis can come to
    end-to-end exploitability without dynamic verification.
    """
    chains = []

    del apk, analysis  # unused — consistent signature for orchestrator
    exported_full = accumulated.get("exported_components_full", [])
    has_sql = accumulated.get("cwe89_has_sql_injection_risk", False)
    has_cleartext = accumulated.get("cwe319_cleartext_traffic", False)
    has_v1_only = accumulated.get("cwe327_v1_only_signature", False)
    has_ecb = accumulated.get("cwe327_ecb_cbc_used", False)
    has_secret = accumulated.get("cwe798_has_hardcoded_secrets", False)
    has_backup = accumulated.get("cwe749_backup_enabled", False)
    no_pinning = accumulated.get("no_certificate_pinning", False)
    js_iface = accumulated.get("javascript_interfaces", [])
    wv_loads_http = accumulated.get("webview_loads_http", False)
    insecure_hv = accumulated.get("insecure_hostname_verifier", False)
    insecure_ssl = accumulated.get("insecure_ssl_error_handler", False)
    audio_used = accumulated.get("unauthorized_audio_capture", False)
    loc_used = accumulated.get("unauthorized_location_capture", False)
    cam_used = accumulated.get("unauthorized_camera_access", False)
    taint_summary = accumulated.get("taint_chain_summary", {})

    # Helper to add a chain
    def add(typ, sev, desc, evidence):
        chains.append({
            "type": typ,
            "severity": sev,
            "description": desc,
            "evidence": evidence,
        })

    # 1. Exported provider with no permission and SQL execution → SQL injection over IPC
    exported_providers_unprot = [
        e for e in exported_full
        if e["type"] == "provider" and not (e.get("permission") or e.get("read_permission") or e.get("write_permission"))
    ]
    if exported_providers_unprot and has_sql:
        add(
            "Cross-App SQL Injection via Exported ContentProvider",
            "CRITICAL",
            "Unprotected exported ContentProvider plus rawQuery/execSQL sites — "
            "any installed app can issue arbitrary SQL via the provider URI.",
            {
                "providers": [p["name"] for p in exported_providers_unprot],
                "sql_sites_present": True,
            },
        )

    # 2. Exported provider with grantUriPermissions=true → URI-based file leak / path traversal
    leaky_providers = [
        e for e in exported_full
        if e["type"] == "provider" and e.get("grant_uri_permissions") == "true"
    ]
    if leaky_providers:
        add(
            "Path Traversal / Arbitrary File Read via grantUriPermissions",
            "HIGH",
            "ContentProvider exposes URI grants to other apps; without strict path "
            "validation an attacker may read arbitrary app-private files.",
            {"providers": [p["name"] for p in leaky_providers]},
        )

    # 3. Custom URL scheme deep links on exported activity → intent spoofing / open redirect
    deep_link_acts = [
        e for e in exported_full
        if e["type"] in ("activity", "activity-alias")
        and any(s not in ("https", "http") for s in e.get("schemes", []))
    ]
    if deep_link_acts:
        add(
            "Deep-Link / Intent Spoofing",
            "MEDIUM",
            "Exported activities with custom URL schemes accept untrusted Intents "
            "from any app or web page (BROWSABLE category) — potential for "
            "credential/session theft via crafted deep links.",
            {"activities": [a["name"] for a in deep_link_acts][:20]},
        )

    # 4. WebView XSS / RCE chain
    if js_iface and wv_loads_http:
        add(
            "WebView JavaScript Interface RCE",
            "CRITICAL",
            "addJavascriptInterface used while WebView loads cleartext HTTP "
            "content — an MITM attacker can inject JS that calls into the host "
            "app via @JavascriptInterface (CVE-2012-6636 / CWE-749 pattern).",
            {"js_interface_methods": js_iface[:10], "http_loaded": True},
        )
    elif js_iface and (insecure_hv or insecure_ssl):
        add(
            "WebView JavaScript Interface + Permissive TLS",
            "HIGH",
            "addJavascriptInterface used and TLS validation is disabled "
            "(permissive HostnameVerifier or WebViewClient.proceed() on SSL "
            "error) — MITM can still reach the JS bridge.",
            {"js_interface_methods": js_iface[:10]},
        )

    # 5. Janus signature vulnerability (V1-only on legacy targetSdk)
    if has_v1_only:
        add(
            "Janus APK Signature Bypass (CVE-2017-13156)",
            "HIGH",
            "APK signed only with the v1 (JAR) scheme. On Android < 7.0 an "
            "attacker can prepend a malicious DEX without invalidating the "
            "signature.",
            {"signature_schemes": accumulated.get("signature_schemes", {})},
        )

    # 6. Cleartext network + sensitive sinks → MITM data exfil
    if has_cleartext and (audio_used or loc_used or has_secret):
        add(
            "Cleartext Exfiltration of Sensitive Data",
            "HIGH",
            "Cleartext HTTP allowed in manifest combined with collection of "
            "sensitive data (location/audio/secrets). MITM can intercept and "
            "modify in transit.",
            {
                "audio": audio_used,
                "location": loc_used,
                "hardcoded_secrets": has_secret,
            },
        )

    # 7. Lack of certificate pinning + auth/token telemetry
    if no_pinning and (has_secret or accumulated.get("cwe798_api_keys_count", 0) > 0):
        add(
            "Token Theft via Missing Certificate Pinning",
            "MEDIUM",
            "App ships hardcoded API keys / credentials and performs TLS "
            "without certificate pinning — server impersonation can capture "
            "credentials.",
            {"api_keys": accumulated.get("cwe798_api_keys_count", 0)},
        )

    # 8. Insecure crypto (ECB/AES with hardcoded secrets) → credential disclosure
    if has_ecb and has_secret:
        add(
            "Hardcoded Key + ECB / Insecure Mode",
            "HIGH",
            "AES/ECB or otherwise insecure transformation observed alongside "
            "hardcoded secrets in the binary — encrypted blobs (e.g. cached "
            "credentials, license tokens) are recoverable.",
            {
                "modes": accumulated.get("cwe327_non_aead_modes", []),
                "weak_algos": accumulated.get("cwe327_weak_algos", []),
            },
        )

    # 9. Insecure deserialization paths
    if any(k.endswith("->deserialize") for k in taint_summary):
        add(
            "Untrusted Input → Deserialization",
            "HIGH",
            "Tainted data from Intent extras / network reaches "
            "ObjectInputStream.readObject — classic insecure deserialization "
            "vector (RCE on vulnerable gadget chains).",
            {
                "matched_chains": {
                    k: v for k, v in taint_summary.items() if k.endswith("->deserialize")
                }
            },
        )

    # 10. Untrusted input → reflection / dynamic class loader (RCE potential)
    if any(k.endswith("->reflection") for k in taint_summary):
        add(
            "Untrusted Input → Reflection / DexClassLoader",
            "HIGH",
            "Tainted source flows into Class.forName / Method.invoke / "
            "DexClassLoader — attacker may load arbitrary code.",
            {
                "matched_chains": {
                    k: v for k, v in taint_summary.items() if k.endswith("->reflection")
                }
            },
        )

    # 11. Untrusted input → command execution
    if any(k.endswith("->exec") for k in taint_summary):
        add(
            "Untrusted Input → Runtime.exec / ProcessBuilder",
            "CRITICAL",
            "Tainted source flows into a process-execution sink — command "
            "injection is feasible if any caller passes attacker-controlled "
            "strings.",
            {
                "matched_chains": {
                    k: v for k, v in taint_summary.items() if k.endswith("->exec")
                }
            },
        )

    # 12. Intent extras → outbound Intent dispatch (intent redirection / PendingIntent forwarding)
    intent_redir = {
        k: v for k, v in taint_summary.items()
        if k.startswith("intent_extras->intent_dispatch")
    }
    if intent_redir:
        add(
            "Intent Redirection / Implicit PendingIntent Forwarding",
            "MEDIUM",
            "Intent extras flow into another startActivity / sendBroadcast "
            "/ PendingIntent. Without explicit component restriction this is "
            "the classic 'intent redirection' bug (CWE-927 / CVE-2023-20963 "
            "pattern).",
            {"matched_chains": intent_redir},
        )

    # 13. Backup enabled + DBs / secrets → adb-backup data theft
    if has_backup and (
        accumulated.get("cwe312_unencrypted_db_count", 0) > 0 or has_secret
    ):
        add(
            "ADB Backup Data Exfiltration",
            "MEDIUM",
            "android:allowBackup=true and unencrypted SQLite databases / "
            "hardcoded secrets present — `adb backup` (or any device with USB "
            "debug) yields a recoverable copy of user data on Android < 12.",
            {
                "db_count": accumulated.get("cwe312_unencrypted_db_count", 0),
                "secrets": has_secret,
            },
        )

    # 14. BOOT_COMPLETED receiver exported + sensitive permissions → silent re-arm
    boot_recv_exported = [
        e for e in exported_full
        if e["type"] == "receiver"
        and any(a in BOOT_ACTIONS for a in e.get("actions", []))
        and not e.get("permission")
    ]
    if boot_recv_exported and (audio_used or loc_used or cam_used):
        add(
            "Persistent Background Surveillance on Boot",
            "HIGH",
            "Exported BOOT_COMPLETED receiver with no permission, plus active "
            "use of audio/location/camera APIs — app silently restarts and "
            "resumes data collection; receiver can also be triggered by other "
            "apps.",
            {
                "boot_receivers": [b["name"] for b in boot_recv_exported],
                "audio": audio_used,
                "location": loc_used,
                "camera": cam_used,
            },
        )

    # 15. Sensitive sources reaching log sink (PII to logcat)
    sensitive_log = {
        k: v for k, v in taint_summary.items()
        if k.endswith("->log") and k.split("->")[0] in
        ("device_id", "location", "intent_extras", "shared_prefs", "user_input", "network")
    }
    if sensitive_log:
        add(
            "Sensitive Data Logged to Logcat (CWE-532)",
            "LOW",
            "Tainted sensitive source data reaches Log.* — pre-Android 4.1 "
            "this is world-readable; on modern Android any app holding "
            "READ_LOGS sees it. Useful auxiliary leak for chained attacks.",
            {"matched_chains": sensitive_log},
        )

    # 16. Permissive HostnameVerifier — universal MITM
    if insecure_hv or insecure_ssl:
        add(
            "Universal MITM via Disabled TLS Validation",
            "CRITICAL",
            "HostnameVerifier returns true unconditionally and/or "
            "WebViewClient.onReceivedSslError() calls proceed() — any TLS "
            "endpoint in the app is MITM-able.",
            {
                "permissive_hostname_verifier": insecure_hv,
                "ssl_error_proceed": insecure_ssl,
            },
        )

    severity_score = sum(EXPLOIT_SEVERITY_WEIGHTS.get(c["severity"], 0) for c in chains)

    return {
        "exploit_chains": chains,
        "exploit_chain_count": len(chains),
        "exploit_severity_score": severity_score,
        "exploit_severity_breakdown": {
            sev: sum(1 for c in chains if c["severity"] == sev)
            for sev in EXPLOIT_SEVERITY_WEIGHTS
        },
    }


# ===========================================================================
# Risk Score (paper-aligned)
# ===========================================================================

def calculate_paper_risk_score(results):
    """
    Composite risk score based on the paper's vulnerability categories.
    Weight reflects severity as described in the paper.
    """
    score = 0

    # Manifest & Config
    if results.get("cwe250_has_dangerous_perms"):
        score += 3 * min(len(results.get("cwe250_dangerous_permissions", [])), 4)
    if results.get("cwe926_exported_unprotected_count", 0) > 0:
        score += min(results["cwe926_exported_unprotected_count"], 20)
    if results.get("cwe749_backup_enabled"):
        score += 2

    # Cryptographic
    if results.get("cwe327_v1_only_signature"):
        score += 3
    if results.get("cwe330_insecure_rng"):
        score += 3
    if results.get("cwe327_ecb_cbc_used"):
        score += 4
    if results.get("no_certificate_pinning"):
        score += 3

    # Network & Storage
    if results.get("cwe319_cleartext_traffic"):
        score += 5
    if results.get("cwe312_unencrypted_db_count", 0) > 0:
        score += min(results["cwe312_unencrypted_db_count"], 10)
    if results.get("cwe798_has_hardcoded_secrets"):
        score += 5

    # Code-Level
    if results.get("cwe89_has_sql_injection_risk"):
        score += 4
    if results.get("cwe532_sensitive_logging"):
        score += 2

    # Covert Behaviors
    if results.get("unauthorized_audio_capture"):
        score += 5
    if results.get("unauthorized_location_capture"):
        score += 5
    if results.get("auto_restart_on_boot"):
        score += 2

    # Exploit chains and taint flows
    score += results.get("exploit_severity_score", 0)
    if results.get("taint_chain_count", 0) > 0:
        # Reward presence of *any* source→sink chains, capped
        score += min(results["taint_chain_count"], 20)

    return score


# ===========================================================================
# Main APK Analysis Orchestrator
# ===========================================================================

def analyze_apk(apk_path):
    """Analyze a single APK file and return structured results."""
    try:
        basename = os.path.basename(apk_path)
        print(f"[*] Loading: {basename}")
        apk, _, analysis = AnalyzeAPK(apk_path)
        app_name = apk.get_app_name() or basename
        pkg_name = apk.get_package() or "unknown"

        print(f"[*] Analyzing: {app_name} ({pkg_name})")
        results = {
            "apk_file": basename,
            "app_name": app_name,
            "package_name": pkg_name,
        }

        print("    → Manifest & Configuration (CWE-250, CWE-926, CWE-749)...")
        results.update(check_manifest_config(apk, analysis))

        print("    → Cryptographic weaknesses (CWE-327, CWE-330)...")
        results.update(check_cryptographic(apk, analysis))

        print("    → Network & Storage (CWE-319, CWE-312, CWE-798)...")
        results.update(check_network_storage(apk, analysis))

        print("    → Code-Level Risks (CWE-89, CWE-532)...")
        results.update(check_code_level_risks(apk, analysis))

        print("    → Covert Behaviors (boot persistence, audio/location)...")
        results.update(check_covert_behaviors(apk, analysis))

        print("    → Endpoint Analysis (Table 4)...")
        results.update(check_endpoint_analysis(apk, analysis))

        print("    → WebView Components (Table 8)...")
        results.update(check_webview_components(apk, analysis))

        print("    → SSL/TLS Vulnerabilities...")
        results.update(check_ssl_vulnerabilities(analysis))

        print("    → IPTV Streaming Indicators...")
        results.update(check_iptv_streaming_indicators(analysis))

        print("    → Taint Flow Analysis (sources → sinks)...")
        results.update(check_taint_flows(analysis))

        print("    → Per-app Exploit Chain Analysis...")
        results.update(check_exploit_chains(apk, analysis, results))

        results["risk_score"] = calculate_paper_risk_score(results)
        print(f"    ✓ Done — Risk Score: {results['risk_score']} | "
              f"Exploit Chains: {results.get('exploit_chain_count', 0)} | "
              f"Taint Flows: {results.get('taint_chain_count', 0)}")

        return results

    except Exception as e:
        print(f"[!] Error analyzing {os.path.basename(apk_path)}: {e}")
        return {"apk_file": os.path.basename(apk_path), "analysis_error": str(e)}


# ===========================================================================
# Report Generation (maps to paper Tables 3, 4, 7, 8, 9)
# ===========================================================================

def generate_table3_summary(all_results):
    """
    Reproduce Table 3: Consolidated Vulnerability Summary.
    Output a matrix of CWEs × apps with ● ▲ ■ markers.
    """
    print("\n" + "=" * 80)
    print("TABLE 3 REPRODUCTION: Consolidated Vulnerability Summary")
    print("=" * 80)

    apps = [r for r in all_results if "analysis_error" not in r]
    if not apps:
        print("  No successful analyses.")
        return

    rows = [
        ("Manifest & Config", "Dangerous Permissions (CWE-250)", "cwe250_has_dangerous_perms"),
        ("Manifest & Config", "Unprotected Exported Components (CWE-926)", "cwe926_exported_unprotected_count"),
        ("Manifest & Config", "Data Backup Enabled (CWE-749)", "cwe749_backup_enabled"),
        ("Cryptographic", "Weak Signature / Janus (CWE-327)", "cwe327_v1_only_signature"),
        ("Cryptographic", "Insecure RNG (CWE-330)", "cwe330_insecure_rng"),
        ("Cryptographic", "AES in ECB/CBC mode (CWE-327)", "cwe327_ecb_cbc_used"),
        ("Cryptographic", "Lack of Certificate Pinning", "no_certificate_pinning"),
        ("Network & Storage", "Cleartext HTTP Traffic (CWE-319)", "cwe319_cleartext_traffic"),
        ("Network & Storage", "Unencrypted Local Storage (CWE-312)", "cwe312_unencrypted_db_count"),
        ("Network & Storage", "Hardcoded Secrets (CWE-798)", "cwe798_has_hardcoded_secrets"),
        ("Code-Level Risks", "SQL Injection (CWE-89)", "cwe89_has_sql_injection_risk"),
        ("Code-Level Risks", "Sensitive Logging to Logcat (CWE-532)", "cwe532_sensitive_logging"),
        ("Covert Behaviors", "Unauthorized Audio/Location Capture", "unauthorized_audio_capture"),
        ("Covert Behaviors", "Auto-Restart on Boot", "auto_restart_on_boot"),
    ]

    # Header
    app_labels = [r.get("app_name", r["apk_file"])[:15] for r in apps]
    header = f"{'Category':<20} {'Subcategory':<42} " + " ".join(
        f"{lbl:>15}" for lbl in app_labels
    )
    print(header)
    print("-" * len(header))

    for cat, subcat, key in rows:
        vals = []
        for r in apps:
            v = r.get(key, False)
            if isinstance(v, bool):
                vals.append("●" if v else " ")
            elif isinstance(v, int):
                vals.append("●" if v > 0 else " ")
            else:
                vals.append("●" if v else " ")
        line = f"{cat:<20} {subcat:<42} " + " ".join(f"{v:>15}" for v in vals)
        print(line)

    # Tally
    print("\nLegend: ● = Vulnerability present")
    for cat, subcat, key in rows:
        count = sum(
            1
            for r in apps
            if (
                (isinstance(r.get(key), bool) and r.get(key))
                or (isinstance(r.get(key), int) and r.get(key) > 0)
            )
        )
        print(f"  {subcat}: {count}/{len(apps)} apps")


def generate_table4_summary(all_results):
    """Reproduce Table 4: Endpoint Analysis."""
    print("\n" + "=" * 80)
    print("TABLE 4 REPRODUCTION: Endpoint Analysis")
    print("=" * 80)

    apps = [r for r in all_results if "analysis_error" not in r]
    if not apps:
        return

    header = (
        f"{'App Name':<20} {'Unenc DBs':>10} {'Hardcoded Creds':>16} "
        f"{'API Keys':>10} {'Analytics':>10} {'Ad Servers':>11} {'Unknown':>10}"
    )
    print(header)
    print("-" * len(header))

    for r in apps:
        name = r.get("app_name", r["apk_file"])[:18]
        print(
            f"{name:<20} "
            f"{r.get('cwe312_unencrypted_db_count', 0):>10} "
            f"{r.get('cwe798_hardcoded_credentials_count', 0):>16} "
            f"{r.get('cwe798_api_keys_count', 0):>10} "
            f"{r.get('analytics_tracking_server_count', 0):>10} "
            f"{r.get('ad_server_count', 0):>11} "
            f"{r.get('unknown_api_server_count', 0):>10}"
        )


def generate_table7_summary(all_results):
    """Reproduce Table 7: Unencrypted Databases."""
    print("\n" + "=" * 80)
    print("TABLE 7 REPRODUCTION: Unencrypted Databases")
    print("=" * 80)

    apps = [r for r in all_results if "analysis_error" not in r]
    for r in apps:
        name = r.get("app_name", r["apk_file"])
        dbs = r.get("cwe312_unencrypted_databases", [])
        print(f"\n{name}:")
        if dbs:
            print(f"  {', '.join(dbs)}")
        else:
            print("  (none detected)")


def generate_table8_summary(all_results):
    """Reproduce Table 8: WebView Components."""
    print("\n" + "=" * 80)
    print("TABLE 8 REPRODUCTION: WebView Components & JavaScript Interfaces")
    print("=" * 80)

    apps = [r for r in all_results if "analysis_error" not in r]
    for r in apps:
        name = r.get("app_name", r["apk_file"])
        wv = r.get("webview_components", [])
        js = r.get("javascript_interfaces", [])
        if wv or js:
            print(f"\n{name}:")
            if wv:
                print(f"  WebView loaders: {', '.join(wv[:10])}")
            if js:
                print(f"  JS interfaces:   {', '.join(js[:10])}")


def generate_table9_summary(all_results):
    """Reproduce Table 9: Excessive Permissions."""
    print("\n" + "=" * 80)
    print("TABLE 9 REPRODUCTION: Excessive Android Permissions")
    print("=" * 80)

    apps = [r for r in all_results if "analysis_error" not in r]
    for r in apps:
        name = r.get("app_name", r["apk_file"])
        perms = r.get("excessive_permissions", [])
        if perms:
            print(f"\n{name}:")
            print(f"  {', '.join(perms)}")


def generate_full_report(all_results, output_path):
    """Write complete JSON report, CSV summary, and Excel workbook."""
    # JSON report (full detail)
    # Convert sets to lists for JSON serialization
    serializable = []
    for r in all_results:
        clean = {}
        for k, v in r.items():
            if isinstance(v, set):
                clean[k] = sorted(v)
            else:
                clean[k] = v
        serializable.append(clean)

    with open(output_path, "w") as f:
        json.dump(serializable, f, indent=2, default=str)
    print(f"\n[+] Full JSON report saved to: {output_path}")

    # CSV summary (Table 3 matrix style)
    csv_path = output_path.replace(".json", ".csv")
    summary_keys = [
        "apk_file",
        "app_name",
        "package_name",
        "cwe250_has_dangerous_perms",
        "exported_components_count",
        "cwe926_exported_unprotected_count",
        "cwe749_backup_enabled",
        "cwe327_v1_only_signature",
        "cwe330_insecure_rng",
        "cwe327_ecb_cbc_used",
        "no_certificate_pinning",
        "cwe319_cleartext_traffic",
        "cwe312_unencrypted_db_count",
        "cwe798_has_hardcoded_secrets",
        "cwe89_has_sql_injection_risk",
        "cwe532_sensitive_logging",
        "unauthorized_audio_capture",
        "unauthorized_location_capture",
        "auto_restart_on_boot",
        "analytics_tracking_server_count",
        "ad_server_count",
        "unknown_api_server_count",
        "taint_chain_count",
        "exploit_chain_count",
        "exploit_severity_score",
        "risk_score",
    ]

    rows = []
    for r in all_results:
        row = {k: r.get(k, "") for k in summary_keys}
        rows.append(row)

    df = pd.DataFrame(rows, columns=summary_keys)
    df.to_csv(csv_path, index=False)
    print(f"[+] CSV summary saved to: {csv_path}")

    # Excel workbook with multiple sheets
    xlsx_path = output_path.replace(".json", ".xlsx")
    generate_excel_report(all_results, xlsx_path, summary_keys)


def _truncate(s, n=32000):
    """Excel cell hard-limit is 32767 characters."""
    s = str(s)
    return s if len(s) <= n else s[:n] + "...[truncated]"


def _sanitize_df_for_xlsx(df):
    """Apply _xlsx_safe to every object column so openpyxl never chokes."""
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].map(_xlsx_safe)
    return df


def _safe_write(writer, df, sheet_name):
    df = _sanitize_df_for_xlsx(df)
    df.to_excel(writer, sheet_name=sheet_name, index=False)


def generate_excel_report(all_results, xlsx_path, summary_keys):
    """
    Write a multi-sheet Excel workbook summarising every analysis dimension.

    Sheets:
      - Summary, Permissions, ExportedComponents, TaintFlows, ExploitChains,
        Endpoints, WebView, CleartextURLs, HardcodedSecrets, Databases,
        CryptoFindings, IPTVIndicators, RiskScores, BootReceivers
    """
    apps = [r for r in all_results if "analysis_error" not in r]

    with pd.ExcelWriter(xlsx_path, engine="openpyxl") as writer:
        # 1) Summary
        df = pd.DataFrame(
            [{k: r.get(k, "") for k in summary_keys} for r in all_results],
            columns=summary_keys,
        )
        _safe_write(writer, df, "Summary")

        # 2) Permissions (long-form, one row per (app, permission))
        rows = []
        for r in apps:
            for p in r.get("excessive_permissions", []):
                rows.append({"app": r.get("app_name", r["apk_file"]),
                             "package": r.get("package_name", ""),
                             "dangerous_permission": p})
        _safe_write(writer, pd.DataFrame(rows or [{"info": "no dangerous permissions found"}]), "Permissions")

        # 3) ExportedComponents (one row per component)
        rows = []
        for r in apps:
            for c in r.get("exported_components_full", []):
                rows.append({
                    "app": r.get("app_name", r["apk_file"]),
                    "type": c.get("type"),
                    "component": c.get("name"),
                    "permission": c.get("permission") or "",
                    "protection_level": c.get("protection_level") or "",
                    "grant_uri_permissions": c.get("grant_uri_permissions") or "",
                    "authorities": c.get("authorities") or "",
                    "actions": ", ".join(c.get("actions", [])),
                    "categories": ", ".join(c.get("categories", [])),
                    "schemes": ", ".join(c.get("schemes", [])),
                    "hosts": ", ".join(c.get("hosts", [])),
                    "launch_mode": c.get("launch_mode") or "",
                    "task_affinity": c.get("task_affinity") or "",
                    "risks": "; ".join(c.get("risks", [])),
                })
        _safe_write(writer, pd.DataFrame(rows or [{"info": "no exported components"}]), "ExportedComponents")

        # 4) TaintFlows summary table (source_label, sink_label, app, count)
        rows = []
        for r in apps:
            for key, count in (r.get("taint_chain_summary") or {}).items():
                src, sink = (key.split("->", 1) + [""])[:2]
                rows.append({
                    "app": r.get("app_name", r["apk_file"]),
                    "source_category": src,
                    "sink_category": sink,
                    "chain_count": count,
                })
        _safe_write(writer, pd.DataFrame(rows or [{"info": "no taint chains"}]), "TaintFlows")

        # 4b) Top sample taint chains (for spot-checking)
        rows = []
        for r in apps:
            for ch in (r.get("taint_chains") or [])[:50]:
                rows.append({
                    "app": r.get("app_name", r["apk_file"]),
                    "source_category": ch.get("source_label"),
                    "sink_category": ch.get("sink_label"),
                    "depth": ch.get("depth"),
                    "path": _truncate(" -> ".join(ch.get("path", []))),
                })
        if rows:
            _safe_write(writer, pd.DataFrame(rows), "TaintChainSamples")

        # 5) ExploitChains
        rows = []
        for r in apps:
            for ch in r.get("exploit_chains", []):
                rows.append({
                    "app": r.get("app_name", r["apk_file"]),
                    "package": r.get("package_name", ""),
                    "type": ch.get("type"),
                    "severity": ch.get("severity"),
                    "description": ch.get("description"),
                    "evidence": _truncate(json.dumps(ch.get("evidence", {}), default=str)),
                })
        _safe_write(writer, pd.DataFrame(rows or [{"info": "no exploit chains identified"}]), "ExploitChains")

        # 6) Endpoints
        rows = []
        for r in apps:
            name = r.get("app_name", r["apk_file"])
            for d in r.get("analytics_tracking_servers", []):
                rows.append({"app": name, "category": "analytics", "domain": d})
            for d in r.get("ad_servers", []):
                rows.append({"app": name, "category": "ad", "domain": d})
            for d in r.get("unknown_api_servers", []):
                rows.append({"app": name, "category": "unknown", "domain": d})
        _safe_write(writer, pd.DataFrame(rows or [{"info": "no endpoints detected"}]), "Endpoints")

        # 7) WebView
        rows = []
        for r in apps:
            name = r.get("app_name", r["apk_file"])
            for c in r.get("webview_components", []):
                rows.append({"app": name, "kind": "loader_method", "value": c})
            for c in r.get("javascript_interfaces", []):
                rows.append({"app": name, "kind": "addJavascriptInterface_caller", "value": c})
            rows.append({"app": name, "kind": "webview_loads_http",
                         "value": str(r.get("webview_loads_http", False))})
            rows.append({"app": name, "kind": "webview_loads_https",
                         "value": str(r.get("webview_loads_https", False))})
        if rows:
            _safe_write(writer, pd.DataFrame(rows), "WebView")

        # 8) CleartextURLs
        rows = []
        for r in apps:
            name = r.get("app_name", r["apk_file"])
            for u in r.get("cleartext_urls_found", []):
                rows.append({"app": name, "cleartext_url": _truncate(u, 1000)})
        _safe_write(writer, pd.DataFrame(rows or [{"info": "no cleartext URLs found"}]), "CleartextURLs")

        # 9) HardcodedSecrets
        rows = []
        for r in apps:
            name = r.get("app_name", r["apk_file"])
            for s in r.get("cwe798_hardcoded_secrets", []):
                rows.append({"app": name, "secret_snippet": _truncate(s, 1000)})
        _safe_write(writer, pd.DataFrame(rows or [{"info": "no hardcoded secrets matched"}]), "HardcodedSecrets")

        # 10) Databases / Storage
        rows = []
        for r in apps:
            name = r.get("app_name", r["apk_file"])
            for db in r.get("cwe312_unencrypted_databases", []):
                rows.append({
                    "app": name,
                    "db_or_file": db,
                    "database_in_external_storage": r.get("database_in_external_storage", False),
                })
        _safe_write(writer, pd.DataFrame(rows or [{"info": "no DB references"}]), "Databases")

        # 11) Crypto findings
        rows = []
        for r in apps:
            name = r.get("app_name", r["apk_file"])
            sigs = r.get("signature_schemes", {}) or {}
            rows.append({
                "app": name,
                "v1": sigs.get("v1"),
                "v2": sigs.get("v2"),
                "v3": sigs.get("v3"),
                "v1_only_janus_risk": r.get("cwe327_v1_only_signature", False),
                "weak_algos": ", ".join(r.get("cwe327_weak_algos", [])),
                "non_aead_modes": ", ".join(r.get("cwe327_non_aead_modes", [])),
                "insecure_rng": r.get("cwe330_insecure_rng", False),
                "no_cert_pinning": r.get("no_certificate_pinning", False),
                "insecure_hostname_verifier": r.get("insecure_hostname_verifier", False),
                "insecure_ssl_error_handler": r.get("insecure_ssl_error_handler", False),
            })
        if rows:
            _safe_write(writer, pd.DataFrame(rows), "CryptoFindings")

        # 12) IPTV Indicators
        rows = []
        for r in apps:
            rows.append({
                "app": r.get("app_name", r["apk_file"]),
                "package": r.get("package_name", ""),
                "hls_dash_detected": r.get("hls_dash_detected", False),
                "drm_hooks_detected": r.get("drm_hooks_detected", False),
                "streaming_protocols": ", ".join(r.get("streaming_protocols", [])),
                "iptv_indicators": ", ".join(r.get("iptv_indicators", [])),
            })
        if rows:
            _safe_write(writer, pd.DataFrame(rows), "IPTVIndicators")

        # 13) Risk Scores
        rows = []
        for r in apps:
            rows.append({
                "app": r.get("app_name", r["apk_file"]),
                "package": r.get("package_name", ""),
                "risk_score": r.get("risk_score", 0),
                "exploit_severity_score": r.get("exploit_severity_score", 0),
                "exploit_chain_count": r.get("exploit_chain_count", 0),
                "taint_chain_count": r.get("taint_chain_count", 0),
                **r.get("exploit_severity_breakdown", {}),
            })
        if rows:
            df = pd.DataFrame(rows).sort_values("risk_score", ascending=False)
            _safe_write(writer, df, "RiskScores")

        # 14) BootReceivers (boot persistence)
        rows = []
        for r in apps:
            for rcv in r.get("boot_receivers", []):
                rows.append({"app": r.get("app_name", r["apk_file"]), "boot_receiver": rcv})
        if rows:
            _safe_write(writer, pd.DataFrame(rows), "BootReceivers")

    print(f"[+] Excel workbook saved to: {xlsx_path}")


# ===========================================================================
# CLI Entry Point
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="IPTV APK Static Analysis — validates CCS'26 paper claims"
    )
    parser.add_argument(
        "--folder",
        default=DEFAULT_FOLDER,
        help=f"Directory containing APK files (default: {DEFAULT_FOLDER})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Output JSON report path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Process at most N new APKs in this run (0 = unlimited).",
    )
    parser.add_argument(
        "--apps",
        default=None,
        help="Comma-separated list of APK basenames (with or without extension, "
             "e.g. 'emby,ottnavigator,perfectplayer') to (re)analyze. Forces "
             "reprocessing of just those apps even if already present in "
             "--output, leaving every other app in the report untouched.",
    )
    args = parser.parse_args()

    folder = args.folder
    if not os.path.exists(folder):
        os.makedirs(folder)
        print(
            f"Created directory '{folder}'. Place APK files inside and re-run."
        )
        return

    apk_files = sorted(
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.endswith(".apk") or f.endswith(".apkm")
    )
    if not apk_files:
        print(f"No APK or APKM files found in '{folder}'.")
        return

    print(f"[+] Found {len(apk_files)} APK(s) to analyze")
    print("=" * 70)

    # Resume support: load any pre-existing JSON results
    all_results = []
    processed = set()
    if os.path.exists(args.output):
        try:
            with open(args.output, "r") as f:
                all_results = json.load(f)
            processed = {r.get("apk_file") for r in all_results if r.get("apk_file")}
            if processed:
                print(f"[+] Resuming — {len(processed)} APKs already in {args.output}")
        except Exception as e:
            print(f"[!] Could not load existing report ({e}). Starting fresh.")
            all_results = []
            processed = set()

    # Prune entries for APKs that no longer exist in --folder (e.g. an app
    # was removed/replaced) so stale results don't linger in the report.
    current_basenames = {os.path.basename(p) for p in apk_files}
    stale = [r for r in all_results if r.get("apk_file") and r["apk_file"] not in current_basenames]
    if stale:
        print(f"[+] Pruning {len(stale)} stale entry(ies) no longer in '{folder}': "
              f"{', '.join(r['apk_file'] for r in stale)}")
        all_results = [r for r in all_results if r not in stale]
        processed = {r.get("apk_file") for r in all_results if r.get("apk_file")}

    # --apps: restrict this run to specific APKs and force their reprocessing
    # even if already present in the report (other apps are left untouched).
    if args.apps:
        requested = {a.strip() for a in args.apps.split(",") if a.strip()}

        def _matches_requested(basename):
            stem = os.path.splitext(basename)[0]
            return basename in requested or stem in requested

        apk_files = [p for p in apk_files if _matches_requested(os.path.basename(p))]
        if not apk_files:
            print(f"[!] --apps '{args.apps}' matched no files in '{folder}'.")
            return
        target_basenames = {os.path.basename(p) for p in apk_files}
        all_results = [r for r in all_results if r.get("apk_file") not in target_basenames]
        processed = {r.get("apk_file") for r in all_results if r.get("apk_file")}
        print(f"[+] --apps: forcing reprocessing of {len(apk_files)} app(s): "
              f"{', '.join(target_basenames)}")

    ok = sum(1 for r in all_results if "analysis_error" not in r)
    new_in_this_run = 0
    for i, path in enumerate(apk_files, 1):
        basename = os.path.basename(path)
        if basename in processed:
            print(f"\n[{i}/{len(apk_files)}] {basename} — already processed, skipping")
            continue
        if args.limit and new_in_this_run >= args.limit:
            print(f"\n[+] Reached --limit {args.limit}; stopping for this run.")
            break
        print(f"\n[{i}/{len(apk_files)}] {basename}")
        # For .apkm bundles, extract base.apk and analyse that instead.
        if basename.endswith(".apkm"):
            try:
                actual_apk = extract_base_from_apkm(path)
            except Exception as e:
                print(f"[!] Failed to extract base.apk from {basename}: {e}")
                all_results.append({"apk_file": basename, "analysis_error": str(e)})
                new_in_this_run += 1
                continue
            result = analyze_apk(actual_apk)
            # Label with the original .apkm filename so reports stay consistent
            result["apk_file"] = basename
        else:
            result = analyze_apk(path)
        all_results.append(result)
        new_in_this_run += 1
        if "analysis_error" not in result:
            ok += 1
        # Persist after every APK so partial runs are not lost and Excel
        # is always up to date.
        try:
            generate_full_report(all_results, args.output)
        except Exception as e:
            print(f"[!] Incremental report write failed for {basename}: {e}")

    # ---- Reports ----
    generate_full_report(all_results, args.output)
    generate_table3_summary(all_results)
    generate_table4_summary(all_results)
    generate_table7_summary(all_results)
    generate_table8_summary(all_results)
    generate_table9_summary(all_results)

    # ---- Final summary ----
    print("\n" + "=" * 70)
    print(f"[+] Successfully analyzed: {ok}/{len(all_results)} APKs in report")
    apps = [r for r in all_results if "analysis_error" not in r]
    if apps:
        scores = [r.get("risk_score", 0) for r in apps]
        print(f"[+] Risk scores: min={min(scores)}, max={max(scores)}, "
              f"avg={sum(scores)/len(scores):.1f}")

        # Paper claim validation summary
        print("\n[+] Paper Claim Validation (Table 3 expected ratios):")
        checks = [
            ("Dangerous Permissions (CWE-250)", "cwe250_has_dangerous_perms", "4/5"),
            ("Exported Components (CWE-926)", "cwe926_exported_unprotected_count", "4/5"),
            ("Backup Enabled (CWE-749)", "cwe749_backup_enabled", "3/5"),
            ("V1-only Signature (CWE-327)", "cwe327_v1_only_signature", "2/5"),
            ("Insecure RNG (CWE-330)", "cwe330_insecure_rng", "4/5"),
            ("ECB/CBC mode (CWE-327)", "cwe327_ecb_cbc_used", "4/5"),
            ("No Cert Pinning", "no_certificate_pinning", "4/5"),
            ("Cleartext HTTP (CWE-319)", "cwe319_cleartext_traffic", "1/5"),
            ("Unencrypted Storage (CWE-312)", "cwe312_unencrypted_db_count", "4/5"),
            ("Hardcoded Secrets (CWE-798)", "cwe798_has_hardcoded_secrets", "1/5"),
            ("SQL Injection (CWE-89)", "cwe89_has_sql_injection_risk", "4/5"),
            ("Logcat Logging (CWE-532)", "cwe532_sensitive_logging", "5/5"),
            ("Audio/Location Capture", "unauthorized_audio_capture", "1/5"),
            ("Auto-Restart Boot", "auto_restart_on_boot", "5/5"),
        ]
        for label, key, expected in checks:
            actual = sum(
                1
                for r in apps
                if (
                    (isinstance(r.get(key), bool) and r.get(key))
                    or (isinstance(r.get(key), int) and r.get(key) > 0)
                )
            )
            match = "✓" if f"{actual}/{len(apps)}" == expected else "≠"
            print(f"  {match} {label}: {actual}/{len(apps)} (paper: {expected})")


if __name__ == "__main__":
    main()