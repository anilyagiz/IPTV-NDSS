# Supplementary Material: End-to-End Lifecycle of Illicit IPTV Services

Data collection and static analysis code for the submission *All Hands on Deck! Understanding the End-to-End Lifecycle of Illicit IPTV Services* (CHI '27, under review).

The repository contains three command-line tools and the precomputed reports they produced for the ten Android applications analyzed in Section 5 of the paper:

1. `crawler.py` performs query-based search and forum crawling to build the corpus described in Section 3.1.
2. `static_analysis.py` extracts manifest metadata, permissions, exported components, hardcoded endpoints, database references, and candidate taint paths from APKs (Sections 3.3, 5.2, 5.3).
3. `p2p_server_rotation_analysis.py` scans decompiled APK trees for P2P/torrent delivery indicators and server-rotation indicators (Sections 4.2, 5.1).

The tools are released to document how the reported measurements were obtained. They characterize code-level properties of publicly obtainable applications. They do not detect malware, do not confirm exploitability, and do not access or interact with any IPTV service.

Author identifiers, institution names, and repository history have been removed for anonymous review.

## Contents

| Path | Description |
| --- | --- |
| `crawler.py` | Asynchronous search and forum crawler with keyword scoring, language detection, translation, theme tagging, and APK link discovery. |
| `static_analysis.py` | Androguard-based APK analysis producing per-app manifest, endpoint, storage, and taint findings. |
| `p2p_server_rotation_analysis.py` | Pattern scanner over apktool output (smali, assets, resources) for P2P and server-rotation indicators. |
| `iptv_vulnerability_report.{json,csv,xlsx}` | Output of `static_analysis.py` for the ten analyzed applications. |
| `p2p_server_rotation_report.{json,xlsx}` | Output of `p2p_server_rotation_analysis.py` for the same ten applications. |
| `requirements.txt` | Dependencies for `crawler.py` only. See Requirements below. |
| `.env.example` | Template for the search API key. |

## Requirements

- Python 3.9 or later. `crawler.py` runs on 3.8, but `p2p_server_rotation_analysis.py` uses builtin generic annotations (`list[...]`, `dict[...]`) evaluated at import time, which require 3.9.
- A Serper API key for `crawler.py` (<https://serper.dev>). Without a key the crawler starts but performs no searches.
- `apktool` on `PATH`, and a Java runtime, for `p2p_server_rotation_analysis.py`. The script decompiles `.apk` and `.apkm` inputs by invoking `apktool` as a subprocess; it can also run directly on already-decompiled directories.
- APK files. None are redistributed here. See Obtaining the applications.

`requirements.txt` covers the crawler only. The two analysis scripts additionally require `androguard`, `pandas`, and `openpyxl`, which must be installed separately.

## Installation

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt   # crawler dependencies
pip install androguard pandas openpyxl   # analysis dependencies
```

Configure the search API key:

```bash
cp .env.example .env              # then edit .env
export SERPER_API_KEY=your_key    # required: see note below
```

`crawler.py` reads `SERPER_API_KEY` from the process environment via `os.getenv` and does not load `.env` itself. Export the variable in your shell, or source the file (`set -a; . ./.env; set +a`), or add `python-dotenv` and a `load_dotenv()` call.

## Usage

### Crawling

```bash
python crawler.py
```

The crawler runs the 17 seed queries in `DEFAULT_QUERIES`, expands them with `site:` queries over `DEFAULT_FORUM_DOMAINS`, then crawls the resulting pages. It follows links only on pages classified as forums, stays within the originating host, and respects `robots.txt` and a per-domain minimum request interval.

Settings are edited in the `CrawlerConfig` instance in `main()`:

| Parameter | Value in `main()` | Description |
| --- | --- | --- |
| `max_pages_total` | 1200 | Global page budget |
| `max_pages_per_domain` | 250 | Per-domain page budget |
| `max_results_per_query` | 30 | Search results retained per query |
| `search_pages` | 1 | Result pages requested per query |
| `concurrency` | 20 | Concurrent workers |
| `per_domain_min_interval_sec` | 2.0 | Minimum seconds between requests to one host |
| `follow_links_on_forums_only` | True | Restrict link following to forum pages |
| `max_depth_for_forums` | 2 | Maximum forum crawl depth |
| `respect_robots` | True | Honor `robots.txt` |
| `translation_enabled` | True | Translate non-English page text before theme tagging |

A page is recorded when it matches at least one keyword or is classified as a forum page. Records are written to `outputs/`:

| File | Contents |
| --- | --- |
| `pages.jsonl` | One JSON record per retained page |
| `pages.csv` | Same records, list fields joined with `\|` |
| `apk_links.txt` | Deduplicated APK download URLs discovered in page links |

Record fields: `url`, `source`, `depth`, `hostname`, `title`, `language`, `text_snippet`, `matched_terms`, `keyword_score`, `is_forum`, `themes_en`, `discovered_apk_urls`, `timestamp`.

`themes_en` uses the three lexicons in `THEME_LEXICON`: `infrastructure_distribution`, `economics_marketing`, and `security_privacy_risks`. A theme is assigned if any of its terms occurs in the translated page text. Tagging is lexicon-based and is used for triage, not as the qualitative coding reported in Section 3.2, which was performed manually.

### APK static analysis

```bash
python static_analysis.py --folder apks/ --output iptv_vulnerability_report.json
```

Accepts `.apk` files and `.apkm` bundles, from which `base.apk` is extracted. For each application the script reports declared permissions, exported components and their intent filters, signature schemes, cryptographic API usage, cleartext transport configuration, local database references, hardcoded secret patterns, logging and SQL sinks, boot-persistence components, endpoint classification, and candidate source-to-sink taint paths. Results are written as JSON, CSV, and XLSX.

Columns in `iptv_vulnerability_report.csv`:

`apk_file`, `app_name`, `package_name`, `cwe250_has_dangerous_perms`, `exported_components_count`, `cwe926_exported_unprotected_count`, `cwe749_backup_enabled`, `cwe327_v1_only_signature`, `cwe330_insecure_rng`, `cwe327_ecb_cbc_used`, `no_certificate_pinning`, `cwe319_cleartext_traffic`, `cwe312_unencrypted_db_count`, `cwe798_has_hardcoded_secrets`, `cwe89_has_sql_injection_risk`, `cwe532_sensitive_logging`, `unauthorized_audio_capture`, `unauthorized_location_capture`, `auto_restart_on_boot`, `analytics_tracking_server_count`, `ad_server_count`, `unknown_api_server_count`, `taint_chain_count`, `exploit_chain_count`, `exploit_severity_score`, `risk_score`.

The CSV reports more properties than the paper does. Only the subset listed under Mapping to the paper is used in the manuscript; the remaining columns are provided for completeness.

### P2P and server-rotation analysis

```bash
python p2p_server_rotation_analysis.py --folder apks/ --output p2p_server_rotation_report.xlsx
```

The script scans each decompiled application for two sets of indicators.

P2P indicators: torrent-related manifest components and smali classes, P2P native libraries, magnet URIs, tracker announce paths, DHT and bencoding strings, peer-wire constants, and WebRTC usage.

Server-rotation indicators: hardcoded base URLs and their TLD distribution, raw IP endpoints, asset and `res/raw` files containing two or more distinct URLs, classes combining string arrays with multiple URL constants, remote configuration fetch URLs, SharedPreferences keys holding server state, and connection-retry handlers.

Each application receives a weighted score and a `NONE`/`LOW`/`MEDIUM`/`HIGH` confidence label per indicator set. The scores are a triage aid defined by the weights in `analyze_p2p` and `analyze_server_rotation`; they are ordinal, not calibrated probabilities, and the paper reports the underlying counts rather than the labels. The XLSX report contains thirteen sheets: a per-app summary followed by the evidence behind each indicator category.

## Obtaining the applications

No APKs are redistributed. The ten applications were obtained from Google Play and from third-party repositories identified through forum discussions and operator guides, as described in Section 3.3. To reproduce the reports, place the corresponding `.apk` or `.apkm` files in `apks/` and rerun the two analysis scripts.

`app_name` and `package_name` in the included reports identify the analyzed applications, which the paper refers to as App-A through App-J. **[TO SUPPLY: the App-A to App-J mapping, and the version code and SHA-256 of each analyzed APK, so that the reports can be tied to specific artifacts.]**

## Mapping to the paper

| Paper location | Produced by | Fields |
| --- | --- | --- |
| Section 3.1, query-based search and crawling | `crawler.py` | `DEFAULT_QUERIES`, `DEFAULT_FORUM_DOMAINS`, `pages.csv` |
| Section 3.3, APK collection | `crawler.py` | `apk_links.txt`, `discovered_apk_urls` |
| Table 4, Base (unique hardcoded base URLs) | `p2p_server_rotation_analysis.py` | `unique_base_url_count` |
| Table 4, Config (startup config-fetch URLs) | `p2p_server_rotation_analysis.py` | `config_fetch_url_count` |
| Section 5.1, absence of user-facing P2P delivery | `p2p_server_rotation_analysis.py` | `p2p_confidence`, `p2p_score`, `P2P_Components` sheet |
| Table 5, DB (unencrypted databases) | `static_analysis.py` | `cwe312_unencrypted_db_count` |
| Table 5, Ad and AS (advertising and analytics servers) | `static_analysis.py` | `ad_server_count`, `analytics_tracking_server_count` |
| Table 5, TE (third-party endpoints) | `static_analysis.py` | **[TO CONFIRM: `unknown_api_server_count`, and how the eight ownership categories in the right panel of Table 5 were assigned]** |
| Section 5.3, boot-related components | `static_analysis.py` | `auto_restart_on_boot` |
| Section 5.3, sensitive permissions and data flows | `static_analysis.py` | `unauthorized_location_capture`, `unauthorized_audio_capture`, `taint_chain_count`, `cwe319_cleartext_traffic` |

## What the tools do and do not establish

- The crawler retrieves and scores publicly reachable pages. It does not authenticate to any site, purchase any subscription, or access private forum sections.
- Theme tags and keyword scores are lexicon matches over page text. They support corpus triage and are not the manual thematic coding reported in Section 3.2.
- Static analysis identifies code-level properties: declared permissions, referenced endpoints, database names, exported components, and candidate data-flow paths. Candidate taint paths are reachability results over Androguard cross-references within a bounded number of hops. They indicate that a sink is reachable from a source, not that sensitive data is transmitted at runtime.
- Hardcoded endpoint pools indicate client-side redundancy. They do not establish that endpoints are rotated at runtime, which would require dynamic observation.
- Absence of P2P indicators is evidence of absence within the analyzed APK sample only. It does not speak to operator-side or private infrastructure.
- No application was executed, instrumented, or connected to a live service. All analysis was performed in an isolated environment.

## Ethics

The crawler honors `robots.txt`, rate-limits per domain, sets an identifying user agent, and collects only publicly accessible pages. Forum names, URLs, usernames, and profile data are excluded from the paper. Only publicly obtainable applications were analyzed, and no subscriptions, panels, or premium tools were purchased. The analysis scripts report code properties rather than newly discovered vulnerabilities; findings for applications distributed through Google Play were shared with Google Play Protect. Users of this code are responsible for compliance with applicable law and with the terms of service of any site they crawl.

## License

MIT.
