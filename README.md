# IPTV Crawler

This repository contains the data collection tool used in our CCS 2026 paper on illicit IPTV ecosystem analysis. The crawler performs query-based web searches, forum crawling, and APK link discovery to gather data about IPTV services.

## Requirements

- Python 3.8+
- Serper API key

## Installation

```bash
# Clone and setup
git clone <repository-url>
cd iptv

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure API key
cp .env.example .env
# Edit .env and add: SERPER_API_KEY=your_key
```

Get a Serper API key at https://serper.dev

## Usage

```bash
python crawler.py
```

### Configuration

Modify `crawler.py` to adjust settings:

```python
config = CrawlerConfig(
    max_pages_total=1200,
    max_pages_per_domain=250,
    concurrency=20,
    per_domain_min_interval_sec=2.0,
    follow_links_on_forums_only=True,
    max_depth_for_forums=2,
    translation_enabled=True,
    respect_robots=True,
    output_dir="outputs"
)
```

## Output

Results are saved to `outputs/`:

| File | Description |
|------|-------------|
| `pages.jsonl` | Complete crawl records (URL, content, themes, APK links) |
| `pages.csv` | Structured data for analysis |
| `apk_links.txt` | Discovered APK download URLs |

### CSV Columns

`url`, `source`, `depth`, `hostname`, `title`, `language`, `text_snippet`, `matched_terms`, `keyword_score`, `is_forum`, `themes_en`, `discovered_apk_urls`, `timestamp`

## Theme Classification

Content is automatically tagged with:

- **Infrastructure**: CDN, DNS, M3U playlists, Xtream panels
- **Economics**: Resellers, subscriptions, pricing, affiliates
- **Security**: Malware, phishing, credential theft, data leaks

## Configuration Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_pages_total` | 1000 | Maximum pages to crawl |
| `max_pages_per_domain` | 200 | Per-domain limit |
| `concurrency` | 20 | Concurrent workers |
| `per_domain_min_interval_sec` | 2.0 | Rate limit (seconds) |
| `follow_links_on_forums_only` | True | Restrict link following to forums |
| `max_depth_for_forums` | 2 | Forum crawl depth |
| `respect_robots` | True | Honor robots.txt |
| `translation_enabled` | True | Translate non-English content |

## Ethics

This tool was developed for academic research purposes. The crawler:

- Respects robots.txt directives
- Implements rate limiting to avoid server overload
- Uses standard HTTP headers

Users must comply with applicable laws and website terms of service.

## License

MIT License
