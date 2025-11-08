# IPTV Crawler

A professional, asynchronous web crawler designed for IPTV research and analysis. This crawler performs query-based searches, forum-focused crawling, APK link discovery, and exports results in multiple formats.

## Features

- 🚀 **Asynchronous Crawling**: High-performance concurrent crawling with configurable workers
- 🔍 **Smart Search Integration**: Uses Serper API for compliant Google search
- 🌐 **Forum-Focused**: Specialized crawling for forum discussions and threads
- 🤖 **Robots.txt Compliance**: Respects robots.txt and implements polite rate limiting
- 🌍 **Multi-Language Support**: Automatic language detection and translation to English
- 🏷️ **Theme Classification**: Automatic tagging of content by theme (infrastructure, economics, security)
- 📱 **APK Discovery**: Finds and extracts APK download links
- 📊 **Multiple Export Formats**: JSONL, CSV, and TXT outputs
- 🛡️ **Robust Error Handling**: Comprehensive error handling and logging

## Requirements

- Python 3.8 or higher
- Serper API key (for search functionality)

## Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd iptv
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and add your Serper API key:

```
SERPER_API_KEY=your_actual_api_key_here
```

**Get your Serper API key**: Visit [https://serper.dev](https://serper.dev) and sign up for a free account.

## Usage

### Basic Usage

Run the crawler with default settings:

```bash
python crawler.py
```

### Advanced Usage

You can customize the crawler by modifying the configuration in `crawler.py`:

```python
config = CrawlerConfig(
    max_pages_total=1200,              # Maximum total pages to crawl
    max_pages_per_domain=250,          # Maximum pages per domain
    concurrency=20,                     # Number of concurrent workers
    per_domain_min_interval_sec=2.0,   # Rate limit per domain (seconds)
    follow_links_on_forums_only=True,  # Only follow links on forum pages
    max_depth_for_forums=2,            # Maximum crawl depth for forums
    translation_enabled=True,          # Enable auto-translation
    respect_robots=True,               # Respect robots.txt
    log_level="INFO",                  # Logging level
    output_dir="outputs"               # Output directory
)
```

### Custom Queries

Modify the `DEFAULT_QUERIES` list to add your own search queries:

```python
DEFAULT_QUERIES = [
    "iptv",
    "free iptv",
    "your custom query here"
]
```

### Custom Forum Domains

Add or modify forum domains to focus on specific sites:

```python
DEFAULT_FORUM_DOMAINS = [
    "reddit.com",
    "your-forum-site.com"
]
```

## Output Files

The crawler generates three output files in the `outputs/` directory:

### 1. `pages.jsonl`
Complete page records in JSON Lines format. Each line is a JSON object containing:
- URL, title, hostname
- Source and crawl depth
- Language and text snippet
- Matched keywords and score
- Discovered themes
- APK links found
- Timestamp

### 2. `pages.csv`
Structured CSV file with all page data, suitable for analysis in Excel or data tools.

Columns:
- `url`: Page URL
- `source`: "search" or "forum-crawl"
- `depth`: Crawl depth
- `hostname`: Domain name
- `title`: Page title
- `language`: Detected language
- `text_snippet`: Text preview (800 chars)
- `matched_terms`: Keywords found (pipe-separated)
- `keyword_score`: Relevance score
- `is_forum`: Boolean forum indicator
- `themes_en`: Detected themes (pipe-separated)
- `discovered_apk_urls`: APK links (pipe-separated)
- `timestamp`: ISO 8601 timestamp

### 3. `apk_links.txt`
Plain text file with one APK download URL per line.

## Configuration Reference

### CrawlerConfig Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `queries` | List[str] | DEFAULT_QUERIES | Search queries to execute |
| `keywords` | List[str] | DEFAULT_KEYWORDS | Keywords for matching content |
| `forum_domains` | List[str] | DEFAULT_FORUM_DOMAINS | Forum domains to prioritize |
| `site_specific_expansion` | bool | True | Perform site-specific searches |
| `max_results_per_query` | int | 30 | Search results per query |
| `search_pages` | int | 1 | Search pages to fetch |
| `max_pages_total` | int | 1000 | Maximum total pages |
| `max_pages_per_domain` | int | 200 | Maximum pages per domain |
| `follow_links_on_forums_only` | bool | True | Only follow forum links |
| `max_depth_for_forums` | int | 2 | Forum crawl depth |
| `concurrency` | int | 20 | Concurrent workers |
| `per_domain_min_interval_sec` | float | 2.0 | Rate limit (seconds) |
| `request_timeout_sec` | int | 15 | Request timeout |
| `respect_robots` | bool | True | Honor robots.txt |
| `translation_enabled` | bool | True | Enable translation |
| `translate_to_lang` | str | "en" | Target language |
| `output_dir` | str | "outputs" | Output directory |
| `log_level` | str | "INFO" | Logging level |

## Theme Classification

The crawler automatically tags content with these themes:

### 1. **Infrastructure & Distribution**
- CDN, DNS, hosting, servers
- M3U/M3U8 playlists
- Xtream panels
- Load balancers, anonymizers

### 2. **Economics & Marketing**
- Resellers, subscriptions
- Pricing, trials, payments
- Affiliate programs
- Revenue models

### 3. **Security & Privacy Risks**
- Malware, phishing
- Credential theft, spyware
- Data leaks
- Vulnerabilities

## Best Practices

### Ethical Crawling

1. **Respect Rate Limits**: Don't reduce `per_domain_min_interval_sec` below 2.0 seconds
2. **Honor robots.txt**: Keep `respect_robots=True` unless explicitly permitted
3. **Use Responsibly**: This tool is for research and educational purposes only
4. **Identify Yourself**: Update the `user_agent` with your contact information

### Performance Optimization

1. **Adjust Concurrency**: Lower `concurrency` for slower networks
2. **Domain Limits**: Set `max_pages_per_domain` to avoid overwhelming single sites
3. **Targeted Queries**: Use specific search queries for better results
4. **Forum Focus**: Enable `follow_links_on_forums_only` for relevant content

## Logging

The crawler provides detailed logging at multiple levels:

- **INFO**: Progress updates, milestones, export completion
- **DEBUG**: Detailed crawling decisions, robots.txt checks, errors
- **WARNING**: API issues, translation failures, search errors
- **ERROR**: Critical failures

Change log level in configuration:

```python
config = CrawlerConfig(
    log_level="DEBUG"  # Options: DEBUG, INFO, WARNING, ERROR
)
```

## Troubleshooting

### "SERPER_API_KEY not found in environment"

**Solution**: Make sure you've created a `.env` file with your API key:

```bash
cp .env.example .env
# Edit .env and add your key
```

Then load it in your environment or use a package like `python-dotenv`.

### "Blocked by robots.txt"

**Solution**: This is normal and respectful. The crawler will skip URLs blocked by robots.txt. If you need to crawl these URLs, you must get explicit permission from the site owner.

### Low number of results

**Solutions**:
1. Check your Serper API key is valid and has credits
2. Try different search queries
3. Increase `max_results_per_query` and `search_pages`
4. Add more forum domains to `forum_domains`

### Crawler is slow

**Solutions**:
1. Increase `concurrency` (up to 50 for powerful machines)
2. Reduce `per_domain_min_interval_sec` (but be respectful!)
3. Disable translation: `translation_enabled=False`
4. Reduce `max_depth_for_forums`

## Development

### Running Tests

```bash
pytest tests/
```

### Code Formatting

```bash
black crawler.py
flake8 crawler.py
```

### Type Checking

```bash
mypy crawler.py
```

## Architecture

```
crawler.py
├── Configuration (CrawlerConfig)
├── Search Provider (SerperSearchProvider)
├── Rate Limiting (DomainRateLimiter)
├── Robots.txt (RobotsCache)
├── Content Analysis (KeywordMatcher, tag_themes)
├── HTML Parsing (BeautifulSoup + lxml)
├── Language Detection (langdetect)
├── Translation (deep-translator)
└── Main Crawler (IPTVCrawler)
    ├── run() - Main execution
    ├── _gather_seeds() - Search queries
    ├── _worker() - Worker pool
    ├── _process_url() - Page processing
    └── _export() - Results export
```

## License

MIT License - See LICENSE file for details

## Ethics & Legal

This crawler is designed for **research and educational purposes only**. Users are responsible for:

- Obtaining necessary permissions
- Complying with website terms of service
- Respecting copyright and intellectual property laws
- Following applicable regulations and laws in their jurisdiction

The authors assume no liability for misuse of this software.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues, questions, or contributions:

- Open an issue on GitHub
- Check existing issues for solutions
- Read the documentation carefully

## Changelog

### Version 2.0.0 (Current)

- ✅ Complete refactor to professional Python module
- ✅ Fixed DEFAULT_FORUM_DOMAINS bug
- ✅ All messages and documentation in English
- ✅ Improved error handling and logging
- ✅ Better progress reporting
- ✅ Comprehensive documentation
- ✅ Type hints and docstrings
- ✅ Modular, maintainable code structure

### Version 1.0.0 (Legacy)

- Initial Jupyter notebook implementation
- Basic crawling functionality

---

**Made with ❤️ for IPTV Research**
