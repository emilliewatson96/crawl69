# Advanced C Web Crawler

A high-performance, multi-threaded web crawler written in C with SQLite3 storage, Wayback Machine integration, and parameter discovery capabilities.

## Features

- **Depth-First Search (DFS)** traversal with configurable depth
- **Asynchronous HTTP requests** using libcurl multi interface
- **Wayback Machine integration** for historical URL discovery
- **SQLite3 database** storage with parameter categorization
- **Plain text export** of all findings
- **Modern Colorized CLI** with real-time status updates
- **Multi-target support** from file or command-line
- **CIDR expansion** for IP range crawling
- **User-Agent rotation** for anti-bot evasion
- **Cookie handling** for session persistence
- **Parameter categorization** (Sensitive, Navigation, Search, Standard)

## Requirements

- GCC compiler
- libcurl development files
- libxml2 development files  
- SQLite3 development files
- pthread library

### Install Dependencies (Debian/Ubuntu)

```bash
apt-get install -y libcurl4-openssl-dev libxml2-dev libsqlite3-dev build-essential
```

## Compilation

```bash
# Build with dynamic linking (recommended)
make

# Build statically linked binary (portable)
make static

# Debug build
make debug

# Clean build artifacts
make clean
```

## Usage

```bash
# Show help
./crawler -h

# Crawl a single domain
./crawler example.com

# Crawl with custom depth
./crawler -d 5 example.com

# Load targets from file
./crawler -t targets.txt

# Multiple options combined
./crawler -t targets.txt -d 5 -v

# Skip Wayback Machine lookup
./crawler -w example.com

# CIDR range crawling
./crawler 192.168.1.0/24
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --targets FILE` | Read targets from file (one per line) | - |
| `-d, --depth NUM` | Maximum crawl depth | 3 |
| `-c, --concurrency NUM` | Concurrent requests | 10 |
| `-o, --output DIR` | Output directory | output/ |
| `-w, --no-wayback` | Skip Wayback Machine lookup | false |
| `-v, --verbose` | Verbose output | false |
| `-h, --help` | Show help message | - |

### Target File Format

Create a `targets.txt` file with one target per line:

```
example.com
api.example.com
https://subdomain.example.org
192.168.1.0/24
10.0.0.1
```

Lines starting with `#` are treated as comments.

## Output

### Database (crawler.db)

The crawler stores all findings in a SQLite3 database with three tables:

#### pages
- `id` - Primary key
- `full_url` - Complete URL
- `host` - Domain/IP
- `path` - URL path
- `query` - Query string
- `file_type` - Detected file type (html, js, css, etc.)
- `status_code` - HTTP response code
- `content_length` - Response size in bytes
- `depth` - Crawl depth
- `is_wayback` - Flag for Wayback Machine URLs
- `crawled_at` - Timestamp

#### params
- `id` - Primary key
- `page_id` - Foreign key to pages
- `param_name` - Parameter name
- `param_value` - Parameter value
- `category` - SENSITIVE, NAVIGATION, SEARCH, or STANDARD

#### assets
- `id` - Primary key
- `page_id` - Foreign key to pages
- `asset_url` - Asset URL
- `asset_type` - image, javascript, stylesheet, etc.

### Text Exports (output/)

- `urls_found.txt` - All discovered URLs with status codes
- `params_found.txt` - Parameters categorized by type
- `assets_found.txt` - Static assets (images, scripts, stylesheets)

## Parameter Categories

The crawler automatically categorizes discovered parameters:

- **SENSITIVE**: password, token, key, auth, user, email, api_key, etc.
- **NAVIGATION**: page, offset, limit, sort, filter, category, etc.
- **SEARCH**: q, query, search, keyword, term, etc.
- **STANDARD**: All other parameters

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Crawler Main                      │
├─────────────────────────────────────────────────────┤
│  Seed Processor → URL Parser → Stack (DFS)          │
│         ↓                                            │
│  libcurl Multi (Async HTTP)                          │
│         ↓                                            │
│  Response Handler                                    │
│    ├─→ Status Code & Content Length                 │
│    ├─→ libxml2 HTML Parser                          │
│    │     ├─→ Link Extraction (<a href>)             │
│    │     └─→ Asset Extraction (img, script, link)   │
│    └─→ Parameter Extraction & Categorization        │
│         ↓                                            │
│  SQLite3 Database + Text Export                      │
├─────────────────────────────────────────────────────┤
│  Wayback Machine Integration (archive.org API)       │
└─────────────────────────────────────────────────────┘
```

## Anti-Bot Evasion

- **User-Agent Rotation**: Random selection from 8+ real browser signatures
- **Cookie Support**: Automatic cookie handling via libcurl
- **Rate Limiting**: Configurable delay between requests (default: 50ms)
- **Browser Headers**: Realistic Accept, Accept-Language headers

## Blacklisted Domains

The crawler automatically ignores links to:
- google.com, youtube.com, instagram.com, facebook.com
- twitter.com, linkedin.com, amazon.com, microsoft.com
- apple.com, cloudflare.com, akamai.com

## Examples

### Basic Crawl

```bash
$ ./crawler example.com

  ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗    ██████╗ ███████╗███████╗
 ██╔════╝██║  ██║██╔══██╗██║████╗  ██║    ██╔══██╗██╔════╝██╔════╝
 ██║     ███████║███████║██║██╔██╗ ██║    ██████╔╝█████╗  ███████╗
 ██║     ██╔══██║██╔══██║██║██║╚██╗██║    ██╔══██╗██╔══╝  ╚════██║
 ╚██████╗██║  ██║██║  ██║██║██║ ╚████║    ██║  ██║███████╗███████║
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝    ╚═╝  ╚═╝╚══════╝╚══════╝
  Advanced Web Crawler & Parameter Hunter
  v2.0 | SQLite3 + Wayback + Async

[SEED] Added target: example.com
[DB] Database initialized: crawler.db
[WAYBACK] Fetching historical URLs for example.com...
[WAYBACK] Found 47 historical URLs
[CRAWL] Starting crawl with 48 URLs in queue
--- STATUS: Active: 0 | Queued: 47 | Visited: 1 | Pages: 1 | Params: 5 | Assets: 12 | Time: 2s ---
```

### Query Database

```bash
# Find all sensitive parameters
sqlite3 crawler.db "SELECT param_name, COUNT(*) FROM params WHERE category='SENSITIVE' GROUP BY param_name;"

# List all unique hosts
sqlite3 crawler.db "SELECT DISTINCT host FROM pages;"

# Find pages with errors
sqlite3 crawler.db "SELECT full_url, status_code FROM pages WHERE status_code >= 400;"
```

## License

MIT License - See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `make test`
5. Submit a pull request

## Security Notice

This tool is intended for authorized security testing and research only. Always obtain proper permission before crawling websites.
