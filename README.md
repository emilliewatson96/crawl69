# C-Based Web Crawler with SQLite Storage

A comprehensive depth-first web crawler implemented in C with SQLite3 storage, anti-bot evasion, and URL parameter extraction.

## Features

- **Seed Processing**: Accepts domains, subdomains, IP addresses, and CIDR ranges
- **DNS Resolution**: Automatically resolves hostnames to IPs
- **CIDR Expansion**: Converts CIDR notation (e.g., `192.168.1.0/24`) to individual IPs
- **Depth-First Crawl**: Stack-based DFS traversal for deep site exploration
- **HTTP Client**: libcurl-based with full HTTP support
- **Cookie Handling**: Automatic cookie management like a real browser
- **User-Agent Rotation**: 8 realistic browser UAs rotated randomly
- **HTML Parsing**: libxml2-based parser with XPath queries
- **Link Extraction**: Finds all `<a href>` links from HTML pages
- **Asset Discovery**: Extracts images, scripts, stylesheets
- **Parameter Extraction**: Parses URL query parameters
- **SQLite3 Storage**: Embedded database - no server required!
- **Domain Filtering**: Blacklists major platforms (Google, YouTube, etc.)
- **Configurable Depth**: Set maximum crawl depth
- **Rate Limiting**: Built-in request throttling

## Prerequisites

### Debian/Ubuntu
```bash
sudo apt-get install libcurl4-openssl-dev libxml2-dev libsqlite3-dev build-essential
```

### RHEL/CentOS/Fedora
```bash
sudo dnf install libcurl-devel libxml2-devel sqlite3-devel gcc make
```

### Alpine Linux
```bash
apk add curl-dev libxml2-dev sqlite-dev gcc make musl-dev
```

## Installation

1. Clone or download the source files:
   ```bash
   git clone <repository-url>
   cd web-crawler
   ```

2. Compile the crawler:
   ```bash
   make
   ```

3. (Optional) Build static binary for portability:
   ```bash
   make static
   ```

## Usage

### Basic Usage
```bash
./crawler example.com
```

### Multiple Seeds
```bash
./crawler example.com api.example.com
```

### With Custom Depth
```bash
./crawler -d 5 example.com
```

### CIDR Range
```bash
./crawler 192.168.1.0/24
```

### Help
```bash
./crawler -h
```

## Output

The crawler creates a SQLite database file `crawler.db` in the current directory with three tables:

### Tables

**pages** - Stores crawled page information
- `id`: Primary key
- `host`: Domain or IP address
- `path`: URL path
- `query`: Query string
- `full_url`: Complete URL
- `status_code`: HTTP response code
- `content_length`: Response size
- `content_type`: Content-Type header
- `crawled_at`: Timestamp

**url_params** - Extracted URL parameters
- `id`: Primary key
- `page_id`: Foreign key to pages
- `param_name`: Parameter name
- `param_value`: Parameter value

**assets** - Discovered assets
- `id`: Primary key
- `page_id`: Foreign key to pages
- `asset_url`: Asset URL
- `asset_type`: Type (image, script, stylesheet)

### Query Examples

View all crawled pages:
```bash
sqlite3 crawler.db "SELECT id, host, path, status_code FROM pages;"
```

Find all unique parameter names:
```bash
sqlite3 crawler.db "SELECT DISTINCT param_name FROM url_params;"
```

Count pages by status code:
```bash
sqlite3 crawler.db "SELECT status_code, COUNT(*) FROM pages GROUP BY status_code;"
```

List all discovered assets:
```bash
sqlite3 crawler.db "SELECT asset_type, COUNT(*) FROM assets GROUP BY asset_type;"
```

## Database Schema

Initialize the database manually (optional - auto-created on first run):
```bash
sqlite3 crawler.db < schema.sql
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Seeds     │────▶│  URL Frontier│────▶│  libcurl    │
│ (input)     │     │  (DFS Stack) │     │  (HTTP)     │
└─────────────┘     └──────────────┘     └─────────────┘
                           ▲                    │
                           │                    ▼
                    ┌──────────────┐     ┌─────────────┐
                    │   Visited    │◀────│   Response  │
                    │     Set      │     │   Buffer    │
                    └──────────────┘     └─────────────┘
                                                │
                          ┌─────────────────────┼─────────────────────┐
                          │                     │                     │
                          ▼                     ▼                     ▼
                   ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
                   │  Link       │      │  Asset      │      │  Parameter  │
                   │  Extractor  │      │  Extractor  │      │  Extractor  │
                   │  (libxml2)  │      │             │      │             │
                   └─────────────┘      └─────────────┘      └─────────────┘
                          │                     │                     │
                          └─────────────────────┼─────────────────────┘
                                                │
                                                ▼
                                         ┌─────────────┐
                                         │   SQLite3   │
                                         │  Database   │
                                         └─────────────┘
```

## Configuration

Edit `crawler.c` to modify:

- `MAX_DEPTH`: Maximum crawl depth (default: 10)
- `MAX_URLS`: Maximum URLs to visit (default: 10000)
- `REQUEST_DELAY_MS`: Delay between requests in ms (default: 100)
- `DB_FILE`: SQLite database filename (default: "crawler.db")
- `BLACKLISTED_DOMAINS`: Domains to skip
- `USER_AGENTS`: User-Agent strings for rotation

## Building

### Dynamic Linking (Default)
```bash
make
# or
gcc -o crawler crawler.c -lcurl -lxml2 -lsqlite3 -lz -lssl -lcrypto
```

### Static Linking (Portable Binary)
```bash
make static
# or
gcc -static -o crawler-static crawler.c -lcurl -lxml2 -lsqlite3 -lz -lssl -lcrypto
```

### Debug Build
```bash
gcc -g -DDEBUG -o crawler crawler.c -lcurl -lxml2 -lsqlite3 -lz -lssl -lcrypto
```

## Troubleshooting

### "sqlite3.h: No such file or directory"
Install SQLite development package:
```bash
sudo apt-get install libsqlite3-dev
```

### "undefined reference to sqlite3_*"
Ensure you're linking with `-lsqlite3`.

### Crawler connects but finds no links
- Check if the site uses JavaScript-heavy rendering (this crawler doesn't execute JS)
- Verify the site allows crawling in robots.txt
- Try increasing the depth limit

### Database locked errors
SQLite supports concurrent reads but only one writer at a time. If running multiple crawlers, use different database files.

## Legal Notice

Use this tool responsibly and ethically:
- Respect `robots.txt` files
- Do not overload servers (rate limiting is built-in)
- Only crawl sites you have permission to test
- Comply with applicable laws and terms of service

## License

MIT License - See LICENSE file for details.

## Credits

Built with:
- [libcurl](https://curl.se/libcurl/) - HTTP client library
- [libxml2](https://xmlsoft.org/) - HTML/XML parsing
- [SQLite3](https://www.sqlite.org/) - Embedded database
