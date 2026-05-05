# C-Based Web Crawler

A comprehensive depth-first web crawler implemented in C with MySQL storage, anti-bot evasion, and URL parameter extraction.

## Features

- **Multiple Seed Types**: Accepts domains, subdomains, IP addresses, and CIDR ranges
- **Depth-First Traversal**: Uses stack-based DFS to explore sites deeply before backtracking
- **Anti-Bot Evasion**:
  - User-Agent rotation (8 different browser signatures)
  - Cookie handling via libcurl's cookie engine
  - Browser-like headers (Accept, Accept-Language, etc.)
  - Request throttling (100ms delay between requests)
- **HTML Parsing**: Extracts links, assets (images, scripts, stylesheets), and URL parameters using libxml2 XPath
- **MySQL Storage**: Stores all crawled data with foreign key relationships
- **Domain Filtering**: Blacklists major platforms (Google, YouTube, Instagram, etc.)
- **CIDR Expansion**: Automatically expands IP ranges to individual hosts
- **Static Linking Option**: Can compile to a single portable binary

## Requirements

### Build Dependencies

**Debian/Ubuntu:**
```bash
sudo apt-get install libcurl4-openssl-dev libxml2-dev libmysqlclient-dev build-essential
```

**RHEL/CentOS/Fedora:**
```bash
sudo dnf install libcurl-devel libxml2-devel mysql-devel gcc make
```

**Alpine Linux:**
```bash
apk add curl-dev libxml2-dev mysql-dev gcc make musl-dev
```

### Runtime Dependencies

- MySQL server (for database storage)
- Network access to target websites

## Installation

### 1. Clone or Download

```bash
cd /workspace
```

### 2. Build

**Dynamic linking (standard):**
```bash
make
```

**Static linking (portable binary):**
```bash
make static
```

### 3. Setup Database

```bash
# Create database and tables
mysql -u root -p < schema.sql
```

Or manually:
```sql
CREATE DATABASE web_crawler;
USE web_crawler;
-- Tables are auto-created by the crawler on first run
```

## Usage

### Basic Usage

```bash
# Crawl a single domain
./crawler example.com

# Crawl multiple seeds
./crawler example.com api.example.com

# Crawl with CIDR range
./crawler 192.168.1.0/24

# Set maximum depth
./crawler -d 5 example.com

# Quiet mode
./crawler -q example.com
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d <depth>` | Maximum crawl depth | 10 |
| `-q` | Quiet mode (less output) | verbose |
| `-h` | Show help message | - |

### Seed Formats

- **Domain**: `example.com`
- **Subdomain**: `api.example.com`
- **IP Address**: `192.168.1.1`
- **CIDR Range**: `192.168.1.0/24`
- **Full URL**: `http://example.com/path`

## Database Schema

The crawler creates three main tables:

### `pages`
Stores crawled page information:
- `id`: Primary key
- `host`: Domain or IP
- `path`: URL path
- `query`: Query string
- `status_code`: HTTP response code
- `content_length`: Response size
- `content_type`: MIME type
- `crawled_at`: Timestamp

### `url_params`
Stores extracted URL parameters:
- `page_id`: Foreign key to pages
- `param_name`: Parameter name
- `param_value`: Parameter value (URL decoded)

### `assets`
Stores discovered assets:
- `page_id`: Foreign key to pages
- `asset_url`: Asset URL
- `asset_type`: image/script/stylesheet

## Example Queries

```sql
-- Get summary per host
SELECT * FROM v_host_summary;

-- Find all unique parameters
SELECT * FROM v_unique_params;

-- Find pages with specific parameter
SELECT p.* FROM pages p 
JOIN url_params up ON p.id = up.page_id 
WHERE up.param_name = 'id';

-- Find forbidden pages
SELECT * FROM pages WHERE status_code = 403;

-- Get asset distribution
SELECT * FROM v_asset_distribution;
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Crawler Main                      │
├─────────────────────────────────────────────────────┤
│  Seed Processor  →  Stack (DFS)  →  URL Processor   │
│       ↓                                              │
│  CIDR Expander                                       │
│  DNS Resolver                                        │
└─────────────────────────────────────────────────────┘
                          ↓
        ┌─────────────────┼─────────────────┐
        ↓                 ↓                 ↓
   ┌─────────┐     ┌──────────┐      ┌──────────┐
   │ libcurl │     │ libxml2  │      │ MySQL    │
   │ (HTTP)  │     │ (Parser) │      │ (Storage)│
   └─────────┘     └──────────┘      └──────────┘
        ↓                 ↓                 ↓
   Fetch Pages      Extract Links     Store Results
   Rotate UA        Extract Assets    
   Handle Cookies   Extract Params    
```

## Configuration

Edit constants in `crawler.c`:

```c
#define MAX_DEPTH 10              // Maximum crawl depth
#define REQUEST_DELAY_MS 100      // Delay between requests
#define MAX_STACK_SIZE 50000      // Maximum URLs in stack
#define MAX_VISITED 100000        // Maximum visited URLs

#define DB_HOST "localhost"
#define DB_USER "crawler"
#define DB_PASS "crawler_pass"
#define DB_NAME "web_crawler"
```

## Anti-Bot Features

1. **User-Agent Rotation**: Randomly selects from 8 real browser signatures
2. **Cookie Management**: Automatic cookie handling via libcurl
3. **Header Spoofing**: Sends browser-like Accept and Accept-Language headers
4. **Rate Limiting**: Configurable delay between requests
5. **Domain Filtering**: Avoids blacklisted domains

## Limitations

- Does not execute JavaScript (libcurl limitation)
- Single-threaded (can be extended with libcurl multi-interface)
- No robots.txt compliance (add if needed for production)
- Session-based challenges require manual cookie input

## Compilation Flags

For production builds, consider:

```bash
# Optimized build
gcc -O3 -o crawler crawler.c -lcurl -lxml2 -lmysqlclient

# Debug build
gcc -g -DDEBUG -o crawler crawler.c -lcurl -lxml2 -lmysqlclient

# Static portable build
gcc -static -o crawler-static crawler.c -lcurl -lxml2 -lmysqlclient -lz -lssl -lcrypto
```

## License

This project is provided as-is for educational and authorized testing purposes only.

## Disclaimer

**Important**: Only use this crawler on websites you own or have explicit permission to crawl. Unauthorized crawling may violate terms of service and laws.

## Troubleshooting

### Build Errors

**"mysql.h: No such file or directory"**
```bash
# Install MySQL dev package
sudo apt-get install libmysqlclient-dev
```

**"curl/curl.h: No such file or directory"**
```bash
# Install libcurl dev package
sudo apt-get install libcurl4-openssl-dev
```

### Runtime Errors

**"MySQL connect failed"**
```bash
# Check MySQL is running
sudo systemctl status mysql

# Verify credentials in crawler.c
```

**"No seeds provided"**
```bash
# Provide at least one seed
./crawler example.com
```

## Contributing

Contributions welcome! Areas for improvement:
- Multi-threaded crawling with libcurl multi-interface
- Robots.txt compliance
- JavaScript rendering (via headless browser integration)
- Proxy support
- Output formats (JSON, CSV export)
