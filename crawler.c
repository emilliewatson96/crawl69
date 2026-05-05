/*
 * C-Based Web Crawler with Depth-First Traversal
 * 
 * Features:
 * - Seed input: domains, subdomains, IPs, CIDR ranges, or file with targets
 * - DNS resolution and URL construction
 * - Depth-first crawl strategy with stack-based traversal
 * - Asynchronous HTTP fetching using libcurl multi interface
 * - HTTP client using libcurl with cookie support
 * - User-Agent rotation for anti-bot evasion
 * - HTML parsing with libxml2 for link/asset extraction
 * - URL parameter extraction with categorization
 * - Wayback Machine integration for historical URLs
 * - SQLite3 storage for crawled data
 * - External domain filtering (Google, YouTube, etc.)
 * - Plain text export of results
 * - Colorized CLI output
 *
 * Compile: gcc -o crawler crawler.c -lcurl -lxml2 -lsqlite3 -lz -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

/* libcurl headers */
#include <curl/curl.h>

/* libxml2 headers */
#include <libxml/HTMLparser.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

/* SQLite3 headers */
#include <sqlite3.h>

/* ===================== CONFIGURATION ===================== */
#define MAX_URL_LENGTH 2048
#define MAX_HOSTS 10000
#define MAX_VISITED 100000
#define MAX_STACK_SIZE 50000
#define MAX_PARAMS_PER_URL 100
#define MAX_ASSETS_PER_PAGE 500
#define REQUEST_DELAY_MS 50
#define MAX_DEPTH 10
#define MAX_LINKS_PER_PAGE 1000
#define MAX_CONCURRENT_REQUESTS 20
#define WAYBACK_BATCH_SIZE 1000

/* Database configuration */
#define DB_FILE "crawler.db"
#define OUTPUT_DIR "output"

/* ANSI Color codes for CLI */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"

/* Parameter categories */
typedef enum {
    PARAM_SENSITIVE,
    PARAM_NAVIGATION,
    PARAM_SEARCH,
    PARAM_STANDARD,
    PARAM_UNKNOWN
} ParamCategory;

/* Blacklisted domains to ignore */
const char *BLACKLISTED_DOMAINS[] = {
    "google.com", "youtube.com", "instagram.com", "facebook.com",
    "twitter.com", "linkedin.com", "amazon.com", "microsoft.com",
    "apple.com", "cloudflare.com", "akamai.com", "robots.txt",
    NULL
};

/* User-Agent strings for rotation */
const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    NULL
};

/* ===================== DATA STRUCTURES ===================== */

/* URL structure */
typedef struct {
    char host[256];
    char path[1024];
    char query[1024];
    char full_url[MAX_URL_LENGTH];
    int port;
    int is_https;
    int depth;
} URL;

/* URL Parameter structure */
typedef struct {
    char name[256];
    char value[512];
    ParamCategory category;
} URLParam;

/* Asset structure */
typedef struct {
    char url[MAX_URL_LENGTH];
    char type[64];  /* image, script, stylesheet, etc. */
} Asset;

/* Stack node for DFS */
typedef struct StackNode {
    URL url;
    struct StackNode *next;
} StackNode;

/* Visited URL set (simple hash table) */
typedef struct VisitedNode {
    char url[MAX_URL_LENGTH];
    struct VisitedNode *next;
} VisitedNode;

#define VISITED_HASH_SIZE 10007

typedef struct {
    VisitedNode *buckets[VISITED_HASH_SIZE];
    int count;
} VisitedSet;

/* Async request context for multi interface */
typedef struct {
    CURL *easy;
    URL url;
    ResponseBuffer response;
    long status_code;
    long content_length;
    char *content_type;
    sqlite3_int64 page_id;
    Crawler *crawler;
} AsyncRequest;

/* Crawler state */
typedef struct {
    StackNode *stack;
    int stack_size;
    VisitedSet visited;
    CURLM *multi;  /* Multi handle for async requests */
    sqlite3 *db_conn;
    int total_pages;
    int total_params;
    int total_assets;
    int active_requests;
    time_t start_time;
    char target_host[256];
    int max_depth;
    int verbose;
    int use_colors;
    pthread_mutex_t db_mutex;
    pthread_mutex_t output_mutex;
    FILE *urls_file;
    FILE *params_file;
    FILE *assets_file;
} Crawler;

/* Response buffer for libcurl */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} ResponseBuffer;

/* ===================== FUNCTION PROTOTYPES ===================== */

/* CIDR and IP handling */
int expand_cidr(const char *cidr, char **ips, int max_ips);
int is_valid_ip(const char *ip);
int resolve_hostname(const char *hostname, char *ip);

/* URL parsing and manipulation */
int parse_url(const char *url_str, URL *url);
void build_url(const URL *url, char *output);
int is_same_domain(const char *host1, const char *host2);
int is_blacklisted(const char *host);
char *extract_hostname(const char *url);

/* Stack operations */
void stack_push(Crawler *crawler, const URL *url);
int stack_pop(Crawler *crawler, URL *url);
int stack_empty(Crawler *crawler);

/* Visited set operations */
void visited_init(VisitedSet *set);
int visited_add(VisitedSet *set, const char *url);
int visited_contains(VisitedSet *set, const char *url);
void visited_free(VisitedSet *set);

/* HTTP fetching with libcurl */
int fetch_url(Crawler *crawler, const URL *url, ResponseBuffer *response,
              long *status_code, long *content_length, char **content_type);
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);

/* HTML parsing with libxml2 */
int extract_links(Crawler *crawler, const char *html, const URL *base_url, URL *links, int max_links);
int extract_assets(Crawler *crawler, const char *html, const URL *base_url, Asset *assets, int max_assets);
int extract_parameters(const char *query, URLParam *params, int max_params);

/* Database operations */
int db_connect(Crawler *crawler);
int db_insert_page(Crawler *crawler, const URL *url, long status_code, 
                   long content_length, const char *content_type, sqlite3_int64 *page_id);
int db_insert_param(Crawler *crawler, sqlite3_int64 page_id, const URLParam *param);
int db_insert_asset(Crawler *crawler, sqlite3_int64 page_id, const Asset *asset);
void db_create_tables(sqlite3 *conn);

/* Wayback Machine integration */
int fetch_wayback_urls(Crawler *crawler, const char *host);

/* File I/O for plain text export */
int init_output_files(Crawler *crawler);
void close_output_files(Crawler *crawler);
void export_url_to_file(Crawler *crawler, const URL *url, long status_code, long content_length);
void export_param_to_file(Crawler *crawler, const URLParam *param, const char *full_url);
void export_asset_to_file(Crawler *crawler, const Asset *asset, const char *source_url);

/* Async multi interface handlers */
void async_request_init(Crawler *crawler);
void async_fetch_url(Crawler *crawler, const URL *url);
void async_process_completed(Crawler *crawler);

/* Utility functions */
char *get_random_user_agent(void);
void sleep_ms(int milliseconds);
char *str_dup(const char *s);
void url_decode(char *dst, const char *src);
int hash_string(const char *str);
ParamCategory categorize_parameter(const char *name);
const char *param_category_name(ParamCategory cat);

/* CLI output helpers */
void print_banner(void);
void print_status(Crawler *crawler, const char *format, ...);
void print_success(const char *format, ...);
void print_error(const char *format, ...);
void print_info(const char *format, ...);
void print_warning(const char *format, ...);

/* Main crawler logic */
void crawler_init(Crawler *crawler, const char *target);
void crawler_run(Crawler *crawler);
void crawler_cleanup(Crawler *crawler);
void process_url(Crawler *crawler, const URL *url);

/* Seed processing */
int process_seeds(Crawler *crawler, char **seeds, int seed_count);
int process_seed_file(Crawler *crawler, const char *filename);

/* ===================== IMPLEMENTATION ===================== */

/* Hash function for visited set */
int hash_string(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash % VISITED_HASH_SIZE;
}

/* Initialize visited set */
void visited_init(VisitedSet *set) {
    memset(set->buckets, 0, sizeof(set->buckets));
    set->count = 0;
}

/* Add URL to visited set */
int visited_add(VisitedSet *set, const char *url) {
    if (visited_contains(set, url))
        return 0;
    
    int idx = hash_string(url);
    VisitedNode *node = malloc(sizeof(VisitedNode));
    if (!node) return -1;
    
    strncpy(node->url, url, MAX_URL_LENGTH - 1);
    node->url[MAX_URL_LENGTH - 1] = '\0';
    node->next = set->buckets[idx];
    set->buckets[idx] = node;
    set->count++;
    
    return 1;
}

/* Check if URL was visited */
int visited_contains(VisitedSet *set, const char *url) {
    int idx = hash_string(url);
    VisitedNode *node = set->buckets[idx];
    
    while (node) {
        if (strcmp(node->url, url) == 0)
            return 1;
        node = node->next;
    }
    return 0;
}

/* Free visited set */
void visited_free(VisitedSet *set) {
    for (int i = 0; i < VISITED_HASH_SIZE; i++) {
        VisitedNode *node = set->buckets[i];
        while (node) {
            VisitedNode *next = node->next;
            free(node);
            node = next;
        }
        set->buckets[i] = NULL;
    }
    set->count = 0;
}

/* Categorize parameter based on name */
ParamCategory categorize_parameter(const char *name) {
    const char *sensitive_keywords[] = {
        "pass", "password", "pwd", "secret", "token", "auth", "key", "api_key",
        "apikey", "session", "sess", "cookie", "cred", "login", "user", "username",
        "email", "phone", "ssn", "credit", "card", "cvv", "pin", NULL
    };
    
    const char *navigation_keywords[] = {
        "page", "p", "offset", "limit", "start", "end", "sort", "order", "dir",
        "filter", "category", "cat", "section", "tab", "view", "mode", NULL
    };
    
    const char *search_keywords[] = {
        "q", "query", "search", "find", "lookup", "term", "keyword", "text",
        "filter", "where", "like", NULL
    };
    
    char name_lower[256];
    strncpy(name_lower, name, sizeof(name_lower) - 1);
    name_lower[sizeof(name_lower) - 1] = '\0';
    
    /* Convert to lowercase */
    for (char *p = name_lower; *p; p++)
        *p = tolower(*p);
    
    /* Check sensitive */
    for (int i = 0; sensitive_keywords[i] != NULL; i++) {
        if (strstr(name_lower, sensitive_keywords[i]) != NULL)
            return PARAM_SENSITIVE;
    }
    
    /* Check navigation */
    for (int i = 0; navigation_keywords[i] != NULL; i++) {
        if (strcmp(name_lower, navigation_keywords[i]) == 0 ||
            strstr(name_lower, navigation_keywords[i]) != NULL)
            return PARAM_NAVIGATION;
    }
    
    /* Check search */
    for (int i = 0; search_keywords[i] != NULL; i++) {
        if (strcmp(name_lower, search_keywords[i]) == 0 ||
            strstr(name_lower, search_keywords[i]) != NULL)
            return PARAM_SEARCH;
    }
    
    return PARAM_STANDARD;
}

/* Get parameter category name */
const char *param_category_name(ParamCategory cat) {
    switch (cat) {
        case PARAM_SENSITIVE: return "SENSITIVE";
        case PARAM_NAVIGATION: return "NAVIGATION";
        case PARAM_SEARCH: return "SEARCH";
        case PARAM_STANDARD: return "STANDARD";
        default: return "UNKNOWN";
    }
}

/* Print colorful banner */
void print_banner(void) {
    printf("\n");
    printf(COLOR_BOLD COLOR_CYAN "╔═══════════════════════════════════════════════════════════╗\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_CYAN "║         C-Based Web Crawler with DFS Traversal           ║\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_CYAN "║       SQLite3 + Wayback Machine + Async Fetching         ║\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_CYAN "╚═══════════════════════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");
}

/* Print status message with colors */
void print_status(Crawler *crawler, const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (crawler && crawler->use_colors)
        printf(COLOR_BLUE "[*] " COLOR_RESET);
    else
        printf("[*] ");
    
    vprintf(format, args);
    printf(COLOR_RESET "\n");
    
    va_end(args);
}

/* Print success message */
void print_success(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    printf(COLOR_GREEN "[+] " COLOR_RESET);
    vprintf(format, args);
    printf(COLOR_RESET "\n");
    
    va_end(args);
}

/* Print error message */
void print_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    fprintf(stderr, COLOR_RED "[!] " COLOR_RESET);
    vfprintf(stderr, format, args);
    fprintf(stderr, COLOR_RESET "\n");
    
    va_end(args);
}

/* Print info message */
void print_info(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    printf(COLOR_WHITE "[i] " COLOR_RESET);
    vprintf(format, args);
    printf(COLOR_RESET "\n");
    
    va_end(args);
}

/* Print warning message */
void print_warning(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    printf(COLOR_YELLOW "[!] " COLOR_RESET);
    vprintf(format, args);
    printf(COLOR_RESET "\n");
    
    va_end(args);
}

/* Stack push */
void stack_push(Crawler *crawler, const URL *url) {
    if (crawler->stack_size >= MAX_STACK_SIZE) {
        if (crawler->verbose)
            fprintf(stderr, "[!] Stack full, skipping URL\n");
        return;
    }
    
    StackNode *node = malloc(sizeof(StackNode));
    if (!node) return;
    
    memcpy(&node->url, url, sizeof(URL));
    node->next = crawler->stack;
    crawler->stack = node;
    crawler->stack_size++;
}

/* Stack pop */
int stack_pop(Crawler *crawler, URL *url) {
    if (!crawler->stack)
        return 0;
    
    StackNode *node = crawler->stack;
    memcpy(url, &node->url, sizeof(URL));
    crawler->stack = node->next;
    free(node);
    crawler->stack_size--;
    
    return 1;
}

/* Check if stack is empty */
int stack_empty(Crawler *crawler) {
    return crawler->stack == NULL;
}

/* Get random user agent */
char *get_random_user_agent(void) {
    int count = 0;
    while (USER_AGENTS[count] != NULL)
        count++;
    
    srand(time(NULL) ^ getpid());
    int idx = rand() % count;
    return (char *)USER_AGENTS[idx];
}

/* Sleep in milliseconds */
void sleep_ms(int milliseconds) {
    usleep(milliseconds * 1000);
}

/* Duplicate string */
char *str_dup(const char *s) {
    char *d = malloc(strlen(s) + 1);
    if (d)
        strcpy(d, s);
    return d;
}

/* URL decode */
void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16*a+b;
            src+=3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

/* Extract hostname from URL */
char *extract_hostname(const char *url) {
    static char host[256];
    const char *start = strstr(url, "://");
    if (!start)
        start = url;
    else
        start += 3;
    
    const char *end = strchr(start, '/');
    const char *colon = strchr(start, ':');
    
    if (!end) end = start + strlen(start);
    if (colon && colon < end)
        end = colon;
    
    int len = end - start;
    if (len >= 256) len = 255;
    
    strncpy(host, start, len);
    host[len] = '\0';
    
    return host;
}

/* Check if domain is blacklisted */
int is_blacklisted(const char *host) {
    for (int i = 0; BLACKLISTED_DOMAINS[i] != NULL; i++) {
        if (strstr(host, BLACKLISTED_DOMAINS[i]) != NULL)
            return 1;
    }
    return 0;
}

/* Check if two hosts are in the same domain */
int is_same_domain(const char *host1, const char *host2) {
    /* Simple check: same host or one is subdomain of other */
    if (strcmp(host1, host2) == 0)
        return 1;
    
    /* Check if host2 is a subdomain of host1 */
    int len1 = strlen(host1);
    int len2 = strlen(host2);
    
    if (len2 > len1 && strcmp(host2 + len2 - len1 - 1, ".") == 0 &&
        strcmp(host2 + len2 - len1, host1) == 0)
        return 1;
    
    /* Check if host1 is a subdomain of host2 */
    if (len1 > len2 && strcmp(host1 + len1 - len2 - 1, ".") == 0 &&
        strcmp(host1 + len1 - len2, host2) == 0)
        return 1;
    
    return 0;
}

/* Parse URL into components */
int parse_url(const char *url_str, URL *url) {
    memset(url, 0, sizeof(URL));
    
    /* Check for https */
    if (strncmp(url_str, "https://", 8) == 0) {
        url->is_https = 1;
        url->port = 443;
        url_str += 8;
    } else if (strncmp(url_str, "http://", 7) == 0) {
        url->is_https = 0;
        url->port = 80;
        url_str += 7;
    } else {
        /* Default to http */
        url->is_https = 0;
        url->port = 80;
    }
    
    /* Copy full URL */
    strncpy(url->full_url, url_str, MAX_URL_LENGTH - 1);
    
    /* Extract host */
    const char *path_start = strchr(url_str, '/');
    const char *query_start = strchr(url_str, '?');
    
    int host_len;
    if (path_start)
        host_len = path_start - url_str;
    else if (query_start)
        host_len = query_start - url_str;
    else
        host_len = strlen(url_str);
    
    if (host_len >= 256) host_len = 255;
    strncpy(url->host, url_str, host_len);
    url->host[host_len] = '\0';
    
    /* Extract port if present */
    char *colon = strchr(url->host, ':');
    if (colon) {
        *colon = '\0';
        url->port = atoi(colon + 1);
    }
    
    /* Extract path and query */
    if (path_start) {
        if (query_start && query_start > path_start) {
            int path_len = query_start - path_start;
            strncpy(url->path, path_start, path_len);
            url->path[path_len] = '\0';
            strncpy(url->query, query_start + 1, sizeof(url->query) - 1);
        } else {
            strncpy(url->path, path_start, sizeof(url->path) - 1);
            url->query[0] = '\0';
        }
    } else {
        strcpy(url->path, "/");
        if (query_start)
            strncpy(url->query, query_start + 1, sizeof(url->query) - 1);
    }
    
    return 0;
}

/* Build URL string from components */
void build_url(const URL *url, char *output) {
    sprintf(output, "http%s://%s%s%s%s",
            url->is_https ? "s" : "",
            url->host,
            url->path,
            url->query[0] ? "?" : "",
            url->query);
}

/* Validate IP address */
int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

/* Expand CIDR range to individual IPs */
int expand_cidr(const char *cidr, char **ips, int max_ips) {
    char ip_str[64];
    char *slash = strchr(cidr, '/');
    
    if (!slash) {
        /* Not a CIDR, just return the IP/host */
        if (max_ips > 0) {
            ips[0] = str_dup(cidr);
            return 1;
        }
        return 0;
    }
    
    *slash = '\0';
    int prefix_len = atoi(slash + 1);
    
    struct in_addr addr;
    if (inet_pton(AF_INET, cidr, &addr) != 1) {
        *slash = '/';
        return 0;
    }
    
    uint32_t ip = ntohl(addr.s_addr);
    uint32_t mask = prefix_len ? (~0U << (32 - prefix_len)) : 0;
    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;
    
    *slash = '/';
    
    int count = 0;
    for (uint32_t i = network; i <= broadcast && count < max_ips; i++) {
        /* Skip network and broadcast addresses */
        if (i == network || i == broadcast)
            continue;
        
        struct in_addr ia;
        ia.s_addr = htonl(i);
        char *ip_copy = str_dup(inet_ntoa(ia));
        if (ip_copy)
            ips[count++] = ip_copy;
    }
    
    return count;
}

/* Resolve hostname to IP */
int resolve_hostname(const char *hostname, char *ip) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0)
        return -1;
    
    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);
    
    freeaddrinfo(res);
    return 0;
}

/* Write callback for libcurl */
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    ResponseBuffer *buf = (ResponseBuffer *)userp;
    
    /* Grow buffer if needed */
    if (buf->size + realsize + 1 > buf->capacity) {
        size_t new_capacity = buf->capacity * 2;
        if (new_capacity < buf->size + realsize + 1)
            new_capacity = buf->size + realsize + 1024;
        
        char *new_data = realloc(buf->data, new_capacity);
        if (!new_data)
            return 0;
        
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    
    memcpy(buf->data + buf->size, contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = '\0';
    
    return realsize;
}

/* Fetch URL using libcurl */
int fetch_url(Crawler *crawler, const URL *url, ResponseBuffer *response,
              long *status_code, long *content_length, char **content_type) {
    char full_url[MAX_URL_LENGTH];
    build_url(url, full_url);
    
    /* Initialize response buffer */
    response->data = malloc(4096);
    if (!response->data)
        return -1;
    
    response->size = 0;
    response->capacity = 4096;
    response->data[0] = '\0';
    
    /* Set curl options */
    curl_easy_setopt(crawler->curl, CURLOPT_URL, full_url);
    curl_easy_setopt(crawler->curl, CURLOPT_USERAGENT, get_random_user_agent());
    curl_easy_setopt(crawler->curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(crawler->curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(crawler->curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(crawler->curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(crawler->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(crawler->curl, CURLOPT_WRITEDATA, (void *)response);
    curl_easy_setopt(crawler->curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(crawler->curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    /* Enable cookies */
    curl_easy_setopt(crawler->curl, CURLOPT_COOKIEFILE, "");
    
    /* Additional browser-like headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.5");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    curl_easy_setopt(crawler->curl, CURLOPT_HTTPHEADER, headers);
    
    /* Perform request */
    CURLcode res = curl_easy_perform(crawler->curl);
    
    curl_slist_free_all(headers);
    
    if (res != CURLE_OK) {
        if (crawler->verbose)
            fprintf(stderr, "[!] curl error: %s\n", curl_easy_strerror(res));
        free(response->data);
        response->data = NULL;
        return -1;
    }
    
    /* Get response info */
    curl_easy_getinfo(crawler->curl, CURLINFO_RESPONSE_CODE, status_code);
    curl_easy_getinfo(crawler->curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, content_length);
    curl_easy_getinfo(crawler->curl, CURLINFO_CONTENT_TYPE, content_type);
    
    return 0;
}

/* Extract links from HTML using libxml2 */
int extract_links(Crawler *crawler, const char *html, const URL *base_url, 
                  URL *links, int max_links) {
    int count = 0;
    
    /* Parse HTML */
    htmlDocPtr doc = htmlReadMemory(html, strlen(html), NULL, NULL, 
                                     HTML_PARSE_RECOVER | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING);
    if (!doc)
        return 0;
    
    /* Create XPath context */
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    if (!ctx) {
        xmlFreeDoc(doc);
        return 0;
    }
    
    /* Find all <a> tags with href attribute */
    xmlXPathObjectPtr result = xmlXPathEvalExpression((const xmlChar *)"//a/@href", ctx);
    if (result) {
        xmlNodeSetPtr nodes = result->nodesetval;
        if (nodes) {
            for (int i = 0; i < nodes->nodeNr && count < max_links; i++) {
                xmlChar *href = xmlNodeGetContent(nodes->nodeTab[i]);
                if (href) {
                    char abs_url[MAX_URL_LENGTH];
                    
                    /* Convert relative URL to absolute */
                    if (href[0] == '/') {
                        sprintf(abs_url, "http%s://%s%s",
                                base_url->is_https ? "s" : "",
                                base_url->host, href);
                    } else if (strstr((char *)href, "://")) {
                        strncpy(abs_url, (char *)href, MAX_URL_LENGTH - 1);
                    } else {
                        /* Relative path */
                        char *last_slash = strrchr(base_url->path, '/');
                        if (last_slash) {
                            int path_len = last_slash - base_url->path + 1;
                            char base_path[1024];
                            strncpy(base_path, base_url->path, path_len);
                            base_path[path_len] = '\0';
                            sprintf(abs_url, "http%s://%s%s%s",
                                    base_url->is_https ? "s" : "",
                                    base_url->host, base_path, href);
                        } else {
                            sprintf(abs_url, "http%s://%s/%s",
                                    base_url->is_https ? "s" : "",
                                    base_url->host, href);
                        }
                    }
                    
                    abs_url[MAX_URL_LENGTH - 1] = '\0';
                    
                    /* Parse the absolute URL */
                    URL new_url;
                    if (parse_url(abs_url, &new_url) == 0) {
                        /* Check if it's within our target domain */
                        if (is_same_domain(new_url.host, crawler->target_host) &&
                            !is_blacklisted(new_url.host)) {
                            links[count++] = new_url;
                        }
                    }
                    
                    xmlFree(href);
                }
            }
        }
        xmlXPathFreeObject(result);
    }
    
    xmlXPathFreeContext(ctx);
    xmlFreeDoc(doc);
    
    return count;
}

/* Extract assets (images, scripts, stylesheets) from HTML */
int extract_assets(Crawler *crawler, const char *html, const URL *base_url,
                   Asset *assets, int max_assets) {
    int count = 0;
    
    htmlDocPtr doc = htmlReadMemory(html, strlen(html), NULL, NULL,
                                     HTML_PARSE_RECOVER | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING);
    if (!doc)
        return 0;
    
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    if (!ctx) {
        xmlFreeDoc(doc);
        return 0;
    }
    
    /* Extract images */
    xmlXPathObjectPtr result = xmlXPathEvalExpression((const xmlChar *)"//img/@src", ctx);
    if (result && result->nodesetval) {
        xmlNodeSetPtr nodes = result->nodesetval;
        for (int i = 0; i < nodes->nodeNr && count < max_assets; i++) {
            xmlChar *src = xmlNodeGetContent(nodes->nodeTab[i]);
            if (src) {
                strncpy(assets[count].url, (char *)src, MAX_URL_LENGTH - 1);
                strcpy(assets[count].type, "image");
                count++;
                xmlFree(src);
            }
        }
        xmlXPathFreeObject(result);
    }
    
    /* Extract scripts */
    result = xmlXPathEvalExpression((const xmlChar *)"//script/@src", ctx);
    if (result && result->nodesetval) {
        xmlNodeSetPtr nodes = result->nodesetval;
        for (int i = 0; i < nodes->nodeNr && count < max_assets; i++) {
            xmlChar *src = xmlNodeGetContent(nodes->nodeTab[i]);
            if (src) {
                strncpy(assets[count].url, (char *)src, MAX_URL_LENGTH - 1);
                strcpy(assets[count].type, "script");
                count++;
                xmlFree(src);
            }
        }
        xmlXPathFreeObject(result);
    }
    
    /* Extract stylesheets */
    result = xmlXPathEvalExpression((const xmlChar *)"//link[@rel='stylesheet']/@href", ctx);
    if (result && result->nodesetval) {
        xmlNodeSetPtr nodes = result->nodesetval;
        for (int i = 0; i < nodes->nodeNr && count < max_assets; i++) {
            xmlChar *href = xmlNodeGetContent(nodes->nodeTab[i]);
            if (href) {
                strncpy(assets[count].url, (char *)href, MAX_URL_LENGTH - 1);
                strcpy(assets[count].type, "stylesheet");
                count++;
                xmlFree(href);
            }
        }
        xmlXPathFreeObject(result);
    }
    
    xmlXPathFreeContext(ctx);
    xmlFreeDoc(doc);
    
    return count;
}

/* Extract parameters from query string */
int extract_parameters(const char *query, URLParam *params, int max_params) {
    int count = 0;
    
    if (!query || !*query)
        return 0;
    
    char *query_copy = strdup(query);
    if (!query_copy)
        return 0;
    
    char *saveptr;
    char *token = strtok_r(query_copy, "&", &saveptr);
    
    while (token && count < max_params) {
        char *eq = strchr(token, '=');
        if (eq) {
            *eq = '\0';
            strncpy(params[count].name, token, sizeof(params[count].name) - 1);
            
            /* URL decode name and value */
            char decoded_name[256], decoded_value[512];
            url_decode(decoded_name, params[count].name);
            url_decode(decoded_value, eq + 1);
            
            strncpy(params[count].name, decoded_name, sizeof(params[count].name) - 1);
            strncpy(params[count].value, decoded_value, sizeof(params[count].value) - 1);
            count++;
        } else {
            /* Parameter without value */
            char decoded[256];
            url_decode(decoded, token);
            strncpy(params[count].name, decoded, sizeof(params[count].name) - 1);
            params[count].value[0] = '\0';
            count++;
        }
        
        token = strtok_r(NULL, "&", &saveptr);
    }
    
    free(query_copy);
    return count;
}

/* Connect to SQLite database */
int db_connect(Crawler *crawler) {
    int rc = sqlite3_open(DB_FILE, &crawler->db_conn);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[!] SQLite open failed: %s\n", sqlite3_errmsg(crawler->db_conn));
        return -1;
    }
    
    /* Create tables if they don't exist */
    db_create_tables(crawler->db_conn);
    
    return 0;
}

/* Create database tables */
void db_create_tables(sqlite3 *conn) {
    const char *queries[] = {
        "CREATE TABLE IF NOT EXISTS pages ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  host TEXT NOT NULL,"
        "  path TEXT NOT NULL,"
        "  query TEXT,"
        "  full_url TEXT NOT NULL,"
        "  status_code INTEGER,"
        "  content_length INTEGER,"
        "  content_type TEXT,"
        "  crawled_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ")",
        
        "CREATE TABLE IF NOT EXISTS url_params ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  page_id INTEGER NOT NULL,"
        "  param_name TEXT NOT NULL,"
        "  param_value TEXT,"
        "  FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE"
        ")",
        
        "CREATE TABLE IF NOT EXISTS assets ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  page_id INTEGER NOT NULL,"
        "  asset_url TEXT NOT NULL,"
        "  asset_type TEXT,"
        "  FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE"
        ")"
    };
    
    char *err_msg = NULL;
    for (int i = 0; i < 3; i++) {
        if (sqlite3_exec(conn, queries[i], NULL, NULL, &err_msg) != SQLITE_OK) {
            fprintf(stderr, "[!] Table creation failed: %s\n", err_msg);
            sqlite3_free(err_msg);
            err_msg = NULL;
        }
    }
}

/* Insert page record into database */
int db_insert_page(Crawler *crawler, const URL *url, long status_code,
                   long content_length, const char *content_type, sqlite3_int64 *page_id) {
    if (!crawler->db_conn)
        return -1;
    
    sqlite3_stmt *stmt;
    char full_url[MAX_URL_LENGTH];
    build_url(url, full_url);
    
    const char *sql = "INSERT INTO pages (host, path, query, full_url, status_code, content_length, content_type) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?)";
    
    pthread_mutex_lock(&crawler->db_mutex);
    
    if (sqlite3_prepare_v2(crawler->db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[!] DB prepare failed: %s\n", sqlite3_errmsg(crawler->db_conn));
        pthread_mutex_unlock(&crawler->db_mutex);
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, url->host, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, url->path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, url->query[0] ? url->query : NULL, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, full_url, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, (int)status_code);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)content_length);
    sqlite3_bind_text(stmt, 7, content_type ? content_type : NULL, -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "[!] DB insert failed: %s\n", sqlite3_errmsg(crawler->db_conn));
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&crawler->db_mutex);
        return -1;
    }
    
    if (page_id)
        *page_id = sqlite3_last_insert_rowid(crawler->db_conn);
    
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&crawler->db_mutex);
    
    return 0;
}

/* Insert URL parameter into database with category */
int db_insert_param(Crawler *crawler, sqlite3_int64 page_id, const URLParam *param) {
    if (!crawler->db_conn)
        return -1;
    
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO url_params (page_id, param_name, param_value, param_category) VALUES (?, ?, ?, ?)";
    
    pthread_mutex_lock(&crawler->db_mutex);
    
    if (sqlite3_prepare_v2(crawler->db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[!] Param prepare failed: %s\n", sqlite3_errmsg(crawler->db_conn));
        pthread_mutex_unlock(&crawler->db_mutex);
        return -1;
    }
    
    sqlite3_bind_int64(stmt, 1, page_id);
    sqlite3_bind_text(stmt, 2, param->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, param->value, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, param_category_name(param->category), -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "[!] Param insert failed: %s\n", sqlite3_errmsg(crawler->db_conn));
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&crawler->db_mutex);
        return -1;
    }
    
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&crawler->db_mutex);
    return 0;
}

/* Insert asset into database */
int db_insert_asset(Crawler *crawler, sqlite3_int64 page_id, const Asset *asset) {
    if (!crawler->db_conn)
        return -1;
    
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO assets (page_id, asset_url, asset_type) VALUES (?, ?, ?)";
    
    if (sqlite3_prepare_v2(crawler->db_conn, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[!] Asset prepare failed: %s\n", sqlite3_errmsg(crawler->db_conn));
        return -1;
    }
    
    sqlite3_bind_int64(stmt, 1, page_id);
    sqlite3_bind_text(stmt, 2, asset->url, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, asset->type, -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "[!] Asset insert failed: %s\n", sqlite3_errmsg(crawler->db_conn));
        sqlite3_finalize(stmt);
        return -1;
    }
    
    sqlite3_finalize(stmt);
    return 0;
}

/* Initialize crawler */
void crawler_init(Crawler *crawler, const char *target) {
    memset(crawler, 0, sizeof(Crawler));
    
    visited_init(&crawler->visited);
    
    /* Initialize libcurl */
    curl_global_init(CURL_GLOBAL_ALL);
    crawler->curl = curl_easy_init();
    if (!crawler->curl) {
        fprintf(stderr, "[!] Failed to initialize libcurl\n");
        exit(1);
    }
    
    /* Connect to database */
    if (db_connect(crawler) != 0) {
        fprintf(stderr, "[!] Warning: Database connection failed, running without storage\n");
    }
    
    strncpy(crawler->target_host, target, sizeof(crawler->target_host) - 1);
    crawler->max_depth = MAX_DEPTH;
    crawler->verbose = 1;
    crawler->start_time = time(NULL);
    
    printf("[+] Crawler initialized for target: %s\n", target);
}

/* Process seeds and add to stack */
int process_seeds(Crawler *crawler, char **seeds, int seed_count) {
    int added = 0;
    
    for (int i = 0; i < seed_count; i++) {
        char *seed = seeds[i];
        
        /* Check if it's a CIDR range */
        if (strchr(seed, '/')) {
            char *ips[MAX_HOSTS];
            int ip_count = expand_cidr(seed, ips, MAX_HOSTS);
            
            for (int j = 0; j < ip_count; j++) {
                URL url;
                char url_str[MAX_URL_LENGTH];
                snprintf(url_str, sizeof(url_str), "http://%s/", ips[j]);
                
                if (parse_url(url_str, &url) == 0) {
                    url.depth = 0;
                    stack_push(crawler, &url);
                    added++;
                }
                free(ips[j]);
            }
        } else {
            /* Regular domain or IP */
            URL url;
            char url_str[MAX_URL_LENGTH];
            
            /* Add scheme if missing */
            if (strncmp(seed, "http://", 7) != 0 && strncmp(seed, "https://", 8) != 0) {
                snprintf(url_str, sizeof(url_str), "http://%s/", seed);
            } else {
                strncpy(url_str, seed, sizeof(url_str) - 1);
            }
            
            if (parse_url(url_str, &url) == 0) {
                url.depth = 0;
                
                /* Update target host if this is the first seed */
                if (crawler->target_host[0] == '\0')
                    strncpy(crawler->target_host, url.host, sizeof(crawler->target_host) - 1);
                
                stack_push(crawler, &url);
                added++;
            }
        }
    }
    
    printf("[+] Added %d seed URLs to crawl queue\n", added);
    return added;
}

/* Process a single URL */
void process_url(Crawler *crawler, const URL *url) {
    char full_url[MAX_URL_LENGTH];
    build_url(url, full_url);
    
    if (crawler->verbose)
        printf("[*] Crawling: %s (depth: %d)\n", full_url, url->depth);
    
    /* Fetch the URL */
    ResponseBuffer response;
    long status_code = 0, content_length = 0;
    char *content_type = NULL;
    
    if (fetch_url(crawler, url, &response, &status_code, &content_length, &content_type) != 0) {
        return;
    }
    
    /* Record in database for relevant status codes */
    sqlite3_int64 page_id = -1;
    if (status_code == 200 || status_code == 403 || status_code == 500) {
        db_insert_page(crawler, url, status_code, content_length, content_type, &page_id);
        crawler->total_pages++;
        
        /* Export to plain text file */
        export_url_to_file(crawler, url, status_code, content_length);
    }
    
    /* Only parse HTML responses */
    if (content_type && strstr(content_type, "text/html") && response.data) {
        /* Extract links */
        URL links[MAX_LINKS_PER_PAGE];
        int link_count = extract_links(crawler, response.data, url, links, MAX_LINKS_PER_PAGE);
        
        for (int i = 0; i < link_count; i++) {
            char link_url[MAX_URL_LENGTH];
            build_url(&links[i], link_url);
            
            /* Check if already visited */
            if (!visited_contains(&crawler->visited, link_url)) {
                visited_add(&crawler->visited, link_url);
                links[i].depth = url->depth + 1;
                
                /* Only add if within depth limit */
                if (links[i].depth <= crawler->max_depth) {
                    stack_push(crawler, &links[i]);
                }
            }
        }
        
        /* Extract and store parameters */
        if (url->query[0] != '\0') {
            URLParam params[MAX_PARAMS_PER_URL];
            int param_count = extract_parameters(url->query, params, MAX_PARAMS_PER_URL);
            
            for (int i = 0; i < param_count && page_id > 0; i++) {
                /* Categorize the parameter */
                params[i].category = categorize_parameter(params[i].name);
                
                db_insert_param(crawler, page_id, &params[i]);
                crawler->total_params++;
                
                /* Export to plain text file */
                export_param_to_file(crawler, &params[i], url->full_url);
            }
        }
        
        /* Extract and store assets */
        Asset assets[MAX_ASSETS_PER_PAGE];
        int asset_count = extract_assets(crawler, response.data, url, assets, MAX_ASSETS_PER_PAGE);
        
        for (int i = 0; i < asset_count && page_id > 0; i++) {
            db_insert_asset(crawler, page_id, &assets[i]);
            crawler->total_assets++;
            
            /* Export to plain text file */
            export_asset_to_file(crawler, &assets[i], url->full_url);
        }
    }
    
    free(response.data);
    sleep_ms(REQUEST_DELAY_MS);
}

/* Run the crawler */
void crawler_run(Crawler *crawler) {
    printf("[+] Starting depth-first crawl...\n");
    
    while (!stack_empty(crawler)) {
        URL url;
        if (stack_pop(crawler, &url)) {
            char url_str[MAX_URL_LENGTH];
            build_url(&url, url_str);
            
            /* Mark as visited */
            if (!visited_add(&crawler->visited, url_str))
                continue;
            
            process_url(crawler, &url);
            
            /* Progress report every 100 pages */
            if (crawler->total_pages % 100 == 0 && crawler->total_pages > 0) {
                time_t now = time(NULL);
                int elapsed = now - crawler->start_time;
                printf("[*] Progress: %d pages, %d params, %d assets (%d seconds elapsed)\n",
                       crawler->total_pages, crawler->total_params, crawler->total_assets, elapsed);
            }
        }
    }
    
    time_t now = time(NULL);
    int elapsed = now - crawler->start_time;
    
    printf("\n[+] Crawl complete!\n");
    printf("    Total pages: %d\n", crawler->total_pages);
    printf("    Total parameters: %d\n", crawler->total_params);
    printf("    Total assets: %d\n", crawler->total_assets);
    printf("    Time elapsed: %d seconds\n", elapsed);
}

/* Cleanup crawler resources */
void crawler_cleanup(Crawler *crawler) {
    /* Free stack */
    while (!stack_empty(crawler)) {
        URL url;
        stack_pop(crawler, &url);
    }
    
    /* Free visited set */
    visited_free(&crawler->visited);
    
    /* Cleanup libcurl */
    if (crawler->curl)
        curl_easy_cleanup(crawler->curl);
    curl_global_cleanup();
    
    /* Close database connection */
    if (crawler->db_conn)
        sqlite3_close(crawler->db_conn);
}

/* Print usage */
void print_usage(const char *prog) {
    printf("Usage: %s [options] <seed1> [seed2] ...\n\n", prog);
    printf("Seeds can be:\n");
    printf("  - Domain: example.com\n");
    printf("  - Subdomain: api.example.com\n");
    printf("  - IP address: 192.168.1.1\n");
    printf("  - CIDR range: 192.168.1.0/24\n\n");
    printf("Options:\n");
    printf("  -d <depth>    Maximum crawl depth (default: %d)\n", MAX_DEPTH);
    printf("  -q            Quiet mode (less output)\n");
    printf("  -h            Show this help\n\n");
    printf("Examples:\n");
    printf("  %s example.com\n", prog);
    printf("  %s -d 5 example.com api.example.com\n", prog);
    printf("  %s 192.168.1.0/24\n", prog);
}

/* Main entry point */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    /* Parse command line arguments */
    char **seeds = malloc(argc * sizeof(char *));
    int seed_count = 0;
    int max_depth = MAX_DEPTH;
    int verbose = 1;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            max_depth = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-q") == 0) {
            verbose = 0;
        } else if (argv[i][0] != '-') {
            seeds[seed_count++] = argv[i];
        }
    }
    
    if (seed_count == 0) {
        fprintf(stderr, "[!] Error: No seeds provided\n");
        print_usage(argv[0]);
        free(seeds);
        return 1;
    }
    
    /* Initialize libraries */
    if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
        fprintf(stderr, "[!] Failed to initialize libcurl\n");
        free(seeds);
        return 1;
    }
    
    xmlInitParser();
    LIBXML_TEST_VERSION
    
    /* Initialize crawler */
    Crawler crawler;
    crawler_init(&crawler, "");
    crawler.max_depth = max_depth;
    crawler.verbose = verbose;
    
    /* Process seeds */
    process_seeds(&crawler, seeds, seed_count);
    
    /* Run crawler */
    crawler_run(&crawler);
    
    /* Cleanup */
    crawler_cleanup(&crawler);
    xmlCleanupParser();
    curl_global_cleanup();
    free(seeds);
    
    return 0;
}
