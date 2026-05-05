/*
 * Stable Multi-Threaded Web Crawler
 * Fixed version with proper synchronization and memory safety
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <curl/curl.h>
#include <sqlite3.h>
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#include <signal.h>
#include <sys/stat.h>

#define MAX_URL 2048
#define MAX_HOST 256
#define MAX_PATH_LEN 1024
#define MAX_QUERY 512
#define QUEUE_SIZE 5000
#define MAX_THREADS 16

volatile int g_shutdown = 0;

typedef struct {
    char url[MAX_URL];
    char host[MAX_HOST];
    char path[MAX_PATH_LEN];
    char query[MAX_QUERY];
    int depth;
} URLItem;

typedef struct {
    URLItem items[QUEUE_SIZE];
    int head, tail, count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty, not_full;
    int shutdown;
} URLQueue;

typedef struct {
    char *content;
    size_t size;
    long status;
    long length;
    char content_type[128];
} PageData;

typedef struct {
    sqlite3 *db;
    URLQueue queue;
    pthread_t threads[MAX_THREADS];
    int num_threads;
    int max_depth;
    int verbose;
    int save_assets;
    char target[MAX_HOST];
    int fetched;
    int errors;
    pthread_mutex_t stats_lock;
    pthread_mutex_t db_lock;
} Crawler;

void init_queue(URLQueue *q) {
    q->head = q->tail = q->count = q->shutdown = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

void destroy_queue(URLQueue *q) {
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
}

int push_queue(URLQueue *q, URLItem *item) {
    pthread_mutex_lock(&q->lock);
    while (q->count == QUEUE_SIZE && !q->shutdown)
        pthread_cond_wait(&q->not_full, &q->lock);
    if (q->shutdown) { pthread_mutex_unlock(&q->lock); return 0; }
    memcpy(&q->items[q->tail], item, sizeof(URLItem));
    q->tail = (q->tail + 1) % QUEUE_SIZE;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return 1;
}

int pop_queue(URLQueue *q, URLItem *item) {
    pthread_mutex_lock(&q->lock);
    while (q->count == 0 && !q->shutdown)
        pthread_cond_wait(&q->not_empty, &q->lock);
    if (q->count == 0) { pthread_mutex_unlock(&q->lock); return 0; }
    memcpy(item, &q->items[q->head], sizeof(URLItem));
    q->head = (q->head + 1) % QUEUE_SIZE;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return 1;
}

size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data) {
    size_t realsize = size * nmemb;
    PageData *page = (PageData*)data;
    if (page->size + realsize > 10*1024*1024) return realsize;
    char *newp = realloc(page->content, page->size + realsize + 1);
    if (!newp) return 0;
    page->content = newp;
    memcpy(page->content + page->size, ptr, realsize);
    page->size += realsize;
    page->content[page->size] = 0;
    return realsize;
}

void init_db(sqlite3 **db) {
    sqlite3_open("crawler.db", db);
    const char *sql[] = {
        "CREATE TABLE IF NOT EXISTS pages(id INTEGER PRIMARY KEY,url TEXT UNIQUE,host,path,query,status,length,type,date)",
        "CREATE TABLE IF NOT EXISTS params(id INTEGER PRIMARY KEY,page_id,name,value)",
        "CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY,page_id,url,type)",
        "CREATE INDEX IF NOT EXISTS idx_host ON pages(host)",
        NULL
    };
    for (int i = 0; sql[i]; i++) {
        char *err; sqlite3_exec(*db, sql[i], 0, 0, &err);
        if (err) sqlite3_free(err);
    }
}

void insert_page(Crawler *c, const char *url, const char *host, const char *path, 
                 const char *query, long status, long len, const char *type) {
    pthread_mutex_lock(&c->db_lock);
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(c->db, "INSERT OR IGNORE INTO pages VALUES(NULL,?,?,?,?,?,?,?,datetime('now'))", -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, url, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, host, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, path, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, query, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 5, status);
        sqlite3_bind_int64(stmt, 6, len);
        sqlite3_bind_text(stmt, 7, type, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&c->db_lock);
}

void normalize_url(const char *base, const char *link, char *out, size_t outsize) {
    if (!link || !base) { out[0]=0; return; }
    if (strstr(link, "http://") == link || strstr(link, "https://") == link) {
        strncpy(out, link, outsize-1); out[outsize-1]=0; return;
    }
    if (link[0] == '/') {
        char host[MAX_HOST]={0};
        if (sscanf(base, "%*[^/]/%[^/?#]", host) == 1)
            snprintf(out, outsize, "https://%s%s", host, link);
        else snprintf(out, outsize, "https://%s", link);
        return;
    }
    char basecopy[MAX_URL]; strncpy(basecopy, base, sizeof(basecopy)-1);
    char *slash = strrchr(basecopy, '/');
    if (slash && !strchr(slash, '?')) *slash = 0;
    snprintf(out, outsize, "%s/%s", basecopy, link);
}

int valid_host(const char *host, const char *target) {
    if (!host || !target) return 0;
    if (strcasecmp(host, target) == 0) return 1;
    size_t tl = strlen(target), hl = strlen(host);
    return (hl > tl && strcmp(host+hl-tl, target)==0 && host[hl-tl-1]=='.');
}

void parse_links(Crawler *c, const char *html, const char *base, int depth) {
    if (!html || !base) return;
    htmlDocPtr doc = htmlReadMemory(html, strlen(html), NULL, NULL, HTML_PARSE_RECOVER|HTML_PARSE_NOERROR|HTML_PARSE_NOWARNING);
    if (!doc) return;
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    if (!ctx) { xmlFreeDoc(doc); return; }
    
    xmlXPathObjectPtr links = xmlXPathEvalExpression((xmlChar*)"//a/@href", ctx);
    if (links && links->nodesetval) {
        for (int i = 0; i < links->nodesetval->nodeNr && !g_shutdown; i++) {
            xmlChar *href = xmlNodeGetContent(links->nodesetval->nodeTab[i]);
            if (href) {
                char norm[MAX_URL], host[MAX_HOST]={0}, path[MAX_PATH_LEN]={0}, query[MAX_QUERY]={0};
                normalize_url(base, (char*)href, norm, sizeof(norm));
                if (sscanf(norm, "%*[^/]/%[^/?#]", host) != 1)
                    sscanf(norm, "https://%[^/?#]", host);
                char *ps = strstr(norm, host);
                if (ps) { ps += strlen(host);
                    char *q = strchr(ps, '?');
                    if (q) { strncpy(path, ps, q-ps); strncpy(query, q+1, sizeof(query)-1); }
                    else strncpy(path, ps, sizeof(path)-1);
                } else strcpy(path, "/");
                if (valid_host(host, c->target) && depth < c->max_depth) {
                    URLItem item = {.depth = depth+1};
                    strncpy(item.url, norm, sizeof(item.url)-1);
                    strncpy(item.host, host, sizeof(item.host)-1);
                    strncpy(item.path, path, sizeof(item.path)-1);
                    strncpy(item.query, query, sizeof(item.query)-1);
                    push_queue(&c->queue, &item);
                }
                xmlFree(href);
            }
        }
        xmlXPathFreeObject(links);
    }
    xmlXPathFreeContext(ctx);
    xmlFreeDoc(doc);
}

void *worker(void *arg) {
    Crawler *c = (Crawler*)arg;
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    URLItem item;
    while (!g_shutdown && pop_queue(&c->queue, &item)) {
        PageData page = {0};
        struct curl_slist *hdrs = NULL;
        hdrs = curl_slist_append(hdrs, "Accept: text/html,*/*;q=0.8");
        curl_easy_setopt(curl, CURLOPT_URL, item.url);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &page);
        
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            long status=0, len=0; char *type=NULL;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
            curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &len);
            curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &type);
            pthread_mutex_lock(&c->stats_lock); c->fetched++; pthread_mutex_unlock(&c->stats_lock);
            if (c->verbose) printf("[%d] %s (%ld)\n", c->fetched, item.url, status);
            if (status==200 || status==403 || status==500) {
                insert_page(c, item.url, item.host, item.path, item.query, status, len, type?type:"");
                if (type && strstr(type, "text/html") && page.content)
                    parse_links(c, page.content, item.url, item.depth);
            }
        } else {
            pthread_mutex_lock(&c->stats_lock); c->errors++; pthread_mutex_unlock(&c->stats_lock);
        }
        curl_slist_free_all(hdrs);
        free(page.content);
    }
    curl_easy_cleanup(curl);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <target|file> [-d depth] [-t threads] [-v] [-a]\n", argv[0]); return 1; }
    int depth=5, threads=4, verbose=0, assets=0;
    char *targets[100]; int tcount=0;
    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"-d") && i+1<argc) depth=atoi(argv[++i]);
        else if (!strcmp(argv[i],"-t") && i+1<argc) threads=atoi(argv[++i]);
        else if (!strcmp(argv[i],"-v")) verbose=1;
        else if (!strcmp(argv[i],"-a")) assets=1;
        else if (argv[i][0]!='-' && tcount<100) targets[tcount++]=argv[i];
    }
    if (threads>MAX_THREADS) threads=MAX_THREADS;
    if (tcount==0) { fprintf(stderr, "No targets\n"); return 1; }
    
    printf("\n╔═══════════════════════════════════════════════════╗\n");
    printf("║     Fast Multi-Threaded Web Crawler              ║\n");
    printf("╚═══════════════════════════════════════════════════╝\n\n");
    
    curl_global_init(CURL_GLOBAL_ALL);
    xmlInitParser();
    sqlite3 *db; init_db(&db);
    
    Crawler c = {.db=db, .max_depth=depth, .verbose=verbose, .save_assets=assets, .fetched=0, .errors=0};
    init_queue(&c.queue);
    pthread_mutex_init(&c.stats_lock, NULL);
    pthread_mutex_init(&c.db_lock, NULL);
    
    int seeds=0;
    for (int i=0; i<tcount && !g_shutdown; i++) {
        FILE *f=fopen(targets[i],"r");
        if (f) {
            char line[MAX_URL];
            while (fgets(line,sizeof(line),f) && !g_shutdown) {
                line[strcspn(line,"\n")]=0;
                if (strlen(line)>0 && line[0]!='#') {
                    URLItem item={0}; strncpy(item.url,line,sizeof(item.url)-1);
                    char *s=strstr(line,"://"); s=s?s+3:line;
                    char *e=strchr(s,'/'); if(e)*e=0;
                    strncpy(item.host,s,sizeof(item.host)-1); if(e)*e='/';
                    push_queue(&c.queue,&item); seeds++;
                    if (seeds==1) strncpy(c.target,item.host,sizeof(c.target)-1);
                }
            }
            fclose(f);
        } else {
            URLItem item={0}; strncpy(item.url,targets[i],sizeof(item.url)-1);
            char *s=strstr(targets[i],"://"); s=s?s+3:targets[i];
            char *e=strchr(s,'/'); if(e)*e=0;
            strncpy(item.host,s,sizeof(item.host)-1); if(e)*e='/';
            push_queue(&c.queue,&item); seeds++;
            if (seeds==1) strncpy(c.target,item.host,sizeof(c.target)-1);
        }
    }
    
    printf("[+] Targets: %d | Scope: %s\n", seeds, c.target);
    printf("[+] Threads: %d | Max Depth: %d\n\n", threads, depth);
    
    signal(SIGINT, (void(*)(int))0);
    signal(SIGTERM, (void(*)(int))0);
    
    c.num_threads = threads;
    for (int i=0; i<threads; i++) pthread_create(&c.threads[i], NULL, worker, &c);
    for (int i=0; i<threads; i++) pthread_join(c.threads[i], NULL);
    
    printf("\n[✓] Done! Fetched: %d, Errors: %d\n", c.fetched, c.errors);
    printf("[✓] Database: crawler.db\n");
    
    destroy_queue(&c.queue);
    pthread_mutex_destroy(&c.stats_lock);
    pthread_mutex_destroy(&c.db_lock);
    sqlite3_close(db);
    curl_global_cleanup();
    xmlCleanupParser();
    return 0;
}
