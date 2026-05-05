#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>
#include <sqlite3.h>
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#define MAX_URL 2048
#define MAX_HOST 256
#define QUEUE_SIZE 500
#define MAX_THREADS 8

typedef struct { char url[MAX_URL]; char host[MAX_HOST]; int depth; } URLItem;
typedef struct { URLItem q[QUEUE_SIZE]; int head, tail, cnt; pthread_mutex_t m; pthread_cond_t c; int done; } Queue;
typedef struct { char *data; size_t len; long status; long size; char type[64]; } Page;
typedef struct { sqlite3 *db; Queue q; int depth, verbose, active; char target[MAX_HOST]; int fetched, errs; pthread_mutex_t sm, dm; } Crawl;

void qinit(Queue *q) { q->head=q->tail=q->cnt=q->done=0; pthread_mutex_init(&q->m,NULL); pthread_cond_init(&q->c,NULL); }
void qfree(Queue *q) { pthread_mutex_destroy(&q->m); pthread_cond_destroy(&q->c); }

int qpush(Queue *q, URLItem *i) {
    if(q->cnt>=QUEUE_SIZE-10)return 0;
    pthread_mutex_lock(&q->m);
    memcpy(&q->q[q->tail],i,sizeof(URLItem)); q->tail=(q->tail+1)%QUEUE_SIZE; q->cnt++;
    pthread_cond_broadcast(&q->c); pthread_mutex_unlock(&q->m); return 1;
}

int qpop(Queue *q, URLItem *i, int *active) {
    pthread_mutex_lock(&q->m);
    while(q->cnt==0 && !q->done) {
        struct timeval tv; gettimeofday(&tv,NULL);
        struct timespec ts; ts.tv_sec=tv.tv_sec+1; ts.tv_nsec=tv.tv_usec*1000;
        if(pthread_cond_timedwait(&q->c,&q->m,&ts)==ETIMEDOUT && !*active){
            pthread_mutex_unlock(&q->m);return 0;
        }
    }
    if(!q->cnt){pthread_mutex_unlock(&q->m);return 0;}
    memcpy(i,&q->q[q->head],sizeof(URLItem)); q->head=(q->head+1)%QUEUE_SIZE; q->cnt--;
    pthread_mutex_unlock(&q->m); return 1;
}

size_t wcb(void*p,size_t sz,size_t n,void*d) {
    size_t rs=sz*n; Page*pg=(Page*)d;
    if(pg->len+rs>2*1024*1024)return rs;
    char*np=realloc(pg->data,pg->len+rs+1); if(!np)return rs;
    pg->data=np; memcpy(pg->data+pg->len,p,rs); pg->len+=rs; pg->data[pg->len]=0;
    return rs;
}

void dbinit(sqlite3**db) {
    sqlite3_open("crawl.db",db);
    char*sql[]={"CREATE TABLE IF NOT EXISTS p(id INTEGER PRIMARY KEY,url UNIQUE,host,status,len,type)","CREATE TABLE IF NOT EXISTS params(id,pid,name,val)","CREATE TABLE IF NOT EXISTS assets(id,pid,url,type)",NULL};
    for(int i=0;sql[i];i++){char*e;sqlite3_exec(*db,sql[i],0,0,&e);if(e)sqlite3_free(e);}
}

void inspage(Crawl*c,char*u,char*h,long st,long ln,char*t) {
    pthread_mutex_lock(&c->dm);
    sqlite3_stmt*s; if(sqlite3_prepare_v2(c->db,"INSERT OR IGNORE INTO p VALUES(NULL,?,?,?,?,?)",-1,&s,0)==SQLITE_OK){
        sqlite3_bind_text(s,1,u,-1,SQLITE_STATIC);sqlite3_bind_text(s,2,h,-1,SQLITE_STATIC);
        sqlite3_bind_int64(s,3,st);sqlite3_bind_int64(s,4,ln);sqlite3_bind_text(s,5,t,-1,SQLITE_STATIC);
        sqlite3_step(s);sqlite3_finalize(s);
    }pthread_mutex_unlock(&c->dm);
}

void normurl(const char*b,const char*l,char*o,size_t os) {
    if(!l||!b){o[0]=0;return;}
    if(strstr(l,"http://")==l||strstr(l,"https://")==l){strncpy(o,l,os-1);o[os-1]=0;return;}
    if(l[0]=='/'){char h[MAX_HOST]={0};if(sscanf(b,"%*[^/]/%[^/?#]",h)==1)snprintf(o,os,"https://%s%s",h,l);else snprintf(o,os,"https://%s",l);return;}
    char bc[MAX_URL];strncpy(bc,b,sizeof(bc)-1);char*sl=strrchr(bc,'/');if(sl&&!strchr(sl,'?'))*sl=0;
    snprintf(o,os,"%s/%s",bc,l);
}

int vhost(const char*h,const char*t) {
    if(!h||!t)return 0;
    if(strcasecmp(h,t)==0)return 1;
    size_t tl=strlen(t),hl=strlen(h);
    return(hl>tl&&strcmp(h+hl-tl,t)==0&&h[hl-tl-1]=='.');
}

void parse(Crawl*c,char*html,char*base,int d) {
    if(!html||!base||c->q.cnt>QUEUE_SIZE-50)return;
    htmlDocPtr doc=htmlReadMemory(html,strlen(html),NULL,NULL,HTML_PARSE_RECOVER|HTML_PARSE_NOERROR|HTML_PARSE_NOWARNING);
    if(!doc)return;
    xmlXPathContextPtr ctx=xmlXPathNewContext(doc);if(!ctx){xmlFreeDoc(doc);return;}
    xmlXPathObjectPtr lnk=xmlXPathEvalExpression((xmlChar*)"//a/@href",ctx);
    if(lnk&&lnk->nodesetval)for(int i=0;i<lnk->nodesetval->nodeNr&&c->q.cnt<QUEUE_SIZE-50;i++){
        xmlChar*hf=xmlNodeGetContent(lnk->nodesetval->nodeTab[i]);
        if(hf){char nm[MAX_URL],ho[MAX_HOST]={0};normurl(base,(char*)hf,nm,sizeof(nm));
            if(sscanf(nm,"%*[^/]/%[^/?#]",ho)!=1)sscanf(nm,"https://%[^/?#]",ho);
            if(vhost(ho,c->target)&&d<c->depth){URLItem it={.depth=d+1};strncpy(it.url,nm,sizeof(it.url)-1);
                strncpy(it.host,ho,sizeof(it.host)-1);qpush(&c->q,&it);}
            xmlFree(hf);}}
    if(lnk)xmlXPathFreeObject(lnk);xmlXPathFreeContext(ctx);xmlFreeDoc(doc);
}

void*worker(void*a) {
    Crawl*c=(Crawl*)a; CURL*cu=curl_easy_init();if(!cu)return NULL;URLItem it;
    while(qpop(&c->q,&it,&c->active)){
        Page pg={0};struct curl_slist*hd=NULL;
        hd=curl_slist_append(hd,"Accept:text/html,*/*");
        curl_easy_setopt(cu,CURLOPT_URL,it.url);curl_easy_setopt(cu,CURLOPT_USERAGENT,"Mozilla/5.0 Chrome/120");
        curl_easy_setopt(cu,CURLOPT_HTTPHEADER,hd);curl_easy_setopt(cu,CURLOPT_FOLLOWLOCATION,1L);
        curl_easy_setopt(cu,CURLOPT_MAXREDIRS,5L);curl_easy_setopt(cu,CURLOPT_TIMEOUT,8L);
        curl_easy_setopt(cu,CURLOPT_CONNECTTIMEOUT,3L);curl_easy_setopt(cu,CURLOPT_SSL_VERIFYPEER,0L);
        curl_easy_setopt(cu,CURLOPT_WRITEFUNCTION,wcb);curl_easy_setopt(cu,CURLOPT_WRITEDATA,&pg);
        CURLcode r=curl_easy_perform(cu);
        if(r==CURLE_OK){long st=0,lz=0;char*ty=NULL;
            curl_easy_getinfo(cu,CURLINFO_RESPONSE_CODE,&st);curl_easy_getinfo(cu,CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,&lz);
            curl_easy_getinfo(cu,CURLINFO_CONTENT_TYPE,&ty);
            pthread_mutex_lock(&c->sm);c->fetched++;pthread_mutex_unlock(&c->sm);
            if(c->verbose)printf("[%d]%s(%ld)\n",c->fetched,it.url,st);
            if(st==200||st==403||st==500){inspage(c,it.url,it.host,st,lz,ty?ty:"");
                if(ty&&strstr(ty,"text/html")&&pg.data)parse(c,pg.data,it.url,it.depth);}}
        else{pthread_mutex_lock(&c->sm);c->errs++;pthread_mutex_unlock(&c->sm);}
        curl_slist_free_all(hd);free(pg.data);}
    curl_easy_cleanup(cu);return NULL;
}

int main(int ac,char**av) {
    if(ac<2){fprintf(stderr,"Usage:%s<target|file>[-d depth][-t threads][-v]\n",av[0]);return 1;}
    int d=3,t=4,v=0;char*tg[50];int tc=0;
    for(int i=1;i<ac;i++){if(!strcmp(av[i],"-d")&&i+1<ac)d=atoi(av[++i]);
        else if(!strcmp(av[i],"-t")&&i+1<ac)t=atoi(av[++i]);else if(!strcmp(av[i],"-v"))v=1;
        else if(av[i][0]!='-'&&tc<50)tg[tc++]=av[i];}
    if(t>MAX_THREADS)t=MAX_THREADS;if(!tc){fprintf(stderr,"No targets\n");return 1;}
    printf("\n=== Fast Web Crawler ===\n\n");
    curl_global_init(CURL_GLOBAL_ALL);xmlInitParser();sqlite3*db;dbinit(&db);
    Crawl c={.db=db,.depth=d,.verbose=v,.active=1,.fetched=0,.errs=0};qinit(&c.q);
    pthread_mutex_init(&c.sm,NULL);pthread_mutex_init(&c.dm,NULL);
    int sd=0;for(int i=0;i<tc;i++){FILE*f=fopen(tg[i],"r");
        if(f){char ln[MAX_URL];while(fgets(ln,sizeof(ln),f)){ln[strcspn(ln,"\n")]=0;
            if(strlen(ln)>0&&ln[0]!='#'){URLItem it={0};strncpy(it.url,ln,sizeof(it.url)-1);
                char*s=strstr(ln,"://");s=s?s+3:ln;char*e=strchr(s,'/');if(e)*e=0;
                strncpy(it.host,s,sizeof(it.host)-1);if(e)*e='/';qpush(&c.q,&it);sd++;
                if(sd==1)strncpy(c.target,it.host,sizeof(c.target)-1);}}fclose(f);}
        else{URLItem it={0};strncpy(it.url,tg[i],sizeof(it.url)-1);
            char*s=strstr(tg[i],"://");s=s?s+3:tg[i];char*e=strchr(s,'/');if(e)*e=0;
            strncpy(it.host,s,sizeof(it.host)-1);if(e)*e='/';qpush(&c.q,&it);sd++;
            if(sd==1)strncpy(c.target,it.host,sizeof(c.target)-1);}}
    printf("[+] Seeds:%d Scope:%s Depth:%d Threads:%d\n\n",sd,c.target,d,t);
    pthread_t th[MAX_THREADS];for(int i=0;i<t;i++)pthread_create(&th[i],NULL,worker,&c);
    while(1){usleep(100000);if(c.q.cnt==0){sleep(2);if(c.q.cnt==0)break;}}
    c.q.done=1;c.active=0;pthread_cond_broadcast(&c.q.c);
    for(int i=0;i<t;i++)pthread_join(th[i],NULL);
    printf("\n[+] Done! Pages:%d Errors:%d DB:crawl.db\n",c.fetched,c.errs);
    qfree(&c.q);pthread_mutex_destroy(&c.sm);pthread_mutex_destroy(&c.dm);
    sqlite3_close(db);curl_global_cleanup();xmlCleanupParser();return 0;
}
