
/*
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


#define MAX_HASH_DATA_LEN 64
#define MAX_COOKIE_NAME_LEN 256
#define MAX_COOKIE_VALUE_LEN 128 

typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp;

    ngx_uint_t                         hash;

    int                                hash_flag;
    
    u_char                             tries;

    u_char                             cookie_value[MAX_COOKIE_VALUE_LEN];

    ngx_event_get_peer_pt              get_rr_peer;
} ngx_http_baidu_upstream_cook_hash_peer_data_t;


static u_char g_cookie_name[MAX_COOKIE_NAME_LEN];

static ngx_int_t ngx_http_upstream_init_cook_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_cook_hash_peer(ngx_peer_connection_t *pc,
    void *data);
static char *ngx_http_baidu_upstream_cook_hash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *
ngx_http_upstream_cookie_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_baidu_upstream_cook_hash_commands[] = {

    { ngx_string("cookie_hash"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_http_baidu_upstream_cook_hash,
      0,
      0,
      NULL },
     { ngx_string("cookie_name"),
       NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
       ngx_http_upstream_cookie_name,
       0,
       0,
       NULL},   
      ngx_null_command
};


static ngx_http_module_t  ngx_http_baidu_upstream_cook_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_baidu_upstream_cook_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_baidu_upstream_cook_hash_module_ctx, /* module context */
    ngx_http_baidu_upstream_cook_hash_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_http_upstream_init_cook_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_cook_hash_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_cook_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{

    ngx_http_baidu_upstream_cook_hash_peer_data_t  *cookhp;

    cookhp = ngx_palloc(r->pool, sizeof(ngx_http_baidu_upstream_cook_hash_peer_data_t));
    if (cookhp == NULL) {
        return NGX_ERROR;
    }

    ngx_str_t cookie_name = ngx_string(g_cookie_name);
    cookie_name.len = strlen(g_cookie_name);

    ngx_http_variable_value_t*t =  ngx_http_get_variable(r, &cookie_name,0); 

    cookhp->hash_flag = 0;

    r->upstream->peer.data = &cookhp->rrp;

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_cook_hash_peer;

    unsigned int ip_value = 0;
    if (r->connection->sockaddr->sa_family == AF_INET) {

        struct sockaddr_in* sin = (struct sockaddr_in *) r->connection->sockaddr;
        ip_value = sin->sin_addr.s_addr;
    } else {
		ip_value = 0;
    }

    if (t->not_found == 0) {

        unsigned int max_copy_len = t->len >  (MAX_COOKIE_VALUE_LEN - 1) ? (MAX_COOKIE_VALUE_LEN - 1) : t->len;
		if(max_copy_len > 0){
			strncpy(cookhp->cookie_value, t->data, max_copy_len);
			cookhp->cookie_value[max_copy_len] = '\0';

			cookhp->hash_flag = 1;
			cookhp->hash = ngx_hash_key(t->data, t->len);
			cookhp -> hash += ip_value;
		}
    } 

    cookhp->tries = 0;
    cookhp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_cook_hash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_baidu_upstream_cook_hash_peer_data_t  *cookhp = data;

    time_t                        now;
    uintptr_t                     m;
    ngx_uint_t                    n, p, hash;
    ngx_http_upstream_rr_peer_t  *peer = NULL;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get cookie hash peer, try: %ui", pc->tries);

    if (cookhp->tries > 20 || cookhp->rrp.peers->single || cookhp->hash_flag == 0) {
        return cookhp->get_rr_peer(pc, &cookhp->rrp);
    }

    now = ngx_time();

    pc->cached = 0;
    pc->connection = NULL;

    hash = cookhp->hash;

    for ( ;; ) {

        p = hash % cookhp->rrp.peers->number;

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (!(cookhp->rrp.tried[n] & m)) {

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "get cookie hash peer, cookie_value %s hash:%ui index %ui %04XA", cookhp->cookie_value,hash, p, m);

            peer = &cookhp->rrp.peers->peer[p];

            /* ngx_lock_mutex(cookhp->rrp.peers->mutex); */

            if (!peer->down) {

                if (peer->max_fails == 0 || peer->fails < peer->max_fails) {
                    break;
                }

                if (now - peer->accessed > peer->fail_timeout) {
                    peer->fails = 0;
                    break;
                }
            }

            cookhp->rrp.tried[n] |= m;

            /* ngx_unlock_mutex(iphp->rrp.peers->mutex); */

            pc->tries--;
        }

        if (++cookhp->tries >= 20) {
            return cookhp->get_rr_peer(pc, &cookhp->rrp);
        }
        hash += ngx_crc32_short((u_char*)&hash, sizeof(hash));
    }
	ngx_log_debug4(
        NGX_LOG_DEBUG_HTTP, pc->log, 0,
        "select upstream succ, cookie_value:%s, hash: %ui index:%ui %s", 
        cookhp->cookie_value, 
        hash,
        p, 
        peer->name.data
        );
						   
    cookhp->rrp.current = p;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    /* ngx_unlock_mutex(iphp->rrp.peers->mutex); */

    cookhp->rrp.tried[n] |= m;
    cookhp->hash = hash;

    return NGX_OK;
}


static char *
ngx_http_baidu_upstream_cook_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    uscf->peer.init_upstream = ngx_http_upstream_init_cook_hash;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN;

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_cookie_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;
    ngx_str_t *value;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

	if(cf->args->nelts < 2){
	    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "get cookie name failed, cf->args->nelts < 2: %ui", cf->args->nelts);
        return NGX_CONF_ERROR;
	}
	
    value = cf->args->elts;
    if(value[1].len > MAX_COOKIE_NAME_LEN - 1){
        return NGX_CONF_ERROR;
    }

    u_char* p = ngx_cpymem(g_cookie_name, value[1].data, value[1].len);
    *p = '\0';

    return NGX_CONF_OK;
}
