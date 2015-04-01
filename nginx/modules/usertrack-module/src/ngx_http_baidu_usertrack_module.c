/***************************************************************************
 * 
 * Copyright (c) 2011 Baidu.com, Inc. All Rights Reserved
 * $Id$ 
 * 
 **************************************************************************/
 
 
 
/**
 * @file src/ngx_http_baidu_usertrack_module.c
 * @author forum(xuliqiang@baidu.com)
 * @date 2011/02/17 16:49:01
 * @version $Revision$ 
 * @brief 
 *  
 **/

#include "baidu_des.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/**
 * const 
 */
#define NGX_HTTP_BAIDU_USERTRACK_OFF    0
#define NGX_HTTP_BAIDU_USERTRACK_ON     1
#define NGX_HTTP_BAIDU_USERTRACK_INVALID_OFF    0
#define NGX_HTTP_BAIDU_USERTRACK_INVALID_ON     1
#define NGX_HTTP_BAIDU_USERTRACK_COOKIE_PASS    1
#define NGX_HTTP_BAIDU_USERTRACK_COOKIE_FAIL    0
#define NGX_HTTP_BAIDU_USERTRACK_COOKIE_LEN_MIN 32
#define NGX_HTTP_BAIDU_USERTRACK_COOKIE_DES_LEN 32
#define NGX_HTTP_BAIDU_USERTRACK_COOKIE_DEC_LEN 16
/* 31 Dec 2037 23:55:55 GMT */
#define NGX_HTTP_BAIDU_USERTRACK_MAX_EXPIRES 2145916555
/**
 * define struct ngx_http_baidu_usertrack_conf_t
 */
typedef struct {
    ngx_uint_t  enable;  /* on | off :  0|1**/
	ngx_uint_t  invalid_enable;  /* on | off : 1 | 0 default 0**/
    ngx_str_t   name;    /* default BAIDUID*/
    ngx_str_t   domain;  /* default .baidu.com*/
    ngx_str_t   key;     /* default ''*/
    ngx_str_t   p3pcp;   /* p3p content*/
    ngx_str_t   path;     /* default / */
    time_t      expires; /* default 1 year*/
}ngx_http_baidu_usertrack_conf_t;
typedef struct {
    ngx_str_t           cookie;     /* cookie value of BAIDUUID **/
    ngx_uint_t          check_pass; /* 0 : no cookie or not pass, 1 : pass  */
    des_key_schedule    dks;
}ngx_http_baidu_usertrack_ctx_t;
/**
 * pre define functions
 */
static ngx_int_t ngx_http_baidu_usertrack_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_baidu_usertrack_filter(ngx_http_request_t *r);
static void * ngx_http_baidu_usertrack_create_conf(ngx_conf_t *cf);
static char * ngx_http_baidu_usertrack_merge_conf(ngx_conf_t *cf, 
    void *parent, void *child);
static ngx_int_t ngx_http_baidu_usertrack_init_worker(ngx_cycle_t *cycle);
static ngx_http_baidu_usertrack_ctx_t * ngx_http_baidu_usertrack_get_and_check(
    ngx_http_request_t *r, ngx_http_baidu_usertrack_conf_t *conf);
static ngx_int_t ngx_http_baidu_usertrack_set(ngx_http_request_t *r,
    ngx_http_baidu_usertrack_ctx_t *ctx, ngx_http_baidu_usertrack_conf_t *conf);
/**
 * set expires of cookie
 */
static char * ngx_http_baidu_usertrack_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_baidu_usertrack_domain(ngx_conf_t *cf, void *post, void *data);
static char * ngx_http_baidu_usertrack_path(ngx_conf_t *cf, void *post, void *data);
static char * ngx_http_baidu_usertrack_p3pcp(ngx_conf_t *cf, void *post, void *data);
static ngx_conf_post_handler_pt ngx_http_baidu_usertrack_domain_p = 
    ngx_http_baidu_usertrack_domain;
static ngx_conf_post_handler_pt ngx_http_baidu_usertrack_path_p = 
    ngx_http_baidu_usertrack_path;
static ngx_conf_post_handler_pt ngx_http_baidu_usertrack_p3pcp_p = 
    ngx_http_baidu_usertrack_p3pcp;
/**
 * define header filter ptr
 */
static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_conf_enum_t ngx_http_baidu_usertrack_state[] = {
    {ngx_string("off"), NGX_HTTP_BAIDU_USERTRACK_OFF},
    {ngx_string("on"), NGX_HTTP_BAIDU_USERTRACK_ON},
    {ngx_null_string, 0}
};
static ngx_conf_enum_t ngx_http_baidu_usertrack_invalid_state[] = {
    {ngx_string("off"), NGX_HTTP_BAIDU_USERTRACK_INVALID_OFF},
    {ngx_string("on"), NGX_HTTP_BAIDU_USERTRACK_INVALID_ON},
    {ngx_null_string, 0}
};
static u_char baidu_usertrack_default_expires[] = "; expires=Thu, 31-Dec-37 23:55:55 GMT";
/**
 *
 * define baidu_usertrack command
 */
static ngx_command_t ngx_http_baidu_usertrack_commands[] = {
    {
        ngx_string("usertrack"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_usertrack_conf_t, enable),
        ngx_http_baidu_usertrack_state
    },
	{
        ngx_string("usertrack_invalid"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_usertrack_conf_t, invalid_enable),
        ngx_http_baidu_usertrack_invalid_state
    },    
    {
        ngx_string("usertrack_name"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_usertrack_conf_t, name),
        NULL 
    }, 
    {
        ngx_string("usertrack_domain"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_usertrack_conf_t, domain),
        &ngx_http_baidu_usertrack_domain_p 
    },
    {
        ngx_string("usertrack_key"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_usertrack_conf_t, key),
        NULL 
    },
    {
        ngx_string("usertrack_p3pcp"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_usertrack_conf_t, p3pcp),
        &ngx_http_baidu_usertrack_p3pcp_p 
    },
    {
        ngx_string("usertrack_path"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_usertrack_conf_t, path),
        &ngx_http_baidu_usertrack_path_p 
    },
    {
        ngx_string("usertrack_expires"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_baidu_usertrack_expires,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL 
    },
    ngx_null_command
};

static ngx_http_module_t  ngx_http_baidu_usertrack_module_ctx = {
    NULL,         /* preconfiguration */
    ngx_http_baidu_usertrack_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_baidu_usertrack_create_conf,           /* create location configration */
    ngx_http_baidu_usertrack_merge_conf             /* merge location configration */
};


ngx_module_t  ngx_http_baidu_usertrack_module = {
    NGX_MODULE_V1,
    &ngx_http_baidu_usertrack_module_ctx,    /* module context */
    ngx_http_baidu_usertrack_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_baidu_usertrack_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
/**
 * init , add ngx_http_baidu_usertrack_filter to filter chain
 */
static ngx_int_t ngx_http_baidu_usertrack_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_baidu_usertrack_filter;
    return NGX_OK;
}
/**
 * TODO
 * main filter callback
 */ 
static ngx_int_t ngx_http_baidu_usertrack_filter(ngx_http_request_t *r)
{
    ngx_http_baidu_usertrack_ctx_t *ctx;
    ngx_http_baidu_usertrack_conf_t *conf;
    if (r != r->main) {
        return ngx_http_next_header_filter(r);
    }
    conf = ngx_http_get_module_loc_conf(r, ngx_http_baidu_usertrack_module);
    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"test name[%s]", conf->name.data);
    if (conf->enable != NGX_HTTP_BAIDU_USERTRACK_ON) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "usertrack is off [%d]", conf->enable);
        return ngx_http_next_header_filter(r);
    }
    //get form cookie, and check it
    ctx = ngx_http_baidu_usertrack_get_and_check(r, conf);
    if (NULL == ctx) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "get usertrack error!ctx is null");
        return NGX_ERROR;
    }
    //set
    if (ctx->check_pass == NGX_HTTP_BAIDU_USERTRACK_COOKIE_PASS) {
        //pass
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "usertrack pass, name[%V], value[%V]", &conf->name, &ctx->cookie);
        return ngx_http_next_header_filter(r);
    } else {
        //not pass , need set
        if (ngx_http_baidu_usertrack_set(r, ctx, conf) == NGX_OK) {
            //set succ
            return ngx_http_next_header_filter(r);
        }
        //set fail
    }
    return NGX_ERROR;
}
static ngx_http_baidu_usertrack_ctx_t *
ngx_http_baidu_usertrack_get_and_check(ngx_http_request_t *r, 
    ngx_http_baidu_usertrack_conf_t *conf)
{
    ngx_int_t                n;
    ngx_http_baidu_usertrack_ctx_t   *ctx;
    char dec_str[NGX_HTTP_BAIDU_USERTRACK_COOKIE_DEC_LEN+1];
    unsigned int *ptr, cs, server_ip[2];
    ctx = ngx_http_get_module_ctx(r, ngx_http_baidu_usertrack_module);
    if (ctx) {
        return ctx;
    }
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "conf domain[%V], conf path[%V], conf p3pcp[%V]", &conf->domain, &conf->path, &conf->p3pcp);
    if (ctx == NULL) {
        //init
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_baidu_usertrack_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }
        ctx->check_pass = NGX_HTTP_BAIDU_USERTRACK_COOKIE_FAIL;
        //init des key
        initKeySchedule(&(ctx->dks), conf->key.data);
        ngx_http_set_ctx(r, ctx, ngx_http_baidu_usertrack_module);
    }
    n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &conf->name,
        &ctx->cookie);
    if (n == NGX_DECLINED) {
        return ctx;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "get cookie[%V]", &ctx->cookie);
    if (ctx->cookie.len < NGX_HTTP_BAIDU_USERTRACK_COOKIE_LEN_MIN) {
        //invaild cookie
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "usertrack cookie too short [%V]", &ctx->cookie);
        return ctx;
    }
    //parse 
    if (desdecrypt(dec_str, NGX_HTTP_BAIDU_USERTRACK_COOKIE_DEC_LEN, 
            ctx->cookie.data, NGX_HTTP_BAIDU_USERTRACK_COOKIE_DES_LEN, 
            &ctx->dks) < 0 ){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "decrypt cookie_name value[%V] failed", &ctx->cookie);
        return ctx;
    }
    //check
    ptr = (unsigned int*)dec_str;
    cs = checksum(dec_str, 12);
    if (ptr[3] != cs) {
        //check not pass
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "checksum not equal: read[%ud] should[%ud]", ptr[3], cs);
        return ctx;
    }
	if (conf->invalid_enable == NGX_HTTP_BAIDU_USERTRACK_INVALID_ON && ptr[0] != 0) {
		//invalid intranet ip
		server_ip[0] = (unsigned char)*((char *)&ptr[0]+0);
		server_ip[1] = (unsigned char)*((char *)&ptr[0]+1);
		if((server_ip[0] == 10) || (server_ip[0] == 172 && server_ip[1] >= 16 && server_ip[1] <= 31) || (server_ip[0] == 192 && server_ip[1] == 168)) {
			ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
				"cookie server-side invalided, cookie[%V], id1[%ud], id2[%ud], id3[%ud]",
				&ctx->cookie, ptr[0], ptr[1], ptr[2]);
			return ctx;
		}
    }
    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
        "cookie check pass, cookie[%V], id1[%ud], id2[%ud], id3[%ud]",
        &ctx->cookie, ptr[0], ptr[1], ptr[2]);
    //check pass
    ctx->check_pass = NGX_HTTP_BAIDU_USERTRACK_COOKIE_PASS;
    return ctx;
}
static ngx_int_t ngx_http_baidu_usertrack_build_baiduid(ngx_http_request_t *r,
    ngx_http_baidu_usertrack_ctx_t *ctx, ngx_http_baidu_usertrack_conf_t *conf,
    char *out_des_str, int out_des_str_len)
{
    unsigned int src[4], cs;
    ngx_connection_t     *c;
    struct sockaddr_in   *sin;
    /* cookie_name value = DES(IP + request_time + random + checksum) */
    /* get IP */
    c = r->connection;
	/* AF_INET only */
	if (c->sockaddr->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) c->sockaddr;
		src[0] = sin->sin_addr.s_addr;
    } else {
        src[0] = 0;
    }
    src[1] = r->start_sec;
    src[2] = random();
    cs =checksum((char *)src, 12);
    src[3] = cs;
    
    if(desencrypt(out_des_str, out_des_str_len, 
        (char*)src, sizeof(src), &ctx->dks) < 0) {
        //des fail
        return NGX_ERROR;
    }
    return NGX_OK;
}
static ngx_int_t ngx_http_baidu_usertrack_set(ngx_http_request_t *r,
    ngx_http_baidu_usertrack_ctx_t *ctx, ngx_http_baidu_usertrack_conf_t *conf)
{
    char des_str[NGX_HTTP_BAIDU_USERTRACK_COOKIE_DES_LEN + 1];
    unsigned int cookie_len;
    ngx_str_t fg = ngx_string(":FG=1");
    ngx_str_t version = ngx_string("; version=1");
    u_char *cookie, *p;
    u_char max_age_str[256];
    int max_age_str_len;
    ngx_table_elt_t  *set_cookie, *p3p;
    memset(des_str, 0, sizeof(des_str));
    //build baiduid
    if (ngx_http_baidu_usertrack_build_baiduid(r, ctx, conf, des_str, 
            NGX_HTTP_BAIDU_USERTRACK_COOKIE_DES_LEN) != NGX_OK ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "usertrack desencrypt error!");
        return NGX_OK;
    }
   //set cookie and p3pcp
    /**
     * Set-Cookie: BAIDUID=966121D4F1DE42D5ACE51C9C8CA128E8:FG=1; expires=Mon, 21-Feb-41 05:13:10 GMT; path=/; domain=.baidu.com
     * Set-Cookie: BAIDUID=5387116CDF334CF81DC83710D4723371:FG=1; expires=Tue, 21-Feb-12 08:42:56 GMT; max-age=31536000; path=/; domain=.baidu.com; version=1
     * P3P: CP=" OTI DSP COR IVA OUR IND COM "
     */
    max_age_str_len = snprintf(max_age_str, sizeof(max_age_str), "; max-age=%lu", conf->expires);
    cookie_len = conf->name.len + 1 + NGX_HTTP_BAIDU_USERTRACK_COOKIE_DES_LEN + conf->path.len;
    cookie_len += sizeof(baidu_usertrack_default_expires) - 1 + max_age_str_len;
    cookie_len += conf->domain.len + version.len;
    cookie_len += 1;
    if (conf->p3pcp.len > 0) {
        /* I don't know what FG does, but if it is missing other usertrack will
         * discard our cookie and make a new one */
        cookie_len += fg.len; 
    }
    cookie = ngx_pnalloc(r->pool, cookie_len);
    if (NULL == cookie) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "usertrack set, pnalloc fail!");
        return NGX_ERROR;
    }
    p = ngx_copy(cookie, conf->name.data, conf->name.len);
    *p++ = '=';
    p = ngx_copy(p, des_str, NGX_HTTP_BAIDU_USERTRACK_COOKIE_DES_LEN);
    if (conf->p3pcp.len > 0) {
        p = ngx_copy(p, fg.data, fg.len);
    }
    //build with expires
    if (conf->expires == NGX_HTTP_BAIDU_USERTRACK_MAX_EXPIRES) {
        //max
        p = ngx_cpymem(p, baidu_usertrack_default_expires, 
            sizeof(baidu_usertrack_default_expires) - 1);
    } else {
        p = ngx_cpymem(p, baidu_usertrack_default_expires, 
            sizeof("; expires=")-1);
        p = ngx_http_cookie_time(p, ngx_time() + conf->expires);
    }
    p = ngx_copy(p, max_age_str, max_age_str_len);
    /* build with path/domain/version**/
    p = ngx_copy(p, conf->path.data, conf->path.len);
    p = ngx_copy(p, conf->domain.data, conf->domain.len);
    p = ngx_copy(p, version.data, version.len);
    /* build cookie end, debug*/
    /* add to output header*/
    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "usertrack push cookie to headers_out fail!");
        return NGX_ERROR;
    }
    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
        "build cookie[%s],cookie2[%s]", cookie, set_cookie->value.data);
    //p3p
    if (conf->p3pcp.len == 0) {
        return NGX_OK;
    }
    p3p = ngx_list_push(&r->headers_out.headers);
    if (p3p == NULL) {
        return NGX_ERROR;
    }
    p3p->hash = 1;
    ngx_str_set(&p3p->key, "P3P");
    p3p->value = conf->p3pcp;
    return NGX_OK;
}
/**
 * set expires
 */
static char * 
ngx_http_baidu_usertrack_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_baidu_usertrack_conf_t *ucf = conf;
    ngx_str_t  *value;

    if (ucf->expires != NGX_CONF_UNSET) {
        return "is duplicate";
    }
    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "max") == 0) {
        ucf->expires = NGX_HTTP_BAIDU_USERTRACK_MAX_EXPIRES;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ucf->expires = 0;
        return NGX_CONF_OK;
    }

    ucf->expires = ngx_parse_time(&value[1], 1);
    if (ucf->expires == NGX_ERROR) {
        return "invalid value";
    }
	/*
    if (ucf->expires == NGX_PARSE_LARGE_TIME) {
        return "value must be less than 68 years";
    }
	*/
    return NGX_CONF_OK;
}
static void * ngx_http_baidu_usertrack_create_conf(ngx_conf_t *cf)
{
    ngx_http_baidu_usertrack_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_baidu_usertrack_conf_t));
    if (NULL == conf) {
        return NULL;
    }
    conf->enable = NGX_CONF_UNSET_UINT;
	conf->invalid_enable = NGX_CONF_UNSET_UINT;
    conf->expires = NGX_CONF_UNSET;
    return conf;
}
static char * ngx_http_baidu_usertrack_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_baidu_usertrack_conf_t *prev = parent;
    ngx_http_baidu_usertrack_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->enable, prev->enable, NGX_HTTP_BAIDU_USERTRACK_ON);
	ngx_conf_merge_uint_value(conf->invalid_enable, prev->invalid_enable, NGX_HTTP_BAIDU_USERTRACK_INVALID_ON);
    ngx_conf_merge_str_value(conf->name, prev->name, "BAIDUID");
    ngx_conf_merge_str_value(conf->domain, prev->domain, "; domain=.baidu.com");
    ngx_conf_merge_str_value(conf->path, prev->path, "; path=/");
    ngx_conf_merge_str_value(conf->p3pcp, prev->p3pcp, "CP=\" OTI DSP COR IVA OUR IND COM \"");
    ngx_conf_merge_str_value(conf->key, prev->key, "ZxdeacAD");
    ngx_conf_merge_sec_value(conf->expires, prev->expires, 31536000);//365 * 3600 * 24
    
    return NGX_CONF_OK;
}
static ngx_int_t ngx_http_baidu_usertrack_init_worker(ngx_cycle_t *cycle)
{
    //nothing todo
    return NGX_OK;
}
/* get domain form nginx.conf, and rebuild it */
static char * ngx_http_baidu_usertrack_domain(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *domain = data;
    u_char  *p, *new;

    if (ngx_strcmp(domain->data, "none") == 0) {
        ngx_str_set(domain, "");
        return NGX_CONF_OK;
    }

    new = ngx_pnalloc(cf->pool, sizeof("; domain=") - 1 + domain->len);
    if (new == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(new, "; domain=", sizeof("; domain=") - 1);
    ngx_memcpy(p, domain->data, domain->len);

    domain->len += sizeof("; domain=") - 1;
    domain->data = new;

    return NGX_CONF_OK;
}
static char * ngx_http_baidu_usertrack_path(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *path = data;
    u_char  *p, *new;

    new = ngx_pnalloc(cf->pool, sizeof("; path=") - 1 + path->len);
    if (new == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(new, "; path=", sizeof("; path=") - 1);
    ngx_memcpy(p, path->data, path->len);

    path->len += sizeof("; path=") - 1;
    path->data = new;

    return NGX_CONF_OK;
}
static char * ngx_http_baidu_usertrack_p3pcp(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *p3p = data;

    if (ngx_strcmp(p3p->data, "none") == 0) {
        ngx_str_set(p3p, "");
    }

    return NGX_CONF_OK;
}
/* vim: set ts=4 sw=4 sts=4 tw=100 */
