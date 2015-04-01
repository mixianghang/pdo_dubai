/***************************************************************************
 * 
 * Copyright (c) 2011 Baidu.com, Inc. All Rights Reserved
 * $Id$ 
 * 
 **************************************************************************/



/**
 * @file ngx_http_baidu_cache_monitor_module.c
 * @author changming(changming01@baidu.com)
 * @date 2011/10/29 17:48:37
 * @version $Revision$ 
 * @brief 
 *  
 **/
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static void* ngx_http_baidu_cache_monitor_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_baidu_cache_monitor_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_baidu_cache_monitor_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_cache_monitor_header_filter(ngx_http_request_t *r);

typedef struct {
    ngx_flag_t enable;
	size_t rate;
    size_t max_time_value;
    ngx_str_t time_field_name;
    size_t header_size;
} ngx_http_baidu_cache_monitor_loc_conf_t;

static ngx_command_t  ngx_http_baidu_cache_monitor_commands[] = {
    {
		ngx_string("cache_monitor"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_cache_monitor_loc_conf_t, enable),
		NULL
	},
    {
		ngx_string("send_rate"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_cache_monitor_loc_conf_t, rate),
		NULL
	},
    {
		ngx_string("max_time_value"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_cache_monitor_loc_conf_t, max_time_value),
		NULL
	},
    {
		ngx_string("time_field_name"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_cache_monitor_loc_conf_t, time_field_name),
		NULL
	},
    {
		ngx_string("header_size"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_baidu_cache_monitor_loc_conf_t, header_size),
		NULL
	},
    ngx_null_command
};

static ngx_http_module_t  ngx_http_baidu_cache_monitor_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_baidu_cache_monitor_init,           /* postconfiguration */
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_baidu_cache_monitor_create_loc_conf,  /* create location configuration */
    ngx_http_baidu_cache_monitor_merge_loc_conf /* merge location configuration */
};


ngx_module_t  ngx_http_baidu_cache_monitor_module = {
    NGX_MODULE_V1,
    &ngx_http_baidu_cache_monitor_module_ctx, /* module context */
    ngx_http_baidu_cache_monitor_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static ngx_int_t
ngx_http_baidu_cache_monitor_init(ngx_conf_t *cf)
{
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_cache_monitor_header_filter;

	return NGX_OK;
}

static ngx_int_t
ngx_http_cache_monitor_header_filter(ngx_http_request_t *r)
{
	ngx_http_baidu_cache_monitor_loc_conf_t *conf = NULL;
	conf = ngx_http_get_module_loc_conf(r, ngx_http_baidu_cache_monitor_module);
	if(conf == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get conf failed in cache monitor ");
		return NGX_ERROR;
	}

	if(!conf->enable) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "header filter failed, cache monitor is off");
		return ngx_http_next_header_filter(r);
	}

    int send_rate = 0;
    int send_total_time = 0;
    u_char* p = NULL;

    if ( r->args.len > 0){
        p = ngx_strstr(r->args.data, conf->time_field_name.data);
    }

    if( p == NULL){
        send_rate = conf->rate;
    } else {
        p += conf->time_field_name.len;
        while( p < (r->args.data + r->args.len - 2)){
            if ( *p != ' ' && *p != '\t' ) {
                break;
            } 
            p++;
        }
		
		if ( *p != '=' ) {
            send_rate = conf->rate;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "*p != \"=\"");
		} else {
		    p ++;

            send_total_time = atoi(p); 
            if ( send_total_time > (int)conf->max_time_value ) {
                send_total_time = conf -> max_time_value;
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "send total time > conf->max_time_value");
            }

            if ( send_total_time <= 0 ) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "send total time < 0");
                return ngx_http_next_header_filter(r);
            }

            send_rate = conf->header_size / send_total_time;
        }
    }

    if(send_rate <= 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rate <= 0");
        return ngx_http_next_header_filter(r);
    }

    if(r->headers_out.status == NGX_HTTP_OK){
		r->limit_rate = send_rate;
    }

	return ngx_http_next_header_filter(r);
}

static void *
ngx_http_baidu_cache_monitor_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_baidu_cache_monitor_loc_conf_t  *conf = NULL;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_baidu_cache_monitor_loc_conf_t));
    if (conf == NULL) {
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, "conf alloc failed");
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
	conf->rate = NGX_CONF_UNSET_SIZE;
    conf->header_size = NGX_CONF_UNSET_SIZE;
    conf->max_time_value = NGX_CONF_UNSET_SIZE;

    return conf;
}
static char *
ngx_http_baidu_cache_monitor_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_baidu_cache_monitor_loc_conf_t *prev = parent;
    ngx_http_baidu_cache_monitor_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
	ngx_conf_merge_size_value(conf->rate, prev->rate, 200);
    ngx_conf_merge_size_value(conf->max_time_value, prev->max_time_value, 5);
    ngx_conf_merge_size_value(conf->header_size, prev->header_size, 426);
    ngx_conf_merge_str_value(conf->time_field_name, prev->time_field_name, "t");

    return NGX_CONF_OK;
}

