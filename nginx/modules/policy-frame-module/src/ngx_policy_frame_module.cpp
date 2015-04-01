/***************************************************************************
 *
 * Copyright (c) 2011 Baidu.com, Inc. All Rights Reserved
 * $Id$
 *
 **************************************************************************/



/**
 * @file src/ngx_http_baidu_usertrack_module.c
 * @author forum(xuliqiang@baidu.com)
 * @date 2011/11/27 16:49:01
 * @version $Revision$
 * @brief
 *
 **/
// stub module to test header files' C++ compatibilty

extern "C" {
  #include <ngx_config.h>
  #include <ngx_core.h>
  #include <ngx_event.h>
  #include <ngx_event_connect.h>
  #include <ngx_event_pipe.h>

  #include <ngx_http.h>
}
#include "dis.h"
#include "frame.h"
#include "frame_util.h"
#include "policy.h"
#include "policyframe.h"
#include "region.h"

// nginx header files should go before other, because they define 64-bit off_t
// #include <string>
static ngx_flag_t g_policy_frame = 0;	/*	is policy valid, default 0ff*/
typedef struct {
	ngx_flag_t  enable;		/* 	open policy or not , default on */
	ngx_str_t	path;		/*	policy frame config path, default ./ */
	ngx_str_t	dtdname;	/*	policy frame config dtd file name, default policy.dtd*/
	ngx_str_t	docname;	/*	policy frame config doc file name, default policy.xml*/
	ngx_str_t	logpath;	/*	policy frame log path, default ./logs*/
	ngx_str_t	logfile;	/*	policy frame log filename, default policylog */
	ngx_int_t	logsize;	/*	policy frame log size, default 1600*/
	ngx_int_t	loglevel;	/*	policy frame log level, default 16*/
}ngx_http_policy_frame_main_conf_t;

static ngx_command_t ngx_http_policy_frame_commands[] = {
		{
				ngx_string("policy_frame"),
				NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
				ngx_conf_set_flag_slot,
				NGX_HTTP_MAIN_CONF_OFFSET,
				offsetof(ngx_http_policy_frame_main_conf_t, enable),
				NULL
		},
		{
				ngx_string("policy_path"),
				NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
				ngx_conf_set_str_slot,
				NGX_HTTP_MAIN_CONF_OFFSET,
				offsetof(ngx_http_policy_frame_main_conf_t, path),
				NULL
		},
		{
				ngx_string("policy_dtdname"),
				NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
				ngx_conf_set_str_slot,
				NGX_HTTP_MAIN_CONF_OFFSET,
				offsetof(ngx_http_policy_frame_main_conf_t, dtdname),
				NULL
		},
		{
				ngx_string("policy_docname"),
				NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
				ngx_conf_set_str_slot,
				NGX_HTTP_MAIN_CONF_OFFSET,
				offsetof(ngx_http_policy_frame_main_conf_t, docname),
				NULL
		},
		{
				ngx_string("policy_logpath"),
				NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
				ngx_conf_set_str_slot,
				NGX_HTTP_MAIN_CONF_OFFSET,
				offsetof(ngx_http_policy_frame_main_conf_t, logpath),
				NULL
		},
		{
				ngx_string("policy_logfile"),
				NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
				ngx_conf_set_str_slot,
				NGX_HTTP_MAIN_CONF_OFFSET,
				offsetof(ngx_http_policy_frame_main_conf_t, logfile),
				NULL
		},
		{
				ngx_string("policy_logsize"),
				NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
				ngx_conf_set_num_slot,
				NGX_HTTP_MAIN_CONF_OFFSET,
				offsetof(ngx_http_policy_frame_main_conf_t, logsize),
				NULL
		},
		{
				ngx_string("policy_loglevel"),
				NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
				ngx_conf_set_num_slot,
				NGX_HTTP_MAIN_CONF_OFFSET,
				offsetof(ngx_http_policy_frame_main_conf_t, loglevel),
				NULL
		},
	ngx_null_command
};
static void *ngx_http_policy_frame_create_conf(ngx_conf_t *cf);
static char *ngx_http_policy_frame_init_conf(ngx_conf_t *cf, void *conf);

static ngx_int_t ngx_http_policy_frame_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_policy_frame_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_policy_frame_handler(ngx_http_request_t *r);
static ngx_http_module_t  ngx_http_policy_frame_module_ctx = {
	NULL,         							/* preconfiguration */
	ngx_http_policy_frame_init,             /* postconfiguration */

	ngx_http_policy_frame_create_conf,      /* create main configuration */
	ngx_http_policy_frame_init_conf,       /* init main configuration */

	NULL,                                  	/* create server configuration */
	NULL,                                  	/* merge server configuration */

	NULL,           						/* create location configration */
	NULL             						/* merge location configration */
};
ngx_module_t  ngx_http_policy_frame_module = {
	NGX_MODULE_V1,
	&ngx_http_policy_frame_module_ctx,    /* module context */
	ngx_http_policy_frame_commands,              /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	ngx_http_policy_frame_init_worker,           /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};
static void *ngx_http_policy_frame_create_conf(ngx_conf_t *cf)
{
	ngx_http_policy_frame_main_conf_t *conf;
	conf = (ngx_http_policy_frame_main_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_policy_frame_main_conf_t));
	if (conf == NULL) {
		return NULL;
	}
	conf->enable = NGX_CONF_UNSET;
	conf->logsize = NGX_CONF_UNSET;
	conf->loglevel = NGX_CONF_UNSET;
	return conf;
}
static char *ngx_http_policy_frame_init_conf(ngx_conf_t *cf, void *conf)
{
	ngx_http_policy_frame_main_conf_t *pconf = (ngx_http_policy_frame_main_conf_t *)conf;
	ngx_conf_init_value(pconf->enable, 1);
	ngx_conf_init_value(pconf->loglevel, 16);
	ngx_conf_init_value(pconf->logsize, 1600);
	if (pconf->path.data == NULL) {
		pconf->path.data = (u_char *)"./";
		pconf->path.len = sizeof("./") - 1;
	}
	if (pconf->docname.data == NULL) {
		pconf->docname.data = (u_char *)"policy.xml";
		pconf->docname.len = sizeof("policy.xml") - 1;
	}
	if (pconf->dtdname.data == NULL) {
		pconf->dtdname.data = (u_char *)"policy.dtd";
		pconf->dtdname.len = sizeof("policy.dtd") - 1;
	}
	if (pconf->logpath.data == NULL) {
		pconf->logpath.data = (u_char *)"./logs";
		pconf->logpath.len = sizeof("./logs") - 1;
	}
	if (pconf->logfile.data == NULL) {
		pconf->logfile.data = (u_char *)"policylog";
		pconf->logfile.len = sizeof("policylog") - 1;
	}
	return NGX_CONF_OK;
}
static ngx_int_t ngx_http_policy_frame_init_log(ngx_http_policy_frame_main_conf_t *conf)
{
	if (NULL == conf) {
		return NGX_ERROR;
	}
	ul_logstat_t log_stat;
	log_stat.events = conf->loglevel;
	log_stat.spec = 0;
	log_stat.to_syslog = 0;
	if(ul_openlog((const char *)conf->logpath.data, (const char *)conf->logfile.data, 
				&log_stat, conf->logsize) < 0)
	{
		ul_closelog(0);
		if(ul_openlog((const char *)conf->logpath.data, (const char *)conf->logfile.data,
                                &log_stat, conf->logsize) < 0)
		{
			return NGX_ERROR;
		}
	}
	return NGX_OK;
}
static ngx_int_t ngx_http_policy_frame_init_worker(ngx_cycle_t *cycle)
{
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
			"ngx_http_policy_frame_init_worker begin");

	ngx_http_policy_frame_main_conf_t *conf = (ngx_http_policy_frame_main_conf_t *)
			ngx_http_cycle_get_module_main_conf(cycle, ngx_http_policy_frame_module);
	if (conf == NULL) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
				"init worker, ngx_http_policy_frame_conf_t is NULL");
		return NGX_ERROR;
	}
	if (! conf->enable) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
				"nginx policy frameis is off");
		return NGX_OK;
	}
	if (NGX_OK != ngx_http_policy_frame_init_log(conf)) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_http_policy_frame_init_log error");
		return NGX_ERROR;
	}
	void *(*old_pcre_malloc)(size_t);
	void (*old_pcre_free)(void *);
	old_pcre_malloc = pcre_malloc;
	old_pcre_free = pcre_free;
	pcre_malloc = malloc;
	pcre_free = free;
	int ret = load_policyframe_conf((const char *)conf->path.data, (const char *)conf->dtdname.data,
			(const char *)conf->docname.data);
	pcre_malloc = old_pcre_malloc;
	pcre_free = old_pcre_free;
	if (ret) {
		ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "load_policyframe_conf error [%s][%s][%s]",
				conf->path.data, conf->dtdname.data, conf->docname.data);
		return NGX_OK;// continue work
	}
	g_policy_frame = 1;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
			"ngx_http_policy_frame_init_worker end ret[%d]", ret);
	return NGX_OK;
}

static ngx_int_t ngx_http_policy_frame_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = (ngx_http_core_main_conf_t *)ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = (ngx_http_handler_pt *)ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_policy_frame_handler;

    return NGX_OK;
}
static ngx_int_t ngx_http_policy_frame_set_stat(ngx_http_request_t *r, stat_t *conn) 
{
	int uri_len = 0;
	struct sockaddr_in          *sin = NULL;

	if (NULL == r || NULL == conn) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"ngx_http_policy_frame_set_stat input invalid!");
		return NGX_ERROR;
	}
	conn->client_addr.s_addr = 0;
	conn->uri = NULL;
	conn->refer = NULL;
	conn->user_agent = NULL;
	conn->host = NULL;
	conn->accept_encoding = NULL;
	conn->cookie = NULL;
	conn->rtcode = 0;

	sin = (struct sockaddr_in *) r->connection->sockaddr;
	conn->client_addr = sin->sin_addr;

	uri_len = r->uri_end - r->uri_start;
	//uri_len = r->uri.len;
	if (uri_len > 0) {
		u_char *uri = (u_char *)ngx_pnalloc(r->pool, uri_len + 1);
		if (NULL == uri) {
			return NGX_ERROR;
		}
		ngx_copy(uri, r->uri_start, uri_len);
		//ngx_copy(uri, r->uri.data, uri_len);
		conn->uri = (char *)uri;
		conn->uri[uri_len] = '\0';
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "policy frame URI[%s]", conn->uri);
	}

	if (r->headers_in.referer != NULL && r->headers_in.referer->value.len > 0) {
		u_char *refer = (u_char *)ngx_pnalloc(r->pool, r->headers_in.referer->value.len + 1);
		if (NULL == refer) {
			return NGX_ERROR;
		}
		ngx_copy(refer, r->headers_in.referer->value.data, r->headers_in.referer->value.len);
		conn->refer = (char *)refer;
		conn->refer[r->headers_in.referer->value.len] = '\0';
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "policy frame Refer[%s]", conn->refer);
	}

	if (r->headers_in.user_agent != NULL && r->headers_in.user_agent->value.len > 0) {
		u_char *user_agent = (u_char *)ngx_pnalloc(r->pool, r->headers_in.user_agent->value.len + 1);
		if (NULL == user_agent) {
			return NGX_ERROR;
		}
		ngx_copy(user_agent, r->headers_in.user_agent->value.data, 
				r->headers_in.user_agent->value.len);
		conn->user_agent = (char *)user_agent;
		conn->user_agent[r->headers_in.user_agent->value.len] = '\0';
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "policy frame User-Agent[%s]", conn->user_agent);
	}
	if (r->headers_in.host != NULL && r->headers_in.host->value.len > 0 ) {
		u_char *host = (u_char *)ngx_pnalloc(r->pool, r->headers_in.host->value.len + 1);
		if (NULL == host) {
			return NGX_ERROR;
		}
		ngx_copy(host, r->headers_in.host->value.data, r->headers_in.host->value.len);
		conn->host = (char *)host;
		conn->host[r->headers_in.host->value.len] = '\0';
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "policy frame Host[%s]", conn->host);
	}
	if (r->headers_in.accept_encoding != NULL && r->headers_in.accept_encoding->value.len > 0) {
		u_char *accept_encoding = (u_char *)ngx_pnalloc(r->pool, 
				r->headers_in.accept_encoding->value.len + 1);
		if (NULL == accept_encoding) {
			return NGX_ERROR;
		}
		ngx_copy(accept_encoding, r->headers_in.accept_encoding->value.data,
				r->headers_in.accept_encoding->value.len);
		conn->accept_encoding = (char *)accept_encoding;
		conn->accept_encoding[r->headers_in.accept_encoding->value.len] = '\0';
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "policy frame Accept-Encoding[%s]", conn->accept_encoding);
	}
	//build cookie str
	ngx_array_t *cookies = &(r->headers_in.cookies);
	if (cookies != NULL) {
		if (cookies->nelts > 0) {
			//cookies exists, gene cookie
			ssize_t            len 	= 0;
			ngx_uint_t         i 	= 0;
			ngx_table_elt_t  **h 	= (ngx_table_elt_t **)cookies->elts;			
			u_char *p 		= NULL;
			ngx_uint_t 	   n	= cookies->nelts;

			len = - (ssize_t) (sizeof("; ") - 1);
			for (i = 0; i < n; i++) {
				len += h[i]->value.len + sizeof("; ") - 1;
			}
			p = (u_char *)ngx_pnalloc(r->pool, len + 1);
			conn->cookie = (char *)p;
			if (NULL == p) {
				return NGX_ERROR;
			}
			for (i = 0; /* void */ ; i++) {
				p = ngx_copy(p, h[i]->value.data, h[i]->value.len);
				if (i == n - 1) {
					break;
				}
				*p++ = ';'; *p++ = ' ';
			}
			conn->cookie[len] = '\0';
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "policy frame Cookie[%s]", conn->cookie);
		}
	}
	return NGX_OK;
}
static ngx_int_t ngx_http_policy_frame_handler(ngx_http_request_t *r)
{
	ngx_http_policy_frame_main_conf_t	*conf = NULL;
	int ret = 0;
	/**
	 * can not NULL
	 */
	conf = (ngx_http_policy_frame_main_conf_t *)ngx_http_get_module_main_conf(r, ngx_http_policy_frame_module);
	if (conf->enable && g_policy_frame && r->connection->sockaddr->sa_family == AF_INET) {
		/*quest_t conn;
		conn.in_buffer = (char *)r->header_in->start;
		conn.length = r->header_in->last - r->header_in->start;
		sin = (struct sockaddr_in *) r->connection->sockaddr;
		conn.client_addr =  sin->sin_addr;*/
		stat_t conn;
		ret = ngx_http_policy_frame_set_stat(r, &conn);
		if (ret != NGX_OK) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"ngx_http_policy_frame_set_stat error, ret[%d]", ret);
			return NGX_DECLINED;
		}
		int returncode = processPolicy(&conn, 1);
		if (returncode >= 1 && returncode < 512) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"connection is denied by policyframe[return code:%d]", returncode);
			return NGX_HTTP_FORBIDDEN;
		} else if (returncode >= 512 && returncode < 2048) {
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					"policyframe return code[%d]", returncode);
			return NGX_DECLINED;
		}
	}
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "policy frame off");
	return NGX_DECLINED;
}

