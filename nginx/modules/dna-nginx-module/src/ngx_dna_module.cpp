/***************************************************************************
 *
 * Copyright (c) 2012 Baidu.com, Inc. All Rights Reserved
 * $Id$
 *
 **************************************************************************/



/**
 * @file src/ngx_http_dna_module.c
 * @author changming01(changming01@baidu.com)
 * @date 2012/07/30 16:49:01
 * @version 1.0
 * @brief
 * domain name adaption
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
#include "odict.h"
#include "dictmgr.h"
#include "adaption.h"
#include "adapt_dictentry.h"
#include "adaptor_def.h"
#include "dep/dep_conf.h"
#include "ul_ullib.h"
#include "ul_conf.h"
#include "ul_dict.h"
#include "ul_net.h"
#include "ul_dictmatch.h"
#include "ul_thr.h"
#include "ul_file.h"

#define MAX_STRING_LEN 64
#define DEFAULT_URL_ARG (u_char *)"arg_device"
#define DEFAULT_COOKIE_ARG (u_char *)"cookie_device"

// nginx header files should go before other, because they define 64-bit off_t
static Adaption_intf g_adaptor; 
static ngx_int_t g_device_index;
static ngx_int_t g_enable_adaption = 0 ;
static char  g_adaption_path[2048] = {0};


u_char g_url_adaption[MAX_STRING_LEN] = "arg_device";
u_char g_cookie_adaption[MAX_STRING_LEN] = "cookie_device";

typedef struct {
	ngx_flag_t  enable;		/* 	open domain name adaption or not , default off */
	ngx_str_t	adapt_path;		/*	domain name adaption config path, default ./ */
    ngx_str_t   dna_cookie_adaption;
    ngx_str_t   dna_url_adaption;
	ngx_str_t	log_path;	/*	domain name adaption log path, default ./logs*/
	ngx_str_t	log_file;	/*	domain name adaption log filename, default adapt_log */
	size_t  	log_size;	/*	domain name adaption log size, default 1600*/
	ngx_uint_t	log_level;	/*	domain name adaption log level, default 16*/
	ngx_str_t	url_arg;    /*  domain name adaption url argument, default device*/
	ngx_str_t	cookie_arg; /*  domain name adaption cookie argument, default device*/
}ngx_http_dna_conf_t;

//create and merge location conf 
static void *ngx_http_dna_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dna_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
//about variables
static ngx_int_t ngx_http_get_variable_device (ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_dna_add_variables(ngx_conf_t *cf);
//url or cookie args
static char *ngx_http_url_adaption(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_cookie_adaption(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
//initialize
static ngx_int_t ngx_http_dna_init_log(ngx_http_dna_conf_t *conf);
static ngx_int_t nginx_http_dna_init_header(ngx_http_request_t *r, header_info_t *headers);
static ngx_int_t ngx_http_dna_init(ngx_conf_t *cf);
//handler
static ngx_int_t ngx_http_dna_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_dna_commands[] = {
	{
		ngx_string("dna"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dna_conf_t, enable),
		NULL
	},
	{
		ngx_string("dna_adapt_path"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dna_conf_t, adapt_path),
		NULL
	},
	{
		ngx_string("dna_log_path"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dna_conf_t, log_path),
		NULL
	},
	{
		ngx_string("dna_log_file"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dna_conf_t, log_file),
		NULL
	},
	{
		ngx_string("dna_log_size"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dna_conf_t, log_size),
		NULL
	},
	{
		ngx_string("dna_log_level"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dna_conf_t, log_level),
		NULL
	},
	{
		ngx_string("dna_url_adaption"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_http_url_adaption,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dna_conf_t, url_arg),
		NULL
	},
	{
		ngx_string("dna_cookie_adaption"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_http_cookie_adaption,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_dna_conf_t, cookie_arg),
		NULL
	},
	ngx_null_command
};


static ngx_http_variable_t ngx_http_dna_vars[] = {
    {
        ngx_string("dna_device"), 
        NULL, ngx_http_get_variable_device, 0,
        NGX_HTTP_VAR_INDEXED|NGX_HTTP_VAR_CHANGEABLE, 0
    },  
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
}; 

static ngx_http_module_t  ngx_http_dna_module_ctx = {
	ngx_http_dna_add_variables,				/* preconfiguration */
	ngx_http_dna_init,                      /* postconfiguration */

	NULL,                                   /* create main configuration */
	NULL,                                   /* init main configuration */

	NULL,                                  	/* create server configuration */
	NULL,                                  	/* merge server configuration */

	ngx_http_dna_create_loc_conf, 			/* create location configration */
	ngx_http_dna_merge_loc_conf				/* merge location configration */
};
ngx_module_t  ngx_http_dna_module = {
	NGX_MODULE_V1,
	&ngx_http_dna_module_ctx,              /* module context */
	ngx_http_dna_commands,                 /* module directives */
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

static void *ngx_http_dna_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_dna_conf_t *conf;
	conf = (ngx_http_dna_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_dna_conf_t));
	if (conf == NULL) {
		return NULL;
	}
	conf->enable = NGX_CONF_UNSET;
	//conf->adapt_path = NGX_CONF_UNSET;
	//conf->log_path = NGX_CONF_UNSET;
	//conf->log_file = NGX_CONF_UNSET;
	conf->log_size = NGX_CONF_UNSET_SIZE;
	conf->log_level = NGX_CONF_UNSET_UINT;

	return conf;
}

static char * ngx_http_dna_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_dna_conf_t *prev = (ngx_http_dna_conf_t *)parent;
	ngx_http_dna_conf_t *conf = (ngx_http_dna_conf_t *)child;

	ngx_conf_merge_str_value(conf ->adapt_path, prev ->adapt_path, "./");
	ngx_conf_merge_str_value(conf ->log_path, prev ->log_path, "./logs");
	ngx_conf_merge_str_value(conf ->log_file, prev ->log_file, "dna_log");
	ngx_conf_merge_uint_value(conf ->log_level, prev ->log_level, 16);
	ngx_conf_merge_size_value(conf ->log_size, prev ->log_size, 1600);

	ngx_conf_merge_value(conf ->enable, prev ->enable, 0);

	ngx_conf_merge_str_value(conf ->dna_url_adaption, prev ->dna_url_adaption, "");
	ngx_conf_merge_str_value(conf ->dna_cookie_adaption, prev ->dna_cookie_adaption, "");

	if(conf->enable){
		g_enable_adaption = 1;
                if( conf->adapt_path.len >= sizeof(g_adaption_path)){
                    ngx_log_error(NGX_LOG_ERR, cf->log,  0, 
                        "initialize adaptor failed, adaption_path[%d] to long", 
                        conf->adapt_path.len);

                    return (char*)NGX_CONF_ERROR;
                }
                strncpy(g_adaption_path, (const char*)conf->adapt_path.data, conf->adapt_path.len);
                g_adaption_path[conf->adapt_path.len] = '\0';
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_get_variable_device (ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	if((char *)data != NULL)
	{
		v->len = ngx_strlen(data);
		v->valid = 1;
		v->not_found = 0;
		v->data = (u_char *)data;
	}
	return NGX_OK;
}

static ngx_int_t ngx_http_dna_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var = NULL, *v = NULL; 

    for(v = ngx_http_dna_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if(var == NULL) { 
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "add variable %s failed!", v->name.data);
            return NGX_ERROR;
        }       
        var->get_handler = v->get_handler;
        var->data = v->data;
		g_device_index = ngx_http_get_variable_index(cf, &v->name);
		if(g_device_index == NGX_ERROR)
		{
			ngx_log_error(NGX_LOG_ERR, cf->log, 0, "get variable %s index failed", v->name.data);
			return NGX_ERROR;
		}
    }

    return NGX_OK; 
}

static char *ngx_http_url_adaption(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dna_conf_t *dcf;  
    ngx_str_t *value; 

    dcf = (ngx_http_dna_conf_t *)ngx_http_conf_get_module_loc_conf(cf, ngx_http_dna_module);

    if(cf->args->nelts < 2){
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                   "get url adaption name failed, default device");
		ngx_memcpy(g_url_adaption, DEFAULT_URL_ARG, ngx_strlen(DEFAULT_URL_ARG));
    }
    
    value = (ngx_str_t *)cf->args->elts;
    if(value[1].len > MAX_STRING_LEN - 1){
		ngx_log_error(NGX_LOG_WARN, cf->log, 0, "too long url name!");
		ngx_memcpy(g_url_adaption, DEFAULT_URL_ARG, ngx_strlen(DEFAULT_URL_ARG));
        return NGX_CONF_OK;
    }

	ngx_snprintf(g_url_adaption, MAX_STRING_LEN, "arg_%s", value[1].data);

    return NGX_CONF_OK;
}

static char *ngx_http_cookie_adaption(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dna_conf_t *dcf;  
    ngx_str_t *value; 

    dcf = (ngx_http_dna_conf_t *)ngx_http_conf_get_module_loc_conf(cf, ngx_http_dna_module);

    if(cf->args->nelts < 2){
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                   "get cookie adaption name failed, default device");
		ngx_memcpy(g_cookie_adaption, DEFAULT_COOKIE_ARG, ngx_strlen(DEFAULT_COOKIE_ARG));
        return NGX_CONF_OK;
    }
    
    value = (ngx_str_t *)cf->args->elts;
    if(value[1].len > MAX_STRING_LEN - 1){
		ngx_memcpy(g_cookie_adaption, DEFAULT_COOKIE_ARG, ngx_strlen(DEFAULT_COOKIE_ARG));
		ngx_log_error(NGX_LOG_WARN, cf->log, 0, "too long cookie name!");
        return NGX_CONF_OK;
    }
	ngx_snprintf(g_cookie_adaption, MAX_STRING_LEN, "cookie_%s", value[1].data);

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_dna_init_log(ngx_http_dna_conf_t *conf)
{
    if (NULL == conf) { 
        return NGX_ERROR;
    }

    if ( conf -> log_level == 0 || conf -> log_level == NGX_CONF_UNSET_UINT){
        conf -> log_level = 4;
    }

    if ( conf -> log_path.len == 0){
        conf -> log_path.data = (u_char*)"./logs";
        conf -> log_path.len = sizeof("./logs") - 1;
    }
 
    if( conf -> log_file.len == 0){
        conf -> log_file.data = (u_char*)"dna_log";
        conf -> log_file.len = sizeof("dna_log") - 1;
    }

    if ( conf -> log_size == 0){
        conf -> log_size = 1600;
    }

    ul_logstat_t log_stat;
    log_stat.events = conf->log_level;
    log_stat.spec = 0;
    log_stat.to_syslog = 0;
    if(ul_openlog((const char *)conf->log_path.data, (const char *)conf->log_file.data, 
                &log_stat, conf->log_size) < 0)
    {
		ul_closelog(0);
		if(ul_openlog((const char *)conf->log_path.data, (const char *)conf->log_file.data, 
                &log_stat, conf->log_size) < 0)
		{
			return NGX_ERROR;
		}
    }
    return NGX_OK; 
}

static ngx_int_t ngx_http_dna_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
	ngx_http_dna_conf_t *dcf = NULL;

	dcf = (ngx_http_dna_conf_t *) ngx_http_conf_get_module_loc_conf(cf, ngx_http_dna_module);
	if(dcf == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, "get cycle conf failed!");
		return NGX_ERROR;
	}
	int ret =  ngx_http_dna_init_log(dcf); 
	if(ret != NGX_OK){
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, "init log failed!");
		return ret;
	}

    if(g_enable_adaption){
        int ret = g_adaptor.init(g_adaption_path);
        if( ret != Adaption_intf::SUCCESS){
            ngx_log_error(NGX_LOG_NOTICE, cf->log,  0, "initialize adaptor failed, ret %d", ret);
            return NGX_ERROR;
        }
    }

    cmcf = (ngx_http_core_main_conf_t *)ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = (ngx_http_handler_pt *)ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_dna_handler;

	return NGX_OK;
}

static ngx_int_t ngx_http_dna_handler(ngx_http_request_t *r)
{

    ngx_http_dna_conf_t *dna_conf = NULL;
    dna_conf = (ngx_http_dna_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_dna_module);
	if(!dna_conf || !dna_conf ->enable)
	{
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "domain name adaption module is off");
		return NGX_DECLINED;
	}
	if(r->headers_in.headers.part.nelts == 0)
	{
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "headers_in is null");
		return NGX_DECLINED;
	}
	
	header_info_t headers;
	ngx_memzero(&headers, sizeof(header_info_t));
	ngx_int_t init_ret = 0;
	ngx_http_variable_value_t *user_assign = NULL; 
    ngx_int_t is_mobile = 0;
    ngx_int_t is_pad = 0;
	u_char * device = NULL;
	u_char * ip = r->connection->addr_text.data;
	ngx_str_t url_adaption = ngx_string(g_url_adaption);
	ngx_str_t cookie_adaption = ngx_string(g_cookie_adaption);
	url_adaption.len = (char *)g_url_adaption != NULL ? ngx_strlen((char *)g_url_adaption) : 0;
	cookie_adaption.len = (char *)g_cookie_adaption != NULL ? ngx_strlen((char *)g_cookie_adaption) : 0;

	device = (u_char *) ngx_pcalloc(r->connection->pool, MAX_STRING_LEN);
	if(device == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "alloc failed");
		return NGX_DECLINED;
	}
	ngx_snprintf(device, MAX_STRING_LEN, "pc");
	init_ret = nginx_http_dna_init_header(r, &headers);
	if(init_ret != NGX_OK)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get http headers failed");
		return NGX_DECLINED;
	}
	if(ip == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get ip failed");
		return NGX_DECLINED;
	}

	user_assign = ngx_http_get_variable(r, &url_adaption, 0);
	if(user_assign ->not_found)
	{
		user_assign = ngx_http_get_variable(r, &cookie_adaption, 0);
	}
	if(user_assign ->not_found)
	{
		is_mobile = g_adaptor.is_mobile_device(&headers, (char *)ip);
	}
	if(user_assign ->not_found == 0 && user_assign ->len > 0 && user_assign->data != NULL)
	{
		ngx_snprintf(device, user_assign->len, "%s", user_assign->data);
		device[user_assign->len] = '\0';
	}
	else if(is_mobile == 1)
	{
		ngx_snprintf(device, MAX_STRING_LEN, "mobile");
	}
	else
	{
		is_pad = g_adaptor.is_pad_device(&headers);
		if(is_pad == 1)
		{
			ngx_snprintf(device, MAX_STRING_LEN, "pad");
		}
	}
	if(device != NULL)
	{
		r->variables[g_device_index].len = ngx_strlen(device);
		r->variables[g_device_index].valid = 1;
		r->variables[g_device_index].no_cacheable = 0;
		r->variables[g_device_index].not_found = 0;
		r->variables[g_device_index].data = device;
	}

	return NGX_DECLINED;
}

static ngx_int_t nginx_http_dna_init_header(ngx_http_request_t *r, header_info_t *headers)
{
	ngx_int_t j = 0;
	ngx_uint_t i = 0;
	ngx_list_part_t *part;
    ngx_table_elt_t *header;

	part = &r->headers_in.headers.part;
    header = (ngx_table_elt_t *)part->elts;
    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = (ngx_table_elt_t *)part->elts;
            i = 0;
        }	
        if(j >= MAX_ITEM_NUM){
            break;
        }
		if(header[i].key.len == 0 || header[i].value.len == 0){
			continue;
		}
		char* name = (char *) ngx_pcalloc(r->connection->pool, header[i].key.len + 1);
		if(name == NULL){
			break;
		}
	//	snprintf(name, header[i].key.len + 1, "%s", (char *)header[i].key.data);
		int real_index =  0;	
		while( header[i].key.data[real_index] == ' ' || 
		       header[i].key.data[real_index] == '\n'|| 
                       header[i].key.data[real_index] == '\r'){
			real_index ++;
			if(real_index >= header[i].key.len){
				break;
			}
		}

		if(real_index >= header[i].key.len){
			continue;
		}
		int name_index = 0;
		for(int index = real_index; index < header[i].key.len; index++){
			name[name_index++] = header[i].key.data[index];
		}

		//strncpy(name, (char *)header[i].key.data, header[i].key.len);
		name[name_index] = '\0';


	    char* value = (char *) ngx_pcalloc(r->connection->pool, header[i].value.len + 1);
		if(value == NULL){
			break;
		}
		real_index = 0;
		while( header[i].value.data[real_index] == ' ' || 
		       header[i].value.data[real_index] == '\n'|| 
                       header[i].value.data[real_index] == '\r'){
			real_index ++;
			if(real_index >= header[i].value.len){
				break;
			}
		}
		if(real_index >= header[i].value.len){
			continue;
		}
		int value_index = 0;
		for(int index = real_index; index < header[i].value.len; index++){
			value[value_index++] = header[i].value.data[index];
		}

		//strncpy(name, (char *)header[i].key.data, header[i].key.len);
		value[value_index] = '\0';



		//snprintf(value, header[i].value.len + 1, "%s", (char *)header[i].value.data);
		//strncpy(value, (char *)header[i].value.data, header[i].value.len);
		//value[header[i].value.len] = '\0';
	

		headers->request_item_arr[j].item_name = name;
		headers->request_item_arr[j].item_value = value;
		j++;
    }
	headers->info_count = j;
	return NGX_OK;
}

