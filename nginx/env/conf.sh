#!/bin/sh

ROOT_PATH=`pwd`
ROOT_PATH=${ROOT_PATH%/*};

#路径配置
INSTALL_PATH=
SRC_ROOT_PATH=$ROOT_PATH"/src"

#源码配置
NGINX_SOURCE=nginx-1.2.4
PCRE_SOURCE=pcre-8.01

#模块配置
MODULE_ROOT_PATH=$ROOT_PATH"/modules"
MODULE_CONF_FILE=$ROOT_PATH"/env/nginx_access_module.conf"

#nginx配置文件路径
#目前有web_server、proxy_server以及static_server
#等专用配置
NGINX_CONF_PATH=$ROOT_PATH"/conf/web_server"
NGINX_PUBLIC_CONF_PATH=$ROOT_PATH"/conf/public"

#nginx启动脚本
NGINX_SCRIPT_PATH=$ROOT_PATH"/script/loadnginx.sh"

#编译参数配置
CPP_LD_FLAG="--with-ld-opt=-lstdc++"
#是否需要拷贝公共配置文件,1：需要拷贝 0：不需要拷贝
COPY_CONF_ON_INSTALL=1

#日志配置
pid_path=
http_log_path=
error_log_path=

client_body_temp_path="${ODP_ROOT}/webserver/cache/client_body"
proxy_temp_path="${ODP_ROOT}/webserver/cache/proxy"
fastcgi_temp_path="${ODP_ROOT}/webserver/cache/fastcgi"
uwsgi_temp_path="${ODP_ROOT}/webserver/cache/uwsgi"
scgi_temp_path="${ODP_ROOT}/webserver/cache/scgi"
