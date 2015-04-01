#!/bin/sh

ROOT_PATH=`pwd`
ROOT_PATH=${ROOT_PATH%/*};

#·������
INSTALL_PATH=
SRC_ROOT_PATH=$ROOT_PATH"/src"

#Դ������
NGINX_SOURCE=nginx-1.2.4
PCRE_SOURCE=pcre-8.01

#ģ������
MODULE_ROOT_PATH=$ROOT_PATH"/modules"
MODULE_CONF_FILE=$ROOT_PATH"/env/nginx_access_module.conf"

#nginx�����ļ�·��
#Ŀǰ��web_server��proxy_server�Լ�static_server
#��ר������
NGINX_CONF_PATH=$ROOT_PATH"/conf/web_server"
NGINX_PUBLIC_CONF_PATH=$ROOT_PATH"/conf/public"

#nginx�����ű�
NGINX_SCRIPT_PATH=$ROOT_PATH"/script/loadnginx.sh"

#�����������
CPP_LD_FLAG="--with-ld-opt=-lstdc++"
#�Ƿ���Ҫ�������������ļ�,1����Ҫ���� 0������Ҫ����
COPY_CONF_ON_INSTALL=1

#��־����
pid_path=
http_log_path=
error_log_path=

client_body_temp_path="${ODP_ROOT}/webserver/cache/client_body"
proxy_temp_path="${ODP_ROOT}/webserver/cache/proxy"
fastcgi_temp_path="${ODP_ROOT}/webserver/cache/fastcgi"
uwsgi_temp_path="${ODP_ROOT}/webserver/cache/uwsgi"
scgi_temp_path="${ODP_ROOT}/webserver/cache/scgi"
