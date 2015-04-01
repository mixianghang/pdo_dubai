#!/bin/bash

#nginx安装目录
NGINXHOME=${WS_HOME}
#nginx名成
NGINX=$NGINXHOME/sbin/nginx

LOGHOME=${ODP_ROOT}/log/webserver

ODP_ROOT=${ODP_ROOT}
nginx_log="access_log error_log"

#logs

/etc/rc.d/init.d/functions

RETVAL=0

start() {
    echo -n $"Starting nginx: "
    
    if [ ! -d "$ODP_ROOT/log/webserver" ]
    then
        mkdir "$ODP_ROOT/log/webserver"
    fi

    for i in $nginx_log
    do
        if [ ! -f "$ODP_ROOT/log/webserver/$i" ] ; then
            touch "$ODP_ROOT/log/webserver/$i"
        fi
        if [ ! -h "$ODP_ROOT/log/$i" ] ; then
            ln -s "$ODP_ROOT/log/webserver/$i" "$ODP_ROOT/log/$i"
        fi
    done
    
    nohup limit -n 65535 $NGINX >/dev/null 2>&1 &

    RETVAL=$?
    if [ $RETVAL -eq 0 ]
    then
        echo "OK"
    else
        echo "Failed!"
    fi
    return $RETVAL
}

stop() {
    echo -n $"Stopping nginx: "
    
    $NGINX -s stop
    echo  $"Stop OK,please check it youself ";
    #return $RETVAL
}

restart() {
    stop
    sleep 2
    start
}


case "$1" in
start)
    start
    ;;

stop)
    stop
    ;;

restart)
    restart
    ;;

reload)
    $NGINX -s reload
    echo  $"reload OK,please check it youself";
    ;;

chkconfig)
    $NGINX -t
    ;;

*)
echo "Usage: $0 {start|stop|restart|chkconfg|reload}"
echo $NGINX
exit 1
esac
