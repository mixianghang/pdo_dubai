#!/bin/bash

source conf.sh

all_modules=
all_module_tar_files=
all_nginx_modules=
all_nginx_without_modules=
line=0;

function is_section(){
    errcode=2;
    if [[ "$1" == \[* ]]
    then
	if [[ "$1" != *\] ]]
	then
		errcode=0;
	else 
		errcode=1;
	fi
    elif [[ "$module_info" == *\] ]]
    then
	errcode=0;
    fi
    return $errcode;
}

function process_modules(){
    module_info="$1";
    module_name=${module_info%%:*};
    module_type=${module_info##*:};

    module_name_len=${#module_name};
    module_type_len=${#module_type};

    if [ $module_type_len -eq 0 ];then
	return 0;
    fi
    if [ $module_name_len -eq 0 ] ; then
	return 0;
    fi
    if [ "$module_type" != "c" ] and [ "$module_type" != "c++" ] 
    then
	return 0;
    fi
    all_modules_temp="${all_modules/$module_info}";
    all_modules=$all_modules_temp" "$module_info;	
    return 1;

}

function process_compress_file(){
    compress=$1;
    len=${#compress};

    if [ $len -eq 0 ];then
	return 0;
    fi
    #echo $compress;
    ext=${compress##*.};
    is_tar_file=0;
    #echo $ext;
    if [ "$ext" == "tar" ]
    then
	is_tar_file=1;
    elif [ "$ext" == "gz" ]
    then
	is_tar_file=1;
    fi

    if [ $is_tar_file -eq 0 ] 
    then
	return 0;
    fi
    #echo $compress; 
    all_module_tar_temp="${all_module_tar_files/$compress}";
    all_module_tar_files=$all_module_tar_temp" "$compress;	
    return 1;
}

function process_nginx_modules(){
    module=$1;
    module=${module%% *};
    len=${#module};

    if [ $len -eq 0 ];then
	return 0;
    fi
    all_nginx_module_temp="${all_nginx_module/$module}";
    all_nginx_module=$all_nginx_module" "$module;	
    echo $module;
    echo $all_nginx_module;
    return 1;
}

function process_nginx_without_modules(){
    module=$1;
    module=${module%% *};
    len=${#module};

    if [ $len -eq 0 ];then
	return 0;
    fi
    all_nginx_without_module_temp="${all_nginx_without_module/$module}";
    all_nginx_without_module=$all_nginx_without_module" "$module;	

    echo $module;
    echo $all_nginx_without_module;
    return 1;
}

function load_conf(){
file=$1;
in_modules=0
in_compress=0
#1-->baidu_modules
#2-->nginx_modules
#3-->nginx_without_modules
#4-->compress
in_section=0
while read LINE
do
    line=$((line+1));
    len=${#LINE};
    if [ $len -eq 0 ] 
    then
        continue;
    fi;
    if [[ "$LINE" == \#* ]]
    then
        continue;
    fi
    module_info=${LINE%%\#*};
    len=${#module_info};
    if [ $len -eq 0 ] 
    then
        continue;
    fi
    is_section "$module_info"; 
    ret=$? 
    if [ $ret -eq 0 ] 
    then
        echo "Error:line $line is invalid section";
	return -1;
    fi
    if [ $ret -eq 2 ]  #文本
    then
	if [ $in_section -eq 1 ] 
	then
	   process_modules $module_info;
	   ret=$?;
	   if [ $ret -eq 0 ];then
		echo "Error:line $line is invalid module info;example(modulename:type)";
		return -2;
	   fi
	
	fi

	if [ $in_section -eq 2 ] 
	then
	   process_nginx_modules $module_info;
	   ret=$?;
	   if [ $ret -eq 0 ];then
		echo "Error:line $line is invalid module info;example(modulename:type)";
		return -2;
	   fi
	
	fi

	if [ $in_section -eq 3 ] 
	then
	   process_nginx_without_modules $module_info;
	   ret=$?;
	   if [ $ret -eq 0 ];then
		echo "Error:line $line is invalid module info;example(modulename:type)";
		return -2;
	   fi
	
	fi


	if [ $in_section -eq 4 ] 
	then
	   process_compress_file $module_info;
	   ret=$?;
	   if [ $ret -eq 0 ];then
		echo "Error:line $line, $module_info is invalid compress file";
		return -2;
	   fi
	fi;
    else
	section=${module_info#[};
        section=${section%]};
	section=${section## };
	section=${section%% };
	if [ $section == "baidu_modules" ] 
	then
		in_section=1;
	elif [ $section == "unzip" ] 
	then
		in_section=4;
	elif [ $section == "nginx_modules" ] 
	then
		in_section=2;
		
	elif [ $section == "nginx_without_modules" ] 
	then
		in_section=3;
	else
		in_section=0;
	fi	
    fi
	
   done <$file; 
   return 1;
}
load_conf "$MODULE_CONF_FILE";
if [ $? -ne 1 ] 
then
    echo "load conf failed";
    exit 0;
fi
echo "nginx without modules "$all_nginx_without_module;
echo "nginx modules "$all_nginx_module;
echo "all tar file "$all_module_tar_files;
echo "all baidu modules "$all_modules;
#解压自定义模块
cd $ROOT_PATH;
echo "开始解压自定义模块";
all_module_tar_temp=$all_module_tar_files;
for i in $all_module_tar_files
do
	cd $ROOT_PATH;
	echo $i;
        ext=${i##*.};
	echo $ext;
	if [ $ext == "gz" ] || [ $ext == "tar" ]
	then 
	    origin_dir=${i%%.*};
	    rm -rf $origin_dir;
	    module_dir=${i%/*};
	    echo "$module_dir";
	    fullname=$ROOT_PATH"/"$i;	
	    cd $module_dir;
	    tar xzvf $fullname;

	    continue;
	fi;
	echo "Error :file $i is not right compress file";
	exit -1;
done
#exit 0;
cd $SRC_ROOT_PATH"/"$NGINX_SOURCE;
#组织编译参数
compile_args=
#组织nginx官方模块
for  i in $all_nginx_module
do
	compile_args=$compile_args"--with-"$i"   ";
done;
#组织nginx官方模块
for  i in $all_nginx_without_module
do
	compile_args=$compile_args"--without-"$i"   ";
done;
#组织自定义模块
for  i in $all_modules
do
	module_name=${i%%:*};
	module_type=${i##*:};
	if [ $module_type == "c++" ] 
	then
		compile_args=$compile_args$CPP_LD_FLAG"  ";
	fi
	compile_args=$compile_args"--add-module="$MODULE_ROOT_PATH"/"$module_name"   ";
done;

echo $compile_args;
#exit 0;
make clean
./configure \
    --prefix="$ODP_ROOT/webserver"  \
    --with-pcre=$SRC_ROOT_PATH"/$PCRE_SOURCE" \
    --http-log-path=$http_log_path \
    --error-log-path=$error_log_path \
    --http-client-body-temp-path=$client_body_temp_path \
    --http-proxy-temp-path=$proxy_temp_path \
    --http-fastcgi-temp-path=$fastcgi_temp_path \
    --http-uwsgi-temp-path=$uwsgi_temp_path \
    --http-scgi-temp-path=$scgi_temp_path \
    --pid-path=$pid_path \
	--with-cc-opt="-Wno-error" \
    $compile_args

make 
make install

echo "make done!";
cd $SRC_ROOT_PATH"/../"
rm -rf $INSTALL_PATH"/cache/"
mkdir -p $INSTALL_PATH"/cache/"

cd $NGINX_CONF_PATH;
cp -r ./* $INSTALL_PATH"/conf/"

if [ $COPY_CONF_ON_INSTALL -eq 1 ]
then
	#echo $NGINX_CONF_PATH"/*";
	
	cd $NGINX_PUBLIC_CONF_PATH
	cp -r ./* $INSTALL_PATH"/conf/"
fi

#拷贝load脚本
cp $NGINX_SCRIPT_PATH  $INSTALL_PATH/

#删除default文件
cd $INSTALL_PATH;
rm conf/*.default;
#clean
for i in $all_module_tar_files
do
	cd $ROOT_PATH;
	origin_dir=${i%.*};
	while [ ! -d $origin_dir ] 
	do
		origin_dir=${origin_dir%.*};
	done
	echo "delete:"$origin_dir;
	rm -rf $origin_dir;
done
