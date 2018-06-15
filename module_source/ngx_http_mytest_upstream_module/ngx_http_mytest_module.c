#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

extern ngx_module_t  ngx_http_mytest_module;
static ngx_str_t  ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};

static char* ngx_conf_set_myconfig(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *conf);
static ngx_int_t mytest_upstream_create_request(ngx_http_request_t *r);
static ngx_int_t mytest_upstream_status_line(ngx_http_request_t *r);
static ngx_int_t mytest_upstream_process_header(ngx_http_request_t *r);
static void mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

//自定义配置项，用于自定义解析配置项
typedef struct
{
        ngx_str_t config_str;
        ngx_int_t   config_num;
}ngx_http_config_conf_t;

//存储loc级别配置项的结构体
typedef struct
{
    ngx_str_t   my_str;
    ngx_int_t my_num;
    ngx_flag_t my_flag;
    size_t my_size;
    ngx_array_t* my_str_array;
    ngx_array_t* my_keyval;
    off_t my_off;
    ngx_msec_t my_msec;
    time_t my_sec;
    ngx_bufs_t  my_bufs;
    ngx_uint_t  my_enum_seq;
    ngx_uint_t  my_bitmask;
    ngx_uint_t  my_access;
    ngx_path_t  my_path;
    ngx_http_config_conf_t my_config;
    ngx_http_upstream_conf_t upstream;
}ngx_http_mytest_conf_t;

//mytest模块上下文
typedef struct
{
    ngx_http_status_t status;
    ngx_str_t backendServer;
}ngx_http_mytest_ctx_t;

static ngx_conf_enum_t  test_enums[] = {
        {ngx_string("apple"), 1},
        {ngx_string("banana"), 2},
        {ngx_string("orange"), 3},
        {ngx_null_string, 0}
};

static ngx_conf_bitmask_t test_bitmasks[] = {
        {ngx_string("good"), 0x0002},
        {ngx_string("better"), 0x0004},
        {ngx_string("best"), 0x0008},
        {ngx_null_string, 0}
};

//创建结构体用于存储loc级别配置项
static void*  ngx_http_mytest_create_loc_conf(ngx_conf_t    *cf)
{
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "创建结构体用于存储loc级别配置项\n");
        ngx_http_mytest_conf_t   *mycf;
        mycf = (ngx_http_mytest_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_mytest_conf_t ));
        if(NULL == mycf)
        {
            ngx_log_error(NGX_LOG_ERR,cf->log, 0, "____weijl line=%d____\n", __LINE__);
            return NULL;
        }

        mycf->my_flag = NGX_CONF_UNSET;
        mycf->my_num = NGX_CONF_UNSET;
        mycf->my_str_array = NGX_CONF_UNSET_PTR;
        mycf->my_keyval = NULL;
        mycf->my_off = NGX_CONF_UNSET;
        mycf->my_msec = NGX_CONF_UNSET_MSEC;
        mycf->my_sec = NGX_CONF_UNSET;
        mycf->my_size = NGX_CONF_UNSET_SIZE;
        mycf->my_config.config_num = NGX_CONF_UNSET;
        mycf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
        mycf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
        mycf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
        mycf->upstream.buffering = NGX_CONF_UNSET;
        mycf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
        mycf->upstream.busy_buffers_size = NGX_CONF_UNSET_SIZE;
        mycf->upstream.temp_file_write_size = NGX_CONF_UNSET_SIZE;
        mycf->upstream.max_temp_file_size = NGX_CONF_UNSET_SIZE;

        mycf->upstream.store_access = 600;

        mycf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
        mycf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

        //创建结构体的方法返回时，将创建的结构体传递给HTTP框架
        return mycf;
}

//请求包体接收完后回调的函数
void ngx_http_mytest_body_handler(ngx_http_request_t *r)
{

}

//HTTP的NGX_HTTP_CONTENT_PHASE阶段mytest模块介入处理http请求内容
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r)
{
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "HTTP的HTTP_CONTENT_PHASE阶段模块介入处理http请求内容\n");
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_pagesize=%d\n",ngx_pagesize);
        //首先调用ngx_http_get_module_ctx宏来获取上下文结构体
        ngx_http_mytest_ctx_t* myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
        if(NULL == myctx)
        {
            //必须在当前请求的内存池r->pool中分配上下文结构体，这样请求结束时结构体占用的内存才会释放
            myctx = ngx_pcalloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
            if(NULL == myctx)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
                return NGX_ERROR;
            }
            //将刚分配的结构体设置到当前请求的上下文中
            ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);
        }

        //必须时GET或者HEAD方法，否则返回405 Not Allowed
        if(!(r->method &(NGX_HTTP_GET | NGX_HTTP_HEAD)))
        {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "weijl NGX_HTTP_NOT_ALLOWED");
                return NGX_HTTP_NOT_ALLOWED;
        }

        //对每个要使用upstream的请求，必须调用且只能调用一次ngx_http_upstream_create方法，它会初始化r->upstream成员
        if(ngx_http_upstream_create(r) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create() failed\n");

            return NGX_ERROR;
        }

        //得打配置结构体ngx_http_mytest_conf_t
        ngx_http_mytest_conf_t* mycf = (ngx_http_mytest_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
        ngx_http_upstream_t *u = r->upstream;
        //这里用配置文件中的结构体来赋给r->upstream->conf成员
        u->conf = &mycf->upstream;
        //决定转发包体时使用的缓冲区
        u->buffering = mycf->upstream.buffering;

        //以下代码开始初始化resolved结构体，用来保存上游服务器地址
        u->resolved = (ngx_http_upstream_resolved_t*)ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
        if(NULL == u->resolved )
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_pcalloc resolved error. %s.", strerror(errno));

            return NGX_ERROR;
        }

        //这里的上游服务器就是s.taobao.com
        static struct sockaddr_in backendSockAddr;
        struct hostent *pHost = gethostbyname((char*)"s.taobao.com");
        if(NULL == pHost)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gethostbyname fail. %s.", strerror(errno));

            return NGX_ERROR;
        }

        //访问上游服务器的80端口
        backendSockAddr.sin_family = AF_INET;
        backendSockAddr.sin_port = htons((in_port_t)80);
        char * pDmsIP = inet_ntoa(*(struct in_addr*)(pHost->h_addr_list[0]));
        backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
        myctx->backendServer.data = (u_char*)pDmsIP;
        myctx->backendServer.len = strlen(pDmsIP);

        //将地址设置到resolved成员中
        u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
        u->resolved->socklen = sizeof(struct sockaddr_in);
        u->resolved->naddrs = 1;
        u->resolved->port = backendSockAddr.sin_port;

        //设置3个必须实现的回调方法
        u->create_request = mytest_upstream_create_request;
        u->process_header = mytest_upstream_status_line;
        u->finalize_request = mytest_upstream_finalize_request;

        //这里必须将count成员加1
        r->main->count++;
        //启动upstream
        ngx_http_upstream_init(r);

        //必须返回NGX_DONE
        return NGX_DONE;

        //以下注释部分为构造包体直接发送给客户端，临时注释掉
        /*
        //丢弃请求中的包体
        ngx_int_t rc = ngx_http_discard_request_body(r);
        if(rc != NGX_OK)
        {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "weijl rc=%d", rc);
                return rc;
        }

        //设置返回的Content_Type。注意，ngx_str_t有一个很方便的初始化宏ngx_string,它可以把ngx_str_t的data和len成员都设置好
        ngx_str_t type = ngx_string("text/plain");
        //设置返回状态码
        r->headers_out.status = NGX_HTTP_OK;

        //发送HTTP头部
        rc = ngx_http_send_header(r);
        if(rc == NGX_ERROR || rc > NGX_OK || r->header_only)
        {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "weijl rc=%d", rc);
                return rc;
        }

        //构造ngx_buf_t结构体准备发送包体
        ngx_buf_t *b;
        b = ngx_palloc(r->pool, sizeof(ngx_buf_t));
        if(NULL == b)
        {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "weijl b=NULL");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        u_char* filename = (u_char*)"/home/weijl/workspace/nginx-1.10.3/src/http/config";
        b->in_file = 1;
        b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
        b->file->fd = ngx_open_file(filename, NGX_FILE_RDONLY | NGX_FILE_NONBLOCK , NGX_FILE_OPEN, 0);
        b->file->log = r->connection->log;
        b->file->name.data = filename;
        b->file->name.len = strlen((const char*)filename);
        if(b->file->fd <= 0)
        {
                return NGX_HTTP_NOT_FOUND;
        }

        if(ngx_file_info(filename, &b->file->info) == NGX_FILE_ERROR)
        {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        //响应包是由包体内容的，需要设置Conten-Length长度
        r->headers_out.content_length_n = b->file->info.st_size;
        //设置Content-Type
        r->headers_out.content_type = type;

        b->file_pos = 0;
        b->file_last = b->file->info.st_size;
        //声明这是最后一块缓冲区
        b->last_buf =1;

        //构造发送时的ngx_chain_t结构体
        ngx_chain_t out;
        out.buf = b;
        //设置next为NULL
        out.next = NULL;

        //清理文件句柄
        ////在请求结束时调用cln的handler方法清理资源
        ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
        if(NULL == cln)
        {
                return NGX_ERROR;
        }
        //将Nginx提供的ngx_pool_cleanup_file函数设置为回调方法
        cln->handler = ngx_pool_cleanup_file;
        //设置回调方法的参数
        ngx_pool_cleanup_file_t *clnf = cln->data;

        clnf->fd = b->file->fd;
        clnf->name = b->file->name.data;
        clnf->log = r->pool->log;

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "weijl 构造包体完成，开始发送包体\n");

        //最后一步为发送包体，发送结束后HTTP框架会调用ngx_http_finalize_request方法结束请求
        return ngx_http_output_filter(r, &out);*/
}

//没有什么工作必须在HTTP框架初始化时完成，不必实现ngx_http_module_t的8个回调方法
static ngx_http_module_t ngx_http_mytest_module_ctx =
{
        NULL,//preconfiguration解析配置文件前调用
        NULL,//postconfiguration完成配置文件解析后调用

        NULL,//ceate_main_conf创建存储全局配置项的结构体
        NULL,//init_main_conf常用于初始化main级别的配置项

        NULL,//create_srv_conf创建存储srv级别配置项的结构体
        NULL,//merge_srv_conf主要用于合并main级别和srv级别下的同名配置项

        ngx_http_mytest_create_loc_conf,//create_loc_conf创建用于存储loc级别配置项的结构体
        ngx_http_mytest_merge_loc_conf//merge_loc_conf主要用于合并srv级别和loc级别下的同名配置项
};

//“mytest”配置项解析的回调方法
static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "mytest配置项解析的回调方法\n");
        ngx_http_core_loc_conf_t  *clcf;
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

        /*HTTP框架在处理用户请求进行到NGX_HTTP_CONTENT_PHASE阶段时，如果请求的主机域名、URI与mytest
         * 配置项所在的配置块相匹配，就将调用ngx_http_mytest_handler方法处理这个请求*/
        clcf->handler = ngx_http_mytest_handler;

        return NGX_CONF_OK;
}

//mytest配置项的处理
static ngx_command_t  ngx_http_mytest_commands[] = {
        {ngx_string("mytest"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
        ngx_http_mytest,//在出现配置项mytest时调用ngx_http_mytest解析
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL},

        {ngx_string("test_flag"),
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,//在出现配置项test_flag时调用ngx_conf_set_flag_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_flag),
        NULL},

        {ngx_string("test_str"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,//在出现配置项test_str时调用ngx_conf_set_str_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_str),
        NULL},

        {ngx_string("test_str_array"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,//在出现配置项test_str_array时调用ngx_conf_set_str_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_str_array),
        NULL},

        {ngx_string("test_keyval"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_conf_set_keyval_slot,//在出现配置项test_keyval时调用ngx_conf_set_keyval_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_keyval),
        NULL},

        {ngx_string("test_num"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,//在出现配置项test_num时调用ngx_conf_set_num_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_num),
        NULL},

        {ngx_string("test_size"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,//在出现配置项test_size时调用ngx_conf_set_size_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_size),
        NULL},

        {ngx_string("test_off"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_off_slot,//在出现配置项test_off时调用ngx_conf_set_off_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_off),
        NULL},

        {ngx_string("test_msec"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,//在出现配置项test_msec时调用ngx_conf_set_msec_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_msec),
        NULL},

        {ngx_string("test_sec"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_sec_slot,//在出现配置项test_sec时调用ngx_conf_set_sec_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_sec),
        NULL},

        {ngx_string("test_bufs"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_conf_set_bufs_slot,//在出现配置项test_bufs时调用ngx_conf_set_bufs_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_bufs),
        NULL},

        {ngx_string("test_enum"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,//在出现配置项test_enum时调用ngx_conf_set_enum_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_enum_seq),
        test_enums},

        {ngx_string("test_bitmask"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_bitmask_slot,//在出现配置项test_bitmask时调用ngx_conf_set_bitmask_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_bitmask),
        test_bitmasks},

        {ngx_string("test_access"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
        ngx_conf_set_access_slot,//在出现配置项test_access时调用ngx_conf_set_access_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_access),
        NULL},

        {ngx_string("test_path"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
        ngx_conf_set_path_slot,//在出现配置项test_path时调用ngx_conf_set_path_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_path),
        NULL},

        {ngx_string("test_myconfig"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
        ngx_conf_set_myconfig,//在出现配置项test_myconfig时调用ngx_conf_set_myconfig解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_config),
        NULL},

        {ngx_string("upstream_connect_timeout"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,//在出现配置项upstream_connect_timeout时调用ngx_conf_set_msec_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, upstream.connect_timeout),
        NULL},

        { ngx_string("upstream_send_timeout"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot, //在出现配置项upstream_send_timeout时调用ngx_conf_set_msec_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.send_timeout),
        NULL },

        { ngx_string("upstream_read_timeout"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot, //在出现配置项upstream_read_timeout时调用ngx_conf_set_msec_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.read_timeout),
        NULL },

        { ngx_string("upstream_store_access"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_access_slot,   //在出现配置项upstream_store_access时调用ngx_conf_set_access_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.store_access),
        NULL },

        { ngx_string("upstream_buffering"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot, //在出现配置项upstream_buffering时调用ngx_conf_set_num_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.buffering),
        NULL },

        { ngx_string("upstream_bufs"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        ngx_conf_set_bufs_slot, //在出现配置项upstream_buffering时调用ngx_conf_set_num_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.bufs),
        NULL },

        { ngx_string("upstream_buffer_size"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot, //在出现配置项upstream_buffer_size时调用ngx_conf_set_size_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.buffer_size),
        NULL },

        { ngx_string("upstream_busy_buffers_size"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot, //在出现配置项upstream_busy_buffers_size时调用ngx_conf_set_size_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.busy_buffers_size),
        NULL },

        { ngx_string("upstream_temp_file_write_size"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot, //在出现配置项upstream_temp_file_write_size时调用ngx_conf_set_size_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.temp_file_write_size),
        NULL },

        { ngx_string("upstream_max_temp_file_size"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot, //在出现配置项upstream_max_temp_file_size时调用ngx_conf_set_size_slot解析
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.max_temp_file_size),
        NULL },

        //更多的配置项可以在这里定义

        ngx_null_command
};

//定义mytest模块
ngx_module_t  ngx_http_mytest_module = {
    NGX_MODULE_V1,
    &ngx_http_mytest_module_ctx,             /* module context */
    ngx_http_mytest_commands,                /* module directives */
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

//自定义配置项处理方法
static char* ngx_conf_set_myconfig(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "自定义配置项处理方法\n");
        //注意，参数conf就是HTTP框架传给用户的在ngx_http_mytest_create_loc_conf回调方法中分配的结构体ngx_http_mytest_conf_t
        ngx_http_mytest_conf_t *mycf = conf;

        /*cf->args是一个ngx_array_t队列，它的成员都是ngx_str_t结构。我们用value指向ngx_array_t的elts的内容，其中value[1]
         * 就是第一个参数，同理，value[2]是第二个参数*/
        ngx_str_t* value  = cf->args->elts;

        //ngx_array_t的nelts表示参数的个数
        if(cf->args->nelts > 1)
        {
                //直接赋值即可，ngx_str_t结构只是指针的传递
                mycf->my_config.config_str = value[1];
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "weijl config_str=%V", &mycf->my_config.config_str);
        }

        if(cf->args->nelts > 2)
        {
                //将字符串形式的第二个参数转为整型
                mycf->my_config.config_num = ngx_atoi(value[2].data, value[2].len);
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "weijl config_num=%d", mycf->my_config.config_num);
                //如果字符串转为整型失败，将报"invalid number"错误，Nginx启动失败
                if(mycf->my_config.config_num == NGX_ERROR)
                {
                        return "invalid number";
                }
        }

        //返回成功
        return NGX_CONF_OK;
}

//合并配置项
static char* ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *conf)
{
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "合并配置项\n");
        ngx_http_mytest_conf_t *prev = (ngx_http_mytest_conf_t*)parent;
        ngx_http_mytest_conf_t *this = (ngx_http_mytest_conf_t*)conf;
        //ngx_conf_merge_str_value(this->my_str, prev->my_str, "dedaultstr");

        ngx_hash_init_t hash;
        hash.max_size = 100;
        hash.bucket_size = 1024;
        hash.name = "proxy_headers_hash";
        if(ngx_http_upstream_hide_headers_hash(cf, &this->upstream, &prev->upstream, ngx_http_proxy_hide_headers, &hash) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "____weijl line=%d____\n", __LINE__);
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
}

//构造发往上游服务器的请求内容
static ngx_int_t mytest_upstream_create_request(ngx_http_request_t *r)
{
    /*发往baidu上游服务器的请求很简单，就是模仿正常的搜索请求，以/search?=...的URI来发起请。*/
    static ngx_str_t backendQueryLine = ngx_string("GET /search?q=%V HTTP/1.1\r\nHost: s.taobao.com\r\nConnection: close\r\n\r\n");
    ngx_int_t queryLineLen = backendQueryLine.len + r->args.len-2;
    /*必须在内存池中申请内存，这有以下两点好处：一个好处是，在网络情况不佳的情况下，向上游服务器发送请求时，可能需要
     * epoll多次调度send才能发送完成，这时必须保证这段内存不会被释放;另一个好处是，在结束请求时，这段内存会被自动释放，
     * 降低内存泄露的可能*/
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, queryLineLen);
    if(NULL == b)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
        return NGX_ERROR;
    }
    //last要指向请求的末尾
    b->last = b->pos + queryLineLen;

    //作用相当于snprintf，只是它支持ngx中的所有转换格式
    ngx_snprintf(b->pos, queryLineLen, (char*)backendQueryLine.data, &r->args);
    /*r->upstream->request_bufs是一个ngx_chain_t结构，它包含着要发送给上游服务器的请求*/
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if(NULL == r->upstream->request_bufs)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
        return NGX_ERROR;
    }

    //request->bufs在这里只包含一个ngx_buf_t缓冲区
    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;

    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;
    //header_hash不可以为0
    r->header_hash = 1;

    return NGX_OK;
}

static ngx_int_t mytest_upstream_status_line(ngx_http_request_t *r)
{
    size_t len;
    ngx_int_t rc;
    ngx_http_upstream_t *u;

    //上下文中才会保存多次解析HTTP响应行的状态，下面首先取出请求的上下文
    ngx_http_mytest_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if(NULL == ctx)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
        return NGX_ERROR;
    }

    u = r->upstream;

    /*HTTP框架提供的ngx_http_parse_status_line方法可以解析HTTP响应行，它的输入就是收到的字符流和上下文
     * 中的ngx_http_status_t结构*/
    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
    //返回NGX_AGAIN时，表示还没有解析出完整的HTTP响应行，需要接收更多的字符流再进行解析
    if(NGX_AGAIN == rc)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
        return rc;
    }

    //返回NGX_ERROR时，表示没有接收到合法的HTTP响应行
    if(NGX_ERROR == rc)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent no valid HTTP/1.0 header");

        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;

        return NGX_OK;
    }

    /*以下表示在解析到完整的HTTP响应行时，会做一些简单的赋值操作，将解析出的信息设置到r->upstream->headers_in
     * 结构体中。当upstream解析完所有的包头时，会把headers_in中的成员设置到将要向下游发送的r->headers_out结构体
     * 中，也就是说，现在用户向headers_in中设置的信息，最终都会发往下游客户端。为什么不直接设置r->headers_out而
     * 要多此一举呢？因为upstream希望能够按照ngx_http_upstream_conf_t配置结构体中的hide_headers等成员对发往
     * 下游的响应头部做统一处理*/
    if(u->state)
    {
        u->state->status = ctx->status.code;
    }

    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;

    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if(u->headers_in.status_line.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
        return NGX_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    /*下一步将开始解析HTTP头部。设置process_header回调方法为mytest_upstream_process_header，之后再收到新的字符流就由
     * mytest_upstream_process_header解析*/
    u->process_header = mytest_upstream_process_header;

    /*如果本次收到的字符流处理HTTP响应行外，还有多余的字符，那么将由mytest_upstream_process_header方法解析*/
    return mytest_upstream_process_header(r);
}

static ngx_int_t mytest_upstream_process_header(ngx_http_request_t *r)
{
    ngx_int_t   rc;
    ngx_table_elt_t *h;
    ngx_http_upstream_header_t  *hh;
    ngx_http_upstream_main_conf_t *umcf;

    /**这里将upstream模块配置项ngx_http_upstream_main_conf_t取出来，目的只有一个，就是对将要转发给下游客户端的HTTP
     * 响应头部进行统一处理。该结构体中存储了需要进行统一处理的HTTP头部名称和回调方法*/
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    //循环地解析所有的HTTP头部
    for(; ;)
    {
        //HTTP框架提供了基础性的ngx_http_parse_header_line方法，它用于解析HTTP头部
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
        //返回NGX_OK时，表示解析出一行HTTP头部
        if(NGX_OK == rc)
        {
            //向headers_in.headers这个ngx_list_t链表中添加HTTP头部
            h = ngx_list_push(&r->upstream->headers_in.headers);
            if(NULL == h)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
                return NGX_ERROR;
            }

            //下面开始构造刚刚添加到headers链表中的HTTP头部
            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;
            //必须在内存池中分配存放HTTP头部的内存空间
            h->key.data = ngx_pnalloc(r->pool, h->key.len + 1 + h->value.len + 1 + h->key.len);
            if(h->key.data == NULL)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if(h->key.len == r->lowcase_index)
            {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            }
            else
            {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            //upstream模块会对一些HTTP头部做特殊处理
            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);
            if(hh && hh->handler(r, h, hh->offset) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
                return NGX_ERROR;
            }

            continue;
        }

        /*返回NGX_HTTP_PARSE_HEADER_DONE时，表示响应中所有的HTTP头部都解析完毕，接下来再接收到的都将是HTTP包体*/
        if(NGX_HTTP_PARSE_HEADER_DONE == rc)
        {
            /*如果之前解析HTTP头部时没有发现server和data头部，那么下面会根据HTTP协议规范添加这个两个头部*/
            if(r->upstream->headers_in.server == NULL)
            {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if(NULL == h)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char*)"server";
            }

            if(r->upstream->headers_in.date == NULL)
            {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if(NULL == h)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *)"date";
            }

            return NGX_OK;
        }

        /*如果返回NGX_AGAIN，则表示状态机还没有解析到完整的HTTP头部，此时要求upsream模块继续接收新的字节流，然后交由process_header回调方法解析*/
        if(NGX_AGAIN == rc)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
            return NGX_AGAIN;
        }

        //其他返回值都是非法的
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent invalid header");

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

static void mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "mytest_upstream_finalize_request");
}
