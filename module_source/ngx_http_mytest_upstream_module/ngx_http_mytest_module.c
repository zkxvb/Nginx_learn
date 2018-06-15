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

//�Զ�������������Զ������������
typedef struct
{
        ngx_str_t config_str;
        ngx_int_t   config_num;
}ngx_http_config_conf_t;

//�洢loc����������Ľṹ��
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

//mytestģ��������
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

//�����ṹ�����ڴ洢loc����������
static void*  ngx_http_mytest_create_loc_conf(ngx_conf_t    *cf)
{
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "�����ṹ�����ڴ洢loc����������\n");
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

        //�����ṹ��ķ�������ʱ���������Ľṹ�崫�ݸ�HTTP���
        return mycf;
}

//�������������ص��ĺ���
void ngx_http_mytest_body_handler(ngx_http_request_t *r)
{

}

//HTTP��NGX_HTTP_CONTENT_PHASE�׶�mytestģ����봦��http��������
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r)
{
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "HTTP��HTTP_CONTENT_PHASE�׶�ģ����봦��http��������\n");
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_pagesize=%d\n",ngx_pagesize);
        //���ȵ���ngx_http_get_module_ctx������ȡ�����Ľṹ��
        ngx_http_mytest_ctx_t* myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
        if(NULL == myctx)
        {
            //�����ڵ�ǰ������ڴ��r->pool�з��������Ľṹ�壬�����������ʱ�ṹ��ռ�õ��ڴ�Ż��ͷ�
            myctx = ngx_pcalloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
            if(NULL == myctx)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
                return NGX_ERROR;
            }
            //���շ���Ľṹ�����õ���ǰ�������������
            ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);
        }

        //����ʱGET����HEAD���������򷵻�405 Not Allowed
        if(!(r->method &(NGX_HTTP_GET | NGX_HTTP_HEAD)))
        {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "weijl NGX_HTTP_NOT_ALLOWED");
                return NGX_HTTP_NOT_ALLOWED;
        }

        //��ÿ��Ҫʹ��upstream�����󣬱��������ֻ�ܵ���һ��ngx_http_upstream_create�����������ʼ��r->upstream��Ա
        if(ngx_http_upstream_create(r) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create() failed\n");

            return NGX_ERROR;
        }

        //�ô����ýṹ��ngx_http_mytest_conf_t
        ngx_http_mytest_conf_t* mycf = (ngx_http_mytest_conf_t*)ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
        ngx_http_upstream_t *u = r->upstream;
        //�����������ļ��еĽṹ��������r->upstream->conf��Ա
        u->conf = &mycf->upstream;
        //����ת������ʱʹ�õĻ�����
        u->buffering = mycf->upstream.buffering;

        //���´��뿪ʼ��ʼ��resolved�ṹ�壬�����������η�������ַ
        u->resolved = (ngx_http_upstream_resolved_t*)ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
        if(NULL == u->resolved )
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_pcalloc resolved error. %s.", strerror(errno));

            return NGX_ERROR;
        }

        //��������η���������s.taobao.com
        static struct sockaddr_in backendSockAddr;
        struct hostent *pHost = gethostbyname((char*)"s.taobao.com");
        if(NULL == pHost)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gethostbyname fail. %s.", strerror(errno));

            return NGX_ERROR;
        }

        //�������η�������80�˿�
        backendSockAddr.sin_family = AF_INET;
        backendSockAddr.sin_port = htons((in_port_t)80);
        char * pDmsIP = inet_ntoa(*(struct in_addr*)(pHost->h_addr_list[0]));
        backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
        myctx->backendServer.data = (u_char*)pDmsIP;
        myctx->backendServer.len = strlen(pDmsIP);

        //����ַ���õ�resolved��Ա��
        u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
        u->resolved->socklen = sizeof(struct sockaddr_in);
        u->resolved->naddrs = 1;
        u->resolved->port = backendSockAddr.sin_port;

        //����3������ʵ�ֵĻص�����
        u->create_request = mytest_upstream_create_request;
        u->process_header = mytest_upstream_status_line;
        u->finalize_request = mytest_upstream_finalize_request;

        //������뽫count��Ա��1
        r->main->count++;
        //����upstream
        ngx_http_upstream_init(r);

        //���뷵��NGX_DONE
        return NGX_DONE;

        //����ע�Ͳ���Ϊ�������ֱ�ӷ��͸��ͻ��ˣ���ʱע�͵�
        /*
        //���������еİ���
        ngx_int_t rc = ngx_http_discard_request_body(r);
        if(rc != NGX_OK)
        {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "weijl rc=%d", rc);
                return rc;
        }

        //���÷��ص�Content_Type��ע�⣬ngx_str_t��һ���ܷ���ĳ�ʼ����ngx_string,�����԰�ngx_str_t��data��len��Ա�����ú�
        ngx_str_t type = ngx_string("text/plain");
        //���÷���״̬��
        r->headers_out.status = NGX_HTTP_OK;

        //����HTTPͷ��
        rc = ngx_http_send_header(r);
        if(rc == NGX_ERROR || rc > NGX_OK || r->header_only)
        {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "weijl rc=%d", rc);
                return rc;
        }

        //����ngx_buf_t�ṹ��׼�����Ͱ���
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

        //��Ӧ�����ɰ������ݵģ���Ҫ����Conten-Length����
        r->headers_out.content_length_n = b->file->info.st_size;
        //����Content-Type
        r->headers_out.content_type = type;

        b->file_pos = 0;
        b->file_last = b->file->info.st_size;
        //�����������һ�黺����
        b->last_buf =1;

        //���췢��ʱ��ngx_chain_t�ṹ��
        ngx_chain_t out;
        out.buf = b;
        //����nextΪNULL
        out.next = NULL;

        //�����ļ����
        ////���������ʱ����cln��handler����������Դ
        ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
        if(NULL == cln)
        {
                return NGX_ERROR;
        }
        //��Nginx�ṩ��ngx_pool_cleanup_file��������Ϊ�ص�����
        cln->handler = ngx_pool_cleanup_file;
        //���ûص������Ĳ���
        ngx_pool_cleanup_file_t *clnf = cln->data;

        clnf->fd = b->file->fd;
        clnf->name = b->file->name.data;
        clnf->log = r->pool->log;

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "weijl ���������ɣ���ʼ���Ͱ���\n");

        //���һ��Ϊ���Ͱ��壬���ͽ�����HTTP��ܻ����ngx_http_finalize_request������������
        return ngx_http_output_filter(r, &out);*/
}

//û��ʲô����������HTTP��ܳ�ʼ��ʱ��ɣ�����ʵ��ngx_http_module_t��8���ص�����
static ngx_http_module_t ngx_http_mytest_module_ctx =
{
        NULL,//preconfiguration���������ļ�ǰ����
        NULL,//postconfiguration��������ļ����������

        NULL,//ceate_main_conf�����洢ȫ��������Ľṹ��
        NULL,//init_main_conf�����ڳ�ʼ��main�����������

        NULL,//create_srv_conf�����洢srv����������Ľṹ��
        NULL,//merge_srv_conf��Ҫ���ںϲ�main�����srv�����µ�ͬ��������

        ngx_http_mytest_create_loc_conf,//create_loc_conf�������ڴ洢loc����������Ľṹ��
        ngx_http_mytest_merge_loc_conf//merge_loc_conf��Ҫ���ںϲ�srv�����loc�����µ�ͬ��������
};

//��mytest������������Ļص�����
static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "mytest����������Ļص�����\n");
        ngx_http_core_loc_conf_t  *clcf;
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

        /*HTTP����ڴ����û�������е�NGX_HTTP_CONTENT_PHASE�׶�ʱ��������������������URI��mytest
         * ���������ڵ����ÿ���ƥ�䣬�ͽ�����ngx_http_mytest_handler���������������*/
        clcf->handler = ngx_http_mytest_handler;

        return NGX_CONF_OK;
}

//mytest������Ĵ���
static ngx_command_t  ngx_http_mytest_commands[] = {
        {ngx_string("mytest"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
        ngx_http_mytest,//�ڳ���������mytestʱ����ngx_http_mytest����
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL},

        {ngx_string("test_flag"),
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,//�ڳ���������test_flagʱ����ngx_conf_set_flag_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_flag),
        NULL},

        {ngx_string("test_str"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,//�ڳ���������test_strʱ����ngx_conf_set_str_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_str),
        NULL},

        {ngx_string("test_str_array"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,//�ڳ���������test_str_arrayʱ����ngx_conf_set_str_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_str_array),
        NULL},

        {ngx_string("test_keyval"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_conf_set_keyval_slot,//�ڳ���������test_keyvalʱ����ngx_conf_set_keyval_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_keyval),
        NULL},

        {ngx_string("test_num"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,//�ڳ���������test_numʱ����ngx_conf_set_num_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_num),
        NULL},

        {ngx_string("test_size"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,//�ڳ���������test_sizeʱ����ngx_conf_set_size_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_size),
        NULL},

        {ngx_string("test_off"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_off_slot,//�ڳ���������test_offʱ����ngx_conf_set_off_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_off),
        NULL},

        {ngx_string("test_msec"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,//�ڳ���������test_msecʱ����ngx_conf_set_msec_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_msec),
        NULL},

        {ngx_string("test_sec"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_sec_slot,//�ڳ���������test_secʱ����ngx_conf_set_sec_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_sec),
        NULL},

        {ngx_string("test_bufs"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_conf_set_bufs_slot,//�ڳ���������test_bufsʱ����ngx_conf_set_bufs_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_bufs),
        NULL},

        {ngx_string("test_enum"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,//�ڳ���������test_enumʱ����ngx_conf_set_enum_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_enum_seq),
        test_enums},

        {ngx_string("test_bitmask"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_bitmask_slot,//�ڳ���������test_bitmaskʱ����ngx_conf_set_bitmask_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_bitmask),
        test_bitmasks},

        {ngx_string("test_access"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
        ngx_conf_set_access_slot,//�ڳ���������test_accessʱ����ngx_conf_set_access_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_access),
        NULL},

        {ngx_string("test_path"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
        ngx_conf_set_path_slot,//�ڳ���������test_pathʱ����ngx_conf_set_path_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_path),
        NULL},

        {ngx_string("test_myconfig"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
        ngx_conf_set_myconfig,//�ڳ���������test_myconfigʱ����ngx_conf_set_myconfig����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, my_config),
        NULL},

        {ngx_string("upstream_connect_timeout"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,//�ڳ���������upstream_connect_timeoutʱ����ngx_conf_set_msec_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, upstream.connect_timeout),
        NULL},

        { ngx_string("upstream_send_timeout"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot, //�ڳ���������upstream_send_timeoutʱ����ngx_conf_set_msec_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.send_timeout),
        NULL },

        { ngx_string("upstream_read_timeout"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot, //�ڳ���������upstream_read_timeoutʱ����ngx_conf_set_msec_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.read_timeout),
        NULL },

        { ngx_string("upstream_store_access"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_access_slot,   //�ڳ���������upstream_store_accessʱ����ngx_conf_set_access_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.store_access),
        NULL },

        { ngx_string("upstream_buffering"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot, //�ڳ���������upstream_bufferingʱ����ngx_conf_set_num_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.buffering),
        NULL },

        { ngx_string("upstream_bufs"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        ngx_conf_set_bufs_slot, //�ڳ���������upstream_bufferingʱ����ngx_conf_set_num_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.bufs),
        NULL },

        { ngx_string("upstream_buffer_size"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot, //�ڳ���������upstream_buffer_sizeʱ����ngx_conf_set_size_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.buffer_size),
        NULL },

        { ngx_string("upstream_busy_buffers_size"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot, //�ڳ���������upstream_busy_buffers_sizeʱ����ngx_conf_set_size_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.busy_buffers_size),
        NULL },

        { ngx_string("upstream_temp_file_write_size"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot, //�ڳ���������upstream_temp_file_write_sizeʱ����ngx_conf_set_size_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.temp_file_write_size),
        NULL },

        { ngx_string("upstream_max_temp_file_size"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot, //�ڳ���������upstream_max_temp_file_sizeʱ����ngx_conf_set_size_slot����
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t,upstream.max_temp_file_size),
        NULL },

        //�������������������ﶨ��

        ngx_null_command
};

//����mytestģ��
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

//�Զ������������
static char* ngx_conf_set_myconfig(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "�Զ������������\n");
        //ע�⣬����conf����HTTP��ܴ����û�����ngx_http_mytest_create_loc_conf�ص������з���Ľṹ��ngx_http_mytest_conf_t
        ngx_http_mytest_conf_t *mycf = conf;

        /*cf->args��һ��ngx_array_t���У����ĳ�Ա����ngx_str_t�ṹ��������valueָ��ngx_array_t��elts�����ݣ�����value[1]
         * ���ǵ�һ��������ͬ��value[2]�ǵڶ�������*/
        ngx_str_t* value  = cf->args->elts;

        //ngx_array_t��nelts��ʾ�����ĸ���
        if(cf->args->nelts > 1)
        {
                //ֱ�Ӹ�ֵ���ɣ�ngx_str_t�ṹֻ��ָ��Ĵ���
                mycf->my_config.config_str = value[1];
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "weijl config_str=%V", &mycf->my_config.config_str);
        }

        if(cf->args->nelts > 2)
        {
                //���ַ�����ʽ�ĵڶ�������תΪ����
                mycf->my_config.config_num = ngx_atoi(value[2].data, value[2].len);
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "weijl config_num=%d", mycf->my_config.config_num);
                //����ַ���תΪ����ʧ�ܣ�����"invalid number"����Nginx����ʧ��
                if(mycf->my_config.config_num == NGX_ERROR)
                {
                        return "invalid number";
                }
        }

        //���سɹ�
        return NGX_CONF_OK;
}

//�ϲ�������
static char* ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *conf)
{
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "�ϲ�������\n");
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

//���췢�����η���������������
static ngx_int_t mytest_upstream_create_request(ngx_http_request_t *r)
{
    /*����baidu���η�����������ܼ򵥣�����ģ������������������/search?=...��URI�������롣*/
    static ngx_str_t backendQueryLine = ngx_string("GET /search?q=%V HTTP/1.1\r\nHost: s.taobao.com\r\nConnection: close\r\n\r\n");
    ngx_int_t queryLineLen = backendQueryLine.len + r->args.len-2;
    /*�������ڴ���������ڴ棬������������ô���һ���ô��ǣ�������������ѵ�����£������η�������������ʱ��������Ҫ
     * epoll��ε���send���ܷ�����ɣ���ʱ���뱣֤����ڴ治�ᱻ�ͷ�;��һ���ô��ǣ��ڽ�������ʱ������ڴ�ᱻ�Զ��ͷţ�
     * �����ڴ�й¶�Ŀ���*/
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, queryLineLen);
    if(NULL == b)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
        return NGX_ERROR;
    }
    //lastҪָ�������ĩβ
    b->last = b->pos + queryLineLen;

    //�����൱��snprintf��ֻ����֧��ngx�е�����ת����ʽ
    ngx_snprintf(b->pos, queryLineLen, (char*)backendQueryLine.data, &r->args);
    /*r->upstream->request_bufs��һ��ngx_chain_t�ṹ����������Ҫ���͸����η�����������*/
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if(NULL == r->upstream->request_bufs)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
        return NGX_ERROR;
    }

    //request->bufs������ֻ����һ��ngx_buf_t������
    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;

    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;
    //header_hash������Ϊ0
    r->header_hash = 1;

    return NGX_OK;
}

static ngx_int_t mytest_upstream_status_line(ngx_http_request_t *r)
{
    size_t len;
    ngx_int_t rc;
    ngx_http_upstream_t *u;

    //�������вŻᱣ���ν���HTTP��Ӧ�е�״̬����������ȡ�������������
    ngx_http_mytest_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if(NULL == ctx)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
        return NGX_ERROR;
    }

    u = r->upstream;

    /*HTTP����ṩ��ngx_http_parse_status_line�������Խ���HTTP��Ӧ�У�������������յ����ַ�����������
     * �е�ngx_http_status_t�ṹ*/
    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
    //����NGX_AGAINʱ����ʾ��û�н�����������HTTP��Ӧ�У���Ҫ���ո�����ַ����ٽ��н���
    if(NGX_AGAIN == rc)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
        return rc;
    }

    //����NGX_ERRORʱ����ʾû�н��յ��Ϸ���HTTP��Ӧ��
    if(NGX_ERROR == rc)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent no valid HTTP/1.0 header");

        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;

        return NGX_OK;
    }

    /*���±�ʾ�ڽ�����������HTTP��Ӧ��ʱ������һЩ�򵥵ĸ�ֵ������������������Ϣ���õ�r->upstream->headers_in
     * �ṹ���С���upstream���������еİ�ͷʱ�����headers_in�еĳ�Ա���õ���Ҫ�����η��͵�r->headers_out�ṹ��
     * �У�Ҳ����˵�������û���headers_in�����õ���Ϣ�����ն��ᷢ�����οͻ��ˡ�Ϊʲô��ֱ������r->headers_out��
     * Ҫ���һ���أ���Ϊupstreamϣ���ܹ�����ngx_http_upstream_conf_t���ýṹ���е�hide_headers�ȳ�Ա�Է���
     * ���ε���Ӧͷ����ͳһ����*/
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

    /*��һ������ʼ����HTTPͷ��������process_header�ص�����Ϊmytest_upstream_process_header��֮�����յ��µ��ַ�������
     * mytest_upstream_process_header����*/
    u->process_header = mytest_upstream_process_header;

    /*��������յ����ַ�������HTTP��Ӧ���⣬���ж�����ַ�����ô����mytest_upstream_process_header��������*/
    return mytest_upstream_process_header(r);
}

static ngx_int_t mytest_upstream_process_header(ngx_http_request_t *r)
{
    ngx_int_t   rc;
    ngx_table_elt_t *h;
    ngx_http_upstream_header_t  *hh;
    ngx_http_upstream_main_conf_t *umcf;

    /**���ｫupstreamģ��������ngx_http_upstream_main_conf_tȡ������Ŀ��ֻ��һ�������ǶԽ�Ҫת�������οͻ��˵�HTTP
     * ��Ӧͷ������ͳһ�����ýṹ���д洢����Ҫ����ͳһ�����HTTPͷ�����ƺͻص�����*/
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    //ѭ���ؽ������е�HTTPͷ��
    for(; ;)
    {
        //HTTP����ṩ�˻����Ե�ngx_http_parse_header_line�����������ڽ���HTTPͷ��
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
        //����NGX_OKʱ����ʾ������һ��HTTPͷ��
        if(NGX_OK == rc)
        {
            //��headers_in.headers���ngx_list_t���������HTTPͷ��
            h = ngx_list_push(&r->upstream->headers_in.headers);
            if(NULL == h)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
                return NGX_ERROR;
            }

            //���濪ʼ����ո���ӵ�headers�����е�HTTPͷ��
            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;
            //�������ڴ���з�����HTTPͷ�����ڴ�ռ�
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

            //upstreamģ����һЩHTTPͷ�������⴦��
            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);
            if(hh && hh->handler(r, h, hh->offset) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
                return NGX_ERROR;
            }

            continue;
        }

        /*����NGX_HTTP_PARSE_HEADER_DONEʱ����ʾ��Ӧ�����е�HTTPͷ����������ϣ��������ٽ��յ��Ķ�����HTTP����*/
        if(NGX_HTTP_PARSE_HEADER_DONE == rc)
        {
            /*���֮ǰ����HTTPͷ��ʱû�з���server��dataͷ������ô��������HTTPЭ��淶����������ͷ��*/
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

        /*�������NGX_AGAIN�����ʾ״̬����û�н�����������HTTPͷ������ʱҪ��upsreamģ����������µ��ֽ�����Ȼ����process_header�ص���������*/
        if(NGX_AGAIN == rc)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "____weijl line=%d____\n", __LINE__);
            return NGX_AGAIN;
        }

        //��������ֵ���ǷǷ���
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent invalid header");

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

static void mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "mytest_upstream_finalize_request");
}
