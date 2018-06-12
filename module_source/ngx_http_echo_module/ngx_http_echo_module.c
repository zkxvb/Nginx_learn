/*
* Copyright (C) Eric Zhang
*/
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Module config */
typedef struct {
    ngx_str_t  ed;
} ngx_http_echo_loc_conf_t;

static char *ngx_http_echo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_echo_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_echo_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

/* Directives */
static ngx_command_t  ngx_http_echo_commands[] = {
    { ngx_string("echo"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_echo,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_echo_loc_conf_t, ed),
        NULL },
        ngx_null_command
};
/* Http context of the module */
static ngx_http_module_t  ngx_http_echo_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    ngx_http_echo_create_loc_conf,         /* create location configration */
    ngx_http_echo_merge_loc_conf           /* merge location configration */
};
/* Module */
ngx_module_t  ngx_http_echo_module = {
    NGX_MODULE_V1,
    &ngx_http_echo_module_ctx,             /* module context */
    ngx_http_echo_commands,                /* module directives */
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

/* Handler function */
static ngx_int_t
ngx_http_echo_handler(ngx_http_request_t *r)
{
	//must is Get or Head method
	if(!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))){
		return NGX_HTTP_NOT_ALLOWED;
	}

	//discard the body of the request
	ngx_int_t rc = ngx_http_discard_request_body(r);
	if(rc != NGX_OK){
		return rc;
	}

	ngx_buf_t *b;
	b = ngx_palloc(r->pool, sizeof(ngx_buf_t));

	//the file which want to open 
	u_char* filename = (u_char*)"/tmp/test.txt";
	b->in_file = 1;
	b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
	b->file->fd = ngx_open_file(filename, NGX_FILE_RDONLY | NGX_FILE_NONBLOCK, NGX_FILE_OPEN, 0);
	b->file->log = r->connection->log;
	b->file->name.data = filename;
	b->file->name.len = sizeof(filename) - 1;
	if(b->file->fd <= 0){
		return NGX_HTTP_NOT_FOUND;
	}

	//support the duan_dian_xu_chuan
	r->allow_ranges = 1;

	//get the length of the file
	if(ngx_file_info(filename, &b->file->info) == NGX_FILE_ERROR){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	//set the file block which the cache point
	b->file_pos = 0;
	b->file_last = b->file->info.st_size;

	ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
	if(cln == NULL){
		return NGX_ERROR;
	}

	cln->handler = ngx_pool_cleanup_file;
	//set value to data of ngx_pool_cleanup_t
	ngx_pool_cleanup_file_t *clnf = cln->data;
	clnf->fd = b->file->fd;
	clnf->name = b->file->name.data;
	clnf->log = r->pool->log;

	//set the Content-Type
	ngx_str_t type = ngx_string("text/plain");
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = b->file->info.st_size;
	r->headers_out.content_type = type;

	//send the http header
	rc = ngx_http_send_header(r);
	if(rc == NGX_ERROR || rc > NGX_OK || r->header_only){
		return rc;
	}

	//generate the ngx_chain_t struct
	ngx_chain_t out;
	out.buf = b;
	out.next = NULL;

	return ngx_http_output_filter(r, &out);
}

static char *
ngx_http_echo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_echo_handler;
    ngx_conf_set_str_slot(cf,cmd,conf);
    return NGX_CONF_OK;
}
static void *
ngx_http_echo_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_echo_loc_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_echo_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->ed.len = 0;
    conf->ed.data = NULL;
    return conf;
}
static char *
ngx_http_echo_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_echo_loc_conf_t *prev = parent;
    ngx_http_echo_loc_conf_t *conf = child;
    ngx_conf_merge_str_value(conf->ed, prev->ed, "");
    return NGX_CONF_OK;
}
