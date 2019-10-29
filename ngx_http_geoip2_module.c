/*
 * Copyright (C) Lee Valentine <lee@leev.net>
 *
 * Based on nginx's 'ngx_http_geoip_module.c' by Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <maxminddb.h>


typedef struct {
    MMDB_s                   mmdb;
    MMDB_lookup_result_s     result;
    time_t                   last_check;
    time_t                   last_change;
    time_t                   check_interval;
#if (NGX_HAVE_INET6)
    uint8_t                  address[16];
#else
    unsigned long            address;
#endif
    ngx_queue_t              queue;
} ngx_http_geoip2_db_t;

typedef struct {
    ngx_queue_t              databases;
    ngx_array_t              *proxies;
    ngx_flag_t               proxy_recursive;
} ngx_http_geoip2_conf_t;

typedef struct {
    ngx_http_geoip2_db_t     *database;
    const char               **lookup;
    ngx_str_t                default_value;
    ngx_http_complex_value_t source;
} ngx_http_geoip2_ctx_t;

typedef struct {
    ngx_http_geoip2_db_t     *database;
    ngx_str_t                metavalue;
} ngx_http_geoip2_metadata_t;


static ngx_int_t ngx_http_geoip2_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_geoip2_metadata(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_geoip2_create_conf(ngx_conf_t *cf);
static char *ngx_http_geoip2_init_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_geoip2(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip2_parse_config(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);
static char *ngx_http_geoip2_add_variable(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);
static char *ngx_http_geoip2_add_variable_geodata(ngx_conf_t *cf,
    ngx_http_geoip2_db_t *database);
static char *ngx_http_geoip2_add_variable_metadata(ngx_conf_t *cf,
    ngx_http_geoip2_db_t *database);
static char *ngx_http_geoip2_proxy(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_geoip2_cidr_value(ngx_conf_t *cf, ngx_str_t *net,
    ngx_cidr_t *cidr);
static void ngx_http_geoip2_cleanup(void *data);
static ngx_int_t ngx_http_geoip2_init(ngx_conf_t *cf);


#define FORMAT(fmt, ...) do {                           \
        p = ngx_palloc(r->pool, NGX_OFF_T_LEN);         \
        if (p == NULL) {                                \
            return NGX_ERROR;                           \
        }                                               \
        v->len = ngx_sprintf(p, fmt, __VA_ARGS__) - p;  \
        v->data = p;                                    \
} while (0)

static ngx_command_t  ngx_http_geoip2_commands[] = {

    { ngx_string("geoip2"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
        ngx_http_geoip2,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("geoip2_proxy"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_http_geoip2_proxy,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("geoip2_proxy_recursive"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_geoip2_conf_t, proxy_recursive),
        NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_geoip2_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_geoip2_init,                  /* postconfiguration */

    ngx_http_geoip2_create_conf,           /* create main configuration */
    ngx_http_geoip2_init_conf,             /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_geoip2_module = {
    NGX_MODULE_V1,
    &ngx_http_geoip2_module_ctx,           /* module context */
    ngx_http_geoip2_commands,              /* module directives */
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


static ngx_int_t
ngx_http_geoip2_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_geoip2_ctx_t   *geoip2 = (ngx_http_geoip2_ctx_t *) data;
    ngx_http_geoip2_db_t    *database = geoip2->database;
    int                     mmdb_error;
    MMDB_entry_data_s       entry_data;
    ngx_http_geoip2_conf_t  *gcf;
    ngx_addr_t              addr;
    ngx_array_t             *xfwd;
    u_char                  *p;
    ngx_str_t               val;

#if (NGX_HAVE_INET6)
    uint8_t address[16], *addressp = address;
#else
    unsigned long address;
#endif

    if (geoip2->source.value.len > 0) {
         if (ngx_http_complex_value(r, &geoip2->source, &val) != NGX_OK) {
             goto not_found;
         }

        if (ngx_parse_addr(r->pool, &addr, val.data, val.len) != NGX_OK) {
            goto not_found;
        }
    } else {
        gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip2_module);
        addr.sockaddr = r->connection->sockaddr;
        addr.socklen = r->connection->socklen;

        xfwd = &r->headers_in.x_forwarded_for;

        if (xfwd->nelts > 0 && gcf->proxies != NULL) {
            (void) ngx_http_get_forwarded_addr(r, &addr, xfwd, NULL,
                                               gcf->proxies, gcf->proxy_recursive);
        }
    }

    switch (addr.sockaddr->sa_family) {
        case AF_INET:
#if (NGX_HAVE_INET6)
            ngx_memset(addressp, 0, 12);
            ngx_memcpy(addressp + 12, &((struct sockaddr_in *)
                                        addr.sockaddr)->sin_addr.s_addr, 4);
            break;

        case AF_INET6:
            ngx_memcpy(addressp, &((struct sockaddr_in6 *)
                                   addr.sockaddr)->sin6_addr.s6_addr, 16);
#else
            address = ((struct sockaddr_in *)addr.sockaddr)->sin_addr.s_addr;
#endif
            break;

        default:
            goto not_found;
    }

#if (NGX_HAVE_INET6)
    if (ngx_memcmp(&address, &database->address, sizeof(address))
        != 0) {
#else
    if (address != database->address) {
#endif
        memcpy(&database->address, &address, sizeof(address));
        database->result = MMDB_lookup_sockaddr(&database->mmdb,
                                           addr.sockaddr, &mmdb_error);

        if (mmdb_error != MMDB_SUCCESS) {
            goto not_found;
        }
    }

    if (!database->result.found_entry
            || MMDB_aget_value(&database->result.entry, &entry_data,
                               geoip2->lookup) != MMDB_SUCCESS) {
        goto not_found;
    }

    if (!entry_data.has_data) {
        goto not_found;
    }

    switch (entry_data.type) {
        case MMDB_DATA_TYPE_BOOLEAN:
            FORMAT("%d", entry_data.boolean);
            break;
        case MMDB_DATA_TYPE_UTF8_STRING:
            v->len = entry_data.data_size;
            v->data = ngx_pnalloc(r->pool, v->len);
            if (v->data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(v->data, (u_char *) entry_data.utf8_string, v->len);
            break;
        case MMDB_DATA_TYPE_BYTES:
            v->len = entry_data.data_size;
            v->data = ngx_pnalloc(r->pool, v->len);
            if (v->data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(v->data, (u_char *) entry_data.bytes, v->len);
            break;
        case MMDB_DATA_TYPE_FLOAT:
            FORMAT("%.5f", entry_data.float_value);
            break;
        case MMDB_DATA_TYPE_DOUBLE:
            FORMAT("%.5f", entry_data.double_value);
            break;
        case MMDB_DATA_TYPE_UINT16:
            FORMAT("%uD", entry_data.uint16);
            break;
        case MMDB_DATA_TYPE_UINT32:
            FORMAT("%uD", entry_data.uint32);
            break;
        case MMDB_DATA_TYPE_INT32:
            FORMAT("%D", entry_data.int32);
            break;
        case MMDB_DATA_TYPE_UINT64:
            FORMAT("%uL", entry_data.uint64);
            break;
        case MMDB_DATA_TYPE_UINT128: ;
#if MMDB_UINT128_IS_BYTE_ARRAY
            uint8_t *val = (uint8_t *)entry_data.uint128;
            FORMAT( "0x%02x%02x%02x%02x%02x%02x%02x%02x"
                      "%02x%02x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3],
                    val[4], val[5], val[6], val[7],
                    val[8], val[9], val[10], val[11],
                    val[12], val[13], val[14], val[15]);
#else
            mmdb_uint128_t val = entry_data.uint128;
            FORMAT("0x%016uxL%016uxL",
                    (uint64_t) (val >> 64), (uint64_t) val);
#endif
            break;
        default:
            goto not_found;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:
    if (geoip2->default_value.len > 0) {
        v->data = geoip2->default_value.data;
        v->len = geoip2->default_value.len;

        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip2_metadata(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_geoip2_metadata_t  *metadata = (ngx_http_geoip2_metadata_t *) data;
    ngx_http_geoip2_db_t        *database = metadata->database;
    u_char                      *p;

    if (ngx_strncmp(metadata->metavalue.data, "build_epoch", 11) == 0) {
        FORMAT("%uL", database->mmdb.metadata.build_epoch);
    } else if (ngx_strncmp(metadata->metavalue.data, "last_check", 10) == 0) {
        FORMAT("%T", database->last_check);
    } else if (ngx_strncmp(metadata->metavalue.data, "last_change", 11) == 0) {
        FORMAT("%T", database->last_change);
    } else {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static void *
ngx_http_geoip2_create_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t      *cln;
    ngx_http_geoip2_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_geoip2_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->proxy_recursive = NGX_CONF_UNSET;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    ngx_queue_init(&conf->databases);

    cln->handler = ngx_http_geoip2_cleanup;
    cln->data = conf;

    return conf;
}


static char *
ngx_http_geoip2(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip2_conf_t  *gcf = conf;
    ngx_str_t               *value;
    int                     status;
    ngx_http_geoip2_db_t    *database;
    char                    *rv;
    ngx_conf_t              save;
    ngx_queue_t             *q;

    value = cf->args->elts;

    if (value[1].data && value[1].data[0] != '/') {
        if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (!ngx_queue_empty(&gcf->databases)) {
        for (q = ngx_queue_head(&gcf->databases);
             q != ngx_queue_sentinel(&gcf->databases);
             q = ngx_queue_next(q))
        {
            database = ngx_queue_data(q, ngx_http_geoip2_db_t, queue);
            if (ngx_strcmp(value[1].data, database->mmdb.filename) == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "Duplicate GeoIP2 mmdb - %V", &value[1]);
                return NGX_CONF_ERROR;
            }
        }
    }

    database = ngx_pcalloc(cf->pool, sizeof(ngx_http_geoip2_db_t));
    if (database == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_queue_insert_tail(&gcf->databases, &database->queue);
    database->last_check = database->last_change = ngx_time();

    status = MMDB_open((char *) value[1].data, MMDB_MODE_MMAP, &database->mmdb);

    if (status != MMDB_SUCCESS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "MMDB_open(\"%V\") failed - %s", &value[1],
                           MMDB_strerror(status));
        return NGX_CONF_ERROR;
    }

    save = *cf;
    cf->handler = ngx_http_geoip2_parse_config;
    cf->handler_conf = (void *) database;

    rv = ngx_conf_parse(cf, NULL);
    *cf = save;
    return rv;
}


static char *
ngx_http_geoip2_parse_config(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_http_geoip2_db_t  *database;
    ngx_str_t             *value;
    time_t                interval;

    value = cf->args->elts;

    if (value[0].data[0] == '$') {
        return ngx_http_geoip2_add_variable(cf, dummy, conf);
    }

    if (value[0].len == 11
            && ngx_strncmp(value[0].data, "auto_reload", 11) == 0) {
        if ((int) cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid number of arguments for auto_reload");
            return NGX_CONF_ERROR;
        }

        interval = ngx_parse_time(&value[1], true);

        if (interval == (time_t) NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid interval for auto_reload \"%V\"",
                               value[1]);
            return NGX_CONF_ERROR;
        }


        database = (ngx_http_geoip2_db_t *) conf;
        database->check_interval = interval;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid setting \"%V\"", &value[0]);
    return NGX_CONF_ERROR;
}


static char *
ngx_http_geoip2_add_variable(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_http_geoip2_db_t  *database;
    ngx_str_t             *value;
    int                   nelts;

    value = cf->args->elts;

    if (value[0].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[0]);
        return NGX_CONF_ERROR;
    }

    value[0].len--;
    value[0].data++;

    nelts = (int) cf->args->nelts;
    database = (ngx_http_geoip2_db_t *) conf;

    if (nelts > 0 && value[1].len == 8 && ngx_strncmp(value[1].data, "metadata", 8) == 0) {
        return ngx_http_geoip2_add_variable_metadata(cf, database);
    }

    return ngx_http_geoip2_add_variable_geodata(cf, database);
}


static char *
ngx_http_geoip2_add_variable_metadata(ngx_conf_t *cf, ngx_http_geoip2_db_t *database)
{
    ngx_http_geoip2_metadata_t  *metadata;
    ngx_str_t                   *value, name;
    ngx_http_variable_t         *var;

    metadata = ngx_pcalloc(cf->pool, sizeof(ngx_http_geoip2_metadata_t));
    if (metadata == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
    name = value[0];

    metadata->database = database;
    metadata->metavalue = value[2];

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_geoip2_metadata;
    var->data = (uintptr_t) metadata;

    return NGX_CONF_OK;
}


static char *
ngx_http_geoip2_add_variable_geodata(ngx_conf_t *cf, ngx_http_geoip2_db_t *database)
{
    ngx_http_geoip2_ctx_t             *geoip2;
    ngx_http_compile_complex_value_t  ccv;
    ngx_str_t                         *value, name, source;
    ngx_http_variable_t               *var;
    int                               i, nelts, idx;

    geoip2 = ngx_pcalloc(cf->pool, sizeof(ngx_http_geoip2_ctx_t));
    if (geoip2 == NULL) {
        return NGX_CONF_ERROR;
    }

    geoip2->database = database;
    ngx_str_null(&source);

    value = cf->args->elts;
    name = value[0];

    nelts = (int) cf->args->nelts;
    idx = 1;

    if (nelts > idx) {
        for (i = idx; i < nelts; i++) {
            if (ngx_strnstr(value[idx].data, "=", value[idx].len) == NULL) {
                break;
            }

            if (value[idx].len > 8 && ngx_strncmp(value[idx].data, "default=", 8) == 0) {
                if (geoip2->default_value.len > 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "default has already been declared for  \"$%V\"", &name);
                    return NGX_CONF_ERROR;
                }

                geoip2->default_value.len  = value[idx].len - 8;
                geoip2->default_value.data = value[idx].data + 8;
            } else if (value[idx].len > 7 && ngx_strncmp(value[idx].data, "source=", 7) == 0) {
                if (source.len > 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "source has already been declared for  \"$%V\"", &name);
                    return NGX_CONF_ERROR;
                }

                source.len  = value[idx].len - 7;
                source.data = value[idx].data + 7;

                if (source.data[0] != '$') {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid source variable name \"%V\"", &source);
                    return NGX_CONF_ERROR;
                }

                ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
                ccv.cf = cf;
                ccv.value = &source;
                ccv.complex_value = &geoip2->source;

                if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "unable to compile \"%V\" for \"$%V\"", &source, &name);
                    return NGX_CONF_ERROR;
                }
            } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid setting \"%V\" for \"$%V\"", &value[idx], &name);
                    return NGX_CONF_ERROR;
            }

            idx++;
        }
    }

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    geoip2->lookup = ngx_pcalloc(cf->pool, sizeof(const char *) *
                                 (cf->args->nelts - (idx - 1)));

    if (geoip2->lookup == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = idx; i < nelts; i++) {
        geoip2->lookup[i - idx] = (char *) value[i].data;
    }
    geoip2->lookup[i - idx] = NULL;

    var->get_handler = ngx_http_geoip2_variable;
    var->data = (uintptr_t) geoip2;

    return NGX_CONF_OK;
}


static char *
ngx_http_geoip2_init_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_geoip2_conf_t  *gcf = conf;
    ngx_conf_init_value(gcf->proxy_recursive, 0);
    return NGX_CONF_OK;
}


static char *
ngx_http_geoip2_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip2_conf_t  *gcf = conf;
    ngx_str_t               *value;
    ngx_cidr_t              cidr, *c;

    value = cf->args->elts;

    if (ngx_http_geoip2_cidr_value(cf, &value[1], &cidr) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (gcf->proxies == NULL) {
        gcf->proxies = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
        if (gcf->proxies == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    c = ngx_array_push(gcf->proxies);
    if (c == NULL) {
        return NGX_CONF_ERROR;
    }

    *c = cidr;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_geoip2_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr)
{
    ngx_int_t  rc;

    if (ngx_strcmp(net->data, "255.255.255.255") == 0) {
        cidr->family = AF_INET;
        cidr->u.in.addr = 0xffffffff;
        cidr->u.in.mask = 0xffffffff;

        return NGX_OK;
    }

    rc = ngx_ptocidr(net, cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid network \"%V\"", net);
        return NGX_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", net);
    }

    return NGX_OK;
}


static void
ngx_http_geoip2_cleanup(void *data)
{
    ngx_http_geoip2_conf_t  *gcf = data;
    ngx_queue_t             *q;
    ngx_http_geoip2_db_t    *database;

    while (!ngx_queue_empty(&gcf->databases)) {
        q = ngx_queue_head(&gcf->databases);
        ngx_queue_remove(q);
        database = ngx_queue_data(q, ngx_http_geoip2_db_t, queue);
        MMDB_close(&database->mmdb);
    }
}


static ngx_int_t
ngx_http_geoip2_log_handler(ngx_http_request_t *r)
{
    int                      status;
    MMDB_s                   tmpdb;
    ngx_queue_t              *q;
    ngx_file_info_t          fi;
    ngx_http_geoip2_db_t    *database;
    ngx_http_geoip2_conf_t  *gcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "geoip2 http log handler");

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip2_module);

    if (ngx_queue_empty(&gcf->databases)) {
        return NGX_OK;
    }

    for (q = ngx_queue_head(&gcf->databases);
         q != ngx_queue_sentinel(&gcf->databases);
         q = ngx_queue_next(q))
    {
        database = ngx_queue_data(q, ngx_http_geoip2_db_t, queue);
        if (database->check_interval == 0) {
            continue;
        }

        if ((database->last_check + database->check_interval)
            > ngx_time())
        {
            continue;
        }

        database->last_check = ngx_time();

        if (ngx_file_info(database->mmdb.filename, &fi) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, ngx_errno,
                          ngx_file_info_n " \"%s\" failed",
                          database->mmdb.filename);

            continue;
        }

        if (ngx_file_mtime(&fi) <= database->last_change) {
            continue;
        }

        /* do the reload */

        ngx_memzero(&tmpdb, sizeof(MMDB_s));
        status = MMDB_open(database->mmdb.filename, MMDB_MODE_MMAP, &tmpdb);

        if (status != MMDB_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "MMDB_open(\"%s\") failed to reload - %s",
                          database->mmdb.filename, MMDB_strerror(status));

            continue;
        }

        database->last_change = ngx_file_mtime(&fi);
        MMDB_close(&database->mmdb);
        database->mmdb = tmpdb;

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "Reload MMDB \"%s\"",
                      database->mmdb.filename);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_geoip2_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_geoip2_log_handler;

    return NGX_OK;
}
