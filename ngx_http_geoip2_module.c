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
#if (NGX_HAVE_INET6)
    uint8_t                  address[16];
#else
    unsigned long            address;
#endif
} ngx_http_geoip2_db_t;

typedef struct {
    ngx_array_t              *databases;
    ngx_array_t              *proxies;
    ngx_flag_t               proxy_recursive;
} ngx_http_geoip2_conf_t;

typedef struct {
    ngx_http_geoip2_db_t     *database;
    const char               **lookup;
    ngx_str_t                default_value;
    ngx_http_complex_value_t source;
} ngx_http_geoip2_ctx_t;


static ngx_int_t ngx_http_geoip2_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_geoip2_create_conf(ngx_conf_t *cf);
static char *ngx_http_geoip2_init_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_geoip2(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip2_add_variable(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);
static char *ngx_http_geoip2_proxy(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_geoip2_cidr_value(ngx_conf_t *cf, ngx_str_t *net,
    ngx_cidr_t *cidr);
static void ngx_http_geoip2_cleanup(void *data);


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
    NULL,                                  /* preconfiguration */

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
            v->data = (u_char *) entry_data.utf8_string;
            v->len = entry_data.data_size;
            break;
        case MMDB_DATA_TYPE_BYTES:
            v->data = (u_char *) entry_data.bytes;
            v->len = entry_data.data_size;
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

    cln->handler = ngx_http_geoip2_cleanup;
    cln->data = conf;

    return conf;
}


static char *
ngx_http_geoip2(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip2_conf_t  *gcf = conf;
    ngx_str_t               *value;
    int                     status, nelts, i;
    ngx_http_geoip2_db_t    *database;
    char                    *rv;
    ngx_conf_t              save;

    value = cf->args->elts;

    if (gcf->databases == NULL) {
        gcf->databases = ngx_array_create(cf->pool, 2,
                                        sizeof(ngx_http_geoip2_db_t));
        if (gcf->databases == NULL) {
            return NGX_CONF_ERROR;
        }
    } else {
        nelts = (int) gcf->databases->nelts;
        database = gcf->databases->elts;

        for (i = 0; i < nelts; i++) {
            if (ngx_strcmp(value[1].data, database[i].mmdb.filename) == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "Duplicate GeoIP2 mmdb - %V", &value[1]);
                return NGX_CONF_ERROR;
            }
        }
    }

    database = ngx_array_push(gcf->databases);
    if (database == NULL) {
        return NGX_CONF_ERROR;
    }

    status = MMDB_open((char *) value[1].data, MMDB_MODE_MMAP, &database->mmdb);

    if (status != MMDB_SUCCESS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "MMDB_open(\"%V\") failed - %s", &value[1],
                           MMDB_strerror(status));
        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_INET6)
    ngx_memset(&database->address, 0, sizeof(database->address));
#else
    database->address = 0;
#endif

    save = *cf;
    cf->handler = ngx_http_geoip2_add_variable;
    cf->handler_conf = (void *) database;

    rv = ngx_conf_parse(cf, NULL);
    *cf = save;
    return rv;
}


static char *
ngx_http_geoip2_add_variable(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_str_t                          *value, name, source;
    ngx_http_geoip2_ctx_t              *geoip2;
    ngx_http_variable_t                *var;
    int                                i, nelts, idx;
    ngx_http_compile_complex_value_t   ccv;

    geoip2 = ngx_pcalloc(cf->pool, sizeof(ngx_http_geoip2_ctx_t));
    if (geoip2 == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
    name = value[0];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;
    nelts = (int) cf->args->nelts;
    idx = 1;
    geoip2->database = (ngx_http_geoip2_db_t *) conf;
    ngx_str_null(&source);

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
    ngx_uint_t              i;
    ngx_http_geoip2_db_t    *database;

    if (gcf->databases != NULL) {
        database = gcf->databases->elts;

        for (i = 0; i < gcf->databases->nelts; i++) {
            MMDB_close(&database[i].mmdb);
        }

        ngx_array_destroy(gcf->databases);
    }
}
