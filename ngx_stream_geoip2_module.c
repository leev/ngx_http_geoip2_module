/*
 * Copyright (C) Lee Valentine <lee@leev.net>
 * Copyright (C) Andrei Belov <defanator@gmail.com>
 *
 * Based on nginx's 'ngx_stream_geoip_module.c' by Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <maxminddb.h>


typedef struct {
    MMDB_s                   mmdb;
    MMDB_lookup_result_s     result;
#if (NGX_HAVE_INET6)
    uint8_t                  address[16];
#else
    unsigned long            address;
#endif
} ngx_stream_geoip2_db_t;

typedef struct {
    ngx_array_t              *databases;
} ngx_stream_geoip2_conf_t;

typedef struct {
    ngx_stream_geoip2_db_t   *database;
    const char               **lookup;
    ngx_str_t                default_value;
    ngx_stream_complex_value_t source;
} ngx_stream_geoip2_ctx_t;


static ngx_int_t ngx_stream_geoip2_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static void *ngx_stream_geoip2_create_conf(ngx_conf_t *cf);
static char *ngx_stream_geoip2(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_geoip2_add_variable(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);
static void ngx_stream_geoip2_cleanup(void *data);


#define FORMAT(fmt, ...) do {                               \
        p = ngx_palloc(s->connection->pool, NGX_OFF_T_LEN); \
        if (p == NULL) {                                    \
            return NGX_ERROR;                               \
        }                                                   \
        v->len = ngx_sprintf(p, fmt, __VA_ARGS__) - p;      \
        v->data = p;                                        \
} while (0)

static ngx_command_t  ngx_stream_geoip2_commands[] = {

    { ngx_string("geoip2"),
        NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
        ngx_stream_geoip2,
        NGX_STREAM_MAIN_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command
};


static ngx_stream_module_t  ngx_stream_geoip2_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* preconfiguration */

    ngx_stream_geoip2_create_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_geoip2_module = {
    NGX_MODULE_V1,
    &ngx_stream_geoip2_module_ctx,         /* module context */
    ngx_stream_geoip2_commands,            /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
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
ngx_stream_geoip2_variable(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    uintptr_t data)
{
    int                       mmdb_error;
    u_char                   *p;
    ngx_str_t                 val;
    ngx_addr_t                addr;
    MMDB_entry_data_s         entry_data;
    ngx_stream_geoip2_ctx_t  *geoip2 = (ngx_stream_geoip2_ctx_t *) data;
    ngx_stream_geoip2_db_t   *database = geoip2->database;

#if (NGX_HAVE_INET6)
    uint8_t address[16], *addressp = address;
#else
    unsigned long address;
#endif

    if (geoip2->source.value.len > 0) {
         if (ngx_stream_complex_value(s, &geoip2->source, &val) != NGX_OK) {
             goto not_found;
         }

        if (ngx_parse_addr(s->connection->pool, &addr, val.data, val.len) != NGX_OK) {
            goto not_found;
        }
    } else {
        addr.sockaddr = s->connection->sockaddr;
        addr.socklen = s->connection->socklen;
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
    if (ngx_memcmp(&address, &database->address, sizeof(address)) != 0) {
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
        || MMDB_aget_value(&database->result.entry, &entry_data, geoip2->lookup)
        != MMDB_SUCCESS)
    {
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
            uint8_t *val = (uint8_t *) entry_data.uint128;
            FORMAT("0x%02x%02x%02x%02x%02x%02x%02x%02x"
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

        return NGX_OK;
    }

    v->not_found = 1;

    return NGX_OK;
}


static void *
ngx_stream_geoip2_create_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t        *cln;
    ngx_stream_geoip2_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_geoip2_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_stream_geoip2_cleanup;
    cln->data = conf;

    return conf;
}


static char *
ngx_stream_geoip2(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    int                        status, nelts, i;
    char                      *rv;
    ngx_str_t                 *value;
    ngx_conf_t                 save;
    ngx_stream_geoip2_db_t    *database;
    ngx_stream_geoip2_conf_t  *gcf = conf;

    value = cf->args->elts;

    if (gcf->databases == NULL) {
        gcf->databases = ngx_array_create(cf->pool, 2,
                                          sizeof(ngx_stream_geoip2_db_t));
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
    cf->handler = ngx_stream_geoip2_add_variable;
    cf->handler_conf = (void *) database;

    rv = ngx_conf_parse(cf, NULL);
    *cf = save;
    return rv;
}


static char *
ngx_stream_geoip2_add_variable(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    int                                  i, nelts, idx;
    ngx_str_t                           *value, name, source;
    ngx_stream_variable_t               *var;
    ngx_stream_geoip2_ctx_t             *geoip2;
    ngx_stream_compile_complex_value_t   ccv;

    geoip2 = ngx_pcalloc(cf->pool, sizeof(ngx_stream_geoip2_ctx_t));
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
    geoip2->database = (ngx_stream_geoip2_db_t *) conf;
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

                ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
                ccv.cf = cf;
                ccv.value = &source;
                ccv.complex_value = &geoip2->source;

                if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
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

    var = ngx_stream_add_variable(cf, &name, NGX_STREAM_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    geoip2->lookup = ngx_pcalloc(cf->pool,
                         sizeof(const char *) * (cf->args->nelts - (idx - 1)));

    if (geoip2->lookup == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = idx; i < nelts; i++) {
        geoip2->lookup[i - idx] = (char *) value[i].data;
    }
    geoip2->lookup[i - idx] = NULL;

    var->get_handler = ngx_stream_geoip2_variable;
    var->data = (uintptr_t) geoip2;

    return NGX_CONF_OK;
}


static void
ngx_stream_geoip2_cleanup(void *data)
{
    ngx_uint_t                 i;
    ngx_stream_geoip2_db_t    *database;
    ngx_stream_geoip2_conf_t  *gcf = data;

    if (gcf->databases != NULL) {
        database = gcf->databases->elts;

        for (i = 0; i < gcf->databases->nelts; i++) {
            MMDB_close(&database[i].mmdb);
        }

        ngx_array_destroy(gcf->databases);
    }
}
