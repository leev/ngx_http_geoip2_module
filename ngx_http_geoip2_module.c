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
    MMDB_s                  database;
    int                     initialized;
    ngx_array_t             *proxies;
    ngx_flag_t              proxy_recursive;
    MMDB_lookup_result_s    result;
#if (NGX_HAVE_INET6)
    uint8_t                 address[16];
#else
    unsigned long           address;
#endif
} ngx_http_geoip2_conf_t;


typedef struct {
    const char              **lookup;
    ngx_str_t               default_value;
} ngx_http_geoip2_ctx_t;


static ngx_int_t ngx_http_geoip2_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_geoip2_create_conf(ngx_conf_t *cf);
static char *ngx_http_geoip2_init_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_geoip2_data(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip2_mmdb(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_geoip2_proxy(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_geoip2_cidr_value(ngx_conf_t *cf, ngx_str_t *net,
    ngx_cidr_t *cidr);
static void ngx_http_geoip2_cleanup(void *data);


static ngx_command_t  ngx_http_geoip2_commands[] = {

    { ngx_string("geoip2_mmdb"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_http_geoip2_mmdb,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("geoip2_data"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
        ngx_http_geoip2_data,
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
    int                     mmdb_error;
    MMDB_entry_data_s       entry_data;
    ngx_http_geoip2_conf_t  *gcf;
    ngx_addr_t              addr;
    ngx_array_t             *xfwd;

#if (NGX_HAVE_INET6)
    uint8_t address[16], *addressp = address;
#else
    unsigned long address;
#endif

    gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip2_module);

    if (!gcf->initialized) {
        goto not_found;
    }

    addr.sockaddr = r->connection->sockaddr;
    addr.socklen = r->connection->socklen;

    xfwd = &r->headers_in.x_forwarded_for;

    if (xfwd->nelts > 0 && gcf->proxies != NULL) {
        (void) ngx_http_get_forwarded_addr(r, &addr, xfwd, NULL,
                                           gcf->proxies, gcf->proxy_recursive);
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
    if (ngx_memcmp(&address, &gcf->address, sizeof(address)) != 0) {
#else
    if (address != gcf->address) {
#endif
        memcpy(&gcf->address, &address, sizeof(address));
        gcf->result = MMDB_lookup_sockaddr(&gcf->database, addr.sockaddr,
                                           &mmdb_error);

        if (mmdb_error != MMDB_SUCCESS) {
            goto not_found;
        }
    }

    if (!gcf->result.found_entry || MMDB_aget_value(&gcf->result.entry,
                                                &entry_data,
                                                geoip2->lookup)
                                    != MMDB_SUCCESS) {
        goto not_found;
    }

    if (!entry_data.has_data) {
        goto not_found;
    }

    switch (entry_data.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
            v->data = (u_char *) entry_data.utf8_string;
            v->len = entry_data.data_size;
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
    conf->initialized = 0;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_geoip2_cleanup;
    cln->data = conf;

    return conf;
}


static char *
ngx_http_geoip2_data(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t               *value, name;
    ngx_http_geoip2_ctx_t   *geoip2;
    ngx_http_variable_t     *var;
    int                     i, nelts, lookup_idx;
    char                    *prefix = "default=";
    size_t                  prefix_len = sizeof("default=") - 1;

    geoip2 = ngx_pcalloc(cf->pool, sizeof(ngx_http_geoip2_ctx_t));
    if (geoip2 == NULL) {
        return NGX_CONF_ERROR;
    }

    geoip2->lookup = ngx_pcalloc(cf->pool,
                                 sizeof(const char *) * (cf->args->nelts - 1));
    if (geoip2->lookup == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
    name = value[1];
    nelts = (int) cf->args->nelts;

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    lookup_idx = 2;
    if (nelts > 2 && value[2].len >= prefix_len &&
            ngx_strncmp(value[2].data, prefix, prefix_len) == 0) {
        geoip2->default_value.len = value[2].len - prefix_len;
        geoip2->default_value.data = value[2].data + prefix_len;
        lookup_idx++;
    }

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = lookup_idx; i < nelts; i++) {
        geoip2->lookup[i-lookup_idx] = (char *) value[i].data;
    }
    geoip2->lookup[i] = NULL;

    var->get_handler = ngx_http_geoip2_variable;
    var->data = (uintptr_t) geoip2;

    return NGX_CONF_OK;
}


static char *
ngx_http_geoip2_init_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_geoip2_conf_t  *gcf = conf;

    ngx_conf_init_value(gcf->proxy_recursive, 0);

#if (NGX_HAVE_INET6)
    ngx_memset(&gcf->address, 0, sizeof(gcf->address));
#else
    gcf->address = 0;
#endif

    return NGX_CONF_OK;
}


static char *
ngx_http_geoip2_mmdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_geoip2_conf_t  *gcf = conf;
    ngx_str_t               *value;

    if (gcf->initialized) {
        return "is duplicate";
    }

    value = cf->args->elts;

    int status = MMDB_open((char *) value[1].data,
                           MMDB_MODE_MMAP, &gcf->database);

    if (status != MMDB_SUCCESS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "MMDB_open(\"%V\") failed - %s", &value[1],
                           MMDB_strerror(status));
        return NGX_CONF_ERROR;
    }

    gcf->initialized = 1;
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

    if (gcf->initialized) {
        MMDB_close(&gcf->database);
        gcf->initialized = 0;
    }
}
