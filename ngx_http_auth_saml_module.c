/* ngx_http_auth_saml_module.c  -  nginx module for using ZXID based SAML, OpenID Connect, etc.
 * Copyright (c) Sampo Kellomaki (sampo@iki.fi), All Rights Reerved.
 * Author: Sampo Kellomaki (sampo@iki.fi)
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing.
 * Licensed under Apache License 2.0, see file COPYING.
 * $Id: $
 *
 * 20170815 created --Sampo
 *
 * apt install libcurl4-openssl-dev
 * cd nginx-1.12.1
 * ./configure --with-debug --with-http_ssl_module --add-module=/home/sampo/zxid
 * make
 * make install
 * /usr/local/nginx/sbin/nginx -c ~/zxid/nginx.conf
 * ~/nginx-1.12.1/objs/nginx -c ~/zxid/nginx.conf -g 'daemon off;'
 * tailf /usr/local/nginx/logs/error.log &
 *
 * Phase order (see nginx-1.12.1/src/http/ngx_http_core_module.h)
 * - post-read
 * - server-rewrite
 * - (find-config)  <--.
 * - rewrite           |   -- used by set
 * - (post-rewrite) ---'
 * - preaccess
 * - access                -- used by ngx_access, ngx_auth_request
 * - (post-access)
 * - try-files
 * - content               -- used by echo
 * - log
 *
 * nginx-1.12.1/src/http/ngx_http.c  -- Construction of phases arrays
 * nginx-1.12.1/src/http/ngx_http_core_module.c
 *   - ngx_http_core_run_phases()
 *   - ngx_http_core_generic_phase() -- Used by post-read and pre-access
 *   - ngx_http_core_rewrite_phase()
 *   - ngx_http_core_find_config_phase()
 *   - ngx_http_core_post_rewrite_phase()
 *   - ngx_http_core_access_phase()
 *   - ngx_http_core_post_access_phase()
 *   - ngx_http_core_try_files_phase()
 *   - ngx_http_core_content_phase()
 *
 * NGX_OK       - exact match
 * NGX_DONE     - auto redirect
 * NGX_AGAIN    - inclusive match
 * NGX_DECLINED - no match
 *
 * See also: http://www.evanmiller.org/nginx-modules-guide.html
 */

#define USE_OPENSSL
#define USE_CURL

#include <zx/platform.h>
#include <zx/errmac.h>
#include <zx/zxid.h>
#include <zx/zxidpriv.h>
#include <zx/zxidconf.h>
#include <zx/zxidutil.h>
#include <zx/c/zxidvers.h>

#include <malloc.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#ifndef MINGW
#include <grp.h>
#endif
#ifdef USE_CURL
#include <curl/curl.h>
#endif

#undef CRLF   /* conflict between errmac.h and src/core/ngx_core.h */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_module_t  ngx_http_auth_saml_module;

static ngx_int_t ngx_http_auth_saml_handler(ngx_http_request_t* req)
{
  //ngx_buf_t    *nb;
  ngx_chain_t   out;
  zxid_conf* loc_cf;
  loc_cf = ngx_http_get_module_loc_conf(req, ngx_http_auth_saml_module);

  D("HERE %p", loc_cf);
  return NGX_DECLINED;
  
#if 0
  /* nginx can call handler from multiple phases. We want to run only on first try
   * so we check and set the internal flag. */
  if (req->main->internal) {
    return NGX_DECLINED;
  }
  req->main->internal = 1;
#endif
#if 0
  // check if cookie session ok

  location = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie, &cookie_value);

  
  /* Prepare response in buffer */
  nb = ngx_pcalloc(req->pool, sizeof(ngx_buf_t));
  if (!nb) {
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, 
		  "Failed to allocate response buffer.");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  
  nb->pos = some_bytes; /* first position in memory of the data */
  nb->last = some_bytes + some_bytes_length; /* last position */

  nb->memory = 1; /* content is in read-only memory */
  /* (i.e., filters should copy it rather than rewrite in place) */

  nb->last_buf = 1; /* there will be no more buffers in the request */
  
  out.buf = nb;
  out.next = NULL;
#endif
#if 0
  // adding header to request
  ngx_table_elt_t *h;
  h = ngx_list_push(&r->headers_out.headers);
  h->hash = 1;
  ngx_str_set(&h->key, "X-NGINX-Tutorial");
  ngx_str_set(&h->value, "Hello World!");
#endif
  
  //return NGX_DECLINED;
  return ngx_http_output_filter(req, &out);
}

char* ngx_http_auth_saml_zxidconf_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  char* buf;
  ngx_str_t* value;
  zxid_conf* loc_cf = (zxid_conf*)conf;
  ngx_http_core_loc_conf_t  *clcf;

  /* Install content (?) handler for location */
  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  clcf->handler = ngx_http_auth_saml_handler;  /* content handler (?) */

  value = cf->args->elts;
  D("arg(%.*s) cf=%p", (int)value[1].len, value[1].data, loc_cf);
  /* We make a copy (which is leaked) of the value because zxid_parse_conf() references
   * places inside the configuration string and we can not assume cf->args is long lived enough. */
  buf = ZX_ALLOC(loc_cf->ctx, value[1].len+1);
  memcpy(buf, value[1].data, value[1].len);
  buf[value[1].len] = 0;
  zxid_parse_conf(loc_cf, buf);
  return NGX_CONF_OK;
}

char* ngx_http_auth_saml_zxiddebug_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  char buf[1024];
  ngx_str_t* value;

  value = cf->args->elts;
  D("old debug=%x, new debug(%.*s)", errmac_debug, (int)value[1].len, value[1].data);
  sscanf((const char*)value[1].data, "%i", &errmac_debug);
  INFO("debug=0x%x now arg(%.*s) cwd(%s)", errmac_debug, (int)value[1].len, value[1].data, getcwd(buf, sizeof(buf)));
  {
    struct rlimit rlim;
    getrlimit(RLIMIT_CORE, &rlim);
    D("MALLOC_CHECK_(%s) core_rlimit=%d,%d", getenv("MALLOC_CHECK_"), (int)rlim.rlim_cur, (int)rlim.rlim_max);
  }
  return NGX_CONF_OK;
}

static void * ngx_http_auth_saml_create_loc_conf(ngx_conf_t *cf)
{
  strncpy(errmac_instance, "\tngxmas", sizeof(errmac_instance));
  return zxid_new_conf_to_cf(0);
}

#if 0
// installing the content (?) handler happens in ngx_http_auth_saml_zxidconf_cmd() when
// ZXIDConf config stanza is seen.
static ngx_int_t ngx_http_auth_saml_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;
  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  // ***
  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  *h = ngx_http_auth_saml_handler;
  return NGX_OK;
}
#endif

static ngx_command_t  ngx_http_auth_saml_commands[] = {
    { ngx_string("ZXIDConf"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_saml_zxidconf_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,  /* no offset */
      0 /* no post_handler for this config command */ },
    { ngx_string("ZXIDDebug"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_saml_zxiddebug_cmd,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      0 },
      ngx_null_command
};

static ngx_http_module_t  ngx_http_auth_saml_module_ctx = {
    0,                          /* preconfiguration */
    0,  // ngx_http_auth_saml_init,    /* postconfiguration */
    0,                          /* create main configuration */
    0,                          /* init main configuration */
    0,                          /* create server configuration */
    0,                          /* merge server configuration */
    ngx_http_auth_saml_create_loc_conf,  /* create location configuration */
    0  //ngx_http_auth_saml_merge_loc_conf /* merge location configuration */
};

ngx_module_t  ngx_http_auth_saml_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_saml_module_ctx, /* module context */
    ngx_http_auth_saml_commands,    /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    0,                          /* init master */
    0,                          /* init module */
    0,                          /* init process */
    0,                          /* init thread */
    0,                          /* exit thread */
    0,                          /* exit process */
    0,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

/* EOF - ngx_http_auth_saml_module.c */
