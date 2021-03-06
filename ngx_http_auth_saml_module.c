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
 * - (post-access)         -- implements satisfy
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
 *   chkuid() in mod_auth_saml.c
 * http://nginx.org/en/docs/dev/development_guide.html#http_request_finalization
 * http://www.nginxguts.com/2011/01/phases/
 *
dot -Tpdf >ngx-calls.pdf <DOT

digraph ngx_calls {
ngx_http_core_run_phases
-> ngx_http_core_access_phase  // checker
-> ngx_http_auth_saml_handler;

ngx_http_core_run_phases
-> ngx_http_core_content_phase  // checker
-> ngx_http_auth_saml_handler;

//ngx_http_auth_saml_handler
//-> ngx_http_auth_saml_process_zxid_simple_outcome;

ngx_http_auth_saml_handler
-> ngx_http_read_client_request_body [label="POST /saml"];
ngx_http_read_client_request_body
-> ngx_http_auth_saml_post_read
-> ngx_http_auth_saml_handler_rest;
//-> ngx_http_auth_saml_process_zxid_simple_outcome;

ngx_http_auth_saml_handler
-> ngx_http_auth_saml_handler_rest [label="GET /saml"];

ngx_http_read_client_request_body
-> ngx_http_read_client_request_body_handler;
ngx_http_read_client_request_body_handler
-> ngx_http_do_read_client_request_body
-> ngx_http_auth_saml_post_read
-> zxid_sp_soap_parse;

ngx_http_auth_saml_post_read
-> ngx_http_finalize_request;

ngx_http_upstream_send_request_body
-> ngx_http_read_unbuffered_request_body
-> ngx_http_do_read_client_request_body;

ngx_http_read_client_request_body
-> ngx_http_do_read_client_request_body;

//ngx_http_auth_saml_handler_rest -> zxid_get_ses;
ngx_http_auth_saml_handler_rest -> zxid_simple_ses_active_cf [label="/saml w/ses"];
ngx_http_auth_saml_handler_rest -> zxid_simple_no_ses_cf [label="/saml login needed"];

//ngx_http_auth_saml_handler -> zxid_get_ses;
ngx_http_auth_saml_handler -> zxid_simple_ses_active_cf [label="PC w/ses"];
ngx_http_auth_saml_handler -> zxid_simple_no_ses_cf [label="PC login needed"];

zxid_simple_no_ses_cf -> ngx_http_auth_saml_process_zxid_simple_outcome [style=dotted];
zxid_simple_ses_active_cf -> ngx_http_auth_saml_process_zxid_simple_outcome [style=dotted];

ngx_http_core_content_phase [style=dotted];
ngx_http_auth_saml_handler [color=red, style=filled];
ngx_http_auth_saml_post_read [color=red, style=filled];
ngx_http_auth_saml_handler_rest [color=red, style=filled];
ngx_http_auth_saml_process_zxid_simple_outcome [color=red, style=filled];
//zxid_get_ses [color=red, style=filled, shape=box];
zxid_simple_ses_active_cf [color=red, style=filled, shape=box];
zxid_simple_no_ses_cf [color=red, style=filled, shape=box];
zxid_sp_soap_parse [color=red, style=filled, shape=box];
}

DOT

pdftops -paper A4 ngx-calls.pdf - | nc psps 9100

https://localhost:8443/protected/content.txt
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

/* Per request, per module, context. */

typedef struct {
  int req_kind;
  zxid_conf* loc_cf;
  zxid_cgi cgi;
  zxid_ses ses;
  char* post_body;
} ngx_http_auth_saml_ctx_t;

#define NGXAS_KIND_PC    (2)
#define NGXAS_KIND_ENDPT (3)
#define NGXAS_KIND_WSP   (4)
#define NGXAS_KIND_UMA   (5)

/*() Convert session attribute pool into nginx variables
 * that will be passed to Python and other modules using uwsgi_param directives.
 *
 * OUTMAP will be applied to decide which attributes to pass to the environment
 * and to rename them.
 *
 * This is considered internal function to auth_saml.
 * You should not call this directly, unless you know what you are doing.
 *
 * return:: ngx error code, typically OK (==0), which allows ngx continue
 *     processing the request. */

static int pool2ngx(zxid_conf* cf, ngx_http_request_t* req, struct zxid_attr* pool)
{
  int ret = 0;
#if 0
  char* name;
  //char* rs = 0;
  //char* rs_qs;
  char* setcookie = 0;
  char* setptmcookie = 0;
  char* cookie = 0;
  char* idpnid = 0;
  struct zxid_map* map;
  struct zxid_attr* at;
  struct zxid_attr* av;
  ngx_http_variable_t  *var, *v;
  //req_ctx = ngx_http_get_module_ctx(req, ngx_http_auth_saml_module);
  
  for (at = pool; at; at = at->n) {
    map = zxid_find_map(cf->outmap, at->name);
    if (map) {
      if (map->rule == ZXID_MAP_RULE_DEL) {
	D("attribute(%s) filtered out by del rule in OUTMAP", at->name);
	continue;
      }
      at->map_val = zxid_map_val(cf, 0, 0, map, at->name, at->val);
      if (map->dst && *map->dst && map->src && map->src[0] != '*') {
	name = map->dst;
      } else {
	name = at->name;
      }

      name = ngx_pcalloc(req->pool, strlen(cf->mod_saml_attr_prefix)+strlen(name)+1);
      sprintf(name, "%s%s", cf->mod_saml_attr_prefix, name);
      var = ngx_http_add_variable(ncf, name, 0);

      //***
      //apr_table_set(sbe, name, at->val);
      //for (av = at->nv; av; av = av->n) {
      //av->map_val = zxid_map_val(cf, 0, 0, map, at->name, av->val);
      //apr_table_set(sbe, name, av->map_val->s);
      //}
    } else {
      if ((errmac_debug & ERRMAC_DEBUG_MASK)>2)
	D("ATTR(%s)=VAL(%s)", at->name, STRNULLCHKNULL(at->val));
      else
	D("ATTR(%s)=VAL(%.*s)", at->name, at->val?(int)MIN(35,strlen(at->val)):6, at->val?at->val:"(null)");
      name = ngx_pcalloc(req->pool, strlen(cf->mod_saml_attr_prefix)+strlen(name)+1);
      sprintf(name, "%s%s", cf->mod_saml_attr_prefix, at->name);
      var = ngx_http_add_variable(ncf, name, 0);
      /* *** handling of multivalued attributes (right now only last is preserved) */

      //apr_table_set(sbe, name, at->val);
      //for (av = at->nv; av; av = av->n)
      //	apr_table_set(sbe, name, av->val);
    }
    if      (!strcmp(at->name, "idpnid"))       idpnid = at->val;      /* Capture special */
    else if (!strcmp(at->name, "setcookie"))    setcookie = at->val;
    else if (!strcmp(at->name, "setptmcookie")) setptmcookie = at->val;
    else if (!strcmp(at->name, "cookie"))       cookie = at->val;
    //else if (!strcmp(at->name, "rs"))         rs = at->val;
  }

  /* See zxidsimp.c: zxid_show_protected_content_setcookie() */
#if 0
  hrr_set_cookies(cf, r, setcookie, setptmcookie);  
  if (cookie && cookie[0] != '-') {
    D("Cookie(%s) 2", cookie);
      var = ngx_http_add_variable(ncf, "Cookie", 0);
    apr_table_addn(HRR_headers_in(r), "Cookie", cookie);  /* so internal redirect sees it */
  }
#endif
  if (idpnid && idpnid[0] != '-') {
    D("REMOTE_USER(%s)", idpnid);
    var = ngx_http_add_variable(ncf, "REMOTE_USER", 0);
    // ***
    //apr_table_set(sbe, "REMOTE_USER", idpnid);
    //HRR_set_user(r, idpnid);  /* set r->user httpd-2.4 anz framework requires this, 2.2 does not care */
  }
  
  //apr_table_setn(r->subprocess_env, apr_psprintf(r->pool, "%sLDIF", cf->mod_saml_attr_prefix), ldif);
  D("SSO OK ret(%d) uri(%s) filename(%s) path_info(%s) user(%s)=%p", ret, (char*)HRR_uri(r), (char*)HRR_filename(r), (char*)HRR_path_info(r), STRNULLCHKD((char*)HRR_user(r)), HRR_user(r));
#endif
  return ret;
}


/* 0x6000 outf QS + JSON = no output on successful sso, the attrubutes are in session
 * 0x1000 debug
 * 0x0e00 11 + 10 = Generate all HTML + Mgmt w/headers as string
 * 0x00a0 10 + 10 = Login w/headers as string + Meta w/headers as string
 * 0x0008 10 + 00 = SOAP w/headers as string + no auto redir, no exit(2) */
#define AUTO_FLAGS 0x6ea8

static ngx_int_t ngx_http_auth_saml_hdr_out(ngx_http_request_t* req, const char* name, const char* val)
{
  int len;
  char* cp;
  ngx_table_elt_t* hdr;
  
  if (!val || !*val)
    return NGX_DONE;
  
  hdr = ngx_list_push(&req->headers_out.headers);
  if (!hdr) {
    ERR("hdr(%s) allocation failed", name);
    return NGX_ERROR;
  }
  
  len = strlen(val);
  D("setting hdr(%s)=(%s)", name, val);
  cp = ngx_pcalloc(req->pool, len+1);
  strcpy(cp, val);
  hdr->hash = 1;
  hdr->key.len = strlen(name);
  hdr->key.data = (u_char*)name;
  hdr->value.len = len;
  hdr->value.data = (u_char*)cp;
  return NGX_DONE;
}

static ngx_int_t ngx_http_auth_saml_send_content(ngx_http_request_t* req, char* cont)
{
  int ctype_len, len, ret;
  const char* ctype;
  ngx_buf_t*  buf;
  ngx_chain_t out;

  if (!memcmp(cont, "Content-Type: ", 14)) {
    /* res returned by zxid_simple() always has the same format: it starts
     * by Content-Type and Content-Length headers followed by double CRNL. */
    cont += 14;  /* skip Content-Type header */
    ctype = cont;
    cont = strchr(cont, '\r');
    ctype_len = cont - ctype;
    cont = cont+2 + 16;  /* skip CRNL and "Content-Length: " (16 chars) */
    cont = strchr(cont, '\r') + 4; /* skip CRFL pair before body */
  } else {
    ctype = "text/plain";
    ctype_len = 10;
  }
  len = strlen(cont);
  
  req->headers_out.status = NGX_HTTP_OK;
  req->headers_out.content_length_n = len;
  req->headers_out.content_type.len = ctype_len;
  req->headers_out.content_type.data = (u_char *)ctype;
  ret = ngx_http_send_header(req);
  if (ret == NGX_ERROR || ret > NGX_OK || req->header_only)
    return ret;
  
  buf = ngx_pcalloc(req->pool, sizeof(ngx_buf_t));
  if (!buf) {
    ERR("failed to alloc buf %d", (int)sizeof(ngx_buf_t));
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  buf->pos = buf->start = (unsigned char*)cont; /* first position in memory of the data */
  buf->last = (unsigned char*)cont + len; /* last position */
  buf->memory = 1; /* content is in read-only memory */
  /* (i.e., filters should copy it rather than rewrite in place) */
  buf->last_buf = 1; /* there will be no more buffers in the response */
  
  out.buf = buf;
  out.next = 0;
  return ngx_http_output_filter(req, &out);
}

static ngx_int_t ngx_http_auth_saml_process_zxid_simple_outcome(ngx_http_request_t* req, zxid_conf* loc_cf, zxid_ses* ses, char* res)
{
  D_INDENT("simple_outcome: ");
#if 0
  if (cookie_hdr && cookie_hdr[0]) {
    D("Passing previous cookie(%s) to environment", cookie_hdr);
    zxid_add_attr_to_ses(loc_cf, ses, "cookie", zx_dup_str(loc_cf->ctx, cookie_hdr));
  }
#endif
  switch (res[0]) {
  case 'L':
    if (errmac_debug & MOD_AUTH_SAML_INOUT) INFO("REDIR(%s)", res);
    ngx_http_auth_saml_hdr_out(req, "Location", res+10);
    ngx_http_auth_saml_hdr_out(req, "Set-Cookie", ses->setcookie);
    ngx_http_auth_saml_hdr_out(req, "Set-Cookie", ses->setptmcookie);
    D_DEDENT("simple_outcome: ");
    return NGX_HTTP_SEE_OTHER;
  case 'C':
    if (errmac_debug & MOD_AUTH_SAML_INOUT) INFO("CONTENT(%s)", res);
    ngx_http_auth_saml_hdr_out(req, "Set-Cookie", ses->setcookie);
    ngx_http_auth_saml_hdr_out(req, "Set-Cookie", ses->setptmcookie);
    D_DEDENT("simple_outcome: ");
    return ngx_http_auth_saml_send_content(req, res);
  case 'z':
    INFO("User not authorized %d", 0);
    D_DEDENT("simple_outcome: ");
    return NGX_HTTP_FORBIDDEN;
  case 0: /* Logged in case */
    D("SSO OK pc %d", 0);
    pool2ngx(loc_cf, req, ses->at);
    D_DEDENT("simple_outcome: ");
    return NGX_DECLINED;
#if 0
  case 'd': /* Logged in case */
    if (errmac_debug & MOD_AUTH_SAML_INOUT) INFO("SSO OK LDIF(%s)", res);
    D("SSO OK pre uri(%s) filename(%s) path_info(%s)", uri, (char*)HRR_filename(r), (char*)HRR_path_info(r));
    ret = ldif2apache(cf, r, res);
    D_DEDENT("simple_outcome: ");
    return ret;
#endif
  default:
    ERR("Unknown zxid_simple response(%s)", res);
    D_DEDENT("simple_outcome: ");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  D("final ok %d", NGX_DECLINED);
  D_DEDENT("simple_outcome: ");
  return NGX_DECLINED;
}

/*() Latter part of handler.
 * Only for SSO or WSP protocol messages. Ordinary protected content
 * never comes here even if it is POST.
 * If POST method is used (and thus POST body needs to be read in), this
 * function is called by ngx_http_auth_saml_post_read() (which is called
 * from ngx_http_read_client_request_body()) once the body is complete
 * and has been analyzed into CGI variables.
 * For GET requests, this is called directly by ngx_http_auth_saml_handler().
 * Returns ngx result code, e.g. NGX_OK or NGX_ERROR.
 */

static ngx_int_t ngx_http_auth_saml_handler_rest(ngx_http_request_t* req, zxid_conf* loc_cf, ngx_http_auth_saml_ctx_t* req_ctx)
{
  char* res;
  D_INDENT("rest: ");
  switch (req_ctx->req_kind) {
  case NGXAS_KIND_ENDPT:
    if (ONE_OF_2(req_ctx->cgi.op, 'L', 'A')) /* SSO (Login, Artifact) activity */
      break;                                 /*     overrides current session. */
    if (!req_ctx->cgi.sid || !zxid_get_ses(loc_cf, &req_ctx->ses, req_ctx->cgi.sid)) {
      D("No session(%s) active op(%c)", STRNULLCHK(req_ctx->cgi.sid), req_ctx->cgi.op);
      break;
    }
    res = zxid_simple_ses_active_cf(loc_cf, &req_ctx->cgi, &req_ctx->ses, 0, AUTO_FLAGS);
    goto out;
  case NGXAS_KIND_WSP:
    if (zxid_wsp_validate(loc_cf, &req_ctx->ses, 0, req_ctx->post_body)) {
      D("WSP(%.*s) request valid", (int)req->uri.len, req->uri.data);
      pool2ngx(loc_cf, req, req_ctx->ses.at);
      D_DEDENT("rest: ");
      return NGX_DECLINED;  /* Let the request be handled in an ordinary way. */
      /* *** how to decorate the CGI return value?!? New hook needed? --Sampo */
    } else {
      ERR("WSP(%.*s) request validation failed", (int)req->uri.len, req->uri.data);
      D_DEDENT("rest: ");
      return NGX_HTTP_FORBIDDEN;
    }
  case NGXAS_KIND_UMA:
    // *** add UMA Resource Server stuff here
    pool2ngx(loc_cf, req, req_ctx->ses.at);
    ERR("UMA NOT IMPLEMENTED %.*s", (int)req->uri.len, req->uri.data);
    break;
  case NGXAS_KIND_PC:
    ERR("Protected Content seen in wrong place %.*s", (int)req->uri.len, req->uri.data);
    break;    
  default:
    ERR("Unknown request kind=%d req_ctx=%p req=%p uri(%.*s)", req_ctx->req_kind, req_ctx, req, (int)req->uri.len, req->uri.data);
  }
  res = zxid_simple_no_ses_cf(loc_cf, &req_ctx->cgi, &req_ctx->ses, 0, AUTO_FLAGS);

  D("final ok %d", NGX_DECLINED);
 out:
  D_DEDENT("rest: ");
  return ngx_http_auth_saml_process_zxid_simple_outcome(req, loc_cf, &req_ctx->ses, res);
  //return NGX_DECLINED;
  //return ngx_http_output_filter(req, &out);
}

/*() Post content callback.
 * When POST method is used (and thus POST body needs to be read in), this
 * function is called by ngx_http_read_client_request_body() once the
 * body is complete. Eventually this calls ngx_http_auth_saml_handler_rest(req).
 * Only protocol posts to /saml come here. Payload posts follow normal
 * path through nginx.
 */

static void ngx_http_auth_saml_post_read(ngx_http_request_t* req)
{
  int len, ret;
  zxid_conf* loc_cf;
  ngx_http_auth_saml_ctx_t* req_ctx;  /* per request per module variables */
  ngx_chain_t* in;
  char* cp;
  
  D_INDENT("post_read: ");
  loc_cf = ngx_http_get_module_loc_conf(req, ngx_http_auth_saml_module);
  if (!loc_cf) {
    ERR("NULL configuration %p", loc_cf);
    goto err;
  }
  req_ctx = ngx_http_get_module_ctx(req, ngx_http_auth_saml_module);
  if (!req_ctx) {
    ERR("request context missing %p", req);
    goto err;
  }
  if (!req->request_body || !req->request_body->bufs) {
    ERR("No POST request_body %p", req->request_body);
    goto err;
  }
#if 0
  ngx_buf_t* buf;
  if (req->request_body->bufs->next) {
    ERR("POST request body split in more than one buffer. Consider adjusting client_body_buffer_size in configuration. Only first buffer is processed. %p", req->request_body->bufs->next->next);
  }
  /* We need to make a copy of the POST content because zxid_parse_cgi() modifies the buffer
   * and points cgi fields inside the buffer. Also guarantee nul termination. */
  buf = req->request_body->bufs->buf;
  D("request_body start=%p end=%p pos=%p last=%p", buf->start, buf->end, buf->pos, buf->last);
  
  len = buf->end - buf->start;
  req_ctx->post_body = ngx_pcalloc(req->pool, len+1);
  if (!req_ctx->post_body) {
    ERR("Failed to allocate buffer for POST content parson len=%d", len);
    goto err;
  }
  memcpy(req_ctx->post_body, buf->start, len);
  req_ctx->post_body[len] = 0;
#else
  /* We need to make a copy of the POST content because zxid_parse_cgi() modifies the buffer
   * and points cgi fields inside the buffer. Also guarantee nul termination.
   * Gather the content from chain of ngx buffers. */
  
  for (len=0,in = req->request_body->bufs; in; in = in->next)
    len += ngx_buf_size(in->buf);
  req_ctx->post_body = ngx_pcalloc(req->pool, len+1);
  if (!req_ctx->post_body) {
    ERR("Failed to allocate buffer for POST content parson len=%d", len);
    goto err;
  }
  cp = req_ctx->post_body;
  for (in = req->request_body->bufs; in; in = in->next) {
    len = ngx_buf_size(in->buf);
    memcpy(cp, in->buf->pos, len);
    cp += len;
  }
  *cp = 0;
#endif
  
  if (req_ctx->cgi.op == 'S') {
    ret = zxid_sp_soap_parse(loc_cf, &req_ctx->cgi, &req_ctx->ses, len, req_ctx->post_body);
    D("POST soap parse returned %d", ret);
    // *** what next?
  } else {
    zxid_parse_cgi(loc_cf, &req_ctx->cgi, req_ctx->post_body);
    ret = ngx_http_auth_saml_handler_rest(req, loc_cf, req_ctx);
    D("POST ngx_http_auth_saml_handler_rest() returned %d", ret);
  }
  ngx_http_finalize_request(req, ret);
  D_DEDENT("post_read: ");
  return;
 err:
  ngx_http_finalize_request(req, NGX_HTTP_INTERNAL_SERVER_ERROR);
  D_DEDENT("post_read: ");
  return;
}

/*() nginx access phase handler
 */

static ngx_int_t ngx_http_auth_saml_handler(ngx_http_request_t* req)
{
  char buf[1024];
  char* res;
  char* cp;
  int url_len;
  zxid_conf* loc_cf;
  ngx_http_auth_saml_ctx_t* req_ctx;  /* per request per module variables */
  ngx_str_t cookie_name;
  ngx_str_t cookie_value;
  ngx_int_t rc;
  
  D_INDENT("handler: ");
  loc_cf = ngx_http_get_module_loc_conf(req, ngx_http_auth_saml_module);
  if (!req || !loc_cf) {
    ERR("NULL request %p or configuration %p", req, loc_cf);
  err:
    D_DEDENT("handler: ");
    return NGX_ERROR;
  }
  
  /* The context object is per module and per request */
  req_ctx = ngx_http_get_module_ctx(req, ngx_http_auth_saml_module);
  if (!req_ctx) {
    req_ctx = ngx_pcalloc(req->pool, sizeof(ngx_http_auth_saml_ctx_t));
    if (!req_ctx) {
      ERR("Failed to allocate request context %d", 0);
      goto err;
    }
    memset(req_ctx, 0, sizeof(ngx_http_auth_saml_ctx_t));
    req_ctx->loc_cf = loc_cf;
    ngx_http_set_ctx(req, req_ctx, ngx_http_auth_saml_module);
    D("req_ctx=%p allocated, loc_cf=%p", req_ctx, loc_cf);
  }
  
  /* Check if we are supposed to enter zxid due to URL suffix - to
   * process protocol messages rather than ordinary pages. To do this
   * correctly we need to ignore the query string part. We are looking
   * here at an exact match, like /protected/saml, rather than any of
   * the other documents under /protected/ (which are handled in the
   * else clause). Both then and else -clause URLs are defined as requiring
   * SSO by virtue of location directive in the web server configuration. */
  url_len = strlen(loc_cf->burl);
  for (cp = loc_cf->burl + url_len - 1; cp > loc_cf->burl; --cp)
    if (*cp == '?')
      break;
  if (cp == loc_cf->burl)
    cp = loc_cf->burl + url_len;
  url_len = cp - loc_cf->burl;
  
  if (url_len >= (int)req->uri.len
      && !memcmp(cp - req->uri.len, req->uri.data, req->uri.len)) {  /* Suffix match */
    req_ctx->req_kind = NGXAS_KIND_ENDPT;                                      /* /saml case */
  } else if (zx_match(loc_cf->wsp_pat, req->uri.len, (char*)req->uri.data)) {  /* WSP case */
    req_ctx->req_kind = NGXAS_KIND_WSP;
  } else if (zx_match(loc_cf->uma_pat, req->uri.len, (char*)req->uri.data)) {  /* UMA case */
    req_ctx->req_kind = NGXAS_KIND_UMA;
  } else if (zx_match(loc_cf->sso_pat, req->uri.len, (char*)req->uri.data)) {  /* Any SSO case */
    /* Ordinary protected content falls thru to here. Just check for session validity. */
    D("Protected SSO_PAT(%s) uri(%.*s) len=%d", loc_cf->sso_pat, (int)req->uri.len, STRNULLCHK(req->uri.data), (int)req->uri.len);
    req_ctx->req_kind = NGXAS_KIND_PC;
  } else {
    /* Access phase handler is called before location has been determined.
     * Hence we need to pass thru the locations that are not ours. */
    D("outside SSO_PAT(%s) uri(%.*s) len=%d", loc_cf->sso_pat, (int)req->uri.len, STRNULLCHK(req->uri.data), (int)req->uri.len);
    D_DEDENT("handler: ");
    return NGX_DECLINED;
  }
  if (errmac_debug & MOD_AUTH_SAML_INOUT) INFO("===== START %s kind=%d req=%p uri(%.*s) qs(%.*s) pid=%d cwd(%s)", ZXID_REL, req_ctx->req_kind, req, (int)req->uri.len, STRNULLCHK(req->uri.data), (int)req->args.len, STRNULLCHK(req->args.data), getpid(), getcwd(buf,sizeof(buf)));
  
  if (loc_cf->wd && *loc_cf->wd)
    chdir(loc_cf->wd);  /* Ensure the working dir is not / (sometimes Apache httpd changes dir) */
  
  if (req->uri.len && req->uri.data) {
    /* We need to make copy of the uri as we might modify it. Also guarantee nul termination. */
    req_ctx->cgi.uri_path = ngx_pcalloc(req->pool, req->uri.len+1);
    if (!req_ctx->cgi.uri_path) {
      ERR("Failed to allocate uri_path buffer. len=%d", (int)req->uri.len);
      goto err;
    }
    memcpy(req_ctx->cgi.uri_path, req->uri.data, req->uri.len);
    req_ctx->cgi.uri_path[req->uri.len] = 0;
  }
  if (req->args.len && req->args.data) {
    /* We need to make copy of the query string because zxid_parse_cgi() modifies the buffer
     * and points cgi fields inside the buffer. Also guarantee nul termination. */
    cp = ngx_pcalloc(req->pool, req->args.len+1);
    if (!cp) {
      ERR("Failed to allocate query string parsing buffer. len=%d", (int)req->args.len);
      goto err;
    }
    memcpy(cp, req->args.data, req->args.len);
    cp[req->args.len] = 0;
    zxid_parse_cgi(loc_cf, &req_ctx->cgi, cp);
  }
  
  /* Probe for Session ID in cookie. Also propagate the cookie to subrequests. */
  
  if (loc_cf->ses_cookie_name && *loc_cf->ses_cookie_name) {
    D("Looking for cookie(%s)", loc_cf->ses_cookie_name);
    cookie_name.len = strlen(loc_cf->ses_cookie_name);
    cookie_name.data = (u_char*)loc_cf->ses_cookie_name;
    rc = ngx_http_parse_multi_header_lines(&req->headers_in.cookies, &cookie_name, &cookie_value);
    if (rc != NGX_DECLINED) {
      D("found cookie(%.*s)", (int)cookie_value.len, STRNULLCHK(cookie_value.data));
      req_ctx->cgi.sid = ngx_pcalloc(req->pool, cookie_value.len+1);
      memcpy(req_ctx->cgi.sid, cookie_value.data, cookie_value.len);
      req_ctx->cgi.sid[cookie_value.len] = 0;
    } else {
      D("cookie(%s) not found", loc_cf->ses_cookie_name);
    }
  }

  switch (req_ctx->req_kind) {
  case NGXAS_KIND_ENDPT:
    if (req->method == NGX_HTTP_POST)
      goto post;
    D_DEDENT("handler: ");
    return ngx_http_auth_saml_handler_rest(req, loc_cf, req_ctx);
  case NGXAS_KIND_WSP:
  case NGXAS_KIND_UMA:
    if (req->method == NGX_HTTP_POST)
      goto post;
    ERR("uri(%.*s) must be called with POST method %d", (int)req->uri.len, req->uri.data, (int)req->method);
    D_DEDENT("handler: ");
    return NGX_HTTP_NOT_ALLOWED;
  }
  
  if (req_ctx->cgi.sid && req_ctx->cgi.sid[0]
      && zxid_get_ses(loc_cf, &req_ctx->ses, req_ctx->cgi.sid)) {
    res = zxid_simple_ses_active_cf(loc_cf, &req_ctx->cgi, &req_ctx->ses, 0, AUTO_FLAGS);
    if (res) {
      D_DEDENT("handler: ");
      return ngx_http_auth_saml_process_zxid_simple_outcome(req, loc_cf, &req_ctx->ses, res);
    }
  } else {
    if (loc_cf->optional_login_pat
	&& zx_match(loc_cf->optional_login_pat, req->uri.len, (char*)req->uri.data)) {
      D("optional_login_pat(%s) matches", loc_cf->optional_login_pat);
      // *** set_user(r, "-anon-");  /* httpd-2.4 anz framework requires this, 2.2 does not care */
      D_DEDENT("handler: ");
      return NGX_DECLINED;  /* Allow normal processing to happen */
    }
    D("No active session sid(%s)",STRNULLCHK(req_ctx->cgi.sid));
  }
  D("other page: no_ses op(%c) templ(%s) tf(%s) k(%s)", req_ctx->cgi.op?req_ctx->cgi.op:'-', STRNULLCHKNULL(req_ctx->cgi.templ), STRNULLCHKNULL(loc_cf->idp_sel_templ_file), STRNULLCHKNULL(req_ctx->cgi.skin));
  
  res = zxid_simple_no_ses_cf(loc_cf, &req_ctx->cgi, &req_ctx->ses, 0, AUTO_FLAGS);
  if (res) {
    D_DEDENT("handler: ");
    return ngx_http_auth_saml_process_zxid_simple_outcome(req, loc_cf, &req_ctx->ses, res);
  }
  ERR("zxid_simple() returned NULL %d", 0);
  D_DEDENT("handler: ");
  return NGX_DECLINED;  /* Allow normal processing to happen */

 post:
  rc = ngx_http_read_client_request_body(req, ngx_http_auth_saml_post_read);
  if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
    ERR("ngx_http_read_client_request_body() rc=%d", (int)rc);
    D_DEDENT("handler: ");
    return rc;
  }
  /* When we return nginx machinery reads the POST body and eventually calls
   * ngx_http_auth_saml_post_read() so we can continue handler processing. */
  D("ngx_http_read_client_request_body() returned %d", (int)rc);
  D_DEDENT("handler: ");
  return NGX_DONE;
}

/* --------------------------------------------- */

/* Provide a value for ZXID_VERSION variable. */

static ngx_int_t ngx_http_zxid_version_get(ngx_http_request_t* req, ngx_http_variable_value_t *v, uintptr_t data)
{
  char* p = (char*)ngx_pnalloc(req->pool, 11);
  D("HERE %d", 0);
  if (!p) {
    return NGX_ERROR;
  }
  v->len = sprintf(p, "0x%08x", zxid_version());
  D("len=%d val(%.*s)", v->len, v->len, p);
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;
  v->data = (u_char*)p;
  return NGX_OK;
}

/* Evaluate variable, referenceable in nginx configuration and request processing */

static ngx_int_t ngx_http_zxid_var_get(ngx_http_request_t* req, ngx_http_variable_value_t* val, uintptr_t data)
{
  ngx_http_auth_saml_ctx_t* req_ctx = ngx_http_get_module_ctx(req, ngx_http_auth_saml_module);
  char* name = (char*)data;
  struct zxid_map* map;
  struct zxid_attr* at;
  //struct zxid_attr* av;
  
  D("looking up var(%s) req_ctx=%p at_pool=%p", name, req_ctx, req_ctx?req_ctx->ses.at:0);
  if (!req_ctx) {
    D("Missing req_ctx, session attribute(%s) not found. You must have ZXIDConf directive in the location section to enable SSO",name);
    val->not_found = 1;
    return NGX_OK;
  }
  at = zxid_find_at(req_ctx->ses.at, name);
  if (!at) {
    D("session attribute(%s) not found",name);
    val->not_found = 1;
    return NGX_OK;
  }
  D("HERE %d",0);
  map = zxid_find_map(req_ctx->loc_cf->outmap, name);
  D("var(%s) at=%p map=%p", name, at, map);
  if (map) {
    if (map->rule == ZXID_MAP_RULE_DEL) {
      D("attribute(%s) filtered out by del rule in OUTMAP", name);
      val->not_found = 1;
      return NGX_OK;
    }
    at->map_val = zxid_map_val(req_ctx->loc_cf, &req_ctx->ses, 0, map, name, at->val);
    val->len = at->map_val->len;
    val->data = (u_char*)(at->map_val->s);
#if 0
    if (map->dst && *map->dst && map->src && map->src[0] != '*') {
      name = map->dst;
    } else {
      name = at->name;
    }
#endif
    //apr_table_set(sbe, name, at->val);
    //for (av = at->nv; av; av = av->n) {
    //  av->map_val = zxid_map_val(cf, 0, 0, map, at->name, av->val);
    //  apr_table_set(sbe, name, av->map_val->s);
    //}
  } else {
    if ((errmac_debug & ERRMAC_DEBUG_MASK)>2)
      D("ATTR(%s)=VAL(%s)", at->name, STRNULLCHKNULL(at->val));
    else
      D("ATTR(%s)=VAL(%.*s)", at->name, at->val?(int)MIN(35,strlen(at->val)):6, at->val?at->val:"(null)");
    //name = ngx_pcalloc(req->pool, strlen(cf->mod_saml_attr_prefix)+strlen(name)+1);
    //sprintf(name, "%s%s", cf->mod_saml_attr_prefix, at->name);
    //var = ngx_http_add_variable(ncf, name, 0);
    /* *** handling of multivalued attributes (right now only last is preserved) */
    
    val->len = strlen(at->val);
    val->data = (u_char*)(at->val);
    //apr_table_set(sbe, name, at->val);
    //for (av = at->nv; av; av = av->n)
    //	apr_table_set(sbe, name, av->val);
  }
  val->valid = 1;
  val->no_cacheable = 0;
  val->not_found = 0;
  return NGX_OK;
}

/* *** this list should be dynamic or runtime configurable */
static const char* ngx_zxid_vars[] = {
  "fedusername",
  "sesid",
  "sespath",
  "localuid",
  "localpath",
  "lang",
  "nick",
  "cn",
  "tel",
  "email",
  0
};

//static ngx_int_t ngx_http_auth_saml_add_vars(ngx_conf_t* ncf, zxid_conf* loc_cf)
static ngx_int_t ngx_http_auth_saml_add_vars(ngx_conf_t* ncf)
{
  const char** name;
  ngx_str_t ns = ngx_string("zxid_version");
  ngx_http_variable_t* var;
  //ngx_http_core_main_conf_t* cmcf;
  
  var = ngx_http_add_variable(ncf, &ns, 0);
  if (!var)
    goto err;
  var->get_handler = ngx_http_zxid_version_get;
  //ERR("var(%.*s)=%p", (int)ns.len, ns.data, var);

  for (name = ngx_zxid_vars; *name; ++name) {
#if 0
    ns.len = loc_cf->mod_saml_attr_prefix?strlen(loc_cf->mod_saml_attr_prefix):0+strlen(*name);
    ns.data = ngx_pnalloc(ncf->pool, ns.len+1);
    sprintf((char*)ns.data, "%s%s", STRNULLCHK(loc_cf->mod_saml_attr_prefix), *name);
#else
    ns.len = sizeof("saml_")-1+strlen(*name);
    ns.data = ngx_pnalloc(ncf->pool, ns.len+1);
    sprintf((char*)ns.data, "saml_%s", *name);
#endif
    //ERR("len=%d var(%s)", (int)ns.len, ns.data);
    var = ngx_http_add_variable(ncf, &ns, 0);
    if (!var)
      goto err;
    var->get_handler = ngx_http_zxid_var_get;
    var->data = (uintptr_t)*name;
    DD("VAR(%s) len=%d var(%s)=%p handler=%p", (char*)var->data, (int)ns.len, ns.data, var, var->get_handler);
  }
  return NGX_OK;
 err:
  ERR("var(%.*s) not added", (int)ns.len, ns.data);
  return NGX_ERROR;
}

/*() Process ZXIDConf configuration file directive */

char* ngx_http_auth_saml_zxidconf_cmd(ngx_conf_t* ncf, ngx_command_t* cmd, void* conf)
{
  char* buf;
  ngx_str_t* value;
  zxid_conf* loc_cf = (zxid_conf*)conf;
#if 0
  ngx_http_core_loc_conf_t  *clcf;

  /* Install content (?) handler for location */
  clcf = ngx_http_conf_get_module_loc_conf(ncf, ngx_http_core_module);
  if (!clcf) {
    ERR("NULL core module local configuration %p", clcf);
  }
  clcf->handler = ngx_http_auth_saml_handler;  /* content handler (?) */
#endif
  
  if (!ncf->args || !ncf->args->elts) {
    ERR("configuration NULL args %p", ncf->args);
  }
  value = ncf->args->elts;
  D("arg(%.*s) loc_cf=%p", (int)value[1].len, value[1].data, loc_cf);
  /* We make a copy (which is leaked) of the value because zxid_parse_conf() references
   * places inside the configuration string and we can not assume cf->args is long lived enough. */
  buf = ZX_ALLOC(loc_cf->ctx, value[1].len+1);
  memcpy(buf, value[1].data, value[1].len);
  buf[value[1].len] = 0;
  zxid_parse_conf(loc_cf, buf);
  DD("DEFAULTQS(%s) loc_cf=%p", loc_cf->defaultqs, loc_cf);
  return NGX_CONF_OK;
}

char* ngx_http_auth_saml_zxiddebug_cmd(ngx_conf_t *ncf, ngx_command_t *cmd, void *conf)
{
  char buf[1024];
  ngx_str_t* value;

  value = ncf->args->elts;
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

static int n_calls = 0;

static void* ngx_http_auth_saml_create_loc_conf(ngx_conf_t* ncf)
{
  zxid_conf* loc_cf;
  //strncpy(errmac_instance, "\tngxas", sizeof(errmac_instance));
  strncpy(errmac_instance, "\t" CC_BLUY("ngxas"), sizeof(errmac_instance));
  /* Empty CPATH= prevents reading initial conf file /var/zxid/zxid.conf
   * Empty SSO_PATH= prevents this module applying outside locations. */
  loc_cf = zxid_new_conf_to_cf("CPATH=&SSO_PAT=&BURL=https://impossible/impossible");
  //ngx_http_auth_saml_add_vars(ncf, loc_cf);
  //loc_cf->redirect_hack_zxid_url = ;
  INFO("%d: ncf=%p->name(%s) loc_cf=%p", ++n_calls, ncf, ncf->name, loc_cf);
  return loc_cf;
}

/*() Install access handler
 * auth_saml needs to be access phase handler because there can only be one
 * content phase handler and that typicallyis uwsgw or fastcgi or similar.
 * Installing the content handler would happen in ngx_http_auth_saml_zxidconf_cmd() when
 * ZXIDConf config stanza is seen.
 */

static ngx_int_t ngx_http_auth_saml_init(ngx_conf_t *ncf)
{
  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;
  cmcf = ngx_http_conf_get_module_main_conf(ncf, ngx_http_core_module);
  // ***
  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  *h = ngx_http_auth_saml_handler;
  return NGX_OK;
}

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
  ngx_http_auth_saml_add_vars,           /* preconfiguration */
  ngx_http_auth_saml_init,    /* postconfiguration */
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
